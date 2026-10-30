import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readFile,mkdir,open,unlink} from 'node:fs/promises';
import {insideTenantData} from './lib/tenant/environments.mjs';
import {safeRequest} from './lib/network.mjs';
import {CERTIFICATION_PORT,checkCertification,certificationFolderRefusal} from './lib/certification.mjs';
import {randomBytes,randomUUID,timingSafeEqual,createHash} from 'node:crypto';
import {Store} from './lib/store.mjs';
import {Vault} from './lib/vault.mjs';
import {ConnectionManager,catalogFor} from './lib/connections.mjs';
import {describeConnectionOptions} from './lib/connection-options.mjs';
import {GoogleOAuthManager} from './lib/oauth.mjs';
import {OAuth2Provider} from './lib/providers/oauth2.mjs';
import {ContinuationService} from './lib/continuations.mjs';
import {catalogPage,activityPage,approvalPage} from './lib/ui-contracts.mjs';
import {AppDetailService} from './lib/app-detail.mjs';
import {definitionFor,reviewedProviderIds} from './lib/providers/definitions.mjs';
import {RELAY_PORTS,relayed,relayOrigin,relayRedirect,relayPortHelp} from './lib/oauth-relay.mjs';
import {LocalDriver,workspaceCapabilities} from './lib/local-driver.mjs';
import {BrowserBridge} from './lib/browser-bridge.mjs';
import {Runtime} from './lib/runtime.mjs';
import {HeartbeatScheduler} from './lib/heartbeat.mjs';
import {AcquisitionEngine} from './lib/acquisition.mjs';
import {DiscoveryEngine} from './lib/discovery.mjs';
import {validateCapability,canonicalHash} from './lib/compiler.mjs';
import {DeviceDriver,deviceCapabilities} from './lib/device-driver.mjs';
import {ConnectorResolver,planConnection} from './lib/connector-resolver.mjs';
import {FabricProtocol,protocolManifest,FABRIC_PROTOCOL} from './lib/fabric-protocol.mjs';
import {AdapterFactory} from './lib/adapter-factory.mjs';
import {BrowserSetup} from './lib/browser-setup.mjs';
import {PersistentBrowser} from './lib/persistent-browser.mjs';
import {matchingBrowserTransport} from './lib/permissions.mjs';
import {loadActionsSafely,demoteActions} from './lib/action-gate.mjs';
import {LocalRepository} from './lib/repositories/local.mts';
import {checkedClock} from './contracts/repository.mts';
import {validatePrincipal} from './contracts/identity.mts';
import {captureConnectionAuthority,assertConnectionAuthority} from './lib/authority-guard.mjs';
import {offeredLevels,heldLevel} from './lib/access-levels.mjs';
import {pagesLevel} from './lib/connection-notes.mjs';
import {distributionOf} from './lib/slack-limits.mjs';

const ROOT=path.dirname(fileURLToPath(import.meta.url));
// Every helper, pairing, setup and saved-profile route. Designated authority mode parks the browser driver (I12B), so all of them fail closed there.
const BROWSER_ROUTE=/^\/api\/(?:browser\/|browser-setup$|pair(?:\/|$)|session-browser(?:\/|$))/;
const secureEqual=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const cookies=req=>Object.fromEntries(String(req.headers.cookie||'').split(';').map(x=>x.trim().split('=' )).filter(x=>x.length===2));
async function body(req) {
  if(!String(req.headers['content-type']||'').startsWith('application/json')) throw new Error('JSON Content-Type required.');
  let size=0;const chunks=[];for await(const chunk of req){size+=chunk.length;if(size>2_000_000) throw new Error('Request exceeds 2 MB.');chunks.push(chunk);}
  const value=JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}');if(!value||typeof value!=='object'||Array.isArray(value)) throw new Error('JSON object required.');return value;
}
function json(res,status,data,headers={}) {res.writeHead(status,{'Content-Type':'application/json; charset=utf-8',...headers});res.end(JSON.stringify(data));}
function publicOrigin(value) {const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash||u.hostname==='localhost'||/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname)||u.hostname.includes(':')) throw new Error('Application origins must be public HTTPS hostnames without paths.');return u.origin;}

export async function createApp({dataDir=process.env.FABRIC_DATA_DIR||path.join(ROOT,'.fabric'),port=Number(process.env.FABRIC_PORT||4188),publicCallbackBase=process.env.FABRIC_PUBLIC_CALLBACK_BASE,relayPorts=RELAY_PORTS,request,modelConfig={},browserSetup,sessionBrowserLaunch,localAuthority,clock=Date.now,actions:actionOptions={},certification}={}) {
  clock=checkedClock(clock);
  // Checked before any local state opens, so a bad relay setting names itself and leaves nothing open.
  const relayBase=relayOrigin(publicCallbackBase);
  // relayPorts is a test seam: the deployed page forwards RELAY_PORTS only.
  if(!Array.isArray(relayPorts)||relayPorts.length<1||relayPorts.length>8||relayPorts.some(value=>!Number.isSafeInteger(value)||value<1||value>65535)) throw new Error('Relay ports must be one to eight TCP port numbers.');
  // F10.12: a certification Fabric (the live-test harness, docs/F10.12-BUILD-MAP.md part 1) is an embedding option, never an environment flag.
  // It needs a live guard with wrap and signIn, a designated store, port 4320 and a folder the harness may use, all checked before any local
  // state opens. Then every module below sends through the guard: no embedding can forget the wrap.
  if(certification!==undefined) {
    checkCertification(certification);
    if(localAuthority===undefined) throw new Error('A certification Fabric needs a designated local authority store.');
    if(port!==CERTIFICATION_PORT) throw new Error(`A certification Fabric runs on port ${CERTIFICATION_PORT} only.`);
    const refusal=certificationFolderRefusal(dataDir,{root:ROOT});if(refusal) throw new Error(refusal);
    request=certification.guard.wrap(request??safeRequest);
  }
  // F03.0: a developer environment folder is never opened by the single-owner runtime.
  if(insideTenantData(dataDir))throw new Error('This folder belongs to the developer layer (a tenant root, an environment, the platform catalog or the registry); the local runtime cannot open it.');
  // Version 2 consent policies: a bad publishing setting names itself before any local state opens.
  for(const [key,value] of Object.entries(process.env))if(/^FABRIC_[A-Z0-9_]+_PUBLISHING$/.test(key)&&value!=='testing'&&value!=='production')throw new Error(`${key} must be testing or production.`);
  // F10.4: how long one consent lasts (Google's Testing mode: 7), the same way.
  for(const [key,value] of Object.entries(process.env))if(/^FABRIC_[A-Z0-9_]+_CONSENT_DAYS$/.test(key)&&!(/^\d{1,3}$/.test(value)&&Number(value)>=1&&Number(value)<=365))throw new Error(`${key} must be a whole number of days from 1 to 365.`);
  // F10.21: how Fabric's Slack app is installed (lib/slack-limits.mjs), read once, the same way.
  const slackDistribution=distributionOf(process.env);
  // Explicit embedding/test seam only. No environment flag or silent activation
  // of private prototype data. Local HTTP sessions are not human authentication:
  // this single-owner runtime trusts the operator-controlled loopback machine.
  let ownerPrincipal=null;
  if(localAuthority!==undefined) {
    canonicalHash(localAuthority);
    if(Object.keys(localAuthority).some(key=>!['mode','ownerPrincipal'].includes(key))||!['new','require'].includes(localAuthority.mode)||path.resolve(dataDir)===path.join(ROOT,'.fabric')) throw new Error('Designate an isolated local runtime explicitly with new or require mode.');
    ownerPrincipal=validatePrincipal(localAuthority.ownerPrincipal);
    if(ownerPrincipal.kind!=='local_owner') throw new Error('A configured local owner is required.');
  }
  const origin=`http://127.0.0.1:${port}`;const store=new LocalRepository({store:new Store({dataDir,clock,...(localAuthority?{localAuthority:localAuthority.mode}:{})}),...(ownerPrincipal?{scope:ownerPrincipal.scope}:{})});
  if(ownerPrincipal) {
    try {
      const designation={id:'owner',schemaVersion:1,ownerPrincipal};
      if(localAuthority.mode==='new')store.put('localDeployment',designation);
      else if(canonicalHash(store.get('localDeployment','owner'))!==canonicalHash(designation))throw new Error('The saved deployment owner does not match. No ownership backfill is permitted.');
    } catch(error) {store.close();throw error;}
  }
  const vault=new Vault(dataDir);
  const startedAt=new Date(clock()).toISOString();
  const setup=browserSetup||new BrowserSetup({root:ROOT,origin});
  const connections=new ConnectionManager({store,vault,clock,...(request?{request}:{})});
  // F10.12: in certification no adapter ever asks a provider to revoke (decision 13), and every sign-in asks the guard first.
  const signInOptions=certification?{revocationPolicy:'local_only',signInGuard:certification.guard.signIn}:{};
  const oauth=new GoogleOAuthManager({store,vault,connections,clock,redirectUri:`${origin}/api/oauth/google/callback`,...signInOptions,...(request?{request}:{})});connections.setOAuthManager(oauth);
  // One trusted OAuth adapter per reviewed auth definition; each owns /api/oauth/<provider>/callback.
  const oauthProviders=new Map([['google',oauth]]);
  // Callback relay for providers that refuse loopback callbacks (Slack, Notion): the provider redirects to
  // <base>/oauth/<provider>/<port>/callback, the static page in relay/index.html sends the browser straight back
  // to this loopback callback, and the flow cookie and state are checked here as usual. Nothing local is exposed.
  // The page forwards only RELAY_PORTS; on any other port those providers say so instead of dead-ending at the page.
  const relayHere=Boolean(relayBase)&&relayPorts.includes(port);
  for(const id of reviewedProviderIds().filter(id=>id!=='google')){const definition=definitionFor(id),hosted=relayHere&&relayed(definition);
    const provider=new OAuth2Provider(definition,{store,vault,connections,clock,redirectUri:hosted?relayRedirect(relayBase,id,port):`${origin}/api/oauth/${id}/callback`,...(hosted?{allowHostedRedirect:true}:{}),...(relayBase&&!relayHere?{callbackHelp:relayPortHelp(port,relayPorts)}:{}),...signInOptions,...(request?{request}:{})});connections.setOAuthProvider(provider);oauthProviders.set(id,provider);}
  // Access levels a sign-in can offer and the level an account holds, from the provider's normalized app entry (lib/access-levels.mjs).
  const appAccess=(appId,providerId=connections.providers.providerFor(appId))=>{const provider=providerId&&oauthProviders.get(providerId);if(!provider)return null;try{return provider.access(provider.app(appId));}catch{return null;}};
  const accessLevels=appId=>offeredLevels(appAccess(appId));
  // F10.7: a route also says what its sign-in asks for: the levels it offers (pages for Notion) and the adapter's consent mode.
  const oauthRoute=appId=>{const id=connections.providers.providerFor(appId),provider=id&&oauthProviders.get(id);if(!provider)return null;const {configured,available,reason}=provider.availability();return {providerId:id,name:provider.name,configured,available,reason,levels:accessLevels(appId),consentMode:provider.consentMode};};
  // F10.19: a page grant reads with its account note, "Pages you shared (N)" (lib/connection-notes.mjs).
  const accessLevelOf=connection=>connection?.authMethod!=='oauth'?'custom':pagesLevel(store,connection,heldLevel(appAccess(connection.appId,connections.providerOf?.(connection)||connections.providers.providerFor(connection.appId)),connection.scopes));
  const oauthStart=(res,provider,input,trusted)=>{const flow=provider.start(input,trusted);res.setHeader('Set-Cookie',`fabric_oauth=${flow.flowId}; HttpOnly; SameSite=Lax; Path=/api/oauth/${provider.providerId}/callback; Max-Age=600`);return flow;};
  const local=new LocalDriver(path.join(dataDir,'workspace'));await local.init();
  const device=new DeviceDriver();await device.init();
  for(const cap of workspaceCapabilities) if(!store.get('capabilities',cap.id)) store.put('capabilities',cap);
  for(const cap of deviceCapabilities) if(!store.get('capabilities',cap.id)) store.put('capabilities',cap);
  // F10.11 part p: the action catalog (catalog/actions) loads once, with the stored maps, through the one guarded import (lib/action-gate.mjs),
  // and its statuses are written before either recovery reads them. One that will not load leaves every action unsupported and every stored
  // active action record a candidate, and Fabric still starts. `actions` is a test seam ({directory, evidenceRoot, codeHashes, deps, importer}).
  const actions=await loadActionsSafely({...actionOptions,maps:new Map(store.list('applicationMaps').map(map=>[map.appId??map.id,map]))},actionOptions.importer?{importer:actionOptions.importer}:{});
  if(actions)actions.seed(store);else demoteActions(store);
  const catalog=()=>catalogFor(store).map(app=>({...app,connectionOptions:describeConnectionOptions(app,{googleOAuthConfigured:oauth.configured,oauthRoute})}));const browser=new BrowserBridge({store,catalog});
  const persistentBrowser=new PersistentBrowser({store,catalog,dataDir,...(sessionBrowserLaunch?{launch:sessionBrowserLaunch}:{})});
  const resolver=new ConnectorResolver({store,catalog,settings:()=>({googleOAuthConfigured:oauth.configured,oauthRoute}),...(request?{request}:{})});
  const runtime=new Runtime({store,connections,local,browser,persistentBrowser,device,slackDistribution,clock,actions,...(ownerPrincipal?{ownerPrincipal}:{}),...(certification?{certification:true}:{}),...(request?{request}:{})});runtime.recover();
  // F10.21 (lib/retention.mjs): Slack data past its 24 hours goes every minute too. Never keeps the process alive; cleared at close.
  const retention=setInterval(()=>{try{runtime.sweepRetention();}catch{}},60_000);retention.unref();
  const protocol=new FabricProtocol({store,runtime,clock,origin,appName:id=>catalog().find(app=>app.id===id)?.name||id});
  // Missing-access handoffs (designated mode only). Recovery runs after runtime recovery and never dispatches.
  const continuations=new ContinuationService({store,runtime,protocol,connections,clock,origin,oauthRoute,signInProvider:appId=>oauthProviders.get(connections.providers.providerFor(appId))||null,appName:id=>catalog().find(app=>app.id===id)?.name||id});
  protocol.continuations=continuations;protocol.oauthRoute=oauthRoute;continuations.recover();
  // F10.4: {remote, confirmSiblings} reach the sign-in adapter on every disconnect path.
  const revokeConnection=async (id,options={})=>{const c=connections.get(id);if(c?.transport==='persistent')return {connection:await persistentBrowser.revoke(id),remoteRevoked:false};if(c?.authMethod==='oauth')return (oauthProviders.get(connections.providerOf(store.get('connections',id)))||oauth).revoke(id,undefined,options);return {connection:connections.revoke(id),remoteRevoked:false};};
  const disconnectOptions=data=>{if(Object.keys(data).some(key=>!['remote','confirmSiblings'].includes(key))||['remote','confirmSiblings'].some(key=>data[key]!==undefined&&typeof data[key]!=='boolean'))throw new Error('Send remote and confirmSiblings only, each true or false.');return {remote:data.remote,confirmSiblings:data.confirmSiblings};};
  const appDetails=new AppDetailService({store,runtime,catalog,accessLevels,accessLevelOf,oauthProviderFor:appId=>oauthProviders.get(connections.providers.providerFor(appId))||null,revoke:revokeConnection});
  // T7, the callback wall: whatever an upgrade granted beyond the card the owner confirmed is saved at Ask as it lands.
  connections.setUpgradeGuard((previous,next,confirmedScopes)=>appDetails.pinUnconfirmed(previous,next,confirmedScopes));
  // T2: a version 2 sign-in refused for a missing required scope names the permissions that need it.
  connections.setAccessExplainer((appId,scopes)=>appDetails.rowsNeeding(appId,scopes));
  const CONTINUATION_STATUS={not_found:404,unsupported_route:404,tampered:409,invalid_transition:409,view_changed:409,policy_denied:409,authority_changed:409,capability_retired:409,client_revoked:409,attempts_exhausted:409,signin_unavailable:409,continuation_expired:410,clock_behind:409,review_required:409,confirm_required:409,account_ineligible:400,invalid_request:400};
  const ownerContinuation=async run=>{try{return await run();}catch(error){error.httpStatus=CONTINUATION_STATUS[error.code]??400;throw error;}};
  runtime.authorizeSource=job=>{protocol.authorizeJob(job);if(store.authorityEnabled&&job.source?.heartbeatId)heartbeats.assertJobAuthority(job);};
  const acquisition=new AcquisitionEngine({store,catalog,...modelConfig,...(request?{request}:{})});
  // F10.11 part p: a map stored for an app (/api/discover, the adapter factory) loads that app's actions again and writes their statuses.
  const discovery=new DiscoveryEngine({store,catalog,acquisition,...(request?{request}:{}),onMapStored:appId=>{if(!actions)return;actions.reload(appId,store.get('applicationMaps',appId));actions.seed(store,{appId});}});
  const factory=new AdapterFactory({store,catalog,discovery,acquisition,runtime,connections,...(request?{request}:{})});
  function healthSchedule(connectionId) {
    const checks=store.list('heartbeats').filter(h=>!h.capabilityId&&(!h.connectionId||h.connectionId===connectionId));
    const next=checks.filter(h=>h.enabled).sort((a,b)=>Date.parse(a.nextRunAt)-Date.parse(b.nextRunAt))[0];
    const latest=checks.filter(h=>h.lastRunAt).sort((a,b)=>Date.parse(b.lastRunAt)-Date.parse(a.lastRunAt))[0];
    return {enabled:Boolean(next),intervalSeconds:next?.intervalSeconds||null,nextRunAt:next?.nextRunAt||null,lastRunAt:latest?.lastRunAt||null,lastResult:latest?.lastResult?.status||null};
  }
  function connectionView(c) {
    if(!c)return c;
    const savedSession=c.driver==='browser'&&c.transport==='persistent';
    const browserEvidence=c.driver==='browser'?(savedSession?persistentBrowser.evidence(c):browser.getConnectionEvidence(c)):null;
    const lifecycle={kind:c.driver==='browser'?'browser-tab':c.authMethod==='oauth'?'oauth':c.driver==='http'?'provider-credential':'local',
      expiresAt:Number.isFinite(c.expiresAt)?new Date(c.expiresAt).toISOString():null,refreshAvailable:Boolean(c.refreshAvailable),
      renewal:c.driver==='browser'?'Sign in on the provider website when required.':c.authMethod==='oauth'?'Fabric checks for renewal before use and during scheduled health checks, starting 60 seconds before access expires.':'No automatic credential renewal is available for this route.',
      requirements:c.driver==='browser'?'Keep the paired tab, browser and local Fabric runtime open. Account session lifetime is controlled by the app.':c.driver==='http'?'Provider access must remain valid and Fabric must be running. Revocation or a rejected renewal requires reconnecting.':'The local Fabric runtime must be running. This does not grant access to unrelated files or devices.',
      lastVerifiedAt:c.driver==='browser'?null:c.lastCheckedAt||null,health:healthSchedule(c.id)};
    if(savedSession) Object.assign(lifecycle,{kind:'persistent-browser',expiresAt:null,retention:'until-disconnected',sessionState:browserEvidence?.session?.state||'dormant',
      renewal:'Saved locally until you disconnect. Fabric reopens its dedicated browser when an approved read needs it. Sign in again if the app requires it.',
      requirements:'The local Fabric runtime and computer must be available. Closing an application tab does not delete this saved session. Each read requires approval; provider account identity is not independently verified.',
      refreshAvailable:false});
    if(c.driver==='browser'&&c.sessionScope==='browser-profile'&&c.bridgeVersion==='0.3') Object.assign(lifecycle,{kind:'browser-profile',expiresAt:null,retention:'until-disconnected',sessionState:browserEvidence?.bridge?.executionState||'unknown',
      renewal:'Fabric saves your app permission until you disconnect. The website manages its own login; sign in again if it expires.',
      requirements:'Keep this Chrome or Edge profile and the local Fabric runtime running. App tabs can be closed: an approved read opens a temporary tab on demand. Actions need a fresh page inspection and exact approval. The signed-in account is not independently verified.',
      refreshAvailable:false});
    return {...c,...(browserEvidence?{browserEvidence}:{}),lifecycle};
  }
  const connectionViews=()=>connections.list().map(connectionView);
  const runtimeView=()=>({running:true,startedAt,backgroundMode:'while-runtime-running',healthCheck:healthSchedule(),browserPollSeconds:30,browserStaleAfterSeconds:90,persistentBrowserSessions:!store.authorityEnabled,durableHelperConnections:!store.authorityEnabled,unattendedBrowserActions:false,autonomousDiscovery:false,authorityMode:store.authorityEnabled?'isolated-local':'legacy'});
  function connectorDetail(appId) {
    const app=catalog().find(a=>a.id===appId);if(!app) throw new Error('Application not found.');
    const accounts=connectionViews().filter(c=>c.appId===appId);
    return {app:{...app,iconUrl:`/api/icons/${encodeURIComponent(appId)}`},plan:planConnection(app,{googleOAuthConfigured:oauth.configured,oauthRoute}),map:store.get('applicationMaps',appId),connections:accounts,permissionsByConnection:Object.fromEntries(accounts.map(c=>[c.id,runtime.permissions.list(c.id).map(decision=>withAddAccess(app,c.id,decision))]))};
  }
  // F10.7 (open question 19): a typed operation the account lacks access for carries the exact Add access body the app page computes
  // for that one member (or why there is none), so the workspace sends it unchanged to that provider's start route.
  const withAddAccess=(app,connectionId,decision)=>{if(decision.providerAccess!=='missing'||decision.locked)return decision;const connection=store.get('connections',connectionId);if(!connection)return decision;const {addAccess,addBlocked}=appDetails.addAccess(app,connection,[{decision,capability:store.get('capabilities',decision.capabilityId)}]);return {...decision,...(addAccess?{addAccess}:{}),...(addBlocked?{addBlocked}:{})};};
  const checkConnection=async id=>{const c=connections.get(id);if(!c||c.status==='revoked') throw new Error('Connection is not active.');const authority=captureConnectionAuthority(store,id);if(c.driver==='browser'){if(store.authorityEnabled)throw new Error('Browser authority provenance is not implemented in this isolated mode.');return c.transport==='persistent'?persistentBrowser.check(id):browser.check(id);}if(c.driver==='workspace'||c.driver==='device'){await(c.driver==='device'?device.init():local.init());assertConnectionAuthority(store,authority);const current=store.get('connections',id);if(!current||current.status==='revoked') throw new Error('Connection was revoked during check.');const fresh={...current,status:'ready',lastCheckedAt:new Date(clock()).toISOString()};store.put('connections',fresh);return connections.get(id);}return connections.check(id);};
  function connectWorkspace() {
    let connection=store.list('connections').find(c=>c.appId==='workspace'&&c.status==='ready');
    if(!connection){connection={id:randomUUID(),appId:'workspace',driver:'workspace',authMethod:'workspace',label:'Fabric workspace',status:'ready',identity:{id:local.root,displayName:'Dedicated local workspace'},allowedOrigins:[],createdAt:new Date(clock()).toISOString(),updatedAt:new Date(clock()).toISOString()};store.put('connections',connection);store.audit({type:'connection.connected',connectionId:connection.id,appId:'workspace'});}
    return connections.get(connection.id);
  }
  const heartbeats=new HeartbeatScheduler({store,runtime,checkConnection,clock});
  if(!store.list('heartbeats').length) heartbeats.create({name:'Connection health',intervalSeconds:60});
  const sessions=new Map();
  function session(req,res) {
    const id=cookies(req).fabric_session;const existing=sessions.get(id);
    if(existing&&existing.expires>clock()) return existing;
    for(const [key,s] of sessions) if(s.expires<clock()) sessions.delete(key);
    const sessionId=randomBytes(32).toString('hex');const next={csrf:randomBytes(32).toString('hex'),expires:clock()+12*60*60_000};sessions.set(sessionId,next);
    res.setHeader('Set-Cookie',`fabric_session=${sessionId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`);return next;
  }
  function assertBrowserOrigin(req) {if(req.headers.origin&&!/^chrome-extension:\/\/[a-p]{32}$/.test(req.headers.origin)) throw new Error('Browser extension origin required.');}
  function assertLocal(req) {if(req.headers.origin&&req.headers.origin!==origin) throw new Error('Cross-origin API access denied.');if(req.headers['sec-fetch-site']&& !['same-origin','none'].includes(req.headers['sec-fetch-site'])) throw new Error('Cross-site API access denied.');}
  async function handler(req,res) {
    res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    try {
      if(req.headers.host!==`127.0.0.1:${port}`) return json(res,403,{error:'Use the explicit 127.0.0.1 loopback address.'});
      const u=new URL(req.url,origin);const route=u.pathname;
      if(store.authorityEnabled&&BROWSER_ROUTE.test(route)) throw new Error('Browser authority provenance is not implemented in this isolated mode.');
      if(route==='/health'&&req.method==='GET') return json(res,200,{status:'ok',product:'Fabric',version:'0.3.0'});
      if(route==='/fabric/v1/manifest'&&req.method==='GET') {assertLocal(req);return json(res,200,protocolManifest);}
      if(route==='/fabric/v1') {
        assertLocal(req);
        if(req.method!=='POST') return json(res,405,{protocol:FABRIC_PROTOCOL,id:null,error:{code:'invalid_request',message:'POST required.'}});
        let envelope;try{envelope=await body(req);}catch{return json(res,400,{protocol:FABRIC_PROTOCOL,id:null,error:{code:'invalid_request',message:'A bounded JSON request envelope is required.'}});}
        const response=await protocol.handle(req.headers.authorization,envelope);
        const status=response.error?.code==='unauthorized'?401:response.error?.code==='permission_denied'?403:response.error?400:200;
        return json(res,status,response);
      }
      const oauthCallback=req.method==='GET'&&/^\/api\/oauth\/([a-z][a-z0-9-]{1,39})\/callback$/.exec(route);
      if(oauthCallback&&oauthProviders.has(oauthCallback[1])) {
        const provider=oauthProviders.get(oauthCallback[1]),flowCookie=cookies(req).fabric_oauth;
        // A browser returning from an account-request sign-in goes back to that handoff, never to a generic page.
        const flowHash=typeof flowCookie==='string'&&flowCookie.length<=256?createHash('sha256').update(flowCookie).digest('hex'):null;
        const target=store.authorityEnabled&&flowHash?continuations.byFlowIdHash(flowHash):null;
        let message,connection=null,failure=null;
        try {connection=await provider.callback({state:u.searchParams.get('state'),code:u.searchParams.get('code'),error:u.searchParams.get('error'),flowId:flowCookie},{admitContinuation:flow=>continuations.admitCallback(flow)});message='connected';}
        catch(error){failure=error;store.audit({type:'oauth.failed',code:error.code||'error'});message=error.message;}
        if(target){try{continuations.completeSignIn(target.id,flowHash,connection?{connection}:{error:failure});}catch{}}
        // A callback that never consumed this browser's flow (stale or another sign-in's state) leaves its cookie in place.
        res.writeHead(303,{'Location':target?`/continue/${target.id}`:`/?oauth=${encodeURIComponent(message)}`,...(failure?.code==='invalid_state'?{}:{'Set-Cookie':`fabric_oauth=; HttpOnly; SameSite=Lax; Path=/api/oauth/${provider.providerId}/callback; Max-Age=0`})});return res.end();
      }
      if(route.startsWith('/api/browser/')) {
        assertBrowserOrigin(req);if(req.method!=='POST') return json(res,405,{error:'POST required.'});
        const data=await body(req);const token=String(req.headers.authorization||'').replace(/^Bearer /,'');
        if(route==='/api/browser/pair') return json(res,201,browser.pair(data));
        if(route==='/api/browser/poll') return json(res,200,browser.poll(token,data));
        if(route==='/api/browser/result') return json(res,200,browser.result(token,data));
        return json(res,404,{error:'Unknown browser operation.'});
      }
      if(route.startsWith('/api/')) {
        assertLocal(req);const s=session(req,res);
        if(req.method==='GET'&&/^\/api\/icons\/[^/]+$/.test(route)) {const icon=await resolver.icon(decodeURIComponent(route.split('/')[3]));res.writeHead(200,{'Content-Type':icon.type,'Cache-Control':'private, max-age=3600'});return res.end(icon.data);}
        if(req.method==='GET'&&/^\/api\/catalog\/icons\/[^/]+$/.test(route)) {const icon=await resolver.candidateIcon(decodeURIComponent(route.split('/')[4]));res.writeHead(200,{'Content-Type':icon.type,'Cache-Control':'private, max-age=3600'});return res.end(icon.data);}
        if(req.method!=='GET'&&!secureEqual(req.headers['x-fabric-csrf'],s.csrf)) return json(res,403,{error:'Session expired or missing CSRF token. Refresh Fabric.'});
        if(route==='/api/browser-setup'&&req.method==='GET') return json(res,200,await setup.status());
        if(route==='/api/session-browser'&&req.method==='GET') return json(res,200,await persistentBrowser.availability());
        if(route==='/api/state'&&req.method==='GET') return json(res,200,{catalog:catalog(),connections:connectionViews(),runtime:runtimeView(),capabilities:store.list('capabilities'),applicationMaps:store.list('applicationMaps'),jobs:store.list('jobs').slice(-100).reverse(),activity:store.list('activity').slice(-100).reverse(),heartbeats:store.list('heartbeats'),capabilityStats:store.list('capabilityStats'),pendingHandoffs:continuations.pendingCount(),settings:{modelConfigured:acquisition.configured,modelName:acquisition.modelName||null,googleOAuthConfigured:oauth.configured,googleOAuth:oauth.configuration(),oauthProviders:Object.fromEntries([...oauthProviders].map(([id,provider])=>[id,{name:provider.name,...provider.availability(),redirectUri:provider.redirectUri,authorizationOrigin:new URL(provider.definition.authorization.url).origin,apps:provider.appIds,consentMode:provider.consentMode}])),persistentBrowser:await persistentBrowser.availability(),browserExtension:{directory:(await setup.status()).directory,browsers:['Chrome','Edge']}},csrfToken:s.csrf,workspaceRoot:local.root});
        if(route==='/api/status'&&req.method==='GET') return json(res,200,{product:'Fabric',pendingHandoffs:continuations.pendingCount(),runtime:runtimeView(),connections:connectionViews().map(({id,appId,driver,status,transport,persistentSession,bridgeVersion,sessionScope,browserEvidence,lifecycle})=>({id,appId,driver,status,...(transport?{transport,persistentSession}:{}),...(bridgeVersion?{bridgeVersion}:{}),...(sessionScope?{sessionScope}:{}),...(browserEvidence?{browserEvidence}:{}),lifecycle})),discovery:{autonomous:false,applications:store.list('applicationMaps').map(m=>({appId:m.appId,discoveredAt:m.discoveredAt,counts:m.counts})),capabilityCount:store.list('capabilities').length},execution:{pendingApprovals:store.list('jobs').filter(j=>j.status==='awaiting_approval').length,jobCount:store.list('jobs').length},agent:{transport:'fabric/0.1',alwaysOnAgent:false,activeClients:protocol.listClients().filter(c=>c.status==='active'&&Date.parse(c.expiresAt)>clock()).length}});
        if(req.method==='GET'&&/^\/api\/pair\/[^/]+\/status$/.test(route)) return json(res,200,browser.status(decodeURIComponent(route.split('/')[3])));
        if(req.method==='GET'&&route==='/api/catalog/search') return json(res,200,{apps:resolver.search(u.searchParams.get('q')||'')});
        if(req.method==='GET'&&route==='/api/clients') return json(res,200,{clients:protocol.listClients(),protocol:protocolManifest});
        if(req.method==='GET'&&route==='/api/ui/catalog'){const q=u.searchParams;return json(res,200,await ownerContinuation(()=>catalogPage({apps:catalog(),connections:connectionViews(),party:'owner',status:q.get('status')||'all',q:q.get('q')||'',categoryId:q.get('category')||undefined,cursor:q.get('cursor')||undefined,limit:q.get('limit')||undefined,accessLevels})));}
        const appRoute=/^\/api\/ui\/apps\/([a-z0-9][a-z0-9-]{0,63})$/.exec(route),accountRoute=/^\/api\/ui\/apps\/([a-z0-9][a-z0-9-]{0,63})\/accounts\/([^/]{1,256})\/(permissions|reset|background|disconnect)$/.exec(route);
        const approvalRoute=/^\/api\/ui\/approvals\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.exec(route);
        if(req.method==='GET'&&(route==='/api/ui/activity'||approvalRoute)){const shown=id=>{const c=id&&store.get('connections',id);return c?(c.identity?.workspaceName||c.identity?.email||c.identity?.displayName||c.label||null):null;};
          const names={appName:id=>catalog().find(app=>app.id===id)?.name||id||null,capabilityName:id=>store.get('capabilities',id)?.name||null,accountName:shown,clientName:id=>id?store.get('clientGrants',id)?.name||null:null,now:clock(),
            // F10.11 part j: an action job's card shows its prepared bytes, read here; without them it offers no Approve.
            prepared:id=>store.get('actionPrepared',id)};
          if(approvalRoute){const job=store.get('jobs',approvalRoute[1]);if(!job) return json(res,404,{error:'This approval is not in this Fabric.',code:'not_found'});return json(res,200,approvalPage(job,names));}
          return json(res,200,await ownerContinuation(()=>activityPage({jobs:store.list('jobs'),continuations:store.authorityEnabled?store.list('continuations'):[],...names,cursor:u.searchParams.get('cursor')||undefined})));}
        if(req.method==='GET'&&appRoute) return json(res,200,await ownerContinuation(()=>appDetails.view(appRoute[1],u.searchParams.get('account')||undefined)));
        if(req.method==='GET'&&route==='/api/continuations') return json(res,200,{continuations:await ownerContinuation(()=>continuations.ownerList())});
        if(req.method==='GET'&&/^\/api\/continuations\/[^/]+$/.test(route)) return json(res,200,await ownerContinuation(()=>continuations.ownerView(decodeURIComponent(route.split('/')[3]))));
        if(req.method==='GET'&&route==='/api/factory/builds') return json(res,200,{builds:factory.list({...(u.searchParams.has('appId')?{appId:u.searchParams.get('appId')}:{})})});
        if(req.method==='GET'&&/^\/api\/connectors\/[^/]+(?:\/(tools|history))?$/.test(route)) {
          const appId=decodeURIComponent(route.split('/')[3]),detail=connectorDetail(appId);
          if(route.endsWith('/history')) return json(res,200,{appId,history:store.list('applicationMapHistory').filter(m=>m.appId===appId).slice(-20).reverse()});
          if(route.endsWith('/tools')) {
            const connectionId=u.searchParams.get('connectionId');
            if(connectionId&&!detail.connections.some(c=>c.id===connectionId)) throw new Error('Connection does not belong to this application.');
            const decisions=connectionId?detail.permissionsByConnection[connectionId]:[];
            // F10.11 part l: actions first, each with its own record's output schema, which its checked output always meets.
            const listed=store.list('capabilities').filter(c=>c.appId===appId),ordered=[...listed.filter(c=>c.driver==='action'),...listed.filter(c=>c.driver!=='action')];
            return json(res,200,{specVersion:'fabric-tools/0.1',appId,connectionId:connectionId||null,source:detail.map?{url:detail.map.sourceUrl,fingerprint:detail.map.fingerprint,discoveredAt:detail.map.discoveredAt}:null,coverage:detail.map?.counts||null,tools:ordered.map(cap=>{const op=detail.map?.operations.find(o=>o.capabilityId===cap.id),removed=detail.map?.historicalCapabilityIds?.includes(cap.id)&&!op,action=cap.driver==='action';return {id:cap.id,name:cap.name,description:cap.description,driver:cap.driver,inputSchema:cap.inputSchema,outputSchema:action?cap.outputSchema:op?.responseSchema||null,outputSchemaValidated:action,status:removed?'removed':cap.status,definitionStatus:cap.status,providerRequirements:{scopeSets:op?.scopeSets||null,requiredScopes:op?.requiredScopes||[],resource:op?.resource||null},limitations:op?.gaps||[],permission:decisions.find(p=>p.capabilityId===cap.id)||null,invoke:{method:'POST',path:'/api/jobs',body:{connectionId:connectionId||'<choose-account>',capabilityId:cap.id,args:'<validated-input>'}},evidence:store.get('capabilityStats',cap.id)||null};}),gaps:detail.map?.operations.filter(o=>!o.capabilityId)||[],notice:'Discovered tools are not account grants or proof of execution. Invocation uses the same approval and permission checks as the UI.'});
          }
          return json(res,200,detail);
        }
        if(req.method==='GET'&&/^\/api\/capabilities\/[^/]+\/export$/.test(route)){const cap=store.get('capabilities',decodeURIComponent(route.split('/')[3]));if(!cap) return json(res,404,{error:'Capability not found.'});return json(res,200,cap,{'Content-Disposition':`attachment; filename="${cap.id}.json"`});}
        if(req.method!=='POST') return json(res,405,{error:'Unsupported method.'});
        const data=await body(req);
        if(route==='/api/session-browser/connect') {
          if(Object.keys(data).some(key=>!['appId','consent'].includes(key))||data.consent!==true)throw new Error('Explicit consent to a saved local browser session is required.');
          const connection=await persistentBrowser.connect(data);
          return json(res,201,{connection:connectionView(connections.get(connection.id))});
        }
        if(/^\/api\/session-browser\/[^/]+\/open$/.test(route)) {
          if(Object.keys(data).length)throw new Error('Session recovery accepts no new destinations or credentials.');
          const connection=await persistentBrowser.open(decodeURIComponent(route.split('/')[3]));
          return json(res,200,{connection:connectionView(connections.get(connection.id))});
        }
        if(route==='/api/browser-setup') {
          if(Object.keys(data).some(key=>!['action','browser','appId'].includes(key))) throw new Error('Only the selected browser, application, and setup action are accepted.');
          const app=catalog().find(item=>item.id===data.appId);
          if(!app||(app.webOrigins||app.browserOrigins||[]).length===0) throw new Error('Select an application with a browser connection first.');
          return json(res,200,await setup.perform({action:data.action,browser:data.browser,appId:app.id}));
        }
        if(accountRoute){const [,appId,raw,verb]=accountRoute,account=decodeURIComponent(raw);
          return json(res,200,await ownerContinuation(()=>verb==='permissions'?appDetails.setRow(appId,account,data):verb==='reset'?appDetails.reset(appId,account,data):verb==='background'?appDetails.setBackground(appId,account,data):appDetails.disconnect(appId,account,data)));}
        if(route==='/api/clients'){try{return json(res,201,protocol.createClient(data,ownerPrincipal));}catch(error){if(error.code==='unsupported_route')error.httpStatus=404;throw error;}}
        const handoffAction=/^\/api\/continuations\/([^/]+)\/(select|decline|sign-in|confirm|reject-account)$/.exec(route);
        if(handoffAction){
          const id=decodeURIComponent(handoffAction[1]),verb=handoffAction[2];
          if(verb==='sign-in'){
            const started=await ownerContinuation(()=>continuations.signIn(id,data,ownerPrincipal));
            const maxAge=Math.max(1,Math.ceil((Date.parse(started.expiresAt)-clock())/1000));
            res.setHeader('Set-Cookie',`fabric_oauth=${started.flowId}; HttpOnly; SameSite=Lax; Path=/api/oauth/${started.providerId}/callback; Max-Age=${maxAge}`);
            return json(res,200,{authorizationUrl:started.authorizationUrl,expiresAt:started.expiresAt});
          }
          const run={select:()=>continuations.select(id,data,ownerPrincipal),decline:()=>continuations.decline(id,data,ownerPrincipal),confirm:()=>continuations.confirm(id,data,ownerPrincipal),'reject-account':()=>continuations.rejectAccount(id,data,ownerPrincipal)}[verb];
          return json(res,200,await ownerContinuation(run));
        }
        if(/^\/api\/clients\/[^/]+\/revoke$/.test(route)) return json(res,200,protocol.revokeClient(decodeURIComponent(route.split('/')[3])));
        if(route==='/api/catalog/lookup') return json(res,200,await resolver.lookup(data.query));
        if(route==='/api/catalog/select') return json(res,200,await resolver.select(data.candidateId));
        if(route==='/api/factory/build') return json(res,200,await factory.build(data));
        if(route==='/api/factory/record-execution') return json(res,200,factory.recordExecution(data));
        if(route==='/api/resolve') return json(res,200,await resolver.resolve(data.query));
        if(route==='/api/connect/start') {
          const app=catalog().find(item=>item.id===data.appId);if(!app) throw new Error('Select an application first.');
          const plan=planConnection(app,{googleOAuthConfigured:oauth.configured,oauthRoute}),explicitMethod=Object.hasOwn(data,'method'),method=explicitMethod?data.method:plan.recommended;
          const selected=typeof method==='string'&&['device','workspace','oauth','browser'].includes(method)?plan.routes.find(item=>item.method===method&&item.available):null;
          if(!selected) {
            const offered=typeof method==='string'?plan.routes.find(item=>item.method===method):null;
            const message=offered?`${offered.label} is not available on this Fabric installation. ${(offered.requires||[]).join('. ')}. No connection was established.`:explicitMethod?'The requested connection method is not supported for this application. No different method was started and no connection was established.':`Fabric identified ${app.name}, but this installation has no supported account or browser connection for it yet. Published action descriptions do not grant access. No connection was established.`;
            return json(res,200,{kind:'unsupported',code:'connection_route_unavailable',app:{id:app.id,name:app.name},message,plan,connectionEstablished:false});
          }
          if(method==='device') {
            let connection=store.list('connections').find(item=>item.appId==='local-device'&&item.status==='ready');
            if(!connection){connection=await device.connect();store.put('connections',connection);store.audit({type:'connection.connected',connectionId:connection.id,appId:app.id});}
            return json(res,200,{kind:'connected',connection:connections.get(connection.id)});
          }
          if(method==='workspace') return json(res,200,{kind:'connected',connection:connectWorkspace()});
          if(method==='oauth') {const signIn=oauthRoute(app.id);if(!signIn)throw new Error('This application has no reviewed sign-in route.');const flow=oauthStart(res,oauthProviders.get(signIn.providerId),{appId:app.id,level:'full'});return json(res,200,{kind:'oauth',authorizationUrl:flow.authorizationUrl,expiresAt:flow.expiresAt});}
          if(store.authorityEnabled)throw new Error('Browser authority provenance is not implemented in this isolated mode.');
          const origins=app.webOrigins||app.browserOrigins||[];
          if(data.origin&&!origins.includes(data.origin)) throw new Error('The requested website is not part of this application.');
          const pairing=browser.createPair(app.id);
          return json(res,200,{kind:'browser',app:{id:app.id,name:app.name},origin:data.origin||origins[0],pairing:{...pairing,launchUrl:data.origin||pairing.launchUrl||origins[0]}});
        }
        if(route==='/api/applications') {
          if(!/^[a-z][a-z0-9-]{1,63}$/.test(data.id)||catalog().some(a=>a.id===data.id)) throw new Error('Choose a unique lowercase application ID.');
          if(typeof data.name!=='string'||!data.name.trim()||data.name.length>100) throw new Error('Application name required (up to 100 characters).');
          const apiOrigins=(data.apiOrigins||[]).map(publicOrigin),webOrigins=(data.webOrigins||[]).map(publicOrigin);
          if(!apiOrigins.length&&!webOrigins.length) throw new Error('Declare at least one API or browser origin.');if(apiOrigins.length>5||webOrigins.length>5) throw new Error('At most five origins per route.');
          if(data.identityProbe&&(!apiOrigins.length||typeof data.identityProbe.path!=='string'||!data.identityProbe.path.startsWith('/')||data.identityProbe.path.startsWith('//')||typeof data.identityProbe.idPointer!=='string'||!data.identityProbe.idPointer.startsWith('/'))) throw new Error('Identity probe needs a relative path and an idPointer.');
          let discoverySource;
          if(data.discovery){const source=new URL(data.discovery.url);if(!['openapi','google-discovery'].includes(data.discovery.kind)||source.protocol!=='https:'||source.username||source.password||source.hash||source.port&&source.port!=='443') throw new Error('Discovery requires a declared public HTTPS OpenAPI or Google Discovery JSON source.');publicOrigin(source.origin);discoverySource={kind:data.discovery.kind,url:source.href};}
          const app={id:data.id,name:data.name.trim(),description:String(data.description||'').slice(0,1000),category:String(data.category||'Custom').slice(0,40),apiOrigins,webOrigins,...(discoverySource?{discovery:discoverySource}:{}),...(data.identityProbe?{identityProbe:{path:data.identityProbe.path,idPointer:data.identityProbe.idPointer,displayNamePointer:data.identityProbe.displayNamePointer||data.identityProbe.idPointer}}:{})};
          store.put('applications',app);store.audit({type:'application.added',appId:app.id});return json(res,201,app);
        }
        if(route==='/api/connections/local') {
          return json(res,201,connectWorkspace());
        }
        if(route==='/api/connections') return json(res,201,await connections.connect(data));
        if(/^\/api\/connections\/[^/]+\/permissions$/.test(route)) {
          const connectionId=decodeURIComponent(route.split('/')[3]),connection=connections.get(connectionId),cap=store.get('capabilities',data.capabilityId);
          // F10.11 (part d): an action is set only through its permission row, so this route neither records nor promotes one.
          if(cap?.driver==='action') throw new Error('Set this action with its permission row.');
          if(!['allow','ask','deny'].includes(data.mode)) throw new Error('Choose Allow, Ask or Deny.');
          if(!connection||!['ready','session_ready'].includes(connection.status)||!cap||cap.appId!==connection.appId||cap.driver!==connection.driver||!matchingBrowserTransport(connection,cap)) throw new Error('Choose an active account and an operation for that connection route.');
          if(cap.status==='candidate'&&data.mode!=='deny'&&data.review!==true) throw new Error('Review this generated operation before allowing it or enabling approval requests.');
          // Never is always allowed; Allow and Ask need a capability the current compiler rules accept.
          if(cap.driver==='http'&&data.mode!=='deny') validateCapability(cap);
          runtime.permissions.set({connectionId,capabilityId:cap.id,mode:data.mode});
          if(cap.status==='candidate'&&data.mode!=='deny'){cap.status='active';store.put('capabilities',cap);store.audit({type:'capability.promoted',capabilityId:cap.id,definitionHash:canonicalHash(cap)});}
          return json(res,200,runtime.permissions.list(connectionId).find(p=>p.capabilityId===cap.id));
        }
        if(/^\/api\/connections\/[^/]+\/check$/.test(route)) return json(res,200,connectionView(await checkConnection(route.split('/')[3])));
        if(/^\/api\/connections\/[^/]+\/revoke$/.test(route)) {const id=route.split('/')[3],c=connections.get(id),options=disconnectOptions(data);if(c?.transport==='persistent')return json(res,200,connectionView(await persistentBrowser.revoke(id)));return json(res,200,c?.authMethod==='oauth'?await ownerContinuation(()=>(oauthProviders.get(connections.providerOf(store.get('connections',id)))||oauth).revoke(id,undefined,options)):connections.revoke(id));}
        const oauthStartRoute=/^\/api\/oauth\/([a-z][a-z0-9-]{1,39})\/start$/.exec(route);
        if(oauthStartRoute){const provider=oauthProviders.get(oauthStartRoute[1]);if(!provider)throw new Error('Unknown sign-in provider.');
          // Account-request binding is trusted in-process input; the public start route accepts only these fields.
          // F10.7 (correction 2): fullUpgrade is the owner's explicit full upgrade, which plan() checks names an account and the full level.
          if(Object.keys(data).some(key=>!['connectionId','label','writeAccess','level','appId','scopes','fullUpgrade','confirmRows'].includes(key)))throw new Error('Only the account, label, access level, application, scopes, full upgrade and confirmed rows are accepted.');
          // T7: a sign-in that widens what the owner approved for an account (a full upgrade or Add access) starts only with the
          // card's etag when the card lists rows that would run at Allow afterwards. The flow carries what was confirmed.
          const {confirmRows,...input}=data,upgrade=input.connectionId?appDetails.upgradeFor(provider,input):null;
          if(upgrade?.rows.length&&confirmRows!==upgrade.etag)throw Object.assign(new Error(`After this sign-in, agents could do these without asking: ${upgrade.rows.map(row=>row.label).join(', ').slice(0,300)}. Confirm to continue.`),{code:'confirm_required',httpStatus:409,upgrade:{rows:upgrade.rows,etag:upgrade.etag}});
          const flow=oauthStart(res,provider,input,upgrade?{upgrade:{etag:upgrade.etag,scopes:upgrade.scopes}}:{});return json(res,200,{authorizationUrl:flow.authorizationUrl,expiresAt:flow.expiresAt});}
        if(route==='/api/pair') return json(res,201,browser.createPair(data.appId));
        if(route==='/api/discover') return json(res,200,await discovery.discover(data));
        if(route==='/api/import') return json(res,201,acquisition.import(data));
        if(route==='/api/acquire') return json(res,201,await acquisition.acquire(data));
        if(route==='/api/bundles') return json(res,201,{capabilities:acquisition.saveCandidates(data.bundle?.appId,[data.bundle])});
        if(/^\/api\/capabilities\/[^/]+\/promote$/.test(route)) {const cap=store.get('capabilities',decodeURIComponent(route.split('/')[3]));if(!cap) throw new Error('Capability not found.');if(cap.driver==='action') throw new Error('Actions become active only from a reviewed file with live evidence.');if(cap.driver==='http') validateCapability(cap);cap.status='active';store.put('capabilities',cap);store.audit({type:'capability.promoted',capabilityId:cap.id,definitionHash:canonicalHash(cap)});return json(res,200,cap);}
        if(route==='/api/jobs') {
          if(Object.keys(data).some(key=>!['connectionId','capabilityId','args'].includes(key)))throw new Error('Job inputs cannot select a caller, source, scope or approval.');
          return json(res,201,await runtime.createJob(data,ownerPrincipal));
        }
        if(/^\/api\/jobs\/[^/]+\/approve$/.test(route)) {
          if(Object.keys(data).some(key=>key!=='approvalDigest'))throw new Error('Approval accepts only the displayed exact-action digest.');
          return json(res,200,await runtime.approve(route.split('/')[3],data.approvalDigest,ownerPrincipal));
        }
        if(/^\/api\/jobs\/[^/]+\/cancel$/.test(route)) return json(res,200,runtime.cancel(route.split('/')[3]));
        if(route==='/api/heartbeats') return json(res,201,heartbeats.create(data,ownerPrincipal));
        if(/^\/api\/heartbeats\/[^/]+\/(pause|resume)$/.test(route)) return json(res,200,heartbeats.setEnabled(route.split('/')[3],route.endsWith('/resume')));
        return json(res,404,{error:'Unknown API operation.'});
      }
      if(req.method!=='GET') return json(res,405,{error:'GET required.'});
      // The handoff link only opens the owner's page; it carries no data and grants nothing.
      if(req.method==='GET'&&/^\/continue\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(route)){if(!store.authorityEnabled) return json(res,404,{error:'Missing-access handoffs require a designated authority store.',code:'unsupported_route'});const content=await readFile(path.join(ROOT,'public/continue.html'));res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(content);}
      if(req.method==='GET'&&/^\/approve\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(route)){const content=await readFile(path.join(ROOT,'public/hosted-approve.html'));res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(content);}
      if(req.method==='GET'&&route==='/activity'){const content=await readFile(path.join(ROOT,'public/hosted-activity.html'));res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(content);}
      if(req.method==='GET'&&/^\/connectors\/[a-z0-9][a-z0-9-]{0,63}$/.test(route)){const content=await readFile(path.join(ROOT,'public/hosted-app.html'));res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(content);}
      if(req.method==='GET'&&(route==='/connectors'||route==='/connectors/')){const content=await readFile(path.join(ROOT,'public/hosted-catalog.html'));res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(content);}
      const files={'/':'public/index.html','/app.js':'public/app.js','/connect-client.js':'public/connect-client.js','/styles.css':'public/styles.css','/connectors.css':'public/connectors.css','/continue.js':'public/continue.js','/hosted-catalog.js':'public/hosted-catalog.js','/hosted.css':'public/hosted.css','/hosted-app.js':'public/hosted-app.js','/hosted-activity.js':'public/hosted-activity.js','/hosted-approve.js':'public/hosted-approve.js','/hosted-approval.js':'public/hosted-approval.js','/sign-in-target.js':'public/sign-in-target.js','/hosted-text.js':'public/hosted-text.js','/hosted-base.js':'public/hosted-base.js','/examples/google-calendar.openapi.json':'examples/google-calendar.openapi.json','/examples/github.openapi.json':'examples/github.openapi.json','/capability.schema.json':'schemas/capability.schema.json'};
      if(!files[route]) return json(res,404,{error:'Not found.'});
      const content=await readFile(path.join(ROOT,files[route]));res.writeHead(200,{'Content-Type':route.endsWith('.js')?'text/javascript; charset=utf-8':route.endsWith('.css')?'text/css; charset=utf-8':route.endsWith('.json')?'application/json':'text/html; charset=utf-8'});res.end(content);
    }catch(error){if(!res.headersSent) json(res,error.httpStatus??(error.code==='browser_revoked'?401:error.code==='ENOENT'?404:400),{...(error.view?{view:error.view}:{}),...(error.upgrade?{upgrade:{rows:error.upgrade.rows,etag:error.upgrade.etag}}:{}),...(Array.isArray(error.siblings)?{siblings:error.siblings.map(item=>({connectionId:item.connectionId,appId:item.appId,displayName:item.displayName,waiting:item.waiting===true}))}:{}),...(Array.isArray(error.affected)?{affected:error.affected.map(item=>({connectionId:item.connectionId,appId:item.appId}))}:{}),error:String(error.message||'Request failed.').slice(0,800),code:error.code||'invalid_request'});else res.end();}
  }
  const server=http.createServer(handler);server.requestTimeout=60000;server.headersTimeout=15000;
  return {server,store,vault,connections,oauth,local,device,resolver,runtime,browser,persistentBrowser,heartbeats,acquisition,discovery,factory,protocol,continuations,actions,origin,start:()=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',()=>{heartbeats.start();resolve();});}),close:async()=>{clearInterval(retention);heartbeats.stop();browser.close();await persistentBrowser.shutdown();await new Promise(resolve=>server.close(resolve));await continuations.drain();store.close();}};
}

/** The data folder's lock (runtime.lock): one Fabric per folder. A lock whose process is gone is taken over. Returns its release.
 *  F10.12: exported, so the live-test harness takes the same lock as the main block. */
export async function lockDataDir(dataDir) {
  await mkdir(dataDir,{recursive:true,mode:0o700});const lockPath=path.join(dataDir,'runtime.lock');
  try {const lock=await open(lockPath,'wx',0o600);await lock.writeFile(String(process.pid));await lock.close();}catch(error){if(error.code!=='EEXIST') throw error;const pid=Number(await readFile(lockPath,'utf8'));let live=false;if(Number.isSafeInteger(pid)&&pid>0){try{process.kill(pid,0);live=true;}catch(e){if(e.code==='EPERM') live=true;}}if(live) throw new Error(`Fabric is already running (PID ${pid}).`);await unlink(lockPath);const lock=await open(lockPath,'wx',0o600);await lock.writeFile(String(process.pid));await lock.close();}
  return ()=>unlink(lockPath).catch(()=>{});
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const dataDir=process.env.FABRIC_DATA_DIR||path.join(ROOT,'.fabric');const stop=error=>{console.error(`Error: ${error.message}`);process.exit(1);};const release=await lockDataDir(dataDir).catch(stop);
  let app;try{app=await createApp({dataDir});await app.start();console.log(`Fabric 0.3 running at ${app.origin}\nLocal data: ${dataDir}`);}catch(error){await release();stop(error);}
  let closing=false;for(const signal of ['SIGINT','SIGTERM']) process.on(signal,async()=>{if(closing)return;closing=true;await app.close();await release();process.exit(0);});
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Store } from '../lib/store.mjs';
import { Vault } from '../lib/vault.mjs';
import { ConnectionManager } from '../lib/connections.mjs';
import { OAuth2Provider } from '../lib/providers/oauth2.mjs';
import { v1Definition } from './fixtures/auth-v1/urls.mjs';

// F10.7: adapter cases on the version 1 Google definition (T6 through the fixtures); the shipped catalog is version 2.
const V1GoogleProvider = class extends OAuth2Provider { constructor(options) { super(v1Definition('google'), options); } };

const scope = 'openid email https://www.googleapis.com/auth/calendar.calendarlist.readonly https://www.googleapis.com/auth/calendar.events.readonly';
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(),'fabric-oauth-')),store = new Store({dataDir:dir}),vault = new Vault(dir);
  const state = {now:Date.now(),account:'google-1',requests:[],refreshCount:0,tokenError:false,remoteRevoke:200,scope};
  const request = async req => {
    state.requests.push(req);
    if (req.url.endsWith('/token')) {
      const body = new URLSearchParams(req.body), refreshing = body.get('grant_type') === 'refresh_token';
      if (refreshing) state.refreshCount++;
      if (state.tokenError) return {status:400,data:{error:'invalid_grant',error_description:'access-secret refresh-secret client-secret'}};
      return {status:200,data:{access_token:refreshing ? 'fresh-access-secret' : 'access-secret',refresh_token:refreshing ? undefined : 'refresh-secret',token_type:'Bearer',expires_in:3600,scope:state.scope}};
    }
    if (req.url.endsWith('/userinfo')) return {status:200,data:{sub:state.account,email:'fixture@example.com'}};
    if (req.url.includes('/calendar/v3/')) return {status:200,data:{kind:'calendar#calendarList'}};
    if (req.url.includes('/gmail/v1/users/me/profile')) return {status:200,data:{emailAddress:'fixture@example.com'}};
    if (req.url.endsWith('/revoke')) return {status:state.remoteRevoke,data:null};
    throw new Error('Unexpected fixture URL');
  };
  const connections = new ConnectionManager({store,vault,request});
  const oauth = new V1GoogleProvider({store,vault,connections,request,clientId:'fixture-client',clientSecret:'client-secret',clock:() => state.now});
  connections.setOAuthProvider(oauth);
  t.after(() => {store.close();rmSync(dir,{recursive:true,force:true});});
  const connect = async options => { const flow = oauth.start(options); return {flow,connection:await oauth.callback({state:new URL(flow.authorizationUrl).searchParams.get('state'),code:'fixture-code',flowId:flow.flowId})}; };
  return {store,vault,state,connections,oauth,connect,request};
}
test('OAuth requires operator configuration and produces read-only PKCE bound to browser',async t => {
  const {oauth,store,vault,connections,request} = fixture(t);
  const missing = new V1GoogleProvider({store,vault,connections,request,clientId:'',clientSecret:''});
  assert.equal(missing.configured,false); assert.throws(() => missing.start(),/not configured/);
  const flow = oauth.start(),url = new URL(flow.authorizationUrl);
  assert.equal(url.origin,'https://accounts.google.com'); assert.equal(url.searchParams.get('code_challenge_method'),'S256');
  assert.equal(url.searchParams.get('scope'),scope); assert.equal(url.searchParams.get('access_type'),'offline');
  assert.equal(url.searchParams.has('client_secret'),false);
  const id = createHash('sha256').update(url.searchParams.get('state')).digest('hex');
  const verifier = vault.get(`oauth:${id}`).verifier;
  assert.equal(createHash('sha256').update(verifier).digest('base64url'),url.searchParams.get('code_challenge'));
  assert.equal(JSON.stringify(store.list('oauthFlows')).includes(verifier),false);
});
test('state mismatch, browser mismatch, expiry and replay cannot create connections',async t => {
  const {oauth,state,connections} = fixture(t);
  const flow = oauth.start(),params = {state:new URL(flow.authorizationUrl).searchParams.get('state'),code:'fixture-code',flowId:flow.flowId};
  await assert.rejects(oauth.callback({...params,state:'wrong'}),/state/);
  await assert.rejects(oauth.callback({...params,flowId:'wrong'}),/browser/);
  const connection = await oauth.callback(params); assert.equal(connection.status,'ready');
  await assert.rejects(oauth.callback(params),/already used/);
  const expired = oauth.start(); state.now += 11*60*1000;
  await assert.rejects(oauth.callback({...params,state:new URL(expired.authorizationUrl).searchParams.get('state'),flowId:expired.flowId}),/expired/);
  assert.equal(connections.list().length,1);
});
test('cancelled consent consumes state without making provider requests',async t => {
  const {oauth,state} = fixture(t); const flow = oauth.start();
  const params = {state:new URL(flow.authorizationUrl).searchParams.get('state'),flowId:flow.flowId,error:'access_denied'};
  await assert.rejects(oauth.callback(params),/declined/); assert.equal(state.requests.length,0);
  await assert.rejects(oauth.callback(params),/already used/);
});
test('Google tokens are encrypted, renewed once concurrently, and old account binding persists',async t => {
  const {connect,connections,state,store,vault} = fixture(t);
  const {connection} = await connect();
  assert.equal(connection.refreshAvailable,true); assert.equal(connection.identity.id,'google-1');
  assert.equal(JSON.stringify(connections.list()).includes('access-secret'),false);
  assert.equal(JSON.stringify(store.list('activity')).includes('refresh-secret'),false);
  state.now += 3600*1000;
  const [a,b] = await Promise.all([connections.credentials(connection.id),connections.credentials(connection.id)]);
  assert.equal(a.headers.Authorization,'Bearer fresh-access-secret'); assert.deepEqual(a,b); assert.equal(state.refreshCount,1);
  assert.equal(vault.get(connection.id).refreshToken,'refresh-secret');
  state.now += 3600*1000; state.account = 'different-account';
  await assert.rejects(connections.credentials(connection.id),/identity changed/);
  assert.equal(connections.get(connection.id).identity.id,'google-1'); assert.equal(connections.get(connection.id).status,'reconnect_required');
});
test('reconnect rejects another Google account without changing original credentials',async t => {
  const {connect,state,vault,connections} = fixture(t); const {connection} = await connect();
  state.account = 'different-account';
  await assert.rejects(connect({connectionId:connection.id}),/Account mismatch/);
  assert.equal(connections.get(connection.id).identity.id,'google-1'); assert.equal(vault.get(connection.id).accessToken,'access-secret');
});
test('revoked refresh grant becomes reconnect-required with sanitized failure',async t => {
  const {connect,state,connections,store} = fixture(t); const {connection} = await connect();
  state.now += 3600*1000; state.tokenError = true;
  await assert.rejects(connections.credentials(connection.id),/expired or was revoked/);
  assert.equal(connections.get(connection.id).status,'reconnect_required');
  assert.equal(JSON.stringify(store.list('connections')).includes('refresh-secret'),false);
});
test('remote revoke failure still removes local tokens and reports uncertainty honestly',async t => {
  const {connect,state,connections,oauth,vault} = fixture(t); const {connection} = await connect(); state.remoteRevoke = 503;
  const result = await oauth.revoke(connection.id);
  assert.equal(result.remoteRevoked,false); assert.equal(result.connection.status,'revoked'); assert.equal(vault.get(connection.id),null);
  await assert.rejects(connections.credentials(connection.id),/active API connection/);
});
test('revocation during a refresh cannot resurrect a connection',async t => {
  const {connect,state,connections,oauth,vault,request} = fixture(t); const {connection} = await connect(); state.now += 3600*1000;
  oauth.request = async req => { if (req.url.endsWith('/token')) connections.revoke(connection.id); return request(req); };
  await assert.rejects(oauth.refresh(connection.id),/disconnected/);
  assert.equal(connections.get(connection.id).status,'revoked'); assert.equal(vault.get(connection.id),null);
});
test('pending reconnect consent cannot reactivate a subsequently disconnected account',async t => {
  const {connect,oauth,connections} = fixture(t); const {connection} = await connect();
  const flow = oauth.start({connectionId:connection.id});
  connections.revoke(connection.id);
  await assert.rejects(oauth.callback({state:new URL(flow.authorizationUrl).searchParams.get('state'),code:'fixture-code',flowId:flow.flowId}),/changed while/);
  assert.equal(connections.get(connection.id).status,'revoked');
});
for(const lateStatus of [200,400]) test(`stale OAuth renewal ${lateStatus} cannot replace or disable a newer reconnect`,async t=>{
  const {connect,state,connections,oauth,vault,store,request}=fixture(t);
  const {connection}=await connect();state.now+=3600*1000;
  let release;
  oauth.request=async req=>{
    if(req.url.endsWith('/token')&&new URLSearchParams(req.body).get('grant_type')==='refresh_token') return new Promise(resolve=>{release=resolve;});
    return request(req);
  };
  const refresh=oauth.refresh(connection.id);
  assert.equal(typeof release,'function');
  // The fixture deliberately reissues identical token strings. Revision binding, not
  // credential string comparison alone, must protect this newly reviewed consent.
  await connect({connectionId:connection.id});
  const replacement=store.get('connections',connection.id),tokens=vault.get(connection.id);
  release(lateStatus===200?{status:200,data:{access_token:'obsolete-access',refresh_token:'obsolete-refresh',token_type:'Bearer',expires_in:3600,scope}}:{status:400,data:{error:'invalid_grant'}});
  await assert.rejects(refresh,lateStatus===200?/changed during renewal/:/expired or was revoked/);
  assert.equal(connections.get(connection.id).status,'ready');
  assert.deepEqual(store.get('connections',connection.id),replacement);
  assert.deepEqual(vault.get(connection.id),tokens);
});
test('Gmail consent and renewal use Gmail identity access, never Calendar access',async t => {
  const {connect,state,connections}=fixture(t);
  state.scope='openid email https://www.googleapis.com/auth/gmail.readonly';
  const {connection,flow}=await connect({appId:'gmail'});
  assert.equal(new URL(flow.authorizationUrl).searchParams.get('scope'),state.scope);
  assert.equal(connection.appId,'gmail');assert.equal(connection.status,'ready');
  state.now+=3600*1000;await connections.credentials(connection.id);
  assert.equal(state.requests.some(r=>r.url.includes('/calendar/')),false);
  assert.equal(state.requests.filter(r=>r.url.includes('/gmail/v1/')).length,2);
});
test('permission upgrades only request scopes discovered for the selected application',async t => {
  const {oauth,store,connect,state}=fixture(t);
  const send='https://www.googleapis.com/auth/gmail.send';
  state.scope='openid email https://www.googleapis.com/auth/gmail.readonly';
  const {connection}=await connect({appId:'gmail'});
  assert.throws(()=>oauth.start({appId:'gmail',scopes:[send]}),/discovered/);
  store.put('applicationMaps',{id:'gmail',operations:[{requiredScopes:[send]}]});
  const flow=oauth.start({connectionId:connection.id,scopes:[send]});
  const requested=new URL(flow.authorizationUrl).searchParams.get('scope').split(' ');
  assert.ok(requested.includes(send));assert.ok(requested.includes('https://www.googleapis.com/auth/gmail.readonly'));
  assert.throws(()=>oauth.start({appId:'google-calendar',connectionId:connection.id}),/this application/);
  assert.throws(()=>oauth.start({appId:'gmail',scopes:['https://www.googleapis.com/auth/drive']}),/discovered/);
});
test('partially declined Gmail upgrade preserves existing account and grants',async t => {
  const {oauth,store,connect,state,connections,vault}=fixture(t);
  const send='https://www.googleapis.com/auth/gmail.send';
  state.scope='openid email https://www.googleapis.com/auth/gmail.readonly';
  const {connection}=await connect({appId:'gmail'});const previous=vault.get(connection.id);
  store.put('applicationMaps',{id:'gmail',operations:[{requiredScopes:[send]}]});
  const flow=oauth.start({connectionId:connection.id,scopes:[send]});
  await assert.rejects(oauth.callback({state:new URL(flow.authorizationUrl).searchParams.get('state'),flowId:flow.flowId,code:'fixture-code'}),/did not grant all/);
  assert.deepEqual(vault.get(connection.id),previous);
  assert.equal(connections.get(connection.id).scopes.includes(send),false);
});

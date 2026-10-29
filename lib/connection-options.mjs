// These descriptors describe implemented connection routes, never account readiness.
// They do not grant access, install an extension, or initiate provider requests.
import {accessSummary} from './app-detail.mjs';
const GOOGLE_APPS=new Set(['google-calendar','gmail']);
const methods=app=>Array.isArray(app?.authMethods)?app.authMethods:[];
function browserOrigins(app) {
  const values=app?.webOrigins??app?.browserOrigins;
  if(!Array.isArray(values)) return [];
  return [...new Set(values.filter(value=>{
    if(typeof value!=='string') return false;
    try {const url=new URL(value);return url.protocol==='https:'&&url.origin===value&&!url.username&&!url.password;} catch {return false;}
  }))];
}

// oauthRoute(appId) -> {providerId,name,configured,levels,consentMode} | null comes from the reviewed
// provider registry. Without it only the original Google route is described.
function signInRoute(appId,googleOAuthConfigured,oauthRoute) {
  if(typeof oauthRoute==='function') return oauthRoute(appId);
  return GOOGLE_APPS.has(appId)?{providerId:'google',name:'Google',configured:googleOAuthConfigured}:null;
}
// F10.7: what sign-in asks for, in the app page's words (lib/app-detail.mjs accessSummary()), from the levels the app's sign-in offers
// and its consent mode. A route that does not say (no registry) promises nothing about the level.
function accessWords({name,levels,consentMode}) {
  const words=Array.isArray(levels)?accessSummary({oauth:true,levels,consentMode,providerName:name}):null;
  return `${words?`${words} `:''}What ${name} grants and Fabric's operation settings are separate.`;
}
function providerSignIn(app,{providerId,name,configured,available=configured,reason=null,levels,consentMode}) {
  // A configured provider can still be unusable here (for example Slack requires an HTTPS callback).
  const usable=Boolean(configured&&available);
  return {
    id:`${providerId}-oauth`,method:'oauth',label:`Sign in with ${name}`,kind:'consumer',
    availability:usable?'available':configured?'unavailable':'setup_required',enabled:usable,recommended:false,
    description:`Sign in on ${name} and choose which account permissions to grant. No access token needs to be copied into Fabric.`,
    setupReason:usable?null:configured?reason:`The product operator must configure the ${name} sign-in client before this button can open consent. You do not need to create or paste an access token.`,
    action:{method:'POST',path:`/api/oauth/${providerId}/start`,body:{appId:app.id}},
    requirements:[`A configured ${name} OAuth client for this product.`,`Your ${name} account sign-in and explicit provider consent.`],
    capabilities:[`Verified ${name} account identity`,'Authorized API operations','Renewal while the provider grant remains valid'],
    limitations:[accessWords({name,levels,consentMode}),'Discovery is not account access. Generated operations require review before execution.',`${name} can expire or revoke access; this route does not promise a permanent connection.`],
    identityVerification:'provider-account',
  };
}

export function describeConnectionOptions(app,{googleOAuthConfigured=false,browserBridgeAvailable=true,oauthRoute}={}) {
  if(!app||typeof app.id!=='string') return [];
  const options=[],authMethods=methods(app),origins=browserOrigins(app),signIn=signInRoute(app.id,googleOAuthConfigured,oauthRoute);
  // Reviewed provider definitions, not catalog labels, decide whether a non-Google sign-in exists.
  if(signIn&&signIn.providerId!=='google') options.push(providerSignIn(app,signIn));
  if(signIn?.providerId==='google'&&GOOGLE_APPS.has(app.id)&&authMethods.includes('oauth')) options.push({
    id:'google-oauth',method:'oauth',label:'Sign in with Google',kind:'consumer',
    availability:signIn.configured?'available':'setup_required',enabled:Boolean(signIn.configured),recommended:false,
    description:'Sign in on Google and choose which account permissions to grant. No access token needs to be copied into Fabric.',
    setupReason:signIn.configured?null:'The product operator must configure the Google sign-in client before this button can open consent. You do not need to create or paste an access token.',
    action:{method:'POST',path:'/api/oauth/google/start',body:{appId:app.id}},
    requirements:['A configured Google OAuth client for this product.','Your Google account sign-in and explicit provider consent.'],
    capabilities:['Verified Google account identity','Authorized API operations','Refresh while the provider grant remains valid'],
    limitations:[accessWords({name:'Google',levels:signIn.levels,consentMode:signIn.consentMode}),'Discovery is not account access. Generated operations require review before execution.','Google can expire or revoke access; this route does not promise a permanent session.'],
    identityVerification:'provider-account',
  });
  if(origins.length) options.push({
    id:'browser-session',method:'browser',label:'Use in your browser',kind:'consumer',
    availability:browserBridgeAvailable?'setup_required':'unavailable',enabled:Boolean(browserBridgeAvailable),recommended:false,
    description:'Approve the Fabric helper to open and connect a browser tab. Read the page, or approve individual clicks and field entries.',
    setupReason:browserBridgeAvailable?'Load the Fabric extension in Chrome or Edge, then pair the chosen app tab. The catalog cannot determine whether the extension is installed.':'The browser bridge is unavailable in this product configuration.',
    action:{method:'POST',path:'/api/pair',body:{appId:app.id}},origins,
    requirements:['Open Fabric in Chrome or Edge with the Fabric Manifest V3 extension loaded.','Approve the helper’s request to open and connect the chosen website.','Complete any sign-in or consent in the application itself.','Keep the paired tab open and the browser awake.'],
    capabilities:['Inspect the visible paired page','Read a selected visible page element','Approve a click on an observed control','Approve entry into an observed non-sensitive field'],
    limitations:['This is browser-tab access, not an API connection or full-account integration.','Every click or fill requires exact-action approval; persistent effects are not automatically verified.','Provider account identity is not independently verified. Switching accounts in the paired tab changes what can be observed.','No cookies, passwords, or provider access tokens are imported. Fabric does not sign in for you or bypass consent.','Keep the paired browser tab active; unattended browser schedules are disabled.','The extension supports Chrome and Edge, not Safari or the in-app browser.'],
    identityVerification:'origin-and-tab-only',
  });
  if(app.id==='local-device') options.push({id:'local-device',method:'device',label:'This computer',kind:'consumer',availability:'available',enabled:true,recommended:true,description:'Connect this computer to read system information, USB inventory and installed command-line tools.',action:{method:'POST',path:'/api/connect/start',body:{appId:app.id,method:'device'}},requirements:['Your approval to connect this computer.'],capabilities:['Read system information','List USB devices','Find installed command-line tools'],limitations:['Read-only inventory. Device control and arbitrary command execution are not implemented.'],identityVerification:'local-runtime'});
  if(app.id==='workspace'&&authMethods.includes('workspace')) options.push({
    id:'workspace',method:'workspace',label:'Use local workspace',kind:'consumer',
    availability:'available',enabled:true,recommended:false,
    description:'Connect the dedicated Fabric workspace on this computer. No online account is required.',setupReason:null,
    action:{method:'POST',path:'/api/connections/local',body:{}},
    requirements:['Access to the dedicated local Fabric workspace.'],
    capabilities:['List workspace files','Read workspace files','Write workspace files with verification'],
    limitations:['This does not grant access to your entire computer.','Writes follow the same Allow, Ask, or Deny operation settings.'],
    identityVerification:'local-workspace',
  });
  if(authMethods.includes('token')) options.push({
    id:'developer-token',method:'token',label:'Developer access token',kind:'advanced',
    availability:'available',enabled:true,recommended:false,
    description:'Advanced setup for people who already manage a provider integration or access token. This is not consumer account sign-in.',setupReason:null,
    action:{method:'POST',path:'/api/connections',body:{appId:app.id}},
    requirements:['A provider-issued token with only the permissions you intend to grant.','A successful account or integration identity check before Fabric stores the token.'],
    capabilities:['Verified provider account or integration identity','API operations permitted by the supplied token'],
    limitations:['You create or obtain the token outside Fabric; this route does not implement provider sign-in.','Token scopes can be unknown locally and remain provider-enforced.','Tokens may expire or be revoked. Automatic renewal is not implemented for this route.'],
    identityVerification:'provider-account-or-integration',
  });
  const preferred=options.find(option=>option.id==='local-device'&&option.enabled)||options.find(option=>option.method==='oauth'&&option.enabled)
    ||options.find(option=>option.id==='workspace'&&option.enabled)
    ||options.find(option=>option.id==='browser-session'&&option.enabled)
    ||options.find(option=>option.method==='oauth');
  if(preferred) preferred.recommended=true;
  return options;
}

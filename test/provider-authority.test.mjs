import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';

const scopes=['openid','email','https://www.googleapis.com/auth/calendar.calendarlist.readonly','https://www.googleapis.com/auth/calendar.events.readonly'];
const tokenResponse=(extra={})=>({status:200,data:{access_token:'fixture-access',refresh_token:'fixture-refresh',token_type:'Bearer',expires_in:3600,scope:scopes.join(' '),...extra}});
const changed=error=>error.code==='connection_changed';
function deferred(){let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};}
function fixture(t) {
  const dir=mkdtempSync(join(tmpdir(),'fabric-provider-authority-'));
  const store=new Store({dataDir:dir,localAuthority:'new'}),vault=new Vault(dir);
  const state={now:Date.parse('2026-10-11T00:00:00Z'),requests:[],tokenHook:null,identityHook:null,applicationHook:null,scopes};
  const request=async req=>{
    state.requests.push(req.url);
    if(req.url.endsWith('/token')) return state.tokenHook?state.tokenHook(req):tokenResponse({scope:state.scopes.join(' ')});
    if(req.url.endsWith('/userinfo')||req.url.endsWith('/user')) return state.identityHook?state.identityHook(req):{status:200,data:req.url.endsWith('/userinfo')?{sub:'fixture-account',email:'fixture@example.test'}:{id:1,login:'fixture'}};
    if(req.url.includes('/calendar/v3/')||req.url.includes('/gmail/v1/')) return state.applicationHook?state.applicationHook(req):{status:200,data:{kind:'calendar#calendarList'}};
    if(req.url.endsWith('/revoke')) return {status:200,data:null};
    throw new Error('Unexpected synthetic request');
  };
  const connections=new ConnectionManager({store,vault,request,clock:()=>state.now});
  // F10.7: these are adapter cases on the version 1 Google definition (T6 through the fixtures); the shipped catalog is version 2.
  const oauth=new OAuth2Provider(v1Definition('google'),{store,vault,connections,request,clientId:'fixture-client',clientSecret:'fixture-client-secret',clock:()=>state.now});
  connections.setOAuthProvider(oauth);
  const params=flow=>({state:new URL(flow.authorizationUrl).searchParams.get('state'),code:'fixture-code',flowId:flow.flowId});
  const connect=async options=>oauth.callback(params(oauth.start(options)));
  const expire=()=>{state.now+=3600*1000;};
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  return {store,vault,state,connections,oauth,connect,expire,params};
}
function aba(store,id) {
  const before=store.get('connections',id);
  store.put('connections',{...before,identity:{...before.identity,id:'intermediate-account'}});
  store.put('connections',before);
  return before;
}

test('same-account same-scope fresh consent is a renewal that keeps the generation; unchanged refresh and health preserve it',async t=>{
  const {store,vault,connections,connect,expire,state}=fixture(t);
  const first=await connect(),original=vault.get(first.id);
  assert.equal(store.connectionGeneration(first.id),1);
  await connect({connectionId:first.id});assert.equal(store.connectionGeneration(first.id),1);
  assert.deepEqual(vault.get(first.id),original);
  expire();state.tokenHook=async()=>tokenResponse({scope:[...scopes].reverse().concat('openid').join(' ')});
  const values=await Promise.all([connections.credentials(first.id),connections.credentials(first.id)]);
  assert.deepEqual(values[0],values[1]);assert.equal(store.connectionGeneration(first.id),1);
  assert.equal(state.requests.filter(url=>url.endsWith('/token')).length,3);
  assert.equal((await connections.check(first.id)).status,'ready');assert.equal(store.connectionGeneration(first.id),1);
});

test('same-account same-token token reconnect is new consent while unchanged display checks are not',async t=>{
  const {store,connections}=fixture(t),first=await connections.connect({appId:'github',token:'fixture-token'});
  await connections.connect({appId:'github',token:'fixture-token',connectionId:first.id});
  assert.equal(store.connectionGeneration(first.id),2);
  await connections.check(first.id);assert.equal(store.connectionGeneration(first.id),2);
});

for(const status of [200,401]) test(`late token health ${status} cannot overwrite or return an ABA replacement`,async t=>{
  const {store,vault,connections,state}=fixture(t);
  const first=await connections.connect({appId:'github',token:'fixture-token'}),gate=deferred();
  state.identityHook=()=>gate.promise;
  const pending=connections.check(first.id),replacement=aba(store,first.id),tokens=vault.get(first.id);
  gate.resolve({status,data:status===200?{id:1,login:'obsolete'}:{error:'invalid_token'}});
  await assert.rejects(pending,changed);
  assert.deepEqual(store.get('connections',first.id),replacement);assert.deepEqual(vault.get(first.id),tokens);
});

for(const operation of ['token reconnect','OAuth establishment']) test(`late ${operation} cannot replace an ABA authorization`,async t=>{
  const f=fixture(t),isToken=operation==='token reconnect';
  const first=isToken?await f.connections.connect({appId:'github',token:'fixture-token'}):await f.connect();
  const gate=deferred();f.state.identityHook=()=>gate.promise;
  const pending=isToken?f.connections.connect({appId:'github',token:'obsolete',connectionId:first.id}):f.connections.establishOAuth({connectionId:first.id,tokens:{accessToken:'obsolete',refreshToken:'obsolete-refresh',scopes,expiresAt:f.state.now+3600000}});
  const before=aba(f.store,first.id),tokens=f.vault.get(first.id);
  gate.resolve({status:200,data:isToken?{id:1,login:'obsolete'}:{sub:'fixture-account'}});
  await assert.rejects(pending,changed);
  assert.deepEqual(f.store.get('connections',first.id),before);assert.deepEqual(f.vault.get(first.id),tokens);
});

test('late failed reconnect rejects stale authority without touching the replacement',async t=>{
  const {store,vault,connections,state}=fixture(t),first=await connections.connect({appId:'github',token:'fixture-token'}),gate=deferred();
  state.identityHook=()=>gate.promise;
  const pending=connections.connect({appId:'github',token:'obsolete',connectionId:first.id}),replacement=aba(store,first.id),tokens=vault.get(first.id);
  gate.resolve({status:401,data:{error:'invalid_token'}});await assert.rejects(pending,changed);
  assert.deepEqual(store.get('connections',first.id),replacement);assert.deepEqual(vault.get(first.id),tokens);
});

test('OAuth flow stores existing authority and rejects ABA before token exchange',async t=>{
  const {store,oauth,connect,params,state}=fixture(t),first=await connect();
  const flow=oauth.start({connectionId:first.id}),input=params(flow);
  const id=createHash('sha256').update(input.state).digest('hex');
  assert.deepEqual(store.get('oauthFlows',id).connectionAuthority,{id:first.id,generation:1});
  aba(store,first.id);const count=state.requests.length;
  await assert.rejects(oauth.callback(input),changed);assert.equal(state.requests.length,count);
  assert.equal(store.get('oauthFlows',id),null);
});

for(const existing of [false,true]) test(`authority-mode ${existing?'existing':'new'} consent rejects historical missing snapshots`,async t=>{
  const {store,oauth,connect,params,state}=fixture(t),first=existing?await connect():null;
  const flow=oauth.start(first?{connectionId:first.id}:undefined),input=params(flow),id=createHash('sha256').update(input.state).digest('hex');
  const record=store.get('oauthFlows',id);delete record.connectionAuthority;store.put('oauthFlows',record);
  const count=state.requests.length;
  await assert.rejects(oauth.callback(input),changed);assert.equal(state.requests.length,count);
});

for(const status of [200,400]) test(`late consent token ${status} rejects changed generation without replacing credentials`,async t=>{
  const f=fixture(t),first=await f.connect(),gate=deferred();f.state.tokenHook=()=>gate.promise;
  const pending=f.oauth.callback(f.params(f.oauth.start({connectionId:first.id}))),before=aba(f.store,first.id),tokens=f.vault.get(first.id);
  gate.resolve(status===200?tokenResponse({access_token:'obsolete'}):{status:400,data:{error:'invalid_grant'}});
  await assert.rejects(pending,changed);
  assert.deepEqual(f.store.get('connections',first.id),before);assert.deepEqual(f.vault.get(first.id),tokens);
});

for(const status of [200,400]) test(`late refresh ${status} cannot overwrite or disable an ABA authorization`,async t=>{
  const f=fixture(t),first=await f.connect();f.expire();const gate=deferred();f.state.tokenHook=()=>gate.promise;
  const pending=f.oauth.refresh(first.id),before=aba(f.store,first.id),tokens=f.vault.get(first.id),requestCount=f.state.requests.length;
  gate.resolve(status===200?tokenResponse({access_token:'obsolete',refresh_token:'obsolete-refresh'}):{status:400,data:{error:'invalid_grant'}});
  await assert.rejects(pending,changed);
  assert.deepEqual(f.store.get('connections',first.id),before);assert.deepEqual(f.vault.get(first.id),tokens);
  assert.equal(f.state.requests.length,requestCount,'stale tokens are not sent to an identity endpoint');
});

test('refresh coalesces only within the same generation and late completion cannot delete the new waiter',async t=>{
  const f=fixture(t),first=await f.connect();f.expire();const oldGate=deferred(),newGate=deferred();let count=0;
  f.state.tokenHook=()=>++count===1?oldGate.promise:newGate.promise;
  const stale=f.oauth.refresh(first.id);aba(f.store,first.id);
  const current=f.oauth.refresh(first.id);assert.equal(count,2);
  oldGate.resolve(tokenResponse({access_token:'obsolete'}));await assert.rejects(stale,changed);
  const joined=f.oauth.refresh(first.id);assert.equal(count,2);
  newGate.resolve(tokenResponse({access_token:'current'}));
  assert.equal((await current).accessToken,'current');assert.equal((await joined).accessToken,'current');
  assert.equal(f.vault.get(first.id).accessToken,'current');
});

test('scope shrink records authority drift but never returns or stores credentials from the old request',async t=>{
  const f=fixture(t),first=await f.connect(),tokens=f.vault.get(first.id);f.expire();
  f.state.tokenHook=async()=>tokenResponse({access_token:'narrower',scope:scopes.slice(0,-1).join(' ')});
  await assert.rejects(f.connections.credentials(first.id),changed);
  assert.equal(f.store.connectionGeneration(first.id),2);
  assert.deepEqual(f.store.get('connections',first.id).scopes,scopes.slice(0,-1));
  assert.deepEqual(f.vault.get(first.id),tokens);
});

test('post-refresh identity wait cannot probe, save or return tokens after connection deletion',async t=>{
  const f=fixture(t),first=await f.connect();f.expire();const gate=deferred(),entered=deferred();
  f.state.identityHook=()=>{entered.resolve();return gate.promise;};
  const pending=f.connections.credentials(first.id);await entered.promise;
  f.store.delete('connections',first.id);const before=f.vault.get(first.id),requestCount=f.state.requests.length;
  gate.resolve({status:200,data:{sub:'fixture-account'}});
  await assert.rejects(pending,changed);assert.equal(f.store.get('connections',first.id),null);assert.deepEqual(f.vault.get(first.id),before);
  assert.equal(f.state.requests.length,requestCount,'revoked credentials never reach the next application probe');
});

for(const operation of ['refresh','credentials']) test(`cached-token ${operation} rechecks generation before async return`,async t=>{
  const f=fixture(t),first=await f.connect();
  const pending=operation==='refresh'?f.oauth.refresh(first.id):f.connections.credentials(first.id);
  aba(f.store,first.id);await assert.rejects(pending,changed);
});

test('missing authority counter rejects before provider I/O or local vault mutation',async t=>{
  const f=fixture(t),first=await f.connect(),tokens=f.vault.get(first.id),count=f.state.requests.length;
  f.store.db.exec('DELETE FROM _fabric_local_authority_counters');
  await assert.rejects(f.connections.credentials(first.id),error=>error.code==='invalid_local_authority');
  assert.throws(()=>f.connections.revoke(first.id),error=>error.code==='invalid_local_authority');
  assert.deepEqual(f.vault.get(first.id),tokens);assert.equal(f.state.requests.length,count);
});

for(const appId of ['google-calendar','gmail']) for(const hop of ['identity','application']) for(const status of [200,401]) test(`${appId} ${hop} probe ${status} cannot continue after authority changes`,async t=>{
  const f=fixture(t);
  if(appId==='gmail') f.state.scopes=['openid','email','https://www.googleapis.com/auth/gmail.readonly'];
  const first=await f.connect({appId});f.expire();const gate=deferred(),entered=deferred();
  f.state[hop==='identity'?'identityHook':'applicationHook']=()=>{entered.resolve();return gate.promise;};
  const pending=f.connections.credentials(first.id);await entered.promise;
  const before=aba(f.store,first.id),tokens=f.vault.get(first.id),requestCount=f.state.requests.length;
  gate.resolve({status,data:status===200?{sub:'fixture-account',kind:'calendar#calendarList'}:{error:'invalid_token'}});
  await assert.rejects(pending,changed);
  assert.equal(f.state.requests.length,requestCount);
  assert.deepEqual(f.store.get('connections',first.id),before);assert.deepEqual(f.vault.get(first.id),tokens);
});

test('trusted provider probe guard runs before and after every hop, including network rejection',async t=>{
  const f=fixture(t),provider=f.connections.providers.resolve({providerId:'google',appId:'google-calendar'});
  for(const failAt of [1,2,3,4]) {
    let checks=0;const before=f.state.requests.length;
    await assert.rejects(provider.observeIdentity({appId:'google-calendar',accessToken:'fixture-access',authorize:()=>{if(++checks===failAt)throw Object.assign(new Error('Changed'),{code:'connection_changed'});}}),changed);
    assert.equal(f.state.requests.length-before,Math.floor(failAt/2));
  }
  let checks=0;
  f.state.identityHook=async()=>{throw new Error('Synthetic network failure');};
  await assert.rejects(provider.observeIdentity({appId:'google-calendar',accessToken:'fixture-access',authorize:()=>{if(++checks===2)throw Object.assign(new Error('Changed'),{code:'connection_changed'});}}),changed);
  assert.equal(checks,2);
});

test('omitted refresh scopes preserve existing scope authority',async t=>{
  const f=fixture(t),first=await f.connect();f.expire();f.state.tokenHook=async()=>tokenResponse({scope:undefined});
  await f.connections.credentials(first.id);
  assert.equal(f.store.connectionGeneration(first.id),1);assert.deepEqual(f.store.get('connections',first.id).scopes,scopes);
});

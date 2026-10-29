import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {mkdtemp,rm,access,writeFile,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../lib/store.mjs';
import {PersistentBrowser} from '../lib/persistent-browser.mjs';
import {canonicalHash} from '../lib/compiler.mjs';

const origin='https://fixture.example';
const owner={schemaVersion:1,kind:'local_owner',id:'owner',scope:{schemaVersion:1,kind:'local',localOwnerId:'owner'}};
const client=id=>({schemaVersion:1,kind:'local_client',id,scope:owner.scope,delegatedBy:{kind:'local_owner',id:'owner'}});
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
class Page extends EventEmitter{
  constructor(){super();this.address='about:blank';this.closed=false;this.reads=0;}
  url(){return this.address;}mainFrame(){return this;}isClosed(){return this.closed;}
  async goto(url){this.address=url;this.emit('framenavigated',this);}async bringToFront(){}
  async evaluate(){this.reads++;return {origin,title:'Fixture',text:'Private fixture body'};}
  async close(){this.closed=true;this.emit('close');}
}
class Context extends EventEmitter{
  constructor(){super();this.items=[];this.closed=false;}
  pages(){return this.items.filter(page=>!page.closed);}browser(){return {isConnected:()=>!this.closed};}
  async newPage(){const page=new Page();this.items.push(page);return page;}
  async close(){if(this.closed)return;for(const page of this.pages())await page.close();this.closed=true;this.emit('close');}
}
async function fixture(t,options={}){
  const dataDir=await mkdtemp(path.join(tmpdir(),'fabric-profile-authority-'));let store=new Store({dataDir,localAuthority:'new'});
  const calls=[],catalog=()=>[{id:'fixture',name:'Fixture',webOrigins:[origin]}];
  const launch=options.launch||(async directory=>{const context=new Context();calls.push({directory,context});return context;});
  let browser=new PersistentBrowser({store,catalog,dataDir,launch,ownerPrincipal:owner});
  const f={dataDir,catalog,launch,calls,get store(){return store;},get browser(){return browser;},
    async connect(){const connection=await browser.connect({appId:'fixture',consent:true},owner);f.connection=connection;return connection;},
    async restart(){await browser.shutdown();store.close();store=new Store({dataDir,localAuthority:'require'});browser=new PersistentBrowser({store,catalog,dataDir,launch,ownerPrincipal:owner});}};
  t.after(async()=>{await browser.shutdown();store.close();await rm(dataDir,{recursive:true,force:true});});return f;
}
function authorization(f,op='observe',args={},principal=owner){
  const cap=f.store.get('capabilities',`fixture.session.${op}.v1`);
  return {cap,request:{schemaVersion:1,id:'request',scope:owner.scope,principal,access:{kind:'connection',id:f.connection.id,generation:f.store.connectionGeneration(f.connection.id)},capability:{appId:'fixture',id:cap.id,version:cap.version,definitionHash:canonicalHash(cap),effect:'read'},args,policyRevision:1,idempotencyKey:'request-key',createdAt:new Date().toISOString(),deadline:new Date(Date.now()+600000).toISOString()}};
}
function read(f,decision=authorization(f)){return f.browser.execute(f.connection.id,{op:'observe'},{},()=>decision);}
function changeAuthority(f){const c=f.store.get('connections',f.connection.id);f.store.put('connections',{...c,authRevision:'replacement'});}

test('saved-profile consent requires exact separate owner and rejects descriptor/body injection',async t=>{
  const f=await fixture(t);let getters=0;
  await assert.rejects(f.browser.connect({appId:'fixture',consent:true}));
  await assert.rejects(f.browser.connect({appId:'fixture',consent:true},client('agent')));
  await assert.rejects(f.browser.connect({appId:'fixture',consent:true,ownerPrincipal:owner},owner));
  await assert.rejects(f.browser.connect({get appId(){getters++;return 'fixture';},consent:true},owner));
  assert.equal(getters,0);assert.equal(f.calls.length,0);
  const inert=new PersistentBrowser({store:f.store,catalog:f.catalog,dataDir:f.dataDir,launch:f.launch});
  await assert.rejects(inert.connect({appId:'fixture',consent:true},owner));await inert.shutdown();
});
test('connection freezes input/catalog before availability and rechecks saved owner afterward',async t=>{
  for(const changed of ['input','catalog','owner'])await t.test(changed,async t=>{
    const f=await fixture(t),gate=deferred(),started=deferred(),input={appId:'fixture',consent:true},app={id:'fixture',name:'Original',webOrigins:[origin]};
    f.browser.catalog=()=>[app];f.browser.availability=async()=>{started.resolve();await gate.promise;return {available:true};};
    const promise=f.browser.connect(input,owner);const rejected=changed==='owner'?assert.rejects(promise):null;await started.promise;
    if(changed==='input')input.appId='changed';else if(changed==='catalog'){app.id='changed';app.webOrigins.push('https://other.example');}else f.store.put('localDeployment',{id:'owner',ownerPrincipal:client('agent')});
    gate.resolve();if(rejected){await rejected;assert.equal(f.calls.length,0);}else{const c=await promise;assert.equal(c.appId,'fixture');assert.deepEqual(c.allowedOrigins,[origin]);}
  });
});
test('final generation consent survives health/page/context reopen and restart with no identity claim',async t=>{
  const f=await fixture(t),c=await f.connect(),generation=f.store.connectionGeneration(c.id);
  assert.equal(generation,2);const session=f.store.get('persistentSessions',c.id),grant=f.store.get('persistentProfileConsents',session.consentId);assert.equal(grant.connectionAuthority.generation,generation);
  await read(f);assert.equal(f.browser.evidence(c).page.status,'observed');assert.equal(f.browser.evidence(c).account.verified,false);
  await f.calls[0].context.pages()[0].close();await read(f);await f.calls[0].context.close();await f.browser.open(c.id,owner);
  assert.equal(f.store.connectionGeneration(c.id),generation);await f.restart();await read(f);assert.equal(f.store.connectionGeneration(c.id),generation);
  assert.equal(JSON.stringify(f.store.list('persistentSessions')).includes('Private fixture body'),false);
});
test('partial consent save and historical missing provenance never become usable or dormant-stamped',async t=>{
  const f=await fixture(t),put=f.store.put.bind(f.store);
  f.store.put=(collection,value)=>{if(collection==='persistentProfileConsents')throw new Error('Fixture grant save failure');return put(collection,value);};
  await assert.rejects(f.connect(),/Fixture/);f.store.put=put;
  const c=f.store.list('connections')[0],session=f.store.get('persistentSessions',c.id);
  assert.equal(f.calls.length,0);await f.restart();assert.deepEqual(f.store.get('persistentSessions',c.id),session);assert.equal(f.browser.evidence(c).bridge.status,'unavailable');
  await assert.rejects(f.browser.open(c.id,owner));
});
test('parent and side ABA, deletion/recreation and missing provenance cannot revive profiles',async t=>{
  for(const kind of ['parent','side','delete','grant'])await t.test(kind,async t=>{
    const f=await fixture(t),c=await f.connect(),session=f.store.get('persistentSessions',c.id);
    if(kind==='parent'){changeAuthority(f);f.store.put('connections',c);}else if(kind==='side'){f.store.put('persistentSessions',{...session,consent:{...session.consent,grantedAt:'changed'}});f.store.put('persistentSessions',session);}else if(kind==='delete'){f.store.delete('connections',c.id);f.store.put('connections',c);}else f.store.delete('persistentProfileConsents',session.consentId);
    const before=f.store.get('persistentSessions',c.id);await f.restart();assert.deepEqual(f.store.get('persistentSessions',c.id),before);assert.equal(f.browser.evidence(c).bridge.status,'unavailable');await assert.rejects(f.browser.open(c.id,owner));
  });
});
test('typed execution rejects missing/no-op/async authorizers and writes before touching pages',async t=>{
  const f=await fixture(t);await f.connect();const page=f.calls[0].context.pages()[0];
  await assert.rejects(read(f,null));await assert.rejects(f.browser.execute(f.connection.id,{op:'observe'},{},()=>{}));
  await assert.rejects(f.browser.execute(f.connection.id,{op:'observe'},{},async()=>{throw new Error('Fixture async denial');}));
  for(const op of ['click','fill','shell'])await assert.rejects(f.browser.execute(f.connection.id,{op},{},()=>authorization(f)));
  await assert.rejects(f.browser.open(f.connection.id));await assert.rejects(f.browser.revoke(f.connection.id,client('agent')));assert.equal(page.reads,0);
});
test('accepted request is captured before queue; client substitution and permission deadline fail',async t=>{
  for(const kind of ['client','request','deadline','generation'])await t.test(kind,async t=>{
    const f=await fixture(t);await f.connect();const gate=deferred(),started=deferred(),page=f.calls[0].context.pages()[0];page.evaluate=async()=>{started.resolve();await gate.promise;return {origin};};
    const first=read(f),firstRejected=kind==='generation'?assert.rejects(first):null;await started.promise;
    let decision=authorization(f,'observe',{},client('a'));
    const queued=f.browser.execute(f.connection.id,{op:'observe'},{},()=>decision),rejected=assert.rejects(queued);
    if(kind==='client')decision={...decision,request:{...decision.request,principal:client('b')}};
    if(kind==='request')decision={...decision,request:{...decision.request,id:'different'}};
    if(kind==='deadline')decision={...decision,request:{...decision.request,deadline:new Date(Date.now()-1000).toISOString()}};
    if(kind==='generation')changeAuthority(f);
    gate.resolve();await(firstRejected||first);await rejected;
  });
});
test('in-flight read authority changes withhold data and never write replacement evidence',async t=>{
  const f=await fixture(t);await f.connect();const gate=deferred(),started=deferred(),page=f.calls[0].context.pages()[0];
  page.evaluate=async()=>{started.resolve();return gate.promise;};const pending=read(f),rejected=assert.rejects(pending);await started.promise;
  changeAuthority(f);const replacement={...f.store.get('persistentSessions',f.connection.id),lastAttempt:{status:'succeeded',at:'replacement'}};f.store.put('persistentSessions',replacement);
  gate.resolve({origin,title:'Old result'});await rejected;assert.deepEqual(f.store.get('persistentSessions',f.connection.id),replacement);
});
test('revoke before awaiting close denies later reads and retains explicit cleanup after restart',async t=>{
  const f=await fixture(t),c=await f.connect(),context=f.calls[0].context,gate=deferred(),started=deferred(),close=context.close.bind(context);
  context.close=async()=>{started.resolve();await gate.promise;return close();};const revoking=f.browser.revoke(c.id,owner);await started.promise;
  assert.equal(f.store.get('connections',c.id).status,'revoked');await assert.rejects(read(f));gate.resolve();const result=await revoking;
  assert.equal(result.profileCleanup.status,'retained');assert.equal(result.profileCleanup.cleanupRequired,true);await access(f.calls[0].directory);
  assert.equal(f.browser.evidence(c).session.state,'revoked');assert.equal(f.browser.evidence(c).session.profileCleanup.cleanupRequired,true);
  await f.restart();await assert.rejects(f.browser.open(c.id,owner));await access(f.calls[0].directory);
});
test('old revoke cannot close replacement resource or delete replacement profile while awaiting cleanup',async t=>{
  const f=await fixture(t),c=await f.connect(),context=f.calls[0].context,gate=deferred(),started=deferred(),close=context.close.bind(context);
  context.close=async()=>{started.resolve();await gate.promise;return close();};const revoking=f.browser.revoke(c.id,owner),rejected=assert.rejects(revoking);await started.promise;
  f.store.put('connections',{...c,authRevision:'replacement'});const replacement=new Context();f.browser.contexts.set(c.id,replacement);
  const marker=path.join(f.calls[0].directory,'replacement-marker');await writeFile(marker,'replacement');gate.resolve();await rejected;
  assert.equal(f.browser.contexts.get(c.id),replacement);assert.equal(replacement.closed,false);assert.equal(await readFile(marker,'utf8'),'replacement');
});
test('old page navigation/close/crash events cannot invalidate replacement page or evidence',async t=>{
  for(const event of ['framenavigated','close','crash'])await t.test(event,async t=>{
    const f=await fixture(t),c=await f.connect(),context=f.calls[0].context,old=context.pages()[0];await old.close();await read(f);const page=context.pages()[0],before=f.store.get('persistentSessions',c.id);
    old.emit(event,old);assert.equal(f.browser.pages.get(c.id),page);assert.deepEqual(f.store.get('persistentSessions',c.id),before);
  });
});
test('same-URL document navigation during evaluation invalidates data without trusting login',async t=>{
  const f=await fixture(t);await f.connect();const page=f.calls[0].context.pages()[0];page.evaluate=async()=>{page.emit('framenavigated',page);return {origin,title:'Old document'};};
  await assert.rejects(read(f));assert.equal(f.browser.evidence(f.connection).observedPage,null);assert.equal(f.browser.evidence(f.connection).account.verified,false);
});
test('owner or generation change during pending launch closes old resource without reinstalling it',async t=>{
  for(const kind of ['owner','generation','closeFailure'])await t.test(kind,async t=>{
    const gate=deferred(),started=deferred(),old=new Context();const f=await fixture(t,{launch:async()=>{started.resolve();await gate.promise;return old;}});
    const pending=f.connect(),rejected=assert.rejects(pending);await started.promise;const c=f.store.list('connections')[0];f.connection=c;
    if(kind==='owner')f.store.put('localDeployment',{id:'owner',ownerPrincipal:client('other')});else changeAuthority(f);
    if(kind==='closeFailure')old.close=async()=>{throw new Error('Fixture old close failure');};
    const replacement=new Context();f.browser.contexts.set(c.id,replacement);const before=f.store.get('persistentSessions',c.id);gate.resolve();await rejected;
    assert.equal(f.browser.contexts.get(c.id),replacement);assert.equal(replacement.closed,false);assert.deepEqual(f.store.get('persistentSessions',c.id),before);
    if(kind!=='closeFailure')assert.equal(old.closed,true);
  });
});
test('pending newPage/goto/front await cannot adopt replacement authority or page',async t=>{
  for(const kind of ['newPage','goto','front'])await t.test(kind,async t=>{
    const f=await fixture(t),c=await f.connect(),context=f.calls[0].context,gate=deferred(),started=deferred();await context.pages()[0].close();
    const original=context.newPage.bind(context);context.newPage=async()=>{const page=await original();
      if(kind==='newPage'){started.resolve();await gate.promise;}
      if(kind==='goto')page.goto=async()=>{started.resolve();await gate.promise;};
      if(kind==='front')page.bringToFront=async()=>{started.resolve();await gate.promise;};return page;};
    const pending=f.browser.open(c.id,owner),rejected=assert.rejects(pending);await started.promise;changeAuthority(f);const before=f.store.get('persistentSessions',c.id);gate.resolve();await rejected;assert.deepEqual(f.store.get('persistentSessions',c.id),before);
  });
});
test('shutdown late finally cannot change replacement session or remove replacement maps',async t=>{
  const f=await fixture(t),c=await f.connect(),context=f.calls[0].context,gate=deferred(),started=deferred(),close=context.close.bind(context);
  context.close=async()=>{started.resolve();await gate.promise;return close();};const stopping=f.browser.shutdown();await started.promise;
  changeAuthority(f);const replacement=new Context();f.browser.contexts.set(c.id,replacement);const before=f.store.get('persistentSessions',c.id);gate.resolve();await stopping;
  assert.equal(f.browser.contexts.get(c.id),replacement);assert.equal(replacement.closed,false);assert.deepEqual(f.store.get('persistentSessions',c.id),before);
});
test('a context from another accepted generation never becomes live evidence for a new consent',async t=>{
  const f=await fixture(t),c=await f.connect(),context=f.calls[0].context;
  f.browser.contextAuthorities.set(context,{...f.browser.profileAuthority(c.id),consentId:'obsolete'});
  assert.notEqual(f.browser.evidence(c).bridge.status,'alive');assert.equal(f.browser.evidence(c).page.status,'not_observed');
});
test('revocation during launch reports failed close and retains profile rather than reporting success',async t=>{
  const gate=deferred(),started=deferred(),context=new Context();let failClose=true;const close=context.close.bind(context);
  context.close=async()=>{if(failClose)throw new Error('Fixture close failure');return close();};
  const f=await fixture(t,{launch:async()=>{started.resolve();await gate.promise;return context;}});
  const connecting=f.connect(),connectRejected=assert.rejects(connecting);await started.promise;const c=f.store.list('connections')[0];
  const revoking=f.browser.revoke(c.id,owner),revokeRejected=assert.rejects(revoking,/could not be closed/);gate.resolve();await connectRejected;await revokeRejected;
  assert.equal(f.store.get('connections',c.id).status,'revoked');await access(path.join(f.dataDir,'browser-profiles',c.id));assert.equal(f.browser.contexts.has(c.id),false);
  failClose=false;
});
test('observation commit failure rejects data instead of reporting an observed result',async t=>{
  const f=await fixture(t);await f.connect();const put=f.store.put.bind(f.store);
  f.store.put=(collection,value)=>{if(collection==='persistentSessions'&&value.lastAttempt?.status==='succeeded')throw new Error('Fixture observation commit failure');return put(collection,value);};
  await assert.rejects(read(f));f.store.put=put;assert.equal(f.browser.evidence(f.connection).observedPage,null);
});
test('navigation during the post-commit authorizer withholds the previous document result',async t=>{
  const f=await fixture(t);await f.connect();const page=f.calls[0].context.pages()[0],decision=authorization(f);let navigated=false;
  const pending=f.browser.execute(f.connection.id,{op:'observe'},{},()=>{
    if(!navigated&&f.store.get('persistentSessions',f.connection.id).observationCurrent){navigated=true;page.emit('framenavigated',page);}
    return decision;
  });
  await assert.rejects(pending);assert.equal(navigated,true);
  const evidence=f.browser.evidence(f.connection);assert.equal(evidence.page.status,'stale');assert.equal(evidence.page.lastAttempt.status,'failed');
  assert.equal(f.store.get('persistentSessions',f.connection.id).observationCurrent,false);
});
test('result-time deadline and page changes are checked after typed authorization immediately before commit',async t=>{
  for(const kind of ['deadline','page'])await t.test(kind,async t=>{
    t.mock.timers.enable({apis:['Date'],now:Date.now()});
    const f=await fixture(t);await f.connect();const page=f.calls[0].context.pages()[0],decision=authorization(f);let returned=false,checks=0;
    page.evaluate=async()=>{returned=true;return {origin,title:'Never accepted'};};
    const pending=f.browser.execute(f.connection.id,{op:'observe'},{},()=>{
      if(returned&&++checks===2){if(kind==='deadline')t.mock.timers.setTime(Date.parse(decision.request.deadline)+1);else page.emit('framenavigated',page);}
      return decision;
    });
    await assert.rejects(pending);assert.equal(f.browser.evidence(f.connection).observedPage,null);
  });
});

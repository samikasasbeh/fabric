import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {mkdtemp,rm,stat,symlink,rename,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../lib/store.mjs';
import {PersistentBrowser} from '../lib/persistent-browser.mjs';

class FakePage extends EventEmitter {
  constructor(){super();this.current='about:blank';this.closed=false;this.evaluations=[];}
  isClosed(){return this.closed;}
  url(){return this.current;}
  mainFrame(){return this;}
  async goto(url){this.current=url;this.emit('framenavigated',this);}
  async bringToFront(){}
  async evaluate(fn,arg){this.evaluations.push({fn,arg});return {origin:new URL(this.current).origin,title:'Fixture page',text:'Fixture body',controls:[]};}
  async close(){this.closed=true;this.emit('close');}
}
class FakeContext extends EventEmitter {
  constructor(){super();this.openPages=[];this.closed=false;}
  pages(){return this.openPages.filter(p=>!p.closed);}
  async newPage(){const page=new FakePage();this.openPages.push(page);return page;}
  browser(){return {isConnected:()=>!this.closed};}
  async close(){if(this.closed)return;this.closed=true;for(const page of this.pages())await page.close();this.emit('close');}
}
function deferred(){let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}
async function fixture(t,options={}){
  const dataDir=await mkdtemp(path.join(tmpdir(),'fabric-persistent-test-')),store=new Store({dataDir}),calls=[];
  const catalog=()=>[{id:'fixture',name:'Fixture',webOrigins:['https://fixture.example']},{id:'second',name:'Second',webOrigins:['https://second.example']}];
  const launch=options.launch||(async(directory,settings)=>{const context=new FakeContext();calls.push({directory,settings,context});return context;});
  const browser=new PersistentBrowser({store,catalog,dataDir,launch});
  t.after(async()=>{await browser.shutdown();store.close();await rm(dataDir,{recursive:true,force:true});});
  return {dataDir,store,catalog,launch,calls,browser};
}
test('persistent connect requires explicit consent and creates separate durable profiles without claiming provider identity',async t=>{
  const f=await fixture(t);await assert.rejects(f.browser.connect({appId:'fixture'}),/consent/i);assert.equal(f.calls.length,0);
  const a=await f.browser.connect({appId:'fixture',consent:true}),b=await f.browser.connect({appId:'fixture',consent:true});
  assert.notEqual(a.id,b.id);assert.equal(a.transport,'persistent');assert.equal(a.persistentSession,true);assert.equal(a.status,'session_ready');assert.equal(a.expiresAt,null);assert.equal(a.identity.verified,false);
  assert.notEqual(f.calls[0].directory,f.calls[1].directory);assert.equal(path.dirname(f.calls[0].directory),path.join(f.dataDir,'browser-profiles'));assert.equal((await stat(f.calls[0].directory)).mode&0o777,0o700);
  assert.equal(f.calls[0].settings.headless,false);assert.equal(f.calls[0].settings.acceptDownloads,false);
  assert.equal(f.browser.evidence(a).account.verified,false);assert.equal(f.browser.evidence(a).page.status,'not_observed');
  const caps=f.store.list('capabilities');assert.deepEqual(caps.map(c=>c.id).sort(),['fixture.session.observe.v1','fixture.session.read.v1']);assert.ok(caps.every(c=>c.effect==='read'&&c.transport==='persistent'));
});
test('closing the app page recreates a page in the same profile without reconnecting, and reads do not persist private content',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true}),context=f.calls[0].context;
  await context.pages()[0].close();let checks=0;
  const result=await f.browser.execute(c.id,{op:'observe'},{},()=>{checks++;});
  assert.equal(f.calls.length,1);assert.equal(context.pages().length,1);assert.equal(result.data.origin,'https://fixture.example');assert.equal(result.verification.status,'observed');assert.ok(checks>=4);
  const persisted=JSON.stringify(f.store.list('persistentSessions'));assert.equal(persisted.includes('Fixture body'),false);assert.equal(f.browser.evidence(c).page.status,'observed');assert.equal(f.browser.evidence(c).account.verified,false);
  context.pages()[0].current='https://fixture.example/other';context.pages()[0].emit('framenavigated',context.pages()[0]);assert.equal(f.browser.evidence(c).page.status,'stale');
});
test('shutdown preserves profiles; a fresh runtime lazily recovers without logging in or reading accounts',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true}),directory=f.calls[0].directory;
  await f.browser.shutdown();await access(directory);assert.equal(f.calls[0].context.closed,true);
  const restarted=new PersistentBrowser({store:f.store,catalog:f.catalog,dataDir:f.dataDir,launch:f.launch});t.after(()=>restarted.shutdown());
  assert.equal(restarted.evidence(c).session.state,'dormant');assert.equal((await restarted.check(c.id)).status,'session_ready');assert.equal(f.calls.length,1);
  await restarted.execute(c.id,{op:'read'},{selector:'main'},()=>{});assert.equal(f.calls.length,2);assert.equal(f.calls[1].directory,directory);assert.equal(f.calls[1].context.pages()[0].evaluations.length,1);
});
test('persistent sessions reject writes, unknown arguments and missing runtime authorization before touching the browser',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true});
  for(const op of ['click','fill','evaluate','shell'])await assert.rejects(f.browser.execute(c.id,{op},{},()=>{}),/read.only|unsupported/i);
  await assert.rejects(f.browser.execute(c.id,{op:'observe'},{code:'alert(1)'},()=>{}),/argument/i);
  await assert.rejects(f.browser.execute(c.id,{op:'read'},{selector:'x'.repeat(501)},()=>{}),/selector/i);
  await assert.rejects(f.browser.execute(c.id,{op:'observe'},{},null),/authorization/i);
  assert.equal(f.calls[0].context.pages()[0].evaluations.length,0);
});
test('cross-origin page, redirect and forged read result cannot become successful observations',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true}),page=f.calls[0].context.pages()[0];
  page.current='https://login.example';await assert.rejects(f.browser.execute(c.id,{op:'observe'},{},()=>{}),/origin|sign.in/i);assert.equal(page.evaluations.length,0);
  page.current='https://fixture.example';page.evaluate=async()=>({origin:'https://other.example',title:'Fake success'});
  await assert.rejects(f.browser.execute(c.id,{op:'observe'},{},()=>{}),/origin/i);assert.equal(f.browser.evidence(c).page.status,'not_observed');
  page.evaluate=async()=>{page.current='https://other.example';return {origin:'https://fixture.example',title:'Old page'};};
  await assert.rejects(f.browser.execute(c.id,{op:'observe'},{},()=>{}),/origin|changed/i);
});
test('revoke during an in-flight read withholds its result and deletes only this connection profile',async t=>{
  const f=await fixture(t),a=await f.browser.connect({appId:'fixture',consent:true}),b=await f.browser.connect({appId:'fixture',consent:true});
  const started=deferred(),reply=deferred();f.calls[0].context.pages()[0].evaluate=async()=>{started.resolve();return reply.promise;};
  const pending=f.browser.execute(a.id,{op:'observe'},{},()=>{}),rejected=assert.rejects(pending,/revoked/);await started.promise;
  await f.browser.revoke(a.id);reply.resolve({origin:'https://fixture.example',title:'Late read'});await rejected;
  assert.equal(f.store.get('connections',a.id).status,'revoked');assert.equal(f.browser.evidence(a).account.verified,false);await assert.rejects(access(f.calls[0].directory));await access(f.calls[1].directory);assert.equal(f.calls[1].context.closed,false);
  await assert.rejects(f.browser.execute(a.id,{op:'observe'},{},()=>{}),/revoked/);assert.equal(f.store.get('connections',b.id).status,'session_ready');
});
test('revoke during browser launch cancels opening without resurrecting the connection',async t=>{
  const gate=deferred(),started=deferred(),context=new FakeContext();
  const f=await fixture(t,{launch:async()=>{started.resolve();await gate.promise;return context;}});
  const pending=f.browser.connect({appId:'fixture',consent:true}),rejected=assert.rejects(pending,/revoked/);await started.promise;
  const c=f.store.list('connections')[0],revoking=f.browser.revoke(c.id);assert.equal(f.store.get('connections',c.id).status,'revoked');gate.resolve();await rejected;await revoking;
  assert.equal(context.closed,true);assert.equal(f.store.get('persistentSessions',c.id).state,'revoked');await assert.rejects(access(path.join(f.dataDir,'browser-profiles',c.id)));
});
test('permission revoked while reading and queued work never return data or replay on recovery',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true}),gate=deferred(),started=deferred();let allowed=true;
  const page=f.calls[0].context.pages()[0];page.evaluate=async()=>{started.resolve();await gate.promise;return {origin:'https://fixture.example',title:'Withheld'};};
  const authorize=()=>{if(!allowed)throw new Error('Permission revoked');};
  const first=f.browser.execute(c.id,{op:'observe'},{},authorize),firstRejected=assert.rejects(first,/Permission revoked/);await started.promise;
  const second=f.browser.execute(c.id,{op:'observe'},{},authorize),secondRejected=assert.rejects(second,/Permission revoked/);allowed=false;gate.resolve();await firstRejected;await secondRejected;
  assert.equal(f.browser.evidence(c).observedPage,null);
});
test('concurrent opens and jobs share one profile owner; crashed context becomes dormant and reopens',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true});await f.calls[0].context.close();
  await Promise.all([f.browser.open(c.id),f.browser.open(c.id),f.browser.execute(c.id,{op:'observe'},{},()=>{})]);assert.equal(f.calls.length,2);
  await f.calls[1].context.close();assert.equal(f.browser.evidence(c).session.state,'dormant');assert.equal(f.browser.evidence(c).page.status,'stale');
  await f.browser.execute(c.id,{op:'observe'},{},()=>{});assert.equal(f.calls.length,3);
});
test('profile paths fail closed on tampering, traversal, and symlink replacement',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true}),directory=f.calls[0].directory;
  await f.calls[0].context.close();const original=f.store.get('persistentSessions',c.id);f.store.put('persistentSessions',{...original,profileId:'../../outside'});
  await assert.rejects(f.browser.open(c.id),/profile/i);f.store.put('persistentSessions',original);
  const saved=path.join(f.dataDir,'saved-profile');await rename(directory,saved);await symlink(saved,directory,'dir');
  await assert.rejects(f.browser.open(c.id),/profile|symlink/i);await assert.rejects(f.browser.revoke(c.id),/profile|symlink/i);await access(saved);assert.equal(f.store.get('connections',c.id).status,'revoked');
});
test('metadata checks never launch, read account pages, or give persistent permission an invented expiry',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true});await f.calls[0].context.close();
  await f.browser.check(c.id);f.browser.evidence(c);assert.equal(f.calls.length,1);assert.equal(f.calls[0].context.openPages[0].evaluations.length,0);
  assert.equal(f.store.get('connections',c.id).expiresAt,null);assert.equal(f.browser.evidence(c).session.expiresAt,null);assert.equal((await f.browser.availability()).available,true);
});
test('same-URL document navigation during a read invalidates the result, and crashed pages are not reused',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true}),context=f.calls[0].context,page=context.pages()[0];
  page.evaluate=async()=>{page.emit('framenavigated',page);return {origin:'https://fixture.example',title:'Old document'};};
  await assert.rejects(f.browser.execute(c.id,{op:'observe'},{},()=>{}),/changed|unavailable/);assert.equal(f.browser.evidence(c).observedPage,null);
  page.emit('crash');await f.browser.execute(c.id,{op:'observe'},{},()=>{});assert.equal(context.openPages.length,2);assert.equal(f.calls.length,1);
});
test('revoked-during-launch browser close failure retains its profile and never restores execution authority',async t=>{
  const gate=deferred(),started=deferred(),context=new FakeContext();let canClose=false;
  const close=context.close.bind(context);context.close=async()=>{if(!canClose)throw new Error('Fixture close failure');return close();};
  const f=await fixture(t,{launch:async()=>{started.resolve();await gate.promise;return context;}});
  const pending=f.browser.connect({appId:'fixture',consent:true}),rejected=assert.rejects(pending,/revoked/);await started.promise;
  const c=f.store.list('connections')[0],revoking=f.browser.revoke(c.id),failedClose=assert.rejects(revoking,/could not be closed/);gate.resolve();await rejected;await failedClose;
  await access(path.join(f.dataDir,'browser-profiles',c.id));assert.equal(f.store.get('connections',c.id).status,'revoked');
  canClose=true;await f.browser.revoke(c.id);assert.equal(context.closed,true);await assert.rejects(access(path.join(f.dataDir,'browser-profiles',c.id)));
});
test('revocation during page navigation cancels results, closes context, and never relaunches a queued job',async t=>{
  const gate=deferred(),started=deferred(),f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true}),context=f.calls[0].context;
  await context.pages()[0].close();
  const newPage=context.newPage.bind(context);context.newPage=async()=>{const page=await newPage();page.goto=async url=>{started.resolve();await gate.promise;page.current=url;};return page;};
  const pending=f.browser.execute(c.id,{op:'observe'},{},()=>{}),rejected=assert.rejects(pending,/revoked/);await started.promise;
  const queued=f.browser.execute(c.id,{op:'observe'},{},()=>{}),queuedRejected=assert.rejects(queued,/revoked/);
  await f.browser.revoke(c.id);gate.resolve();await rejected;await queuedRejected;assert.equal(f.calls.length,1);
});
test('missing runtime dependency is reported without creating profiles or opening a browser',async t=>{
  const f=await fixture(t);const unavailable=new PersistentBrowser({store:f.store,catalog:f.catalog,dataDir:f.dataDir});
  // The actual installation may be present on this machine; availability is a
  // bounded dependency/executable check, never a browser launch or account read.
  const status=await unavailable.availability();assert.equal(typeof status.available,'boolean');
  if(!status.available)assert.match(status.error,/installed/);
  assert.equal(f.calls.length,0);assert.equal(f.store.list('connections').length,0);await assert.rejects(access(path.join(f.dataDir,'browser-profiles')));
  await unavailable.shutdown();
});
test('the grant snapshots every declared exact origin, supports www redirects, and never inherits later catalog broadening',async t=>{
  const f=await fixture(t);let origins=['https://www.fixture.example','https://fixture.example'];f.browser.catalog=()=>[{id:'fixture',name:'Fixture',webOrigins:origins}];
  const c=await f.browser.connect({appId:'fixture',consent:true}),page=f.calls[0].context.pages()[0];assert.deepEqual(c.allowedOrigins,origins);
  page.current='https://fixture.example/home';const result=await f.browser.execute(c.id,{op:'observe'},{},()=>{});
  assert.equal(result.verification.origin,'https://fixture.example');assert.equal(page.evaluations[0].arg.expectedOrigin,'https://fixture.example');assert.equal(f.browser.evidence(c).page.status,'observed');
  origins=[...origins,'https://login.fixture.example'];page.current='https://login.fixture.example/';await assert.rejects(f.browser.execute(c.id,{op:'observe'},{},()=>{}),/origin/);assert.equal(page.evaluations.length,1);
  f.store.put('connections',{...c,allowedOrigins:origins});await assert.rejects(f.browser.open(c.id),/profile metadata/);
});
test('profile grants reject unbounded, insecure, and local catalog origins without opening browsers',async t=>{
  const f=await fixture(t);
  for(const origins of [Array.from({length:6},(_,i)=>`https://site${i}.example`),['http://fixture.example'],['https://localhost'],['https://127.0.0.1'],['https://fixture.local'],['https://fixture.example/path'],['https://user:password@fixture.example']]){
    f.browser.catalog=()=>[{id:'fixture',webOrigins:origins}];await assert.rejects(f.browser.connect({appId:'fixture',consent:true}));
  }
  assert.equal(f.calls.length,0);assert.equal(f.store.list('connections').length,0);
});
test('shutdown drains cancelled reads before allowing the caller to close the store',async t=>{
  const f=await fixture(t),c=await f.browser.connect({appId:'fixture',consent:true}),context=f.calls[0].context,started=deferred(),gate=deferred();
  context.pages()[0].evaluate=async()=>{started.resolve();await gate.promise;return {origin:'https://fixture.example',text:'Late body'};};
  const pending=f.browser.execute(c.id,{op:'observe'},{},()=>{}),rejected=assert.rejects(pending,/stopped/);await started.promise;
  let completed=false;const stopping=f.browser.shutdown().then(()=>{completed=true;});await new Promise(resolve=>setImmediate(resolve));assert.equal(completed,false);
  gate.resolve();await rejected;await stopping;assert.equal(completed,true);assert.equal(f.browser.evidence(c).observedPage,null);
});

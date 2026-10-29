import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../lib/store.mjs';
import {BrowserBridge} from '../lib/browser-bridge.mjs';

// Isolated bridge fixtures only. These never contact a website or real account.
function fixture(t) {
  const dir=mkdtempSync(join(tmpdir(),'fabric-browser-evidence-')),store=new Store({dataDir:dir});
  const catalog=()=>[{id:'fixture',name:'Fixture',webOrigins:['https://fixture.example']}];
  const bridge=new BrowserBridge({store,catalog});
  const pairing=bridge.createPair('fixture');
  const linked=bridge.pair({code:pairing.code,origin:'https://fixture.example',label:'Sign in',bridgeVersion:'0.2'});
  t.after(()=>{bridge.close();store.close();rmSync(dir,{recursive:true,force:true});});
  return {store,catalog,bridge,...linked};
}
async function observation(f,data={origin:'https://fixture.example',title:'Sign in',text:'Private fixture page text'}) {
  const pending=f.bridge.execute(f.connection.id,{op:'observe'},{},()=>{});
  const command=f.bridge.poll(f.token).command;
  f.bridge.result(f.token,{id:command.id,ok:true,data});
  return pending;
}
test('pairing, legacy lastCheckedAt, and heartbeat never verify an account or imply a page read',t=>{
  const f=fixture(t),evidence=f.bridge.getConnectionEvidence(f.connection);
  assert.equal(evidence.bridge.status,'waiting');assert.equal(evidence.bridge.lastHeartbeatAt,null);
  assert.deepEqual(evidence.account,{status:'unverified',verified:false});
  assert.equal(evidence.page.status,'not_observed');assert.equal(evidence.observedPage,null);
  assert.equal(f.bridge.getConnectionEvidence({driver:'http'}),null);
  const before=JSON.stringify(f.store.list('browserDevices'));
  f.bridge.getConnectionEvidence(f.connection);assert.equal(JSON.stringify(f.store.list('browserDevices')),before);
  assert.equal(f.bridge.check(f.connection.id).status,'unavailable');
  f.bridge.poll(f.token);
  const after=f.bridge.getConnectionEvidence(f.connection);
  assert.equal(after.bridge.status,'alive');assert.ok(after.bridge.lastHeartbeatAt);
  assert.equal(f.bridge.check(f.connection.id).status,'session_ready');
  assert.equal(after.page.status,'not_observed');assert.equal(after.account.verified,false);
});
test('a successful matching-origin read stores only bounded page evidence, not account identity or private content',async t=>{
  const f=fixture(t);
  await observation(f,{origin:'https://fixture.example',title:'Sign\nin '+ 'x'.repeat(500),text:'PRIVATE_PAGE_TEXT',url:'https://fixture.example/?secret=PRIVATE_QUERY',controls:[{label:'PRIVATE_CONTROL'}],account:{status:'verified'}});
  const evidence=f.bridge.getConnectionEvidence(f.connection);
  assert.equal(evidence.bridge.status,'alive');assert.equal(evidence.page.status,'observed');
  assert.deepEqual(evidence.page.lastAttempt,{status:'succeeded',at:evidence.observedPage.observedAt});
  assert.equal(evidence.observedPage.origin,'https://fixture.example');assert.ok(evidence.observedPage.title.length<=160);assert.equal(evidence.observedPage.title.includes('\n'),false);
  assert.equal(evidence.account.verified,false);
  const persisted=JSON.stringify(f.store.list('browserDevices'));
  for(const privateValue of ['PRIVATE_PAGE_TEXT','PRIVATE_QUERY','PRIVATE_CONTROL'])assert.equal(persisted.includes(privateValue),false);
  const restarted=new BrowserBridge({store:f.store,catalog:f.catalog});t.after(()=>restarted.close());
  assert.deepEqual(restarted.getConnectionEvidence(f.connection),evidence);
});
test('stale heartbeat, stale page, future timestamps and revocation cannot retain live page evidence',async t=>{
  const f=fixture(t);await observation(f);
  const device=f.store.get('browserDevices',f.connection.id);
  f.store.put('browserDevices',{...device,lastHeartbeatAt:new Date(Date.now()-91000).toISOString()});
  assert.equal(f.bridge.getConnectionEvidence(f.connection).bridge.status,'stale');assert.equal(f.bridge.getConnectionEvidence(f.connection).page.status,'stale');
  assert.equal(f.bridge.check(f.connection.id).status,'unavailable');
  f.bridge.poll(f.token);
  f.store.put('browserDevices',{...f.store.get('browserDevices',f.connection.id),observedPage:{...device.observedPage,observedAt:new Date(Date.now()-121000).toISOString()}});
  assert.equal(f.bridge.getConnectionEvidence(f.connection).page.status,'stale');
  f.store.put('browserDevices',{...device,lastHeartbeatAt:new Date(Date.now()+60000).toISOString()});
  assert.notEqual(f.bridge.getConnectionEvidence(f.connection).bridge.status,'alive');
  f.store.put('browserDevices',device);f.store.put('connections',{...f.connection,status:'revoked'});
  const revoked=f.bridge.getConnectionEvidence(f.connection);assert.equal(revoked.bridge.status,'revoked');assert.equal(revoked.page.status,'stale');assert.ok(revoked.observedPage);assert.equal(revoked.account.verified,false);
  assert.throws(()=>f.bridge.poll(f.token),/revoked/);
});
test('failed reads invalidate current page evidence and later heartbeats cannot turn them into read success',async t=>{
  const f=fixture(t);await observation(f);
  const pending=f.bridge.execute(f.connection.id,{op:'read'},{selector:'main'},()=>{}),rejected=assert.rejects(pending,/Browser operation failed/);
  const {command}=f.bridge.poll(f.token);f.bridge.result(f.token,{id:command.id,ok:false,error:'Fixture read failed'});await rejected;
  f.bridge.poll(f.token);
  const evidence=f.bridge.getConnectionEvidence(f.connection);
  assert.equal(evidence.bridge.status,'alive');assert.equal(evidence.page.status,'stale');assert.equal(evidence.page.lastAttempt.status,'failed');assert.ok(evidence.observedPage);
});
test('mismatched-origin successful results and writes never produce page observation evidence',async t=>{
  const f=fixture(t);
  const pending=f.bridge.execute(f.connection.id,{op:'observe'},{},()=>{});
  const rejected=assert.rejects(pending,/origin/),{command}=f.bridge.poll(f.token);
  const response=f.bridge.result(f.token,{id:command.id,ok:true,data:{origin:'https://other.example',title:'Signed in'}});
  await rejected;assert.equal(response.accepted,false);assert.equal(f.bridge.getConnectionEvidence(f.connection).observedPage,null);
  const write=f.bridge.execute(f.connection.id,{op:'click'},{snapshotId:'fixture-snapshot',targetId:'fixture-target'},()=>{});
  const next=f.bridge.poll(f.token).command;
  f.bridge.result(f.token,{id:next.id,ok:true,data:{origin:'https://fixture.example',title:'Signed in',operation:'click',targetId:'fixture-target',dispatchStatus:'dispatched',persistentEffect:'unverified'}});await write;
  assert.equal(f.bridge.getConnectionEvidence(f.connection).observedPage,null);assert.equal(f.bridge.getConnectionEvidence(f.connection).account.verified,false);
});
test('a read timeout invalidates prior page evidence without creating a new read or exposing result data',async t=>{
  t.mock.timers.enable({apis:['Date','setTimeout'],now:Date.now()});
  const f=fixture(t);await observation(f);
  const pending=f.bridge.execute(f.connection.id,{op:'observe'},{},()=>{}),rejected=assert.rejects(pending,/did not respond/);
  t.mock.timers.tick(40001);await rejected;
  const evidence=f.bridge.getConnectionEvidence(f.connection);
  assert.equal(evidence.page.status,'stale');assert.equal(evidence.page.lastAttempt.status,'timed_out');assert.ok(evidence.observedPage);
  f.bridge.poll(f.token);assert.equal(f.bridge.getConnectionEvidence(f.connection).page.status,'stale');
});
test('authority revoked before a result prevents observation evidence and records cancellation',async t=>{
  const f=fixture(t);let allowed=true;
  const pending=f.bridge.execute(f.connection.id,{op:'observe'},{},()=>{if(!allowed)throw new Error('Fixture permission revoked');});
  const rejected=assert.rejects(pending,/permission revoked/),{command}=f.bridge.poll(f.token);allowed=false;
  assert.deepEqual(f.bridge.result(f.token,{id:command.id,ok:true,data:{origin:'https://fixture.example',title:'Fixture'}}),{accepted:false});await rejected;
  const evidence=f.bridge.getConnectionEvidence(f.connection);assert.equal(evidence.observedPage,null);assert.equal(evidence.page.lastAttempt.status,'cancelled');
});
test('late timed-out results cannot refresh observations and a subsequent successful read clears stale failure state',async t=>{
  t.mock.timers.enable({apis:['Date','setTimeout'],now:Date.now()});
  const f=fixture(t);await observation(f);
  const old=f.bridge.getConnectionEvidence(f.connection).observedPage;
  const pending=f.bridge.execute(f.connection.id,{op:'observe'},{},()=>{}),rejected=assert.rejects(pending,/did not respond/);
  const {command}=f.bridge.poll(f.token);t.mock.timers.tick(40001);await rejected;
  assert.throws(()=>f.bridge.result(f.token,{id:command.id,ok:true,data:{origin:'https://fixture.example',title:'Late response'}}),/outstanding/);
  assert.deepEqual(f.bridge.getConnectionEvidence(f.connection).observedPage,old);
  await observation(f,{origin:'https://fixture.example',title:'Current fixture page'});
  assert.equal(f.bridge.getConnectionEvidence(f.connection).page.status,'observed');assert.equal(f.bridge.getConnectionEvidence(f.connection).page.lastAttempt.status,'succeeded');
});
test('restart cancels orphaned read evidence while legacy connection fields alone remain unobserved',t=>{
  const f=fixture(t);f.bridge.close();
  f.store.put('browserCommands',{id:'orphan-fixture-read',connectionId:f.connection.id,action:{op:'observe'},status:'dispatched'});
  const restarted=new BrowserBridge({store:f.store,catalog:f.catalog});t.after(()=>restarted.close());
  const evidence=restarted.getConnectionEvidence(f.connection);
  assert.equal(evidence.bridge.status,'waiting');assert.equal(evidence.observedPage,null);assert.equal(evidence.page.lastAttempt.status,'cancelled');
  assert.equal(evidence.account.verified,false);
  f.store.delete('browserDevices',f.connection.id);
  assert.equal(restarted.getConnectionEvidence(f.connection).bridge.status,'unavailable');
});

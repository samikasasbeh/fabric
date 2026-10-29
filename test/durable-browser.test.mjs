import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../lib/store.mjs';
import {BrowserBridge} from '../lib/browser-bridge.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {FabricProtocol} from '../lib/fabric-protocol.mjs';
import {createApp} from '../server.mjs';

function fixture(t) {
  const dir=mkdtempSync(join(tmpdir(),'fabric-durable-')),store=new Store({dataDir:dir});
  const catalog=()=>['notes','tasks'].map(id=>({id,name:id,webOrigins:[`https://${id}.example`]}));
  const bridge=new BrowserBridge({store,catalog}),permissions=new PermissionManager({store});
  const pair=(appId='notes',extra={})=>bridge.pair({code:bridge.createPair(appId).code,origin:`https://${appId}.example`,bridgeVersion:'0.3',sessionScope:'browser-profile',...extra});
  t.after(()=>{bridge.close();store.close();rmSync(dir,{recursive:true,force:true});});
  return {store,bridge,permissions,catalog,pair};
}

test('durable scope requires new explicit pairing; old helpers never silently gain recovery authority',t=>{
  const {bridge,pair}=fixture(t),setup=bridge.createPair('notes');
  assert.equal(setup.bridgeVersion,'0.3');assert.equal(setup.sessionScope,'browser-profile');
  assert.throws(()=>bridge.pair({code:setup.code,origin:'https://notes.example',bridgeVersion:'0.3'}),/scope/i);
  assert.equal(bridge.status(setup.pairingId).status,'pending');
  assert.throws(()=>pair('notes',{bridgeVersion:'0.2'}),/scope/i);
  const legacy=pair('notes',{bridgeVersion:'0.2',sessionScope:undefined});
  assert.notEqual(legacy.connection.sessionScope,'browser-profile');
  const current=pair();assert.equal(current.connection.sessionScope,'browser-profile');
  assert.equal(current.connection.bridgeVersion,'0.3');assert.equal(current.connection.identity.verified,false);
});

test('idle helper remains reachable without a page; this is not account authentication or a current page read',async t=>{
  const {bridge,pair,store}=fixture(t),{connection,token}=pair();
  assert.deepEqual(bridge.poll(token,{execution:{state:'idle'}}),{command:null});
  let evidence=bridge.getConnectionEvidence(connection);
  assert.equal(evidence.bridge.status,'alive');assert.equal(evidence.bridge.scope,'browser-profile');
  assert.equal(evidence.bridge.executionState,'idle');assert.equal(evidence.account.verified,false);
  assert.equal(evidence.page.status,'not_observed');assert.equal(store.list('browserCommands').length,0);
  const read=bridge.execute(connection.id,{op:'observe'},{},()=>{});
  const {command}=bridge.poll(token,{execution:{state:'idle'}});
  assert.equal(command.action.op,'observe');
  bridge.result(token,{id:command.id,ok:true,data:{origin:'https://notes.example',title:'Fixture'}});await read;
  assert.equal(bridge.getConnectionEvidence(connection).page.status,'observed');
  bridge.poll(token,{execution:{state:'idle'}});
  evidence=bridge.getConnectionEvidence(connection);
  assert.equal(evidence.bridge.status,'alive');assert.equal(evidence.page.status,'stale');
  assert.equal(bridge.check(connection.id).status,'session_ready');
  bridge.poll(token,{execution:{state:'open'}});
  assert.equal(bridge.getConnectionEvidence(connection).page.status,'stale','opening another page cannot renew an old observation');
});

test('saved app grants coexist across runtime restart; no jobs replay and revocation is explicit',t=>{
  const {bridge,pair,store,catalog}=fixture(t),notes=pair(),tasks=pair('tasks');
  bridge.poll(notes.token,{execution:{state:'idle'}});bridge.poll(tasks.token,{execution:{state:'idle'}});
  bridge.close();const restarted=new BrowserBridge({store,catalog});t.after(()=>restarted.close());
  for(const saved of [notes,tasks])assert.equal(restarted.poll(saved.token,{execution:{state:'idle'}}).command,null);
  assert.equal(store.list('browserCommands').length,0);
  store.put('connections',{...notes.connection,status:'revoked'});
  assert.throws(()=>restarted.poll(notes.token,{execution:{state:'idle'}}),{code:'browser_revoked'});
  assert.equal(restarted.poll(tasks.token,{execution:{state:'idle'}}).command,null);
});

test('scope and origin changes invalidate old permissions and client grants; durable reads and writes require approval',t=>{
  const {pair,permissions,store}=fixture(t),{connection}=pair();
  const cap=store.get('capabilities','notes.browser.observe.v1'),write=store.get('capabilities','notes.browser.click.v2');
  assert.ok(write);assert.equal(permissions.set({connectionId:connection.id,capabilityId:cap.id,mode:'allow'}).mode,'ask');
  const protocol=new FabricProtocol({store,runtime:{permissions}});
  const {client}=protocol.createClient({name:'Durable test agent',bindings:[{connectionId:connection.id,capabilityId:cap.id},{connectionId:connection.id,capabilityId:write.id}]});
  assert.ok(client.id);assert.equal(permissions.decision(connection,write).requiresApproval,true);
  store.put('connections',{...connection,sessionScope:'browser-tab'});
  assert.throws(()=>protocol.assertBinding(client.id,connection.id,cap.id),{code:'grant_changed'});
  assert.equal(permissions.decision(connection,cap).stale,true);
  const before=permissions.binding(connection,cap);
  assert.notEqual(permissions.binding({...connection,allowedOrigins:['https://other.example']},cap),before);
});

test('durable writes retain exact-job authorization and never infer a successful persistent effect',async t=>{
  const {bridge,pair}=fixture(t),{connection,token}=pair();let checks=0;
  const execution=bridge.execute(connection.id,{op:'click'},{snapshotId:'snapshot',targetId:'control'},()=>checks++);
  const {command}=bridge.poll(token,{execution:{state:'open'}});
  bridge.result(token,{id:command.id,ok:true,data:{origin:'https://notes.example',operation:'click',targetId:'control',dispatchStatus:'dispatched',persistentEffect:'unverified'}});
  const result=await execution;assert.equal(checks,3);assert.equal(result.verification.status,'unverified');
});

test('durable command has a bounded startup budget, and expiry never replays when helper returns',async t=>{
  t.mock.timers.enable({apis:['Date','setTimeout'],now:Date.now()});
  const {bridge,pair,store}=fixture(t),{connection,token}=pair();
  const read=bridge.execute(connection.id,{op:'observe'},{},()=>{}),rejected=assert.rejects(read,/did not respond/);
  t.mock.timers.tick(50000);
  assert.equal(store.list('browserCommands')[0].status,'queued');
  const {command}=bridge.poll(token,{execution:{state:'idle'}});
  assert.equal(Date.parse(command.expiresAt)-Date.now(),25000);
  t.mock.timers.tick(25001);await rejected;
  assert.equal(bridge.poll(token,{execution:{state:'idle'}}).command,null);
  assert.throws(()=>bridge.result(token,{id:command.id,ok:true,data:{origin:'https://notes.example'}}),/outstanding/);
});

test('poll checks wall-clock expiry even if the process has not delivered its timeout callback',async t=>{
  t.mock.timers.enable({apis:['Date'],now:Date.now()});
  const {bridge,pair}=fixture(t),{connection,token}=pair();
  const read=bridge.execute(connection.id,{op:'observe'},{},()=>{}),rejected=assert.rejects(read,/expired before dispatch/);
  t.mock.timers.setTime(Date.now()+75001);
  assert.equal(bridge.poll(token,{execution:{state:'idle'}}).command,null);await rejected;
});

test('late results cannot renew page evidence when the timeout callback is delayed',async t=>{
  t.mock.timers.enable({apis:['Date'],now:Date.now()});
  const {bridge,pair,store}=fixture(t),{connection,token}=pair();
  const read=bridge.execute(connection.id,{op:'observe'},{},()=>{}),rejected=assert.rejects(read,/expired.*effect is unknown/i);
  const {command}=bridge.poll(token,{execution:{state:'idle'}});
  t.mock.timers.setTime(Date.parse(command.expiresAt)+1);
  assert.deepEqual(bridge.result(token,{id:command.id,ok:true,data:{origin:'https://notes.example',title:'Late fixture'}}),{accepted:false});
  await rejected;
  assert.equal(store.get('browserCommands',command.id).status,'expired');
  assert.equal(bridge.getConnectionEvidence(connection).page.status,'not_observed');
  assert.equal(bridge.getConnectionEvidence(connection).page.lastAttempt.status,'timed_out');
  assert.equal(bridge.pending.size,0);
});

test('HTTP lifecycle distinguishes saved permission, idle execution, expired helper evidence and provider identity',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'fabric-durable-http-'));
  const app=await createApp({dataDir:dir,port:48500+Math.floor(Math.random()*200),request:async()=>{throw new Error('No provider access in this fixture');}});
  await app.start();t.after(async()=>{await app.close();rmSync(dir,{recursive:true,force:true});});
  const setup=app.browser.createPair('slack'),origin=setup.origins[0];
  const linked=app.browser.pair({code:setup.code,origin,bridgeVersion:'0.3',sessionScope:'browser-profile'});
  const headers={'Content-Type':'application/json',Origin:`chrome-extension://${'a'.repeat(32)}`,Authorization:`Bearer ${linked.token}`};
  const poll=()=>fetch(app.origin+'/api/browser/poll',{method:'POST',headers,body:JSON.stringify({execution:{state:'idle'}})});
  assert.equal((await poll()).status,200);
  for(const path of ['/api/state','/api/status','/api/connectors/slack']) {
    const response=await fetch(app.origin+path),body=await response.json();
    const saved=body.connections.find(c=>c.id===linked.connection.id);
    assert.equal(saved.bridgeVersion,'0.3');assert.equal(saved.sessionScope,'browser-profile');
    assert.equal(saved.lifecycle.kind,'browser-profile');assert.equal(saved.lifecycle.retention,'until-disconnected');
    assert.equal(saved.lifecycle.expiresAt,null);assert.equal(saved.lifecycle.lastVerifiedAt,null);
    assert.equal(saved.browserEvidence.bridge.executionState,'idle');assert.equal(saved.browserEvidence.bridge.status,'alive');
    assert.equal(saved.browserEvidence.account.verified,false);assert.equal(JSON.stringify(body).includes(linked.token),false);
  }
  const device=app.store.get('browserDevices',linked.connection.id);
  app.store.put('browserDevices',{...device,lastHeartbeatAt:new Date(Date.now()-91000).toISOString()});
  assert.equal(app.browser.check(linked.connection.id).status,'unavailable');
  assert.equal((await poll()).status,200);assert.equal(app.connections.get(linked.connection.id).status,'session_ready');
  app.connections.revoke(linked.connection.id);
  const revoked=await poll();assert.equal(revoked.status,401);assert.equal((await revoked.json()).code,'browser_revoked');
});

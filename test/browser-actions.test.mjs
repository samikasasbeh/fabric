import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../lib/store.mjs';
import {BrowserBridge} from '../lib/browser-bridge.mjs';

function fixture(t,version='0.2'){
  const dir=mkdtempSync(join(tmpdir(),'fabric-browser-actions-')),store=new Store({dataDir:dir});
  const bridge=new BrowserBridge({store,catalog:()=>[{id:'fixture',name:'Fixture App',webOrigins:['https://fixture.example']}]});
  const pairing=bridge.createPair('fixture');const linked=bridge.pair({code:pairing.code,origin:'https://fixture.example',bridgeVersion:version});
  t.after(()=>{bridge.close();store.close();rmSync(dir,{recursive:true,force:true});});
  return {store,bridge,pairing,...linked};
}
test('browser v0.2 pairs exact setup id, exposes observed-target action schemas, and preserves v0.1 read IDs',t=>{
  const {store,pairing,connection,pairingId}=fixture(t);
  assert.equal(pairing.bridgeVersion,'0.3');assert.equal(pairing.launchUrl,'https://fixture.example');assert.equal(pairing.appName,'Fixture App');
  assert.equal(connection.bridgeVersion,'0.2');assert.equal(pairingId,pairing.pairingId);
  assert.ok(store.get('capabilities','fixture.browser.observe.v1'));
  const cap=store.get('capabilities','fixture.browser.fill.v2');assert.equal(cap.effect,'write');assert.deepEqual(cap.inputSchema.required,['snapshotId','targetId','value']);assert.equal(cap.inputSchema.additionalProperties,false);
});
test('browser action cannot dispatch without runtime authorization, observed targets, or current bridge version',async t=>{
  const {bridge,connection}=fixture(t);const args={snapshotId:'snapshot',targetId:'target'};
  await assert.rejects(bridge.execute(connection.id,{op:'click'},args),/exact-job/);
  await assert.rejects(bridge.execute(connection.id,{op:'click'},{...args,script:'evil'},()=>{}),/declared action/);
  await assert.rejects(bridge.execute(connection.id,{op:'eval'},{script:'evil'},()=>{}),/No JavaScript or shell/);
  const old=fixture(t,'0.1');await assert.rejects(old.bridge.execute(old.connection.id,{op:'click'},args,()=>{}),/Reconnect/);
});
test('browser actions recheck authority at queue, dispatch, and result; completion stays unverified',async t=>{
  const {bridge,connection,token}=fixture(t);let checks=0;
  const execution=bridge.execute(connection.id,{op:'click'},{snapshotId:'snapshot',targetId:'target'},()=>{checks++;});
  assert.equal(checks,1);const {command}=bridge.poll(token);assert.equal(checks,2);
  bridge.result(token,{id:command.id,ok:true,data:{origin:'https://fixture.example',operation:'click',targetId:'target',dispatchStatus:'dispatched',persistentEffect:'unverified',verification:{status:'verified'}}});
  const result=await execution;assert.equal(checks,3);assert.equal(result.verification.status,'unverified');assert.equal(result.verification.kind,'paired-browser-dispatch');
});
test('revoked exact-job authorization cancels a queued write before dispatch',async t=>{
  const {bridge,connection,token,store}=fixture(t);let allowed=true;
  const execution=bridge.execute(connection.id,{op:'fill'},{snapshotId:'snapshot',targetId:'target',value:'Fixture'},()=>{if(!allowed)throw new Error('Permission revoked');});
  const rejected=assert.rejects(execution,/Permission revoked/);allowed=false;assert.equal(bridge.poll(token).command,null);await rejected;
  assert.equal(store.list('browserCommands')[0].status,'cancelled');
});
test('write receipts must match the approved origin, operation and target without claiming persistence',async t=>{
  const {bridge,connection,token}=fixture(t);
  const valid={origin:'https://fixture.example',operation:'click',targetId:'target',dispatchStatus:'dispatched',persistentEffect:'unverified'};
  for(const bad of [{},{...valid,origin:'https://other.example'},{...valid,operation:'fill'},{...valid,targetId:'other'},
    {...valid,dispatchStatus:'verified'},{...valid,persistentEffect:'verified'}]) {
    const execution=bridge.execute(connection.id,{op:'click'},{snapshotId:'snapshot',targetId:'target'},()=>{});
    const rejected=assert.rejects(execution,/receipt did not match/);
    const {command}=bridge.poll(token);
    assert.equal(bridge.result(token,{id:command.id,ok:true,data:bad}).accepted,false);
    await rejected;
  }
});

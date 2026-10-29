import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {Store} from '../lib/store.mjs';
import {BrowserBridge} from '../lib/browser-bridge.mjs';

function fixture(t) {
  const dir=mkdtempSync(join(tmpdir(),'fabric-pairing-')),store=new Store({dataDir:dir});
  const catalog=()=>[{id:'fixture-app',webOrigins:['https://example.com']}];
  const bridge=new BrowserBridge({store,catalog});
  t.after(()=>{bridge.close();store.close();rmSync(dir,{recursive:true,force:true});});
  return {store,bridge,catalog};
}
test('exact pairing session becomes paired only after its own secret code is consumed',t=>{
  const {store,bridge}=fixture(t),first=bridge.createPair('fixture-app'),second=bridge.createPair('fixture-app');
  assert.notEqual(first.pairingId,first.code);assert.notEqual(first.pairingId,second.pairingId);
  assert.equal(bridge.status(first.pairingId).status,'pending');
  const linked=bridge.pair({code:second.code,origin:'https://example.com'});
  assert.equal(bridge.status(first.pairingId).status,'pending');
  assert.equal(bridge.status(first.pairingId).connectionId,undefined);
  const status=bridge.status(second.pairingId);
  assert.equal(status.status,'paired');assert.equal(status.connectionId,linked.connection.id);
  assert.equal(status.connectionStatus,'session_ready');assert.ok(status.pairedAt);
  const persisted=JSON.stringify([store.list('pairings'),store.list('pairingSessions')]);
  for(const secret of [first.code,second.code,linked.token]) {assert.equal(persisted.includes(secret),false);assert.equal(JSON.stringify(status).includes(secret),false);}
  assert.throws(()=>bridge.pair({code:second.code,origin:'https://example.com'}),/already used/);
});
test('pairing id cannot authorize a browser session and wrong-origin pairing stays pending',t=>{
  const {bridge}=fixture(t),pair=bridge.createPair('fixture-app');
  assert.throws(()=>bridge.pair({code:pair.pairingId,origin:'https://example.com'}),/Invalid pairing code/);
  assert.throws(()=>bridge.pair({code:pair.code,origin:'https://elsewhere.example'}),/does not match/);
  assert.equal(bridge.status(pair.pairingId).status,'pending');
  assert.throws(()=>bridge.poll(pair.pairingId),/revoked or unknown/);
  assert.throws(()=>bridge.status(pair.code),/Unknown browser pairing session/);
  assert.throws(()=>bridge.status(randomUUID()),/Unknown browser pairing session/);
});
test('expired exact session cannot be paired and does not infer success from another app connection',t=>{
  const {store,bridge}=fixture(t),pair=bridge.createPair('fixture-app');
  const id=createHash('sha256').update(pair.code).digest('hex');
  store.put('pairings',{...store.get('pairings',id),expiresAt:Date.now()-1});
  store.put('pairingSessions',{...store.get('pairingSessions',pair.pairingId),expiresAt:Date.now()-1});
  const other=bridge.createPair('fixture-app');bridge.pair({code:other.code,origin:'https://example.com'});
  const status=bridge.status(pair.pairingId);assert.equal(status.status,'expired');assert.equal(status.connectionId,undefined);
  assert.throws(()=>bridge.pair({code:pair.code,origin:'https://example.com'}),/expired/);
});
test('paired session status survives restart and reports its own revoked or unavailable connection truthfully',t=>{
  const {store,bridge,catalog}=fixture(t),pair=bridge.createPair('fixture-app');
  const {connection}=bridge.pair({code:pair.code,origin:'https://example.com'});
  bridge.close();const restarted=new BrowserBridge({store,catalog});t.after(()=>restarted.close());
  assert.equal(restarted.status(pair.pairingId).connectionId,connection.id);
  store.put('connections',{...connection,status:'unavailable'});
  assert.equal(restarted.status(pair.pairingId).status,'paired');assert.equal(restarted.status(pair.pairingId).connectionStatus,'unavailable');
  store.put('connections',{...connection,status:'revoked'});
  const status=restarted.status(pair.pairingId);assert.equal(status.status,'revoked');assert.equal(status.connectionStatus,undefined);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../lib/store.mjs';
import {LocalDriver,workspaceCapabilities} from '../lib/local-driver.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {HeartbeatScheduler} from '../lib/heartbeat.mjs';
import {BrowserBridge} from '../lib/browser-bridge.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';

async function setup(t) {
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-runtime-'));const store=new Store({dataDir:dir});const local=new LocalDriver(path.join(dir,'workspace'));await local.init();
  for(const c of workspaceCapabilities) store.put('capabilities',c);
  store.put('connections',{id:'local',appId:'workspace',driver:'workspace',status:'ready',identity:{id:'test-workspace'}});
  const runtime=new Runtime({store,local,connections:{credentials:async()=>({headers:{Authorization:'Bearer test-only'},allowedOrigins:['https://api.example.com']})}});
  t.after(async()=>{store.close();await rm(dir,{recursive:true,force:true});});return {store,local,runtime,dir};
}
test('real local write requires exact approval and independently reads back bytes',async t=>{
  const {runtime,local}=await setup(t);const j=await runtime.createJob({connectionId:'local',capabilityId:'workspace.write.v1',args:{path:'test.txt',content:'Real persisted file'}});
  assert.equal(j.status,'awaiting_approval');assert.equal((await local.snapshot('test.txt')).exists,false);
  await assert.rejects(runtime.approve(j.id,'wrong'),/exact action/);
  const done=await runtime.approve(j.id,j.approvalDigest);assert.equal(done.status,'succeeded');assert.equal(done.result.verification.status,'verified');assert.equal(await readFile(path.join(local.root,'test.txt'),'utf8'),'Real persisted file');
  await assert.rejects(runtime.approve(j.id,j.approvalDigest),/not awaiting/);
});
test('approval is invalidated by changed target contents, account, or capability',async t=>{
  const {runtime,local,store}=await setup(t);
  const args={path:'changed.txt',content:'requested'};
  const j=await runtime.createJob({connectionId:'local',capabilityId:'workspace.write.v1',args});await writeFile(path.join(local.root,args.path),'concurrent');
  assert.notEqual((await runtime.approve(j.id,j.approvalDigest)).status,'succeeded');assert.equal(await readFile(path.join(local.root,args.path),'utf8'),'concurrent');
  const k=await runtime.createJob({connectionId:'local',capabilityId:'workspace.write.v1',args:{path:'new.txt',content:'x'}});store.put('connections',{...store.get('connections','local'),identity:{id:'different'}});assert.equal((await runtime.approve(k.id,k.approvalDigest)).status,'failed');
});
test('workspace rejects traversal, symlinks and mismatched application route',async t=>{
  const {local,runtime,dir,store}=await setup(t);for(const name of ['../secret','.env','nested/file','/tmp/file','a..b']) await assert.rejects(local.resolve(name));
  const outside=path.join(dir,'outside.txt');await writeFile(outside,'private');await symlink(outside,path.join(local.root,'link.txt'));await assert.rejects(local.resolve('link.txt'),/symlink/);
  store.put('connections',{id:'wrong',appId:'github',driver:'http',status:'ready'});await assert.rejects(runtime.createJob({connectionId:'wrong',capabilityId:'workspace.list.v1'}),/does not belong/);
});
test('restart records interrupted execution as uncertain rather than replaying writes',async t=>{
  const {runtime,store}=await setup(t);store.put('jobs',{id:'interrupted',status:'running'});runtime.recover();assert.equal(store.get('jobs','interrupted').status,'uncertain');
});
test('revoked connection and malformed arguments fail before execution',async t=>{
  const {runtime,store}=await setup(t);await assert.rejects(runtime.createJob({connectionId:'local',capabilityId:'workspace.read.v1',args:{path:4}}));store.put('connections',{...store.get('connections','local'),status:'revoked'});await assert.rejects(runtime.createJob({connectionId:'local',capabilityId:'workspace.list.v1'}),/not ready/);
});
test('HTTP write response alone remains uncertain and is never retried',async t=>{
  const {runtime,store}=await setup(t);const document={openapi:'3.0.3',info:{title:'Fixture',version:'1'},servers:[{url:'https://api.example.com'}],paths:{'/items':{post:{operationId:'createItem',responses:{200:{description:'Created'}}}}}};
  const cap=compileOpenApi({appId:'fixture',document}).capabilities[0];store.put('capabilities',{...cap,status:'active'});store.put('connections',{id:'fixture',appId:'fixture',driver:'http',status:'ready',identity:{id:'fixture'}});
  let calls=0;runtime.request=async()=>{calls++;return {status:200,data:{id:'42'}};};
  const j=await runtime.createJob({connectionId:'fixture',capabilityId:cap.id,args:{}});assert.equal(calls,0);const done=await runtime.approve(j.id,j.approvalDigest);assert.equal(done.status,'uncertain');assert.equal(calls,1);
});
test('heartbeat wakes, persists next tick, coalesces downtime, and rejects write schedules',async t=>{
  const {runtime,store}=await setup(t);let clock=100_000;const scheduler=new HeartbeatScheduler({store,runtime,checkConnection:async id=>store.get('connections',id),clock:()=>clock});
  assert.throws(()=>scheduler.create({name:'no',intervalSeconds:10}));assert.throws(()=>scheduler.create({name:'no writes',intervalSeconds:30,connectionId:'local',capabilityId:'workspace.write.v1'}),/read-only/);
  const h=scheduler.create({name:'Observe files',intervalSeconds:30,connectionId:'local',capabilityId:'workspace.list.v1'});await scheduler.tick();assert.equal(store.get('heartbeats',h.id).runs,0);
  clock+=30000;await scheduler.tick();assert.equal(store.get('heartbeats',h.id).runs,1);assert.equal(store.get('heartbeats',h.id).lastResult.status,'succeeded');
  clock+=86400000;await scheduler.tick();assert.equal(store.get('heartbeats',h.id).runs,2);scheduler.setEnabled(h.id,false);clock+=30000;await scheduler.tick();assert.equal(store.get('heartbeats',h.id).runs,2);
});
test('browser pairing is one-time origin-bound and observations require paired authority',async t=>{
  const {store}=await setup(t);const bridge=new BrowserBridge({store,catalog:()=>[{id:'test',webOrigins:['https://example.com']}]});t.after(()=>bridge.close());
  const pair=bridge.createPair('test');assert.throws(()=>bridge.pair({code:pair.code,origin:'https://attacker.example'}),/does not match/);
  const linked=bridge.pair({code:pair.code,origin:'https://example.com'});assert.equal(linked.connection.status,'session_ready');assert.throws(()=>bridge.pair({code:pair.code,origin:'https://example.com'}),/already used/);assert.throws(()=>bridge.poll('incorrect'),/revoked or unknown/);
  const result=bridge.execute(linked.connection.id,{op:'observe'},{});const {command}=bridge.poll(linked.token);assert.equal(command.origin,'https://example.com');bridge.result(linked.token,{id:command.id,ok:true,data:{origin:'https://example.com',title:'Actual fixture observation'}});assert.equal((await result).verification.status,'observed');
  store.put('connections',{...linked.connection,status:'revoked'});assert.throws(()=>bridge.poll(linked.token),/revoked or unknown/);
});

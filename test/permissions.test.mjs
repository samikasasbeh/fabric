import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,readdir} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {Store} from '../lib/store.mjs';
import {PermissionManager,capabilityPermissionHash} from '../lib/permissions.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {HeartbeatScheduler} from '../lib/heartbeat.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {BrowserBridge} from '../lib/browser-bridge.mjs';
import {LocalDriver,workspaceCapabilities} from '../lib/local-driver.mjs';

async function fixture(t) {
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-permissions-')),store=new Store({dataDir:dir});
  t.after(async()=>{store.close();await rm(dir,{recursive:true,force:true});});
  const document={openapi:'3.0.3',info:{title:'Permission test fixture',version:'1'},servers:[{url:'https://api.example.com'}],paths:{'/items':{get:{operationId:'listItems',parameters:[{name:'limit',in:'query',schema:{type:'integer',minimum:1,maximum:20}}],responses:{200:{description:'Read'}}},post:{operationId:'createItem',responses:{200:{description:'Created'}}},delete:{operationId:'deleteItems',responses:{200:{description:'Deleted'}}}}}};
  const caps=compileOpenApi({appId:'fixture',document}).capabilities.map(cap=>({...cap,status:'active'}));
  for(const cap of caps) store.put('capabilities',cap);
  const read=caps.find(cap=>cap.request.method==='GET'),write=caps.find(cap=>cap.request.method==='POST'),del=caps.find(cap=>cap.request.method==='DELETE');
  const connection={id:'account-1',appId:'fixture',driver:'http',authMethod:'token',authRevision:'first-authorization',status:'ready',identity:{id:'user-1'},allowedOrigins:['https://api.example.com'],createdAt:new Date().toISOString()};
  store.put('connections',connection);
  const permissions=new PermissionManager({store}),calls=[];
  const connections={credentials:async()=>({headers:{Authorization:'Bearer private-fixture-token'},allowedOrigins:['https://api.example.com']})};
  const runtime=new Runtime({store,connections,permissions,request:async request=>{calls.push(request);return {status:200,data:{id:'item-1',items:[]}};}});
  const map=(operations,history=operations.map(op=>op.capabilityId))=>store.put('applicationMaps',{id:'fixture',operations,historicalCapabilityIds:history});
  const set=mode=>permissions.set({connectionId:connection.id,capabilityId:read.id,mode});
  return {dir,store,connection,permissions,runtime,connections,calls,read,write,del,map,set};
}

test('effective rows expose read Allow, write/delete Ask and unknown token scopes truthfully',async t=>{
  const {connection,permissions,read,write,del}=await fixture(t);
  const rows=permissions.list(connection.id);
  assert.equal(rows.length,3);
  assert.equal(rows.find(row=>row.capabilityId===read.id).mode,'allow');
  assert.equal(rows.find(row=>row.capabilityId===write.id).mode,'ask');
  const deletion=rows.find(row=>row.capabilityId===del.id);
  assert.equal(deletion.mode,'ask');assert.equal(deletion.effect,'delete');
  for(const row of rows) {assert.equal(row.providerAccess,'unknown');assert.equal(row.status,'active');assert.equal(row.policySource,'default');}
});
test('Deny blocks reads and writes before dispatch or job creation',async t=>{
  const {store,connection,permissions,runtime,calls,read,write}=await fixture(t);
  for(const cap of [read,write]) {
    const row=permissions.set({connectionId:connection.id,capabilityId:cap.id,mode:'deny'});
    assert.equal(row.executable,false);
    await assert.rejects(runtime.createJob({connectionId:connection.id,capabilityId:cap.id}),/denied/);
  }
  assert.equal(calls.length,0);assert.equal(store.list('jobs').length,0);
});
test('read Ask requires an exact digest-bound single-action approval',async t=>{
  const {connection,runtime,calls,read,set}=await fixture(t);set('ask');
  const pending=await runtime.createJob({connectionId:connection.id,capabilityId:read.id,args:{limit:2}});
  assert.equal(pending.status,'awaiting_approval');assert.equal(calls.length,0);
  await assert.rejects(runtime.approve(pending.id,'not-the-action-digest'),/exact action/);
  const completed=await runtime.approve(pending.id,pending.approvalDigest);
  assert.equal(completed.status,'succeeded');assert.equal(completed.approvedBy,'single-action');assert.equal(calls.length,1);
  await assert.rejects(runtime.approve(pending.id,pending.approvalDigest),/not awaiting/);
});
test('editing the arguments of a pending read Ask invalidates approval',async t=>{
  const {store,connection,runtime,calls,read,set}=await fixture(t);set('ask');
  const pending=await runtime.createJob({connectionId:connection.id,capabilityId:read.id,args:{limit:2}});
  store.put('jobs',{...pending,args:{limit:20}});
  await assert.rejects(runtime.approve(pending.id,pending.approvalDigest),/exact action/);assert.equal(calls.length,0);
});
test('write Allow is real standing consent, bounded per job and never replayed',async t=>{
  const {connection,permissions,runtime,calls,write}=await fixture(t);
  const row=permissions.set({connectionId:connection.id,capabilityId:write.id,mode:'allow'});
  assert.equal(row.mode,'allow');assert.equal(row.providerAccess,'unknown');
  const result=await runtime.createJob({connectionId:connection.id,capabilityId:write.id});
  assert.equal(calls.length,1);assert.equal(result.status,'uncertain');assert.equal(result.approvedBy,'standing-policy');
  assert.equal(result.approvalDigest,runtime.digest(result));
  await assert.rejects(runtime.approve(result.id,result.approvalDigest),/not awaiting/);
  await assert.rejects(runtime.execute(result.id),/not queued/);assert.equal(calls.length,1);
});
test('local Allow cannot manufacture missing provider OAuth scopes',async t=>{
  const {store,connection,permissions,runtime,calls,read,map}=await fixture(t);
  store.put('connections',{...connection,authMethod:'oauth',scopes:['unrelated-scope']});
  map([{capabilityId:read.id,support:'candidate',requiredScopes:['items.read','items.all']}]);
  const decision=permissions.set({connectionId:connection.id,capabilityId:read.id,mode:'allow'});
  assert.equal(decision.providerAccess,'missing');assert.equal(decision.executable,false);
  await assert.rejects(runtime.createJob({connectionId:connection.id,capabilityId:read.id}),/required provider scope/);assert.equal(calls.length,0);
  store.put('connections',{...store.get('connections',connection.id),scopes:['items.all']});
  assert.equal(permissions.decision(connection,read).providerAccess,'granted');
  assert.equal((await runtime.createJob({connectionId:connection.id,capabilityId:read.id})).status,'succeeded');
});
test('OpenAPI scopeSets preserve OR of AND requirements instead of weakening to a flat OR',async t=>{
  const {store,connection,permissions,read,map}=await fixture(t);
  map([{capabilityId:read.id,support:'candidate',requiredScopes:['items.read','identity.read','admin'],scopeSets:[['items.read','identity.read'],['admin']]}]);
  for(const [scopes,expected] of [[['items.read'],'missing'],[['items.read','identity.read'],'granted'],[['admin'],'granted']]) {
    store.put('connections',{...connection,authMethod:'oauth',scopes});
    assert.equal(permissions.decision(connection,read).providerAccess,expected);
  }
});
test('provider scopes are rechecked after asynchronous credential renewal before dispatch',async t=>{
  const {store,connection,runtime,connections,calls,read,map}=await fixture(t);
  store.put('connections',{...connection,authMethod:'oauth',scopes:['items.read']});
  map([{capabilityId:read.id,support:'candidate',requiredScopes:['items.read']}]);
  const original=connections.credentials;
  connections.credentials=async()=>{store.put('connections',{...store.get('connections',connection.id),scopes:[]});return original();};
  const result=await runtime.createJob({connectionId:connection.id,capabilityId:read.id});
  assert.equal(result.status,'failed');assert.match(result.error,/required provider scope/);assert.equal(calls.length,0);
});
test('Deny received during credential acquisition stops the pending dispatch',async t=>{
  const {connection,runtime,connections,calls,read,set}=await fixture(t);
  const original=connections.credentials;connections.credentials=async()=>{set('deny');return original();};
  const result=await runtime.createJob({connectionId:connection.id,capabilityId:read.id});
  assert.equal(result.status,'failed');assert.match(result.error,/denied/);assert.equal(calls.length,0);
});
test('reconnect, account identity and immutable schema drift invalidate saved standing permission',async t=>{
  const {store,connection,permissions,write}=await fixture(t);
  permissions.set({connectionId:connection.id,capabilityId:write.id,mode:'allow'});
  assert.equal(permissions.decision(connection,write).mode,'allow');
  store.put('connections',{...connection,authRevision:'new-consent'});
  let row=permissions.decision(connection,write);assert.equal(row.stale,true);assert.equal(row.mode,'ask');
  store.put('connections',{...connection,identity:{id:'another-user'}});
  row=permissions.decision(connection,write);assert.equal(row.stale,true);assert.equal(row.mode,'ask');
  store.put('connections',connection);
  row=permissions.decision(connection,{...write,description:'changed operation definition'});assert.equal(row.stale,true);assert.equal(row.mode,'ask');
});
test('reconnect invalidates a pending one-shot approval even for the same provider account',async t=>{
  const {store,connection,runtime,calls,write}=await fixture(t);
  const pending=await runtime.createJob({connectionId:connection.id,capabilityId:write.id});
  store.put('connections',{...connection,authRevision:'new-consent'});
  const result=await runtime.approve(pending.id,pending.approvalDigest);
  assert.equal(result.status,'failed');assert.match(result.error,/authorization or permission setting changed/);assert.equal(calls.length,0);
});
test('candidate permission changes never promote or execute a capability; promotion does not change immutable binding',async t=>{
  const {store,connection,permissions,runtime,read}=await fixture(t);
  const candidate={...read,status:'candidate'};store.put('capabilities',candidate);
  // Ask is not this read's default, so it is saved (choosing a default stores nothing).
  const decision=permissions.set({connectionId:connection.id,capabilityId:read.id,mode:'ask'});
  assert.equal(decision.status,'candidate');assert.equal(decision.executable,false);assert.equal(store.get('capabilities',read.id).status,'candidate');
  await assert.rejects(runtime.createJob({connectionId:connection.id,capabilityId:read.id}),/reviewed, active/);
  assert.equal(capabilityPermissionHash(candidate),capabilityPermissionHash(read));
  store.put('capabilities',read);assert.equal(permissions.decision(connection,read).policySource,'saved');
});
test('rediscovery removes or disables mapped actions without disabling unrelated hand imports',async t=>{
  const {connection,permissions,runtime,read,write,map}=await fixture(t);
  map([{capabilityId:read.id,support:'candidate',requiredScopes:[]}]);
  assert.equal(permissions.decision(connection,read).status,'active');
  map([],[read.id]);
  assert.equal(permissions.decision(connection,read).status,'removed');
  await assert.rejects(runtime.createJob({connectionId:connection.id,capabilityId:read.id}),/absent from the current application map/);
  assert.equal(permissions.decision(connection,write).status,'active');
  map([{capabilityId:read.id,support:'unsupported',requiredScopes:[]}]);
  assert.equal(permissions.decision(connection,read).status,'unsupported');
  await assert.rejects(runtime.createJob({connectionId:connection.id,capabilityId:read.id}),/unsupported/);
});
test('heartbeat refuses Ask/Deny, obeys policy changes, and does not inherit a reconnected authorization',async t=>{
  const {store,connection,runtime,calls,read,set}=await fixture(t);let clock=100000;
  const scheduler=new HeartbeatScheduler({store,runtime,clock:()=>clock,checkConnection:async()=>connection});
  set('ask');assert.throws(()=>scheduler.create({name:'Asks',intervalSeconds:30,connectionId:connection.id,capabilityId:read.id}),/Ask and Deny/);
  set('deny');assert.throws(()=>scheduler.create({name:'Denied',intervalSeconds:30,connectionId:connection.id,capabilityId:read.id}),/denied/);
  set('allow');const scheduled=scheduler.create({name:'Allowed',intervalSeconds:30,connectionId:connection.id,capabilityId:read.id});
  set('ask');clock+=30000;await scheduler.tick();assert.equal(calls.length,0);assert.equal(store.get('heartbeats',scheduled.id).lastResult.status,'failed');
  set('allow');clock+=30000;await scheduler.tick();assert.equal(calls.length,1);
  store.put('connections',{...connection,authRevision:'new-authorization'});clock+=30000;await scheduler.tick();
  assert.equal(calls.length,1);assert.match(store.get('heartbeats',scheduled.id).lastResult.error,/requires approval|authorization or operation definition changed/);
});
test('browser observations default to Ask while workspace scopes are local',async t=>{
  const {store,permissions}=await fixture(t);
  const browser={id:'browser-account',appId:'browser',driver:'browser',status:'session_ready',identity:{id:'paired-tab'}};
  const cap={id:'browser-observe',appId:'browser',driver:'browser',status:'active',action:{op:'observe'},name:'Observe paired tab'};
  store.put('connections',browser);store.put('capabilities',cap);
  assert.equal(permissions.decision(browser,cap).mode,'ask');assert.equal(permissions.decision(browser,cap).providerAccess,'unknown');
  const local={id:'workspace-account',appId:'workspace',driver:'workspace',status:'ready',identity:{id:'local-workspace'}};
  store.put('connections',local);
  assert.equal(permissions.decision(local,{...cap,id:'workspace-read',appId:'workspace',driver:'workspace',action:{op:'read'}}).providerAccess,'local');
});
test('stale Deny stays denied and a stale write Allow becomes Ask rather than silently broadening',async t=>{
  const {store,connection,permissions,read,write,set}=await fixture(t);
  set('deny');store.put('connections',{...connection,authRevision:'reauthorized'});
  let decision=permissions.decision(connection,read);assert.equal(decision.stale,true);assert.equal(decision.mode,'deny');assert.equal(decision.executable,false);
  permissions.set({connectionId:connection.id,capabilityId:write.id,mode:'allow'});store.put('connections',{...connection,authRevision:'authorized-again'});
  decision=permissions.decision(connection,write);assert.equal(decision.stale,true);assert.equal(decision.mode,'ask');assert.equal(decision.requiresApproval,true);
});
test('choosing an operation\'s default follows it and a reset returns saved settings to their defaults',async t=>{
  const {store,connection,permissions,read,write,set}=await fixture(t);
  const saved=()=>store.list('permissions').filter(policy=>policy.connectionId===connection.id&&!policy.followsDefault).map(policy=>policy.capabilityId).sort();
  set('allow');assert.deepEqual(saved(),[],'Allow is a read\'s default, so it follows the default');
  assert.equal(permissions.decision(connection,read).policySource,'default');
  set('ask');assert.deepEqual(saved(),[read.id]);
  set('allow');assert.deepEqual(saved(),[],'returning to the default follows it again');
  permissions.set({connectionId:connection.id,capabilityId:write.id,mode:'ask'});assert.deepEqual(saved(),[],'Ask is a write\'s default');
  permissions.set({connectionId:connection.id,capabilityId:write.id,mode:'allow'});set('deny');
  assert.deepEqual(saved(),[read.id,write.id].sort());
  assert.equal(permissions.reset({connectionId:connection.id,capabilityIds:[read.id]}),1);assert.deepEqual(saved(),[write.id]);
  assert.equal(permissions.reset({connectionId:connection.id}),1);assert.deepEqual(saved(),[]);
  assert.equal(permissions.decision(connection,write).mode,'ask');assert.equal(permissions.decision(connection,read).mode,'allow');
  const reset=store.list('activity').filter(event=>event.type==='permission.reset');
  assert.deepEqual(reset.map(event=>event.count),[1,1]);
});
test('a queued browser command is cancelled if its permission is denied before extension polling',async t=>{
  const {store,runtime,permissions}=await fixture(t);
  const bridge=new BrowserBridge({store,catalog:()=>[{id:'browser-fixture',webOrigins:['https://example.com']}]});t.after(()=>bridge.close());runtime.browser=bridge;
  const pair=bridge.createPair('browser-fixture'),linked=bridge.pair({code:pair.code,origin:'https://example.com'}),capabilityId='browser-fixture.browser.observe.v1';
  const pending=await runtime.createJob({connectionId:linked.connection.id,capabilityId});
  assert.equal(pending.status,'awaiting_approval');
  const resultPromise=runtime.approve(pending.id,pending.approvalDigest);
  assert.equal(store.list('browserCommands').filter(c=>c.status==='queued').length,1);
  permissions.set({connectionId:linked.connection.id,capabilityId,mode:'deny'});
  assert.equal(bridge.poll(linked.token).command,null);
  const result=await resultPromise;assert.equal(result.status,'failed');assert.match(result.error,/denied/);
  assert.equal(store.list('browserCommands')[0].status,'cancelled');
});
test('browser restart expires queued and dispatched work and never dispatches orphaned commands',async t=>{
  const {store}=await fixture(t);
  const first=new BrowserBridge({store,catalog:()=>[{id:'browser-fixture',webOrigins:['https://example.com']}]});
  const pair=first.createPair('browser-fixture'),linked=first.pair({code:pair.code,origin:'https://example.com'});
  for(const status of ['queued','dispatched']) store.put('browserCommands',{id:`before-restart-${status}`,connectionId:linked.connection.id,status,action:{op:'observe'},args:{}});
  const restarted=new BrowserBridge({store,catalog:()=>[]});t.after(()=>{first.close();restarted.close();});
  assert.equal(store.list('browserCommands').every(c=>c.status==='expired'),true);
  assert.equal(restarted.poll(linked.token).command,null);
  store.put('browserCommands',{id:'orphan-after-start',connectionId:linked.connection.id,status:'queued',action:{op:'observe'},args:{}});
  assert.equal(restarted.poll(linked.token).command,null);assert.equal(store.get('browserCommands','orphan-after-start').status,'expired');
});
test('local write rechecks current permission immediately before atomic rename',async t=>{
  const {dir,store,runtime,permissions}=await fixture(t);
  const local=new LocalDriver(path.join(dir,'workspace'));await local.init();runtime.local=local;
  for(const cap of workspaceCapabilities) store.put('capabilities',cap);
  store.put('connections',{id:'local',appId:'workspace',driver:'workspace',status:'ready',identity:{id:local.root}});
  const pending=await runtime.createJob({connectionId:'local',capabilityId:'workspace.write.v1',args:{path:'denied.txt',content:'Must not be committed'}});
  const original=local.snapshot.bind(local);let snapshots=0;
  local.snapshot=async name=>{const value=await original(name);snapshots++;if(snapshots===2) permissions.set({connectionId:'local',capabilityId:'workspace.write.v1',mode:'deny'});return value;};
  const result=await runtime.approve(pending.id,pending.approvalDigest);
  assert.notEqual(result.status,'succeeded');assert.match(result.error,/denied/);
  await assert.rejects(readFile(path.join(local.root,'denied.txt')),error=>error.code==='ENOENT');
  assert.deepEqual(await readdir(local.root),[]);
});

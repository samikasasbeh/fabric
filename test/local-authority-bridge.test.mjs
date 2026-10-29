import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {Store} from '../lib/store.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {LocalDriver,workspaceCapabilities} from '../lib/local-driver.mjs';
import {HeartbeatScheduler} from '../lib/heartbeat.mjs';
import {compileOpenApi,finalizeCapability} from '../lib/compiler.mjs';
import {createApp} from '../server.mjs';

const owner={schemaVersion:1,id:'fixture-owner',kind:'local_owner',scope:{schemaVersion:1,kind:'local',localOwnerId:'fixture-owner'}};
const other={schemaVersion:1,id:'other-owner',kind:'local_owner',scope:{schemaVersion:1,kind:'local',localOwnerId:'other-owner'}};
function deferred(){let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};}
async function fixture(t){
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-authority-bridge-'));
  let store=new Store({dataDir:dir,localAuthority:'new'}),time=Date.parse('2026-10-11T00:00:00.000Z');
  const clock=()=>time,local=new LocalDriver(path.join(dir,'workspace'));await local.init();
  for(const cap of workspaceCapabilities)store.put('capabilities',cap);
  const connection={id:'local',appId:'workspace',driver:'workspace',authMethod:'workspace',status:'ready',authRevision:'first',identity:{id:'fixture'},createdAt:new Date(time).toISOString()};
  store.put('connections',connection);
  const make=()=>new Runtime({store,local,clock,ownerPrincipal:owner});let runtime=make();
  t.after(async()=>{store.close();await rm(dir,{recursive:true,force:true});});
  return {dir,local,connection,clock,get store(){return store;},get runtime(){return runtime;},advance(ms){time+=ms;},restart(){store.close();store=new Store({dataDir:dir,localAuthority:'require'});runtime=make();},write:()=>runtime.createJob({connectionId:'local',capabilityId:'workspace.write.v1',args:{path:'test.txt',content:'fixture bytes'}},owner)};
}

test('accepted local requests require a separate trusted caller and exact owner approval',async t=>{
  const f=await fixture(t),input={connectionId:'local',capabilityId:'workspace.list.v1'};
  await assert.rejects(f.runtime.createJob(input),/identity/);
  await assert.rejects(f.runtime.createJob(input,other),/owner/);
  await assert.rejects(f.runtime.createJob({...input,principal:owner},owner),/Unexpected/);
  const pending=await f.write();
  assert.equal(pending.executionRequest.principal.id,owner.id);assert.equal(pending.executionRequest.access.generation,1);
  assert.equal(pending.executionRequest.policyRevision,1);assert.ok(Object.isFrozen(pending.executionRequest));
  await assert.rejects(f.runtime.approve(pending.id,pending.approvalDigest,other),/owner/);
  const completed=await f.runtime.approve(pending.id,pending.approvalDigest,owner);
  assert.equal(completed.status,'succeeded');assert.equal(completed.executionApproval.approver.id,owner.id);
  assert.equal(await readFile(path.join(f.local.root,'test.txt'),'utf8'),'fixture bytes');
});

test('policy away and back with the original legacy record cannot restore an approval after restart',async t=>{
  const f=await fixture(t),p=f.runtime.permissions;
  p.set({connectionId:'local',capabilityId:'workspace.write.v1',mode:'ask'});
  const id=p.policyId('local','workspace.write.v1'),saved=f.store.get('permissions',id),pending=await f.write();
  f.store.put('permissions',{...saved,mode:'deny'});f.store.put('permissions',saved);f.restart();
  await assert.rejects(f.runtime.approve(pending.id,pending.approvalDigest,owner),/policy revision/);
  assert.equal((await f.local.snapshot('test.txt')).exists,false);
  const fresh=await f.write();assert.ok(fresh.executionRequest.policyRevision>pending.executionRequest.policyRevision);
  assert.equal((await f.runtime.approve(fresh.id,fresh.approvalDigest,owner)).status,'succeeded');
});

test('account ABA, revoke restore and delete recreate cannot restore accepted authorization',async t=>{
  for(const change of ['account','revoke','delete']){
    const f=await fixture(t),pending=await f.write();
    if(change==='account')f.store.put('connections',{...f.connection,identity:{id:'other'}});
    else if(change==='revoke')f.store.put('connections',{...f.connection,status:'revoked'});
    else f.store.delete('connections','local');
    f.store.put('connections',f.connection);
    await assert.rejects(f.runtime.approve(pending.id,pending.approvalDigest,owner),/generation/);
    assert.equal((await f.local.snapshot('test.txt')).exists,false);
  }
});

test('health-only changes retain usable accepted requests but historical jobs have no fabricated authority',async t=>{
  const f=await fixture(t),pending=await f.write();
  f.store.put('connections',{...f.connection,lastCheckedAt:'2026-10-11T00:00:01Z',error:null,expiresAt:12345});
  assert.equal((await f.runtime.approve(pending.id,pending.approvalDigest,owner)).status,'succeeded');
  const historical=await f.write();delete historical.executionRequest;delete historical.executionRequestHash;
  historical.approvalDigest=f.runtime.digest(historical);f.store.put('jobs',historical);
  await assert.rejects(f.runtime.approve(historical.id,historical.approvalDigest,owner),/execution contract/);
});

test('preview awaits freeze caller input and recheck authority before persisting a proposal',async t=>{
  const f=await fixture(t),entered=deferred(),resume=deferred(),snapshot=f.local.snapshot.bind(f.local);
  f.local.snapshot=async name=>{entered.resolve();await resume.promise;return snapshot(name);};
  const input={connectionId:'local',capabilityId:'workspace.write.v1',args:{path:'test.txt',content:'original'}};
  const work=f.runtime.createJob(input,owner);await entered.promise;input.args.content='changed by caller';
  f.store.put('connections',{...f.connection,identity:{id:'other'}});f.store.put('connections',f.connection);resume.resolve();
  await assert.rejects(work,/generation/);assert.equal(f.store.list('jobs').length,0);
  f.local.snapshot=snapshot;
  const ready=await f.runtime.createJob(input,owner);input.args.content='later mutation';
  assert.equal(ready.executionRequest.args.content,'changed by caller');assert.equal(ready.args.content,'changed by caller');
});

function httpFixture(f,method='GET',readback=false){
  const doc={openapi:'3.0.3',info:{title:'Isolated fixture',version:'1'},servers:[{url:'https://api.example.com'}],paths:{'/items':{[method.toLowerCase()]:{operationId:'items',responses:{200:{description:'OK'}}}}}};
  let cap=compileOpenApi({appId:'fixture',document:doc}).capabilities[0];
  if(readback)cap=finalizeCapability({...cap,verification:{kind:'http-readback',description:'Fixture item',request:{method:'GET',url:'https://api.example.com/items/{itemId}',pathParameters:['itemId'],queryParameters:[]},bindings:{itemId:{from:'response',pointer:'/id',schema:{type:'string'}}},assertions:[{pointer:'/id',equalsResponse:'/id'}]}});
  f.store.put('capabilities',{...cap,status:'active'});const connection={id:'api',appId:'fixture',driver:'http',status:'ready',identity:{id:'fixture-account'},allowedOrigins:['https://api.example.com']};f.store.put('connections',connection);
  f.runtime.connections={credentials:async()=>({headers:{Authorization:'Bearer fixture-only'},allowedOrigins:['https://api.example.com']})};
  return {cap,connection,input:{connectionId:'api',capabilityId:cap.id,args:{}}};
}

test('post-credential authority change blocks HTTP dispatch',async t=>{
  const f=await fixture(t),h=httpFixture(f);let calls=0;
  f.runtime.connections.credentials=async()=>{f.store.put('connections',{...h.connection,identity:{id:'other'}});f.store.put('connections',h.connection);return {headers:{},allowedOrigins:h.connection.allowedOrigins};};
  f.runtime.request=async()=>{calls++;return {status:200,data:{}};};
  const result=await f.runtime.createJob(h.input,owner);assert.equal(result.status,'failed');assert.equal(result.result,null);assert.equal(calls,0);
});

test('stale read responses are withheld and dispatched writes remain uncertain without credential readback',async t=>{
  for(const method of ['GET','POST','DELETE']){
    const f=await fixture(t),h=httpFixture(f,method,method==='POST');let calls=0,credentials=0;
    f.runtime.connections.credentials=async()=>{credentials++;return {headers:{},allowedOrigins:h.connection.allowedOrigins};};
    f.runtime.request=async()=>{calls++;f.store.put('connections',{...h.connection,status:'revoked'});f.store.put('connections',h.connection);return {status:200,data:{id:'fixture-item',private:'withhold'}};};
    const pending=await f.runtime.createJob(h.input,owner);
    const result=method==='GET'?pending:await f.runtime.approve(pending.id,pending.approvalDigest,owner);
    assert.equal(result.status,method==='GET'?'failed':'uncertain');assert.equal(result.result,null);assert.equal(calls,1);assert.equal(credentials,1);
    assert.equal(result.executionRequest.capability.effect,method==='DELETE'?'delete':method==='GET'?'read':'write');
  }
});

test('policy changes while independent readback is pending discard verification evidence',async t=>{
  const f=await fixture(t),h=httpFixture(f,'POST',true);let calls=0;
  f.runtime.request=async()=>{calls++;if(calls===2){const p=f.runtime.permissions,id=p.policyId('api',h.cap.id);f.store.delete('permissions',id);}return {status:200,data:{id:'fixture-item'}};};
  const pending=await f.runtime.createJob(h.input,owner),done=await f.runtime.approve(pending.id,pending.approvalDigest,owner);
  assert.equal(done.status,'uncertain');assert.equal(done.result,null);assert.equal(calls,2);
});

test('read deadlines apply before credential acquisition and terminal result disclosure',async t=>{
  const f=await fixture(t),h=httpFixture(f);f.runtime.request=async()=>({status:200,data:{id:'fixture-item'}});
  const done=await f.runtime.createJob(h.input,owner);assert.equal(done.status,'succeeded');
  f.advance(600000);assert.throws(()=>f.runtime.assertAcceptedAuthority(done),/deadline/);
});

test('scheduled authority is persisted, rechecked on dispatch and cannot be invented for historical schedules',async t=>{
  const f=await fixture(t),scheduler=new HeartbeatScheduler({store:f.store,runtime:f.runtime,clock:f.clock,checkConnection:async()=>{throw new Error('No health check expected');}});
  f.runtime.authorizeSource=job=>scheduler.assertJobAuthority(job);
  const data={name:'Fixture schedule',intervalSeconds:30,connectionId:'local',capabilityId:'workspace.list.v1'};
  assert.throws(()=>scheduler.create(data),/identity/);
  const scheduled=scheduler.create(data,owner);f.advance(30000);await scheduler.tick();assert.equal(f.store.get('heartbeats',scheduled.id).lastResult.status,'succeeded');
  const p=f.runtime.permissions,id=p.policyId('local','workspace.list.v1');f.store.delete('permissions',id);
  f.advance(30000);await scheduler.tick();assert.equal(f.store.get('heartbeats',scheduled.id).lastResult.status,'failed');assert.equal(f.store.list('jobs').length,1);
  const historical=scheduler.create(data,owner);delete historical.authority;f.store.put('heartbeats',historical);
  f.advance(30000);await scheduler.tick();assert.match(f.store.get('heartbeats',historical.id).lastResult.error,/Historical schedule/);
});

test('browser operations and delegated callers without a trusted resolver fail closed in designated mode',async t=>{
  const f=await fixture(t);
  const client={schemaVersion:1,kind:'local_client',id:'client',scope:owner.scope,delegatedBy:{kind:'local_owner',id:owner.id}};
  await assert.rejects(f.runtime.createJob({connectionId:'local',capabilityId:'workspace.list.v1',source:{kind:'client',clientId:'client',requestId:'request'}},client),/resolver/);
  f.store.put('capabilities',{...workspaceCapabilities[0],id:'browser.read',driver:'browser'});
  await assert.rejects(f.runtime.createJob({connectionId:'local',capabilityId:'browser.read'},owner),/provenance/);
});

async function freePort(){const server=createServer();server.listen(0,'127.0.0.1');await once(server,'listening');const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;}
test('designated mode parks every browser route, including setup, pairing status and saved-profile reads',async t=>{
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-authority-browser-parked-')),port=await freePort();
  const app=await createApp({dataDir:dir,port,localAuthority:{mode:'new',ownerPrincipal:owner}});await app.start();
  t.after(async()=>{await app.close();await rm(dir,{recursive:true,force:true});});
  const response=await fetch(`${app.origin}/api/state`),state=await response.json(),cookie=response.headers.get('set-cookie').split(';')[0];
  const call=(method,route,data)=>fetch(`${app.origin}${route}`,{method,headers:{'content-type':'application/json','x-fabric-csrf':state.csrfToken,cookie},...(data?{body:JSON.stringify(data)}:{})});
  const routes=[['POST','/api/browser/pair',{}],['POST','/api/browser/poll',{}],['POST','/api/browser/result',{}],['POST','/api/pair',{appId:'slack'}],['GET','/api/pair/any/status'],
    ['GET','/api/browser-setup'],['POST','/api/browser-setup',{action:'open-extensions',browser:'chrome',appId:'slack'}],['GET','/api/session-browser'],
    ['POST','/api/session-browser/connect',{appId:'slack'}],['POST','/api/session-browser/any/open',{}]];
  for(const [method,route,data] of routes){
    const result=await call(method,route,data);assert.equal(result.status,400,`${method} ${route}`);
    assert.match((await result.json()).error,/Browser authority provenance is not implemented/,`${method} ${route}`);
  }
  const start=await call('POST','/api/connect/start',{appId:'slack',method:'browser'}),started=await start.json();
  assert.ok(start.status===400||started.connectionEstablished===false,'connect/start never establishes a browser route');
  for(const collection of ['pairings','pairingSessions','browserDevices','browserHelperConsents','browserCommands','persistentSessions','persistentProfileConsents','connections'])
    assert.deepEqual(app.store.list(collection),[],collection);
});
test('isolated HTTP deployment persists exact owner and refuses caller overrides and browser setup',async t=>{
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-authority-http-')),port=await freePort();
  let app=await createApp({dataDir:dir,port,localAuthority:{mode:'new',ownerPrincipal:owner}});await app.start();
  t.after(async()=>{await app.close();await rm(dir,{recursive:true,force:true});});
  const response=await fetch(`${app.origin}/api/state`),state=await response.json(),cookie=response.headers.get('set-cookie').split(';')[0];
  const post=async(route,data)=>fetch(`${app.origin}${route}`,{method:'POST',headers:{'content-type':'application/json','x-fabric-csrf':state.csrfToken,cookie},body:JSON.stringify(data)});
  const connect=await post('/api/connections/local',{}),connection=await connect.json();assert.equal(connect.status,201);
  const input={connectionId:connection.id,capabilityId:'workspace.list.v1'};
  for(const override of [{source:{kind:'user'}},{principal:owner},{scope:owner.scope}])assert.equal((await post('/api/jobs',{...input,...override})).status,400);
  const job=await post('/api/jobs',input);assert.equal(job.status,201);assert.equal((await job.json()).executionRequest.principal.id,owner.id);
  assert.equal((await post('/api/pair',{appId:'slack'})).status,400);
  await app.close();
  await assert.rejects(createApp({dataDir:dir,port,localAuthority:{mode:'require',ownerPrincipal:other}}),/saved deployment owner/);
  app=await createApp({dataDir:dir,port,localAuthority:{mode:'require',ownerPrincipal:owner}});
  assert.equal(app.store.scope.localOwnerId,owner.id);assert.equal(app.store.connectionGeneration(connection.id),1);
});

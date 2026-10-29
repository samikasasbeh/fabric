import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../lib/store.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {compileOpenApi,finalizeCapability} from '../lib/compiler.mjs';
import {createApp} from '../server.mjs';

function fixture(t) {
  const dir=mkdtempSync(join(tmpdir(),'fabric-runtime-clock-'));
  let time=Date.parse('2026-01-02T03:04:05.000Z'),dispatches=0;
  const clock=()=>time,store=new Store({dataDir:dir,clock});
  const document={openapi:'3.0.3',info:{title:'Clock fixture',version:'1'},servers:[{url:'https://api.example.com'}],paths:{'/items':{post:{operationId:'createItem',responses:{200:{description:'Created'}}},get:{operationId:'listItems',responses:{200:{description:'Items'}}}}}};
  const caps=compileOpenApi({appId:'clock-fixture',document}).capabilities;
  for(const cap of caps) store.put('capabilities',{...cap,status:'active'});
  store.put('connections',{id:'connection',appId:'clock-fixture',driver:'http',status:'ready',identity:{id:'fixture-account'}});
  const runtime=new Runtime({store,clock,connections:{credentials:async()=>({headers:{},allowedOrigins:['https://api.example.com']})},request:async()=>{dispatches++;return {status:200,data:{id:'fixture-item'}};}});
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  return {store,runtime,read:caps.find(cap=>cap.request.method==='GET'),write:caps.find(cap=>cap.request.method==='POST'),setTime:value=>{time=value;},time:()=>time,dispatches:()=>dispatches};
}

test('runtime approval expiry is controlled at the exact clock boundary without sleeping',async t=>{
  const f=fixture(t);
  const job=await f.runtime.createJob({connectionId:'connection',capabilityId:f.write.id});
  assert.equal(job.createdAt,new Date(f.time()).toISOString());
  assert.equal(Date.parse(job.approvalExpiresAt),f.time()+600000);
  f.setTime(Date.parse(job.approvalExpiresAt));
  await assert.rejects(f.runtime.approve(job.id,job.approvalDigest),/Approval expired/);
  assert.equal(f.dispatches(),0);
  const next=await f.runtime.createJob({connectionId:'connection',capabilityId:f.write.id});
  f.setTime(Date.parse(next.approvalExpiresAt)-1);
  const done=await f.runtime.approve(next.id,next.approvalDigest);
  assert.equal(done.status,'uncertain');
  assert.equal(done.approvedAt,new Date(f.time()).toISOString());
  assert.equal(f.dispatches(),1);
});

test('runtime result, recovery, cancellation and audit timestamps use the injected clock',async t=>{
  const f=fixture(t),stamp=new Date(f.time()).toISOString();
  const read=await f.runtime.createJob({connectionId:'connection',capabilityId:f.read.id});
  assert.equal(read.status,'succeeded');
  assert.equal(read.updatedAt,stamp);
  assert.equal(read.result.verification.checkedAt,stamp);
  const write=await f.runtime.createJob({connectionId:'connection',capabilityId:f.write.id});
  f.setTime(f.time()+1000);
  assert.equal(f.runtime.cancel(write.id).updatedAt,new Date(f.time()).toISOString());
  f.store.put('jobs',{id:'interrupted',status:'running'});
  f.runtime.recover();
  assert.equal(f.store.get('jobs','interrupted').updatedAt,new Date(f.time()).toISOString());
  assert.equal(f.store.list('activity')[0].createdAt,stamp);
});

test('approval expiry during credential acquisition prevents dispatch under the injected clock',async t=>{
  const f=fixture(t);
  const job=await f.runtime.createJob({connectionId:'connection',capabilityId:f.write.id});
  f.runtime.connections.credentials=async()=>{
    f.setTime(Date.parse(job.approvalExpiresAt));
    return {headers:{},allowedOrigins:['https://api.example.com']};
  };
  const done=await f.runtime.approve(job.id,job.approvalDigest);
  assert.equal(done.status,'failed');
  assert.match(done.error,/no current approval/);
  assert.equal(f.dispatches(),0);
});

test('independent HTTP readback records the injected verification time',async t=>{
  const f=fixture(t);
  const capability=finalizeCapability({...f.store.get('capabilities',f.write.id),verification:{
    kind:'http-readback',description:'Read exact fixture item',
    request:{method:'GET',url:'https://api.example.com/items/{itemId}',pathParameters:['itemId'],queryParameters:[]},
    bindings:{itemId:{from:'response',pointer:'/id',schema:{type:'string'}}},
    assertions:[{pointer:'/id',equalsResponse:'/id'}],
  }});
  f.store.put('capabilities',{...capability,status:'active'});
  const job=await f.runtime.createJob({connectionId:'connection',capabilityId:capability.id});
  const done=await f.runtime.approve(job.id,job.approvalDigest);
  assert.equal(done.status,'succeeded');
  assert.equal(done.result.verification.kind,'http-readback');
  assert.equal(done.result.verification.checkedAt,new Date(f.time()).toISOString());
  assert.equal(f.dispatches(),2);
});

test('runtime browser target freshness uses its clock without changing browser driver timers',t=>{
  const f=fixture(t),connection={id:'browser-connection',allowedOrigins:['https://example.com']};
  f.store.put('jobs',{id:'observation',connectionId:connection.id,status:'succeeded',effect:'read',updatedAt:new Date(f.time()).toISOString(),result:{
    verification:{kind:'paired-browser-dom',status:'observed'},
    data:{snapshotId:'snapshot',origin:'https://example.com',url:'https://example.com/page',expiresAt:new Date(f.time()+120000).toISOString(),controls:[{targetId:'target',canClick:true,label:'Fixture control'}]},
  }});
  const job={source:{kind:'user'},args:{snapshotId:'snapshot',targetId:'target'}},cap={action:{op:'click'}};
  assert.equal(f.runtime.browserTarget(job,connection,cap).label,'Fixture control');
  f.setTime(f.time()+120000);
  assert.throws(()=>f.runtime.browserTarget(job,connection,cap),/Inspect this page again/);
});

test('createApp wires the common clock and local facade without opening a listener or provider',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'fabric-app-clock-'));
  const time=Date.parse('2026-01-02T03:04:05.000Z');
  const app=await createApp({dataDir:dir,clock:()=>time,request:async()=>{throw new Error('No provider requests expected');}});
  t.after(async()=>{await app.close();rmSync(dir,{recursive:true,force:true});});
  assert.equal(app.store.scope.kind,'local');
  assert.equal(app.store.guarantees.tenantIsolation,false);
  for(const owner of [app.connections,app.runtime,app.oauth,app.protocol,app.heartbeats]) assert.equal(owner.clock(),time);
  assert.equal(app.store.audit({type:'clock.fixture'}).createdAt,new Date(time).toISOString());
  assert.equal(app.store.list('heartbeats')[0].createdAt,new Date(time).toISOString());
  assert.equal(app.server.listening,false);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {HeartbeatScheduler} from '../lib/heartbeat.mjs';
import {BrowserBridge} from '../lib/browser-bridge.mjs';
import {compileOpenApi,finalizeCapability} from '../lib/compiler.mjs';
import {createApp} from '../server.mjs';

async function setup(t,{secret='fixture-api-credential-7291'}={}) {
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-security-integration-'));
  const store=new Store({dataDir:dir}),vault=new Vault(dir),connections=new ConnectionManager({store,vault});
  store.put('connections',{id:'fixture-account',appId:'fixture',driver:'http',authMethod:'token',status:'ready',identity:{id:'verified-user'},allowedOrigins:['https://api.example.com']});
  vault.set('fixture-account',{accessToken:secret});
  const runtime=new Runtime({store,connections});
  t.after(async()=>{store.close();await rm(dir,{recursive:true,force:true});});
  return {store,vault,connections,runtime,secret};
}
function capability(method='get') {
  const document={openapi:'3.0.3',info:{title:'Controlled fixture provider',version:'1'},servers:[{url:'https://api.example.com'}],paths:{'/items':{[method]:{operationId:method==='get'?'listItems':'createItem',responses:{200:{description:'Fixture result'}}}}}};
  const cap=compileOpenApi({appId:'fixture',document}).capabilities[0];
  if(method==='post') {
    cap.verification={kind:'http-readback',description:'Read the exact created object',request:{method:'GET',url:'https://api.example.com/items/{itemId}',pathParameters:['itemId'],queryParameters:[]},bindings:{itemId:{from:'response',pointer:'/id',schema:{type:'string'}}},assertions:[{pointer:'/id',equalsResponse:'/id'},{pointer:'/kind',equals:'fixture-item'}]};
  }
  return {...finalizeCapability(cap),status:'active'};
}
test('revoking an HTTP connection during a write prevents a subsequent readback dispatch',async t=>{
  const {store,connections,runtime}=await setup(t);const cap=capability('post');store.put('capabilities',cap);
  const calls=[];
  runtime.request=async request=>{
    calls.push(request.method);
    connections.revoke('fixture-account');
    return {status:200,data:{id:'created-once',kind:'fixture-item'}};
  };
  const prepared=await runtime.createJob({connectionId:'fixture-account',capabilityId:cap.id,args:{}});
  const result=await runtime.approve(prepared.id,prepared.approvalDigest);
  assert.deepEqual(calls,['POST']);
  assert.equal(result.status,'uncertain');
  assert.equal(connections.get('fixture-account').status,'revoked');
  assert.match(result.error,/active API connection|revoked/i);
});
test('revocation during asynchronous credential acquisition prevents the first HTTP dispatch',async t=>{
  const {store,connections,runtime}=await setup(t);const cap=capability();store.put('capabilities',cap);
  const original=connections.credentials.bind(connections);
  connections.credentials=async id=>{const authority=await original(id);connections.revoke(id);return authority;};
  let calls=0;runtime.request=async()=>{calls++;return {status:200,data:{items:[]}};};
  const result=await runtime.createJob({connectionId:'fixture-account',capabilityId:cap.id,args:{}});
  assert.equal(calls,0);assert.equal(result.status,'failed');assert.match(result.error,/authority changed/i);
});
test('provider credential echoes are removed from nested persisted and returned job results',async t=>{
  const {store,runtime,secret}=await setup(t);const cap=capability();store.put('capabilities',cap);
  runtime.request=async()=>({status:200,data:{normal:'safe data',echo:`Bearer ${secret}`,nested:[{value:`prefix ${secret} suffix`,authorization:`Bearer ${secret}`,password:'another-private-value',refresh_token:'other-refresh-value'}]}});
  const result=await runtime.createJob({connectionId:'fixture-account',capabilityId:cap.id,args:{}});
  assert.equal(result.status,'succeeded');assert.equal(result.result.data.normal,'safe data');
  for(const privateValue of [secret,'another-private-value','other-refresh-value']) {
    assert.equal(JSON.stringify(result).includes(privateValue),false);
    assert.equal(JSON.stringify(store.list('jobs')).includes(privateValue),false);
    assert.equal(JSON.stringify(store.list('activity')).includes(privateValue),false);
  }
});
test('short provider credentials and credential-bearing object keys are redacted too',async t=>{
  const {store,runtime,secret}=await setup(t,{secret:'k7Q4x'});const cap=capability();store.put('capabilities',cap);
  runtime.request=async()=>({status:200,data:{[secret]:'key containing the token',echo:secret}});
  const result=await runtime.createJob({connectionId:'fixture-account',capabilityId:cap.id,args:{}});
  assert.equal(result.status,'succeeded');
  assert.equal(JSON.stringify(result).includes(secret),false);
  assert.equal(JSON.stringify(store.list('jobs')).includes(secret),false);
});
test('unverified browser-account capabilities cannot be scheduled or executed by a persisted heartbeat',async t=>{
  const {store,runtime}=await setup(t);
  const bridge=new BrowserBridge({store,catalog:()=>[{id:'browser-fixture',webOrigins:['https://example.com']}]});
  t.after(()=>bridge.close());
  const pair=bridge.createPair('browser-fixture'),linked=bridge.pair({code:pair.code,origin:'https://example.com'});
  const capId='browser-fixture.browser.observe.v1';
  let executions=0;runtime.createJob=async()=>{executions++;return {status:'succeeded'};};
  const scheduler=new HeartbeatScheduler({store,runtime,checkConnection:async id=>store.get('connections',id),clock:()=>100000});
  assert.throws(()=>scheduler.create({name:'Browser data collection',intervalSeconds:30,connectionId:linked.connection.id,capabilityId:capId}),/identity.*not independently bound/i);
  store.put('heartbeats',{id:'legacy-browser-schedule',name:'Previously persisted browser read',intervalSeconds:30,connectionId:linked.connection.id,capabilityId:capId,args:{},enabled:true,nextRunAt:new Date(0).toISOString(),runs:0});
  await scheduler.tick();
  assert.equal(executions,0);assert.equal(store.get('heartbeats','legacy-browser-schedule').lastResult.status,'failed');
});
test('workspace health check cannot reactivate a connection revoked while initialization awaits',async t=>{
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-workspace-revocation-'));
  // No listening server or network required: exercise the exact server-supplied scheduler callback.
  const app=await createApp({dataDir:dir,port:43989});
  t.after(async()=>{await app.close();await rm(dir,{recursive:true,force:true});});
  const connection={id:'workspace-race',appId:'workspace',driver:'workspace',authMethod:'workspace',status:'ready',identity:{id:app.local.root},allowedOrigins:[]};
  app.store.put('connections',connection);
  let release,entered;
  const gate=new Promise(resolve=>{release=resolve;});const started=new Promise(resolve=>{entered=resolve;});
  app.local.init=async()=>{entered();await gate;};
  const pending=app.heartbeats.checkConnection(connection.id);
  await started;app.connections.revoke(connection.id);release();
  await assert.rejects(pending,/revoked during check/);
  assert.equal(app.connections.get(connection.id).status,'revoked');
});

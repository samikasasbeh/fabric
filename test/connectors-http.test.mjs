import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {createApp} from '../server.mjs';

// Real local server and storage; remote provider is an explicitly injected fixture.
test('connector discovery, review, Ask/Deny and machine-readable tools use one enforced backend',async t=>{
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-connectors-http-'));
  const port=43200+Math.floor(Math.random()*250);let reads=0;
  const document={openapi:'3.1.0',info:{title:'Fixture',version:'1'},servers:[{url:'https://api.fixture.example'}],paths:{'/items':{get:{operationId:'listItems',summary:'Read items',responses:{200:{description:'Items',content:{'application/json':{schema:{type:'object',properties:{items:{type:'array',items:{type:'string'}}}}}}}}}}}};
  const request=async req=>{
    if(req.url==='https://docs.fixture.example/openapi.json'){assert.equal(req.headers?.Authorization,undefined);return {status:200,data:structuredClone(document)};}
    if(req.url==='https://api.fixture.example/me')return {status:200,data:{id:'fixture-account',name:'Fixture account'}};
    if(req.url==='https://api.fixture.example/items'){reads++;return {status:200,data:{items:['verified fixture item']}};}
    throw new Error('Unexpected fixture request');
  };
  const app=await createApp({dataDir:dir,port,request});await app.start();
  t.after(async()=>{await app.close();await rm(dir,{recursive:true,force:true});});
  const base=app.origin,boot=await fetch(base+'/api/state'),cookie=boot.headers.get('set-cookie').split(';')[0],state=await boot.json();
  const get=async route=>{const res=await fetch(base+route,{headers:{Cookie:cookie}});return res.json();};
  const post=async(route,data,expected=200)=>{const res=await fetch(base+route,{method:'POST',headers:{'Content-Type':'application/json',Cookie:cookie,'X-Fabric-CSRF':state.csrfToken},body:JSON.stringify(data)});const value=await res.json();assert.equal(res.status,expected,JSON.stringify(value));return value;};
  await post('/api/applications',{id:'connector-fixture',name:'Fixture',apiOrigins:['https://api.fixture.example'],identityProbe:{path:'/me',idPointer:'/id',displayNamePointer:'/name'},discovery:{kind:'openapi',url:'https://docs.fixture.example/openapi.json'}},201);
  const map=await post('/api/discover',{appId:'connector-fixture'});assert.equal(map.operations.length,1);
  const capabilityId=map.operations[0].capabilityId;assert.ok(capabilityId);
  const connection=await post('/api/connections',{appId:'connector-fixture',token:'fixture-only-token'},201);
  const detail=await get('/api/connectors/connector-fixture');assert.equal(detail.map.fingerprint,map.fingerprint);assert.equal(detail.permissionsByConnection[connection.id][0].status,'candidate');
  await post(`/api/connections/${connection.id}/permissions`,{capabilityId,mode:'ask'},400);
  assert.equal(app.store.get('capabilities',capabilityId).status,'candidate');
  await post(`/api/connections/${connection.id}/permissions`,{capabilityId,mode:'ask',review:true});
  const job=await post('/api/jobs',{connectionId:connection.id,capabilityId,args:{}},201);assert.equal(job.status,'awaiting_approval');assert.equal(reads,0);
  const approved=await post(`/api/jobs/${job.id}/approve`,{approvalDigest:job.approvalDigest});assert.equal(approved.status,'succeeded');assert.equal(reads,1);
  const machine=await get(`/api/connectors/connector-fixture/tools?connectionId=${connection.id}`);assert.equal(machine.tools[0].permission.mode,'ask');assert.equal(machine.tools[0].invoke.path,'/api/jobs');assert.equal(JSON.stringify(machine).includes('fixture-only-token'),false);
  await post(`/api/connections/${connection.id}/permissions`,{capabilityId,mode:'deny'});
  await post('/api/jobs',{connectionId:connection.id,capabilityId,args:{}},400);assert.equal(reads,1);
  await post(`/api/connections/${connection.id}/permissions`,{capabilityId,mode:'allow'});
  const reused=await post('/api/acquire',{appId:'connector-fixture',goal:'Read items'},201);assert.equal(reused.mode,'discovered-interface');assert.equal(reused.capabilities[0].id,capabilityId);
  delete document.paths['/items'];document.paths['/items-v2']={get:{operationId:'listItemsV2',responses:{200:{description:'Updated items'}}}};
  await post('/api/discover',{appId:'connector-fixture'});
  await post('/api/jobs',{connectionId:connection.id,capabilityId,args:{}},400);assert.equal(reads,1);
  const history=await get('/api/connectors/connector-fixture/history');assert.equal(history.history.length,2);
});

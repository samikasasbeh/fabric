import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {Store} from '../lib/store.mjs';
import {LocalRepository} from '../lib/repositories/local.mts';
import {LocalDriver, workspaceCapabilities} from '../lib/local-driver.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {FabricProtocol, FABRIC_PROTOCOL} from '../lib/fabric-protocol.mjs';
import {canonicalHash, compileOpenApi} from '../lib/compiler.mjs';
import {validatePrincipal} from '../contracts/identity.mts';

const owner = validatePrincipal({schemaVersion:1,kind:'local_owner',id:'fixture-owner',scope:{schemaVersion:1,kind:'local',localOwnerId:'fixture-owner'}});
const otherOwner = validatePrincipal({schemaVersion:1,kind:'local_owner',id:'other-owner',scope:{schemaVersion:1,kind:'local',localOwnerId:'other-owner'}});
const clientPrincipal = id => ({schemaVersion:1,kind:'local_client',id,scope:owner.scope,delegatedBy:{kind:'local_owner',id:owner.id}});

async function fixture(t) {
  const dir=await mkdtemp(path.join(tmpdir(),'fabric-protocol-authority-'));
  const local=new LocalDriver(path.join(dir,'workspace'));await local.init();
  let now=Date.parse('2026-10-11T10:00:00.000Z'),store,runtime,protocol,requests=0;
  const clock=()=>now;
  const open=mode=>{
    store=new LocalRepository({store:new Store({dataDir:dir,localAuthority:mode,clock}),scope:owner.scope});
    runtime=new Runtime({store,local,ownerPrincipal:owner,clock,
      connections:{credentials:async()=>({headers:{Authorization:'Bearer synthetic-only'},allowedOrigins:['https://fixture.example']})},
      request:async()=>{requests++;return {status:200,data:{id:'synthetic-result'}};}});
    protocol=new FabricProtocol({store,runtime,clock});runtime.authorizeSource=job=>protocol.authorizeJob(job);
  };
  open('new');
  t.after(async()=>{store.close();await rm(dir,{recursive:true,force:true});});
  for(const capability of workspaceCapabilities)store.put('capabilities',capability);
  const connection={id:randomUUID(),appId:'workspace',driver:'workspace',authMethod:'workspace',authRevision:'consent-a',status:'ready',identity:{id:'synthetic-workspace'},allowedOrigins:[],createdAt:new Date(now).toISOString()};
  store.put('connections',connection);
  return {
    dir,local,connection,owner,
    get store(){return store;},get runtime(){return runtime;},get protocol(){return protocol;},get requests(){return requests;},
    advance(ms){now+=ms;},
    reopen(){store.close();open('require');runtime.recover();},
    grant(ids=['workspace.list.v1'],principal=owner,connectionId=connection.id){return protocol.createClient({name:'Synthetic delegated client',bindings:ids.map(capabilityId=>({connectionId,capabilityId}))},principal);},
    invoke(token,method,params={},id=randomUUID()){return protocol.handle(`Bearer ${token}`,{protocol:FABRIC_PROTOCOL,id,method,params});},
    input(client,capabilityId=client.bindings[0].capabilityId,args={}){const binding=client.bindings.find(item=>item.capabilityId===capabilityId);return {connectionId:binding.connectionId,capabilityId,definitionHash:binding.definitionHash,args};},
    policy(mode,capabilityId='workspace.list.v1'){return runtime.permissions.set({connectionId:connection.id,capabilityId,mode});},
  };
}

test('designated protocol requires the configured owner to create grants and derives the authenticated local client',async t=>{
  const f=await fixture(t),data={name:'Client',bindings:[{connectionId:f.connection.id,capabilityId:'workspace.list.v1'}]};
  for(const principal of [undefined,otherOwner,clientPrincipal(randomUUID()),{...owner,scope:otherOwner.scope}])assert.throws(()=>f.protocol.createClient(data,principal),{code:'unauthorized'});
  assert.throws(()=>f.protocol.createClient({...data,ownerPrincipal:owner},owner),{code:'invalid_request'});
  const {client,token}=f.grant(),saved=f.store.get('clientGrants',client.id);
  assert.deepEqual(saved.ownerPrincipal,owner);assert.equal(saved.bindings[0].connectionGeneration,1);
  assert.equal(Object.hasOwn(saved.bindings[0],'policyRevision'),false);
  assert.equal(Object.hasOwn(client,'tokenHash'),false);assert.equal(JSON.stringify(saved).includes(token),false);
  const invalidToken=token.slice(0,-1)+(token.endsWith('a')?'b':'a');
  assert.equal((await f.invoke(invalidToken,'calls.create',f.input(client))).error.code,'unauthorized');
  assert.equal(f.store.list('jobs').length,0);
  const result=await f.invoke(token,'calls.create',f.input(client));assert.equal(result.result.status,'succeeded');
  const job=f.store.get('jobs',result.result.id);
  assert.deepEqual(job.executionRequest.principal,clientPrincipal(client.id));
  assert.equal(job.executionRequest.id,job.id);assert.equal(job.executionRequest.access.generation,1);
  assert.equal(job.executionRequestHash,canonicalHash(job.executionRequest));
  assert.equal(JSON.stringify(result).includes('executionRequest'),false);
});

test('designated grants never delegate a parked browser capability, even when policy allows it',async t=>{
  const f=await fixture(t),connection={id:randomUUID(),appId:'slack',driver:'browser',transport:'helper',bridgeVersion:'0.3',sessionScope:'browser-profile',authMethod:'browser',authRevision:'consent-browser',status:'ready',identity:{id:'synthetic-page'},allowedOrigins:['https://app.slack.com'],createdAt:new Date().toISOString()};
  const capability={id:'slack.browser.read.v1',specVersion:'fabric/0.1',version:1,appId:'slack',driver:'browser',name:'Read a page element',description:'Synthetic read-only browser fixture.',status:'active',effect:'read',action:{op:'read'},
    inputSchema:{type:'object',properties:{selector:{type:'string',minLength:1,maxLength:500}},required:['selector'],additionalProperties:false},provenance:{kind:'builtin',source:'fixture'},verification:{kind:'observed-browser-state'}};
  f.store.put('connections',connection);f.store.put('capabilities',capability);
  f.runtime.permissions.set({connectionId:connection.id,capabilityId:capability.id,mode:'allow'});
  assert.throws(()=>f.protocol.createClient({name:'Browser client',bindings:[{connectionId:connection.id,capabilityId:capability.id}]},owner),{code:'unsupported_route'});
  assert.equal(f.store.list('clientGrants').length,0);
});

test('grant generation rejects restored legacy account hashes and delete-recreate cycles',async t=>{
  for(const mutation of ['account-aba','consent-aba','revoke-ready','delete-recreate'])await t.test(mutation,async t=>{
    const f=await fixture(t),{client,token}=f.grant(),original=f.store.get('connections',f.connection.id);
    if(mutation==='delete-recreate')f.store.delete('connections',original.id);
    else f.store.put('connections',{...original,...(mutation==='account-aba'?{identity:{id:'other-account'}}:mutation==='consent-aba'?{authRevision:'other-consent'}:{status:'revoked'})});
    f.store.put('connections',original);
    assert.equal(f.runtime.permissions.decision(original,f.store.get('capabilities','workspace.list.v1')).bindingHash,client.bindings[0].bindingHash);
    assert.ok(f.store.connectionGeneration(original.id)>client.bindings[0].connectionGeneration);
    assert.equal((await f.invoke(token,'calls.create',f.input(client))).error.code,'grant_changed');
    assert.equal(f.store.list('jobs').length,0);
    const renewed=f.grant();assert.equal((await f.invoke(renewed.token,'calls.create',f.input(renewed.client))).result.status,'succeeded');
  });
});

test('health-only changes preserve client generation and permission changes do not force regrant',async t=>{
  const f=await fixture(t),{client,token}=f.grant();
  f.store.put('connections',{...f.connection,label:'Updated label',lastCheckedAt:'2026-10-11T10:00:01.000Z',error:null});
  assert.equal(f.store.connectionGeneration(f.connection.id),1);
  for(const mode of ['deny','ask','allow'])f.policy(mode);
  assert.deepEqual(f.store.get('clientGrants',client.id).bindings,client.bindings);
  assert.equal((await f.invoke(token,'capabilities.list')).result.capabilities[0].status,'available');
  assert.equal((await f.invoke(token,'calls.create',f.input(client))).result.status,'succeeded');
});

test('authority request IDs reject leading punctuation before a replay reservation is persisted',async t=>{
  const f=await fixture(t),{client,token}=f.grant(),params=f.input(client);
  for(const id of ['.request','-request',':request','_request','a'.repeat(129)]){
    assert.equal((await f.invoke(token,'calls.create',params,id)).error.code,'invalid_request');
    await assert.rejects(f.protocol.createCall(client,id,params,clientPrincipal(client.id)),{code:'invalid_request'});
  }
  assert.deepEqual(f.store.list('protocolRequests'),[]);assert.deepEqual(f.store.list('jobs'),[]);
  assert.equal((await f.invoke(token,'calls.create',params,'a'.repeat(128))).result.status,'succeeded');
});

test('pending requests are readable without approval but policy cycles withhold old requests and replay after restart',async t=>{
  const f=await fixture(t);f.policy('ask');
  const {client,token}=f.grant(),params=f.input(client),requestId='old-policy-request';
  const pending=await f.invoke(token,'calls.create',params,requestId);assert.equal(pending.result.status,'awaiting_approval');
  assert.equal((await f.invoke(token,'calls.get',{callId:pending.result.id})).result.status,'awaiting_approval');
  const accepted=f.store.get('jobs',pending.result.id).executionRequest;
  for(const mode of ['deny','ask','allow'])f.policy(mode);
  f.reopen();
  assert.equal((await f.invoke(token,'capabilities.list')).result.capabilities[0].status,'available');
  assert.equal((await f.invoke(token,'calls.get',{callId:pending.result.id})).error.code,'permission_denied');
  assert.equal((await f.invoke(token,'calls.create',params,requestId)).error.code,'permission_denied');
  assert.deepEqual(f.store.get('jobs',pending.result.id).executionRequest,accepted);
  assert.equal((await f.invoke(token,'calls.create',params,'new-policy-request')).result.status,'succeeded');
  assert.equal(f.store.list('jobs').length,2);
});

test('completed result retrieval is bound to its accepted policy, not only the surviving grant',async t=>{
  const f=await fixture(t),{client,token}=f.grant(),params=f.input(client);
  const completed=await f.invoke(token,'calls.create',params,'completed');assert.equal(completed.result.status,'succeeded');
  for(const mode of ['deny','ask','allow'])f.policy(mode);
  const response=await f.invoke(token,'calls.get',{callId:completed.result.id});
  assert.equal(response.error.code,'permission_denied');assert.equal(response.result,undefined);
  assert.equal((await f.invoke(token,'calls.create',params,'completed')).error.code,'permission_denied');
  assert.equal(f.store.get('jobs',completed.result.id).status,'succeeded');
});

test('clients cannot inject principals or source fields, self-approve, or read another client request',async t=>{
  const f=await fixture(t),one=f.grant(['workspace.write.v1']),two=f.grant(['workspace.write.v1']);
  const params=f.input(one.client,'workspace.write.v1',{path:'approved.txt',content:'Owner-approved synthetic content'});
  for(const extra of [{source:{kind:'user'}},{principal:owner},{scope:owner.scope},{ownerPrincipal:owner}])assert.equal((await f.invoke(one.token,'calls.create',{...params,...extra})).error.code,'invalid_request');
  assert.equal(f.store.list('jobs').length,0);
  const pending=await f.invoke(one.token,'calls.create',params),job=f.store.get('jobs',pending.result.id);
  assert.equal((await f.invoke(two.token,'calls.get',{callId:job.id})).error.code,'not_found');
  assert.equal((await f.invoke(one.token,'calls.approve',{callId:job.id,approvalDigest:job.approvalDigest})).error.code,'method_not_found');
  await assert.rejects(f.runtime.approve(job.id,job.approvalDigest,clientPrincipal(one.client.id)));
  await assert.rejects(f.runtime.approve(job.id,job.approvalDigest,otherOwner));
  assert.equal(f.store.get('jobs',job.id).status,'awaiting_approval');
  const done=await f.runtime.approve(job.id,job.approvalDigest,owner);assert.equal(done.status,'succeeded');
  assert.equal(await readFile(path.join(f.local.root,'approved.txt'),'utf8'),'Owner-approved synthetic content');
});

test('historical grants, malformed expiry and changed owner scope fail closed before client identity is used',async t=>{
  const f=await fixture(t),{client,token}=f.grant(),original=f.store.get('clientGrants',client.id);
  const withoutOwner=structuredClone(original);delete withoutOwner.ownerPrincipal;
  const withoutGeneration=structuredClone(original);delete withoutGeneration.bindings[0].connectionGeneration;
  const variants=[withoutOwner,withoutGeneration,{...original,ownerPrincipal:otherOwner},{...original,ownerPrincipal:clientPrincipal(client.id)},...['not-a-date',null,[],123].map(expiresAt=>({...original,expiresAt})),{...original,tokenHash:null},{...original,bindings:[]}];
  for(const grant of variants){f.store.put('clientGrants',grant);const response=await f.invoke(token,'calls.create',f.input(client));assert.equal(response.error.code,'unauthorized');assert.equal(response.result,undefined);}
  f.store.put('clientGrants',original);assert.equal(f.store.list('jobs').length,0);
  assert.equal((await f.invoke(token,'calls.create',f.input(client))).result.status,'succeeded');
});

test('historical jobs missing immutable authority cannot be disclosed or replayed',async t=>{
  const f=await fixture(t),{client,token}=f.grant(),params=f.input(client);
  const created=await f.invoke(token,'calls.create',params,'historical');
  const original=f.store.get('jobs',created.result.id);
  for(const field of ['executionRequest','executionRequestHash']){
    const historical=structuredClone(original);delete historical[field];f.store.put('jobs',historical);
    assert.equal((await f.invoke(token,'calls.get',{callId:original.id})).error.code,'permission_denied');
    assert.equal((await f.invoke(token,'calls.create',params,'historical')).error.code,'permission_denied');
    assert.equal(f.store.list('jobs').length,1);
  }
});

test('concurrent duplicates retain one immutable request, detached arguments and distinct wire hash across restart',async t=>{
  const f=await fixture(t),{client,token}=f.grant(['workspace.write.v1']);
  const params=f.input(client,'workspace.write.v1',{path:'stable.txt',content:'Accepted content'}),original=structuredClone(params);
  const first=f.invoke(token,'calls.create',params,'stable-request');params.args.content='Unaccepted mutation';
  const [a,b]=await Promise.all([first,f.invoke(token,'calls.create',original,'stable-request')]);
  assert.equal(a.result.id,b.result.id);assert.equal(f.store.list('jobs').length,1);
  const job=f.store.get('jobs',a.result.id),entry=f.store.get('protocolRequests',canonicalHash({clientId:client.id,requestId:'stable-request'}));
  assert.equal(job.executionRequest.args.content,'Accepted content');assert.equal(job.args.content,'Accepted content');
  assert.equal(entry.requestHash,canonicalHash(original));assert.notEqual(entry.requestHash,job.executionRequestHash);
  const immutable=structuredClone(job.executionRequest);f.advance(1000);f.reopen();
  assert.equal((await f.invoke(token,'calls.create',original,'stable-request')).result.id,job.id);
  assert.deepEqual(f.store.get('jobs',job.id).executionRequest,immutable);
  assert.equal((await f.invoke(token,'calls.create',params,'stable-request')).error.code,'idempotency_conflict');
});

test('post-execution policy change withholds data without erasing the recorded idempotency reservation',async t=>{
  const f=await fixture(t),{client,token}=f.grant(),params=f.input(client);
  let release,started;const barrier=new Promise(resolve=>{release=resolve;}),began=new Promise(resolve=>{started=resolve;});
  const create=f.runtime.createJob.bind(f.runtime);
  f.runtime.createJob=async(...args)=>{const job=await create(...args);started();await barrier;return job;};
  const pending=f.invoke(token,'calls.create',params,'late-policy');await began;
  for(const mode of ['deny','ask','allow'])f.policy(mode);release();
  assert.equal((await pending).error.code,'permission_denied');
  const entry=f.store.get('protocolRequests',canonicalHash({clientId:client.id,requestId:'late-policy'}));
  assert.equal(entry.status,'recorded');assert.ok(entry.jobId);assert.equal(f.store.get('jobs',entry.jobId).status,'succeeded');
  assert.equal((await f.invoke(token,'calls.create',params,'late-policy')).error.code,'permission_denied');
  assert.equal(f.store.list('jobs').length,1);
});

test('replay cannot substitute another client job or relabel its accepted principal',async t=>{
  const f=await fixture(t),one=f.grant(),two=f.grant(),params=f.input(one.client);
  const a=await f.invoke(one.token,'calls.create',params,'one'),b=await f.invoke(two.token,'calls.create',f.input(two.client),'two');
  const key=canonicalHash({clientId:one.client.id,requestId:'one'}),entry=f.store.get('protocolRequests',key),foreign=f.store.get('jobs',b.result.id);
  f.store.put('protocolRequests',{...entry,jobId:foreign.id});
  assert.equal((await f.invoke(one.token,'calls.create',params,'one')).error.code,'not_found');
  f.store.put('jobs',{...foreign,source:{kind:'client',clientId:one.client.id,requestId:'one'}});
  assert.equal((await f.invoke(one.token,'calls.create',params,'one')).error.code,'permission_denied');
  assert.notEqual(a.result.id,b.result.id);
});

test('uncertain dispatched writes and incomplete reservations are never replayed after restart',async t=>{
  const f=await fixture(t),cap=compileOpenApi({appId:'fixture',document:{openapi:'3.0.3',info:{title:'Synthetic fixture',version:'1'},servers:[{url:'https://fixture.example'}],paths:{'/items':{post:{operationId:'create',responses:{200:{description:'Created'}}}}}}}).capabilities[0];
  f.store.put('capabilities',{...cap,status:'active'});f.store.put('connections',{id:'http-fixture',appId:'fixture',driver:'http',authMethod:'token',authRevision:'fixture-consent',status:'ready',identity:{id:'fixture-account'},allowedOrigins:['https://fixture.example']});
  const {client,token}=f.grant([cap.id],owner,'http-fixture'),params=f.input(client),pending=await f.invoke(token,'calls.create',params,'uncertain-write');
  const job=f.store.get('jobs',pending.result.id),done=await f.runtime.approve(job.id,job.approvalDigest,owner);
  assert.equal(done.status,'uncertain');assert.equal(f.requests,1);const accepted=done.executionRequest;
  f.reopen();assert.equal((await f.invoke(token,'calls.create',params,'uncertain-write')).result.status,'uncertain');
  assert.equal(f.requests,1);assert.deepEqual(f.store.get('jobs',job.id).executionRequest,accepted);
  const requestId='incomplete';f.store.put('protocolRequests',{id:canonicalHash({clientId:client.id,requestId}),clientId:client.id,requestId,requestHash:canonicalHash(params),status:'reserved'});
  assert.equal((await f.invoke(token,'calls.create',params,requestId)).error.code,'outcome_unknown');assert.equal(f.requests,1);
});

test('same-client replay rejects a substituted job and inconsistent reservation provenance',async t=>{
  const f=await fixture(t),{client,token}=f.grant(),params=f.input(client);
  const first=await f.invoke(token,'calls.create',params,'first'),second=await f.invoke(token,'calls.create',params,'second');
  const key=canonicalHash({clientId:client.id,requestId:'first'}),entry=f.store.get('protocolRequests',key);
  f.store.put('protocolRequests',{...entry,jobId:second.result.id});
  assert.equal((await f.invoke(token,'calls.create',params,'first')).error.code,'outcome_unknown');
  for(const patch of [{clientId:'incorrect'},{requestId:'incorrect'},{status:'reserved'}]){
    f.store.put('protocolRequests',{...entry,...patch});
    assert.equal((await f.invoke(token,'calls.create',params,'first')).error.code,'outcome_unknown');
  }
  f.store.put('protocolRequests',entry);assert.equal((await f.invoke(token,'calls.create',params,'first')).result.id,first.result.id);
  assert.equal(f.store.list('jobs').length,2);
});

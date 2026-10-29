import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../lib/store.mjs';
import {BrowserBridge} from '../lib/browser-bridge.mjs';
import {canonicalHash} from '../lib/compiler.mjs';

const owner={schemaVersion:1,kind:'local_owner',id:'owner',scope:{schemaVersion:1,kind:'local',localOwnerId:'owner'}};
const client=id=>({schemaVersion:1,kind:'local_client',id,scope:owner.scope,delegatedBy:{kind:'local_owner',id:owner.id}});
const origin='https://fixture.example';
function fixture(t,{pair=true}={}) {
  const dir=mkdtempSync(join(tmpdir(),'fabric-helper-authority-'));
  let store=new Store({dataDir:dir,localAuthority:'new'});
  const catalog=()=>[{id:'fixture',name:'Fixture',webOrigins:[origin]}];
  let bridge=new BrowserBridge({store,catalog,ownerPrincipal:owner});
  t.after(()=>{bridge.close();store.close();rmSync(dir,{recursive:true,force:true});});
  const f={dir,catalog,get store(){return store;},get bridge(){return bridge;},restart(){bridge.close();store.close();store=new Store({dataDir:dir,localAuthority:'require'});bridge=new BrowserBridge({store,catalog,ownerPrincipal:owner});},
    pair(){const setup=bridge.createPair('fixture',owner);return {...bridge.pair({code:setup.code,origin,bridgeVersion:'0.3',sessionScope:'browser-profile'}),setup};}};
  if(pair)Object.assign(f,f.pair());
  return f;
}
function authorization(f,op='observe',args={},principal=owner) {
  const cap=f.store.get('capabilities',`fixture.browser.${op}.${['click','fill'].includes(op)?'v2':'v1'}`);
  const request={schemaVersion:1,id:'request',scope:owner.scope,principal,access:{kind:'connection',id:f.connection.id,generation:f.store.connectionGeneration(f.connection.id)},
    capability:{appId:'fixture',id:cap.id,version:cap.version,definitionHash:canonicalHash(cap),effect:['click','fill'].includes(op)?'write':'read'},args,policyRevision:1,idempotencyKey:'request-key',createdAt:new Date().toISOString(),deadline:new Date(Date.now()+600000).toISOString()};
  return {cap,request};
}
function start(f,op='observe',args={},principal=owner) {
  let decision=authorization(f,op,args,principal);
  const promise=f.bridge.execute(f.connection.id,{op},args,()=>decision);
  return {promise,get decision(){return decision;},set decision(value){decision=value;}};
}
function result(f,command,data={origin,title:'Fixture'}) {return f.bridge.result(f.token,{id:command.id,ok:true,data});}

test('authority-mode pairing requires separate exact owner; absent owner bridge stays inert',t=>{
  const f=fixture(t,{pair:false}),inert=new BrowserBridge({store:f.store,catalog:f.catalog});
  assert.throws(()=>inert.createPair('fixture',owner));
  assert.throws(()=>f.bridge.createPair('fixture'));
  assert.throws(()=>f.bridge.createPair('fixture',client('agent')));
  assert.throws(()=>f.bridge.createPair('fixture',{...owner,id:'other',scope:{...owner.scope,localOwnerId:'other'}}));
  assert.deepEqual(f.store.list('pairings'),[]);
});
test('pairing rejects descriptor tricks, owner injection, and changed code/session consent',async t=>{
  for(const change of ['app','origins','session','owner','missing'])await t.test(change,t=>{
    const f=fixture(t,{pair:false}),setup=f.bridge.createPair('fixture',owner),pair=f.store.list('pairings')[0];
    if(change==='session')f.store.put('pairingSessions',{...f.store.get('pairingSessions',setup.pairingId),authority:{...pair.authority,consentId:'other'}});
    else f.store.put('pairings',{...pair,...(change==='app'?{appId:'other'}:change==='origins'?{origins:['https://other.example',origin]}:change==='owner'?{authority:{...pair.authority,ownerPrincipal:client('agent')}}:{authority:null})});
    assert.throws(()=>f.bridge.pair({code:setup.code,origin,bridgeVersion:'0.3',sessionScope:'browser-profile'}));
    assert.deepEqual(f.store.list('browserDevices'),[]);
  });
  const f=fixture(t,{pair:false}),setup=f.bridge.createPair('fixture',owner);let accessed=0;
  assert.throws(()=>f.bridge.pair({get code(){accessed++;return setup.code;},origin}));assert.equal(accessed,0);
  assert.throws(()=>f.bridge.pair({code:setup.code,origin,ownerPrincipal:owner}));
});
test('final committed generation binds consent without health updates self-invalidating; restart preserves valid token',t=>{
  const f=fixture(t),id=f.connection.id,device=f.store.get('browserDevices',id),consent=f.store.get('browserHelperConsents',device.consentId);
  assert.equal(f.store.connectionGeneration(id),2);assert.equal(consent.connectionAuthority.generation,2);
  f.bridge.poll(f.token);f.bridge.check(id);assert.equal(f.store.connectionGeneration(id),2);
  assert.equal(f.bridge.status(f.setup.pairingId).status,'paired');assert.equal(f.bridge.getConnectionEvidence(f.connection).account.verified,false);
  f.restart();assert.equal(f.bridge.authenticate(f.token).id,id);assert.equal(f.store.connectionGeneration(id),2);
});
test('partial consent save never returns usable helper authorization',t=>{
  const f=fixture(t,{pair:false}),setup=f.bridge.createPair('fixture',owner),put=f.store.put.bind(f.store);
  f.store.put=(collection,value)=>{if(collection==='browserHelperConsents')throw new Error('Fixture consent save failure');return put(collection,value);};
  assert.throws(()=>f.bridge.pair({code:setup.code,origin,bridgeVersion:'0.3',sessionScope:'browser-profile'}),/Fixture/);
  f.store.put=put;const connection=f.store.list('connections')[0];
  assert.equal(f.bridge.getConnectionEvidence(connection).bridge.status,'unavailable');assert.deepEqual(f.store.list('browserHelperConsents'),[]);
});
test('authority changes, missing provenance and malformed token digests fail closed without invented history',async t=>{
  for(const change of ['deviceABA','parentABA','revoke','delete','missingConsent','missingDeviceConsent','badDigest','owner'])await t.test(change,t=>{
    const f=fixture(t),device=f.store.get('browserDevices',f.connection.id),connection=f.store.get('connections',f.connection.id);
    if(change==='deviceABA'){f.store.put('browserDevices',{...device,origin:'https://other.example'});f.store.put('browserDevices',device);}
    if(change==='parentABA'){f.store.put('connections',{...connection,authRevision:'new'});f.store.put('connections',connection);}
    if(change==='revoke')f.store.put('connections',{...connection,status:'revoked'});
    if(change==='delete'){f.store.delete('connections',connection.id);f.store.put('connections',connection);}
    if(change==='missingConsent')f.store.delete('browserHelperConsents',device.consentId);
    if(change==='missingDeviceConsent'){delete device.consentId;f.store.put('browserDevices',device);}
    if(change==='badDigest')f.store.put('browserDevices',{...device,tokenHash:'bad'});
    if(change==='owner')f.store.put('localDeployment',{id:'owner',ownerPrincipal:client('agent')});
    assert.throws(()=>f.bridge.poll(f.token),error=>error.name!=='RangeError');
    assert.notEqual(f.bridge.getConnectionEvidence(connection).bridge.status,'alive');
    assert.equal(f.bridge.getConnectionEvidence(connection).observedPage,null);
  });
});
test('new-mode execution requires typed runtime decision and exact operation arguments and principal',async t=>{
  const f=fixture(t);
  await assert.rejects(f.bridge.execute(f.connection.id,{op:'observe'},{},()=>{}));
  for(const change of ['args','operation','connection','capability','principal']) {
    const decision=authorization(f);
    if(change==='args')decision.request.args={selector:'changed'};
    if(change==='operation')decision.cap={...decision.cap,action:{op:'read'}};
    if(change==='connection')decision.request.access.id='other';
    if(change==='capability')decision.request.capability.definitionHash='a'.repeat(64);
    if(change==='principal')decision.request.principal={...owner,id:'other',scope:{...owner.scope,localOwnerId:'other'}};
    await assert.rejects(f.bridge.execute(f.connection.id,{op:'observe'},{},()=>decision));
  }
  assert.deepEqual(f.store.list('browserCommands'),[]);
});
test('validated reads and writes retain provider-account and persistent-effect uncertainty',async t=>{
  const f=fixture(t),read=start(f,'observe',{},client('agent'));
  const command=f.bridge.poll(f.token).command;assert.ok(command);assert.equal(result(f,command).accepted,true);
  assert.equal((await read.promise).verification.status,'observed');assert.equal(f.store.connectionGeneration(f.connection.id),2);
  assert.equal(f.bridge.getConnectionEvidence(f.connection).account.verified,false);
  const write=start(f,'click',{snapshotId:'snapshot',targetId:'target'}),next=f.bridge.poll(f.token).command;
  result(f,next,{origin,operation:'click',targetId:'target',dispatchStatus:'dispatched',persistentEffect:'unverified'});
  assert.equal((await write.promise).verification.status,'unverified');
});
test('queued command mutation and client/request substitution cannot dispatch',async t=>{
  for(const change of ['args','action','connection','authority','principal','request'])await t.test(change,async t=>{
    const f=fixture(t),work=start(f,'observe',{},client('agent-a')),rejected=assert.rejects(work.promise);
    const command=f.store.list('browserCommands')[0];
    if(change==='principal')work.decision={...work.decision,request:{...work.decision.request,principal:client('agent-b')}};
    else if(change==='request')work.decision={...work.decision,request:{...work.decision.request,id:'replacement-request'}};
    else f.store.put('browserCommands',{...command,...(change==='args'?{args:{selector:'main'}}:change==='action'?{action:{op:'click'}}:change==='connection'?{authority:{...command.authority,connectionAuthority:{id:'other',generation:2}}}:{authority:null})});
    assert.equal(f.bridge.poll(f.token).command,null);await rejected;
    if(['principal','request'].includes(change))assert.equal(f.store.get('browserDevices',f.connection.id).lastReadAttempt.status,'cancelled');
    else assert.equal(f.store.get('browserDevices',f.connection.id).lastReadAttempt,undefined);
  });
});
test('result rejects changed accepted client or command; does not persist page evidence',async t=>{
  const f=fixture(t),work=start(f,'observe',{},client('agent-a')),rejected=assert.rejects(work.promise),command=f.bridge.poll(f.token).command;
  work.decision={...work.decision,request:{...work.decision.request,principal:client('agent-b')}};
  assert.equal(result(f,command).accepted,false);await rejected;assert.equal(f.bridge.getConnectionEvidence(f.connection).observedPage,null);
});
test('authorize callback authority mutation is checked after callback at each stage',async t=>{
  for(const stage of [1,2,3])await t.test(String(stage),async t=>{
    const f=fixture(t),decision=authorization(f);let calls=0;
    const work=f.bridge.execute(f.connection.id,{op:'observe'},{},()=>{if(++calls===stage)f.store.put('connections',{...f.connection,authRevision:'new'});return decision;});
    const rejected=assert.rejects(work);
    if(stage>1){const command=f.bridge.poll(f.token).command;if(stage===2)assert.equal(command,null);else assert.equal(result(f,command).accepted,false);}
    await rejected;assert.equal(f.store.get('browserDevices',f.connection.id).observedPage,undefined);
  });
});
test('timeout and close cannot write evidence onto changed authority or a substituted command',async t=>{
  for(const cleanup of ['timeout','close'])for(const change of ['generation','command'])await t.test(`${cleanup}-${change}`,async t=>{
    t.mock.timers.enable({apis:['Date','setTimeout'],now:Date.now()});
    const f=fixture(t),work=start(f),rejected=assert.rejects(work.promise),device=f.store.get('browserDevices',f.connection.id);
    if(change==='generation'){f.store.put('browserDevices',{...device,tokenHash:'b'.repeat(64)});f.store.put('browserDevices',device);}
    else{const command=f.store.list('browserCommands')[0];f.store.put('browserCommands',{...command,args:{selector:'changed'}});}
    if(cleanup==='close')f.bridge.close();else t.mock.timers.tick(75001);
    await rejected;assert.equal(f.store.get('browserDevices',f.connection.id).lastReadAttempt,undefined);
  });
});
test('restart expires orphan commands without writing historical evidence',t=>{
  const f=fixture(t),device=f.store.get('browserDevices',f.connection.id);
  f.store.put('browserCommands',{id:'orphan',connectionId:f.connection.id,status:'dispatched',action:{op:'observe'},args:{}});
  f.restart();assert.equal(f.store.get('browserCommands','orphan').status,'expired');assert.deepEqual(f.store.get('browserDevices',f.connection.id),device);
});
test('authorize cannot restore terminal commands at dispatch or result acceptance',async t=>{
  for(const stage of [2,3])for(const status of ['cancelled','expired','done'])await t.test(`${stage}-${status}`,async t=>{
    const f=fixture(t),decision=authorization(f);let calls=0;
    const promise=f.bridge.execute(f.connection.id,{op:'observe'},{},()=>{if(++calls===stage){const c=f.store.list('browserCommands')[0];f.store.put('browserCommands',{...c,status});}return decision;});
    const rejected=assert.rejects(promise),command=f.bridge.poll(f.token).command;
    if(stage===2)assert.equal(command,null);else assert.equal(result(f,command).accepted,false);
    await rejected;assert.equal(f.store.list('browserCommands')[0].status,status);assert.equal(f.store.get('browserDevices',f.connection.id).lastReadAttempt,undefined);
  });
});
test('poll/result envelopes reject getters without invoking them',async t=>{
  const f=fixture(t);let reads=0;
  assert.throws(()=>f.bridge.poll(f.token,{get execution(){reads++;return {state:'open'};}}));
  const work=start(f),command=f.bridge.poll(f.token).command;
  assert.throws(()=>f.bridge.result(f.token,{get id(){reads++;return command.id;},ok:true,data:{origin}}));
  assert.equal(reads,0);result(f,command);await work.promise;
});
test('caller input is detached before authorization and cannot change queued work afterward',async t=>{
  const f=fixture(t),args={selector:'main'},action={op:'read'},decision=authorization(f,'read',{selector:'main'});
  const promise=f.bridge.execute(f.connection.id,action,args,()=>{args.selector='aside';action.op='click';return decision;});
  const command=f.bridge.poll(f.token).command;assert.deepEqual(command.action,{op:'read'});assert.deepEqual(command.args,{selector:'main'});
  result(f,command);await promise;
});
test('accepted helper result data is detached from the caller before resolving execution',async t=>{
  const f=fixture(t),work=start(f),command=f.bridge.poll(f.token).command,data={origin,title:'Original',controls:[{label:'Original'}]};
  result(f,command,data);data.title='Changed';data.controls[0].label='Changed';
  const completed=await work.promise;assert.equal(completed.data.title,'Original');assert.equal(completed.data.controls[0].label,'Original');
});
test('async authorizers never queue work or leave unhandled rejected promises',async t=>{
  const f=fixture(t);
  await assert.rejects(f.bridge.execute(f.connection.id,{op:'observe'},{},async()=>authorization(f)),/synchronous/);
  await assert.rejects(f.bridge.execute(f.connection.id,{op:'observe'},{},async()=>{throw new Error('Fixture asynchronous denial');}),/synchronous/);
  await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(f.store.list('browserCommands'),[]);
});
test('command deadline is checked again when authorization advances time before dispatch or result',async t=>{
  for(const stage of [2,3])await t.test(String(stage),async t=>{
    t.mock.timers.enable({apis:['Date','setTimeout'],now:Date.now()});
    const f=fixture(t),decision=authorization(f);let calls=0;
    const promise=f.bridge.execute(f.connection.id,{op:'observe'},{},()=>{if(++calls===stage)t.mock.timers.setTime(Date.now()+75001);return decision;});
    const rejected=assert.rejects(promise,/expired/),command=f.bridge.poll(f.token).command;
    if(stage===2)assert.equal(command,null);else assert.equal(result(f,command).accepted,false);
    await rejected;assert.equal(f.store.get('browserDevices',f.connection.id).observedPage,undefined);assert.equal(f.store.list('browserCommands')[0].status,'cancelled');
  });
});

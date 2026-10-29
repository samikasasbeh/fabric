import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../lib/store.mjs';
import {LocalRepository} from '../lib/repositories/local.mts';
import {PermissionManager} from '../lib/permissions.mjs';

const connection={id:'account',appId:'fixture',driver:'http',authMethod:'oauth',authRevision:'consent-1',status:'ready',identity:{id:'person'},scopes:['read'],allowedOrigins:['https://example.invalid'],createdAt:'2026-10-11T00:00:00Z'};
const capability={id:'fixture.read.v1',appId:'fixture',driver:'http',status:'active',name:'Read fixture',request:{method:'GET',path:'/items'},inputSchema:{type:'object',properties:{}}};

function fixture(t,{enabled=true,facade=false}={}) {
  const dir=mkdtempSync(join(tmpdir(),'fabric-permission-authority-'));
  let store=new Store({dataDir:dir,...(enabled?{localAuthority:'new'}:{})});
  store.put('connections',connection);store.put('capabilities',capability);
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  const view=()=>facade?new LocalRepository({store}):store;
  return {get store(){return store;},manager:()=>new PermissionManager({store:view()}),restart(){store.close();store=new Store({dataDir:dir,...(enabled?{localAuthority:'require'}:{})});}};
}

test('designated stores add trusted numeric authority while legacy decisions remain byte-compatible',t=>{
  const old=fixture(t,{enabled:false}),current=fixture(t);
  const before=old.manager().decision(connection,capability),after=current.manager().decision(connection,capability);
  const {connectionGeneration,policyRevision,...legacy}=after;
  assert.deepEqual(legacy,before);assert.equal(connectionGeneration,1);assert.equal(policyRevision,1);
  assert.equal(Object.hasOwn(before,'connectionGeneration'),false);assert.equal(Object.hasOwn(before,'policyRevision'),false);
  assert.deepEqual(current.store.get('connections',connection.id),connection);
  assert.deepEqual(current.store.list('permissions'),[]);
});

test('permission changes are durable even when an Allow Deny Ask Allow cycle has no intervening reads',t=>{
  const f=fixture(t),manager=f.manager(),id=manager.policyId(connection.id,capability.id);
  const initial=manager.decision(connection,capability);
  for(const [index,mode] of ['allow','deny','ask','allow'].entries()) f.store.put('permissions',{id,connectionId:connection.id,capabilityId:capability.id,mode,bindingHash:initial.bindingHash,revision:`consent-${index}`});
  f.restart();const decision=f.manager().decision(connection,capability);
  assert.equal(decision.mode,'allow');assert.equal(decision.policyRevision,5);
  assert.equal(decision.connectionGeneration,1);
  assert.equal(f.store.get('permissions',id).revision,'consent-3');
});

test('deleting repeated or nonexistent policies never resurrects an older default policy revision',t=>{
  const f=fixture(t),manager=f.manager(),id=manager.policyId(connection.id,capability.id);
  assert.equal(manager.decision(connection,capability).policyRevision,1);
  f.store.delete('permissions',id);
  assert.equal(manager.decision(connection,capability).policyRevision,2);
  manager.set({connectionId:connection.id,capabilityId:capability.id,mode:'ask'});
  assert.equal(manager.decision(connection,capability).policyRevision,3);
  f.store.delete('permissions',id);f.restart();
  const restored=f.manager().decision(connection,capability);
  assert.equal(restored.policySource,'default');assert.equal(restored.policyRevision,4);
  assert.equal(restored.mode,'allow');
  assert.deepEqual(f.store.list('permissions'),[]);
});

test('repeated owner permission consent advances revisions through the repository facade without changing its guarantees',t=>{
  const f=fixture(t,{facade:true}),manager=f.manager();
  const first=manager.set({connectionId:connection.id,capabilityId:capability.id,mode:'ask'});
  const second=manager.set({connectionId:connection.id,capabilityId:capability.id,mode:'ask'});
  assert.equal(first.policyRevision,2);assert.equal(second.policyRevision,3);
  assert.equal(first.bindingHash,second.bindingHash);assert.notEqual(first.policyHash,second.policyHash);
  const repository=new LocalRepository({store:f.store});
  assert.equal(repository.guarantees.transactions,false);assert.equal(repository.guarantees.atomicSecretUpdates,false);
  assert.equal(repository.guarantees.compareAndSwap,false);assert.equal(repository.guarantees.tenantIsolation,false);
});

test('numeric connection generations detect A B A even when the legacy binding hash returns to its previous value',t=>{
  const f=fixture(t),manager=f.manager(),before=manager.decision(connection,capability);
  f.store.put('connections',{...connection,identity:{id:'another-person'}});
  f.store.put('connections',connection);
  const after=manager.decision(connection,capability);
  assert.equal(after.bindingHash,before.bindingHash);assert.equal(after.policyHash,before.policyHash);
  assert.equal(after.connectionGeneration,3);assert.equal(after.policyRevision,1);
  // Field values supplied by an API projection are not trusted revision facts.
  assert.equal(manager.decision({...connection,connectionGeneration:500,policyRevision:500},capability).connectionGeneration,3);
});

test('health-only updates preserve authority and missing persisted connections fail closed',t=>{
  const f=fixture(t),manager=f.manager();
  f.store.put('connections',{...connection,status:'unavailable',lastCheckedAt:'2026-10-11T00:01:00Z',updatedAt:'2026-10-11T00:01:00Z',error:'Fixture provider temporarily unavailable.'});
  assert.equal(manager.decision(connection,capability).connectionGeneration,1);
  assert.equal(manager.decision(connection,capability).executable,false);
  f.store.put('connections',{...connection,lastCheckedAt:'2026-10-11T00:02:00Z',updatedAt:'2026-10-11T00:02:00Z',expiresAt:1234,refreshAvailable:true,error:null,identity:{...connection.identity,displayName:'A new label',email:'label@example.invalid'}});
  assert.equal(manager.decision(connection,capability).connectionGeneration,1);
  f.store.delete('connections',connection.id);
  assert.throws(()=>manager.decision(connection,capability));
});

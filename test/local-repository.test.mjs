import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../lib/store.mjs';
import {LocalRepository} from '../lib/repositories/local.mts';
import {checkedClock} from '../contracts/repository.mts';

const scope = {schemaVersion:1,kind:'local',localOwnerId:'fixture-owner'};
function fixture(t) {
  const dir=mkdtempSync(join(tmpdir(),'fabric-repository-'));
  let time=Date.parse('2026-01-02T03:04:05.000Z');
  const store=new Store({dataDir:dir,clock:()=>time});
  const repository=new LocalRepository({store,scope});
  t.after(()=>{repository.close();rmSync(dir,{recursive:true,force:true});});
  return {store,repository,setTime:value=>{time=value;}};
}

test('local repository delegates synchronous documents without adding ownership or changing payloads',t=>{
  const {store,repository}=fixture(t);
  const record={id:'legacy-id',specVersion:'fabric/0.1',provenance:{fingerprint:'unchanged'},nested:{value:7}};
  const saved=repository.put('capabilities',record);
  assert.equal(saved instanceof Promise,false);
  assert.deepEqual(saved,record);
  assert.deepEqual(store.get('capabilities',record.id),record);
  saved.nested.value=99;
  assert.equal(repository.get('capabilities',record.id).nested.value,7);
  repository.put('capabilities',{id:'second'});
  assert.deepEqual(repository.list('capabilities').map(item=>item.id),['legacy-id','second']);
  assert.equal(repository.delete('capabilities','legacy-id'),true);
  assert.equal(repository.delete('capabilities','legacy-id'),false);
  assert.equal(repository.get('capabilities','legacy-id'),null);
});

test('local repository rejects tenant scope and cannot be rebound to another local owner',t=>{
  const {store,repository}=fixture(t);
  const tenant={schemaVersion:1,kind:'tenant',organizationId:'org',projectId:'project',environmentId:'production'};
  assert.throws(()=>new LocalRepository({store,scope:tenant}),error=>error.code==='unsupported_repository_scope');
  assert.throws(()=>repository.assertScope(tenant),error=>error.code==='unsupported_repository_scope');
  assert.throws(()=>repository.assertScope({...scope,localOwnerId:'other-owner'}),/scope mismatch/i);
  assert.doesNotThrow(()=>repository.assertScope({...scope}));
  assert.equal(Object.isFrozen(repository.scope),true);
  assert.throws(()=>{repository.scope.localOwnerId='other-owner';},TypeError);
  assert.throws(()=>{repository.scope=tenant;},TypeError);
  assert.throws(()=>new LocalRepository({store,scope:{...scope,schemaVersion:2}}),/identity contract/i);
});

test('unsupported multi-document, CAS and lease guarantees fail before calling or mutating anything',t=>{
  const {repository}=fixture(t);
  repository.put('jobs',{id:'job',status:'queued'});
  let called=false;
  for(const operation of [
    ()=>repository.transaction(()=>{called=true;}),
    ()=>repository.compareAndSwap('jobs','job','old',{id:'job',status:'running'}),
    ()=>repository.acquireLease('job'),
    ()=>repository.renewLease('job'),
    ()=>repository.releaseLease('job'),
  ]) assert.throws(operation,error=>error.code==='unsupported_repository_operation');
  assert.equal(called,false);
  assert.equal(repository.get('jobs','job').status,'queued');
  assert.deepEqual(repository.guarantees,{synchronous:true,documentAtomicity:true,uniqueness:'collection-and-id',transactions:false,compareAndSwap:false,leases:false,fencing:false,tenantIsolation:false,atomicSecretUpdates:false});
  assert.equal(Object.isFrozen(repository.guarantees),true);
});

test('audit uses the injected local clock and preserves existing secret redaction',t=>{
  const {repository,setTime}=fixture(t);
  const first=repository.audit({type:'fixture',accessToken:'never-log',nested:{password:'never-log',safe:true}});
  assert.equal(first.createdAt,'2026-01-02T03:04:05.000Z');
  assert.equal(JSON.stringify(first).includes('never-log'),false);
  setTime(Date.parse('2026-01-02T03:04:06.000Z'));
  assert.equal(repository.audit({type:'next'}).createdAt,'2026-01-02T03:04:06.000Z');
});

test('clock contract requires a finite integer epoch and validates every reading',()=>{
  let time=0;
  const clock=checkedClock(()=>time);
  assert.equal(clock(),0);
  time=-1;assert.equal(clock(),-1);
  for(const invalid of [NaN,Infinity,1.5,8640000000000001,'123',undefined]) {
    time=invalid;assert.throws(()=>clock(),/clock/i);
  }
  assert.throws(()=>checkedClock(123),/clock/i);
});

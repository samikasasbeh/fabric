import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {Store} from '../lib/store.mjs';

const at='2026-01-01T00:00:00.000Z', origin='https://fixture.example';
const connection=(persistent=false,id='fixture')=>({id,appId:'fixture',driver:'browser',authMethod:'browser',...(persistent?{transport:'persistent',persistentSession:true}:{bridgeVersion:'0.3',sessionScope:'browser-profile'}),allowedOrigins:[origin],status:'session_ready',createdAt:at});
const device=(overrides={})=>({id:'fixture',tokenHash:'a'.repeat(64),origin,bridgeVersion:'0.3',sessionScope:'browser-profile',createdAt:at,...overrides});
const session=(overrides={})=>({id:'fixture',connectionId:'fixture',profileId:'fixture',appId:'fixture',origin,origins:[origin],consent:{granted:true,grantedAt:at,scope:'read-only browser observation',expiresAt:null},state:'dormant',createdAt:at,...overrides});
const sides=[['browserDevices','browserDevice',device,false],['persistentSessions','persistentSession',session,true]];
const rejected=operation=>assert.throws(operation,error=>error.code==='invalid_local_authority');
function fixture(t,mode='new') {
  const dir=mkdtempSync(join(tmpdir(),'fabric-browser-authority-'));
  let store=new Store({dataDir:dir,...(mode?{localAuthority:mode}:{})});
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  return {dir,get store(){return store;},reopen(){store.close();store=new Store({dataDir:dir,localAuthority:'require'});return store;}};
}
const counter=(store,kind,id='fixture')=>store.db.prepare('SELECT * FROM _fabric_local_authority_counters WHERE kind=? AND id=?').get(kind,id);
function rewriteChecksum(store,version=2) {
  const hash=createHash('sha256').update(`fabric-local-authority-v${version}/default-policy=1\n`);
  for(const row of store.db.prepare('SELECT * FROM _fabric_local_authority_counters ORDER BY kind,id').all()) hash.update(JSON.stringify([row.kind,row.id,row.revision,row.present,row.document_hash,row.authority_hash])+'\n');
  store.db.prepare('UPDATE _fabric_local_authority_meta SET version=?,checksum=? WHERE id=1').run(version,hash.digest('hex'));
}

test('new designated stores use version 2; older designation is rejected without upgrading it',t=>{
  const f=fixture(t);assert.equal(f.store.db.prepare('SELECT version FROM _fabric_local_authority_meta').get().version,2);
  f.store.put('connections',connection());rewriteChecksum(f.store,1);
  const before=f.store.db.prepare('SELECT * FROM _fabric_local_authority_meta').get();
  for(const localAuthority of ['require','baseline','new',undefined]) rejected(()=>new Store({dataDir:f.dir,localAuthority}));
  assert.deepEqual(f.store.db.prepare('SELECT * FROM _fabric_local_authority_meta').get(),before);
  rejected(()=>f.store.put('connections',{...connection(),status:'revoked'}));
});

test('explicit baseline rejects existing browser side records without manufacturing their history',async t=>{
  for(const [collection,,record,persistent] of sides) await t.test(collection,t=>{
    const f=fixture(t,null);f.store.put('connections',connection(persistent));f.store.put(collection,record());
    rejected(()=>new Store({dataDir:f.dir,localAuthority:'baseline'}));
    assert.equal(f.store.db.prepare('PRAGMA application_id').get().application_id,0);
    assert.deepEqual(f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(row=>row.name),['documents']);
    assert.deepEqual(f.store.get(collection,'fixture'),record());
  });
});

test('legacy browser records retain unrestricted pairing order and unchanged document payloads',t=>{
  const {store}=fixture(t,null);store.put('browserDevices',device());store.put('connections',connection());store.put('persistentSessions',session());
  assert.deepEqual(store.get('browserDevices','fixture'),device());assert.deepEqual(store.get('persistentSessions','fixture'),session());
  assert.equal(store.authorityEnabled,false);
});

test('side creation advances only its owning connection and preserves the parent payload',async t=>{
  for(const [collection,kind,record,persistent] of sides) await t.test(collection,t=>{
    const {store}=fixture(t);const parent=connection(persistent);store.put('connections',parent);store.put('connections',connection(persistent,'other'));
    store.put(collection,record());assert.equal(store.connectionGeneration('fixture'),2);assert.equal(store.connectionGeneration('other'),1);
    assert.equal(counter(store,kind).revision,1);assert.deepEqual(store.get('connections','fixture'),parent);
    store.put(collection,record());assert.equal(store.connectionGeneration('fixture'),2);
  });
});

test('side authority ABA survives restart even without intermediate generation reads',async t=>{
  for(const [collection,kind,record,persistent] of sides) await t.test(collection,t=>{
    const f=fixture(t);f.store.put('connections',connection(persistent));f.store.put(collection,record());
    f.store.put(collection,record(persistent?{consent:{...session().consent,scope:'changed'}}:{tokenHash:'b'.repeat(64)}));
    f.store.put(collection,record());f.reopen();assert.equal(f.store.connectionGeneration('fixture'),4);assert.equal(counter(f.store,kind).revision,3);
  });
});

test('helper heartbeats and page evidence preserve authority but update committed integrity',t=>{
  const f=fixture(t);f.store.put('connections',connection());f.store.put('browserDevices',device());
  for(const executionState of ['idle','open','unknown']) f.store.put('browserDevices',device({lastHeartbeatAt:'later',executionState,observationInvalidated:true,observedPage:{title:'Fixture',origin,at},lastReadAttempt:{status:'cancelled'}}));
  assert.equal(f.store.connectionGeneration('fixture'),2);assert.equal(counter(f.store,'browserDevice').revision,1);
  f.reopen();assert.equal(f.store.connectionGeneration('fixture'),2);
});

test('same-profile reopen, page epochs and health do not renew persistent consent',t=>{
  const f=fixture(t);f.store.put('connections',connection(true));f.store.put('persistentSessions',session());
  for(const state of ['opening','available','dormant']) f.store.put('persistentSessions',session({state,updatedAt:'later',lastOpenedAt:'later',lastError:'temporary',sessionEpoch:5,documentEpoch:9,observationCurrent:true,observedPage:{title:'Fixture',origin,at},lastAttempt:{status:'failed'}}));
  f.reopen();assert.equal(f.store.connectionGeneration('fixture'),2);assert.equal(counter(f.store,'persistentSession').revision,1);
  f.store.put('persistentSessions',session({state:'revoked'}));assert.equal(f.store.connectionGeneration('fixture'),3);
  f.store.put('persistentSessions',session());assert.equal(f.store.connectionGeneration('fixture'),4);
});

test('all declared authority fields and unknown fields remain bound without derived-key collisions',async t=>{
  const changes={browserDevices:[{origin:'https://other.example'},{bridgeVersion:'0.2'},{sessionScope:'tab'},{createdAt:'later'},{futureAuthority:'bound'},{revoked:'first'},{revoked:'second'}],persistentSessions:[{origin:'https://other.example'},{origins:['https://other.example',origin]},{origins:[origin,'https://other.example']},{consent:{...session().consent,granted:false}},{createdAt:'later'},{futureAuthority:'bound'},{revoked:'first'},{revoked:'second'}]};
  for(const [collection,,record,persistent] of sides) await t.test(collection,t=>{
    const {store}=fixture(t);store.put('connections',connection(persistent));let value=record();store.put(collection,value);let revision=2;
    for(const change of changes[collection]) {value={...value,...change};store.put(collection,value);assert.equal(store.connectionGeneration('fixture'),++revision);}
  });
});

test('side tombstones survive deletion/recreation and permit cleanup after parent deletion',async t=>{
  for(const [collection,kind,record,persistent] of sides) await t.test(collection,t=>{
    const f=fixture(t),store=f.store;store.put('connections',connection(persistent));store.put(collection,record());
    assert.equal(store.delete(collection,'fixture'),true);assert.equal(store.connectionGeneration('fixture'),3);
    store.put(collection,record());assert.equal(store.connectionGeneration('fixture'),4);assert.equal(counter(store,kind).revision,3);
    store.delete('connections','fixture');assert.equal(store.connectionGeneration('fixture'),5);
    rejected(()=>store.put(collection,record()));
    store.delete(collection,'fixture');assert.equal(store.connectionGeneration('fixture'),6);assert.equal(counter(store,kind).present,0);
    f.reopen();f.store.put('connections',connection(persistent));f.store.put(collection,record());assert.equal(f.store.connectionGeneration('fixture'),8);
  });
});

test('side writes require an existing browser owner and cannot rebind another connection or profile',t=>{
  const {store}=fixture(t);rejected(()=>store.put('browserDevices',device()));rejected(()=>store.delete('browserDevices','fixture'));
  store.put('connections',{id:'fixture',driver:'http'});rejected(()=>store.put('browserDevices',device()));
  store.put('connections',connection(true));store.put('connections',connection(true,'other'));
  for(const record of [session({connectionId:'other'}),session({profileId:'other'}),session({appId:'other'}),session({state:[]}),session({state:'unknown-authority-state'}),device({connectionId:'other'})]) rejected(()=>store.put(record.tokenHash?'browserDevices':'persistentSessions',record));
  assert.equal(store.connectionGeneration('other'),1);assert.deepEqual(store.list('persistentSessions'),[]);assert.deepEqual(store.list('browserDevices'),[]);
});

test('side documents reject caller counters and getters before accessing or serializing them',t=>{
  const {store}=fixture(t);store.put('connections',connection());let accessed=0;
  const value=device();Object.defineProperty(value,'id',{enumerable:true,get(){accessed++;return 'fixture';}});
  rejected(()=>store.put('browserDevices',value));assert.equal(accessed,0);
  for(const [collection,,record] of sides) for(const key of ['generation','connectionGeneration','policyRevision']) rejected(()=>store.put(collection,record({[key]:999})));
});

test('same-ID helper and persistent grants cannot coexist or adopt an incompatible transport',t=>{
  const {store}=fixture(t);store.put('connections',connection());
  rejected(()=>store.put('persistentSessions',session()));store.put('browserDevices',device());
  store.put('connections',connection(true));
  rejected(()=>store.put('browserDevices',device()));rejected(()=>store.put('persistentSessions',session()));
  store.delete('browserDevices','fixture');store.put('persistentSessions',session());
  store.put('connections',connection());
  rejected(()=>store.put('persistentSessions',session()));rejected(()=>store.put('browserDevices',device()));
  store.delete('persistentSessions','fixture');store.put('browserDevices',device());
  assert.equal(counter(store,'persistentSession').present,0);assert.equal(counter(store,'browserDevice').present,1);
});

test('missing side counters, tombstones and committed document changes fail before any later mutation',async t=>{
  for(const [collection,kind,record,persistent] of sides) for(const fault of ['row','tombstone','document']) await t.test(`${collection} ${fault}`,t=>{
    const f=fixture(t),store=f.store;store.put('connections',connection(persistent));store.put(collection,record());
    if(fault==='tombstone')store.delete(collection,'fixture');
    if(fault==='document')store.db.prepare('UPDATE documents SET document=? WHERE collection=? AND id=?').run(JSON.stringify(record({unexpected:'mutation'})),collection,'fixture');
    else store.db.prepare('DELETE FROM _fabric_local_authority_counters WHERE kind=? AND id=?').run(kind,'fixture');
    rejected(()=>store.connectionGeneration('fixture'));rejected(()=>store.put('jobs',{id:'must-not-write'}));rejected(()=>new Store({dataDir:f.dir,localAuthority:'require'}));
    assert.equal(store.get('jobs','must-not-write'),null);
  });
});

test('side, owning generation and checksum writes roll back as one mutation',async t=>{
  for(const [collection,kind,record,persistent] of sides) for(const fault of ['side','owner','checksum']) await t.test(`${collection} ${fault}`,t=>{
    const {store}=fixture(t);store.put('connections',connection(persistent));store.put(collection,record());
    const before=counter(store,kind);
    const target=fault==='checksum'?'_fabric_local_authority_meta':'_fabric_local_authority_counters';
    const when=fault==='checksum'?'':`WHEN NEW.kind='${fault==='owner'?'connection':kind}'`;
    store.db.exec(`CREATE TRIGGER fault BEFORE UPDATE ON ${target} ${when} BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;`);
    assert.throws(()=>store.put(collection,record({extraAuthority:'change'})),/fixture failure/);
    assert.deepEqual(store.get(collection,'fixture'),record());assert.deepEqual(counter(store,kind),before);assert.equal(store.connectionGeneration('fixture'),2);
    assert.throws(()=>store.delete(collection,'fixture'),/fixture failure/);
    assert.deepEqual(store.get(collection,'fixture'),record());assert.deepEqual(counter(store,kind),before);assert.equal(store.connectionGeneration('fixture'),2);
    store.db.exec('DROP TRIGGER fault');store.put(collection,record({extraAuthority:'change'}));assert.equal(store.connectionGeneration('fixture'),3);
  });
});

test('overflow of either side or owning counter rejects the complete mutation',async t=>{
  for(const [collection,kind,record,persistent] of sides) for(const limited of [kind,'connection']) await t.test(`${collection} ${limited}`,t=>{
    const {store}=fixture(t);store.put('connections',connection(persistent));store.put(collection,record());
    store.db.prepare('UPDATE _fabric_local_authority_counters SET revision=? WHERE kind=? AND id=?').run(Number.MAX_SAFE_INTEGER,limited,'fixture');rewriteChecksum(store);
    const before=counter(store,kind),generation=store.connectionGeneration('fixture');
    rejected(()=>store.put(collection,record({extraAuthority:'overflow'})));rejected(()=>store.delete(collection,'fixture'));
    assert.deepEqual(store.get(collection,'fixture'),record());assert.deepEqual(counter(store,kind),before);assert.equal(store.connectionGeneration('fixture'),generation);
  });
});

test('two handles observe side-record authority and cannot lose its committed update',t=>{
  const f=fixture(t);f.store.put('connections',connection());f.store.put('browserDevices',device());
  const other=new Store({dataDir:f.dir,localAuthority:'require'});t.after(()=>other.close());
  other.put('browserDevices',device({tokenHash:'b'.repeat(64)}));assert.equal(f.store.connectionGeneration('fixture'),3);
  f.store.put('browserDevices',device());assert.equal(other.connectionGeneration('fixture'),4);
});

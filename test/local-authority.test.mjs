import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {Store} from '../lib/store.mjs';
import {LocalRepository} from '../lib/repositories/local.mts';

const connection = (overrides={}) => ({id:'connection',appId:'fixture',driver:'http',authMethod:'oauth',authRevision:'consent-a',identity:{id:'account-a',displayName:'Fixture'},allowedOrigins:['https://fixture.example'],scopes:['read','write'],status:'ready',createdAt:'2026-01-01T00:00:00.000Z',...overrides});
const policy = (mode='allow') => ({id:'policy',connectionId:'connection',capabilityId:'operation',mode,revision:'legacy-consent'});
function fixture(t, mode='new') {
  const dir=mkdtempSync(join(tmpdir(),'fabric-authority-'));
  let store=new Store({dataDir:dir,...(mode?{localAuthority:mode}:{})});
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  return {dir,get store(){return store;},reopen(mode='require'){store.close();store=new Store({dataDir:dir,...(mode?{localAuthority:mode}:{})});return store;}};
}
const rejected = operation => assert.throws(operation,error=>error.code==='invalid_local_authority');

test('authority is explicitly opt-in and legacy stores keep their schema and payloads',t=>{
  const f=fixture(t,null),record=connection({generation:900});
  f.store.put('connections',record);
  assert.equal(f.store.authorityEnabled,false);
  assert.deepEqual(f.store.get('connections','connection'),record);
  assert.deepEqual(f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(row=>row.name),['documents']);
  rejected(()=>f.store.connectionGeneration('connection'));
  rejected(()=>new Store({dataDir:f.dir,localAuthority:'new'}));
  rejected(()=>new Store({dataDir:f.dir,localAuthority:'require'}));
  rejected(()=>new Store({dataDir:f.dir,localAuthority:'invalid'}));
});

test('explicit baseline persists existing document generations without modifying payloads or defaults',t=>{
  const f=fixture(t,null),record=connection(),saved=policy();
  f.store.put('connections',record);f.store.put('permissions',saved);
  f.reopen('baseline');
  assert.equal(f.store.authorityEnabled,true);
  assert.equal(f.store.connectionGeneration('connection'),1);
  assert.equal(f.store.policyRevision('policy'),1);
  assert.equal(f.store.policyRevision('absent-policy'),1);
  assert.deepEqual(f.store.get('connections','connection'),record);
  assert.deepEqual(f.store.list('permissions'),[saved]);
  f.reopen();assert.equal(f.store.connectionGeneration('connection'),1);
  rejected(()=>new Store({dataDir:f.dir}));
  rejected(()=>new Store({dataDir:f.dir,localAuthority:'baseline'}));
  rejected(()=>new Store({dataDir:f.dir,localAuthority:'new'}));
});

test('connection consent, route, account, origin order and scope changes advance at each mutation',t=>{
  const {store}=fixture(t);let record=connection();store.put('connections',record);
  let revision=1;
  for(const change of [
    {authRevision:'consent-b'},{authRevision:'consent-a'},
    {identity:{id:'account-b'}},{identity:{id:'account-a'}},
    {status:'revoked'},{status:'ready'},
    {allowedOrigins:['https://fixture.example','https://other.example']},
    {allowedOrigins:['https://other.example','https://fixture.example']},
    {identityProbe:{path:'/me'}},{authMethod:'token'},
    {scopes:['read']},{scopes:['read','write']},
    {transport:'helper'},{bridgeVersion:'0.3'},{sessionScope:'browser-profile'},
    {persistentSession:true},{grantExpiresAt:123},{profileId:'new-profile'},
    {identity:{id:'account-a',workspaceId:'workspace'}},{identity:{id:'account-a',verified:true}},
    {createdAt:'2026-02-01T00:00:00.000Z'},{futureAuthorityField:'conservative'},{revoked:'unknown-field-still-bound'},
  ]) {record={...record,...change};store.put('connections',record);assert.equal(store.connectionGeneration(record.id),++revision);}
});

test('health, metadata and unchanged-scope token refresh preserve generation and committed payload',t=>{
  const {store}=fixture(t);let record=connection();store.put('connections',record);
  for(const status of ['unavailable','reconnect_required','session_ready','ready']) {
    record={...record,status,label:'New label',updatedAt:'later',lastCheckedAt:'later',error:'temporary',expiresAt:123,refreshAvailable:true,scopes:['write','read','read'],identity:{id:'account-a',displayName:'Updated',email:'fixture@example.test',workspaceName:'Renamed'}};
    store.put('connections',record);assert.equal(store.connectionGeneration(record.id),1);
    assert.deepEqual(store.get('connections',record.id),record);
  }
});

// F10.4 (T7): which sign-in wrote a record, and when, is not authority; a renewal that changes nothing else keeps the generation.
test('sign-in revision and time are health: a renewal that changes nothing else keeps the generation',t=>{
  const {store}=fixture(t);let record=connection({grantCeiling:['read','write'],signInRevision:'sign-in-a',signedInAt:'2026-01-01T00:00:00.000Z'});
  store.put('connections',record);
  for(const change of [{signInRevision:'sign-in-b',signedInAt:'2026-01-08T00:00:00.000Z'},{signInRevision:'sign-in-c'},{signedInAt:'2026-01-15T00:00:00.000Z'}]) {
    record={...record,...change};store.put('connections',record);
    assert.equal(store.connectionGeneration(record.id),1);assert.deepEqual(store.get('connections',record.id),record);
  }
  const {signInRevision,signedInAt,...withoutSignIn}=record;void signInRevision;void signedInAt;
  store.put('connections',withoutSignIn);assert.equal(store.connectionGeneration(record.id),1);
});

test('grant ceiling order never moves the generation; its contents do',t=>{
  const {store}=fixture(t);let record=connection({grantCeiling:['read','write']});store.put('connections',record);
  record={...record,grantCeiling:['write','read','read']};store.put('connections',record);assert.equal(store.connectionGeneration(record.id),1);
  record={...record,grantCeiling:['read','write','admin']};store.put('connections',record);assert.equal(store.connectionGeneration(record.id),2);
  record={...record,grantCeiling:['read']};store.put('connections',record);assert.equal(store.connectionGeneration(record.id),3);
  const {grantCeiling,...withoutCeiling}=record;void grantCeiling;
  store.put('connections',withoutCeiling);assert.equal(store.connectionGeneration(record.id),4);
});

test('a malformed sign-in revision or grant ceiling fails closed, as a malformed authorization revision does',t=>{
  const {store}=fixture(t);
  for(const value of [connection({signInRevision:[]}),connection({signInRevision:''}),connection({signInRevision:7}),connection({signInRevision:'x'.repeat(257)}),
    connection({grantCeiling:'read'}),connection({grantCeiling:[1]}),connection({grantCeiling:['']}),connection({grantCeiling:['x'.repeat(2001)]}),connection({grantCeiling:Array.from({length:1001},(_,i)=>`scope-${i}`)})]) rejected(()=>store.put('connections',value));
  assert.deepEqual(store.list('connections'),[]);
  store.put('connections',connection({signInRevision:'x'.repeat(256),grantCeiling:Array.from({length:1000},(_,i)=>`scope-${i}`)}));
  assert.equal(store.connectionGeneration('connection'),1);
});

test('a store written before sign-in revisions verifies unchanged after them',t=>{
  // Written by the authority projection at f03d034, before grantCeiling, signInRevision and signedInAt existed.
  const f=fixture(t);f.store.put('connections',connection());
  assert.equal(f.store.db.prepare("SELECT authority_hash FROM _fabric_local_authority_counters WHERE kind='connection' AND id='connection'").get().authority_hash,'32ed1943054f64bbbcfe147eb60269e63068f1bf768fa93459817befcbfffeca');
  assert.equal(f.store.db.prepare('SELECT checksum FROM _fabric_local_authority_meta WHERE id=1').get().checksum,'cfed8016971882faa5067c6174314d36886b50ea6e4ce0f0933a1cead8a81cf2');
  f.reopen();assert.equal(f.store.connectionGeneration('connection'),1);
  f.store.put('connections',connection({signInRevision:'first-renewal',signedInAt:'2026-01-08T00:00:00.000Z'}));
  assert.equal(f.store.connectionGeneration('connection'),1);
});

test('policy cycles and repeated consent advance without intervening reads and survive restart',t=>{
  const f=fixture(t);assert.equal(f.store.policyRevision('policy'),1);
  for(const mode of ['allow','deny','ask','allow','allow']) f.store.put('permissions',policy(mode));
  f.reopen();assert.equal(f.store.policyRevision('policy'),6);
  assert.equal(f.store.get('permissions','policy').revision,'legacy-consent');
});

test('connection and policy tombstones survive delete/recreate including deletion of implicit default',t=>{
  const f=fixture(t),store=f.store;
  store.put('connections',connection());assert.equal(store.delete('connections','connection'),true);
  assert.equal(store.connectionGeneration('connection'),2);
  store.put('connections',connection());assert.equal(store.connectionGeneration('connection'),3);
  assert.equal(store.delete('permissions','policy'),false);assert.equal(store.policyRevision('policy'),2);
  assert.equal(store.delete('permissions','policy'),false);assert.equal(store.policyRevision('policy'),3);
  store.put('permissions',policy());assert.equal(store.policyRevision('policy'),4);
  assert.equal(store.delete('permissions','policy'),true);assert.equal(store.policyRevision('policy'),5);
  f.reopen();assert.equal(f.store.connectionGeneration('connection'),3);assert.equal(f.store.policyRevision('policy'),5);
  f.store.put('permissions',policy());assert.equal(f.store.policyRevision('policy'),6);
  rejected(()=>f.store.connectionGeneration('never-created'));
});

test('counter metadata is not writable through generic documents or caller-supplied counters',t=>{
  const {store}=fixture(t);
  for(const key of ['generation','connectionGeneration','policyRevision']) rejected(()=>store.put('connections',connection({[key]:999})));
  rejected(()=>store.put('permissions',{...policy(),policyRevision:999}));
  for(const name of ['_fabric_local_authority_meta','_fabric_local_authority_counters']) {
    rejected(()=>store.put(name,{id:'connection',revision:999}));rejected(()=>store.delete(name,'connection'));
    assert.deepEqual(store.list(name),[]);
  }
  store.put('connections',connection());assert.equal(store.connectionGeneration('connection'),1);
});

test('authority documents are bounded descriptor-safe JSON before reading id or serializing',t=>{
  const {store}=fixture(t);let called=0;
  const accessor={...connection()};Object.defineProperty(accessor,'id',{enumerable:true,get(){called++;return 'connection';}});
  const toJSON={...connection(),toJSON(){called++;return connection();}};
  for(const value of [accessor,toJSON,connection({scopes:[1]}),connection({scopes:['']}),connection({status:[]}),connection({identity:'bad'}),connection({authRevision:[]}),connection({extra:'x'.repeat(2*1024*1024)})]) rejected(()=>store.put('connections',value));
  assert.equal(called,0);assert.deepEqual(store.list('connections'),[]);
});

test('document and counter changes roll back together on either SQLite write failure',t=>{
  const {store}=fixture(t);store.put('connections',connection());
  store.db.exec("CREATE TRIGGER authority_fault BEFORE UPDATE ON _fabric_local_authority_counters BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;");
  assert.throws(()=>store.put('connections',connection({authRevision:'consent-b'})),/fixture failure/);
  assert.equal(store.get('connections','connection').authRevision,'consent-a');assert.equal(store.connectionGeneration('connection'),1);
  store.db.exec('DROP TRIGGER authority_fault');
  store.db.exec("CREATE TRIGGER checksum_fault BEFORE UPDATE ON _fabric_local_authority_meta BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;");
  assert.throws(()=>store.put('connections',connection({authRevision:'consent-b'})),/fixture failure/);
  assert.equal(store.get('connections','connection').authRevision,'consent-a');assert.equal(store.connectionGeneration('connection'),1);
  store.db.exec('DROP TRIGGER checksum_fault');
  store.db.exec("CREATE TRIGGER document_fault BEFORE DELETE ON documents BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;");
  assert.throws(()=>store.delete('connections','connection'),/fixture failure/);
  assert.equal(store.connectionGeneration('connection'),1);
});

test('missing metadata, counters and partial document changes fail closed before another mutation',async t=>{
  for(const sql of [
    'DELETE FROM _fabric_local_authority_meta',
    'DELETE FROM _fabric_local_authority_counters',
    'UPDATE _fabric_local_authority_counters SET revision=0',
    'UPDATE _fabric_local_authority_counters SET revision=1.5',
    "UPDATE documents SET document='{}' WHERE collection='connections'",
    "INSERT INTO documents VALUES('connections','unexpected','{\"id\":\"unexpected\"}')",
  ]) await t.test(sql,t=>{
    const f=fixture(t);f.store.put('connections',connection());f.store.db.exec(sql);
    rejected(()=>f.store.connectionGeneration('connection'));
    rejected(()=>f.store.policyRevision('new-policy'));
    rejected(()=>f.store.put('permissions',policy()));
    assert.equal(f.store.get('permissions','policy'),null);
    rejected(()=>new Store({dataDir:f.dir,localAuthority:'require'}));
    rejected(()=>new Store({dataDir:f.dir,localAuthority:'baseline'}));
  });
});

test('designation marker prevents reseeding after internal tables are lost',t=>{
  const f=fixture(t);f.store.db.exec('DROP TABLE _fabric_local_authority_counters; DROP TABLE _fabric_local_authority_meta;');
  rejected(()=>new Store({dataDir:f.dir,localAuthority:'baseline'}));
  rejected(()=>new Store({dataDir:f.dir,localAuthority:'new'}));
  rejected(()=>new Store({dataDir:f.dir}));
});

test('new designation requires the entire document store to be empty, not only authority collections',t=>{
  const f=fixture(t,null);f.store.put('jobs',{id:'historical',status:'awaiting_approval'});
  rejected(()=>new Store({dataDir:f.dir,localAuthority:'new'}));
  assert.equal(f.store.db.prepare('PRAGMA application_id').get().application_id,0);
  f.reopen('baseline');assert.equal(f.store.authorityEnabled,true);
  assert.equal(f.store.get('jobs','historical').status,'awaiting_approval');
});

test('designated stores never silently recreate a missing documents table, even without live authority records',async t=>{
  for(const tombstones of [false,true]) await t.test(tombstones?'tombstones only':'empty authority',t=>{
    const f=fixture(t);
    if(tombstones){f.store.put('connections',connection());f.store.delete('connections','connection');f.store.delete('permissions','policy');}
    f.store.put('jobs',{id:'history',status:'succeeded'});
    f.store.db.exec('DROP TABLE documents');
    for(const mode of ['require','baseline','new',undefined]) {
      rejected(()=>new Store({dataDir:f.dir,localAuthority:mode}));
      assert.equal(f.store.db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name='documents'").get().n,0);
    }
  });
});

test('failed baseline is rolled back and closed, allowing a corrected explicit baseline',t=>{
  const f=fixture(t,null);f.store.put('connections',connection({scopes:[1]}));
  rejected(()=>new Store({dataDir:f.dir,localAuthority:'baseline'}));
  assert.equal(f.store.db.prepare('PRAGMA application_id').get().application_id,0);
  assert.deepEqual(f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(row=>row.name),['documents']);
  f.store.put('connections',connection());f.reopen('baseline');
  assert.equal(f.store.connectionGeneration('connection'),1);
});

test('legacy handles opened before baseline reject later writes under the designation lock',t=>{
  const f=fixture(t,null);f.store.put('connections',connection());
  const designated=new Store({dataDir:f.dir,localAuthority:'baseline'});t.after(()=>designated.close());
  assert.equal(f.store.authorityEnabled,false);
  rejected(()=>f.store.put('connections',connection({authRevision:'untracked'})));
  rejected(()=>f.store.delete('connections','connection'));
  rejected(()=>f.store.put('permissions',policy()));
  rejected(()=>f.store.put('jobs',{id:'untracked-job'}));
  assert.equal(designated.connectionGeneration('connection'),1);
  assert.equal(designated.get('connections','connection').authRevision,'consent-a');
  assert.deepEqual(designated.list('permissions'),[]);
});

test('losing one tombstone is corruption rather than a new default or connection baseline',async t=>{
  for(const [kind,collection,id] of [['connection','connections','connection'],['policy','permissions','policy']]) await t.test(kind,t=>{
    const f=fixture(t);f.store.put('connections',connection());f.store.put('permissions',policy());
    f.store.delete(collection,id);
    f.store.db.prepare('DELETE FROM _fabric_local_authority_counters WHERE kind=? AND id=?').run(kind,id);
    rejected(()=>f.store.policyRevision('policy'));
    rejected(()=>f.store.connectionGeneration('connection'));
    rejected(()=>f.store.put('connections',connection()));
    rejected(()=>f.store.put('permissions',policy()));
    rejected(()=>new Store({dataDir:f.dir,localAuthority:'require'}));
  });
});

// Raw SQL here is deliberate fault injection into an isolated fixture. Rebuild
// the non-security checksum so overflow is tested independently of corruption.
function setCounterAtLimit(store,kind,id,revision) {
  store.db.prepare('UPDATE _fabric_local_authority_counters SET revision=? WHERE kind=? AND id=?').run(revision,kind,id);
  const rows=store.db.prepare('SELECT kind,id,revision,present,document_hash,authority_hash FROM _fabric_local_authority_counters ORDER BY kind,id').all();
  const hash=createHash('sha256').update('fabric-local-authority-v2/default-policy=1\n');
  for(const row of rows) hash.update(JSON.stringify([row.kind,row.id,row.revision,row.present,row.document_hash,row.authority_hash])+'\n');
  store.db.prepare('UPDATE _fabric_local_authority_meta SET checksum=? WHERE id=1').run(hash.digest('hex'));
}

test('positive safe-integer overflow rejects before authority document or tombstone changes',t=>{
  const {store}=fixture(t);store.put('connections',connection());store.put('permissions',policy());
  setCounterAtLimit(store,'connection','connection',Number.MAX_SAFE_INTEGER);
  assert.equal(store.connectionGeneration('connection'),Number.MAX_SAFE_INTEGER);
  store.put('connections',connection({updatedAt:'health-only'}));
  rejected(()=>store.put('connections',connection({authRevision:'overflow'})));
  rejected(()=>store.delete('connections','connection'));
  assert.equal(store.get('connections','connection').authRevision,'consent-a');
  assert.equal(store.connectionGeneration('connection'),Number.MAX_SAFE_INTEGER);
  setCounterAtLimit(store,'policy','policy',Number.MAX_SAFE_INTEGER);
  rejected(()=>store.put('permissions',policy('deny')));
  rejected(()=>store.delete('permissions','policy'));
  assert.equal(store.get('permissions','policy').mode,'allow');
  assert.equal(store.policyRevision('policy'),Number.MAX_SAFE_INTEGER);
});

test('two Store handles observe committed generations rather than cached authority',t=>{
  const f=fixture(t);f.store.put('connections',connection());
  const other=new Store({dataDir:f.dir,localAuthority:'require'});t.after(()=>other.close());
  other.put('connections',connection({authRevision:'second'}));
  assert.equal(f.store.connectionGeneration('connection'),2);
  f.store.put('connections',connection({authRevision:'third'}));
  assert.equal(other.connectionGeneration('connection'),3);
});

test('repository exposes narrow authority lookups without adding transaction or tenant guarantees',t=>{
  const f=fixture(t),repository=new LocalRepository({store:f.store});
  assert.equal(repository.authorityEnabled,true);repository.put('connections',connection());
  assert.equal(repository.connectionGeneration('connection'),1);assert.equal(repository.policyRevision('policy'),1);
  assert.equal(repository.guarantees.transactions,false);assert.equal(repository.guarantees.tenantIsolation,false);
  assert.throws(()=>{repository.authorityEnabled=false;},TypeError);
});

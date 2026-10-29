import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {linkSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {canonicalHash} from '../lib/compiler.mjs';
import {migrateLocalFixture, rollbackLocalFixture} from '../migrations/local-v1.mts';

const now = Date.parse('2026-01-02T03:04:05.000Z');
const owner = {schemaVersion:1,kind:'local',localOwnerId:'synthetic-owner'};
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const marker = version => JSON.stringify({schemaVersion:version,kind:'fabric-synthetic-local-fixture',closed:true});
function bytesAt(directory) {
  const result = {};
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory,name);
    if (statSync(path).isDirectory()) {
      for (const [child,bytes] of Object.entries(bytesAt(path))) result[`${name}/${child}`] = bytes;
    } else result[name] = readFileSync(path);
  }
  return result;
}
function withDb(path, action) {
  const db = new DatabaseSync(join(path,'fabric.sqlite'));
  try { return action(db); } finally { db.close(); }
}
const documentsAt = path => withDb(path,db=>db.prepare('SELECT collection,id,document FROM documents ORDER BY rowid').all());
const get = (path,collection,id) => JSON.parse(documentsAt(path).find(row=>row.collection===collection&&row.id===id).document);
function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(),'fabric-migration-test-')));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const source=join(root,'source'), destination=join(root,'migrated');
  const store=new Store({dataDir:source,clock:()=>now});
  const vault=new Vault(source);
  const secret={token:'synthetic-only-never-report-this-value',refreshToken:'synthetic-refresh'};
  vault.set('connection-1',secret);
  vault.set('oauth:flow-1',{verifier:'synthetic-verifier'});
  store.put('applications',{id:'fixture-app',name:'Fixture'});
  store.put('capabilities',{id:'cap-1',appId:'fixture-app',driver:'http',version:'1.0.0',effect:'read',provenance:{source:'synthetic',sourceHash:'f'.repeat(64)}});
  // A raw formatting/order fingerprint must not be normalized by migration.
  store.db.prepare('UPDATE documents SET document=? WHERE collection=? AND id=?').run('{ "id":"cap-1", "appId":"fixture-app", "driver":"http", "version":"1.0.0", "effect":"read", "provenance":{"source":"synthetic","sourceHash":"'+ 'f'.repeat(64)+'"} }','capabilities','cap-1');
  store.put('connections',{id:'connection-1',appId:'fixture-app',driver:'http',status:'ready',authMethod:'token',authRevision:'old-revision',identity:{id:'account-1'}});
  store.put('connections',{id:'revoked-connection',appId:'fixture-app',driver:'http',status:'revoked'});
  for (const status of ['awaiting_approval','queued','running','uncertain','succeeded','failed','cancelled']) store.put('jobs',{id:`job-${status}`,connectionId:'connection-1',capabilityId:'cap-1',args:{message:'same arguments'},effect:'write',status,approvalDigest:'a'.repeat(64),approvalExpiresAt:'2030-01-01T00:00:00.000Z',approvedBy:'old-local-owner'});
  for (const mode of ['allow','ask','deny']) store.put('permissions',{id:`permission-${mode}`,connectionId:'connection-1',capabilityId:'cap-1',mode,bindingHash:'b'.repeat(64),revision:'prior-revision'});
  store.put('heartbeats',{id:'heartbeat-1',enabled:true,connectionId:'connection-1',capabilityId:'cap-1',args:{},nextRunAt:'2025-01-01T00:00:00.000Z',lastResult:{status:'running'},runs:3});
  store.put('clientGrants',{id:'grant-1',status:'active',tokenHash:sha('synthetic-token'),expiresAt:'2030-01-01T00:00:00.000Z',bindings:[{connectionId:'connection-1',capabilityId:'cap-1'}]});
  store.put('oauthFlows',{id:'flow-1',appId:'fixture-app',flowIdHash:sha('synthetic-flow'),expiresAt:now+60000,connectionId:'connection-1'});
  store.put('protocolRequests',{id:'request-reserved',status:'reserved',requestHash:sha('synthetic-request')});
  store.put('protocolRequests',{id:'request-recorded',status:'recorded',jobId:'job-succeeded',requestHash:sha('other-synthetic-request')});
  store.audit({type:'fixture.created',connectionId:'connection-1'});
  store.close();
  writeFileSync(join(source,'fixture.json'),marker(0),{mode:0o600});
  const options={rootDirectory:root,sourceName:'source',destinationName:'migrated',localOwnerId:owner.localOwnerId,targetVersion:1,now};
  const rollback={rootDirectory:root,migratedName:'migrated',destinationName:'restored',localOwnerId:owner.localOwnerId,targetVersion:0};
  return {root,source,destination,secret,options,rollback};
}

test('migration namespaces copied SQLite records without changing IDs, raw capability payloads, provenance or vault bytes',t=>{
  const f=fixture(t), original=bytesAt(f.source), before=documentsAt(f.source);
  const report=migrateLocalFixture(f.options);
  assert.equal(report.schemaVersion,1); assert.deepEqual(report.scope,owner); assert.equal(report.idempotent,false);
  assert.equal(Object.isFrozen(report),true); assert.equal(Object.isFrozen(report.scope),true);
  assert.equal(report.records,before.length);
  assert.deepEqual(bytesAt(f.source),original);
  assert.deepEqual(bytesAt(join(f.destination,'snapshot')),original);
  const after=documentsAt(f.destination);
  assert.deepEqual(after.map(({collection,id})=>[collection,id]),before.map(({collection,id})=>[collection,id]));
  assert.equal(after.find(row=>row.collection==='capabilities').document,before.find(row=>row.collection==='capabilities').document);
  assert.deepEqual(get(f.destination,'capabilities','cap-1').provenance,get(f.source,'capabilities','cap-1').provenance);
  withDb(f.destination,db=>{
    assert.equal(db.prepare('PRAGMA user_version').get().user_version,1);
    const sidecars=db.prepare('SELECT * FROM local_ownership ORDER BY rowid').all();
    assert.equal(sidecars.length,before.length);
    for (const sidecar of sidecars) {
      assert.deepEqual(JSON.parse(sidecar.envelope),{schemaVersion:1,scope:owner,owner:{kind:'local_owner',id:owner.localOwnerId}});
      assert.equal(sidecar.source_document_hash,sha(before.find(row=>row.collection===sidecar.collection&&row.id===sidecar.id).document));
    }
  });
  assert.deepEqual(bytesAt(join(f.destination,'vault')),bytesAt(join(f.source,'vault')));
  // Only tests decrypt synthetic values, proving exact logical IDs/AAD and key survive.
  assert.deepEqual(new Vault(f.destination).get('connection-1'),f.secret);
  assert.deepEqual(new Vault(f.destination).get('oauth:flow-1'),{verifier:'synthetic-verifier'});
  assert.equal(JSON.stringify(report).includes(f.secret.token),false);
  assert.equal(JSON.stringify(report).includes('synthetic-verifier'),false);
  assert.equal(statSync(f.destination).mode&0o777,0o700);
  assert.equal(statSync(join(f.destination,'vault','master.key')).mode&0o777,0o600);
});

test('old authority is invalidated, Deny remains exact, schedules pause and uncertain writes never become queued',t=>{
  const f=fixture(t), report=migrateLocalFixture(f.options);
  assert.equal(get(f.destination,'connections','connection-1').status,'revoked');
  assert.deepEqual(get(f.destination,'connections','revoked-connection'),get(f.source,'connections','revoked-connection'));
  assert.equal(get(f.destination,'permissions','permission-allow').mode,'ask');
  for (const mode of ['ask','deny']) assert.equal(documentsAt(f.destination).find(row=>row.id===`permission-${mode}`).document,documentsAt(f.source).find(row=>row.id===`permission-${mode}`).document);
  for (const status of ['awaiting_approval','queued','running']) {
    const job=get(f.destination,'jobs',`job-${status}`);
    assert.equal(job.status,status==='awaiting_approval'?'cancelled':'uncertain');
    assert.match(job.migrationReason,/fresh_authorization/);
    assert.equal(Object.hasOwn(job,'approvalDigest'),false);
    assert.equal(Object.hasOwn(job,'approvedBy'),false);
    assert.deepEqual(job.args,get(f.source,'jobs',job.id).args);
  }
  for (const status of ['uncertain','succeeded','failed','cancelled']) assert.deepEqual(get(f.destination,'jobs',`job-${status}`),get(f.source,'jobs',`job-${status}`));
  assert.equal(get(f.destination,'heartbeats','heartbeat-1').enabled,false);
  assert.equal(get(f.destination,'clientGrants','grant-1').status,'revoked');
  assert.equal(get(f.destination,'oauthFlows','flow-1').expiresAt,0);
  assert.equal(get(f.destination,'oauthFlows','flow-1').status,'invalidated');
  assert.equal(get(f.destination,'protocolRequests','request-reserved').status,'failed');
  assert.deepEqual(get(f.destination,'protocolRequests','request-recorded'),get(f.source,'protocolRequests','request-recorded'));
  assert.equal(report.workUncertain,2); assert.equal(report.schedulesPaused,1); assert.equal(report.invalidated,6);
});

test('rerunning with the same source and owner is byte-idempotent and ignores a newer clock',t=>{
  const f=fixture(t), first=migrateLocalFixture(f.options), original=bytesAt(f.destination);
  const repeated=migrateLocalFixture({...f.options,now:now+100000});
  assert.deepEqual(repeated,{...first,idempotent:true});
  assert.deepEqual(bytesAt(f.destination),original);
});

test('migration and rollback refuse owner reassignment; manifest edits do not rebind the migrated database',t=>{
  const f=fixture(t); migrateLocalFixture(f.options);
  assert.throws(()=>migrateLocalFixture({...f.options,localOwnerId:'other-owner'}),/owner reassignment/);
  assert.throws(()=>rollbackLocalFixture({...f.rollback,localOwnerId:'other-owner'}),/owner reassignment/);
  const manifestPath=join(f.destination,'migration.json'), manifest=JSON.parse(readFileSync(manifestPath));
  manifest.scope.localOwnerId='other-owner'; writeFileSync(manifestPath,JSON.stringify(manifest));
  assert.throws(()=>migrateLocalFixture({...f.options,localOwnerId:'other-owner'}),/database owner reassignment/);
});

test('failure injection at each staging boundary leaves source untouched and publishes nothing',t=>{
  for (const point of ['after_copy','during_transform','before_publish']) {
    const f=fixture(t), original=bytesAt(f.source);
    assert.throws(()=>migrateLocalFixture({...f.options,injectFailureAt:point}),/injected failure/);
    assert.deepEqual(bytesAt(f.source),original);
    assert.deepEqual(readdirSync(f.root),['source']);
    assert.equal(migrateLocalFixture(f.options).idempotent,false);
  }
});

test('rollback restores the exact untouched snapshot to a fresh copy even after the migrated database changes',t=>{
  const f=fixture(t), original=bytesAt(f.source), report=migrateLocalFixture(f.options);
  withDb(f.destination,db=>db.exec("DELETE FROM documents WHERE collection IN ('jobs','oauthFlows');"));
  const modified=bytesAt(f.destination);
  assert.throws(()=>migrateLocalFixture(f.options),/migrated copy changed/);
  const rolledBack=rollbackLocalFixture(f.rollback), restored=join(f.root,'restored');
  assert.deepEqual(rolledBack,{schemaVersion:0,sourceFingerprint:report.sourceFingerprint,restored:true});
  assert.deepEqual(bytesAt(restored),original);
  assert.deepEqual(bytesAt(f.source),original);
  assert.deepEqual(bytesAt(f.destination),modified);
  assert.equal(get(restored,'jobs','job-awaiting_approval').status,'awaiting_approval');
  assert.deepEqual(new Vault(restored).get('connection-1'),f.secret);
  assert.throws(()=>rollbackLocalFixture(f.rollback),/fresh destination/);
});

test('tampered snapshots cannot be rolled back and existing output files are never overwritten',t=>{
  const f=fixture(t); migrateLocalFixture(f.options);
  const snapshotKey=join(f.destination,'snapshot','vault','master.key');
  writeFileSync(snapshotKey,Buffer.alloc(32));
  assert.throws(()=>rollbackLocalFixture(f.rollback),/snapshot changed/);
  assert.equal(readdirSync(f.root).includes('restored'),false);
  const other=fixture(t); mkdirSync(other.destination); writeFileSync(join(other.destination,'sentinel'),'leave alone');
  assert.throws(()=>migrateLocalFixture(other.options));
  assert.equal(readFileSync(join(other.destination,'sentinel'),'utf8'),'leave alone');
  assert.throws(()=>migrateLocalFixture({...other.options,destinationName:'source'}),/fresh destination/);
});

test('unknown migration, database, fixture and vault versions fail closed',t=>{
  const cases=[
    f=>{f.options.targetVersion=2;},
    f=>writeFileSync(join(f.source,'fixture.json'),marker(2)),
    f=>withDb(f.source,db=>db.exec('PRAGMA user_version=2;')),
    f=>{const encrypted=readdirSync(join(f.source,'vault')).find(name=>name.endsWith('.enc'));const path=join(f.source,'vault',encrypted);const value=JSON.parse(readFileSync(path));value.version=2;writeFileSync(path,JSON.stringify(value));},
    f=>writeFileSync(join(f.source,'fixture.json'),JSON.stringify({schemaVersion:0,kind:'fabric-synthetic-local-fixture',closed:false})),
  ];
  for (const change of cases) {
    const f=fixture(t); change(f); const original=bytesAt(f.source);
    assert.throws(()=>migrateLocalFixture(f.options),/version|options|marker|envelope/);
    assert.deepEqual(bytesAt(f.source),original); assert.deepEqual(readdirSync(f.root),['source']);
  }
});

test('unsupported browser/workspace authority, unknown collections and already scoped records are rejected',t=>{
  for (const [collection,document] of [
    ['browserDevices',{id:'browser',tokenHash:'opaque'}],
    ['pairingSessions',{id:'pair',status:'pending'}],
    ['connections',{id:'browser',driver:'browser',status:'ready'}],
    ['connections',{id:'workspace',driver:'workspace',status:'ready',root:'/outside'}],
    ['capabilities',{id:'browser-cap',driver:'browser'}],
    ['capabilities',{id:'already-scoped',driver:'http',scope:owner}],
    ['jobs',{id:'future-state',status:'future'}],
  ]) {
    const f=fixture(t);
    withDb(f.source,db=>db.prepare('INSERT INTO documents(collection,id,document) VALUES(?,?,?)').run(collection,document.id,JSON.stringify(document)));
    const original=bytesAt(f.source);
    assert.throws(()=>migrateLocalFixture(f.options),/unsupported|only HTTP|scoped|unknown job/);
    assert.deepEqual(bytesAt(f.source),original); assert.deepEqual(readdirSync(f.root),['source']);
  }
});

test('journal sidecars and non-DELETE SQLite modes are rejected, never recovered or checkpointed by migration',t=>{
  for (const suffix of ['-journal','-wal','-shm']) {
    const f=fixture(t); writeFileSync(join(f.source,`fabric.sqlite${suffix}`),'synthetic-sidecar');
    const original=bytesAt(f.source);
    assert.throws(()=>migrateLocalFixture(f.options),/active SQLite journal/);
    assert.deepEqual(bytesAt(f.source),original);
  }
  const f=fixture(t); withDb(f.source,db=>db.exec('PRAGMA journal_mode=WAL;'));
  const original=bytesAt(f.source);
  assert.throws(()=>migrateLocalFixture(f.options),/DELETE-journal|journal/);
  assert.deepEqual(bytesAt(f.source),original);
});

test('paths cannot escape the root or target a .fabric directory',t=>{
  const f=fixture(t);
  for (const name of ['../outside','/tmp/outside','.fabric','source/nested','..','']) assert.throws(()=>migrateLocalFixture({...f.options,destinationName:name}),/direct named children/);
  const privateRoot=join(f.root,'.fabric'); mkdirSync(privateRoot);
  assert.throws(()=>migrateLocalFixture({...f.options,rootDirectory:privateRoot}),/fixture root/);
  const alias=join(f.root,'alias'); symlinkSync(f.source,alias);
  assert.throws(()=>migrateLocalFixture({...f.options,sourceName:'alias'}),/fixture directory/);
  symlinkSync(join(f.root,'not-created'),f.destination);
  assert.throws(()=>migrateLocalFixture(f.options));
  assert.equal(statSync(f.source).isDirectory(),true);
});

test('symlinked files, vault directories and hardlinked input files fail closed',t=>{
  for (const name of ['fabric.sqlite','vault','vault/master.key']) {
    const f=fixture(t), path=join(f.source,name), moved=join(f.root,`moved-${name.replaceAll('/','-')}`);
    renameSync(path,moved); symlinkSync(moved,path);
    assert.throws(()=>migrateLocalFixture(f.options),/invalid fixture|invalid or oversized/);
    assert.equal(readdirSync(f.root).includes('migrated'),false);
  }
  const f=fixture(t); linkSync(join(f.source,'fabric.sqlite'),join(f.root,'database-hardlink'));
  assert.throws(()=>migrateLocalFixture(f.options),/invalid or oversized fixture file/);
  assert.equal(readdirSync(f.root).includes('migrated'),false);
});

test('unsupported database objects and malformed record IDs fail before publishing',t=>{
  for (const change of [
    db=>db.exec('CREATE TABLE extra (id TEXT);'),
    db=>db.exec('CREATE TABLE sqliteHidden (id TEXT);'),
    db=>db.exec("CREATE TRIGGER source_trigger AFTER INSERT ON documents BEGIN DELETE FROM documents; END;"),
    db=>db.prepare('UPDATE documents SET document=? WHERE id=?').run('{"id":"wrong","driver":"http"}','cap-1'),
    db=>db.prepare('UPDATE documents SET document=? WHERE id=?').run('{"id":"cap-1","driver":"http","constructor":{}}','cap-1'),
  ]) {
    const f=fixture(t); withDb(f.source,change); const original=bytesAt(f.source);
    assert.throws(()=>migrateLocalFixture(f.options),/unsupported database|ID mismatch|invalid bounded JSON/);
    assert.deepEqual(bytesAt(f.source),original); assert.deepEqual(readdirSync(f.root),['source']);
  }
});

test('changed source cannot be mistaken for the already migrated fixture',t=>{
  const f=fixture(t); migrateLocalFixture(f.options); const migrated=bytesAt(f.destination);
  withDb(f.source,db=>db.prepare('UPDATE documents SET document=? WHERE id=?').run(JSON.stringify({id:'cap-1',driver:'http',version:'2.0.0'}),'cap-1'));
  assert.throws(()=>migrateLocalFixture(f.options),/different fixture/);
  assert.deepEqual(bytesAt(f.destination),migrated);
  assert.equal(canonicalHash(get(f.source,'capabilities','cap-1'))===canonicalHash(get(f.destination,'capabilities','cap-1')),false);
});

test('source authority enums reject arrays and other coercible non-string values before publishing',t=>{
  for (const [collection,id,field,valid] of [
    ['permissions','permission-allow','mode','allow'],
    ['connections','connection-1','status','ready'],
    ['jobs','job-awaiting_approval','status','awaiting_approval'],
    ['clientGrants','grant-1','status','active'],
    ['protocolRequests','request-reserved','status','reserved'],
    ['capabilities','cap-1','driver','http'],
    ['connections','connection-1','driver','http'],
  ]) {
    for (const invalid of [[valid],null,{},1,true]) {
      const f=fixture(t), original=get(f.source,collection,id);
      withDb(f.source,db=>db.prepare('UPDATE documents SET document=? WHERE collection=? AND id=?').run(JSON.stringify({...original,[field]:invalid}),collection,id));
      const sourceBytes=bytesAt(f.source);
      assert.throws(()=>migrateLocalFixture(f.options),/unknown|only HTTP/);
      assert.deepEqual(bytesAt(f.source),sourceBytes);
      assert.deepEqual(readdirSync(f.root),['source']);
    }
  }
});

test('legacy ConnectionManager cannot read retained tokens, perform provider I/O or reactivate a migrated connection',async t=>{
  const f=fixture(t), token='synthetic-github-token';
  new Vault(f.source).set('connection-1',{accessToken:token});
  const connection={...get(f.source,'connections','connection-1'),appId:'github',identity:{id:'1'},allowedOrigins:['https://api.github.com'],refreshAvailable:true};
  withDb(f.source,db=>db.prepare('UPDATE documents SET document=? WHERE collection=? AND id=?').run(JSON.stringify(connection),'connections','connection-1'));
  const originalVault=bytesAt(join(f.source,'vault'));
  migrateLocalFixture(f.options);
  const store=new Store({dataDir:f.destination,clock:()=>now});
  try {
    const vault=new Vault(f.destination); let reads=0, requests=0;
    const read=vault.get.bind(vault); vault.get=id=>{reads++;return read(id);};
    const manager=new ConnectionManager({store,vault,clock:()=>now,request:async ()=>{requests++;return {status:200,data:{id:1,login:'fixture'}};}});
    await assert.rejects(manager.check('connection-1'),error=>error.code==='invalid_input');
    await assert.rejects(manager.credentials('connection-1'),error=>error.code==='reconnect_required');
    assert.equal(reads,0); assert.equal(requests,0);
    const migrated=store.get('connections','connection-1');
    assert.equal(migrated.status,'revoked'); assert.equal(migrated.refreshAvailable,false);
    assert.notEqual(migrated.authRevision,connection.authRevision);
    assert.equal(migrated.revokedAt,new Date(now).toISOString());
    assert.deepEqual(bytesAt(join(f.destination,'vault')),originalVault);
    assert.deepEqual(read('connection-1'),{accessToken:token});
  } finally {store.close();}
});

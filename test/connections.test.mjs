import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../lib/store.mjs';
import { Vault } from '../lib/vault.mjs';
import { ConnectionManager, catalogFor } from '../lib/connections.mjs';

function fixture(t,request) {
  const dir = mkdtempSync(join(tmpdir(),'fabric-connections-'));
  const store = new Store({dataDir:dir}), vault = new Vault(dir);
  t.after(() => {store.close(); rmSync(dir,{recursive:true,force:true});});
  return {dir,store,vault,manager:new ConnectionManager({store,vault,request})};
}
test('verified token connection persists; public data and audit never expose credentials',async t => {
  const token = 'fixture-private-token-123456';
  const {dir,store,vault,manager} = fixture(t,async request => {
    assert.equal(request.url,'https://api.github.com/user');
    assert.equal(request.headers.Authorization,`Bearer ${token}`);
    return {status:200,data:{id:17,login:'fixture-user'}};
  });
  const connection = await manager.connect({appId:'github',token});
  assert.equal(connection.status,'ready'); assert.equal(connection.identity.id,'17');
  assert.equal(JSON.stringify(manager.list()).includes(token),false);
  assert.equal(JSON.stringify(store.list('activity')).includes(token),false);
  assert.equal(readFileSync(join(dir,'fabric.sqlite')).includes(Buffer.from(token)),false);
  const enc = readdirSync(join(dir,'vault')).find(name => name.endsWith('.enc'));
  assert.equal(readFileSync(join(dir,'vault',enc)).includes(Buffer.from(token)),false);
  assert.equal(statSync(join(dir,'vault','master.key')).mode & 0o777,0o600);
  assert.equal(new Vault(dir).get(connection.id).accessToken,token);
  assert.deepEqual((await manager.credentials(connection.id)).allowedOrigins,['https://api.github.com']);
  assert.equal((await manager.check(connection.id)).status,'ready');
  manager.revoke(connection.id);
  assert.equal(vault.get(connection.id),null);
  await assert.rejects(manager.credentials(connection.id),/active API connection/);
});
test('failed identity check never creates fake readiness or persists token',async t => {
  const {store,manager} = fixture(t,async () => ({status:401,data:{error:'secret provider error'}}));
  await assert.rejects(manager.connect({appId:'github',token:'secret'}),/provider rejected/);
  assert.deepEqual(store.list('connections'),[]);
});
test('account binding survives health checks and rejects reconnect account switches',async t => {
  let account = 1;
  const {manager,vault} = fixture(t,async () => ({status:200,data:{id:account,login:`account-${account}`}}));
  const connection = await manager.connect({appId:'github',token:'original'});
  account = 2;
  assert.equal((await manager.check(connection.id)).status,'reconnect_required');
  assert.equal(manager.get(connection.id).identity.id,'1');
  await assert.rejects(manager.connect({appId:'github',token:'replacement',connectionId:connection.id}),/Account mismatch/);
  assert.equal(vault.get(connection.id).accessToken,'original');
});
test('provider exceptions are sanitized and unavailable differs from revoked credentials',async t => {
  let fail = false;
  const {manager} = fixture(t,async () => { if (fail) throw new Error('Authorization: Bearer super-secret'); return {status:200,data:{id:1,login:'fixture'}}; });
  const connection = await manager.connect({appId:'github',token:'private'}); fail = true;
  const checked = await manager.check(connection.id);
  assert.equal(checked.status,'unavailable');
  assert.equal(JSON.stringify(checked).includes('super-secret'),false);
});
for (const lateStatus of [200,401]) test(`stale health ${lateStatus} cannot overwrite a newer successful reconnect`,async t => {
  let pending=false,release;
  const {manager,store,vault}=fixture(t,async request=>{
    const old=request.headers.Authorization==='Bearer original-token';
    if(pending&&old) return new Promise(resolve=>{release=resolve;});
    return {status:200,data:{id:1,login:old?'old-name':'new-name'}};
  });
  const connection=await manager.connect({appId:'github',token:'original-token'});
  pending=true;const check=manager.check(connection.id);
  assert.equal(typeof release,'function');
  await manager.connect({appId:'github',token:'replacement-token',connectionId:connection.id});
  const replacement=store.get('connections',connection.id);
  release({status:lateStatus,data:lateStatus===200?{id:1,login:'obsolete-name'}:{error:'invalid_token'}});
  const checked=await check;
  assert.equal(checked.status,'ready');assert.equal(checked.identity.displayName,'new-name');
  assert.deepEqual(store.get('connections',connection.id),replacement);
  assert.equal(vault.get(connection.id).accessToken,'replacement-token');
});
test('Slack and Notion use provider identities, not merely HTTP 200',async t => {
  let provider = 'slack';
  const {manager} = fixture(t,async () => ({status:200,data:provider === 'slack' ? {ok:false,error:'invalid_auth'} : {id:'bot-1',type:'bot',name:'Fixture'}}));
  await assert.rejects(manager.connect({appId:'slack',token:'xoxb-fixture'}),/Slack rejected/);
  provider = 'notion';
  const connection = await manager.connect({appId:'notion',token:'ntn-fixture'});
  assert.equal(connection.identity.id,'bot-1');
});
test('user-created catalogue application connects using declared stable identity probe',async t => {
  const {manager,store} = fixture(t,async request => {
    assert.equal(request.url,'https://api.example.com/v1/me');
    assert.deepEqual(request.allowedOrigins,['https://api.example.com']);
    return {status:200,data:{account:{id:'custom-123',name:'Custom user'}}};
  });
  store.put('applications',{id:'custom',name:'Custom',apiOrigins:['https://api.example.com'],webOrigins:[],identityProbe:{path:'/v1/me',idPointer:'/account/id',displayNamePointer:'/account/name'}});
  assert.equal(catalogFor(store).find(app => app.id === 'custom').authMethods[0],'token');
  const connection = await manager.connect({appId:'custom',token:'custom-secret'});
  assert.equal(connection.status,'ready'); assert.equal(connection.identity.id,'custom-123');
  store.put('applications',{...store.get('applications','custom'),apiOrigins:['https://changed.example.com']});
  assert.deepEqual((await manager.credentials(connection.id)).allowedOrigins,['https://api.example.com']);
  assert.equal((await manager.check(connection.id)).status,'ready');
});
test('vault rejects tampering without leaking ciphertext or plaintext',t => {
  const {vault,dir} = fixture(t,async () => {});
  vault.set('example',{accessToken:'secret'});
  const path = join(dir,'vault',readdirSync(join(dir,'vault')).find(name => name.endsWith('.enc')));
  const encrypted = JSON.parse(readFileSync(path,'utf8'));
  encrypted.tag = Buffer.alloc(16).toString('base64'); writeFileSync(path,JSON.stringify(encrypted));
  assert.throws(() => vault.get('example'),/^Error: Credential record cannot be decrypted\.$/);
});
test('audit excludes sensitive fields recursively',t => {
  const {store} = fixture(t,async () => {});
  const audit = store.audit({type:'safe',accessToken:'private',nested:{password:'private',Authorization:'Bearer private',count:1},message:'Bearer private'});
  assert.equal(JSON.stringify(audit).includes('private'),false);
  assert.equal(audit.nested.count,1);
});

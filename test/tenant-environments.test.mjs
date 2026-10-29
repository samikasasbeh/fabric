import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {EnvironmentStores, tenantScope, DESIGNATION_FILE} from '../lib/tenant/environments.mjs';
import {PLATFORM_COLLECTIONS} from '../lib/repositories/tenant.mts';
import {createApp} from '../server.mjs';

// F03.0a (docs/F03-DEVELOPER-LAYER.md): sealed storage per developer environment. Every case here is an attempt by one
// environment to reach another's data, plus a control that the same action on its own data works.
const A = {organizationId: 'acme', projectId: 'agent', environmentId: 'production'};
const B = {organizationId: 'beta', projectId: 'agent', environmentId: 'production'};
const ADEV = {...A, environmentId: 'development'};

function setup(t, options = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-tenants-'));
  const stores = new EnvironmentStores({root, ...options});
  t.after(() => { try { stores.closeAll(); } catch {} rmSync(root, {recursive: true, force: true}); });
  return {root, stores};
}
const digest = dir => {
  const files = [];
  const walk = folder => { for (const name of readdirSync(folder, {withFileTypes: true})) { const full = path.join(folder, name.name); if (name.isDirectory()) walk(full); else files.push(`${path.relative(dir, full)}:${createHash('sha256').update(readFileSync(full)).digest('hex')}`); } };
  if (existsSync(dir)) walk(dir);
  return files.sort().join('\n');
};

test('each environment gets its own folder, database and vault key; the same ids in two environments never collide', t => {
  const {stores} = setup(t);
  const a = stores.open(A), b = stores.open(B), dev = stores.open(ADEV);
  assert.notEqual(a.folder, b.folder); assert.notEqual(a.folder, dev.folder);
  assert.notDeepEqual(readFileSync(path.join(a.folder, 'vault', 'master.key')), readFileSync(path.join(b.folder, 'vault', 'master.key')));
  a.repository.put('connections', {id: 'same-id', appId: 'gmail', label: 'A'});
  b.repository.put('connections', {id: 'same-id', appId: 'gmail', label: 'B'});
  assert.equal(a.repository.get('connections', 'same-id').label, 'A');
  assert.equal(b.repository.get('connections', 'same-id').label, 'B');
  assert.equal(dev.repository.get('connections', 'same-id'), null, 'development is sealed from production too');
  assert.equal(a.repository.get('connections', 'same-id').scope, 'acme/agent/production', 'stamped on write');
  assert.equal(stores.open(A), a, 'opened once and cached');
});

test('a document carrying another environment\'s scope, or none, is refused on read and on write', t => {
  const {stores} = setup(t);
  const a = stores.open(A);
  assert.throws(() => a.repository.put('connections', {id: 'x', scope: 'beta/agent/production'}), {code: 'scope_mismatch'});
  // A row planted directly in A's database file (for example copied from B) is refused, not served.
  const db = new DatabaseSync(path.join(a.folder, 'fabric.sqlite'));
  db.prepare('INSERT INTO documents(collection,id,document) VALUES(?,?,?)').run('connections', 'planted', JSON.stringify({id: 'planted', scope: 'beta/agent/production'}));
  db.prepare('INSERT INTO documents(collection,id,document) VALUES(?,?,?)').run('connections', 'bare', JSON.stringify({id: 'bare'}));
  db.close();
  assert.throws(() => a.repository.get('connections', 'planted'), {code: 'scope_mismatch'});
  assert.throws(() => a.repository.get('connections', 'bare'), {code: 'scope_mismatch'});
  assert.throws(() => a.repository.list('connections'), {code: 'scope_mismatch'});
  assert.throws(() => a.repository.put('connections', {id: 'planted', label: 'overwrite'}), {code: 'scope_mismatch'}, 'cannot overwrite a foreign row');
  assert.throws(() => a.repository.delete('connections', 'planted'), {code: 'scope_mismatch'});
  a.repository.audit({type: 'connection.connected', connectionId: 'c1'});
  assert.equal(a.repository.list('activity')[0].scope, 'acme/agent/production', 'audit rows carry the scope');
});

test('a vault record copied from one environment to another fails to decrypt', t => {
  const {stores} = setup(t);
  const a = stores.open(A), b = stores.open(B);
  a.vault.set('connection-1', {accessToken: 'synthetic-a'});
  assert.deepEqual(a.vault.get('connection-1'), {accessToken: 'synthetic-a'});
  const name = id => `${createHash('sha256').update(id).digest('hex')}.enc`;
  copyFileSync(path.join(a.folder, 'vault', name('acme/agent/production:connection-1')), path.join(b.folder, 'vault', name('beta/agent/production:connection-1')));
  assert.throws(() => b.vault.get('connection-1'), /cannot be decrypted/);
  assert.equal(b.vault.get('other'), null);
});

test('platform collections are read-only for every environment and come only from the platform catalog', t => {
  const {stores} = setup(t);
  const a = stores.open(A);
  for (const collection of PLATFORM_COLLECTIONS) {
    assert.throws(() => a.repository.put(collection, {id: 'cap-1'}), {code: 'platform_read_only'}, collection);
    assert.throws(() => a.repository.delete(collection, 'cap-1'), {code: 'platform_read_only'}, collection);
    assert.equal(a.repository.get(collection, 'cap-1'), null, `${collection}: no catalog attached, nothing served`);
  }
  const catalog = {get: (collection, id) => ({id, collection}), list: collection => [{id: 'only', collection}]};
  const withCatalog = setup(t, {catalog}).stores.open(A);
  assert.deepEqual(withCatalog.repository.get('capabilities', 'cap-1'), {id: 'cap-1', collection: 'capabilities'});
});

test('a folder is opened only by its own environment: designations, symbolic links, forbidden roots and bad ids are refused', t => {
  const {root, stores} = setup(t);
  const a = stores.open(A); stores.open(B); stores.closeAll();
  // Swap the designations: opening B's folder as B now finds A's designation and refuses.
  const bMarker = path.join(stores.folder(B), DESIGNATION_FILE);
  writeFileSync(bMarker, readFileSync(path.join(a.folder, DESIGNATION_FILE)));
  assert.throws(() => stores.open(B), {code: 'designation_mismatch'});
  // A folder holding data but no designation (a local runtime folder) is never adopted.
  const local = stores.folder({...B, organizationId: 'gamma'});
  mkdirSync(local, {recursive: true}); writeFileSync(path.join(local, 'fabric.sqlite'), '');
  assert.throws(() => stores.open({...B, organizationId: 'gamma'}), {code: 'designation_mismatch'});
  // Ids: no dots, slashes, capitals or empty values; environments are development or production only.
  for (const bad of ['..', 'a/b', 'Acme', '', 'a.b', 'x'.repeat(64)]) assert.throws(() => tenantScope({...A, organizationId: bad}), {code: 'invalid_scope'}, bad);
  assert.throws(() => tenantScope({...A, environmentId: 'Env_1'}), {code: 'invalid_scope'});
  assert.equal(tenantScope({organizationId: 'org_abc', projectId: 'prj_abc', environmentId: 'env_abc'}).environmentId, 'env_abc', 'prefixed ids are valid');
  // A symbolic link anywhere under the root is refused.
  const outside = mkdtempSync(path.join(tmpdir(), 'fabric-outside-'));
  t.after(() => rmSync(outside, {recursive: true, force: true}));
  symlinkSync(outside, path.join(root, 'orgs', 'delta'));
  assert.throws(() => stores.open({...A, organizationId: 'delta'}), {code: 'forbidden_root'});
  assert.throws(() => new EnvironmentStores({root: path.join(root, 'orgs', 'delta')}), {code: 'forbidden_root'});
  // The data root may not be, sit in, or contain a forbidden folder (the local runtime's .fabric, certification data).
  const certification = path.join(outside, 'data-4320');
  assert.throws(() => new EnvironmentStores({root: path.join(certification, 'tenants'), forbiddenRoots: [certification]}), {code: 'forbidden_root'});
  assert.throws(() => new EnvironmentStores({root: outside, forbiddenRoots: [certification]}), {code: 'forbidden_root'});
  assert.throws(() => new EnvironmentStores({root: 'relative/path'}), {code: 'invalid_root'});
});

test('destroying one environment removes its database and vault key and nothing else; damage in one never blocks another', t => {
  const {stores} = setup(t);
  const a = stores.open(A), b = stores.open(B);
  a.repository.put('connections', {id: 'c1'}); b.repository.put('connections', {id: 'c1'});
  b.vault.set('k', {v: 1});
  stores.close(B);
  const before = digest(stores.folder(B));
  // Damage A's database file; B keeps working.
  stores.close(A);
  writeFileSync(path.join(stores.folder(A), 'fabric.sqlite'), 'not a database');
  const b2 = stores.open(B);
  b2.repository.put('connections', {id: 'c2'});
  assert.equal(b2.repository.get('connections', 'c1').id, 'c1');
  stores.close(B);
  assert.notEqual(digest(stores.folder(B)), '', 'B still has its files');
  assert.equal(stores.destroy(A), true);
  assert.equal(existsSync(stores.folder(A)), false);
  const after = digest(stores.folder(B));
  assert.equal(after.split('\n').filter(line => line.startsWith('vault/')).join(), before.split('\n').filter(line => line.startsWith('vault/')).join(), 'B\'s vault untouched');
  assert.deepEqual(stores.open(B).vault.get('k'), {v: 1});
});

test('an environment with work in flight is never closed, evicted or destroyed; a second process cannot open it', t => {
  const {root, stores} = setup(t, {maxOpen: 2});
  stores.open(A); stores.pin(A);
  stores.open(B);
  stores.open(ADEV);
  assert.equal(stores.isOpen(A), true, 'the pinned environment stays open');
  assert.equal(stores.isOpen(B), false, 'the least recently used unpinned one closed');
  assert.throws(() => stores.close(A), {code: 'pinned'});
  assert.throws(() => stores.destroy(A), {code: 'pinned'});
  stores.pin(ADEV);
  // Every slot busy: the cache grows past maxOpen rather than lock another environment out (review ISO-3).
  assert.ok(stores.open(B)); assert.equal(stores.isOpen(A) && stores.isOpen(ADEV), true);
  stores.unpin(ADEV); stores.unpin(A);
  assert.throws(() => stores.unpin(A), {code: 'not_pinned'});
  // Another holder of the same environment (here a live process's lock) is refused.
  const other = new EnvironmentStores({root});
  assert.throws(() => other.open(A), {code: 'locked'});
  stores.close(A);
  assert.ok(other.open(A));
  other.closeAll();
});

test('the single-owner runtime refuses a developer environment folder and leaves its database untouched', async t => {
  const {stores} = setup(t);
  const a = stores.open(A);
  a.repository.put('connections', {id: 'c1'});
  stores.close(A);
  const before = digest(a.folder);
  await assert.rejects(createApp({dataDir: a.folder, port: 0}), /belongs to the developer layer/);
  assert.equal(digest(a.folder), before);
});

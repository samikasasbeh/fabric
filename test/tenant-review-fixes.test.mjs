import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync, symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {EnvironmentStores, resolveTenantRoot, insideTenantData, takeLock, releaseLock} from '../lib/tenant/environments.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {TenantRegistry} from '../lib/tenant/registry.mjs';
import {createApp} from '../server.mjs';

// The independent security review of F03.0 (7 findings): each fix has a test that fails without it.
const A = {organizationId: 'acme', projectId: 'agent', environmentId: 'production'};
const temp = (t, prefix = 'fabric-review-') => { const dir = mkdtempSync(path.join(tmpdir(), prefix)); t.after(() => rmSync(dir, {recursive: true, force: true})); return dir; };

test('finding 1: the single-owner runtime refuses the tenant root, the platform catalog, the registry and anything under them', async t => {
  const root = temp(t);
  new PlatformStore({root}).close();
  new TenantRegistry({root}).close();
  assert.equal(existsSync(path.join(root, 'tenant-root.json')), true, 'the root carries its marker');
  for (const dataDir of [root, path.join(root, 'platform'), path.join(root, 'registry'), path.join(root, 'anything', 'below')]) {
    assert.equal(insideTenantData(dataDir), true, dataDir);
    await assert.rejects(createApp({dataDir, port: 0}), /belongs to the developer layer/, dataDir);
  }
  assert.equal(insideTenantData(temp(t)), false);
  // A folder that does not exist yet, reached through a link into tenant data, is inside it too (exit check 6).
  mkdirSync(path.join(root, 'orgs'), {recursive: true});
  const outside = temp(t, 'fabric-link-'), link = path.join(outside, 'into-tenant');
  symlinkSync(path.join(root, 'orgs'), link);
  for (const dataDir of [link, path.join(link, 'new-folder'), path.join(link, 'new', 'deeper')]) {
    assert.equal(insideTenantData(dataDir), true, dataDir);
    await assert.rejects(createApp({dataDir, port: 0}), /belongs to the developer layer/, dataDir);
  }
  assert.equal(existsSync(path.join(root, 'orgs', 'new-folder')), false, 'nothing was created inside tenant data');
});

test('finding 3: destroy is refused while another holder has the environment open; a released handle\'s vault refuses', t => {
  const root = temp(t);
  const server = new EnvironmentStores({root}), admin = new EnvironmentStores({root});
  const handle = server.open(A);
  handle.vault.set('k', {v: 1});
  assert.throws(() => admin.destroy(A), {code: 'locked'});
  assert.equal(existsSync(admin.folder(A)), true);
  server.close(A);
  assert.throws(() => handle.vault.get('k'), {code: 'closed'});
  assert.throws(() => handle.vault.set('k', {v: 2}), {code: 'closed'});
  assert.equal(admin.destroy(A), true);
  assert.equal(existsSync(admin.folder(A)), false);
});

test('finding 4: the lock is an operating-system lock; a leftover lock file never blocks and two holders never coexist', t => {
  const root = temp(t), stores = new EnvironmentStores({root});
  const folder = stores.folder(A);
  mkdirSync(folder, {recursive: true});
  writeFileSync(path.join(folder, 'environment.lock'), '12345');
  const handle = stores.open(A);
  assert.ok(handle, 'a leftover file with a dead process id does not block');
  assert.throws(() => new EnvironmentStores({root}).open(A), {code: 'locked'});
  const file = path.join(temp(t), 'x.lock'), lock = takeLock(file);
  assert.throws(() => takeLock(file), {code: 'locked'});
  releaseLock(lock);
  releaseLock(takeLock(file));
  stores.closeAll();
});

test('finding 5: the forbidden-root check sees through letter case, and the top of the disk is refused', t => {
  const base = temp(t), local = path.join(base, 'local');
  mkdirSync(local);
  assert.throws(() => resolveTenantRoot(path.join(base, 'LOCAL', 'tenants'), [local]), {code: 'forbidden_root'});
  assert.throws(() => resolveTenantRoot(path.join(base, 'Local'), [local]), {code: 'forbidden_root'});
  assert.throws(() => resolveTenantRoot('/', [local]), {code: 'forbidden_root'});
  assert.throws(() => resolveTenantRoot('/', []), {code: 'forbidden_root'}, 'the top of the disk on its own rule');
  // Folders that do not exist yet keep the case they were typed in; the comparison must still see them as one.
  const future = path.join(base, 'not-yet', 'local');
  assert.throws(() => resolveTenantRoot(path.join(base, 'NOT-YET', 'LOCAL', 'tenants'), [future]), {code: 'forbidden_root'});
  assert.ok(resolveTenantRoot(path.join(base, 'tenants'), [local]));
});

test('finding 6: a root may not sit in or be a Fabric data folder; extra forbidden roots come from the operator; destroy refuses nested data', t => {
  const base = temp(t);
  const stores = new EnvironmentStores({root: path.join(base, 'root')});
  const handle = stores.open(A);
  assert.throws(() => resolveTenantRoot(path.join(handle.folder, 'nested-root')), {code: 'forbidden_root'}, 'not inside an environment');
  const runtime = path.join(base, 'runtime');
  mkdirSync(runtime); writeFileSync(path.join(runtime, 'fabric.sqlite'), '');
  assert.throws(() => resolveTenantRoot(runtime), {code: 'forbidden_root'}, 'not a local runtime folder');
  assert.throws(() => resolveTenantRoot(path.join(runtime, 'tenants')), {code: 'forbidden_root'}, 'not inside one');
  const certification = path.join(base, 'data-4320');
  const previous = process.env.FABRIC_TENANT_FORBIDDEN_ROOTS;
  process.env.FABRIC_TENANT_FORBIDDEN_ROOTS = certification;
  t.after(() => { if (previous === undefined) delete process.env.FABRIC_TENANT_FORBIDDEN_ROOTS; else process.env.FABRIC_TENANT_FORBIDDEN_ROOTS = previous; });
  assert.throws(() => resolveTenantRoot(path.join(certification, 'tenants')), {code: 'forbidden_root'});
  // A foreign marker planted inside an environment stops destroy from deleting it.
  stores.close(A);
  mkdirSync(path.join(handle.folder, 'smuggled'));
  writeFileSync(path.join(handle.folder, 'smuggled', 'platform-catalog.json'), '{}');
  assert.throws(() => stores.destroy(A), {code: 'designation_mismatch'});
});

test('finding 7: custom applications and non-string collection names cannot pass the platform wall', t => {
  const root = temp(t), env = new EnvironmentStores({root}).open(A);
  assert.throws(() => env.repository.put('applications', {id: 'custom-app'}), {code: 'platform_read_only'});
  for (const bad of [['capabilities'], {toString: () => 'capabilities'}, 'capabilities/x', '']) {
    assert.throws(() => env.repository.put(bad, {id: 'cap'}), {code: 'platform_read_only'}, String(bad));
    assert.throws(() => env.repository.get(bad, 'cap'), {code: 'platform_read_only'}, String(bad));
  }
  const platform = new PlatformStore({root: temp(t)});
  assert.throws(() => platform.put(['capabilities'], {id: 'c'}), {code: 'not_platform'});
  platform.close();
});

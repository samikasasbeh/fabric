import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {EnvironmentStores} from '../lib/tenant/environments.mjs';
import {PlatformStore, PlatformCatalog} from '../lib/tenant/platform.mjs';
import {discoverToPlatform, promoteInPlatform, main} from '../scripts/tenant-admin.mjs';
import {runCoverage} from '../scripts/coverage.mjs';

// F03.0b: the platform catalog. The operator's command writes reviewed operations once; every developer environment
// reads them through a read-only catalog and can never write them.
const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'coverage');
const SPECS = Object.fromEntries(JSON.parse(readFileSync(path.join(FIXTURES, 'manifest.json'), 'utf8')).map(entry => [entry.appId, entry]));
const load = appId => { const spec = SPECS[appId]; return {...spec, document: JSON.parse(readFileSync(path.join(FIXTURES, spec.file), 'utf8'))}; };
const appEntry = spec => ({id: spec.appId, name: spec.appId, discovery: {kind: spec.kind, url: spec.sourceUrl}, apiOrigins: spec.apiOrigins});
const fixtureRequest = spec => async () => ({status: 200, headers: {'content-type': 'application/json'}, data: structuredClone(spec.document)});
const A = {organizationId: 'acme', projectId: 'agent', environmentId: 'production'};

function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-platform-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  return root;
}

test('the catalog command discovers into the platform catalog, byte for byte the same capabilities as today\'s compiler (I1)', async t => {
  const root = setup(t);
  for (const appId of ['coverage', 'coverage-google']) {
    const spec = load(appId);
    const map = await discoverToPlatform({root, appId, apps: [appEntry(spec)], request: fixtureRequest(spec)});
    const catalog = new PlatformCatalog({root});
    const stored = catalog.list('capabilities').filter(capability => capability.appId === appId).map(capability => capability.id).sort();
    const reference = await runCoverage(spec);
    const expected = [...new Set(reference.discovery.operations.map(operation => operation.capabilityId).filter(Boolean))].sort();
    assert.deepEqual(stored, expected, appId);
    assert.ok(stored.length > 0, appId);
    assert.equal(catalog.get('applicationMaps', appId).operations.length, map.operations.length);
    assert.ok(catalog.list('capabilities').filter(capability => capability.appId === appId).every(capability => capability.status === 'candidate'), 'discovery never activates');
    catalog.close();
  }
});

test('promote activates named candidates only, all or nothing, each audited with its definition hash', async t => {
  const root = setup(t);
  const spec = load('coverage-google');
  await discoverToPlatform({root, appId: 'coverage-google', apps: [appEntry(spec)], request: fixtureRequest(spec)});
  const candidates = (() => { const catalog = new PlatformCatalog({root}); try { return catalog.list('capabilities').map(capability => capability.id); } finally { catalog.close(); } })();
  assert.throws(() => promoteInPlatform({root, appId: 'coverage-google', capabilityIds: [candidates[0], 'not-a-capability']}), /not a capability of coverage-google/);
  const unchanged = new PlatformCatalog({root});
  assert.equal(unchanged.get('capabilities', candidates[0]).status, 'candidate', 'a bad list changes nothing');
  unchanged.close();
  assert.throws(() => promoteInPlatform({root, appId: 'other-app', capabilityIds: [candidates[0]]}), /not a capability of other-app/);
  assert.deepEqual(promoteInPlatform({root, appId: 'coverage-google', capabilityIds: [candidates[0]]}), [candidates[0]]);
  assert.throws(() => promoteInPlatform({root, appId: 'coverage-google', capabilityIds: [candidates[0]]}), /is active, not a candidate/);
  const store = new PlatformStore({root});
  const audit = store.activity().filter(event => event.type === 'platform.capability_promoted');
  assert.equal(audit.length, 1); assert.equal(audit[0].capabilityId, candidates[0]); assert.match(audit[0].definitionHash, /^[0-9a-f]{64}$/);
  assert.ok(store.activity().some(event => event.type === 'platform.discovered' && event.appId === 'coverage-google'));
  store.close();
});

test('environments read the platform catalog and can never write it; the catalog serves platform collections only', async t => {
  const root = setup(t);
  const spec = load('coverage');
  await discoverToPlatform({root, appId: 'coverage', apps: [appEntry(spec)], request: fixtureRequest(spec)});
  const catalog = new PlatformCatalog({root});
  const stores = new EnvironmentStores({root, catalog});
  t.after(() => { stores.closeAll(); catalog.close(); });
  const env = stores.open(A);
  const capabilities = env.repository.list('capabilities');
  assert.ok(capabilities.length > 0);
  assert.deepEqual(env.repository.get('capabilities', capabilities[0].id), capabilities[0]);
  assert.throws(() => env.repository.put('capabilities', {...capabilities[0], status: 'active'}), {code: 'platform_read_only'});
  assert.throws(() => catalog.get('connections', 'x'), {code: 'not_platform'});
  assert.equal(typeof catalog.put, 'undefined', 'the tenant view has no write method');
  // The platform store is single-holder and refuses non-platform collections.
  const operator = new PlatformStore({root});
  assert.throws(() => new PlatformStore({root}), {code: 'locked'});
  assert.throws(() => operator.put('connections', {id: 'c'}), {code: 'not_platform'});
  operator.close();
  // An environment folder cannot be the platform folder, and a missing catalog is named.
  assert.throws(() => new PlatformCatalog({root: path.join(root, 'empty')}), {code: 'platform_catalog_missing'});
});

test('the command refuses forbidden roots and bad arguments', async t => {
  const root = setup(t);
  await assert.rejects(main(['catalog', 'discover']), /Usage/);
  await assert.rejects(main(['catalog', 'delete', 'x', '--root', root]), /Usage/);
  assert.throws(() => promoteInPlatform({root, appId: 'x', capabilityIds: []}), /Name 1 to 500 capability ids/);
  await assert.rejects(discoverToPlatform({root: path.join(root, 'local'), appId: 'coverage', apps: [], forbiddenRoots: [path.join(root, 'local')]}), {code: 'forbidden_root'});
  await assert.rejects(discoverToPlatform({root, appId: 'unknown', apps: []}), /Unknown catalog application/);
});

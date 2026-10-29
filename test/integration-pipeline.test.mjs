import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonicalHash, validateCapability } from '../lib/compiler.mjs';
import { assessMaintenance, buildIntegrationBatch, buildIntegrationPackage, validateIntegrationManifest } from '../lib/integration-pipeline.mjs';

const copy = value => structuredClone(value);
const load = name => JSON.parse(readFileSync(new URL(`../examples/${name}.openapi.json`, import.meta.url), 'utf8'));
const document = () => ({
  openapi: '3.1.0',
  info: { title: 'Local reviewed fixture', version: '1' },
  servers: [{ url: 'https://api.example.com/v1' }],
  paths: {
    '/items': { get: { operationId: 'list-items', responses: { 200: { description: 'Items' } } } },
    '/items/{id}': { delete: { operationId: 'delete-item', parameters: [{ in: 'path', name: 'id', required: true, schema: { type: 'string' } }], responses: { 204: { description: 'Deleted' } } } },
  },
});
const manifest = (appId = 'fixture') => ({
  schemaVersion: 1, appId, version: '1.0.0',
  source: { kind: 'openapi', url: 'https://docs.example.com/api', allowedOrigins: ['https://api.example.com'] },
  auth: { kind: 'oauth2' },
  maintenance: { owner: 'api-team', backupOwner: 'platform-team', tier: 'pilot', reviewIntervalDays: 30 },
});
const entry = appId => ({ manifest: manifest(appId), document: document() });
const built = () => buildIntegrationPackage(entry('fixture'));
const observation = pkg => ({ packageHash: pkg.packageHash, sourceHash: pkg.sourceHash, checkedAt: '2026-10-10T12:00:00Z', lastReviewedAt: '2026-10-01T12:00:00Z' });
const now = '2026-10-11T12:00:00Z';
const assess = (pkg, observed = observation(pkg), at = now) => assessMaintenance({ package: pkg, observation: observed, now: at });

test('strict manifest validation returns a detached normalized manifest', () => {
  const input = manifest();
  input.source.allowedOrigins = ['https://z.example.com/', 'https://api.example.com'];
  input.source.sourceHash = canonicalHash(document());
  const validated = validateIntegrationManifest(input);
  assert.deepEqual(validated.source.allowedOrigins, ['https://api.example.com', 'https://z.example.com']);
  validated.maintenance.owner = 'changed';
  assert.equal(input.maintenance.owner, 'api-team');
  assert.deepEqual(input.source.allowedOrigins, ['https://z.example.com/', 'https://api.example.com']);
});

test('manifest rejects unknown versions, credentials, authority claims, and malformed bounded metadata', () => {
  const mutations = [
    m => { m.schemaVersion = 2; },
    m => { delete m.schemaVersion; },
    m => { m.appId = 'Wrong App'; },
    m => { m.version = '01.0.0'; },
    m => { m.version = '1.0'; },
    m => { m.version = 1; },
    m => { m.version = `${'1'.repeat(65)}.0.0`; },
    m => { m.status = 'certified'; },
    m => { m.auth.kind = 'bearer'; },
    m => { m.auth.token = 'DO-NOT-EMIT'; },
    m => { m.auth.scopes = ['all']; },
    m => { m.source.kind = 'script'; },
    m => { m.source.sourceHash = 'A'.repeat(64); },
    m => { m.source.sourceHash = 123; },
    m => { m.maintenance.owner = ''; },
    m => { m.maintenance.owner = ' api-team'; },
    m => { m.maintenance.owner = 'a'.repeat(161); },
    m => { m.maintenance.backupOwner = 'API-TEAM'; },
    m => { m.maintenance.tier = 'enterprise'; },
    m => { m.maintenance.reviewIntervalDays = 0; },
    m => { m.maintenance.reviewIntervalDays = 366; },
    m => { m.maintenance.reviewIntervalDays = 1.5; },
    m => { m.maintenance.reviewIntervalDays = '30'; },
  ];
  for (const mutate of mutations) { const input = manifest(); mutate(input); assert.throws(() => validateIntegrationManifest(input)); }
  for (const kind of ['oauth2', 'api-key', 'none']) {
    const input = manifest(); input.auth.kind = kind;
    assert.equal(validateIntegrationManifest(input).auth.kind, kind);
  }
});

test('source and origin URLs reject credentials, query, fragments, private literals and encoded authority', () => {
  const invalid = [
    'http://api.example.com', 'https://user:secret@api.example.com',
    'https://api.example.com?token=secret', 'https://api.example.com/#secret',
    'https://127.0.0.1', 'https://[::1]', 'https://metadata.google.internal',
    'https://localhost', 'https://api.example.com:8080', 'https://api.example.com.',
    'https://%61pi.example.com', 'https://api.example.com/%2e%2e/admin',
    'https://api.example.com/../admin', 'https://api.example.com\\@evil.example.com',
    'https://{tenant}.example.com', 'https://api.example.com?', 'https://api.example.com/#',
    'https://@api.example.com', 'https://api..example.com', 'https://-api.example.com',
  ];
  for (const url of invalid) {
    const input = manifest(); input.source.url = url;
    assert.throws(() => validateIntegrationManifest(input), undefined, url);
    input.source.url = manifest().source.url; input.source.allowedOrigins = [url];
    assert.throws(() => validateIntegrationManifest(input), undefined, url);
  }
  for (const origins of [[], Array(17).fill('https://api.example.com'), ['https://api.example.com/path'], ['https://api.example.com', 'https://api.example.com/']]) {
    const input = manifest(); input.source.allowedOrigins = origins;
    assert.throws(() => validateIntegrationManifest(input));
  }
});

test('HTTPS scheme casing matches the manifest schema and origin normalization remains stable', () => {
  for (const scheme of ['HTTPS://', 'Https://', 'hTTps://']) {
    const input = entry();
    input.manifest.source.url = `${scheme}docs.example.com/api`;
    assert.throws(() => validateIntegrationManifest(input.manifest), /lowercase https/);
    input.manifest.source.url = manifest().source.url;
    input.manifest.source.allowedOrigins = [`${scheme}api.example.com`];
    assert.throws(() => validateIntegrationManifest(input.manifest), /lowercase https/);
    input.manifest.source.allowedOrigins = manifest().source.allowedOrigins;
    input.document.servers[0].url = `${scheme}api.example.com/v1`;
    assert.throws(() => buildIntegrationPackage(input), /lowercase https/);
  }
  const input = manifest(); input.source.allowedOrigins = ['https://API.EXAMPLE.COM/'];
  assert.deepEqual(validateIntegrationManifest(input).source.allowedOrigins, ['https://api.example.com']);
});

test('JSON guards reject accessors without invoking them and reject pollution or cyclic inputs', () => {
  let invoked = false;
  const accessor = { get schemaVersion() { invoked = true; return 1; } };
  assert.throws(() => validateIntegrationManifest(accessor), /accessor/);
  const wrapper = { get manifest() { invoked = true; return manifest(); }, document: document() };
  assert.throws(() => buildIntegrationPackage(wrapper), /accessor/);
  const cyclic = manifest(); cyclic.self = cyclic;
  assert.throws(() => validateIntegrationManifest(cyclic), /cyclic/);
  assert.throws(() => validateIntegrationManifest(JSON.parse('{"__proto__":{"polluted":true}}')), /unsafe/);
  assert.equal(invoked, false);
  assert.equal({}.polluted, undefined);
});

test('packages contain only candidates with explicit outstanding review and release gates', () => {
  const input = entry();
  const original = copy(input);
  const pkg = buildIntegrationPackage(input);
  assert.equal(pkg.schemaVersion, 1);
  assert.equal(pkg.status, 'candidate');
  assert.equal(pkg.sourceHash, canonicalHash(input.document));
  assert.deepEqual(pkg.counts, { capabilities: 2, read: 1, write: 1 });
  assert.deepEqual(pkg.requiredGates, ['scope-resource-mapping-review', 'identity-auth-setup', 'fixture-certification', 'live-certification', 'release-approval']);
  for (const capability of pkg.capabilities) {
    assert.equal(capability.status, 'candidate');
    assert.equal(capability.provenance.fingerprint, pkg.sourceHash);
    validateCapability(capability);
  }
  const { packageHash, ...content } = pkg;
  assert.equal(packageHash, canonicalHash(content));
  assert.deepEqual(input, original);
  assert.equal(Object.hasOwn(pkg, 'connected'), false);
});

test('package hashes remain stable across repeated builds and object key order', () => {
  function reversed(value) {
    if (Array.isArray(value)) return value.map(reversed);
    if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).reverse().map(key => [key, reversed(value[key])]));
    return value;
  }
  const input = entry();
  input.manifest.source.allowedOrigins.push('https://extra.example.com');
  const first = buildIntegrationPackage(input);
  const reordered = reversed(input);
  reordered.manifest.source.allowedOrigins.reverse();
  assert.deepEqual(buildIntegrationPackage(reordered), first);
  assert.deepEqual(buildIntegrationPackage(copy(input)), first);
});

test('source pins are enforced and source, auth, owner, version, and operations change package identity', () => {
  const input = entry();
  input.manifest.source.sourceHash = canonicalHash(input.document);
  assert.equal(buildIntegrationPackage(input).sourceHash, input.manifest.source.sourceHash);
  input.document.info.title = 'Changed source';
  assert.throws(() => buildIntegrationPackage(input), /sourceHash/);
  const baseline = built();
  for (const mutate of [
    e => { e.manifest.version = '1.0.1'; },
    e => { e.manifest.auth.kind = 'api-key'; },
    e => { e.manifest.maintenance.owner = 'new-team'; },
    e => { e.manifest.source.url = 'https://docs.example.com/updated'; },
    e => { e.document.info.title = 'New source'; },
    e => { delete e.document.paths['/items/{id}']; },
  ]) {
    const modified = entry(); mutate(modified);
    assert.notEqual(buildIntegrationPackage(modified).packageHash, baseline.packageHash);
  }
});

test('server origin mismatch blocks the package including ignored or referenced operation servers', () => {
  for (const mutate of [
    e => { e.document.servers[0].url = 'https://evil.example.com'; },
    e => { e.document.paths['/items'].servers = [{ url: 'https://evil.example.com' }]; },
    e => { e.document.paths['/items'].get.servers = [{ url: 'https://evil.example.com' }]; },
    e => { e.document.paths['/ignored'] = { trace: { servers: [{ url: 'https://evil.example.com' }] } }; },
    e => { e.document.components = { operations: { hidden: { servers: [{ url: 'https://evil.example.com' }] } } }; e.document.paths['/items'].get = { $ref: '#/components/operations/hidden' }; },
    e => { e.document.components = { pathItems: { hidden: { servers: [{ url: 'https://evil.example.com' }] } } }; e.document.paths['/items'] = { $ref: '#/components/pathItems/hidden' }; },
  ]) { const input = entry(); mutate(input); assert.throws(() => buildIntegrationPackage(input), /outside manifest/); }
  const input = entry(); input.document.servers[0].url = 'https://user:secret@api.example.com';
  assert.throws(() => buildIntegrationPackage(input), /credential-free/);
});

test('schema properties named servers are ordinary data and unsupported operations remain visible as warnings', () => {
  const input = entry();
  input.document.paths['/items'].post = { operationId: 'create-item', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { servers: { type: 'string' } }, additionalProperties: false } } } } };
  input.document.paths['/upload'] = { post: { requestBody: { content: { 'multipart/form-data': { schema: { type: 'string' } } } } } };
  const pkg = buildIntegrationPackage(input);
  assert.equal(pkg.counts.capabilities, 3);
  assert.ok(pkg.warnings.some(warning => warning.includes('/upload')));
  assert.equal(pkg.status, 'candidate');
});

test('external refs, operation limits and duplicate operation identifiers fail deterministically', () => {
  const external = entry(); external.document.paths['/items'] = { $ref: 'https://evil.example.com/spec' };
  assert.throws(() => buildIntegrationPackage(external), /internal/);
  const repeated = entry(); repeated.document.paths['/items/{id}'].delete.operationId = 'list-items';
  assert.throws(() => buildIntegrationPackage(repeated), /operationIds must be unique/);
  const oversized = entry(); oversized.document.paths = Object.fromEntries(Array.from({ length: 257 }, (_, index) => [`/items-${index}`, { get: { operationId: `items-${index}` } }]));
  assert.throws(() => buildIntegrationPackage(oversized), /256 operation limit/);
});

test('multi-app batch compiles reviewed GitHub and Calendar snapshots without changing their capabilities', () => {
  const github = entry('github'); github.document = load('github'); github.manifest.source.url = 'https://docs.github.com/en/rest'; github.manifest.source.allowedOrigins = ['https://api.github.com'];
  const google = entry('google-calendar'); google.document = load('google-calendar'); google.manifest.source.url = 'https://developers.google.com/workspace/calendar/api/v3/reference'; google.manifest.source.allowedOrigins = ['https://www.googleapis.com'];
  const batch = buildIntegrationBatch([github, google]);
  assert.equal(batch.status, 'candidate');
  assert.deepEqual(batch.counts, { total: 2, candidate: 2, blocked: 0, capabilities: 9 });
  assert.deepEqual(batch.results.map(result => result.appId), ['github', 'google-calendar']);
  assert.ok(batch.results.every(result => result.package.capabilities.every(capability => capability.status === 'candidate')));
  assert.deepEqual(buildIntegrationBatch([github, google]), batch);
});

test('batch isolates invalid manifests, compiler failures and accessor entries', () => {
  const invalidManifest = entry('invalid-manifest'); invalidManifest.manifest.auth.token = 'DO-NOT-EMIT';
  const invalidDocument = entry('invalid-document'); invalidDocument.document.paths = {};
  let invoked = false;
  const accessor = { get manifest() { invoked = true; return manifest(); } };
  const batch = buildIntegrationBatch([entry('valid-one'), invalidManifest, null, invalidDocument, accessor, entry('valid-two')]);
  assert.equal(batch.status, 'blocked');
  assert.deepEqual(batch.counts, { total: 6, candidate: 2, blocked: 4, capabilities: 4 });
  assert.deepEqual(batch.results.map(result => result.index), [0, 1, 2, 3, 4, 5]);
  assert.ok(batch.results.filter(result => result.status === 'blocked').every(result => !result.package && result.errors.length));
  assert.equal(JSON.stringify(batch).includes('DO-NOT-EMIT'), false);
  assert.equal(invoked, false);
});

test('every duplicate app/version is blocked; different versions and unrelated apps survive', () => {
  const first = entry('duplicated');
  const second = copy(first); second.document.info.title = 'Conflicting source';
  const version = copy(first); version.manifest.version = '1.0.1';
  const batch = buildIntegrationBatch([first, second, version, entry('unrelated')]);
  assert.deepEqual(batch.counts, { total: 4, candidate: 2, blocked: 2, capabilities: 4 });
  for (const result of batch.results.slice(0, 2)) assert.match(result.errors.join(' '), /Duplicate appId\/version/);
  const invalidDuplicate = copy(first); invalidDuplicate.manifest.maintenance.owner = '';
  assert.equal(buildIntegrationBatch([first, invalidDuplicate]).counts.blocked, 2);
});

test('invalid wrapper fields cannot bypass duplicate identity collection', () => {
  const first = entry('duplicated');
  const invalid = { ...copy(first), extra: true };
  for (const duplicates of [[first, invalid], [invalid, first]]) {
    const batch = buildIntegrationBatch([...duplicates, entry('unrelated')]);
    assert.deepEqual(batch.counts, { total: 3, candidate: 1, blocked: 2, capabilities: 2 });
    for (const result of batch.results.slice(0, 2)) {
      assert.equal(result.appId, 'duplicated');
      assert.equal(result.status, 'blocked');
      assert.match(result.errors.join(' '), /Duplicate appId\/version/);
      assert.equal(Object.hasOwn(result, 'package'), false);
    }
    const invalidResult = batch.results[duplicates.indexOf(invalid)];
    assert.match(invalidResult.errors.join(' '), /unsupported field extra/);
  }
});

test('batch cardinality is bounded and malformed array containers cannot execute getters', () => {
  assert.equal(buildIntegrationBatch(Array.from({ length: 25 }, (_, index) => entry(`app-${index}`))).counts.candidate, 25);
  for (const value of [[], {}, Array.from({ length: 26 }, () => entry()), Array(1)]) assert.throws(() => buildIntegrationBatch(value));
  let invoked = false;
  const accessor = [entry()]; Object.defineProperty(accessor, 0, { get() { invoked = true; return entry(); }, enumerable: true });
  assert.throws(() => buildIntegrationBatch(accessor), /accessor/);
  const custom = [entry()]; Object.setPrototypeOf(custom, { map() { invoked = true; } });
  assert.throws(() => buildIntegrationBatch(custom), /plain JSON array/);
  assert.equal(invoked, false);
});

test('maintenance uses only supplied timestamps and hashes without promoting the candidate', () => {
  const pkg = built();
  const original = copy(pkg);
  const result = assess(pkg);
  assert.equal(result.status, 'candidate');
  assert.equal(result.reviewDue, false);
  assert.equal(result.sourceDrift, false);
  assert.equal(result.observationStale, false);
  assert.equal(result.nextReviewAt, '2026-10-31T12:00:00.000Z');
  assert.equal(result.nextCheckAt, '2026-11-09T12:00:00.000Z');
  assert.deepEqual(result.requiredActions, []);
  assert.deepEqual(pkg, original);
  assert.deepEqual(assess(pkg), result);
  assert.equal(Object.hasOwn(result, 'healthy'), false);
  assert.equal(Object.hasOwn(result, 'certified'), false);
});

test('maintenance reports due reviews at the boundary and missing review history', () => {
  const pkg = built();
  const observed = observation(pkg); observed.checkedAt = '2026-10-31T12:00:00Z';
  const boundary = assess(pkg, observed, '2026-10-31T12:00:00Z');
  assert.equal(boundary.reviewDue, true);
  assert.equal(boundary.observationStale, false);
  assert.deepEqual(boundary.requiredActions, ['maintenance-review']);
  delete observed.lastReviewedAt;
  const missing = assess(pkg, observed, '2026-10-31T12:00:00Z');
  assert.equal(missing.nextReviewAt, null);
  assert.equal(missing.reviewDue, true);
});

test('stale observations cannot be described as current, and source changes require review', () => {
  const pkg = built();
  const observed = observation(pkg); observed.sourceHash = 'a'.repeat(64);
  const drift = assess(pkg, observed);
  assert.equal(drift.sourceDrift, true);
  assert.deepEqual(drift.requiredActions, ['source-change-review']);
  observed.sourceHash = pkg.sourceHash;
  const stale = assess(pkg, observed, '2026-11-09T12:00:00Z');
  assert.equal(stale.observationStale, true);
  assert.equal(stale.sourceDrift, false);
  assert.equal(stale.status, 'blocked');
  assert.deepEqual(stale.requiredActions, ['maintenance-review', 'source-check']);
});

test('maintenance rejects missing inputs, future dates, invalid dates and unrelated package observations', () => {
  const pkg = built();
  for (const mutate of [
    o => { o.checkedAt = '2026-10-12T12:00:00Z'; },
    o => { o.lastReviewedAt = '2026-10-11T12:00:00Z'; },
    o => { o.lastReviewedAt = '2026-02-31T12:00:00Z'; },
    o => { o.checkedAt = '2026-10-10T12:00:00'; },
    o => { o.checkedAt = '2026-10-10T24:00:00Z'; },
    o => { o.sourceHash = 'missing'; },
    o => { o.packageHash = 'b'.repeat(64); },
    o => { delete o.packageHash; },
    o => { o.certified = true; },
  ]) { const observed = observation(pkg); mutate(observed); assert.throws(() => assess(pkg, observed)); }
  assert.throws(() => assessMaintenance({ package: pkg, observation: observation(pkg) }));
  assert.throws(() => assessMaintenance({ package: pkg, now }));
});

test('maintenance verifies package integrity and candidate semantics before considering observations', () => {
  const original = built();
  for (const mutate of [
    p => { p.manifest.maintenance.reviewIntervalDays = 365; },
    p => { p.status = 'certified'; },
    p => { p.capabilities[0].status = 'active'; },
    p => { p.capabilities[0].request.url = 'https://evil.example.com'; },
    p => { p.counts.capabilities = 999; },
    p => { p.requiredGates = []; },
  ]) { const pkg = copy(original); mutate(pkg); assert.throws(() => assess(pkg), /integrity/); }
  for (const mutate of [
    p => { p.capabilities[0].status = 'active'; },
    p => { p.counts.capabilities = 999; },
    p => { p.requiredGates = []; },
    p => { p.status = 'certified'; },
  ]) {
    const pkg = copy(original); mutate(pkg);
    const { packageHash: ignored, ...content } = pkg; pkg.packageHash = canonicalHash(content);
    assert.throws(() => assess(pkg), /candidate|counts|gates/);
  }
});

test('package preparation and maintenance do not fetch any source or provider URL', () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('Network access is forbidden in this test'); };
  try {
    const pkg = built();
    assert.equal(assess(pkg).status, 'candidate');
    assert.equal(buildIntegrationBatch([entry('first'), entry('second')]).counts.candidate, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

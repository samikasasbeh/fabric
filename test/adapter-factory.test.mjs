import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../lib/store.mjs';
import { AdapterFactory } from '../lib/adapter-factory.mjs';
import { Runtime } from '../lib/runtime.mjs';
import { canonicalHash, prepareRequest } from '../lib/compiler.mjs';

// Explicit schema and transport fixtures, not live accounts. The separate
// verify-public-adapters script fetches public provider descriptions over HTTPS.
const openApiSource = 'https://schemas.example.com/fixture.json';
const googleSource = 'https://www.googleapis.com/discovery/v1/apis/fixture/v1/rest';
function openApiDocument() {
  return {
    openapi: '3.1.0', info: { title: 'Fixture inventory', version: '1' }, servers: [{ url: 'https://api.example.com/v1' }],
    paths: {
      '/items': { get: { operationId: 'listItems', parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 20 } }], responses: { 200: { description: 'Item list' } } } },
      '/items/{id}': { delete: { operationId: 'deleteItem', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 204: { description: 'Deleted' } } } },
      '/upload': { post: { operationId: 'upload', requestBody: { required: true, content: { 'multipart/form-data': { schema: { type: 'object' } } } }, responses: {} } },
    },
  };
}
function googleDocument() {
  return {
    kind: 'discovery#restDescription', discoveryVersion: 'v1', protocol: 'rest', name: 'fixture', version: 'v1',
    rootUrl: 'https://www.googleapis.com/', servicePath: 'fixture/v1/',
    schemas: { Books: { type: 'object', properties: { items: { type: 'array', items: { type: 'string' } } } } },
    resources: { books: { methods: {
      list: { id: 'fixture.books.list', httpMethod: 'GET', path: 'books', parameters: { maxResults: { type: 'integer', location: 'query', minimum: '1', maximum: '10' } }, response: { $ref: 'Books' } },
      get: { id: 'fixture.books.get', httpMethod: 'GET', path: 'books/{id}', parameters: { id: { type: 'string', location: 'path', required: true } } },
    } } },
  };
}
async function setup(t, { kind = 'openapi', document, request, extraApps = [] } = {}) {
  const dataDir = await mkdtemp(join(tmpdir(), 'fabric-factory-test-'));
  const store = new Store({ dataDir });
  t.after(async () => { store.close(); await rm(dataDir, { recursive: true, force: true }); });
  const state = { document: document || (kind === 'openapi' ? openApiDocument() : googleDocument()) };
  const apps = [{ id: 'fixture', name: 'Schema fixture', apiOrigins: [kind === 'openapi' ? 'https://api.example.com' : 'https://www.googleapis.com'], discovery: { kind, url: kind === 'openapi' ? openApiSource : googleSource } }, ...extraApps];
  const calls = [];
  const factory = new AdapterFactory({ store, catalog: () => apps, request: request || (async args => { calls.push(args); return { status: 200, data: structuredClone(state.document), headers: {} }; }) });
  return { store, factory, state, apps, calls };
}

test('OpenAPI builds real constrained definitions and evidence without connecting, activating or granting', async t => {
  const { factory, store, state, calls } = await setup(t);
  const report = await factory.build({ appId: 'fixture' });
  assert.equal(report.status, 'built');
  assert.deepEqual(report.counts, { total: 3, built: 2, unsupported: 1 });
  assert.equal(report.source.documentHash, canonicalHash(state.document));
  assert.equal(report.source.url, openApiSource);
  assert.equal(report.validation.passed, true);
  assert.equal(report.accountVerified, false);
  assert.equal(report.connectionCreated, false);
  assert.equal(report.permissionsGranted, false);
  assert.match(report.unsupported[0].reason, /json|multipart/i);
  assert.deepEqual(calls.map(call => [call.url, call.method]), [[openApiSource, 'GET']]);
  const read = store.get('capabilities', report.capabilities.find(cap => cap.operationId === 'listItems').id);
  assert.equal(read.status, 'candidate');
  assert.equal(prepareRequest(read, { limit: 4 }).url, 'https://api.example.com/v1/items?limit=4');
  assert.throws(() => prepareRequest(read, { limit: 21 }), /maximum/);
  assert.throws(() => prepareRequest(read, { token: 'not-a-real-secret' }), /undeclared/);
  assert.equal(report.capabilities.find(cap => cap.operationId === 'deleteItem').effect, 'delete');
  for (const collection of ['connections', 'permissions', 'jobs']) assert.deepEqual(store.list(collection), []);
  assert.deepEqual(store.get('adapterBuilds', report.id), report);
});

test('Google REST Discovery builds a different nested schema dialect through the same factory', async t => {
  const { factory, store } = await setup(t, { kind: 'google-discovery' });
  const report = await factory.build({ appId: 'fixture' });
  assert.equal(report.status, 'built');
  assert.equal(report.source.kind, 'google-discovery');
  assert.equal(report.capabilityIds.length, 2);
  const get = store.get('capabilities', report.capabilities.find(cap => cap.operationId.endsWith('.get')).id);
  assert.equal(prepareRequest(get, { id: 'book-1' }).url, 'https://www.googleapis.com/fixture/v1/books/book-1');
  assert.throws(() => prepareRequest(get, {}), /required/);
});

test('unknown or browser-only apps produce honest persisted blocked builds, not fake routes', async t => {
  const { factory, store, calls } = await setup(t, { extraApps: [{ id: 'browser-only', name: 'Browser only' }] });
  for (const appId of ['browser-only', 'missing-app']) {
    const report = await factory.build({ appId });
    assert.equal(report.status, 'blocked');
    assert.equal(report.source, null);
    assert.deepEqual(report.capabilityIds, []);
    assert.ok(report.error);
  }
  assert.equal(calls.length, 0);
  assert.equal(store.list('adapterBuilds').length, 2);
  await assert.rejects(factory.build({ appId: '../invalid' }), /valid catalog/);
});

test('HTTP failure retains prior good build and no new successful evidence', async t => {
  const { factory, store } = await setup(t);
  const good = await factory.build({ appId: 'fixture' });
  factory.discovery.request = async () => ({ status: 503, data: { error: 'not persisted in the build' } });
  const failed = await factory.build({ appId: 'fixture' });
  assert.equal(failed.status, 'blocked');
  assert.match(failed.error, /HTTP 503/);
  assert.equal(failed.source.documentHash, null);
  assert.deepEqual(store.get('adapterBuilds', good.id), good);
  assert.equal(store.list('capabilities').length, 2);
  assert.equal(factory.list({ appId: 'fixture' })[0].id, failed.id);
});

test('independent factory validation catches changed persisted source and candidate definitions', async t => {
  for (const tamper of ['source', 'candidate']) {
    const { factory, store } = await setup(t);
    const realDiscover = factory.discovery.discover.bind(factory.discovery);
    factory.discovery.discover = async args => {
      const map = await realDiscover(args);
      if (tamper === 'source') {
        const source = store.get('discoverySources', `fixture:${map.fingerprint}`);
        source.document.info.title = 'Changed after fetch'; store.put('discoverySources', source);
      } else {
        const cap = store.get('capabilities', map.operations.find(op => op.capabilityId).capabilityId);
        cap.request.url = cap.request.url.replace('https://api.example.com', 'https://unapproved.example.com'); store.put('capabilities', cap);
      }
      return map;
    };
    const report = await factory.build({ appId: 'fixture' });
    assert.equal(report.status, 'blocked');
    assert.equal(report.validation.passed, false);
    assert.match(report.error, tamper === 'source' ? /provenance hash/ : /immutable|identifier|fingerprint/i);
    assert.deepEqual(store.list('connections'), []);
  }
});

test('changing catalog authority while fetching blocks build attestation', async t => {
  const { factory, apps } = await setup(t);
  const realDiscover = factory.discovery.discover.bind(factory.discovery);
  factory.discovery.discover = async args => { const map = await realDiscover(args); apps[0].apiOrigins.push('https://other.example.com'); return map; };
  const report = await factory.build({ appId: 'fixture' });
  assert.equal(report.status, 'blocked');
  assert.match(report.error, /authority changed/);
});

test('repeat builds preserve activation and immutable IDs but never expand existing grants', async t => {
  const { factory, store, state } = await setup(t);
  const first = await factory.build({ appId: 'fixture' });
  const original = store.get('capabilities', first.capabilityIds[0]);
  store.put('capabilities', { ...original, status: 'active' }); // Explicit test review.
  const second = await factory.build({ appId: 'fixture' });
  assert.equal(second.status, 'built');
  assert.deepEqual(first.capabilityIds, second.capabilityIds);
  assert.equal(store.get('capabilities', original.id).status, 'active');
  state.document.paths['/items'].get.parameters[0].schema.maximum = 10;
  const third = await factory.build({ appId: 'fixture' });
  assert.equal(third.status, 'built');
  assert.notEqual(third.source.documentHash, first.source.documentHash);
  assert.notEqual(third.capabilities.find(cap => cap.operationId === 'listItems').id, first.capabilities.find(cap => cap.operationId === 'listItems').id);
  assert.equal(store.list('permissions').length, 0);
  assert.equal(factory.list().length, 3);
});

test('completed runtime public reads attach metadata evidence only, after explicit review', async t => {
  const { factory, store } = await setup(t);
  const report = await factory.build({ appId: 'fixture' });
  const artifact = report.capabilities.find(cap => cap.operationId === 'listItems');
  const cap = store.get('capabilities', artifact.id);
  const connection = store.put('connections', { id: 'public-fixture', appId: 'fixture', driver: 'http', status: 'ready', authMethod: 'public-no-auth', identity: { kind: 'public-endpoint', displayName: 'Explicit isolated public-route fixture, not an account' } });
  let dispatches = 0;
  const runtime = new Runtime({ store, connections: { credentials: async () => ({ headers: {}, allowedOrigins: ['https://api.example.com'] }) }, request: async args => { dispatches++; assert.equal(args.method, 'GET'); assert.equal(args.headers.Authorization, undefined); return { status: 200, data: { items: [{ id: 'fixture-private-body-not-for-build-report' }] } }; } });
  await assert.rejects(runtime.createJob({ connectionId: connection.id, capabilityId: cap.id }), /reviewed/);
  assert.equal(dispatches, 0);
  store.put('capabilities', { ...cap, status: 'active' }); // Explicit isolated test review.
  const job = await runtime.createJob({ connectionId: connection.id, capabilityId: cap.id, args: { limit: 2 } });
  assert.equal(job.status, 'succeeded', job.error);
  const recorded = factory.recordExecution({ buildId: report.id, jobId: job.id });
  assert.equal(recorded.executions[0].scope, 'public-endpoint');
  assert.equal(recorded.executions[0].verification.status, 'observed');
  assert.equal(recorded.executions[0].verification.httpStatus, 200);
  assert.equal(recorded.accountVerified, false);
  assert.doesNotMatch(JSON.stringify(recorded), /fixture-private-body|\"args\"|\"identity\"/);
  assert.equal(factory.recordExecution({ buildId: report.id, jobId: job.id }).executions.length, 1);
  assert.equal(dispatches, 1);
  const unrelated = store.put('jobs', { ...job, id: 'different-build-job', capabilityId: 'not-part-of-this-build' });
  assert.throws(() => factory.recordExecution({ buildId: report.id, jobId: unrelated.id }), /does not belong/);
  const wrongDefinition = store.put('jobs', { ...job, id: 'wrong-definition-job', capabilityHash: '0'.repeat(64) });
  assert.throws(() => factory.recordExecution({ buildId: report.id, jobId: wrongDefinition.id }), /different capability definition/);
  runtime.permissions.set({ connectionId: connection.id, capabilityId: cap.id, mode: 'deny' });
  await assert.rejects(runtime.createJob({ connectionId: connection.id, capabilityId: cap.id }), /denied/);
  assert.equal(dispatches, 1);
});

test('an observed schema with no supported functions reports coverage failures without activation', async t => {
  const document = openApiDocument();
  document.paths = { '/upload': document.paths['/upload'] };
  const { factory, store } = await setup(t, { document });
  const report = await factory.build({ appId: 'fixture' });
  assert.equal(report.status, 'blocked');
  assert.equal(report.validation.passed, true); // Source checks can pass without supported functions.
  assert.equal(report.unsupported.length, 1);
  assert.equal(report.source.documentHash, canonicalHash(document));
  assert.deepEqual(report.capabilityIds, []);
  assert.deepEqual(store.list('capabilities'), []);
  assert.match(report.error, /no operation is supported/);
  assert.deepEqual(store.list('activity').filter(item => item.type.startsWith('adapter.build.')).map(item => item.type), ['adapter.build.requested', 'adapter.build.completed']);
});

test('in-flight builds coalesce into one bounded schema request and one report', async t => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let requests = 0;
  const { factory, store } = await setup(t, { request: async () => { requests++; await gate; return { status: 200, data: openApiDocument() }; } });
  const first = factory.build({ appId: 'fixture' });
  const second = factory.build({ appId: 'fixture' });
  release();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.id, b.id);
  assert.equal(requests, 1);
  assert.equal(store.list('adapterBuilds').length, 1);
});

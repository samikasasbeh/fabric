import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../lib/store.mjs';
import { AdapterFactory } from '../lib/adapter-factory.mjs';
import { prepareRequest } from '../lib/compiler.mjs';

async function build(t, server, { origins = ['https://api.example.com'], operationServer } = {}) {
  const dataDir = await mkdtemp(join(tmpdir(), 'fabric-relative-schema-'));
  const store = new Store({ dataDir });
  t.after(async () => { store.close(); await rm(dataDir, { recursive: true, force: true }); });
  const url = 'https://api.example.com/spec/openapi.json';
  const document = { openapi: '3.1.0', info: { title: 'Relative fixture', version: '1' }, servers: [server], paths: {
    '/items': { get: { operationId: 'listItems', responses: { 200: { description: 'List' } }, ...(operationServer ? { servers: [{ url: operationServer }] } : {}) } },
  } };
  const app = { id: 'relative-fixture', name: 'Relative fixture', apiOrigins: origins, discovery: { kind: 'openapi', url } };
  const factory = new AdapterFactory({ store, catalog: [app], request: async request => { assert.equal(request.url, url); return { status: 200, data: document }; } });
  const report = await factory.build({ appId: app.id });
  return { store, report, url };
}

test('root-relative and document-relative servers resolve against source with exact origin authority', async t => {
  for (const [server, expected] of [['/api/v3', '/api/v3/items'], ['./v1', '/spec/v1/items'], ['../v2', '/v2/items']]) {
    const { store, report, url } = await build(t, { url: server });
    assert.equal(report.status, 'built', report.error);
    const cap = store.get('capabilities', report.capabilityIds[0]);
    assert.equal(prepareRequest(cap, {}).url, `https://api.example.com${expected}`);
    assert.equal(cap.provenance.source, url);
    assert.equal(cap.status, 'candidate');
    assert.equal(report.connectionCreated, false);
    assert.equal(store.list('connections').length, 0);
  }
});

test('relative server cannot borrow an unrelated catalog or mirror origin', async t => {
  const { report } = await build(t, { url: '/v3' }, { origins: ['https://other.example.com'] });
  assert.equal(report.status, 'blocked');
  assert.equal(report.capabilityIds.length, 0);
  assert.match(report.unsupported[0].reason, /outside.*authority/);
});

test('ambiguous, encoded, credential-bearing and templated relative routes stay unsupported', async t => {
  for (const url of ['//elsewhere.example.com/api', '/api?key=secret', '/api#fragment', '/api/%2e%2e/admin', '/api/{version}', '/api\\admin', '']) {
    const { report } = await build(t, { url });
    assert.equal(report.status, 'blocked', url);
    assert.equal(report.capabilityIds.length, 0, url);
  }
  const { report } = await build(t, { url: '/api/{version}', variables: { version: { default: 'v1' } } });
  assert.equal(report.status, 'blocked');
});

test('relative source resolution does not override operation-specific servers', async t => {
  const { report } = await build(t, { url: '/api' }, { operationServer: 'https://elsewhere.example.com' });
  assert.equal(report.status, 'blocked');
  assert.match(report.unsupported[0].reason, /Per-path\/operation servers/);
});

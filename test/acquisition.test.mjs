import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AcquisitionEngine } from '../lib/acquisition.mjs';
import { Store } from '../lib/store.mjs';
import { Runtime } from '../lib/runtime.mjs';
import { canonicalHash, compileOpenApi, finalizeCapability, validateCapability } from '../lib/compiler.mjs';

// All remote responses in this file are injected fixtures. The only real I/O is
// the temporary SQLite journal. No account, model endpoint or provider is called.
const origin = 'https://api.example.com';
const modelEndpoint = 'https://model.example.com/v1/chat/completions';
const catalog = () => [
  { id: 'fixture', allowedOrigins: [origin] },
  { id: 'fixture-two', allowedOrigins: [origin] },
];
function document() {
  return {
    openapi: '3.1.0', info: { title: 'Controlled fixture API', version: '1' }, servers: [{ url: origin }],
    paths: {
      '/items': {
        get: { operationId: 'list-items', summary: 'List items', responses: { 200: { description: 'Item list' } } },
        post: {
          operationId: 'create-item', summary: 'Create item',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { title: { type: 'string', minLength: 1 } }, required: ['title'], additionalProperties: false } } } },
          responses: { 201: { description: 'New item' } },
        },
      },
    },
  };
}
async function setup(t, extra = {}) {
  const dataDir = await mkdtemp(join(tmpdir(), 'fabric-acquisition-test-'));
  const store = new Store({ dataDir });
  t.after(async () => { store.close(); await rm(dataDir, { recursive: true, force: true }); });
  const engine = new AcquisitionEngine({ store, catalog, modelUrl: null, modelKey: null, modelName: null, request: async () => { throw new Error('Unexpected network call'); }, ...extra });
  return { store, engine };
}
const modelConfig = request => ({ request, modelUrl: modelEndpoint, modelKey: 'fixture-model-secret', modelName: 'fixture-model' });
const modelResponse = value => ({ status: 200, data: { choices: [{ message: { content: JSON.stringify(value) } }] } });

test('OpenAPI acquisition persists candidates and never overwrites a promoted immutable capability', async t => {
  const { store, engine } = await setup(t);
  const first = engine.import({ appId: 'fixture', document: document() });
  assert.equal(first.capabilities.length, 2);
  assert.ok(first.capabilities.every(cap => cap.status === 'candidate'));
  const promoted = { ...first.capabilities[0], status: 'active' };
  store.put('capabilities', promoted);
  const second = engine.import({ appId: 'fixture', document: document() });
  assert.deepEqual(store.get('capabilities', promoted.id), promoted);
  assert.equal(second.capabilities.find(cap => cap.id === promoted.id).status, 'active');
  assert.equal(store.list('capabilities').length, 2);
  const changed = document(); changed.paths['/items'].get.summary = 'Read items in a new reviewed revision';
  const next = engine.import({ appId: 'fixture', document: changed });
  assert.notEqual(next.capabilities[0].id, promoted.id);
  assert.equal(next.capabilities[0].status, 'candidate');
  assert.deepEqual(store.get('capabilities', promoted.id), promoted);
  assert.ok(store.list('activity').every(event => event.type === 'capabilities.compiled'));
});

test('import and acquisition reject unknown apps and destinations beyond the selected catalog authority', async t => {
  const { store, engine } = await setup(t);
  assert.throws(() => engine.import({ appId: 'unknown', document: document() }), /catalog/);
  const outside = document(); outside.servers[0].url = 'https://attacker.example.com';
  assert.throws(() => engine.import({ appId: 'fixture', document: outside }), /origins/);
  assert.equal(store.list('capabilities').length, 0);
  assert.equal(store.list('surfaces').length, 0);
  await assert.rejects(engine.acquire({ appId: 'unknown', goal: 'List my items' }), /Unknown catalog/);
  const wrongApp = compileOpenApi({ appId: 'fixture-two', document: document() }).capabilities[0];
  assert.throws(() => engine.saveCandidates('fixture', [wrongApp]), /origins/);
  assert.equal(store.list('capabilities').length, 0);
});

test('candidate batch preflight does not partially persist before rejecting an out-of-origin member', async t => {
  const { store, engine } = await setup(t);
  const good = compileOpenApi({ appId: 'fixture', document: document() }).capabilities[0];
  const bad = finalizeCapability({ ...good, request: { ...good.request, url: 'https://attacker.example.com/items' } });
  assert.throws(() => engine.saveCandidates('fixture', [good, bad]), /origins/);
  assert.equal(store.list('capabilities').length, 0);
});

test('no documentation and no configured model is explicitly blocked, not simulated', async t => {
  let requests = 0;
  const { store, engine } = await setup(t, { request: async () => { requests++; throw new Error('Should not call'); } });
  assert.equal(engine.configured, false);
  await assert.rejects(engine.acquire({ appId: 'fixture', goal: 'Invent an endpoint to do anything' }), /No operation was invented/);
  assert.equal(requests, 0);
  assert.equal(store.list('capabilities').length, 0);
  assert.equal(store.list('acquisitions').length, 0);
  await assert.rejects(engine.acquire({ appId: 'fixture', goal: ' ' }), /bounded goal/);
});

test('schema-backed acquisition compiles on first use and reuses stored source without a model', async t => {
  const { store, engine } = await setup(t);
  const acquired = await engine.acquire({ appId: 'fixture', goal: 'Create an item', document: document() });
  assert.equal(acquired.mode, 'schema-compiler');
  assert.equal(acquired.capabilities[0].provenance.operationId, 'create-item');
  assert.equal(acquired.capabilities[0].effect, 'write');
  assert.ok(acquired.capabilities.every(cap => cap.status === 'candidate'));
  const reused = await engine.acquire({ appId: 'fixture', goal: 'List items' });
  assert.equal(reused.mode, 'schema-compiler');
  assert.equal(reused.capabilities[0].provenance.operationId, 'list-items');
  assert.equal(store.list('acquisitions').length, 2);
  assert.equal(store.list('connections').length, 0);
  assert.equal(store.list('jobs').length, 0);
});

test('identical schema fingerprints stay isolated by application and can both be reacquired', async t => {
  const { store, engine } = await setup(t);
  const first = engine.import({ appId: 'fixture', document: document() });
  const second = engine.import({ appId: 'fixture-two', document: document() });
  assert.equal(first.fingerprint, second.fingerprint);
  const surfaces = store.list('surfaces');
  assert.equal(surfaces.length, 2);
  assert.equal(new Set(surfaces.map(surface => surface.id)).size, 2);
  assert.ok(store.get('surfaces', `fixture:${first.fingerprint}`));
  assert.ok(store.get('surfaces', `fixture-two:${second.fingerprint}`));
  for (const appId of ['fixture', 'fixture-two']) {
    const result = await engine.acquire({ appId, goal: 'List items' });
    assert.equal(result.mode, 'schema-compiler');
    assert.equal(result.capabilities.length, 2);
    assert.ok(result.capabilities.every(cap => cap.appId === appId));
  }
});

test('new document uses its own server and source rather than a previous import override', async t => {
  const { store, engine } = await setup(t);
  engine.import({ appId: 'fixture', document: document(), baseUrl: `${origin}/legacy`, sourceUrl: 'https://docs.example.com/old-schema' });
  const reused = await engine.acquire({ appId: 'fixture', goal: 'List items' });
  assert.ok(reused.capabilities.every(cap => cap.request.url === `${origin}/legacy/items`));
  assert.ok(reused.capabilities.every(cap => cap.provenance.source === 'https://docs.example.com/old-schema'));
  const fresh = document();
  fresh.servers = [{ url: `${origin}/fresh` }];
  fresh.info.version = '2';
  const acquired = await engine.acquire({ appId: 'fixture', goal: 'List items', document: fresh });
  assert.ok(acquired.capabilities.every(cap => cap.request.url === `${origin}/fresh/items`));
  assert.ok(acquired.capabilities.every(cap => cap.provenance.source === 'uploaded'));
  const newSurface = store.get('surfaces', `fixture:${acquired.fingerprint}`);
  assert.equal(newSurface.baseUrl, null);
  assert.equal(newSurface.sourceUrl, null);
  const later = await engine.acquire({ appId: 'fixture', goal: 'List items' });
  assert.ok(later.capabilities.every(cap => cap.request.url === `${origin}/fresh/items`));
});

test('configured schema selection sees operation descriptions only and cannot activate invented IDs', async t => {
  let calls = 0;
  const { store, engine } = await setup(t, modelConfig(async request => {
    calls++;
    assert.equal(request.url, modelEndpoint);
    assert.deepEqual(request.allowedOrigins, ['https://model.example.com']);
    const payload = JSON.parse(request.body);
    assert.equal(payload.model, 'fixture-model');
    const supplied = JSON.parse(payload.messages[1].content);
    assert.equal(supplied.operations.length, 2);
    assert.deepEqual(Object.keys(supplied).sort(), ['goal', 'operations']);
    const chosen = supplied.operations.find(op => op.effect === 'read');
    return modelResponse({ ids: [chosen.id, 'invented.id'], reason: 'Selected documented read operation' });
  }));
  const result = await engine.acquire({ appId: 'fixture', goal: 'List items', document: document() });
  assert.equal(calls, 1);
  assert.equal(result.mode, 'model-assisted-schema-compiler');
  assert.equal(result.capabilities.length, 1);
  assert.equal(result.capabilities[0].effect, 'read');
  assert.equal(result.capabilities[0].status, 'candidate');
  assert.equal(store.get('capabilities', 'invented.id'), null);
  assert.equal(store.list('jobs').length, 0);
});

test('documentation synthesis finalizes a real declarative candidate, overwriting model authority claims', async t => {
  const documentation = 'Controlled fixture documentation: GET https://api.example.com/items lists accessible items. No parameters.';
  let calls = 0;
  const { store, engine } = await setup(t, modelConfig(async request => {
    calls++;
    const payload = JSON.parse(request.body);
    const supplied = JSON.parse(payload.messages[1].content);
    assert.equal(supplied.documentation, documentation);
    const output = compileOpenApi({ appId: 'fixture', document: document() }).capabilities[0];
    output.id = 'invented.stale'; output.appId = 'attacker'; output.status = 'active';
    output.provenance = { kind: 'manual', fingerprint: '0'.repeat(64), source: 'not the supplied source' };
    return modelResponse(output);
  }));
  const result = await engine.acquire({ appId: 'fixture', goal: 'List items', documentation });
  assert.equal(calls, 1);
  assert.equal(result.mode, 'documentation-synthesis');
  const cap = result.capabilities[0];
  validateCapability(cap);
  assert.equal(cap.appId, 'fixture');
  assert.equal(cap.status, 'candidate');
  assert.equal(cap.provenance.kind, 'model');
  assert.equal(cap.provenance.fingerprint, canonicalHash(documentation));
  assert.match(cap.id, /^fixture\.generated\.[a-f0-9]{24}$/);
  assert.equal(store.list('connections').length, 0);
  assert.equal(store.list('jobs').length, 0);
  assert.ok(!JSON.stringify(store.list('activity')).includes('fixture-model-secret'));
});

test('synthesis requires actual documentation and rejects model errors, executable fields and external origins', async t => {
  for (const responseKind of ['insufficient', 'code', 'outside', 'malformed']) {
    const { store, engine } = await setup(t, modelConfig(async () => {
      if (responseKind === 'insufficient') return modelResponse({ error: 'No documented endpoint' });
      if (responseKind === 'malformed') return { status: 200, data: { choices: [{ message: { content: 'not JSON' } }] } };
      const cap = compileOpenApi({ appId: 'fixture', document: document() }).capabilities[0];
      if (responseKind === 'code') cap.code = 'process.exit()';
      else cap.request.url = 'https://attacker.example.com/collect';
      return modelResponse(cap);
    }));
    await assert.rejects(engine.acquire({ appId: 'fixture', goal: 'List items', documentation: 'Real controlled fixture description of a documented GET operation.' }));
    assert.equal(store.list('capabilities').length, 0);
    assert.equal(store.list('acquisitions').length, 0);
  }
  let calls = 0;
  const { engine } = await setup(t, modelConfig(async () => { calls++; return modelResponse({}); }));
  await assert.rejects(engine.acquire({ appId: 'fixture', goal: 'List items' }), /actual API documentation/);
  assert.equal(calls, 0);
});

function verifiedWrite() {
  const cap = compileOpenApi({ appId: 'fixture', document: document() }).capabilities.find(cap => cap.effect === 'write');
  cap.verification = {
    kind: 'http-readback',
    request: { method: 'GET', url: `${origin}/items/{itemId}`, pathParameters: ['itemId'], queryParameters: [] },
    bindings: { itemId: { from: 'response', pointer: '/id', schema: { type: 'string' } } },
    assertions: [{ pointer: '/id', equalsResponse: '/id' }, { pointer: '/title', equalsInput: '/body/title' }],
  };
  return { ...finalizeCapability(cap), status: 'active' };
}
async function runtimeSetup(t, responseData) {
  const { store } = await setup(t);
  const cap = verifiedWrite();
  store.put('capabilities', cap);
  store.put('connections', { id: 'fixture-account', appId: 'fixture', driver: 'http', status: 'ready', identity: { id: 'authorized-fixture-account' } });
  const calls = [];
  const runtime = new Runtime({
    store,
    connections: { credentials: async () => ({ headers: { Authorization: 'Bearer fixture-only-secret' }, allowedOrigins: [origin] }) },
    request: async request => {
      calls.push(request);
      assert.deepEqual(request.allowedOrigins, [origin]);
      assert.equal(request.headers.Authorization, 'Bearer fixture-only-secret');
      if (request.method === 'POST') return { status: 201, data: { id: 'item123', title: 'Requested title' } };
      assert.equal(request.method, 'GET');
      assert.equal(request.url, `${origin}/items/item123`);
      return { status: 200, data: responseData };
    },
  });
  return { runtime, cap, store, calls };
}

test('approved HTTP write independently reads back exact provider identity and requested field', async t => {
  const { runtime, cap, store, calls } = await runtimeSetup(t, { id: 'item123', title: 'Requested title' });
  const pending = await runtime.createJob({ connectionId: 'fixture-account', capabilityId: cap.id, args: { body: { title: 'Requested title' } } });
  assert.equal(pending.status, 'awaiting_approval');
  assert.equal(calls.length, 0);
  const done = await runtime.approve(pending.id, pending.approvalDigest);
  assert.equal(done.status, 'succeeded');
  assert.deepEqual(calls.map(request => request.method), ['POST', 'GET']);
  assert.equal(calls[0].url, `${origin}/items`);
  assert.deepEqual(JSON.parse(calls[0].body), { title: 'Requested title' });
  assert.equal(done.result.verification.kind, 'http-readback');
  assert.equal(done.result.verification.status, 'verified');
  assert.deepEqual(done.result.verification.checks, [{ pointer: '/id', passed: true }, { pointer: '/title', passed: true }]);
  assert.equal(store.get('capabilityStats', cap.id).succeeded, 1);
  assert.ok(!JSON.stringify(store.list('jobs')).includes('fixture-only-secret'));
  await assert.rejects(runtime.approve(pending.id, pending.approvalDigest), /not awaiting/);
  assert.equal(calls.length, 2);
});

test('wrong, missing or mismatched readback fields remain uncertain and are never retried', async t => {
  for (const observed of [{ id: 'other-object', title: 'Requested title' }, { id: 'item123', title: 'Different title' }, { id: 'item123' }]) {
    const { runtime, cap, calls } = await runtimeSetup(t, observed);
    const pending = await runtime.createJob({ connectionId: 'fixture-account', capabilityId: cap.id, args: { body: { title: 'Requested title' } } });
    const done = await runtime.approve(pending.id, pending.approvalDigest);
    assert.equal(done.status, 'uncertain');
    assert.equal(done.result.verification.status, 'failed');
    assert.ok(done.result.verification.checks.some(check => !check.passed));
    assert.equal(calls.length, 2);
    await assert.rejects(runtime.approve(pending.id, pending.approvalDigest), /not awaiting/);
    assert.equal(calls.length, 2);
  }
});

test('missing provider object ID prevents readback and leaves an acknowledged write uncertain', async t => {
  const { runtime, cap } = await runtimeSetup(t, {});
  let calls = 0;
  runtime.request = async () => { calls++; return { status: 201, data: { title: 'Requested title' } }; };
  const pending = await runtime.createJob({ connectionId: 'fixture-account', capabilityId: cap.id, args: { body: { title: 'Requested title' } } });
  const done = await runtime.approve(pending.id, pending.approvalDigest);
  assert.equal(done.status, 'uncertain');
  assert.match(done.error, /pointer missing/);
  assert.equal(calls, 1);
});

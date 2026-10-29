import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../lib/store.mjs';
import { AcquisitionEngine } from '../lib/acquisition.mjs';
import { DiscoveryEngine } from '../lib/discovery.mjs';
import { PermissionManager } from '../lib/permissions.mjs';
import { Runtime } from '../lib/runtime.mjs';

// Real discovery/compiler/permission/runtime path with a clearly injected schema
// and provider transport. No real account, provider token or network call.
async function setup(t, security) {
  const dataDir = await mkdtemp(join(tmpdir(), 'fabric-discovery-permissions-'));
  const store = new Store({ dataDir });
  t.after(async () => { store.close(); await rm(dataDir, { recursive: true, force: true }); });
  const document = {
    openapi: '3.1.0', info: { title: 'Scope semantics fixture', version: '1' }, servers: [{ url: 'https://api.example.com' }],
    components: { securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer' },
      oauth: { type: 'oauth2', flows: { authorizationCode: { authorizationUrl: 'https://auth.example.com/authorize', tokenUrl: 'https://auth.example.com/token', scopes: { read: 'Read', identity: 'Identity', admin: 'Admin' } } } },
    } },
    paths: { '/items': { get: { operationId: 'listItems', security, responses: { 200: { description: 'Read' } } } } },
  };
  const catalog = () => [{ id: 'fixture', name: 'Scope fixture', apiOrigins: ['https://api.example.com'], discovery: { kind: 'openapi', url: 'https://schemas.example.com/fixture.json' } }];
  const acquisition = new AcquisitionEngine({ store, catalog });
  const discovery = new DiscoveryEngine({ store, catalog, acquisition, request: async () => ({ status: 200, data: document }) });
  const map = await discovery.discover({ appId: 'fixture' });
  const operation = map.operations[0];
  const cap = operation.capabilityId ? store.get('capabilities', operation.capabilityId) : null;
  const connection = store.put('connections', { id: 'scope-fixture', appId: 'fixture', driver: 'http', status: 'ready', authMethod: 'token', authRevision: 'fixture-consent', identity: { id: 'fixture-account' } });
  const permissions = new PermissionManager({ store });
  const calls = [];
  const connections = { credentials: async () => ({ headers: { Authorization: 'Bearer fixture-not-live-token' }, allowedOrigins: ['https://api.example.com'] }) };
  const runtime = new Runtime({ store, permissions, connections, request: async request => { calls.push(request); return { status: 200, data: { items: [] } }; } });
  const review = () => store.put('capabilities', { ...cap, status: 'active' });
  const setAccount = (authMethod, scopes = []) => store.put('connections', { ...connection, authMethod, scopes });
  return { store, map, operation, cap, connection, permissions, runtime, connections, calls, review, setAccount };
}

test('discovered bearerAuth with no named scopes is valid but still needs review, connection and credentials', async t => {
  const app = await setup(t, [{ bearerAuth: [] }]);
  assert.equal(app.operation.support, 'candidate');
  assert.deepEqual(app.operation.scopeSets, [[]]);
  assert.deepEqual(app.operation.requiredScopes, []);
  let decision = app.permissions.decision(app.connection, app.cap);
  assert.equal(decision.status, 'candidate');
  assert.equal(decision.executable, false);
  const cap = app.review();
  decision = app.permissions.decision(app.connection, cap);
  assert.equal(decision.status, 'active');
  assert.equal(decision.providerAccess, 'unknown');
  assert.equal(decision.executable, true);
  const job = await app.runtime.createJob({ connectionId: app.connection.id, capabilityId: cap.id });
  assert.equal(job.status, 'succeeded');
  assert.equal(app.calls.length, 1);
  assert.equal(app.calls[0].headers.Authorization, 'Bearer fixture-not-live-token');
  app.connections.credentials = async () => { throw new Error('Fixture credential unavailable'); };
  assert.equal((await app.runtime.createJob({ connectionId: app.connection.id, capabilityId: cap.id })).status, 'failed');
  assert.equal(app.calls.length, 1);
  app.store.put('connections', { ...app.connection, status: 'revoked' });
  await assert.rejects(app.runtime.createJob({ connectionId: app.connection.id, capabilityId: cap.id }), /not ready/);
});

test('an OAuth connection cannot turn a zero-scope bearer requirement into a granted-scope claim', async t => {
  const app = await setup(t, [{ bearerAuth: [] }]);
  const cap = app.review();
  app.setAccount('oauth', []);
  const decision = app.permissions.decision(app.connection, cap);
  assert.equal(decision.providerAccess, 'unknown');
  assert.equal(decision.executable, true);
  assert.match(decision.reason, /not proof of provider access/);
  app.permissions.set({ connectionId: app.connection.id, capabilityId: cap.id, mode: 'deny' });
  await assert.rejects(app.runtime.createJob({ connectionId: app.connection.id, capabilityId: cap.id }), /denied/);
  assert.equal(app.calls.length, 0);
});

test('anonymous-or-scoped alternatives allow zero named scopes without inventing provider consent', async t => {
  const app = await setup(t, [{}, { oauth: ['read', 'identity'] }]);
  assert.deepEqual(app.operation.scopeSets, [[], ['read', 'identity']]);
  const cap = app.review();
  for (const scopes of [[], ['read']]) {
    app.setAccount('oauth', scopes);
    const decision = app.permissions.decision(app.connection, cap);
    assert.equal(decision.providerAccess, 'unknown');
    assert.equal(decision.executable, true);
  }
  app.setAccount('oauth', ['read', 'identity']);
  assert.equal(app.permissions.decision(app.connection, cap).providerAccess, 'granted');
  app.permissions.set({ connectionId: app.connection.id, capabilityId: cap.id, mode: 'ask' });
  const pending = await app.runtime.createJob({ connectionId: app.connection.id, capabilityId: cap.id });
  assert.equal(pending.status, 'awaiting_approval');
  assert.equal(app.calls.length, 0);
});

test('discovery preserves AND within each scope alternative and OR between alternatives', async t => {
  const app = await setup(t, [{ oauth: ['read', 'identity'] }, { oauth: ['admin'] }]);
  assert.deepEqual(app.operation.scopeSets, [['read', 'identity'], ['admin']]);
  const cap = app.review();
  for (const [scopes, access] of [[[], 'missing'], [['read'], 'missing'], [['identity'], 'missing'], [['read', 'identity'], 'granted'], [['admin'], 'granted']]) {
    app.setAccount('oauth', scopes);
    const decision = app.permissions.decision(app.connection, cap);
    assert.equal(decision.providerAccess, access);
    assert.equal(decision.executable, access === 'granted');
    if (access === 'missing') await assert.rejects(app.runtime.createJob({ connectionId: app.connection.id, capabilityId: cap.id }), /required provider scope/);
  }
  assert.equal(app.calls.length, 0);
});

test('malformed scope metadata stays blocked, including malformed alternatives beside a valid empty one', async t => {
  const app = await setup(t, [{ bearerAuth: [] }]);
  const cap = app.review();
  app.setAccount('oauth', ['read', 'identity', 'admin']);
  for (const scopeSets of [null, {}, 'read', [[] , null], [[] , 'read'], [[] , ['']], [[] , [123]], [[] , ['x'.repeat(1001)]]]) {
    app.store.put('applicationMaps', { ...app.map, operations: [{ ...app.operation, scopeSets }] });
    const decision = app.permissions.decision(app.connection, cap);
    assert.equal(decision.status, 'unsupported');
    assert.equal(decision.executable, false);
    await assert.rejects(app.runtime.createJob({ connectionId: app.connection.id, capabilityId: cap.id }), /malformed/);
  }
  app.store.put('applicationMaps', { ...app.map, operations: [{ ...app.operation, requiredScopes: [123], scopeSets: [[]] }] });
  assert.equal(app.permissions.decision(app.connection, cap).executable, false);
  assert.equal(app.calls.length, 0);
});

test('malformed provider security is rejected during discovery instead of converted to zero scopes', async t => {
  const app = await setup(t, [{ bearerAuth: 'not-an-array' }]);
  assert.equal(app.operation.support, 'unsupported');
  assert.equal(app.operation.capabilityId, null);
  assert.match(app.operation.reason, /Invalid OpenAPI required scopes/);
  assert.equal(app.store.list('capabilities').length, 0);
});

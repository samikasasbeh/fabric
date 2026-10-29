import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createApp } from '../server.mjs';

// Real loopback routes and isolated storage; no real provider account or network.
async function setup(t) {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'fabric-route-outcome-'));
  const app = await createApp({ dataDir, port: 56100 + Math.floor(Math.random() * 1200), request: async () => { throw new Error('Provider requests are forbidden in this route fixture.'); } });
  app.oauth.clientId = ''; app.oauth.clientSecret = '';
  await app.start();
  t.after(async () => { await app.close(); await rm(dataDir, { recursive: true, force: true }); });
  const boot = await fetch(`${app.origin}/api/state`), state = await boot.json();
  const cookie = boot.headers.get('set-cookie').split(';')[0];
  const start = async data => {
    const response = await fetch(`${app.origin}/api/connect/start`, { method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json', 'X-Fabric-CSRF': state.csrfToken }, body: JSON.stringify(data) });
    const result = await response.json();
    assert.equal(response.status, 200, result.error || 'Expected a structured connection outcome.');
    return result;
  };
  return { app, start };
}

test('an indexed API with no usable account route returns unsupported without fake state or retry errors', async t => {
  const { app, start } = await setup(t);
  app.store.put('applications', { id: 'schema-only-fixture', name: 'Schema-only fixture', apiOrigins: ['https://api.fixture.example'], webOrigins: [] });
  const result = await start({ appId: 'schema-only-fixture' });
  assert.equal(result.kind, 'unsupported');
  assert.equal(result.connectionEstablished, false);
  assert.equal(result.plan.recommended, null);
  assert.deepEqual(result.plan.routes, []);
  assert.match(result.message, /no supported.*connection/i);
  assert.equal(result.connection, undefined);
  assert.equal(result.pairing, undefined);
  assert.equal(app.store.list('connections').length, 0);
  assert.equal(app.store.list('pairingSessions').length, 0);
});

test('explicit invalid or unavailable methods never fall through to a different connection route', async t => {
  const { app, start } = await setup(t);
  for (const method of [null, false, 0, '', {}, [], 'arbitrary', 'browser', 'workspace']) {
    const result = await start({ appId: 'local-device', method });
    assert.equal(result.kind, 'unsupported');
    assert.equal(result.connectionEstablished, false);
  }
  const google = await start({ appId: 'gmail', method: 'oauth' });
  assert.equal(google.kind, 'unsupported');
  assert.equal(google.plan.recommended, 'browser');
  assert.match(google.message, /configure Google sign-in/i);
  assert.equal(google.pairing, undefined);
  assert.equal(app.store.list('connections').length, 0);
  assert.equal(app.store.list('pairingSessions').length, 0);
  const browser = await start({ appId: 'notion', method: 'browser' });
  assert.equal(browser.kind, 'browser');
  assert.equal(app.store.list('connections').length, 0);
  assert.equal(app.store.list('pairingSessions').length, 1);
});

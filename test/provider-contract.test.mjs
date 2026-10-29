import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { validateProviderBinding } from '../contracts/provider.mts';
import { TrustedProviderRegistry } from '../lib/providers/registry.mts';
import { GoogleProvider } from '../lib/providers/google.mjs';
import { ConnectionError, ConnectionManager } from '../lib/connections.mjs';
import { GoogleOAuthManager } from '../lib/oauth.mjs';
import { Store } from '../lib/store.mjs';
import { Vault } from '../lib/vault.mjs';
import { OAuth2Provider } from '../lib/providers/oauth2.mjs';
import { v1Definition } from './fixtures/auth-v1/urls.mjs';

const CALENDAR_SCOPE = 'openid email https://www.googleapis.com/auth/calendar.calendarlist.readonly https://www.googleapis.com/auth/calendar.events.readonly';
const GMAIL_SCOPE = 'openid email https://www.googleapis.com/auth/gmail.readonly';

// F10.7: the adapter cases run on the version 1 Google definition (T6 through the fixtures). Only the legacy facade case binds
// GoogleProvider, which reads the shipped version 2 definition.
function fixture(t, { facade = false } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'fabric-provider-'));
  const state = { now: Date.UTC(2026, 9, 11, 12), account: 'google-123', scope: CALENDAR_SCOPE, requests: [], omitRefresh: false, failToken: false, failIdentity: false, revokeStatus: 503 };
  const clock = () => state.now;
  const store = new Store({ dataDir: directory, clock });
  const vault = new Vault(directory);
  const request = async request => {
    state.requests.push(request);
    if (request.url.endsWith('/token')) {
      state.onToken?.();
      if (state.failToken) return { status: 400, data: { error: 'invalid_grant', error_description: 'DO-NOT-PRINT-private-provider-body' } };
      return { status: 200, data: { access_token: 'private-access', ...(state.omitRefresh ? {} : { refresh_token: 'private-refresh' }), token_type: 'Bearer', expires_in: 3600, scope: state.scope } };
    }
    if (request.url.endsWith('/revoke')) { state.onRevoke?.(); return { status: state.revokeStatus, data: null }; }
    if (state.failIdentity) return { status: 401, data: { error: 'DO-NOT-PRINT-private-provider-body' } };
    if (request.url.endsWith('/userinfo')) return { status: 200, data: { sub: state.account, email: 'person@example.com', name: 'Person' } };
    if (request.url.includes('/calendar/v3/')) return { status: 200, data: { kind: 'calendar#calendarList' } };
    if (request.url.includes('/gmail/v1/')) return { status: 200, data: { emailAddress: 'person@example.com' } };
    if (request.url === 'https://api.github.com/user') return { status: 200, data: { id: 123, login: 'person' } };
    throw new Error('Unexpected fixture provider endpoint');
  };
  const connections = new ConnectionManager({ store, vault, request, clock });
  const options = { store, vault, connections, request, clock, clientId: 'fixture-client', clientSecret: 'DO-NOT-PRINT-client-secret' };
  const provider = facade ? new GoogleOAuthManager(options) : new OAuth2Provider(v1Definition('google'), options);
  const bind = () => facade ? connections.setOAuthManager(provider) : connections.setOAuthProvider(provider);
  const connect = async (options = {}) => {
    const flow = provider.start(options);
    const state = new URL(flow.authorizationUrl).searchParams.get('state');
    const connection = await provider.callback({ state, flowId: flow.flowId, code: 'fixture-code' });
    return { flow, connection };
  };
  t.after(() => { store.close(); rmSync(directory, { recursive: true, force: true }); });
  return { state, clock, store, vault, connections, provider, request, connect, bind };
}

test('provider contract permits only exact Google application pairs and returns frozen bindings', () => {
  for (const appId of ['google-calendar', 'gmail']) {
    const input = { providerId: 'google', appId };
    const result = validateProviderBinding(input);
    assert.deepEqual(result, input);
    assert.notEqual(result, input);
    assert.equal(Object.isFrozen(result), true);
  }
  for (const value of [null, [], {}, { providerId: 'google', appId: 'github' }, { providerId: 'github', appId: 'gmail' }, { providerId: 'Google', appId: 'gmail' }, { providerId: 'google', appId: 'drive' }, { providerId: 'google', appId: 'gmail', module: '/private/DO-NOT-PRINT' }]) {
    assert.throws(() => validateProviderBinding(value), error => error.code === 'invalid_input' && error.message === 'Unsupported provider/application binding.');
  }
});

test('provider binding rejects accessors and unsafe JSON without invoking or echoing them', () => {
  let invoked = false;
  const getter = { providerId: 'google', get appId() { invoked = true; return 'gmail'; } };
  for (const input of [getter, JSON.parse('{"providerId":"google","appId":"gmail","__proto__":{"admin":true}}'), { providerId: 'google', appId: undefined }]) {
    assert.throws(() => validateProviderBinding(input), /Unsupported provider\/application binding/);
  }
  assert.equal(invoked, false);
  assert.equal({}.admin, undefined);
});

test('registry has a fixed immutable Google mapping and rejects fake adapters or mismatched pairs', t => {
  const { provider } = fixture(t, { facade: true });
  const registry = new TrustedProviderRegistry(provider);
  assert.deepEqual(registry.list(), [{ providerId: 'google', appId: 'google-calendar' }, { providerId: 'google', appId: 'gmail' }]);
  assert.equal(Object.isFrozen(registry.list()), true);
  assert.ok(registry.list().every(Object.isFrozen));
  for (const appId of ['gmail', 'google-calendar']) {
    assert.equal(registry.supportsApp(appId), true);
    assert.equal(registry.resolve({ providerId: 'google', appId }), provider);
  }
  for (const appId of ['github', 'Google Calendar', '../google', null, {}]) assert.equal(registry.supportsApp(appId), false);
  for (const value of [{ providerId: 'google', appId: 'github' }, { providerId: 'other', appId: 'gmail' }, { providerId: 'google', appId: 'gmail', path: 'module.mjs' }]) {
    assert.throws(() => registry.resolve(value), error => error instanceof ConnectionError && error.code === 'invalid_input');
  }
  const fake = { providerId: 'google', appIds: ['gmail', 'google-calendar'] };
  assert.throws(() => new TrustedProviderRegistry(fake), /trusted Google provider/);
  assert.throws(() => registry.bindGoogleOAuth(fake), /trusted Google provider/);
  assert.equal(registry.resolve({ providerId: 'google', appId: 'gmail' }), provider);
});

test('legacy OAuth facade binds the full SPI without changing public configuration or credentials exposure', t => {
  const { provider, connections } = fixture(t, { facade: true });
  const registry = connections.providers;
  assert.equal(registry.resolve({ providerId: 'google', appId: 'gmail' }).configured, false);
  assert.equal(provider instanceof GoogleProvider, true);
  connections.setOAuthManager(provider);
  assert.equal(connections.oauth, provider);
  assert.equal(connections.providers, registry);
  assert.equal(registry.resolve({ providerId: 'google', appId: 'gmail' }), provider);
  for (const method of ['configuration', 'start', 'callback', 'observeIdentity', 'refresh', 'revoke']) assert.equal(typeof provider[method], 'function');
  assert.deepEqual(provider.configuration(), { configured: true, redirectUri: 'http://127.0.0.1:4188/api/oauth/google/callback', requiredEnvironment: ['FABRIC_GOOGLE_CLIENT_ID', 'FABRIC_GOOGLE_CLIENT_SECRET'], defaultAccess: 'full' });
  // F10.7 (g8): the default follows the definition: full for the shipped version 2 one, read-only for a version 1 one.
  assert.equal(fixture(t).provider.configuration().defaultAccess, 'read-only');
  assert.equal(JSON.stringify(provider.configuration()).includes('DO-NOT-PRINT-client-secret'), false);
  provider.clientId = '';
  assert.equal(provider.configured, false);
  assert.throws(() => provider.start(), error => error instanceof ConnectionError && error.code === 'not_configured');
});

for (const appId of ['gmail', 'google-calendar']) test(`${appId} identity adapter requires Google sub plus its exact application access probe`, async t => {
  const { state, provider, connections, bind } = fixture(t);
  bind();
  const identity = await connections.observe(appId, 'private-access');
  assert.deepEqual(identity, { id: 'google-123', displayName: 'person@example.com', email: 'person@example.com' });
  assert.equal(state.requests.length, 2);
  assert.equal(state.requests[0].url, 'https://openidconnect.googleapis.com/v1/userinfo');
  assert.deepEqual(state.requests[0].allowedOrigins, ['https://openidconnect.googleapis.com']);
  assert.equal(state.requests[0].headers.Authorization, 'Bearer private-access');
  if (appId === 'gmail') {
    assert.equal(state.requests[1].url, 'https://gmail.googleapis.com/gmail/v1/users/me/profile?fields=emailAddress');
    assert.deepEqual(state.requests[1].allowedOrigins, ['https://gmail.googleapis.com']);
  } else {
    assert.equal(state.requests[1].url, 'https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1&fields=kind');
    assert.deepEqual(state.requests[1].allowedOrigins, ['https://www.googleapis.com']);
  }
});

test('Google identity failures are sanitized and do not substitute email for provider subject', async t => {
  const { provider, connections, state, request, bind } = fixture(t);
  bind();
  connections.request = async request => request.url.endsWith('/userinfo') ? { status: 200, data: { email: 'person@example.com' } } : { status: 200, data: {} };
  await assert.rejects(provider.observeIdentity({ appId: 'gmail', accessToken: 'private-access' }), /no verifiable account identity/);
  connections.request = async () => { throw new Error('DO-NOT-PRINT-private-token'); };
  await assert.rejects(provider.observeIdentity({ appId: 'gmail', accessToken: 'private-access' }), error => error instanceof ConnectionError && !error.message.includes('DO-NOT-PRINT'));
  connections.request = request; state.failIdentity = true;
  await assert.rejects(provider.observeIdentity({ appId: 'gmail', accessToken: 'private-access' }), error => error.code === 'reconnect_required' && !error.message.includes('DO-NOT-PRINT'));
});

test('Google subject identity is never coerced, cleaned to empty, or silently truncated', async t => {
  const { provider, connections } = fixture(t);
  for (const sub of [123, true, {}, [], '', '   ', '\u0000', 'google\n123', 'a'.repeat(201)]) {
    let requests = 0;
    connections.request = async () => { requests++; return { status: 200, data: { sub, email: 'person@example.com' } }; };
    await assert.rejects(provider.observeIdentity({ appId: 'gmail', accessToken: 'private-access' }), /no verifiable account identity/);
    assert.equal(requests, 1);
  }
});

test('unsupported direct provider applications fail before any provider network call', async t => {
  const { provider, state, connections, store, vault } = fixture(t);
  assert.throws(() => provider.start({ appId: 'github' }), /Unsupported Google application/);
  await assert.rejects(provider.observeIdentity({ appId: 'github', accessToken: 'private-access' }), /Unsupported Google application/);
  store.put('connections', { id: 'wrong-provider', appId: 'github', authMethod: 'oauth', status: 'ready' });
  vault.set('wrong-provider', { accessToken: 'private-access', refreshToken: 'private-refresh', expiresAt: 0 });
  await assert.rejects(provider.refresh('wrong-provider'), /Unsupported Google application/);
  await assert.rejects(provider.revoke('wrong-provider'), /Unsupported Google application/);
  assert.equal(connections.get('wrong-provider').status, 'ready');
  assert.equal(vault.get('wrong-provider').accessToken, 'private-access');
  assert.equal(state.requests.length, 0);
});

test('callback consumes state and verifier before token-service I/O, including failures', async t => {
  const { provider, state, store, vault } = fixture(t);
  const flow = provider.start();
  const stateValue = new URL(flow.authorizationUrl).searchParams.get('state');
  const id = createHash('sha256').update(stateValue).digest('hex');
  state.failToken = true;
  state.onToken = () => {
    assert.equal(store.get('oauthFlows', id), null);
    assert.equal(vault.get(`oauth:${id}`), null);
  };
  const input = { state: stateValue, flowId: flow.flowId, code: 'fixture-code' };
  await assert.rejects(provider.callback(input), error => error.code === 'reconnect_required' && !error.message.includes('DO-NOT-PRINT'));
  await assert.rejects(provider.callback(input), /already used/);
  assert.equal(state.requests.length, 1);
});

test('corrupted flow application is consumed and rejected before token exchange', async t => {
  const { provider, state, store, vault } = fixture(t);
  const flow = provider.start();
  const stateValue = new URL(flow.authorizationUrl).searchParams.get('state');
  const id = createHash('sha256').update(stateValue).digest('hex');
  store.put('oauthFlows', { ...store.get('oauthFlows', id), appId: 'github' });
  await assert.rejects(provider.callback({ state: stateValue, flowId: flow.flowId, code: 'fixture-code' }), /Unsupported Google application/);
  assert.equal(state.requests.length, 0);
  assert.equal(store.get('oauthFlows', id), null);
  assert.equal(vault.get(`oauth:${id}`), null);
});

test('omitted reconnect refresh token is retained only after verification of the same subject', async t => {
  const { provider, connections, state, vault, connect, bind } = fixture(t);
  bind();
  const { connection } = await connect();
  state.omitRefresh = true;
  await connect({ connectionId: connection.id });
  assert.equal(vault.get(connection.id).refreshToken, 'private-refresh');
  const previous = vault.get(connection.id);
  state.account = 'another-google-sub';
  await assert.rejects(connect({ connectionId: connection.id }), /Account mismatch/);
  assert.deepEqual(vault.get(connection.id), previous);
  assert.equal(connections.get(connection.id).identity.id, 'google-123');
});

test('provider revoke disables local access before attempting remote revoke', async t => {
  const { provider, connections, state, vault, connect, bind } = fixture(t);
  bind();
  const { connection } = await connect();
  let observedLocalDisable = false;
  state.onRevoke = () => {
    observedLocalDisable = true;
    assert.equal(connections.get(connection.id).status, 'revoked');
    assert.equal(vault.get(connection.id), null);
  };
  const result = await connections.providers.resolve({ providerId: 'google', appId: 'google-calendar' }).revoke(connection.id);
  assert.equal(observedLocalDisable, true);
  assert.equal(result.remoteRevoked, false);
  assert.equal(result.connection.status, 'revoked');
});

test('connection timestamps consistently use the injected clock for token and OAuth lifecycle paths', async t => {
  const { provider, connections, state, connect, bind } = fixture(t);
  bind();
  let expected = new Date(state.now).toISOString();
  const token = await connections.connect({ appId: 'github', token: 'private-github' });
  for (const field of ['createdAt', 'updatedAt', 'lastCheckedAt']) assert.equal(token[field], expected);
  const { connection } = await connect();
  for (const field of ['createdAt', 'updatedAt', 'lastCheckedAt']) assert.equal(connection[field], expected);
  state.now += 1000; expected = new Date(state.now).toISOString();
  const checked = await connections.check(connection.id);
  assert.equal(checked.updatedAt, expected); assert.equal(checked.lastCheckedAt, expected);
  state.now += 1000; expected = new Date(state.now).toISOString(); state.failIdentity = true;
  const failed = await connections.check(connection.id);
  assert.equal(failed.status, 'reconnect_required'); assert.equal(failed.updatedAt, expected);
  state.now += 1000; expected = new Date(state.now).toISOString();
  assert.equal(connections.revoke(connection.id).updatedAt, expected);
});

test('SPI Gmail consent uses only Gmail baseline scopes and does not enable Calendar probes', async t => {
  const { connections, provider, state, connect, bind } = fixture(t);
  bind(); state.scope = GMAIL_SCOPE;
  const { connection, flow } = await connect({ appId: 'gmail' });
  assert.equal(connection.appId, 'gmail');
  assert.equal(new URL(flow.authorizationUrl).searchParams.get('scope'), GMAIL_SCOPE);
  assert.equal(state.requests.some(request => request.url.includes('/calendar/')), false);
});

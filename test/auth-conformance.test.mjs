import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Store } from '../lib/store.mjs';
import { Vault } from '../lib/vault.mjs';
import { ConnectionManager, catalog } from '../lib/connections.mjs';
import { OAuth2Provider } from '../lib/providers/oauth2.mjs';
import { reviewedProviderIds } from '../lib/providers/definitions.mjs';
import { v1Definition } from './fixtures/auth-v1/urls.mjs';
import { SIMULATORS } from './fixtures/oauth-simulators.mjs';

// The admission test for every reviewed auth definition: the real engine and
// connection manager run each definition against an independent simulation of
// that provider's documented rules. A new definition is not connectable until
// it passes this matrix, and live certification remains a separate gate.
// F10.7: the matrix runs on the version 1 definitions in test/fixtures/auth-v1 (T6 through the fixtures). The shipped version 2
// definitions are exercised against the same simulators by test/partial-grant.test.mjs and test/f10-7-full-access.test.mjs.
const definitionFor = v1Definition;
const CLIENT = { clientId: 'fixture-client-id', clientSecret: 'fixture-secret/with:special chars' };
// Slack refuses plain-HTTP callbacks, so its protocol is exercised through a hosted HTTPS
// callback; the local loopback limit is pinned separately below.
// Notion refuses IP-address callbacks (observed while registering, 2026-10-12), so it runs hosted too.
const HOSTED = { slack: 'https://fabric.example/api/oauth/slack/callback', notion: 'https://fabric.example/oauth/notion/4188/callback' };
const EXPECTED = {
  google: { identity: { id: 'google-sub-a', displayName: 'a@example.com', email: 'a@example.com' }, headers: {}, lifetime: 3599, write: ['https://www.googleapis.com/auth/calendar.calendarlist.readonly', 'https://www.googleapis.com/auth/calendar.events'] },
  github: { identity: { id: '101', displayName: 'octo-a' }, headers: { 'User-Agent': 'Capability-Fabric/0.1', 'X-GitHub-Api-Version': '2022-11-28' }, lifetime: 28800, write: ['read:user', 'repo'] },
  slack: { identity: { id: 'T0001:U000A', displayName: 'alice', workspaceId: 'T0001', workspaceName: 'Fixture Team' }, headers: {}, lifetime: 43200, write: ['channels:read', 'channels:history', 'users:read', 'chat:write'] },
  notion: { identity: { id: 'ws-a:notion-user-a', displayName: 'Avery A', email: 'avery@a.example', workspaceName: 'Workspace A' }, headers: { 'Notion-Version': '2025-09-03' }, lifetime: null, write: [] },
};
const sameSet = (a, b) => assert.deepEqual([...new Set(a || [])].sort(), [...new Set(b || [])].sort());

function harness(t, providerId, { authority = false, hosted = true } = {}) {
  const directory = mkdtempSync(join(tmpdir(), `fabric-conformance-${providerId}-`));
  let now = Date.UTC(2026, 9, 11, 12);
  const clock = () => now;
  const sim = new SIMULATORS[providerId]({ ...CLIENT, clock });
  const store = new Store({ dataDir: directory, clock, ...(authority ? { localAuthority: 'new' } : {}) });
  const vault = new Vault(directory);
  const hooks = { onRequest: null };
  const request = async req => { await hooks.onRequest?.(req); return sim.request(req); };
  const connections = new ConnectionManager({ store, vault, request, clock });
  const definition = definitionFor(providerId), appId = definition.apps[0].appId;
  const redirect = hosted && HOSTED[providerId] ? { redirectUri: HOSTED[providerId], allowHostedRedirect: true } : {};
  const provider = new OAuth2Provider(definition, { store, vault, connections, request, clock, ...CLIENT, ...redirect });
  connections.setOAuthProvider(provider);
  t.after(() => { store.close(); rmSync(directory, { recursive: true, force: true }); });
  const start = (options = {}) => provider.start({ appId, ...options });
  const finish = (flow, consent, overrides = {}) => provider.callback({ state: consent.state, code: consent.code, error: consent.error, flowId: flow.flowId, ...overrides });
  const connect = async ({ account = 'a', grant = 'all', deny = false, ...options } = {}) => {
    const flow = start(options), consent = sim.consent(flow.authorizationUrl, { account, grant, deny });
    return { flow, consent, connection: await finish(flow, consent) };
  };
  const tokenCalls = () => sim.calls.filter(req => req.url === definition.token.url);
  const refreshCalls = () => tokenCalls().filter(req => (req.body.startsWith('{') ? JSON.parse(req.body) : Object.fromEntries(new URLSearchParams(req.body))).grant_type === 'refresh_token');
  const identityCalls = () => sim.calls.filter(req => req.url === definition.identity.request.url);
  return { directory, sim, store, vault, connections, provider, definition, appId, start, finish, connect, tokenCalls, refreshCalls, identityCalls, hooks, advance: ms => { now += ms; }, get now() { return now; } };
}
const rotating = providerId => { const d = definitionFor(providerId); return d.refresh.supported && !d.refresh.keepPreviousWhenOmitted; };

for (const providerId of reviewedProviderIds()) {
  const expected = EXPECTED[providerId];
  test(`${providerId} definition has an independent provider simulator and expectations`, () => {
    assert.ok(SIMULATORS[providerId], 'every reviewed definition needs a documented-behaviour simulator');
    assert.ok(expected, 'every reviewed definition needs conformance expectations');
  });
  if (!expected || !SIMULATORS[providerId]) continue;
  const lifetime = expected.lifetime;

  test(`${providerId}: consent connects the exact account and keeps every credential private`, async t => {
    const h = harness(t, providerId);
    const flow = h.start(), url = new URL(flow.authorizationUrl);
    const verifier = h.vault.get(`oauth:${createHash('sha256').update(url.searchParams.get('state')).digest('hex')}`).verifier;
    // A pending flow is stored as hashes only; secrets never sit in the store before consumption.
    const pending = JSON.stringify(h.store.list('oauthFlows'));
    for (const secret of [CLIENT.clientSecret, verifier, url.searchParams.get('state'), flow.flowId]) assert.equal(pending.includes(secret), false);
    assert.equal(readFileSync(join(h.directory, 'fabric.sqlite')).includes(Buffer.from(verifier)), false);
    assert.equal(url.searchParams.has('client_secret'), false);
    assert.equal(url.searchParams.has('code_challenge'), h.definition.authorization.pkce === 'S256');
    const consent = h.sim.consent(flow.authorizationUrl), connection = await h.finish(flow, consent);
    assert.equal(connection.status, 'ready'); assert.equal(connection.authMethod, 'oauth'); assert.equal(connection.appId, h.appId);
    assert.deepEqual(connection.identity, expected.identity);
    assert.equal(h.store.get('connections', connection.id).providerId, providerId);
    const secrets = [CLIENT.clientSecret, consent.code, h.vault.get(connection.id).accessToken, h.vault.get(connection.id).refreshToken].filter(Boolean);
    const exposed = JSON.stringify([h.connections.list(), h.store.list('activity'), h.store.list('oauthFlows'), h.store.list('connections')]);
    for (const secret of secrets) assert.equal(exposed.includes(secret), false);
    const database = readFileSync(join(h.directory, 'fabric.sqlite'));
    for (const secret of secrets) assert.equal(database.includes(Buffer.from(secret)), false);
  });

  test(`${providerId}: write access requests and verifies every permission it asks for`, async t => {
    const h = harness(t, providerId);
    const { flow, connection } = await h.connect({ writeAccess: true });
    const url = new URL(flow.authorizationUrl), userGrant = h.definition.authorization.userScopeParameter !== null;
    if (expected.write.length) sameSet(url.searchParams.get(userGrant ? 'user_scope' : 'scope').split(h.definition.authorization.scopeSeparator).filter(scope => !h.definition.authorization.identityScopes.includes(scope)), expected.write);
    if (userGrant) assert.equal(url.searchParams.has('scope'), false, 'a user-credential app never requests a bot grant');
    if (expected.write.length) sameSet(h.store.get('connections', connection.id).scopes.filter(scope => !h.definition.authorization.identityScopes.includes(scope) && !scope.startsWith('https://www.googleapis.com/auth/userinfo')), expected.write);
    if (!expected.write.length) return;
    await assert.rejects(h.connect({ writeAccess: true, grant: 'partial' }), error => error.code === 'insufficient_scope');
    assert.equal(h.connections.list().length, 1);
  });

  test(`${providerId}: replayed, cross-browser, expired and declined callbacks never connect`, async t => {
    const h = harness(t, providerId);
    const flow = h.start(), consent = h.sim.consent(flow.authorizationUrl);
    await assert.rejects(h.finish(flow, consent, { flowId: 'another-browser' }), error => error.code === 'invalid_state');
    const connection = await h.finish(flow, consent);
    assert.equal(connection.status, 'ready');
    await assert.rejects(h.finish(flow, consent), /already used/);
    const late = h.start(), lateConsent = h.sim.consent(late.authorizationUrl);
    h.advance(11 * 60 * 1000);
    await assert.rejects(h.finish(late, lateConsent), error => error.code === 'invalid_state');
    const before = h.tokenCalls().length;
    const declined = h.start(), refusal = h.sim.consent(declined.authorizationUrl, { deny: true });
    assert.equal(JSON.stringify(h.store.list('oauthFlows')).includes(CLIENT.clientSecret), false);
    await assert.rejects(h.finish(declined, refusal), error => error.code === 'consent_denied');
    await assert.rejects(h.finish(declined, refusal), /already used/);
    assert.equal(h.tokenCalls().length, before, 'declined consent makes no token request');
    assert.equal(h.connections.list().length, 1);
  });

  test(`${providerId}: rejected codes, client credentials and rate limits are classified without provider text`, async t => {
    const h = harness(t, providerId);
    const flow = h.start(), consent = h.sim.consent(flow.authorizationUrl);
    await assert.rejects(h.finish(flow, consent, { code: 'not-a-real-code' }), error => error.code === 'reconnect_required' && !/incorrect|Invalid code|Bad Request|expired\./.test(error.message));
    const limited = h.start(), limitedConsent = h.sim.consent(limited.authorizationUrl);
    h.sim.failToken = { status: 429, data: { error: 'rate_limited', message: 'DO-NOT-PRINT' } };
    await assert.rejects(h.finish(limited, limitedConsent), error => error.code === 'unavailable' && /temporarily unavailable/.test(error.message) && !error.message.includes('DO-NOT-PRINT'));
    const second = h.start(), approval = h.sim.consent(second.authorizationUrl);
    h.provider.clientSecret = 'wrong-secret';
    await assert.rejects(h.finish(second, approval), error => error.code === 'oauth_rejected' && !error.message.includes('wrong-secret'));
    assert.deepEqual(h.connections.list(), []);
  });

  test(`${providerId}: partially granted permissions never activate a connection`, async t => {
    const h = harness(t, providerId);
    const asked = [...h.definition.apps[0].scopes.read, ...h.definition.apps[0].userScopes.read];
    if (!asked.length) {
      // Providers without OAuth scopes (Notion capabilities are portal-configured) send none.
      const { flow, connection } = await h.connect({ grant: 'partial' });
      assert.equal(new URL(flow.authorizationUrl).searchParams.has('scope'), false);
      assert.equal(connection.status, 'ready');
      return;
    }
    await assert.rejects(h.connect({ grant: 'partial' }), error => error.code === 'insufficient_scope');
    assert.deepEqual(h.connections.list(), []);
  });

  test(`${providerId}: API credentials carry definition headers and only declared origins`, async t => {
    const h = harness(t, providerId);
    const { connection } = await h.connect();
    const credentials = await h.connections.credentials(connection.id);
    assert.equal(credentials.headers.Authorization, `Bearer ${h.vault.get(connection.id).accessToken}`);
    for (const [name, value] of Object.entries(expected.headers)) assert.equal(credentials.headers[name], value);
    assert.deepEqual(credentials.allowedOrigins, catalog.find(app => app.id === h.appId).allowedOrigins);
  });

  test(`${providerId}: renewal follows the provider's documented refresh model`, async t => {
    const h = harness(t, providerId);
    if (lifetime === null) {
      const { connection } = await h.connect();
      const before = h.tokenCalls().length, token = h.vault.get(connection.id).accessToken;
      h.advance(400 * 24 * 3600 * 1000);
      assert.equal((await h.connections.credentials(connection.id)).headers.Authorization, `Bearer ${token}`);
      assert.equal(h.tokenCalls().length, before, 'no expiry was issued, so no refresh is attempted');
      return;
    }
    h.sim.expiring = true;
    const { connection } = await h.connect();
    const original = h.vault.get(connection.id);
    assert.equal(typeof original.expiresAt, 'number');
    h.advance(lifetime * 1000);
    const [first, second] = await Promise.all([h.connections.credentials(connection.id), h.connections.credentials(connection.id)]);
    assert.deepEqual(first, second);
    assert.equal(h.refreshCalls().length, 1, 'concurrent callers share one refresh');
    const renewed = h.vault.get(connection.id);
    assert.notEqual(renewed.accessToken, original.accessToken);
    assert.equal(Object.hasOwn(renewed, 'identityPending'), false);
    if (h.definition.refresh.keepPreviousWhenOmitted) assert.equal(renewed.refreshToken, original.refreshToken, 'omitted refresh credential is kept');
    else {
      assert.notEqual(renewed.refreshToken, original.refreshToken, 'rotated refresh credential replaces the old one');
      assert.equal(h.sim.refresh.has(original.refreshToken), false, 'the provider no longer accepts the rotated-out refresh token');
    }
    assert.equal(h.connections.get(connection.id).status, 'ready');
    assert.equal(h.connections.get(connection.id).identity.id, connection.identity.id);
  });

  if (lifetime !== null && rotating(providerId)) {
    test(`${providerId}: a rotated pair survives an identity outage right after refresh`, async t => {
      const h = harness(t, providerId);
      h.sim.expiring = true;
      const { connection } = await h.connect();
      const original = h.vault.get(connection.id);
      h.advance(lifetime * 1000);
      h.sim.failIdentity = 1;
      await assert.rejects(h.connections.credentials(connection.id), error => error.code !== 'reconnect_required' && /Try again later/.test(error.message));
      const pending = h.vault.get(connection.id);
      assert.notEqual(pending.refreshToken, original.refreshToken, 'the new single-use pair was saved before the identity check');
      assert.equal(pending.identityPending, true);
      assert.equal(h.connections.get(connection.id).status, 'ready');
      const refreshes = h.refreshCalls().length;
      const recovered = await h.connections.credentials(connection.id);
      assert.equal(recovered.headers.Authorization, `Bearer ${pending.accessToken}`);
      assert.equal(h.refreshCalls().length, refreshes, 'recovery verifies identity without spending another refresh');
      assert.equal(Object.hasOwn(h.vault.get(connection.id), 'identityPending'), false);
    });

    test(`${providerId}: a dead refresh credential becomes reconnect-required, not a configuration error`, async t => {
      const h = harness(t, providerId);
      h.sim.expiring = true;
      const { connection } = await h.connect();
      h.sim.refresh.clear();
      h.advance(lifetime * 1000);
      await assert.rejects(h.connections.credentials(connection.id), error => error.code === 'reconnect_required' && !/incorrect|invalid_refresh|bad_refresh/.test(error.message));
      assert.equal(h.connections.get(connection.id).status, 'reconnect_required');
    });

    test(`${providerId}: an omitted rotated refresh credential is not kept`, async t => {
      const h = harness(t, providerId);
      h.sim.expiring = true;
      const { connection } = await h.connect();
      h.sim.omitRotatedRefresh = true;
      h.advance(lifetime * 1000);
      await h.connections.credentials(connection.id);
      assert.equal(h.vault.get(connection.id).refreshToken, undefined);
      assert.equal(h.connections.get(connection.id).refreshAvailable, false);
      const before = h.tokenCalls().length;
      h.advance(lifetime * 1000);
      await assert.rejects(h.connections.credentials(connection.id), error => error.code === 'reconnect_required');
      assert.equal(h.tokenCalls().length, before, 'no token request is made without a refresh credential');
    });
  }

  test(`${providerId}: provider-side revocation becomes reconnect-required without provider text`, async t => {
    const h = harness(t, providerId);
    const { connection } = await h.connect();
    h.sim.revokeAccount('a');
    const checked = await h.connections.check(connection.id);
    assert.equal(checked.status, 'reconnect_required');
    assert.doesNotMatch(String(checked.error), /Bad credentials|invalid_auth|unauthorized|Token has been/);
    await assert.rejects(h.connections.credentials(connection.id), /active API connection|Reconnect/);
  });

  test(`${providerId}: reconnect binds the same account and refuses a different one`, async t => {
    const h = harness(t, providerId);
    const { connection } = await h.connect();
    const again = await h.connect({ connectionId: connection.id });
    assert.equal(again.connection.id, connection.id); assert.equal(again.connection.identity.id, connection.identity.id);
    const current = h.vault.get(connection.id);
    await assert.rejects(h.connect({ connectionId: connection.id, account: 'b' }), error => error.code === 'account_mismatch');
    assert.deepEqual(h.vault.get(connection.id), current, 'a different account never replaces stored credentials');
    assert.equal(h.connections.get(connection.id).identity.id, connection.identity.id);
  });

  test(`${providerId}: disconnect is local first and reports exactly what the provider revoked`, async t => {
    const h = harness(t, providerId);
    const { connection } = await h.connect();
    const revokeOrigin = new URL(h.definition.revocation.url.replace('{client_id}', 'x')).origin;
    let observedLocalFirst = false;
    h.hooks.onRequest = req => {
      if (req.url.startsWith(revokeOrigin) && req.method === h.definition.revocation.method && req.url !== h.definition.identity.request.url) observedLocalFirst = h.vault.get(connection.id) === null && h.connections.get(connection.id).status === 'revoked';
    };
    const result = await h.provider.revoke(connection.id);
    assert.equal(result.connection.status, 'revoked');
    assert.equal(h.vault.get(connection.id), null);
    assert.equal(observedLocalFirst, true, 'local access is disabled before any provider call');
    assert.equal(result.remoteRevoked, true);
    assert.equal(result.revokedScope, h.definition.revocation.covers);
    assert.match(result.message, h.definition.revocation.covers === 'grant' ? /revocation confirmed/ : /revoked this connection's token.*remove it/);
    await assert.rejects(h.connections.credentials(connection.id), /active API connection/);
    const calls = h.sim.calls.length;
    const again = await h.provider.revoke(connection.id);
    assert.equal(again.remoteRevoked, false); assert.match(again.message, /not confirmed/);
    assert.equal(h.sim.calls.length, calls, 'a second disconnect with no credential makes no provider request');
    const other = await h.connect();
    h.sim.revokeFails = true;
    const failed = await h.provider.revoke(other.connection.id);
    assert.equal(failed.remoteRevoked, false); assert.match(failed.message, /not confirmed/);
    assert.equal(h.vault.get(other.connection.id), null);
  });

  test(`${providerId}: designated authority rejects consent that completes after a revoke`, async t => {
    const h = harness(t, providerId, { authority: true });
    const { connection } = await h.connect();
    const flow = h.start({ connectionId: connection.id }), consent = h.sim.consent(flow.authorizationUrl);
    h.connections.revoke(connection.id);
    await assert.rejects(h.finish(flow, consent), error => error.code === 'connection_changed');
    assert.equal(h.connections.get(connection.id).status, 'revoked');
    assert.equal(h.vault.get(connection.id), null);
  });

  if (catalog.find(app => app.id === definitionFor(providerId).apps[0].appId)?.authMethods.includes('token')) {
    test(`${providerId}: a pasted developer token resolves through the same reviewed identity rules`, async t => {
      const h = harness(t, providerId);
      const extra = providerId === 'notion' ? { bot: h.sim.issueBot('a', { internal: true }) } : {};
      const issued = h.sim.issue('a', [], { refreshable: false, extra });
      const connection = await h.connections.connect({ appId: h.appId, token: issued.accessToken });
      const identity = { ...connection.identity };
      if (providerId === 'notion') assert.equal(identity.id, extra.bot.botId, 'an internal integration has no human owner and keys on its bot');
      else assert.deepEqual(identity, expected.identity);
      assert.equal(connection.authMethod, 'token');
    });
  }
}

test('slack: a loopback callback is reported unavailable and never starts a sign-in', async t => {
  const h = harness(t, 'slack', { hosted: false });
  assert.deepEqual(h.provider.availability(), { configured: true, available: false, reason: 'Slack only accepts HTTPS callbacks. Sign-in becomes available once FABRIC_PUBLIC_CALLBACK_BASE names the hosted callback relay.' });
  assert.throws(() => h.start(), error => error.code === 'redirect_unsupported');
  assert.deepEqual(h.store.list('oauthFlows'), []);
  assert.equal(h.sim.calls.length, 0);
});

test('slack: the simulator enforces the documented HTTPS redirect rule', async t => {
  const h = harness(t, 'slack', { hosted: false });
  const forced = new OAuth2Provider(definitionFor('slack'), { store: h.store, vault: h.vault, connections: h.connections, request: req => h.sim.request(req), ...CLIENT });
  assert.equal(forced.redirectSupported, false);
  const url = new URL('https://slack.com/oauth/v2/authorize');
  for (const [key, value] of Object.entries({ client_id: CLIENT.clientId, user_scope: 'channels:read', redirect_uri: 'http://127.0.0.1:4188/api/oauth/slack/callback', state: 'state' })) url.searchParams.set(key, value);
  assert.equal(h.sim.consent(url.href).error, 'bad_redirect_uri');
});

test('slack: upgrades and reconnects travel as user scopes and are verified', async t => {
  const h = harness(t, 'slack');
  h.store.put('applicationMaps', { id: 'slack', operations: [{ requiredScopes: ['groups:read'] }] });
  const { connection } = await h.connect({ writeAccess: true });
  const reconnect = h.start({ connectionId: connection.id }), url = new URL(reconnect.authorizationUrl);
  assert.equal(url.searchParams.has('scope'), false);
  assert.ok(url.searchParams.get('user_scope').split(',').includes('chat:write'), 'a read-only reconnect keeps the granted write scope as a user scope');
  const upgrade = h.start({ connectionId: connection.id, scopes: ['groups:read'] }), upgradeUrl = new URL(upgrade.authorizationUrl);
  assert.equal(upgradeUrl.searchParams.has('scope'), false);
  assert.ok(upgradeUrl.searchParams.get('user_scope').split(',').includes('groups:read'));
  const before = h.vault.get(connection.id);
  const partial = h.sim.consent(upgrade.authorizationUrl, { grant: 'partial' });
  await assert.rejects(h.finish(upgrade, partial), error => error.code === 'insufficient_scope');
  assert.deepEqual(h.vault.get(connection.id), before, 'a partially declined upgrade keeps the existing grant');
  const next = h.start({ connectionId: connection.id, scopes: ['groups:read'] });
  await h.finish(next, h.sim.consent(next.authorizationUrl));
  assert.ok(h.store.get('connections', connection.id).scopes.includes('groups:read'));
  assert.deepEqual(h.sim.botTokens, [], 'no workspace bot credential was ever requested');
});

test('github: overlapping implied scopes are not offered as upgrades', async t => {
  const h = harness(t, 'github');
  h.store.put('applicationMaps', { id: 'github', operations: [{ requiredScopes: ['public_repo', 'read:org'] }] });
  assert.throws(() => h.start({ scopes: ['public_repo'] }), error => error.code === 'invalid_scope');
  const { connection } = await h.connect({ writeAccess: true, scopes: ['read:org'] });
  sameSet(h.store.get('connections', connection.id).scopes, ['read:user', 'repo', 'read:org']);
});

test('github: token exchange always asks for JSON, which GitHub otherwise returns form-encoded', async t => {
  const h = harness(t, 'github');
  await h.connect();
  for (const call of h.tokenCalls()) assert.equal(call.headers.Accept, 'application/json');
});

test('notion: a null refresh credential keeps the previous one', async t => {
  const h = harness(t, 'notion');
  const { connection } = await h.connect();
  const original = h.vault.get(connection.id);
  h.sim.nullRefresh = true;
  h.vault.set(connection.id, { ...original, expiresAt: h.now - 1 });
  const renewed = await h.provider.refresh(connection.id);
  assert.notEqual(renewed.accessToken, original.accessToken);
  assert.equal(renewed.refreshToken, original.refreshToken);
});

test('notion: designated authority renewal never persists an undefined scope field', async t => {
  const h = harness(t, 'notion', { authority: true });
  const { connection } = await h.connect();
  assert.equal(Object.hasOwn(h.store.get('connections', connection.id), 'scopes'), false);
  h.vault.set(connection.id, { ...h.vault.get(connection.id), expiresAt: h.now - 1 });
  const renewed = await h.provider.refresh(connection.id);
  assert.ok(renewed.accessToken);
  assert.equal(h.connections.get(connection.id).status, 'ready');
  assert.equal(Object.hasOwn(h.store.get('connections', connection.id), 'scopes'), false);
});

test('google: legacy flows recorded without a provider still complete on Google', async t => {
  const h = harness(t, 'google');
  const flow = h.start(), consent = h.sim.consent(flow.authorizationUrl);
  const record = h.store.list('oauthFlows')[0], { providerId, ...legacy } = record;
  h.store.put('oauthFlows', legacy);
  assert.equal(providerId, 'google');
  const connection = await h.finish(flow, consent);
  assert.equal(connection.status, 'ready');
  assert.equal(h.store.get('connections', connection.id).providerId, 'google');
});

test('google: strict legacy token parsing and exact consent parameters are preserved', async t => {
  const h = harness(t, 'google');
  const flow = h.start(), params = Object.fromEntries(new URL(flow.authorizationUrl).searchParams);
  assert.deepEqual(Object.keys(params), ['client_id', 'redirect_uri', 'response_type', 'scope', 'access_type', 'prompt', 'state', 'code_challenge', 'code_challenge_method']);
  assert.equal(params.access_type, 'offline'); assert.equal(params.prompt, 'consent'); assert.equal(params.code_challenge_method, 'S256');
  for (const data of [{ access_token: 'x', token_type: 'Bearer', scope: 'openid' }, { access_token: 'x', token_type: 'mac', expires_in: 3600 }, { access_token: 'x', token_type: 'Bearer', expires_in: 3600, refresh_token: null }]) {
    assert.throws(() => h.provider.parseTokens({ status: 200, data }), /invalid (token response|refresh credential)/);
  }
  for (const response of [{ status: 200, data: { error: 'invalid_grant' } }, { status: 400, data: { code: 'invalid_grant' } }]) {
    assert.throws(() => h.provider.parseTokens(response), error => error.code !== 'reconnect_required', 'GitHub and Notion quirks never apply to Google');
  }
  // Returning consent still yields renewal because Google is always asked with prompt=consent.
  const first = await h.connect(), second = await h.connect();
  assert.ok(h.vault.get(first.connection.id).refreshToken); assert.ok(h.vault.get(second.connection.id).refreshToken);
});

test('github: a reconnect without a refresh credential drops the superseded rotating one', async t => {
  const h = harness(t, 'github');
  h.sim.expiring = true;
  const { connection } = await h.connect();
  assert.ok(h.vault.get(connection.id).refreshToken);
  h.sim.expiring = false;
  await h.connect({ connectionId: connection.id });
  assert.equal(h.vault.get(connection.id).refreshToken, undefined);
  assert.equal(h.connections.get(connection.id).refreshAvailable, false);
});

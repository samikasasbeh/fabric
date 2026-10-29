import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { validateAuthDefinition, AuthDefinitionError } from '../contracts/auth-definition.mts';
import { definitionFor } from '../lib/providers/definitions.mjs';
import { OAuth2Provider } from '../lib/providers/oauth2.mjs';
import { GoogleProvider } from '../lib/providers/google.mjs';
import { TrustedProviderRegistry } from '../lib/providers/registry.mts';
import { Store } from '../lib/store.mjs';
import { Vault } from '../lib/vault.mjs';
import { v1Definition } from './fixtures/auth-v1/urls.mjs';
import { catalogDefinition, versionTwoUrls } from './fixtures/auth-v2/urls.mjs';

const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);
const schema = ajv.compile(JSON.parse(readFileSync(new URL('../contracts/auth-definition.schema.json', import.meta.url))));
const google = () => JSON.parse(readFileSync(new URL('../catalog/auth/google.json', import.meta.url)));
const rejects = (mutate, pattern = /Invalid auth definition/) => { const value = google(); mutate(value); assert.throws(() => validateAuthDefinition(value), error => error instanceof AuthDefinitionError && error.code === 'invalid_definition' && pattern.test(error.message)); return value; };
const isDeepFrozen = value => value === null || typeof value !== 'object' || (Object.isFrozen(value) && Object.values(value).every(isDeepFrozen));

test('the reviewed Google definition passes semantic and structural validation and loads detached and frozen', () => {
  const raw = google(), checked = validateAuthDefinition(raw);
  assert.deepEqual(checked, raw); assert.notEqual(checked, raw); assert.equal(isDeepFrozen(checked), true);
  assert.ok(schema(raw), JSON.stringify(schema.errors));
  const loaded = definitionFor('google');
  assert.equal(loaded, definitionFor('google'), 'loader caches the validated definition');
  assert.equal(isDeepFrozen(loaded), true); assert.deepEqual(loaded, raw);
});

test('definitions only reach public HTTPS endpoints without credentials, ports, queries or fragments', () => {
  for (const url of ['http://accounts.example.com/auth', 'https://user:pw@accounts.example.com/auth', 'https://accounts.example.com:8443/auth', 'https://accounts.example.com/auth?x=1', 'https://accounts.example.com/auth#x', 'https://127.0.0.1/auth', 'https://localhost/auth', 'https://[::1]/auth', 'ftp://accounts.example.com/auth', 'not a url']) {
    const value = rejects(definition => { definition.authorization.url = url; }, /public HTTPS URL|HTTPS URL/);
    if (/^(http:|ftp:|not|https:\/\/user|https:\/\/[^/]+:8443|.*[?#])/.test(url)) assert.equal(schema(value), false, url);
  }
  rejects(definition => { definition.token.url = 'https://oauth2.example.com/token?client_secret=x'; });
  rejects(definition => { definition.identity.request.url = 'http://openid.example.com/userinfo'; });
  rejects(definition => { definition.revocation.url = 'https://oauth2.example.com:444/revoke'; });
  rejects(definition => { definition.apps[0].accessProbe.url = 'https://user@www.googleapis.com/calendar/v3/x'; });
});

test('reserved OAuth parameters and credential headers can never be supplied by a definition', () => {
  for (const name of ['client_id', 'client_secret', 'redirect_uri', 'state', 'scope', 'user_scope', 'code_challenge', 'code_challenge_method', 'response_type', 'nonce']) {
    const value = rejects(definition => { definition.authorization.extraParameters[name] = 'attacker'; }, /not an allowed name/);
    assert.ok(schema(value), 'reserved-name rules are semantic and enforced by the authoritative validator');
  }
  for (const header of ['Authorization', 'authorization', 'Cookie', 'Host', 'Proxy-Authorization']) {
    rejects(definition => { definition.apiHeaders[header] = 'x'; }, /not an allowed name/);
    rejects(definition => { definition.identity.request.headers[header] = 'x'; }, /not an allowed name/);
  }
  rejects(definition => { definition.apiHeaders['X-Version'] = 'line\nbreak'; });
});

test('prototype-chain pointers, unknown fields, duplicates and contradictory rules fail closed', () => {
  for (const pointer of ['/__proto__', '/constructor/name', '/a/prototype', 'sub', '/', '/a b']) {
    const value = rejects(definition => { definition.identity.id.pointers = [pointer]; });
    assert.equal(schema(value), false, pointer);
  }
  assert.equal(schema(rejects(definition => { definition.unexpected = true; }, /not allowed/)), false);
  assert.equal(schema(rejects(definition => { definition.token.extra = 1; }, /not allowed/)), false);
  // F10.7: the shipped Google definition is version 2, so these mutate version 2 fields.
  assert.equal(schema(rejects(definition => { definition.schemaVersion = 1; })), false);
  assert.equal(schema(rejects(definition => { definition.reviewStatus = 'certified'; })), false);
  rejects(definition => { definition.apps.push(structuredClone(definition.apps[0])); }, /duplicate/);
  rejects(definition => { definition.apps[1].appId = definition.apps[0].appId; }, /duplicated/);
  rejects(definition => { definition.apps[0].access.grant = 'user_scope'; }, /userScopeParameter/);
  rejects(definition => { definition.refresh.supported = false; }, /requires refresh support/);
  rejects(definition => { definition.revocation.successStatuses = [302]; }, /2xx/);
  rejects(definition => { definition.apps[0].upgradeScopes = { prefixes: ['https:'], exact: [] }; }, /upgradeScopes is not allowed/);
  // The version 1 rules still hold for a version 1 definition (T6 through the fixtures).
  for (const [mutate, pattern] of [[definition => { definition.apps[0].upgradeScopes.prefixes = ['https:']; }, /too broad/], [definition => { definition.apps[0].userScopes.read = ['users:read']; }, /userScopeParameter/]]) {
    const value = v1Definition('google'); mutate(value);
    assert.throws(() => validateAuthDefinition(value), error => error instanceof AuthDefinitionError && pattern.test(error.message));
  }
  rejects(definition => { definition.identity.id.pointers = ['/team_id', '/user_id']; definition.identity.id.separator = ''; }, /composite/);
  rejects(definition => { definition.identity.request.body = 'empty-form'; }, /none for GET/);
  rejects(definition => { definition.credentialEnvironment.clientSecret = definition.credentialEnvironment.clientId; }, /must be FABRIC_GOOGLE_CLIENT_ID and FABRIC_GOOGLE_CLIENT_SECRET/);
  rejects(definition => { definition.credentialEnvironment.clientId = 'PATH'; });
  rejects(definition => { definition.token.maxLifetimeSeconds = 10; });
});

test('accessors, non-plain objects and prototype keys are rejected without being invoked', () => {
  let invoked = false;
  const value = google();
  Object.defineProperty(value, 'displayName', { enumerable: true, get() { invoked = true; return 'Google'; } });
  assert.throws(() => validateAuthDefinition(value), AuthDefinitionError);
  assert.equal(invoked, false);
  assert.throws(() => validateAuthDefinition(JSON.parse(JSON.stringify(google()).replace('"apiHeaders":{}', '"apiHeaders":{"__proto__":{"admin":"true"}}'))), AuthDefinitionError);
  assert.equal({}.admin, undefined);
  class Custom {}
  assert.throws(() => validateAuthDefinition(Object.assign(new Custom(), google())), AuthDefinitionError);
  for (const bad of [null, [], 'google', 1]) assert.throws(() => validateAuthDefinition(bad), AuthDefinitionError);
});

test('the definition loader resolves only exact reviewed provider file names', () => {
  for (const id of ['../google', 'google/../google', 'Google', 'google.json', '', 'g', 'missing-provider', null, {}]) {
    assert.throws(() => definitionFor(id), error => error.code === 'invalid_input');
  }
});

// A deliberately non-Google provider: Basic client auth, JSON token bodies,
// comma-separated scopes, no PKCE, non-expiring tokens and DELETE revocation.
const fixtureDefinition = () => ({
  schemaVersion: 1, providerId: 'fixture-oauth', displayName: 'Fixture', reviewStatus: 'reviewed',
  credentialEnvironment: { clientId: 'FABRIC_FIXTURE_OAUTH_CLIENT_ID', clientSecret: 'FABRIC_FIXTURE_OAUTH_CLIENT_SECRET' },
  authorization: { url: 'https://auth.fixture.example/authorize', pkce: 'none', scopeParameter: 'scope', userScopeParameter: null, loopbackRedirect: 'allowed', scopeSeparator: ',', identityScopes: [], extraParameters: { allow_signup: 'false' } },
  token: { url: 'https://auth.fixture.example/token', encoding: 'json', clientAuthentication: 'basic', responseFormat: 'oauth2', scopeSeparator: ',', acceptedTokenTypes: ['bearer'], reconnectErrors: ['bad_verification_code'], requireExpiry: false, maxLifetimeSeconds: 28800, quirks: { errorInSuccessBody: true, errorCodeField: 'error', nullRefreshMeansNone: false, basicEncoding: 'form-urlencoded' } },
  refresh: { supported: false, keepPreviousWhenOmitted: false },
  revocation: { url: 'https://api.fixture.example/applications/{client_id}/token', method: 'DELETE', encoding: 'json', clientAuthentication: 'basic', tokenParameter: 'access_token', preferredToken: 'access', successStatuses: [204], successRequire: [], covers: 'token' },
  apiHeaders: { 'User-Agent': 'Capability-Fabric/0.1', 'X-Fixture-Api-Version': '2026-01-01' },
  identity: { request: { url: 'https://api.fixture.example/user', method: 'GET', headers: {}, body: 'none' }, require: [], requireFailure: 'unverifiable', id: { pointers: ['/id'], separator: '', allowNumbers: true }, alternateId: null, displayName: { pointers: ['/login'], fallback: 'Fixture account' }, email: null, attributes: {} },
  apps: [{ appId: 'fixture-app', scopes: { read: ['repo:read'], write: ['repo:read', 'repo:write'] }, userScopes: { read: [], write: [] }, upgradeScopes: { prefixes: ['repo:admin'], exact: [] }, accessProbe: null }],
});

function engineFixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'fabric-auth-engine-'));
  const store = new Store({ dataDir: directory }), vault = new Vault(directory), requests = [], established = [];
  let issued = 0;
  const request = async req => {
    requests.push(req);
    if (req.url === 'https://auth.fixture.example/token') return { status: 200, data: { access_token: `fixture-access-${++issued}`, token_type: 'bearer', scope: 'repo:read,repo:write' } };
    if (req.url === 'https://api.fixture.example/user') return { status: 200, data: { id: 42, login: 'octo' } };
    if (req.url === 'https://api.fixture.example/applications/fixture%20client/token') return { status: 204, data: null };
    throw new Error('Unexpected fixture endpoint');
  };
  const connections = {
    request, revoked: [],
    get: id => store.get('connections', id),
    revoke(id) { this.revoked.push(id); const record = { ...store.get('connections', id), status: 'revoked' }; store.put('connections', record); vault.delete(id); return record; },
    observe: (appId, accessToken) => provider.observeIdentity({ appId, accessToken }),
    async establishOAuth(input) { established.push(input); const identity = await provider.observeIdentity({ appId: input.appId, accessToken: input.tokens.accessToken }); const record = { id: `conn-${established.length}`, appId: input.appId, authMethod: 'oauth', status: 'ready', identity, scopes: input.tokens.scopes }; store.put('connections', record); vault.set(record.id, input.tokens); return record; },
  };
  const provider = new OAuth2Provider(fixtureDefinition(), { store, vault, connections, request, clock: () => Date.UTC(2026, 9, 11), clientId: 'fixture client', clientSecret: 'se:cr et/+' });
  t.after(() => { store.close(); rmSync(directory, { recursive: true, force: true }); });
  return { store, vault, requests, established, connections, provider, request };
}

test('the engine refuses candidate definitions and derives its callback from the provider ID', t => {
  const { store, vault, connections } = engineFixture(t);
  assert.throws(() => new OAuth2Provider({ ...fixtureDefinition(), reviewStatus: 'candidate' }, { store, vault, connections, clientId: 'a', clientSecret: 'b' }), /candidate definition/);
  const provider = new OAuth2Provider(fixtureDefinition(), { store, vault, connections, clientId: 'a', clientSecret: 'b' });
  assert.equal(provider.redirectUri, 'http://127.0.0.1:4188/api/oauth/fixture-oauth/callback');
  assert.deepEqual(provider.configuration().requiredEnvironment, ['FABRIC_FIXTURE_OAUTH_CLIENT_ID', 'FABRIC_FIXTURE_OAUTH_CLIENT_SECRET']);
  assert.throws(() => new OAuth2Provider(fixtureDefinition(), { store, vault, connections, clientId: 'a', clientSecret: 'b', redirectUri: 'https://evil.example/callback' }), /loopback/);
});

test('the engine follows a non-Google definition end to end without leaking client credentials', async t => {
  const { provider, requests, established, store, vault } = engineFixture(t);
  const flow = provider.start(), url = new URL(flow.authorizationUrl);
  assert.equal(url.origin + url.pathname, 'https://auth.fixture.example/authorize');
  assert.equal(url.searchParams.get('scope'), 'repo:read');
  assert.equal(url.searchParams.get('allow_signup'), 'false');
  assert.equal(url.searchParams.has('code_challenge'), false, 'pkce:none sends no challenge');
  assert.equal(url.searchParams.has('client_secret'), false);
  assert.equal(store.list('oauthFlows')[0].providerId, 'fixture-oauth');
  const connection = await provider.callback({ state: url.searchParams.get('state'), flowId: flow.flowId, code: 'fixture-code' });
  const token = requests.find(req => req.url.endsWith('/token'));
  assert.equal(token.headers['Content-Type'], 'application/json');
  assert.equal(token.headers.Authorization, `Basic ${Buffer.from('fixture%20client:se%3Acr%20et%2F%2B').toString('base64')}`);
  assert.deepEqual(JSON.parse(token.body), { grant_type: 'authorization_code', code: 'fixture-code', redirect_uri: 'http://127.0.0.1:4188/api/oauth/fixture-oauth/callback' });
  assert.deepEqual(token.allowedOrigins, ['https://auth.fixture.example']);
  assert.equal(established[0].tokens.expiresAt, null);
  assert.deepEqual(established[0].tokens.scopes, ['repo:read', 'repo:write']);
  assert.deepEqual(connection.identity, { id: '42', displayName: 'octo' });
  const identity = requests.find(req => req.url === 'https://api.fixture.example/user');
  assert.equal(identity.headers['User-Agent'], 'Capability-Fabric/0.1'); assert.equal(identity.headers['X-Fixture-Api-Version'], '2026-01-01');
  assert.deepEqual(identity.allowedOrigins, ['https://api.fixture.example']);
  const before = requests.length;
  assert.equal((await provider.refresh(connection.id)).accessToken, 'fixture-access-1', 'non-expiring tokens are returned without a refresh request');
  assert.equal(requests.length, before);
  const revoked = await provider.revoke(connection.id), call = requests.at(-1);
  assert.equal(revoked.remoteRevoked, true); assert.equal(call.method, 'DELETE');
  assert.deepEqual(JSON.parse(call.body), { access_token: 'fixture-access-1' });
  assert.equal(call.headers.Authorization.startsWith('Basic '), true);
  assert.equal(vault.get(connection.id), null);
  for (const req of requests) assert.equal(JSON.stringify(req).includes('se:cr et/+'), false, 'raw client secret never appears in a request');
});

test('expired non-refreshable access requires reconnect instead of a token request', async t => {
  const { provider, store, vault, requests } = engineFixture(t);
  store.put('connections', { id: 'expiring', appId: 'fixture-app', authMethod: 'oauth', status: 'ready', identity: { id: '42' }, authRevision: 'a' });
  vault.set('expiring', { accessToken: 'old', refreshToken: 'unused', expiresAt: 0 });
  await assert.rejects(provider.refresh('expiring'), error => error.code === 'reconnect_required' && /cannot be renewed/.test(error.message));
  assert.equal(requests.length, 0);
  assert.equal(store.get('connections', 'expiring').status, 'reconnect_required');
});

test('a flow started for one provider can never be completed or consumed by another', async t => {
  const { provider, store, vault, connections, request } = engineFixture(t);
  const googleProvider = new GoogleProvider({ store, vault, connections, request, clientId: 'g', clientSecret: 'g' });
  const flow = provider.start(), state = new URL(flow.authorizationUrl).searchParams.get('state');
  await assert.rejects(googleProvider.callback({ state, flowId: flow.flowId, code: 'fixture-code' }), error => error.code === 'invalid_state');
  assert.equal(store.list('oauthFlows').length, 1, 'the other provider did not consume the flow');
  const connection = await provider.callback({ state, flowId: flow.flowId, code: 'fixture-code' });
  assert.equal(connection.status, 'ready');
  const googleFlow = googleProvider.start(), googleState = new URL(googleFlow.authorizationUrl).searchParams.get('state');
  await assert.rejects(provider.callback({ state: googleState, flowId: googleFlow.flowId, code: 'fixture-code' }), error => error.code === 'invalid_state');
  assert.equal(store.list('oauthFlows').length, 1);
});

test('legacy Google flows recorded without a provider ID still complete only on Google', async t => {
  const { store, vault, connections, request, provider } = engineFixture(t);
  const googleProvider = new GoogleProvider({ store, vault, connections, request, clientId: 'g', clientSecret: 'g' });
  const flow = googleProvider.start(), state = new URL(flow.authorizationUrl).searchParams.get('state');
  const record = store.list('oauthFlows')[0]; const { providerId, ...legacy } = record; store.put('oauthFlows', legacy);
  assert.equal(providerId, 'google');
  await assert.rejects(provider.callback({ state, flowId: flow.flowId, code: 'fixture-code' }), error => error.code === 'invalid_state');
  assert.equal(store.list('oauthFlows').length, 1);
});

test('a definition may read only its own provider client credentials', () => {
  for (const [clientId, clientSecret] of [['FABRIC_GITHUB_CLIENT_ID', 'FABRIC_GITHUB_CLIENT_SECRET'], ['FABRIC_GOOGLE_CLIENT_ID', 'FABRIC_MODEL_API_KEY'], ['FABRIC_MODEL_API_KEY', 'FABRIC_GOOGLE_CLIENT_SECRET']]) {
    rejects(definition => { definition.credentialEnvironment = { clientId, clientSecret }; }, /credentialEnvironment must be FABRIC_GOOGLE_CLIENT_ID/);
  }
  assert.doesNotThrow(() => validateAuthDefinition({ ...fixtureDefinition(), providerId: 'my-app', credentialEnvironment: { clientId: 'FABRIC_MY_APP_CLIENT_ID', clientSecret: 'FABRIC_MY_APP_CLIENT_SECRET' } }));
});

test('loopback, private-suffix, trailing-dot and single-label hosts are never public endpoints', () => {
  for (const url of ['https://foo.localhost/authorize', 'https://localhost./authorize', 'https://intranet/authorize', 'https://printer.local/authorize', 'https://metadata.google.internal/token', 'https://accounts.example.com./auth']) {
    rejects(definition => { definition.authorization.url = url; }, /public HTTPS URL/);
  }
});

test('presence rules, alternate identities, quirks, revocation coverage and redirect rules are validated', () => {
  assert.doesNotThrow(() => validateAuthDefinition({ ...google(), identity: { ...google().identity, require: [{ pointer: '/sub', present: true }], alternateId: { pointers: ['/id'], separator: '' } } }));
  rejects(definition => { definition.identity.require = [{ pointer: '/sub', present: false }]; }, /present must be true/);
  rejects(definition => { definition.identity.require = [{ pointer: '/sub', present: true, equals: 'x' }]; }, /not allowed/);
  rejects(definition => { definition.identity.alternateId = { pointers: ['/a', '/b'], separator: '' }; }, /composite/);
  rejects(definition => { delete definition.token.quirks.basicEncoding; }, /basicEncoding is required/);
  rejects(definition => { definition.token.quirks.errorCodeField = 'message'; }, /errorCodeField/);
  rejects(definition => { definition.revocation.covers = 'everything'; }, /covers/);
  rejects(definition => { definition.authorization.loopbackRedirect = 'sometimes'; }, /loopbackRedirect/);
  for (const value of [google(), ...['github', 'slack', 'notion'].map(id => JSON.parse(readFileSync(new URL(`../catalog/auth/${id}.json`, import.meta.url))))]) assert.ok(schema(value), JSON.stringify(schema.errors));
});

test('client Basic credentials follow the definition: raw for providers that document it', async t => {
  const { store, vault, connections, requests } = engineFixture(t);
  const raw = fixtureDefinition(); raw.token.quirks.basicEncoding = 'raw';
  const provider = new OAuth2Provider(raw, { store, vault, connections, request: async req => { requests.push(req); return { status: 200, data: { access_token: 'raw-access', token_type: 'bearer' } }; }, clientId: 'fixture client', clientSecret: 'se:cr et/+' });
  const flow = provider.start(), state = new URL(flow.authorizationUrl).searchParams.get('state');
  await provider.callback({ state, flowId: flow.flowId, code: 'fixture-code' }).catch(() => {});
  const token = requests.find(req => req.url.endsWith('/token'));
  assert.equal(token.headers.Authorization, `Basic ${Buffer.from('fixture client:se:cr et/+').toString('base64')}`);
});

test('a provider without a revocation endpoint and an unconfigured provider never call out on disconnect', async t => {
  const { store, vault, connections, requests } = engineFixture(t);
  const none = fixtureDefinition(); none.revocation = null;
  const silent = new OAuth2Provider(none, { store, vault, connections, request: async req => { requests.push(req); throw new Error('no call expected'); }, clientId: 'a', clientSecret: 'b' });
  store.put('connections', { id: 'no-revoke', appId: 'fixture-app', authMethod: 'oauth', status: 'ready', identity: { id: '42' }, authRevision: 'a' });
  vault.set('no-revoke', { accessToken: 'live-token' });
  const result = await silent.revoke('no-revoke');
  assert.equal(result.remoteRevoked, false); assert.match(result.message, /does not offer remote revocation/);
  const unconfigured = new OAuth2Provider(fixtureDefinition(), { store, vault, connections, request: async req => { requests.push(req); throw new Error('no call expected'); }, clientId: '', clientSecret: '' });
  store.put('connections', { id: 'unconfigured', appId: 'fixture-app', authMethod: 'oauth', status: 'ready', identity: { id: '42' }, authRevision: 'b' });
  vault.set('unconfigured', { accessToken: 'live-token' });
  const skipped = await unconfigured.revoke('unconfigured');
  assert.equal(skipped.remoteRevoked, false); assert.match(skipped.message, /not attempted because Fixture sign-in is not configured/);
  assert.equal(requests.length, 0); assert.equal(vault.get('unconfigured'), null);
});

test('identity keys: positive numeric IDs only, alternate key only when a primary field is absent', async t => {
  const { store, vault } = engineFixture(t);
  const definition = fixtureDefinition();
  definition.identity.id = { pointers: ['/workspace', '/owner'], separator: ':', allowNumbers: true };
  definition.identity.alternateId = { pointers: ['/id'], separator: '' };
  let body;
  const connections = { request: async () => ({ status: 200, data: body }) };
  const provider = new OAuth2Provider(definition, { store, vault, connections, clientId: 'a', clientSecret: 'b' });
  const observe = data => { body = data; return provider.observeIdentity({ appId: 'fixture-app', accessToken: 'token' }); };
  assert.equal((await observe({ workspace: 'w', owner: 7, id: 'bot' })).id, 'w:7');
  assert.equal((await observe({ workspace: 'w', id: 'bot' })).id, 'bot', 'a missing owner falls back to the alternate key');
  for (const data of [{ workspace: 'w', owner: 0, id: 'bot' }, { workspace: 'w', owner: -3, id: 'bot' }, { workspace: 'w', owner: { id: 1 }, id: 'bot' }, { workspace: 'w\n', owner: 1, id: 'bot' }]) {
    await assert.rejects(observe(data), /no verifiable account identity/);
  }
  await assert.rejects(observe({ workspace: 'w' }), /no verifiable account identity/, 'an absent alternate key also fails');
});

test('the registry lets each application belong to exactly one installed trusted provider', t => {
  const { store, vault, connections } = engineFixture(t);
  const options = { store, vault, connections, clientId: '', clientSecret: '' };
  const googleProvider = new GoogleProvider(options), github = new OAuth2Provider(definitionFor('github'), options);
  const registry = new TrustedProviderRegistry(googleProvider, github);
  assert.equal(registry.providerFor('github'), 'github'); assert.equal(registry.providerFor('gmail'), 'google');
  assert.throws(() => registry.resolve({ providerId: 'slack', appId: 'slack' }), /Unsupported provider/, 'a reviewed but uninstalled provider is not resolvable');
  const impostor = definitionFor('github'), clash = JSON.parse(JSON.stringify(impostor));
  clash.providerId = 'gitlab'; clash.displayName = 'GitLab'; clash.credentialEnvironment = { clientId: 'FABRIC_GITLAB_CLIENT_ID', clientSecret: 'FABRIC_GITLAB_CLIENT_SECRET' };
  assert.throws(() => registry.bind(new OAuth2Provider(clash, options)), /already served by another trusted provider/);
  assert.throws(() => registry.bind(new GoogleProvider(options)), /trusted provider adapter/);
  assert.throws(() => registry.bind({ providerId: 'evil', appIds: ['github'] }), /trusted provider adapter/);
  assert.equal(registry.providerFor('github'), 'github');
});

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, spec lines 1144-1147): grantHeader names the response header in which a provider lists
// what a token holds (GitHub's X-OAuth-Scopes), so Fabric can notice a narrowed grant. Version 2 only, one lowercase x- header name, never
// one Fabric sends itself; it moves no sign-in URL (T6).
const githubDefinition = () => JSON.parse(readFileSync(new URL('../catalog/auth/github.json', import.meta.url)));
test('grantHeader is version 2 only: one lowercase x- header name of at most 64 characters that Fabric never sends itself', () => {
  const checked = validateAuthDefinition(githubDefinition());
  assert.equal(checked.grantHeader, 'x-oauth-scopes');
  assert.ok(schema(githubDefinition()), JSON.stringify(schema.errors));
  const without = githubDefinition();
  delete without.grantHeader;
  assert.equal(Object.hasOwn(validateAuthDefinition(without), 'grantHeader'), false, 'it is optional');
  assert.ok(schema(without));
  assert.equal(validateAuthDefinition({...githubDefinition(), grantHeader: `x-${'a'.repeat(62)}`}).grantHeader.length, 64);
  for (const value of ['authorization', 'Authorization', 'cookie', 'user-agent', 'X-OAuth-Scopes', 'oauth-scopes', 'x-', `x-${'a'.repeat(63)}`, 'x-oauth_scopes', 'x-oauth scopes', 'x-oauth-scopes\n', 7, null, '']) {
    const definition = {...githubDefinition(), grantHeader: value};
    assert.throws(() => validateAuthDefinition(definition), error => error instanceof AuthDefinitionError && /grantHeader/.test(error.message), JSON.stringify(value));
    assert.equal(schema(definition), false, JSON.stringify(value));
  }
  // A header the definition's own requests carry is one Fabric sends: refused by the authoritative validator.
  for (const value of ['x-github-api-version']) assert.throws(() => validateAuthDefinition({...githubDefinition(), grantHeader: value}), /grantHeader names a header Fabric sends/);
  const v1 = v1Definition('github');
  v1.grantHeader = 'x-oauth-scopes';
  assert.throws(() => validateAuthDefinition(v1), error => error instanceof AuthDefinitionError && /grantHeader is not allowed/.test(error.message));
  assert.equal(schema(v1), false, 'a version 1 definition has no grantHeader');
});

test('the grant header moves no sign-in URL: every version 2 URL is byte for byte the golden with it and without it (T6)', () => {
  const golden = JSON.parse(readFileSync(new URL('./fixtures/auth-v2/urls.golden.json', import.meta.url), 'utf8'));
  const without = providerId => { const definition = catalogDefinition(providerId); delete definition.grantHeader; return definition; };
  assert.deepEqual(versionTwoUrls(), golden);
  assert.deepEqual(versionTwoUrls(without), golden);
});

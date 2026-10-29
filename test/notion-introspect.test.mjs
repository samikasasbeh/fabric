import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, readdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {OAuth2Provider, INTROSPECTION} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {validatePrincipal} from '../contracts/identity.mts';
import {SIMULATORS} from './fixtures/oauth-simulators.mjs';

// F10.19 part 1 (docs/F10.19-BUILD-MAP.md part 1 item 2, spec line 1174, B6): Notion's token introspection. OAuth2Provider.introspect(id) asks
// Notion, with the integration's own client credentials (HTTP Basic, as revocation does), whether one account's access token is active and
// which scope it lists, and returns exactly {active, scope}: never the token, its issue time or Notion's request id. Only Notion has one; any
// other provider refuses with nothing sent. It is never a route: no server handler, agent protocol or developer route calls it, and the
// proxy refuses POST /v1/oauth/introspect as before (a Never row, its member unavailable). Step 20's harness calls it once, in N0.
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLIENT = {clientId: 'f1019-introspect-client', clientSecret: 'f1019-introspect-secret'};
const REDIRECT = {notion: 'https://connect.example.com/oauth/notion/4320', slack: 'https://connect.example.com/oauth/slack/4320', github: 'http://127.0.0.1:59999/api/oauth/github/callback',
  google: 'http://127.0.0.1:59999/api/oauth/google/callback'};
const URL_INTROSPECT = 'https://api.notion.com/v1/oauth/introspect';
const OWNER = validatePrincipal({schemaVersion: 1, kind: 'local_owner', id: 'f1019-owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'f1019-owner'}});
const header = (req, name) => Object.entries(req.headers ?? {}).find(([key]) => key.toLowerCase() === name)?.[1];

/** A designated store, a real ConnectionManager and one adapter for `providerId` on its OAuth simulator; `client` overrides the client values. */
function harness(t, providerId, {client = CLIENT} = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), `fabric-f1019-introspect-${providerId}-`));
  const now = Date.UTC(2026, 9, 26, 12), clock = () => now, sim = new SIMULATORS[providerId]({...CLIENT, clock});
  const store = new Store({dataDir: directory, clock, localAuthority: 'new'}), vault = new Vault(directory);
  t.after(() => { store.close(); rmSync(directory, {recursive: true, force: true}); });
  const request = req => sim.request(req), connections = new ConnectionManager({store, vault, request, clock});
  const provider = new OAuth2Provider(definitionFor(providerId), {store, vault, connections, request, clock, ...client, publishing: 'testing', redirectUri: REDIRECT[providerId],
    allowHostedRedirect: REDIRECT[providerId].startsWith('https:')});
  connections.setOAuthProvider(provider);
  return {sim, store, vault, connections, provider, clock};
}
async function signIn(h, appId) {
  const started = h.provider.start({appId}), consent = h.sim.consent(started.authorizationUrl, {});
  return h.provider.callback({state: consent.state, code: consent.code, flowId: started.flowId});
}

test('INTROSPECTION names Notion\'s one reviewed address, on its token origin', () => {
  assert.deepEqual(INTROSPECTION, {notion: URL_INTROSPECT});
  assert.ok(Object.isFrozen(INTROSPECTION));
  assert.equal(new URL(INTROSPECTION.notion).origin, new URL(definitionFor('notion').token.url).origin, 'only the token origin is allowed');
});

test('Notion\'s introspect() sends one request with Basic client authentication, {token} and the version header, and returns {active, scope} only', async t => {
  const h = harness(t, 'notion'), connection = await signIn(h, 'notion');
  const token = h.vault.get(connection.id).accessToken, before = h.sim.calls.length;
  const answer = await h.provider.introspect(connection.id);
  assert.deepEqual(answer, {active: true, scope: h.sim.introspectScope}, 'exactly two fields: never the token, iat or a request id');
  assert.deepEqual(Object.keys(answer).sort(), ['active', 'scope']);
  assert.equal(h.sim.calls.length, before + 1, 'one request');
  const sent = h.sim.calls.at(-1);
  assert.deepEqual([sent.url, sent.method, sent.allowedOrigins], [URL_INTROSPECT, 'POST', ['https://api.notion.com']]);
  assert.equal(header(sent, 'authorization'), `Basic ${Buffer.from(`${CLIENT.clientId}:${CLIENT.clientSecret}`).toString('base64')}`, 'the client authenticates, never the bearer token');
  assert.equal(header(sent, 'notion-version'), '2026-03-11');
  assert.match(String(header(sent, 'content-type')), /^application\/json/);
  assert.deepEqual(JSON.parse(sent.body), {token}, 'the body holds the token and nothing else: the client secret is never in it');
  assert.equal(JSON.stringify(answer).includes(token), false);
  // A token Notion no longer holds is inactive, with no scope.
  h.sim.revokeAccount('a');
  assert.deepEqual(await h.provider.introspect(connection.id), {active: false, scope: null});
  // Nothing is stored or audited about it: introspection reads, it never changes the account.
  assert.deepEqual(h.store.list('activity').filter(event => /introspect/i.test(JSON.stringify(event))), []);
});

test('Google, GitHub and Slack refuse introspection with nothing sent; so does Notion without client credentials or without the account', async t => {
  for (const [providerId, appId] of [['google', 'google-calendar'], ['github', 'github'], ['slack', 'slack']]) {
    const h = harness(t, providerId), connection = await signIn(h, appId), before = h.sim.calls.length;
    await assert.rejects(h.provider.introspect(connection.id), error => error.code === 'invalid_input', providerId);
    assert.equal(h.sim.calls.length, before, `${providerId}: nothing sent`);
  }
  const signedIn = harness(t, 'notion'), connection = await signIn(signedIn, 'notion');
  const unconfigured = new OAuth2Provider(definitionFor('notion'), {store: signedIn.store, vault: signedIn.vault, connections: signedIn.connections, request: req => signedIn.sim.request(req),
    clock: signedIn.clock, clientId: '', clientSecret: '', publishing: 'testing', redirectUri: REDIRECT.notion, allowHostedRedirect: true});
  const before = signedIn.sim.calls.length;
  await assert.rejects(unconfigured.introspect(connection.id), error => error.code === 'not_configured');
  await assert.rejects(signedIn.provider.introspect('no-such-account'), error => error.code === 'invalid_input');
  signedIn.vault.delete(connection.id);
  await assert.rejects(signedIn.provider.introspect(connection.id), error => error.code === 'reconnect_required');
  assert.equal(signedIn.sim.calls.length, before, 'nothing sent');
});

test('the proxy still refuses POST /v1/oauth/introspect: a Never row whose member is unavailable, no job and no request', async t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-f1019-introspect-proxy-'));
  const clock = () => Date.UTC(2026, 9, 26, 12), store = new Store({dataDir: directory, clock, localAuthority: 'new'}), vault = new Vault(directory);
  t.after(() => { store.close(); rmSync(directory, {recursive: true, force: true}); });
  const calls = [], request = async req => { calls.push(req); return {status: 200, headers: {}, data: Buffer.from('{}')}; };
  const connections = new ConnectionManager({store, vault, request, clock});
  store.put('connections', {id: 'notion-a', appId: 'notion', providerId: 'notion', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'Notion',
    identity: {id: 'ws-a:notion-user-a'}, allowedOrigins: ['https://api.notion.com'], createdAt: new Date(clock()).toISOString()});
  vault.set('notion-a', {accessToken: 'ntn_f1019introspectproxy00000000000', expiresAt: null});
  const runtime = new Runtime({store, connections, clock, ownerPrincipal: OWNER, request});
  await assert.rejects(runtime.createProxyJob({connectionId: 'notion-a', request: {method: 'POST', path: '/v1/oauth/introspect', body: {token: 'x'}}}, OWNER),
    error => ['policy_denied', 'provider_access_missing'].includes(error.code));
  assert.deepEqual([store.list('jobs').length, calls.length], [0, 0]);
});

/** Every source file a server, agent protocol, developer route or command loads, under lib/ and at the top. */
function sources() {
  const walk = folder => readdirSync(path.join(ROOT, folder), {withFileTypes: true}).flatMap(entry => entry.isDirectory() ? walk(`${folder}/${entry.name}`)
    : /\.(mjs|mts|js)$/.test(entry.name) ? [`${folder}/${entry.name}`] : []);
  return [...walk('lib'), ...walk('public'), 'server.mjs', 'developer-server.mjs', 'cli.mjs', 'mcp.mts'];
}
// F10.19 part 2 listed churn: the live guard reads INTROSPECTION's address to pass it as sign-in traffic (lib/live-guard.mjs), and the
// live-test command (scripts/, outside this scan) calls introspect() once before N0; neither is a route, an agent protocol or a tenant handler.
test('a source scan finds no route, agent protocol or tenant handler that calls introspect(): only lib/providers/oauth2.mjs calls it, and only the live guard reads its address', () => {
  const text = file => readFileSync(path.join(ROOT, file), 'utf8');
  assert.deepEqual(sources().filter(file => /\bintrospect\s*\(/.test(text(file))), ['lib/providers/oauth2.mjs']);
  assert.deepEqual(sources().filter(file => /\bINTROSPECTION\b/.test(text(file))), ['lib/live-guard.mjs', 'lib/providers/oauth2.mjs']);
  const reached = new Set(['server.mjs', 'developer-server.mjs', 'mcp.mts', 'cli.mjs']);
  for (const file of reached) assert.ok(!/live-guard|live-certify/.test(text(file)), `${file} loads no live-test module`);
});

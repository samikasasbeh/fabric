import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomUUID} from 'node:crypto';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';
import {createDeveloperApp} from '../developer-server.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';

// F10.4 (T7, correction 7 of docs/F10.4-BUILD-MAP.md): a token refresh never widens what the owner approved, in every
// store, not only designated ones. Scopes outside the ceiling (grantCeiling, or the scopes a record from before ceilings
// holds) are never delivered and the account needs a sign-in; a narrower grant narrows the account, which stays usable.
const READ = ['openid', 'email', 'https://www.googleapis.com/auth/calendar.calendarlist.readonly', 'https://www.googleapis.com/auth/calendar.events.readonly'];
const WIDER = [...READ, 'https://www.googleapis.com/auth/calendar.events'];
const tokenResponse = (extra = {}) => ({status: 200, data: {access_token: 'fixture-access', refresh_token: 'fixture-refresh', token_type: 'Bearer', expires_in: 3600, scope: READ.join(' '), ...extra}});

/** F10.7: the single-owner engine on the version 1 Google definition of test/fixtures/auth-v1 (T6 through the fixtures), whose Calendar
 *  read level READ is; the shipped catalog is version 2. */
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'fabric-refresh-wall-'));
  const store = new Store({dataDir: dir, localAuthority: 'new'}), vault = new Vault(dir);
  const state = {now: Date.parse('2026-10-11T00:00:00Z'), tokenHook: null};
  const request = async req => {
    if (req.url.endsWith('/token')) return state.tokenHook ? state.tokenHook(req) : tokenResponse();
    if (req.url.endsWith('/userinfo')) return {status: 200, data: {sub: 'fixture-account', email: 'fixture@example.test'}};
    if (req.url.includes('/calendar/v3/')) return {status: 200, data: {kind: 'calendar#calendarList'}};
    throw new Error('Unexpected synthetic request');
  };
  const connections = new ConnectionManager({store, vault, request, clock: () => state.now});
  const oauth = new OAuth2Provider(v1Definition('google'), {store, vault, connections, request, clientId: 'fixture-client', clientSecret: 'fixture-client-secret', clock: () => state.now});
  connections.setOAuthProvider(oauth);
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  const connect = async () => { const flow = oauth.start(); return oauth.callback({state: new URL(flow.authorizationUrl).searchParams.get('state'), code: 'fixture-code', flowId: flow.flowId}); };
  return {store, vault, state, connections, oauth, connect, expire: () => { state.now += 3600 * 1000; }};
}

test('a refresh that comes back wider than the ceiling is never delivered; the account needs a sign-in and stays that way', async t => {
  const f = fixture(t), {id} = await f.connect(), before = f.store.get('connections', id), tokens = f.vault.get(id);
  f.expire(); f.state.tokenHook = async () => tokenResponse({access_token: 'wider-access', scope: WIDER.join(' ')});
  await assert.rejects(f.connections.credentials(id), {code: 'reconnect_required'});
  const after = f.store.get('connections', id);
  assert.equal(after.status, 'reconnect_required'); assert.match(after.error, /more access/);
  assert.deepEqual(after.scopes, before.scopes, 'the wider scopes are not recorded either');
  assert.equal(f.store.connectionGeneration(id), 1); assert.deepEqual(f.vault.get(id), tokens);
  assert.equal((await f.connections.check(id)).status, 'reconnect_required', 'a check refreshes again and meets the same wall');
  assert.deepEqual(f.vault.get(id), tokens);
});

test('a rotated credential that comes back wider is kept undeliverable: no check revives it', async t => {
  const f = fixture(t), {id} = await f.connect();
  f.expire(); f.state.tokenHook = async () => tokenResponse({access_token: 'wider-access', refresh_token: 'rotated-refresh', scope: WIDER.join(' ')});
  await assert.rejects(f.connections.credentials(id), {code: 'reconnect_required'});
  // The provider invalidated the old refresh credential, so the new pair is kept, but only as pending.
  assert.equal(f.vault.get(id).identityPending, true);
  f.state.tokenHook = null;
  assert.equal((await f.connections.check(id)).status, 'reconnect_required');
  await assert.rejects(f.connections.credentials(id), {code: 'reconnect_required'});
  assert.equal(f.vault.get(id).identityPending, true);
});

test('a narrower refresh narrows the account without marking it, and the scopes coming back within the ceiling are accepted', async t => {
  const f = fixture(t), {id} = await f.connect(), ceiling = f.store.get('connections', id).grantCeiling;
  // F10.5: what a sign-in asked for and did not get (a version 2 sign-in stores it) belongs to that sign-in; a refresh keeps it.
  const grant = {level: 'full', missing: [WIDER.at(-1)]};
  f.store.put('connections', {...f.store.get('connections', id), grant});
  f.expire(); f.state.tokenHook = async () => tokenResponse({access_token: 'narrower-access', scope: READ.slice(0, -1).join(' ')});
  await assert.rejects(f.connections.credentials(id), {code: 'connection_changed'});
  let record = f.store.get('connections', id);
  assert.deepEqual([record.status, record.scopes, record.grantCeiling, record.grant], ['ready', READ.slice(0, -1), ceiling, grant]);
  assert.equal((await f.connections.credentials(id)).headers.Authorization, 'Bearer narrower-access');
  f.expire(); f.state.tokenHook = async () => tokenResponse({access_token: 'restored-access', scope: READ.join(' ')});
  await assert.rejects(f.connections.credentials(id), {code: 'connection_changed'});
  record = f.store.get('connections', id);
  assert.deepEqual([record.status, record.scopes], ['ready', READ]);
  assert.equal((await f.connections.credentials(id)).headers.Authorization, 'Bearer restored-access');
});

test('in a developer environment, a refresh that returns an extra scope marks the account and delivers nothing', async t => {
  const root = mkdtempSync(join(tmpdir(), 'fabric-refresh-wall-dev-'));
  const sim = {grant: '', refreshGrant: null};
  const request = async req => {
    if (req.url === 'https://oauth2.googleapis.com/token') {
      const refreshing = new URLSearchParams(req.body).get('grant_type') === 'refresh_token';
      return {status: 200, headers: {}, data: {access_token: `ya29.${randomUUID()}`, refresh_token: '1//refresh', token_type: 'Bearer', expires_in: 3600, scope: refreshing && sim.refreshGrant !== null ? sim.refreshGrant : sim.grant}};
    }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') return {status: 200, headers: {}, data: {sub: 'person-1', email: 'one@example.com', name: 'One'}};
    if (req.url.startsWith('https://gmail.googleapis.com/')) return {status: 200, headers: {}, data: {emailAddress: 'one@example.com'}};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: {google: {clientId: 'g-shared', clientSecret: 'g-shared-secret'}}, request});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const created = await (await fetch(`${app.origin}/v1/connect-sessions`, {method: 'POST', headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify({externalUserId: 'u1', appId: 'gmail'})})).json();
  const binding = `browser-${created.id}`;
  app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
  const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl), definition = definitionFor(started.providerId);
  sim.grant = url.searchParams.get('scope').split(definition.authorization.scopeSeparator).join(definition.token.scopeSeparator);
  const back = await fetch(`${app.origin}${started.callbackPath}?state=${encodeURIComponent(url.searchParams.get('state'))}&code=c`, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${started.flowId}`}});
  const finish = back.headers.getSetCookie().find(line => line.startsWith('fabric_t_finish=')).split(';')[0].slice('fabric_t_finish='.length);
  const {accountRef} = app.sessions.confirm(created.id, binding, finish).result;
  const env = app.stores.open(scope), before = env.repository.get('connections', accountRef);
  assert.equal(before.status, 'ready');
  env.vault.set(accountRef, {...env.vault.get(accountRef), expiresAt: Date.now() - 1000});
  const tokens = env.vault.get(accountRef);
  sim.refreshGrant = `${sim.grant} https://www.googleapis.com/auth/gmail.send`;
  await assert.rejects(app.runtimes.bundle(scope).connections.credentials(accountRef), {code: 'reconnect_required'});
  const after = env.repository.get('connections', accountRef);
  assert.equal(after.status, 'reconnect_required');
  assert.deepEqual(after.scopes, before.scopes);
  assert.deepEqual(env.vault.get(accountRef), tokens, 'nothing from the wider refresh is kept');
});

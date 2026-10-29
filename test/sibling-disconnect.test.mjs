import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../server.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {FABRIC_PROTOCOL} from '../lib/fabric-protocol.mjs';
import {owner, freePort, fixture as githubFixture} from './fixtures/signin-fixture.mjs';
import {GoogleSimulator} from './fixtures/oauth-simulators.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {endUser, stampOwner, tenantDeployment} from '../lib/tenant/deployment.mjs';
import {describeApp, siblingChoices} from '../public/hosted-app.js';
import {errorOf} from '../public/hosted-base.js';

// F10.4 (B1, B2, T1): Google's revocation removes the whole grant of an account on one sign-in client, so disconnecting
// Gmail at Google also signs the same account out of Calendar. Before anything changes, the disconnect names those
// siblings and asks for a confirm; after a confirmed revoke they need a sign-in (a renewal, which keeps their settings),
// and `remote: false` disconnects here only. No automatic path (a closed account request, a decline, a rejected
// account) ever revokes a Google grant. An isolated designated app against the Google simulator; nothing leaves the process.
const GOOGLE = {FABRIC_GOOGLE_CLIENT_ID: 'sibling-google-client', FABRIC_GOOGLE_CLIENT_SECRET: 'sibling-google-secret'};
const REVOKE = 'https://oauth2.googleapis.com/revoke';
const calendar = {openapi: '3.0.3', info: {title: 'Synthetic Calendar', version: '1'}, servers: [{url: 'https://www.googleapis.com/calendar/v3'}],
  paths: {'/users/me/calendarList': {get: {operationId: 'listCalendars', responses: {200: {description: 'Calendars'}}}}}};

async function fixture(t) {
  const previous = Object.fromEntries(Object.keys(GOOGLE).map(key => [key, process.env[key]]));
  Object.assign(process.env, GOOGLE);
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-sibling-disconnect-')), clock = () => Date.parse('2026-10-11T10:00:00.000Z');
  const sim = new GoogleSimulator({clientId: GOOGLE.FABRIC_GOOGLE_CLIENT_ID, clientSecret: GOOGLE.FABRIC_GOOGLE_CLIENT_SECRET, clock}), hooks = {token: null, revoke: null};
  const request = async req => {
    if (req.url === 'https://oauth2.googleapis.com/token' && hooks.token) { const hook = hooks.token; hooks.token = null; await hook(); }
    if (req.url === REVOKE && hooks.revoke) { const hook = hooks.revoke; hooks.revoke = null; await hook(); }
    if (/^https:\/\/[a-z0-9.]*google(apis)?\.com\//.test(req.url)) return sim.request(req);
    throw new Error('No network in this fixture');
  };
  const app = await createApp({dataDir: dir, port: await freePort(), clock, request, localAuthority: {mode: 'new', ownerPrincipal: owner}});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  const cap = {...compileOpenApi({appId: 'google-calendar', document: calendar}).capabilities[0], status: 'active'};
  app.store.put('capabilities', cap); app.store.put('applicationMaps', {id: 'google-calendar', operations: [{capabilityId: cap.id, requiredScopes: []}]});
  const first = await fetch(`${app.origin}/api/state`), csrf = (await first.json()).csrfToken, session = first.headers.get('set-cookie').split(';')[0];
  const raw = (method, route, data, cookie = '') => fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'content-type': 'application/json', 'x-fabric-csrf': csrf, cookie: [session, cookie].filter(Boolean).join('; ')}, ...(data !== undefined ? {body: JSON.stringify(data)} : {})});
  const call = async (method, route, data) => { const response = await raw(method, route, data); return {status: response.status, body: await response.json()}; };
  const g = {
    app, sim, hooks, call,
    revocations: () => sim.calls.filter(req => req.url === REVOKE).length,
    active: account => [...sim.access.values()].some(entry => entry.account === account),
    record: id => app.store.get('connections', id),
    notices: id => app.store.list('activity').filter(event => event.type === 'connection.health' && event.connectionId === id),
    disconnect: (appId, id, body = {}) => call('POST', `/api/ui/apps/${appId}/accounts/${encodeURIComponent(id)}/disconnect`, body),
    revoke: (id, body = {}) => call('POST', `/api/connections/${encodeURIComponent(id)}/revoke`, body),
    /** An ordinary sign-in: a live, ready account. */
    async connect(appId, account = 'a', options = {}) {
      const flow = app.oauth.start({appId, ...options}), grant = sim.consent(flow.authorizationUrl, {account});
      return app.oauth.callback({state: grant.state, code: grant.code, flowId: flow.flowId});
    },
    /** An account request for Calendar, signed in through the owner's browser: the account waits for the owner's confirm. */
    async request() {
      const {client, token} = app.protocol.createClient({name: 'Agent', bindings: [], requestable: [{capabilityId: cap.id}]}, owner);
      const {result} = await app.protocol.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id: 'ask', method: 'calls.create', params: {appId: 'google-calendar', capabilityId: cap.id, definitionHash: client.requestable[0].definitionHash, args: {}}});
      return result.id;
    },
    async signIn(id, account = 'a') {
      const started = app.continuations.signIn(id, {viewDigest: app.continuations.ownerView(id).viewDigest}, owner), grant = sim.consent(started.authorizationUrl, {account});
      return (await raw('GET', `/api/oauth/google/callback?${new URLSearchParams({state: grant.state, code: grant.code})}`, undefined, `fabric_oauth=${started.flowId}`)).headers.get('location');
    },
    async quarantined(account = 'a') {
      const id = await g.request();
      assert.equal(await g.signIn(id, account), `/continue/${id}`);
      const view = app.continuations.ownerView(id);
      assert.equal(view.status, 'awaiting_confirmation');
      return {id, connectionId: view.pendingConnection.connectionId};
    },
  };
  return g;
}

test('disconnecting Gmail answers confirm_required naming Calendar on both routes; nothing changes and Google is never asked', async t => {
  const g = await fixture(t);
  const mail = await g.connect('gmail'), cal = await g.connect('google-calendar'), generation = g.app.store.connectionGeneration(cal.id);
  for (const answer of [await g.disconnect('gmail', mail.id), await g.revoke(mail.id), await g.revoke(mail.id, {remote: true})]) {
    assert.equal(answer.status, 409); assert.equal(answer.body.code, 'confirm_required');
    assert.deepEqual(answer.body.siblings, [{connectionId: cal.id, appId: 'google-calendar', displayName: 'a@example.com', waiting: false}]);
    assert.match(answer.body.error, /Google Calendar/);
    assert.match(answer.body.error, /other Fabric folders and the 4188 prototype/, 'the store cannot see every app on this sign-in client');
  }
  assert.equal(g.revocations(), 0, 'no provider call');
  assert.equal(g.record(mail.id).status, 'ready'); assert.ok(g.app.vault.get(mail.id)?.accessToken, 'nothing was erased here');
  assert.equal(g.record(cal.id).status, 'ready'); assert.equal(g.app.store.connectionGeneration(cal.id), generation);
  assert.equal(g.active('a'), true);
  // Only the two fields, each true or false, on both routes.
  for (const body of [{confirm: true}, {confirmSiblings: 'yes'}, {remote: 1}]) {
    assert.equal((await g.disconnect('gmail', mail.id, body)).status, 400);
    assert.equal((await g.revoke(mail.id, body)).status, 400);
  }
  assert.equal(g.revocations(), 0); assert.equal(g.record(mail.id).status, 'ready');
});

test('after confirmSiblings, Calendar needs a sign-in, keeps its generation and settings, and has one reconnect notice', async t => {
  const g = await fixture(t);
  const mail = await g.connect('gmail'), cal = await g.connect('google-calendar'), before = g.record(cal.id), generation = g.app.store.connectionGeneration(cal.id);
  const cap = g.app.store.list('capabilities').find(item => item.appId === 'google-calendar');
  g.app.runtime.permissions.set({connectionId: cal.id, capabilityId: cap.id, mode: 'deny'});
  const answer = await g.disconnect('gmail', mail.id, {confirmSiblings: true});
  assert.equal(answer.status, 200); assert.equal(answer.body.remoteRevoked, true); assert.equal(answer.body.account.status, 'revoked');
  assert.deepEqual(answer.body.affected, [{connectionId: cal.id, appId: 'google-calendar'}]);
  assert.match(answer.body.message, /revocation confirmed\. Google also signed a@example\.com out of every other app that uses this Google sign-in client, including other Fabric folders and the 4188 prototype\./);
  assert.equal(g.revocations(), 1); assert.equal(g.active('a'), false, 'Google removed the whole grant');
  const after = g.record(cal.id);
  assert.equal(after.status, 'reconnect_required'); assert.equal(after.error, 'Disconnected together with Gmail.');
  assert.equal(g.app.store.connectionGeneration(cal.id), generation, 'only health fields changed');
  assert.deepEqual([after.authRevision, after.signInRevision], [before.authRevision, before.signInRevision]);
  const notices = g.notices(cal.id);
  assert.deepEqual(notices.map(notice => [notice.kind, notice.signInRevision]), [['reconnect_required', before.signInRevision]]);
  assert.deepEqual(g.notices(mail.id), [], 'the account disconnected on purpose gets no notice');
  // Signing Calendar in again is a renewal: the generation and the saved Never survive.
  await g.connect('google-calendar', 'a', {connectionId: cal.id});
  assert.equal(g.record(cal.id).status, 'ready'); assert.equal(g.app.store.connectionGeneration(cal.id), generation);
  assert.equal(g.app.runtime.permissions.decision(g.record(cal.id), cap).mode, 'deny');
});

test('the connection revoke route confirms siblings the same way and answers what it affected', async t => {
  const g = await fixture(t);
  const mail = await g.connect('gmail'), cal = await g.connect('google-calendar');
  const answer = await g.revoke(cal.id, {confirmSiblings: true});
  assert.equal(answer.status, 200); assert.equal(answer.body.remoteRevoked, true);
  assert.deepEqual(answer.body.affected, [{connectionId: mail.id, appId: 'gmail'}]);
  assert.equal(g.record(cal.id).status, 'revoked');
  assert.deepEqual([g.record(mail.id).status, g.record(mail.id).error], ['reconnect_required', 'Disconnected together with Google Calendar.']);
  assert.equal(g.revocations(), 1);
});

test('a sibling that signs in again while Google revokes is left as its new sign-in wrote it', async t => {
  const g = await fixture(t);
  const mail = await g.connect('gmail'), cal = await g.connect('google-calendar'), before = g.record(cal.id);
  g.hooks.revoke = () => g.connect('google-calendar', 'a', {connectionId: cal.id});
  const answer = await g.disconnect('gmail', mail.id, {confirmSiblings: true});
  assert.equal(answer.status, 200); assert.equal(answer.body.remoteRevoked, true); assert.equal('affected' in answer.body, false);
  const after = g.record(cal.id);
  assert.notEqual(after.signInRevision, before.signInRevision);
  assert.deepEqual([after.status, after.error], ['ready', null], 'a revoke that began before a sign-in never marks it');
  assert.deepEqual(g.notices(cal.id), []);
});

test('in a developer environment, siblings are the same end user\'s accounts on the same provider app only', async t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-tenant-siblings-')), store = new Store({dataDir: dir}), vault = new Vault(dir), calls = [];
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  const request = async req => { calls.push(req.url); if (req.url === REVOKE) return {status: 200, data: {}}; throw new Error('No network in this fixture'); };
  const deployment = tenantDeployment({schemaVersion: 1, kind: 'tenant', organizationId: 'org', projectId: 'project', environmentId: 'environment'});
  const connections = new ConnectionManager({store, vault, request, deployment});
  // A shared-app adapter that would ask Google, as a developer's own app will once its revocation is lifted (F10.4 part g).
  const adapter = new OAuth2Provider(definitionFor('google'), {store, vault, connections, request, clientId: 'tenant-client', clientSecret: 'tenant-secret', consentDays: null});
  connections.setOAuthProvider(adapter);
  const one = endUser({subjectId: 'person-one', userRecordId: `usr_${'a'.repeat(26)}`}), two = endUser({subjectId: 'person-two', userRecordId: `usr_${'b'.repeat(26)}`});
  const put = (id, appId, user, extra = {}) => { store.put('connections', stampOwner({id, appId, providerId: 'google', driver: 'http', authMethod: 'oauth', status: 'ready', identity: {id: 'same-google-account', displayName: 'same@example.com'}, allowedOrigins: [], scopes: [], authRevision: id, createdAt: '2026-10-11T00:00:00.000Z', ...extra}, user)); vault.set(id, {accessToken: `token-${id}`}); };
  put('mail-one', 'gmail', one); put('cal-one', 'google-calendar', one); put('cal-two', 'google-calendar', two);
  put('cal-own-app', 'google-calendar', one, {providerApp: {kind: 'developer', id: `pa_${'c'.repeat(26)}`}});
  assert.deepEqual(adapter.siblings(store.get('connections', 'mail-one'), one).map(item => item.id), ['cal-one']);
  await assert.rejects(adapter.revoke('mail-one', one), error => error.code === 'confirm_required' && JSON.stringify(error.siblings.map(item => item.connectionId)) === '["cal-one"]' && /which Fabric cannot see from here/.test(error.message));
  assert.deepEqual(calls, []);
  const result = await adapter.revoke('mail-one', one, {confirmSiblings: true});
  assert.deepEqual(result.affected, [{connectionId: 'cal-one', appId: 'google-calendar'}]);
  assert.match(result.message, /out of every other app that uses this Google sign-in client, including any that Fabric cannot see from here\./); assert.doesNotMatch(result.message, /4188/);
  assert.deepEqual(['cal-one', 'cal-two', 'cal-own-app'].map(id => store.get('connections', id).status), ['reconnect_required', 'ready', 'ready']);
});

test('the owner\'s app page sends the choice it offers: here only stays local, everywhere confirms the other accounts', async t => {
  const g = await fixture(t);
  const send = async request => { const answer = await g.call('POST', request.path, request.body); if (answer.status >= 400) throw errorOf(answer.body, answer.status); return answer.body; };
  const choose = async id => {
    const model = describeApp((await g.call('GET', `/api/ui/apps/gmail?account=${encodeURIComponent(id)}`)).body), asked = await send(model.disconnect.request).catch(error => error);
    assert.equal(asked.code, 'confirm_required');
    return siblingChoices(model.disconnect, asked);
  };
  const cal = await g.connect('google-calendar'), first = await g.connect('gmail');
  const local = await choose(first.id);
  assert.match(local.text, /Google Calendar/);
  assert.equal((await send(local.hereOnly.request)).remoteRevoked, false);
  assert.deepEqual([g.revocations(), g.record(first.id).status, g.record(cal.id).status], [0, 'revoked', 'ready']);
  const second = await g.connect('gmail'), everywhere = await choose(second.id);
  const done = await send(everywhere.everywhere.request);
  assert.deepEqual([done.remoteRevoked, done.affected], [true, [{connectionId: cal.id, appId: 'google-calendar'}]]);
  assert.deepEqual([g.revocations(), g.record(cal.id).status], [1, 'reconnect_required']);
});

test('remote: false erases here only: no provider request, and Calendar stays ready', async t => {
  const g = await fixture(t);
  const mail = await g.connect('gmail'), cal = await g.connect('google-calendar');
  const answer = await g.disconnect('gmail', mail.id, {remote: false});
  assert.equal(answer.status, 200); assert.equal(answer.body.remoteRevoked, false);
  assert.deepEqual(Object.keys(answer.body).sort(), ['account', 'message', 'remoteRevoked']);
  assert.equal(g.record(mail.id).status, 'revoked'); assert.equal(g.app.vault.get(mail.id), null);
  assert.equal(g.revocations(), 0); assert.equal(g.record(cal.id).status, 'ready');
  assert.equal(g.sim.access.has(g.app.vault.get(cal.id).accessToken), true, 'Calendar still reads');
  const again = await g.revoke(cal.id, {remote: false});
  assert.equal(again.status, 200); assert.equal(again.body.remoteRevoked, false); assert.equal(g.revocations(), 0);
});

test('a different Google account is never a sibling and stays untouched', async t => {
  const g = await fixture(t);
  const mail = await g.connect('gmail', 'a'), cal = await g.connect('google-calendar', 'b');
  const answer = await g.disconnect('gmail', mail.id);
  assert.equal(answer.status, 200); assert.equal(answer.body.remoteRevoked, true); assert.equal('affected' in answer.body, false);
  // No sibling is visible here, but Google still signs the account out of every app on this client: the words say so (map 7.5).
  assert.match(answer.body.message, /Google also signed a@example\.com out of every other app that uses this Google sign-in client, including other Fabric folders and the 4188 prototype\./);
  assert.equal(g.revocations(), 1); assert.equal(g.active('a'), false);
  assert.equal(g.record(cal.id).status, 'ready'); assert.equal(g.active('b'), true);
  assert.equal(g.sim.access.has(g.app.vault.get(cal.id).accessToken), true);
});

test('a GitHub revocation covers only the token, so disconnecting one of two accounts of the same person needs no confirm', async t => {
  const f = await githubFixture(t);
  const start = async () => { const response = await f.owned('POST', '/api/oauth/github/start', {appId: 'github'}); return {body: await response.json(), flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie'))[1]}; };
  for (let i = 0; i < 2; i++) assert.equal((await f.callback(await start(), {account: 'a'})).location, '/?oauth=connected');
  const [one, two] = f.connections();
  assert.equal(one.identity.id, two.identity.id);
  const answer = await f.json('POST', `/api/ui/apps/github/accounts/${one.id}/disconnect`, {});
  assert.equal(answer.status, 200); assert.equal(answer.body.remoteRevoked, true);
  assert.deepEqual(Object.keys(answer.body).sort(), ['account', 'message', 'remoteRevoked']);
  assert.doesNotMatch(answer.body.message, /every other app|4188/, 'a token revoke signs nothing else out');
  assert.equal(f.app.store.get('connections', two.id).status, 'ready');
});

test('a waiting account of the same Google account is listed as waiting, and erased here after a confirmed revoke', async t => {
  const g = await fixture(t);
  const mail = await g.connect('gmail'), {connectionId} = await g.quarantined('a');
  const asked = await g.disconnect('gmail', mail.id);
  assert.equal(asked.status, 409);
  assert.deepEqual(asked.body.siblings, [{connectionId, appId: 'google-calendar', displayName: 'a@example.com', waiting: true}]);
  assert.equal(g.record(connectionId).status, 'pending_confirmation');
  const answer = await g.disconnect('gmail', mail.id, {confirmSiblings: true});
  assert.equal(answer.status, 200); assert.deepEqual(answer.body.affected, [{connectionId, appId: 'google-calendar'}]);
  assert.equal(g.record(connectionId).status, 'revoked'); assert.equal(g.app.vault.get(connectionId), null);
  assert.deepEqual(g.notices(connectionId), [], 'an erased account needs no notice');
});

test('the closed account-request path never asks Google to revoke: shared when another app holds the grant, may_remain otherwise', async t => {
  for (const [live, expected] of [[true, 'shared'], [false, 'may_remain']]) {
    await t.test(expected, async t => {
      const g = await fixture(t);
      const mail = live ? await g.connect('gmail') : null, id = await g.request();
      g.hooks.token = async () => assert.equal((await g.call('POST', `/api/continuations/${id}/decline`, {})).status, 200);
      assert.equal(await g.signIn(id), `/continue/${id}`);
      assert.equal(g.revocations(), 0, 'T1: no automatic revoke of a grant-wide provider');
      assert.deepEqual(g.app.store.list('activity').filter(event => event.type === 'continuation.late_signin_discarded').map(event => event.providerGrant), [expected]);
      assert.equal(g.app.store.get('continuations', id).outcome.providerGrant, expected);
      assert.equal(g.app.store.list('connections').filter(connection => connection.appId === 'google-calendar').length, 0, 'no account was kept');
      if (mail) { assert.equal(g.record(mail.id).status, 'ready'); assert.equal(g.sim.access.has(g.app.vault.get(mail.id).accessToken), true); }
    });
  }
});

test('decline and reject never revoke a Google grant: a live Gmail account of the same person keeps it shared', async t => {
  const g = await fixture(t);
  const mail = await g.connect('gmail');
  const declined = await g.quarantined('a');
  assert.equal((await g.call('POST', `/api/continuations/${declined.id}/decline`, {})).status, 200);
  assert.equal(g.revocations(), 0);
  assert.equal(g.app.store.get('continuations', declined.id).outcome.providerGrant, 'shared', 'another app holds the same grant');
  assert.equal(g.record(declined.connectionId).status, 'revoked'); assert.equal(g.app.vault.get(declined.connectionId), null);
  assert.equal(g.record(mail.id).status, 'ready'); assert.equal(g.sim.access.has(g.app.vault.get(mail.id).accessToken), true);
  const rejected = await g.quarantined('b');
  assert.equal((await g.call('POST', `/api/continuations/${rejected.id}/reject-account`, {})).status, 200);
  assert.equal(g.revocations(), 0, 'a rejected Google account is revoked here only');
  assert.equal(g.record(rejected.connectionId).status, 'revoked'); assert.equal(g.app.vault.get(rejected.connectionId), null);
  assert.equal(g.active('b'), true, 'its grant may remain at Google');
});

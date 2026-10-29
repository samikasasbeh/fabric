import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../server.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {FABRIC_PROTOCOL} from '../lib/fabric-protocol.mjs';
import {owner, ENV, fixture, freePort} from './fixtures/signin-fixture.mjs';
import {GoogleSimulator} from './fixtures/oauth-simulators.mjs';

// F02.3c exits from a signed-in (quarantined) account, and what happens to the provider grant on each:
// owner decline, the shared-grant guard, closing during the token exchange, client exits, an account
// arriving after its handoff moved on, a tampered reject, the one-job guard and a clock stepped back.
// Isolated designated apps on loopback ports against the GitHub and Google simulators only.
const GITHUB_REVOKE = `https://api.github.com/applications/${ENV.FABRIC_GITHUB_CLIENT_ID}/token`;
const githubRevocations = f => f.sim.calls.filter(req => req.method === 'DELETE' && req.url === GITHUB_REVOKE);
const audits = (app, type) => app.store.list('activity').filter(event => event.type === type);
const readyA = f => ({id: 'ready-a', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'consent', status: 'ready', label: 'Ready', identity: {id: '101', displayName: 'octo-a'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date(f.now).toISOString()});

/** A handoff whose sign-in finished: the account is quarantined and awaits the owner's confirmation. */
async function quarantined(f, account = 'a') {
  const asked = await f.ask();
  await f.callback(await f.signIn(asked.id), {account});
  const view = await f.view(asked.id);
  assert.equal(view.status, 'awaiting_confirmation');
  return {...asked, view, connectionId: view.pendingConnection.connectionId};
}
/** An ordinary (non-handoff) GitHub sign-in: a live, ready account holding a real simulator token. */
async function liveGitHub(f, account) {
  const response = await f.owned('POST', '/api/oauth/github/start', {appId: 'github'});
  const started = {body: await response.json(), flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie'))[1]};
  assert.equal((await f.callback(started, {account})).location, '/?oauth=connected');
  const [live] = f.connections().filter(connection => connection.status === 'ready' && !connection.origin);
  return {live, token: f.app.vault.get(live.id).accessToken};
}

// Google revocation removes an account's whole grant, which is what the shared-grant guard is for.
const GOOGLE = {FABRIC_GOOGLE_CLIENT_ID: 'exits-google-client', FABRIC_GOOGLE_CLIENT_SECRET: 'exits-google-secret'};
const calendar = {openapi: '3.0.3', info: {title: 'Synthetic Calendar', version: '1'}, servers: [{url: 'https://www.googleapis.com/calendar/v3'}],
  paths: {'/users/me/calendarList': {get: {operationId: 'listCalendars', responses: {200: {description: 'Calendars'}}}}}};
async function google(t) {
  const previous = Object.fromEntries(Object.keys(GOOGLE).map(key => [key, process.env[key]]));
  Object.assign(process.env, GOOGLE);
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-signin-exits-')), clock = () => Date.parse('2026-10-11T10:00:00.000Z');
  const sim = new GoogleSimulator({clientId: GOOGLE.FABRIC_GOOGLE_CLIENT_ID, clientSecret: GOOGLE.FABRIC_GOOGLE_CLIENT_SECRET, clock});
  const request = async req => { if (/^https:\/\/[a-z0-9.]*google(apis)?\.com\//.test(req.url)) return sim.request(req); throw new Error('No network in this fixture'); };
  const app = await createApp({dataDir: dir, port: await freePort(), clock, request, localAuthority: {mode: 'new', ownerPrincipal: owner}});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  const cap = {...compileOpenApi({appId: 'google-calendar', document: calendar}).capabilities[0], status: 'active'};
  app.store.put('capabilities', cap); app.store.put('applicationMaps', {id: 'google-calendar', operations: [{capabilityId: cap.id, requiredScopes: []}]});
  const first = await fetch(`${app.origin}/api/state`), csrf = (await first.json()).csrfToken, session = first.headers.get('set-cookie').split(';')[0];
  const call = (method, route, data, cookie = '') => fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'content-type': 'application/json', 'x-fabric-csrf': csrf, cookie: [session, cookie].filter(Boolean).join('; ')}, ...(data !== undefined ? {body: JSON.stringify(data)} : {})});
  const consent = async ({authorizationUrl, flowId}, account) => {
    const grant = sim.consent(authorizationUrl, {account});
    return (await call('GET', `/api/oauth/google/callback?${new URLSearchParams({state: grant.state, code: grant.code})}`, undefined, `fabric_oauth=${flowId}`)).headers.get('location');
  };
  const g = {
    app, sim, call,
    revocations: () => sim.calls.filter(req => req.url === 'https://oauth2.googleapis.com/revoke').length,
    active: account => [...sim.access.values()].some(entry => entry.account === account),
    async live(account) {
      const response = await call('POST', '/api/oauth/google/start', {appId: 'google-calendar'});
      assert.equal(await consent({authorizationUrl: (await response.json()).authorizationUrl, flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie'))[1]}, account), '/?oauth=connected');
      return app.store.list('connections').find(connection => connection.status === 'ready');
    },
    async quarantined(account) {
      const {client, token} = app.protocol.createClient({name: 'Agent', bindings: [], requestable: [{capabilityId: cap.id}]}, owner);
      const {result} = await app.protocol.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id: 'ask', method: 'calls.create', params: {appId: 'google-calendar', capabilityId: cap.id, definitionHash: client.requestable[0].definitionHash, args: {}}});
      const started = app.continuations.signIn(result.id, {viewDigest: app.continuations.ownerView(result.id).viewDigest}, owner);
      assert.equal(await consent(started, account), `/continue/${result.id}`);
      const view = app.continuations.ownerView(result.id);
      assert.equal(view.status, 'awaiting_confirmation');
      return {id: result.id, connectionId: view.pendingConnection.connectionId, duplicateOf: view.pendingConnection.duplicateOf};
    },
  };
  return g;
}

/** Closes the handoff while the provider is issuing tokens, then checks that nothing of the sign-in survives. */
async function closeDuringExchange(t, close, {liveAccount = null} = {}) {
  const f = await fixture(t);
  const live = liveAccount ? await liveGitHub(f, liveAccount) : null;
  const {token, id} = await f.ask(), started = await f.signIn(id), existing = f.connections();
  const issued = [], written = [];
  const issue = f.sim.issue.bind(f.sim), set = f.app.vault.set.bind(f.app.vault);
  f.sim.issue = (...args) => { const tokens = issue(...args); issued.push(tokens.accessToken); return tokens; };
  f.app.vault.set = (key, value) => { written.push(key); return set(key, value); };
  let release;
  f.hooks.token = () => new Promise(resolve => { release = resolve; f.hooks.token = null; });
  const back = f.callback(started);
  while (!release) await new Promise(resolve => setTimeout(resolve, 5));
  await close(f, {token, id});
  release();
  assert.equal((await back).location, `/continue/${id}`);
  assert.deepEqual(f.connections(), existing, 'beforePersist refused the closed handoff: no connection');
  assert.deepEqual(written, [], 'no credential reached the vault');
  assert.equal(issued.length, 1, 'the provider issued exactly one token');
  const revoked = githubRevocations(f);
  assert.equal(revoked.length, 1, 'the dropped token was revoked at the provider');
  assert.equal(JSON.parse(revoked[0].body).access_token, issued[0]);
  assert.equal(f.sim.access.has(issued[0]), false, 'the provider no longer accepts the issued token');
  assert.deepEqual(audits(f.app, 'continuation.late_signin_discarded').map(({continuationId, providerGrant}) => ({continuationId, providerGrant})), [{continuationId: id, providerGrant: 'revoked'}]);
  return {f, id, live};
}

/** A client-side exit revokes the quarantined account locally only and says the provider grant may remain. */
function assertRevokedLocally(f, id, connectionId, code) {
  assert.equal(f.app.store.get('connections', connectionId).status, 'revoked');
  assert.equal(f.app.vault.get(connectionId), null, 'the credential is gone');
  const record = f.app.store.get('continuations', id);
  assert.equal(record.status, 'cancelled'); assert.equal(record.outcome.code, code);
  assert.equal(record.outcome.connectionDisposition, 'revoked'); assert.equal(record.outcome.providerGrantMayRemain, true);
  assert.deepEqual(audits(f.app, 'connection.quarantine_revoked').map(event => event.connectionId), [connectionId]);
  assert.equal(githubRevocations(f).length, 0, 'a client exit revokes locally only');
}

test('an owner decline at awaiting_confirmation revokes the quarantined account at the provider', async t => {
  const f = await fixture(t);
  const {id, connectionId} = await quarantined(f);
  const {accessToken} = f.app.vault.get(connectionId);
  assert.equal(f.sim.access.has(accessToken), true);
  const declined = await f.json('POST', `/api/continuations/${id}/decline`, {});
  assert.equal(declined.status, 200); assert.equal(declined.body.status, 'declined');
  const revoked = githubRevocations(f);
  assert.equal(revoked.length, 1, 'exactly one provider revocation');
  assert.equal(JSON.parse(revoked[0].body).access_token, accessToken);
  assert.equal(f.sim.access.has(accessToken), false, 'the provider no longer accepts the token');
  assert.equal(f.app.vault.get(connectionId), null);
  assert.equal(f.app.store.get('connections', connectionId).status, 'revoked');
  const {outcome} = f.app.store.get('continuations', id);
  assert.equal(outcome.code, 'owner_declined'); assert.equal(outcome.connectionDisposition, 'revoked');
  assert.equal(outcome.providerGrant, 'revoked'); assert.equal(outcome.providerGrantMayRemain, false);
  assert.deepEqual(declined.body.outcome, outcome, 'the owner sees the recorded outcome');
});

test('a declined Google account that shares its grant with a live connection is revoked locally only', async t => {
  const g = await google(t);
  const live = await g.live('a');
  const {id, connectionId, duplicateOf} = await g.quarantined('a');
  assert.equal(duplicateOf, live.id);
  const declined = await g.call('POST', `/api/continuations/${id}/decline`, {});
  assert.equal(declined.status, 200);
  assert.equal(g.revocations(), 0, 'revoking the grant would cut off the live connection');
  assert.equal(g.app.store.get('connections', connectionId).status, 'revoked'); assert.equal(g.app.vault.get(connectionId), null);
  const {outcome} = g.app.store.get('continuations', id);
  assert.equal(outcome.providerGrant, 'shared'); assert.equal(outcome.connectionDisposition, 'revoked');
  assert.equal(g.app.store.get('connections', live.id).status, 'ready');
  assert.equal(g.sim.access.has(g.app.vault.get(live.id).accessToken), true, 'the live connection keeps its provider grant');
});

test('a declined Google account is revoked here only, even with no other connection of it: the provider grant may remain (T1)', async t => {
  const g = await google(t);
  const live = await g.live('b');
  const {id, connectionId, duplicateOf} = await g.quarantined('a');
  assert.equal(duplicateOf, null);
  assert.equal((await g.call('POST', `/api/continuations/${id}/decline`, {})).status, 200);
  assert.equal(g.revocations(), 0, 'Google revokes the whole grant, so Fabric never asks automatically');
  assert.equal(g.active('a'), true, 'the declined account\'s grant may remain at Google');
  assert.equal(g.app.store.get('connections', connectionId).status, 'revoked'); assert.equal(g.app.vault.get(connectionId), null);
  const {outcome} = g.app.store.get('continuations', id);
  assert.equal(outcome.providerGrant, 'may_remain'); assert.equal(outcome.providerGrantMayRemain, true);
  assert.equal(g.app.store.get('connections', live.id).status, 'ready'); assert.equal(g.sim.access.has(g.app.vault.get(live.id).accessToken), true);
});

test('a GitHub revocation covers only the presented token, so a duplicate account is still revoked at the provider', async t => {
  const f = await fixture(t);
  const {live, token} = await liveGitHub(f, 'a');
  const {id, view, connectionId} = await quarantined(f, 'a');
  assert.equal(view.pendingConnection.duplicateOf, live.id);
  const {accessToken} = f.app.vault.get(connectionId);
  assert.equal((await f.json('POST', `/api/continuations/${id}/decline`, {})).status, 200);
  assert.deepEqual(githubRevocations(f).map(req => JSON.parse(req.body).access_token), [accessToken], 'only the quarantined token was revoked');
  assert.equal(f.app.store.get('continuations', id).outcome.providerGrant, 'revoked');
  assert.equal(f.app.store.get('connections', live.id).status, 'ready'); assert.equal(f.sim.access.has(token), true);
});

test('a decline during the token exchange revokes the issued token and keeps no account', async t => {
  const {f, id} = await closeDuringExchange(t, async (f, {id}) => assert.equal((await f.json('POST', `/api/continuations/${id}/decline`, {})).status, 200));
  assert.equal(f.app.store.get('continuations', id).status, 'declined');
});

test('a token dropped after a decline is revoked even when a live connection of the same GitHub account exists', async t => {
  const {f, live} = await closeDuringExchange(t, async (f, {id}) => assert.equal((await f.json('POST', `/api/continuations/${id}/decline`, {})).status, 200), {liveAccount: 'a'});
  assert.equal(f.app.store.get('connections', live.live.id).status, 'ready');
  assert.equal(f.sim.access.has(live.token), true, 'revoking one GitHub token leaves the live one working');
});

test('a client cancel during the token exchange revokes the issued token and keeps no account', async t => {
  const {f, id} = await closeDuringExchange(t, async (f, {token, id}) => assert.equal((await f.protocol(token, 'calls.cancel', {callId: id})).result.status, 'cancelled'));
  assert.equal(f.app.store.get('continuations', id).outcome.code, 'client_cancelled');
});

test('a client cancel at awaiting_confirmation revokes the quarantined account locally', async t => {
  const f = await fixture(t);
  const {token, id, connectionId} = await quarantined(f);
  const cancelled = await f.protocol(token, 'calls.cancel', {callId: id});
  assert.equal(cancelled.result.status, 'cancelled'); assert.equal(cancelled.result.handoff.outcome, 'client_cancelled');
  assertRevokedLocally(f, id, connectionId, 'client_cancelled');
});

test('the owner revoking the client at awaiting_confirmation revokes the quarantined account locally', async t => {
  const f = await fixture(t);
  const {id, connectionId} = await quarantined(f);
  const revoked = await f.json('POST', `/api/clients/${f.app.store.get('continuations', id).clientId}/revoke`, {});
  assert.equal(revoked.status, 200); assert.equal(revoked.body.status, 'revoked');
  assertRevokedLocally(f, id, connectionId, 'client_revoked');
});

test('an account that arrives after its handoff moved on is revoked and audited', async t => {
  const f = await fixture(t);
  f.app.store.put('connections', readyA(f)); f.app.vault.set('ready-a', {accessToken: 'synthetic-only-token'});
  const {id} = await f.ask(), started = await f.signIn(id);
  // The owner picks the existing account after the sign-in persisted its account, before the handoff recorded it.
  const establish = f.app.connections.establishOAuth.bind(f.app.connections);
  let selected;
  f.app.connections.establishOAuth = async input => {
    const connection = await establish(input);
    selected = await f.json('POST', `/api/continuations/${id}/select`, {connectionId: 'ready-a', viewDigest: (await f.view(id)).viewDigest});
    return connection;
  };
  const back = await f.callback(started, {account: 'b'});
  assert.equal(back.location, `/continue/${id}`);
  assert.equal(selected.status, 200); assert.equal(selected.body.status, 'resumed');
  await f.app.continuations.settled(id);
  const [arrived] = f.connections().filter(connection => connection.origin?.continuationId === id);
  assert.equal(arrived.identity.id, '202');
  assert.equal(arrived.status, 'revoked', 'the late account is not left behind'); assert.equal(f.app.vault.get(arrived.id), null);
  assert.deepEqual(audits(f.app, 'connection.quarantine_revoked').map(({connectionId, continuationId}) => ({connectionId, continuationId})), [{connectionId: arrived.id, continuationId: id}]);
  const record = f.app.store.get('continuations', id);
  assert.equal(record.status, 'resumed'); assert.equal(record.binding.connectionId, 'ready-a'); assert.equal(record.pendingConnection, null);
  assert.deepEqual(f.app.store.list('jobs').map(job => job.connectionId), ['ready-a']);
});

test('reject-account revokes only this handoff\'s quarantined account, never a ready one it is pointed at', async t => {
  const f = await fixture(t);
  const {live, token} = await liveGitHub(f, 'a');
  const {id} = await quarantined(f, 'b');
  const record = f.app.store.get('continuations', id);
  f.app.store.put('continuations', {...record, pendingConnection: {...record.pendingConnection, connectionId: live.id}});
  const rejected = await f.json('POST', `/api/continuations/${id}/reject-account`, {});
  assert.equal(rejected.status, 409); assert.equal(rejected.body.code, 'authority_changed');
  const closed = f.app.store.get('continuations', id);
  assert.equal(closed.status, 'failed'); assert.equal(closed.outcome.code, 'authority_changed');
  assert.equal(f.app.store.get('connections', live.id).status, 'ready');
  assert.equal(f.app.vault.get(live.id).accessToken, token);
  assert.equal(githubRevocations(f).length, 0, 'nothing was revoked at the provider');
  assert.equal(f.sim.access.has(token), true);
});

test('confirm is refused when a job already names the handoff, and no second job is created', async t => {
  const f = await fixture(t);
  const {id, view, connectionId} = await quarantined(f);
  const before = {record: f.app.store.get('continuations', id), connection: f.app.store.get('connections', connectionId)};
  const first = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: view.confirmDigest});
  assert.equal(first.body.status, 'resumed');
  await f.app.continuations.settled(id);
  // Roll the handoff and its account back to the moment before confirmation; the job it produced remains.
  f.app.store.put('continuations', before.record); f.app.store.put('connections', before.connection);
  assert.equal((await f.view(id)).confirmDigest, view.confirmDigest);
  const again = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: view.confirmDigest});
  assert.equal(again.status, 409); assert.equal(again.body.code, 'authority_changed');
  assert.equal(f.app.store.get('continuations', id).outcome.code, 'fabric_failed', 'closed by the one-job guard');
  assert.deepEqual(f.app.store.list('jobs').map(job => job.id), [first.body.derived.jobId]);
  assert.equal(f.api.length, 1, 'the operation ran once');
});

test('selecting an existing account while the clock is behind answers clock_behind and succeeds once it recovers', async t => {
  const f = await fixture(t);
  f.app.store.put('connections', readyA(f)); f.app.vault.set('ready-a', {accessToken: 'synthetic-only-token'});
  const {id} = await f.ask();
  const body = {connectionId: 'ready-a', viewDigest: (await f.view(id)).viewDigest}, record = f.app.store.get('continuations', id);
  f.advance(-5 * 60_000);
  const behind = await f.json('POST', `/api/continuations/${id}/select`, body);
  assert.equal(behind.status, 409); assert.equal(behind.body.code, 'clock_behind');
  assert.deepEqual(f.app.store.get('continuations', id), record, 'the handoff was not changed');
  assert.deepEqual(f.app.store.list('jobs'), []);
  f.advance(5 * 60_000);
  const selected = await f.json('POST', `/api/continuations/${id}/select`, body);
  assert.equal(selected.status, 200); assert.equal(selected.body.status, 'resumed');
  await f.app.continuations.settled(id);
  assert.equal(f.api.length, 1);
});

test('confirming while the clock is behind answers clock_behind and succeeds once it recovers', async t => {
  const f = await fixture(t);
  const {id, view, connectionId} = await quarantined(f);
  const record = f.app.store.get('continuations', id);
  f.advance(-5 * 60_000);
  const behind = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: view.confirmDigest});
  assert.equal(behind.status, 409); assert.equal(behind.body.code, 'clock_behind');
  assert.deepEqual(f.app.store.get('continuations', id), record, 'the handoff was not changed');
  assert.equal(f.app.store.get('connections', connectionId).status, 'pending_confirmation');
  assert.deepEqual(f.app.store.list('jobs'), []);
  f.advance(5 * 60_000);
  const confirmed = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: view.confirmDigest});
  assert.equal(confirmed.status, 200); assert.equal(confirmed.body.status, 'resumed');
  await f.app.continuations.settled(id);
  assert.equal(f.app.store.get('connections', connectionId).status, 'ready'); assert.equal(f.api.length, 1);
});

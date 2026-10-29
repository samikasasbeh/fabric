import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createApp} from '../server.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {owner, freePort, fixture as accountRequestFixture} from './fixtures/signin-fixture.mjs';
import {GoogleSimulator} from './fixtures/oauth-simulators.mjs';
import {CONTINUATIONS} from '../lib/continuations.mjs';

// F10.4 (T7, critique test 12): a renewal is the same account signing in again within the widest set the owner approved
// (grantCeiling). It keeps the authorization, saved settings, client grants and the connection generation, and writes a
// fresh sign-in revision. Anything wider is an upgrade: a new authorization, so saved Allows become Ask and Never stays
// Never. An isolated designated app against the Google simulator; nothing leaves the process.
const GOOGLE = {FABRIC_GOOGLE_CLIENT_ID: 'renewal-google-client', FABRIC_GOOGLE_CLIENT_SECRET: 'renewal-google-secret'};
// F10.7: Gmail signs in with version 2. A first sign-in here asks for the read level (gmail.readonly, the scopes these cases were
// written for), and Add access adds gmail.modify, the full level's scope.
const READONLY = 'https://www.googleapis.com/auth/gmail.readonly', ADDED = 'https://www.googleapis.com/auth/gmail.modify', COMPOSE = 'https://www.googleapis.com/auth/gmail.compose';
const SIGNED_IN = ['email', READONLY, 'openid'];
const gmail = {openapi: '3.0.3', info: {title: 'Synthetic Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com/gmail/v1'}], paths: {
  '/users/me/messages': {post: {operationId: 'insertMessage', requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}, required: ['raw']}}}}, responses: {200: {description: 'Imported'}}}},
  '/users/me/threads': {get: {operationId: 'listThreads', responses: {200: {description: 'Threads'}}}},
  '/users/me/drafts': {get: {operationId: 'listDrafts', responses: {200: {description: 'Drafts'}}}}}};

async function fixture(t) {
  const previous = Object.fromEntries(Object.keys(GOOGLE).map(key => [key, process.env[key]]));
  Object.assign(process.env, GOOGLE);
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-renewal-upgrade-'));
  let now = Date.parse('2026-10-11T10:00:00.000Z');
  const clock = () => now;
  const sim = new GoogleSimulator({clientId: GOOGLE.FABRIC_GOOGLE_CLIENT_ID, clientSecret: GOOGLE.FABRIC_GOOGLE_CLIENT_SECRET, clock});
  const request = async req => { if (/^https:\/\/[a-z0-9.]*google(apis)?\.com\//.test(req.url)) return sim.request(req); throw new Error('No network in this fixture'); };
  const app = await createApp({dataDir: dir, port: await freePort(), clock, request, localAuthority: {mode: 'new', ownerPrincipal: owner}});
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  const caps = Object.fromEntries(compileOpenApi({appId: 'gmail', document: gmail}).capabilities.map(cap => [cap.name, {...cap, status: 'active'}]));
  for (const cap of Object.values(caps)) app.store.put('capabilities', cap);
  // Synthetic requirements: insert (in "Import emails", a row whose default is Ask) and threads need the access a sign-in grants, drafts the
  // scope Add access asks for. F10.15 listed churn: the write is messages.insert, since Gmail's typed messages.import is unsupported.
  app.store.put('applicationMaps', {id: 'gmail', operations: [{capabilityId: caps.insertMessage.id, id: 'gmail.users.messages.insert', requiredScopes: [READONLY]}, {capabilityId: caps.listThreads.id, requiredScopes: [READONLY]}, {capabilityId: caps.listDrafts.id, requiredScopes: [ADDED]}]});
  const f = {
    app, sim, caps,
    advance(ms) { now += ms; },
    get now() { return now; },
    record: id => app.store.get('connections', id),
    generation: id => app.store.connectionGeneration(id),
    decision: (id, name) => app.runtime.permissions.decision(app.store.get('connections', id), caps[name]),
    audits: id => app.store.list('activity').filter(event => event.connectionId === id && /^connection\.(connected|reconsented|upgraded|renewed)$/.test(event.type)).map(event => event.type),
    /** Start, consent at the simulator, come back: the whole local sign-in. */
    async signIn(options = {}, account = 'a') {
      const flow = app.oauth.start({appId: 'gmail', ...(options.connectionId ? {} : {level: 'read'}), ...options}), grant = sim.consent(flow.authorizationUrl, {account});
      return app.oauth.callback({state: grant.state, code: grant.code, flowId: flow.flowId});
    },
    /** A sign-in whose grant is exactly `scopes`, through establishOAuth directly (for version 1 the local callback refuses a grant narrower than asked). */
    async direct(connectionId, scopes, account = 'a') {
      const issued = sim.issue(account, scopes, {refreshable: true});
      return app.connections.establishOAuth({connectionId, appId: 'gmail', tokens: {...issued, expiresAt: now + 3599 * 1000, scopes}});
    },
    /** One saved Allow (a write whose default is Ask), one saved Never (a read) and a client grant on the Allow. */
    settle(id) {
      app.runtime.permissions.set({connectionId: id, capabilityId: caps.insertMessage.id, mode: 'allow'});
      app.runtime.permissions.set({connectionId: id, capabilityId: caps.listThreads.id, mode: 'deny'});
      return app.protocol.createClient({name: 'Agent', expiresInSeconds: 30 * 86400, bindings: [{connectionId: id, capabilityId: caps.insertMessage.id}]}, owner).client;
    },
  };
  return f;
}
const grantHolds = (f, client, id) => f.app.protocol.assertBinding(client.id, id, f.caps.insertMessage.id).decision.executable;
const grantChanged = (f, client, id) => assert.throws(() => f.app.protocol.assertBinding(client.id, id, f.caps.insertMessage.id), {code: 'grant_changed'});
const settings = (f, id) => ({allowed: [f.decision(id, 'insertMessage').mode, f.decision(id, 'insertMessage').policySource], never: f.decision(id, 'listThreads').mode});

test('a first sign-in records the ceiling it granted and its sign-in; a renewal keeps a saved Allow, a Never, a client grant and the generation', async t => {
  const f = await fixture(t), {id} = await f.signIn(), first = f.record(id);
  assert.deepEqual(first.grantCeiling, SIGNED_IN);
  assert.match(first.signInRevision, /^[0-9a-f-]{36}$/); assert.equal(first.signedInAt, new Date(f.now).toISOString());
  const client = f.settle(id), generation = f.generation(id);
  f.advance(7 * 24 * 3600 * 1000);
  const renewed = await f.signIn({connectionId: id});
  assert.equal(renewed.status, 'ready');
  const record = f.record(id);
  assert.equal(f.generation(id), generation, 'the connection generation is compared directly');
  assert.equal(record.authRevision, first.authRevision);
  assert.notEqual(record.signInRevision, first.signInRevision); assert.match(record.signInRevision, /^[0-9a-f-]{36}$/);
  assert.equal(record.signedInAt, new Date(f.now).toISOString());
  assert.deepEqual([record.createdAt, record.grantCeiling, record.identity], [first.createdAt, first.grantCeiling, first.identity]);
  assert.deepEqual(settings(f, id), {allowed: ['allow', 'saved'], never: 'deny'});
  assert.equal(grantHolds(f, client, id), true);
  assert.deepEqual(f.audits(id), ['connection.connected', 'connection.reconsented']);
});

test('an upgrade (Add access outside the ceiling) turns the saved Allow into Ask, keeps Never, widens the ceiling and ends the client grant', async t => {
  const f = await fixture(t), {id} = await f.signIn(), first = f.record(id), client = f.settle(id), generation = f.generation(id);
  assert.equal(f.decision(id, 'listDrafts').providerAccess, 'missing');
  await f.signIn({connectionId: id, scopes: [ADDED]});
  const record = f.record(id);
  assert.notEqual(record.authRevision, first.authRevision); assert.notEqual(record.signInRevision, first.signInRevision);
  assert.deepEqual(record.grantCeiling, [...SIGNED_IN, ADDED].sort());
  assert.ok(f.generation(id) > generation);
  assert.deepEqual(settings(f, id), {allowed: ['ask', 'stale'], never: 'deny'});
  assert.equal(f.decision(id, 'listDrafts').providerAccess, 'granted');
  grantChanged(f, client, id);
  assert.deepEqual(f.audits(id), ['connection.connected', 'connection.upgraded']);
  // The ceiling only grows: an upgrade that drops what an earlier one approved still keeps it within the ceiling.
  await f.direct(id, ['openid', 'email', COMPOSE]);
  assert.deepEqual(f.record(id).grantCeiling, [...SIGNED_IN, ADDED, COMPOSE].sort());
  assert.deepEqual(f.record(id).scopes, ['openid', 'email', COMPOSE]);
  assert.equal(f.audits(id).at(-1), 'connection.upgraded');
});

test('a narrower renewal keeps the authorization but moves the generation; adding the scope back within the ceiling is still a renewal', async t => {
  const f = await fixture(t), {id} = await f.signIn();
  await f.signIn({connectionId: id, scopes: [ADDED]});
  const upgraded = f.record(id), client = f.settle(id), generation = f.generation(id);
  assert.equal(f.decision(id, 'listDrafts').providerAccess, 'granted');
  await f.direct(id, ['openid', 'email', READONLY]);
  const narrower = f.record(id);
  assert.equal(narrower.authRevision, upgraded.authRevision, 'still a renewal');
  assert.deepEqual(narrower.grantCeiling, upgraded.grantCeiling, 'the ceiling never narrows');
  assert.equal(f.generation(id), generation + 1, 'fewer scopes held is the fail-safe direction');
  assert.equal(f.decision(id, 'listDrafts').providerAccess, 'missing', 'the row needs more access');
  assert.deepEqual(settings(f, id), {allowed: ['allow', 'saved'], never: 'deny'});
  grantChanged(f, client, id);
  await f.signIn({connectionId: id, scopes: [ADDED]});
  const back = f.record(id);
  assert.equal(back.authRevision, upgraded.authRevision, 'within the ceiling: a renewal');
  assert.notEqual(back.signInRevision, narrower.signInRevision);
  assert.equal(f.decision(id, 'listDrafts').providerAccess, 'granted');
  assert.deepEqual(settings(f, id), {allowed: ['allow', 'saved'], never: 'deny'});
  assert.deepEqual(f.audits(id), ['connection.connected', 'connection.upgraded', 'connection.reconsented', 'connection.reconsented']);
});

test('a different account is still refused as account_mismatch and changes nothing', async t => {
  const f = await fixture(t), {id} = await f.signIn(), before = f.record(id), tokens = f.app.vault.get(id);
  await assert.rejects(f.signIn({connectionId: id}, 'b'), {code: 'account_mismatch'});
  await assert.rejects(f.direct(id, ['openid', 'email', READONLY], 'b'), {code: 'account_mismatch'});
  assert.deepEqual(f.record(id), before); assert.deepEqual(f.app.vault.get(id), tokens);
});

test('an account activated through an account request renews with its origin and generation unchanged', async t => {
  const f = await fixture(t), {id} = await f.signIn();
  // confirm() promotes an account request's account with a spread, so it keeps the request it came from.
  const origin = {kind: 'continuation', continuationId: randomUUID()};
  f.app.store.put('connections', {...f.record(id), origin});
  const client = f.settle(id), generation = f.generation(id), before = f.record(id);
  await f.signIn({connectionId: id});
  assert.deepEqual(f.record(id).origin, origin);
  assert.equal(f.record(id).authRevision, before.authRevision);
  assert.equal(f.generation(id), generation);
  assert.equal(grantHolds(f, client, id), true);
});

test('an account marked reconnect_required (an expired Testing-mode grant) renews: it is ready again and keeps its settings and grants', async t => {
  const f = await fixture(t), {id} = await f.signIn(), client = f.settle(id), generation = f.generation(id), first = f.record(id);
  f.sim.revokeAccount('a'); f.advance(3600 * 1000);
  await assert.rejects(f.app.connections.credentials(id), {code: 'reconnect_required'});
  assert.equal(f.record(id).status, 'reconnect_required'); assert.equal(f.generation(id), generation);
  await f.signIn({connectionId: id});
  const record = f.record(id);
  assert.deepEqual([record.status, record.error, record.authRevision], ['ready', null, first.authRevision]);
  assert.equal(f.generation(id), generation);
  assert.deepEqual(settings(f, id), {allowed: ['allow', 'saved'], never: 'deny'});
  assert.equal(grantHolds(f, client, id), true);
});

test('a legacy record without a ceiling renews against the scopes it holds and is not backfilled; anything wider is an upgrade', async t => {
  const f = await fixture(t), {id} = await f.signIn();
  const {grantCeiling, signInRevision, signedInAt, ...legacy} = f.record(id);
  void grantCeiling; void signInRevision; void signedInAt;
  f.app.store.put('connections', legacy);
  const generation = f.generation(id);
  await f.signIn({connectionId: id});
  const renewed = f.record(id);
  assert.equal(renewed.authRevision, legacy.authRevision); assert.equal(Object.hasOwn(renewed, 'grantCeiling'), false);
  assert.equal(f.generation(id), generation);
  await f.signIn({connectionId: id, scopes: [ADDED]});
  const upgraded = f.record(id);
  assert.notEqual(upgraded.authRevision, legacy.authRevision);
  assert.deepEqual(upgraded.grantCeiling, [...SIGNED_IN, ADDED].sort());
  assert.deepEqual(f.audits(id), ['connection.connected', 'connection.reconsented', 'connection.upgraded']);
});

test('a sign-in whose application origins differ from the account\'s is an upgrade', async t => {
  const f = await fixture(t), {id} = await f.signIn();
  f.app.store.put('connections', {...f.record(id), allowedOrigins: ['https://gmail.googleapis.com']});
  const client = f.settle(id), before = f.record(id);
  await f.signIn({connectionId: id});
  const record = f.record(id);
  assert.notEqual(record.authRevision, before.authRevision);
  assert.deepEqual(record.allowedOrigins, ['https://gmail.googleapis.com', 'https://www.googleapis.com']);
  assert.deepEqual(settings(f, id), {allowed: ['ask', 'stale'], never: 'deny'});
  grantChanged(f, client, id);
  assert.equal(f.audits(id).at(-1), 'connection.upgraded');
});

test('a sign-in after a disconnect is a first sign-in: its ceiling starts again from what it grants', async t => {
  const f = await fixture(t), {id} = await f.signIn();
  await f.signIn({connectionId: id, scopes: [ADDED]});
  assert.deepEqual(f.record(id).grantCeiling, [...SIGNED_IN, ADDED].sort());
  f.app.connections.revoke(id);
  const revoked = f.record(id);
  await f.direct(id, ['openid', 'email', READONLY]);
  const again = f.record(id);
  assert.equal(again.status, 'ready');
  assert.notEqual(again.authRevision, revoked.authRevision);
  assert.deepEqual(again.grantCeiling, SIGNED_IN, 'the ceiling resets: what the owner approved before the disconnect is gone');
  assert.equal(f.audits(id).at(-1), 'connection.connected');
  // So adding the scope back is an upgrade, not a renewal.
  await f.signIn({connectionId: id, scopes: [ADDED]});
  assert.notEqual(f.record(id).authRevision, again.authRevision);
  assert.equal(f.audits(id).at(-1), 'connection.upgraded');
});

test('plan() gives the scopes a start records and writes nothing', async t => {
  const f = await fixture(t), {id} = await f.signIn();
  const flows = f.app.store.list('oauthFlows').length, activity = f.app.store.list('activity').length;
  const planned = f.app.oauth.plan({appId: 'gmail', connectionId: id, scopes: [ADDED]});
  assert.deepEqual([planned.appId, planned.level, planned.existing?.id], ['gmail', 'read', id]);
  assert.equal(f.app.store.list('oauthFlows').length, flows); assert.equal(f.app.store.list('activity').length, activity);
  const started = f.app.oauth.start({appId: 'gmail', connectionId: id, scopes: [ADDED]});
  assert.deepEqual(new URL(started.authorizationUrl).searchParams.get('scope').split(' '), planned.scopes);
  assert.deepEqual(planned.userScopes, []);
  assert.throws(() => f.app.oauth.plan({appId: 'gmail', connectionId: randomUUID()}), {code: 'invalid_input'});
});

test('an account confirmed from an account request survives a restart while it waits for its renewal, and the renewal keeps its settings', async t => {
  // Restart recovery revokes accounts an account request signed in that the owner never confirmed. A renewal keeps the
  // origin, so a confirmed account waiting for its weekly sign-in must not look like one of those.
  const f = await accountRequestFixture(t), {id: callId} = await f.ask();
  await f.callback(await f.signIn(callId));
  assert.equal((await f.json('POST', `/api/continuations/${callId}/confirm`, {confirmDigest: (await f.view(callId)).confirmDigest})).status, 200);
  await f.app.continuations.settled(callId);
  const [account] = f.connections();
  assert.deepEqual([account.status, account.origin], ['ready', {kind: 'continuation', continuationId: callId}]);
  f.app.runtime.permissions.set({connectionId: account.id, capabilityId: f.write.id, mode: 'allow'});
  const generation = f.app.store.connectionGeneration(account.id), saved = () => { const decision = f.app.runtime.permissions.decision(f.app.store.get('connections', account.id), f.write); return [decision.mode, decision.policySource]; };
  f.sim.revokeAccount('a');
  assert.equal((await f.app.connections.check(account.id)).status, 'reconnect_required');
  assert.deepEqual(f.app.continuations.heldAccounts(f.app.store.get(CONTINUATIONS, callId)), [], 'closing its handoff would not revoke it either');
  await f.restart();
  assert.equal(f.app.store.get('connections', account.id).status, 'reconnect_required', 'restart recovery leaves a confirmed account alone');
  const provider = f.app.connections.oauthProvider(f.app.store.get('connections', account.id));
  const flow = provider.start({connectionId: account.id, appId: 'github'}), grant = f.sim.consent(flow.authorizationUrl);
  await provider.callback({state: grant.state, code: grant.code, flowId: flow.flowId});
  const renewed = f.app.store.get('connections', account.id);
  assert.deepEqual([renewed.status, renewed.authRevision, renewed.origin], ['ready', account.authRevision, account.origin]);
  assert.equal(f.app.store.connectionGeneration(account.id), generation);
  assert.deepEqual(saved(), ['allow', 'saved']);
  f.sim.revokeAccount('a');
  assert.equal((await f.app.connections.check(account.id)).status, 'reconnect_required');
  await f.restart();
  assert.equal(f.app.store.get('connections', account.id).status, 'reconnect_required', 'and again after the renewal');
  // An account still in quarantine is never the owner's, whatever its handoff says: a crash before promotion still revokes it.
  f.app.store.put('connections', {...f.app.store.get('connections', account.id), status: 'pending_confirmation'});
  await f.restart();
  assert.equal(f.app.store.get('connections', account.id).status, 'revoked');
});

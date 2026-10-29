import test from 'node:test';
import assert from 'node:assert/strict';
import {owner, fixture} from './fixtures/signin-fixture.mjs';

// F02.3c: signing in to a new account from a handoff. The connection is quarantined until the
// owner confirms its verified identity. Isolated designated app, loopback port, GitHub simulator.

test('sign-in from a handoff creates a quarantined account that only the owner confirmation activates', async t => {
  const f = await fixture(t);
  const {token, id} = await f.ask();
  const view = await f.view(id);
  assert.equal(view.signIn.available, true); assert.ok(view.actions.includes('sign_in'));
  const started = await f.signIn(id);
  assert.equal(started.status, 200); assert.ok(started.flowId); assert.ok(started.maxAge > 0 && started.maxAge <= 600);
  const flow = f.app.store.list('oauthFlows')[0];
  assert.equal(flow.continuationId, id); assert.ok(flow.expiresAt <= Date.parse((await f.view(id)).expiresAt));
  const back = await f.callback(started);
  assert.equal(back.status, 303); assert.equal(back.location, `/continue/${id}`);
  const pending = await f.view(id);
  assert.equal(pending.status, 'awaiting_confirmation'); assert.equal(pending.pendingConnection.identity.displayName, 'octo-a');
  assert.ok(pending.confirmDigest); assert.deepEqual(f.app.store.list('jobs'), []);
  const [connection] = f.connections();
  assert.equal(connection.status, 'pending_confirmation'); assert.deepEqual(connection.origin, {kind: 'continuation', continuationId: id});
  const generation = f.app.store.connectionGeneration(connection.id);
  // Quarantine: nothing can use, check, permit, grant or reconnect it.
  await assert.rejects(f.app.connections.credentials(connection.id));
  await assert.rejects(f.app.connections.check(connection.id), /waiting for the owner/);
  assert.throws(() => f.app.runtime.permissions.set({connectionId: connection.id, capabilityId: f.read.id, mode: 'allow'}));
  assert.equal((await f.json('POST', '/api/clients', {name: 'X', bindings: [{connectionId: connection.id, capabilityId: f.read.id}]})).status, 400);
  assert.equal((await f.json('POST', '/api/jobs', {connectionId: connection.id, capabilityId: f.read.id})).status, 400);
  assert.equal((await f.json('POST', '/api/oauth/github/start', {connectionId: connection.id, appId: 'github'})).status, 400);
  assert.equal(f.app.store.get('connections', connection.id).status, 'pending_confirmation');
  const confirmed = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: pending.confirmDigest});
  assert.equal(confirmed.status, 200); assert.equal(confirmed.body.status, 'resumed');
  assert.equal(f.app.store.connectionGeneration(connection.id), generation, 'promotion keeps the authority generation');
  await f.app.continuations.settled(id);
  assert.equal(f.api.length, 1);
  assert.equal((await f.protocol(token, 'calls.get', {callId: id})).result.status, 'succeeded');
});

test('a write signed in from a handoff waits for its own approval', async t => {
  const f = await fixture(t);
  const {token, id} = await f.ask(f.write, {owner: 'o', repo: 'r', body: {title: 'Synthetic'}});
  const started = await f.signIn(id);
  assert.ok(new URL(started.body.authorizationUrl).searchParams.get('scope').split(' ').includes('repo'));
  await f.callback(started);
  const confirmed = (await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: (await f.view(id)).confirmDigest})).body;
  assert.equal(confirmed.phase, 'awaiting_approval'); assert.equal(f.api.length, 0);
  const job = f.app.store.get('jobs', confirmed.derived.jobId);
  const approved = await f.json('POST', `/api/jobs/${job.id}/approve`, {approvalDigest: confirmed.derived.approval.digest});
  assert.equal(approved.status, 200); assert.equal(f.api.length, 1);
  assert.equal((await f.protocol(token, 'calls.get', {callId: id})).result.resumedCallId, job.id);
});

test('the owner can reject the wrong account, retry, and a duplicate identity binds the new connection', async t => {
  const f = await fixture(t);
  f.app.store.put('connections', {id: 'existing-a', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'consent', status: 'ready', label: 'Existing', identity: {id: '101', displayName: 'octo-a'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date(f.now).toISOString()});
  const {id} = await f.ask();
  await f.callback(await f.signIn(id), {account: 'b'});
  const wrong = await f.view(id);
  assert.equal(wrong.pendingConnection.identity.displayName, 'octo-b');
  const rejected = await f.json('POST', `/api/continuations/${id}/reject-account`, {});
  assert.equal(rejected.body.status, 'awaiting_owner'); assert.equal(rejected.body.lastAttempt.outcome, 'wrong_account');
  const b = f.connections().find(connection => connection.identity?.id === '202');
  assert.equal(b.status, 'revoked'); assert.equal(f.app.vault.get(b.id), null);
  await f.callback(await f.signIn(id), {account: 'a'});
  const right = await f.view(id);
  assert.equal(right.pendingConnection.duplicateOf, 'existing-a');
  const bound = (await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: right.confirmDigest})).body;
  await f.app.continuations.settled(id);
  assert.equal(f.app.store.get('jobs', bound.derived.jobId).connectionId, right.pendingConnection.connectionId);
  assert.notEqual(right.pendingConnection.connectionId, 'existing-a');
  assert.equal(f.app.store.get('continuations', id).attempts, 2);
});

test('provider denial, partial grants and token errors return to the owner without any account', async t => {
  const f = await fixture(t);
  const {id} = await f.ask(f.write, {owner: 'o', repo: 'r', body: {title: 't'}});
  await f.callback(await f.signIn(id), {deny: true});
  let view = await f.view(id);
  assert.equal(view.status, 'awaiting_owner'); assert.equal(view.lastAttempt.outcome, 'declined_at_provider');
  // F10.7: an optional scope declined only narrows the account, so the partial grant here drops a required one.
  await f.callback(await f.signIn(id), {grant: {omit: ['repo']}});
  view = await f.view(id);
  assert.equal(view.lastAttempt.outcome, 'insufficient_scope');
  assert.deepEqual(f.connections(), []);
  f.sim.failToken = {status: 200, data: {error: 'incorrect_client_credentials'}};
  await f.callback(await f.signIn(id));
  assert.equal((await f.view(id)).lastAttempt.outcome, 'sign_in_failed');
  for (let i = 0; i < 2; i++) await f.signIn(id);
  const exhausted = await f.signIn(id);
  assert.equal(exhausted.status, 409); assert.equal(exhausted.body.code, 'attempts_exhausted');
  assert.deepEqual(f.connections(), []);
});

test('replayed, cookieless, superseded and expired callbacks never exchange a code', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const first = await f.signIn(id), second = await f.signIn(id);
  const before = f.tokenCalls();
  const stale = await f.callback(first);
  assert.equal(stale.location, `/continue/${id}`); assert.equal(f.tokenCalls(), before, 'a superseded flow is discarded');
  const noCookie = await f.callback(second, {cookie: null});
  assert.match(noCookie.location, /^\/\?oauth=/); assert.equal(f.tokenCalls(), before);
  assert.equal((await f.view(id)).status, 'signing_in');
  const good = await f.callback(await f.signIn(id));
  assert.equal(good.location, `/continue/${id}`); assert.equal((await f.view(id)).status, 'awaiting_confirmation');
  const replay = await f.owned('GET', `/api/oauth/github/callback?${good.query}`, undefined, `fabric_oauth=${(await f.signIn(id)).flowId}`);
  assert.equal(replay.status, 303); assert.equal((await f.view(id)).status, 'awaiting_confirmation');
  const other = await f.ask();
  const started = await f.signIn(other.id);
  await f.json('POST', `/api/continuations/${other.id}/select`, {connectionId: 'none', viewDigest: 'x'});
  await f.json('POST', `/api/continuations/${other.id}/decline`, {});
  const tokens = f.tokenCalls();
  await f.callback(started);
  assert.equal(f.tokenCalls(), tokens, 'a callback after decline exchanges nothing');
  const late = await f.ask(), lateStart = await f.signIn(late.id);
  f.advance(31 * 60_000);
  await f.callback(lateStart);
  assert.equal(f.tokenCalls(), tokens, 'a callback after expiry exchanges nothing');
});

test('a decline during the token exchange leaves no credential and no connection', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const started = await f.signIn(id);
  let release;
  f.hooks.token = () => new Promise(resolve => { release = resolve; f.hooks.token = null; });
  const pending = f.callback(started);
  while (!release) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal((await f.json('POST', `/api/continuations/${id}/decline`, {})).status, 200);
  release();
  await pending;
  assert.deepEqual(f.connections(), [], 'beforePersist refused the closed handoff');
  assert.equal(f.app.store.get('continuations', id).status, 'declined');
});

test('closing a handoff that holds a quarantined account revokes it, and confirm refuses a changed account', async t => {
  const f = await fixture(t);
  const declined = await f.ask();
  await f.callback(await f.signIn(declined.id));
  await f.json('POST', `/api/continuations/${declined.id}/decline`, {});
  assert.ok(f.connections().every(connection => connection.status === 'revoked'));
  const expiring = await f.ask();
  await f.callback(await f.signIn(expiring.id));
  f.advance(31 * 60_000);
  assert.equal((await f.view(expiring.id)).status, 'expired');
  assert.equal(f.app.store.get('continuations', expiring.id).outcome.providerGrantMayRemain, true);
  assert.ok(f.connections().every(connection => connection.status === 'revoked'));
  const drift = await f.ask();
  await f.callback(await f.signIn(drift.id));
  const view = await f.view(drift.id);
  f.app.connections.revoke(view.pendingConnection.connectionId);
  const refused = await f.json('POST', `/api/continuations/${drift.id}/confirm`, {confirmDigest: view.confirmDigest});
  assert.equal(refused.status, 409); assert.deepEqual(f.app.store.list('jobs'), []);
});

test('restart keeps a waiting sign-in, recovers an interrupted one and revokes orphaned quarantined accounts', async t => {
  const f = await fixture(t);
  const kept = await f.ask(), startedKept = await f.signIn(kept.id);
  const interrupted = await f.ask(); await f.signIn(interrupted.id);
  f.app.store.delete('oauthFlows', f.app.store.list('oauthFlows').find(flow => flow.continuationId === interrupted.id).id);
  f.app.store.put('connections', {id: 'orphan', appId: 'github', providerId: 'github', driver: 'http', authMethod: 'oauth', authRevision: 'x', status: 'pending_confirmation', origin: {kind: 'continuation', continuationId: interrupted.id}, identity: {id: '303'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date(f.now).toISOString()});
  await f.restart();
  assert.equal((await f.view(interrupted.id)).lastAttempt.outcome, 'sign_in_interrupted');
  assert.equal(f.app.store.get('connections', 'orphan').status, 'revoked');
  assert.equal((await f.view(kept.id)).status, 'signing_in');
  const back = await f.callback(startedKept);
  assert.equal(back.location, `/continue/${kept.id}`); assert.equal((await f.view(kept.id)).status, 'awaiting_confirmation');
});

test('sign-in requires the current view, refuses smuggled bindings and reports unavailable providers', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const stale = await f.owned('POST', `/api/continuations/${id}/sign-in`, {viewDigest: 'stale'});
  assert.equal(stale.status, 409);
  assert.equal((await f.owned('POST', `/api/continuations/${id}/sign-in`, {viewDigest: (await f.view(id)).viewDigest, scopes: ['repo']})).status, 400);
  assert.equal((await f.json('POST', '/api/oauth/github/start', {appId: 'github', continuationId: id})).status, 400);
  const ordinary = await f.json('POST', '/api/oauth/github/start', {appId: 'github'});
  assert.equal(ordinary.status, 200);
  assert.equal(f.app.store.list('oauthFlows').find(flow => !flow.continuationId) !== undefined, true);
  // Provider configuration is read at construction; report it unconfigured through the service's route view.
  f.app.continuations.oauthRoute = () => ({providerId: 'github', name: 'GitHub', configured: false, available: false, reason: 'The product operator must configure the GitHub sign-in client.'});
  const unavailable = await f.owned('POST', `/api/continuations/${id}/sign-in`, {viewDigest: (await f.view(id)).viewDigest});
  assert.equal(unavailable.status, 409); assert.equal((await unavailable.json()).code, 'signin_unavailable');
});

test('choosing an existing account mid sign-in ends that sign-in, and stale or foreign callbacks change nothing', async t => {
  const f = await fixture(t);
  f.app.store.put('connections', {id: 'ready-a', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'consent', status: 'ready', label: 'Ready', identity: {id: '101', displayName: 'octo-a'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date(f.now).toISOString()});
  f.app.vault.set('ready-a', {accessToken: 'synthetic-only-token'});
  const mid = await f.ask(), started = await f.signIn(mid.id);
  const selected = await f.json('POST', `/api/continuations/${mid.id}/select`, {connectionId: 'ready-a', viewDigest: (await f.view(mid.id)).viewDigest});
  assert.equal(selected.body.status, 'resumed');
  assert.equal(f.app.store.list('oauthFlows').some(flow => flow.continuationId === mid.id), false, 'the sign-in flow was discarded');
  const before = f.tokenCalls();
  await f.callback(started);
  assert.equal(f.tokenCalls(), before);
  // A flow that survived its handoff (crash between the two writes) is refused before the exchange.
  const crashed = await f.ask(), crashStart = await f.signIn(crashed.id), flow = f.app.store.list('oauthFlows').find(item => item.continuationId === crashed.id);
  const verifier = f.app.vault.get(`oauth:${flow.id}`);
  await f.json('POST', `/api/continuations/${crashed.id}/decline`, {});
  f.app.store.put('oauthFlows', flow); f.app.vault.set(`oauth:${flow.id}`, verifier);
  await f.callback(crashStart);
  assert.equal(f.tokenCalls(), before, 'the closed handoff refused the exchange');
  assert.equal(f.connections().filter(connection => connection.origin).length, 0);
  // Another browser's flow cookie never completes or disturbs this handoff.
  const mine = await f.ask(), theirs = await f.ask();
  const mineStart = await f.signIn(mine.id), theirStart = await f.signIn(theirs.id);
  await f.callback(mineStart, {cookie: theirStart.flowId});
  assert.equal((await f.view(mine.id)).status, 'signing_in'); assert.equal((await f.view(theirs.id)).status, 'signing_in');
  assert.equal(f.tokenCalls(), before);
  // A stale confirmation digest is refused.
  await f.callback(mineStart);
  const pending = await f.view(mine.id);
  const stale = await f.json('POST', `/api/continuations/${mine.id}/confirm`, {confirmDigest: 'stale'});
  assert.equal(stale.status, 409); assert.equal(stale.body.code, 'view_changed'); assert.equal(stale.body.view.confirmDigest, pending.confirmDigest);
});

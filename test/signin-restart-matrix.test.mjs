import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {readdirSync} from 'node:fs';
import {owner, fixture} from './fixtures/signin-fixture.mjs';

// F02.3c restart recovery and the remaining sign-in matrix (spec sections 6, 9 and 13 items 45-55).
// Isolated designated app on a loopback port, GitHub OAuth simulator, temporary data directory.
const TOKEN_URL = 'https://github.com/login/oauth/access_token';
const sha256 = value => createHash('sha256').update(value).digest('hex');
const at = f => new Date(f.now).toISOString();
const record = (f, id) => f.app.store.get('continuations', id);
const audits = (f, type) => f.app.store.list('activity').filter(event => event.type === type);
const vaultEntries = f => readdirSync(f.app.vault.dir).filter(name => name.endsWith('.enc')).length;
const revokeCalls = f => f.sim.calls.filter(req => req.method === 'DELETE' && /\/applications\/[^/]+\/token$/.test(req.url)).length;
const scopesOf = started => new URL(started.body.authorizationUrl).searchParams.get('scope').split(' ');
async function awaitingConfirmation(f, {account = 'a', cap, args} = {}) {
  const asked = await f.ask(cap, args);
  await f.callback(await f.signIn(asked.id), {account});
  const view = await f.view(asked.id);
  return {...asked, view, connectionId: view.pendingConnection.connectionId};
}
// Crash window: the quarantined account is persisted but Fabric stops before the handoff records it.
const crashBeforeRecording = f => { f.app.continuations.completeSignIn = () => { throw new Error('stopped before recording the sign-in'); }; };
const recordAgain = f => { delete f.app.continuations.completeSignIn; };

test('54: a restart after the callback consumed the flow returns the owner to the choice, and the late callback still lands on the handoff', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const started = await f.signIn(id);
  const flow = f.app.store.list('oauthFlows').find(item => item.continuationId === id);
  // The provider callback consumes the flow before any network I/O; Fabric stops before recording an outcome.
  f.app.store.delete('oauthFlows', flow.id); f.app.vault.delete(`oauth:${flow.id}`);
  await f.restart();
  const recovered = record(f, id);
  assert.equal(recovered.status, 'awaiting_owner'); assert.equal(recovered.signIn, null); assert.equal(recovered.attempts, 1);
  assert.deepEqual(recovered.lastAttempt, {outcome: 'sign_in_interrupted', at: at(f)});
  assert.deepEqual(recovered.superseded, [sha256(started.flowId)], 'the interrupted flow stays recognisable');
  const view = await f.view(id);
  assert.deepEqual(view.actions, ['select', 'sign_in', 'decline']); assert.equal(view.signIn.attemptsLeft, 4);
  const tokens = f.tokenCalls();
  const late = await f.callback(started);
  assert.equal(late.status, 303); assert.equal(late.location, `/continue/${id}`, 'never the generic /?oauth= page');
  assert.equal(f.tokenCalls(), tokens, 'nothing is exchanged');
  assert.deepEqual(record(f, id), recovered, 'the late callback changes nothing');
  await f.callback(await f.signIn(id));
  assert.equal((await f.view(id)).status, 'awaiting_confirmation', 'a new sign-in after the restart completes');
});

test('54: a restart keeps a handoff awaiting confirmation with its quarantined account and credential, and confirming afterwards runs the request', async t => {
  const f = await fixture(t);
  const {token, id, view: before, connectionId} = await awaitingConfirmation(f);
  const stored = f.app.store.get('connections', connectionId), secret = f.app.vault.get(connectionId);
  assert.equal(typeof secret.accessToken, 'string', 'precondition: the quarantined account holds a credential');
  await f.restart();
  assert.deepEqual(f.app.store.get('connections', connectionId), stored, 'recovery leaves the quarantined account untouched');
  assert.deepEqual(f.app.vault.get(connectionId), secret, 'the vault entry survives the restart');
  const after = await f.view(id);
  assert.equal(after.status, 'awaiting_confirmation'); assert.deepEqual(after.actions, ['confirm', 'reject_account', 'decline']);
  assert.deepEqual(after.pendingConnection, before.pendingConnection); assert.deepEqual(after.pendingConnection.identity, {displayName: 'octo-a'});
  assert.equal(after.confirmDigest, before.confirmDigest);
  const confirmed = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: before.confirmDigest});
  assert.equal(confirmed.status, 200); assert.equal(confirmed.body.status, 'resumed');
  await f.app.continuations.settled(id);
  assert.equal(f.app.store.get('connections', connectionId).status, 'ready'); assert.equal(f.api.length, 1);
  const done = (await f.protocol(token, 'calls.get', {callId: id})).result;
  assert.equal(done.status, 'succeeded'); assert.equal(done.connectionId, connectionId);
});

test('54: a handoff awaiting confirmation is kept only until expiry: after an overdue restart it is expired and its account revoked', async t => {
  const f = await fixture(t);
  const {id, connectionId} = await awaitingConfirmation(f);
  f.advance(31 * 60_000);
  await f.restart();
  const closed = record(f, id);
  assert.equal(closed.status, 'expired');
  assert.deepEqual(closed.outcome, {code: 'continuation_expired', at: at(f), connectionDisposition: 'revoked', providerGrantMayRemain: true});
  assert.equal(f.app.store.get('connections', connectionId).status, 'revoked'); assert.equal(f.app.vault.get(connectionId), null);
  assert.deepEqual(audits(f, 'connection.quarantine_revoked').map(event => [event.connectionId, event.continuationId]), [[connectionId, id]]);
});

test('54: a decline revokes its unrecorded account at once, and recovery revokes accounts no handoff awaits: one beside a live confirmation and one of an unknown handoff', async t => {
  const f = await fixture(t);
  const live = await f.ask();
  crashBeforeRecording(f); await f.callback(await f.signIn(live.id), {account: 'b'}); recordAgain(f);
  assert.equal(record(f, live.id).status, 'signing_in', 'precondition: the handoff never recorded the first account');
  const crashed = f.connections().find(connection => connection.identity.id === '202');
  await f.callback(await f.signIn(live.id), {account: 'a'});
  const kept = (await f.view(live.id)).pendingConnection.connectionId, keptSecret = f.app.vault.get(kept);
  const declined = await f.ask();
  crashBeforeRecording(f); await f.callback(await f.signIn(declined.id)); recordAgain(f);
  const abandoned = f.connections().find(connection => connection.origin?.continuationId === declined.id);
  await f.json('POST', `/api/continuations/${declined.id}/decline`, {});
  // Found by its origin, the account a crash never recorded is revoked by the decline itself, not left for restart.
  assert.equal(f.app.store.get('connections', abandoned.id).status, 'revoked'); assert.equal(f.app.vault.get(abandoned.id), null);
  f.app.store.put('connections', {id: 'unknown-owner', appId: 'github', providerId: 'github', driver: 'http', authMethod: 'oauth', authRevision: 'x', status: 'pending_confirmation', origin: {kind: 'continuation', continuationId: randomUUID()}, identity: {id: '303'}, allowedOrigins: ['https://api.github.com'], createdAt: at(f)});
  f.app.vault.set('unknown-owner', {accessToken: 'synthetic-only-token'});
  const orphans = [crashed.id, 'unknown-owner'];
  assert.deepEqual(orphans.map(id => f.app.store.get('connections', id).status), ['pending_confirmation', 'pending_confirmation'], 'precondition: nothing revoked them before the restart');
  const remote = revokeCalls(f);
  await f.restart();
  assert.deepEqual(orphans.map(id => f.app.store.get('connections', id).status), ['revoked', 'revoked']);
  assert.deepEqual(orphans.map(id => f.app.vault.get(id)), [null, null]);
  assert.equal(revokeCalls(f), remote, 'startup revokes locally and calls no provider');
  assert.equal(f.app.store.get('connections', kept).status, 'pending_confirmation'); assert.deepEqual(f.app.vault.get(kept), keptSecret);
  const view = await f.view(live.id);
  assert.equal(view.status, 'awaiting_confirmation'); assert.equal(view.pendingConnection.connectionId, kept);
});

test('45: sign-in asks for exactly the app default access and clamps the flow and its cookie to the handoff deadline', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const first = await f.signIn(id);
  // F10.7: GitHub's default access is the version 2 full level, asked for whole under the testing consent policy.
  assert.deepEqual(scopesOf(first), ['read:user', 'repo', 'read:org', 'gist', 'workflow'], 'the full level, nothing more');
  const flow = f.app.store.list('oauthFlows')[0];
  assert.equal(flow.continuationId, id); assert.equal(flow.expiresAt, f.now + 600_000);
  assert.equal(first.maxAge, 600); assert.equal(first.body.expiresAt, new Date(f.now + 600_000).toISOString());
  assert.deepEqual(Object.keys(first.body).sort(), ['authorizationUrl', 'expiresAt'], 'the flow id travels only in the cookie');
  f.advance(25 * 60_000);
  const late = await f.signIn(id), expiresAt = (await f.view(id)).expiresAt;
  const [clamped] = f.app.store.list('oauthFlows');
  assert.equal(f.app.store.list('oauthFlows').length, 1, 'the earlier flow was discarded');
  assert.equal(clamped.expiresAt, Date.parse(expiresAt)); assert.equal(late.body.expiresAt, expiresAt);
  assert.equal(late.maxAge, 300, 'the cookie lives no longer than the handoff');
});

test('45: an operation the default access does not cover adds only its least-privileged documented alternative', async t => {
  const f = await fixture(t);
  f.app.store.put('applicationMaps', {id: 'github', operations: [
    {capabilityId: f.read.id, requiredScopes: ['gist', 'read:org', 'workflow'], scopeSets: [['gist', 'workflow'], ['read:org']]},
    {capabilityId: f.write.id, requiredScopes: ['repo']}]});
  const {id} = await f.ask();
  assert.deepEqual((await f.view(id)).signIn.scopes, ['read:org']);
  const started = await f.signIn(id);
  assert.deepEqual(scopesOf(started), ['read:user', 'repo', 'read:org', 'gist', 'workflow'], 'the full level already holds read:org');
  await f.callback(started);
  assert.equal((await f.view(id)).pendingConnection.afterConfirm, 'runs_now');
});

test('45: an unconfigured provider is reported with its reason, offers no sign-in and consumes no attempt', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  delete process.env.FABRIC_GITHUB_CLIENT_SECRET; // restored by the fixture
  await f.restart();
  const reason = 'The product operator must configure the GitHub sign-in client.';
  const view = await f.view(id);
  assert.equal(view.signIn.available, false); assert.equal(view.signIn.reason, reason); assert.deepEqual(view.actions, ['select', 'decline']);
  const refused = await f.owned('POST', `/api/continuations/${id}/sign-in`, {viewDigest: view.viewDigest});
  assert.equal(refused.status, 409); assert.deepEqual(await refused.json(), {error: reason, code: 'signin_unavailable'});
  assert.equal(refused.headers.get('set-cookie'), null);
  assert.equal(record(f, id).attempts, 0); assert.equal(record(f, id).status, 'awaiting_owner'); assert.deepEqual(f.app.store.list('oauthFlows'), []);
});

test('46: a quarantined account starts at generation 1, is never executable or offered to another handoff, and health checks write nothing to it', async t => {
  const f = await fixture(t);
  const {connectionId} = await awaitingConfirmation(f);
  const stored = f.app.store.get('connections', connectionId);
  assert.equal(f.app.store.connectionGeneration(connectionId), 1);
  const decision = f.app.runtime.permissions.decision(stored, f.read);
  assert.equal(decision.executable, false); assert.equal(decision.reason, 'The connection is not ready. Check or reconnect it first.');
  const other = await f.ask();
  assert.deepEqual((await f.view(other.id)).accounts, [], 'a pending account is shown only as the pending connection of its own handoff');
  f.app.heartbeats.stop(); f.advance(61_000);
  await f.app.heartbeats.tick();
  const [beat] = f.app.store.list('heartbeats');
  assert.deepEqual(beat.lastResult.connections, [{id: connectionId, status: 'unavailable'}]);
  await assert.rejects(f.app.connections.check(connectionId), /waiting for the owner/);
  assert.deepEqual(f.app.store.get('connections', connectionId), stored, 'neither the tick nor check() wrote to it');
  assert.equal(f.app.store.connectionGeneration(connectionId), 1);
  assert.equal(audits(f, 'connection.checked').length, 0);
  assert.equal(f.tokenCalls(), 1, 'no renewal was attempted');
});

test('47: a policy change while awaiting confirmation makes the shown digest stale, and confirming under Deny binds nothing', async t => {
  const f = await fixture(t);
  const {id, view, connectionId} = await awaitingConfirmation(f);
  const permissions = f.app.runtime.permissions, stored = f.app.store.get('connections', connectionId);
  // permissions.set refuses a quarantined account, so the policy row is written directly.
  f.app.store.put('permissions', {id: permissions.policyId(connectionId, f.read.id), connectionId, capabilityId: f.read.id, mode: 'deny', bindingHash: permissions.binding(stored, f.read), revision: randomUUID(), updatedAt: at(f)});
  const revision = record(f, id).revision;
  const stale = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: view.confirmDigest});
  assert.equal(stale.status, 409); assert.equal(stale.body.code, 'view_changed');
  assert.equal(stale.body.view.pendingConnection.policy.mode, 'deny'); assert.equal(stale.body.view.pendingConnection.afterConfirm, 'blocked');
  assert.notEqual(stale.body.view.confirmDigest, view.confirmDigest);
  assert.equal(record(f, id).revision, revision); assert.equal(f.app.store.get('connections', connectionId).status, 'pending_confirmation');
  const denied = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: stale.body.view.confirmDigest});
  assert.equal(denied.status, 409); assert.equal(denied.body.code, 'policy_denied');
  assert.equal(record(f, id).status, 'failed'); assert.equal(record(f, id).outcome.code, 'policy_denied');
  assert.deepEqual(f.app.store.list('jobs'), []); assert.equal(f.api.length, 0);
  assert.equal(f.app.store.get('connections', connectionId).status, 'ready', 'the owner confirmed the account, so it stays connected');
});

test('48: rejecting the wrong account advances its generation and revokes it at the provider; confirming the account signed in binds exactly it', async t => {
  const f = await fixture(t);
  const {token, id, view: wrong, connectionId: first} = await awaitingConfirmation(f, {account: 'b'});
  assert.deepEqual(wrong.pendingConnection.identity, {displayName: 'octo-b'});
  const generation = f.app.store.connectionGeneration(first), remote = revokeCalls(f);
  const rejected = await f.json('POST', `/api/continuations/${id}/reject-account`, {});
  assert.equal(rejected.status, 200); assert.equal(rejected.body.status, 'awaiting_owner'); assert.equal(rejected.body.signIn.attemptsLeft, 4);
  assert.equal(f.app.store.connectionGeneration(first), generation + 1); assert.equal(f.app.vault.get(first), null);
  assert.equal(revokeCalls(f), remote + 1, 'the rejected account is revoked at the provider');
  await f.callback(await f.signIn(id), {account: 'b'});
  const again = await f.view(id), second = again.pendingConnection.connectionId;
  assert.notEqual(second, first); assert.deepEqual(again.pendingConnection.identity, {displayName: 'octo-b'});
  const bound = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: again.confirmDigest});
  assert.equal(bound.status, 200);
  await f.app.continuations.settled(id);
  assert.equal(f.app.store.get('jobs', bound.body.derived.jobId).connectionId, second);
  assert.equal((await f.protocol(token, 'calls.get', {callId: id})).result.connectionId, second);
  assert.equal(record(f, id).attempts, 2);
});

test('49: a partial grant and a token endpoint 4xx leave no account and no vault entry, and a retry after a provider denial succeeds', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  // F10.7: an optional scope declined only narrows the account, so the partial grant here drops a required one.
  await f.callback(await f.signIn(id), {grant: {omit: ['repo']}});
  assert.equal(record(f, id).lastAttempt.outcome, 'insufficient_scope');
  assert.deepEqual(f.connections(), []); assert.equal(vaultEntries(f), 0);
  f.sim.failToken = {status: 400, data: {error: 'invalid_request'}};
  await f.callback(await f.signIn(id));
  assert.equal(record(f, id).lastAttempt.outcome, 'sign_in_failed');
  assert.deepEqual(f.connections(), []); assert.equal(vaultEntries(f), 0);
  await f.callback(await f.signIn(id), {deny: true});
  assert.equal(record(f, id).lastAttempt.outcome, 'declined_at_provider');
  await f.callback(await f.signIn(id));
  const view = await f.view(id);
  assert.equal(view.status, 'awaiting_confirmation'); assert.equal(view.pendingConnection.identity.displayName, 'octo-a');
  assert.equal(record(f, id).attempts, 4);
});

test('50: an exact replay of a completed callback, same state and same cookie, is refused and changes nothing', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const started = await f.signIn(id);
  const good = await f.callback(started);
  const settled = record(f, id), connections = f.connections(), tokens = f.tokenCalls();
  const replay = await f.owned('GET', `/api/oauth/github/callback?${good.query}`, undefined, `fabric_oauth=${started.flowId}`);
  assert.equal(replay.status, 303); assert.equal(replay.headers.get('location'), `/continue/${id}`);
  assert.equal(replay.headers.get('set-cookie'), null, 'a callback that consumed nothing leaves the cookie alone');
  assert.equal(audits(f, 'oauth.failed').at(-1).code, 'invalid_state');
  assert.deepEqual(record(f, id), settled); assert.deepEqual(f.connections(), connections); assert.equal(f.tokenCalls(), tokens);
});

test('52: a decline, client cancel, client revoke or expiry after the provider issued tokens persists nothing, and the late tokens are revoked at the provider', async t => {
  const f = await fixture(t);
  const cases = [
    ['decline', ({id}) => f.json('POST', `/api/continuations/${id}/decline`, {}), 'declined', 'owner_declined'],
    ['client cancel', ({token, id}) => f.protocol(token, 'calls.cancel', {callId: id}), 'cancelled', 'client_cancelled'],
    ['client revoke', ({id}) => f.json('POST', `/api/clients/${record(f, id).clientId}/revoke`, {}), 'cancelled', 'client_revoked'],
    ['expiry', () => f.advance(31 * 60_000), 'expired', 'continuation_expired'],
  ];
  for (const [name, exit, status, code] of cases) {
    const asked = await f.ask(), started = await f.signIn(asked.id), remote = revokeCalls(f), issue = f.sim.request;
    f.sim.request = async req => { const response = await issue.call(f.sim, req); if (req.url === TOKEN_URL) { delete f.sim.request; await exit(asked); } return response; };
    const back = await f.callback(started);
    assert.equal(back.location, `/continue/${asked.id}`, name);
    assert.equal(record(f, asked.id).status, status, name); assert.equal(record(f, asked.id).outcome.code, code, name);
    assert.equal(revokeCalls(f), remote + 1, `${name}: the dropped tokens were revoked at the provider`);
    assert.deepEqual(audits(f, 'continuation.late_signin_discarded').filter(event => event.continuationId === asked.id).map(event => event.providerGrant), ['revoked'], name);
  }
  assert.deepEqual(f.connections(), []); assert.equal(vaultEntries(f), 0);
});

test('52: when the handoff moves on after the account was persisted but before the outcome is recorded, the new account is revoked', async t => {
  const f = await fixture(t);
  const {token, id} = await f.ask();
  const started = await f.signIn(id), service = f.app.continuations;
  service.completeSignIn = (...args) => { delete service.completeSignIn; service.clientCancel(record(f, id).clientId, id); return service.completeSignIn(...args); };
  const back = await f.callback(started);
  assert.equal(back.location, `/continue/${id}`);
  const [connection] = f.connections();
  assert.equal(connection.origin.continuationId, id, 'precondition: the account was persisted quarantined');
  assert.equal(connection.status, 'revoked'); assert.equal(f.app.vault.get(connection.id), null);
  assert.deepEqual(audits(f, 'connection.quarantine_revoked').map(event => [event.connectionId, event.continuationId]), [[connection.id, id]]);
  assert.equal(record(f, id).pendingConnection, null);
  assert.equal((await f.protocol(token, 'calls.get', {callId: id})).result.status, 'cancelled');
});

test('53: a client cancel or client revoke at awaiting confirmation revokes the quarantined account locally and records its disposition', async t => {
  const f = await fixture(t);
  const cases = [
    ['client cancel', ({token, id}) => f.protocol(token, 'calls.cancel', {callId: id}), 'client_cancelled'],
    ['client revoke', ({id}) => f.json('POST', `/api/clients/${record(f, id).clientId}/revoke`, {}), 'client_revoked'],
  ];
  for (const [name, exit, code] of cases) {
    const pending = await awaitingConfirmation(f), remote = revokeCalls(f);
    await exit(pending);
    assert.equal(record(f, pending.id).status, 'cancelled', name);
    assert.deepEqual(record(f, pending.id).outcome, {code, at: at(f), connectionDisposition: 'revoked', providerGrantMayRemain: true}, name);
    assert.equal(f.app.store.get('connections', pending.connectionId).status, 'revoked', name); assert.equal(f.app.vault.get(pending.connectionId), null, name);
    assert.equal(revokeCalls(f), remote, `${name}: revoked locally only`);
  }
});

test('53: an owner decline at awaiting confirmation revokes the account at the provider and records whether the grant may remain', async t => {
  const f = await fixture(t);
  const confirmed = await awaitingConfirmation(f), remote = revokeCalls(f);
  const declined = await f.json('POST', `/api/continuations/${confirmed.id}/decline`, {});
  assert.equal(declined.status, 200);
  assert.deepEqual(declined.body.outcome, {code: 'owner_declined', at: at(f), connectionDisposition: 'revoked', providerGrantMayRemain: false, providerGrant: 'revoked'});
  assert.equal(revokeCalls(f), remote + 1);
  assert.equal(f.app.store.get('connections', confirmed.connectionId).status, 'revoked'); assert.equal(f.app.vault.get(confirmed.connectionId), null);
  const unconfirmed = await awaitingConfirmation(f);
  f.sim.revokeFails = true;
  const failed = await f.json('POST', `/api/continuations/${unconfirmed.id}/decline`, {});
  assert.deepEqual(failed.body.outcome, {code: 'owner_declined', at: at(f), connectionDisposition: 'revoked', providerGrantMayRemain: true, providerGrant: 'may_remain'});
  assert.equal(f.app.store.get('connections', unconfirmed.connectionId).status, 'revoked'); assert.equal(f.app.vault.get(unconfirmed.connectionId), null);
});

test('53: confirm refuses a quarantined account whose verified identity changed, closes authority_changed and revokes it', async t => {
  const f = await fixture(t);
  const {id, view, connectionId} = await awaitingConfirmation(f, {account: 'b'});
  f.app.store.put('connections', {...f.app.store.get('connections', connectionId), identity: {id: '999', displayName: 'octo-b'}});
  const refused = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: view.confirmDigest});
  assert.equal(refused.status, 409); assert.equal(refused.body.code, 'authority_changed');
  assert.deepEqual(record(f, id).outcome, {code: 'authority_changed', at: at(f), connectionDisposition: 'revoked', providerGrantMayRemain: true});
  assert.equal(f.app.store.get('connections', connectionId).status, 'revoked'); assert.equal(f.app.vault.get(connectionId), null);
  assert.deepEqual(f.app.store.list('jobs'), []); assert.equal(f.api.length, 0);
});

test('55: an ordinary sign-in while a handoff is signing in still lands on /?oauth=connected and leaves the handoff untouched', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  await f.signIn(id);
  const waiting = record(f, id);
  const response = await f.owned('POST', '/api/oauth/github/start', {appId: 'github'});
  const ordinary = {body: await response.json(), flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie'))[1]};
  const back = await f.callback(ordinary);
  assert.equal(back.status, 303); assert.equal(back.location, '/?oauth=connected');
  const [connection] = f.connections();
  assert.equal(connection.status, 'ready'); assert.equal(connection.origin, undefined);
  assert.deepEqual(record(f, id), waiting);
  assert.deepEqual((await f.view(id)).accounts.map(account => account.connectionId), [connection.id]);
});

test('section 6: sign-in, confirm, reject-account and decline accept only their own body keys; anything else is 400 and changes nothing', async t => {
  const f = await fixture(t);
  const {token, id} = await f.ask();
  const snapshot = () => ({record: record(f, id), flows: f.app.store.list('oauthFlows'), connections: f.connections(), jobs: f.app.store.list('jobs'), provider: f.sim.calls.length});
  const forged = [{principal: owner}, {decidedBy: 'owner'}, {clientId: 'x'}, {generation: 1}, {scope: owner.scope}, {source: {kind: 'user'}}, {connectionId: 'x'}];
  const refuse = async (verb, base, extras) => {
    for (const extra of [...forged, ...extras]) {
      const before = snapshot(), label = `${verb} + ${Object.keys(extra)}`;
      const response = await f.json('POST', `/api/continuations/${id}/${verb}`, {...base, ...extra});
      assert.equal(response.status, 400, label); assert.equal(response.body.code, 'invalid_request', label);
      assert.deepEqual(snapshot(), before, label);
    }
    const before = snapshot();
    assert.equal((await f.owned('POST', `/api/continuations/${id}/${verb}`, [base])).status, 400, `${verb} array body`);
    const noCsrf = await fetch(`${f.app.origin}/api/continuations/${id}/${verb}`, {method: 'POST', headers: {'content-type': 'application/json', authorization: `Bearer ${token}`}, body: JSON.stringify(base)});
    assert.equal(noCsrf.status, 403, `${verb} with a client token and no session`);
    assert.deepEqual(snapshot(), before, verb);
  };
  const choosing = await f.view(id);
  await refuse('sign-in', {viewDigest: choosing.viewDigest}, [{scopes: ['repo']}, {writeAccess: true}, {continuationId: id}, {flowId: 'x'}, {confirmDigest: 'x'}]);
  await refuse('decline', {}, [{reason: 'x'}, {viewDigest: choosing.viewDigest}]);
  const oauthStart = await f.json('POST', '/api/oauth/github/start', {appId: 'github', extra: 1});
  assert.equal(oauthStart.status, 400); assert.deepEqual(f.app.store.list('oauthFlows'), []);
  await f.callback(await f.signIn(id));
  const pending = await f.view(id);
  await refuse('confirm', {confirmDigest: pending.confirmDigest}, [{viewDigest: choosing.viewDigest}, {scopes: ['repo']}]);
  await refuse('reject-account', {}, [{confirmDigest: pending.confirmDigest}, {reason: 'x'}]);
  await refuse('decline', {}, [{confirmDigest: pending.confirmDigest}]);
  assert.equal(f.app.store.get('connections', pending.pendingConnection.connectionId).status, 'pending_confirmation');
  const confirmed = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: pending.confirmDigest});
  assert.equal(confirmed.status, 200, 'the exact body still works'); assert.equal(confirmed.body.status, 'resumed');
});

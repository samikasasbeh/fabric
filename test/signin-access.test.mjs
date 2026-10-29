import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fixture} from './fixtures/signin-fixture.mjs';

// F02.3c sign-in access and flow handling: a handoff sign-in asks for the app's reviewed default access (since F10.7 the
// full level) plus only the least-privileged documented alternative still needed; the flow and its cookie
// never outlive the handoff; a callback that did not consume this browser's flow changes nothing.
const sha256 = value => createHash('sha256').update(value).digest('hex');
const CLEARED = 'fabric_oauth=; HttpOnly; SameSite=Lax; Path=/api/oauth/github/callback; Max-Age=0';
const params = started => new URL(started.body.authorizationUrl).searchParams;
const flowsFor = (f, id) => f.app.store.list('oauthFlows').filter(flow => flow.continuationId === id);
const stored = (f, id) => f.app.store.get('continuations', id);
const failures = f => f.app.store.list('activity').filter(event => event.type === 'oauth.failed').map(event => event.code);
/** The account holder approves at the simulated provider; returns the redirect query. */
const consent = (f, started, options) => {
  const result = f.sim.consent(started.body.authorizationUrl, options);
  return new URLSearchParams({state: result.state, ...(result.code ? {code: result.code} : {error: result.error})}).toString();
};
/** The browser follows the provider redirect carrying exactly this fabric_oauth cookie. */
const arrive = async (f, query, cookie) => {
  const response = await f.owned('GET', `/api/oauth/github/callback?${query}`, undefined, `fabric_oauth=${cookie}`);
  return {status: response.status, location: response.headers.get('location'), setCookie: response.headers.get('set-cookie')};
};
const mapWith = (f, readOperation) => f.app.store.put('applicationMaps', {id: 'github', operations: [{capabilityId: f.read.id, ...readOperation}, {capabilityId: f.write.id, requiredScopes: ['repo']}]});

// F10.7: GitHub signs in with version 2, so a handoff sign-in asks for the whole full level (testing consent). An operation the
// required scopes do not cover still names the least-privileged alternative it needs, which makes that scope required (F10.5
// correction 1); every such scope is in the full level, so the URL is the full level. One only a scope outside it covers cannot be
// signed in for.
const FULL = 'read:user repo read:org gist workflow';
test('a read handoff sign-in requests the full level and nothing more', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const view = await f.view(id);
  assert.deepEqual(view.signIn.scopes, [], 'no extra scope for a read the full level covers');
  assert.deepEqual([view.signIn.writeAccess, view.signIn.access], [true, 'full'], 'connecting grants full access');
  assert.equal(view.signIn.afterSignIn, 'runs_now');
  const started = await f.signIn(id);
  assert.equal(started.status, 200);
  assert.equal(params(started).get('scope'), FULL, 'the full level, not a read-only set');
  assert.equal(params(started).has('user_scope'), false, 'GitHub grants carry no user scopes');
  assert.deepEqual(flowsFor(f, id).map(flow => flow.scopes), [FULL.split(' ')]);
  assert.equal(stored(f, id).signIn.writeAccess, true); assert.deepEqual(stored(f, id).signIn.scopes, []);
});

test('a write handoff sign-in requests the same full level because it already covers the write', async t => {
  const f = await fixture(t);
  const {id} = await f.ask(f.write, {owner: 'o', repo: 'r', body: {title: 'Synthetic'}});
  const view = await f.view(id);
  assert.deepEqual(view.signIn.scopes, [], 'repo is in the full level, so nothing is added');
  assert.equal(view.signIn.writeAccess, true);
  assert.equal(view.signIn.afterSignIn, 'asks_approval');
  const started = await f.signIn(id);
  assert.equal(params(started).get('scope'), FULL);
  assert.equal(params(started).has('user_scope'), false);
  assert.deepEqual(flowsFor(f, id).map(flow => flow.scopes), [FULL.split(' ')]);
});

test('an operation the required scopes do not cover names exactly read:org, never admin:org or both; one only admin:org covers cannot sign in', async t => {
  const f = await fixture(t);
  mapWith(f, {requiredScopes: ['admin:org', 'read:org'], scopeSets: [['admin:org'], ['read:org']]});
  const {id} = await f.ask();
  const view = await f.view(id);
  assert.deepEqual(view.signIn.scopes, ['read:org'], 'only the alternative this app may request, named so it is required');
  const started = await f.signIn(id);
  assert.equal(params(started).get('scope'), FULL, 'the full level, which holds read:org; admin:org never');
  assert.deepEqual(stored(f, id).signIn.scopes, ['read:org']);
  assert.deepEqual(flowsFor(f, id).map(flow => flow.required), [['read:user', 'repo', 'read:org']], 'the named scope is required');
  await f.callback(started);
  const pending = (await f.view(id)).pendingConnection;
  assert.deepEqual(pending.scopes, FULL.split(' '));
  assert.equal(pending.afterConfirm, 'runs_now', 'the full level is enough to run the operation');
  // An operation only a scope outside the full level covers: signing in cannot grant it, so the sign-in is not offered.
  const other = await fixture(t);
  mapWith(other, {requiredScopes: ['admin:org'], scopeSets: [['admin:org']]});
  const refused = (await other.view((await other.ask()).id)).signIn;
  assert.deepEqual([refused.available, refused.reason], [false, 'Signing in cannot grant the permission this operation needs. Ask the developer to review it.']);
});

test('among documented alternatives the one adding the fewest scopes wins, not the first or the union', async t => {
  const f = await fixture(t);
  mapWith(f, {requiredScopes: ['gist', 'workflow', 'read:org'], scopeSets: [['gist', 'workflow'], ['read:org']]});
  const {id} = await f.ask();
  assert.deepEqual((await f.view(id)).signIn.scopes, ['read:org']);
  const started = await f.signIn(id);
  assert.equal(params(started).get('scope'), FULL);
});

test('an operation with an alternative the full level already covers adds no scope', async t => {
  const f = await fixture(t);
  mapWith(f, {requiredScopes: ['read:org', 'repo'], scopeSets: [['read:org'], ['repo']]});
  const {id} = await f.ask();
  assert.deepEqual((await f.view(id)).signIn.scopes, []);
  const started = await f.signIn(id);
  assert.equal(params(started).get('scope'), FULL);
});

test('with more than ten minutes left the flow and its cookie last exactly ten minutes', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const started = await f.signIn(id);
  assert.equal(started.maxAge, 600);
  assert.equal(started.body.expiresAt, new Date(f.now + 600_000).toISOString());
  assert.deepEqual(flowsFor(f, id).map(flow => flow.expiresAt), [f.now + 600_000]);
});

test('with less than ten minutes left the flow and its cookie end exactly at the handoff expiry', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const expiresAt = (await f.view(id)).expiresAt, expiry = Date.parse(expiresAt);
  f.advance(expiry - f.now - 299_500);
  const started = await f.signIn(id);
  assert.equal(started.status, 200);
  assert.equal(started.maxAge, 300, 'Max-Age is the remaining 299.5 seconds rounded up');
  assert.equal(started.body.expiresAt, expiresAt);
  assert.deepEqual(flowsFor(f, id).map(flow => flow.expiresAt), [expiry], 'the stored flow ends with the handoff');
  assert.equal(stored(f, id).signIn.expiresAt, expiresAt);
});

test('a callback at the clamped expiry is refused as invalid_state before any token exchange', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const expiry = Date.parse((await f.view(id)).expiresAt);
  f.advance(expiry - f.now - 120_000);
  const started = await f.signIn(id), query = consent(f, started);
  f.advance(expiry - f.now);
  const back = await arrive(f, query, started.flowId);
  assert.equal(back.status, 303); assert.equal(back.location, `/continue/${id}`);
  assert.deepEqual(failures(f), ['invalid_state'], 'the flow itself had expired');
  assert.equal(f.tokenCalls(), 0); assert.deepEqual(f.connections(), []);
  assert.equal((await f.view(id)).status, 'expired');
});

test('replaying the same state and cookie after a successful callback is invalid_state and changes nothing', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const started = await f.signIn(id), query = consent(f, started);
  const first = await arrive(f, query, started.flowId);
  assert.equal(first.status, 303); assert.equal(first.location, `/continue/${id}`); assert.equal(first.setCookie, CLEARED);
  assert.equal(f.tokenCalls(), 1);
  const view = await f.view(id), before = stored(f, id), [connection] = f.connections();
  assert.equal(view.status, 'awaiting_confirmation');
  const replay = await arrive(f, query, started.flowId);
  assert.equal(replay.status, 303); assert.equal(replay.location, `/continue/${id}`);
  assert.deepEqual(failures(f), ['invalid_state'], 'the consumed flow cannot be used again');
  assert.equal(f.tokenCalls(), 1, 'no second token exchange');
  assert.deepEqual(f.connections().map(item => item.id), [connection.id], 'no second connection');
  assert.deepEqual(stored(f, id), before, 'the handoff record is untouched');
  assert.equal((await f.view(id)).confirmDigest, view.confirmDigest);
});

test('a superseded sign-in is discarded: its consent exchanges nothing and the current sign-in still completes', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const first = await f.signIn(id), [firstFlow] = flowsFor(f, id);
  const second = await f.signIn(id);
  assert.deepEqual(flowsFor(f, id).map(flow => flow.flowIdHash), [sha256(second.flowId)], 'only the current flow remains');
  assert.equal(f.app.vault.get(`oauth:${firstFlow.id}`), null, 'the superseded verifier is gone');
  assert.deepEqual(stored(f, id).superseded, [sha256(first.flowId)]);
  const before = stored(f, id), firstQuery = consent(f, first);
  const stale = await arrive(f, firstQuery, first.flowId);
  assert.equal(stale.location, `/continue/${id}`);
  // The same browser now holds the second cookie when the first consent returns.
  const crossed = await arrive(f, firstQuery, second.flowId);
  assert.equal(crossed.location, `/continue/${id}`); assert.equal(crossed.setCookie, null);
  assert.deepEqual(failures(f), ['invalid_state', 'invalid_state']);
  assert.equal(f.tokenCalls(), 0); assert.deepEqual(f.connections(), []);
  assert.deepEqual(stored(f, id), before, 'the handoff is still waiting for the current sign-in');
  const current = await arrive(f, consent(f, second), second.flowId);
  assert.equal(current.setCookie, CLEARED);
  assert.equal((await f.view(id)).status, 'awaiting_confirmation');
  assert.equal(f.tokenCalls(), 1); assert.equal(f.connections().length, 1);
});

test('a superseded flow that survived its discard is refused before the token exchange', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const first = await f.signIn(id), [firstFlow] = flowsFor(f, id), verifier = f.app.vault.get(`oauth:${firstFlow.id}`);
  const second = await f.signIn(id);
  // A crash between the discard and the handoff write would leave the old flow behind.
  f.app.store.put('oauthFlows', firstFlow); f.app.vault.set(`oauth:${firstFlow.id}`, verifier);
  const before = stored(f, id);
  const stale = await arrive(f, consent(f, first), first.flowId);
  assert.equal(stale.location, `/continue/${id}`);
  assert.deepEqual(failures(f), ['continuation_closed'], 'the handoff admits only its current flow');
  assert.equal(f.tokenCalls(), 0); assert.deepEqual(f.connections(), []);
  assert.deepEqual(stored(f, id), before);
  await arrive(f, consent(f, second), second.flowId);
  assert.equal((await f.view(id)).status, 'awaiting_confirmation');
});

test('declining mid sign-in discards the flow, and its callback creates nothing', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  const started = await f.signIn(id), [flow] = flowsFor(f, id), query = consent(f, started);
  assert.equal((await f.json('POST', `/api/continuations/${id}/decline`, {})).status, 200);
  assert.deepEqual(flowsFor(f, id), [], 'the flow was discarded with the handoff');
  assert.equal(f.app.vault.get(`oauth:${flow.id}`), null);
  const before = stored(f, id);
  assert.equal(before.status, 'declined');
  const back = await arrive(f, query, started.flowId);
  assert.equal(back.status, 303); assert.equal(back.location, `/continue/${id}`);
  assert.deepEqual(failures(f), ['invalid_state']);
  assert.equal(f.tokenCalls(), 0); assert.deepEqual(f.connections(), []);
  assert.deepEqual(stored(f, id), before);
});

test('a callback with another handoff state keeps this browser cookie, and both sign-ins still complete', async t => {
  const f = await fixture(t);
  const mine = await f.ask(), theirs = await f.ask();
  const mineStart = await f.signIn(mine.id), theirStart = await f.signIn(theirs.id);
  const theirQuery = consent(f, theirStart), mineBefore = stored(f, mine.id), theirBefore = stored(f, theirs.id);
  const foreign = await arrive(f, theirQuery, mineStart.flowId);
  assert.equal(foreign.status, 303); assert.equal(foreign.location, `/continue/${mine.id}`);
  assert.equal(foreign.setCookie, null, 'the fabric_oauth cookie is not cleared');
  assert.deepEqual(failures(f), ['invalid_state']);
  assert.equal(f.tokenCalls(), 0); assert.deepEqual(f.connections(), []);
  assert.deepEqual(stored(f, mine.id), mineBefore); assert.deepEqual(stored(f, theirs.id), theirBefore);
  assert.equal(flowsFor(f, theirs.id).length, 1, 'the other handoff flow was not consumed');
  const own = await arrive(f, consent(f, mineStart), mineStart.flowId);
  assert.equal(own.location, `/continue/${mine.id}`); assert.equal(own.setCookie, CLEARED);
  assert.equal((await f.view(mine.id)).status, 'awaiting_confirmation');
  const other = await arrive(f, theirQuery, theirStart.flowId);
  assert.equal(other.location, `/continue/${theirs.id}`);
  assert.equal((await f.view(theirs.id)).status, 'awaiting_confirmation');
  assert.equal(f.tokenCalls(), 2); assert.equal(f.connections().length, 2);
});

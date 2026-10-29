import test from 'node:test';
import assert from 'node:assert/strict';
import {hostedSetup} from './fixtures/hosted-fixture.mjs';
import {PAGE_IDLE_LIMIT_MS} from '../lib/tenant/connect-sessions.mjs';

// F03.10 (docs/F03-DEVELOPER-LAYER.md sections 5.6 and 5.13): links to Fabric's hosted manage and approval pages. Each
// is its own power (connect:manage, connect:approve), lasts at most 10 minutes, is delivered by redirect only, never
// creates a person and never starts a sign-in. An approve link names one of that person's waiting calls.
const without = ({requestId, ...rest}) => rest;
const errorOf = response => without(response.body.error);

test('manage and approve links last at most 10 minutes and use redirect delivery only', async t => {
  const {keys, call, account, ask, now, advance} = await hostedSetup(t);
  await account('u1', 'g-1');
  const make = body => call(keys.full, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', ...body});
  const manage = await make({purpose: 'manage'});
  assert.equal(manage.status, 201); assert.equal(manage.body.expiresAt, new Date(now() + 600_000).toISOString());
  const waiting = await ask('u1');
  for (const extra of [{purpose: 'manage'}, {purpose: 'approve', callRef: waiting.callRef}]) {
    for (const refused of [{expiresInSeconds: 601}, {expiresInSeconds: 59}, {delivery: 'message'}, {delivery: 'message', userHint: 'Sam'}, {userHint: 'Sam'}, {presentation: 'direct'}, {consentEtag: 'x'}]) {
      const response = await make({...extra, ...refused});
      assert.equal(response.status, 400, JSON.stringify({...extra, ...refused})); assert.equal(response.body.error.code, 'invalid_request');
    }
    assert.equal((await make({...extra, expiresInSeconds: 60})).status, 201);
  }
  assert.equal((await make({purpose: 'approve'})).status, 400, 'an approve link names its call');
  assert.equal((await make({purpose: 'approve', callRef: waiting.callRef, appId: 'gmail'})).status, 400);
  assert.equal((await make({purpose: 'manage', callRef: waiting.callRef})).status, 400);
  assert.equal((await make({callRef: waiting.callRef})).status, 400, 'a connect link takes no callRef');
  // An approve link never outlives the approval it is for.
  advance(6 * 60_000);
  const late = await make({purpose: 'approve', callRef: waiting.callRef});
  assert.equal(late.status, 201); assert.equal(late.body.expiresAt, waiting.approval.expiresAt);
});

test('each purpose is its own power: connect:write, connect:manage, connect:approve', async t => {
  const {keys, call, account, ask} = await hostedSetup(t);
  await account('u1', 'g-1');
  const waiting = await ask('u1');
  const make = (key, body) => call(key, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', ...body});
  for (const body of [{purpose: 'manage'}, {purpose: 'approve', callRef: waiting.callRef}]) {
    const refused = await make(keys.standard, body);
    assert.equal(refused.status, 403); assert.equal(refused.body.error.code, 'forbidden_scope');
  }
  assert.equal((await make(keys.standard, {appId: 'github'})).status, 201, 'the standard preset still connects');
  assert.equal((await make(keys.manage, {purpose: 'manage'})).status, 201);
  assert.equal((await make(keys.manage, {appId: 'github'})).status, 403, 'connect:manage alone cannot connect');
  assert.equal((await make(keys.manage, {purpose: 'approve', callRef: waiting.callRef})).status, 403);
  assert.equal((await make(keys.approve, {purpose: 'approve', callRef: waiting.callRef})).status, 201);
  assert.equal((await make(keys.approve, {purpose: 'manage'})).status, 403);
  // Minting the link again is the purpose's power too, whichever key made the session.
  const session = (await make(keys.manage, {purpose: 'manage'})).body;
  const relink = await call(keys.connectOnly, 'POST', `/v1/connect-sessions/${session.id}/link`);
  assert.equal(relink.status, 403); assert.equal(relink.body.error.code, 'forbidden_scope');
  assert.equal((await call(keys.manage, 'POST', `/v1/connect-sessions/${session.id}/link`)).status, 200);
  // Unchanged: handoff is Fabric's own and other purposes do not exist. F10.4: reconnect is connect:write's power, and
  // add_access, a decision, connect:manage's.
  assert.equal((await make(keys.full, {purpose: 'handoff'})).status, 422);
  assert.equal((await make(keys.manage, {purpose: 'reconnect'})).status, 403);
  assert.equal((await make(keys.standard, {purpose: 'add_access'})).status, 403);
  assert.equal((await make(keys.full, {purpose: 'sideways'})).status, 400);
});

test('an approve link for another person\'s call, an unknown call or a malformed one is the same not_found, and writes nothing', async t => {
  const {app, keys, call, repo, account, ask, advance} = await hostedSetup(t);
  await account('u1', 'g-1'); await account('u2', 'g-2');
  const theirs = await ask('u2'), theirsSettled = await ask('u2');
  const digest2 = (await call(keys.full, 'GET', '/v1/users/u2/approvals')).body.approvals.find(item => item.callRef === theirsSettled.callRef).digest;
  assert.equal((await call(keys.full, 'POST', `/v1/users/u2/approvals/${theirsSettled.callRef}/decision`, {decision: 'reject', digest: digest2})).status, 200);
  const counts = () => ({users: repo().list('endUsers').length, sessions: repo().list('connectSessions').length, routes: app.registry.list('sessionRoutes').length, audit: repo().list('activity').length});
  const before = counts();
  const answers = [];
  // Another person's call reads as unknown whatever its state: waiting or already settled (ownership before state).
  for (const callRef of [theirs.callRef, theirsSettled.callRef, '00000000-0000-4000-8000-000000000000', 'not-a-call', 'A'.repeat(36)]) {
    const response = await call(keys.full, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'approve', callRef});
    assert.equal(response.status, 404, callRef); answers.push(JSON.stringify(errorOf(response)));
  }
  assert.equal(new Set(answers).size, 1, 'the same answer for each');
  assert.deepEqual(counts(), before, 'no user, session, route or audit row');
  // A call that is not waiting any more, or whose approval ran out.
  const mine = await ask('u1');
  const digest = (await call(keys.full, 'GET', '/v1/users/u1/approvals')).body.approvals.find(item => item.callRef === mine.callRef).digest;
  assert.equal((await call(keys.full, 'POST', `/v1/users/u1/approvals/${mine.callRef}/decision`, {decision: 'reject', digest})).status, 200);
  const settled = await call(keys.full, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'approve', callRef: mine.callRef});
  assert.equal(settled.status, 409); assert.equal(settled.body.error.code, 'not_awaiting_approval');
  const later = await ask('u1');
  advance(11 * 60_000);
  const expired = await call(keys.full, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'approve', callRef: later.callRef});
  assert.equal(expired.status, 410); assert.equal(expired.body.error.code, 'approval_expired');
});

test('manage and approve links never create a person and never start a sign-in', async t => {
  const {app, keys, call, repo, account, open} = await hostedSetup(t);
  const users = repo().list('endUsers').length;
  const stranger = await call(keys.full, 'POST', '/v1/connect-sessions', {externalUserId: 'nobody', purpose: 'manage'});
  assert.equal(stranger.status, 404); assert.equal(repo().list('endUsers').length, users, 'no user was created');
  await account('u1', 'g-1');
  const {id, person} = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'});
  const flows = app.registry.list('flowRoutes').length;
  for (const body of [{}, {appId: 'github'}, {appId: 'gmail'}]) assert.equal((await person.call('POST', `/connect/${id}/v1/start`, body)).status, 404);
  assert.equal(app.registry.list('flowRoutes').length, flows); assert.equal(repo().get('connectSessions', id).state, 'opened');
});

test('claim and view: a manage link says which page it opens, an approve link names its call to the developer', async t => {
  const {keys, call, account, ask, open} = await hostedSetup(t);
  await account('u1', 'g-1');
  const manage = await open(keys.full, {externalUserId: 'u1', purpose: 'manage', successRedirectUri: 'http://localhost:5173/settings'});
  const view = (await manage.person.call('GET', `/connect/${manage.id}/v1/view`)).body;
  assert.match(view.csrf, /^[0-9a-f]{64}$/);
  const {csrf, ...shown} = view;
  assert.deepEqual(shown, {state: 'opened', purpose: 'manage', delivery: 'redirect', developer: {appName: 'Acme Assistant'}, manage: {appId: null}});
  const scoped = await open(keys.full, {externalUserId: 'u1', purpose: 'manage', appId: 'gmail'});
  assert.deepEqual((await scoped.person.call('GET', `/connect/${scoped.id}/v1/view`)).body.manage, {appId: 'gmail'});
  const waiting = await ask('u1');
  const approve = await open(keys.full, {externalUserId: 'u1', purpose: 'approve', callRef: waiting.callRef});
  const approveView = (await approve.person.call('GET', `/connect/${approve.id}/v1/view`)).body;
  assert.equal(approveView.purpose, 'approve'); assert.equal(approveView.callRef, undefined, 'the page loads the approval itself'); assert.equal(approveView.manage, undefined);
  const read = (await call(keys.full, 'GET', `/v1/connect-sessions/${approve.id}`)).body;
  assert.deepEqual([read.purpose, read.callRef, read.state, read.externalUserId], ['approve', waiting.callRef, 'opened', 'u1']);
});

test('expiry and the idle limit end access (session level): 5 idle minutes, and never past the link\'s 10', async t => {
  const {app, keys, account, open, advance} = await hostedSetup(t);
  await account('u1', 'g-1');
  const idle = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'});
  assert.equal(app.sessions.pageCaller(idle.id, idle.person.binding, ['manage']).owner.subjectId, 'u1');
  advance(PAGE_IDLE_LIMIT_MS + 1);
  assert.throws(() => app.sessions.pageCaller(idle.id, idle.person.binding, ['manage']), {status: 410, code: 'expired'});
  assert.equal((await idle.person.call('GET', `/connect/${idle.id}/v1/view`)).body.state, 'expired');
  const busy = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'});
  for (let minute = 0; minute < 9; minute += 3) { advance(3 * 60_000); assert.equal(app.sessions.pageCaller(busy.id, busy.person.binding, ['manage']).session.state, 'opened'); }
  advance(60_000 + 1);
  assert.throws(() => app.sessions.pageCaller(busy.id, busy.person.binding, ['manage']), {status: 410, code: 'expired'});
});

test('the page acts only for the session\'s own live person: a user deleted and made again under the same id is someone else', async t => {
  const {app, keys, repo, account, open, userOf} = await hostedSetup(t);
  await account('u1', 'g-1'); await account('u2', 'g-2');
  const first = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'});
  const caller = app.sessions.pageCaller(first.id, first.person.binding, ['manage']);
  assert.deepEqual(caller.party, {decidedIn: 'fabric_page', keyId: keys.full.keyId, serviceClientId: keys.full.serviceClientId, sessionId: first.id, canDecide: true});
  assert.throws(() => app.sessions.pageCaller(first.id, first.person.binding, ['approve']), {status: 404}, 'a manage link is not an approve link');
  // The same external id, a new person record: the session still names the old one.
  const old = userOf('u1');
  repo().put('endUsers', {...old, status: 'deleting'});
  repo().put('endUsers', {id: 'usr_' + 'a'.repeat(26), subjectId: 'u1', status: 'active', createdAt: app.registry.now()});
  assert.throws(() => app.sessions.pageCaller(first.id, first.person.binding, ['manage']), {status: 404, code: 'not_found'});
  // A session whose record id points at someone with another external id.
  const second = await open(keys.full, {externalUserId: 'u2', purpose: 'manage'});
  repo().put('connectSessions', {...repo().get('connectSessions', second.id), userRecordId: old.id});
  assert.throws(() => app.sessions.pageCaller(second.id, second.person.binding, ['manage']), {status: 404, code: 'not_found'});
  // A connect link is never a page caller.
  const connect = await open(keys.full, {externalUserId: 'u2', appId: 'github'});
  assert.throws(() => app.sessions.pageCaller(connect.id, connect.person.binding, ['manage', 'approve']), {status: 404});
});

test('the key that minted the link must still be active and still hold the power, or the link ends', async t => {
  const {app, keys, call, account, open} = await hostedSetup(t);
  await account('u1', 'g-1');
  const minter = app.keys.mint({environmentId: app.registry.list('environments')[0].id, scopes: ['connect:manage', 'connect:write']});
  const revoked = await open(minter, {externalUserId: 'u1', purpose: 'manage'});
  app.keys.updateScopes(minter.serviceClientId, ['connect:write']);
  assert.throws(() => app.sessions.pageCaller(revoked.id, revoked.person.binding, ['manage']), {status: 410, code: 'expired'}, 'the power was taken away');
  app.keys.updateScopes(minter.serviceClientId, ['connect:manage']);
  assert.equal(app.sessions.pageCaller(revoked.id, revoked.person.binding, ['manage']).party.keyId, minter.keyId);
  app.keys.revoke(minter.keyId);
  assert.throws(() => app.sessions.pageCaller(revoked.id, revoked.person.binding, ['manage']), {status: 410, code: 'expired'}, 'the key was revoked');
  // A link minted again names the key that minted it.
  const created = (await call(keys.manage, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'manage'})).body;
  const relinked = (await call(keys.full, 'POST', `/v1/connect-sessions/${created.id}/link`)).body;
  const claimed = app.sessions.claim(created.id, new URL(relinked.connectUrl).hash.slice(3), 'a-browser-binding-of-enough-length');
  assert.equal(app.sessions.pageCaller(created.id, claimed.binding, ['manage']).party.keyId, keys.full.keyId);
});

test('N10: every page request comes from Fabric\'s own page, with the CSRF value for actions', async t => {
  const {app, keys, account, open} = await hostedSetup(t);
  await account('u1', 'g-1');
  const {id, person} = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'});
  assert.equal((await person.call('GET', `/connect/${id}/v1/view`, undefined, {'Sec-Fetch-Site': 'cross-site'})).status, 403);
  assert.equal((await person.call('POST', `/connect/${id}/v1/close`, {}, {'Sec-Fetch-Site': 'same-site'})).status, 403);
  const cookie = `fabric_t_session=${person.binding}`;
  const bare = await fetch(`${app.origin}/connect/${id}/v1/close`, {method: 'POST', headers: {Cookie: cookie, Origin: app.origin, 'Content-Type': 'application/json'}, body: '{}'});
  assert.equal(bare.status, 403, 'no Sec-Fetch-Site');
  for (const csrf of [undefined, 'f'.repeat(64), 'short']) {
    const response = await fetch(`${app.origin}/connect/${id}/v1/close`, {method: 'POST', headers: {Cookie: cookie, Origin: app.origin, 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin', ...(csrf ? {'X-Fabric-CSRF': csrf} : {})}, body: '{}'});
    assert.equal(response.status, 403, String(csrf)); assert.equal((await response.json()).error.code, 'csrf_mismatch');
  }
  assert.equal(app.stores.open(app.registry.scopeOf(app.registry.list('environments')[0])).repository.get('connectSessions', id).state, 'opened', 'nothing changed');
});

test('Done: a manage link ends completed and returns the person; an approval closed without a decision is cancelled', async t => {
  const {keys, call, account, ask, open} = await hostedSetup(t);
  await account('u1', 'g-1');
  const manage = await open(keys.full, {externalUserId: 'u1', purpose: 'manage', successRedirectUri: 'http://localhost:5173/settings?tab=apps'});
  const done = await manage.person.call('POST', `/connect/${manage.id}/v1/close`, {});
  assert.equal(done.status, 200); assert.equal(done.body.state, 'completed');
  assert.equal(done.body.redirect, `http://localhost:5173/settings?tab=apps&fabric_session=${manage.id}&fabric_state=completed`);
  const read = (await call(keys.full, 'GET', `/v1/connect-sessions/${manage.id}`)).body;
  assert.equal(read.state, 'completed'); assert.deepEqual(read.result, {});
  const again = await manage.person.call('POST', `/connect/${manage.id}/v1/close`, {});
  assert.equal(again.status, 409); assert.equal(again.body.error.code, 'already_finished');
  const after = (await manage.person.call('GET', `/connect/${manage.id}/v1/view`)).body;
  assert.equal(after.state, 'completed'); assert.equal(after.redirect, done.body.redirect);
  const waiting = await ask('u1');
  const approve = await open(keys.full, {externalUserId: 'u1', purpose: 'approve', callRef: waiting.callRef});
  assert.equal((await approve.person.call('POST', `/connect/${approve.id}/v1/close`, {})).body.state, 'cancelled');
  assert.equal((await call(keys.full, 'GET', `/v1/users/u1/approvals`)).body.approvals.length, 1, 'the call still waits for a decision');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {hostedSetup} from './fixtures/hosted-fixture.mjs';
import {PAGE_IDLE_LIMIT_MS} from '../lib/tenant/connect-sessions.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {exactAction} from '../lib/ui-contracts.mjs';

// F03.10 (docs/F03-DEVELOPER-LAYER.md sections 5.13 and 6): the data routes behind Fabric's hosted manage and approval
// pages. The person, the environment and the party come from the browser's own session; nothing the page sends names
// anyone. Every page decision records fabric_page, the key that minted the link, and the session.
const without = ({requestId, ...rest}) => rest;
const rowOf = (view, groupId) => view.sections.flatMap(section => section.rows).find(row => row.groupId === groupId);
const PERSON_ACCOUNT_FIELDS = new Set(['accountRef', 'displayName', 'email', 'workspaceName', 'initial', 'status', 'attention', 'accessLevel', 'accessLabel', 'connectedAt', 'isDefault', 'lastUsedAt']);

/** The page's own calls for one opened link. */
const pageOf = ({id, person}) => ({
  get: (path, query = '') => person.call('GET', `/connect/${id}/v1/${path}${query}`),
  post: (path, body = {}) => person.call('POST', `/connect/${id}/v1/${path}`, body),
});

async function world(t) {
  const setup = await hostedSetup(t);
  const {app, keys, call, repo, account, ask, caps} = setup;
  const u1 = await account('u1', 'g-1'), u2 = await account('u2', 'g-2');
  // U3 lives in another environment (another project of the same organization).
  const organizationId = app.registry.list('environments')[0].organizationId, otherProject = app.registry.createProject({organizationId, name: 'Other'});
  const other = app.registry.createEnvironment({projectId: otherProject.id, kind: 'development'}, app.stores), otherScope = app.registry.scopeOf(other);
  const otherKey = app.keys.mint({environmentId: other.id, preset: 'full'});
  await call(otherKey, 'POST', '/v1/connect-sessions', {externalUserId: 'u3'});
  const u3User = app.stores.open(otherScope).repository.list('endUsers').find(item => item.subjectId === 'u3'), u3 = randomUUID();
  app.stores.open(otherScope).repository.put('connections', stampOwner({id: u3, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: 'g-3', displayName: 'g-3@example.com'}, allowedOrigins: ['https://gmail.googleapis.com'], scopes: ['https://www.googleapis.com/auth/gmail.readonly'], createdAt: app.registry.now(), updatedAt: app.registry.now(), authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: 'u3', userRecordId: u3User.id}));
  // Each person in environment A: a saved row, a background setting, a finished call and a waiting one.
  const read = (await caps()).find(item => item.id.includes('messages-get'));
  for (const [externalUserId, ref] of [['u1', u1], ['u2', u2]]) {
    const view = (await call(keys.full, 'GET', `/v1/users/${externalUserId}/apps/gmail?account=${ref}`)).body;
    await call(keys.full, 'POST', `/v1/users/${externalUserId}/accounts/${ref}/permissions`, {groupId: 'gmail.messages.read', mode: 'ask', etag: rowOf(view, 'gmail.messages.read').etag});
    await call(keys.full, 'POST', `/v1/users/${externalUserId}/accounts/${ref}/background`, {mode: 'deny', etag: view.background.etag});
    await call(keys.full, 'PUT', `/v1/users/${externalUserId}/apps/gmail/default-account`, {accountRef: ref});
    await call(keys.standard, 'POST', '/v1/executions', {externalUserId, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}}, {'Idempotency-Key': randomUUID()});
  }
  const waiting1 = await ask('u1'), waiting2 = await ask('u2');
  const snapshot = () => JSON.stringify(['connections', 'permissions', 'backgroundPolicies', 'jobs', 'endUsers'].map(name => repo().list(name).map(item => ({...item, lastUsedAt: undefined})).sort((a, b) => a.id < b.id ? -1 : 1)));
  return {...setup, u1, u2, u3, waiting1, waiting2, snapshot, otherScope};
}

test('a manage session for U1 reads and changes nothing of U2\'s (or U3\'s in another environment)', async t => {
  const {keys, open, account, u1, u2, u3, snapshot} = await world(t);
  const link = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'}), page = pageOf(link);
  const catalog = (await page.get('catalog')).body;
  const cards = [...catalog.featured, ...catalog.categories.flatMap(entry => entry.preview), ...(catalog.results || [])];
  assert.ok(cards.length > 0 && cards.every(card => card.connectionState.state !== 'available'), 'connected apps only');
  assert.ok(cards.every(card => card.iconUrl === `/assets/icons/${card.id}`), 'icons on Fabric\'s own origin');
  const text = JSON.stringify(catalog);
  for (const other of [u2, u3, 'g-2', 'g-3']) assert.equal(text.includes(other), false);
  const mine = (await page.get('apps/gmail', `?account=${u1}`)).body;
  assert.equal(mine.selectedAccountRef, u1); assert.deepEqual(mine.accounts.map(row => row.accountRef), [u1]);
  assert.ok(mine.accounts.every(row => Object.keys(row).every(key => PERSON_ACCOUNT_FIELDS.has(key))), 'the person\'s own account fields only');
  assert.equal(mine.proxyRows, undefined, 'no proxy rows on Fabric\'s page');
  // The person's own account of another app is not an account of this one.
  const notion = await account('u1', 'ws1:user1', {appId: 'notion', displayName: 'User One'});
  const before = snapshot(), refusals = [];
  for (const ref of [u2, u3, randomUUID()]) {
    const read = await page.get('apps/gmail', `?account=${ref}`);
    assert.equal(read.status, 404); refusals.push(JSON.stringify(without(read.body.error)));
    for (const [path, body] of [['permissions', {groupId: 'gmail.messages.read', mode: 'deny', etag: 'x'}], ['reset', {}], ['background', {mode: 'allow', etag: 'x'}], ['disconnect', {}]]) {
      const response = await page.post(`apps/gmail/accounts/${ref}/${path}`, body);
      assert.equal(response.status, 404, `${path} ${ref}`); refusals.push(JSON.stringify(without(response.body.error)));
    }
  }
  const crossed = await page.get('apps/gmail', `?account=${notion}`);
  assert.equal(crossed.status, 404); refusals.push(JSON.stringify(without(crossed.body.error)));
  for (const path of ['reset', 'disconnect']) { const response = await page.post(`apps/gmail/accounts/${notion}/${path}`, {}); assert.equal(response.status, 404, path); refusals.push(JSON.stringify(without(response.body.error))); }
  assert.equal(new Set(refusals).size, 1, 'one answer for every refusal');
  assert.equal(snapshot(), before, 'nothing changed');
  // Activity: U1's calls only, and waiting approvals with no decision path (a manage link never decides).
  const activity = (await page.get('activity', '?externalUserId=u2')).body;
  const items = activity.days.flatMap(day => day.items);
  assert.ok(items.length >= 2 && items.every(item => item.accountRef === u1));
  // U1's read waits too (the saved row is Ask), so two approvals: both U1's, neither with a decision path.
  assert.equal(activity.approvals.length, 2); assert.ok(activity.approvals.every(item => item.accountRef === u1 && item.decide === undefined));
  assert.equal((await page.post(`apps/gmail/accounts/${u1}/reset`, {externalUserId: 'u2'})).status, 400, 'a body cannot name anyone');
  // An app-scoped link manages that app only.
  const scoped = pageOf(await open(keys.full, {externalUserId: 'u1', purpose: 'manage', appId: 'notion'}));
  assert.equal((await scoped.get('apps/gmail')).status, 404); assert.equal((await scoped.get('catalog')).status, 404);
  assert.equal((await scoped.get('apps/notion')).status, 200);
  assert.ok((await scoped.get('activity', '?appId=gmail')).status === 404);
});

test('expiry and the idle limit end access (route level), and after Done every route is closed', async t => {
  const {keys, open, u1, snapshot, advance} = await world(t);
  const routes = page => [() => page.get('catalog'), () => page.get('apps/gmail'), () => page.get('activity'), () => page.post(`apps/gmail/accounts/${u1}/reset`, {}), () => page.post(`apps/gmail/accounts/${u1}/disconnect`, {})];
  const idle = pageOf(await open(keys.full, {externalUserId: 'u1', purpose: 'manage'}));
  advance(PAGE_IDLE_LIMIT_MS + 1);
  const before = snapshot();
  for (const route of routes(idle)) { const response = await route(); assert.equal(response.status, 410); assert.equal(response.body.error.code, 'expired'); }
  assert.equal(snapshot(), before);
  const busy = pageOf(await open(keys.full, {externalUserId: 'u1', purpose: 'manage'}));
  for (let minute = 0; minute < 9; minute += 3) { advance(3 * 60_000); assert.equal((await busy.get('catalog')).status, 200); }
  advance(60_000 + 1);
  assert.equal((await busy.get('catalog')).status, 410);
  const done = pageOf(await open(keys.full, {externalUserId: 'u1', purpose: 'manage'}));
  assert.equal((await done.post('close')).body.state, 'completed');
  for (const route of routes(done)) assert.equal((await route()).status, 409);
});

test('Allow on a write keeps the standing-consent review on Fabric\'s page; a ceiling hides Allow; review is refused', async t => {
  const {keys, call, repo, open, account, u1} = await world(t);
  const link = await open(keys.manage, {externalUserId: 'u1', purpose: 'manage'}), page = pageOf(link);
  let view = (await page.get('apps/gmail', `?account=${u1}`)).body;
  // F10.15 listed churn: the write row whose default is Allow is "Manage labels"; "Draft emails" is Never only now (the next test).
  const send = rowOf(view, 'gmail.messages.send'), labels = rowOf(view, 'gmail.labels.manage'), reads = rowOf(view, 'gmail.messages.read');
  assert.equal(send.allowNeedsConfirm, true); assert.equal(labels.allowNeedsConfirm, true); assert.equal(reads.allowNeedsConfirm, false);
  assert.ok([send, labels, reads].every(row => row.reviewRequired === false));
  const set = (row, mode, extra = {}) => page.post(`apps/gmail/accounts/${u1}/permissions`, {groupId: row.groupId, mode, etag: row.etag, ...extra});
  const refused = await set(send, 'allow');
  assert.equal(refused.status, 409); assert.equal(refused.body.error.code, 'confirm_required'); assert.doesNotMatch(refused.body.error.message, /confirmAllow/);
  assert.equal(rowOf((await page.get('apps/gmail', `?account=${u1}`)).body, 'gmail.messages.send').mode, 'ask', 'nothing changed');
  const allowed = await set(send, 'allow', {confirmAllow: true});
  assert.equal(allowed.status, 200); assert.equal(allowed.body.mode, 'allow');
  const audit = repo().list('activity').filter(item => item.type === 'permission.relayed').at(-1);
  assert.deepEqual([audit.decidedIn, audit.byKey, audit.sessionId, audit.decision], ['fabric_page', keys.manage.keyId, link.id, true]);
  // Manage labels defaults to Allow; set to Ask, Allow comes back only with the review.
  assert.equal((await set(labels, 'ask')).status, 200);
  view = (await page.get('apps/gmail', `?account=${u1}`)).body;
  assert.equal((await set(rowOf(view, 'gmail.labels.manage'), 'allow')).body.error.code, 'confirm_required');
  assert.equal((await set(reads, 'allow', {review: true})).status, 400, 'review is refused');
  // A read row with a write member (Notion's view queries) still needs the review.
  const notion = await account('u1', 'ws1:user1', {appId: 'notion', displayName: 'User One'});
  const content = rowOf((await page.get('apps/notion', `?account=${notion}`)).body, 'notion.content.read');
  assert.equal(content.effect, 'read'); assert.equal(content.allowNeedsConfirm, true);
  // Under an Ask ceiling Allow is not offered, and posting it is refused.
  await call(keys.full, 'PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.messages.read': 'ask'}});
  view = (await page.get('apps/gmail', `?account=${u1}`)).body;
  const capped = rowOf(view, 'gmail.messages.read');
  assert.deepEqual(capped.allowedModes, ['ask', 'deny']);
  const above = await set(capped, 'allow');
  assert.equal(above.status, 409); assert.equal(above.body.error.code, 'mode_not_allowed');
  // Reset on the page brings a write Allow back as Ask (Q6), and says how many.
  const reset = (await page.post(`apps/gmail/accounts/${u1}/reset`, {})).body;
  assert.equal(rowOf({sections: [{rows: reset.rows}]}, 'gmail.labels.manage').mode, 'ask'); assert.ok(reset.clampedToAsk >= 1);
});

// F10.15 (spec line 123, N6): on Fabric's own page too, "Draft emails" offers Never only and says why; anything else is refused.
test('"Draft emails" on Fabric\'s page: not offered, with the drafts reason; Ask and Allow are refused in the page\'s own words; Never is kept', async t => {
  const {keys, open, u1} = await world(t);
  const page = pageOf(await open(keys.manage, {externalUserId: 'u1', purpose: 'manage'}));
  const drafts = rowOf((await page.get('apps/gmail', `?account=${u1}`)).body, 'gmail.drafts.write');
  assert.deepEqual([drafts.allowedModes, drafts.access, drafts.accessReason], [['deny'], 'unavailable',
    'Fabric\'s plain form of this operation cannot carry a whole message, so it would save an empty draft or blank one. Fabric writes drafts through its reviewed Gmail actions.']);
  for (const [mode, extra] of [['ask', {}], ['allow', {confirmAllow: true}]]) {
    const refused = await page.post(`apps/gmail/accounts/${u1}/permissions`, {groupId: drafts.groupId, mode, etag: drafts.etag, ...extra});
    assert.deepEqual([refused.status, refused.body.error.code, refused.body.error.message], [409, 'mode_not_allowed', 'That choice is not available for this permission here.'], mode);
  }
  assert.equal((await page.post(`apps/gmail/accounts/${u1}/permissions`, {groupId: drafts.groupId, mode: 'deny', etag: drafts.etag})).body.mode, 'deny');
});

test('the approval page shows the exact bytes, and refuses to approve a body too long to show', async t => {
  const {keys, repo, open, ask} = await world(t);
  const tricky = await ask('u1', 'a‮b​c');
  const shown = (await pageOf(await open(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: tricky.callRef})).get('approval')).body;
  assert.equal(shown.state, 'pending');
  assert.deepEqual(shown.approval.exact.blocks, exactAction(repo().get('jobs', tricky.callRef)).blocks, 'byte for byte');
  assert.match(JSON.stringify(shown.approval.exact.blocks), /\\u202e|‮/i);
  assert.equal(/\/api\//.test(JSON.stringify(shown)), false, 'no owner paths');
  const long = await ask('u1', 'x'.repeat(100_001));
  const link = await open(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: long.callRef}), page = pageOf(link);
  const incomplete = (await page.get('approval')).body;
  assert.equal(incomplete.approval.exact.complete, false); assert.equal(incomplete.approval.approve, null); assert.ok(incomplete.approval.cancel);
  const approve = await page.post(`approvals/${long.callRef}/decision`, {decision: 'approve', digest: incomplete.approval.digest});
  assert.equal(approve.status, 409); assert.equal(approve.body.error.code, 'exact_action_incomplete');
  assert.equal(repo().get('jobs', long.callRef).status, 'awaiting_approval');
  const reject = await page.post(`approvals/${long.callRef}/decision`, incomplete.approval.cancel.body);
  assert.equal(reject.status, 200); assert.equal(reject.body.decision, 'rejected'); assert.equal(repo().get('jobs', long.callRef).status, 'cancelled');
});

test('an approve link decides its own call only, recorded as Fabric\'s page with the link\'s key and session', async t => {
  const {keys, call, repo, open, ask, waiting1, snapshot, sim} = await world(t);
  const link = await open(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: waiting1.callRef, successRedirectUri: 'http://localhost:5173/chat'}), page = pageOf(link);
  const shown = (await page.get('approval')).body.approval;
  assert.equal(shown.approve.path, `/connect/${link.id}/v1/approvals/${waiting1.callRef}/decision`);
  // Other links, and this link for another call, cannot decide it; nor can a wrong digest.
  const other = await ask('u1'), before = snapshot();
  for (const attempt of [
    () => pageOf(link).post(`approvals/${other.callRef}/decision`, {decision: 'approve', digest: shown.digest}),
    async () => pageOf(await open(keys.full, {externalUserId: 'u1', purpose: 'manage'})).post(`approvals/${waiting1.callRef}/decision`, shown.approve.body),
    async () => pageOf(await open(keys.full, {externalUserId: 'u1', appId: 'github'})).post(`approvals/${waiting1.callRef}/decision`, shown.approve.body),
    async () => pageOf(await open(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: other.callRef})).post(`approvals/${waiting1.callRef}/decision`, shown.approve.body),
  ]) { const response = await attempt(); assert.equal(response.status, 404); }
  const jobsBefore = JSON.parse(before)[3];
  assert.deepEqual(JSON.parse(snapshot())[3].filter(job => jobsBefore.some(item => item.id === job.id)).map(job => job.status), jobsBefore.map(job => job.status), 'nothing was decided');
  const wrong = await page.post(`approvals/${waiting1.callRef}/decision`, {decision: 'approve', digest: 'f'.repeat(64)});
  assert.equal(wrong.status, 409); assert.equal(wrong.body.error.code, 'digest_mismatch');
  const sends = sim.calls.filter(line => line.includes('/messages/send')).length;
  const decided = await page.post(`approvals/${waiting1.callRef}/decision`, shown.approve.body);
  assert.equal(decided.status, 200);
  assert.deepEqual([decided.body.state, decided.body.decision], ['completed', 'approved']);
  assert.equal(decided.body.redirect, `http://localhost:5173/chat?fabric_session=${link.id}&fabric_state=completed`);
  assert.equal(JSON.stringify(decided.body).includes('sent-1'), false, 'never the provider\'s answer');
  const job = repo().get('jobs', waiting1.callRef);
  assert.deepEqual([job.decision.decidedIn, job.decision.keyId, job.decision.sessionId], ['fabric_page', keys.approve.keyId, link.id]);
  const session = (await call(keys.full, 'GET', `/v1/connect-sessions/${link.id}`)).body;
  assert.deepEqual([session.state, session.result], ['completed', {callRef: waiting1.callRef, decision: 'approved'}]);
  assert.equal((await page.post(`approvals/${waiting1.callRef}/decision`, shown.approve.body)).status, 409, 'a second decision');
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(sim.calls.filter(line => line.includes('/messages/send')).length, sends + 1, 'the approved call ran once');
  const activity = (await call(keys.full, 'GET', '/v1/users/u1/activity')).body.days.flatMap(day => day.items).find(item => item.callRef === waiting1.callRef);
  assert.equal(activity.decidedIn, 'fabric_page');
});

test('seeded fault "ignore the etag": a stale etag on a row or on background changes nothing', async t => {
  const {keys, open, u1, snapshot} = await world(t);
  const page = pageOf(await open(keys.full, {externalUserId: 'u1', purpose: 'manage'}));
  const view = (await page.get('apps/gmail', `?account=${u1}`)).body, row = rowOf(view, 'gmail.messages.read');
  assert.equal((await page.post(`apps/gmail/accounts/${u1}/permissions`, {groupId: row.groupId, mode: 'deny', etag: row.etag})).status, 200);
  const before = snapshot();
  const stale = await page.post(`apps/gmail/accounts/${u1}/permissions`, {groupId: row.groupId, mode: 'ask', etag: row.etag});
  assert.equal(stale.status, 409); assert.equal(stale.body.error.code, 'etag_mismatch'); assert.match(stale.body.error.message, /Reload the page/);
  assert.equal((await page.post(`apps/gmail/accounts/${u1}/background`, {mode: 'allow', etag: view.background.etag})).status, 200);
  const staleBackground = await page.post(`apps/gmail/accounts/${u1}/background`, {mode: 'deny', etag: view.background.etag});
  assert.equal(staleBackground.status, 409); assert.equal(staleBackground.body.error.code, 'etag_mismatch');
  assert.notEqual(snapshot(), before, 'the background change in between was saved');
  assert.equal((await page.post(`apps/gmail/accounts/${u1}/permissions`, {groupId: row.groupId, mode: 'ask', etag: row.etag, proxy: true})).status, 400, 'no proxy rows from the page');
});

test('seeded fault "leave the session unbound to its subject" (route level): a user made again under the same id sees nothing', async t => {
  const {app, keys, repo, open, userOf, u1} = await world(t);
  const page = pageOf(await open(keys.full, {externalUserId: 'u1', purpose: 'manage'}));
  const old = userOf('u1');
  repo().put('endUsers', {...old, status: 'deleting'});
  const fresh = {id: 'usr_' + 'b'.repeat(26), subjectId: 'u1', status: 'active', createdAt: app.registry.now()};
  repo().put('endUsers', fresh);
  repo().put('connections', stampOwner({...repo().get('connections', u1), id: randomUUID()}, {subjectId: 'u1', userRecordId: fresh.id}));
  for (const route of [() => page.get('catalog'), () => page.get('apps/gmail'), () => page.get('activity'), () => page.post(`apps/gmail/accounts/${u1}/reset`, {})]) {
    const response = await route();
    assert.equal(response.status, 404); assert.equal(response.body.error.code, 'not_found');
  }
});

test('disconnect from Fabric\'s page: the person\'s own row, recorded with the link\'s key and session; no remote revoke', async t => {
  const {keys, repo, open, u1} = await world(t);
  const link = await open(keys.manage, {externalUserId: 'u1', purpose: 'manage'}), page = pageOf(link);
  const remote = await page.post(`apps/gmail/accounts/${u1}/disconnect`, {remote: true});
  assert.equal(remote.status, 422); assert.equal(remote.body.error.code, 'remote_unavailable');
  const done = await page.post(`apps/gmail/accounts/${u1}/disconnect`, {});
  assert.equal(done.status, 200); assert.equal(done.body.remoteRevoked, false); assert.match(done.body.message, /Disconnected here/);
  assert.ok(Object.keys(done.body.account).every(key => PERSON_ACCOUNT_FIELDS.has(key)), JSON.stringify(Object.keys(done.body.account)));
  const audit = repo().list('activity').find(item => item.type === 'tenant.account_disconnected');
  assert.deepEqual([audit.decidedIn, audit.byKey, audit.sessionId], ['fabric_page', keys.manage.keyId, link.id]);
  assert.equal((await page.get('apps/gmail', `?account=${u1}`)).status, 404, 'the account is gone');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../server.mjs';
import {PREPARED} from '../lib/actions-runtime.mjs';
import {approvalItem, approvalPage, activityPage, EXACT_LIMIT} from '../lib/ui-contracts.mjs';
import {callCard, validateCard} from '../lib/cards.mjs';
import {WARNINGS} from '../public/hosted-approval.js';
import {assertStateTransition, validateApproval, validateExecutionRequest} from '../contracts/execution.mts';
import {actionHarness, certifiedFile, slackHarness, EVIDENCE} from './fixtures/actions/runtime-fixture.mjs';
import {freePort} from './fixtures/signin-fixture.mjs';

// F10.11 part j (docs/F10.11-BUILD-MAP.md part j and section 3): two-phase approval on the owner's side. A job whose reads need approval
// stops in phase reads, showing each read it will send; a perform that needs approval stops in phase final, showing the exact bytes; each
// stop has its own window, digest and decision. A two-phase action's resolving write is shown by its exact bytes before it is sent. Run on
// the fake app's simulator and, for the resolving write, the Slack direct-message helper on a scripted Slack (test/fixtures/actions).

const OK = {status: [200], require: []};
const WRITE_HINTS = {readOnly: false, destructive: false, idempotent: false, openWorld: true};
const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
/** Find, then label: a reviewed-read search whose body is known from the inputs, a read whose URL comes from the search's answer, then a
 *  label named after what that read found. */
const findThenLabel = () => ({id: `fixture.action.find-then-label.v1.${'0'.repeat(24)}`, key: 'find-then-label', version: 1, name: 'Find, then label', description: 'Labels the first item a search finds.',
  effect: 'write', row: 'fixture.labels.write', hints: WRITE_HINTS, inputSchema: closed({query: words()}), outputSchema: closed({id: {type: 'string', maxLength: 64}}), guards: [],
  prepare: [{id: 'search', method: 'POST', path: '/items/search', body: {object: {query: {input: '/query'}}}, expect: OK},
    {id: 'item', method: 'GET', path: '/items/{item_id}', params: {item_id: {step: 'search', pointer: '/results/0/id'}}, expect: OK}],
  perform: [{id: 'label', method: 'POST', path: '/labels', body: {object: {name: {step: 'item', pointer: '/name'}}}, expect: OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/labels/{label_id}', params: {label_id: {step: 'label', pointer: '/id'}}, expect: OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'label', pointer: '/id'}}], assert: []},
  output: {id: {step: 'label', pointer: '/id'}}, preview: [{label: 'Label', expr: {step: 'item', pointer: '/name'}}], definitive: [400, 409],
  certified: {evidence: EVIDENCE, definitionHash: '0'.repeat(64)}});
/** Keys, then label: its read sits in fixture.keys.read and its readback in fixture.items.read, so the prepare row can ask while the perform
 *  and verify rows allow. GET /keys is not the sensitive member, so the action is not sensitive. */
const keysThenLabel = () => ({...findThenLabel(), id: `fixture.action.keys-then-label.v1.${'0'.repeat(24)}`, key: 'keys-then-label', name: 'Label the first key', inputSchema: closed({}),
  prepare: [{id: 'keys', method: 'GET', path: '/keys', expect: OK}],
  perform: [{id: 'label', method: 'POST', path: '/labels', body: {object: {name: {step: 'keys', pointer: '/keys/0/name'}}}, expect: OK}],
  preview: [{label: 'Label', expr: {step: 'keys', pointer: '/keys/0/name'}}]});
const harness = (t, options = {}) => actionHarness(t, {file: certifiedFile(file => { file.actions.push(findThenLabel(), keysThenLabel()); }), ...options});
const run = (h, key, args) => h.runtime.createJob({connectionId: h.account, capabilityId: h.idOf(key), args}, h.owner);
const setOwn = (h, key, mode) => h.permissions.set({connectionId: h.account, capabilityId: h.idOf(key), mode});
const setRow = (h, groupId, mode) => h.proxyPolicy.set({connectionId: h.account, row: `group:${groupId}`, mode, confirmAllow: true});
const dm = (s, args = {email: 'grace@example.com', text: 'Hello <there>'}) => s.runtime.createJob({connectionId: s.account, capabilityId: s.id, args}, s.owner);
const card = (store, job) => approvalItem(job, {prepared: id => store.get(PREPARED, id)});
const block = (item, label) => item.exact.blocks.find(entry => entry.label === label)?.text;
const sha = text => createHash('sha256').update(text).digest('hex');
const MINUTE = 60_000;

test('part j: with an Ask prepare row, phase 1 shows each known read as an exact request, a reviewed-read POST body included, and a dependent read as its template', async t => {
  const h = harness(t);
  setRow(h, 'fixture.items.read', 'ask');
  setOwn(h, 'find-then-label v1', 'ask');
  const job = await run(h, 'find-then-label v1', {query: 'plan'});
  assert.deepEqual([job.status, job.action.phase, h.simulator.calls.length], ['awaiting_approval', 'reads', 0]);
  assert.deepEqual(job.action.reads, [
    {stepId: 'search', index: 0, method: 'POST', url: 'https://api.fixture.test/items/search', headers: {}, added: [{name: 'Authorization', value: '(added by Fabric, hidden)'},
      {name: 'Accept', value: 'application/json'}, {name: 'Content-Type', value: 'application/json; charset=utf-8'}], bodySha256: sha('{"query":"plan"}'), bodyBytes: 16},
    {stepId: 'item', template: 'GET /items/{item_id}'}]);
  const item = card(h.store, job);
  assert.ok(item.approve && item.warnings.includes('prepares_first'));
  assert.deepEqual(item.exact.blocks.map(entry => entry.label), ['search: Request', 'search: Added by Fabric', 'search: Body', 'item: Request']);
  assert.equal(block(item, 'search: Request'), 'POST https://api.fixture.test/items/search');
  assert.equal(block(item, 'search: Body'), '{"query":"plan"}');
  assert.equal(block(item, 'item: Request'), 'GET https://api.fixture.test/items/{item_id} (filled from the read above)');
});

test('part j: changing one read body byte changes the phase reads digest; approving it sends no perform write', async t => {
  const h = harness(t);
  setRow(h, 'fixture.items.read', 'ask');
  setOwn(h, 'find-then-label v1', 'ask');
  const job = await run(h, 'find-then-label v1', {query: 'plan'});
  const [search] = job.action.reads;
  assert.notEqual(h.runtime.digest({...job, action: {...job.action, reads: [{...search, bodySha256: sha('{"query":"plaN"}')}, job.action.reads[1]]}}), job.approvalDigest);
  const next = await h.runtime.approve(job.id, job.approvalDigest, h.owner);
  assert.deepEqual([next.status, next.action.phase, h.simulator.writes().length], ['awaiting_approval', 'final', 0]);
  assert.deepEqual(h.simulator.calls.map(call => `${call.method} ${call.path}`), ['POST /items/search', 'GET /items/I4']);
});

test('part j: phase 2 shows the final bytes with a fresh window; a phase 1 digest is refused for phase 2', async t => {
  const h = harness(t);
  setRow(h, 'fixture.items.read', 'ask');
  setOwn(h, 'find-then-label v1', 'ask');
  const job = await run(h, 'find-then-label v1', {query: 'plan'});
  h.advance(4 * MINUTE);
  const next = await h.runtime.approve(job.id, job.approvalDigest, h.owner);
  assert.equal(Date.parse(next.approvalExpiresAt), h.now + 10 * MINUTE, 'a fresh ten-minute window');
  assert.notEqual(next.approvalDigest, job.approvalDigest);
  const item = card(h.store, next);
  assert.deepEqual(item.exact.blocks.map(entry => entry.label), ['Fields', 'label: Request', 'label: Added by Fabric', 'label: Body']);
  assert.equal(block(item, 'Fields'), 'Label: Plan B');
  assert.equal(block(item, 'label: Body'), '{"name":"Plan B"}');
  assert.ok(!item.warnings.includes('prepares_first'));
  await assert.rejects(h.runtime.approve(job.id, job.approvalDigest, h.owner), /Approval does not match the exact action/);
  assert.deepEqual(next.action.decisions.map(decision => [decision.phase, decision.decision]), [['reads', 'approved']], 'every decision stays on the job');
  const done = await h.runtime.approve(job.id, next.approvalDigest, h.owner);
  assert.equal(done.status, 'succeeded');
  assert.deepEqual(done.action.decisions.map(decision => decision.phase), ['reads', 'final']);
});

test('part j: standing Allow on the perform rows binds exactly those bytes; Ask perform rows need a second approval; a twoPhase action under Allow asks nothing in phase 1', async t => {
  const h = harness(t);
  // The keys row's own default is Ask, which a proxy record cannot add (it follows the default), so a developer's ceiling makes it ask.
  h.permissions.ceilingOf = (appId, groupId) => groupId === 'fixture.keys.read' ? 'ask' : null;
  const job = await run(h, 'keys-then-label v1', {});
  assert.deepEqual([job.status, job.action.phase, job.action.modes.perform], ['awaiting_approval', 'reads', 'allow']);
  const done = await h.runtime.approve(job.id, job.approvalDigest, h.owner);
  assert.deepEqual([done.status, done.approvedBy, done.action.phase, done.result.data], ['succeeded', 'standing-policy', 'final', {id: 'L4'}]);
  assert.equal(done.approvalDigest, h.runtime.digest(done), 'the standing setting is bound to the final digest of exactly these bytes');
  assert.deepEqual(h.simulator.writes().map(call => call.body), [{name: 'Deploy key'}]);
  assert.doesNotThrow(() => h.runtime.assertAuthorization(done));
  assert.throws(() => h.runtime.assertAuthorization({...done, approvalDigest: '0'.repeat(64)}), error => error.code === 'approval_required', 'a standing Allow binds only these bytes');
  // Ask perform rows: a second, single-action approval of the final bytes. A job stored in phase final that skipped that stop (only the
  // reads were approved) refuses at dispatch with nothing sent.
  setOwn(h, 'keys-then-label v1', 'ask');
  const asked = await run(h, 'keys-then-label v1', {});
  const stopped = await h.runtime.approve(asked.id, asked.approvalDigest, h.owner);
  assert.deepEqual([stopped.status, stopped.action.phase], ['awaiting_approval', 'final']);
  const writes = h.simulator.writes().length;
  h.store.put('jobs', {...stopped, status: 'queued', approvedAt: new Date(h.now).toISOString(), approvedBy: 'single-action', action: {...stopped.action, approvedPhase: 'reads'}});
  const skipped = await h.runtime.execute(stopped.id);
  assert.deepEqual([skipped.status, h.simulator.writes().length], ['failed', writes]);
  // The Slack direct message, its own record at Allow: no stop at all.
  const s = slackHarness(t);
  s.permissions.set({connectionId: s.account, capabilityId: s.id, mode: 'allow'});
  const sent = await dm(s);
  assert.deepEqual([sent.status, sent.result.data], ['succeeded', {channel: 'DU2', ts: '1761210000.000200'}]);
  assert.deepEqual(s.script.calls.map(call => call.name), ['users.lookupByEmail', 'conversations.open', 'chat.postMessage', 'chat.getPermalink']);
  assert.equal(s.script.calls[2].body.text, 'Hello &lt;there&gt;');
});

test('part j: the resolving write: with the own record at Ask or the conversations.open row at Ask, the job stops before it with its exact bytes, bound by the digest', async t => {
  for (const variant of ['own', 'row']) {
    const ceilings = {}, s = slackHarness(t, {ceilingOf: (appId, groupId) => appId === 'slack' ? ceilings[groupId] ?? null : null});
    if (variant === 'row') { s.permissions.set({connectionId: s.account, capabilityId: s.id, mode: 'allow'}); ceilings['slack.conversations.mark'] = 'ask'; }
    const job = await dm(s);
    assert.deepEqual([job.status, job.action.phase, job.action.readsDone, s.script.calls.map(call => call.name)], ['awaiting_approval', 'reads', true, ['users.lookupByEmail']], variant);
    assert.deepEqual(job.action.resolving, {stepId: 'open', index: 0, method: 'POST', url: 'https://slack.com/api/conversations.open', headers: {},
      added: [{name: 'Authorization', value: '(added by Fabric, hidden)'}, {name: 'Accept', value: 'application/json'}, {name: 'Content-Type', value: 'application/json; charset=utf-8'}],
      bodySha256: sha('{"users":"U2"}'), bodyBytes: 14});
    const item = card(s.store, job);
    assert.equal(block(item, 'open: Body'), '{"users":"U2"}');
    assert.equal(block(item, 'person: Request'), 'GET https://slack.com/api/users.lookupByEmail?email=grace%40example.com', 'the read already sent, exactly');
    assert.notEqual(s.runtime.digest({...job, action: {...job.action, resolving: {...job.action.resolving, bodySha256: sha('{"users":"U3"}')}}}), job.approvalDigest);
    // A changed byte refuses: the approved entry says U3, Fabric would send U2.
    const tampered = {...job, action: {...job.action, resolving: {...job.action.resolving, bodySha256: sha('{"users":"U3"}')}}};
    tampered.approvalDigest = s.runtime.digest(tampered);
    s.store.put('jobs', tampered);
    const refused = await s.runtime.approve(job.id, tampered.approvalDigest, s.owner);
    assert.deepEqual([refused.status, refused.reason, s.script.writes().length], ['failed', 'prepared_changed', 0], variant);
  }
  // Untampered: approving sends conversations.open, then stops at the final bytes, whose body reads the channel it opened.
  const s = slackHarness(t), job = await dm(s), next = await s.runtime.approve(job.id, job.approvalDigest, s.owner);
  assert.deepEqual([next.status, next.action.phase, next.action.writesSent, s.script.writes().map(call => call.name)], ['awaiting_approval', 'final', ['open'], ['conversations.open']]);
  assert.equal(block(card(s.store, next), 'post: Body'), '{"channel":"DU2","text":"Hello &lt;there&gt;"}');
  assert.equal(block(card(s.store, next), 'Fields'), 'To: Grace Hopper\nMessage: Hello <there>');
});

test('part j: with an Ask prepare row a second phase reads stop shows the resolving write after the read; writesSent is persisted before the send', async t => {
  const s = slackHarness(t);
  s.setRow('slack.workspace.read', 'ask');
  const job = await dm(s);
  assert.deepEqual([job.action.phase, job.action.resolving, s.script.calls.length], ['reads', null, 0], 'its bytes are not known before the read');
  assert.deepEqual(card(s.store, job).exact.blocks.map(entry => entry.label), ['person: Request', 'person: Added by Fabric']);
  const second = await s.runtime.approve(job.id, job.approvalDigest, s.owner);
  assert.deepEqual([second.status, second.action.phase, second.action.resolving.stepId, s.script.calls.map(call => call.name)], ['awaiting_approval', 'reads', 'open', ['users.lookupByEmail']]);
  assert.equal(block(card(s.store, second), 'open: Body'), '{"users":"U2"}');
  let persisted = null;
  const send = s.script.request;
  s.runtime.request = async options => { if (/conversations\.open/.test(options.url)) persisted = s.store.get('jobs', job.id).action.writesSent; return send(options); };
  const final = await s.runtime.approve(job.id, second.approvalDigest, s.owner);
  assert.deepEqual([persisted, final.action.phase], [['open'], 'final']);
  assert.deepEqual(final.action.decisions.map(decision => decision.phase), ['reads', 'reads']);
});

test('part j: designated mode: the request, each stop\'s approval record and the 25-minute deadline validate; a phase 2 approval after its window is refused', async t => {
  const s = slackHarness(t, {designated: true});
  s.setRow('slack.workspace.read', 'ask');
  const job = await dm(s);
  const request = validateExecutionRequest(job.executionRequest);
  assert.equal(Date.parse(request.deadline) - Date.parse(request.createdAt), 25 * MINUTE);
  s.advance(MINUTE);
  const second = await s.runtime.approve(job.id, job.approvalDigest, s.owner);
  s.advance(MINUTE);
  const final = await s.runtime.approve(job.id, second.approvalDigest, s.owner);
  assert.equal(final.action.approvals.length, 2);
  for (const record of final.action.approvals) assert.doesNotThrow(() => validateApproval(record, {request, now: new Date(s.now).toISOString()}));
  assert.ok(Date.parse(final.approvalExpiresAt) <= Date.parse(request.deadline));
  s.advance(10 * MINUTE + 1000);
  await assert.rejects(s.runtime.approve(job.id, final.approvalDigest, s.owner), /Approval expired/);
  assert.deepEqual(s.script.writes().map(call => call.name), ['conversations.open']);
  // Within the window the final approval sends the message.
  const t2 = slackHarness(t, {designated: true}), quick = await dm(t2), opened = await t2.runtime.approve(quick.id, quick.approvalDigest, t2.owner);
  const sent = await t2.runtime.approve(quick.id, opened.approvalDigest, t2.owner);
  assert.deepEqual([sent.status, sent.action.approvals.length], ['succeeded', 2]);
});

test('part j: a long body shows as complete consecutive blocks with its sha256', async t => {
  const h = actionHarness(t), content = 'x'.repeat(150_000);
  const job = await run(h, 'put-file v1', {path: 'docs/long.md', content, message: 'Add', kind: 'file'});
  assert.deepEqual([job.status, job.action.phase], ['awaiting_approval', 'final']);
  const item = card(h.store, job), body = h.store.get(PREPARED, job.id).content.perform[0].body;
  const parts = item.exact.blocks.filter(entry => entry.label.startsWith('put: Body ('));
  assert.ok(parts.length >= 3 && parts.every(entry => entry.text.length <= EXACT_LIMIT));
  assert.equal(parts.map(entry => entry.text).join(''), body, 'nothing is cut');
  assert.equal(block(item, 'put: Body sha256'), sha(body));
  assert.deepEqual([item.exact.complete, Boolean(item.approve)], [true, true]);
});

test('part j: the new card sentence and both new warnings appear; validateCard() still refuses other text; a typed call keeps "Nothing has run yet."', () => {
  const origin = 'https://fabric.example.com', id = randomUUID(), expiresAt = '2026-10-23T09:10:00.000Z', now = Date.parse('2026-10-23T09:00:00.000Z');
  const view = prepared => ({id, status: 'awaiting_approval', approval: {url: `${origin}/approve/${id}`, expiresAt, ...(prepared ? {prepared: true} : {})}, updatedAt: '2026-10-23T09:00:00.000Z'});
  const names = {requesterName: 'Agent', appId: 'fixture', appName: 'Fixture', operationName: 'Send a draft', effect: 'write', origin, now};
  const action = callCard(view(true), names), typed = callCard(view(false), names);
  assert.equal(action.summary, 'Fabric prepared the exact request. Waiting for approval in Fabric.');
  assert.equal(typed.summary, 'Waiting for approval in Fabric. Nothing has run yet.');
  assert.equal(validateCard(action, {origin}), action);
  assert.throws(() => validateCard({...action, summary: 'Fabric prepared something. Approve it.', text: action.text.replace(action.summary, 'Fabric prepared something. Approve it.')}, {origin}), /not a valid Fabric card/);
  assert.equal(WARNINGS.prepares_first, 'Fabric runs these steps first. It shows you the exact final request before sending it.');
  assert.equal(WARNINGS.not_made_by_fabric, 'Fabric did not make this record, so it asks first.');
  const job = {id, status: 'awaiting_approval', kind: 'action', effect: 'write', approvalExpiresAt: expiresAt, approvalDigest: 'd', preview: {warnings: ['prepares_first', 'not_made_by_fabric', 'made_up', 'background_reads']}};
  assert.deepEqual(approvalItem(job).warnings, ['prepares_first', 'not_made_by_fabric'], 'a job never claims a watch\'s warning');
});

test('part j: on the runtime path a job that sent a perform write other than its resolving write never reaches awaiting_approval, and the contract refuses the same transition', async t => {
  const s = slackHarness(t), job = await dm(s);
  // A broken state: a perform write is already recorded as sent while the job waits before its resolving write.
  s.store.put('jobs', {...job, action: {...job.action, writesSent: ['post']}});
  const done = await s.runtime.approve(job.id, job.approvalDigest, s.owner);
  assert.deepEqual([done.status, done.errorCode, done.reason, done.action.phase], ['uncertain', 'outcome_uncertain', 'card_after_write', 'reads']);
  assert.equal(s.store.get(PREPARED, job.id), null, 'no card is stored');
  const context = writesSent => ({effect: 'write', kind: 'action', writesSent, resolvingStepId: 'open'});
  assert.doesNotThrow(() => assertStateTransition('running', 'awaiting_approval', context([])));
  assert.doesNotThrow(() => assertStateTransition('running', 'awaiting_approval', context(['open'])));
  for (const bad of [context(['post']), context(['open', 'post']), {...context([]), kind: 'typed'}]) {
    assert.throws(() => assertStateTransition('running', 'awaiting_approval', bad), error => error.code === 'invalid_transition');
  }
  assert.throws(() => assertStateTransition('running', 'awaiting_approval', {effect: 'write'}), error => error.code === 'invalid_contract');
  assert.throws(() => assertStateTransition('running', 'succeeded', context([])), error => error.code === 'invalid_contract', 'every other transition keeps {effect}');
  assert.doesNotThrow(() => assertStateTransition('running', 'succeeded', {effect: 'write'}));
});

test('part j: fail closed: a missing actionPrepared row and a tampered one each show no Approve on the owner\'s activity page and approval page', async t => {
  const h = actionHarness(t), job = await run(h, 'reschedule-event v1', {eventId: 'E1', start: '2026-10-29T10:00:00Z', end: '2026-10-29T10:30:00Z'});
  const row = h.store.get(PREPARED, job.id), now = h.now;
  const views = reader => [approvalItem(job, {prepared: reader}).approve, approvalPage(job, {prepared: reader, now}).approval.approve, activityPage({jobs: [job], prepared: reader, now}).approvals[0].approve];
  assert.ok(views(id => id === job.id ? row : null).every(Boolean), 'with its own prepared bytes, Approve is offered');
  const tampered = structuredClone(row);
  tampered.content.perform[0].body = tampered.content.perform[0].body.replace('10:00', '10:05');
  const otherPhase = {...structuredClone(row), content: {...structuredClone(row.content), phase: 'reads'}};
  for (const [name, reader] of [['no reader', undefined], ['missing', () => null], ['tampered', () => tampered], ['another phase', () => otherPhase]]) {
    assert.deepEqual(views(reader), [null, null, null], name);
    assert.equal(approvalItem(job, {prepared: reader}).exact.complete, false, `${name}: never falls back to the inputs`);
  }
  // The row is the job's own, unchanged, but the job now stands at another phase than the row: no Approve either.
  const moved = {...job, action: {...job.action, phase: 'reads'}};
  assert.deepEqual([approvalItem(moved, {prepared: () => row}).approve, approvalItem(moved, {prepared: () => row}).exact.complete], [null, false]);
  // The owner's server passes its reader: the approval route and the activity route fail closed the same way.
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-approval-app-')), port = await freePort();
  const app = await createApp({dataDir: dir, port, clock: () => now, request: async () => { throw new Error('no network in this test'); }});
  await app.start();
  t.after(async () => { await app.close(); rmSync(dir, {recursive: true, force: true}); });
  app.store.put('jobs', job);
  const approve = async () => {
    const page = await (await fetch(`${app.origin}/api/ui/approvals/${job.id}`)).json(), activity = await (await fetch(`${app.origin}/api/ui/activity`)).json();
    return [Boolean(page.approval?.approve), Boolean(activity.approvals[0]?.approve)];
  };
  assert.deepEqual(await approve(), [false, false], 'no row');
  app.store.put(PREPARED, row);
  assert.deepEqual(await approve(), [true, true]);
  app.store.put(PREPARED, tampered);
  assert.deepEqual(await approve(), [false, false], 'tampered');
});

test('part j: the workspace dialog shows an action\'s exact blocks from Fabric\'s approval page, never its prepared data, and Approve only when that page offers it', () => {
  const source = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8'), start = source.indexOf('async function actionApprovalDialog(job) {');
  const dialog = source.slice(start, source.indexOf('function jobDialog(job) {', start));
  assert.ok(start > 0 && source.includes("function jobDialog(job) {\n  if (job.kind === 'action' && job.status === 'awaiting_approval') return actionApprovalDialog(job);"));
  assert.match(dialog, /api\(`\/api\/ui\/approvals\/\$\{encodeURIComponent\(job\.id\)\}`\)/);
  assert.match(dialog, /describeApproval\(page\.approval\)/);
  assert.match(dialog, /if \(!model\?\.approve\)/);
  assert.ok(!/actionPrepared|preview|approvalDigest|jsonBlock/.test(dialog), 'never the stored prepared data, the preview or the job\'s own digest');
});

test('part j: choice inputs show "label (id)" from Fabric\'s own lookup read only; resource-dependent inputs show the fields as read; cancelling removes the prepared bytes', async t => {
  const h = actionHarness(t);
  setOwn(h, 'list-items v1', 'ask');
  const listed = await run(h, 'list-items v1', {kind: 'all', labelId: 'L2'});
  assert.equal(block(card(h.store, listed), 'Choices'), 'labelId: Work (L2)');
  // A lookup that answers another id names nothing: no label is shown that Fabric did not read for this value.
  h.simulator.fail('GET /labels/{label_id}', {status: 200, data: {id: 'L9', name: 'Other'}});
  const other = await run(h, 'list-items v1', {kind: 'all', labelId: 'L2'});
  assert.equal(block(card(h.store, other), 'Choices'), undefined);
  // Add a row: the table's fields, as read, and the prefix of their schema hash.
  h.simulator.data.items.push({id: 'T1', name: 'Costs', kind: 'table', labels: [], in_trash: false, updated: '2026-10-01T09:00:00.000Z', properties: {Name: {id: 'title', type: 'title'}}});
  const row = await run(h, 'add-row v1', {tableId: 'T1', values: {Name: 'Taxi'}});
  assert.equal(block(card(h.store, row), 'Resource fields'), `values: Fields as read at 2026-10-23T09:00:00.000Z (schema ${row.action.schemaHashes.values.slice(0, 12)})`);
  // Cancel at a stop: the job is cancelled and its prepared bytes are gone.
  assert.ok(h.store.get(PREPARED, row.id));
  const cancelled = h.runtime.cancel(row.id, h.owner);
  assert.deepEqual([cancelled.status, h.store.get(PREPARED, row.id)], ['cancelled', null]);
});

test('part j: designated mode: a window never passes the deadline, and a final dispatch without this stop\'s approval record is refused with nothing sent', async t => {
  const s = slackHarness(t, {designated: true});
  const job = await dm(s);
  s.advance(5 * MINUTE);
  const opened = await s.runtime.approve(job.id, job.approvalDigest, s.owner);
  assert.equal(Date.parse(opened.approvalExpiresAt), s.now + 10 * MINUTE);
  // Three stops, each approved near the end of its window: the third is made 18 minutes in, and ends at the deadline.
  const late = slackHarness(t, {designated: true});
  late.setRow('slack.workspace.read', 'ask');
  let slow = await dm(late);
  for (let stop = 0; stop < 2; stop++) { late.advance(9 * MINUTE); slow = await late.runtime.approve(slow.id, slow.approvalDigest, late.owner); }
  assert.deepEqual([slow.action.phase, Date.parse(slow.approvalExpiresAt)], ['final', Date.parse(slow.executionRequest.deadline)], 'min(now + 10 minutes, the deadline)');
  // The final stop queued as if approved, with the earlier stop's record removed: the accepted request needs this stop's approval.
  const before = s.script.writes().length;
  s.store.put('jobs', {...opened, status: 'queued', approvedAt: new Date(s.now).toISOString(), approvedBy: 'single-action', action: {...opened.action, approvedPhase: 'final'}, executionApproval: undefined});
  const refused = await s.runtime.execute(job.id);
  assert.deepEqual([refused.status, refused.error, s.script.writes().length], ['uncertain', 'An exact human approval is required.', before], 'conversations.open was sent in phase 1, so the job is uncertain; nothing more is sent');
});

test('part j: one card covers the reads and the resolving write when its bytes are known by then; a lapsed stop drops its prepared bytes', async t => {
  // A direct message to yourself: conversations.open reads {account: 'userId'}, known before any read, so the stop that shows the reads
  // shows it too, and its approval sends it with no second phase reads stop.
  const s = slackHarness(t, {change: action => ({...action, perform: [{...action.perform[0], body: {object: {users: {account: 'userId'}}}}, action.perform[1]]})});
  s.store.put('connections', {...s.store.get('connections', s.account), identity: {id: 'T1:U1', userId: 'U1'}});
  s.setRow('slack.workspace.read', 'ask');
  const job = await dm(s);
  assert.deepEqual([job.action.phase, job.action.reads.map(read => read.stepId), job.action.resolving?.bodySha256, s.script.calls.length], ['reads', ['person'], sha('{"users":"U1"}'), 0]);
  assert.deepEqual(card(s.store, job).exact.blocks.map(entry => entry.label), ['person: Request', 'person: Added by Fabric', 'open: Request', 'open: Added by Fabric', 'open: Body']);
  const next = await s.runtime.approve(job.id, job.approvalDigest, s.owner);
  assert.deepEqual([next.action.phase, next.action.writesSent, next.action.decisions.length], ['final', ['open'], 1], 'one stop covered both');
  // The final stop lapses: the attempt to approve it is refused and its prepared bytes go.
  s.advance(10 * MINUTE + 1000);
  await assert.rejects(s.runtime.approve(job.id, next.approvalDigest, s.owner), /Approval expired/);
  assert.equal(s.store.get(PREPARED, job.id), null);
  assert.deepEqual(s.script.writes().map(call => call.name), ['conversations.open']);
});

// ---- the F10.11 check (parts h to j) ---------------------------------------------------------------------------------------------------
test('part j: a known read is sent only with its approved bytes: a body byte, a header or a header Fabric adds that differs from the approved entry is not sent', async t => {
  for (const [name, change] of [['body', () => ({bodySha256: sha('{"query":"plaN"}')})], ['headers', () => ({headers: {'X-Fixture-Trace': '1'}})],
    ['added', read => ({added: [...read.added, {name: 'X-Fixture-Version', value: '2026-11'}]})]]) {
    const h = harness(t);
    setRow(h, 'fixture.items.read', 'ask');
    setOwn(h, 'find-then-label v1', 'ask');
    const job = await run(h, 'find-then-label v1', {query: 'plan'});
    // The approved entry of the reviewed-read search differs from what Fabric builds in one part only, and is approved as shown.
    const [search, item] = job.action.reads, tampered = {...job, action: {...job.action, reads: [{...search, ...change(search)}, item]}};
    tampered.approvalDigest = h.runtime.digest(tampered);
    h.store.put('jobs', tampered);
    const done = await h.runtime.approve(job.id, tampered.approvalDigest, h.owner);
    assert.deepEqual([done.status, done.errorCode, done.reason, h.simulator.calls.length], ['failed', 'fabric_failed', 'prepared_changed', 0], name);
  }
});

test('part j: the final card shows each perform request\'s own headers, so the owner sees the If-Match the write carries', async t => {
  const h = actionHarness(t), job = await run(h, 'reschedule-event v1', {eventId: 'E1', start: '2026-10-29T10:00:00Z', end: '2026-10-29T10:30:00Z'});
  const item = card(h.store, job);
  assert.deepEqual(item.exact.blocks.map(entry => entry.label), ['Fields', 'move: Request', 'move: Headers', 'move: Added by Fabric', 'move: Body']);
  assert.equal(block(item, 'move: Headers'), 'If-Match: "1"');
  assert.deepEqual(job.action.perform[0].headers, {'If-Match': '"1"'}, 'the headers the digest binds are the ones shown');
});

test('part j: a resource-dependent action under an Ask prepare row runs its schema read and the reads after it once approved, then stops at its final bytes', async t => {
  // Add a row with one more read after its schema step: the schema hash is bound by the final stop, not while the approved reads run.
  const h = actionHarness(t, {file: certifiedFile(file => { file.actions.find(action => action.key === 'add-row').prepare = [{id: 'labels', method: 'GET', path: '/labels', expect: OK}]; })});
  h.simulator.data.items.push({id: 'T1', name: 'Costs', kind: 'table', labels: [], in_trash: false, updated: '2026-10-01T09:00:00.000Z', properties: {Name: {id: 'title', type: 'title'}}});
  setRow(h, 'fixture.items.read', 'ask');
  const job = await run(h, 'add-row v1', {tableId: 'T1', values: {Name: 'Taxi'}});
  assert.deepEqual([job.status, job.action.phase, job.action.schemaHashes, job.action.reads.map(read => read.stepId)], ['awaiting_approval', 'reads', {}, ['table', 'labels']]);
  const next = await h.runtime.approve(job.id, job.approvalDigest, h.owner);
  assert.deepEqual([next.status, next.action.phase, h.simulator.calls.map(call => `${call.method} ${call.path}`)], ['awaiting_approval', 'final', ['GET /items/T1', 'GET /labels']], next.error);
  assert.match(next.action.schemaHashes.values, /^[0-9a-f]{64}$/);
  assert.notEqual(h.runtime.digest({...next, action: {...next.action, schemaHashes: {}}}), next.approvalDigest, 'the final stop binds the schema it read');
  const done = await h.runtime.approve(job.id, next.approvalDigest, h.owner);
  assert.deepEqual([done.status, h.simulator.writes().map(call => `${call.method} ${call.path}`)], ['succeeded', ['POST /items']], done.error);
});

test('part h: a stop nobody decided in time keeps no prepared bytes once the next action job is accepted', async t => {
  const h = actionHarness(t), event = {eventId: 'E1', start: '2026-10-29T10:00:00Z', end: '2026-10-29T10:30:00Z'};
  const lapsed = await run(h, 'reschedule-event v1', event), open = await run(h, 'reschedule-event v1', {...event, start: '2026-10-29T11:00:00Z', end: '2026-10-29T11:30:00Z'});
  assert.ok(h.store.get(PREPARED, lapsed.id) && h.store.get(PREPARED, open.id));
  h.advance(10 * MINUTE + 1000);
  h.store.put('jobs', {...open, approvalExpiresAt: new Date(h.now + MINUTE).toISOString()});
  const next = await run(h, 'reschedule-event v1', event);
  assert.deepEqual(h.store.list(PREPARED).map(row => row.id).sort(), [open.id, next.id].sort(), 'only stops that can still be approved keep their bytes');
  assert.equal(h.store.get('jobs', lapsed.id).status, 'awaiting_approval', 'the lapsed job itself is unchanged');
});

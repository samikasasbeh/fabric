import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, randomBytes} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {validateActionFile} from '../lib/actions.mjs';
import {ACTION_REFUSED, PREPARED, RUN_WORDS} from '../lib/actions-runtime.mjs';
import {STATUS_WORDS} from '../lib/action-catalog.mjs';
import {FabricProtocol} from '../lib/fabric-protocol.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {RULES, createGuard} from '../lib/live-guard.mjs';
import {checkPlan, fillPlaceholders} from '../lib/live-certify.mjs';
import {gmailHarness, gmailDeps, gmailFile, OWNER_EMAIL, MODIFY, TOKEN} from './fixtures/actions/gmail-harness.mjs';
import {ORIGIN} from './fixtures/provider-simulators/gmail.mjs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {actionSchema, withIds} from './fixtures/actions/fixture-app.mjs';

// F10.15 part 2 (docs/F10.15-BUILD-MAP.md section 3, part 2): Gmail's 13 reviewed actions (catalog/actions/gmail.json) on the Gmail simulator,
// through the action runtime, as an agent's call and the owner's approval run them; every case of Gmail's simulator case list
// (test/fixtures/provider-simulators/gmail.cases.json) through caseTests(); and the live plan G0 to G10 (catalog/live-tests/gmail.json) against
// step 12's plan check and, through the live guard, the simulator. Nothing here reaches Google. Every test reads the file with its ids
// recomputed (withIds()), so a seeded fault inside it is caught by what the action does; test/f10-15-churn.test.mjs checks the shipped ids.

const READ = {readOnly: true, destructive: false, idempotent: true, openWorld: true}, WRITE = {readOnly: false, destructive: false, idempotent: false, openWorld: true};
const PUT = {readOnly: false, destructive: false, idempotent: true, openWorld: true}, TRASH = {readOnly: false, destructive: true, idempotent: false, openWorld: true};
/** Section 2's table: each action's row, effect and hints. */
const TABLE = Object.freeze({
  'find-emails': ['gmail.messages.read', 'read', READ], 'read-email': ['gmail.messages.read', 'read', READ], 'read-conversation': ['gmail.messages.read', 'read', READ],
  'send-email': ['gmail.messages.send', 'write', WRITE], reply: ['gmail.messages.send', 'write', WRITE], 'create-draft': ['gmail.drafts.write', 'write', WRITE],
  'edit-draft': ['gmail.drafts.write', 'write', PUT], 'send-draft': ['gmail.messages.send', 'write', WRITE], 'organize-email': ['gmail.messages.mark', 'write', WRITE],
  'create-label': ['gmail.labels.manage', 'write', WRITE], 'move-to-trash': ['gmail.messages.trash', 'delete', TRASH], 'set-out-of-office': ['gmail.settings.write', 'write', PUT],
  'auto-label': ['gmail.settings.write', 'write', WRITE]});
const SEND = 'POST /messages/send', MESSAGE = 'GET /messages/{id}';
const sha256 = text => createHash('sha256').update(text).digest('hex');

/** Asserts how a job ended, and any of its fields. */
function ended(job, status, errorCode, extra = {}) {
  assert.deepEqual([job.status, job.errorCode ?? null], [status, errorCode], `${job.error} ${JSON.stringify(job.details ?? job.reason ?? '')}`);
  for (const [key, value] of Object.entries(extra)) assert.deepEqual(job[key], value, key);
  return job;
}
/** An action refusal: failed, action_refused, its reason (and transform) in details. */
const refusedAs = (job, reason) => { ended(job, 'failed', ACTION_REFUSED); assert.equal(job.details?.reason, reason, JSON.stringify(job.details)); return job; };
const writes = h => h.simulator.writes().map(call => `${call.method} ${call.path}`);
const calls = h => h.simulator.calls.map(call => `${call.method} ${call.path}`);
/** A write job prepared to its one card: awaiting the owner, phase final, nothing written yet. */
async function prepared(h, key, input) {
  const before = h.simulator.writes().length, job = await h.run(key, input);
  assert.deepEqual([job.status, job.action?.phase, h.simulator.writes().length], ['awaiting_approval', 'final', before], `${key}: ${job.error ?? ''} ${JSON.stringify(job.details ?? '')}`);
  return job;
}
const approved = async (h, key, input) => h.approve(await prepared(h, key, input));
/** The exact body a prepared job will send, parsed. */
const bodyOf = (h, job, index = 0) => JSON.parse(h.prepared(job).content.perform[index].body);
const urlOf = (h, job, index = 0) => new URL(h.prepared(job).content.perform[index].url);
/** A whole message, as Gmail's raw carries it: base64url of its header lines and body. */
const raw = (lines, body = 'Hello there.') => Buffer.from(`${lines.join('\r\n')}\r\n\r\n${body}\r\n`, 'utf8').toString('base64url');
/** The fields of a raw message, unfolded, and its body as the builder wrote it (base64 lines decoded). */
function decoded(text) {
  const message = Buffer.from(text, 'base64url').toString('utf8'), [head, body] = message.split('\r\n\r\n');
  const fields = Object.fromEntries(head.replace(/\r\n[ \t]/g, ' ').split('\r\n').map(line => [line.slice(0, line.indexOf(':')), line.slice(line.indexOf(':') + 2)]));
  return {fields, text: Buffer.from(body.replace(/\r\n/g, ''), 'base64').toString('utf8')};
}
/** Mail that arrives for the owner: from Ann unless the fields say otherwise. */
let mails = 0;
const mail = (h, fields = {}, body = 'Hello there.', labels) => h.simulator.deliver(raw(Object.entries({From: 'Ann <ann@example.com>', To: OWNER_EMAIL, Subject: 'Hello',
  'Message-ID': `<mail${++mails}@example.com>`, ...fields}).map(([name, value]) => `${name}: ${value}`), body), labels);
const NEW = {to: ['bob@example.com'], subject: 'Plan', text: 'See you at ten.'};
const stored = (h, id) => h.simulator.state().messages[id];

// ---- the file ---------------------------------------------------------------------------------------------------------------------------
/** Gmail's shipped file with each id recomputed from its content, as an author writes them. */
const currentFile = (deps = gmailDeps()) => withIds(gmailFile(), deps);

// F10.16 listed churn: step 16's live pass (run ISRREHKN) certified all 13, each naming the shipped evidence; that each names the hash of
// exactly its definition, with a passing record, is test/live-evidence.test.mjs's, so an edit of the file is caught here by what it breaks.
test('the file: 13 actions, each placed in its row with its effect and hints (section 2); each certified by step 16\'s evidence, no superseded id; userId pinned to me', () => {
  const file = currentFile(), {actions} = validateActionFile(file, gmailDeps());
  assert.deepEqual(actions.map(entry => entry.key), Object.keys(TABLE));
  for (const entry of actions) {
    const [row, effect, hints] = TABLE[entry.key];
    assert.deepEqual([entry.version, entry.row, entry.effect, entry.action.hints, entry.unplaced, entry.sensitive], [1, row, effect, hints, false, false], entry.key);
    assert.ok(entry.placements.every(placement => !placement.unplaced && placement.groupId.startsWith('gmail.')), entry.key);
    assert.equal(entry.placements.filter(placement => placement.phase === 'perform').at(-1).groupId, row, `${entry.key}: the last perform step lands in its row`);
    assert.deepEqual([Object.keys(entry.action.certified), entry.action.certified.evidence], [['evidence', 'definitionHash'], 'docs/live-evidence/gmail/actions.json'], `${entry.key}: certified by step 16's evidence`);
  }
  assert.deepEqual([file.specVersion, file.pinnedParameters, file.superseded, ['candidate', 'reviewed'].includes(file.reviewStatus)], ['fabric/0.2', {userId: 'me'}, undefined, true]);
  const schema = actionSchema();
  assert.ok(schema(file), JSON.stringify(schema.errors));
  // At most 27 requests: Organize email on 25 messages (the labels, the batchModify and 25 readbacks).
  const organize = actions.find(entry => entry.key === 'organize-email');
  assert.deepEqual(organize.paths.map(item => [item.value, item.perform, item.verify]), [['messages', ['batch'], ['check']], ['thread', ['modify'], ['checkThread']]]);
  // Every message an action sends is built from the account's own address, never one an agent names.
  for (const entry of actions.filter(item => item.transforms.includes('rfc5322.build@1'))) assert.match(JSON.stringify(entry.action.perform), /"from":\{"object":\{"address":\{"account":"email"\}\}\}/, entry.key);
});

test('without Google\'s map the file validates as 13 unplaced actions and is never refused (no action is a reviewed-read POST)', () => {
  const {actions} = validateActionFile(currentFile(), gmailDeps({map: null}));
  assert.deepEqual(actions.map(entry => [entry.key, entry.unplaced]), Object.keys(TABLE).map(key => [key, true]));
});

test('at start without live evidence: 13 candidates that never run and that no agent can be given', async t => {
  const h = gmailHarness(t, {evidence: false});
  assert.deepEqual([...h.catalog.entries.values()].map(item => [item.status, item.reason]), Array(13).fill(['candidate', STATUS_WORDS.evidence]));
  assert.ok(h.store.list('capabilities').filter(capability => capability.driver === 'action').every(capability => capability.status === 'candidate'));
  await assert.rejects(h.run('find-emails v1', {maxResults: 5}));
  const protocol = new FabricProtocol({store: h.store, runtime: h.runtime, clock: () => h.now, origin: 'http://127.0.0.1:59996'});
  assert.throws(() => protocol.createClient({name: 'Gmail agent', bindings: [{connectionId: h.account, capabilityId: h.idOf('find-emails v1')}]}, null), {code: 'permission_denied'});
  assert.deepEqual([h.simulator.calls.length, h.store.list('clientGrants').length], [0, 0]);
});

// ---- spec lines 1111 to 1121 ---------------------------------------------------------------------------------------------------------------
test('spec line 1111: a subject of "Hi\\r\\nBcc: x@evil" refuses header_injection before any request, in every action that builds a message', async t => {
  const h = gmailHarness(t), draft = h.simulator.seedDraft(raw([`To: ${OWNER_EMAIL}`, 'Subject: Mine']));
  const evil = {...NEW, subject: 'Hi\r\nBcc: x@evil'};
  for (const [key, input] of [['send-email v1', evil], ['create-draft v1', evil]]) {
    const job = refusedAs(await h.run(key, input), 'header_injection');
    assert.equal(job.details.transform, 'rfc5322.build@1', key);
  }
  assert.deepEqual(h.simulator.calls, [], 'refused before any request');
  // Edit draft reads the draft first; the build refuses before the write.
  refusedAs(await h.run('edit-draft v1', {draftId: draft.id, ...evil}), 'header_injection');
  assert.deepEqual(writes(h), []);
});

test('spec line 1112: Reply sets threadId, In-Reply-To and References; To is the parent\'s Reply-To; reply-all drops the owner in any letter case and keeps everyone else', async t => {
  const h = gmailHarness(t);
  const parent = mail(h, {'Reply-To': 'list@example.org', To: `Bob <bob@example.com>, ${OWNER_EMAIL.toUpperCase()}`, Cc: 'cy@example.com, Owner@Example.com',
    'Message-ID': '<p1@example.com>', References: '<p0@example.com>'});
  const all = await prepared(h, 'reply v1', {messageId: parent.id, replyAll: true, text: 'Thanks, all.'});
  const body = bodyOf(h, all), sent = decoded(body.raw);
  assert.equal(body.threadId, parent.threadId);
  assert.deepEqual([sent.fields.From, sent.fields.To, sent.fields.Cc, sent.fields.Subject, sent.fields['In-Reply-To'], sent.fields.References, sent.text],
    [OWNER_EMAIL, 'list@example.org, Bob <bob@example.com>', 'cy@example.com', 'Re: Hello', '<p1@example.com>', '<p0@example.com> <p1@example.com>', 'Thanks, all.']);
  const done = ended(await h.approve(all), 'succeeded', null);
  assert.deepEqual([done.result.data.threadId, stored(h, done.result.data.id).threadId, done.result.verification.status], [parent.threadId, parent.threadId, 'verified']);
  assert.deepEqual(h.simulator.deliveries().map(item => item.to).sort(), ['bob@example.com', 'cy@example.com', 'list@example.org']);
  // Without reply-all, only the Reply-To.
  const one = await prepared(h, 'reply v1', {messageId: parent.id, replyAll: false, text: 'Thanks.'});
  assert.deepEqual([decoded(bodyOf(h, one).raw).fields.To, decoded(bodyOf(h, one).raw).fields.Cc], ['list@example.org', undefined]);
});

test('spec line 1113: Organize refuses SENT, DRAFT, TRASH and SPAM, by name or id in any case, and an unknown name, after the labels read and before any write; it never creates a label', async t => {
  const h = gmailHarness(t), message = mail(h);
  const labels = () => h.simulator.state().labels;
  for (const [name, reason] of [['SENT', 'label_system'], ['draft', 'label_system'], ['Trash', 'label_system'], ['spam', 'label_system'], ['Receipts', 'label_unknown']]) {
    for (const side of ['addLabels', 'removeLabels']) {
      const before = h.simulator.calls.length;
      const job = refusedAs(await h.run('organize-email v1', {target: 'messages', messageIds: [message.id], addLabels: [], removeLabels: [], [side]: [name]}), reason);
      assert.equal(job.details.transform, 'collections.labelIds@1');
      assert.deepEqual(h.simulator.calls.slice(before).map(call => `${call.method} ${call.path}`), ['GET /labels'], `${name} in ${side}: the labels read, nothing else`);
    }
  }
  refusedAs(await h.run('organize-email v1', {target: 'thread', threadId: message.threadId, addLabels: ['TRASH'], removeLabels: []}), 'label_system');
  assert.deepEqual([writes(h), labels()], [[], {}], 'nothing written, no label created');
});

test('spec line 1114: the out-of-office start must be before the end (time_window, reason window_order) with nothing sent; the body carries epoch-millisecond strings', async t => {
  const h = gmailHarness(t), on = {enable: true, contactsOnly: true, subject: 'Away', text: 'Back on Tuesday.', start: '2026-11-02T09:00:00-05:00', end: '2026-11-03T09:00:00-05:00'};
  for (const end of ['2026-11-02T09:00:00-05:00', '2026-11-01T09:00:00-05:00']) {
    const job = refusedAs(await h.run('set-out-of-office v1', {...on, end}), 'time_window');
    assert.deepEqual([job.details.transform, job.details.transformReason], ['time.window@1', 'window_order']);
  }
  assert.deepEqual(h.simulator.calls, [], 'nothing sent, the settings read included');
  const job = await prepared(h, 'set-out-of-office v1', on);
  assert.deepEqual(bodyOf(h, job), {enableAutoReply: true, responseSubject: 'Away', responseBodyPlainText: 'Back on Tuesday.', restrictToContacts: true,
    startTime: String(Date.parse('2026-11-02T14:00:00Z')), endTime: String(Date.parse('2026-11-03T14:00:00Z'))});
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.data, h.simulator.state().vacation.startTime], [{enabled: true, contactsOnly: true, subject: 'Away', start: '2026-11-02T14:00:00.000Z',
    end: '2026-11-03T14:00:00.000Z'}, String(Date.parse('2026-11-02T14:00:00Z'))]);
  // Off sends only {enableAutoReply: false}, the one off form the live guard passes; off takes nothing else.
  const off = await prepared(h, 'set-out-of-office v1', {enable: false});
  assert.deepEqual(bodyOf(h, off), {enableAutoReply: false});
  ended(await h.approve(off), 'succeeded', null);
  for (const input of [{enable: false, contactsOnly: true}, {enable: false, subject: 'Away'}, {...on, start: undefined}, (({text, ...rest}) => rest)(on)]) {
    refusedAs(await h.run('set-out-of-office v1', JSON.parse(JSON.stringify(input))), 'wrong_kind');
  }
});

test('spec line 1115: the approval binds the sha256 of raw: the job\'s perform summary holds the body\'s sha256, and a body changed after approval is not sent', async t => {
  const h = gmailHarness(t), job = await prepared(h, 'send-email v1', NEW);
  const row = h.prepared(job), body = row.content.perform[0].body;
  assert.equal(job.action.perform[0].bodySha256, sha256(body));
  assert.ok(JSON.parse(body).raw.length > 100);
  // The stored bytes are changed after the card was shown: another recipient in raw.
  row.content.perform[0].body = JSON.stringify({raw: raw(['From: owner@example.com', 'To: eve@example.com', 'Subject: Plan'])});
  h.store.put(PREPARED, row);
  ended(await h.approve(job), 'failed', 'fabric_failed', {reason: 'prepared_changed', error: RUN_WORDS.prepared_changed});
  assert.deepEqual([writes(h), h.simulator.deliveries()], [[], []]);
});

test('spec line 1116: Send reads back the same id with SENT; a readback without SENT, or a swallowed send, ends unverified', async t => {
  const h = gmailHarness(t);
  const done = ended(await approved(h, 'send-email v1', NEW), 'succeeded', null);
  assert.deepEqual([done.result.verification.status, h.simulator.calls.at(-1).path, h.simulator.calls.at(-1).query], ['verified', `/messages/${done.result.data.id}`, {format: 'minimal'}]);
  // The readback finds the message, but without SENT.
  const job = await prepared(h, 'send-email v1', NEW), gate = h.simulator.hold(MESSAGE), pending = h.approve(job);
  await gate.reached;
  const sent = h.simulator.calls.filter(call => call.route === SEND).at(-1);
  assert.ok(sent);
  for (const message of Object.values(h.simulator.data.messages)) if (message.labelIds.includes('SENT') && message.seq === Math.max(...Object.values(h.simulator.data.messages).map(item => item.seq))) message.labelIds = ['INBOX'];
  gate.release();
  const unlabelled = ended(await pending, 'uncertain', 'outcome_uncertain');
  assert.equal(unlabelled.result.verification.status, 'unverified');
  h.simulator.swallow(SEND);
  const swallowed = ended(await approved(h, 'send-email v1', NEW), 'uncertain', 'outcome_uncertain');
  assert.equal(swallowed.result.verification.status, 'unverified');
});

test('spec line 1117, critique test 3: Send draft prepared on v1, the draft edited to v2 before approval, sends v1 as {id, message: {raw}}; the draft is gone', async t => {
  const h = gmailHarness(t), v1 = raw([`From: ${OWNER_EMAIL}`, 'To: bob@example.com', 'Subject: Plan'], 'Version one.');
  const draft = h.simulator.seedDraft(v1);
  const job = await prepared(h, 'send-draft v1', {draftId: draft.id});
  const prepared_ = bodyOf(h, job), read = h.simulator.calls.find(call => call.route === 'GET /drafts/{id}');
  assert.deepEqual(read.query, {format: 'raw'});
  h.simulator.editDraft(draft.id, raw([`From: ${OWNER_EMAIL}`, 'To: eve@example.com', 'Subject: Plan'], 'Version two.'));
  const done = ended(await h.approve(job), 'succeeded', null);
  const send = h.simulator.calls.find(call => call.route === 'POST /drafts/send');
  assert.deepEqual(send.body, {id: draft.id, message: {raw: prepared_.message.raw}});
  assert.equal(Buffer.from(send.body.message.raw, 'base64url').toString('utf8'), Buffer.from(v1, 'base64url').toString('utf8'));
  assert.deepEqual(h.simulator.deliveries().map(item => item.to), ['bob@example.com'], 'v1 went out, to v1\'s recipient');
  assert.ok(Buffer.from(h.simulator.deliveries()[0].raw, 'base64url').toString('utf8').includes('Version one.'));
  assert.deepEqual([done.result.verification.status, h.simulator.calls.at(-1).status, h.simulator.state().drafts], ['verified', 404, {}]);
});

test('Send draft reads the draft back gone: a draft that is still there after the send ends unverified', async t => {
  const h = gmailHarness(t), draft = h.simulator.seedDraft(raw([`From: ${OWNER_EMAIL}`, 'To: bob@example.com', 'Subject: Plan'], 'Version one.'));
  const job = await prepared(h, 'send-draft v1', {draftId: draft.id}), gate = h.simulator.hold('GET /drafts/{id}'), pending = h.approve(job);
  await gate.reached;
  // The send went out; the draft comes back before the readback (Gmail kept it, or the owner saved it again).
  const sent = h.simulator.calls.find(call => call.route === 'POST /drafts/send' && call.status === 200);
  assert.ok(sent);
  h.simulator.data.drafts[draft.id] = Object.keys(h.simulator.data.messages)[0];
  gate.release();
  const done = ended(await pending, 'uncertain', 'outcome_uncertain');
  assert.deepEqual([done.result.verification.status, h.simulator.calls.at(-1).status], ['unverified', 200]);
});

test('Send draft\'s card shows the whole message as sent, so no recipient hides past a cut (T4, T5); a draft longer than a card shows whole (50,000 characters) is refused before the send', async t => {
  const h = gmailHarness(t), long = count => Array.from({length: count}, (_, index) => `${'a'.repeat(230)}${index}@example.com`);
  // A draft an agent made at Allow, with no card: 50 addresses of about 245 characters in To put its Bcc past character 12,000 of the message.
  const made = ended(await h.run('create-draft v1', {to: long(50), bcc: ['collector@example.net'], subject: 'Numbers', text: 'The numbers.'}), 'succeeded', null);
  const job = await prepared(h, 'send-draft v1', {draftId: made.result.data.id}), message = Buffer.from(bodyOf(h, job).message.raw, 'base64url').toString('utf8');
  assert.ok(message.indexOf('\r\nBcc: collector@example.net\r\n') > 12_000);
  assert.equal(h.fields(job)['Message as sent'], message, 'the card shows the message whole, Bcc included');
  // A draft the card cannot show whole is refused after the draft read and before any write; it is never cut.
  const big = h.simulator.seedDraft(raw([`From: ${OWNER_EMAIL}`, 'To: bob@example.com', 'Subject: Long'], 'w'.repeat(60_000)));
  const refused = refusedAs(await h.run('send-draft v1', {draftId: big.id}), 'wrong_kind');
  assert.deepEqual([refused.details.transform, refused.details.transformReason], ['collections.oneOf@1', 'not_one_of']);
  assert.deepEqual([writes(h), h.simulator.deliveries(), Object.hasOwn(h.simulator.state().drafts, big.id)], [['POST /drafts'], [], true]);
});

test('spec line 1118, critique test 4: with "Access emails" at Ask, Reply stops at phase reads, then its final card shows the recipients taken from Reply-To', async t => {
  const h = gmailHarness(t), parent = mail(h, {'Reply-To': 'Desk <desk@example.org>', 'Message-ID': '<p2@example.com>'});
  h.setRow('gmail.messages.read', 'ask');
  const reads = await h.run('reply v1', {messageId: parent.id, replyAll: false, text: 'On it.'});
  assert.deepEqual([reads.status, reads.action.phase, h.simulator.calls.length], ['awaiting_approval', 'reads', 0]);
  const final = await h.approve(reads);
  assert.deepEqual([final.status, final.action.phase, h.simulator.writes().length], ['awaiting_approval', 'final', 0]);
  assert.deepEqual([h.fields(final).To, h.fields(final)['In reply to']], ['desk@example.org', 'ann@example.com']);
  ended(await h.approve(final), 'succeeded', null);
  assert.deepEqual(h.simulator.deliveries().map(item => item.to), ['desk@example.org']);
});

test('spec line 1119 (D3): Edit draft on a draft Create draft made runs at Allow with no card; on any other draft it asks, even with its own record at Allow, and the card says so', async t => {
  const h = gmailHarness(t);
  const made = ended(await h.run('create-draft v1', NEW), 'succeeded', null);
  assert.deepEqual([made.action.modes, made.result.data.to, made.result.data.subject], [{prepare: 'allow', resolve: null, perform: 'allow'}, ['bob@example.com'], 'Plan']);
  const edited = ended(await h.run('edit-draft v1', {draftId: made.result.data.id, ...NEW, subject: 'Plan 2'}), 'succeeded', null);
  assert.deepEqual([edited.action.askUnless, edited.result.verification.status], [false, 'verified']);
  const hand = h.simulator.seedDraft(raw([`To: ${OWNER_EMAIL}`, 'Bcc: boss@example.com', 'Subject: Mine'], 'Written in Gmail.'));
  h.allow('edit-draft v1');
  const job = await prepared(h, 'edit-draft v1', {draftId: hand.id, ...NEW});
  assert.deepEqual([job.action.askUnless, job.action.modes.perform], [true, 'ask']);
  assert.ok(h.card(job).warnings.includes('not_made_by_fabric'));
  assert.match(h.fields(job)['Draft now'], /^To: owner@example\.com\r\nBcc: boss@example\.com\r\nSubject: Mine\r\n/, 'the card shows the draft as it is, every header');
  ended(await h.approve(job), 'succeeded', null);
  assert.equal(decoded(h.simulator.calls.find(call => call.method === 'PUT' && call.path === `/drafts/${hand.id}`).body.message.raw).fields.Subject, 'Plan');
});

test('spec line 1120: more than 100 addresses in a field refuse before any call; a parent with 501 recipients refuses Reply-all after the parent read and before the send', async t => {
  const h = gmailHarness(t), many = count => Array.from({length: count}, (_, index) => `p${index}@example.com`);
  await assert.rejects(h.run('send-email v1', {...NEW, to: many(101)}));
  await assert.rejects(h.run('create-draft v1', {...NEW, bcc: many(101)}));
  assert.deepEqual(h.simulator.calls, []);
  const parent = mail(h, {To: many(300).join(', '), Cc: many(501).slice(300).join(', '), 'Message-ID': '<big@example.com>'});
  const job = refusedAs(await h.run('reply v1', {messageId: parent.id, replyAll: true, text: 'Hi all.'}), 'too_many_recipients');
  assert.equal(job.details.transform, 'rfc5322.replyHeaders@1');
  assert.deepEqual([calls(h), writes(h)], [[`GET /messages/${parent.id}`], []]);
  // The builder holds the same cap: 100 + 100 + 100 is within it.
  ended(await approved(h, 'send-email v1', {...NEW, to: many(100), cc: many(200).slice(100), bcc: many(300).slice(200)}), 'succeeded', null);
});

test('spec line 1121: each of Google\'s limit answers ends failed with the limited words and the provider status, never retried; any other 403 keeps the failed words', async t => {
  for (const [kind, status] of [['tooManyRequests', 429], ['dailyLimitExceeded', 403], ['userRateLimitExceeded', 403], ['rateLimitExceeded', 403]]) {
    const h = gmailHarness(t);
    h.simulator.limit(SEND, kind);
    const job = ended(await approved(h, 'send-email v1', NEW), 'failed', 'provider_failed', {providerStatus: status, reason: 'http_status', error: RUN_WORDS.limited});
    assert.equal(job.result, null);
    assert.deepEqual([h.simulator.calls.filter(call => call.route === SEND).length, h.simulator.deliveries()], [1, []], `${kind}: one send, never retried`);
    // A limit on a read before any write: the same words.
    const read = gmailHarness(t);
    read.simulator.limit('GET /messages', kind);
    ended(await read.run('find-emails v1', {maxResults: 5}), 'failed', 'provider_failed', {providerStatus: status, error: RUN_WORDS.limited});
  }
  const h = gmailHarness(t);
  h.simulator.fail(SEND, {status: 403, data: {error: {code: 403, message: 'Forbidden', errors: [{domain: 'global', reason: 'forbidden', message: 'Forbidden'}], status: 'PERMISSION_DENIED'}}});
  ended(await approved(h, 'send-email v1', NEW), 'failed', 'provider_failed', {providerStatus: 403, error: RUN_WORDS.failed});
  // A limit reason in another app's answer is not Gmail's: Calendar keeps its own words (open question 6).
  h.simulator.fail(SEND, {status: 403, data: {error: {code: 403, message: 'No', errors: [{domain: 'usageLimits', reason: 'quotaExceeded', message: 'No'}]}}});
  ended(await approved(h, 'send-email v1', NEW), 'failed', 'provider_failed', {providerStatus: 403, error: RUN_WORDS.failed});
});

// ---- modes and access (T8) ----------------------------------------------------------------------------------------------------------------
const SETTINGS_READ = 'gmail.labels.read';
test('modes: reads run at Allow with no card; Create draft and Create label at Allow; every other write asks once; a Never row refuses before any call', async t => {
  const h = gmailHarness(t), message = mail(h);
  for (const [key, input] of [['find-emails v1', {maxResults: 5}], ['read-email v1', {messageId: message.id}], ['read-conversation v1', {threadId: message.threadId}]]) {
    const job = ended(await h.run(key, input), 'succeeded', null);
    assert.deepEqual([job.action.modes, job.action.approvals, [...h.runtime.writeLocks]], [{prepare: 'allow', resolve: null, perform: 'allow'}, [], []], key);
  }
  for (const [key, input] of [['create-draft v1', NEW], ['create-label v1', {name: 'Receipts'}]]) ended(await h.run(key, input), 'succeeded', null);
  const draft = h.simulator.seedDraft(raw([`To: ${OWNER_EMAIL}`, 'Subject: Mine']));
  for (const [key, input] of [['send-email v1', NEW], ['reply v1', {messageId: message.id, replyAll: false, text: 'Hi.'}], ['send-draft v1', {draftId: draft.id}],
    ['edit-draft v1', {draftId: draft.id, ...NEW}], ['organize-email v1', {target: 'messages', messageIds: [message.id], addLabels: ['Receipts'], removeLabels: []}],
    ['move-to-trash v1', {move: 'trash-message', messageId: message.id}], ['set-out-of-office v1', {enable: false}], ['auto-label v1', {from: 'news@example.com', label: 'Receipts'}]]) {
    const job = await prepared(h, key, input);
    assert.deepEqual([job.action.modes.prepare, job.action.modes.perform], ['allow', 'ask'], key);
  }
  // "Access labels, filters and settings" at Never: every action that reads labels or settings is refused before any call (T8).
  const never = gmailHarness(t);
  never.setRow(SETTINGS_READ, 'deny');
  for (const [key, input] of [['organize-email v1', {target: 'thread', threadId: 't', addLabels: [], removeLabels: []}], ['create-label v1', {name: 'Receipts'}],
    ['auto-label v1', {from: 'news@example.com', label: 'Receipts'}], ['set-out-of-office v1', {enable: false}]]) {
    await assert.rejects(never.run(key, input), error => error.code === 'permission_denied' || /Never/.test(error.message), key);
  }
  assert.equal(never.simulator.calls.length, 0);
  ended(await never.run('find-emails v1', {maxResults: 5}), 'succeeded', null);
});

test('without gmail.settings.basic, Set out-of-office and Auto-label refuse as needing more access before any request; the other 11 run', async t => {
  const h = gmailHarness(t, {scopes: [MODIFY]}), message = mail(h), draft = h.simulator.seedDraft(raw([`To: ${OWNER_EMAIL}`, 'Subject: Mine']));
  for (const [key, input] of [['set-out-of-office v1', {enable: false}], ['auto-label v1', {from: 'news@example.com', label: 'INBOX'}]]) {
    await assert.rejects(h.run(key, input), /does not have a required provider scope/, key);
  }
  assert.equal(h.simulator.calls.length, 0);
  const inputs = {'find-emails v1': {maxResults: 5}, 'read-email v1': {messageId: message.id}, 'read-conversation v1': {threadId: message.threadId}, 'send-email v1': NEW,
    'reply v1': {messageId: message.id, replyAll: false, text: 'Hi.'}, 'create-draft v1': NEW, 'edit-draft v1': {draftId: draft.id, ...NEW}, 'send-draft v1': {draftId: draft.id},
    'organize-email v1': {target: 'messages', messageIds: [message.id], addLabels: [], removeLabels: ['UNREAD']}, 'create-label v1': {name: 'Receipts'},
    'move-to-trash v1': {move: 'trash-message', messageId: message.id}};
  for (const [key, input] of Object.entries(inputs)) {
    const job = await h.run(key, input);
    assert.ok(['succeeded', 'awaiting_approval'].includes(job.status), `${key}: ${job.status} ${job.error}`);
  }
});

// ---- the reads ------------------------------------------------------------------------------------------------------------------------------
test('Find emails: an empty search succeeds with no messages; 25 a page with nextPageToken; times reach the query as epoch seconds; a quote in a value refuses; maxResults is 1 to 25', async t => {
  const h = gmailHarness(t);
  const none = ended(await h.run('find-emails v1', {maxResults: 25, words: 'nothing like this'}), 'succeeded', null);
  assert.deepEqual([none.result.data, calls(h)], [{}, ['GET /messages']], 'no messages, and no message read');
  for (let index = 0; index < 30; index++) { mail(h, {Subject: `Report ${index}`, From: 'Desk <desk@example.org>'}); h.advance(1000); }
  const first = ended(await h.run('find-emails v1', {maxResults: 25, from: 'desk@example.org'}), 'succeeded', null);
  assert.deepEqual([first.result.data.messages.length, typeof first.result.data.nextPageToken, first.result.data.messages[0]], [25, 'string',
    {id: first.result.data.messages[0].id, threadId: first.result.data.messages[0].id, from: 'desk@example.org', subject: 'Report 29', date: undefined, snippet: 'Hello there.', labelIds: ['INBOX', 'UNREAD']}].map(item => item === undefined ? item : JSON.parse(JSON.stringify(item))));
  const meta = h.simulator.calls.filter(call => call.route === MESSAGE).at(-1);
  assert.deepEqual(meta.query, {format: 'metadata', metadataHeaders: ['From', 'To', 'Subject', 'Date']});
  const second = ended(await h.run('find-emails v1', {maxResults: 25, from: 'desk@example.org', pageToken: first.result.data.nextPageToken}), 'succeeded', null);
  assert.deepEqual([second.result.data.messages.length, second.result.data.nextPageToken], [5, undefined]);
  ended(await h.run('find-emails v1', {maxResults: 5, subject: 'Report', after: '2026-10-26T09:00:10-04:00', before: '2026-10-26T13:00:20Z', hasAttachment: false, label: 'INBOX', to: 'owner'}), 'succeeded', null);
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /messages').at(-1).query.q,
    `from:"desk@example.org" to:"owner" subject:"Report" label:"INBOX" -has:attachment after:${Date.parse('2026-10-26T13:00:10Z') / 1000} before:${Date.parse('2026-10-26T13:00:20Z') / 1000}`.replace('from:"desk@example.org" ', ''));
  const sent = h.simulator.calls.length;
  refusedAs(await h.run('find-emails v1', {maxResults: 5, words: 'x" OR in:trash "y'}), 'query_value_invalid');
  for (const maxResults of [0, 26]) await assert.rejects(h.run('find-emails v1', {maxResults}));
  await assert.rejects(h.run('find-emails v1', {}), 'maxResults is required');
  assert.equal(h.simulator.calls.length, sent, 'refused before any call');
});

test('Read email: plain text when there is some, else the HTML as text, each cut at 100,000; attachments listed, never fetched; Read conversation reads oldest first and refuses past 50', async t => {
  const h = gmailHarness(t);
  const plain = mail(h, {Cc: 'Cy <cy@example.com>', 'Reply-To': 'desk@example.org', Date: 'Mon, 26 Oct 2026 09:00:00 -0400'}, 'x'.repeat(100_010));
  const read = ended(await h.run('read-email v1', {messageId: plain.id}), 'succeeded', null).result.data;
  assert.deepEqual([read.from, read.to, read.cc, read.replyTo, read.subject, read.date, [...read.text].length, read.truncated, read.htmlText, read.attachments],
    [['ann@example.com'], [OWNER_EMAIL], ['cy@example.com'], ['desk@example.org'], 'Hello', 'Mon, 26 Oct 2026 09:00:00 -0400', 100_000, true, undefined, []]);
  assert.match(read.text, /\n\[truncated\]$/);
  const boundary = 'b1';
  const html = mail(h, {'Content-Type': `multipart/mixed; boundary="${boundary}"`}, [`--${boundary}`, 'Content-Type: text/html; charset=UTF-8', '', '<p>Hi <b>there</b></p><script>x()</script>',
    `--${boundary}`, 'Content-Type: application/pdf; name="invoice.pdf"', 'Content-Disposition: attachment; filename="invoice.pdf"', 'Content-Transfer-Encoding: base64', '', 'JVBERi0xLjQ=', `--${boundary}--`].join('\r\n'));
  const second = ended(await h.run('read-email v1', {messageId: html.id}), 'succeeded', null).result.data;
  assert.deepEqual([second.text, second.htmlText, second.truncated, second.attachments], [undefined, 'Hi there', undefined, [{filename: 'invoice.pdf', mimeType: 'application/pdf', size: 8}]]);
  assert.ok(!calls(h).some(route => route.includes('/attachments/')), 'attachments are never fetched');
  // A conversation, oldest first; past 50 messages it refuses each_too_long.
  const thread = mail(h, {'Message-ID': '<t0@example.com>', Subject: 'Thread'});
  for (let index = 1; index <= 50; index++) { h.advance(1000); mail(h, {'Message-ID': `<t${index}@example.com>`, 'In-Reply-To': `<t${index - 1}@example.com>`, Subject: 'Re: Thread'}, `Reply ${index}`); }
  assert.equal(Object.values(h.simulator.state().messages).filter(item => item.threadId === thread.threadId).length, 51);
  refusedAs(await h.run('read-conversation v1', {threadId: thread.threadId}), 'each_too_long');
  const short = mail(h, {'Message-ID': '<s0@example.com>', Subject: 'Short'}, 'First.');
  mail(h, {'Message-ID': '<s1@example.com>', 'In-Reply-To': '<s0@example.com>', Subject: 'Re: Short', From: 'bob@example.com'}, 'y'.repeat(2100));
  const conversation = ended(await h.run('read-conversation v1', {threadId: short.threadId}), 'succeeded', null).result.data;
  assert.deepEqual(conversation.messages.map(item => [item.from, item.subject, [...item.text].length, item.truncated]), [['ann@example.com', 'Short', 8, undefined], ['bob@example.com', 'Re: Short', 2000, true]]);
});

// ---- writes -------------------------------------------------------------------------------------------------------------------------------------
test('Create label finds a label in any letter case and creates nothing, and creates a new name once', async t => {
  const h = gmailHarness(t);
  const made = ended(await h.run('create-label v1', {name: 'Receipts'}), 'succeeded', null);
  assert.deepEqual([made.result.data, writes(h)], [{id: 'Label_1', name: 'Receipts', created: true}, ['POST /labels']]);
  assert.deepEqual(h.simulator.writes()[0].body, {name: 'Receipts', labelListVisibility: 'labelShow', messageListVisibility: 'show'});
  for (const name of ['receipts', 'RECEIPTS', ' Receipts'.trim()]) {
    const found = ended(await h.run('create-label v1', {name}), 'succeeded', null);
    assert.deepEqual([found.result.data, found.result.verification.status], [{id: 'Label_1', name: 'Receipts'}, 'verified'], name);
  }
  assert.equal(writes(h).length, 1, 'never a second label');
  ended(await h.run('create-label v1', {name: 'Travel'}), 'succeeded', null);
  assert.deepEqual(Object.values(h.simulator.state().labels).map(label => label.name), ['Receipts', 'Travel']);
});

test('Move to trash or restore: each of the four paths reads its own write back, TRASH present or absent; the card says Gmail empties Trash after 30 days', async t => {
  const h = gmailHarness(t), first = mail(h, {'Message-ID': '<m0@example.com>'});
  h.advance(1000);
  mail(h, {'Message-ID': '<m1@example.com>', 'In-Reply-To': '<m0@example.com>', Subject: 'Re: Hello'});
  const trash = await prepared(h, 'move-to-trash v1', {move: 'trash-message', messageId: first.id});
  assert.deepEqual(h.fields(trash), {Move: 'trash-message', Message: first.id, Subject: 'Hello', Trash: 'Gmail deletes mail in Trash for good after 30 days.'});
  assert.ok(h.card(trash).warnings.includes('delete'));
  for (const [move, input, route, holds] of [['trash-message', {messageId: first.id}, `/messages/${first.id}/trash`, true], ['restore-message', {messageId: first.id}, `/messages/${first.id}/untrash`, false],
    ['trash-thread', {threadId: first.threadId}, `/threads/${first.threadId}/trash`, true], ['restore-thread', {threadId: first.threadId}, `/threads/${first.threadId}/untrash`, false]]) {
    const done = ended(await approved(h, 'move-to-trash v1', {move, ...input}), 'succeeded', null);
    assert.deepEqual([done.result.verification.status, writes(h).at(-1), h.simulator.writes().at(-1).body], ['verified', `POST ${route}`, undefined], move);
    const labels = Object.values(h.simulator.state().messages).filter(item => input.messageId ? item.id === first.id : item.threadId === first.threadId).map(item => item.labelIds.includes('TRASH'));
    assert.ok(labels.length && labels.every(item => item === holds), move);
  }
  // Each path checks its own outcome: a swallowed restore of the conversation leaves TRASH, which its readback sees.
  ended(await approved(h, 'move-to-trash v1', {move: 'trash-thread', threadId: first.threadId}), 'succeeded', null);
  h.simulator.swallow('POST /threads/{id}/untrash');
  const swallowed = ended(await approved(h, 'move-to-trash v1', {move: 'restore-thread', threadId: first.threadId}), 'uncertain', 'outcome_uncertain');
  assert.equal(swallowed.result.verification.status, 'unverified');
  // The id must match the move: a message move takes messageId and a conversation move threadId.
  for (const input of [{move: 'trash-message', threadId: first.threadId}, {move: 'trash-thread', messageId: first.id}, {move: 'restore-message'}, {move: 'trash-message', messageId: first.id, threadId: first.threadId}]) {
    refusedAs(await h.run('move-to-trash v1', input), 'wrong_kind');
  }
});

test('Organize email changes labels on the messages, or on every message of a conversation, and each path reads its own change back; a swallowed change ends unverified', async t => {
  const h = gmailHarness(t), first = mail(h, {'Message-ID': '<o0@example.com>'});
  mail(h, {'Message-ID': '<o1@example.com>', 'In-Reply-To': '<o0@example.com>', Subject: 'Re: Hello'});
  ended(await h.run('create-label v1', {name: 'Receipts'}), 'succeeded', null);
  const job = await prepared(h, 'organize-email v1', {target: 'messages', messageIds: [first.id], addLabels: ['receipts', 'STARRED'], removeLabels: ['UNREAD', 'inbox']});
  assert.deepEqual(bodyOf(h, job), {ids: [first.id], addLabelIds: ['Label_1', 'STARRED'], removeLabelIds: ['UNREAD', 'INBOX']});
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.data, stored(h, first.id).labelIds], [{added: ['Label_1', 'STARRED'], removed: ['UNREAD', 'INBOX']}, ['Label_1', 'STARRED']]);
  const thread = ended(await approved(h, 'organize-email v1', {target: 'thread', threadId: first.threadId, addLabels: [], removeLabels: ['Receipts']}), 'succeeded', null);
  assert.deepEqual([thread.result.verification.status, writes(h).at(-1)], ['verified', `POST /threads/${first.threadId}/modify`]);
  assert.ok(Object.values(h.simulator.state().messages).every(item => !item.labelIds.includes('Label_1')));
  // A removal only, swallowed: the readback still holds the label, so the removal check ends it unverified.
  for (const [route, input] of [['POST /messages/batchModify', {target: 'messages', messageIds: [first.id], addLabels: [], removeLabels: ['STARRED']}],
    ['POST /threads/{id}/modify', {target: 'thread', threadId: first.threadId, addLabels: [], removeLabels: ['UNREAD']}],
    ['POST /threads/{id}/modify', {target: 'thread', threadId: first.threadId, addLabels: ['Receipts'], removeLabels: []}]]) {
    h.simulator.swallow(route);
    const swallowed = ended(await approved(h, 'organize-email v1', input), 'uncertain', 'outcome_uncertain');
    assert.equal(swallowed.result.verification.status, 'unverified', route);
  }
  for (const input of [{target: 'messages', threadId: first.threadId}, {target: 'thread', messageIds: [first.id]}, {target: 'messages'}]) {
    refusedAs(await h.run('organize-email v1', {addLabels: [], removeLabels: [], ...input}), 'wrong_kind');
  }
});

test('Auto-label: the filter adds one of your labels and never holds a forward; TRASH and an unknown label refuse before any write', async t => {
  const h = gmailHarness(t);
  ended(await h.run('create-label v1', {name: 'News'}), 'succeeded', null);
  const job = await prepared(h, 'auto-label v1', {from: 'news@example.com', label: 'news'});
  assert.deepEqual(bodyOf(h, job), {criteria: {from: 'news@example.com'}, action: {addLabelIds: ['Label_1']}});
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.data.from, done.result.data.labelId, done.result.verification.status], ['news@example.com', 'Label_1', 'verified']);
  assert.ok(!JSON.stringify(h.simulator.writes()).includes('forward'));
  for (const [label, reason] of [['TRASH', 'label_system'], ['spam', 'label_system'], ['Unknown', 'label_unknown']]) refusedAs(await h.run('auto-label v1', {from: 'x@example.com', label}), reason);
  assert.equal(writes(h).length, 2);
});

// ---- cards --------------------------------------------------------------------------------------------------------------------------------------
test('every card\'s lines, whole: what each write sends, every recipient, and the mail as it is now', async t => {
  const h = gmailHarness(t), card = async (key, input) => h.fields(await prepared(h, key, input));
  const parent = mail(h, {'Reply-To': 'desk@example.org', To: `${OWNER_EMAIL}, bob@example.com`, Cc: 'cy@example.com', 'Message-ID': '<c1@example.com>'});
  const text = 'z'.repeat(10_000);
  assert.deepEqual(await card('send-email v1', {to: ['bob@example.com', 'cy@example.com'], cc: ['dan@example.com'], bcc: ['eve@example.com'], subject: 'Plan', text}),
    {From: OWNER_EMAIL, To: 'bob@example.com\ncy@example.com', Cc: 'dan@example.com', Bcc: 'eve@example.com', Subject: 'Plan', Text: text});
  assert.deepEqual(await card('reply v1', {messageId: parent.id, replyAll: true, text: 'Noted.'}),
    {From: OWNER_EMAIL, To: 'desk@example.org\nbob@example.com', Cc: 'cy@example.com', Subject: 'Re: Hello', 'In reply to': 'ann@example.com', Text: 'Noted.'});
  h.permissions.set({connectionId: h.account, capabilityId: h.idOf('create-draft v1'), mode: 'ask'});
  assert.deepEqual(await card('create-draft v1', NEW), {From: OWNER_EMAIL, To: 'bob@example.com', Cc: '', Bcc: '', Subject: 'Plan', Text: 'See you at ten.'});
  const draft = h.simulator.seedDraft(raw([`From: ${OWNER_EMAIL}`, 'To: bob@example.com', 'Reply-To: eve@example.com', 'Subject: Mine'], 'Draft text.'));
  const message = Buffer.from(raw([`From: ${OWNER_EMAIL}`, 'To: bob@example.com', 'Reply-To: eve@example.com', 'Subject: Mine'], 'Draft text.'), 'base64url').toString('utf8');
  assert.deepEqual(await card('edit-draft v1', {draftId: draft.id, ...NEW}), {'Draft now': message, From: OWNER_EMAIL, To: 'bob@example.com', Cc: '', Bcc: '', Subject: 'Plan', Text: 'See you at ten.'});
  assert.deepEqual(await card('send-draft v1', {draftId: draft.id}), {'Message as sent': message, Subject: 'Mine', Text: 'Draft text.\r\n', Attachments: 0});
  const longRaw = raw([`From: ${OWNER_EMAIL}`, 'To: bob@example.com', 'Subject: Long'], 'w'.repeat(12_000)), long = h.simulator.seedDraft(longRaw);
  const cut = await card('send-draft v1', {draftId: long.id});
  assert.deepEqual([[...cut.Text].length, cut.Text.endsWith('\n[truncated]'), cut['Message as sent']], [10_000, true, Buffer.from(longRaw, 'base64url').toString('utf8')]);
  ended(await h.run('create-label v1', {name: 'Receipts'}), 'succeeded', null);
  assert.deepEqual(await card('organize-email v1', {target: 'messages', messageIds: [parent.id, 'other'], addLabels: ['receipts'], removeLabels: ['UNREAD', 'INBOX']}),
    {'Labels to add': 'Receipts', 'Labels to remove': 'UNREAD\nINBOX', Messages: `${parent.id}\nother`});
  assert.deepEqual(await card('organize-email v1', {target: 'thread', threadId: parent.threadId, addLabels: [], removeLabels: []}),
    {'Labels to add': '', 'Labels to remove': '', Messages: '', Conversation: parent.threadId});
  assert.deepEqual(await card('move-to-trash v1', {move: 'trash-thread', threadId: parent.threadId}),
    {Move: 'trash-thread', Conversation: parent.threadId, Subject: 'Hello', Trash: 'Gmail deletes mail in Trash for good after 30 days.'});
  assert.deepEqual(await card('set-out-of-office v1', {enable: true, contactsOnly: false, subject: 'Away', text: 'Back Monday.', start: '2026-11-02T09:00:00-05:00', end: '2026-11-03T09:00:00-05:00'}),
    {'Auto-reply now': 'off', 'Auto-reply': 'on', 'Who gets the reply': 'Everyone who writes to you', Starts: '2026-11-02T09:00:00-05:00', Ends: '2026-11-03T09:00:00-05:00', Subject: 'Away', Text: 'Back Monday.'});
  h.simulator.data.vacation = {enableAutoReply: true, responseSubject: 'Gone fishing', restrictToContacts: true};
  assert.deepEqual(await card('set-out-of-office v1', {enable: false}), {'Auto-reply now': 'on', 'Subject now': 'Gone fishing', 'Auto-reply': 'off', 'Who gets the reply': ''});
  assert.deepEqual(await card('auto-label v1', {from: 'news@example.com', label: 'Receipts'}),
    {'When mail is from': 'news@example.com', 'Apply label': 'Receipts', 'To remove it': 'Delete the filter under "Delete drafts, labels or filters".'});
  // A read that asks shows what it reads.
  h.setRow('gmail.messages.read', 'ask');
  const find = await h.run('find-emails v1', {maxResults: 5, subject: 'Hello', after: '2026-10-26T00:00:00Z'});
  assert.deepEqual([find.status, h.fields(find)], ['awaiting_approval', {Search: `subject:"Hello" after:${Date.parse('2026-10-26T00:00:00Z') / 1000}`, Messages: 5}]);
  assert.deepEqual(h.fields(await h.run('read-email v1', {messageId: parent.id})), {Message: parent.id});
  assert.deepEqual(h.fields(await h.run('read-conversation v1', {threadId: parent.threadId})), {Conversation: parent.threadId});
  assert.deepEqual(writes(h), ['POST /labels'], 'nothing sent before an approval but the label made at Allow');
});

// ---- secrets and evidence ----------------------------------------------------------------------------------------------------------------------
test('credentials never reach a job, a prepared request, a card, an audit row or an output; evidence and stores stay under the temp root', async t => {
  const shipped = new URL('../docs/live-evidence/gmail/actions.json', import.meta.url), before = existsSync(shipped) ? readFileSync(shipped, 'utf8') : null;
  const h = gmailHarness(t), message = mail(h, {Subject: `Token ${TOKEN} end`});
  const read = ended(await h.run('read-email v1', {messageId: message.id}), 'succeeded', null);
  // A body Gmail carries as base64 is decoded by a transform, and a transform output that would hold the credential refuses the read.
  refusedAs(await h.run('read-email v1', {messageId: mail(h, {}, `Body ${TOKEN} end`).id}), 'credential_in_request');
  const job = await prepared(h, 'send-email v1', NEW);
  const card = h.card(job), done = ended(await h.approve(job), 'succeeded', null);
  for (const [name, value] of [['jobs', h.store.list('jobs')], ['prepared', h.store.list(PREPARED)], ['card', card], ['audit', h.store.list('activity')], ['outputs', [read.result, done.result]]]) {
    assert.ok(!JSON.stringify(value).includes(TOKEN), name);
  }
  assert.equal(read.result.data.subject, 'Token [redacted] end', 'the token an answer echoes is scrubbed before anything reads it');
  assert.ok(existsSync(`${h.root}/docs/live-evidence/gmail/actions.json`));
  assert.equal(existsSync(shipped) ? readFileSync(shipped, 'utf8') : null, before, 'the shipped evidence is never written by a test');
});

test('difference 14: a credential typed into an email\'s text, which rfc5322.build@1 nests two base64 layers deep in raw, refuses credential_in_request in every action that builds a message; nothing is sent', async t => {
  const h = gmailHarness(t), text = `Here it is: ${TOKEN} end`;
  const draft = ended(await h.run('create-draft v1', NEW), 'succeeded', null).result.data.id, parent = mail(h, {'Message-ID': '<p3@example.com>'});
  const before = writes(h);
  // Send email asks: the owner sees its card, and the check at dispatch refuses after the approval.
  const send = await prepared(h, 'send-email v1', {...NEW, text});
  refusedAs(await h.approve(send), 'credential_in_request');
  refusedAs(await h.run('create-draft v1', {...NEW, text}), 'credential_in_request');
  refusedAs(await h.run('edit-draft v1', {draftId: draft, ...NEW, text}), 'credential_in_request');
  refusedAs(await h.run('reply v1', {messageId: parent.id, replyAll: false, text}), 'credential_in_request');
  assert.deepEqual([writes(h), h.simulator.deliveries()], [before, []], 'nothing sent');
});

test('difference 15: a credential in a subject that rfc5322.build@1 writes as encoded-words, at every place the words can split it, refuses credential_in_request; nothing is sent', async t => {
  const h = gmailHarness(t), before = writes(h);
  for (let lead = 0; lead <= 24; lead++) {
    const subject = `${'é'.repeat(lead)}${TOKEN} fin`;
    refusedAs(await h.run('create-draft v1', {...NEW, subject}), 'credential_in_request');
  }
  const send = await prepared(h, 'send-email v1', {...NEW, subject: `${'é'.repeat(9)}${TOKEN} fin`});
  refusedAs(await h.approve(send), 'credential_in_request');
  assert.deepEqual([writes(h), h.simulator.deliveries()], [before, []], 'nothing sent');
});

// ---- the simulator case list (check 5) --------------------------------------------------------------------------------------------------------
const MANIFEST = JSON.parse(readFileSync(new URL('./fixtures/provider-simulators/gmail.cases.json', import.meta.url), 'utf8'));
const ENTRIES = validateActionFile(currentFile(), gmailDeps()).actions;
const GOOGLE_ERROR = (code, reason) => ({status: code, data: {error: {code, message: reason, errors: [{domain: 'global', reason, message: reason}]}}});
const ROUTES = {send: SEND, drafts: 'POST /drafts', put: 'PUT /drafts/{id}', sendDraft: 'POST /drafts/send', batch: 'POST /messages/batchModify', labels: 'POST /labels',
  trash: 'POST /messages/{id}/trash', vacation: 'PUT /settings/vacation', filters: 'POST /settings/filters'};
const lost = async (h, route, key, input) => { h.simulator.drop(route); return ended(await approved(h, key, input), 'uncertain', 'outcome_uncertain'); };
const swallowed = async (h, route, key, input) => { h.simulator.swallow(route); const job = ended(await approved(h, key, input), 'uncertain', 'outcome_uncertain'); assert.equal(job.result.verification.status, 'unverified'); return job; };
const ran = async (h, key, input) => ended(await h.run(key, input), 'succeeded', null);
const refusedNever = async (h, row, key, input) => {
  h.setRow(row, 'deny');
  await assert.rejects(h.run(key, input), error => error.code === 'permission_denied' || /Never/.test(error.message));
  assert.equal(h.simulator.calls.length, 0);
};
const ON = {enable: true, contactsOnly: true, subject: 'Away', text: 'Back soon.', start: '2026-11-02T09:00:00-05:00', end: '2026-11-03T09:00:00-05:00'};
/** A harness with one message from Ann and a draft the owner wrote, and their ids. */
function stocked(t) {
  const h = gmailHarness(t), message = mail(h, {'Message-ID': '<k1@example.com>'}), draft = h.simulator.seedDraft(raw([`From: ${OWNER_EMAIL}`, 'To: bob@example.com', 'Subject: Mine']));
  return {h, message, draft};
}
const IMPLEMENTATIONS = {
  'find-emails v1/succeeds': async t => { const {h, message} = stocked(t); assert.equal((await ran(h, 'find-emails v1', {maxResults: 5})).result.data.messages.find(item => item.id === message.id).subject, 'Hello'); },
  'find-emails v1/refused': async t => { const h = gmailHarness(t); refusedAs(await h.run('find-emails v1', {maxResults: 5, from: 'a"b'}), 'query_value_invalid'); assert.equal(h.simulator.calls.length, 0); },
  'find-emails v1/provider-refusal': async t => { const h = gmailHarness(t); h.simulator.fail('GET /messages', GOOGLE_ERROR(400, 'invalidArgument')); ended(await h.run('find-emails v1', {maxResults: 5}), 'failed', 'provider_failed', {providerStatus: 400}); },
  'read-email v1/succeeds': async t => { const {h, message} = stocked(t); assert.equal((await ran(h, 'read-email v1', {messageId: message.id})).result.data.text, 'Hello there.\r\n'); },
  'read-email v1/refused': async t => { const {h, message} = stocked(t); await refusedNever(h, 'gmail.messages.read', 'read-email v1', {messageId: message.id}); },
  'read-email v1/provider-refusal': async t => { const h = gmailHarness(t); ended(await h.run('read-email v1', {messageId: 'missing'}), 'failed', 'provider_failed', {providerStatus: 404}); },
  'read-conversation v1/succeeds': async t => { const {h, message} = stocked(t); assert.equal((await ran(h, 'read-conversation v1', {threadId: message.threadId})).result.data.messages.length, 1); },
  'read-conversation v1/refused': async t => { const {h, message} = stocked(t); await refusedNever(h, 'gmail.messages.read', 'read-conversation v1', {threadId: message.threadId}); },
  'read-conversation v1/provider-refusal': async t => { const h = gmailHarness(t); ended(await h.run('read-conversation v1', {threadId: 'missing'}), 'failed', 'provider_failed', {providerStatus: 404}); },
  'send-email v1/succeeds': async t => { const h = gmailHarness(t); ended(await approved(h, 'send-email v1', NEW), 'succeeded', null); assert.deepEqual(h.simulator.deliveries().map(item => item.to), ['bob@example.com']); },
  'send-email v1/refused': async t => { const h = gmailHarness(t); refusedAs(await h.run('send-email v1', {...NEW, subject: 'A\nBcc: eve@example.com'}), 'header_injection'); assert.equal(h.simulator.calls.length, 0); },
  'send-email v1/provider-refusal': async t => { const h = gmailHarness(t); h.simulator.fail(ROUTES.send, GOOGLE_ERROR(400, 'invalidArgument')); ended(await approved(h, 'send-email v1', NEW), 'failed', 'provider_failed', {providerStatus: 400}); assert.deepEqual(h.simulator.deliveries(), []); },
  'send-email v1/unverified': async t => swallowed(gmailHarness(t), ROUTES.send, 'send-email v1', NEW),
  'send-email v1/lost-answer': async t => { const h = gmailHarness(t); await lost(h, ROUTES.send, 'send-email v1', NEW); assert.equal(h.simulator.deliveries().length, 1, 'applied'); },
  'reply v1/succeeds': async t => { const {h, message} = stocked(t); ended(await approved(h, 'reply v1', {messageId: message.id, replyAll: false, text: 'Thanks.'}), 'succeeded', null); },
  'reply v1/refused': async t => { const {h} = stocked(t); const parent = mail(h, {'Message-ID': 'not an id'}); refusedAs(await h.run('reply v1', {messageId: parent.id, replyAll: false, text: 'Hi.'}), 'message_id_invalid'); assert.deepEqual(writes(h), []); },
  'reply v1/provider-refusal': async t => { const h = gmailHarness(t); ended(await h.run('reply v1', {messageId: 'missing', replyAll: false, text: 'Hi.'}), 'failed', 'provider_failed', {providerStatus: 404}); },
  'reply v1/unverified': async t => { const {h, message} = stocked(t); await swallowed(h, ROUTES.send, 'reply v1', {messageId: message.id, replyAll: false, text: 'Thanks.'}); },
  'reply v1/lost-answer': async t => { const {h, message} = stocked(t); await lost(h, ROUTES.send, 'reply v1', {messageId: message.id, replyAll: false, text: 'Thanks.'}); },
  'create-draft v1/succeeds': async t => { const h = gmailHarness(t); assert.equal((await ran(h, 'create-draft v1', NEW)).result.verification.status, 'verified'); },
  'create-draft v1/refused': async t => { const h = gmailHarness(t); await refusedNever(h, 'gmail.drafts.write', 'create-draft v1', NEW); },
  'create-draft v1/provider-refusal': async t => { const h = gmailHarness(t); h.simulator.fail(ROUTES.drafts, GOOGLE_ERROR(403, 'forbidden')); ended(await h.run('create-draft v1', NEW), 'failed', 'provider_failed', {providerStatus: 403}); assert.deepEqual(h.simulator.state().drafts, {}); },
  'create-draft v1/unverified': async t => { const h = gmailHarness(t); h.simulator.swallow(ROUTES.drafts); const job = ended(await h.run('create-draft v1', NEW), 'uncertain', 'outcome_uncertain'); assert.deepEqual([job.result.verification.status, h.store.list('actionRecords')], ['unverified', []]); },
  'create-draft v1/lost-answer': async t => { const h = gmailHarness(t); h.simulator.drop(ROUTES.drafts); ended(await h.run('create-draft v1', NEW), 'uncertain', 'outcome_uncertain'); assert.equal(Object.keys(h.simulator.state().drafts).length, 1, 'applied'); },
  'edit-draft v1/succeeds': async t => { const {h, draft} = stocked(t); ended(await approved(h, 'edit-draft v1', {draftId: draft.id, ...NEW}), 'succeeded', null); },
  'edit-draft v1/refused': async t => { const {h, draft} = stocked(t); refusedAs(await h.run('edit-draft v1', {draftId: draft.id, ...NEW, subject: 'A\r\nTo: eve@example.com'}), 'header_injection'); assert.deepEqual(writes(h), []); },
  'edit-draft v1/provider-refusal': async t => { const h = gmailHarness(t); ended(await h.run('edit-draft v1', {draftId: 'r404', ...NEW}), 'failed', 'provider_failed', {providerStatus: 404}); },
  'edit-draft v1/unverified': async t => { const {h, draft} = stocked(t); await swallowed(h, ROUTES.put, 'edit-draft v1', {draftId: draft.id, ...NEW}); },
  'edit-draft v1/lost-answer': async t => { const {h, draft} = stocked(t); await lost(h, ROUTES.put, 'edit-draft v1', {draftId: draft.id, ...NEW}); },
  'send-draft v1/succeeds': async t => { const {h, draft} = stocked(t); ended(await approved(h, 'send-draft v1', {draftId: draft.id}), 'succeeded', null); },
  'send-draft v1/refused': async t => {
    const h = gmailHarness(t), html = h.simulator.seedDraft(raw([`From: ${OWNER_EMAIL}`, 'To: bob@example.com', 'Subject: Html', 'Content-Type: text/html; charset=UTF-8'], '<p>Hi</p>'));
    refusedAs(await h.run('send-draft v1', {draftId: html.id}), 'wrong_kind');
    assert.deepEqual(writes(h), []);
  },
  'send-draft v1/provider-refusal': async t => { const h = gmailHarness(t); ended(await h.run('send-draft v1', {draftId: 'r404'}), 'failed', 'provider_failed', {providerStatus: 404}); },
  'send-draft v1/unverified': async t => { const {h, draft} = stocked(t); await swallowed(h, ROUTES.sendDraft, 'send-draft v1', {draftId: draft.id}); },
  'send-draft v1/lost-answer': async t => { const {h, draft} = stocked(t); await lost(h, ROUTES.sendDraft, 'send-draft v1', {draftId: draft.id}); assert.deepEqual(h.simulator.state().drafts, {}, 'applied'); },
  'organize-email v1/succeeds': async t => { const {h, message} = stocked(t); ended(await approved(h, 'organize-email v1', {target: 'messages', messageIds: [message.id], addLabels: ['STARRED'], removeLabels: ['UNREAD']}), 'succeeded', null); },
  'organize-email v1/refused': async t => { const {h, message} = stocked(t); refusedAs(await h.run('organize-email v1', {target: 'messages', messageIds: [message.id], addLabels: ['TRASH'], removeLabels: []}), 'label_system'); },
  'organize-email v1/provider-refusal': async t => { const h = gmailHarness(t); ended(await approved(h, 'organize-email v1', {target: 'messages', messageIds: ['missing'], addLabels: ['STARRED'], removeLabels: []}), 'failed', 'provider_failed', {providerStatus: 404}); },
  'organize-email v1/unverified': async t => { const {h, message} = stocked(t); await swallowed(h, ROUTES.batch, 'organize-email v1', {target: 'messages', messageIds: [message.id], addLabels: ['STARRED'], removeLabels: []}); },
  'organize-email v1/lost-answer': async t => { const {h, message} = stocked(t); await lost(h, ROUTES.batch, 'organize-email v1', {target: 'messages', messageIds: [message.id], addLabels: ['STARRED'], removeLabels: []}); },
  'create-label v1/succeeds': async t => { const h = gmailHarness(t); assert.equal((await ran(h, 'create-label v1', {name: 'Receipts'})).result.data.created, true); },
  'create-label v1/refused': async t => { const h = gmailHarness(t); await refusedNever(h, 'gmail.labels.manage', 'create-label v1', {name: 'Receipts'}); },
  'create-label v1/provider-refusal': async t => { const h = gmailHarness(t); h.simulator.fail(ROUTES.labels, GOOGLE_ERROR(409, 'alreadyExists')); ended(await h.run('create-label v1', {name: 'Receipts'}), 'failed', 'provider_failed', {providerStatus: 409}); },
  'create-label v1/unverified': async t => { const h = gmailHarness(t); h.simulator.swallow(ROUTES.labels); const job = ended(await h.run('create-label v1', {name: 'Receipts'}), 'uncertain', 'outcome_uncertain'); assert.equal(job.result.verification.status, 'unverified'); },
  'create-label v1/lost-answer': async t => { const h = gmailHarness(t); h.simulator.drop(ROUTES.labels); ended(await h.run('create-label v1', {name: 'Receipts'}), 'uncertain', 'outcome_uncertain'); },
  'move-to-trash v1/succeeds': async t => { const {h, message} = stocked(t); ended(await approved(h, 'move-to-trash v1', {move: 'trash-message', messageId: message.id}), 'succeeded', null); },
  'move-to-trash v1/refused': async t => { const {h, message} = stocked(t); refusedAs(await h.run('move-to-trash v1', {move: 'trash-thread', messageId: message.id}), 'wrong_kind'); assert.equal(h.simulator.calls.length, 0); },
  'move-to-trash v1/provider-refusal': async t => {
    const {h, message} = stocked(t);
    h.simulator.fail(ROUTES.trash, GOOGLE_ERROR(403, 'forbidden'));
    ended(await approved(h, 'move-to-trash v1', {move: 'trash-message', messageId: message.id}), 'failed', 'provider_failed', {providerStatus: 403});
    assert.ok(!stored(h, message.id).labelIds.includes('TRASH'));
  },
  'move-to-trash v1/unverified': async t => { const {h, message} = stocked(t); await swallowed(h, ROUTES.trash, 'move-to-trash v1', {move: 'trash-message', messageId: message.id}); },
  'move-to-trash v1/lost-answer': async t => { const {h, message} = stocked(t); await lost(h, ROUTES.trash, 'move-to-trash v1', {move: 'trash-message', messageId: message.id}); assert.ok(stored(h, message.id).labelIds.includes('TRASH')); },
  'set-out-of-office v1/succeeds': async t => { const h = gmailHarness(t); ended(await approved(h, 'set-out-of-office v1', ON), 'succeeded', null); },
  'set-out-of-office v1/refused': async t => { const h = gmailHarness(t); refusedAs(await h.run('set-out-of-office v1', {...ON, start: ON.end, end: ON.start}), 'time_window'); assert.equal(h.simulator.calls.length, 0); },
  'set-out-of-office v1/provider-refusal': async t => { const h = gmailHarness(t); h.simulator.fail(ROUTES.vacation, GOOGLE_ERROR(400, 'failedPrecondition')); ended(await approved(h, 'set-out-of-office v1', ON), 'failed', 'provider_failed', {providerStatus: 400}); },
  'set-out-of-office v1/unverified': async t => swallowed(gmailHarness(t), ROUTES.vacation, 'set-out-of-office v1', ON),
  'set-out-of-office v1/lost-answer': async t => { const h = gmailHarness(t); await lost(h, ROUTES.vacation, 'set-out-of-office v1', ON); assert.equal(h.simulator.state().vacation.enableAutoReply, true); },
  'auto-label v1/succeeds': async t => { const h = gmailHarness(t); ended(await approved(h, 'auto-label v1', {from: 'news@example.com', label: 'STARRED'}), 'succeeded', null); },
  'auto-label v1/refused': async t => { const h = gmailHarness(t); refusedAs(await h.run('auto-label v1', {from: 'news@example.com', label: 'TRASH'}), 'label_system'); assert.deepEqual(writes(h), []); },
  'auto-label v1/provider-refusal': async t => { const h = gmailHarness(t); h.simulator.fail(ROUTES.filters, GOOGLE_ERROR(400, 'failedPrecondition')); ended(await approved(h, 'auto-label v1', {from: 'news@example.com', label: 'STARRED'}), 'failed', 'provider_failed', {providerStatus: 400}); },
  'auto-label v1/unverified': async t => swallowed(gmailHarness(t), ROUTES.filters, 'auto-label v1', {from: 'news@example.com', label: 'STARRED'}),
  'auto-label v1/lost-answer': async t => { const h = gmailHarness(t); await lost(h, ROUTES.filters, 'auto-label v1', {from: 'news@example.com', label: 'STARRED'}); assert.equal(Object.keys(h.simulator.state().filters).length, 1); },
};
caseTests(test, MANIFEST, ENTRIES, IMPLEMENTATIONS);

// ---- the live plan (step 16's G0 to G10) ---------------------------------------------------------------------------------------------------------
const PLAN = () => JSON.parse(readFileSync(new URL('../catalog/live-tests/gmail.json', import.meta.url), 'utf8'));
const planDeps = () => ({entries: ENTRIES, superseded: [], groups: PERMISSION_GROUPS.get('gmail'), config: PROXY_CONFIGS.get('gmail'), rules: RULES});

test('the live plan G0 to G11 passes step 12\'s plan check against the shipped file, calls all 13 actions, and undoes every write', () => {
  const checked = checkPlan(PLAN(), planDeps());
  assert.deepEqual(checked.plan.tests.map(item => item.id), ['G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8', 'G9', 'G10', 'G11']);
  assert.deepEqual([...checked.actions.keys()].sort(), ENTRIES.map(entry => `${entry.key}@${entry.version}`).sort());
  assert.deepEqual([checked.plan.timeZone, checked.plan.gone, checked.plan.readRows], [undefined, undefined, ['gmail.messages.read', 'gmail.drafts.read', 'gmail.labels.read']]);
  assert.deepEqual(checked.plan.tests.filter(item => item.undo === undefined).map(item => item.id), ['G0', 'G11']);
  const steps = id => checked.plan.tests.find(item => item.id === id).steps;
  assert.ok(steps('G8').some(step => step.call?.action === 'send-draft@1'), 'G8 certifies Send draft');
  // All tidying in Gmail is G11's, a cleanup test at the end (the owner may leave it, --leave): G1's and G2's drafts, G5's label and G10's
  // filter. No action test waits on the owner to delete anything, so leaving it never touches an action's evidence (Sami, 2026-10-29).
  for (const id of ['G1', 'G2', 'G5', 'G10']) assert.deepEqual(checked.plan.tests.find(item => item.id === id).undo, {test: 'G11'}, id);
  const g11 = checked.plan.tests.find(item => item.id === 'G11');
  assert.deepEqual([g11.cleanup, checked.plan.tests.filter(item => item.cleanup).map(item => item.id)], [true, ['G11']]);
  assert.ok(g11.steps.every(step => step.owner?.until), 'G11 is owner steps that read back, and nothing else');
  // The drafts come first: they need only G1's draft, so a stop before G5 still reaches them when the owner tidies.
  assert.deepEqual(g11.steps.map(step => [...JSON.stringify(step).matchAll(/"\$(?:saved|recorded)":"(\w+)"/g)].map(match => match[1])), [['draft1'], ['handDraft'], ['filter10'], ['label5']]);
  assert.ok(checked.plan.tests.filter(item => !item.cleanup).every(item => !(item.undo?.steps ?? []).some(step => step.owner)), 'no action test\'s undo waits on the owner');
  assert.deepEqual(checked.plan.tests.filter(item => item.steps.some(step => step.owner?.until)).map(item => item.id), ['G9', 'G11'], 'only G9\'s responder check and G11\'s cleanup wait on Gmail');
  // Every address a call names is the owner's own.
  const named = checked.plan.tests.flatMap(item => [...item.steps, ...(item.undo?.steps ?? [])]).map(step => step.call).filter(Boolean).flatMap(call => ['to', 'cc', 'bcc'].flatMap(field => call.args?.[field] ?? []));
  assert.ok(named.length && named.every(value => JSON.stringify(value) === JSON.stringify({$owner: 'email'})));
});

/** A small reader of the plan's checks over a call's output or a read's answer ({status, body}). */
function holds(check, {status, body}, fill) {
  const at = pointer => pointer === '' ? body : pointer.slice(1).split('/').reduce((value, token) => value?.[token], body);
  if (Object.hasOwn(check, 'status')) return [check.status].flat().includes(status);
  if (Object.hasOwn(check, 'gone')) return status === 404 || status === 410;
  if (Object.hasOwn(check, 'present')) return (at(check.pointer) !== undefined) === check.present;
  if (Object.hasOwn(check, 'count')) return at(check.pointer)?.length === check.count;
  return JSON.stringify(at(check.pointer)) === JSON.stringify(fill(check.equals));
}

test('the live plan run on the simulator through the live guard: every call\'s body passes the guard and the simulator, every check holds, and G8 sends v1', async t => {
  const folder = mkdtempSync(path.join(tmpdir(), 'fabric-gmail-plan-'));
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  let h = null;
  const guard = createGuard({appId: 'gmail', runId: 'ABCDEFGH', folder, key: randomBytes(32), clock: () => h.now});
  h = gmailHarness(t, {start: '2026-10-26T13:00:00.000Z', wrap: request => guard.wrap(request)});
  // Muse's preparation (section 7): two read-pass emails to self and one reply, and a hand draft.
  const pass = h.simulator.deliver(raw([`From: ${OWNER_EMAIL}`, `To: ${OWNER_EMAIL}`, 'Subject: [SYNTHETIC] Fabric read pass', 'Message-ID: <rp1@example.com>']));
  h.simulator.deliver(raw([`From: ${OWNER_EMAIL}`, `To: ${OWNER_EMAIL}`, 'Subject: Re: [SYNTHETIC] Fabric read pass', 'Message-ID: <rp2@example.com>', 'In-Reply-To: <rp1@example.com>']));
  const hand = h.simulator.seedDraft(raw([`From: ${OWNER_EMAIL}`, `To: ${OWNER_EMAIL}`, 'Subject: [SYNTHETIC] Fabric hand draft']));
  const recorded = {readMessage: pass.id, readThread: pass.threadId, handDraft: hand.id};
  guard.setOwner({email: OWNER_EMAIL, timeZone: 'America/Toronto', runDate: '2026-10-26', recorded});
  const run = {runId: 'ABCDEFGH', runDate: '2026-10-26', timeZone: 'America/Toronto', recorded, saved: {}};
  const guarded = guard.wrap(h.simulator.request);
  const read = async (item, body) => {
    const fill = value => fillPlaceholders(value, {run, account: {email: OWNER_EMAIL}}, item);
    const params = fill(body.params ?? {}), query = fill(body.query ?? {});
    const route = body.path.replace(/\{(\w+)\}/g, (_, name) => encodeURIComponent(params[name]));
    const answer = await guarded({url: `${ORIGIN}${route}${Object.keys(query).length ? `?${new URLSearchParams(query)}` : ''}`, method: 'GET', headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: [ORIGIN]});
    return {status: answer.status, body: answer.data};
  };
  const owner = {
    // The owner's tidying is G11's, at the end: G1's draft and the hand draft, then G10's filter and G5's label (live run LQ23SCN5 stopped
    // at G2 waiting on Gmail).
    'G11:0': () => h.simulator.remove('draft', run.saved.draft1), 'G11:1': () => h.simulator.remove('draft', hand.id),
    'G11:2': () => h.simulator.remove('filter', run.saved.filter10), 'G11:3': () => h.simulator.remove('label', run.saved.label5),
  };
  let sent = 0;
  for (const item of PLAN().tests) {
    guard.begin(item.id);
    const fill = value => fillPlaceholders(value, {run, account: {email: OWNER_EMAIL}}, item);
    let ownerSteps = 0;
    for (const step of [...item.steps, ...(item.undo?.steps ?? [])]) {
      const [kind] = Object.keys(step), body = step[kind];
      if (kind === 'owner') {
        owner[`${item.id}:${ownerSteps++}`]?.();
        if (body.until) for (const check of body.until.checks) assert.ok(holds(check, await read(item, body.until), fill), `${item.id} owner until ${JSON.stringify(check)}`);
        continue;
      }
      if (kind === 'read') {
        const answer = await read(item, body);
        for (const check of body.checks ?? []) assert.ok(holds(check, answer, fill), `${item.id} read ${body.path} ${JSON.stringify(check)}`);
        for (const [name, pointer] of Object.entries(body.save ?? {})) run.saved[name] = pointer.slice(1).split('/').reduce((value, token) => value?.[token], answer.body);
        continue;
      }
      const key = body.action.replace('@', ' v'), args = fill(body.args);
      let job = await h.run(key, args);
      while (job.status === 'awaiting_approval') {
        // G8: the owner edits the draft to v2 while the Send draft card waits; v1 is what goes out.
        if (key === 'send-draft v1' && job.action.phase === 'final') h.simulator.editDraft(args.draftId, raw([`From: ${OWNER_EMAIL}`, `To: ${OWNER_EMAIL}`, `Subject: ${fill({$text: 'v2'})}`], 'v2'));
        job = await h.approve(job);
      }
      ended(job, 'succeeded', null);
      sent++;
      for (const check of body.checks ?? []) assert.ok(holds(check, {body: job.result.data}, fill), `${item.id} ${key} ${JSON.stringify(check)}: ${JSON.stringify(job.result.data)}`);
      for (const [name, pointer] of Object.entries(body.save ?? {})) run.saved[name] = pointer.slice(1).split('/').reduce((value, token) => value?.[token], job.result.data);
    }
    guard.end();
  }
  assert.ok(sent >= 20);
  // G8 sent v1, never v2; every delivery went to the owner alone; nothing is left on: no draft, no filter, no label, no reply.
  assert.ok(h.simulator.deliveries().every(item => item.to === OWNER_EMAIL));
  assert.ok(!h.simulator.deliveries().some(item => Buffer.from(item.raw, 'base64url').toString('utf8').includes('Subject: [SYNTHETIC] Fabric G8 ABCDEFGH v2')));
  const state = h.simulator.state();
  assert.deepEqual([state.drafts, state.filters, state.labels, state.vacation.enableAutoReply], [{}, {}, {}, false]);
  assert.ok(Object.values(state.messages).filter(item => item.labelIds.includes('SENT')).every(item => item.labelIds.includes('TRASH')), 'every sent message is in Trash');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {canonicalHash} from '../lib/compiler.mjs';
import {validateActionFile} from '../lib/actions.mjs';
import {ACTION_REFUSED, RUN_WORDS} from '../lib/actions-runtime.mjs';
import {STATUS_WORDS} from '../lib/action-catalog.mjs';
import {FabricProtocol} from '../lib/fabric-protocol.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {RULES, createGuard} from '../lib/live-guard.mjs';
import {checkPlan, fillPlaceholders} from '../lib/live-certify.mjs';
import {slackHarness, slackDeps, slackFile, IDS, OWNER, SCOPES, TOKEN} from './fixtures/actions/slack-harness.mjs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {actionSchema, withIds} from './fixtures/actions/fixture-app.mjs';

// F10.21 part 2 (docs/F10.21-BUILD-MAP.md section 3, part 2): Slack's 13 reviewed actions (catalog/actions/slack.json) on the Slack
// simulator, through the action runtime, as an agent's call and the owner's approval run them; every case of Slack's simulator case list
// (test/fixtures/provider-simulators/slack.cases.json) through caseTests(); and the live plan S0 to S6 (catalog/live-tests/slack.json)
// against step 12's plan check and the live guard. Nothing here reaches Slack. Every test reads the file with its ids recomputed
// (withIds()), so a seeded fault inside it is caught by what the action does; test/f10-21-churn.test.mjs checks the shipped ids.

const READ = {readOnly: true, destructive: false, idempotent: true, openWorld: true}, WRITE = {readOnly: false, destructive: false, idempotent: false, openWorld: true};
const SEND = 'slack.messages.send';
/** Section 2's table: each action's row, effect and hints, and how many steps it declares. */
const TABLE = Object.freeze({
  'list-conversations': ['slack.channels.read', 'read', READ, 1], 'read-messages': ['slack.messages.read', 'read', READ, 1], 'read-thread': ['slack.messages.read', 'read', READ, 1],
  'search-messages': ['slack.messages.search', 'read', READ, 1], 'find-person': ['slack.channels.read', 'read', READ, 6], 'send-message': [SEND, 'write', WRITE, 4],
  'reply-thread': [SEND, 'write', WRITE, 7], 'send-dm': [SEND, 'write', WRITE, 5], 'edit-message': [SEND, 'write', WRITE, 4], react: [SEND, 'write', WRITE, 4],
  'schedule-message': [SEND, 'write', WRITE, 5], 'set-status': ['slack.profile.write', 'write', WRITE, 4], 'read-canvas': ['slack.files.read', 'read', READ, 1]});
const OK = {equals: {pointer: '/ok', value: {const: true}}};
const MINUTE = 60_000, HOUR = 60 * MINUTE, DAY = 24 * HOUR;

/** Asserts how a job ended, and any of its fields. */
function ended(job, status, errorCode, extra = {}) {
  assert.deepEqual([job.status, job.errorCode ?? null], [status, errorCode], `${job.error} ${JSON.stringify(job.details ?? job.reason ?? '')}`);
  for (const [key, value] of Object.entries(extra)) assert.deepEqual(job[key], value, key);
  return job;
}
/** An action refusal: failed, action_refused, its reason (and transform) in details. */
const refusedAs = (job, reason) => { ended(job, 'failed', ACTION_REFUSED); assert.equal(job.details?.reason, reason, JSON.stringify(job.details)); return job; };
/** Slack's ok: false: failed, nothing changed, its error code in details. */
const apiError = (job, error) => ended(job, 'failed', 'provider_failed', {reason: 'api_error', details: {providerError: error}});
const names = h => h.simulator.calls.map(call => call.name);
const writes = h => h.simulator.writes().map(call => call.name);
/**
 * A write job prepared to its final card: awaiting the owner, phase final, nothing written yet. Send a direct message (`opens`) first stops at
 * a reads card with the exact conversations.open bytes, since "Mark as read and open direct messages" is Ask for a request template under the
 * signed defaults; its approval sends the open, and the final card follows.
 */
async function prepared(h, key, input, {opens = 0} = {}) {
  const before = h.simulator.writes().length;
  let job = await h.run(key, input);
  if (opens) {
    assert.deepEqual([job.status, job.action?.phase, h.simulator.writes().length], ['awaiting_approval', 'reads', before], `${key}: ${job.error ?? ''} ${JSON.stringify(job.details ?? '')}`);
    job = await h.approve(job);
  }
  assert.deepEqual([job.status, job.action?.phase, h.simulator.writes().length], ['awaiting_approval', 'final', before + opens], `${key}: ${job.error ?? ''} ${JSON.stringify(job.details ?? '')}`);
  return job;
}
/** A refusal at acceptance in a local deployment: its words, no code. */
const NEEDS_ACCESS = /The account does not have a required provider scope/, NEVER_MESSAGES = /Never: "Access messages" is set to Never/;
const approved = async (h, key, input, options) => h.approve(await prepared(h, key, input, options));
/** The exact body a prepared job will send, parsed (the last perform request by default). */
const bodyOf = (h, job, index = -1) => JSON.parse(h.prepared(job).content.perform.at(index).body);
const messagesOf = (h, channel) => h.simulator.state().channels[channel].messages;
const inMinutes = (h, minutes) => new Date(h.now + minutes * MINUTE).toISOString();
const general = h => Object.fromEntries(messagesOf(h, IDS.general).map(message => [message.text, message.ts]));
/** A message link as Slack's Copy link gives it, with thread_ts for a reply. */
const linkOf = (channel, ts, thread) => `https://fabric-test.slack.com/archives/${channel}/p${ts.replace('.', '')}${thread ? `?thread_ts=${thread}&cid=${channel}` : ''}`;

// ---- the file ---------------------------------------------------------------------------------------------------------------------------
/** Slack's shipped file with each id recomputed from its content, as an author writes them. */
const currentFile = (deps = slackDeps()) => withIds(slackFile(), deps);
const stepsOf = action => [...action.prepare, ...action.perform, ...(action.verify?.requests ?? [])];

test('the file: 13 actions, each placed in its row with its effect and hints (section 2); every step requires Slack\'s ok; no certified block; token never named', () => {
  const file = currentFile(), {actions} = validateActionFile(file, slackDeps());
  assert.deepEqual(actions.map(entry => entry.key), Object.keys(TABLE));
  for (const entry of actions) {
    const [row, effect, hints, steps] = TABLE[entry.key];
    assert.deepEqual([entry.version, entry.row, entry.effect, entry.action.hints, entry.unplaced, entry.sensitive, entry.placements.length], [1, row, effect, hints, false, false, steps], entry.key);
    assert.ok(entry.placements.every(placement => !placement.unplaced && placement.groupId.startsWith('slack.')), entry.key);
    assert.equal(entry.placements.filter(placement => placement.phase === 'perform').at(-1).groupId, row, `${entry.key}: the last perform step lands in its row`);
    assert.equal(entry.action.certified, undefined, `${entry.key}: certified only by step 22's evidence`);
    assert.deepEqual(entry.action.definitive, [429], `${entry.key}: Slack answers its own refusals inside a 200`);
    for (const step of stepsOf(entry.action)) assert.deepEqual(step.expect.require[0].anyOf?.[0] ?? step.expect.require[0], OK, `${entry.key}: ${step.id} requires ok`);
  }
  assert.deepEqual([file.specVersion, file.pinnedParameters, file.superseded, ['candidate', 'reviewed'].includes(file.reviewStatus)], ['fabric/0.2', {}, undefined, true]);
  const schema = actionSchema();
  assert.ok(schema(file), JSON.stringify(schema.errors));
  assert.equal(/"token"/.test(JSON.stringify(file)), false, 'the app reserves token at any depth');
  // Send a direct message is the one two-phase action: conversations.open, the reviewed resolving write, in "Mark as read and open direct messages".
  assert.deepEqual(actions.filter(entry => entry.twoPhase).map(entry => entry.key), ['send-dm']);
  assert.deepEqual(actions.find(entry => entry.key === 'send-dm').placements.map(placement => [placement.stepId, placement.groupId]),
    [['person', 'slack.channels.read'], ['open', 'slack.conversations.mark'], ['post', SEND], ['read', 'slack.messages.read'], ['permalink', 'slack.messages.read']]);
  // Find a person's lookup by email is optional, with the users.list read as its fallback (R7).
  assert.deepEqual(actions.find(entry => entry.key === 'find-person').action.prepare.map(step => [step.id, step.optional ?? null, step.fallbackFor ?? null]),
    [['lookup', true, null], ['emailList', null, 'lookup'], ['nameList', null, null]]);
});

test('at start without live evidence: 13 candidates that never run and that no agent can be given', async t => {
  const h = slackHarness(t, {evidence: false});
  assert.deepEqual([...h.catalog.entries.values()].map(item => [item.status, item.reason]), Array(13).fill(['candidate', STATUS_WORDS.evidence]));
  assert.ok(h.store.list('capabilities').filter(capability => capability.driver === 'action').every(capability => capability.status === 'candidate'));
  await assert.rejects(h.run('list-conversations v1', {}));
  const protocol = new FabricProtocol({store: h.store, runtime: h.runtime, clock: () => h.now, origin: 'http://127.0.0.1:59996'});
  assert.throws(() => protocol.createClient({name: 'Slack agent', bindings: [{connectionId: h.account, capabilityId: h.idOf('list-conversations v1')}]}, OWNER), {code: 'permission_denied'});
  assert.deepEqual([h.simulator.calls.length, h.store.list('clientGrants').length], [0, 0]);
});

// ---- spec line 1222: <!channel> is escaped --------------------------------------------------------------------------------------------
const MENTIONS = '<!channel> R&D <@U0ADA0001>', ESCAPED = '&lt;!channel&gt; R&amp;D &lt;@U0ADA0001&gt;';
const FLAGS = {parse: 'none', link_names: false, unfurl_links: false, unfurl_media: false};

test('<!channel> is escaped (spec line 1222): the card and the bytes say &lt;!channel&gt;, with parse none, link_names false and no unfurl, and Slack pings nobody', async t => {
  const h = slackHarness(t);
  const job = await prepared(h, 'send-message v1', {channel: IDS.fabricTest, text: MENTIONS});
  assert.deepEqual(h.fields(job), {Channel: '#fabric-test (C0FABTEST1)', 'People in the channel': 2, Message: ESCAPED});
  assert.deepEqual(bodyOf(h, job), {channel: IDS.fabricTest, text: ESCAPED, ...FLAGS});
  assert.equal(JSON.parse(h.card(job).exact.blocks.find(block => block.label === 'post: Body').text).text, ESCAPED, 'the exact block shows the escaped bytes');
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.verification.status, done.result.data.channel, typeof done.result.data.ts, done.result.data.permalink.startsWith('https://fabric-test.slack.com/archives/C0FABTEST1/p')],
    ['verified', IDS.fabricTest, 'string', true]);
  assert.equal(messagesOf(h, IDS.fabricTest).at(-1).text, ESCAPED, 'stored exactly as sent');
  assert.deepEqual(h.simulator.notifications(), [], 'nobody is pinged');
});

test('Reply in a thread, Send a direct message, Edit my message and Schedule escape the same way, each with parse none and link_names false', async t => {
  const h = slackHarness(t), one = h.simulator.synthetic.one;
  const reply = await prepared(h, 'reply-thread v1', {channel: IDS.fabricTest, ts: one, text: MENTIONS});
  assert.deepEqual([bodyOf(h, reply), h.fields(reply).Message], [{channel: IDS.fabricTest, thread_ts: one, text: ESCAPED, ...FLAGS, reply_broadcast: false}, ESCAPED]);
  const dm = await prepared(h, 'send-dm v1', {user: IDS.ada, text: MENTIONS}, {opens: 1});
  assert.deepEqual([bodyOf(h, dm), h.fields(dm).Message], [{channel: 'D0ADA0001', text: ESCAPED, ...FLAGS}, ESCAPED]);
  const edit = await prepared(h, 'edit-message v1', {channel: IDS.fabricTest, ts: one, text: MENTIONS});
  assert.deepEqual([bodyOf(h, edit), h.fields(edit)['New text']], [{channel: IDS.fabricTest, ts: one, text: ESCAPED, attachments: [], parse: 'none', link_names: false}, ESCAPED]);
  const schedule = await prepared(h, 'schedule-message v1', {do: 'schedule', channel: IDS.fabricTest, text: MENTIONS, at: inMinutes(h, 120)});
  assert.deepEqual([bodyOf(h, schedule), h.fields(schedule).Message], [{channel: IDS.fabricTest, text: ESCAPED, post_at: (h.now + 120 * MINUTE) / 1000, ...FLAGS}, ESCAPED]);
  for (const job of [reply, dm, edit, schedule]) assert.equal(ended(await h.approve(job), 'succeeded', null).result.verification.status, 'verified');
  assert.deepEqual(h.simulator.notifications(), [], 'nobody is pinged');
  assert.equal(messagesOf(h, IDS.fabricTest).find(message => message.ts === one).text, ESCAPED, 'the edit stored the escaped text');
});

// ---- spec line 1223: ts values compare as BigInt and stay strings ---------------------------------------------------------------------
test('ts values compare as BigInt and stay strings (spec line 1223): 1000000000.000000 is newer than 999999999.999999; a ts Slack sends as a number refuses ts_invalid', async t => {
  const h = slackHarness(t);
  h.simulator.seed(IDS.private, {ts: '999999999.999999', user: IDS.ada, text: 'earlier'});
  h.simulator.seed(IDS.private, {ts: '1000000000.000000', user: IDS.grace, text: 'later'});
  const job = ended(await h.run('read-messages v1', {channel: IDS.private}), 'succeeded', null);
  assert.deepEqual(job.result.data.messages.map(message => [message.ts, message.time, message.user, message.text]), [
    ['1000000000.000000', '2001-09-09T01:46:40.000000Z', IDS.grace, 'later'], ['999999999.999999', '2001-09-09T01:46:39.999999Z', IDS.ada, 'earlier']]);
  assert.deepEqual(h.simulator.calls.at(-1).query, {channel: IDS.private, limit: '15'});
  // A ts reaches requests, cards and outputs as text only.
  const edit = await prepared(h, 'edit-message v1', {channel: IDS.fabricTest, ts: h.simulator.synthetic.one, text: 'v2'});
  assert.equal(typeof bodyOf(h, edit).ts, 'string');
  assert.ok(job.result.data.messages.every(message => typeof message.ts === 'string'));
  h.simulator.fail('conversations.history', {data: {ok: true, messages: [{type: 'message', user: IDS.ada, text: 'x', ts: 1793000000.0001}], has_more: false}});
  const number = refusedAs(await h.run('read-messages v1', {channel: IDS.fabricTest}), 'ts_invalid');
  assert.equal(number.details.transform, 'time.slackTs@1');
});

// ---- spec line 1224: Send a direct message uses conversations.open ----------------------------------------------------------------------
test('Send a direct message uses conversations.open (spec line 1224): a reads card shows the exact open bytes under the defaults; the open names one user and the post goes to its D id, never a U id', async t => {
  const h = slackHarness(t);
  const reads = await h.run('send-dm v1', {user: IDS.ada, text: 'Hello Ada'});
  assert.deepEqual([reads.status, reads.action.phase, reads.action.modes, h.simulator.writes().length], ['awaiting_approval', 'reads', {prepare: 'allow', resolve: 'ask', perform: 'ask'}, 0],
    '"Mark as read and open direct messages" asks for a request template under the signed defaults: nothing is sent before its card');
  assert.deepEqual(JSON.parse(h.card(reads).exact.blocks.find(block => block.label === 'open: Body').text), {users: IDS.ada});
  const job = await h.approve(reads);
  assert.deepEqual([job.status, job.action.phase, writes(h)], ['awaiting_approval', 'final', ['conversations.open']]);
  assert.deepEqual(h.fields(job), {To: 'Ada Lovelace (ada) U0ADA0001', Message: 'Hello Ada'});
  assert.deepEqual(h.simulator.writes()[0].body, {users: IDS.ada});
  assert.equal(bodyOf(h, job).channel, 'D0ADA0001');
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.verification.status, done.result.data.channel], ['verified', 'D0ADA0001']);
  // T8: the open is never looser than the action, whose row reaches people and never allows, so even with the row at Allow the open asks first.
  h.setRow('slack.conversations.mark', 'allow');
  const again = await h.run('send-dm v1', {user: IDS.owner, text: 'Note to self'});
  assert.deepEqual([again.status, again.action.phase, again.action.modes.resolve, writes(h).length], ['awaiting_approval', 'reads', 'ask', 2]);
  const once = await h.approve(again);
  assert.equal(bodyOf(h, once).channel, IDS.selfDm, 'your own id opens your self-DM');
  ended(await h.approve(once), 'succeeded', null);
  const posts = h.simulator.calls.filter(call => call.name === 'chat.postMessage');
  assert.ok(posts.length === 2 && posts.every(call => call.body.channel.startsWith('D')), 'nothing is ever posted to a user id');
  // One person only: a list of two fails at the person read, so no group DM is opened; a user id given as a channel is no channel.
  const sent = writes(h).length;
  apiError(await h.run('send-dm v1', {user: `${IDS.ada},${IDS.grace}`, text: 'Both of you'}), 'user_not_found');
  apiError(await h.run('send-message v1', {channel: IDS.ada, text: 'Hi'}), 'channel_not_found');
  assert.equal(writes(h).length, sent, 'nothing written');
});

// ---- spec line 1225: a schedule time outside the window is refused locally ---------------------------------------------------------------
test('a schedule time in the past, or more than 120 days ahead, is refused locally (spec line 1225); 120 days exactly is sent, with post_at in whole seconds', async t => {
  const h = slackHarness(t), base = {do: 'schedule', channel: IDS.fabricTest, text: 'Later'};
  for (const [at, reason] of [[new Date(h.now - MINUTE).toISOString(), 'window_past'], [new Date(h.now + 120 * DAY + 1000).toISOString(), 'window_too_far']]) {
    const job = refusedAs(await h.run('schedule-message v1', {...base, at}), 'time_window');
    assert.deepEqual([job.details.transform, job.details.transformReason], ['time.window@1', reason]);
  }
  assert.deepEqual(h.simulator.calls, [], 'refused before any request');
  const at = new Date(h.now + 120 * DAY).toISOString(), job = await prepared(h, 'schedule-message v1', {...base, at});
  assert.deepEqual([bodyOf(h, job).post_at, h.fields(job)['Posts at'], h.fields(job).Change], [(h.now + 120 * DAY) / 1000, at, 'schedule']);
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.verification.status, done.result.data.postAt, done.result.data.scheduledMessageId], ['verified', (h.now + 120 * DAY) / 1000, 'Q000000001']);
  // A fraction of a second rounds down; an offset is read as the instant it names.
  const odd = await prepared(h, 'schedule-message v1', {...base, at: '2026-10-26T13:30:00.750-02:00'});
  assert.equal(bodyOf(h, odd).post_at, Date.parse('2026-10-26T15:30:00Z') / 1000);
});

test('Schedule or cancel: a cancel names the id and the text Schedule gave, is refused before any card unless Slack still lists that message, and reads back the id gone', async t => {
  const h = slackHarness(t), text = 'Reminder <!here>';
  const done = ended(await approved(h, 'schedule-message v1', {do: 'schedule', channel: IDS.fabricTest, text, at: inMinutes(h, 120)}), 'succeeded', null);
  const id = done.result.data.scheduledMessageId;
  assert.deepEqual(h.simulator.state().scheduled.map(item => [item.id, item.text]), [[id, 'Reminder &lt;!here&gt;']]);
  // The kind guard: schedule takes text and at, cancel takes text and the id.
  for (const input of [{do: 'cancel', channel: IDS.fabricTest, text, at: inMinutes(h, 60), scheduledMessageId: id}, {do: 'cancel', channel: IDS.fabricTest, text},
    {do: 'schedule', channel: IDS.fabricTest, text, scheduledMessageId: id}]) refusedAs(await h.run('schedule-message v1', input), 'wrong_kind');
  // Another text, or an id Slack does not list, fails at the read, before any card.
  for (const input of [{text: 'Reminder'}, {scheduledMessageId: 'Q999999999'}]) {
    ended(await h.run('schedule-message v1', {do: 'cancel', channel: IDS.fabricTest, text, scheduledMessageId: id, ...input}), 'failed', 'provider_failed', {reason: 'require_failed'});
  }
  const cancel = await prepared(h, 'schedule-message v1', {do: 'cancel', channel: IDS.fabricTest, text, scheduledMessageId: id});
  assert.deepEqual(h.fields(cancel), {Channel: '#fabric-test (C0FABTEST1)', Change: 'cancel', 'Scheduled message': id, Message: 'Reminder &lt;!here&gt;'});
  assert.deepEqual(bodyOf(h, cancel), {channel: IDS.fabricTest, scheduled_message_id: id});
  const gone = ended(await h.approve(cancel), 'succeeded', null);
  assert.deepEqual([gone.result.verification.status, gone.result.data, h.simulator.state().scheduled], ['verified', {channel: IDS.fabricTest, scheduledMessageId: id}, []]);
  assert.deepEqual(writes(h), ['chat.scheduleMessage', 'chat.deleteScheduledMessage']);
});

// ---- spec line 1226: clearing a status sets both fields ----------------------------------------------------------------------------------
test('clearing a status sets both fields and the expiry (spec line 1226); Set my status never sends user, and a status always ends within 30 days', async t => {
  const h = slackHarness(t), until = inMinutes(h, 10);
  const set = await prepared(h, 'set-status v1', {do: 'set', text: 'In a meeting', emoji: 'calendar', until});
  assert.deepEqual(bodyOf(h, set), {profile: {status_text: 'In a meeting', status_emoji: ':calendar:', status_expiration: (h.now + 10 * MINUTE) / 1000}});
  assert.deepEqual(h.fields(set), {'Status now': '', 'Emoji now': '', Change: 'set', 'New status': 'In a meeting', Emoji: 'calendar', 'Clears at': until});
  const made = ended(await h.approve(set), 'succeeded', null);
  assert.deepEqual([made.result.verification.status, made.result.data], ['verified', {statusText: 'In a meeting', statusEmoji: ':calendar:', statusExpiration: (h.now + 10 * MINUTE) / 1000}]);
  const clear = await prepared(h, 'set-status v1', {do: 'clear'});
  assert.deepEqual(bodyOf(h, clear), {profile: {status_text: '', status_emoji: '', status_expiration: 0}});
  assert.deepEqual(h.fields(clear), {'Status now': 'In a meeting', 'Emoji now': ':calendar:', Change: 'clear'});
  const cleared = ended(await h.approve(clear), 'succeeded', null);
  assert.deepEqual([cleared.result.verification.status, cleared.result.data], ['verified', {statusText: '', statusEmoji: '', statusExpiration: 0}]);
  for (const call of h.simulator.calls.filter(item => item.name === 'users.profile.set')) assert.deepEqual(Object.keys(call.body), ['profile'], 'never user');
  refusedAs(await h.run('set-status v1', {do: 'set', text: 'Away', emoji: 'palm_tree', until: new Date(h.now + 30 * DAY + 1000).toISOString()}), 'time_window');
  for (const input of [{do: 'set', text: 'Away', emoji: 'palm_tree'}, {do: 'clear', text: 'Away'}]) refusedAs(await h.run('set-status v1', input), 'wrong_kind');
  assert.deepEqual(writes(h), ['users.profile.set', 'users.profile.set']);
});

// ---- spec line 1227: already_reacted is success with no change -------------------------------------------------------------------------
test('already_reacted counts as success with no change (spec line 1227), and no_reaction the same for a removal; the readback looks for your own id; a Unicode emoji refuses', async t => {
  const h = slackHarness(t), ts = h.simulator.synthetic.two, base = {channel: IDS.fabricTest, ts, emoji: 'white_check_mark'};
  const users = () => messagesOf(h, IDS.fabricTest).find(message => message.ts === ts).reactions.find(reaction => reaction.name === 'white_check_mark')?.users ?? [];
  const add = await prepared(h, 'react v1', {...base, do: 'add'});
  assert.deepEqual(h.fields(add), {Channel: '#fabric-test (C0FABTEST1)', Message: ts, Emoji: ':white_check_mark:', Change: 'add'});
  assert.deepEqual(bodyOf(h, add), {channel: IDS.fabricTest, timestamp: ts, name: 'white_check_mark'});
  assert.equal(ended(await h.approve(add), 'succeeded', null).result.verification.status, 'verified');
  const again = ended(await approved(h, 'react v1', {...base, emoji: ':white_check_mark:', do: 'add'}), 'succeeded', null);
  assert.deepEqual([again.result.verification.status, h.simulator.calls.filter(call => call.name === 'reactions.add').at(-1).error, users()], ['verified', 'already_reacted', [IDS.owner]]);
  assert.equal(ended(await approved(h, 'react v1', {...base, do: 'remove'}), 'succeeded', null).result.verification.status, 'verified');
  assert.deepEqual(users(), []);
  const none = ended(await approved(h, 'react v1', {...base, do: 'remove'}), 'succeeded', null);
  assert.deepEqual([none.result.verification.status, h.simulator.calls.filter(call => call.name === 'reactions.remove').at(-1).error], ['verified', 'no_reaction']);
  // Ada's reaction alone never verifies an add Slack swallowed: the readback looks for your own id.
  h.simulator.react(IDS.fabricTest, ts, 'white_check_mark', IDS.ada);
  h.simulator.swallow('reactions.add');
  const swallowed = ended(await approved(h, 'react v1', {...base, do: 'add'}), 'uncertain', 'outcome_uncertain');
  assert.equal(swallowed.result.verification.status, 'unverified');
  const count = h.simulator.writes().length;
  for (const emoji of ['👍', 'Thumbs Up', ':thumbsup']) assert.equal(refusedAs(await h.run('react v1', {...base, emoji, do: 'add'}), 'emoji_invalid').details.transform, 'ids.slackEmoji@1', emoji);
  assert.equal(h.simulator.writes().length, count, 'nothing written');
});

// ---- spec line 1228: missing_scope means failed, and the row needs more access -----------------------------------------------------------
test('ok false with missing_scope means failed, and the row shows "Needs more access" (spec line 1228): React with the token\'s reactions:write revoked', async t => {
  const h = slackHarness(t), args = {do: 'add', channel: IDS.fabricTest, ts: h.simulator.synthetic.two, emoji: 'white_check_mark'};
  h.simulator.revokeScope('reactions:write');
  const job = ended(await approved(h, 'react v1', args), 'failed', 'provider_failed', {reason: 'api_error', error: RUN_WORDS.missing_scope});
  assert.deepEqual(job.details, {providerError: 'missing_scope', needed: ['reactions:write']});
  assert.equal(h.record().scopes.includes('reactions:write'), false, 'the account narrows');
  const decision = h.proxyPolicy.decide(h.account, {method: 'POST', path: '/reactions.add', body: {channel: IDS.fabricTest, timestamp: args.ts, name: 'white_check_mark'}});
  assert.equal(decision.providerAccess, 'missing', '"Send, edit and react to messages" reads "Needs more access"');
  const sent = h.simulator.calls.length;
  await assert.rejects(h.run('react v1', args), NEEDS_ACCESS);
  assert.equal(h.simulator.calls.length, sent, 'nothing more is sent');
});

// ---- spec line 1229: the distributed flag applies Slack's limit --------------------------------------------------------------------------
test('the distributed flag applies the rate limit (spec line 1229): a second Read recent messages within a minute is refused with nothing sent; internal paces nothing', async t => {
  const h = slackHarness(t, {distribution: 'distributed'});
  ended(await h.run('read-messages v1', {channel: IDS.fabricTest}), 'succeeded', null);
  const sent = h.simulator.calls.length;
  const second = ended(await h.run('read-messages v1', {channel: IDS.general}), 'failed', 'rate_limited', {reason: 'slack_pace'});
  assert.ok(second.retryAfterSeconds >= 1 && second.retryAfterSeconds <= 60, String(second.retryAfterSeconds));
  assert.equal(h.simulator.calls.length, sent, 'nothing sent');
  ended(await h.run('read-thread v1', {channel: IDS.fabricTest, ts: h.simulator.synthetic.one}), 'succeeded', null, {});
  h.advance(MINUTE);
  ended(await h.run('read-messages v1', {channel: IDS.general}), 'succeeded', null);
  const internal = slackHarness(t);
  for (let index = 0; index < 3; index++) ended(await internal.run('read-messages v1', {channel: IDS.fabricTest}), 'succeeded', null);
});

// ---- spec line 1230: bodies are dropped after 24 hours -----------------------------------------------------------------------------------
test('bodies are dropped after 24 hours (spec line 1230): a Read recent messages result and a proxied history body both go once swept', async t => {
  const h = slackHarness(t);
  const job = ended(await h.run('read-messages v1', {channel: IDS.fabricTest}), 'succeeded', null);
  const proxied = await h.proxy({method: 'GET', path: '/conversations.history', query: {channel: IDS.fabricTest, limit: '15'}});
  assert.deepEqual([proxied.status, job.result.data.messages.length], ['succeeded', 2]);
  h.advance(DAY - 1);
  h.runtime.sweepRetention();
  assert.deepEqual([h.store.get('jobs', job.id).result.data, h.runtime.proxyResponse(proxied)?.body.ok], [job.result.data, true], 'kept for 24 hours');
  h.advance(2);
  h.runtime.sweepRetention();
  assert.deepEqual(h.store.get('jobs', job.id).result, {verification: job.result.verification, dataHash: canonicalHash(job.result.data), kept: false});
  assert.deepEqual([h.runtime.proxyResponse(proxied), h.store.get('proxyResponses', proxied.id), h.store.get('jobs', job.id).status], [null, null, 'succeeded']);
});

// ---- Edit my message -------------------------------------------------------------------------------------------------------------------
test('Edit my message: the card shows the old and the new text; another person\'s message refuses wrong_kind before any write; it sends attachments: [] and a swallowed update is unverified', async t => {
  const h = slackHarness(t), one = h.simulator.synthetic.one;
  h.simulator.data.channels[IDS.fabricTest].messages.find(message => message.ts === one).attachments = [{text: 'old attachment'}];
  const job = await prepared(h, 'edit-message v1', {channel: IDS.fabricTest, ts: one, text: 'v2'});
  assert.deepEqual(h.fields(job), {Channel: '#fabric-test (C0FABTEST1)', 'Old text': '[SYNTHETIC] Fabric message 1', 'New text': 'v2'});
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([done.result.verification.status, done.result.data], ['verified', {channel: IDS.fabricTest, ts: one}]);
  const edited = messagesOf(h, IDS.fabricTest).find(message => message.ts === one);
  assert.deepEqual([edited.text, edited.attachments], ['v2', undefined], 'the whole text replaced and the attachments removed');
  const other = refusedAs(await h.run('edit-message v1', {channel: IDS.fabricTest, ts: h.simulator.synthetic.two, text: 'mine now'}), 'wrong_kind');
  assert.deepEqual([other.details.transform, other.details.transformReason], ['collections.oneOf@1', 'not_one_of']);
  apiError(await h.run('edit-message v1', {channel: IDS.fabricTest, ts: '1793000000.000001', text: 'gone'}), 'thread_not_found');
  assert.deepEqual(writes(h), ['chat.update'], 'nothing written for either refusal');
  h.simulator.swallow('chat.update');
  const swallowed = ended(await approved(h, 'edit-message v1', {channel: IDS.fabricTest, ts: one, text: 'v3'}), 'uncertain', 'outcome_uncertain');
  assert.equal(swallowed.result.verification.status, 'unverified');
  h.simulator.closeEditWindow();
  ended(await approved(h, 'edit-message v1', {channel: IDS.fabricTest, ts: one, text: 'v4'}), 'failed', 'provider_failed', {reason: 'api_error', details: {providerError: 'edit_window_closed'}});
  assert.equal(messagesOf(h, IDS.fabricTest).find(message => message.ts === one).text, 'v2', 'nothing changed');
});

// ---- Read a thread and Reply in a thread ----------------------------------------------------------------------------------------------
test('Read a thread and Reply in a thread: a reply\'s link reads and replies to its parent; a link and ids together refuse wrong_kind; a bad link refuses slack_link_invalid', async t => {
  const h = slackHarness(t), {['Welcome to #general']: welcome, Hello: hello} = general(h), link = linkOf(IDS.general, hello, welcome);
  const read = ended(await h.run('read-thread v1', {link}), 'succeeded', null);
  assert.deepEqual(read.result.data.messages.map(message => message.text), ['Welcome to #general', 'Thanks', 'Hello']);
  assert.deepEqual(h.simulator.calls.at(-1).query, {channel: IDS.general, ts: welcome, limit: '15'});
  assert.deepEqual(ended(await h.run('read-thread v1', {channel: IDS.general, ts: hello}), 'succeeded', null).result.data.messages.map(message => message.ts), read.result.data.messages.map(message => message.ts));
  const reply = await prepared(h, 'reply-thread v1', {link, text: 'Noted'});
  assert.deepEqual(h.simulator.calls.filter(call => call.name === 'conversations.replies').at(-1).query, {channel: IDS.general, ts: welcome, limit: '1'}, 'the parent is read at the link\'s thread, not its own ts');
  assert.deepEqual(h.fields(reply), {Channel: '#general (C0GENERAL1)', 'Replying to': 'Welcome to #general', Message: 'Noted'});
  assert.deepEqual(bodyOf(h, reply), {channel: IDS.general, thread_ts: welcome, text: 'Noted', ...FLAGS, reply_broadcast: false});
  const done = ended(await h.approve(reply), 'succeeded', null);
  assert.deepEqual([done.result.verification.status, done.result.data.threadTs, done.result.data.permalink.includes(`thread_ts=${welcome}`)], ['verified', welcome, true]);
  const byIds = await prepared(h, 'reply-thread v1', {channel: IDS.general, ts: hello, text: 'Also'});
  assert.equal(bodyOf(h, byIds).thread_ts, welcome, 'the ts of a reply replies to its parent');
  const sent = h.simulator.calls.length;
  for (const input of [{link, channel: IDS.general}, {link, ts: hello}, {channel: IDS.general}, {ts: hello}, {}]) {
    refusedAs(await h.run('read-thread v1', input), 'wrong_kind');
    refusedAs(await h.run('reply-thread v1', {...input, text: 'x'}), 'wrong_kind');
  }
  for (const bad of ['https://example.com/archives/C0GENERAL1/p1793000000000100', `https://fabric-test.slack.com/archives/${IDS.general}/p17930000`]) {
    refusedAs(await h.run('read-thread v1', {link: bad}), 'slack_link_invalid');
    refusedAs(await h.run('reply-thread v1', {link: bad, text: 'x'}), 'slack_link_invalid');
  }
  assert.equal(h.simulator.calls.length, sent, 'refused before any request');
});

test('channel writes refuse a direct message (wrong_kind, nothing written): Send a direct message is the one write there', async t => {
  const h = slackHarness(t);
  const dm = await approved(h, 'send-dm v1', {user: IDS.owner, text: 'Mine'}, {opens: 1}), ts = dm.result.data.ts;
  const count = h.simulator.writes().length;
  for (const [key, input] of [['send-message v1', {channel: IDS.selfDm, text: 'x'}], ['reply-thread v1', {channel: IDS.selfDm, ts, text: 'x'}], ['edit-message v1', {channel: IDS.selfDm, ts, text: 'x'}],
    ['react v1', {do: 'add', channel: IDS.selfDm, ts, emoji: 'eyes'}], ['schedule-message v1', {do: 'schedule', channel: IDS.selfDm, text: 'x', at: inMinutes(h, 60)}]]) {
    const job = refusedAs(await h.run(key, input), 'wrong_kind');
    assert.equal(job.details.transformReason, 'not_one_of', key);
  }
  assert.equal(h.simulator.writes().length, count);
});

// ---- Find a person -----------------------------------------------------------------------------------------------------------------------
test('Find a person: by email with users:read.email only the lookup runs; without it the list runs and finds no hidden email; by name several match; by id users.info; it never guesses', async t => {
  const h = slackHarness(t), ada = {id: IDS.ada, name: 'Ada Lovelace', displayName: 'ada', isBot: false, deleted: false};
  assert.deepEqual(ended(await h.run('find-person v1', {email: 'ADA@example.com'}), 'succeeded', null).result.data, {people: [ada]});
  assert.deepEqual(ended(await h.run('find-person v1', {email: 'nobody@example.com'}), 'succeeded', null).result.data, {people: []}, 'an empty list is an answer');
  assert.deepEqual(names(h), ['users.lookupByEmail', 'users.lookupByEmail'], 'only the lookup runs');
  h.simulator.addPerson({id: 'U0ADA0002', name: 'ada2', realName: 'Ada Lovelace', email: 'ada2@example.com'});
  const byName = ended(await h.run('find-person v1', {name: 'ada lovelace'}), 'succeeded', null);
  assert.deepEqual(byName.result.data.people, [ada, {id: 'U0ADA0002', name: 'Ada Lovelace', displayName: 'ada2', isBot: false, deleted: false}], 'every candidate, in the workspace\'s order');
  assert.deepEqual(names(h).slice(2), ['users.list', 'users.info', 'users.info']);
  assert.deepEqual(h.simulator.calls[2].query, {limit: '100'});
  assert.deepEqual(ended(await h.run('find-person v1', {user: IDS.grace}), 'succeeded', null).result.data.people, [{id: IDS.grace, name: 'Grace Hopper', displayName: 'grace', isBot: false, deleted: false}]);
  assert.deepEqual(ended(await h.run('find-person v1', {user: 'U0NOBODY01'}), 'succeeded', null).result.data.people, []);
  assert.deepEqual(ended(await h.run('find-person v1', {name: 'Nobody At All'}), 'succeeded', null).result.data.people, []);
  for (const input of [{email: 'ada@example.com', name: 'Ada Lovelace'}, {name: 'Ada', user: IDS.ada}, {}]) refusedAs(await h.run('find-person v1', input), 'wrong_kind');
  const bare = slackHarness(t, {scopes: SCOPES.filter(scope => scope !== 'users:read.email')});
  const hidden = ended(await bare.run('find-person v1', {email: 'ada@example.com'}), 'succeeded', null);
  assert.deepEqual([hidden.result.data.people, names(bare)], [[], ['users.list']], 'Slack hides email addresses without the scope: no one, never a guess');
});

// ---- Search messages ---------------------------------------------------------------------------------------------------------------------
test('Search messages: the words stay one quoted phrase and in: and from: come only from ids; without search:read the action needs more access', async t => {
  const h = slackHarness(t), {one, two} = h.simulator.synthetic;
  const job = ended(await h.run('search-messages v1', {words: '[SYNTHETIC] Fabric', channel: IDS.fabricTest}), 'succeeded', null);
  assert.deepEqual(h.simulator.calls.at(-1).query, {query: '"[SYNTHETIC] Fabric" in:<#C0FABTEST1>', count: '20', sort: 'timestamp', sort_dir: 'desc', highlight: 'false'});
  assert.deepEqual(job.result.data.matches.map(match => [match.channel, match.channelName, match.ts, match.user, match.text]), [
    [IDS.fabricTest, 'fabric-test', two, IDS.ada, '[SYNTHETIC] Fabric message 2'], [IDS.fabricTest, 'fabric-test', one, IDS.owner, '[SYNTHETIC] Fabric message 1']]);
  assert.deepEqual([job.result.data.page, job.result.data.pages, job.result.data.total, typeof job.result.data.matches[0].time, job.result.data.matches[0].permalink.includes(IDS.fabricTest)],
    [1, 1, 2, 'string', true]);
  const from = ended(await h.run('search-messages v1', {words: 'Fabric', from: IDS.ada, page: 1}), 'succeeded', null);
  assert.deepEqual([h.simulator.calls.at(-1).query.query, h.simulator.calls.at(-1).query.page, from.result.data.matches.map(match => match.ts)], ['"Fabric" from:<@U0ADA0001>', '1', [two]]);
  const words = ended(await h.run('search-messages v1', {words: 'from:<@U0ADA0001> in:#general'}), 'succeeded', null);
  assert.deepEqual([h.simulator.calls.at(-1).query.query, words.result.data.matches], ['"from:<@U0ADA0001> in:#general"', []], 'a modifier typed in the words stays words');
  const sent = h.simulator.calls.length;
  for (const input of [{words: 'say "hi"'}, {words: 'x', channel: '#general-room'}]) refusedAs(await h.run('search-messages v1', input), 'query_value_invalid');
  assert.equal(h.simulator.calls.length, sent);
  const bare = slackHarness(t, {scopes: SCOPES.filter(scope => scope !== 'search:read')});
  await assert.rejects(bare.run('search-messages v1', {words: 'Fabric'}), NEEDS_ACCESS);
  assert.equal(bare.simulator.calls.length, 0);
});

// ---- Read a canvas -----------------------------------------------------------------------------------------------------------------------
test('Read a canvas: a short canvas comes back whole; 60,000 characters come back cut at 50,000 with the marker', async t => {
  const h = slackHarness(t);
  assert.deepEqual(ended(await h.run('read-canvas v1', {canvas: IDS.canvas}), 'succeeded', null).result.data,
    {canvas: IDS.canvas, content: '# [SYNTHETIC] Fabric canvas\n\nA canvas Fabric reads in its tests.\n'});
  assert.deepEqual(h.simulator.calls.at(-1).body, {canvas_id: IDS.canvas, content_type: 'markdown'});
  h.simulator.data.canvases[IDS.canvas].content = 'x'.repeat(60_000);
  const cut = ended(await h.run('read-canvas v1', {canvas: IDS.canvas}), 'succeeded', null).result.data;
  assert.deepEqual([cut.content.length, cut.content.endsWith('\n[truncated]'), cut.truncated], [50_000, true, true]);
});

// ---- pages -------------------------------------------------------------------------------------------------------------------------------
test('pages: List channels and DMs (100 a page), Read recent messages and Read a thread (15 a page) return nextCursor and take it back; a page size is not an input', async t => {
  const h = slackHarness(t);
  for (let index = 0; index < 100; index++) h.simulator.addChannel({id: `C1PAGE${String(index).padStart(4, '0')}`, name: `page-${index}`});
  const first = ended(await h.run('list-conversations v1', {}), 'succeeded', null);
  assert.deepEqual(h.simulator.calls.at(-1).query, {types: 'public_channel,private_channel,mpim,im', exclude_archived: 'true', limit: '100'});
  assert.deepEqual([first.result.data.channels.length, typeof first.result.data.nextCursor, first.result.data.channels[0]],
    [100, 'string', {id: IDS.general, name: 'general', isPrivate: false, isIm: false, isMpim: false}]);
  assert.ok(first.result.data.channels.some(channel => channel.id === IDS.selfDm && channel.isIm && channel.user === IDS.owner), 'a DM names the person it is with');
  const rest = ended(await h.run('list-conversations v1', {cursor: first.result.data.nextCursor}), 'succeeded', null);
  assert.deepEqual([rest.result.data.channels.map(channel => channel.id), rest.result.data.nextCursor], [['C1PAGE0096', 'C1PAGE0097', 'C1PAGE0098', 'C1PAGE0099'], undefined]);
  for (let index = 0; index < 20; index++) h.simulator.post(IDS.fabricTest, {user: IDS.ada, text: `note ${index}`});
  const page = ended(await h.run('read-messages v1', {channel: IDS.fabricTest}), 'succeeded', null);
  assert.deepEqual([page.result.data.messages.length, page.result.data.hasMore, page.result.data.messages[0].text], [15, true, 'note 19']);
  const next = ended(await h.run('read-messages v1', {channel: IDS.fabricTest, cursor: page.result.data.nextCursor}), 'succeeded', null);
  assert.deepEqual([next.result.data.messages.length, next.result.data.hasMore, next.result.data.nextCursor], [7, false, undefined]);
  for (let index = 0; index < 20; index++) h.simulator.post(IDS.fabricTest, {user: IDS.ada, text: `reply ${index}`, threadTs: h.simulator.synthetic.one});
  const thread = ended(await h.run('read-thread v1', {channel: IDS.fabricTest, ts: h.simulator.synthetic.one}), 'succeeded', null);
  assert.deepEqual([thread.result.data.messages.length, thread.result.data.messages[0].text, thread.result.data.messages[0].replyCount], [15, '[SYNTHETIC] Fabric message 1', 20]);
  const tail = ended(await h.run('read-thread v1', {channel: IDS.fabricTest, ts: h.simulator.synthetic.one, cursor: thread.result.data.nextCursor}), 'succeeded', null);
  assert.deepEqual([tail.result.data.messages.length, tail.result.data.nextCursor], [6, undefined]);
  const sent = h.simulator.calls.length;
  await assert.rejects(h.run('read-messages v1', {channel: IDS.fabricTest, limit: 100}));
  await assert.rejects(h.run('list-conversations v1', {limit: 1000}));
  assert.equal(h.simulator.calls.length, sent);
});

// ---- modes -------------------------------------------------------------------------------------------------------------------------------
test('modes: reads run at Allow with no card; a write asks once under the defaults; a Never on "Access messages" refuses every action that reads it, readbacks included, before any call', async t => {
  const h = slackHarness(t);
  for (const [key, input] of [['list-conversations v1', {}], ['read-messages v1', {channel: IDS.fabricTest}], ['find-person v1', {user: IDS.ada}], ['read-canvas v1', {canvas: IDS.canvas}]]) {
    const job = ended(await h.run(key, input), 'succeeded', null);
    assert.deepEqual([job.action.modes.perform, job.approvedBy], ['allow', 'standing-policy'], key);
  }
  for (const [key, input] of [['send-message v1', {channel: IDS.fabricTest, text: 'x'}], ['set-status v1', {do: 'clear'}]]) {
    assert.deepEqual((await prepared(h, key, input)).action.modes, {prepare: 'allow', resolve: null, perform: 'ask'}, key);
  }
  h.setRow('slack.messages.read', 'deny');
  const sent = h.simulator.calls.length;
  for (const [key, input] of [['edit-message v1', {channel: IDS.fabricTest, ts: h.simulator.synthetic.one, text: 'x'}], ['reply-thread v1', {channel: IDS.fabricTest, ts: h.simulator.synthetic.one, text: 'x'}],
    ['send-message v1', {channel: IDS.fabricTest, text: 'x'}], ['read-thread v1', {channel: IDS.fabricTest, ts: h.simulator.synthetic.one}]]) {
    await assert.rejects(h.run(key, input), NEVER_MESSAGES, key);
  }
  assert.equal(h.simulator.calls.length, sent, 'refused before any call');
});

// ---- secrets and evidence ------------------------------------------------------------------------------------------------------------------
test('credentials never reach a job, a prepared request, a card, an audit row or an output; evidence and stores stay under the temp root', async t => {
  const shipped = new URL('../docs/live-evidence/slack/actions.json', import.meta.url), before = existsSync(shipped) ? readFileSync(shipped, 'utf8') : null;
  const h = slackHarness(t);
  h.simulator.post(IDS.fabricTest, {user: IDS.ada, text: `Pasted ${TOKEN} by mistake`});
  const read = ended(await h.run('read-messages v1', {channel: IDS.fabricTest}), 'succeeded', null);
  const job = await prepared(h, 'send-message v1', {channel: IDS.fabricTest, text: 'Checked'});
  const card = h.card(job), done = ended(await h.approve(job), 'succeeded', null);
  for (const [name, value] of [['jobs', h.store.list('jobs')], ['card', card], ['audit', h.store.list('activity')], ['outputs', [read.result, done.result]], ['calls', h.simulator.calls]]) {
    assert.ok(!JSON.stringify(value).includes(TOKEN), name);
  }
  assert.equal(read.result.data.messages[0].text, 'Pasted [redacted] by mistake', 'the token an answer echoes is scrubbed before anything reads it');
  assert.ok(existsSync(`${h.root}/docs/live-evidence/slack/actions.json`));
  assert.equal(existsSync(shipped) ? readFileSync(shipped, 'utf8') : null, before, 'the shipped evidence is never written by a test');
});

// ---- the simulator case list (check 5) ---------------------------------------------------------------------------------------------------
const MANIFEST = JSON.parse(readFileSync(new URL('./fixtures/provider-simulators/slack.cases.json', import.meta.url), 'utf8'));
const ENTRIES = validateActionFile(currentFile(), slackDeps()).actions;
const SLACK_ERROR = error => ({data: {ok: false, error}});
const refusedNever = async (h, row, key, input) => {
  h.setRow(row, 'deny');
  await assert.rejects(h.run(key, input), /is set to Never, so this action is refused before any call/);
  assert.equal(h.simulator.calls.length, 0);
};
const lost = async (h, name, key, input, options) => { h.simulator.drop(name); return ended(await approved(h, key, input, options), 'uncertain', 'outcome_uncertain'); };
const swallowed = async (h, name, key, input, options) => {
  h.simulator.swallow(name);
  const job = ended(await approved(h, key, input, options), 'uncertain', 'outcome_uncertain');
  assert.equal(job.result.verification.status, 'unverified');
  return job;
};
const SEND_ARGS = {channel: IDS.fabricTest, text: 'Hello'}, DM = {user: IDS.ada, text: 'Hello'};
const reacting = h => ({do: 'add', channel: IDS.fabricTest, ts: h.simulator.synthetic.two, emoji: 'white_check_mark'});
const scheduling = h => ({do: 'schedule', channel: IDS.fabricTest, text: 'Later', at: inMinutes(h, 120)});
const editing = h => ({channel: IDS.fabricTest, ts: h.simulator.synthetic.one, text: 'v2'});
const replying = h => ({channel: IDS.fabricTest, ts: h.simulator.synthetic.one, text: 'Reply'});
const statusing = h => ({do: 'set', text: 'Away', emoji: 'palm_tree', until: inMinutes(h, 30)});
const IMPLEMENTATIONS = {
  'list-conversations v1/succeeds': async t => { const h = slackHarness(t); assert.ok(ended(await h.run('list-conversations v1', {}), 'succeeded', null).result.data.channels.some(channel => channel.id === IDS.fabricTest)); },
  'list-conversations v1/refused': async t => refusedNever(slackHarness(t), 'slack.channels.read', 'list-conversations v1', {}),
  'list-conversations v1/provider-refusal': async t => { const h = slackHarness(t); apiError(await h.run('list-conversations v1', {cursor: 'not-a-cursor'}), 'invalid_cursor'); },
  'read-messages v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await h.run('read-messages v1', {channel: IDS.fabricTest}), 'succeeded', null).result.data.messages[0].ts, h.simulator.synthetic.two); },
  'read-messages v1/refused': async t => refusedNever(slackHarness(t), 'slack.messages.read', 'read-messages v1', {channel: IDS.fabricTest}),
  'read-messages v1/provider-refusal': async t => { const h = slackHarness(t); apiError(await h.run('read-messages v1', {channel: IDS.secret}), 'channel_not_found'); },
  'read-thread v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await h.run('read-thread v1', {channel: IDS.fabricTest, ts: h.simulator.synthetic.one}), 'succeeded', null).result.data.messages.length, 1); },
  'read-thread v1/refused': async t => { const h = slackHarness(t); refusedAs(await h.run('read-thread v1', {link: 'https://example.com/x'}), 'slack_link_invalid'); assert.equal(h.simulator.calls.length, 0); },
  'read-thread v1/provider-refusal': async t => { const h = slackHarness(t); apiError(await h.run('read-thread v1', {channel: IDS.fabricTest, ts: '1793000000.000001'}), 'thread_not_found'); },
  'search-messages v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await h.run('search-messages v1', {words: 'Fabric message'}), 'succeeded', null).result.data.total, 2); },
  'search-messages v1/refused': async t => { const h = slackHarness(t); refusedAs(await h.run('search-messages v1', {words: 'a\nb'}), 'query_value_invalid'); assert.equal(h.simulator.calls.length, 0); },
  'search-messages v1/provider-refusal': async t => { const h = slackHarness(t); h.simulator.fail('search.messages', SLACK_ERROR('invalid_arguments')); apiError(await h.run('search-messages v1', {words: 'Fabric'}), 'invalid_arguments'); },
  'find-person v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await h.run('find-person v1', {user: IDS.ada}), 'succeeded', null).result.data.people[0].name, 'Ada Lovelace'); },
  'find-person v1/refused': async t => { const h = slackHarness(t); refusedAs(await h.run('find-person v1', {email: 'ada@example.com', user: IDS.ada}), 'wrong_kind'); assert.equal(h.simulator.calls.length, 0); },
  'find-person v1/provider-refusal': async t => { const h = slackHarness(t); h.simulator.fail('users.info', SLACK_ERROR('fatal_error')); apiError(await h.run('find-person v1', {user: IDS.ada}), 'fatal_error'); },
  'send-message v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await approved(h, 'send-message v1', SEND_ARGS), 'succeeded', null).result.verification.status, 'verified'); },
  'send-message v1/refused': async t => { const h = slackHarness(t); refusedAs(await h.run('send-message v1', {channel: IDS.selfDm, text: 'x'}), 'wrong_kind'); assert.deepEqual(writes(h), []); },
  'send-message v1/provider-refusal': async t => {
    const h = slackHarness(t), before = messagesOf(h, IDS.archived).length;
    apiError(await approved(h, 'send-message v1', {channel: IDS.archived, text: 'x'}), 'is_archived');
    assert.equal(messagesOf(h, IDS.archived).length, before);
  },
  'send-message v1/unverified': async t => swallowed(slackHarness(t), 'chat.postMessage', 'send-message v1', SEND_ARGS),
  'send-message v1/lost-answer': async t => { const h = slackHarness(t); await lost(h, 'chat.postMessage', 'send-message v1', SEND_ARGS); assert.equal(messagesOf(h, IDS.fabricTest).at(-1).text, 'Hello', 'applied'); },
  'reply-thread v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await approved(h, 'reply-thread v1', replying(h)), 'succeeded', null).result.data.threadTs, h.simulator.synthetic.one); },
  'reply-thread v1/refused': async t => refusedNever(slackHarness(t), 'slack.messages.send', 'reply-thread v1', {channel: IDS.fabricTest, ts: '1793000000.000001', text: 'x'}),
  'reply-thread v1/provider-refusal': async t => { const h = slackHarness(t); h.simulator.fail('chat.postMessage', SLACK_ERROR('restricted_action')); apiError(await approved(h, 'reply-thread v1', replying(h)), 'restricted_action'); },
  'reply-thread v1/unverified': async t => { const h = slackHarness(t); await swallowed(h, 'chat.postMessage', 'reply-thread v1', replying(h)); },
  'reply-thread v1/lost-answer': async t => { const h = slackHarness(t); await lost(h, 'chat.postMessage', 'reply-thread v1', replying(h)); assert.equal(messagesOf(h, IDS.fabricTest).at(-1).thread_ts, h.simulator.synthetic.one); },
  'send-dm v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await approved(h, 'send-dm v1', DM, {opens: 1}), 'succeeded', null).result.data.channel, 'D0ADA0001'); },
  'send-dm v1/refused': async t => refusedNever(slackHarness(t), 'slack.conversations.mark', 'send-dm v1', DM),
  'send-dm v1/provider-refusal': async t => {
    const h = slackHarness(t);
    apiError(await h.approve(await h.run('send-dm v1', {user: IDS.gone, text: 'x'})), 'user_disabled');
    assert.deepEqual(writes(h), ['conversations.open'], 'the open was refused; nothing posted');
  },
  'send-dm v1/unverified': async t => swallowed(slackHarness(t), 'chat.postMessage', 'send-dm v1', DM, {opens: 1}),
  'send-dm v1/lost-answer': async t => lost(slackHarness(t), 'chat.postMessage', 'send-dm v1', DM, {opens: 1}),
  'edit-message v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await approved(h, 'edit-message v1', editing(h)), 'succeeded', null).result.verification.status, 'verified'); },
  'edit-message v1/refused': async t => { const h = slackHarness(t); refusedAs(await h.run('edit-message v1', {...editing(h), ts: h.simulator.synthetic.two}), 'wrong_kind'); assert.deepEqual(writes(h), []); },
  'edit-message v1/provider-refusal': async t => { const h = slackHarness(t), job = await prepared(h, 'edit-message v1', editing(h)); h.simulator.closeEditWindow(); apiError(await h.approve(job), 'edit_window_closed'); },
  'edit-message v1/unverified': async t => { const h = slackHarness(t); await swallowed(h, 'chat.update', 'edit-message v1', editing(h)); },
  'edit-message v1/lost-answer': async t => { const h = slackHarness(t); await lost(h, 'chat.update', 'edit-message v1', editing(h)); assert.equal(messagesOf(h, IDS.fabricTest)[0].text, 'v2', 'applied'); },
  'react v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await approved(h, 'react v1', reacting(h)), 'succeeded', null).result.verification.status, 'verified'); },
  'react v1/refused': async t => { const h = slackHarness(t); refusedAs(await h.run('react v1', {...reacting(h), emoji: '✅'}), 'emoji_invalid'); assert.deepEqual(writes(h), []); },
  'react v1/provider-refusal': async t => { const h = slackHarness(t); apiError(await approved(h, 'react v1', {...reacting(h), ts: '1793000000.000001'}), 'message_not_found'); },
  'react v1/unverified': async t => { const h = slackHarness(t); await swallowed(h, 'reactions.add', 'react v1', reacting(h)); },
  'react v1/lost-answer': async t => { const h = slackHarness(t); await lost(h, 'reactions.add', 'react v1', reacting(h)); assert.deepEqual(messagesOf(h, IDS.fabricTest)[1].reactions[0].users, [IDS.owner]); },
  'schedule-message v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await approved(h, 'schedule-message v1', scheduling(h)), 'succeeded', null).result.verification.status, 'verified'); },
  'schedule-message v1/refused': async t => { const h = slackHarness(t); refusedAs(await h.run('schedule-message v1', {...scheduling(h), at: inMinutes(h, -1)}), 'time_window'); assert.equal(h.simulator.calls.length, 0); },
  'schedule-message v1/provider-refusal': async t => { const h = slackHarness(t); apiError(await approved(h, 'schedule-message v1', {...scheduling(h), channel: IDS.archived}), 'is_archived'); },
  'schedule-message v1/unverified': async t => { const h = slackHarness(t); await swallowed(h, 'chat.scheduleMessage', 'schedule-message v1', scheduling(h)); },
  'schedule-message v1/lost-answer': async t => { const h = slackHarness(t); await lost(h, 'chat.scheduleMessage', 'schedule-message v1', scheduling(h)); assert.equal(h.simulator.state().scheduled.length, 1, 'applied'); },
  'set-status v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await approved(h, 'set-status v1', statusing(h)), 'succeeded', null).result.data.statusText, 'Away'); },
  'set-status v1/refused': async t => { const h = slackHarness(t); refusedAs(await h.run('set-status v1', {...statusing(h), until: inMinutes(h, 31 * 24 * 60)}), 'time_window'); assert.equal(h.simulator.calls.length, 0); },
  'set-status v1/provider-refusal': async t => { const h = slackHarness(t); h.simulator.fail('users.profile.set', SLACK_ERROR('invalid_profile')); apiError(await approved(h, 'set-status v1', statusing(h)), 'invalid_profile'); },
  'set-status v1/unverified': async t => { const h = slackHarness(t); await swallowed(h, 'users.profile.set', 'set-status v1', statusing(h)); },
  'set-status v1/lost-answer': async t => { const h = slackHarness(t); await lost(h, 'users.profile.set', 'set-status v1', statusing(h)); assert.equal(h.simulator.state().people[0].profile.status_text, 'Away', 'applied'); },
  'read-canvas v1/succeeds': async t => { const h = slackHarness(t); assert.equal(ended(await h.run('read-canvas v1', {canvas: IDS.canvas}), 'succeeded', null).result.data.canvas, IDS.canvas); },
  'read-canvas v1/refused': async t => refusedNever(slackHarness(t), 'slack.files.read', 'read-canvas v1', {canvas: IDS.canvas}),
  'read-canvas v1/provider-refusal': async t => { const h = slackHarness(t); apiError(await h.run('read-canvas v1', {canvas: 'F0NOCANVAS1'}), 'canvas_not_found'); },
};
caseTests(test, MANIFEST, ENTRIES, IMPLEMENTATIONS);

// ---- the live plan (step 22's S0 to S6) ----------------------------------------------------------------------------------------------------
const PLAN = () => JSON.parse(readFileSync(new URL('../catalog/live-tests/slack.json', import.meta.url), 'utf8'));
const planDeps = () => ({entries: ENTRIES, superseded: [], groups: PERMISSION_GROUPS.get('slack'), config: PROXY_CONFIGS.get('slack'), rules: RULES});
const callsOf = item => [...item.steps, ...(item.undo?.steps ?? [])].map(step => step.call).filter(Boolean);

test('the live plan S0 to S6 passes step 12\'s plan check against the shipped file and the guard\'s rules, calls all 13 actions, and keeps S0\'s canvas read and the undos of S1, S4 and S6', () => {
  const checked = checkPlan(PLAN(), planDeps());
  assert.deepEqual(checked.plan.tests.map(item => item.id), ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6']);
  assert.deepEqual([...checked.actions.keys()].sort(), ENTRIES.map(entry => `${entry.key}@${entry.version}`).sort());
  assert.deepEqual(Object.keys(checked.plan.recorded), ['fabricTest', 'selfDm', 'ownerUser', 'synthetic1', 'synthetic2', 'canvas']);
  const test = id => checked.plan.tests.find(item => item.id === id);
  assert.deepEqual(callsOf(test('S0')).map(call => call.action), ['list-conversations@1', 'read-messages@1', 'read-thread@1', 'search-messages@1', 'find-person@1', 'read-canvas@1']);
  assert.equal(test('S0').undo, undefined, 'a read pass undoes nothing');
  assert.deepEqual(test('S1').undo.steps.map(step => [step.call.action, step.call.args.do]), [['schedule-message@1', 'cancel']]);
  assert.deepEqual(test('S4').undo.steps.map(step => [step.call.action, step.call.args.do]), [['react@1', 'remove']]);
  assert.deepEqual(test('S6').undo.steps.map(step => [step.call.action, step.call.args.do]), [['set-status@1', 'clear']]);
  for (const id of ['S2', 'S3', 'S5']) assert.match(test(id).undo.none, /chat\.delete/);
  assert.deepEqual(test('S1').steps[0].call.args.at, {$in: {minutes: 120}});
  assert.deepEqual(test('S6').steps[0].call.args.until, {$in: {minutes: 10}});
});

/** One check of a plan step, as lib/live-certify.mjs reads it, over a call's output (no status) or a read's answer. */
function planCheck(check, {status, body}) {
  const at = (value, pointer) => pointer === '' ? value : pointer.slice(1).split('/').reduce((item, key) => item === undefined || item === null ? undefined : item[key], value);
  const same = (a, b) => canonicalHash([a]) === canonicalHash([b]);
  if (Object.hasOwn(check, 'status')) return [check.status].flat().includes(status);
  const value = at(body, check.pointer);
  if (Object.hasOwn(check, 'where')) {
    const chosen = (Array.isArray(value) ? value : []).filter(entry => Object.entries(check.where).every(([pointer, wanted]) => same(at(entry, pointer), wanted)));
    return chosen.length === 1 && same(at(chosen[0], check.field), check.equals);
  }
  if (Object.hasOwn(check, 'equals')) return value !== undefined && same(value, check.equals);
  if (Object.hasOwn(check, 'present')) return (value !== undefined && value !== null) === check.present;
  return assert.fail(`a check the plan does not use: ${JSON.stringify(check)}`);
}

test('a simulated run of S0 to S6: every step of the plan, its placeholders filled, runs on the simulator behind the live guard; every call succeeds verified and every check holds', async t => {
  const h = slackHarness(t), folder = mkdtempSync(path.join(tmpdir(), 'fabric-slack-plan-'));
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  const recorded = {fabricTest: IDS.fabricTest, selfDm: IDS.selfDm, ownerUser: IDS.owner, synthetic1: h.simulator.synthetic.one, synthetic2: h.simulator.synthetic.two, canvas: IDS.canvas};
  const guard = createGuard({appId: 'slack', runId: 'ABCDEFGH', folder, key: randomBytes(32), clock: () => h.now});
  guard.setOwner({email: 'owner@example.com', timeZone: 'UTC', runDate: '2026-10-26', recorded});
  h.runtime.request = guard.wrap(h.simulator.request);
  const run = {runId: 'ABCDEFGH', runDate: '2026-10-26', timeZone: 'UTC', recorded, saved: {}};
  const fill = (value, item) => fillPlaceholders(value, {run, account: {}, clock: () => h.now}, item);
  let calls = 0, reads = 0;
  for (const item of PLAN().tests) {
    guard.begin(item.id);
    for (const step of [...item.steps, ...(item.undo?.steps ?? [])]) {
      if (step.call) {
        let job = await h.run(step.call.action.replace('@', ' v'), fill(step.call.args ?? {}, item));
        while (job.status === 'awaiting_approval') job = await h.approve(job);
        ended(job, 'succeeded', null);
        assert.ok(['verified', 'observed'].includes(job.result.verification.status), `${item.id} ${step.call.action}`);
        for (const [name, pointer] of Object.entries(step.call.save ?? {})) run.saved[name] = pointer.slice(1).split('/').reduce((value, key) => value?.[key], job.result.data);
        for (const check of fill(step.call.checks ?? [], item)) assert.ok(planCheck(check, {body: job.result.data}), `${item.id} ${step.call.action}: ${JSON.stringify(check)}`);
        calls++;
      } else {
        const query = Object.fromEntries(Object.entries(fill(step.read.query ?? {}, item)).map(([name, value]) => [name, String(value)]));
        const job = await h.proxy({method: 'GET', path: step.read.path, ...(Object.keys(query).length ? {query} : {})});
        assert.equal(job.status, 'succeeded', `${item.id} ${step.read.path}`);
        const answer = {status: job.result.response.status, body: h.runtime.proxyResponse(job).body};
        for (const check of fill(step.read.checks ?? [], item)) assert.ok(planCheck(check, answer), `${item.id} ${step.read.path}: ${JSON.stringify(check)}`);
        reads++;
      }
    }
    guard.end();
  }
  assert.deepEqual([calls, reads], [17, 7], 'S0\'s six reads, the eight writes and three undos; seven readbacks');
  assert.ok(guard.counts().writes >= 10, `the guard counted ${guard.counts().writes} writes`);
  assert.deepEqual(h.simulator.notifications(), []);
  assert.deepEqual([h.simulator.state().scheduled, h.simulator.state().people[0].profile.status_text], [[], ''], 'S1 and S6 left nothing behind');
});

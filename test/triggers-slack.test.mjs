import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {triggerIds, validateTriggerFile} from '../lib/triggers.mjs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {BASE, IDS, ORIGIN} from './fixtures/provider-simulators/slack.mjs';
import {slackDeps, TOKEN} from './fixtures/actions/slack-harness.mjs';
import {shippedTriggers, triggerWorld} from './fixtures/actions/trigger-harness.mjs';

// Iteration 9 step 4 (docs/I07-BUILD-MAP.md step 4): Slack's seven triggers on Slack's simulator, on the shipped rows and proxy settings, through fabric/0.1 and the engine as server.mjs wires
// them. The cases of test/fixtures/provider-simulators/slack.trigger-cases.json run once per trigger, and the tests after them are the facts of Slack the map names. Every trigger is proven the
// same way: one write gives one event, and checking again gives none. Nothing here listens on a port or reaches Slack. A row reads as the map's table says: Allow on the shipped defaults.
const CHANNEL = IDS.fabricTest, DM = IDS.selfDm, INTERVAL = 150_000, MOVED = 'C0MOVED001', KEYS = Object.freeze(['new-message', 'new-dm', 'mention-search', 'thread-reply', 'reaction-recent', 'file-shared', 'conversation-joined']);
const READ = 'slack.messages.read', SEARCH = 'slack.messages.search', CHANNELS = 'slack.channels.read', HISTORY = 'conversations.history', REPLIES = 'conversations.replies';
const MENTION = `Hello <@${IDS.owner}>`, FILE = Object.freeze({id: 'F0SYNTH001', name: 'fabric-synthetic.txt', mimetype: 'text/plain'}), EMOJI = Object.freeze(['tada', 'eyes', 'rocket', 'heart', 'fire', 'clap']);
/** The conversation ids of a list of `length`, each a real id's shape. */
const ids = (length, prefix = 'C') => Array.from({length}, (_, index) => `${prefix}0CAPS${String(index).padStart(4, '0')}`);
const permalink = (channel, ts) => `https://fabric-test.slack.com/archives/${channel}/p${ts.replace('.', '')}`;

/**
 * What each trigger reads and how one change reaches it. `write()` makes one change and answers what `expected()` needs. `refuse()` makes Slack refuse the next poll with `refused`. `pages` is the most a
 * poll may read, and `over` the writes that pass it. `sized(n)` is the arguments with a list of n.
 */
const RIGS = Object.freeze({
  'new-message': world => {
    const {simulator} = world;
    return {args: {channels: [CHANNEL]}, sized: length => ({channels: ids(length)}), row: READ, method: HISTORY, write: () => simulator.post(CHANNEL, {user: IDS.ada, text: 'A new message'}), pages: 5, over: 501,
      expected: ts => ({id: `${CHANNEL}:${ts}`, fields: {channel: CHANNEL, ts, user: IDS.ada, self: IDS.owner}, summary: [{label: 'Message', value: 'A new message'}]}), refuse: () => simulator.renameId(CHANNEL, MOVED), refused: 'channel_not_found'};
  },
  'new-dm': world => {
    const {simulator} = world;
    return {args: {conversations: [DM]}, sized: length => ({conversations: ids(length, 'D')}), row: READ, method: HISTORY, write: () => simulator.post(DM, {user: IDS.ada, text: 'A direct message'}), pages: 5, over: 501,
      expected: ts => ({id: `${DM}:${ts}`, fields: {channel: DM, ts, user: IDS.ada, self: IDS.owner}, summary: [{label: 'Message', value: 'A direct message'}]}), refuse: () => simulator.renameId(DM, 'D0MOVED001'), refused: 'channel_not_found'};
  },
  'mention-search': world => {
    const {simulator} = world;
    return {args: {channels: [CHANNEL]}, sized: length => ({channels: ids(length)}), row: SEARCH, method: 'search.messages', write: () => simulator.post(CHANNEL, {user: IDS.ada, text: MENTION}), pages: 1, over: 3,
      expected: ts => ({id: `${CHANNEL}:${ts}`, fields: {channel: CHANNEL, ts, user: IDS.ada, permalink: permalink(CHANNEL, ts)}, summary: [{label: 'Message', value: MENTION}]}), refuse: () => { simulator.searchDeprecated = true; }, refused: 'method_deprecated'};
  },
  'thread-reply': world => {
    const {simulator} = world, parent = simulator.seed(CHANNEL, {user: IDS.ada, text: 'A thread'});
    return {args: {threads: [{channel: CHANNEL, ts: parent}]}, sized: length => ({threads: ids(length).map(channel => ({channel, ts: parent}))}), row: READ, method: REPLIES, parent, pages: 3, over: 601,
      write: () => simulator.post(CHANNEL, {user: IDS.grace, text: 'A reply', threadTs: parent}), refuse: () => simulator.renameId(CHANNEL, MOVED), refused: 'channel_not_found',
      expected: ts => ({id: `${CHANNEL}:${ts}`, fields: {channel: CHANNEL, threadTs: parent, ts, user: IDS.grace, self: IDS.owner}, summary: [{label: 'Reply', value: 'A reply'}]})};
  },
  'reaction-recent': world => {
    const {simulator} = world, target = simulator.synthetic.two;
    let wrote = 0;
    return {args: {channels: [CHANNEL]}, sized: length => ({channels: ids(length)}), row: READ, method: HISTORY, target, pages: 1, over: 3,
      write: () => { const name = EMOJI[wrote++]; simulator.react(CHANNEL, target, name, IDS.grace); return name; }, refuse: () => simulator.renameId(CHANNEL, MOVED), refused: 'channel_not_found',
      expected: name => ({id: `${CHANNEL}:${target}:${name}`, fields: {channel: CHANNEL, ts: target, emoji: name, count: 1, messageUser: IDS.ada}, summary: [{label: 'Emoji', value: name}]})};
  },
  'file-shared': world => {
    const {simulator} = world;
    return {args: {channels: [CHANNEL]}, sized: length => ({channels: ids(length)}), row: READ, method: HISTORY, write: () => simulator.post(CHANNEL, {subtype: 'file_share', user: IDS.ada, upload: true, files: [FILE], text: 'A file'}), pages: 5, over: 501,
      expected: ts => ({id: `${CHANNEL}:${ts}`, fields: {channel: CHANNEL, ts, user: IDS.ada, fileId: FILE.id, fileName: FILE.name, mimetype: FILE.mimetype, self: IDS.owner}, summary: [{label: 'File', value: FILE.name}]}),
      refuse: () => simulator.renameId(CHANNEL, MOVED), refused: 'channel_not_found'};
  },
  'conversation-joined': world => {
    const {simulator} = world;
    let wrote = 0;
    return {args: {kinds: ['public_channel']}, sized: length => ({kinds: [...['public_channel', 'private_channel', 'mpim', 'im'], 'im'].slice(0, length)}), row: CHANNELS, method: 'users.conversations', pages: 5, over: 501,
      write: () => { const id = `C0NEWROOM${wrote++}`; simulator.addChannel({id, name: `room-${wrote}`, creator: IDS.ada, created: 1_761_000_000}); return id; }, refuse: () => { simulator.fail('users.conversations', {data: {ok: false, error: 'token_revoked'}}); }, refused: 'token_revoked',
      expected: id => ({id, fields: {channel: id, kind: 'public_channel', name: `room-${Number(id.slice(9)) + 1}`, creator: IDS.ada, created: 1_761_000_000, self: IDS.owner}, summary: [{label: 'Name', value: `room-${Number(id.slice(9)) + 1}`}]})};
  },
});
/** A world with one watch that has read the present and found nothing, and the clock moved on. */
async function started(t, key, options = {}) {
  const world = triggerWorld(t, 'slack', options), rig = RIGS[key](world), {id} = await world.subscribe(key, rig.args);
  world.approve(id);
  assert.equal((await world.pollNow(id)).status, 'active', `${key}: the first poll reached the present`);
  assert.deepEqual((await world.events()).events, [], `${key}: a baseline stores nothing`);
  world.advance(INTERVAL);
  return {world, rig, id};
}
const reads = (world, method) => world.simulator.calls.filter(call => call.name === method).length;
const feedOf = (world, id) => world.store.get('triggerFeeds', world.record(id).feeds[0]);
const shown = ({id, fields, summary}) => ({id, fields, summary});
const paused = record => [record.status, record.reason, record.detail];
/** Every event left to read. */
async function drained(world) {
  const events = [];
  for (;;) {
    const page = await world.events({limit: 100});
    events.push(...page.events);
    if (page.next >= page.latest) return events;
  }
}
const fired = events => events.filter(event => event.type === 'trigger.event');
const gaps = events => events.filter(event => event.type === 'trigger.gap');
/** One poll after one change: what it told, and the clock moved on. */
async function after(world, id, change = () => {}) {
  const answer = change();
  await world.pollNow(id);
  world.advance(INTERVAL);
  return {answer, events: await drained(world)};
}
/** Stops the next poll between storing its events and moving its cursor, as a crash would. */
function crashAtCursor(world) {
  const {store} = world, {put, appendPoll} = store;
  let appended = false;
  store.appendPoll = poll => { const answer = appendPoll.call(store, poll); appended = true; store.appendPoll = appendPoll; return answer; };
  store.put = (collection, document) => {
    if (appended && collection === 'triggerFeeds') { store.put = put; throw new Error('crashed before the cursor moved'); }
    return put.call(store, collection, document);
  };
}

// ---- the cases, once per trigger ------------------------------------------------------------------------------------------------------------------------
const WINDOWED = new Set(['mention-search', 'reaction-recent']);
const NO_MARK = new Set(['mention-search', 'reaction-recent', 'conversation-joined']);
const CASES = {};
for (const key of KEYS) {
  const named = kind => `${key} v1/${kind}`;
  CASES[named('baseline-silent')] = async t => {
    const world = triggerWorld(t, 'slack'), rig = RIGS[key](world);
    rig.write();
    const {id} = await world.subscribe(key, rig.args);
    world.approve(id);
    rig.write();
    assert.equal((await world.pollNow(id)).status, 'active');
    assert.deepEqual((await drained(world)), [], 'what was there before the first read, and a change made just before it, stay silent');
    world.advance(INTERVAL);
    await world.pollNow(id);
    assert.deepEqual(await drained(world), [], 'and the next read finds them known');
  };
  CASES[named('one-then-zero')] = async t => {
    const {world, rig, id} = await started(t, key), audits = world.store.list('activity').length, {answer, events} = await after(world, id, rig.write);
    assert.deepEqual(events.map(shown), [rig.expected(answer)], 'one write gives one event, with the fields its card lists');
    assert.equal(events[0].subscriptionId, id);
    assert.deepEqual((await after(world, id)).events, [], 'and checking again gives none');
    assert.equal(world.store.list('activity').length, audits, 'a poll writes no audit row');
  };
  CASES[named('crash-before-cursor')] = async t => {
    const {world, rig, id} = await started(t, key), before = structuredClone(feedOf(world, id).cursors), lastGood = feedOf(world, id).lastGoodAt, written = rig.write();
    crashAtCursor(world);
    await assert.rejects(world.pollNow(id), /crashed before the cursor moved/);
    assert.deepEqual([feedOf(world, id).cursors, feedOf(world, id).lastGoodAt], [before, lastGood], 'the crash left the place behind');
    world.advance(INTERVAL);
    await world.pollNow(id);
    if (!NO_MARK.has(key)) assert.notDeepEqual(feedOf(world, id).cursors, before, 'the replay moved it');
    assert.deepEqual((await drained(world)).map(shown), [rig.expected(written)], 'and found the seen rows current');
  };
  CASES[named('background-never')] = async t => {
    const {world, rig, id} = await started(t, key), sent = world.simulator.calls.length;
    world.store.put('backgroundPolicies', {id: world.account, connectionId: world.account, mode: 'deny', updatedAt: 'x'});
    rig.write();
    assert.deepEqual(paused(await world.pollNow(id)).slice(0, 2), ['paused', 'background_off']);
    assert.equal(world.simulator.calls.length, sent, 'zero network calls');
    assert.deepEqual(await drained(world), []);
  };
  CASES[named('row-never-mid-poll')] = async t => {
    const {world, rig, id} = await started(t, key), before = structuredClone(feedOf(world, id).cursors), lastGood = feedOf(world, id).lastGoodAt, held = world.simulator.hold(rig.method);
    rig.write();
    const flight = world.pollNow(id);
    await held.reached;
    world.setRow(rig.row, 'deny');
    held.release();
    assert.deepEqual(paused(await flight).slice(0, 2), ['paused', 'permission_changed']);
    assert.deepEqual([feedOf(world, id).cursors, feedOf(world, id).lastGoodAt], [before, lastGood], 'the results are discarded and the place kept');
    assert.deepEqual(await drained(world), []);
  };
  CASES[named('malformed-cursor')] = async t => {
    const {world, rig, id} = await started(t, key), sent = world.simulator.calls.length, feed = feedOf(world, id);
    // A snapshot's cursor is its seen rows, so what can be spoiled on one is the page it would resume from.
    world.store.put('triggerFeeds', NO_MARK.has(key) ? {...feed, page: {token: 'bad\ncursor', walk: 'delta'}} : {...feed, cursors: {ts: '1761490000'}});
    assert.deepEqual(paused(await world.pollNow(id)), ['paused', 'cursor_invalid', NO_MARK.has(key) ? 'page' : 'high-water-ts@1']);
    assert.equal(world.simulator.calls.length, sent, 'nothing is sent from a place Fabric cannot trust');
    assert.deepEqual(world.store.list('activity').filter(row => row.type === 'trigger.paused').map(row => [row.subscriptionId, row.reason]), [[id, 'cursor_invalid']]);
    world.advance(INTERVAL);
    assert.equal(world.resume(id).status, 'starting');
    assert.equal((await world.pollNow(id)).status, 'active', 'a Resume reads the present again');
    assert.deepEqual(gaps(await drained(world)).map(event => event.fields.reason), ['resume']);
    const {answer, events} = await after(world, id, rig.write);
    assert.deepEqual(events.map(shown), [rig.expected(answer)], 'and the watch reads on');
  };
  CASES[named('caps')] = async t => {
    const {world, rig, id} = await started(t, key), sent = reads(world, rig.method), calls = world.simulator.calls.length;
    await assert.rejects(world.subscribe(key, rig.sized(key === 'conversation-joined' ? 5 : 21)), error => error.code === 'invalid_request', 'a list past its cap is refused');
    assert.equal(world.simulator.calls.length, calls, 'and refused without a read');
    for (let count = 0; count < rig.over; count++) rig.write();
    await world.pollNow(id);
    assert.equal(reads(world, rig.method) - sent, rig.pages, `one poll reads at most ${rig.pages} pages`);
  };
  CASES[named('pause-on-refusal')] = async t => {
    const {world, rig, id} = await started(t, key), before = structuredClone(feedOf(world, id).cursors);
    rig.write();
    rig.refuse();
    assert.deepEqual(paused(await world.pollNow(id)), ['paused', 'provider_refused', rig.refused]);
    assert.deepEqual(feedOf(world, id).cursors, before);
    assert.deepEqual(await drained(world), []);
    const sent = world.simulator.calls.length;
    world.advance(INTERVAL);
    await world.engine.tick();
    assert.equal(world.simulator.calls.length, sent, 'a pause never resumes on its own');
  };
}
CASES['mention-search v1/resync-gap'] = async t => {
  const {world, id} = await started(t, 'mention-search');
  for (let count = 0; count < 101; count++) world.simulator.post(CHANNEL, {user: IDS.ada, text: MENTION});
  const {events} = await after(world, id);
  assert.deepEqual(events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'overflow']], 'a read of one page, all new and full to its bound, may have more behind it: one gap, and those it read are marked');
  const next = await after(world, id);
  assert.deepEqual(next.events, [], 'a re-poll gives zero');
  const ts = world.simulator.post(CHANNEL, {user: IDS.ada, text: MENTION}), {events: more} = await after(world, id);
  assert.deepEqual(fired(more).map(event => event.fields.ts), [ts], 'a known read after it is an ordinary one');
};
CASES['reaction-recent v1/resync-gap'] = async t => {
  const {world, id} = await started(t, 'reaction-recent'), {simulator} = world, messages = Array.from({length: 100}, () => simulator.post(CHANNEL, {user: IDS.ada, text: 'Window'}));
  await world.pollNow(id);
  world.advance(INTERVAL);
  assert.deepEqual(await drained(world), [], 'no reactions yet');
  for (const ts of messages) for (const name of EMOJI.slice(0, 5)) simulator.react(CHANNEL, ts, name, IDS.grace);
  const {events} = await after(world, id);
  assert.deepEqual(events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'overflow']]);
  assert.deepEqual((await after(world, id)).events, []);
  simulator.react(CHANNEL, messages[0], EMOJI[0], IDS.ada);
  const {events: more} = await after(world, id);
  assert.deepEqual(fired(more).map(event => [event.fields.emoji, event.fields.count]), [[EMOJI[0], 2]]);
};
caseTests(test, JSON.parse(readFileSync(new URL('./fixtures/provider-simulators/slack.trigger-cases.json', import.meta.url), 'utf8')), shippedTriggers('slack').triggers, CASES);

// ---- the file --------------------------------------------------------------------------------------------------------------------------------------------
test('the shipped file is the draft with its ids computed, every trigger stays a candidate, and it validates beside the shipped rows', () => {
  assert.ok(existsSync(new URL('../catalog/triggers/slack.json', import.meta.url)), 'catalog/triggers/slack.json ships');
  const file = shippedTriggers('slack'), draft = JSON.parse(readFileSync(new URL('./fixtures/docs/trigger-drafts/slack.json', import.meta.url), 'utf8')), computed = triggerIds(file, slackDeps());
  assert.deepEqual(file.triggers.map(item => item.key), [...KEYS]);
  assert.deepEqual(file.triggers.map(item => item.id), file.triggers.map(item => computed.get(`${item.key} v${item.version}`)), 'each stored id is the computed one');
  assert.deepEqual(file.triggers.map(({id: _id, ...rest}) => rest), draft.triggers.map(({id: _id, ...rest}) => rest), 'nothing but the ids moved');
  assert.deepEqual([file.reviewStatus, file.triggers.filter(item => item.certified).length], ['candidate', 0], 'a candidate until step 9c');
  assert.equal(validateTriggerFile(file, slackDeps()).triggers.length, 7);
  assert.ok(file.triggers.every(item => item.delivery.method === 'polling'), 'a live block would claim an admission no test can reach at $0');
});

// ---- the map's Slack tests ------------------------------------------------------------------------------------------------------------------------------
for (const [key, channel] of [['new-message', CHANNEL], ['new-dm', DM], ['file-shared', CHANNEL]]) {
  test(`${key}: a filtered notice moves the cursor, so a run of notices is not read for ever`, async t => {
    const {world, id} = await started(t, key), notice = world.simulator.seed(channel, {subtype: 'channel_join', user: IDS.grace, text: 'has joined'}), {events} = await after(world, id);
    assert.deepEqual(events, []);
    assert.equal(feedOf(world, id).cursors.ts, notice);
    await world.pollNow(id);
    const sent = world.simulator.calls.at(-1).query.oldest;
    assert.equal(BigInt(notice.split('.')[0]) - BigInt(sent.split('.')[0]), 30n, 'the next read starts from the notice, less the overlap');
  });
}
for (const key of ['new-message', 'new-dm', 'mention-search', 'thread-reply', 'file-shared']) {
  test(`${key}: an edit keeps its ts, so it gives no second event`, async t => {
    const {world, rig, id} = await started(t, key), {answer: ts, events} = await after(world, id, rig.write);
    assert.equal(events.length, 1);
    world.simulator.edit(rig.args.conversations?.[0] ?? CHANNEL, ts, `Edited <@${IDS.owner}>`);
    assert.deepEqual((await after(world, id)).events, []);
  });
}
for (const key of ['new-message', 'new-dm', 'file-shared']) {
  test(`${key}: a poll cut by its bounds on a newest-first list gives one gap for the unread part, and no duplicate`, async t => {
    const {world, rig, id} = await started(t, key), written = Array.from({length: 601}, () => rig.write()), events = (await after(world, id)).events;
    assert.deepEqual(gaps(events).map(event => event.fields.reason), ['bound']);
    const told = fired(events).map(event => event.fields.ts);
    assert.deepEqual(told.length, 500);
    assert.deepEqual(new Set(told).size, 500, 'no duplicate');
    assert.deepEqual(told.sort(), written.slice(-500).sort(), 'the newest are told, and the gap covers the oldest');
    assert.deepEqual((await after(world, id)).events, [], 'a re-poll gives zero');
    const ts = rig.write();
    assert.deepEqual(fired((await after(world, id)).events).map(event => event.fields.ts), [ts], 'and the next write reads as one');
  });
}
test('new-message: a message buried behind more notices than a walk can read still gets its gap, though the walk stored no new key', async t => {
  const {world, rig, id} = await started(t, 'new-message');
  rig.write();
  world.advance(1000);
  for (let count = 0; count < 500; count++) world.simulator.seed(CHANNEL, {subtype: 'channel_join', user: IDS.grace, text: 'has joined'});
  const {events} = await after(world, id);
  assert.deepEqual(events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'bound']]);
});
test('thread-reply: an oldest-first walk cut by its bounds stops with no gap and drains at the next poll, each reply once', async t => {
  const {world, rig, id} = await started(t, 'thread-reply'), written = [];
  for (let count = 0; count < 650; count++) { written.push(rig.write()); world.advance(2000); }
  const first = await after(world, id);
  assert.equal(world.record(id).status, 'active');
  assert.equal(gaps(first.events).length, 0);
  const second = await after(world, id), told = [...first.events, ...second.events].map(event => event.fields.ts);
  assert.deepEqual(gaps(second.events), []);
  assert.deepEqual(told, written, 'in order, each once');
  assert.deepEqual((await after(world, id)).events, []);
});
test('thread-reply: a crash at a stall stores one gap and no duplicate: a burst inside one second passes what an overlap can read, and the feed moves past it', async t => {
  const {world, rig, id} = await started(t, 'thread-reply');
  for (let count = 0; count < 700; count++) rig.write();
  const reading = [];
  for (let poll = 0; poll < 2; poll++) reading.push(...(await after(world, id)).events);
  assert.deepEqual(gaps(reading), [], 'two polls still find new replies');
  const told = fired(reading).length, stalled = feedOf(world, id).cursors;
  crashAtCursor(world);
  await assert.rejects(world.pollNow(id), /crashed before the cursor moved/);
  assert.deepEqual(feedOf(world, id).cursors, stalled);
  await world.pollNow(id);
  const events = await drained(world);
  assert.deepEqual(gaps(events).map(event => event.fields.reason), ['stall'], 'the replay stores nothing twice');
  assert.equal(fired(events).length, 0);
  assert.notEqual(feedOf(world, id).floor, null, 'the floor moved past what could not be read');
  world.advance(INTERVAL);
  const ts = rig.write();
  assert.deepEqual(fired((await after(world, id)).events).map(event => event.fields.ts), [ts]);
  assert.equal(new Set(fired(reading).map(event => event.fields.ts)).size, told, 'no reply was told twice');
});
for (const key of ['new-message', 'new-dm', 'thread-reply', 'reaction-recent', 'file-shared']) {
  test(`${key}: channel_not_found pauses, at the refused conversation, and nothing retries it`, async t => {
    const {world, rig, id} = await started(t, key), sent = reads(world, rig.method);
    rig.refuse();
    assert.deepEqual(paused(await world.pollNow(id)), ['paused', 'provider_refused', 'channel_not_found']);
    assert.equal(reads(world, rig.method), sent + 1, 'one read told it');
  });
}
for (const [key, write] of [['new-message', world => world.simulator.post(IDS.others, {user: IDS.ada, text: 'First'})], ['file-shared', world => world.simulator.post(IDS.others, {user: IDS.ada, files: [FILE], text: 'First'})],
  ['mention-search', world => world.simulator.post(IDS.others, {user: IDS.ada, text: MENTION})]]) {
  test(`${key}: an empty conversation's first item is one event, not a second baseline`, async t => {
    const world = triggerWorld(t, 'slack'), {id} = await world.subscribe(key, {channels: [IDS.others]});
    world.approve(id);
    assert.equal((await world.pollNow(id)).status, 'active');
    assert.deepEqual([feedOf(world, id).baselined, feedOf(world, id).cursors], [true, {}], 'baselined, and no cursor: nothing was there to read one from');
    world.advance(INTERVAL);
    const {answer: ts, events} = await after(world, id, () => write(world));
    assert.deepEqual(events.map(event => event.fields.ts), [ts]);
    assert.deepEqual((await after(world, id)).events, []);
  });
}
test('new-dm: an empty conversation\'s first message is one event', async t => {
  const world = triggerWorld(t, 'slack'), channel = 'D0ADA00001';
  world.simulator.addChannel({id: channel, name: IDS.ada, private: true, members: [IDS.owner, IDS.ada]});
  const {id} = await world.subscribe('new-dm', {conversations: [channel]});
  world.approve(id);
  await world.pollNow(id);
  world.advance(INTERVAL);
  const {answer: ts, events} = await after(world, id, () => world.simulator.post(channel, {user: IDS.ada, text: 'First'}));
  assert.deepEqual(events.map(event => [event.fields.channel, event.fields.ts]), [[channel, ts]]);
});
test('reaction-recent: a first reaction in an empty conversation is one event', async t => {
  const world = triggerWorld(t, 'slack'), {id} = await world.subscribe('reaction-recent', {channels: [IDS.others]});
  world.approve(id);
  await world.pollNow(id);
  world.advance(INTERVAL);
  const ts = world.simulator.post(IDS.others, {user: IDS.ada, text: 'First'});
  world.simulator.react(IDS.others, ts, 'tada', IDS.grace);
  assert.deepEqual((await after(world, id)).events.map(event => [event.fields.ts, event.fields.emoji, event.fields.count]), [[ts, 'tada', 1]]);
});
test('conversation-joined: the first conversation of a kind that held none is one event', async t => {
  const world = triggerWorld(t, 'slack'), {id} = await world.subscribe('conversation-joined', {kinds: ['mpim']});
  world.approve(id);
  assert.equal((await world.pollNow(id)).status, 'active');
  world.advance(INTERVAL);
  world.simulator.addChannel({id: 'G0MPIM0001', name: 'mpdm-owner--ada-1', mpim: true, members: [IDS.owner, IDS.ada]});
  assert.deepEqual((await after(world, id)).events.map(event => [event.fields.channel, event.fields.kind]), [['G0MPIM0001', 'mpim']]);
});
test('thread-reply: a thread with no replies has no latest_reply to seed from, and its first reply is one event; the parent is never reported', async t => {
  const {world, rig, id} = await started(t, 'thread-reply'), {answer, events} = await after(world, id, rig.write);
  assert.deepEqual(events.map(event => event.fields.ts), [answer]);
  assert.ok(!events.some(event => event.fields.ts === rig.parent));
  assert.equal(world.simulator.calls.filter(call => call.name === REPLIES && call.query.limit === '1').length, 1, 'the seed read once');
});
test('new-message and file-shared on one channel make one call: they share a feed, and each watch hears only its own', async t => {
  const world = triggerWorld(t, 'slack'), messages = await world.subscribe('new-message', {channels: [CHANNEL]}), files = await world.subscribe('file-shared', {channels: [CHANNEL]});
  for (const {id} of [messages, files]) world.approve(id);
  await world.pollNow(messages.id);
  await world.pollNow(files.id);
  assert.deepEqual([world.record(messages.id).status, world.record(files.id).status], ['active', 'active']);
  assert.deepEqual(world.record(messages.id).feeds, world.record(files.id).feeds, 'one feed');
  world.advance(INTERVAL);
  const sent = reads(world, HISTORY), plain = world.simulator.post(CHANNEL, {user: IDS.ada, text: 'Plain'}), shared = world.simulator.post(CHANNEL, {user: IDS.ada, files: [FILE], text: 'With a file'});
  await world.engine.tick();
  assert.equal(reads(world, HISTORY), sent + 1, 'one read told both');
  const events = await drained(world), by = id => events.filter(event => event.subscriptionId === id).map(event => event.fields.ts);
  assert.deepEqual([by(messages.id).sort(), by(files.id)], [[plain, shared].sort(), [shared]]);
  assert.equal(events.find(event => event.subscriptionId === files.id).fields.fileName, FILE.name, 'each event by its own trigger');
  assert.equal(Object.hasOwn(events.find(event => event.subscriptionId === messages.id).fields, 'fileName'), false);
});
test('a watch that joins a running channel feed hears nothing from before it joined, and reads no second walk', async t => {
  const {world, id} = await started(t, 'new-message'), before = world.simulator.post(CHANNEL, {user: IDS.ada, files: [FILE], text: 'Before the join'}), joined = await world.subscribe('file-shared', {channels: [CHANNEL]}), sent = reads(world, HISTORY);
  world.approve(joined.id);
  assert.deepEqual(world.record(joined.id).feeds, world.record(id).feeds);
  await world.pollNow(joined.id);
  assert.deepEqual([world.record(joined.id).status, reads(world, HISTORY)], ['active', sent + 1], 'one read of the running feed, and no seed');
  assert.deepEqual((await drained(world)).map(event => [event.subscriptionId, event.fields.ts]), [[id, before]]);
  world.advance(INTERVAL);
  const ts = world.simulator.post(CHANNEL, {user: IDS.ada, files: [FILE], text: 'After the join'}), {events} = await after(world, id);
  assert.deepEqual(events.map(event => [event.subscriptionId, event.fields.ts]).sort(), [[id, ts], [joined.id, ts]].sort());
});
test('new-message and new-dm never share a feed, though they share a poll and a lens', async t => {
  const world = triggerWorld(t, 'slack'), channel = await world.subscribe('new-message', {channels: [CHANNEL]}), direct = await world.subscribe('new-dm', {conversations: [DM]});
  for (const {id} of [channel, direct]) { world.approve(id); await world.pollNow(id); }
  assert.notDeepEqual(world.record(channel.id).feeds, world.record(direct.id).feeds);
  world.advance(INTERVAL);
  const ts = world.simulator.post(DM, {user: IDS.ada, text: 'To me'});
  await world.pollNow(direct.id);
  await world.pollNow(channel.id);
  assert.deepEqual((await drained(world)).map(event => [event.subscriptionId, event.fields.channel, event.fields.ts]), [[direct.id, DM, ts]]);
});
test('a key holds its conversation: one ts in two conversations gives two events, each with its own id', async t => {
  const world = triggerWorld(t, 'slack'), other = 'D0ADA00001';
  world.simulator.addChannel({id: other, name: IDS.ada, private: true, members: [IDS.owner, IDS.ada]});
  const {id} = await world.subscribe('new-dm', {conversations: [DM, other]});
  world.approve(id);
  await world.pollNow(id);
  world.advance(INTERVAL);
  const ts = `${Math.floor(world.now / 1000)}.000500`;
  for (const channel of [DM, other]) world.simulator.seed(channel, {ts, user: IDS.ada, text: 'Same moment'});
  const {events} = await after(world, id);
  assert.deepEqual(events.map(event => event.id).sort(), [`${DM}:${ts}`, `${other}:${ts}`].sort());
});
for (const key of ['new-message', 'new-dm', 'thread-reply', 'file-shared', 'conversation-joined']) {
  test(`${key}: self is set from the account, since a filter can drop nothing by "my own"`, async t => {
    const {world, rig, id} = await started(t, key), {events} = await after(world, id, rig.write);
    assert.equal(events[0].fields.self, IDS.owner);
  });
}
test('a message of Fabric\'s owner is reported, and self lets the agent tell it from anyone else\'s', async t => {
  const {world, id} = await started(t, 'new-message'), ts = world.simulator.post(CHANNEL, {user: IDS.owner, text: 'Mine'}), {events} = await after(world, id);
  assert.deepEqual([events[0].fields.ts, events[0].fields.user, events[0].fields.self], [ts, IDS.owner, IDS.owner]);
});
for (const key of KEYS) {
  test(`${key}: a 429 holds the next read for its full Retry-After, then the write is told once`, async t => {
    const {world, rig, id} = await started(t, key), written = rig.write(), sent = reads(world, rig.method), now = world.now;
    world.simulator.fail(rig.method, {status: 429, headers: {'Retry-After': '120'}, data: {ok: false, error: 'ratelimited'}});
    await world.pollNow(id);
    assert.equal(reads(world, rig.method), sent + 1);
    const feed = feedOf(world, id);
    assert.ok(feed.wait.until >= now + 120_000, 'the wait is durable');
    assert.equal(world.record(id).status, 'active', 'a limit pauses nothing');
    world.advance(119_000);
    await world.engine.tick();
    assert.equal(reads(world, rig.method), sent + 1, 'no read inside the wait');
    world.advance(feed.wait.until - world.now);
    await world.pollNow(id);
    assert.deepEqual((await drained(world)).map(shown), [rig.expected(written)]);
  });
}
test('a tier someone else spent: the watch reads a real 429 with what is left of the minute, waits, and loses nothing', async t => {
  const {world, rig, id} = await started(t, 'new-message');
  world.simulator.tierLimit = true;
  for (let count = 0; count < 50; count++) await world.simulator.request({url: `${BASE}/${HISTORY}?channel=${IDS.general}`, headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: [ORIGIN]});
  const ts = rig.write();
  await world.engine.tick();
  assert.deepEqual(world.simulator.calls.at(-1).status, 429);
  assert.equal(feedOf(world, id).wait.reason, 'limited');
  world.advance(feedOf(world, id).wait.until - world.now);
  await world.pollNow(id);
  assert.deepEqual((await drained(world)).map(event => event.fields.ts), [ts]);
});
test('a wait on one Slack method leaves the others reading: a limit on history holds no search', async t => {
  const world = triggerWorld(t, 'slack'), messages = await world.subscribe('new-message', {channels: [CHANNEL]}), mentions = await world.subscribe('mention-search', {channels: [CHANNEL]});
  for (const {id} of [messages, mentions]) { world.approve(id); await world.pollNow(id); }
  world.advance(INTERVAL * 2);
  world.simulator.fail(HISTORY, {status: 429, headers: {'Retry-After': '900'}, data: {ok: false, error: 'ratelimited'}});
  await world.engine.tick();
  assert.equal(feedOf(world, messages.id).wait?.reason, 'limited');
  assert.equal(feedOf(world, mentions.id).wait, null);
});
test('file-shared: a file with no name gives one event, with the fields it has, and every file field stays optional', async t => {
  const {world, id} = await started(t, 'file-shared'), {simulator} = world;
  const ts = simulator.post(CHANNEL, {user: IDS.ada, files: [{id: 'F0TOMB0001', mode: 'tombstone'}], text: ''}), {events} = await after(world, id);
  assert.deepEqual(events.map(shown), [{id: `${CHANNEL}:${ts}`, fields: {channel: CHANNEL, ts, user: IDS.ada, fileId: 'F0TOMB0001', self: IDS.owner}, summary: []}]);
  const bare = simulator.post(CHANNEL, {user: IDS.ada, files: [{}], text: 'No file fields'}), {events: more} = await after(world, id);
  assert.deepEqual(more.map(event => event.fields), [{channel: CHANNEL, ts: bare, user: IDS.ada, self: IDS.owner}]);
});
test('file-shared: it reads files, not the subtype: a share with no subtype counts, a file_share with no files does not, and a plain message does not', async t => {
  const {world, id} = await started(t, 'file-shared'), {simulator} = world;
  const noSubtype = simulator.post(CHANNEL, {user: IDS.ada, files: [FILE], text: 'Attached'});
  simulator.post(CHANNEL, {subtype: 'file_share', user: IDS.ada, text: 'The file has gone'});
  simulator.post(CHANNEL, {user: IDS.ada, text: 'Plain'});
  simulator.post(CHANNEL, {user: IDS.ada, files: [], text: 'An empty list'});
  assert.deepEqual((await after(world, id)).events.map(event => event.fields.ts), [noSubtype]);
});
for (const key of ['new-message', 'new-dm', 'reaction-recent', 'file-shared', 'thread-reply']) {
  test(`${key}: under a distributed install a subscribe is refused in the app's own words, and nothing is stored or read`, async t => {
    const world = triggerWorld(t, 'slack', {distribution: 'distributed'}), rig = RIGS[key](world), sent = world.simulator.calls.length;
    await assert.rejects(world.subscribe(key, rig.args), error => error.code === 'invalid_request' && /one history or thread read a minute/.test(error.message));
    assert.deepEqual(world.store.list('subscriptions'), []);
    assert.equal(world.simulator.calls.length, sent);
  });
  test(`${key}: a running watch after a restart under distributed: zero conversations.* calls, and paused`, async t => {
    const {world, rig, id} = await started(t, key);
    world.runtime.slackDistribution = 'distributed';
    rig.write();
    const sent = world.simulator.calls.filter(call => call.name?.startsWith('conversations.')).length;
    assert.deepEqual(paused(await world.pollNow(id)), ['paused', 'provider_refused', 'distributed']);
    assert.equal(world.simulator.calls.filter(call => call.name?.startsWith('conversations.')).length, sent);
    assert.equal(world.store.list('activity').filter(row => row.type === 'trigger.paused').length, 1);
  });
}
test('mention-search and conversation-joined read neither history nor replies, so a distributed install keeps them', async t => {
  for (const key of ['mention-search', 'conversation-joined']) {
    const {world, rig, id} = await started(t, key, {distribution: 'distributed'}), {answer, events} = await after(world, id, rig.write);
    assert.deepEqual(events.map(shown), [rig.expected(answer)]);
  }
});

// ---- what a subscribe refuses -----------------------------------------------------------------------------------------------------------------------------
const bad = ['C1> from:<@U2', 'c0fabtest1', 'C0fabtest1', 'U0ADA00001', 'C0FABTEST1 ', 'C0FAB-TEST'];
for (const [key, argsOf] of [['new-message', id => ({channels: [id]})], ['mention-search', id => ({channels: [id]})], ['reaction-recent', id => ({channels: [id]})], ['file-shared', id => ({channels: [id]})], ['thread-reply', id => ({threads: [{channel: id, ts: '1761490000.000100'}]})], ['new-dm', id => ({conversations: [id]})]]) {
  test(`${key}: an id that does not fit is refused at subscribe, so it can never reach a request`, async t => {
    const world = triggerWorld(t, 'slack'), sent = world.simulator.calls.length;
    for (const id of [...bad, ...(key === 'new-dm' ? [CHANNEL, IDS.private] : [DM])]) await assert.rejects(world.subscribe(key, argsOf(id)), error => error.code === 'invalid_request' && /Slack id/.test(error.message), id);
    assert.deepEqual(world.store.list('subscriptions'), []);
    assert.equal(world.simulator.calls.length, sent);
  });
}
test('mention-search: the one query it sends names the owner and the channel, with a checked id, and an unchecked one never reaches it', async t => {
  const {world, id} = await started(t, 'mention-search'), query = `<@${IDS.owner}> in:<#${CHANNEL}>`;
  await world.pollNow(id);
  assert.deepEqual([...new Set(world.simulator.calls.filter(call => call.name === 'search.messages').map(call => call.query.query))], [query]);
  await assert.rejects(world.subscribe('mention-search', {channels: [`C1> from:<@${IDS.ada}`.slice(0, 21)]}), error => error.code === 'invalid_request');
  assert.ok(world.simulator.calls.every(call => call.query?.query === undefined || call.query.query === query), 'nothing but the one query was sent');
});
test('a repeated conversation id is one feed, at subscribe, for a list of channels and a list of threads', async t => {
  const world = triggerWorld(t, 'slack'), rig = RIGS['thread-reply'](world), channels = await world.subscribe('new-message', {channels: [CHANNEL, CHANNEL, IDS.general]}), threads = await world.subscribe('thread-reply', {threads: [...rig.args.threads, ...rig.args.threads]});
  assert.deepEqual(world.record(channels.id).args.channels, [CHANNEL, IDS.general]);
  assert.deepEqual(world.record(threads.id).args.threads, rig.args.threads);
  world.approve(channels.id);
  assert.equal(world.record(channels.id).feeds.length, 2);
});
test('the caps of an account hold across Slack\'s triggers: 20 watches, and the 21st is refused', async t => {
  const world = triggerWorld(t, 'slack'), channels = ids(21);
  for (const channel of channels.slice(0, 20)) world.approve((await world.subscribe('new-message', {channels: [channel]})).id);
  await assert.rejects(world.subscribe('file-shared', {channels: [channels[20]]}), error => error.code === 'subscription_limit');
});

for (const key of KEYS) {
  test(`${key}: a watch only reads, the one method its card lists, with the query its block holds`, async t => {
    const {world, rig, id} = await started(t, key);
    rig.write();
    await world.pollNow(id);
    assert.deepEqual(world.simulator.writes(), [], 'a watch never writes');
    assert.deepEqual([...new Set(world.simulator.calls.map(call => call.name))], [rig.method]);
    assert.ok(world.simulator.calls.every(call => call.method === 'GET' && call.body === null && !call.tokenArgument));
    const QUERIES = {[HISTORY]: key === 'reaction-recent' ? ['channel', 'limit'] : ['channel', 'limit', 'oldest'], [REPLIES]: ['channel', 'ts', 'oldest', 'limit'], 'search.messages': ['query', 'count', 'sort', 'sort_dir', 'highlight'], 'users.conversations': ['types', 'limit']};
    assert.ok(world.simulator.calls.every(call => Object.keys(call.query).every(name => QUERIES[rig.method].includes(name))), JSON.stringify(world.simulator.calls.map(call => call.query)));
  });
}

// ---- what each trigger tells and leaves out ------------------------------------------------------------------------------------------------------------------
test('new-message: a person, a bot with no user, a me_message, a file share and a thread broadcast are told; a notice and a plain reply are not', async t => {
  const {world, id} = await started(t, 'new-message'), {simulator} = world, parent = simulator.post(CHANNEL, {user: IDS.ada, text: 'Parent'});
  const bot = simulator.post(CHANNEL, {subtype: 'bot_message', botId: 'B0FABRIC01', text: 'From a bot'}), me = simulator.post(CHANNEL, {subtype: 'me_message', user: IDS.ada, text: 'waves'});
  const share = simulator.post(CHANNEL, {subtype: 'file_share', user: IDS.ada, files: [FILE], text: 'A file'});
  const broadcast = simulator.post(CHANNEL, {subtype: 'thread_broadcast', user: IDS.grace, threadTs: parent, text: 'To the channel too'});
  simulator.post(CHANNEL, {user: IDS.grace, threadTs: parent, text: 'Only in the thread'});
  for (const subtype of ['channel_join', 'channel_leave', 'channel_topic', 'channel_purpose', 'channel_name', 'channel_archive', 'pinned_item']) simulator.seed(CHANNEL, {subtype, user: IDS.ada, text: subtype});
  const events = (await after(world, id)).events, byTs = Object.fromEntries(events.map(event => [event.fields.ts, event.fields]));
  assert.deepEqual(Object.keys(byTs).sort(), [parent, bot, me, share, broadcast].sort());
  assert.deepEqual(byTs[bot], {channel: CHANNEL, ts: bot, botId: 'B0FABRIC01', subtype: 'bot_message', self: IDS.owner}, 'a bot message has no user, and its event is whole without one');
  assert.deepEqual([byTs[broadcast].subtype, byTs[broadcast].threadTs], ['thread_broadcast', parent]);
});
test('new-message: a message of blocks and empty text is told, with its empty line', async t => {
  const {world, id} = await started(t, 'new-message'), blocks = [{type: 'section', text: {type: 'mrkdwn', text: 'Only blocks'}}], ts = world.simulator.post(CHANNEL, {user: IDS.ada, blocks, text: ''}), {events} = await after(world, id);
  assert.deepEqual(events.map(event => [event.fields.ts, event.summary]), [[ts, [{label: 'Message', value: ''}]]]);
});
test('new-message: a message that quotes the account\'s token reaches the agent with the token scrubbed', async t => {
  const {world, id} = await started(t, 'new-message');
  world.simulator.post(CHANNEL, {user: IDS.ada, text: `Look: ${TOKEN}`});
  const {events} = await after(world, id);
  assert.equal(events.length, 1);
  assert.ok(!JSON.stringify(events).includes(TOKEN));
});
test('new-message: a long text is cut to the summary\'s 120 characters, and only that reaches the agent', async t => {
  const {world, id} = await started(t, 'new-message'), text = 'word '.repeat(100);
  world.simulator.post(CHANNEL, {user: IDS.ada, text});
  assert.deepEqual((await after(world, id)).events.map(event => event.summary[0].value), [text.slice(0, 120)]);
});
for (const end of ['null', 'missing']) {
  test(`new-message: a walk ends at a last page whose cursor is ${end}, as at an empty one`, async t => {
    const {world, rig, id} = await started(t, 'new-message');
    world.simulator.lastPageMeta = end;
    const {answer, events} = await after(world, id, rig.write);
    assert.deepEqual(events.map(event => event.fields.ts), [answer]);
    assert.equal(feedOf(world, id).cursors.ts, answer);
    assert.equal(feedOf(world, id).failures, 0);
  });
}
test('new-message: a page cursor that goes stale mid-walk backs off with nothing stored, and the next poll tells each message once', async t => {
  const {world, rig, id} = await started(t, 'new-message'), written = Array.from({length: 120}, () => rig.write()), {request} = world.runtime, before = feedOf(world, id).cursors;
  let answers = 0;
  world.runtime.request = async options => { const answer = await request(options); if (++answers === 1) world.simulator.expireCursors(); return answer; };
  await world.pollNow(id);
  assert.deepEqual([world.simulator.calls.at(-1).error, feedOf(world, id).failures, feedOf(world, id).cursors, world.record(id).status], ['invalid_cursor', 1, before, 'active']);
  assert.deepEqual(await drained(world), [], 'nothing stored');
  world.runtime.request = request;
  world.advance(INTERVAL * 4);
  await world.pollNow(id);
  assert.deepEqual((await drained(world)).map(event => event.fields.ts).sort(), [...written].sort());
});
test('new-message: if P1 answers that a window reads from its oldest end, a cut poll still loses nothing: it reads on from what it read, and its gap only says more than it must', async t => {
  const {world, rig, id} = await started(t, 'new-message');
  world.simulator.oldestFirst = true;
  const written = Array.from({length: 601}, () => { world.advance(1000); return rig.write(); }), first = await after(world, id), second = await after(world, id);
  assert.deepEqual(gaps(first.events).map(event => event.fields.reason), ['bound']);
  assert.deepEqual(fired([...first.events, ...second.events]).map(event => event.fields.ts).sort(), [...written].sort(), 'every message told once');
});
test('thread-reply: if P2 answers that the parent survives oldest, it is read and never told, and the mark does not go back', async t => {
  const world = triggerWorld(t, 'slack'), rig = RIGS['thread-reply'](world);
  world.advance(60_000);
  const reply = rig.write(), {id} = await world.subscribe('thread-reply', rig.args);
  world.approve(id);
  await world.pollNow(id);
  world.advance(INTERVAL);
  world.simulator.parentSurvivesOldest = true;
  assert.deepEqual((await after(world, id)).events, [], 'the parent came back unseen, and it is no reply');
  assert.equal(feedOf(world, id).cursors.ts, reply);
  const next = rig.write();
  assert.deepEqual((await after(world, id)).events.map(event => event.fields.ts), [next]);
});
test('thread-reply: a broadcast reply reaches a watch of the thread and a watch of the channel, one event each', async t => {
  const world = triggerWorld(t, 'slack'), rig = RIGS['thread-reply'](world), thread = await world.subscribe('thread-reply', rig.args), channel = await world.subscribe('new-message', {channels: [CHANNEL]});
  for (const {id} of [thread, channel]) { world.approve(id); await world.pollNow(id); }
  world.advance(INTERVAL);
  const ts = world.simulator.post(CHANNEL, {subtype: 'thread_broadcast', user: IDS.grace, threadTs: rig.parent, text: 'To both'});
  for (const {id} of [thread, channel]) await world.pollNow(id);
  assert.deepEqual((await drained(world)).map(event => [event.subscriptionId, event.fields.ts]).sort(), [[thread.id, ts], [channel.id, ts]].sort());
});
test('thread-reply: a parent deleted with no replies answers thread_not_found, which pauses; one with replies stays readable as a tombstone', async t => {
  const {world, rig, id} = await started(t, 'thread-reply');
  world.simulator.delete(CHANNEL, rig.parent);
  assert.deepEqual(paused(await world.pollNow(id)), ['paused', 'provider_refused', 'thread_not_found']);
  const other = await started(t, 'thread-reply'), reply = (await after(other.world, other.id, other.rig.write)).answer;
  other.world.simulator.delete(CHANNEL, other.rig.parent);
  const next = other.rig.write(), {events} = await after(other.world, other.id);
  assert.deepEqual(events.map(event => event.fields.ts), [next]);
  assert.notEqual(reply, next);
});
test('reaction-recent: count comes from Slack, past the users it cuts: a rise past the cut fires, a change back fires, and no change does not', async t => {
  const {world, rig, id} = await started(t, 'reaction-recent'), {simulator} = world, {target} = rig, count = async () => (await after(world, id)).events.map(event => [event.fields.emoji, event.fields.count]);
  const people = ['U0ONE00001', 'U0TWO00002', 'U0THREE003', 'U0FOUR0004'];
  for (const user of people) simulator.react(CHANNEL, target, 'tada', user);
  assert.deepEqual(await count(), [['tada', 4]]);
  assert.deepEqual(await count(), []);
  simulator.react(CHANNEL, target, 'tada', 'U0FIVE0005');
  assert.deepEqual(await count(), [['tada', 5]], 'users still shows 3 of them, and count says 5');
  simulator.unreact(CHANNEL, target, 'tada', 'U0FIVE0005');
  assert.deepEqual(await count(), [['tada', 4]], 'the latest value compares, so a return fires');
  simulator.react(CHANNEL, target, 'tada', 'U0FIVE0005');
  assert.deepEqual(await count(), [['tada', 5]], 'and A to B to A fires each time');
});
test('reaction-recent: two emoji on one message are two items, and a message past the newest 100 is not watched', async t => {
  const {world, rig, id} = await started(t, 'reaction-recent'), {simulator} = world, {target} = rig;
  simulator.react(CHANNEL, target, 'tada', IDS.ada);
  simulator.react(CHANNEL, target, 'eyes', IDS.ada);
  assert.deepEqual((await after(world, id)).events.map(event => event.fields.emoji).sort(), ['eyes', 'tada']);
  for (let count = 0; count < 100; count++) simulator.post(CHANNEL, {user: IDS.ada, text: 'Filling the window'});
  simulator.react(CHANNEL, target, 'rocket', IDS.ada);
  assert.deepEqual((await after(world, id)).events, [], 'the card says older messages are not watched');
});
test('reaction-recent: a full read has no page past it, so a new reaction on a known list brings no bound gap', async t => {
  const {world, id} = await started(t, 'reaction-recent'), {simulator} = world, messages = Array.from({length: 100}, () => simulator.post(CHANNEL, {user: IDS.ada, text: 'Window'}));
  await world.pollNow(id);
  world.advance(INTERVAL);
  for (const ts of messages) for (const name of EMOJI.slice(0, 5)) simulator.react(CHANNEL, ts, name, IDS.grace);
  assert.deepEqual((await after(world, id)).events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'overflow']]);
  simulator.react(CHANNEL, messages[0], EMOJI[0], IDS.ada);
  const {events} = await after(world, id);
  assert.deepEqual(events.map(event => [event.type, event.fields.emoji]), [['trigger.event', EMOJI[0]]], 'all 500 were read, so nothing lies past the bound for a gap to tell of');
});
test('reaction-recent: more reactions than a transform may hold pause too_many_items, and are never cut short', async t => {
  const {world, id} = await started(t, 'reaction-recent'), {simulator} = world, messages = Array.from({length: 100}, () => simulator.post(CHANNEL, {user: IDS.ada, text: 'Window'}));
  for (const ts of messages) for (let index = 0; index < 11; index++) simulator.react(CHANNEL, ts, `emoji_${index}`, IDS.grace);
  assert.deepEqual(paused(await world.pollNow(id)), ['paused', 'too_many_items', 'too_many_items']);
});
test('mention-search: search lag delays a mention to a later poll and loses nothing, once', async t => {
  const {world, rig, id} = await started(t, 'mention-search');
  world.simulator.searchLagMs = 240_000;
  const ts = rig.write();
  assert.deepEqual((await after(world, id)).events, [], 'still being indexed');
  world.advance(240_000);
  assert.deepEqual((await after(world, id)).events.map(event => event.fields.ts), [ts]);
  assert.deepEqual((await after(world, id)).events, []);
});
test('mention-search: Slack joins close matches into one, so two quick mentions are one event, as the card says, and never two for one', async t => {
  const {world, rig, id} = await started(t, 'mention-search');
  world.simulator.searchJoinMs = 30_000;
  rig.write();
  const newer = rig.write();
  assert.deepEqual((await after(world, id)).events.map(event => event.fields.ts), [newer]);
  assert.deepEqual((await after(world, id)).events, []);
});
test('mention-search: a mention inside a thread is found, with its reply\'s permalink', async t => {
  const {world, id} = await started(t, 'mention-search'), parent = world.simulator.post(CHANNEL, {user: IDS.ada, text: 'A thread'}), reply = world.simulator.post(CHANNEL, {user: IDS.grace, threadTs: parent, text: MENTION});
  const {events} = await after(world, id);
  assert.deepEqual(events.map(event => [event.fields.ts, event.fields.permalink.includes(`thread_ts=${parent}`)]), [[reply, true]]);
});
test('mention-search: a filter set in Slack hides a match and says nothing, so the watch stays healthy and tells what it can see', async t => {
  const {world, rig, id} = await started(t, 'mention-search');
  world.simulator.searchHidden.add(CHANNEL);
  rig.write();
  assert.deepEqual((await after(world, id)).events, []);
  assert.equal(world.record(id).status, 'active');
});
test('mention-search: an older mention search finds late is behind the floor of its baseline: it is no news, and it is marked as read', async t => {
  const world = triggerWorld(t, 'slack'), rig = RIGS['mention-search'](world), newest = rig.write(), {id} = await world.subscribe('mention-search', rig.args);
  world.approve(id);
  await world.pollNow(id);
  world.advance(INTERVAL);
  world.simulator.seed(CHANNEL, {ts: `${BigInt(newest.split('.')[0]) - 60n}.${newest.split('.')[1]}`, user: IDS.ada, text: MENTION});
  assert.deepEqual((await after(world, id)).events, []);
  assert.deepEqual((await after(world, id)).events, []);
});
test('a scope Slack says is gone pauses a private channel with a C id, read from the conversation and not from its first letter', async t => {
  const world = triggerWorld(t, 'slack'), channel = 'C0PRIVATE1';
  world.simulator.addChannel({id: channel, name: 'private-c', private: true});
  const {id} = await world.subscribe('new-message', {channels: [channel]});
  world.approve(id);
  await world.pollNow(id);
  world.advance(INTERVAL);
  world.simulator.revokeScope('groups:history');
  const watch = await world.pollNow(id);
  assert.deepEqual([watch.status, watch.reason, watch.detail], ['paused', 'access_missing', 'missing_scope']);
});
test('leaving a private channel pauses a watch of it, and a public channel the owner is not in still reads', async t => {
  const world = triggerWorld(t, 'slack'), {id} = await world.subscribe('new-message', {channels: [IDS.private]}), open = await world.subscribe('new-message', {channels: [IDS.others]});
  for (const watch of [id, open.id]) { world.approve(watch); await world.pollNow(watch); }
  world.advance(INTERVAL);
  world.simulator.leave(IDS.private);
  world.simulator.leave(IDS.others);
  assert.deepEqual(paused(await world.pollNow(id)), ['paused', 'provider_refused', 'channel_not_found']);
  assert.equal((await world.pollNow(open.id)).status, 'active');
});
test('conversation-joined: a channel, a private channel, a group DM and a DM each read their own kind, on their own feed', async t => {
  const world = triggerWorld(t, 'slack'), {simulator} = world, {id} = await world.subscribe('conversation-joined', {kinds: ['public_channel', 'private_channel', 'mpim', 'im']});
  world.approve(id);
  assert.equal(world.record(id).feeds.length, 4);
  assert.equal((await world.pollNow(id)).status, 'active');
  assert.deepEqual(await drained(world), []);
  world.advance(INTERVAL);
  simulator.addChannel({id: 'C0ROOMPUB1', name: 'room', creator: IDS.ada, created: 1_761_000_001});
  simulator.addChannel({id: 'C0ROOMSEC1', name: 'fabric-synthetic-tr7', private: true, created: 1_761_000_002});
  simulator.addChannel({id: 'G0MPIM0001', name: 'mpdm-owner--ada-1', mpim: true, members: [IDS.owner, IDS.ada], created: 1_761_000_003});
  await simulator.request({url: `${BASE}/conversations.open`, method: 'POST', headers: {Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json'}, body: JSON.stringify({users: IDS.ada}), allowedOrigins: [ORIGIN]});
  const events = (await after(world, id)).events, found = Object.fromEntries(events.map(event => [event.fields.kind, event.fields]));
  assert.deepEqual(Object.keys(found).sort(), ['im', 'mpim', 'private_channel', 'public_channel']);
  assert.deepEqual([found.public_channel.channel, found.private_channel.name, found.mpim.channel], ['C0ROOMPUB1', 'fabric-synthetic-tr7', 'G0MPIM0001']);
  assert.deepEqual([found.im.otherUser, Object.hasOwn(found.im, 'name'), Object.hasOwn(found.im, 'creator')], [IDS.ada, false, false], 'a direct message has neither, and its event is whole without them');
  assert.deepEqual((await after(world, id)).events, []);
});
test('conversation-joined: pages that hold next to nothing are no long list: one private channel behind six empty pages reaches the present, and a new one behind them is told', async t => {
  const world = triggerWorld(t, 'slack'), {simulator} = world, {id} = await world.subscribe('conversation-joined', {kinds: ['private_channel']});
  world.approve(id);
  simulator.shortPages(0, 0, 0, 0, 0, 0);
  assert.deepEqual(paused(await world.pollNow(id)), ['active', undefined, undefined], 'five pages hold one channel, and Slack said more was to come');
  world.advance(INTERVAL);
  simulator.addChannel({id: 'G0NEWROOM1', name: 'new-room', private: true, creator: IDS.ada, created: 1_761_000_000});
  simulator.shortPages(0, 0, 0, 0, 0, 0, 0);
  assert.deepEqual((await drained((await world.pollNow(id), world))).map(event => event.fields.channel), ['G0NEWROOM1']);
});
test('conversation-joined: pages emptier than a poll\'s requests can walk are a stop that runs again, and pause nothing: only 500 items prove a list is too long', async t => {
  const world = triggerWorld(t, 'slack'), {simulator} = world, {id} = await world.subscribe('conversation-joined', {kinds: ['private_channel']});
  world.approve(id);
  simulator.shortPages(...Array(70).fill(0));
  assert.deepEqual(paused(await world.pollNow(id)), ['starting', undefined, undefined]);
  assert.equal(world.store.get('triggerRuns', world.record(id).feeds[0]).runs.at(-1).outcome, 'cut');
  world.advance(INTERVAL);
  assert.deepEqual(paused(await world.pollNow(id)), ['active', undefined, undefined]);
});
test('new-message: a burst over short pages reads to its end, so a small burst brings no bound gap', async t => {
  const {world, id} = await started(t, 'new-message'), {simulator} = world, posted = Array.from({length: 7}, (_, index) => simulator.post(CHANNEL, {user: IDS.ada, text: `Short ${index}`}));
  simulator.shortPages(1, 1, 1, 1, 1, 1);
  await world.pollNow(id);
  const told = await drained(world);
  assert.deepEqual(told.map(event => event.type).filter(type => type === 'trigger.gap'), []);
  assert.deepEqual(told.map(event => event.fields.ts).sort(), [...posted].sort());
});
test('reaction-recent: the last person leaving takes the emoji off the message and tells nothing, and the same emoji back at the same count compares equal to its seen row, as the card says', async t => {
  const {world, rig, id} = await started(t, 'reaction-recent'), {simulator} = world, {target} = rig, count = async () => (await after(world, id)).events.map(event => [event.fields.emoji, event.fields.count]);
  simulator.react(CHANNEL, target, 'tada', IDS.ada);
  assert.deepEqual(await count(), [['tada', 1]]);
  simulator.unreact(CHANNEL, target, 'tada', IDS.ada);
  assert.deepEqual(await count(), [], 'an emoji that went is no item, so nothing compares it');
  simulator.react(CHANNEL, target, 'tada', IDS.ada);
  assert.deepEqual(await count(), [], 'Slack gives no time for a reaction, so this cannot be told from one that stayed');
  assert.match(shippedTriggers('slack').triggers.find(item => item.key === 'reaction-recent').description, /taken off and added back/);
  simulator.react(CHANNEL, target, 'tada', IDS.grace);
  assert.deepEqual(await count(), [['tada', 2]], 'a new count still fires');
});
test('thread-reply: a reply to a bot\'s message is a reply, whatever Slack shows of its parent', async t => {
  const world = triggerWorld(t, 'slack'), {simulator} = world, parent = simulator.seed(CHANNEL, {subtype: 'bot_message', text: 'From a bot'}), {id} = await world.subscribe('thread-reply', {threads: [{channel: CHANNEL, ts: parent}]});
  world.approve(id);
  await world.pollNow(id);
  world.advance(INTERVAL);
  const reply = simulator.post(CHANNEL, {user: IDS.grace, text: 'A reply', threadTs: parent});
  await world.pollNow(id);
  assert.deepEqual((await drained(world)).map(event => event.fields.ts), [reply]);
});
test('conversation-joined: joining tells once, leaving tells nothing, and coming back tells nothing: it says "first appears"', async t => {
  const {world, id} = await started(t, 'conversation-joined'), {simulator} = world;
  simulator.join(IDS.others);
  assert.deepEqual((await after(world, id)).events.map(event => event.fields.channel), [IDS.others]);
  simulator.leave(IDS.others);
  assert.deepEqual((await after(world, id)).events, []);
  simulator.join(IDS.others);
  assert.deepEqual((await after(world, id)).events, []);
});
test('conversation-joined: an archive tells nothing, and the list stays whole', async t => {
  const {world, id} = await started(t, 'conversation-joined');
  world.simulator.archive(CHANNEL);
  assert.deepEqual((await after(world, id)).events, []);
});
test('conversation-joined: a list longer than a poll may read cannot tell new from old, so it pauses too_many_items, at the baseline as later', async t => {
  const world = triggerWorld(t, 'slack'), {simulator} = world;
  for (let index = 0; index < 501; index++) simulator.addChannel({id: `C0BIG${String(index).padStart(5, '0')}`, name: `big-${index}`});
  const {id} = await world.subscribe('conversation-joined', {kinds: ['public_channel']});
  world.approve(id);
  assert.deepEqual(paused(await world.pollNow(id)), ['paused', 'too_many_items', 'bounds']);
  const {world: later, rig, id: running} = await started(t, 'conversation-joined');
  for (let count = 0; count < 501; count++) rig.write();
  assert.deepEqual(paused(await later.pollNow(running)), ['paused', 'too_many_items', 'bounds']);
});
test('Slack\'s content leaves after 24 hours, and its hashed seen rows stay, so a re-read fires nothing', async t => {
  const {world, rig, id} = await started(t, 'reaction-recent');
  world.store.put('clientGrants', {...world.store.get('clientGrants', world.client.id), expiresAt: new Date(world.now + 7 * 86_400_000).toISOString()});
  rig.write();
  await world.pollNow(id);
  world.advance(24 * 3_600_000 + 1);
  const {events, trimmed} = await world.events({after: 0});
  assert.deepEqual([events, trimmed], [[], 1], 'the event is past its time, and the page says one was trimmed');
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, []);
});

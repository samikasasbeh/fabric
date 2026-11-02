import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {OWNER_EMAIL, TOKEN} from './fixtures/actions/gmail-harness.mjs';
import {shippedTriggers, triggerWorld} from './fixtures/actions/trigger-harness.mjs';

// Iteration 9 step 7 (docs/I07-BUILD-MAP.md, step 7): Gmail's six triggers on its simulator, on the shipped rows and proxy settings, through the real subscribe, approval, poll and events.list. Five share one
// unfiltered history feed, and the search reads a window of messages.list. Each is proven the same way, by gmail.trigger-cases.json: one write gives one event, and checking again gives none. Nothing here
// listens on a port or reaches Google. A trigger file holds no fixture: it is catalog/triggers/gmail.json, copied by the harness into a temp folder and only there marked reviewed.
const SECOND = 1000, TICK = 150 * SECOND, DAY = 86_400_000, FAR = '9007199254740993', CASES = 'test/fixtures/provider-simulators/gmail.trigger-cases.json', ROOT = new URL('../', import.meta.url);
const INBOX = 'new-inbox-email', LABELLED = 'label-added', SENT = 'email-sent', REPLY = 'reply-on-my-thread', FILES = 'new-email-with-attachment', SEARCH = 'new-email-matching-search';
const HISTORY = 'GET /history', MESSAGES = 'GET /messages', MESSAGE = 'GET /messages/{id}', THREAD = 'GET /threads/{id}', LABEL = 'GET /labels/{id}', PROFILE = 'GET /profile', READ = 'gmail.messages.read';
const THEM = 'ann@example.com', BOB = 'bob@example.com', WATCHED = {search: {subject: 'Hello'}};
const encode = text => Buffer.from(text, 'utf8').toString('base64url');
/** A whole message. `subject: null` leaves its field out, and `more` adds headers. */
const mail = (subject = 'Hello', {from = THEM, to = OWNER_EMAIL, more = [], body = 'Hello.'} = {}) => encode(`${[`From: ${from}`, ...(to ? [`To: ${to}`] : []), ...(subject === null ? [] : [`Subject: ${subject}`]), ...more].join('\r\n')}\r\n\r\n${body}\r\n`);
const withFile = (subject = 'Hello', filename = 'notes.txt') => mail(subject, {more: ['Content-Type: multipart/mixed; boundary="fabric"'],
  body: `--fabric\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nHello.\r\n--fabric\r\nContent-Type: text/plain; name="${filename}"\r\nContent-Disposition: attachment; filename="${filename}"\r\n\r\nData.\r\n--fabric--`});
const iso = time => new Date(time).toISOString();
const fired = events => events.filter(event => event.type === 'trigger.event'), gaps = events => events.filter(event => event.type === 'trigger.gap');
const reasons = events => gaps(events).map(event => event.fields.reason);
const routed = (world, route) => world.simulator.reads().filter(call => call.route === route);
const feedOf = (world, id) => world.store.get('triggerFeeds', world.record(id).feeds[0]);
const lastRun = (world, id) => world.store.get('triggerRuns', world.record(id).feeds[0]).runs.at(-1);
const googleError = (status, reason) => ({status, data: {error: {code: status, message: reason, errors: [{domain: 'global', reason, message: reason}]}}});
/** Every event on from where the last read ended. */
async function unread(world) {
  const found = [];
  for (let page = await world.events({limit: 100}); page.events.length; page = await world.events({limit: 100})) found.push(...page.events);
  return found;
}
/** Gmail's world. The harness's client lasts a day, a grant's default, so here it holds the 30 days a grant can, since a stale id and a window take a week to reach. */
function worldOf(t, options) {
  const world = triggerWorld(t, 'gmail', options), [client] = world.store.list('clientGrants');
  world.store.put('clientGrants', {...client, expiresAt: iso(world.now + 30 * DAY)});
  return world;
}
/** A watch through to active, on a new world or on one a test already holds. */
async function watch(world, key, args = {}) {
  const {id} = await world.subscribe(key, args);
  assert.equal(world.approve(id).status, 'starting');
  assert.equal((await world.pollNow(id)).status, 'active');
  return id;
}
async function watching(t, key, args, options) {
  const world = worldOf(t, options);
  return {world, id: await watch(world, key, args)};
}
/** One poll a tick later, answering what it stored. */
async function polled(world, id) {
  world.advance(TICK);
  await world.pollNow(id);
  return unread(world);
}
/** A label the owner made in Gmail. */
function label(world, name = 'Work') {
  const id = `Label_${Object.keys(world.simulator.data.labels).length + 1}`;
  world.simulator.data.labels[id] = {id, name, type: 'user'};
  return id;
}
/** Seen rows for these items, as the polls that told them would have left them, so a test past 5,000 rows need not read each mail at 25 a poll. */
function alreadyTold(world, id, items) {
  const feed = feedOf(world, id), record = world.record(id), lens = world.catalog.triggerLens(world.catalog.triggerOf(record.triggerId).entry, record.args), keyOf = item => createHash('sha256').update(`${feed.id}|${lens}|${item}`).digest('hex');
  world.store.appendPoll({feedId: feed.id, seen: items.map(item => ({lens, itemKey: keyOf(item), valueHash: '', generation: 1, connectionId: feed.connectionId}))});
  return {keys: keyOf, lens};
}
/** Makes the next write of a feed's cursors throw, as a crash between the two stores would. */
function crashAtCursor({store}) {
  const {put, appendPoll} = store;
  let appended = false;
  store.put = (collection, document) => {
    if (appended && collection === 'triggerFeeds') { store.put = put; throw new Error('crashed before the cursor moved'); }
    return put.call(store, collection, document);
  };
  store.appendPoll = poll => { const answer = appendPoll.call(store, poll); appended = true; store.appendPoll = appendPoll; return answer; };
}
const crash = async (world, id) => { crashAtCursor(world); await assert.rejects(world.pollNow(id), /crashed before the cursor moved/); };
/** A mail on a thread the owner started: `first` is what the reply names. */
const REFERENCE = '<plan@example.com>';
const opened = world => world.simulator.ownerSends(mail('Plan', {from: OWNER_EMAIL, to: THEM, more: [`Message-ID: ${REFERENCE}`]}));
const reply = (subject = 'Re: Plan', from = THEM) => mail(subject, {from, more: [`In-Reply-To: ${REFERENCE}`, `References: ${REFERENCE}`]});

/**
 * Each trigger as the cases drive it: `route` its poll request, `args`, `prepare` what must stand first, `write` one write of the kind it reports, answering the fields of the one event it must give, and `noise` a write of
 * another kind, which must give none. A write stands alone, so a case can call it many times.
 */
const SOURCES = {
  [INBOX]: {route: HISTORY, write(world) {
    const {id, threadId} = world.simulator.deliver(mail());
    return {messageId: id, threadId, from: THEM, subject: 'Hello', receivedAt: iso(world.now)};
  }},
  [LABELLED]: {route: HISTORY, prepare: world => ({labelId: label(world)}), args: ({labelId}) => ({labelId}), write(world, {labelId}) {
    const {id, threadId} = world.simulator.deliver(mail());
    world.simulator.relabel(id, {add: [labelId]});
    return {messageId: id, threadId, labelId, labelName: 'Work', from: THEM, subject: 'Hello', historyRecordId: world.simulator.state().historyId};
  }},
  [SENT]: {route: HISTORY, write(world) {
    const {id, threadId} = world.simulator.ownerSends(mail('Out', {from: OWNER_EMAIL, to: BOB}));
    return {messageId: id, threadId, to: BOB, subject: 'Out', receivedAt: iso(world.now)};
  }},
  [REPLY]: {route: HISTORY, prepare: opened, write(world) {
    const {id, threadId} = world.simulator.deliver(reply());
    return {messageId: id, threadId, from: THEM, subject: 'Re: Plan', receivedAt: iso(world.now)};
  }},
  [FILES]: {route: HISTORY, write(world) {
    const {id, threadId} = world.simulator.deliver(withFile());
    return {messageId: id, threadId, from: THEM, subject: 'Hello', receivedAt: iso(world.now), firstFilename: 'notes.txt'};
  }},
  [SEARCH]: {route: MESSAGES, args: () => WATCHED, write(world) {
    const {id, threadId} = world.simulator.deliver(mail());
    return {messageId: id, threadId, from: THEM, subject: 'Hello', receivedAt: iso(world.now)};
  }},
};
const started = async (t, key) => {
  const {prepare = () => ({}), args = () => ({}), ...source} = SOURCES[key], world = worldOf(t), context = prepare(world), id = await watch(world, key, args(context));
  return {world, id, context, ...source, write: () => source.write(world, context)};
};
const denied = world => world.store.put('backgroundPolicies', {id: world.account, connectionId: world.account, mode: 'deny', updatedAt: 'x'});

const KINDS = {
  async 'baseline-silent'(t, key) {
    const {prepare = () => ({}), args = () => ({}), write} = SOURCES[key], world = worldOf(t), context = prepare(world), {id} = await world.subscribe(key, args(context));
    world.approve(id);
    write(world, context);
    assert.equal((await world.pollNow(id)).status, 'active', 'its first poll reached the present');
    assert.deepEqual(await unread(world), [], 'what stood before the watch is not new');
    assert.deepEqual(await polled(world, id), [], 'nor is it on the next poll');
  },
  async 'one-then-zero'(t, key) {
    const {world, id, write} = await started(t, key);
    world.advance(TICK);
    const fields = write(), events = await polled(world, id);
    assert.deepEqual(events.map(event => event.type), ['trigger.event']);
    assert.deepEqual(events[0].fields, fields);
    assert.equal(events[0].subscriptionId, id);
    assert.deepEqual(await polled(world, id), [], 'a re-poll gives none');
  },
  async 'crash-before-cursor'(t, key, {stale}) {
    const {world, id, write} = await started(t, key);
    world.advance(TICK);
    const {messageId} = write();
    await crash(world, id);
    assert.deepEqual(fired(await unread(world)).map(event => event.fields.messageId), [messageId], 'the event landed before the crash');
    assert.deepEqual(await polled(world, id), [], 'the replay finds the seen row and stores nothing');
    stale(world, write);
    await crash(world, id);
    await world.pollNow(id);
    const events = await unread(world);
    assert.equal(gaps(events).length, 1, 'one gap across the crash and its replay');
    assert.equal(fired(events).length, 0);
  },
  async 'background-never'(t, key) {
    const {world, id, write} = await started(t, key), reads = world.simulator.calls.length;
    write();
    denied(world);
    world.advance(TICK);
    const held = await world.pollNow(id);
    assert.deepEqual([held.status, held.reason], ['paused', 'background_off']);
    assert.equal(world.simulator.calls.length, reads, 'nothing was sent');
    assert.deepEqual(await unread(world), []);
  },
  async 'row-never-mid-poll'(t, key) {
    const {world, id, write, route} = await started(t, key), gate = world.simulator.hold(route);
    write();
    world.advance(TICK);
    const poll = world.pollNow(id);
    await gate.reached;
    world.setRow(READ, 'deny');
    const reads = world.simulator.calls.length;
    gate.release();
    const held = await poll;
    assert.deepEqual([held.status, held.reason], ['paused', 'permission_changed']);
    assert.equal(world.simulator.calls.length, reads, 'nothing was read after the row moved');
    assert.deepEqual(await unread(world), [], 'and the answer in hand was dropped');
  },
  async 'malformed-cursor'(t, key, {spoil}) {
    const {world, id} = await started(t, key), reads = world.simulator.calls.length, feed = feedOf(world, id);
    world.store.put('triggerFeeds', {...feed, ...spoil});
    world.advance(TICK);
    const held = await world.pollNow(id);
    assert.deepEqual([held.status, held.reason], ['paused', 'cursor_invalid']);
    assert.equal(world.simulator.calls.length, reads, 'a place Fabric cannot trust is never sent');
  },
  async 'caps'(t, key) {
    const {world, id, write} = await started(t, key), most = 25, written = 30;
    world.advance(TICK);
    const fields = Array.from({length: written}, write), before = routed(world, MESSAGE).length;
    const first = await polled(world, id), reads = routed(world, MESSAGE).length - before;
    assert.ok(reads > 0 && reads <= most, `at most ${most} reads a poll, not ${reads}`);
    assert.equal(first.length, most);
    assert.ok(lastRun(world, id).requests <= 64);
    const rest = await polled(world, id), all = [...first, ...rest];
    assert.deepEqual(fired(all).map(event => event.fields.messageId).sort(), fields.map(item => item.messageId).sort(), 'each once, in the end, with no gap');
    assert.equal(gaps(all).length, 0);
    assert.equal(world.record(id).status, 'active');
  },
  async 'resync-gap'(t, key, {stale, reason}) {
    const {world, id, write} = await started(t, key);
    world.advance(TICK);
    const before = write();
    assert.equal(fired(await polled(world, id))[0].fields.messageId, before.messageId);
    stale(world, write);
    await world.pollNow(id);
    const events = await unread(world);
    assert.deepEqual(reasons(events), [reason]);
    assert.equal(fired(events).length, 0, 'nothing from before it repeats, and nothing inside it is told');
    world.advance(TICK);
    const after = write();
    assert.deepEqual(fired(await polled(world, id)).map(event => event.fields.messageId), [after.messageId]);
    assert.deepEqual(await polled(world, id), []);
  },
  async 'pause-on-refusal'(t, key) {
    const {world, id, route} = await started(t, key);
    world.simulator.fail(route, googleError(403, 'domainPolicy'));
    world.advance(TICK);
    const held = await world.pollNow(id);
    assert.deepEqual([held.status, held.reason, held.detail], ['paused', 'provider_refused', 'http_403']);
  },
};
/** How each kind reaches a block, with a write that must be lost: the history feed loses its place, and the search sleeps past its window. */
const expired = (world, write) => {
  write();
  world.simulator.expireHistory(world.simulator.state().historyId);
  world.advance(TICK);
};
const slept = (world, write) => {
  world.advance(8 * DAY);
  write();
};
const staleOf = key => key === SEARCH ? {stale: slept, reason: 'window', spoil: {page: {token: '\u0007', walk: 'delta'}}} : {stale: expired, reason: 'resync', spoil: {cursors: {history: 'not-a-history-id'}}};

caseTests(test, JSON.parse(readFileSync(new URL(CASES, ROOT), 'utf8')), shippedTriggers('gmail').triggers, Object.fromEntries(Object.keys(SOURCES).flatMap(key => Object.keys(KINDS).map(kind => [`${key} v1/${kind}`, t => KINDS[kind](t, key, staleOf(key))]))));

// ---- the shared feed ---------------------------------------------------------------------------------------------------------------------------------------------------------
test('the five history sources send one request: no labelId and no historyTypes, since a per-source query on a shared cursor would lose events', async t => {
  const world = worldOf(t), labelId = label(world), {feeds} = world.record(await watch(world, INBOX));
  for (const [key, args] of [[LABELLED, {labelId}], [SENT], [REPLY], [FILES]]) assert.deepEqual(world.record(await watch(world, key, args)).feeds, feeds, key);
  const before = routed(world, HISTORY).length, profiles = routed(world, PROFILE).length;
  world.advance(10 * TICK);
  await world.engine.tick();
  const sent = routed(world, HISTORY).slice(before);
  assert.equal(sent.length, 1, 'one poll a tick');
  assert.deepEqual(Object.keys(sent[0].query).sort(), ['maxResults', 'startHistoryId']);
  assert.equal(sent[0].query.maxResults, '500');
  assert.equal(routed(world, PROFILE).length, profiles);
});

test('one new-inbox-email watch sends one enrich read per mail, at metadata with only its two headers, and never format=full', async t => {
  const {world, id} = await watching(t, INBOX), before = routed(world, MESSAGE).length;
  world.advance(TICK);
  world.simulator.deliver(mail('One'));
  world.simulator.deliver(mail('Two'));
  assert.equal(fired(await polled(world, id)).length, 2);
  const reads = routed(world, MESSAGE).slice(before);
  assert.equal(reads.length, 2);
  for (const {query} of reads) assert.deepEqual(query, {format: 'metadata', metadataHeaders: ['From', 'Subject']});
});

test('a lens nobody watches reads nothing: an inbox watch beside no attachment watch sends no thread, label or full read', async t => {
  const {world, id} = await watching(t, INBOX);
  world.advance(TICK);
  world.simulator.deliver(withFile());
  assert.equal(fired(await polled(world, id)).length, 1);
  assert.deepEqual([routed(world, THREAD).length, routed(world, LABEL).length, routed(world, MESSAGE).filter(call => call.query.format === 'full').length], [0, 0, 0]);
});

test('a joiner receives nothing from before it joined, on the same lens or a new one, and hears what follows', async t => {
  const {world, id} = await watching(t, INBOX);
  world.advance(TICK);
  const early = world.simulator.ownerSends(mail('Early', {from: OWNER_EMAIL, to: OWNER_EMAIL}));
  const sent = await world.subscribe(SENT);
  assert.equal(world.approve(sent.id).status, 'starting');
  await world.pollNow(sent.id);
  assert.equal(world.record(sent.id).status, 'active');
  assert.deepEqual(fired(await unread(world)).map(event => [event.subscriptionId, event.fields.messageId]), [[id, early.id]], 'the running watch hears it, and the joiner does not');
  world.advance(TICK);
  const later = world.simulator.ownerSends(mail('Later', {from: OWNER_EMAIL, to: BOB}));
  assert.deepEqual(fired(await polled(world, id)).map(event => [event.subscriptionId, event.fields.messageId]), [[sent.id, later.id]]);
});

test('a self-send fires inbox and sent, once each', async t => {
  const world = worldOf(t), inbox = await watch(world, INBOX), sent = await watch(world, SENT);
  world.advance(TICK);
  const {id} = world.simulator.ownerSends(mail('Note to self', {from: OWNER_EMAIL}));
  assert.deepEqual(fired(await polled(world, inbox)).map(event => [event.subscriptionId, event.fields.messageId]).sort(), [[inbox, id], [sent, id]].sort());
  assert.deepEqual(await polled(world, sent), []);
});

test('labels at enrich time decide: mail archived before the poll gives none, and a mail back in the inbox later is no new mail', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world;
  world.advance(TICK);
  const mailId = simulator.deliver(mail()).id;
  simulator.relabel(mailId, {remove: ['INBOX']});
  assert.deepEqual(await polled(world, id), []);
  simulator.relabel(mailId, {add: ['INBOX']});
  assert.deepEqual(await polled(world, id), [], 'a label change adds no message');
});

test('draft churn costs enrich reads with no event, on every path a draft takes, and sending it gives exactly one', async t => {
  const world = worldOf(t), {simulator} = world, inbox = await watch(world, INBOX), sent = await watch(world, SENT), before = routed(world, MESSAGE).length;
  world.advance(TICK);
  const draft = simulator.seedDraft(mail('One', {from: OWNER_EMAIL, to: BOB}));
  simulator.editDraft(draft.id, mail('Two', {from: OWNER_EMAIL, to: BOB}));
  simulator.editDraft(draft.id, mail('Three', {from: OWNER_EMAIL, to: BOB}));
  assert.deepEqual(await polled(world, inbox), []);
  assert.ok(routed(world, MESSAGE).length > before, 'the feed lists each new id, and only a read can tell a draft');
  assert.deepEqual(await polled(world, inbox), [], 'and it is not read twice');
  const {data: {id}} = await simulator.request({url: `https://gmail.googleapis.com/gmail/v1/users/me/drafts/send`, method: 'POST', headers: {Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json'}, body: JSON.stringify({id: draft.id}), allowedOrigins: ['https://gmail.googleapis.com']});
  assert.deepEqual(fired(await polled(world, sent)).map(event => [event.subscriptionId, event.fields.messageId]), [[sent, id]]);
});

// ---- label-added ------------------------------------------------------------------------------------------------------------------------------------------------------------
test('label-added: remove and re-add gives two events, each on its own record, and another label gives none', async t => {
  const world = worldOf(t), {simulator} = world, labelId = label(world), other = label(world, 'Other'), {id: mailId} = simulator.deliver(mail()), id = await watch(world, LABELLED, {labelId});
  world.advance(TICK);
  simulator.relabel(mailId, {add: [labelId]});
  const first = fired(await polled(world, id));
  simulator.relabel(mailId, {remove: [labelId]});
  assert.deepEqual(await polled(world, id), [], 'a removal is no event');
  simulator.relabel(mailId, {add: [other]});
  assert.deepEqual(await polled(world, id), []);
  simulator.relabel(mailId, {add: [labelId]});
  const second = fired(await polled(world, id));
  assert.deepEqual([first.length, second.length], [1, 1]);
  assert.notEqual(first[0].fields.historyRecordId, second[0].fields.historyRecordId);
});

test('label-added: two watches on two labels share one feed, and each hears only its own label', async t => {
  const world = worldOf(t), {simulator} = world, work = label(world), home = label(world, 'Home'), one = await watch(world, LABELLED, {labelId: work}), two = await watch(world, LABELLED, {labelId: home});
  assert.deepEqual(world.record(one).feeds, world.record(two).feeds);
  world.advance(TICK);
  const {id: mailId} = simulator.deliver(mail());
  simulator.relabel(mailId, {add: [home]});
  assert.deepEqual(fired(await polled(world, one)).map(event => [event.subscriptionId, event.fields.labelName]), [[two, 'Home']]);
  assert.equal(routed(world, LABEL).length, 1, 'the watch with nothing to tell reads no label');
});

test('label-added: a label deleted before the read gives none, and a filter\'s label on arrival fires when Gmail writes the record', async t => {
  const world = worldOf(t), {simulator} = world, labelId = label(world), id = await watch(world, LABELLED, {labelId});
  world.advance(TICK);
  simulator.deliver(mail(), ['INBOX', labelId]);
  assert.deepEqual(await polled(world, id), [], 'with only messagesAdded nothing says a label was added');
  const {id: mailId} = simulator.deliver(mail(), ['INBOX', labelId], {labelsAdded: true});
  assert.deepEqual(fired(await polled(world, id)).map(event => event.fields.messageId), [mailId]);
  const gone = simulator.deliver(mail()).id;
  simulator.relabel(gone, {add: [labelId]});
  simulator.remove('label', labelId);
  assert.deepEqual(await polled(world, id), []);
});

test('labels.read at Never during a poll: no labels.get after it, the label watch pauses, and new-inbox-email still fires', async t => {
  const world = worldOf(t), {simulator} = world, labelId = label(world), inbox = await watch(world, INBOX), labelled = await watch(world, LABELLED, {labelId}), gate = simulator.hold(HISTORY);
  world.advance(TICK);
  const {id: mailId} = simulator.deliver(mail());
  simulator.relabel(mailId, {add: [labelId]});
  const poll = world.pollNow(inbox);
  await gate.reached;
  world.setRow('gmail.labels.read', 'deny');
  gate.release();
  await poll;
  assert.equal(routed(world, LABEL).length, 0);
  assert.deepEqual([world.record(labelled).status, world.record(labelled).reason], ['paused', 'permission_changed']);
  assert.equal(world.record(inbox).status, 'active');
  assert.deepEqual(fired(await unread(world)).map(event => [event.subscriptionId, event.fields.messageId]), [[inbox, mailId]]);
});

test('a Search row at Never leaves the five history watches reading, since none of them searches', async t => {
  const world = worldOf(t), inbox = await watch(world, INBOX), search = await watch(world, SEARCH, WATCHED);
  world.setRow('gmail.messages.search', 'deny');
  world.advance(TICK);
  world.simulator.deliver(mail());
  await world.pollNow(search);
  assert.deepEqual([world.record(search).status, world.record(search).reason], ['paused', 'permission_changed']);
  assert.equal(fired(await polled(world, inbox)).length, 1);
  assert.equal(world.record(inbox).status, 'active');
});

// ---- reply-on-my-thread ----------------------------------------------------------------------------------------------------------------------------------------------------
test('reply-on-my-thread: a reply fires, a thread you never wrote in does not, and neither does your own reply', async t => {
  const world = worldOf(t), {simulator} = world, first = opened(world), id = await watch(world, REPLY);
  world.advance(TICK);
  const theirs = simulator.deliver(reply());
  assert.equal(theirs.threadId, first.threadId);
  simulator.ownerSends(mail('Re: Plan', {from: OWNER_EMAIL, to: THEM, more: [`In-Reply-To: ${REFERENCE}`]}), first.threadId);
  simulator.deliver(mail('Stranger'));
  assert.deepEqual(fired(await polled(world, id)).map(event => event.fields.messageId), [theirs.id]);
  assert.equal(routed(world, THREAD).at(-1).query.format, 'minimal');
});

test('reply-on-my-thread: a thread that has gone by the read gives none, and the feed moves', async t => {
  const world = worldOf(t), {simulator} = world, first = opened(world), id = await watch(world, REPLY);
  world.advance(TICK);
  simulator.deliver(reply());
  simulator.remove('thread', first.threadId);
  assert.deepEqual(await polled(world, id), []);
  assert.equal(feedOf(world, id).cursors.history, simulator.state().historyId);
});

test('reply-on-my-thread: a mail you answered before the poll read it is no reply to you, since nothing of yours came before it', async t => {
  const {world, id} = await watching(t, REPLY), {simulator} = world;
  world.advance(TICK);
  const {threadId} = simulator.deliver(mail('Question', {more: ['Message-ID: <question@example.com>']}));
  simulator.ownerSends(mail('Re: Question', {from: OWNER_EMAIL, to: THEM, more: ['In-Reply-To: <question@example.com>']}), threadId);
  assert.deepEqual(await polled(world, id), []);
});

// ---- losing a place --------------------------------------------------------------------------------------------------------------------------------------------------------
test('a 404 re-baselines from the profile with one gap and no duplicate, and what it skipped is not told', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world, seen = routed(world, PROFILE).length;
  world.advance(TICK);
  const first = simulator.deliver(mail('First'));
  assert.equal(fired(await polled(world, id))[0].fields.messageId, first.id);
  const good = feedOf(world, id).lastGoodAt;
  world.advance(TICK);
  simulator.deliver(mail('Lost'));
  simulator.expireHistory(simulator.state().historyId);
  world.advance(TICK);
  const landed = world.now;
  await world.pollNow(id);
  const events = await unread(world);
  assert.deepEqual(events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'resync']]);
  assert.deepEqual([events[0].fields.from, events[0].fields.to], [iso(good), iso(landed)]);
  assert.equal(routed(world, PROFILE).length, seen + 1);
  assert.equal(feedOf(world, id).cursors.history, simulator.state().historyId, 'the cursor came from the provider\'s answer');
  assert.deepEqual(await polled(world, id), []);
  world.advance(TICK);
  const next = simulator.deliver(mail('Next'));
  assert.deepEqual(fired(await polled(world, id)).map(event => event.fields.messageId), [next.id]);
});

test('a stale id on a shared feed gives each live watch one gap, from one profile read', async t => {
  const world = worldOf(t), {simulator} = world, labelId = label(world), ids = [await watch(world, INBOX), await watch(world, SENT), await watch(world, LABELLED, {labelId})], profiles = routed(world, PROFILE).length;
  world.advance(TICK);
  simulator.deliver(mail('Lost'));
  simulator.expireHistory(simulator.state().historyId);
  world.advance(TICK);
  await world.pollNow(ids[0]);
  assert.deepEqual(gaps(await unread(world)).map(event => event.subscriptionId).sort(), [...ids].sort());
  assert.equal(routed(world, PROFILE).length, profiles + 1);
  assert.deepEqual(await polled(world, ids[1]), []);
});

test('a window of a few hours is out of date the same way, and a failed seed read keeps the old cursor and stores nothing', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world;
  world.advance(TICK);
  simulator.deliver(mail('Old'));
  assert.equal(fired(await polled(world, id)).length, 1);
  const place = feedOf(world, id).cursors.history;
  simulator.deliver(mail('Lost'));
  world.advance(DAY);
  simulator.historyOptions({keepHours: 4});
  simulator.fail(PROFILE, googleError(500, 'backendError'));
  assert.deepEqual(await polled(world, id), []);
  assert.equal(feedOf(world, id).cursors.history, place);
  assert.equal(lastRun(world, id).outcome, 'backoff');
  assert.deepEqual(reasons(await polled(world, id)), ['resync']);
});

test('an empty answer with no id keeps the cursor, and the next mail still lands', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world, place = feedOf(world, id).cursors.history;
  simulator.historyOptions({emptyHoldsId: false});
  assert.deepEqual(await polled(world, id), []);
  assert.equal(feedOf(world, id).cursors.history, place);
  assert.equal(world.record(id).status, 'active');
  world.advance(TICK);
  assert.equal(fired((simulator.deliver(mail()), await polled(world, id))).length, 1);
});

test('ids past 2^53 compare correctly: a Number() would read the first two as one and stop the feed on the old record', async t => {
  const {world, id} = await watching(t, INBOX, {}, {historyId: FAR}), {simulator} = world;
  assert.equal(feedOf(world, id).cursors.history, FAR);
  world.advance(TICK);
  const first = simulator.deliver(mail('First'));
  assert.equal(fired(await polled(world, id))[0].fields.messageId, first.id);
  const place = feedOf(world, id).cursors.history;
  assert.ok(BigInt(place) > BigInt(FAR));
  world.advance(TICK);
  const burst = Array.from({length: 30}, (_, index) => simulator.deliver(mail(`M${index}`)).id);
  const cut = fired(await polled(world, id));
  assert.equal(cut.length, 25);
  const partial = BigInt(feedOf(world, id).cursors.history);
  assert.ok(partial > BigInt(place) && partial < BigInt(simulator.state().historyId), 'a partial poll stops at a record, in exact digits');
  assert.deepEqual([...cut, ...fired(await polled(world, id))].map(event => event.fields.messageId).sort(), [...burst].sort());
});

// ---- a poll cut short ------------------------------------------------------------------------------------------------------------------------------------------------------
test('a partial poll advances to the last whole record: 30 mails at 25 reads a poll, each once, with no gap', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world, before = simulator.state().history.length;
  world.advance(TICK);
  const mails = Array.from({length: 30}, (_, index) => simulator.deliver(mail(`M${index}`)).id), first = await polled(world, id);
  assert.equal(first.length, 25);
  assert.equal(feedOf(world, id).cursors.history, simulator.state().history[before + 24].id, 'the 25th record is the last one whole');
  assert.equal(lastRun(world, id).outcome, 'cut');
  const second = await polled(world, id);
  assert.deepEqual([...first, ...second].map(event => event.fields.messageId), mails, 'in record order');
  assert.equal(gaps(second).length, 0);
  assert.equal(feedOf(world, id).cursors.history, simulator.state().historyId);
});

test('a record is never split: a bulk label over one record keeps the cursor before it until every message of it is told, each once', async t => {
  const world = worldOf(t), {simulator} = world, labelId = label(world), mails = Array.from({length: 30}, (_, index) => simulator.deliver(mail(`M${index}`)).id), id = await watch(world, LABELLED, {labelId}), place = feedOf(world, id).cursors.history;
  world.advance(TICK);
  simulator.together(() => { for (const mailId of mails) simulator.relabel(mailId, {add: [labelId]}); });
  const first = await polled(world, id);
  assert.equal(first.length, 25);
  assert.equal(feedOf(world, id).cursors.history, place, 'the record is not finished, so the cursor stays');
  const second = await polled(world, id);
  assert.deepEqual([...first, ...second].map(event => event.fields.messageId), mails);
  assert.equal(feedOf(world, id).cursors.history, simulator.state().historyId);
});

test('a bulk change past 500 entries on one page stops at a whole record, and the next poll starts after it', async t => {
  const world = worldOf(t), {simulator} = world, labelId = label(world), mails = Array.from({length: 600}, (_, index) => simulator.deliver(mail(`M${index}`)).id), id = await watch(world, LABELLED, {labelId});
  world.advance(TICK);
  simulator.together(() => { for (const mailId of mails.slice(0, 300)) simulator.relabel(mailId, {add: [labelId]}); });
  const first = simulator.state().historyId;
  simulator.together(() => { for (const mailId of mails.slice(300)) simulator.relabel(mailId, {add: [labelId]}); });
  const second = simulator.state().historyId;
  alreadyTold(world, id, [...mails.slice(0, 300).map(mailId => `${first}:${mailId}`), ...mails.slice(300, 590).map(mailId => `${second}:${mailId}`)]);
  assert.deepEqual(await polled(world, id), []);
  assert.equal(feedOf(world, id).cursors.history, first, 'the record it could not hold waits for the next poll');
  assert.deepEqual(fired(await polled(world, id)).map(event => event.fields.messageId), mails.slice(590));
  assert.equal(feedOf(world, id).cursors.history, second);
});

test('one record too large to hold whole is passed over with one gap, and the feed moves on', async t => {
  const world = worldOf(t), {simulator} = world, labelId = label(world), mails = Array.from({length: 501}, (_, index) => simulator.deliver(mail(`M${index}`)).id), id = await watch(world, LABELLED, {labelId});
  world.advance(TICK);
  simulator.together(() => { for (const mailId of mails) simulator.relabel(mailId, {add: [labelId]}); });
  assert.deepEqual(reasons(await polled(world, id)), ['stall']);
  assert.equal(feedOf(world, id).cursors.history, simulator.state().historyId);
  simulator.relabel(mails[0], {remove: [labelId]});
  simulator.relabel(mails[0], {add: [labelId]});
  assert.deepEqual(fired(await polled(world, id)).map(event => event.fields.messageId), [mails[0]]);
});

test('5,001 inbox mails leave the watch active, a crash replay adds nothing, and the feed stays within its bounds at every poll', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world, mails = Array.from({length: 5001}, (_, index) => simulator.deliver(mail(`M${index}`)).id), {keys, lens} = alreadyTold(world, id, mails.slice(0, 4995));
  for (let poll = 0; poll < 9; poll++) {
    assert.deepEqual(await polled(world, id), [], 'known mail sends no read');
    assert.equal(lastRun(world, id).requests, 1, 'one page a poll: the item bound stops the next request');
  }
  world.advance(TICK);
  await crash(world, id);
  const told = await unread(world);
  assert.deepEqual(told.map(event => event.fields.messageId), mails.slice(4995, 5000), 'the page that crashed stored its events first');
  assert.deepEqual(await polled(world, id), [], 'and its replay adds nothing');
  assert.deepEqual((await polled(world, id)).map(event => event.fields.messageId), [mails[5000]]);
  assert.equal(world.record(id).status, 'active');
  assert.equal(feedOf(world, id).cursors.history, simulator.state().historyId);
  assert.equal(world.store.seenRows(feedOf(world, id).id, lens, mails.map(keys)).size, 5000, 'a history feed drops its oldest row past the limit, since that item never comes back');
});

// ---- one message goes wrong ----------------------------------------------------------------------------------------------------------------------------------------------------
test('a 404 on messages.get skips that mail alone: the mail after it fires and the feed moves', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world;
  world.advance(TICK);
  const gone = simulator.deliver(mail('Gone')).id, kept = simulator.deliver(mail('Kept')).id;
  simulator.remove('message', gone);
  assert.deepEqual((await polled(world, id)).map(event => event.fields.messageId), [kept]);
  assert.equal(world.record(id).status, 'active');
  assert.equal(feedOf(world, id).cursors.history, simulator.state().historyId);
  assert.equal(lastRun(world, id).outcome, 'done');
});

test('a 503 on messages.get loses nothing: the poll backs off at the last whole record, and the next poll gives the event', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world, place = feedOf(world, id).cursors.history;
  world.advance(TICK);
  const {id: mailId} = simulator.deliver(mail());
  simulator.fail(MESSAGE, googleError(503, 'backendError'));
  assert.deepEqual(await polled(world, id), []);
  assert.equal(feedOf(world, id).cursors.history, place);
  assert.equal(lastRun(world, id).outcome, 'backoff');
  assert.equal(world.record(id).status, 'active');
  assert.deepEqual(fired(await polled(world, id)).map(event => event.fields.messageId), [mailId]);
});

test('a 3 MiB message is skipped with one gap and the feed moves: the attachment watch tells the next mail, and the inbox watch tells both', async t => {
  const world = worldOf(t), {simulator} = world, files = await watch(world, FILES), inbox = await watch(world, INBOX);
  world.advance(TICK);
  const big = simulator.deliver(mail('Big', {body: 'x'.repeat(3 * 1024 * 1024)})).id, small = simulator.deliver(withFile('Small')).id;
  const events = await polled(world, files);
  assert.deepEqual(reasons(events.filter(event => event.subscriptionId === files)), ['stall']);
  assert.deepEqual(fired(events).filter(event => event.subscriptionId === files).map(event => event.fields.messageId), [small]);
  assert.deepEqual(fired(events).filter(event => event.subscriptionId === inbox).map(event => event.fields.messageId), [big, small]);
  assert.equal(lastRun(world, files).skipped, 1);
  assert.equal(world.record(files).status, 'active');
  assert.equal(feedOf(world, files).cursors.history, simulator.state().historyId);
  assert.deepEqual(await polled(world, files), [], 'one gap, and it is not read again');
});

test('five failed polls on one record skip it with one gap, so one mail cannot hold a feed', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world;
  world.advance(TICK);
  const stuck = simulator.deliver(mail('Stuck')).id, next = simulator.deliver(mail('Next')).id, told = [];
  simulator.fail(MESSAGE, googleError(503, 'backendError'), {times: 5});
  for (let poll = 0; poll < 4; poll++) assert.deepEqual(await polled(world, id), [], `poll ${poll + 1}`);
  told.push(...await polled(world, id));
  assert.deepEqual(reasons(told), ['stall']);
  told.push(...await polled(world, id));
  assert.deepEqual(fired(told).map(event => event.fields.messageId), [next]);
  assert.equal(told.some(event => event.fields.messageId === stuck), false);
  assert.equal(world.record(id).status, 'active');
});

test('five watches through one burst stay within 64 requests a poll, the cursor waits for the slowest, and each hears its own, once', async t => {
  const world = worldOf(t), {simulator} = world, labelId = label(world);
  opened(world);
  const watches = {inbox: await watch(world, INBOX), sent: await watch(world, SENT), labelled: await watch(world, LABELLED, {labelId}), replies: await watch(world, REPLY), files: await watch(world, FILES)}, expected = Object.fromEntries(Object.keys(watches).map(name => [name, []]));
  world.advance(TICK);
  for (let index = 0; index < 30; index++) {
    const file = simulator.deliver(withFile(`F${index}`)).id, answer = simulator.deliver(reply()).id, out = simulator.ownerSends(mail('Out', {from: OWNER_EMAIL, to: BOB})).id;
    simulator.relabel(file, {add: [labelId]});
    expected.inbox.push(file, answer);
    expected.files.push(file);
    expected.labelled.push(file);
    expected.replies.push(answer);
    expected.sent.push(out);
  }
  const told = [];
  for (let poll = 0; poll < 12 && feedOf(world, watches.inbox).cursors.history !== simulator.state().historyId; poll++) {
    told.push(...await polled(world, watches.inbox));
    assert.ok(lastRun(world, watches.inbox).requests <= 64, `poll ${poll + 1} sent ${lastRun(world, watches.inbox).requests}`);
  }
  assert.equal(feedOf(world, watches.inbox).cursors.history, simulator.state().historyId);
  assert.equal(gaps(told).length, 0);
  for (const [name, id] of Object.entries(watches)) assert.deepEqual(told.filter(event => event.subscriptionId === id).map(event => event.fields.messageId).sort(), [...expected[name]].sort(), name);
});

test('five watches through heavy draft churn: mail that has gone answers 404 and takes no seen row, but it cannot hold the cursor, and the mail after it lands', async t => {
  const world = worldOf(t), {simulator} = world, labelId = label(world), first = await watch(world, INBOX);
  for (const [key, args] of [[SENT], [LABELLED, {labelId}], [REPLY], [FILES]]) await watch(world, key, args);
  world.advance(TICK);
  const draft = simulator.seedDraft(mail('Draft', {from: OWNER_EMAIL, to: BOB}));
  for (let index = 0; index < 60; index++) simulator.editDraft(draft.id, mail(`Draft ${index}`, {from: OWNER_EMAIL, to: BOB}));
  const {id: mailId} = simulator.deliver(mail()), told = [];
  for (let poll = 0; poll < 8 && feedOf(world, first).cursors.history !== simulator.state().historyId; poll++) told.push(...await polled(world, first));
  assert.equal(feedOf(world, first).cursors.history, simulator.state().historyId);
  assert.deepEqual(told.map(event => event.fields.messageId), [mailId]);
});

for (const [name, kind] of [['a 429 for too many concurrent requests', 'tooManyConcurrent'], ['a daily limit', 'dailyLimitExceeded'], ['a user limit', 'userRateLimitExceeded'], ['a rate limit', 'rateLimitExceeded']]) {
  test(`${name} waits and never pauses, on the feed and on an enrich read, and the mail lands after it`, async t => {
    const {world, id} = await watching(t, INBOX), {simulator} = world, place = feedOf(world, id).cursors.history;
    world.advance(TICK);
    const {id: mailId} = simulator.deliver(mail());
    simulator.limit(HISTORY, kind);
    assert.deepEqual(await polled(world, id), []);
    assert.deepEqual([world.record(id).status, lastRun(world, id).outcome, feedOf(world, id).cursors.history], ['active', 'limited', place]);
    simulator.limit(MESSAGE, kind);
    assert.deepEqual(await polled(world, id), []);
    assert.deepEqual([world.record(id).status, lastRun(world, id).outcome, feedOf(world, id).cursors.history], ['active', 'limited', place]);
    assert.deepEqual(fired(await polled(world, id)).map(event => event.fields.messageId), [mailId]);
  });
}

for (const reason of ['domainPolicy', 'insufficientPermissions']) {
  test(`a 403 ${reason} is no limit: the watch pauses`, async t => {
    const {world, id} = await watching(t, INBOX);
    world.simulator.fail(HISTORY, googleError(403, reason));
    world.advance(TICK);
    const held = await world.pollNow(id);
    assert.deepEqual([held.status, held.reason, held.detail], ['paused', 'provider_refused', 'http_403']);
  });
}

test('no Subject header, a group From and a Bcc-only send each give one event without that field, and a mail is never lost for a header it lacks', async t => {
  const world = worldOf(t), {simulator} = world, inbox = await watch(world, INBOX), sent = await watch(world, SENT);
  world.advance(TICK);
  const bare = simulator.deliver(mail(null)).id, group = simulator.deliver(mail('Group', {from: 'undisclosed-recipients:;'})).id, blind = simulator.ownerSends(mail('Blind', {from: OWNER_EMAIL, to: null, more: [`Bcc: ${BOB}`]})).id;
  const events = fired(await polled(world, inbox)), of = (subscription, mailId) => events.filter(event => event.subscriptionId === subscription && event.fields.messageId === mailId);
  assert.equal(events.length, 3);
  assert.equal(Object.hasOwn(of(inbox, bare)[0].fields, 'subject'), false);
  assert.deepEqual(of(inbox, bare)[0].summary, [{label: 'From', value: THEM}], 'a summary line with no value is left out');
  assert.equal(Object.hasOwn(of(inbox, group)[0].fields, 'from'), false);
  assert.equal(of(inbox, group)[0].fields.subject, 'Group');
  assert.equal(Object.hasOwn(of(sent, blind)[0].fields, 'to'), false);
  assert.equal(of(sent, blind)[0].fields.subject, 'Blind');
});

test('an attachment watch names the first file and passes over mail with none', async t => {
  const {world, id} = await watching(t, FILES), {simulator} = world;
  world.advance(TICK);
  simulator.deliver(mail('Plain'));
  const {id: mailId} = simulator.deliver(withFile('Report', 'report.pdf'));
  const events = await polled(world, id);
  assert.deepEqual(events.map(event => [event.fields.messageId, event.fields.firstFilename]), [[mailId, 'report.pdf']]);
});

test('a poll writes no audit row, and an event holds no credential a mail tried to carry', async t => {
  const {world, id} = await watching(t, INBOX), {simulator} = world, audits = [];
  const {audit} = world.store;
  world.store.audit = event => { audits.push(event); return audit.call(world.store, event); };
  world.advance(TICK);
  simulator.deliver(mail(`Your token is ${TOKEN}`));
  const [event] = await polled(world, id);
  assert.deepEqual(audits, []);
  assert.equal(JSON.stringify(event).includes(TOKEN), false);
  assert.equal(event.type, 'trigger.event');
});

// ---- the search ------------------------------------------------------------------------------------------------------------------------------------------------------------
test('an empty search is refused before anything is stored, and two searches are two watches on two feeds', async t => {
  const world = worldOf(t);
  await assert.rejects(world.subscribe(SEARCH, {search: {}}), error => error.code === 'invalid_request');
  assert.deepEqual(world.store.list('subscriptions'), []);
  const one = await watch(world, SEARCH, WATCHED), two = await watch(world, SEARCH, {search: {from: BOB}});
  assert.notDeepEqual(world.record(one).feeds, world.record(two).feeds);
});

test('the search reads only its own terms inside seven days, and another subject gives none', async t => {
  const {world, id} = await watching(t, SEARCH, WATCHED), {simulator} = world;
  world.advance(TICK);
  simulator.deliver(mail('Something else'));
  const {id: mailId} = simulator.deliver(mail('Hello'));
  assert.deepEqual((await polled(world, id)).map(event => event.fields.messageId), [mailId]);
  assert.equal(routed(world, MESSAGES).at(-1).query.q, 'subject:"Hello" newer_than:7d');
});

test('a mail that shows in the search late still gives one event, and a draft that matches gives none', async t => {
  const {world, id} = await watching(t, SEARCH, WATCHED), {simulator} = world, lag = 10 * 60_000;
  world.advance(TICK);
  simulator.historyOptions({searchLagMs: lag});
  const {id: mailId} = simulator.deliver(mail());
  simulator.seedDraft(mail());
  simulator.historyOptions({searchLagMs: 0});
  assert.deepEqual(await polled(world, id), [], 'not in q yet');
  world.advance(lag);
  assert.deepEqual((await polled(world, id)).map(event => event.fields.messageId), [mailId]);
  assert.deepEqual(await polled(world, id), []);
});

test('more than 25 matching drafts cannot hold a search back: each is read once, turned down once, and the read still reaches the present', async t => {
  const {world, id} = await watching(t, SEARCH, WATCHED), {simulator} = world, before = routed(world, MESSAGE).length;
  world.advance(TICK);
  for (let index = 0; index < 30; index++) simulator.seedDraft(mail());
  assert.deepEqual(await polled(world, id), []);
  assert.equal(routed(world, MESSAGE).length - before, 25);
  assert.equal(lastRun(world, id).outcome, 'cut');
  assert.deepEqual(await polled(world, id), []);
  assert.equal(routed(world, MESSAGE).length - before, 30, 'the five left, and none of the 25 again');
  assert.equal(lastRun(world, id).outcome, 'done');
  assert.deepEqual(await polled(world, id), []);
  assert.equal(routed(world, MESSAGE).length - before, 30);
});

test('a 503 on a search read loses nothing: the next poll tells the mail, and five failed polls skip it with one gap and a seen row', async t => {
  const {world, id} = await watching(t, SEARCH, WATCHED), {simulator} = world;
  world.advance(TICK);
  const {id: first} = simulator.deliver(mail());
  simulator.fail(MESSAGE, googleError(503, 'backendError'));
  assert.deepEqual(await polled(world, id), []);
  assert.equal(lastRun(world, id).outcome, 'backoff');
  assert.deepEqual((await polled(world, id)).map(event => event.fields.messageId), [first]);
  world.advance(TICK);
  simulator.deliver(mail());
  simulator.fail(MESSAGE, googleError(503, 'backendError'), {times: 5});
  const told = [];
  for (let poll = 0; poll < 5; poll++) told.push(...await polled(world, id));
  assert.deepEqual(told.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'stall']]);
  assert.deepEqual(await polled(world, id), [], 'its seen row keeps it from coming back');
});

test('seven days off gives one gap on the search source, a silent read, and what follows fires', async t => {
  const {world, id} = await watching(t, SEARCH, WATCHED), {simulator} = world, good = feedOf(world, id).lastGoodAt;
  world.advance(TICK);
  simulator.deliver(mail('Hello'));
  await polled(world, id);
  const last = feedOf(world, id).lastGoodAt;
  assert.ok(last > good);
  world.advance(7 * DAY + TICK);
  simulator.deliver(mail('Hello'));
  await world.pollNow(id);
  const events = await unread(world);
  assert.deepEqual(events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'window']]);
  assert.equal(events[0].fields.from, iso(last));
  assert.deepEqual(await polled(world, id), [], 'the gap covers what the silent read marked');
  world.advance(TICK);
  const {id: mailId} = simulator.deliver(mail('Hello'));
  assert.deepEqual((await polled(world, id)).map(event => event.fields.messageId), [mailId]);
});

test('six days off is inside the window: everything still listed is told, with no gap', async t => {
  const {world, id} = await watching(t, SEARCH, WATCHED), {simulator} = world;
  world.advance(6 * DAY);
  const {id: mailId} = simulator.deliver(mail());
  assert.deepEqual((await polled(world, id)).map(event => [event.type, event.fields.messageId]), [['trigger.event', mailId]]);
});

// ---- a search longer than its bound ----------------------------------------------------------------------------------------------------------------------------------------
/** A search with more matches than a poll reads, and one mail its index holds back, so that mail shows behind all of them, past the bound. */
async function longSearch(t, options) {
  const world = worldOf(t, options), {simulator} = world, lag = 10 * 60_000;
  simulator.historyOptions({searchLagMs: lag});
  const late = simulator.deliver(mail()).id;
  simulator.historyOptions({searchLagMs: 0});
  world.advance(SECOND);
  for (let index = 0; index < 600; index++) simulator.deliver(mail());
  const id = await watch(world, SEARCH, WATCHED);
  assert.deepEqual(await unread(world), []);
  world.advance(lag);
  return {world, id, late, lag};
}

test('a search past its bound reads known items and stops: the mail past the bound goes unreported, and one gap says so, which a list that keeps no order owes', async t => {
  const {world, id, late} = await longSearch(t), before = feedOf(world, id).lastGoodAt;
  const events = await polled(world, id);
  assert.deepEqual(reasons(events), ['bound']);
  assert.equal(fired(events).length, 0);
  assert.equal(events[0].fields.from, iso(before));
  assert.equal(events.some(event => event.fields.messageId === late), false);
  assert.equal(world.record(id).status, 'active', 'a window cut by its bound still reaches the present');
  assert.deepEqual((await world.engine.pollNow(id), await unread(world)), [], 'the same list a moment later says nothing new');
});

// ---- a mail a stranger shaped ---------------------------------------------------------------------------------------------------------------------------------------------
const CONTROL_BYTES = () => mail('Control bytes', {body: '\u0001'.repeat(360_000)});
const MANY_HEADERS = () => mail('Many headers', {more: Array.from({length: 17_000}, () => 'X-A: b')});
for (const [label, shaped] of [['a body that escapes past the decoder\'s 2 MiB', CONTROL_BYTES], ['more header lines than a value may hold', MANY_HEADERS]]) {
  test(`${label}: one mail from a stranger skips alone with one gap, the mail behind it is told, and the cursor moves on`, async t => {
    const {world, id} = await watching(t, FILES), {simulator} = world, before = feedOf(world, id).cursors.history;
    world.advance(TICK);
    simulator.deliver(shaped());
    const {id: behind} = simulator.deliver(withFile('Behind it'));
    const events = await polled(world, id);
    assert.equal(world.record(id).status, 'active', 'one mail is no reason to stop the watch');
    assert.deepEqual(events.map(event => [event.type, event.fields.messageId ?? event.fields.reason]), [['trigger.event', behind], ['trigger.gap', 'stall']]);
    assert.notEqual(feedOf(world, id).cursors.history, before);
    assert.deepEqual(await polled(world, id), [], 'its seen row and the cursor keep it from coming back');
  });
}
test('beside an inbox watch, the mail a late filter cannot read still reaches the inbox watch, and the attachment watch stays active', async t => {
  const world = worldOf(t), files = await watch(world, FILES), inbox = await watch(world, INBOX);
  world.advance(TICK);
  const {id: mailId} = world.simulator.deliver(CONTROL_BYTES());
  const events = await polled(world, files);
  assert.equal(world.record(files).status, 'active');
  assert.deepEqual(fired(events).filter(event => event.subscriptionId === inbox).map(event => event.fields.messageId), [mailId]);
});

test('a search past its bound waits its normal interval: reading the window again gets no further, and each read spends the owner\'s quota', async t => {
  const {world, id} = await longSearch(t), sent = routed(world, MESSAGES).length;
  await world.ticking(10 * 60_000);
  assert.equal(routed(world, MESSAGES).length - sent, 10, 'two walks of five pages, one for each interval that passed');
  assert.equal(world.record(id).status, 'active');
});

test('a search past its bound tells of its unread tail once a day, and each gap starts where the last ended, so a long list cannot bury real events', async t => {
  const {world, id} = await longSearch(t);
  const [first] = await polled(world, id);
  for (let poll = 0; poll < 8; poll++) assert.deepEqual(await polled(world, id), [], `poll ${poll + 1}`);
  world.advance(DAY);
  const events = await polled(world, id);
  assert.deepEqual(reasons(events), ['bound']);
  assert.equal(events[0].fields.from, first.fields.to);
  world.advance(TICK);
  const {id: mailId} = world.simulator.deliver(mail());
  assert.deepEqual((await polled(world, id)).map(event => [event.type, event.fields.messageId]), [['trigger.event', mailId]], 'new mail in the read still fires, with no gap for it');
});

test('a poll that fails keeps the day\'s count, so a backoff on a long search tells nothing twice', async t => {
  const {world, id} = await longSearch(t);
  assert.deepEqual(reasons(await polled(world, id)), ['bound']);
  const told = feedOf(world, id).unreadTo;
  world.simulator.fail(MESSAGES, googleError(503, 'backendError'));
  assert.deepEqual(await polled(world, id), []);
  assert.equal(lastRun(world, id).outcome, 'backoff');
  assert.equal(feedOf(world, id).unreadTo, told);
  assert.deepEqual(await polled(world, id), []);
});

test('a search that fits again reads whole: the mail that sat past the bound is told, and the next long read opens a new gap', async t => {
  const {world, id, late} = await longSearch(t), {simulator} = world;
  assert.deepEqual(reasons(await polled(world, id)), ['bound']);
  const newest = (await simulator.request({url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=500&q=subject%3A%22Hello%22', method: 'GET', headers: {Authorization: `Bearer ${TOKEN}`}, allowedOrigins: ['https://gmail.googleapis.com']})).data.messages.map(item => item.id);
  for (const mailId of newest.slice(0, 120)) simulator.remove('message', mailId);
  const told = [];
  for (let poll = 0; poll < 5 && !told.some(event => event.fields?.messageId === late); poll++) told.push(...await polled(world, id));
  assert.ok(told.some(event => event.fields?.messageId === late), 'it is new, and it reaches the agent');
  assert.equal(gaps(told).length, 0);
  assert.equal(feedOf(world, id).unreadTo ?? null, null);
  world.advance(TICK);
  for (let index = 0; index < 120; index++) simulator.deliver(mail());
  const refilled = [];
  for (let poll = 0; poll < 6; poll++) refilled.push(...await polled(world, id));
  assert.deepEqual(reasons(refilled), ['bound']);
});

test('a window with no set reach reads what its bound reaches, so a cut read owes no gap', async t => {
  const {world, id} = await longSearch(t, {engine: {windows: () => ({seconds: null})}});
  assert.deepEqual(await polled(world, id), []);
  assert.equal(feedOf(world, id).unreadTo ?? null, null);
});

test('a read a window cut by its bound stays silent while it baselines: the first gap comes with the first poll that could have told an event', async t => {
  const {world, id} = await longSearch(t);
  assert.deepEqual(await unread(world), []);
  assert.equal(feedOf(world, id).unreadTo ?? null, null);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {GmailSimulator, ORIGIN, BASE} from './fixtures/provider-simulators/gmail.mjs';

// Iteration 9 step 7 (docs/I07-BUILD-MAP.md, step 7): what the Gmail simulator gained for triggers. It is written from Gmail's history guide and reference and from the simulator's own header
// comment, and never from Gmail's trigger file, so a trigger bug and a simulator bug cannot cancel out. Nothing here calls Google.
const TOKEN = 'gmail-token-7c1d', AUTH = {Authorization: `Bearer ${TOKEN}`}, OWNER = 'owner@example.com', START = Date.parse('2026-10-26T13:00:00.000Z'), HOUR = 3_600_000, DAY = 24 * HOUR;
const SCOPE = name => `https://www.googleapis.com/auth/${name}`;
const FAR = '9007199254740993';
function sim(options = {}) {
  let now = START;
  const simulator = new GmailSimulator({token: TOKEN, owner: {email: OWNER}, scopes: [SCOPE('gmail.modify'), SCOPE('gmail.settings.basic')], clock: () => now, ...options});
  simulator.advance = ms => { now += ms; };
  return simulator;
}
const send = (simulator, method, path, {body, query, ...more} = {}) => {
  const url = new URL(`${BASE}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) for (const item of [value].flat()) url.searchParams.append(name, String(item));
  return simulator.request({url: url.href, method, headers: {...AUTH, ...(body === undefined ? {} : {'Content-Type': 'application/json'})}, ...(body === undefined ? {} : {body: JSON.stringify(body)}), allowedOrigins: [ORIGIN], ...more});
};
const raw = (subject = 'Hello', to = OWNER, from = 'ann@example.com') => Buffer.from(`From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\n\r\nHello.\r\n`, 'utf8').toString('base64url');
const current = async simulator => (await send(simulator, 'GET', '/profile')).data.historyId;
const history = (simulator, startHistoryId, query = {}) => send(simulator, 'GET', '/history', {query: {startHistoryId, ...query}});
const reasonOf = answer => [answer.status, answer.data?.error?.errors?.[0]?.reason];
/** What each record says, without its id: its typed fields, each as the message and any labels. */
const shape = list => list.map(({id: _id, messages: _messages, ...types}) => Object.fromEntries(Object.entries(types).map(([type, entries]) => [type, entries.map(entry => entry.labelIds ? [entry.message.id, entry.labelIds] : entry.message.id)])));
const records = async (simulator, start) => (await history(simulator, start)).data.history ?? [];

test('each change writes one record, in order, and a message\'s historyId is the record that last moved it', async () => {
  const simulator = sim(), start = await current(simulator), label = (await send(simulator, 'POST', '/labels', {body: {name: 'Work'}})).data.id, a = simulator.deliver(raw('A')), b = simulator.deliver(raw('B'));
  await send(simulator, 'POST', '/messages/batchModify', {body: {ids: [a.id], addLabelIds: [label], removeLabelIds: ['INBOX']}});
  await send(simulator, 'POST', `/messages/${b.id}/trash`);
  await send(simulator, 'POST', `/messages/${b.id}/untrash`);
  const sent = (await send(simulator, 'POST', '/messages/send', {body: {raw: raw('Out', 'bob@example.com', OWNER)}})).data;
  assert.deepEqual(shape(await records(simulator, start)), [{messagesAdded: [a.id]}, {messagesAdded: [b.id]}, {labelsAdded: [[a.id, [label]]], labelsRemoved: [[a.id, ['INBOX']]]}, {labelsAdded: [[b.id, ['TRASH']]]}, {labelsRemoved: [[b.id, ['TRASH']]]}, {messagesAdded: [sent.id]}]);
  const list = await records(simulator, start), message = (await send(simulator, 'GET', `/messages/${a.id}`, {query: {format: 'minimal'}})).data;
  assert.equal(message.historyId, list[2].id);
  assert.deepEqual(list[0].messages, [{id: a.id, threadId: a.threadId}], 'history[].messages repeats the typed fields');
});

test('draft churn: a new draft adds, an update deletes the old message and adds a new id, a send deletes it and adds another, and each mail goes in the log as Gmail writes it', async () => {
  const simulator = sim(), start = await current(simulator), draft = (await send(simulator, 'POST', '/drafts', {body: {message: {raw: raw('One', 'bob@example.com', OWNER)}}})).data;
  const edited = (await send(simulator, 'PUT', `/drafts/${draft.id}`, {body: {message: {raw: raw('Two', 'bob@example.com', OWNER)}}})).data;
  const sent = (await send(simulator, 'POST', '/drafts/send', {body: {id: draft.id}})).data;
  assert.deepEqual(shape(await records(simulator, start)), [{messagesAdded: [draft.message.id]}, {messagesDeleted: [draft.message.id]}, {messagesAdded: [edited.message.id]}, {messagesDeleted: [edited.message.id]}, {messagesAdded: [sent.id]}]);
});

test('what the owner does in Gmail writes the log too: seedDraft, editDraft and remove', async () => {
  const simulator = sim(), start = await current(simulator), draft = simulator.seedDraft(raw('D')), edited = simulator.editDraft(draft.id, raw('E')), mail = simulator.deliver(raw('M'));
  simulator.remove('message', mail.id);
  simulator.remove('draft', draft.id);
  assert.deepEqual(shape(await records(simulator, start)), [{messagesAdded: [draft.message.id]}, {messagesDeleted: [draft.message.id]}, {messagesAdded: [edited.message.id]}, {messagesAdded: [mail.id]}, {messagesDeleted: [mail.id]}, {messagesDeleted: [edited.message.id]}]);
});

test('removing a label writes labelsRemoved for each message that held it, and removing a thread deletes each message', async () => {
  const simulator = sim(), label = (await send(simulator, 'POST', '/labels', {body: {name: 'Gone'}})).data.id, mail = simulator.deliver(raw('M'), ['INBOX', label]), start = await current(simulator);
  simulator.remove('label', label);
  simulator.remove('thread', mail.threadId);
  assert.deepEqual(shape(await records(simulator, start)), [{labelsRemoved: [[mail.id, [label]]]}, {messagesDeleted: [mail.id]}]);
});

test('a change that changes nothing writes no record and moves no id', async () => {
  const simulator = sim(), mail = simulator.deliver(raw('M')), start = await current(simulator);
  await send(simulator, 'POST', '/messages/batchModify', {body: {ids: [mail.id], addLabelIds: ['INBOX'], removeLabelIds: ['STARRED']}});
  assert.equal(await current(simulator), start);
  assert.deepEqual(await records(simulator, start), []);
});

test('ids rise with gaps of more than one size, so nothing can count them, and every read of the current id agrees', async () => {
  const simulator = sim(), first = await current(simulator);
  for (let index = 0; index < 40; index++) simulator.deliver(raw(`M${index}`));
  const ids = (await records(simulator, first)).map(record => BigInt(record.id)), gaps = ids.slice(1).map((id, index) => id - ids[index]);
  assert.ok(gaps.every(gap => gap > 0n), 'each id is above the last');
  assert.ok(new Set(gaps).size > 5, 'the gaps vary');
  assert.equal(await current(simulator), String(ids.at(-1)));
  assert.equal((await history(simulator, first)).data.historyId, String(ids.at(-1)));
});

test('history ids past 2^53 stay exact: two a Number() would read as one stay apart, and a read after one returns only what followed it', async () => {
  const simulator = sim({historyId: FAR}), start = await current(simulator);
  assert.equal(start, FAR, 'a mailbox can start where a float cannot go');
  const a = simulator.deliver(raw('A')), first = await current(simulator);
  assert.ok(BigInt(first) > BigInt(FAR));
  const b = simulator.deliver(raw('B', OWNER)), ids = (await records(simulator, start)).map(record => record.id);
  assert.deepEqual(shape(await records(simulator, first)), [{messagesAdded: [b.id]}], 'an exact compare finds the second alone');
  assert.equal(ids.length, 2);
  assert.notEqual(ids[0], ids[1]);
  assert.equal(Number(FAR), Number(BigInt(FAR) - 1n), 'the test\'s own premise: a float cannot tell these two apart');
  const thread = (await send(simulator, 'GET', `/threads/${a.threadId}`, {query: {format: 'minimal'}})).data;
  assert.equal(thread.historyId, ids[0], 'a thread\'s id reads as a whole number too');
});

test('an answer with nothing new has no history key and holds the current id, and a switch leaves that id out too', async () => {
  const simulator = sim(), start = await current(simulator), empty = await history(simulator, start);
  assert.deepEqual([empty.status, empty.data], [200, {historyId: start}]);
  simulator.historyOptions({emptyHoldsId: false});
  assert.deepEqual((await history(simulator, start)).data, {}, 'probe U2 decides which of these Google sends');
});

test('a history message holds only id and threadId by default, and a switch adds its labels', async () => {
  const simulator = sim(), start = await current(simulator);
  simulator.deliver(raw('A'));
  assert.deepEqual(Object.keys((await records(simulator, start))[0].messagesAdded[0].message).sort(), ['id', 'threadId']);
  simulator.historyOptions({labels: true});
  assert.deepEqual((await records(simulator, start))[0].messagesAdded[0].message.labelIds, ['INBOX', 'UNREAD']);
});

test('startHistoryId is required, maxResults runs 1 to 500 and defaults to 100, and a page token is opaque and bound to its start', async () => {
  const simulator = sim(), start = await current(simulator);
  for (let index = 0; index < 120; index++) simulator.deliver(raw(`M${index}`));
  assert.deepEqual(reasonOf(await send(simulator, 'GET', '/history')), [400, 'invalidArgument']);
  for (const value of ['abc', '-1', '', '1'.repeat(21)]) assert.deepEqual(reasonOf(await history(simulator, value)), [400, 'invalidArgument'], value);
  for (const value of ['0', '501', 'x']) assert.deepEqual(reasonOf(await history(simulator, start, {maxResults: value})), [400, 'invalidArgument'], value);
  const page = await history(simulator, start);
  assert.equal(page.data.history.length, 100);
  assert.equal((await history(simulator, start, {maxResults: 500})).data.history.length, 120);
  const next = await history(simulator, start, {pageToken: page.data.nextPageToken});
  assert.equal(next.data.history.length, 20);
  assert.equal(Object.hasOwn(next.data, 'nextPageToken'), false);
  assert.equal(next.data.history[0].id > page.data.history[99].id, true);
  assert.deepEqual(reasonOf(await history(simulator, start, {pageToken: 'bm90IGEgdG9rZW4'})), [400, 'invalidArgument']);
  const other = page.data.history[5].id;
  assert.deepEqual(reasonOf(await history(simulator, other, {pageToken: page.data.nextPageToken})), [400, 'invalidArgument'], 'a token holds the list it came from');
  const messages = (await send(simulator, 'GET', '/messages', {query: {maxResults: 5}})).data.nextPageToken;
  assert.deepEqual(reasonOf(await history(simulator, start, {pageToken: messages})), [400, 'invalidArgument'], 'a list\'s token is no history token');
  assert.equal((await send(simulator, 'GET', '/messages', {query: {maxResults: 5, pageToken: messages}})).status, 200, 'and it still pages its own list');
});

test('labelId narrows to messages with that label, and historyTypes repeats, so a query that names them shows what a shared feed would lose', async () => {
  const simulator = sim(), start = await current(simulator), inbox = simulator.deliver(raw('In')), out = simulator.deliver(raw('Out'), ['SENT']);
  simulator.relabel(inbox.id, {add: ['STARRED']});
  assert.deepEqual(shape((await history(simulator, start, {labelId: 'SENT'})).data.history), [{messagesAdded: [out.id]}]);
  assert.deepEqual(shape((await history(simulator, start, {historyTypes: 'messageAdded'})).data.history), [{messagesAdded: [inbox.id]}, {messagesAdded: [out.id]}]);
  assert.deepEqual(shape((await history(simulator, start, {historyTypes: ['messageAdded', 'labelAdded']})).data.history), [{messagesAdded: [inbox.id]}, {messagesAdded: [out.id]}, {labelsAdded: [[inbox.id, ['STARRED']]]}]);
  assert.deepEqual(reasonOf(await history(simulator, start, {historyTypes: 'messageAdded,labelAdded'})), [400, 'invalidArgument'], 'a list in one value is refused');
});

test('an id Gmail no longer holds answers 404 in Google\'s shape, from expireHistory() below an id, from a shrunken window, and above the current id', async () => {
  const simulator = sim(), start = await current(simulator);
  simulator.deliver(raw('A'));
  const middle = await current(simulator);
  simulator.advance(DAY);
  simulator.deliver(raw('B'));
  assert.equal((await history(simulator, start)).status, 200);
  simulator.expireHistory(middle);
  assert.deepEqual(reasonOf(await history(simulator, start)), [404, 'notFound']);
  assert.equal((await history(simulator, middle)).status, 200, 'an id at the line still answers');
  const shrunken = sim(), first = await current(shrunken);
  shrunken.deliver(raw('A'));
  const after = await current(shrunken);
  shrunken.advance(5 * HOUR);
  shrunken.deliver(raw('B'));
  assert.equal((await history(shrunken, first)).status, 200, 'Google says at least a week, as a rule');
  shrunken.historyOptions({keepHours: 4});
  assert.deepEqual(reasonOf(await history(shrunken, first)), [404, 'notFound'], 'and in rare cases a few hours');
  assert.equal((await history(shrunken, after)).status, 200);
  assert.deepEqual(reasonOf(await history(shrunken, String(BigInt(await current(shrunken)) + 1n))), [404, 'notFound']);
  assert.deepEqual(reasonOf(await history(shrunken, '1')), [404, 'notFound'], 'an id from before the mailbox');
});

test('a delete leaves the record and reads of the message answer 404', async () => {
  const simulator = sim(), start = await current(simulator), mail = simulator.deliver(raw('A'));
  simulator.remove('message', mail.id);
  assert.deepEqual(reasonOf(await send(simulator, 'GET', `/messages/${mail.id}`)), [404, 'notFound']);
  assert.deepEqual(reasonOf(await send(simulator, 'GET', `/threads/${mail.threadId}`)), [404, 'notFound']);
  assert.equal((await records(simulator, start)).length, 2);
});

test('newer_than:<n>d reads the clock, in days only, and any other form stays refused', async () => {
  const simulator = sim(), old = simulator.deliver(raw('Old'));
  simulator.advance(6 * DAY);
  const fresh = simulator.deliver(raw('Fresh')), search = q => send(simulator, 'GET', '/messages', {query: {q}});
  assert.deepEqual((await search('newer_than:7d')).data.messages.map(item => item.id), [fresh.id, old.id]);
  simulator.advance(2 * DAY);
  assert.deepEqual((await search('subject:"Fresh" newer_than:7d')).data.messages.map(item => item.id), [fresh.id]);
  assert.deepEqual((await search('-newer_than:7d')).data.messages.map(item => item.id), [old.id], 'it negates as any term does');
  for (const q of ['newer_than:7', 'newer_than:7h', 'newer_than:d', 'older_than:7d']) assert.deepEqual(reasonOf(await search(q)), [400, 'notSimulated'], q);
});

test('a search can lag: a message shows in q only after a delay, keeps its place by date, and the plain list and a read see it at once', async () => {
  const simulator = sim(), old = simulator.deliver(raw('Same'));
  simulator.historyOptions({searchLagMs: HOUR});
  const late = simulator.deliver(raw('Same'));
  simulator.historyOptions({searchLagMs: 0});
  simulator.advance(1000);
  const later = simulator.deliver(raw('Same')), search = () => send(simulator, 'GET', '/messages', {query: {q: 'subject:"Same"'}});
  assert.deepEqual((await search()).data.messages.map(item => item.id), [later.id, old.id]);
  assert.equal((await send(simulator, 'GET', `/messages/${late.id}`)).status, 200);
  assert.equal((await send(simulator, 'GET', '/messages')).data.messages.length, 3);
  simulator.advance(HOUR);
  assert.deepEqual((await search()).data.messages.map(item => item.id), [later.id, late.id, old.id], 'it lands behind what is newer');
});

test('the 429 for too many concurrent requests has Google\'s words and no Retry-After, and changes nothing', async () => {
  const simulator = sim().limit('GET /history', 'tooManyConcurrent'), start = await current(simulator), answer = await send(simulator, 'GET', '/history', {query: {startHistoryId: start}, responseHeaders: ['retry-after']});
  assert.deepEqual(reasonOf(answer), [429, 'rateLimitExceeded']);
  assert.equal(answer.data.error.message, 'Too many concurrent requests for user');
  assert.equal(answer.data.error.errors[0].domain, 'usageLimits');
  assert.deepEqual(answer.headers, {}, 'Google names only "a retry time"');
  assert.equal((await history(simulator, start)).status, 200);
});

test('deliver() with labels writes messagesAdded, and by a switch labelsAdded as well, for mail a filter labels on arrival', async () => {
  const simulator = sim(), start = await current(simulator), plain = simulator.deliver(raw('A'), ['INBOX', 'Label_1']);
  assert.deepEqual(shape(await records(simulator, start)), [{messagesAdded: [plain.id]}]);
  const next = await current(simulator), filtered = simulator.deliver(raw('B'), ['INBOX', 'Label_1'], {labelsAdded: true});
  assert.deepEqual(shape(await records(simulator, next)), [{messagesAdded: [filtered.id]}, {labelsAdded: [[filtered.id, ['INBOX', 'Label_1']]]}]);
});

test('together() puts every change it makes in one record, as a bulk change may be', async () => {
  const simulator = sim(), a = simulator.deliver(raw('A')), b = simulator.deliver(raw('B')), start = await current(simulator);
  simulator.together(() => { simulator.relabel(a.id, {add: ['STARRED']}); simulator.relabel(b.id, {add: ['STARRED']}); });
  const list = await records(simulator, start);
  assert.equal(list.length, 1);
  assert.deepEqual(shape(list), [{labelsAdded: [[a.id, ['STARRED']], [b.id, ['STARRED']]]}]);
  simulator.relabel(a.id, {remove: ['STARRED']});
  assert.equal((await records(simulator, start)).length, 2, 'and it ends with its function');
});

test('ownerSends() is a send from Gmail: one message, SENT, and INBOX too when the owner is a recipient, recorded as no call', async () => {
  const simulator = sim(), start = await current(simulator), self = simulator.ownerSends(raw('Self', OWNER, OWNER)), out = simulator.ownerSends(raw('Out', 'bob@example.com', OWNER));
  assert.deepEqual((await send(simulator, 'GET', `/messages/${self.id}`, {query: {format: 'minimal'}})).data.labelIds, ['SENT', 'INBOX', 'UNREAD']);
  assert.deepEqual((await send(simulator, 'GET', `/messages/${out.id}`, {query: {format: 'minimal'}})).data.labelIds, ['SENT']);
  assert.equal(simulator.writes().length, 0);
  assert.deepEqual(shape(await records(simulator, start)), [{messagesAdded: [self.id]}, {messagesAdded: [out.id]}]);
});

test('a token with none of the read scopes is refused the history route', async () => {
  const simulator = sim({scopes: [SCOPE('gmail.send')]});
  assert.deepEqual(reasonOf(await history(simulator, '1000')), [403, 'insufficientPermissions']);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {TRANSFORMS, runTransform} from '../lib/transforms/index.mjs';
import {PINS} from '../lib/transform-pins.mjs';

// Iteration 9 step 7 (docs/I07-BUILD-MAP.md section 2.7): the two transforms Gmail's triggers read through, in their own file so the other app branches' edits never meet them. Their vectors sit in
// test/fixtures/transforms/collections.json and run there. A history page comes from the provider and a refusal here would stop a feed for good, so what neither can read is left out, and neither ever refuses.
const HISTORY = 'collections.gmailHistory@1', SENT = 'collections.gmailSentBefore@1', LIMIT = 500, FAR = '9007199254740993';
const added = (id, ...messages) => ({id, messages: messages.map(message => ({id: message, threadId: `t${message}`})), messagesAdded: messages.map(message => ({message: {id: message, threadId: `t${message}`}}))});
const labelled = (id, message, labelIds) => ({id, labelsAdded: [{message: {id: message, threadId: `t${message}`}, labelIds}]});
const item = (id, recordId) => ({id, threadId: `t${id}`, recordId});
const history = (list, args = {}) => runTransform(HISTORY, {list, kind: 'messagesAdded', ...args});
const labels = (list, labelId = 'Label_1') => runTransform(HISTORY, {list, kind: 'labelsAdded', labelId});
const thread = (...messages) => ({id: 't', messages: messages.map(([id, ...labelIds]) => ({id, labelIds}))});
const sentBefore = (value, messageId) => runTransform(SENT, {thread: value, messageId}).sentBefore;

test('step 7 registers both transforms: they read step data alone beside their closed arguments, use no clock, refuse nothing, and each has a pin', () => {
  const entry = TRANSFORMS.get(HISTORY), sent = TRANSFORMS.get(SENT);
  assert.deepEqual([entry.kind, entry.usesClock, [...entry.refuses], [...entry.runtimeFacts]], ['map', false, [], []]);
  assert.deepEqual([sent.kind, sent.usesClock, [...sent.refuses], [...sent.runtimeFacts]], ['map', false, [], []]);
  assert.deepEqual(Object.keys(entry.stepData), ['list']);
  assert.equal(entry.stepData.list.maxBytes, 2_097_152, 'a whole history answer, as the step allows');
  assert.deepEqual(Object.keys(sent.stepData), ['thread']);
  assert.equal(sent.stepData.thread.maxBytes, 262_144, 'a thread at format=minimal, as the step allows');
  assert.deepEqual([...entry.input.properties.kind.enum], ['messagesAdded', 'labelsAdded']);
  assert.equal(entry.output.properties.items.maxItems, LIMIT);
  for (const id of [HISTORY, SENT]) assert.match(PINS.transforms[id], /^[0-9a-f]{64}$/, id);
});

test('history: the messages added, in record order, each naming its record, and records of any other type give none', () => {
  const list = [added('11', 'a'), {id: '12', messagesDeleted: [{message: {id: 'z', threadId: 'tz'}}]}, labelled('13', 'q', ['Label_1']), added('14', 'b', 'c')];
  assert.deepEqual(history(list), {items: [item('a', '11'), item('b', '14'), item('c', '14')]});
  assert.deepEqual(history([]), {items: []}, 'a page with no record holds no history');
});

test('history: labelsAdded keeps only entries that added the watched label, and a record that added another gives nothing', () => {
  const list = [labelled('21', 'a', ['Label_1', 'STARRED']), labelled('22', 'b', ['STARRED']), {id: '23', labelsAdded: [{message: {id: 'c', threadId: 'tc'}, labelIds: ['Label_2']}, {message: {id: 'd', threadId: 'td'}, labelIds: ['Label_1']}]}];
  assert.deepEqual(labels(list), {items: [{...item('a', '21'), labelIds: ['Label_1', 'STARRED']}, {...item('d', '23'), labelIds: ['Label_1']}]});
  assert.deepEqual(history(list), {items: []}, 'messagesAdded reads no label record');
});

test('history: a message that carries its labels keeps them, and one that does not has no labelIds', () => {
  assert.deepEqual(history([{id: '1', messagesAdded: [{message: {id: 'a', threadId: 'ta', labelIds: ['INBOX']}}]}]).items, [{id: 'a', threadId: 'ta', labelIds: ['INBOX'], recordId: '1'}]);
  assert.equal(Object.hasOwn(history([added('1', 'a')]).items[0], 'labelIds'), false);
});

test(`history: exactly ${LIMIT} entries fit whole, with no place named`, () => {
  const list = Array.from({length: LIMIT}, (_, index) => added(String(index + 1), `m${index}`)), out = history(list);
  assert.equal(out.items.length, LIMIT);
  assert.equal(Object.hasOwn(out, 'throughRecordId'), false);
});

test(`history: a record that would pass ${LIMIT} is never split: the page stops at the record before it and names that record`, () => {
  const list = [...Array.from({length: LIMIT - 1}, (_, index) => added(String(index + 1), `m${index}`)), added('600', 'x', 'y'), added('601', 'z')], out = history(list);
  assert.equal(out.items.length, LIMIT - 1, 'neither half of the record');
  assert.equal(out.throughRecordId, String(LIMIT - 1));
  assert.equal(out.items.some(entry => entry.recordId === '600'), false);
});

test(`history: a first record of more than ${LIMIT} entries cannot be held whole, so nothing of it comes back and it is named, or a feed would stop on it for ever`, () => {
  const big = added('7', ...Array.from({length: LIMIT + 1}, (_, index) => `m${index}`));
  assert.deepEqual(history([big, added('8', 'after')]), {items: [], throughRecordId: '7'});
});

test('history: only entries that count move the limit, so a page of other labels never stops', () => {
  const list = Array.from({length: LIMIT + 10}, (_, index) => labelled(String(index + 1), `m${index}`, ['STARRED']));
  assert.deepEqual(labels([...list, labelled('9000', 'hit', ['Label_1'])]).items.map(entry => entry.recordId), ['9000']);
});

test('history: a provider\'s junk is left out and never refuses, since a refusal would stop the feed at that record for good', () => {
  const junk = [null, 7, 'text', [], {}, {id: 5, messagesAdded: [{message: {id: 'a', threadId: 'ta'}}]}, {id: 'abc', messagesAdded: [{message: {id: 'b', threadId: 'tb'}}]}, {id: '1'.repeat(21), messagesAdded: [{message: {id: 'c', threadId: 'tc'}}]},
    {id: '2', messagesAdded: 'none'}, {id: '3', messagesAdded: [null, {}, {message: null}, {message: {id: 'no-thread'}}, {message: {id: 7, threadId: 'x'}}, {message: {id: 'x'.repeat(65), threadId: 'x'}}, {message: {id: 'd', threadId: 'y'.repeat(65)}}]},
    {id: '4', messagesAdded: [{message: {id: 'e', threadId: 'te', labelIds: 'INBOX'}}, {message: {id: 'f', threadId: 'tf', labelIds: [1, 2]}}, {message: {id: 'g', threadId: 'tg', labelIds: Array.from({length: 51}, (_, index) => `L${index}`)}}]}];
  assert.deepEqual(history(junk), {items: [item('e', '4'), item('f', '4'), item('g', '4')]}, 'labels that cannot be held are left out, and the message stays');
  assert.deepEqual(labels([{id: '5', labelsAdded: [{message: {id: 'a', threadId: 'ta'}}, {message: {id: 'b', threadId: 'tb'}, labelIds: 'Label_1'}]}]), {items: []});
});

test('history: an id past 2^53 stays as written', () => {
  assert.deepEqual(history([added(FAR, 'a')]), {items: [item('a', FAR)]});
});

test('sentBefore: true only when a message listed before this one holds SENT', () => {
  assert.equal(sentBefore(thread(['a', 'SENT'], ['b', 'INBOX']), 'b'), true);
  assert.equal(sentBefore(thread(['a', 'INBOX'], ['b', 'INBOX']), 'b'), false, 'nobody here sent anything');
  assert.equal(sentBefore(thread(['a', 'INBOX'], ['b', 'SENT'], ['c', 'INBOX']), 'c'), true);
});

test('sentBefore: a message sent after this one does not count, so a reply that came first is not a reply to you', () => {
  assert.equal(sentBefore(thread(['a', 'INBOX'], ['b', 'SENT']), 'a'), false);
  assert.equal(sentBefore(thread(['a', 'SENT', 'INBOX']), 'a'), false, 'its own label is not one before it');
});

test('sentBefore: a thread that does not list the message, or holds junk, answers false and never refuses', () => {
  assert.equal(sentBefore(thread(['a', 'SENT']), 'gone'), false);
  for (const value of [{}, {messages: 'x'}, {messages: [null, 7]}, {messages: [{id: 'b', labelIds: 'SENT'}, {id: 'a'}]}]) assert.equal(sentBefore(value, 'a'), false);
});

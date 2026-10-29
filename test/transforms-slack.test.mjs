import test from 'node:test';
import assert from 'node:assert/strict';
import {CODES, TRANSFORMS, runTransform} from '../lib/transforms/index.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {FAMILY_CODES as FIRST_CODES} from '../lib/transforms/_shared/error.v1.mjs';
import {ROOT, computePins, readPins} from '../lib/transform-pins.mjs';
import {outcome, readVectors} from './fixtures/transform-vectors.mjs';

// F10.21 part 1 e (docs/F10.21-BUILD-MAP.md part 1 e; docs/F10.8-BUILD-MAP.md lines 433-440): the two transforms step 21 owes, in their own
// file so the other app branches' edits to the text and ids tests never meet them. text.slackQuery@1 builds Search messages' query with the
// words in one quoted phrase; ids.slackEmoji@1 takes an emoji name for React and Set my status and refuses a Unicode emoji. Their vectors
// sit in test/fixtures/transforms/text.json and ids.json, and run there.
const QUERY = 'text.slackQuery@1', EMOJI = 'ids.slackEmoji@1';
const run = (id, args) => runTransform(id, args);
const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${error}`);
  assert.equal(error.code, code);
  return true;
};

test('step 21 registers the two transforms, each refusing only with its own codes; emoji_invalid comes from error.v4.mjs, error.v1.mjs is untouched', () => {
  assert.deepEqual(TRANSFORMS.get(QUERY).refuses, ['query_value_invalid', 'query_too_long']);
  assert.deepEqual(TRANSFORMS.get(EMOJI).refuses, ['emoji_invalid']);
  assert.deepEqual([TRANSFORMS.get(QUERY).kind, TRANSFORMS.get(EMOJI).kind], ['map', 'map']);
  assert.deepEqual(TRANSFORMS.get(EMOJI).runtimeFacts, [], 'emoji names are ASCII');
  assert.ok(CODES.get('ids').includes('emoji_invalid'));
  assert.equal(FIRST_CODES.ids.includes('emoji_invalid'), false, 'a later error file adds lists only');
  for (const id of [QUERY, EMOJI]) assert.equal(TRANSFORMS.get(id).usesClock, false, id);
});

test('both are pinned, and adding them moved no existing pin', () => {
  const pins = readPins(ROOT), now = computePins(ROOT);
  for (const id of [QUERY, EMOJI]) assert.equal(pins.transforms[id], now.transforms[id], id);
  assert.equal(pins.harness, now.harness);
});

test('slackQuery: the words are one quoted phrase, so a modifier a person types stays inside it', () => {
  assert.deepEqual(run(QUERY, {words: 'quarterly plan'}), {query: '"quarterly plan"'});
  for (const words of ['in:#secret', 'from:@boss', 'after:2020-01-01', '-x', 'has:link', 'is:thread', '<#C0OTHERS01>', "it's", 'ü 日本 😀']) {
    assert.equal(run(QUERY, {words}).query, `"${words}"`, words);
  }
  assert.equal(run(QUERY, {words: 'a'.repeat(1000)}).query.length, 1002);
  assert.equal(run(QUERY, {words: '😀'.repeat(1000)}).query.length, 2002, 'the limit counts characters (code points)');
});

test('slackQuery: words that could leave their quotes, or run past 1,000 characters, refuse; nothing is cut', () => {
  for (const words of ['a"b', 'a" in:<#C0OTHERS01> "b', 'a\\b', 'a\nb', 'a\rb', 'a\tb', 'a\u0000b', 'a‮b', 'a​b']) {
    assert.throws(() => run(QUERY, {words}), refused('query_value_invalid'), JSON.stringify(words));
  }
  assert.throws(() => run(QUERY, {words: 'a'.repeat(1001)}), refused('query_too_long'));
  assert.throws(() => run(QUERY, {words: '😀'.repeat(1001)}), refused('query_too_long'));
  assert.throws(() => run(QUERY, {words: ''}), refused('input_invalid'), 'an empty search is no search');
  assert.throws(() => run(QUERY, {}), refused('input_invalid'), 'the words are required');
});

test('slackQuery: channel and from are taken only as Slack ids, written in Slack\'s own reference form; days are real dates', () => {
  assert.equal(run(QUERY, {words: 'a', channel: 'C0FABTEST1', from: 'U0ADA0001'}).query, '"a" in:<#C0FABTEST1> from:<@U0ADA0001>');
  assert.equal(run(QUERY, {words: 'a', from: 'W0GRID00001'}).query, '"a" from:<@W0GRID00001>', 'an Enterprise Grid user id');
  assert.equal(run(QUERY, {words: 'a', after: '2026-10-01', before: '2026-10-31'}).query, '"a" after:2026-10-01 before:2026-10-31');
  for (const channel of ['general', '#general', 'C0FAB', 'c0fabtest1', 'D0ADA0001', 'C0FABTEST1 from:<@U0ADA0001>', 'C0FABTEST1>', `C${'0'.repeat(21)}`]) {
    assert.throws(() => run(QUERY, {words: 'a', channel}), refused('query_value_invalid'), channel);
  }
  for (const from of ['ada', '@ada', 'U0ADA', 'u0ada0001', 'B0BOT0001', 'U0ADA0001 in:<#C0OTHERS01>']) assert.throws(() => run(QUERY, {words: 'a', from}), refused('query_value_invalid'), from);
  for (const day of ['2026-02-30', '2026-13-01', '26-10-01', '2026-10-1', '2026-10-01T00:00:00Z', 'yesterday']) {
    for (const field of ['after', 'before']) assert.throws(() => run(QUERY, {words: 'a', [field]: day}), refused('query_value_invalid'), `${field} ${day}`);
  }
});

test('slackEmoji: a name, or a name between colons, with an optional skin tone; code is the :name: form a status takes', () => {
  for (const [name, bare] of [['thumbsup', 'thumbsup'], [':thumbsup:', 'thumbsup'], ['+1', '+1'], ['-1', '-1'], ['white_check_mark::skin-tone-3', 'white_check_mark::skin-tone-3'],
    [':wave::skin-tone-6:', 'wave::skin-tone-6'], ["don't", "don't"], ['a', 'a'], ['a'.repeat(100), 'a'.repeat(100)], ['100', '100'], ['flag-ca', 'flag-ca']]) {
    assert.deepEqual(run(EMOJI, {name}), {name: bare, code: `:${bare}:`}, name);
  }
});

test('slackEmoji outputs are names only: no slash, dot or host in any vector (I4; the colon rule of the ids test reads :name: as a scheme)', () => {
  const outputs = readVectors('ids').cases.filter(item => item.transform === EMOJI && !Object.hasOwn(item, 'refuses')).map(item => outcome(item).output);
  assert.ok(outputs.length >= 4);
  for (const text of outputs.flatMap(output => Object.values(output))) assert.ok(!/[/.]|slack\.com/.test(text), text);
});

test('slackEmoji: a Unicode emoji, capitals, spaces, an empty name, 101 characters or a skin tone outside 2 to 6 refuse emoji_invalid', () => {
  for (const name of ['👍', ':👍:', '✅', 'Thumbs Up', 'Thumbsup', 'thumbs up', '', '::', ':', ':thumbsup', 'thumbsup:', 'a'.repeat(101), `:${'a'.repeat(101)}:`, 'thumbsup::skin-tone-1',
    'thumbsup::skin-tone-7', 'thumbsup:skin-tone-3', 'thumbsup::skin-tone-3::skin-tone-4', 'a.b', 'a/b', 'a<b', 'ünicode', 'a​b', '<!channel>']) {
    assert.throws(() => run(EMOJI, {name}), refused('emoji_invalid'), JSON.stringify(name));
  }
});

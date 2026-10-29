import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {canonicalHash} from '../lib/compiler.mjs';
import {TRANSFORMS, runTransform} from '../lib/transforms/index.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {vectorTests} from './fixtures/transform-vectors.mjs';

// F10.8 (docs/F10.8-BUILD-MAP.md part h): the six text transforms and the vectors of test/fixtures/transforms/text.json. Chunking for
// Notion, Slack escaping, Gmail and GitHub search quoting, a cut with a marker, and the one join that lets a card list reach a preview
// (open point Important 4).
const CHUNK = 'text.chunk@1', ESCAPE = 'text.slackEscape@1', GMAIL = 'text.gmailQuery@1', GITHUB = 'text.githubQuery@1', TRUNCATE = 'text.truncate@1', JOIN = 'text.joinList@1';
const IDS = [CHUNK, ESCAPE, GMAIL, GITHUB, TRUNCATE, JOIN];
const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${error}`);
  assert.equal(error.code, code);
  return true;
};
const run = (id, args) => runTransform(id, args);
const sorted = list => [...list].sort();
// Every character a quoted search value may not hold: the quote and the backslash that could close or escape it, each control (tab, line
// feed and carriage return included), and hidden or direction characters, which could make a query read differently from what it is.
const UNQUOTABLE = ['"', '\\', '\u0000', '\t', '\n', '\r', '\u001b', '\u007f', '\u0085', '​', '‎', '‮', '⁦', ' ', '﻿', '\u{e0041}', '\ud800', '\udc00'];

vectorTests('text');

test('part h registers six transforms; only the two search builders read Unicode tables, through the hidden-character rule', () => {
  for (const id of IDS) assert.ok(TRANSFORMS.has(id), id);
  const entry = id => TRANSFORMS.get(id);
  const refuses = {[CHUNK]: ['too_many_chunks'], [ESCAPE]: ['text_too_long'], [GMAIL]: ['query_value_invalid'],
    [GITHUB]: ['query_scope_missing', 'query_too_long', 'query_value_invalid', 'repo_invalid', 'too_many_operators'], [TRUNCATE]: [], [JOIN]: ['text_too_long']};
  for (const id of IDS) {
    assert.deepEqual(sorted(entry(id).refuses), refuses[id], id);
    assert.deepEqual(entry(id).runtimeFacts, [GMAIL, GITHUB].includes(id) ? ['unicode'] : [], id);
    assert.equal(entry(id).kind, 'map', id);
    assert.equal(entry(id).usesClock, false, id);
    assert.deepEqual(entry(id).stepData, {}, id);
    assert.deepEqual(entry(id).pointerArgs, [], id);
  }
});

test('chunking: at most 2,000 UTF-16 code units a chunk, never splitting a surrogate pair, and at most 100 chunks, never truncating', () => {
  for (let before = 1990; before <= 2010; before++) {
    for (const tail of ['😀', '😀😀', 'é😀', '😀b']) {
      const text = `${'a'.repeat(before)}${tail}${'c'.repeat(before)}`;
      const {chunks} = run(CHUNK, {text});
      assert.equal(chunks.join(''), text, 'the chunks join back to the text');
      for (const chunk of chunks) {
        assert.ok(chunk.length <= 2000 && chunk.length > 0);
        assert.ok(chunk.isWellFormed(), `no chunk holds half a surrogate pair (${before}, ${tail})`);
      }
      assert.ok(chunks.slice(0, -1).every(chunk => chunk.length >= 1999), 'only a pair at the boundary shortens a chunk');
    }
  }
  assert.deepEqual(run(CHUNK, {text: ''}), {chunks: []});
  assert.equal(run(CHUNK, {text: '😀'.repeat(100_000)}).chunks.length, 100, '100,000 emoji are 100 chunks of 1,000');
  assert.throws(() => run(CHUNK, {text: `${'😀'.repeat(100_000)}a`}), refused('too_many_chunks'));
  assert.throws(() => run(CHUNK, {text: 'a\ud800b'}), refused('input_invalid'), 'a lone surrogate has no Notion form');
  // Open point Important 3: a page title is built from these chunks through {each}, so the output keeps Notion's rich text limits.
  const output = TRANSFORMS.get(CHUNK).output.properties.chunks;
  assert.equal(output.maxItems, 100);
  assert.equal(output.items.maxLength, 2000);
});

test('slackEscape gives exactly the escaping of lib/cards.mjs line 165, on the same strings', () => {
  const source = readFileSync(new URL('../lib/cards.mjs', import.meta.url), 'utf8');
  const expression = "value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')";
  assert.ok(source.includes(`const esc = value => ${expression};`), 'toSlack() still escapes this way');
  const esc = value => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  for (const text of ['', '<!channel>', '<!here|here>', '<!everyone>', '<@U123>', '<#C1|general>', '<https://evil.example|click>', '&amp;&lt;&gt;', 'a > b < c & d', 'plain', 'ü & 😀 <x>']) {
    assert.deepEqual(run(ESCAPE, {text}), {text: esc(text)}, text);
  }
  assert.equal(run(ESCAPE, {text: 'a'.repeat(40_000)}).text.length, 40_000);
  assert.throws(() => run(ESCAPE, {text: 'a'.repeat(40_001)}), refused('text_too_long'));
  assert.throws(() => run(ESCAPE, {text: `${'a'.repeat(39_999)}😀`}), refused('text_too_long'), 'the limit counts UTF-16 code units, so Slack never cuts approved text');
  assert.throws(() => run(ESCAPE, {text: 'a\udc00'}), refused('input_invalid'));
});

test('Gmail: each plain field is one quoted operator, and a value that could leave its quotes refuses with query_value_invalid', () => {
  const {q} = run(GMAIL, {subject: 'x OR in:trash', from: 'ann@example.com'});
  assert.equal(q, 'from:"ann@example.com" subject:"x OR in:trash"');
  for (const field of ['from', 'to', 'subject', 'label', 'words']) {
    for (const char of UNQUOTABLE) assert.throws(() => run(GMAIL, {[field]: `a${char}b`}), refused('query_value_invalid'), `${field} with U+${char.codePointAt(0).toString(16)}`);
    assert.throws(() => run(GMAIL, {[field]: ''}), refused('input_invalid'), `an empty ${field} is no search`);
  }
  for (const value of ['ü', '日本', '😀', 'a b', "it's", '(a)', '-x', '{a b}']) assert.equal(run(GMAIL, {words: value}).q, `"${value}"`, value);
});

test('Gmail: after and before take time.rfc3339ToEpochSeconds@1\'s /seconds, written as epoch seconds; a time before 1970 refuses', () => {
  const seconds = time => run('time.rfc3339ToEpochSeconds@1', {time}).seconds;
  const after = seconds('2026-10-20T10:00:00-04:00'), before = seconds('2026-10-21T10:00:00-04:00');
  assert.deepEqual(run(GMAIL, {after, before}), {q: 'after:1792504800 before:1792591200'});
  assert.deepEqual(run(GMAIL, {after: 0}), {q: 'after:0'});
  for (const time of ['1969-12-31T23:59:59Z', '0000-01-01T00:00:00+23:59']) assert.throws(() => run(GMAIL, {after: seconds(time)}), refused('query_value_invalid'), time);
  assert.deepEqual(run(GMAIL, {before: seconds('9999-12-31T23:59:59-23:59')}), {q: 'before:253402387139'});
  const into = TRANSFORMS.get(GMAIL).input.properties, out = TRANSFORMS.get('time.rfc3339ToEpochSeconds@1').output.properties.seconds;
  for (const field of ['after', 'before']) assert.ok(into[field].type === 'integer' && into[field].minimum <= out.minimum && into[field].maximum >= out.maximum, field);
});

test('GitHub: always is:issue or is:pull-request; a repository or an @me scope is required; user text is quoted word by word', () => {
  for (const type of ['issue', 'pull-request']) assert.match(run(GITHUB, {type, scope: 'assignee'}).q, new RegExp(`^is:${type} assignee:@me$`));
  for (const scope of ['author', 'assignee', 'mentions', 'involves', 'review-requested']) assert.equal(run(GITHUB, {type: 'issue', scope}).q, `is:issue ${scope}:@me`);
  assert.throws(() => run(GITHUB, {type: 'issue'}), refused('query_scope_missing'));
  assert.throws(() => run(GITHUB, {type: 'issue', scope: 'owner'}), refused('input_invalid'), 'the scope list is closed');
  assert.throws(() => run(GITHUB, {scope: 'author'}), refused('input_invalid'), 'the type is required, so the query always names one');
  assert.equal(run(GITHUB, {type: 'issue', repo: {owner: 'octo', name: 'hello-world'}, scope: 'mentions', state: 'closed', text: 'crash on start'}).q,
    'is:issue repo:octo/hello-world mentions:@me is:closed "crash" "on" "start"');
  for (const text of ['is:open', 'type:pr', 'repo:other/private', 'org:x', 'user:x', 'in:title', 'label:bug', 'NOT', 'sort:created-asc', '-is:closed']) {
    assert.equal(run(GITHUB, {type: 'issue', scope: 'author', text}).q, `is:issue author:@me "${text}"`, text);
  }
  for (const char of UNQUOTABLE) assert.throws(() => run(GITHUB, {type: 'issue', scope: 'author', text: `foo${char} repo:x/y ${char}bar`}), refused('query_value_invalid'), `U+${char.codePointAt(0).toString(16)}`);
  assert.equal(run(GITHUB, {type: 'issue', scope: 'author', text: '😀'.repeat(256)}).q.length, 'is:issue author:@me '.length + 2 + 512, '256 characters are code points');
  assert.throws(() => run(GITHUB, {type: 'issue', scope: 'author', text: '😀'.repeat(257)}), refused('query_too_long'));
  assert.throws(() => run(GITHUB, {type: 'issue', scope: 'author', text: 'OR '.repeat(6)}), refused('too_many_operators'));
  assert.equal(run(GITHUB, {type: 'issue', scope: 'author', text: 'or and not or and not'}).q.split(' ').length, 8, 'lower-case words are no operators');
  for (const repo of [{owner: 'a'.repeat(40), name: 'b'}, {owner: 'a', name: '.'}, {owner: 'a b', name: 'c'}, {owner: 'a', name: 'b/c'}]) {
    assert.throws(() => run(GITHUB, {type: 'issue', repo}), refused('repo_invalid'), JSON.stringify(repo));
  }
});

test('truncate cuts at a code-point boundary and appends its fixed marker, within max code points', () => {
  const marker = '\n[truncated]';
  for (let length = 95; length <= 105; length++) {
    for (const char of ['a', '😀', 'é']) {
      const text = char.repeat(length), result = run(TRUNCATE, {text, max: 100});
      if (length <= 100) assert.deepEqual(result, {text}, `${length} ${char}`);
      else {
        assert.equal(result.truncated, true);
        assert.ok(result.text.endsWith(marker));
        assert.equal([...result.text].length, 100, 'the marker counts toward max');
        assert.equal(result.text, char.repeat(100 - [...marker].length) + marker);
      }
    }
  }
  assert.throws(() => run(TRUNCATE, {text: 'a', max: 99}), refused('input_invalid'), 'max leaves room for the marker and some text');
});

test('joinList: a card list reaches a preview as one string, one item a line, mailboxes by address (open point Important 4)', () => {
  assert.deepEqual(run(JOIN, {items: ['a', 'b', 'c']}), {text: 'a\nb\nc', count: 3});
  assert.deepEqual(run(JOIN, {mailboxes: [{address: 'a@example.com', name: 'Ann\nB'}]}), {text: 'a@example.com', count: 1}, 'a display name is never shown, so its line breaks do not matter');
  assert.throws(() => run(JOIN, {mailboxes: [{address: 'a@example.com\nb@example.com'}]}), refused('input_invalid'));
  assert.throws(() => run(JOIN, {items: ['']}), refused('input_invalid'), 'an empty item would read as no item');
  assert.equal(run(JOIN, {items: Array.from({length: 50}, () => 'a'.repeat(999))}).text.length, 49_999);
  assert.throws(() => run(JOIN, {items: Array.from({length: 50}, () => 'a'.repeat(1000))}), refused('text_too_long'));
  // Each list an action shows on its card fits an argument of joinList: the guests a merge adds and removes, the label names of an
  // organize (through {each} picking /name), and the recipients of a send, a reply or a draft (the builder's own To, Cc and Bcc schema).
  const entry = id => TRANSFORMS.get(id), join = entry(JOIN).input.properties;
  assert.equal(canonicalHash(join.mailboxes), canonicalHash(entry('rfc5322.build@1').input.properties.to), 'mailboxes takes exactly what the builder takes');
  for (const field of ['to', 'cc', 'bcc']) assert.equal(canonicalHash(entry('rfc5322.build@1').input.properties[field]), canonicalHash(join.mailboxes), field);
  for (const field of ['to', 'cc']) assert.equal(canonicalHash(entry('rfc5322.replyHeaders@1').output.properties[field]), canonicalHash(join.mailboxes), `replyHeaders /${field}`);
  // A list fits when every list its schema allows passes joinList's `items`: bounds on both sides, as the registry's fits() reads them.
  const fitsItems = (schema, what) => {
    assert.equal(schema.type, 'array', what);
    assert.ok(schema.maxItems <= join.items.maxItems, what);
    assert.ok((schema.minItems ?? 0) >= (join.items.minItems ?? 0), what);
    assert.equal(schema.items.type, 'string', what);
    assert.ok(schema.items.maxLength <= join.items.items.maxLength, what);
    assert.ok((schema.items.minLength ?? 0) >= join.items.items.minLength, `${what}: an item its schema allows, the empty string included, is one joinList takes`);
  };
  if (TRANSFORMS.has('collections.mergeEmails@1')) for (const field of ['added', 'removed']) fitsItems(entry('collections.mergeEmails@1').output.properties[field], `mergeEmails /${field}`);
  if (TRANSFORMS.has('collections.labelIds@1')) {
    const labels = entry('collections.labelIds@1').output.properties.labels;
    fitsItems({type: 'array', maxItems: labels.maxItems, items: labels.items.properties.name}, 'labelIds /labels/*/name');
    assert.ok(labels.maxItems <= 100, 'one {each} of at most 100 reaches every label name');
  }
});

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, F10.8 map part k): text.mentions@1 flags what GitHub notifies, for the card of every write
// that carries text GitHub parses for @mentions. It only flags and refuses nothing (F10.8 part k), so it adds no code.
const MENTIONS = 'text.mentions@1';

test('mentions: each @login and @org/team GitHub notifies, once each in any case, in order; an address, a path or a word before the @ is no mention', () => {
  const entry = TRANSFORMS.get(MENTIONS);
  assert.ok(entry, `${MENTIONS} is registered`);
  assert.deepEqual([entry.kind, entry.refuses, entry.runtimeFacts, entry.stepData], ['map', [], [], {}]);
  assert.deepEqual(run(MENTIONS, {text: '@octo-a please look, cc @org/team-x and @Octo-A again.'}), {mentions: ['@octo-a', '@org/team-x']});
  assert.deepEqual(run(MENTIONS, {text: 'mail a@b.com or x@y, see a/@b, ./@c, `@d`, _@e, -@f, 9@g'}), {mentions: []});
  assert.deepEqual(run(MENTIONS, {text: '(@paren) "@quoted" @a1-b2. @-no @x--y @end-'}).mentions, ['@paren', '@quoted', '@a1-b2', '@x', '@end']);
  assert.deepEqual(run(MENTIONS, {text: '```\n@coder\n```'}), {mentions: ['@coder']}, 'a mention in code is flagged too: more, never fewer');
  assert.deepEqual(run(MENTIONS, {text: `@${'a'.repeat(39)} @org/`}).mentions, [`@${'a'.repeat(39)}`, '@org']);
  assert.deepEqual(run(MENTIONS, {}), {mentions: []}, 'absent text gives none, so an optional body never refuses the card');
  assert.deepEqual(run(MENTIONS, {text: ''}), {mentions: []});
});

test('mentions: at most 50, with more past them; text over 65,536 code points is refused by the input schema', () => {
  const many = Array.from({length: 51}, (_, index) => `@user${index}`).join(' '), result = run(MENTIONS, {text: many});
  assert.deepEqual([result.mentions.length, result.mentions[0], result.mentions.at(-1), result.more], [50, '@user0', '@user49', true]);
  assert.equal(run(MENTIONS, {text: many.split(' ').slice(0, 50).join(' ')}).more, undefined, 'exactly 50 is not more');
  assert.equal(run(MENTIONS, {text: '😀'.repeat(65_536)}).mentions.length, 0, '65,536 code points');
  assert.throws(() => run(MENTIONS, {text: 'x'.repeat(65_537)}), refused('input_invalid'));
});

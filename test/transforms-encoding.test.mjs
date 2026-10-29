import test from 'node:test';
import assert from 'node:assert/strict';
import {TRANSFORMS, runTransform} from '../lib/transforms/index.mjs';
import {decodeBase64, encodeBase64} from '../lib/transforms/_shared/base64.v1.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {decodeUtf8, encodeUtf8} from '../lib/transforms/_shared/utf8.v1.mjs';
import {vectorTests} from './fixtures/transform-vectors.mjs';

// F10.8 (docs/F10.8-BUILD-MAP.md parts b and d): the strict base64 and UTF-8 helpers every encoding and MIME transform shares, the four
// encoding transforms, and the vectors of test/fixtures/transforms/encoding.json.
const bytesOf = text => new TextEncoder().encode(text);
const textOf = bytes => bytes === null ? null : Buffer.from(bytes).toString('utf8');
const RFC4648 = [['', ''], ['f', 'Zg=='], ['fo', 'Zm8='], ['foo', 'Zm9v'], ['foob', 'Zm9vYg=='], ['fooba', 'Zm9vYmE='], ['foobar', 'Zm9vYmFy']];

test('RFC 4648 section 10 vectors encode and decode in both alphabets, padded on the way out', () => {
  for (const [plain, encoded] of RFC4648) {
    for (const alphabet of ['base64', 'base64url']) {
      assert.equal(encodeBase64(bytesOf(plain), alphabet), encoded, `${alphabet} encodes ${plain}`);
      assert.equal(textOf(decodeBase64(encoded, alphabet)), plain, `${alphabet} decodes ${encoded}`);
      assert.equal(textOf(decodeBase64(encoded.replace(/=+$/, ''), alphabet)), plain, `${alphabet} decodes ${encoded} without its padding`);
    }
  }
  const high = Uint8Array.of(0xfb, 0xff, 0xbf);
  assert.equal(encodeBase64(high, 'base64'), '+/+/');
  assert.equal(encodeBase64(high, 'base64url'), '-_-_');
  assert.deepEqual([...decodeBase64('+/+/', 'base64')], [...high]);
  assert.deepEqual([...decodeBase64('-_-_', 'base64url')], [...high]);
});

test('the strict decoder refuses everything Buffer would quietly accept', () => {
  assert.equal(Buffer.from('aGVs*bG8', 'base64url').toString(), 'hello', 'Buffer drops the * (measured)');
  const refused = [['aGVs*bG8', 'base64url'], ['aGVs*bG8', 'base64'], ['+/+/', 'base64url'], ['-_-_', 'base64'], ['Zm9v YmFy', 'base64'], ['Zm9v\nYmFy', 'base64'],
    ['Zm9v\tYmFy', 'base64'], ['Zm9vYg=', 'base64'], ['Zm8==', 'base64'], ['Zh==', 'base64'], ['Zm9=', 'base64'], ['Zh', 'base64url'], ['Zm9vY', 'base64'], ['=', 'base64'],
    ['Zg==Zg==', 'base64'], ['Zg=a', 'base64'], ['Zm9v\nYmFy', 'base64url']];
  for (const [encoded, alphabet] of refused) assert.equal(decodeBase64(encoded, alphabet), null, `${alphabet} ${JSON.stringify(encoded)}`);
  assert.equal(textOf(decodeBase64('Zm9v\nYmFy\n', 'base64', 'lf')), 'foobar', 'lf mode takes GitHub\'s wrapped content');
  assert.equal(decodeBase64('Zm9v\r\nYmFy', 'base64', 'lf'), null);
  assert.equal(decodeBase64('Zm9v YmFy', 'base64', 'lf'), null);
  assert.equal(decodeBase64(7, 'base64'), null);
  assert.throws(() => decodeBase64('Zg==', 'base32'), /alphabet/);
  assert.throws(() => decodeBase64('Zg==', 'base64', 'crlf'), /line/);
  assert.throws(() => encodeBase64('text', 'base64'), /bytes/);
});

test('700 KiB of text encodes to 955,736 characters and fits a contents PUT body under 1,048,576 bytes', () => {
  const content = encodeBase64(new Uint8Array(700 * 1024).fill(0x61), 'base64');
  assert.equal(content.length, 955_736);
  const body = JSON.stringify({message: 'Update README.md', content, sha: 'a'.repeat(40), branch: 'fabric/test-run1'});
  assert.ok(Buffer.byteLength(body) < 1_048_576, 'lib/network.mjs line 40');
});

test('bytes become text only through the strict UTF-8 decoder, never with replacement characters', () => {
  for (const [what, bytes] of [['a broken sequence', [0xc3, 0x28]], ['an encoded surrogate', [0xed, 0xa0, 0x80]], ['an overlong form', [0xc0, 0xaf]], ['a truncated sequence', [0xe2, 0x82]]]) {
    assert.equal(decodeUtf8(Uint8Array.from(bytes)), null, what);
  }
  assert.equal(decodeUtf8(bytesOf('café \u{1F600}')), 'café \u{1F600}');
  assert.equal(decodeUtf8(Uint8Array.of(0xef, 0xbb, 0xbf, 0x61)), '﻿a', 'a byte-order mark is kept, so it can be refused as hidden');
  assert.deepEqual([...encodeUtf8('é')], [0xc3, 0xa9]);
  assert.equal(encodeUtf8('a\ud800'), null, 'a lone surrogate has no UTF-8 form');
});

const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${error}`);
  assert.equal(error.code, code);
  return true;
};
const DECODERS = [['encoding.base64Decode@1', 'base64', {lineBreaks: 'none'}], ['encoding.base64urlDecode@1', 'base64url', {}]];
const ENCODERS = [['encoding.base64Encode@1', 'base64'], ['encoding.base64urlEncode@1', 'base64url']];

test('part d registers four encoding transforms: text in and padded text out, or step data in and text or a byte count out', () => {
  const entry = id => TRANSFORMS.get(id);
  for (const [id] of ENCODERS) {
    assert.deepEqual(Object.keys(entry(id).input.properties), ['text']);
    assert.deepEqual(Object.keys(entry(id).output.properties), ['encoded']);
    assert.deepEqual(entry(id).stepData, {});
  }
  for (const [id] of DECODERS) {
    assert.deepEqual(entry(id).stepData, {encoded: {maxBytes: 1_400_000}}, 'the encoded text is step data: a closed string holds at most 1,000,000 code points');
    assert.equal(entry(id).maxInputBytes, 1_400_000);
    assert.deepEqual(Object.keys(entry(id).output.properties).sort(), ['binary', 'bytes', 'text']);
    assert.equal(entry(id).output.properties.text.maxLength, 1_000_000);
  }
  assert.deepEqual(entry('encoding.base64Decode@1').input.properties.lineBreaks.enum, ['none', 'lf']);
  assert.deepEqual(entry('encoding.base64urlDecode@1').input.properties, {}, 'base64url takes no line breaks');
  for (const [id] of [...ENCODERS, ...DECODERS]) assert.deepEqual(entry(id).runtimeFacts, [], `${id} reads no runtime fact`);
});

test('invalid UTF-8 after a valid base64 decode refuses with utf8_invalid, and bytes holding a NUL come back as {binary: true, bytes}', () => {
  const png = Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d);
  for (const [id, alphabet, closed] of DECODERS) {
    for (const bytes of [[0xc3, 0x28], [0xed, 0xa0, 0x80], [0xc0, 0xaf], [0xe2, 0x82], [0x80], [0xff, 0x61]]) {
      assert.throws(() => runTransform(id, {...closed, encoded: encodeBase64(Uint8Array.from(bytes), alphabet)}), refused('utf8_invalid'), `${id} ${bytes}`);
    }
    assert.deepEqual(runTransform(id, {...closed, encoded: encodeBase64(png, alphabet)}), {binary: true, bytes: 12}, `${id}: a PNG header is binary, never text`);
    assert.deepEqual(runTransform(id, {...closed, encoded: encodeBase64(Uint8Array.of(0x61, 0x00), alphabet)}), {binary: true, bytes: 2}, 'one NUL makes the bytes binary');
    assert.deepEqual(runTransform(id, {...closed, encoded: encodeBase64(bytesOf('\ufeffcafé'), alphabet)}), {text: '\ufeffcafé'}, 'a byte-order mark is kept, never dropped');
  }
});

test('the encoders take UTF-8 text of at most 750,000 bytes, so the output is at most 1,000,000 characters; a lone surrogate refuses with utf8_invalid', () => {
  for (const [id] of ENCODERS) {
    assert.equal(runTransform(id, {text: 'a'.repeat(750_000)}).encoded.length, 1_000_000);
    assert.equal(runTransform(id, {text: '\u20ac'.repeat(250_000)}).encoded.length, 1_000_000, 'the cap counts UTF-8 bytes, not code points');
    assert.throws(() => runTransform(id, {text: 'a'.repeat(750_001)}), refused('input_too_large'));
    assert.throws(() => runTransform(id, {text: `${'\u20ac'.repeat(250_000)}a`}), refused('input_too_large'));
    for (const text of ['a\ud800', '\udc00b', 'x\ud83d']) assert.throws(() => runTransform(id, {text}), refused('utf8_invalid'), JSON.stringify(text));
    assert.throws(() => runTransform(id, {text: 7}), refused('input_invalid'));
    assert.throws(() => runTransform(id, {text: 'a', extra: 1}), refused('input_invalid'));
  }
  assert.equal(runTransform('encoding.base64Encode@1', {text: '\u{1F600}'}).encoded, '8J+YgA==');
  assert.equal(runTransform('encoding.base64urlEncode@1', {text: '\u{1F600}'}).encoded, '8J-YgA==', 'base64url is padded too');
});

test('700 KiB of text through encoding.base64Encode@1 gives 955,736 characters and a contents PUT body under 1,048,576 bytes', () => {
  const {encoded} = runTransform('encoding.base64Encode@1', {text: 'a'.repeat(700 * 1024)});
  assert.equal(encoded.length, 955_736);
  assert.ok(Buffer.byteLength(JSON.stringify({message: 'Update README.md', content: encoded, sha: 'a'.repeat(40), branch: 'fabric/test-run1'})) < 1_048_576);
});

test('the decoders take step data of at most 1,400,000 bytes and give text of at most 1,000,000 code points', () => {
  for (const [id, alphabet, closed] of DECODERS) {
    assert.throws(() => runTransform(id, closed), refused('input_invalid'), 'the step data is required');
    for (const encoded of [7, null, ['Zg=='], {data: 'Zg=='}]) assert.throws(() => runTransform(id, {...closed, encoded}), refused('input_invalid'), JSON.stringify(encoded));
    const million = encodeBase64(new Uint8Array(1_000_000).fill(0x61), alphabet);
    assert.equal(runTransform(id, {...closed, encoded: million}).text.length, 1_000_000);
    assert.throws(() => runTransform(id, {...closed, encoded: encodeBase64(new Uint8Array(1_000_002).fill(0x61), alphabet)}), refused('output_too_large'));
    assert.throws(() => runTransform(id, {...closed, encoded: 'A'.repeat(1_400_000)}), refused('input_too_large'), 'the arguments as JSON are at most 1,400,000 bytes');
    assert.equal(runTransform(id, {...closed, encoded: encodeBase64(bytesOf('\u20ac'.repeat(333_333)), alphabet)}).text.length, 333_333, 'code points, not bytes');
  }
});

test('GitHub\'s contents of a 1,000,000-byte file, wrapped every 60 characters with a line feed, decode in lf mode and nowhere else', () => {
  const plain = new Uint8Array(1_000_000).fill(0x62);
  const content = `${encodeBase64(plain, 'base64').match(/.{1,60}/g).join('\n')}\n`;
  assert.ok(Buffer.byteLength(JSON.stringify({encoded: content, lineBreaks: 'lf'})) <= 1_400_000);
  assert.equal(runTransform('encoding.base64Decode@1', {encoded: content, lineBreaks: 'lf'}).text, 'b'.repeat(1_000_000));
  assert.throws(() => runTransform('encoding.base64Decode@1', {encoded: content, lineBreaks: 'none'}), refused('encoding_invalid'));
  assert.throws(() => runTransform('encoding.base64urlDecode@1', {encoded: content}), refused('encoding_invalid'));
  assert.throws(() => runTransform('encoding.base64urlDecode@1', {encoded: 'Zg==', lineBreaks: 'lf'}), refused('input_invalid'));
  assert.throws(() => runTransform('encoding.base64Decode@1', {encoded: 'Zg=='}), refused('input_invalid'), 'lineBreaks is required');
  assert.throws(() => runTransform('encoding.base64Decode@1', {encoded: 'Zg==', lineBreaks: 'crlf'}), refused('input_invalid'));
});

// The check of part d: the text cap counts code points, as the closed schema does, so a character outside the BMP counts once.
test('decoded text of exactly 1,000,000 code points passes when one of them is outside the BMP, and one more refuses', () => {
  for (const [id, alphabet, closed] of DECODERS) {
    const text = `${'a'.repeat(999_999)}\u{1F600}`;
    assert.equal(runTransform(id, {...closed, encoded: encodeBase64(bytesOf(text), alphabet)}).text, text, `${id}: 1,000,001 UTF-16 code units, 1,000,000 code points`);
    assert.throws(() => runTransform(id, {...closed, encoded: encodeBase64(bytesOf(`${text}a`), alphabet)}), refused('output_too_large'));
  }
});

vectorTests('encoding');

import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalHash} from '../lib/compiler.mjs';
import {TRANSFORMS, runTransform} from '../lib/transforms/index.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {vectorTests} from './fixtures/transform-vectors.mjs';

// F10.8 (docs/F10.8-BUILD-MAP.md part e): the six rfc5322 transforms and the vectors of test/fixtures/transforms/rfc5322.json: appendix A
// addressing, RFC 2047 words, header injection, the reply chain, quoted-printable read both ways and Gmail metadata and thread messages.
const NOW = 1_792_504_800_000;
const BUILD = 'rfc5322.build@1', RAW = 'rfc5322.decodeRaw@1', GMAIL = 'rfc5322.decodeGmailPayload@1', REPLY = 'rfc5322.replyHeaders@1';
const BASE = Object.freeze({from: {address: 'owner@example.com', name: 'Owner'}, to: [{address: 'ann@example.com', name: 'Ann'}], subject: 'Hello', text: 'Hi there', now: NOW});
const OWNER = Object.freeze({address: 'owner@example.com'});
const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${error}`);
  assert.equal(error.code, code);
  return true;
};
const b64url = text => Buffer.from(text, 'latin1').toString('base64url');
const utf8url = text => Buffer.from(text, 'utf8').toString('base64url');
/** The message a build gives, one character per byte. */
const messageOf = result => Buffer.from(result.raw, 'base64url').toString('latin1');
const headerSection = message => message.slice(0, message.indexOf('\r\n\r\n'));
const headerNames = message => headerSection(message).split('\r\n').filter(line => !/^[ \t]/.test(line)).map(line => line.slice(0, line.indexOf(':')));
const decodedRaw = result => runTransform(RAW, {raw: result.raw});
/** A Gmail Message holding one text/plain payload with these headers. */
const gmail = (headers, text = 'Hello.', extra = {}) => ({id: 'm1', threadId: 't1', labelIds: ['INBOX'], payload: {partId: '', mimeType: 'text/plain', filename: '',
  headers: [...headers.map(([name, value]) => ({name, value})), {name: 'Content-Type', value: 'text/plain; charset=UTF-8'}], body: {size: text.length, data: utf8url(text)}, ...extra}});
const PARENT = [['From', 'Boss <boss@example.com>'], ['To', 'Owner <owner@example.com>'], ['Subject', 'Plans'], ['Message-ID', '<p1@example.com>']];
const replace = (headers, name, value) => [...headers.filter(([key]) => key !== name), ...(value === undefined ? [] : [[name, value]])];
const reply = (headers, replyAll = false) => runTransform(REPLY, {parent: gmail(headers), owner: OWNER, replyAll});
/** A raw message whose multipart entities nest `depth` levels, with `parts` entities in all. */
function nestedMime(depth, parts) {
  const lines = ['From: a@example.com', 'Subject: deep', 'MIME-Version: 1.0'];
  for (let level = 1; level < depth; level++) lines.push(`Content-Type: multipart/mixed; boundary="b${level}"`, '', `--b${level}`);
  for (let index = 0; index < parts - (depth - 1); index++) lines.push('Content-Type: text/plain; charset=UTF-8', '', `part ${index}`, index === parts - depth ? `--b${depth - 1}--` : `--b${depth - 1}`);
  for (let level = depth - 2; level >= 1; level--) lines.push(`--b${level}--`);
  return lines.join('\r\n');
}
/** A Gmail payload whose multipart parts nest `depth` levels, with `leaves` text parts at the bottom. */
function nestedGmail(depth, leaves) {
  let node = {mimeType: 'multipart/mixed', headers: [], parts: Array.from({length: leaves}, (_, index) => ({mimeType: 'text/plain', headers: [], body: {size: 6, data: utf8url(`leaf ${index}`)}}))};
  for (let level = depth - 2; level >= 1; level--) node = {mimeType: 'multipart/mixed', headers: [], parts: [node]};
  return {id: 'n1', threadId: 'n1', payload: {...node, headers: [{name: 'From', value: 'a@example.com'}, {name: 'Subject', value: 'deep'}]}};
}

test('part e registers six transforms, and each declares the runtime facts its code and its helpers read (open point Minor 3)', () => {
  const facts = id => [...TRANSFORMS.get(id).runtimeFacts].sort();
  assert.deepEqual(facts(BUILD), ['unicode'], 'the hidden-character rule reads Unicode properties');
  for (const id of ['rfc5322.decodeHeader@1', RAW, GMAIL]) assert.deepEqual(facts(id), ['charset'], `${id} decodes named charsets`);
  assert.deepEqual(facts(REPLY), ['charset', 'unicode'], 'replyHeaders decodes names and drops the ones the builder would refuse');
  assert.deepEqual(facts('rfc5322.parseAddresses@1'), []);
  assert.equal(TRANSFORMS.get(BUILD).usesClock, true);
  assert.deepEqual(Object.keys(TRANSFORMS.get(REPLY).stepData), ['parent']);
  assert.deepEqual(Object.keys(TRANSFORMS.get(RAW).stepData), ['raw']);
  assert.deepEqual(Object.keys(TRANSFORMS.get(GMAIL).stepData), ['message']);
  for (const id of [RAW, GMAIL]) assert.deepEqual(TRANSFORMS.get(id).refuses, ['mime_invalid'], `${id} refuses only a value that is no message (open point Minor 9)`);
  // R1: each reply field reaches the build through one {pick}, so its schema is exactly the one the build takes.
  for (const field of ['to', 'cc', 'subject', 'inReplyTo', 'references']) {
    assert.equal(canonicalHash(TRANSFORMS.get(REPLY).output.properties[field]), canonicalHash(TRANSFORMS.get(BUILD).input.properties[field]), field);
  }
  assert.deepEqual(TRANSFORMS.get(REPLY).output.required, ['to', 'cc', 'subject', 'inReplyTo', 'references']);
});

test('the builder refuses a control, a hidden or direction character and a lone surrogate in every header field with header_injection', () => {
  const bad = ['\r', '\n', '\r\n', '\u0000', '\t', '\u007f', '\u0085', ' ', ' ', '‮', '​', '⁦', '﻿', '\ud800', '\udfff'];
  const places = [
    ['the subject', text => ({subject: `Hi${text}there`})],
    ['the From name', text => ({from: {address: 'owner@example.com', name: `Own${text}er`}})],
    ['the From address', text => ({from: {address: `owner${text}@example.com`}})],
    ['a To name', text => ({to: [{address: 'ann@example.com', name: `A${text}nn`}]})],
    ['a Cc address', text => ({cc: [{address: `c${text}@example.com`}]})],
    ['a Bcc name', text => ({bcc: [{address: 'b@example.com', name: `B${text}`}]})],
    ['In-Reply-To', text => ({inReplyTo: `<a${text}@example.com>`})],
    ['References', text => ({references: `<a@example.com>${text}<c@example.com>`})],
  ];
  for (const [where, put] of places) {
    for (const text of bad) assert.throws(() => runTransform(BUILD, {...BASE, ...put(text)}), refused('header_injection'), `${where}: U+${text.charCodeAt(0).toString(16)}`);
  }
  assert.throws(() => runTransform(BUILD, {...BASE, subject: 'Hi\r\nBcc: x@evil'}), refused('header_injection'), 'step 15\'s vector, before any output');
  assert.throws(() => runTransform(BUILD, {...BASE, text: 'body \ud800'}), refused('input_invalid'), 'a body with a lone surrogate has no UTF-8 form');
  assert.ok(runTransform(BUILD, {...BASE, text: 'a body may hold \t tabs, \r\n line breaks and ‮'}).raw, 'only header text is held to the injection rule');
});

test('the builder takes no replyTo, never writes Reply-To or Message-ID, and writes Date in RFC 5322 section 3.3 form in UTC (R19)', () => {
  const build = TRANSFORMS.get(BUILD);
  assert.ok(!Object.hasOwn(build.input.properties, 'replyTo'));
  assert.throws(() => runTransform(BUILD, {...BASE, replyTo: [{address: 'x@evil.example'}]}), refused('input_invalid'));
  const full = {...BASE, cc: [{address: 'cc@example.com'}], bcc: [{address: 'bcc@example.com', name: 'Hidden'}], inReplyTo: '<1234@local.machine.example>',
    references: '<0@local.machine.example> <1234@local.machine.example>'};
  const message = messageOf(runTransform(BUILD, full));
  assert.deepEqual(headerNames(message), ['From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'In-Reply-To', 'References', 'MIME-Version', 'Content-Type', 'Content-Transfer-Encoding']);
  assert.match(message, /\r\nDate: Tue, 20 Oct 2026 14:00:00 \+0000\r\n/);
  assert.match(message, /\r\nMIME-Version: 1\.0\r\nContent-Type: text\/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n/);
  assert.equal(message.slice(message.indexOf('\r\n\r\n') + 4), `${Buffer.from('Hi there').toString('base64')}\r\n`);
  assert.ok(!/^(?:reply-to|message-id|sender):/im.test(headerSection(message)));
  assert.equal(headerNames(messageOf(runTransform(BUILD, BASE))).join(), 'From,To,Subject,Date,MIME-Version,Content-Type,Content-Transfer-Encoding', 'empty fields are not written');
  // The same inputs give the same bytes; another now moves only the Date line.
  assert.equal(runTransform(BUILD, full).raw, runTransform(BUILD, full).raw);
  const later = messageOf(runTransform(BUILD, {...full, now: NOW + 86_400_000 * 13 + 3_723_000}));
  assert.match(later, /\r\nDate: Mon, 02 Nov 2026 15:02:03 \+0000\r\n/);
  assert.equal(later.replace(/Date: [^\r]*/, ''), message.replace(/Date: [^\r]*/, ''));
  // Gmail's sending guide: the headers, a blank line and the body, base64url into raw. Body lines are at most 76 characters.
  const long = messageOf(runTransform(BUILD, {...BASE, text: 'x'.repeat(1000)}));
  const body = long.slice(long.indexOf('\r\n\r\n') + 4).split('\r\n');
  assert.equal(body.at(-1), '');
  assert.ok(body.slice(0, -2).every(line => line.length === 76) && body.at(-2).length <= 76);
  assert.equal(Buffer.from(body.join(''), 'base64').toString(), 'x'.repeat(1000));
});

test('a subject and display names with accents, CJK and an emoji survive build then decode exactly; every encoded-word is at most 75 characters and holds whole code points', () => {
  const subjects = ['Café ☕ 会议 😀', 'Ünïcödé '.repeat(40), '😀'.repeat(60), 'a plain ASCII subject that is long enough to fold more than once because it keeps going and going on and on',
    ' leading and trailing ', 'two  spaces', '=?UTF-8?B?w6k=?= looks encoded', '', 'a'.repeat(200), 'Re: 会议', 'x'.repeat(10_000)];
  const names = ['Zoë Ünïcode', 'Joe Q. Public', 'Giant; "Big" Box', 'back\\slash', '=?x?y?z?=', '张伟', 'Mary Smith: Personal Account', 'a'.repeat(100), 'b '.repeat(60).trim()];
  for (const subject of subjects) {
    const to = names.map((name, index) => ({address: `r${index}@example.com`, name}));
    const result = runTransform(BUILD, {...BASE, subject, to});
    const message = messageOf(result), head = headerSection(message);
    assert.ok(/^[\x00-\x7f]*$/.test(message), 'every byte of the message is ASCII: non-ASCII header text is RFC 2047');
    // Every address here is short, so every line folds within 78 characters; a longer address may take a line of its own, never over 998.
    for (const line of head.split('\r\n')) assert.ok(line.length <= 78, `folded at 78: ${line}`);
    for (const [word, base64] of head.matchAll(/=\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=/g)) {
      assert.ok(word.length <= 75, `${word} is over 75 characters`);
      assert.doesNotThrow(() => new TextDecoder('utf-8', {fatal: true}).decode(Buffer.from(base64, 'base64')), `${word} splits a code point`);
    }
    const decoded = decodedRaw(result);
    assert.equal(decoded.summary.subject, subject, JSON.stringify(subject.slice(0, 40)));
    assert.deepEqual(decoded.summary.to, to);
    assert.equal(decoded.text, 'Hi there');
  }
  const raw = messageOf(runTransform(BUILD, {...BASE, subject: 'Café', to: [{address: 'a@example.com', name: 'Joe Q. Public'}, {address: 'b@example.com', name: 'Giant; "Big" Box'}]}));
  assert.match(raw, /\r\nTo: "Joe Q\. Public" <a@example\.com>, "Giant; \\"Big\\" Box" <b@example\.com>\r\n/, 'ASCII names with specials are quoted');
  assert.match(raw, /\r\nSubject: =\?UTF-8\?B\?Q2Fmw6k=\?=\r\n/);
  assert.match(raw, /^From: Owner <owner@example\.com>\r\n/, 'a name of atoms is written as it is');
});

test('the builder writes only ASCII dot-atom addresses of at most 254 characters, never groups or obsolete forms, and checks message ids', () => {
  for (const address of ['not-an-address', 'é@example.com', '"john smith"@example.com', 'a@b@example.com', '.a@example.com', 'a..b@example.com', 'a@example..com', 'a@[127.0.0.1]',
    `${'a'.repeat(64)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`, 'a@', '@example.com', 'a b@example.com']) {
    assert.throws(() => runTransform(BUILD, {...BASE, cc: [{address}]}), error => error instanceof TransformError && ['address_invalid', 'header_injection'].includes(error.code), address);
  }
  assert.equal(runTransform(BUILD, {...BASE, cc: [{address: `${'a'.repeat(64)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`}]}).recipientCount, 2, 'exactly 254 characters pass');
  assert.equal(runTransform(BUILD, {...BASE, cc: [{address: "o'brien+tag@sub.example.co"}]}).recipientCount, 2);
  for (const id of ['1234@local.machine.example', '<1234>', '<a@b', '<a@b> extra', '<a@@b>', '<.a@b>', '< a@b>']) {
    assert.throws(() => runTransform(BUILD, {...BASE, inReplyTo: id}), refused('message_id_invalid'), id);
  }
  assert.throws(() => runTransform(BUILD, {...BASE, inReplyTo: `<${'a'.repeat(897)}@b>`}), refused('input_invalid'), 'the schema holds a message id to 900 characters');
  for (const references of ['<a@b>  <c@d>', '<a@b> c@d', ' <a@b>', Array.from({length: 101}, (_, index) => `<${index}@example.com>`).join(' ')]) {
    assert.throws(() => runTransform(BUILD, {...BASE, references}), refused('message_id_invalid'), references.slice(0, 40));
  }
  assert.ok(runTransform(BUILD, {...BASE, inReplyTo: '<CAJ+x=y_z@mail.gmail.com>', references: '<a@[10.0.0.1]> <CAJ+x=y_z@mail.gmail.com>'}).raw);
  assert.ok(runTransform(BUILD, {...BASE, inReplyTo: `<${'a'.repeat(896)}@b>`}).raw, 'a message id of 900 characters passes');
  const longest = messageOf(runTransform(BUILD, {...BASE, to: [{address: `${'a'.repeat(64)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`, name: 'Ann'}]}));
  assert.ok(headerSection(longest).split('\r\n').every(line => line.length <= 998), 'an address that cannot fold takes a line of its own, never over 998');
  const message = messageOf(runTransform(BUILD, {...BASE, to: [{address: 'a@example.com', name: 'A Group:'}, {address: 'b@example.com', name: 'x;y'}]}));
  const toValue = headerSection(message).split('\r\nSubject:')[0].split('\r\nTo:')[1];
  const parsed = runTransform('rfc5322.parseAddresses@1', {value: toValue});
  assert.deepEqual(parsed.addresses, [{name: 'A Group:', address: 'a@example.com'}, {name: 'x;y', address: 'b@example.com'}], 'no group: the names are quoted');
});

test('a 750,000-byte message builds to 1,000,000 characters and fits each Gmail send and draft body under 1,048,576 bytes; one byte more refuses with message_too_large', () => {
  const text = 'a'.repeat(500_000);
  const to = lengths => lengths.map((length, index) => ({address: `${`r${index}`.padEnd(length, 'x')}@example.com`}));
  const lengths = Array.from({length: 400}, () => 140);
  const first = runTransform(BUILD, {...BASE, subject: 'Size', text, to: to(lengths)});
  let missing = 750_000 - first.bytes;
  assert.ok(missing > 0 && missing < 400 * 100, `the fixture leaves ${missing} bytes to fill`);
  // Each address sits alone on its folded line, so one more character in it is one more byte of message.
  for (let index = 0; missing > 0; index++) { const add = Math.min(missing, 100); lengths.splice(index, 1, 140 + add); missing -= add; }
  const exact = runTransform(BUILD, {...BASE, subject: 'Size', text, to: to(lengths)});
  assert.equal(exact.bytes, 750_000);
  assert.equal(exact.raw.length, 1_000_000);
  assert.equal(Buffer.from(exact.raw, 'base64url').length, 750_000);
  const raw = exact.raw;
  for (const body of [{raw}, {raw, threadId: '18c2f0e1a2b3c4d5'}, {message: {raw}}, {id: 'r-1234567890123456789', message: {raw}}, {id: 'r-1234567890123456789', message: {raw, threadId: '18c2f0e1a2b3c4d5'}}]) {
    assert.ok(Buffer.byteLength(JSON.stringify(body)) <= 1_048_576, `lib/network.mjs line 40: ${Object.keys(body)}`);
  }
  lengths.splice(399, 1, lengths.at(399) + 1);
  assert.throws(() => runTransform(BUILD, {...BASE, subject: 'Size', text, to: to(lengths)}), refused('message_too_large'));
  assert.throws(() => runTransform(BUILD, {...BASE, text: 'a'.repeat(500_001)}), refused('message_too_large'), 'the text is at most 500,000 bytes');
  assert.throws(() => runTransform(BUILD, {...BASE, text: '€'.repeat(166_667)}), refused('message_too_large'), 'bytes, not code points');
});

test('more than 500 recipients in To, Cc and Bcc together refuse with too_many_recipients', () => {
  const list = (count, prefix) => Array.from({length: count}, (_, index) => ({address: `${prefix}${index}@example.com`}));
  assert.equal(runTransform(BUILD, {...BASE, to: list(200, 't'), cc: list(200, 'c'), bcc: list(100, 'b')}).recipientCount, 500);
  assert.throws(() => runTransform(BUILD, {...BASE, to: list(200, 't'), cc: list(200, 'c'), bcc: list(101, 'b')}), refused('too_many_recipients'));
  assert.equal(runTransform(BUILD, {...BASE, to: []}).recipientCount, 0, 'a draft may have no recipient yet');
});

test('depth 8 decodes; a part at depth 9 is listed as mime_too_deep and never walked; a 101st part is listed as mime_too_many_parts and the walk stops there', () => {
  const eight = runTransform(RAW, {raw: b64url(nestedMime(8, 100))});
  assert.equal(eight.parts.length, 100);
  assert.ok(eight.parts.every(part => part.reason === undefined));
  assert.equal(eight.parts.at(-1).partId, '0.0.0.0.0.0.92');
  assert.equal(eight.text, 'part 0');
  const nine = runTransform(RAW, {raw: b64url(nestedMime(9, 20))});
  const deep = nine.parts.filter(part => part.reason === 'mime_too_deep');
  assert.equal(deep.length, 12);
  assert.ok(deep.every(part => part.decoded === false && part.partId.split('.').length === 8 && part.mimeType === 'text/plain'));
  assert.equal(nine.text, undefined, 'nothing below depth 8 is read');
  const many = runTransform(RAW, {raw: b64url(nestedMime(2, 102))});
  assert.equal(many.parts.length, 101);
  assert.deepEqual(many.parts.at(-1), {partId: '99', mimeType: 'text/plain', decoded: false, reason: 'mime_too_many_parts'});
  assert.ok(many.parts.slice(0, -1).every(part => part.reason === undefined));
  // The same limits hold for a Gmail Message.
  assert.equal(runTransform(GMAIL, {message: nestedGmail(8, 93)}).parts.length, 100);
  const gmailNine = runTransform(GMAIL, {message: nestedGmail(9, 3)});
  assert.deepEqual(gmailNine.parts.filter(part => part.reason).map(part => [part.partId, part.reason]), [['0.0.0.0.0.0.0.0', 'mime_too_deep'], ['0.0.0.0.0.0.0.1', 'mime_too_deep'], ['0.0.0.0.0.0.0.2', 'mime_too_deep']]);
  const gmailMany = runTransform(GMAIL, {message: nestedGmail(2, 150)});
  assert.equal(gmailMany.parts.length, 101);
  assert.equal(gmailMany.parts.at(-1).reason, 'mime_too_many_parts');
});

test('utf-7 is never decoded: a part in utf-7 has no text, and an encoded-word in utf-7 stays literal', () => {
  for (const label of ['utf-7', 'UTF-7', 'utf7', 'unicode-1-1-utf-7', 'csUnicode11UTF7', 'x-unicode-2-0-utf-7']) {
    const message = gmail([['From', 'a@example.com']], 'Hi +AGE-');
    message.payload.headers[1].value = `text/plain; charset=${label}`;
    const result = runTransform(GMAIL, {message});
    assert.deepEqual(result.parts, [{partId: '', mimeType: 'text/plain', charset: label, decoded: false, reason: 'unknown_charset'}], label);
    assert.equal(result.text, undefined);
    const word = `=?${label}?Q?Hi_+AGE-?=`;
    assert.deepEqual(runTransform('rfc5322.decodeHeader@1', {value: word}), {text: word}, label);
  }
});

test('a malformed header value never refuses a decode: it is left out of the summary and named in summary.invalid (open point Minor 9)', () => {
  const thread = [
    gmail([['From', 'Ann <ann@example.com>'], ['Subject', 'Plans'], ['Message-ID', '<p1@example.com>']], 'Dinner at 7?'),
    gmail([['From', 'Ann <<ann@example.com'], ['To', `${'('.repeat(33)}${')'.repeat(33)} b@example.com`], ['Subject', 'Re: Plans'], ['Message-ID', 'nope']], 'See you then.'),
    gmail([['From', 'Bob <bob@example.com>'], ['Subject', 'one'], ['Subject', 'two'], ['Reply-To', 'x@'], ['Cc', 'Undisclosed recipients:;']], 'Two subjects.'),
    gmail([['From', ''], ['Date', 'Fri, 21 Nov 1997 09:55:06 -0600']], 'No sender.'),
  ];
  const results = thread.map(message => runTransform(GMAIL, {message}));
  assert.deepEqual(results.map(result => result.text), ['Dinner at 7?', 'See you then.', 'Two subjects.', 'No sender.']);
  assert.equal(results.at(0).summary.invalid, undefined);
  assert.deepEqual(results.at(1).summary, {subject: 'Re: Plans', invalid: ['from', 'to', 'messageId']});
  assert.deepEqual(results.at(2).summary, {from: [{name: 'Bob', address: 'bob@example.com'}], cc: [], invalid: ['replyTo', 'subject']});
  assert.deepEqual(results.at(3).summary, {date: 'Fri, 21 Nov 1997 09:55:06 -0600', invalid: ['from']}, 'a From with no mailbox is no sender');
  assert.ok(results.at(2).headers.some(header => header.name === 'Subject' && header.value === 'two'), 'every header is still listed');
  // A raw message: header bytes that are not UTF-8 are never replaced; the field is left out, and named when the summary reads it.
  const raw = runTransform(RAW, {raw: b64url('From: Ann <ann@example.com>\r\nSubject: caf\xe9\r\nX-Note: na\xefve\r\nX-Fine: yes\r\n\r\nBody\r\n')});
  assert.deepEqual(raw.summary, {from: [{name: 'Ann', address: 'ann@example.com'}], invalid: ['subject']});
  assert.deepEqual(raw.headers.map(header => header.name), ['From', 'X-Fine']);
  assert.ok(!JSON.stringify(raw).includes('�'), 'no replacement character anywhere');
  assert.equal(raw.text, 'Body\r\n');
  // A part's own bytes: bad base64, an unknown transfer encoding or bytes its charset does not allow mark that part, and the rest decodes.
  const parts = runTransform(RAW, {raw: b64url(['From: a@example.com', 'Content-Type: multipart/mixed; boundary=m', '', '--m', 'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: x-uuencode', '', 'begin 644', '--m', 'Content-Type: text/html; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', 'PHA+*not base64', '--m',
    'Content-Type: text/plain; charset=UTF-8', '', 'second', '--m--', ''].join('\r\n'))});
  assert.deepEqual(parts.parts.map(part => [part.partId, part.decoded, part.reason]), [['', true, undefined], ['0', false, 'unknown_transfer_encoding'], ['1', false, 'malformed'], ['2', false, undefined]]);
  assert.equal(parts.text, undefined, 'text is the first text/plain part; a later one is never put in its place');
  const bad = gmail([['From', 'a@example.com']]);
  bad.payload.body.data = 'not base64url!';
  assert.deepEqual(runTransform(GMAIL, {message: bad}).parts, [{partId: '', mimeType: 'text/plain', charset: 'UTF-8', decoded: false, reason: 'malformed'}]);
  const latin = gmail([['From', 'a@example.com']]);
  latin.payload.body.data = Buffer.from([0x63, 0x61, 0x66, 0xe9]).toString('base64url');
  assert.equal(runTransform(GMAIL, {message: latin}).parts.at(0).reason, 'malformed', 'bytes UTF-8 does not allow are never guessed into text');
});

test('a value that is not a message at all refuses with mime_invalid', () => {
  for (const raw of ['not*base64url', 'Zg=a', 7, null, {raw: 'Zg'}]) assert.throws(() => runTransform(RAW, {raw}), refused('mime_invalid'), JSON.stringify(raw));
  for (const message of [{}, {payload: 'x'}, {payload: []}, 'x', [], {id: 'm', raw: 'Zg'}]) assert.throws(() => runTransform(GMAIL, {message}), refused('mime_invalid'), JSON.stringify(message));
  for (const parent of [{}, {payload: null}]) assert.throws(() => runTransform(REPLY, {parent, owner: OWNER, replyAll: false}), refused('mime_invalid'));
  assert.throws(() => runTransform(RAW, {}), refused('input_invalid'), 'the step data is required');
});

test('text and html are cut at 500,000 code points on a code-point boundary with truncated: true; headers list the first 500 and the summary reads them all', () => {
  const long = gmail([['From', 'a@example.com']], `${'a'.repeat(499_999)}\u{1F600}b`);
  const result = runTransform(GMAIL, {message: long});
  assert.equal(result.truncated, true);
  assert.equal(result.text, `${'a'.repeat(499_999)}\u{1F600}`);
  assert.equal(runTransform(GMAIL, {message: gmail([['From', 'a@example.com']], `${'a'.repeat(499_999)}\u{1F600}`)}).truncated, undefined);
  const headers = [...Array.from({length: 550}, (_, index) => [`X-${index}`, 'v']), ['Subject', 'Late']];
  const many = runTransform(GMAIL, {message: gmail(headers)});
  assert.equal(many.headers.length, 500);
  assert.equal(many.headersTruncated, true);
  assert.equal(many.summary.subject, 'Late');
});

test('decodeRaw applies each part\'s transfer encoding once, then its charset; decodeGmailPayload applies the charset only', () => {
  const raw = ['From: a@example.com', 'Subject: =?ISO-8859-1?Q?caf=E9?=', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="==x=="', '', 'preamble', '--==x==',
    'Content-Type: text/plain; charset=iso-8859-1', 'Content-Transfer-Encoding: 8bit', '', 'caf\xe9 \x80', '--==x==  ',
    'Content-Type: application/octet-stream', 'Content-Disposition: attachment; filename*=UTF-8\'\'%E2%82%AC%20rate.pdf', 'Content-Transfer-Encoding: base64', '',
    'JVBERi0x', 'LjQK', '--==x==', 'Content-Type: image/png; name="=?UTF-8?B?w6l0w6kucG5n?="', 'Content-Transfer-Encoding: base64', '', 'iVBORw==', '--==x==--', 'epilogue'].join('\r\n');
  const result = runTransform(RAW, {raw: b64url(raw)});
  assert.equal(result.summary.subject, 'café');
  assert.equal(result.text, 'café €');
  assert.deepEqual(result.attachments, [{partId: '1', filename: '€ rate.pdf', mimeType: 'application/octet-stream', size: 9}, {partId: '2', filename: 'été.png', mimeType: 'image/png', size: 4}]);
  assert.deepEqual(result.parts.map(part => [part.partId, part.mimeType, part.decoded]), [['', 'multipart/mixed', true], ['0', 'text/plain', true], ['1', 'application/octet-stream', false], ['2', 'image/png', false]]);
  // Gmail's body.data is the part's decoded bytes: a quoted-printable or base64 Content-Transfer-Encoding header is never applied again.
  for (const [encoding, text] of [['quoted-printable', 'a =3D b=\r\nc'], ['base64', 'aGVsbG8=']]) {
    const message = gmail([['From', 'a@example.com'], ['Content-Transfer-Encoding', encoding]], text);
    assert.equal(runTransform(GMAIL, {message}).text, text, encoding);
  }
  // A part with no charset reads as us-ascii (RFC 2045 section 5.2), which the WHATWG labels map to windows-1252.
  assert.equal(runTransform(RAW, {raw: b64url('From: a@example.com\r\n\r\n\x80 caf\xe9')}).text, '€ café');
});

test('reply-all removes the owner in any ASCII case, its output builds a message with no change of shape, and 501 recipients refuse', () => {
  const headers = [['From', 'Boss <boss@example.com>'], ['To', 'OWNER@Example.COM, Ann <ann@example.com>, ann@EXAMPLE.com'], ['Cc', 'Carol <carol@example.com>, Owner <owner@example.com>'],
    ['Subject', 'Plans'], ['Message-ID', '<p1@example.com>']];
  const all = reply(headers, true);
  assert.deepEqual(all, {to: [{name: 'Boss', address: 'boss@example.com'}, {name: 'Ann', address: 'ann@example.com'}], cc: [{name: 'Carol', address: 'carol@example.com'}],
    subject: 'Re: Plans', inReplyTo: '<p1@example.com>', references: '<p1@example.com>'});
  assert.deepEqual(reply(headers).to, [{name: 'Boss', address: 'boss@example.com'}]);
  assert.deepEqual(reply(headers).cc, []);
  // Each field reaches the build through one {pick}, unchanged.
  const built = runTransform(BUILD, {from: {address: 'owner@example.com', name: 'Owner'}, to: all.to, cc: all.cc, subject: all.subject, inReplyTo: all.inReplyTo,
    references: all.references, text: 'Sounds good.', now: NOW});
  const decoded = decodedRaw(built);
  assert.deepEqual([decoded.summary.to, decoded.summary.cc, decoded.summary.subject], [all.to, all.cc, all.subject]);
  assert.match(messageOf(built), /\r\nIn-Reply-To: <p1@example\.com>\r\nReferences: <p1@example\.com>\r\n/);
  const crowd = [['From', 'Boss <boss@example.com>'], ['To', Array.from({length: 500}, (_, index) => `u${index}@example.com`).join(', ')], ['Subject', 'All'], ['Message-ID', '<c@example.com>']];
  assert.throws(() => reply(crowd, true), refused('too_many_recipients'));
  assert.equal(reply(replace(crowd, 'To', Array.from({length: 499}, (_, index) => `u${index}@example.com`).join(', ')), true).to.length, 500);
  assert.equal(reply(crowd).to.length, 1, 'a reply to the sender alone is one recipient');
});

test('replyHeaders: one Re:, Reply-To before From and never a fallback, the References chain, and names the builder would refuse dropped', () => {
  assert.equal(reply(replace(PARENT, 'Subject', 'RE: x')).subject, 'RE: x');
  assert.equal(reply(replace(PARENT, 'Subject', 're:x')).subject, 're:x');
  assert.equal(reply(replace(PARENT, 'Subject', '=?UTF-8?B?w6l0w6k=?=')).subject, 'Re: été');
  assert.equal(reply(replace(PARENT, 'Subject', '')).subject, 'Re:');
  assert.equal(reply(replace(PARENT, 'Subject')).subject, 'Re:');
  assert.throws(() => reply([...PARENT, ['Subject', 'again']]), refused('mime_invalid'), 'two subjects are no subject to answer');
  assert.deepEqual(reply([...PARENT, ['Reply-To', 'Desk <desk@example.com>, help@example.com']]).to, [{name: 'Desk', address: 'desk@example.com'}, {address: 'help@example.com'}]);
  assert.throws(() => reply([...PARENT, ['Reply-To', 'desk@']]), refused('address_invalid'), 'a Reply-To that does not parse never falls back to From');
  assert.throws(() => reply([...PARENT, ['Reply-To', 'Nobody:;']]), refused('address_invalid'), 'nor does an empty one');
  assert.throws(() => reply(replace(PARENT, 'From', 'Boss <<boss@example.com')), refused('address_invalid'));
  assert.throws(() => reply(replace(PARENT, 'From', '"john smith"@example.com')), refused('address_invalid'), 'an address the builder cannot write');
  assert.throws(() => reply(replace(PARENT, 'Message-ID')), refused('message_id_invalid'));
  assert.throws(() => reply([...PARENT, ['Message-ID', '<p2@example.com>']]), refused('message_id_invalid'));
  // References: the parent's References, else its one In-Reply-To, then its Message-ID; malformed ids are skipped; at most 100 are kept.
  assert.equal(reply([...PARENT, ['In-Reply-To', '<p0@example.com>']]).references, '<p0@example.com> <p1@example.com>');
  assert.equal(reply([...PARENT, ['In-Reply-To', '<a@example.com> <b@example.com>']]).references, '<p1@example.com>');
  assert.equal(reply([...PARENT, ['References', '<a@example.com>\r\n bogus <b@example.com><c@example.com>'], ['In-Reply-To', '<x@example.com>']]).references,
    '<a@example.com> <b@example.com> <c@example.com> <p1@example.com>');
  const chain = Array.from({length: 120}, (_, index) => `<r${index}@example.com>`);
  const trimmed = reply([...PARENT, ['References', chain.join(' ')]]).references.split(' ');
  assert.equal(trimmed.length, 100);
  assert.deepEqual([trimmed.at(0), trimmed.at(1), trimmed.at(-2), trimmed.at(-1)], ['<r0@example.com>', '<r22@example.com>', '<r119@example.com>', '<p1@example.com>']);
  // Display names: RFC 2047 decoded; one the builder would refuse is dropped and its address kept.
  assert.deepEqual(reply(replace(PARENT, 'From', '=?UTF-8?B?w4lsb2lzZQ==?= <e@example.com>')).to, [{name: 'Éloise', address: 'e@example.com'}]);
  for (const name of ['Fam \u{1F468}‍\u{1F469}', 'Line=0Abreak', 'x'.repeat(1001)]) {
    const from = name.includes('=0A') ? '=?UTF-8?Q?Line=0Abreak?= <f@example.com>' : `"${name}" <f@example.com>`;
    assert.deepEqual(reply(replace(PARENT, 'From', from)).to, [{address: 'f@example.com'}], name.slice(0, 20));
  }
});

test('decodeHeader decodes only well-formed encoded-words, each on its own, at most 10,000 of them, and joins adjacent ones across white space', () => {
  const decode = value => runTransform('rfc5322.decodeHeader@1', {value}).text;
  assert.equal(decode('=?UTF-8?B?w6k?='), 'é', 'padding may be absent');
  assert.equal(decode('=?utf-8?q?caf=C3=A9?= au lait'), 'café au lait');
  for (const literal of ['=?UTF-8?Q?a?=b', 'x=?UTF-8?Q?a?=', '=?UTF-8?Q?=ZZ?=', '=?UTF-8?B?/w==?=', '=?UTF-8?X?abc?=', '=?UTF-8?Q??=', '=??Q?a?=', '=?UTF-8?Q?a b?=']) {
    assert.equal(decode(literal), literal, literal);
  }
  assert.equal(decode('=?UTF-8?B?w6k=?=\r\n\t=?UTF-8?B?w6k=?= x'), 'éé x');
  assert.equal(decode('a\r\n b'), 'a b', 'a fold is unfolded');
  const words = new Array(10_001).fill('=?UTF-8?Q?a?=').join(' ');
  assert.equal(decode(words), `${'a'.repeat(10_000)} =?UTF-8?Q?a?=`, 'the 10,001st word stays as written');
  const unknown = [...new Array(10_000).fill('=?x-none?Q?b?='), '=?UTF-8?Q?a?='].join(' ');
  assert.equal(decode(unknown), unknown, 'a word that does not decode counts toward the 10,000 too');
});

test('parseAddresses refuses with address_invalid what no address list can be, and reads at most 1,000 addresses', () => {
  for (const value of ['Ann <ann@example.com', '"open quote <a@b.c>', '(open comment a@b.c', 'a@b.c, <>', 'a@b.c;', 'Group: a@b.c', '<a@b.c> trailing', 'a@[open', '\u0000a@b.c', 'a\\b@c.d']) {
    assert.throws(() => runTransform('rfc5322.parseAddresses@1', {value}), refused('address_invalid'), JSON.stringify(value));
  }
  const list = Array.from({length: 1000}, (_, index) => `a${index}@example.com`).join(', ');
  assert.equal(runTransform('rfc5322.parseAddresses@1', {value: list}).addresses.length, 1000);
  assert.deepEqual(runTransform('rfc5322.parseAddresses@1', {value: '""  <a@b.c>, =?UTF-8?B?w6k=?= <e@b.c>, Zoë <z@b.c>'}).addresses,
    [{address: 'a@b.c'}, {name: '=?UTF-8?B?w6k=?=', address: 'e@b.c'}, {name: 'Zoë', address: 'z@b.c'}], 'names stay as written; the decoders decode them');
  assert.deepEqual(runTransform('rfc5322.parseAddresses@1', {value: ''}).addresses, []);
});

// The check of parts d and e: two fixes (folding and RFC 2231 values) and the guards no test above held.
test('a line that holds a token folds before one that would pass 78 characters, so a long address takes a line of its own', () => {
  const long = `${'l'.repeat(60)}@${'d'.repeat(10)}.com`;
  for (let size = 40; size < 75; size++) {
    const message = messageOf(runTransform(BUILD, {...BASE, to: [{address: 'a@b.co', name: 'N'.repeat(size)}, {address: long, name: 'C'}]}));
    for (const line of headerSection(message).split('\r\n')) assert.ok(line.length <= 78, `a name of ${size}: ${line}`);
  }
  const longer = `${'u'.repeat(80)}@example.com`;
  const message = messageOf(runTransform(BUILD, {...BASE, to: [{address: 'a@b.co', name: 'N'.repeat(62)}, {address: longer, name: 'C'}]}));
  assert.ok(headerSection(message).split('\r\n').includes(` <${longer}>`), 'an address no line can hold sits alone on its line');
  const ids = ['<a@example.com>', '<b@example.com>', '<c@example.com>', '<d@example.com>', '<e@b>', `<${'r'.repeat(60)}@example.com>`];
  const references = messageOf(runTransform(BUILD, {...BASE, references: ids.join(' ')}));
  for (const line of headerSection(references).split('\r\n')) assert.ok(line.length <= 78, line);
  assert.deepEqual(decodedRaw(runTransform(BUILD, {...BASE, to: [{address: 'a@b.co', name: 'N'.repeat(63)}, {address: long, name: 'C'}]})).summary.to,
    [{address: 'a@b.co', name: 'N'.repeat(63)}, {address: long, name: 'C'}]);
});

test('an encoded name that starts near the end of a line folds first, so no encoded-word is empty and the name decodes exactly', () => {
  // The first address fills its line to between 43 and 78 characters, so the encoded name starts where 35 to 0 characters are left.
  for (let size = 30; size <= 61; size++) {
    const to = [{address: `${'x'.repeat(size)}@example.com`}, {address: 'b@example.com', name: 'Zoë \u{1F600}'}];
    const result = runTransform(BUILD, {...BASE, to});
    const head = headerSection(messageOf(result));
    assert.ok(!head.includes('=?UTF-8?B??='), `an address of ${size + 12}: no empty encoded-word`);
    for (const line of head.split('\r\n')) assert.ok(line.length <= 78, line);
    assert.deepEqual(decodedRaw(result).summary.to, to, `an address of ${size + 12}`);
  }
});

test('an RFC 2231 value holding a character outside ASCII does not decode, so the plain parameter is used and no byte is guessed', () => {
  const attachment = disposition => utf8url(['From: a@example.com', 'Content-Type: multipart/mixed; boundary=m', '', '--m', 'Content-Type: application/pdf; name="type.pdf"',
    `Content-Disposition: attachment; ${disposition}`, '', 'x', '--m--', ''].join('\r\n'));
  const filename = disposition => runTransform(RAW, {raw: attachment(disposition)}).attachments.map(item => item.filename);
  assert.deepEqual(filename('filename*=utf-8\'\'中.pdf; filename="plain.pdf"'), ['plain.pdf'], 'never the low byte of U+4E2D, a hyphen');
  assert.deepEqual(filename('filename*=iso-8859-1\'\'café.pdf; filename="plain.pdf"'), ['plain.pdf']);
  assert.deepEqual(filename('filename*=utf-8\'\'中.pdf'), ['type.pdf'], 'then the Content-Type name');
  assert.deepEqual(filename('filename*=utf-8\'\'%E4%B8%AD.pdf; filename="plain.pdf"'), ['中.pdf'], 'a percent-encoded value still decodes');
});

test('reply-all removes the owner given in any case; a plain reply keeps the owner; reply-all refuses a To or Cc that does not parse', () => {
  const headers = [['From', 'Boss <boss@example.com>'], ['To', 'owner@example.com, ann@example.com'], ['Subject', 'Plans'], ['Message-ID', '<p1@example.com>']];
  for (const address of ['Owner@EXAMPLE.com', 'OWNER@example.COM']) {
    assert.deepEqual(runTransform(REPLY, {parent: gmail(headers), owner: {address}, replyAll: true}).to, [{name: 'Boss', address: 'boss@example.com'}, {address: 'ann@example.com'}], address);
  }
  // Live test G4 replies to a message the owner sent to themself: a plain reply goes back to the owner.
  const own = [['From', 'Owner <owner@example.com>'], ['To', 'owner@example.com'], ['Subject', 'Note'], ['Message-ID', '<n1@example.com>']];
  assert.deepEqual(reply(own).to, [{name: 'Owner', address: 'owner@example.com'}]);
  // Reply-all never drops part of its audience in silence.
  for (const [name, value] of [['To', 'Ann <<ann@example.com'], ['Cc', '"open quote <c@example.com>']]) {
    const bad = [...PARENT, [name, value]].filter(([key], index, all) => key !== name || index === all.length - 1);
    assert.throws(() => reply(bad, true), refused('address_invalid'), name);
    assert.deepEqual(reply(bad).to, [{name: 'Boss', address: 'boss@example.com'}], `a plain reply reads only Reply-To or From: ${name}`);
  }
});

test('parseAddresses and the builder refuse what the tests above left out: a control inside quotes, a group with no name, a space in a domain literal', () => {
  for (const value of ['"a\u0001b" <a@b.c>', ': a@b.c;', '"x\u001fy" <a@b.c>']) {
    assert.throws(() => runTransform('rfc5322.parseAddresses@1', {value}), refused('address_invalid'), JSON.stringify(value));
  }
  assert.deepEqual(runTransform('rfc5322.parseAddresses@1', {value: '"a\tb" <a@b.c>'}).addresses, [{name: 'a\tb', address: 'a@b.c'}], 'a tab is white space');
  for (const inReplyTo of ['<a@[1 2]>', '<a@[a[b]>', '<a@[a\\b]>']) assert.throws(() => runTransform(BUILD, {...BASE, inReplyTo}), refused('message_id_invalid'), inReplyTo);
  assert.ok(runTransform(BUILD, {...BASE, inReplyTo: '<a@[10.0.0.1]>'}).raw);
});

test('types and parameter names fold to lower case, the first of a repeated parameter counts, a type that is no type/subtype reads as text/plain, and quoted-printable drops trailing white space', () => {
  const raw = ['From: a@example.com', 'Content-Type: Multipart/Alternative; BOUNDARY="b"', '', '--b', 'Content-Type: TEXT/PLAIN; Charset=UTF-8; charset=x-bogus',
    'Content-Transfer-Encoding: Quoted-Printable', '', 'caf=C3=A9   ', 'line two\t', '--b--', ''].join('\r\n');
  const result = runTransform(RAW, {raw: b64url(raw)});
  assert.deepEqual(result.parts.map(part => [part.partId, part.mimeType, part.decoded]), [['', 'multipart/alternative', true], ['0', 'text/plain', true]]);
  assert.equal(result.text, 'café\r\nline two', 'trailing white space on a quoted-printable line was added in transport');
  for (const type of ['text', 'text/', 'not a type', '/plain']) {
    const plain = runTransform(RAW, {raw: b64url(`From: a@example.com\r\nContent-Type: ${type}\r\n\r\nhi`)});
    assert.deepEqual([plain.parts.at(0).mimeType, plain.text], ['text/plain', 'hi'], type);
  }
});

test('a Gmail part with an attachmentId and no filename is listed as an attachment, never read as the text', () => {
  const message = {id: 'm', threadId: 't', payload: {partId: '', mimeType: 'multipart/mixed', filename: '', headers: [{name: 'From', value: 'a@example.com'}], body: {size: 0}, parts: [
    {partId: '0', mimeType: 'text/plain', filename: '', headers: [], body: {size: 90_000, attachmentId: 'ANGjdJ8'}},
    {partId: '1', mimeType: 'text/plain', filename: '', headers: [{name: 'Content-Type', value: 'text/plain; charset=UTF-8'}], body: {size: 5, data: utf8url('Hello')}}]}};
  const result = runTransform(GMAIL, {message});
  assert.deepEqual(result.attachments, [{partId: '0', filename: '', mimeType: 'text/plain', size: 90_000, attachmentId: 'ANGjdJ8'}]);
  assert.equal(result.text, 'Hello');
});

vectorTests('rfc5322');

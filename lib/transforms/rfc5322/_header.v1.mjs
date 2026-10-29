// F10.8 part e (docs/F10.8-BUILD-MAP.md): writing header fields. The injection rule refuses a control (tab, CR and LF included), a hidden
// or direction character (the rule of public/hosted-text.js, through _shared/hidden.v1.mjs, so a module that imports this file declares
// `unicode`), U+2028, U+2029 and a lone surrogate. Text that is printable ASCII with single spaces, no "=?" and lines that fold within 78
// characters is written as it is; any other text becomes RFC 2047 B encoded-words in UTF-8, each at most 75 characters, each holding whole
// code points, sized to the room left on its line. Lines fold at 78 characters where a break is allowed; an address or a message id that
// cannot fold takes a line of its own and never passes 998. The schemas of the fields replyHeaders gives the builder live here, so the two
// are the same objects (R1).
import {encodeBase64} from '../_shared/base64.v1.mjs';
import {hasHidden} from '../_shared/hidden.v1.mjs';
import {utcParts} from '../_shared/utc.v1.mjs';
import {encodeUtf8} from '../_shared/utf8.v1.mjs';

const LINE = 78;
const WORD = 75;
const PLAIN_TOKEN = 70;
const PREFIX = '=?UTF-8?B?';
const SUFFIX = '?=';
const CONTROL = /[\u0000-\u001f\u007f]/;
const ATOM = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+$/;
const PRINTABLE = /^[\x20-\x7e]+$/;
const DAYS = Object.freeze(['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']);
const MONTHS = Object.freeze(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']);

const ADDRESS = Object.freeze({type: 'string', minLength: 1, maxLength: 1000});
const NAME = Object.freeze({type: 'string', minLength: 1, maxLength: 1000});
/** One mailbox the builder writes: {address, name?}. The address rule (ASCII dot-atom, at most 254) is checked in run(). */
export const MAILBOX = Object.freeze({type: 'object', properties: {address: ADDRESS, name: NAME}, required: ['address'], additionalProperties: false});
/** To, Cc or Bcc: at most 500 mailboxes; the three together are at most 500, checked in run(). */
export const RECIPIENTS = Object.freeze({type: 'array', maxItems: 500, items: MAILBOX});
export const SUBJECT = Object.freeze({type: 'string', maxLength: 10_000});
export const MESSAGE_ID = Object.freeze({type: 'string', minLength: 1, maxLength: 900});
export const REFERENCES = Object.freeze({type: 'string', minLength: 1, maxLength: 100_000});

/** True when header text holds a control, a hidden or direction character, U+2028, U+2029 or a lone surrogate. */
export const injected = text => CONTROL.test(text) || hasHidden(text) || !text.isWellFormed();

/** A display name the builder can write: one that is not injected and holds at most 1,000 code points. */
export const writableName = name => typeof name === 'string' && name.length > 0 && !injected(name) && [...name].length <= NAME.maxLength;

/** A header field being written: tokens go on the current line after a space, or on a new folded line when they would pass 78. A line
 * that holds no token yet (the field name's, or a fresh folded one) takes the next token whatever its length, so a token too long for
 * any line sits alone on its own. */
function writer(name) {
  const lines = [];
  let line = `${name}:`, empty = true;
  return {
    room: () => LINE - line.length - 1,
    token(text) {
      if (!empty && line.length + 1 + text.length > LINE) { lines.push(line); line = ''; }
      line += ` ${text}`;
      empty = false;
    },
    fold() { if (!empty) { lines.push(line); line = ''; empty = true; } },
    end() { lines.push(line); return lines.join('\r\n'); },
  };
}

const utf8Length = code => code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
const encodedWord = text => `${PREFIX}${encodeBase64(encodeUtf8(text), 'base64')}${SUFFIX}`;
/** How many bytes the next encoded-word can hold where it will stand, folding first when fewer than a four-byte character fit. */
function capacity(out) {
  if (out.room() < PREFIX.length + SUFFIX.length + 8) out.fold();
  return Math.floor((Math.min(out.room(), WORD) - PREFIX.length - SUFFIX.length) / 4) * 3;
}
/** Writes text as B encoded-words, whole code points in each. White space between two encoded-words is not part of the text. */
function encodedWords(out, text) {
  let chunk = '', bytes = 0, room = capacity(out);
  for (const char of text) {
    const size = utf8Length(char.codePointAt(0));
    if (bytes + size > room) { out.token(encodedWord(chunk)); chunk = ''; bytes = 0; room = capacity(out); }
    chunk += char;
    bytes += size;
  }
  if (chunk) out.token(encodedWord(chunk));
}
/** The words of printable ASCII with single spaces between them and no "=?", or null. */
function plainWords(text) {
  if (!PRINTABLE.test(text) || text.startsWith(' ') || text.endsWith(' ') || text.includes('  ') || text.includes('=?')) return null;
  return text.split(' ');
}

/** An unstructured field (Subject): plain when it folds within 78 characters, else encoded-words. */
export function unstructuredField(name, text) {
  const words = plainWords(text);
  if (words) {
    const out = writer(name);
    for (const word of words) out.token(word);
    const field = out.end();
    if (field.split('\r\n').every(line => line.length <= LINE)) return field;
  }
  const out = writer(name);
  encodedWords(out, text);
  return out.end();
}

/** A mailbox-list field: each display name as atoms, as one quoted string, or as encoded-words; addresses as they are. Never a group. */
export function mailboxField(name, boxes) {
  const out = writer(name);
  boxes.forEach((box, index) => {
    const comma = index < boxes.length - 1 ? ',' : '';
    if (box.name === undefined) { out.token(`${box.address}${comma}`); return; }
    const words = plainWords(box.name), quoted = words && `"${box.name.replace(/["\\]/g, '\\$&')}"`;
    if (words && words.every(word => ATOM.test(word) && word.length <= PLAIN_TOKEN)) for (const word of words) out.token(word);
    else if (quoted && quoted.length <= PLAIN_TOKEN) out.token(quoted);
    else encodedWords(out, box.name);
    out.token(`<${box.address}>${comma}`);
  });
  return out.end();
}

/** A field of message ids, one token each. */
export function idsField(name, ids) {
  const out = writer(name);
  for (const id of ids) out.token(id);
  return out.end();
}

const two = value => String(value).padStart(2, '0');
/** RFC 5322 section 3.3 date-time of epoch milliseconds, in UTC: Tue, 20 Oct 2026 14:00:00 +0000. */
export function dateValue(ms) {
  const parts = utcParts(ms);
  if (parts === null) return null;
  return `${DAYS.at(parts.weekday)}, ${two(parts.day)} ${MONTHS.at(parts.month - 1)} ${String(parts.year).padStart(4, '0')} ${two(parts.hour)}:${two(parts.minute)}:${two(parts.second)} +0000`;
}

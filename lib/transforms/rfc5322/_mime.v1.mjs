// F10.8 part e (docs/F10.8-BUILD-MAP.md): reading mail. RFC 2047 encoded-words, header sections (RFC 5322 section 2.2), Content-Type and its
// parameters (RFC 2045, with single-segment RFC 2231 values), transfer encodings (RFC 2045 section 6), charsets through TextDecoder with
// fatal set (the WHATWG labels, so iso-8859-1 and us-ascii read as windows-1252; a module that imports this file declares `charset`), and
// the walk of a MIME tree, from a raw message (RFC 2046) or from a Gmail Message, whose body.data already holds each part's decoded bytes.
//
// Nothing here refuses because of what a message says (open point Minor 9). A summary field that does not parse, or that occurs twice, is
// left out of the summary and named in summary.invalid. A part deeper than 8 levels, a part past the 100th, a text part in an unknown
// charset or transfer encoding, or bytes its charset does not allow, is listed with decoded: false and its reason; utf-7 is never decoded.
// A raw header field whose bytes are not UTF-8 is left out. Only a value that is not a message at all gives null, and the caller refuses.
import {foldAscii, trimAscii} from '../_shared/ascii.v1.mjs';
import {decodeBase64} from '../_shared/base64.v1.mjs';
import {decodeUtf8} from '../_shared/utf8.v1.mjs';
import {parseAddressList, validMessageId} from './_address.v1.mjs';

const MAX_DEPTH = 8;
const MAX_PARTS = 100;
const MAX_HEADERS = 500;
const MAX_WORDS = 10_000;
const MAX_TEXT = 500_000;
const ENCODED_WORD = /^=\?([!#$%&'+\-0-9A-Z^_`a-z{|}~]+)(?:\*[A-Za-z0-9-]*)?\?([BbQq])\?([\x21-\x3e\x40-\x7e]+)\?=$/;
const HEX2 = /^[0-9A-Fa-f]{2}$/;
const LABEL = /^[a-z0-9._:+-]{1,40}$/;
const UTF7 = /utf-?7/;
const MIME_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;
const FIELD_NAME = /^[\x21-\x39\x3b-\x7e]+$/;
// The summary fields, in the order summary.invalid lists them.
const SUMMARY = Object.freeze([['from', 'from'], ['to', 'to'], ['cc', 'cc'], ['reply-to', 'replyTo'], ['subject', 'subject'], ['date', 'date'], ['message-id', 'messageId']]);
const ADDRESS_FIELDS = new Set(['from', 'to', 'cc', 'replyTo']);
const REASONS = Object.freeze(['unknown_charset', 'malformed', 'unknown_transfer_encoding', 'mime_too_deep', 'mime_too_many_parts']);

const TEXT = Object.freeze({type: 'string'});
const MAILBOXES = Object.freeze({type: 'array', maxItems: 1000, items: {type: 'object', properties: {address: TEXT, name: TEXT}, required: ['address'], additionalProperties: false}});
/** The output of decodeRaw@1 and decodeGmailPayload@1. */
export const DECODED = Object.freeze({type: 'object', properties: {
  headers: {type: 'array', maxItems: MAX_HEADERS, items: {type: 'object', properties: {name: TEXT, value: TEXT}, required: ['name', 'value'], additionalProperties: false}},
  headersTruncated: {type: 'boolean', enum: [true]},
  summary: {type: 'object', properties: {from: MAILBOXES, to: MAILBOXES, cc: MAILBOXES, replyTo: MAILBOXES, subject: TEXT, date: TEXT, messageId: TEXT,
    invalid: {type: 'array', maxItems: SUMMARY.length, items: {type: 'string', enum: SUMMARY.map(([, key]) => key)}}}, additionalProperties: false},
  text: {type: 'string', maxLength: MAX_TEXT}, html: {type: 'string', maxLength: MAX_TEXT}, truncated: {type: 'boolean', enum: [true]},
  attachments: {type: 'array', maxItems: MAX_PARTS, items: {type: 'object', properties: {partId: TEXT, filename: TEXT, mimeType: TEXT, size: {type: 'integer', minimum: 0},
    attachmentId: TEXT}, required: ['partId', 'filename', 'mimeType', 'size'], additionalProperties: false}},
  parts: {type: 'array', maxItems: MAX_PARTS + 1, items: {type: 'object', properties: {partId: TEXT, mimeType: TEXT, charset: TEXT, decoded: {type: 'boolean'},
    reason: {type: 'string', enum: REASONS}}, required: ['partId', 'mimeType', 'decoded'], additionalProperties: false}},
}, required: ['headers', 'summary', 'attachments', 'parts'], additionalProperties: false});

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const isWsp = code => code === 0x20 || code === 0x09;
/** RFC 5322 unfolding: a line break followed by white space goes, the white space stays. */
const unfold = value => value.replace(/\r\n(?=[ \t])|\n(?=[ \t])|\r(?=[ \t])/g, '');

/** {text} of bytes in a charset, or {reason}: unknown_charset (never utf-7) or malformed. Decoders are kept per call in `cache`. */
export function decodeCharset(bytes, label, cache) {
  const key = foldAscii(trimAscii(label));
  if (!cache.has(key)) {
    let decoder = null;
    if (LABEL.test(key) && !UTF7.test(key)) {
      try { decoder = new TextDecoder(key, {fatal: true, ignoreBOM: true}); } catch { decoder = null; }
    }
    cache.set(key, decoder);
  }
  const decoder = cache.get(key);
  if (decoder === null) return {reason: 'unknown_charset'};
  try { return {text: decoder.decode(bytes)}; } catch { return {reason: 'malformed'}; }
}

/** The bytes of Q encoded-text (RFC 2047 section 4.2), or null when an = is not followed by two hex digits. */
function qBytes(text) {
  const out = [];
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code === 0x5f) out.push(0x20);
    else if (code === 0x3d) {
      const hex = text.slice(index + 1, index + 3);
      if (!HEX2.test(hex)) return null;
      out.push(Number.parseInt(hex, 16));
      index += 2;
    } else out.push(code);
  }
  return new Uint8Array(out);
}
/** The text of one encoded-word; null when it is one but does not decode, so it stays as written (RFC 2047 section 6.3); undefined when the
 * run is no encoded-word at all. */
function wordText(run, cache) {
  const match = ENCODED_WORD.exec(run);
  if (!match) return undefined;
  const [, charset, encoding, encoded] = match;
  const bytes = encoding === 'B' || encoding === 'b' ? decodeBase64(encoded, 'base64') : qBytes(encoded);
  if (bytes === null) return null;
  const decoded = decodeCharset(bytes, charset, cache);
  return decoded.reason ? null : decoded.text;
}

/** A header value with its folds undone and its well-formed encoded-words decoded; white space between two goes. At most 10,000 encoded-words
 * are tried, decoded or not, so a value of unknown charsets bounds the work too; any after stay as written. */
export function decodeWords(value, cache = new Map()) {
  const text = unfold(value);
  let out = '', space = '', afterWord = false, words = 0, index = 0;
  while (index < text.length) {
    const blank = isWsp(text.charCodeAt(index));
    let end = index;
    while (end < text.length && isWsp(text.charCodeAt(end)) === blank) end++;
    const run = text.slice(index, end);
    if (blank) space += run;
    else {
      const decoded = words < MAX_WORDS ? wordText(run, cache) : undefined;
      if (decoded !== undefined) words++;
      if (typeof decoded !== 'string') { out += space + run; afterWord = false; }
      else { out += (afterWord ? '' : space) + decoded; afterWord = true; }
      space = '';
    }
    index = end;
  }
  return out + space;
}

/** The pieces of a structured value split at semicolons outside quoted strings. */
function splitParameters(value) {
  const pieces = [];
  let current = '', quoted = false;
  for (let index = 0; index < value.length; index++) {
    const char = value.charAt(index);
    if (quoted && char === '\\') { current += value.slice(index, index + 2); index++; continue; }
    if (char === '"') quoted = !quoted;
    if (char === ';' && !quoted) { pieces.push(current); current = ''; continue; }
    current += char;
  }
  pieces.push(current);
  return pieces;
}
const unquote = value => value.length >= 2 && value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1).replace(/\\(.)/g, '$1') : value;
/** {kind, params} of a Content-Type or Content-Disposition value: the first piece folded to lower case, then name=value pairs. */
function structured(value) {
  const [first, ...rest] = splitParameters(value ?? '');
  const params = new Map();
  for (const piece of rest) {
    const equals = piece.indexOf('=');
    if (equals < 1) continue;
    const name = foldAscii(trimAscii(piece.slice(0, equals)));
    if (!params.has(name)) params.set(name, unquote(trimAscii(piece.slice(equals + 1))));
  }
  return {kind: foldAscii(trimAscii(first)), params};
}
/** The text of an RFC 2231 single-segment value, charset'language'percent-encoded, or null. A character outside printable ASCII is no
 * part of that form, so the value does not decode; its low byte is never taken in its place. */
function extended(value, cache) {
  const first = value.indexOf("'"), second = value.indexOf("'", first + 1);
  if (first < 0 || second < 0) return null;
  const out = [], encoded = value.slice(second + 1);
  for (let index = 0; index < encoded.length; index++) {
    const code = encoded.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) return null;
    if (code !== 0x25) { out.push(code); continue; }
    const hex = encoded.slice(index + 1, index + 3);
    if (!HEX2.test(hex)) return null;
    out.push(Number.parseInt(hex, 16));
    index += 2;
  }
  const decoded = decodeCharset(new Uint8Array(out), value.slice(0, first) || 'us-ascii', cache);
  return decoded.reason ? null : decoded.text;
}
/** A parameter as text: the RFC 2231 form `name*` first, then `name` with its encoded-words decoded. */
function parameter(params, name, cache) {
  const starred = params.get(`${name}*`);
  const value = starred === undefined ? null : extended(starred, cache);
  if (value !== null) return value;
  const plain = params.get(name);
  return plain === undefined ? null : decodeWords(plain, cache);
}

/** The first value of a field by name (ASCII case folded), undefined when there is none. */
export function fieldValue(fields, name) {
  return fields.find(field => foldAscii(field.name) === name)?.value;
}
/** Every value of a field by name. */
export const fieldValues = (fields, name) => fields.filter(field => foldAscii(field.name) === name).map(field => field.value);

/** The mailboxes of an address field with their names decoded, or undefined when the value does not parse. */
function mailboxes(value, cache) {
  const list = parseAddressList(value);
  if (list === null) return undefined;
  return list.map(item => {
    const name = item.name === undefined ? '' : decodeWords(item.name, cache);
    return name ? {name, address: item.address} : {address: item.address};
  });
}
/** One summary field read from its value, or undefined when it does not parse. */
function readField(key, value, cache) {
  if (value === null) return undefined;
  if (ADDRESS_FIELDS.has(key)) {
    const list = mailboxes(value, cache);
    return list === undefined || (key === 'from' && !list.length) ? undefined : list;
  }
  if (key === 'subject') return decodeWords(trimAscii(value), cache);
  if (key === 'date') return trimAscii(unfold(value));
  const id = trimAscii(unfold(value));
  return validMessageId(id) ? id : undefined;
}
/** The summary of a header section: the common fields by name, each read once; one that does not parse or occurs twice is named in invalid. */
export function summarize(fields, cache = new Map()) {
  const keys = new Map(SUMMARY), seen = new Map(), entries = [], invalid = [];
  for (const field of fields) {
    const key = keys.get(foldAscii(field.name));
    if (key === undefined) continue;
    if (!seen.has(key)) seen.set(key, []);
    seen.get(key).push(field.value);
  }
  for (const [, key] of SUMMARY) {
    const values = seen.get(key);
    if (values === undefined) continue;
    const read = values.length === 1 ? readField(key, values.at(0), cache) : undefined;
    if (read === undefined) invalid.push(key);
    else entries.push([key, read]);
  }
  return Object.fromEntries(invalid.length ? [...entries, ['invalid', invalid]] : entries);
}

/** The header fields of a raw header section (one character per byte): {name, value}, the value null when its bytes are not UTF-8. */
function rawFields(section) {
  const fields = [];
  for (const piece of section.split('\n')) {
    const line = piece.endsWith('\r') ? piece.slice(0, -1) : piece;
    if (isWsp(line.charCodeAt(0))) {
      if (fields.length) fields.at(-1).value += `\r\n${line}`;
      continue;
    }
    const colon = line.indexOf(':'), name = trimAscii(line.slice(0, Math.max(colon, 0)));
    if (colon < 1 || !FIELD_NAME.test(name)) continue;
    fields.push({name, value: line.slice(colon + 1)});
  }
  return fields.map(field => ({name: field.name, value: decodeUtf8(Buffer.from(field.value, 'latin1'))}));
}
/** The header fields of a Gmail MessagePart: its {name, value} string pairs. */
const gmailFields = part => Array.isArray(part.headers) ? part.headers.filter(item => record(item) && typeof item.name === 'string' && typeof item.value === 'string')
  .map(item => ({name: item.name, value: item.value})) : [];
/** The header fields of a Gmail Message's payload, or null when the value is not a Message. */
export const messageFields = message => record(message) && record(message.payload) ? gmailFields(message.payload) : null;

/** {fields, body} of a raw entity: the header section ends at the first empty line. */
function entity(text) {
  if (text.startsWith('\r\n')) return {fields: [], body: text.slice(2)};
  if (text.startsWith('\n')) return {fields: [], body: text.slice(1)};
  const crlf = text.indexOf('\r\n\r\n'), lf = text.indexOf('\n\n');
  const at = crlf !== -1 && (lf === -1 || crlf < lf) ? crlf : lf;
  if (at === -1) return {fields: rawFields(text), body: ''};
  return {fields: rawFields(text.slice(0, at)), body: text.slice(at + (at === crlf ? 4 : 2))};
}
/** The entities of a multipart body (RFC 2046 section 5.1.1): preamble and epilogue dropped, at most 101 read. */
function splitMultipart(body, boundary) {
  const marker = `--${boundary}`, out = [];
  let start = -1, lineStart = 0;
  while (lineStart <= body.length) {
    let lineEnd = body.indexOf('\n', lineStart);
    if (lineEnd === -1) lineEnd = body.length;
    if (body.startsWith(marker, lineStart)) {
      const rest = trimAscii(body.slice(lineStart + marker.length, lineEnd));
      if (rest === '' || rest === '--') {
        if (start !== -1) {
          const end = body.startsWith('\r\n', lineStart - 2) ? lineStart - 2 : lineStart - 1;
          out.push(body.slice(start, Math.max(start, end)));
        }
        if (rest === '--' || out.length > MAX_PARTS) return out;
        start = lineEnd + 1;
      }
    }
    lineStart = lineEnd + 1;
  }
  if (start !== -1 && start <= body.length) out.push(body.slice(start));
  return out;
}
/** The bytes of quoted-printable text (RFC 2045 section 6.7): soft breaks go, trailing white space goes, a stray = stays as written. */
function qpBytes(text) {
  const out = [], lines = text.split('\n');
  lines.forEach((piece, index) => {
    let line = piece.endsWith('\r') ? piece.slice(0, -1) : piece;
    while (line.length && isWsp(line.charCodeAt(line.length - 1))) line = line.slice(0, -1);
    const soft = line.endsWith('=');
    if (soft) line = line.slice(0, -1);
    for (let at = 0; at < line.length; at++) {
      const hex = line.charAt(at) === '=' ? line.slice(at + 1, at + 3) : '';
      if (HEX2.test(hex)) { out.push(Number.parseInt(hex, 16)); at += 2; } else out.push(line.charCodeAt(at) & 0xff);
    }
    if (!soft && index < lines.length - 1) out.push(0x0d, 0x0a);
  });
  return new Uint8Array(out);
}

/** What the walk needs to know of a raw entity. A multipart with no boundary, or no delimiter line, is malformed. */
const RAW = Object.freeze({
  emptyReason: 'malformed',
  info(node, cache) {
    const type = structured(fieldValue(node.fields, 'content-type')), disposition = structured(fieldValue(node.fields, 'content-disposition'));
    const filename = parameter(disposition.params, 'filename', cache) ?? parameter(type.params, 'name', cache) ?? '';
    const mimeType = MIME_TYPE.test(type.kind) ? type.kind : 'text/plain';
    return {mimeType, charset: type.params.get('charset') ?? 'us-ascii', boundary: type.params.get('boundary') ?? '', filename,
      attachment: disposition.kind === 'attachment' || filename !== '' || mimeType === 'message/rfc822', attachmentId: undefined};
  },
  children(node, info) {
    if (!info.mimeType.startsWith('multipart/')) return null;
    return info.boundary === '' || info.boundary.length > 200 ? [] : splitMultipart(node.body, info.boundary).map(entity);
  },
  content(node) {
    const encoding = foldAscii(trimAscii(fieldValue(node.fields, 'content-transfer-encoding') ?? '7bit'));
    if (encoding === 'base64') {
      const bytes = decodeBase64(node.body.replace(/[ \t\r\n]/g, ''), 'base64');
      return bytes === null ? {reason: 'malformed'} : {bytes};
    }
    if (encoding === 'quoted-printable') return {bytes: qpBytes(node.body)};
    if (encoding === '7bit' || encoding === '8bit' || encoding === 'binary') return {bytes: new Uint8Array(Buffer.from(node.body, 'latin1'))};
    return {reason: 'unknown_transfer_encoding'};
  },
  size(node) {
    const content = RAW.content(node);
    return content.bytes ? content.bytes.length : node.body.length;
  },
});
/**
 * What the walk needs to know of a Gmail MessagePart. body.data is the part's decoded bytes: no transfer encoding is applied again. A
 * multipart with no parts is what format=metadata gives, so it is listed as not read, with no reason.
 */
const GMAIL = Object.freeze({
  emptyReason: undefined,
  info(node, cache) {
    const fields = gmailFields(node), type = structured(fieldValue(fields, 'content-type')), disposition = structured(fieldValue(fields, 'content-disposition'));
    const body = record(node.body) ? node.body : {};
    const filename = typeof node.filename === 'string' ? node.filename : parameter(disposition.params, 'filename', cache) ?? '';
    const mimeType = typeof node.mimeType === 'string' && MIME_TYPE.test(foldAscii(node.mimeType)) ? foldAscii(node.mimeType) : 'text/plain';
    const attachmentId = typeof body.attachmentId === 'string' ? body.attachmentId : undefined;
    return {mimeType, charset: type.params.get('charset') ?? 'us-ascii', filename, attachmentId,
      attachment: disposition.kind === 'attachment' || filename !== '' || attachmentId !== undefined || mimeType === 'message/rfc822'};
  },
  children: (node, info) => info.mimeType.startsWith('multipart/') ? (Array.isArray(node.parts) ? node.parts.filter(record) : []) : null,
  content(node) {
    const data = record(node.body) ? node.body.data : undefined;
    if (typeof data !== 'string') return {};
    const bytes = decodeBase64(data, 'base64url');
    return bytes === null ? {reason: 'malformed'} : {bytes};
  },
  size: node => record(node.body) && Number.isSafeInteger(node.body.size) && node.body.size >= 0 ? node.body.size : 0,
});

/** Text cut at 500,000 code points on a code-point boundary. */
function cut(text) {
  let count = 0, index = 0;
  while (index < text.length && count < MAX_TEXT) {
    const code = text.charCodeAt(index);
    index += code >= 0xd800 && code <= 0xdbff && index + 1 < text.length ? 2 : 1;
    count++;
  }
  return {text: text.slice(0, index), truncated: index < text.length};
}

/** Lists one part and walks below it: depth first, at most 8 levels and 100 parts, the first text/plain and text/html decoded. */
function walk(state, kind, node, depth, partId) {
  if (state.stopped) return;
  const info = kind.info(node, state.cache);
  if (state.parts.length === MAX_PARTS) {
    state.parts.push({partId, mimeType: info.mimeType, decoded: false, reason: 'mime_too_many_parts'});
    state.stopped = true;
    return;
  }
  if (depth > MAX_DEPTH) { state.parts.push({partId, mimeType: info.mimeType, decoded: false, reason: 'mime_too_deep'}); return; }
  const part = {partId, mimeType: info.mimeType, decoded: false};
  state.parts.push(part);
  const children = kind.children(node, info);
  if (children !== null) {
    part.decoded = children.length > 0;
    if (!children.length && kind.emptyReason !== undefined) part.reason = kind.emptyReason;
    children.forEach((child, index) => walk(state, kind, child, depth + 1, partId === '' ? String(index) : `${partId}.${index}`));
    return;
  }
  if (info.attachment) {
    state.attachments.push({partId, filename: info.filename, mimeType: info.mimeType, size: kind.size(node), ...(info.attachmentId === undefined ? {} : {attachmentId: info.attachmentId})});
    return;
  }
  const slot = info.mimeType === 'text/plain' ? 'text' : info.mimeType === 'text/html' ? 'html' : null;
  if (slot === null || state.taken.has(slot)) return;
  state.taken.add(slot);
  part.charset = info.charset;
  const content = kind.content(node);
  if (content.reason) { part.reason = content.reason; return; }
  if (!content.bytes) return;
  const decoded = decodeCharset(content.bytes, info.charset, state.cache);
  if (decoded.reason) { part.reason = decoded.reason; return; }
  part.decoded = true;
  const {text, truncated} = cut(decoded.text);
  if (slot === 'text') state.text = text; else state.html = text;
  if (truncated) state.truncated = true;
}

/** The decoded message: every readable header (the first 500), the summary, text and html, attachments and parts. */
function decoded(fields, kind, root) {
  const state = {parts: [], attachments: [], taken: new Set(), cache: new Map(), stopped: false, truncated: false, text: undefined, html: undefined};
  walk(state, kind, root, 1, '');
  const readable = fields.filter(field => field.value !== null);
  return {
    headers: readable.slice(0, MAX_HEADERS).map(field => ({name: field.name, value: decodeWords(trimAscii(field.value), state.cache)})),
    ...(readable.length > MAX_HEADERS ? {headersTruncated: true} : {}),
    summary: summarize(fields, state.cache),
    ...(state.text === undefined ? {} : {text: state.text}),
    ...(state.html === undefined ? {} : {html: state.html}),
    ...(state.truncated ? {truncated: true} : {}),
    attachments: state.attachments,
    parts: state.parts,
  };
}

/** A raw message (base64url, as Gmail's format=raw and drafts carry it) decoded, or null when it is not strict base64url. */
export function readRaw(raw) {
  if (typeof raw !== 'string') return null;
  const bytes = decodeBase64(raw, 'base64url');
  if (bytes === null) return null;
  const root = entity(Buffer.from(bytes).toString('latin1'));
  return decoded(root.fields, RAW, root);
}
/** A Gmail Message (format=full or format=metadata) decoded, or null when it has no payload object. */
export function readGmail(message) {
  const fields = messageFields(message);
  return fields === null ? null : decoded(fields, GMAIL, message.payload);
}

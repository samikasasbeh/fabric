// F10.15 part 1 (docs/F10.15-BUILD-MAP.md part 1): a Gmail simulator for Gmail's actions' tests. It is written from Gmail's API v1 reference
// (the Discovery document and Google's guides on sending, drafts, threads, labels, filters, the vacation reply and error handling) and from
// this comment, and it imports only node built-ins: never lib/, catalog/, Gmail's action file or the scope facts fixture, so an action bug
// and a simulator bug cannot cancel out. Test data only: nothing in lib/ imports it, and nothing here calls Google.
//
// The service: https://gmail.googleapis.com/gmail/v1/users/{userId} (ORIGIN; BASE is the owner's own, users/me). One account, the owner
// {email}. Only "me" names it: another user id answers 400 invalidArgument and changes nothing (Google also takes the owner's own address;
// the simulator does not, stricter, never looser). Routes (named "METHOD /template" below users/{userId}, as the switches take them), each
// with the scopes the Discovery document lists for it:
//   GET    /profile                  {emailAddress, messagesTotal, threadsTotal, historyId}
//   GET    /history                  the mailbox's change log (below)
//   GET    /messages                 search (below); GET /messages/{id} one message, by format
//   POST   /messages/send            {raw, threadId?}: sends (below)
//   POST   /messages/batchModify     {ids, addLabelIds, removeLabelIds}: 204
//   POST   /messages/{id}/trash, /messages/{id}/untrash, /threads/{id}/trash, /threads/{id}/untrash
//   GET    /threads/{id}             the thread's messages, oldest first, by format (full, metadata or minimal)
//   POST   /threads/{id}/modify      {addLabelIds, removeLabelIds} on every message of the thread
//   POST   /drafts, GET and PUT /drafts/{id}, POST /drafts/send
//   GET    /labels, GET /labels/{id}, POST /labels
//   GET    and PUT /settings/vacation, POST /settings/filters, GET /settings/filters/{id}
// No other route is served (404): these are what Gmail's 13 actions, their readbacks, the live plan's reads and the trigger polls call. Scopes whose grant
// depends on the object or the request are left out of the table (gmail.addons.current.*, and gmail.metadata where Google lists it on
// messages and threads, since it allows only some formats and no search): such a token is refused, stricter than Google, never looser.
//
// Errors use Google's shape {error: {code, message, errors: [{domain, reason, message}], status}}. Without "Authorization: Bearer <token>"
// every route answers 401 (reason authError); a route whose scopes the token lacks answers 403 insufficientPermissions; an unknown route,
// message, thread, draft, label or filter answers 404 notFound; a body that is not JSON answers 400 parseError, and a field no Discovery
// schema of the request names 400 invalidArgument. A refused request changes nothing.
//
// Messages, as Google documents them:
// - raw is the whole RFC 5322 message, base64url (padding optional). Fields are read unfolded. RFC 2047 encoded words (UTF-8, US-ASCII and
//   ISO-8859-1) are decoded where the simulator reads a value: recipients, the subject and search; its answers carry each field's value as
//   written, unfolded.
// - Send: the recipients are every address of every To, Cc and Bcc field; none answers 400 "Recipient address required", and an item of
//   such a field that holds no address answers 400. Gmail adds a Message-ID field (<...@mail.gmail.com>) first when there is none, and keeps
//   the message as sent, Bcc included, with SENT, plus INBOX and UNREAD when the owner is a recipient. One delivery is recorded per recipient
//   (one named twice, in any ASCII case, once), a copy without its Bcc fields: deliveries() lists {to, messageId, raw}.
// - Threads (Google's threading guide, as the simulator reads it; step 16 checks it live): a message given a threadId joins that thread only
//   when its In-Reply-To or References names the Message-ID of a message of the thread and its subject, after any leading "Re:" (any
//   case), equals the thread's first subject read the same way; otherwise it starts its own thread, whose id is its own. A threadId of no
//   thread answers 404. Mail that arrives (deliver()) threads by the same rule, with no threadId.
// - Get by format: minimal {id, threadId, labelIds, snippet, sizeEstimate, historyId, internalDate}; metadata adds payload {mimeType,
//   headers}, only the metadataHeaders named (any case) when some are; full (the default) adds the payload tree; raw adds raw, padded
//   base64url, and no payload. A part's body.data is padded base64url of its decoded bytes (base64 and quoted-printable undone); a part
//   with a filename has an attachmentId and no data. partId is "" at the root, then "0", "1", "0.1" and so on. The snippet is the first
//   text/plain part's text, white space collapsed, at most 200 characters. Ids are 16 hex digits; internalDate is the clock's milliseconds,
//   as text.
// - Search, GET /messages: q reads only what Fabric writes (text.gmailQuery@1's form): from:"..." (the From field, address or name),
//   to:"..." (the To field), subject:"...", label:"..." (a label's name in any ASCII case, or its id), has:attachment, "a phrase" (in the
//   subject, From, To, Cc or text, in any case), after:N and before:N in epoch seconds (after inclusive, before not), each may start with
//   "-", and newer_than:<n>d reads the clock, in days. Any other operator or form answers 400 notSimulated, so no test trusts a search the simulator cannot do. Mail in TRASH or SPAM is
//   left out unless includeSpamTrash=true. Newest first; maxResults 1 to 500 (default 100) and an opaque pageToken page: {messages: [{id,
//   threadId}], nextPageToken?, resultSizeEstimate}, with no messages key when nothing matches.
// - Drafts: create {message: {raw?, threadId?}} gives {id: r<digits>, message: {id, threadId, labelIds: ['DRAFT']}}; without raw the draft
//   holds an empty message. A draft keeps its message as written. Update (PUT) replaces the message, which gets a new id; without raw it
//   blanks the draft; a body id that is not the path's answers 400. Send {id, message?}: with message.raw it sends that content, without it
//   the stored one, as messages/send sends, into the draft's thread when it joins it; the draft is then gone (404). An empty draft answers
//   400 and stays.
// - Labels: the system labels INBOX, SENT, DRAFT, TRASH, SPAM, UNREAD, STARRED and IMPORTANT, and user labels Label_<n>. A new name equal to
//   another label's, a system one included, in any ASCII case, answers 409 alreadyExists. labelListVisibility is labelShow,
//   labelShowIfUnread or labelHide; messageListVisibility show or hide.
// - batchModify (1 to 1,000 ids, 204) and threads.modify: every label id must be known, none may be SENT or DRAFT, and none both added and
//   removed (400 invalidArgument); every message must exist (404). Trash adds TRASH and untrash takes it off, leaving the other labels.
// - Vacation: {enableAutoReply, responseSubject, responseBodyPlainText, responseBodyHtml, restrictToContacts, restrictToDomain, startTime,
//   endTime}; an update replaces it whole. Times are epoch milliseconds as text (a number answers 400); an endTime not after the startTime
//   answers 400; restrictToDomain is for Google Workspace accounts and answers 400 failedPrecondition here.
// - Filters: {criteria, action}, each with at least one known field; a label id of no label answers 400; an identical filter answers 400
//   failedPrecondition "Filter already exists"; a forward answers 403 insufficientPermissions without gmail.settings.sharing (Fabric never
//   asks for it) and 400 failedPrecondition with it (the simulator has no verified forwarding address).
// - History (Iteration 9 step 7, from Google's history guide and users.history.list, as the simulator reads them; step 9 checks them live): one record per change, in order: {id, messages: [{id,
//   threadId}], and any of messagesAdded and messagesDeleted, [{message}], and labelsAdded and labelsRemoved, [{message, labelIds}]}. labelIds there are the labels that one change moved, and a
//   message holds only id and threadId unless historyOptions({labels: true}) says otherwise. A modify that changes nothing writes no record and moves no id. An id rises by a gap that varies
//   ("increase chronologically but are not contiguous with random gaps"), and it is text, so the historyId option can start a mailbox past 2^53. A message's historyId is the last record that
//   moved it, and a draft's update or send deletes its message and adds another. GET /history takes startHistoryId (required, digits; records after it), maxResults (1 to 500, default 100),
//   an opaque pageToken bound to that startHistoryId, labelId (records with a message holding that label) and repeated historyTypes (messageAdded, messageDeleted, labelAdded, labelRemoved).
//   It answers {history?, nextPageToken?, historyId}: no history key when nothing changed, and historyId the mailbox's current one. An id below expireHistory(id), older than
//   historyOptions({keepHours}), from before the mailbox or above the current one answers 404 notFound. historyOptions({emptyHoldsId: false}) leaves the id out of an empty answer: probe U2
//   decides which Google sends.
// - Search lag: historyOptions({searchLagMs}) sets how long a message written from then on stays out of q. It keeps its place by date, so it can land behind what is newer.
//
// The network contract is lib/network.mjs's seam: `request` takes its options and answers {status, headers, data}. Refused before
// sending, with sent false: a URL that is not https on 443 or carries credentials, an origin outside allowedOrigins or not Gmail's, an
// unsupported method or response handling, an unsafe header, a body that is not a string or Buffer, a body over 1 MiB. After sending,
// with sent true: an answer over maxBytes, and drop(). Only the response headers asked for come back (the seam's default list when none
// are named).
//
// Every request that reaches the simulator is recorded in `calls`, without its Authorization header: {method, origin, path (below
// users/{userId}), user, route, query, headers, body, write, status}. writes() and reads() are the calls to write and read routes; state()
// is a copy of the state; deliveries() the copies Gmail delivered. Switches, each for the next call to one route unless {times} says how
// many: fail(route, {status, headers?, data?}) answers that instead and changes nothing; limit(route, kind) answers as Google documents a
// limit (tooManyRequests and tooManyConcurrent: 429 rateLimitExceeded; dailyLimitExceeded, userRateLimitExceeded or rateLimitExceeded: 403; all in domain
// usageLimits, with no Retry-After, since Google names only "a retry time") and changes nothing; drop(route) applies the call, then throws as a lost answer; swallow(route) answers as if applied but
// changes nothing (a readback then sees the old state); oversize(route, bytes) pads the answer; hold(route) returns {reached, release()}.
// Test data, recorded as no call: deliver(raw, labels, {labelsAdded}) is mail that arrives (INBOX and UNREAD unless labels says; labelsAdded also
// writes that record, for a filter's label, whichever probe U5 finds); seedDraft(raw) is a draft the owner wrote in Gmail; editDraft(id, raw) is
// the owner editing a draft in Gmail; remove(kind, id) is the owner deleting a message, thread, draft, label or filter; relabel(id, {add, remove})
// is the owner changing a message's labels; ownerSends(raw, threadId) is a send from Gmail; together(fn) puts every change fn makes in one record;
// expireHistory(id) and historyOptions() are described above.
import {createHash} from 'node:crypto';

export const ORIGIN = 'https://gmail.googleapis.com';
export const BASE = `${ORIGIN}/gmail/v1/users/me`;
const USERS = '/gmail/v1/users/';
const DEFAULT_RESPONSE_HEADERS = ['content-type', 'etag', 'retry-after', 'x-ratelimit-remaining'];
const UNSAFE_HEADER = /^(host|connection|transfer-encoding|content-length|upgrade|proxy-.*|forwarded|x-forwarded-.*)$/i;
const scopes = (...names) => names.map(name => name === 'mail' ? 'https://mail.google.com/' : `https://www.googleapis.com/auth/${name}`);
const READ = scopes('mail', 'gmail.modify', 'gmail.readonly');
const SEND = scopes('mail', 'gmail.compose', 'gmail.modify', 'gmail.send');
const MODIFY = scopes('mail', 'gmail.modify');
const COMPOSE = scopes('mail', 'gmail.compose', 'gmail.modify');
const DRAFT_READ = scopes('mail', 'gmail.compose', 'gmail.modify', 'gmail.readonly');
const PROFILE = scopes('mail', 'gmail.compose', 'gmail.metadata', 'gmail.modify', 'gmail.readonly');
const LABEL_READ = scopes('mail', 'gmail.labels', 'gmail.metadata', 'gmail.modify', 'gmail.readonly');
const LABEL_WRITE = scopes('mail', 'gmail.labels', 'gmail.modify');
const SETTINGS_READ = scopes('mail', 'gmail.modify', 'gmail.readonly', 'gmail.settings.basic');
const SETTINGS_WRITE = scopes('gmail.settings.basic');
const [SHARING] = scopes('gmail.settings.sharing');
const SYSTEM_LABELS = Object.freeze(['INBOX', 'SENT', 'DRAFT', 'TRASH', 'SPAM', 'UNREAD', 'STARRED', 'IMPORTANT']);
/** Labels Gmail sets itself: a modify neither adds nor removes them. */
const FIXED = new Set(['SENT', 'DRAFT']);
const LEFT_OUT = new Set(['TRASH', 'SPAM']);
const FORMATS = new Set(['minimal', 'full', 'raw', 'metadata']);
const LABEL_LIST = new Set(['labelShow', 'labelShowIfUnread', 'labelHide']), MESSAGE_LIST = new Set(['show', 'hide']);
// The fields each request body's Discovery schema names.
const MESSAGE_FIELDS = ['id', 'threadId', 'labelIds', 'snippet', 'historyId', 'internalDate', 'payload', 'sizeEstimate', 'raw'];
const DRAFT_FIELDS = ['id', 'message'];
const MODIFY_FIELDS = ['addLabelIds', 'removeLabelIds'];
const LABEL_FIELDS = ['id', 'name', 'type', 'labelListVisibility', 'messageListVisibility'];
const VACATION_FLAGS = ['enableAutoReply', 'restrictToContacts', 'restrictToDomain'], VACATION_TEXTS = ['responseSubject', 'responseBodyPlainText', 'responseBodyHtml'];
const VACATION_FIELDS = [...VACATION_FLAGS, ...VACATION_TEXTS, 'startTime', 'endTime'];
// Field names are written capitalized and folded where a lowercase one would sit before a quote, so the test's import scan reads only imports.
const CRITERIA_TEXTS = ['From', 'To', 'Subject', 'Query', 'NegatedQuery'].map(name => name[0].toLowerCase() + name.slice(1)), CRITERIA_FIELDS = [...CRITERIA_TEXTS, 'hasAttachment', 'excludeChats', 'size', 'sizeComparison'];
const ACTION_FIELDS = ['addLabelIds', 'removeLabelIds', 'forward'];
const MAX_BATCH = 1000, MAX_DEPTH = 8;
const STATUS = {400: 'INVALID_ARGUMENT', 401: 'UNAUTHENTICATED', 403: 'PERMISSION_DENIED', 404: 'NOT_FOUND', 409: 'ALREADY_EXISTS', 429: 'RESOURCE_EXHAUSTED'};
/** The limit answers Google documents for Gmail ("Resolve errors"), by kind: [status, reason, message]. */
const LIMITS = Object.freeze({tooManyRequests: [429, 'rateLimitExceeded', 'Rate Limit Exceeded'], tooManyConcurrent: [429, 'rateLimitExceeded', 'Too many concurrent requests for user'], dailyLimitExceeded: [403, 'dailyLimitExceeded', 'Daily Limit Exceeded'],
  userRateLimitExceeded: [403, 'userRateLimitExceeded', 'User Rate Limit Exceeded'], rateLimitExceeded: [403, 'rateLimitExceeded', 'Rate Limit Exceeded']});
/** The fields the from:, to: and subject: operators read. */
const SEARCHED = Object.freeze({from: 'From', to: 'To', subject: 'Subject'});
const OPERATORS = new Set([...Object.keys(SEARCHED), 'label', 'has', 'after', 'before', 'newer_than']);
/** historyTypes as a request names them, and the field of a record each reads. */
const HISTORY_TYPES = Object.freeze({messageAdded: 'messagesAdded', messageDeleted: 'messagesDeleted', labelAdded: 'labelsAdded', labelRemoved: 'labelsRemoved'});
const HOUR_MS = 3_600_000, DAY_MS = 24 * HOUR_MS;

const notSent = message => Object.assign(new Error(message), {sent: false});
const lost = message => Object.assign(new Error(message), {sent: true});
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const hex = text => createHash('sha256').update(text).digest('hex');
/** ASCII case folding: only A to Z. */
const fold = text => text.replace(/[A-Z]/g, char => char.toLowerCase());
const pad = text => text + '='.repeat((4 - text.length % 4) % 4);
const base64url = text => pad(Buffer.from(text, 'latin1').toString('base64url'));
const utf8 = text => Buffer.from(text, 'latin1').toString('utf8');
const googleError = (code, reason, message, {domain = 'global'} = {}) =>
  ({status: code, data: {error: {code, message, errors: [{domain, reason, message}], status: reason === 'failedPrecondition' ? 'FAILED_PRECONDITION' : STATUS[code]}}});
/** A refusal a handler throws: the Google error it answers with. Handlers check everything before they change anything. */
class Refusal extends Error { constructor(answer) { super(answer.data.error.message); this.answer = answer; } }
const refuse = (code, reason, message) => { throw new Refusal(googleError(code, reason, message)); };
const notFound = () => refuse(404, 'notFound', 'Requested entity was not found.');
const invalid = message => refuse(400, 'invalidArgument', message);
const notSimulated = () => refuse(400, 'notSimulated', 'The simulator does not read this search.');
const ok = data => ({status: 200, data});
/** The body as an object naming only the fields its schema has. */
function known(body, fields, where) {
  if (!record(body)) invalid(`Invalid JSON payload received. ${where} must be an object.`);
  for (const name of Object.keys(body)) if (!fields.includes(name)) invalid(`Invalid JSON payload received. Unknown name "${name}" at '${where}': Cannot find field.`);
  return body;
}
/** Sorted-key JSON, so two values compare by content. */
const canonical = value => JSON.stringify(value, (key, item) => record(item) ? Object.fromEntries(Object.keys(item).sort().map(name => [name, item[name]])) : item);

// ---- reading a message ------------------------------------------------------------------------------------------------------------------
/** The message a raw value carries, one character per byte. Only a draft may be empty. */
function rawText(value, {empty = false} = {}) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*={0,2}$/.test(value) || value.replace(/=+$/, '').length % 4 === 1 || (!value && !empty)) {
    invalid("Invalid value at 'message.raw' (TYPE_BYTES), Base64 decoding failed.");
  }
  return Buffer.from(value, 'base64url').toString('latin1');
}
/** A message or part split into its fields, unfolded, as written, and its body. */
function entity(text) {
  const end = /\r?\n\r?\n/.exec(text), head = end ? text.slice(0, end.index) : text, body = end ? text.slice(end.index + end[0].length) : '';
  const fields = [];
  for (const line of head.replace(/\r?\n(?=[ \t])/g, '').split(/\r?\n/)) {
    const colon = line.indexOf(':');
    if (colon > 0) fields.push({name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim()});
  }
  return {fields, body};
}
const valueOf = (fields, name) => fields.find(item => fold(item.name) === name)?.value;
const valuesOf = (fields, name) => fields.filter(item => fold(item.name) === name).map(item => item.value);
/** RFC 2047 encoded words decoded (UTF-8, US-ASCII, ISO-8859-1; any other charset kept as written), the space between two dropped. */
function decodeWords(value) {
  const word = String.raw`=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=`;
  return utf8(value).replace(new RegExp(`(${word})\\s+(?=${word})`, 'g'), '$1').replace(/=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g, (whole, charset, kind, data) => {
    const bytes = /^b$/i.test(kind) ? Buffer.from(data, 'base64') : Buffer.from(data.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_, code) => String.fromCharCode(parseInt(code, 16))), 'latin1');
    const name = fold(charset).split('*')[0];
    return name === 'utf-8' || name === 'us-ascii' ? bytes.toString('utf8') : name === 'iso-8859-1' ? bytes.toString('latin1') : whole;
  });
}
/** The addresses of one address field, decoded; an item that holds none answers 400. */
function addressesOf(name, value) {
  const out = [];
  for (const item of decodeWords(value).match(/(?:"[^"]*"|[^,])+/g) ?? []) {
    if (!item.trim()) continue;
    const match = /<\s*([^<>\s@]+@[^<>\s@]+)\s*>\s*$/.exec(item) ?? /^\s*([^<>\s@",;:()[\]]+@[^<>\s@",;:()[\]]+)\s*$/.exec(item);
    if (!match) invalid(`Invalid ${name} header`);
    out.push(match[1]);
  }
  return out;
}
/** Every address of every To, Cc and Bcc field, in order. */
const recipientsOf = fields => fields.filter(item => ['to', 'cc', 'bcc'].includes(fold(item.name))).flatMap(item => addressesOf(item.name, item.value));
/** The message as delivered: every Bcc field, with its folded lines, taken out of the header. */
function withoutBcc(text) {
  const end = /\r?\n\r?\n/.exec(text), head = end ? text.slice(0, end.index) : text, rest = end ? text.slice(end.index) : '';
  const kept = [];
  let dropping = false;
  for (const line of head.split(/(?<=\n)/)) {
    if (!/^[ \t]/.test(line)) dropping = /^bcc[ \t]*:/i.test(line);
    if (!dropping) kept.push(line);
  }
  return kept.join('').replace(/\r?\n$/, '') + rest;
}
const idsIn = value => value === undefined ? [] : value.match(/<[^<>\s]+>/g) ?? [];
const messageIdOf = message => idsIn(valueOf(entity(message.text).fields, 'message-id'))[0];
const subjectKey = fields => decodeWords(valueOf(fields, 'subject') ?? '').replace(/^(?:\s*re\s*:)+/i, '').trim();
/** A structured field: its first token, ASCII folded, and its parameters, quotes taken off. */
function structured(value = '') {
  const [first, ...rest] = value.split(';'), params = new Map();
  for (const param of rest) {
    const equals = param.indexOf('=');
    if (equals > 0) params.set(fold(param.slice(0, equals).trim()), param.slice(equals + 1).trim().replace(/^"(.*)"$/, '$1'));
  }
  return {kind: fold(first.trim()), params};
}
/** A part's bytes with its transfer encoding undone. */
function bytesOf(fields, body) {
  const encoding = fold(valueOf(fields, 'content-transfer-encoding') ?? '7bit');
  if (encoding === 'base64') return Buffer.from(body.replace(/\s+/g, ''), 'base64');
  if (encoding === 'quoted-printable') return Buffer.from(body.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, code) => String.fromCharCode(parseInt(code, 16))), 'latin1');
  return Buffer.from(body, 'latin1');
}
/** The parts of a multipart body, between its boundary lines. */
function children(body, boundary) {
  const parts = [];
  let current = null;
  for (const line of body.split(/\r?\n/)) {
    const mark = line.trimEnd(), closing = mark === `--${boundary}--`;
    if (mark === `--${boundary}` || closing) {
      if (current) parts.push(current.join('\r\n'));
      if (closing) break;
      current = [];
    } else if (current) current.push(line);
  }
  return parts;
}
/** One part as Gmail's MessagePart: {partId, mimeType, filename, headers, body, parts?}. */
function partOf(text, partId, depth = 0) {
  const {fields, body} = entity(text), type = structured(valueOf(fields, 'content-type') ?? 'text/plain'), mimeType = type.kind || 'text/plain';
  const headers = fields.map(item => ({name: item.name, value: utf8(item.value)}));
  if (mimeType.startsWith('multipart/') && type.params.get('boundary') && depth < MAX_DEPTH) {
    const parts = children(body, type.params.get('boundary')).map((child, index) => partOf(child, partId === '' ? String(index) : `${partId}.${index}`, depth + 1));
    return {partId, mimeType, filename: '', headers, body: {size: 0}, parts};
  }
  const bytes = bytesOf(fields, body), filename = decodeWords(structured(valueOf(fields, 'content-disposition')).params.get('filename') ?? type.params.get('name') ?? '');
  const content = filename ? {attachmentId: `ANGjdJ${hex(`${partId}:${bytes.toString('base64')}`).slice(0, 40)}`, size: bytes.length}
    : {size: bytes.length, ...(bytes.length ? {data: pad(bytes.toString('base64url'))} : {})};
  return {partId, mimeType, filename, headers, body: content};
}
/** The text of the first text/plain part that is no attachment, in its charset (UTF-8 unless ISO-8859-1 says), or null. */
function textOf(part) {
  if (part.parts) {
    for (const child of part.parts) { const found = textOf(child); if (found !== null) return found; }
    return null;
  }
  if (part.mimeType !== 'text/plain' || part.filename) return null;
  const bytes = Buffer.from(part.body.data ?? '', 'base64url'), charset = fold(structured(part.headers.find(item => fold(item.name) === 'content-type')?.value).params.get('charset') ?? 'utf-8');
  return charset === 'iso-8859-1' ? bytes.toString('latin1') : bytes.toString('utf8');
}
const hasAttachment = part => part.parts ? part.parts.some(hasAttachment) : part.filename !== '';
const snippetOf = root => (textOf(root) ?? '').replace(/\s+/g, ' ').trim().slice(0, 200);
/** A search: its terms, each {negated, operator, value}; anything outside Fabric's form answers 400 notSimulated. */
function parseQuery(q) {
  const terms = [];
  let rest = q.trim();
  while (rest) {
    const match = /^(-?)(?:([a-z_]+):)?(?:"([^"]*)"|([^\s"(){}:]+))(?=\s|$)/.exec(rest);
    if (!match) notSimulated();
    const [whole, minus, operator, quoted, bare] = match, value = quoted ?? bare;
    if ((operator !== undefined && !OPERATORS.has(operator)) || ['OR', 'AND'].includes(bare) || !value) notSimulated();
    if (operator === 'has' && value !== 'attachment') notSimulated();
    if ((operator === 'after' || operator === 'before') && !/^[0-9]{1,12}$/.test(value)) notSimulated();
    if (operator === 'newer_than' && !/^[0-9]{1,4}d$/.test(value)) notSimulated();
    terms.push({negated: minus === '-', operator: operator ?? 'words', value});
    rest = rest.slice(whole.length).trimStart();
  }
  return terms;
}
const loose = text => text.toLowerCase().replace(/\s+/g, ' ');
const holds = (text, value) => loose(text).includes(loose(value));

export class GmailSimulator {
  /**
   * clock() gives the time messages carry; token is the bearer token the account sends; owner is {email}; scopes are the token's granted
   * scopes (by default Fabric's Gmail sign-in: gmail.modify and gmail.settings.basic).
   */
  constructor({clock = () => Date.parse('2026-10-26T13:00:00.000Z'), token = 'gmail-token', owner = {email: 'owner@example.com'},
    scopes: granted = scopes('gmail.modify', 'gmail.settings.basic'), historyId = '1000'} = {}) {
    if (!record(owner) || typeof owner.email !== 'string' || !/^[^\s@]+@[^\s@]+$/.test(owner.email)) throw new Error('owner is {email}.');
    this.clock = clock;
    this.token = token;
    this.scopes = new Set(granted);
    this.calls = [];
    this.switches = new Map();
    this.holds = new Map();
    this.historySettings = {labels: false, emptyHoldsId: true, keepHours: null, searchLagMs: 0};
    this.group = null;
    this.data = {owner: {email: owner.email}, messages: {}, drafts: {}, labels: {}, vacation: {enableAutoReply: false}, filters: {}, deliveries: [], history: [], historyId, historyFloor: historyId,
      next: {message: 1, draft: 1, label: 1, filter: 1, history: 1, seq: 1}};
    this.request = this.request.bind(this);
  }
  state() { return structuredClone(this.data); }
  writes() { return this.calls.filter(call => call.write); }
  reads() { return this.calls.filter(call => call.route && !call.write); }
  deliveries() { return structuredClone(this.data.deliveries); }
  #switch(kind, route, extra = {}, {times = 1} = {}) {
    if (!Number.isSafeInteger(times) && times !== Infinity) throw new Error('times is a whole number or Infinity.');
    this.switches.set(route, {kind, left: times, ...extra});
    return this;
  }
  fail(route, answer, options) { return this.#switch('fail', route, {answer: structuredClone(answer)}, options); }
  /** The next call to the route answers as Google documents one of its limits, and changes nothing. */
  limit(route, kind, options) {
    if (!Object.hasOwn(LIMITS, kind)) throw new Error(`limit takes one of ${Object.keys(LIMITS).join(', ')}.`);
    const [status, reason, message] = LIMITS[kind];
    return this.#switch('fail', route, {answer: googleError(status, reason, message, {domain: 'usageLimits'})}, options);
  }
  drop(route, options) { return this.#switch('drop', route, {}, options); }
  swallow(route, options) { return this.#switch('swallow', route, {}, options); }
  oversize(route, bytes, options) { return this.#switch('oversize', route, {bytes}, options); }
  hold(route) {
    let reach, release;
    const reached = new Promise(resolve => { reach = resolve; }), released = new Promise(resolve => { release = resolve; });
    this.holds.set(route, {reached, released, reach, release: () => { this.holds.delete(route); release(); }});
    return {reached, release: this.holds.get(route).release};
  }
  #take(route) {
    const entry = this.switches.get(route);
    if (!entry) return null;
    if (--entry.left <= 0) this.switches.delete(route);
    return entry;
  }

  // ---- test data ---------------------------------------------------------------------------------------------------------------------
  /** Mail that arrives from someone, threaded by its headers: {id, threadId}. */
  deliver(raw, labels = ['INBOX', 'UNREAD'], {labelsAdded = false} = {}) {
    const state = this.data, text = rawText(raw), message = this.#commit(state, {text, labelIds: [...labels], threadId: this.#incoming(state, entity(text).fields)});
    if (labelsAdded) { message.historyId = this.#history(state); this.#log(state, message, 'labelsAdded', [...labels]); }
    return {id: message.id, threadId: message.threadId};
  }
  /** A send from Gmail: as messages/send, with no request. */
  ownerSends(raw, threadId = null) {
    const state = this.data, text = rawText(raw), {fields} = entity(text), {data} = this.#sent(state, text, this.#recipients(fields), threadId ?? this.#incoming(state, fields));
    return {id: data.id, threadId: data.threadId};
  }
  /** The owner changes a message's labels in Gmail. */
  relabel(id, {add = [], remove = []}) {
    const message = this.data.messages[id];
    if (!message) throw new Error(`No message ${id}.`);
    this.#change(this.data, [message], add, remove);
  }
  /** Every change `run` makes lands in one history record. */
  together(run) {
    this.group = {};
    try { run(); } finally { this.group = null; }
  }
  /** Ids below this one are out of date: a read from one answers 404. */
  expireHistory(id) { this.data.historyFloor = String(id); }
  /** Changes how history and search read: {labels, emptyHoldsId, keepHours, searchLagMs}, as the header comment names them. */
  historyOptions(changes) {
    for (const name of Object.keys(changes)) if (!Object.hasOwn(this.historySettings, name)) throw new Error(`No history option ${name}.`);
    Object.assign(this.historySettings, changes);
    return this;
  }
  /** A draft the owner wrote in Gmail: {id, message: {id, threadId}}. */
  seedDraft(raw) {
    const state = this.data, message = this.#commit(state, {text: rawText(raw, {empty: true}), labelIds: ['DRAFT'], threadId: null}), id = this.#draftId(state);
    state.drafts[id] = message.id;
    return {id, message: {id: message.id, threadId: message.threadId}};
  }
  /** The owner edits a draft in Gmail: its message is replaced and gets a new id. */
  editDraft(id, raw) {
    const state = this.data, old = state.messages[state.drafts[id]];
    if (!old) throw new Error(`No draft ${id}.`);
    const text = rawText(raw, {empty: true});
    this.#deleted(state, old);
    delete state.messages[old.id];
    const message = this.#commit(state, {text, labelIds: ['DRAFT'], threadId: old.threadId === old.id ? null : old.threadId});
    state.drafts[id] = message.id;
    return {id, message: {id: message.id, threadId: message.threadId}};
  }
  /** The owner deletes a message, a thread, a draft, a label or a filter in Gmail. */
  remove(kind, id) {
    const state = this.data, fail = () => { throw new Error(`No ${kind} ${id}.`); };
    const forget = messageIds => {
      for (const messageId of messageIds) { this.#deleted(state, state.messages[messageId]); delete state.messages[messageId]; }
      for (const [draftId, messageId] of Object.entries(state.drafts)) if (messageIds.includes(messageId)) delete state.drafts[draftId];
    };
    if (kind === 'message') forget([state.messages[id]?.id ?? fail()]);
    else if (kind === 'thread') forget((list => list.length ? list.map(message => message.id) : fail())(this.#thread(state, id)));
    else if (kind === 'draft') forget([state.drafts[id] ?? fail()]);
    else if (kind === 'label') {
      if (!state.labels[id]) fail();
      delete state.labels[id];
      this.#change(state, Object.values(state.messages), [], [id]);
    } else if (kind === 'filter') { if (!state.filters[id]) fail(); delete state.filters[id]; }
    else throw new Error('remove takes message, thread, draft, label or filter.');
  }

  // ---- shared pieces -----------------------------------------------------------------------------------------------------------------
  #draftId(state) { return `r${BigInt(`0x${hex(`draft:${state.next.draft++}`).slice(0, 15)}`)}`; }
  /** The next history id: the last one plus a gap that varies, kept as text so it stays exact past 2^53. Inside together() every change shares one. */
  #history(state) {
    if (this.group?.id) return this.group.id;
    const gap = BigInt(parseInt(hex(`history:${state.next.history++}`).slice(0, 4), 16) % 97 + 1);
    state.historyId = String(BigInt(state.historyId) + gap);
    if (this.group) this.group.id = state.historyId;
    return state.historyId;
  }
  /** Writes one change under the message's history id. The record holds the labels a message had then, and history[].messages repeats the typed fields. */
  #log(state, message, type, labelIds) {
    const {id, threadId} = message;
    let entry = state.history.at(-1);
    if (entry?.id !== message.historyId) state.history.push(entry = {id: message.historyId, at: this.clock(), messages: []});
    if (!entry.messages.some(item => item.id === id)) entry.messages.push({id, threadId});
    (entry[type] ??= []).push({message: {id, threadId, labelIds: [...message.labelIds]}, ...(labelIds ? {labelIds} : {})});
  }
  /** The log's record of a message that is about to go. */
  #deleted(state, message) {
    message.historyId = this.#history(state);
    this.#log(state, message, 'messagesDeleted');
  }
  /** Stores a message: a new id, the clock's time, a history id and an order; a message with no thread starts its own. */
  #commit(state, {text, labelIds, threadId}) {
    const id = hex(`message:${state.next.message++}`).slice(0, 16);
    const message = {id, threadId: threadId ?? id, labelIds, text, internalDate: this.clock(), searchableAt: this.clock() + this.historySettings.searchLagMs, historyId: this.#history(state), seq: state.next.seq++};
    state.messages[id] = message;
    this.#log(state, message, 'messagesAdded');
    return message;
  }
  #thread(state, id) { return Object.values(state.messages).filter(message => message.threadId === id).sort((a, b) => a.seq - b.seq); }
  /** True when the fields join the thread (the message `skip` left out of it): a reference to one of its messages and the same subject. */
  #joins(state, threadId, fields, skip = null) {
    const thread = this.#thread(state, threadId).filter(message => message.id !== skip);
    if (!thread.length) return false;
    const named = new Set([...idsIn(valueOf(fields, 'in-reply-to')), ...idsIn(valueOf(fields, 'references'))]);
    return thread.some(message => named.has(messageIdOf(message))) && subjectKey(fields) === subjectKey(entity(thread[0].text).fields);
  }
  /** The thread a written message goes in: the given one when it joins it, else null (its own); a threadId of no thread answers 404. */
  #place(state, threadId, fields, skip = null) {
    if (threadId === undefined || threadId === null) return null;
    if (typeof threadId !== 'string' || !threadId) invalid('Invalid thread_id value');
    if (!this.#thread(state, threadId).length) notFound();
    return this.#joins(state, threadId, fields, skip) ? threadId : null;
  }
  /** The thread mail that arrives joins: the thread of a message it names, by the same rule. */
  #incoming(state, fields) {
    const named = new Set([...idsIn(valueOf(fields, 'in-reply-to')), ...idsIn(valueOf(fields, 'references'))]);
    if (!named.size) return null;
    for (const message of Object.values(state.messages).sort((a, b) => a.seq - b.seq)) {
      if (named.has(messageIdOf(message)) && this.#joins(state, message.threadId, fields)) return message.threadId;
    }
    return null;
  }
  /** The recipients of a message to send; none answers 400. */
  #recipients(fields) {
    const recipients = recipientsOf(fields);
    if (!recipients.length) invalid('Recipient address required');
    return recipients;
  }
  /** Sends: a Message-ID when there is none, SENT (and INBOX and UNREAD when the owner is a recipient), one copy per recipient without Bcc. */
  #sent(state, text, recipients, threadId) {
    const stamped = valueOf(entity(text).fields, 'message-id') === undefined ? `Message-ID: <${hex(`message-id:${state.next.message}`).slice(0, 24)}@mail.gmail.com>\r\n${text}` : text;
    const own = recipients.some(address => fold(address) === fold(state.owner.email));
    const message = this.#commit(state, {text: stamped, labelIds: ['SENT', ...(own ? ['INBOX', 'UNREAD'] : [])], threadId});
    const copy = base64url(withoutBcc(stamped)), seen = new Set();
    for (const address of recipients) {
      if (seen.has(fold(address))) continue;
      seen.add(fold(address));
      state.deliveries.push({to: address, messageId: message.id, raw: copy});
    }
    return ok({id: message.id, threadId: message.threadId, labelIds: [...message.labelIds]});
  }
  /** The format a read asks for (raw only where `raw`), and the metadata headers it names. */
  #format(query, {raw = true} = {}) {
    const format = query.get('format') ?? 'full';
    if (!FORMATS.has(format) || (!raw && format === 'raw')) invalid('Invalid value for: format');
    return {format, wanted: query.getAll('metadataHeaders').map(fold)};
  }
  #render(message, {format = 'full', wanted = []} = {}) {
    const root = partOf(message.text, '');
    const out = {id: message.id, threadId: message.threadId, labelIds: [...message.labelIds], snippet: snippetOf(root), sizeEstimate: message.text.length,
      historyId: message.historyId, internalDate: String(message.internalDate)};
    if (format === 'raw') return {...out, raw: base64url(message.text)};
    if (format === 'metadata') return {...out, payload: {mimeType: root.mimeType, headers: root.headers.filter(item => !wanted.length || wanted.includes(fold(item.name)))}};
    return format === 'full' ? {...out, payload: root} : out;
  }
  #threadAnswer(state, id) {
    const thread = this.#thread(state, id);
    return {id, historyId: thread.map(message => message.historyId).reduce((high, value) => BigInt(value) > BigInt(high) ? value : high), messages: thread.map(message => ({id: message.id, threadId: message.threadId, labelIds: [...message.labelIds]}))};
  }
  #labels(state) { return [...SYSTEM_LABELS.map(id => ({id, name: id, type: 'system'})), ...Object.values(state.labels).map(label => ({...label}))]; }
  #labelOf(state, id) { return SYSTEM_LABELS.includes(id) ? {id, name: id, type: 'system'} : state.labels[id] ?? null; }
  /** A list of label ids a modify or filter names: each one known, never SENT or DRAFT. */
  #labelIds(state, list, name) {
    if (list === undefined) return [];
    if (!Array.isArray(list) || list.some(id => typeof id !== 'string')) invalid(`Invalid value for: ${name}`);
    for (const id of list) if (!this.#labelOf(state, id) || FIXED.has(id)) invalid(`Invalid label: ${id}`);
    return list;
  }
  #modifyRequest(state, body, fields) {
    known(body, fields, 'request');
    const add = this.#labelIds(state, body.addLabelIds, 'addLabelIds'), remove = this.#labelIds(state, body.removeLabelIds, 'removeLabelIds');
    if (add.some(id => remove.includes(id))) invalid('A label cannot be added and removed at once.');
    return {add, remove};
  }
  #change(state, messages, add, remove) {
    for (const message of messages) {
      const added = add.filter(id => !message.labelIds.includes(id)), removed = remove.filter(id => message.labelIds.includes(id));
      if (!added.length && !removed.length) continue;
      message.labelIds = [...message.labelIds, ...added].filter(id => !remove.includes(id));
      message.historyId = this.#history(state);
      if (added.length) this.#log(state, message, 'labelsAdded', added);
      if (removed.length) this.#log(state, message, 'labelsRemoved', removed);
    }
  }
  /** A page of `items` at `token`, `max` a page: {items, next}. A token is opaque and names the list it came from. */
  #page(items, token, max, list = 'messages') {
    let start = 0;
    if (token !== null) {
      const decoded = Buffer.from(token, 'base64url').toString('utf8'), place = decoded.startsWith(`${list}:`) ? decoded.slice(list.length + 1) : '';
      if (!/^[0-9]{1,6}$/.test(place) || Buffer.from(decoded).toString('base64url') !== token) invalid('Invalid pageToken');
      start = Number(place);
    }
    return {items: items.slice(start, start + max), next: start + max < items.length ? Buffer.from(`${list}:${start + max}`).toString('base64url') : null};
  }
  #matches(state, message, {operator, value}) {
    const {fields} = entity(message.text), field = name => decodeWords(valuesOf(fields, fold(name)).join(', '));
    if (Object.hasOwn(SEARCHED, operator)) return holds(field(SEARCHED[operator]), value);
    if (operator === 'label') return message.labelIds.some(id => id === value || fold(this.#labelOf(state, id)?.name ?? '') === fold(value));
    if (operator === 'has') return hasAttachment(partOf(message.text, ''));
    if (operator === 'after') return message.internalDate >= Number(value) * 1000;
    if (operator === 'before') return message.internalDate < Number(value) * 1000;
    if (operator === 'newer_than') return message.internalDate >= this.clock() - parseInt(value, 10) * DAY_MS;
    return holds([field('Subject'), field('From'), field('To'), field('Cc'), textOf(partOf(message.text, '')) ?? ''].join('\n'), value);
  }

  // ---- the routes ----------------------------------------------------------------------------------------------------------------------
  #routes = null;
  get routes() {
    return this.#routes ??= [
      {method: 'GET', template: '/profile', scopes: PROFILE, handle: ({state}) => {
        const messages = Object.values(state.messages);
        return ok({emailAddress: state.owner.email, messagesTotal: messages.length, threadsTotal: new Set(messages.map(message => message.threadId)).size, historyId: state.historyId});
      }},
      {method: 'GET', template: '/history', scopes: READ, handle: ctx => this.#historyList(ctx)},
      {method: 'GET', template: '/messages', scopes: READ, handle: ctx => this.#list(ctx)},
      {method: 'GET', template: '/messages/{id}', scopes: READ, handle: ({state, params, query}) => {
        const view = this.#format(query);
        return ok(this.#render(state.messages[params.id] ?? notFound(), view));
      }},
      {method: 'POST', template: '/messages/send', write: true, scopes: SEND, handle: ({state, body}) => {
        known(body, MESSAGE_FIELDS, 'message');
        const text = rawText(body.raw), {fields} = entity(text), recipients = this.#recipients(fields);
        return this.#sent(state, text, recipients, this.#place(state, body.threadId, fields));
      }},
      {method: 'POST', template: '/messages/batchModify', write: true, scopes: MODIFY, handle: ({state, body}) => {
        known(body, ['ids', ...MODIFY_FIELDS], 'request');
        if (!Array.isArray(body.ids) || !body.ids.length || body.ids.length > MAX_BATCH || body.ids.some(id => typeof id !== 'string')) invalid('ids must name 1 to 1,000 messages.');
        const {add, remove} = this.#modifyRequest(state, body, ['ids', ...MODIFY_FIELDS]), messages = body.ids.map(id => state.messages[id] ?? notFound());
        this.#change(state, [...new Set(messages)], add, remove);
        return {status: 204, data: null};
      }},
      {method: 'POST', template: '/messages/{id}/trash', write: true, scopes: MODIFY, handle: ctx => this.#trash(ctx, 'message', true)},
      {method: 'POST', template: '/messages/{id}/untrash', write: true, scopes: MODIFY, handle: ctx => this.#trash(ctx, 'message', false)},
      {method: 'GET', template: '/threads/{id}', scopes: READ, handle: ({state, params, query}) => {
        const view = this.#format(query, {raw: false}), thread = this.#thread(state, params.id);
        if (!thread.length) notFound();
        return ok({id: params.id, historyId: this.#threadAnswer(state, params.id).historyId, messages: thread.map(message => this.#render(message, view))});
      }},
      {method: 'POST', template: '/threads/{id}/modify', write: true, scopes: MODIFY, handle: ({state, params, body}) => {
        const thread = this.#thread(state, params.id);
        if (!thread.length) notFound();
        const {add, remove} = this.#modifyRequest(state, body, MODIFY_FIELDS);
        this.#change(state, thread, add, remove);
        return ok(this.#threadAnswer(state, params.id));
      }},
      {method: 'POST', template: '/threads/{id}/trash', write: true, scopes: MODIFY, handle: ctx => this.#trash(ctx, 'thread', true)},
      {method: 'POST', template: '/threads/{id}/untrash', write: true, scopes: MODIFY, handle: ctx => this.#trash(ctx, 'thread', false)},
      {method: 'POST', template: '/drafts', write: true, scopes: COMPOSE, handle: ({state, body}) => {
        known(body, DRAFT_FIELDS, 'draft');
        const {message, text} = this.#draftMessage(body), stored = this.#commit(state, {text, labelIds: ['DRAFT'], threadId: this.#place(state, message.threadId, entity(text).fields)});
        const id = this.#draftId(state);
        state.drafts[id] = stored.id;
        return ok({id, message: {id: stored.id, threadId: stored.threadId, labelIds: ['DRAFT']}});
      }},
      {method: 'GET', template: '/drafts/{id}', scopes: DRAFT_READ, handle: ({state, params, query}) => {
        const view = this.#format(query);
        return ok({id: params.id, message: this.#render(state.messages[state.drafts[params.id] ?? notFound()], view)});
      }},
      {method: 'PUT', template: '/drafts/{id}', write: true, scopes: COMPOSE, handle: ({state, params, body}) => {
        const old = state.drafts[params.id] ?? notFound();
        known(body, DRAFT_FIELDS, 'draft');
        if (body.id !== undefined && body.id !== params.id) invalid('The draft id in the body is not the one in the path.');
        const {message, text} = this.#draftMessage(body), threadId = this.#place(state, message.threadId, entity(text).fields, old);
        this.#deleted(state, state.messages[old]);
        delete state.messages[old];
        const stored = this.#commit(state, {text, labelIds: ['DRAFT'], threadId});
        state.drafts[params.id] = stored.id;
        return ok({id: params.id, message: {id: stored.id, threadId: stored.threadId, labelIds: ['DRAFT']}});
      }},
      {method: 'POST', template: '/drafts/send', write: true, scopes: COMPOSE, handle: ({state, body}) => {
        known(body, DRAFT_FIELDS, 'draft');
        if (typeof body.id !== 'string' || !body.id) invalid('Draft id is required.');
        const draft = state.messages[state.drafts[body.id] ?? notFound()], given = body.message === undefined ? null : known(body.message, MESSAGE_FIELDS, 'draft.message');
        const text = given?.raw !== undefined ? rawText(given.raw) : draft.text, {fields} = entity(text), recipients = this.#recipients(fields);
        const threadId = given?.threadId !== undefined ? this.#place(state, given.threadId, fields, draft.id) : this.#joins(state, draft.threadId, fields, draft.id) ? draft.threadId : null;
        this.#deleted(state, draft);
        delete state.messages[draft.id];
        delete state.drafts[body.id];
        return this.#sent(state, text, recipients, threadId);
      }},
      {method: 'GET', template: '/labels', scopes: LABEL_READ, handle: ({state}) => ok({labels: this.#labels(state)})},
      {method: 'GET', template: '/labels/{id}', scopes: LABEL_READ, handle: ({state, params}) => {
        const label = this.#labelOf(state, params.id) ?? notFound(), messages = Object.values(state.messages).filter(message => message.labelIds.includes(label.id));
        const unread = messages.filter(message => message.labelIds.includes('UNREAD')), threads = list => new Set(list.map(message => message.threadId)).size;
        return ok({...label, messagesTotal: messages.length, messagesUnread: unread.length, threadsTotal: threads(messages), threadsUnread: threads(unread)});
      }},
      {method: 'POST', template: '/labels', write: true, scopes: LABEL_WRITE, handle: ({state, body}) => {
        known(body, LABEL_FIELDS, 'label');
        if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 225) invalid('Invalid label name');
        if (body.labelListVisibility !== undefined && !LABEL_LIST.has(body.labelListVisibility)) invalid('Invalid value for: labelListVisibility');
        if (body.messageListVisibility !== undefined && !MESSAGE_LIST.has(body.messageListVisibility)) invalid('Invalid value for: messageListVisibility');
        if (this.#labels(state).some(label => fold(label.name) === fold(body.name))) refuse(409, 'alreadyExists', 'Label name exists or conflicts');
        const label = {id: `Label_${state.next.label++}`, name: body.name, type: 'user', ...(body.labelListVisibility === undefined ? {} : {labelListVisibility: body.labelListVisibility}),
          ...(body.messageListVisibility === undefined ? {} : {messageListVisibility: body.messageListVisibility})};
        state.labels[label.id] = label;
        return ok({...label});
      }},
      {method: 'GET', template: '/settings/vacation', scopes: SETTINGS_READ, handle: ({state}) => ok({...state.vacation})},
      {method: 'PUT', template: '/settings/vacation', write: true, scopes: SETTINGS_WRITE, handle: ({state, body}) => {
        known(body, VACATION_FIELDS, 'vacation');
        for (const name of VACATION_FLAGS) if (body[name] !== undefined && typeof body[name] !== 'boolean') invalid(`Invalid value for: ${name}`);
        for (const name of VACATION_TEXTS) if (body[name] !== undefined && typeof body[name] !== 'string') invalid(`Invalid value for: ${name}`);
        for (const name of ['startTime', 'endTime']) if (body[name] !== undefined && (typeof body[name] !== 'string' || !/^[0-9]{1,16}$/.test(body[name]))) invalid(`Invalid value for: ${name}`);
        if (body.startTime !== undefined && body.endTime !== undefined && BigInt(body.endTime) <= BigInt(body.startTime)) invalid('The end time must be after the start time.');
        if (body.restrictToDomain === true) refuse(400, 'failedPrecondition', 'Only a Google Workspace account can restrict the auto-reply to its domain.');
        state.vacation = {...structuredClone(body), enableAutoReply: body.enableAutoReply === true};
        return ok({...state.vacation});
      }},
      {method: 'POST', template: '/settings/filters', write: true, scopes: SETTINGS_WRITE, handle: ctx => this.#filter(ctx)},
      {method: 'GET', template: '/settings/filters/{id}', scopes: SETTINGS_READ, handle: ({state, params}) => ok(structuredClone(state.filters[params.id] ?? notFound()))},
    ].map(route => ({...route, key: `${route.method} ${route.template}`, parts: route.template.slice(1).split('/').map(part => /^\{\w+\}$/.test(part) ? {param: part.slice(1, -1)} : {literal: part})}));
  }

  #draftMessage(body) {
    const message = known(body.message ?? {}, MESSAGE_FIELDS, 'draft.message');
    return {message, text: message.raw === undefined ? '' : rawText(message.raw, {empty: true})};
  }
  /** maxResults, 1 to 500, 100 when not given. */
  #pageSize(query) {
    const given = query.get('maxResults'), max = given === null ? 100 : Number(given);
    if (given !== null && (!/^[0-9]{1,4}$/.test(given) || max < 1 || max > 500)) invalid('Invalid value for: maxResults');
    return max;
  }
  /** One record as an answer shows it, or nothing when its types or its label leave it out. */
  #shown(state, record, types, labelId) {
    const entries = (types.length ? types : Object.keys(HISTORY_TYPES)).map(type => HISTORY_TYPES[type]).filter(field => record[field])
      .map(field => [field, record[field].map(({message: {id, threadId, labelIds}, ...rest}) => ({message: {id, threadId, ...(this.historySettings.labels ? {labelIds} : {})}, ...rest}))]);
    if (!entries.length || (labelId !== null && !record.messages.some(({id}) => state.messages[id]?.labelIds.includes(labelId)))) return [];
    return [{id: record.id, messages: record.messages.map(message => ({...message})), ...Object.fromEntries(entries)}];
  }
  #historyList({state, query}) {
    const start = query.get('startHistoryId'), max = this.#pageSize(query), types = query.getAll('historyTypes');
    if (start === null || !/^[0-9]{1,20}$/.test(start)) invalid('Invalid value for: startHistoryId');
    for (const type of types) if (!Object.hasOwn(HISTORY_TYPES, type)) invalid('Invalid value for: historyTypes');
    const after = BigInt(start), {keepHours, emptyHoldsId} = this.historySettings, lost = keepHours === null ? [] : state.history.filter(record => record.at < this.clock() - keepHours * HOUR_MS);
    if (after < BigInt(state.historyFloor) || after > BigInt(state.historyId) || (lost.length && after < BigInt(lost.at(-1).id))) notFound();
    const found = state.history.filter(record => BigInt(record.id) > after).flatMap(record => this.#shown(state, record, types, query.get('labelId')));
    const page = this.#page(found, query.get('pageToken'), max, `history:${start}`);
    return ok({...(page.items.length ? {history: page.items} : {}), ...(page.next ? {nextPageToken: page.next} : {}), ...(page.items.length || emptyHoldsId ? {historyId: state.historyId} : {})});
  }
  #list({state, query}) {
    const max = this.#pageSize(query);
    const terms = parseQuery(query.get('q') ?? ''), everything = query.get('includeSpamTrash') === 'true', labels = query.getAll('labelIds');
    const found = Object.values(state.messages).filter(message => !terms.length || message.searchableAt <= this.clock()).sort((a, b) => b.internalDate - a.internalDate || b.seq - a.seq)
      .filter(message => (everything || !message.labelIds.some(id => LEFT_OUT.has(id))) && labels.every(id => message.labelIds.includes(id)) && terms.every(term => this.#matches(state, message, term) !== term.negated));
    const page = this.#page(found, query.get('pageToken'), max);
    return ok({...(page.items.length ? {messages: page.items.map(message => ({id: message.id, threadId: message.threadId}))} : {}), ...(page.next ? {nextPageToken: page.next} : {}), resultSizeEstimate: found.length});
  }
  #trash({state, params}, kind, into) {
    const messages = kind === 'message' ? [state.messages[params.id] ?? notFound()] : this.#thread(state, params.id);
    if (!messages.length) notFound();
    this.#change(state, messages, into ? ['TRASH'] : [], into ? [] : ['TRASH']);
    return ok(kind === 'message' ? {id: messages[0].id, threadId: messages[0].threadId, labelIds: [...messages[0].labelIds]} : this.#threadAnswer(state, params.id));
  }
  #filter({state, body}) {
    known(body, ['id', 'criteria', 'action'], 'filter');
    const criteria = known(body.criteria ?? {}, CRITERIA_FIELDS, 'filter.criteria'), action = known(body.action ?? {}, ACTION_FIELDS, 'filter.action');
    if (!Object.keys(criteria).length) invalid('A filter needs at least one criterion.');
    if (!Object.keys(action).length) invalid('A filter needs at least one action.');
    for (const name of CRITERIA_TEXTS) if (criteria[name] !== undefined && (typeof criteria[name] !== 'string' || !criteria[name])) invalid(`Invalid value for: criteria.${name}`);
    for (const name of ['hasAttachment', 'excludeChats']) if (criteria[name] !== undefined && typeof criteria[name] !== 'boolean') invalid(`Invalid value for: criteria.${name}`);
    if (criteria.size !== undefined && !Number.isSafeInteger(criteria.size)) invalid('Invalid value for: criteria.size');
    if (criteria.sizeComparison !== undefined && !['larger', 'smaller'].includes(criteria.sizeComparison)) invalid('Invalid value for: criteria.sizeComparison');
    if (action.forward !== undefined) {
      if (!this.scopes.has(SHARING)) refuse(403, 'insufficientPermissions', 'Request had insufficient authentication scopes.');
      refuse(400, 'failedPrecondition', 'Forwarding address is not verified.');
    }
    for (const name of ['addLabelIds', 'removeLabelIds']) {
      if (action[name] !== undefined && (!Array.isArray(action[name]) || action[name].some(id => typeof id !== 'string' || !this.#labelOf(state, id)))) invalid(`Invalid label in action.${name}`);
    }
    const filter = {criteria: structuredClone(criteria), action: structuredClone(action)};
    if (Object.values(state.filters).some(item => canonical({criteria: item.criteria, action: item.action}) === canonical(filter))) refuse(400, 'failedPrecondition', 'Filter already exists');
    const id = `ANe1Bm${hex(`filter:${state.next.filter++}`).slice(0, 26)}`;
    state.filters[id] = {id, ...filter};
    return ok(structuredClone(state.filters[id]));
  }

  /** The route a method and a decoded path below users/{userId} take, with its parameters; literals win over parameters. */
  #routeOf(method, path) {
    const segments = path === '/' ? [] : path.slice(1).split('/').map(segment => { try { return decodeURIComponent(segment); } catch { return segment; } });
    let best = null;
    for (const route of this.routes) {
      if (route.method !== method || route.parts.length !== segments.length) continue;
      const params = {};
      let score = 0;
      const fits = route.parts.every((part, index) => {
        if (part.literal !== undefined) { score += 2; return part.literal === segments[index]; }
        params[part.param] = segments[index];
        score += 1;
        return segments[index] !== '';
      });
      if (fits && (!best || score > best.score)) best = {route, params, score};
    }
    return best;
  }

  async request({url, method = 'GET', headers = {}, body, allowedOrigins, maxBytes = 2 * 1024 * 1024, responseType = 'json', redirect = 'error', responseHeaders = DEFAULT_RESPONSE_HEADERS, timeoutMs = 15000}) {
    let target;
    try { target = new URL(url); } catch { throw notSent('Invalid request URL.'); }
    if (target.protocol !== 'https:' || target.username || target.password || target.hash || (target.port && target.port !== '443')) throw notSent('Only credential-free HTTPS URLs on port 443 are allowed.');
    if (!Array.isArray(allowedOrigins) || !allowedOrigins.includes(target.origin)) throw notSent('Request origin is outside the connection grant.');
    if (!['json', 'buffer'].includes(responseType) || !['error', 'report'].includes(redirect) || !Array.isArray(responseHeaders)) throw notSent('Unsupported response handling.');
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000 || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 10 * 1024 * 1024) throw notSent('Invalid request limits.');
    if (!/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(method)) throw notSent('Unsupported HTTP method.');
    const lower = {};
    for (const [name, value] of Object.entries(headers)) {
      if (UNSAFE_HEADER.test(name) || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name) || typeof value !== 'string' || /[\r\n]/.test(value)) throw notSent('Unsafe request header.');
      lower[name.toLowerCase()] = value;
    }
    if (body !== undefined && !(typeof body === 'string' || Buffer.isBuffer(body))) throw notSent('Request body must be serialized.');
    if (body !== undefined && Buffer.byteLength(body) > 1024 * 1024) throw notSent('Request body is too large.');
    if (target.origin !== ORIGIN) throw notSent('Provider DNS lookup failed or timed out.');
    // Sent from here on: the call is recorded, without its Authorization header.
    const below = target.pathname.startsWith(USERS) ? target.pathname.slice(USERS.length) : '', slash = below.indexOf('/');
    let user = null;
    if (slash > 0) { try { user = decodeURIComponent(below.slice(0, slash)); } catch { user = below.slice(0, slash); } }
    const path = user === null ? target.pathname : below.slice(slash), found = user === null ? null : this.#routeOf(method, path);
    const raw = body === undefined ? undefined : Buffer.isBuffer(body) ? body.toString('utf8') : body;
    let parsed;
    if (raw !== undefined) { try { parsed = JSON.parse(raw); } catch { parsed = raw; } }
    const query = {};
    for (const [name, value] of target.searchParams) query[name] = Object.hasOwn(query, name) ? [query[name]].flat().concat(value) : value;
    const {authorization, ...kept} = lower;
    const call = {method, origin: target.origin, path, user, route: found?.route.key ?? null, query, headers: kept, body: parsed, write: found?.route.write === true, status: null};
    this.calls.push(call);
    const gate = found ? this.holds.get(found.route.key) : null;
    if (gate) { gate.reach(); await gate.released; }
    const chosen = found ? this.#take(found.route.key) : null;
    let answer;
    if (authorization !== `Bearer ${this.token}`) answer = googleError(401, 'authError', 'Invalid Credentials');
    else if (!found) answer = googleError(404, 'notFound', 'Requested entity was not found.');
    else if (user !== 'me') answer = googleError(400, 'invalidArgument', 'Invalid user id specified in request/Delegation denied');
    else if (!found.route.scopes.some(scope => this.scopes.has(scope))) answer = googleError(403, 'insufficientPermissions', 'Request had insufficient authentication scopes.');
    else if (chosen?.kind === 'fail') answer = structuredClone(chosen.answer);
    else {
      const state = chosen?.kind === 'swallow' ? structuredClone(this.data) : this.data;
      try {
        if (raw !== undefined && typeof parsed === 'string') refuse(400, 'parseError', 'Parse Error');
        answer = found.route.handle({params: found.params, query: target.searchParams, body: parsed, state});
      } catch (error) {
        if (!(error instanceof Refusal)) throw error;
        answer = error.answer;
      }
      if (chosen?.kind === 'drop') { call.status = answer.status; throw lost('Provider connection failed.'); }
      if (chosen?.kind === 'oversize') answer = {...answer, data: {...answer.data, padding: 'x'.repeat(Math.max(0, chosen.bytes))}};
    }
    call.status = answer.status;
    const headersOut = Object.fromEntries(Object.entries(answer.headers ?? {}).map(([name, value]) => [name.toLowerCase(), String(value)]));
    const bytes = answer.data === null || answer.data === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(answer.data), 'utf8');
    if (bytes.length > maxBytes) throw lost('Provider response exceeded the size limit.');
    if (bytes.length) headersOut['content-type'] ??= 'application/json; charset=UTF-8';
    const shown = {};
    for (const key of responseHeaders) if (headersOut[key] !== undefined) shown[key] = headersOut[key];
    // A fresh parse of the bytes, so nothing the caller holds shares memory with the simulator's state.
    return {status: answer.status, headers: shown, data: responseType === 'buffer' ? bytes : bytes.length ? JSON.parse(bytes.toString('utf8')) : null};
  }
}

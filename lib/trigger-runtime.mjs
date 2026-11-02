// Iteration 9 part 2b (docs/I07-BUILD-MAP.md sections 2.2 to 2.4): one poll. runPoll() reads one feed with the action runner's own pieces (createJob,
// buildRequest, checkConcrete, the credential checks), so every request is placed and checked as an action's is, and answers plain data: what the
// scheduler of part 2c must store, in order, and how the next poll should run. It has no timers and writes no document, event or seen row. It reads
// seen rows through the store, and only observeGrant() and narrowOnMissingScope() change anything, each on the account, as they do for an action.
//
// The sender is send() of lib/actions-runtime.mjs without its job: the same checks in the same order, no write spacing and no audit row, so a poll writes
// no audit row. Nothing is retried, a redirect is reported and never followed, and a cursor comes only from a provider's answer. `authority()` is the
// gate, as part 2c binds it: it asks before and after credentials, for every request, so a row turned to Never mid-poll is seen at the next request.
//
// Outcomes. `done` read to the end. `cut` stopped short with its progress kept, and `onward` set when the next poll starts further on. `not_modified` a 304. `resynced` a seed replaced the cursor. `limited` a
// provider asked for a wait. `backoff` a failure that pauses nothing. `paused` see `pause`. `scope_missing` the provider says the account lacks a scope, and
// the scheduler pauses it. `withheld` no live subscription remained, so nothing is stored and the gate says why. `skipped` a gate skip. Only `done`, `cut`, `resynced`
// and an enrich read's `limited` or `backoff` hold anything to store.
import {createHash} from 'node:crypto';
import {canonicalHash} from './compiler.mjs';
import {resolvePointer} from './permission-groups.mjs';
import {scrubValue} from './redaction.mjs';
import {LIMITS, proxyBase} from './proxy-request.mjs';
import {addedHeaders, providerHeaders} from './proxy-runtime.mjs';
import {BOUNDS, ITEM_TIME_FORMATS} from './actions.mjs';
import {ABSENT, ACTION_REFUSED, RESPONSE_HEADERS, actionRefused, assertNoCredential, buildRequest, checkConcrete, createJob, credentialContext, evaluate, holds, holdsCredential, newFrame, nextPage,
  passes, providerReason, scrubAnswer, stepData} from './actions-runtime.mjs';
import {apiRuleOf, apiVerdict, narrowOnMissingScope} from './api-success.mjs';
import {grantHeaderOf, observeGrant, providerOf, takeGrantHeader} from './grant-drift.mjs';
import {paceCheck} from './slack-limits.mjs';
import {PAUSE_ERRORS, WINDOWS, gapPayload, limitAnswer, placeLostAt, refusedCode, retentionMs, windowOf} from './trigger-rules.mjs';
import {TRIGGER_BOUNDS, checkEvent, triggerLens} from './triggers.mjs';
import {runIn} from './transforms/run.mjs';
import {TransformError} from './transforms/_shared/error.v1.mjs';

/** Section 2.4: what a poll asks of an answer. A grant header, when the provider has one, joins this list. */
export const POLL_HEADERS = Object.freeze([...RESPONSE_HEADERS, 'x-poll-interval', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'x-ratelimit-used']);
const RFC3339 = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})$/;
const fits = pattern => value => typeof value === 'string' && pattern.test(value);
/** Section 2.4: the form of each cursor kind, stored or incoming. A snapshot's cursor is its seen rows, so it has no value to check. */
export const CURSOR_CHECKS = Object.freeze({
  'history-id@1': fits(/^[0-9]{1,20}$/),
  'sync-token@1': fits(/^[\x20-\x7e]{1,2048}$/),
  'high-water-time@1': value => fits(RFC3339)(value) && Number.isFinite(Date.parse(value)),
  'high-water-ts@1': fits(/^[0-9]{1,10}\.[0-9]{6}$/),
  'etag@1': fits(/^[\x20-\x7e]{1,512}$/),
  'last-modified@1': fits(/^[\x20-\x7e]{1,64}$/),
});
const CONDITIONAL = new Set(['etag@1', 'last-modified@1']), HIGH_WATER = new Set(['high-water-time@1', 'high-water-ts@1']);
/** Section 2.3 and default 30: what a body cursor binds after a baseline that found no row. It is not a provider value, so no feed ever stores it. */
const NO_ROW_YET = '1970-01-01T00:00:00.000Z';
const RESUME_REFUSED = new Set([400, 404, 410]);
/** A next page, as checked() reads it. A cut sync walk stores it, so it is a place like a cursor: one that carries the credential is no place. Its form is the next poll's to check. */
const PAGE = Object.freeze({kind: 'page'});
const RECORD_TRIES = 5, BUDGET_STOPS = 3, UNREAD_TOLD_MS = 86_400_000, SEEN_LIMIT = 5000, SNAPSHOT_SEEN_LIMIT = 2000, DECIMAL = 'time.decimalCompare@1', LINK_PAGE = 'ids.linkPage@1', NOTION_ID = 'ids.notionId@1', OWNER_REPO = 'ids.ownerRepo@1';
/** Ends a poll with nothing stored: its outcome, and any of `pause`, `wait` and `code`. */
class Stop extends Error {
  constructor(outcome, fields = {}) { super(outcome); Object.assign(this, {outcome}, fields); }
}
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const sha256 = text => createHash('sha256').update(text).digest('hex');
const refusal = error => error?.code === ACTION_REFUSED && record(error.details);
/** canonicalHash() throws a plain Error on a value it will not hash, such as one with a key named __proto__, and `equals` hashes what it compares. Such a value reads as a refusal. */
const unhashable = error => error?.constructor === Error && /^JSON: /.test(error.message);
const invalid = detail => new Stop('paused', {pause: {reason: 'cursor_invalid', detail}});
const asText = time => typeof time === 'number' ? new Date(time).toISOString() : String(time);
const digits = (value, most) => typeof value === 'string' && new RegExp(`^[0-9]{1,${most}}$`).test(value.trim()) ? Number(value.trim()) : null;
const liveLenses = state => state.lenses.filter(lens => lens.live && !lens.gone);
/** Every object of a JSON value, a constant's content aside. */
function* nodes(value) {
  if (Array.isArray(value)) for (const item of value) yield* nodes(item);
  else if (record(value) && !Object.hasOwn(value, 'const')) { yield value; for (const item of Object.values(value)) yield* nodes(item); }
}

// ---- reading an answer ------------------------------------------------------------------------------------------------------------------------
/** One assertion over an answer. A value it cannot compare holds nothing. */
function asserted(node, frame, answer) {
  try { return holds(node, frame, answer); } catch (error) { if (unhashable(error)) return false; throw error; }
}
/** An /error branch with a constant: the one form of a reviewed alternative to an app's success rule. */
const errorBranch = branch => Object.keys(branch).length === 1 && record(branch.equals) && branch.equals.pointer === '/error' && record(branch.equals.value) && Object.hasOwn(branch.equals.value, 'const');
/** A 2xx of an app with a success rule, held to it as an action's is (lib/actions-runtime.mjs ruleFails()). Returns the verdict of a refused answer, or null. */
function ruleFails(context, step, answer, frame) {
  if (!context.apiRule) return null;
  const verdict = apiVerdict(context.apiRule, answer.data);
  if (verdict.state === 'ok' || step.expect.require.some(node => Object.hasOwn(node, 'anyOf') && node.anyOf.some(branch => errorBranch(branch) && asserted(branch, frame, answer)))) return null;
  return verdict;
}
/**
 * Section 2.4's outcome table for one answer, as {is, detail?}: `ok`; `not_modified`; `limited`; `failed`, which backs off; `refused`, which pauses
 * provider_refused; or `scope`, with its verdict. `context` is {appId, apiRule}. A status the step lists counts as an answer, and a 304 reads before any
 * status test. A resync status is the walk's to read first, since only it knows a cursor was sent.
 */
export function judgeAnswer(context, step, answer, frame) {
  const {status} = answer, code = `http_${status}`;
  if (answer.notModified) return {is: 'not_modified'};
  if (answer.redirected) return {is: 'refused', detail: 'moved'};
  if (refusedCode(context.appId, answer)) return {is: 'refused', detail: refusedCode(context.appId, answer)};
  if (status === 429 || status === 529 || limitAnswer(context.appId, answer)) return {is: 'limited'};
  if (status === 401 || status >= 500) return {is: 'failed', detail: code};
  if (!step.expect.status.includes(status)) return status >= 400 ? {is: 'refused', detail: providerReason(context.appId, answer) ?? code} : {is: 'failed', detail: code};
  if (status < 200 || status >= 300) return {is: 'ok'};
  const verdict = ruleFails(context, step, answer, frame);
  if (verdict?.error === 'missing_scope') return {is: 'scope', verdict};
  if (verdict) return PAUSE_ERRORS.includes(verdict.error) ? {is: 'refused', detail: verdict.error} : {is: 'failed', detail: verdict.error};
  return step.expect.require.every(node => asserted(node, frame, answer)) ? {is: 'ok'} : {is: 'failed', detail: 'require_failed'};
}
/**
 * The wait a limit answer sets, as {until, reason, method?}. `until` is a time, or null when the answer names none and the backoff decides. Retry-After counts in
 * full, whatever its size. GitHub with none waits for its reset when its count is spent, and otherwise at least a minute. A Slack wait names its method.
 */
export function waitOf(appId, answer, step, now) {
  const headers = answer.headers ?? {}, seconds = digits(headers['retry-after'], 7), reset = digits(headers['x-ratelimit-reset'], 12);
  const until = seconds !== null ? now + seconds * 1000 : appId !== 'github' ? null : headers['x-ratelimit-remaining'] === '0' && reset !== null ? reset * 1000 : now + 60_000;
  return {until, reason: 'limited', ...(appId === 'slack' ? {method: step.path.slice(1)} : {})};
}
/** What a judged answer that did not pass does to a source or seed step: the Stop that ends the poll with nothing stored. */
function stopFor(state, step, answer, verdict) {
  if (verdict.is === 'limited') return new Stop('limited', {wait: waitOf(state.appId, answer, step, state.runtime.clock())});
  if (verdict.is === 'failed') return new Stop('backoff', {code: verdict.detail});
  if (verdict.is === 'refused') return new Stop('paused', {pause: {reason: 'provider_refused', detail: verdict.detail}});
  narrowOnMissingScope(state.runtime, state.feed.connectionId, verdict.verdict);
  return new Stop('scope_missing', {code: 'missing_scope'});
}
/** A source or seed step's answer, or the Stop it ends the poll with. Answers true for a 304. */
function accepted(state, step, answer, frame) {
  const verdict = judgeAnswer(state, step, answer, frame);
  if (verdict.is === 'ok' || verdict.is === 'not_modified') return verdict.is === 'not_modified';
  throw stopFor(state, step, answer, verdict);
}

// ---- the sender ------------------------------------------------------------------------------------------------------------------------------
/** What one more request may spend: a timeout within the budget left, or null when a bound stops the walk (`lib/proxy-request.mjs` refuses a timeout under one second). */
function room(state) {
  const left = state.until - state.runtime.clock();
  if (state.requests >= BOUNDS.requests || state.bytes > BOUNDS.jobBytes || left < LIMITS.timeoutMin) return null;
  return Math.min(left, LIMITS.timeoutDefault);
}
/** One step's exact request, placed again as an action's is. A trigger has no record of its own, so its step mode is the Allow the gate read. */
function built(state, item, step, frame, cursor, timeoutMs) {
  const {route, runtime} = state;
  let made;
  try { made = buildRequest(item.entry, step, frame, {config: route.config, pinned: item.pinnedParameters ?? {}, provider: providerHeaders(runtime, state.appId), cursor, timeoutMs}); }
  catch (error) { if (error instanceof URIError) throw actionRefused('value_unreadable'); throw error; }
  const placed = checkConcrete(item.entry, step.id, made, {definition: route.definition, config: route.config, map: route.map, typed: state.typed, typedMode: capability => runtime.proxyPolicy.typed(route.connection, capability).mode, stepMode: 'allow'});
  return {...placed, maxBytes: step.maxResponseBytes ?? BOUNDS.responseBytes};
}
/** The gate, as `authority(item, lensId)`. With a lens, whether a live subscription of it remains: if none, it drops out of this poll. With none, whether any remains. A skip ends the poll. */
function held(state, lens = null) {
  const answer = lens ? state.authority(lens.item, lens.id) : state.authority();
  if (answer?.ok === true) return true;
  if (answer?.skip === true) throw new Stop('skipped', {code: answer.detail});
  if (!lens) throw new Stop('withheld');
  lens.gone = true;
  return false;
}
/** What the last answer said about the account's grant, applied once (lib/grant-drift.mjs). */
function settleGrant(state) {
  const seen = state.grantSeen;
  state.grantSeen = null;
  if (seen) observeGrant(state.runtime, seen.connection, seen);
}
/** A poll's job and frames hold the credential context from the first fetch, and again only if the credential changed, since each new context reads every kept output. */
function useCredentials(state, context) {
  const key = context.values.join('\n');
  state.secrets = context;
  if (key === state.secretKey) return;
  state.secretKey = key;
  for (const job of state.jobs.values()) job.useCredentials(context);
}
function noteAnswer(state, answer) {
  const interval = digits(answer.headers['x-poll-interval'], 7), now = state.runtime.clock();
  if (interval !== null) state.notBefore = Math.max(state.notBefore ?? 0, now + interval * 1000);
  const remaining = digits(answer.headers['x-ratelimit-remaining'], 9), reset = digits(answer.headers['x-ratelimit-reset'], 12);
  if (remaining !== null) state.rate = {remaining, ...(reset === null ? {} : {resetAt: reset * 1000})};
  state.status = answer.status;
  // Notion's query says it stopped at its own cap. The walk goes on from its mark, so this asks nothing of the poll: it is a line for the run.
  if (answer.data?.request_status?.type === 'incomplete') state.note = 'incomplete';
}
/**
 * Sends one built request: section 1's send() without its job. The gate holds before the credentials, since a refresh is a network call, and again after them. Answers {answer},
 * scrubbed and with the grant header taken off; or {failure}, one of `timeout`, `response_too_large`, `connection_failed` and `live_guard`; or {dropped} when `lens` lost its last
 * subscription. Nothing is retried.
 */
async function send(state, made, lens = null) {
  const {runtime, feed} = state, {request} = made;
  if (!held(state, lens)) return {dropped: true};
  settleGrant(state);
  let authority;
  try { authority = await runtime.connections.credentials(feed.connectionId); } catch { throw new Stop('backoff', {code: 'credentials'}); }
  const context = credentialContext(authority.headers);
  useCredentials(state, context);
  assertNoCredential([feed.resource, state.subscriptions.map(subscription => subscription.args)], context);
  assertNoCredential([request.url, ...Object.values(request.headers), request.body], context);
  const current = runtime.store.get('connections', feed.connectionId);
  if (!current || current.status === 'revoked' || canonicalHash(current.identity || {}) !== state.identityHash) throw new Stop('withheld', {code: 'account_changed'});
  if (!held(state, lens)) return {dropped: true};
  const base = proxyBase(state.route.config.apiBase), providerId = providerOf(runtime, current), grantHeader = grantHeaderOf(providerId);
  if (!Array.isArray(authority.allowedOrigins) || !authority.allowedOrigins.includes(base.origin)) throw new Stop('backoff', {code: 'proxy_unavailable'});
  const {Authorization: credential, Accept: _accept, ...provider} = authority.headers;
  if (canonicalHash(addedHeaders(request, provider)) !== canonicalHash(made.added)) throw new Stop('backoff', {code: 'prepared_changed'});
  const headers = {...request.headers, ...provider, ...(credential ? {Authorization: credential} : {}), Accept: request.headers.Accept || 'application/json', ...(request.body !== null ? {'Content-Type': 'application/json; charset=utf-8'} : {})};
  const paced = paceCheck(runtime, current, request);
  if (paced) throw new Stop('limited', {code: paced.reason, wait: {until: paced.retryAfterSeconds === undefined ? null : runtime.clock() + paced.retryAfterSeconds * 1000, reason: 'limited', method: new URL(request.url).pathname.split('/').pop()}});
  let response;
  state.requests++;
  try {
    response = await runtime.request({url: request.url, method: request.method, headers, ...(request.body !== null ? {body: request.body} : {}), allowedOrigins: [base.origin], timeoutMs: request.timeoutMs, maxBytes: made.maxBytes,
      responseType: 'json', redirect: 'report', responseHeaders: [...POLL_HEADERS, ...(grantHeader ? [grantHeader] : [])]});
  } catch (error) {
    if (error?.sent === false && refusal(error)) return {failure: 'live_guard'};
    return {failure: /timed out/i.test(error?.message) ? 'timeout' : /size limit/i.test(error?.message) ? 'response_too_large' : 'connection_failed'};
  }
  // A small answer can still nest deeper than scrubbing can follow, and nothing unscrubbed goes further.
  try {
    const taken = takeGrantHeader(response.headers, providerId);
    const answer = scrubAnswer({status: response.status, headers: taken.headers, data: response.data ?? null, ...(response.redirected ? {redirected: true} : {}), ...(response.notModified ? {notModified: true} : {})}, context);
    state.grantSeen = {connection: current, providerId, value: taken.value, status: answer.status, data: answer.data};
    state.bytes += Buffer.byteLength(JSON.stringify(answer.data));
    noteAnswer(state, answer);
    return {answer};
  } catch (error) { if (error instanceof RangeError) return {failure: 'response_too_large'}; throw error; }
}
/** One read of a source or seed step, or null when a bound stops it. Its failures end the poll. */
async function read(state, step, frame, token = null) {
  const timeoutMs = room(state);
  if (timeoutMs === null) return null;
  const made = built(state, state.owner, step, frame, token, timeoutMs), {answer, failure} = await send(state, made);
  if (failure === 'response_too_large') throw new Stop('paused', {pause: {reason: 'too_many_items', detail: failure}});
  if (failure) throw new Stop('backoff', {code: failure});
  return {answer, url: made.request.url};
}

// ---- time and cursors ---------------------------------------------------------------------------------------------------------------------------
/** -1, 0 or 1 by the named pinned transform: seconds, BigInt or Slack's microseconds, and never a float. A value it cannot read throws its TransformError. */
function compared(state, compare, a, b) {
  const {job} = state;
  if (compare === 'time.rfc3339ToEpochSeconds@1') return Math.sign(job.transform(compare, {time: a}).seconds - job.transform(compare, {time: b}).seconds);
  if (compare === 'time.slackTs@1') return job.transform(compare, {ts: a, than: b}).order;
  return job.transform(compare, {a, b}).order;
}
/** compared() of two cursor values. One it cannot read is a place Fabric cannot trust. */
function order(state, compare, a, b) {
  try { return compared(state, compare, a, b); } catch (error) { if (error instanceof TransformError) throw invalid(compare); throw error; }
}
/** The later of two values, either of which may be undefined. */
const later = (state, compare, a, b) => a === undefined ? b : b === undefined ? a : order(state, compare, a, b) > 0 ? a : b;
/** The item's time as a string, or null when it has none that its format can read. */
function timeOf(state, item) {
  if (!state.timeCompare) return null;
  const raw = resolvePointer(item, state.poll.itemTime.pointer), text = typeof raw === 'number' ? String(raw) : raw;
  if (typeof text !== 'string') return null;
  try { compared(state, state.timeCompare, text, text); return text; } catch (error) { if (error instanceof TransformError) return null; throw error; }
}
/** A time moved by whole seconds, in its kind's own form. A Slack ts moves as BigInt, so its microseconds stay exact. */
function shifted(kind, value, seconds) {
  if (kind === 'high-water-time@1') return new Date(Date.parse(value) + seconds * 1000).toISOString();
  const [whole, fraction] = value.split('.'), moved = BigInt(whole) + BigInt(seconds);
  return `${moved < 0n ? 0n : moved}.${fraction}`;
}
/** What a mark sends: less its overlap, or one second on the poll after a cut asc poll, whose overlap would only re-read a drain, and never below the floor. */
function sentMark(state, cursor, mark) {
  const sent = shifted(cursor.kind, mark, -(state.feed.draining ? 1 : cursor.overlapSeconds ?? 0));
  return state.floor !== null && order(state, cursor.compare, sent, state.floor) < 0 ? state.floor : sent;
}
const cursorsIn = value => new Set([...nodes(value)].map(node => node.cursor).filter(name => typeof name === 'string'));
/** Binds the cursors page 1 sends. A conditional cursor goes on page 1 only, and a resumed walk has passed page 1. */
function bind(state) {
  const {bound, cursors, feed, pollStep} = state, body = cursorsIn(pollStep.body);
  bound.clear();
  for (const cursor of state.poll.cursors) {
    const {name, kind} = cursor, value = cursors[name];
    if (kind === 'snapshot@1' || (CONDITIONAL.has(kind) && feed.page)) continue;
    if (value !== undefined) bound.set(name, HIGH_WATER.has(kind) ? sentMark(state, cursor, value) : value);
    else if (kind === 'high-water-time@1' && body.has(name)) bound.set(name, NO_ROW_YET);
  }
}
/** An incoming value, held to its kind's form. A value that carries the credential, or was scrubbed of it, is no cursor. */
function checked(state, cursor, value) {
  const check = CURSOR_CHECKS[cursor.kind];
  if ((check && !check(value)) || String(value).includes('[redacted]') || (state.secrets && holdsCredential(value, state.secrets))) throw invalid(cursor.kind);
  return value;
}
/** A cursor's next value from the walk's last answer. A last-page cursor has none on a walk that stopped short, and an absent value keeps the old one. */
function incoming(state, cursor) {
  const answer = cursor.lastPageOnly && state.cut !== null ? null : state.last, value = answer ? resolvePointer(answer.data, cursor.next.pointer) : undefined;
  return value === undefined || value === null ? undefined : checked(state, cursor, value);
}
function checkStored(state) {
  for (const cursor of state.poll.cursors) {
    const value = state.cursors[cursor.name], check = CURSOR_CHECKS[cursor.kind];
    if (value !== undefined && check && !check(value)) throw invalid(cursor.kind);
  }
  const token = state.feed.page?.token;
  if (token !== null && token !== undefined && !Number.isSafeInteger(token) && !CURSOR_CHECKS['sync-token@1'](token)) throw invalid('page');
}

// ---- gaps --------------------------------------------------------------------------------------------------------------------------------------
/** Notes a gap of this poll, ranging from when the cursor last moved, or from `from`. Its key follows that time, so a replay stores nothing twice and a later gap gets a new key. */
function noteGap(state, reason, from) {
  const {feed, now} = state, start = from ?? (reason === 'resync' ? placeLostAt(feed) : feed.lastGoodAt);
  state.gaps.push({reason, from: asText(start ?? feed.createdAt ?? now), to: asText(state.runtime.clock())});
}
/** Who hears of this feed now: an active subscription, or a starting one that finished this feed. */
const receives = (state, subscription) => subscription.status === 'active' || (subscription.status === 'starting' && !(subscription.pending ?? []).includes(state.feed.id));
/** Each gap as one row for each subscription that hears of this feed. */
function gapRows(state) {
  const kept = Math.max(...state.entries.map(item => retentionMs(item.entry.trigger.retention)));
  const heard = new Map(liveLenses(state).flatMap(lens => lens.subscriptions).filter(subscription => receives(state, subscription)).map(subscription => [subscription.id, subscription]));
  return state.gaps.flatMap(({reason, from, to}) => {
    const payload = gapPayload(reason, from, to);
    return [...heard.values()].map(subscription => ({clientId: subscription.clientId, subscriptionId: subscription.id, dedupeKey: payload.id, connectionId: state.feed.connectionId, userRecordId: subscription.userRecordId ?? null,
      kind: 'trigger.gap', createdAt: state.now, expiresAt: state.now + kept, payload}));
  });
}

// ---- one item ----------------------------------------------------------------------------------------------------------------------------------
const keyOf = (state, lens, id) => sha256(`${state.feed.id}|${lens.id}|${id}`);
const rowOf = (state, lens, key) => lens.rows.get(key) ?? state.store.seenRows(state.feed.id, lens.id, [key]).get(key);
function put(state, lens, key, row, fresh) {
  lens.rows.set(key, row);
  if (!fresh) return;
  lens.wrote = true;
  state.newKey = true;
}
/** Section 2.2: the value a seen row compares. `id` compares none, and an absent field hashes as null. */
function valueOf(lens, item, frame) {
  const {dedupe, poll} = lens.trigger;
  if (dedupe.kind === 'id') return '';
  const value = dedupe.kind === 'id+version' ? resolvePointer(item, poll.itemVersion) ?? null : dedupe.fields.map(node => { const read = evaluate(node, frame); return read === ABSENT ? null : read; });
  try { return canonicalHash({kind: 'fabric-trigger-value', value}); } catch { throw actionRefused('value_unreadable'); }
}
/** The id of an item as text or a safe integer, or null for a partial item. */
function idOf(lens, frame) {
  let id;
  try { id = evaluate(lens.trigger.poll.itemId, frame); } catch (error) { if (refusal(error)) return null; throw error; }
  return (typeof id === 'string' && id) || Number.isSafeInteger(id) ? id : null;
}
/** dedupe.knownBy: the first present value must have a seen row in this lens, or this change is a create. */
function knownTo(state, lens, frame) {
  for (const node of lens.trigger.dedupe.knownBy) {
    const value = evaluate(node, frame);
    if (value !== ABSENT && value !== null) return Boolean(rowOf(state, lens, keyOf(state, lens, value)));
  }
  return false;
}
/**
 * One subscription's event: built by its own trigger with its args, held by checkEvent(), scrubbed, and scanned as an action's bytes are. Null for one that fails, which is skipped and counted.
 * Two triggers can share a lens and differ here, and a watch holds only what its own card lists.
 */
function eventOf(state, {entry}, frame, subscription, itemId) {
  const block = entry.trigger.event, own = {...frameOf(state, state.jobs.get(entry.id), entry.trigger, subscription.args), item: frame.item, steps: frame.steps}, fields = {};
  try {
    for (const [name, node] of Object.entries(block.fields)) { const value = evaluate(node, own); if (value !== ABSENT) fields[name] = value; }
    const summary = block.summary.map(line => {
      const value = evaluate(line.expr, own);
      if (value === ABSENT || value === null) return undefined;
      return typeof value === 'string' && line.truncate !== undefined ? [...value].slice(0, line.truncate).join('') : value;
    });
    const event = checkEvent(entry, {itemId, id: evaluate(block.id, own), occurredAt: evaluate(block.occurredAt, own), fields, summary});
    const lines = block.summary.flatMap((line, index) => summary[index] === undefined ? [] : [{label: line.label, value: summary[index]}]);
    const payload = assertNoCredential(scrubValue({type: 'trigger.event', id: event.id, occurredAt: event.occurredAt, fields: event.fields, summary: lines}, state.secrets), state.secrets);
    return Buffer.byteLength(JSON.stringify(payload)) > TRIGGER_BOUNDS.eventBytes ? null : payload;
  } catch { return null; }
}
/** An item's time as the number the store sorts by, in one unit for the poll. */
function timeNumber(state, time) {
  const value = state.poll.itemTime.format === 'rfc3339' ? Date.parse(time) : Number(time);
  return Number.isFinite(value) ? value : undefined;
}
function fire(state, lens, frame, {id, key, valueHash, generation, time}) {
  const dedupeKey = `${key}|${valueHash}|${generation}`, itemTime = time === null ? undefined : timeNumber(state, time);
  for (const subscription of lens.subscriptions) {
    if (!receives(state, subscription)) continue;
    const item = lens.owners.get(subscription.id), payload = eventOf(state, item, frame, subscription, id);
    if (payload === null) { state.skipped++; noteStall(state); continue; }
    lens.events.push({clientId: subscription.clientId, subscriptionId: subscription.id, dedupeKey, connectionId: state.feed.connectionId, userRecordId: subscription.userRecordId ?? null, kind: 'trigger.event',
      createdAt: state.now, expiresAt: state.now + retentionMs(item.entry.trigger.retention), payload, ...(itemTime === undefined ? {} : {itemTime})});
  }
}
/** A real item that cannot be told, which must not be lost in silence: one gap a poll says so. */
function noteStall(state) {
  if (!state.gaps.some(gap => gap.reason === 'stall')) noteGap(state, 'stall');
}
/** An item Fabric stops trying to read. Its seen row keeps it from coming back, or a list that still shows it would give a gap at every poll. */
function giveUp(state, lens, at) {
  put(state, lens, at.key, {valueHash: '', generation: at.row?.generation ?? 0}, !at.row);
  noteStall(state);
}
/** An enrich failure that ends the walk: what the answer says sets the wait or backoff. After 5 polls fail on one item it takes a seen row and one stall gap, so it cannot hold a feed. */
function enrichFailed(state, lens, at, failure) {
  lens.stopped = true;
  state.failure = failure;
  state.recordFailures = lens.wrote ? 1 : state.recordFailures + 1;
  if (state.recordFailures < RECORD_TRIES) return;
  giveUp(state, lens, at);
  state.recordFailures = 0;
}
/** One enrich request, reusing an answer for the same request within the poll. Answers it, or null when this item goes no further. */
async function enrichRead(state, lens, step, frame, at) {
  if (!held(state, lens)) return null;
  const timeoutMs = room(state);
  if (timeoutMs === null) { lens.stopped = true; return null; }
  let made;
  try { made = built(state, lens.item, step, frame, null, timeoutMs); } catch (error) { if (!refusal(error)) throw error; state.skipped++; giveUp(state, lens, at); return null; }
  const key = `${made.request.method} ${made.request.url} ${made.request.bodyHash}`;
  if (state.answers.has(key)) return state.answers.get(key);
  if (state.requests >= lens.until) { lens.stopped = true; return null; }
  const {answer, failure, dropped} = await send(state, made, lens);
  if (dropped) return null;
  if (failure === 'live_guard') { state.skipped++; return null; }
  if (failure === 'response_too_large') { state.skipped++; giveUp(state, lens, at); return null; }
  if (failure) { enrichFailed(state, lens, at, {outcome: 'backoff', code: failure}); return null; }
  const verdict = judgeAnswer(state, step, answer, frame);
  if (verdict.is === 'ok') { state.answers.set(key, answer); return answer; }
  if (verdict.is === 'scope') throw stopFor(state, step, answer, verdict);
  if (verdict.is === 'limited') enrichFailed(state, lens, at, {outcome: 'limited', wait: waitOf(state.appId, answer, step, state.runtime.clock())});
  else if (verdict.is === 'refused' && answer.status === 404) state.skipped++;
  else if (verdict.is === 'refused') dropLens(state, lens, verdict.detail, 'provider_refused');
  else enrichFailed(state, lens, at, {outcome: 'backoff', code: verdict.detail ?? 'not_modified'});
  return null;
}
/** Runs a live lens's enrich steps for one item, within enrich.max. True when each step answered, so the event can read it. */
async function enrich(state, lens, frame, at) {
  if (lens.enriched >= lens.enrichBlock.max) { lens.stopped = true; return false; }
  lens.enriched++;
  for (const step of lens.enrichBlock.steps) {
    const answer = await enrichRead(state, lens, step, frame, at);
    if (answer === null) return false;
    try { frame.steps.set(step.id, {status: answer.status, headers: answer.headers, data: stepData(step, [answer])}); } catch (error) { if (!refusal(error)) throw error; state.skipped++; giveUp(state, lens, at); return false; }
  }
  return true;
}
/**
 * An item an answered read turned down takes a seen row, as one it told does, or each poll would read it again and spend its reads on what it already knows it will not report. An item whose read did
 * not answer has gone, so it takes none.
 */
function turnedDown(state, lens, frame, {key, row, generation}) {
  if (!row && lens.enrichBlock.steps.every(step => frame.steps.get(step.id).status < 300)) put(state, lens, key, {valueHash: '', generation}, true);
}
/**
 * The filter tests that read an enrich answer. That answer holds one item, so a refusal here says that item is more than Fabric can read, as an answer too large does. It goes alone, with its seen row and one
 * gap, or one mail a stranger shaped would stop the watch, and every Resume would stop on it again.
 */
function keepsItem(state, lens, frame, at) {
  try { return lens.after.every(test => passes(test, frame)); } catch (error) {
    if (!refusal(error) && !unhashable(error)) throw error;
    state.skipped++;
    giveUp(state, lens, at);
    return null;
  }
}
/** Section 2.2's eight steps for one item of one lens. */
async function readItem(state, lens, item) {
  const frame = {...lens.frame, item, steps: new Map(state.steps)}, {dedupe} = lens.trigger;
  if (state.history) {
    const record = resolvePointer(item, '/recordId');
    if (record !== lens.record) { if (lens.record !== undefined) lens.finished = lens.record; lens.record = record; }
  }
  const time = timeOf(state, item);
  if (time !== null) lens.mark = later(state, state.timeCompare, time, lens.mark);
  const id = idOf(lens, frame);
  if (!lens.before.every(test => passes(test, frame))) return;
  if (id === null || (state.timeCompare && time === null)) { state.skipped++; return; }
  const key = keyOf(state, lens, id), row = rowOf(state, lens, key), generation = row?.generation ?? 0;
  if (row) lens.known++;
  if (row && dedupe.kind === 'id') { if (state.snapshot) lens.rows.set(key, row); return; }
  if (!lens.live) { if (!lens.enrichBlock && !state.history) put(state, lens, key, {valueHash: valueOf(lens, item, frame), generation}, !row); return; }
  if (state.silent) { put(state, lens, key, {valueHash: valueOf(lens, item, frame), generation}, !row); return; }
  if (state.snapshot && !row && time !== null && state.floor !== null && order(state, state.timeCompare, time, state.floor) < 0) { put(state, lens, key, {valueHash: valueOf(lens, item, frame), generation}, true); return; }
  if (lens.enrichBlock) {
    if (!await enrich(state, lens, frame, {key, row})) return;
    const kept = keepsItem(state, lens, frame, {key, row});
    if (kept === false) turnedDown(state, lens, frame, {key, row, generation});
    if (!kept) return;
  }
  const valueHash = valueOf(lens, item, frame), fires = !row || (dedupe.kind !== 'id' && row.valueHash !== valueHash);
  if (!fires || (dedupe.knownBy !== undefined && !knownTo(state, lens, frame))) {
    if (!row || row.valueHash !== valueHash) put(state, lens, key, {valueHash, generation}, !row);
    else if (state.snapshot) lens.rows.set(key, row);
    return;
  }
  put(state, lens, key, {valueHash, generation: generation + 1}, !row);
  fire(state, lens, frame, {id, key, valueHash, generation: generation + 1, time});
}
/** A lens that stops for this poll and pauses, or leaves the feed if nobody watches it: a transform's refusal or the provider's, as the scheduler reads `lensPauses`. */
function dropLens(state, lens, code, reason = 'too_many_items') {
  lens.gone = true;
  state.lensPauses.push({lens: lens.id, code, reason});
}

// ---- one page ----------------------------------------------------------------------------------------------------------------------------------
const listOf = value => value === ABSENT ? [] : Array.isArray(value) ? value : [value];
/** One run of a lens's items over this page, never over joined pages, so a transform's own limit holds. A history feed reads the items and where the page was cut together. */
function itemsOf(state, lens) {
  const {items} = lens.trigger.poll;
  if (!state.history) return {items: listOf(evaluate(items, lens.frame))};
  const whole = evaluate(Object.hasOwn(items, 'pick') ? {...items, pointer: ''} : items, lens.frame);
  return record(whole) && Array.isArray(whole.items) ? {items: whole.items, through: whole.throughRecordId} : {items: listOf(whole)};
}
async function readLens(state, lens) {
  const {items, through} = itemsOf(state, lens), fired = lens.events.length;
  lens.read += items.length;
  state.items = Math.max(state.items, lens.read);
  for (const item of items) {
    await readItem(state, lens, item);
    if (lens.stopped || lens.gone) return;
  }
  lens.firedAtEnd = lens.events.length > fired;
  if (!state.history) return;
  lens.finished = through ?? later(state, DECIMAL, state.pageRecord, lens.record);
  if (through !== undefined) lens.stopped = true;
  // A first record too large to hold whole is named with no items: nothing of it can be told, and only this says so.
  if (through !== undefined && !items.length && lens.live && !state.silent) noteStall(state);
}
async function readLenses(state) {
  let waiting = liveLenses(state).filter(lens => !lens.stopped).length;
  for (const lens of state.lenses) {
    if (lens.gone || lens.stopped) continue;
    // A poll's requests are shared, what one lens leaves going to the next. A lens that reads nothing holds a history feed's cursor for all of them, so none may spend what the others need.
    if (lens.live) lens.until = state.requests + Math.ceil((BOUNDS.requests - state.requests) / waiting--);
    try { await readLens(state, lens); } catch (error) {
      if (!refusal(error) && !unhashable(error)) throw error;
      dropLens(state, lens, unhashable(error) ? 'value_unreadable' : error.details.reason);
    }
    if (state.failure) return;
  }
}
/** Runs `read`, and turns a refusal of a whole answer into its pause: it came before any lens read the page, and a next link that cannot be trusted is the provider's. */
function wholeAnswer(read) {
  try { return read(); } catch (error) {
    if (!refusal(error)) throw error;
    throw new Stop('paused', {pause: error.details.transform === LINK_PAGE ? {reason: 'provider_refused', detail: 'link_invalid'} : {reason: 'too_many_items', detail: error.details.reason}});
  }
}
/** This answer as the frames read it, and the next page. `pages: 0` keeps nextPage() from refusing at page.max: a poll stops there and keeps its progress. */
function pageOf(state, step, answer, url) {
  return wholeAnswer(() => {
    const data = stepData(step, [answer]), last = Array.isArray(data) ? resolvePointer(data.at(-1), '/id') : undefined;
    state.steps.set(step.id, {status: answer.status, headers: answer.headers, data});
    state.pageRecord = CURSOR_CHECKS['history-id@1'](last) ? last : undefined;
    return step.page === undefined ? null : nextPage(step, answer, {pages: 0, job: state.job, url});
  });
}

// ---- the walk ----------------------------------------------------------------------------------------------------------------------------------
/**
 * Slack's method pages say fewer than `limit` may come back before the end, so a short page says nothing of how long a list is, and it spends none of a walk's pages. The request and time budgets still hold
 * the walk. Calendar's and Notion's lists page short too, but a cut walk there keeps its place, and only Slack's whole lists and newest-first feeds must end inside one poll.
 */
const shortPage = (state, step, list) => state.appId === 'slack' && Array.isArray(list) && list.length < step.query?.limit?.const;
/** The list item a seed's cursor reads a field of, when that field is the time the poll reads each item by. Any other field can be missing from a whole item: a Slack thread with no replies has no latest_reply. */
function seedItem(state, answer, pointer) {
  const [, item, field] = /^(.*\/[0-9]+)(\/[^/]+)$/.exec(pointer) ?? [];
  return item === undefined || field !== state.poll.itemTime?.pointer ? undefined : resolvePointer(answer.data, item);
}
async function readSeed(state) {
  const {seed} = state.poll, got = await read(state, seed.step, state.frame);
  if (!got) throw new Stop('backoff', {code: 'budget'});
  accepted(state, seed.step, got.answer, state.frame);
  const value = resolvePointer(got.answer.data, seed.cursor.pointer);
  // A first item with no value in it is no empty list: a partial object says nothing of the time, and reading it as empty would make every row new.
  if ((value === undefined || value === null) && record(seedItem(state, got.answer, seed.cursor.pointer))) throw new Stop('backoff', {code: 'seed_partial'});
  return value === undefined || value === null ? undefined : checked(state, state.poll.cursors.find(cursor => cursor.name === seed.cursor.name), value);
}
/** A new feed's seed. A body cursor with no value leaves its parent behind, so with none the seed takes the poll step's place. */
async function seedFirst(state) {
  const {poll, feed, cursors} = state, name = poll.seed?.cursor.name;
  if (!poll.seed || feed.baselined) return;
  if (cursors[name] === undefined) { const value = await readSeed(state); if (value !== undefined) cursors[name] = value; }
  state.seedOnly = cursors[name] === undefined && cursorsIn(state.pollStep.body).has(name);
}
/** The steps before the poll step, each once a poll, and in full: only the poll step's walk stops short. */
async function readEarlier(state) {
  for (const step of state.earlier) {
    const answers = [];
    for (let token = null, more = true; more;) {
      const got = await read(state, step, state.frame, token);
      if (!got) throw new Stop('backoff', {code: 'budget'});
      accepted(state, step, got.answer, state.frame);
      answers.push(got.answer);
      const next = step.page === undefined ? null : wholeAnswer(() => nextPage(step, got.answer, {pages: answers.length, job: state.job, url: got.url}));
      more = next !== null;
      token = next?.cursor ?? null;
    }
    const [{status, headers}] = answers.slice(-1);
    state.steps.set(step.id, {status, headers, data: wholeAnswer(() => stepData(step, answers))});
  }
}
/** Whether this answer means the provider no longer knows the place the poll sent. Only a poll that sent one can lose it, and one refused resume has lost it too. */
function lostPlace(state, answer, token) {
  if (state.resynced || (token === null && state.bound.size === 0)) return false;
  return state.poll.resync.statusIn.includes(answer.status) || (token !== null && token === state.feed.page?.token && RESUME_REFUSED.has(answer.status));
}
/** Section 2.4's resync row. With a seed the cursor is replaced now and the poll ends. With none the cursor drops and this walk runs silently from the top. Answers true when the poll is over. */
async function resync(state) {
  const {poll, feed} = state;
  state.resynced = true;
  for (const cursor of poll.cursors) delete state.cursors[cursor.name];
  if (!poll.seed) {
    state.silent = true;
    state.resync = feed.baselined === true;
    bind(state);
    return false;
  }
  const value = await readSeed(state);
  if (value === undefined) throw new Stop('backoff', {code: 'seed_empty'});
  state.cursors[poll.seed.cursor.name] = value;
  state.seeded = true;
  return true;
}
async function walk(state) {
  const step = state.pollStep, most = Math.min(state.bounds.pages, step.page?.max ?? 1);
  let token = state.token;
  bind(state);
  for (;;) {
    const got = await read(state, step, state.frame, token);
    if (!got) { state.cut = 'budget'; return; }
    const {answer, url} = got;
    if (lostPlace(state, answer, token)) {
      if (await resync(state)) return;
      token = state.token = null;
      continue;
    }
    for (const cursor of state.poll.cursors) if (CONDITIONAL.has(cursor.kind)) state.bound.delete(cursor.name);
    if (accepted(state, step, answer, state.frame)) { state.notModified = true; return; }
    const next = pageOf(state, step, answer, url);
    state.pages++;
    if (!shortPage(state, step, state.steps.get(step.id).data)) state.fullPages++;
    state.first ??= answer;
    state.last = answer;
    await readLenses(state);
    if (!liveLenses(state).length) throw new Stop('withheld');
    if (state.failure) { state.cut = 'failed'; return; }
    if (liveLenses(state).some(lens => lens.stopped)) { state.cut = 'lens'; return; }
    if (next === null) return;
    token = state.token = checked(state, PAGE, next.cursor);
    if (state.fullPages >= most || state.items >= state.bounds.items) { state.cut = 'bounds'; return; }
  }
}

// ---- how a poll ends ---------------------------------------------------------------------------------------------------------------------------
function result(state, fields) {
  const {outcome, code, pause, wait, gap, unreadTo, onward, ...rest} = fields, events = {};
  for (const row of rest.events) if (row.kind === 'trigger.event') events[row.subscriptionId] = (events[row.subscriptionId] ?? 0) + 1;
  return {outcome, ...rest, notBefore: state.notBefore, lensPauses: state.lensPauses, ...(gap ? {gap} : {}), ...(unreadTo ? {unreadTo} : {}), ...(onward ? {onward} : {}), ...(pause ? {pause} : {}), ...(wait ? {wait} : {}), ...(state.rate ? {rate: state.rate} : {}),
    run: {at: state.now, outcome, status: state.status, requests: state.requests, items: state.items, skipped: state.skipped, events, ...(code ? {code} : {}), ...(state.note ? {note: state.note} : {})}};
}
/** A poll that stores nothing: the feed's own fields, as they were. */
function ended(state, {outcome, code, pause, wait}) {
  const {feed} = state;
  return result(state, {outcome, code, pause, wait, cursors: structuredClone(feed.cursors ?? {}), page: feed.page ?? null, floor: feed.floor ?? null, draining: feed.draining === true, budgetStops: feed.budgetStops ?? 0,
    recordFailures: feed.recordFailures ?? 0, unreadTo: feed.unreadTo ?? null, baselined: feed.baselined === true, lastGoodAt: feed.lastGoodAt ?? null, reachedEdge: false, seen: [], seenLimits: {}, events: []});
}
/** The next value of one high-water cursor, and what a stopped walk does to it (section 2.4's table and stall rule). `out` takes the feed fields it moves. */
function highWater(state, cursor, out) {
  const {cut, poll, silent} = state, {compare, name} = cursor, stored = state.cursors[name], present = state.lenses.filter(lens => !lens.gone);
  const marks = cursor.next.max ? present.map(lens => lens.mark) : [incoming(state, cursor)];
  const highest = marks.reduce((high, mark) => later(state, compare, mark, high), undefined);
  if (poll.order === 'asc') {
    const stopped = present.filter(lens => lens.stopped).map(lens => lens.mark);
    const reached = !stopped.length ? highest : stopped.includes(undefined) ? undefined : stopped.reduce((low, mark) => later(state, compare, mark, low) === mark ? low : mark);
    const next = later(state, compare, reached, stored);
    if (cut !== null) out.draining = state.pages > 0 || state.feed.draining === true;
    if (cut === 'bounds' && !state.newKey && stored !== undefined && order(state, compare, next, stored) <= 0) {
      if (!silent) noteGap(state, 'stall');
      out.floor = shifted(cursor.kind, next, 1);
    }
    return next;
  }
  const stops = cut === 'budget' || cut === 'lens' ? (state.feed.budgetStops ?? 0) + Math.min(state.pages, 1) : 0;
  if (cut === 'bounds' || stops >= BUDGET_STOPS) {
    const next = later(state, compare, highest, stored);
    // With more in an overlap than a walk can read, this stop comes at every poll, and a read that found nothing new adds nothing to what the last gap said. So one run of the cut tells once. A mark that held
    // has passed nothing, so an item past the bound stays inside the next read, and the gap that the mark's next move owes starts at this run. Only an unordered list owes its first stop a gap with nothing
    // new, since an item there can sit past the bound. On a newest-first list a new item sorts to the front, so nothing new means nothing lost.
    if (!silent && (state.newKey || next !== stored || (poll.order !== 'desc' && (state.feed.unreadTo ?? null) === null))) { noteGap(state, 'bound'); out.unreadTo = state.now; }
    out.edge = true;
    return next;
  }
  out.budgetStops = stops;
  return cut === null ? later(state, compare, highest, stored) : stored;
}
function historyNext(state, cursor) {
  const {compare, name} = cursor, stored = state.cursors[name];
  if (state.cut === null) return later(state, compare, incoming(state, cursor), stored);
  const finished = liveLenses(state).map(lens => lens.finished);
  if (finished.includes(undefined)) return stored;
  return later(state, compare, finished.reduce((low, id) => order(state, compare, id, low) < 0 ? id : low), stored);
}
/** A conditional cursor holds only for a whole walk of one page: any longer walk reads every page, and a 304 would hide what a shorter one left unread. */
function conditionalNext(state, cursor, cursors) {
  if (state.pages === 0) return;
  if (state.pages > 1 || state.cut !== null) { delete cursors[cursor.name]; return; }
  const value = state.first.headers[cursor.next.header];
  if (value !== undefined) cursors[cursor.name] = checked(state, cursor, value);
}
const seenOf = state => state.lenses.flatMap(lens => [...lens.rows].map(([itemKey, row]) => ({lens: lens.id, itemKey, ...row, connectionId: state.feed.connectionId})));
/** What each lens may hold: high-water, history and window feeds drop their oldest rows, since those items cannot come back. Past it, any other feed cannot tell new from changed. */
function seenLimitsOf(state) {
  const evict = state.poll.cursors.some(cursor => HIGH_WATER.has(cursor.kind) || cursor.kind === 'history-id@1') || Boolean(state.window);
  return Object.fromEntries(state.lenses.map(lens => [lens.id, {limit: state.snapshot ? SNAPSHOT_SEEN_LIMIT : SEEN_LIMIT, evict}]));
}
/**
 * A timed window on a list that keeps no order, cut by its bound. Section 2.3's "a window's bound is its reach" holds for a window with no set reach, whose bound is all it promises, and for a list that
 * keeps new items first. Here the window promises more than the bound reads, and a new item can sit past it, unseen by any read: one gap says so. A long list is cut at every poll, so this is told once a
 * day, each gap starting where the last ended, or it would bury real events.
 */
function noteUnread(state, out) {
  const told = state.feed.unreadTo ?? null;
  if (told !== null && state.now - told < UNREAD_TOLD_MS) return;
  noteGap(state, 'bound', told ?? undefined);
  out.unreadTo = state.now;
}
/** A poll that ran: its stop rules, its cursors and everything to store. */
function finish(state) {
  const {feed, poll, cut, silent} = state, cursors = {...state.cursors}, out = {floor: state.floor, draining: false, budgetStops: 0, page: null, edge: cut === null};
  out.unreadTo = cut === null ? null : feed.unreadTo ?? null;
  // A window's gap tells of what its silent read marks as seen, so it ends with that read, as a resync's does.
  for (const gap of state.gaps) if (gap.reason === 'window') gap.to = asText(state.runtime.clock());
  if (state.seeded) {
    if (feed.baselined) noteGap(state, 'resync');
    return result(state, {outcome: 'resynced', gap: state.gaps[0], cursors, page: null, floor: out.floor, draining: false, budgetStops: 0, recordFailures: 0, baselined: feed.baselined === true, lastGoodAt: state.now,
      unreadTo: out.unreadTo, reachedEdge: feed.baselined === true, seen: [], seenLimits: {}, events: gapRows(state)});
  }
  // A list with no paging has no next page to say more was there, so a read that fills its bound stops as a walk cut by it does. It is no cut: nothing more can be read, so the feed keeps its interval.
  const filled = cut === null && Boolean(state.window) && state.pollStep.page === undefined && state.items >= state.bounds.items;
  if (state.snapshot && (cut === 'bounds' || filled)) {
    if (!state.window) throw new Stop('paused', {pause: {reason: 'too_many_items', detail: 'bounds'}});
    out.edge = true;
    if (liveLenses(state).every(lens => lens.known === 0) && state.lenses.some(lens => lens.events.length)) {
      noteGap(state, 'overflow');
      for (const lens of state.lenses) lens.events = [];
    } else if (state.window.seconds && poll.order === 'unordered' && !silent) noteUnread(state, out);
    else if (cut === 'bounds' && poll.order === 'unordered' && state.lenses.some(lens => lens.firedAtEnd)) {
      // A list that is not in order can hide a new item past the bound, and Fabric cannot read there. An item new on the last page read is the sign that changes reach that far.
      // A new item nearer the top is no such sign: on a long list every read is cut, and a gap with every event would say nothing. A full read of a list with no paging has no page past it, so it owes nothing here.
      noteGap(state, 'bound');
    }
  }
  for (const cursor of poll.cursors) {
    const {kind, name} = cursor;
    if (kind === 'snapshot@1') continue;
    if (CONDITIONAL.has(kind)) { conditionalNext(state, cursor, cursors); continue; }
    const next = HIGH_WATER.has(kind) ? highWater(state, cursor, out) : kind === 'history-id@1' ? historyNext(state, cursor) : incoming(state, cursor) ?? cursors[name];
    if (next !== undefined) cursors[name] = checked(state, cursor, next);
  }
  const sync = poll.cursors.some(cursor => cursor.kind === 'sync-token@1');
  if (cut !== null && (sync || state.resync)) out.page = {token: sync ? state.token : null, walk: silent ? 'baseline' : 'delta'};
  if (state.resync && cut === null) noteGap(state, 'resync');
  if (state.snapshot && silent && out.edge && state.timeCompare) out.floor = later(state, state.timeCompare, state.lenses.reduce((high, lens) => later(state, state.timeCompare, lens.mark, high), undefined), state.floor ?? undefined) ?? null;
  // A resync walk still under way has found no place yet, so a later gap keeps its range from when the cursor was last good.
  const place = poll.cursors.filter(({kind}) => !CONDITIONAL.has(kind)), walking = state.resync && cut !== null, moved = !walking && (place.some(({name}) => cursors[name] !== feed.cursors?.[name]) || ((state.snapshot || !feed.baselined) && out.edge));
  // A cut walk runs again at once only if the next poll starts further on than this one did. A read that starts from the same place, as every read of a window does, gets no further for coming sooner.
  const onward = cut !== null && !out.edge && (place.some(({name}) => cursors[name] !== feed.cursors?.[name]) || (out.page?.token ?? null) !== (feed.page?.token ?? null));
  const {outcome = state.notModified ? 'not_modified' : cut === null ? 'done' : 'cut', wait, code} = state.failure ?? {};
  return result(state, {outcome, code, wait, gap: state.gaps[0], onward, cursors, page: out.page, floor: out.floor, draining: out.draining, budgetStops: out.budgetStops, recordFailures: state.failure ? state.recordFailures : 0,
    unreadTo: out.unreadTo, baselined: feed.baselined === true || out.edge, lastGoodAt: moved ? state.now : feed.lastGoodAt ?? null, reachedEdge: out.edge, seen: seenOf(state), seenLimits: seenLimitsOf(state),
    events: [...state.lenses.flatMap(lens => lens.events), ...gapRows(state)]});
}

// ---- starting a poll ----------------------------------------------------------------------------------------------------------------------------
/** WINDOWS as a poll reads it: `alerts` marks a window a subscription's lead sets, whose filter holds what has started, so its feed runs on after a sleep. */
export function windowRule(appId, key, args) {
  const rule = windowOf(appId, key, args);
  return rule && {...rule, alerts: WINDOWS[`${appId}.${key}`].minutesInput !== undefined};
}
/** A trigger's frame on this feed. `feed.resource` holds the resource's values by index, as triggerPollHash() numbers them, so the inputs of two triggers on one poll may have different names. */
function frameOf(state, job, trigger, args = {}) {
  const {resource} = trigger, values = state.feed.resource ?? [], named = Array.isArray(resource) ? Object.fromEntries(resource.map((name, index) => [name, values[index]])) : {};
  return {...newFrame(job, {...args, ...named}, state.steps), vars: new Map(Array.isArray(resource) ? [] : [[resource.as, values[0]]])};
}
/** The lenses `feed.lenses` tracks: the catalog's own, and the one each live subscription gives. A lens no trigger or subscription can give now has no way to read this poll. */
function lensesOf(state) {
  const found = new Map(), lensFor = (id, item) => {
    if (found.has(id)) return found.get(id);
    const {entry} = item, trigger = entry.trigger, block = trigger.poll.enrich ?? null, enrichIds = new Set((block?.steps ?? []).map(step => step.id));
    const late = test => [...nodes(test)].some(node => enrichIds.has(node.step)), filter = trigger.filter ?? [];
    const lens = {id, item, entry, trigger, enrichBlock: block, subscriptions: [], owners: new Map(), rows: new Map(), events: [], before: filter.filter(test => !late(test)), after: filter.filter(late), read: 0, known: 0, wrote: false, enriched: 0, stopped: false, gone: false};
    found.set(id, lens);
    return lens;
  };
  for (const item of state.entries) for (const id of item.lenses) lensFor(id, item);
  for (const subscription of state.subscriptions) {
    const item = state.entries.find(candidate => candidate.entry.id === subscription.triggerId);
    if (!item) continue;
    const lens = lensFor(triggerLens(item.entry, subscription.args), item);
    lens.subscriptions.push(subscription);
    lens.owners.set(subscription.id, item);
  }
  return (state.feed.lenses ?? []).filter(id => found.has(id)).map(id => {
    const lens = found.get(id);
    return Object.assign(lens, {live: lens.subscriptions.length > 0, frame: frameOf(state, state.jobs.get(lens.entry.id), lens.trigger, lens.subscriptions[0]?.args)});
  });
}
/** A snapshot feed's window: its triggers must all read one, and the shortest reach holds. Null for a whole list. */
function windowFor(state, windows) {
  if (!state.snapshot) return null;
  const rules = state.entries.map(item => {
    const args = state.subscriptions.find(subscription => subscription.triggerId === item.entry.id)?.args;
    return windows(item.appId, item.entry.key, frameOf(state, state.job, item.entry.trigger, args).input);
  });
  if (!rules.length || rules.some(rule => !rule)) return null;
  const reaches = rules.map(rule => rule.seconds).filter(seconds => Number.isFinite(seconds));
  return {seconds: reaches.length ? Math.min(...reaches) : null, alerts: rules.every(rule => rule.alerts === true)};
}
/** A timed window left unread for longer than it reaches: one gap, then a silent poll, unless its filter already holds back what passed. */
function noteSleep(state) {
  const {window, feed} = state;
  if (!window?.seconds || state.silent || typeof feed.lastGoodAt !== 'number' || state.now - feed.lastGoodAt <= window.seconds * 1000) return;
  noteGap(state, 'window');
  if (!window.alerts) state.silent = true;
}
function prepare(state, {entries, memo, deadline, windows}) {
  const {runtime, feed} = state, catalog = runtime.actions, owner = entries.find(item => Array.isArray(item.entry.trigger.poll.source?.steps));
  if (!owner) throw new Stop('backoff', {code: 'no_run_path'});
  let route;
  try { route = runtime.proxyPolicy.route(feed.connectionId); } catch { throw new Stop('backoff', {code: 'proxy_unavailable'}); }
  const trigger = owner.entry.trigger, {poll, bounds} = trigger, steps = poll.source.steps, walking = feed.page?.walk === 'baseline';
  const most = name => Math.min(bounds[name], ...entries.map(item => item.entry.trigger.bounds[name]));
  const bound = new Map(), jobs = new Map(entries.map(item => [item.entry.id, createJob({jobId: `${feed.id}:${item.entry.id}:${state.now}`, entry: item.entry, appId: item.appId, identity: route.connection.identity ?? {}, clock: runtime.clock,
    transforms: catalog.transforms, cursors: bound, now: state.now})]));
  Object.assign(state, {entries, owner, route, poll, bound, jobs, job: jobs.get(owner.entry.id), earlier: steps.slice(0, -1), pollStep: steps.at(-1), appId: feed.appId, apiRule: apiRuleOf(feed.appId, catalog.identityOf?.(feed.appId) ?? null),
    typed: runtime.permissions.memoized(memo, `${feed.connectionId}:typedTemplates`, () => runtime.proxyPolicy.typedTemplates(route)), identityHash: canonicalHash(route.connection.identity || {}), bounds: {pages: most('pages'), items: most('items')},
    until: Math.min(state.now + most('pollSeconds') * 1000, deadline ?? Infinity), cursors: structuredClone(feed.cursors ?? {}), floor: feed.floor ?? null, token: feed.page?.token ?? null, silent: !feed.baselined || walking, resync: feed.baselined === true && walking,
    snapshot: poll.cursors.some(cursor => cursor.kind === 'snapshot@1'), history: poll.cursors.some(cursor => cursor.kind === 'history-id@1'), timeCompare: poll.itemTime ? ITEM_TIME_FORMATS[poll.itemTime.format] : null});
  state.frame = frameOf(state, state.job, trigger);
  state.lenses = lensesOf(state);
  state.window = windowFor(state, windows);
  if (!liveLenses(state).length) throw new Stop('withheld');
}
/**
 * One poll of one feed. `entries` are the catalog's items on this poll (triggersOnPoll()), `subscriptions` the live ones whose args build events, `memo` the template list alone, for one tick,
 * and `authority(item?, lensId?)` the gate, answering as gate() does. `deadline`, when given, is a time this poll must end by; the feed's strictest pollSeconds holds as well. `windows` replaces
 * the table of windows, as a test does. Returns {outcome, cursors, page, floor, draining, budgetStops, recordFailures, notBefore, baselined, lastGoodAt, reachedEdge, seen, seenLimits, events, gap?, unreadTo?, onward?, pause?,
 * lensPauses: [{lens, code, reason}], wait?, rate?, run}, all plain data. `seen`, `seenLimits` and `events` go to store.appendPoll(), and only then the feed fields to the feed. Nothing here throws for
 * anything a provider sends.
 */
export async function runPoll({runtime, feed, entries, subscriptions, memo = new Map(), authority, deadline, windows = windowRule}) {
  const state = {runtime, feed, subscriptions, authority, store: runtime.store, now: runtime.clock(), cut: null, status: null, requests: 0, pages: 0, fullPages: 0, items: 0, skipped: 0, bytes: 0, notBefore: feed.notBefore ?? null, rate: null, lensPauses: [], steps: new Map(),
    answers: new Map(), grantSeen: null, secrets: null, secretKey: null, gaps: [], failure: null, recordFailures: feed.recordFailures ?? 0, newKey: false, resynced: false, seeded: false, seedOnly: false, notModified: false};
  try {
    prepare(state, {entries, memo, deadline, windows});
    checkStored(state);
    noteSleep(state);
    await readEarlier(state);
    await seedFirst(state);
    if (!state.seedOnly) await walk(state);
    return finish(state);
  } catch (error) {
    if (error instanceof Stop) return ended(state, error);
    if (refusal(error)) return ended(state, {outcome: 'backoff', code: error.details.reason});
    throw error;
  } finally { settleGrant(state); }
}

/** Default 48: how a resource value of each app reads as one spelling. GitHub reads a name in any case, and an owner/name rule holds only ASCII, so a name folds safely. */
const SPELLINGS = Object.freeze({notion: {transform: NOTION_ID, read: ({id}) => id}, github: {transform: OWNER_REPO, read: ({owner, repo}) => `${owner}/${repo}`.toLowerCase()}});
/**
 * Part 2b, default 48: a subscription's args as Fabric stores them, run at subscribe. Notion page and data source values go through ids.notionId@1, so a link, a dashed id and a plain id
 * give one value, GitHub's repository goes through ids.ownerRepo@1, so .. never reaches a path, and a repeated value of a resource list goes. So one change never makes two feeds. The stored
 * args, the card and the feed key all read the result.
 */
export function normalizeArgs(entry, args, transforms) {
  const {resource} = entry.trigger, out = structuredClone(args), [appId] = entry.id.split('.'), spelling = Object.hasOwn(SPELLINGS, appId) ? SPELLINGS[appId] : null;
  const one = value => {
    if (!spelling || typeof value !== 'string') return value;
    try { return spelling.read(runIn(transforms, spelling.transform, {value})); } catch (error) { if (error instanceof TransformError) throw actionRefused(error.code, {transform: spelling.transform}); throw error; }
  };
  if (Array.isArray(resource)) { for (const name of resource.filter(input => Object.hasOwn(out, input))) out[name] = one(out[name]); return out; }
  const name = resource.each.slice(1), seen = new Set();
  out[name] = out[name].map(one).filter(value => { const key = canonicalHash([value]); return !seen.has(key) && Boolean(seen.add(key)); });
  return out;
}

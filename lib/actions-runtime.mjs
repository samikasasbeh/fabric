// F10.11 parts g to j (docs/F10.11-BUILD-MAP.md parts g, h, i and j; spec lines 888-950 and the F10.9 and F10.10 hooks): the action runtime.
// The pure half (part g): evaluate() and passes() hold every expression and test of the closed grammar (lib/action-expressions.mjs) to its
// run-time rule over one job's frame; stepData() and nextPage() say what a forEach or paged step's answers are; buildRequest() turns one
// step's slots into the exact request the proxy's normalizer gives (lib/proxy-request.mjs), with the network's 1 MiB body cap and the headers
// Fabric adds; checkConcrete() places every built request again before anything is sent; the credential checks keep an account's token out
// of every byte, base64 spellings included; and actionRefused() is the one way an action refuses, with code action_refused and its own
// reason in every deployment. The running half (parts h to j): acceptAction() decides a job at acceptance with no network call;
// prepareAction() runs its reads and its resolving write and stores the exact perform bytes in actionPrepared; executeAction() sends those
// bytes unchanged and verifyAction() reads them back; a stop between them is an approval in phase reads or final, each with its own digest
// (actionDigest()) over the exact bytes. The runtime (lib/runtime.mjs) reaches all of it only through the action catalog (part p).
import {createHash} from 'node:crypto';
import {canonicalHash, validateValue, validateInput} from './compiler.mjs';
import {credentialValues, secretContext, scrubString, scrubValue} from './redaction.mjs';
import {parseTemplate, resolvePointer} from './permission-groups.mjs';
import {templatesFor, fitsTemplate} from './proxy-match.mjs';
import {normalizeProxyRequest, proxyBase} from './proxy-request.mjs';
import {fitsLocked} from './proxy-policy.mjs';
import {addedHeaders, providerHeaders} from './proxy-runtime.mjs';
import {LOCK_WORDS} from './row-locks.mjs';
import {placeRequest} from './action-placement.mjs';
import {ACCOUNT_TYPES, STEP_HEADERS} from './action-expressions.mjs';
import {REFUSALS, BOUNDS, jobKey, checkRequest, checkOutput, checkPreview, runPlan, effectiveInputSchema, resolvedSchemaHash} from './actions.mjs';
import {ownedBy, stampOwner} from './tenant/deployment.mjs';
import {notePages} from './connection-notes.mjs';
import {noteWrite, spaceWrite} from './write-spacing.mjs';
import {grantHeaderOf, observeGrant, providerOf, takeGrantHeader} from './grant-drift.mjs';
import {assertDispatchable, assertStateTransition} from '../contracts/execution.mts';
import {TRANSFORMS} from './transforms/index.mjs';
import {runIn} from './transforms/run.mjs';
import {TransformError} from './transforms/_shared/error.v1.mjs';
import {apiRuleOf, apiVerdict, narrowOnMissingScope, providerDetails} from './api-success.mjs';
import {retentionOf} from './retention.mjs';
import {paceCheck} from './slack-limits.mjs';

/** A value the run time leaves out: a {when} that does not hold, an unbound cursor, an optional input or a field an answer lacks. An object
 *  member, a list item, a query value or a header that is left out is dropped; anywhere a value is needed it refuses. */
export const ABSENT = Symbol('absent');
/** The code of every action refusal, in every deployment (one error format for /api, fabric/0.1, MCP and /v1). */
export const ACTION_REFUSED = 'action_refused';
/** I7: the most items a paged step's pages hold together, and the most bytes a built request body holds (the network's cap, lib/network.mjs). */
export const MAX_ITEMS = 1000;
export const REQUEST_BODY_BYTES = 1024 * 1024;
const MIN_SECRET = 8, STRICT = {allow: 0, ask: 1, deny: 2};
/**
 * The fixed words of every action refusal, by the reason details.reason carries: a guard's own code (REFUSALS), a rule of the run time, and
 * `transform` for a map transform's refusal, whose own code is the reason. Each ends in a full stop and names no value it refused.
 */
export const REFUSAL_WORDS = Object.freeze({
  ...REFUSALS,
  transform: 'Fabric could not build this request from the values given. Nothing was sent.',
  value_missing: 'A value this request needs is missing. Nothing was sent.',
  path_value: 'A value in the request path is missing, or is not one piece of text, a number or true or false. Nothing was sent.',
  query_value: 'A query value is not text, a number or true or false, or a list of them where the app takes one. Nothing was sent.',
  header_value: 'A header value is not one piece of text. Nothing was sent.',
  concat_part: 'Joined text may hold only text and whole numbers. Nothing was sent.',
  concat_too_long: 'Joined text is longer than this action allows. Nothing was sent.',
  each_list: 'This action walks a value that is not a list. Nothing was sent.',
  each_too_long: 'A list is longer than this action allows. Fabric never cuts it short. Nothing was sent.',
  account_value: 'This account does not record a value this action needs, or records one Fabric cannot use. Sign in again.',
  account_user_id: 'Sign in to Slack again so Fabric can read your user id.',
  resolved_missing: 'The fields of this resource were not read first. Nothing was sent.',
  page_items: 'A page of results holds no list where this action reads one. Nothing was sent.',
  page_cursor: 'The provider gave a next page that is not text or a whole number. Nothing was sent.',
  too_many_items: 'The pages hold more than 1,000 items. Fabric never cuts a list short. Nothing was sent.',
  too_many_pages: 'The results span more pages than this action reads. Fabric never cuts a list short. Nothing was sent.',
  raw_value: 'The request would copy a whole provider value where only text, a number, true or false or null may sit. Nothing was sent.',
  request_invalid: 'The request this action built is not one Fabric sends. Nothing was sent.',
  not_on_member: 'The request this action built lands outside the step it was reviewed as. Nothing was sent.',
  locked: LOCK_WORDS,
  stricter_typed: 'The request this action built is set stricter for this account than the action is. Nothing was sent.',
  credential_short: 'The account credential is too short to keep out of requests safely. Nothing was sent.',
  credential_in_request: 'The request would carry the account credential. Nothing was sent.',
  output_invalid: 'The result does not fit what this action returns, so it was withheld.',
  preview_invalid: 'A line of this action\'s card is not text or a number. Nothing was sent.',
  too_many_requests: 'This action would send more than 64 requests. Fabric stopped before the next one.',
  too_much_data: 'The answers to this action came to more than it may hold. Fabric stopped before the next request.',
  scope_missing: 'This account was not granted a permission this request needs. Add access, then ask again. Nothing was sent.',
});

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const scalar = value => typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value));
/**
 * The one action refusal: an Error with code action_refused in every deployment, the reason in details.reason and that reason's fixed words.
 * A map transform's refusal passes {transform}, so its own code is the reason and its words are the transform words; a guard passes the
 * transform and the transform's own code beside the guard's (transformReason).
 */
export function actionRefused(reason, extra = {}) {
  const words = extra.transform !== undefined && extra.transformReason === undefined ? REFUSAL_WORDS.transform : REFUSAL_WORDS[reason] ?? REFUSAL_WORDS.transform;
  return Object.assign(new Error(words), {code: ACTION_REFUSED, details: {reason, ...extra}});
}
const refuse = (reason, extra) => { throw actionRefused(reason, extra); };
/** A transform's refusal, the one refusal a read-back or an output may turn into unverified. A credential found, or an account Fabric cannot use, keeps its own ending. */
const transformRefused = error => error?.code === ACTION_REFUSED && error.details?.transform !== undefined;

// ---- the job --------------------------------------------------------------------------------------------------------------------------
/**
 * One job's run-time context: its id and action, the account's identity (the connection's), the clock read at most once ({now}), its job
 * keys built once ({jobKey}, jobKey(jobId, actionId, name)), each transform run once per canonical argument set through runIn(), the cursors a
 * poll binds (an ordinary call binds none) and the resolved schemas of its resource-dependent inputs. useCredentials() gives it the credential
 * context once fetched: every transform output, before and after, is checked against it. snapshot() is what the digest binds (part h).
 * A job that continues after a stop (part h) passes the `now` it read and the transform `runs` it kept (runsOf()), so it reads the clock
 * once and runs each transform once in all.
 */
export function createJob({jobId, entry, appId, identity = {}, clock, transforms = TRANSFORMS, cursors = new Map(), resolved = new Map(), now: read = null, runs: kept = []}) {
  if (typeof jobId !== 'string' || !jobId || typeof clock !== 'function') throw new Error('A job needs its id and a clock.');
  let now = read ?? undefined, credentials = null;
  const keys = new Map(), runs = new Map(kept.map(([key, output]) => [key, {output}]));
  return Object.freeze({jobId, actionId: entry.id, appId, identity: identity ?? {}, cursors, resolved,
    now() {
      if (now === undefined) {
        const read = clock();
        if (!Number.isSafeInteger(read) || read < 0) throw new Error('The clock gave no time.');
        now = read;
      }
      return now;
    },
    jobKey(name) {
      if (!keys.has(name)) keys.set(name, jobKey(jobId, entry.id, name));
      return keys.get(name);
    },
    transform(id, args) {
      let key;
      try { key = canonicalHash({id, args}); } catch { throw new TransformError('input_too_large'); }
      if (!runs.has(key)) {
        let result;
        try { result = {output: runIn(transforms, id, args)}; } catch (error) { result = {error}; }
        runs.set(key, result);
        if (credentials && result.output !== undefined) assertNoCredential(result.output, credentials);
      }
      const {output, error} = runs.get(key);
      if (error) throw error;
      return output;
    },
    useCredentials(context) {
      credentials = context;
      for (const {output} of runs.values()) if (output !== undefined) assertNoCredential(output, context);
    },
    get credentials() { return credentials; },
    snapshot() { return {now: now ?? null, jobKeys: Object.fromEntries([...keys].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))}; },
    runsOf() { return [...runs].filter(([, result]) => result.output !== undefined).map(([key, result]) => [key, result.output]); },
  });
}
/** A frame: the job, the call's inputs and the answers of the steps that ran (id to {status, headers, data}); a forEach run adds `item`. */
export const newFrame = (job, input, steps = new Map()) => ({job, input, steps, vars: new Map()});

// ---- the evaluator ----------------------------------------------------------------------------------------------------------------------
const KINDS = ['const', 'input', 'step', 'item', 'pick', 'each', 'var', 'account', 'transform', 'object', 'array', 'concat', 'when', 'either', 'now', 'jobKey', 'cursor', 'resolved'];
const found = value => value === undefined ? ABSENT : structuredClone(value);
/** The arguments of a transform call or guard: each evaluated, one left out not passed. */
function argsOf(args, frame) {
  const out = {};
  for (const [name, node] of Object.entries(args)) { const value = evaluate(node, frame); if (value !== ABSENT) out[name] = value; }
  return out;
}
const NODES = {
  const: node => structuredClone(node.const),
  input: (node, frame) => found(resolvePointer(frame.input, node.input)),
  step(node, frame) {
    const ran = frame.steps.get(node.step);
    if (!ran) return ABSENT;
    if (Object.hasOwn(node, 'header')) { const value = ran.headers?.[node.header]; return typeof value === 'string' ? value : ABSENT; }
    return found(resolvePointer(ran.data, node.pointer));
  },
  item: (node, frame) => found(resolvePointer(frame.item, node.item)),
  pick(node, frame) {
    const base = evaluate(node.pick, frame);
    return base === ABSENT ? ABSENT : found(resolvePointer(base, node.pointer));
  },
  // A list longer than its max refuses; an element its do leaves out is dropped.
  each(node, frame) {
    const list = evaluate(node.each, frame);
    if (!Array.isArray(list)) refuse('each_list');
    if (list.length > node.max) refuse('each_too_long');
    const out = [];
    for (const element of list) {
      const value = evaluate(node.do, {...frame, vars: new Map(frame.vars).set(node.as, element)});
      if (value !== ABSENT) out.push(value);
    }
    return out;
  },
  var: (node, frame) => found(frame.vars.get(node.var)),
  // Each account value fits its type before any call; Slack's user id is recorded only at a sign-in or refresh since F10.9.
  account(node, frame) {
    const {job} = frame, value = job.identity?.[node.account];
    if (value === undefined || value === null) refuse(node.account === 'userId' && job.appId === 'slack' ? 'account_user_id' : 'account_value');
    try { validateValue(ACCOUNT_TYPES[node.account], value, '$account'); } catch { refuse('account_value'); }
    return value;
  },
  // A map transform runs once per job per argument set; its own refusal refuses the action with its own code.
  transform(node, frame) {
    const args = argsOf(node.args, frame);
    try { return structuredClone(frame.job.transform(node.transform, args)); }
    catch (error) { if (error instanceof TransformError) refuse(error.code, {transform: node.transform}); throw error; }
  },
  object(node, frame) {
    const out = {};
    for (const [key, member] of Object.entries(node.object)) { const value = evaluate(member, frame); if (value !== ABSENT) out[key] = value; }
    return out;
  },
  array: (node, frame) => node.array.map(item => evaluate(item, frame)).filter(value => value !== ABSENT),
  // Each part is text or a safe integer written in plain decimal, and the joined text stays within its max.
  concat(node, frame) {
    let text = '';
    for (const part of node.concat) {
      const value = evaluate(part, frame);
      if (typeof value === 'string') text += value;
      else if (Number.isSafeInteger(value)) text += String(value);
      else refuse('concat_part');
    }
    if ([...text].length > node.max) refuse('concat_too_long');
    return text;
  },
  when: (node, frame) => passes(node.when, frame) ? evaluate(node.then, frame) : ABSENT,
  either(node, frame) {
    const first = evaluate(node.either[0], frame);
    return first === ABSENT ? evaluate(node.either[1], frame) : first;
  },
  now: (node, frame) => frame.job.now(),
  jobKey: (node, frame) => frame.job.jobKey(node.jobKey),
  cursor: (node, frame) => frame.job.cursors.has(node.cursor) ? structuredClone(frame.job.cursors.get(node.cursor)) : ABSENT,
  resolved(node, frame) {
    if (!frame.job.resolved.has(node.resolved)) refuse('resolved_missing');
    return structuredClone(frame.job.resolved.get(node.resolved));
  },
};
/**
 * The value of one expression of a validated action in a frame, or ABSENT. Every node keeps its run-time rule: a concat part is text or a
 * safe integer and the joined text stays within its max, an each longer than its max refuses, each account value fits ACCOUNT_TYPES, {now}
 * is the job's one reading of the clock, {jobKey} the job's key, a cursor is bound only when the job holds one, and a transform runs once per
 * job per argument set. A registration value ({receiver}, {secret} and the like) never reads in an action. Refusals are actionRefused().
 */
export function evaluate(node, frame) {
  const kind = record(node) ? KINDS.find(name => Object.hasOwn(node, name)) : undefined;
  if (kind === undefined) refuse('value_missing');
  return NODES[kind](node, frame);
}
/** One test of a validated action: present (null counts, as body routes read it), absent, nonEmpty, equals a constant, a step's status, anyOf. */
export function passes(node, frame) {
  if (Object.hasOwn(node, 'anyOf')) return node.anyOf.some(test => passes(test, frame));
  if (Object.hasOwn(node, 'status')) { const ran = frame.steps.get(node.status.step); return Boolean(ran) && node.status.in.includes(ran.status); }
  if (Object.hasOwn(node, 'equals')) { const value = evaluate(node.equals[0], frame); return value !== ABSENT && canonicalHash([value]) === canonicalHash([node.equals[1].const]); }
  if (Object.hasOwn(node, 'present')) return evaluate(node.present, frame) !== ABSENT;
  if (Object.hasOwn(node, 'absent')) return evaluate(node.absent, frame) === ABSENT;
  if (Object.hasOwn(node, 'nonEmpty')) {
    const value = evaluate(node.nonEmpty, frame);
    return typeof value === 'string' || Array.isArray(value) ? value.length > 0 : record(value) ? Object.keys(value).length > 0 : value !== ABSENT && value !== null;
  }
  return refuse('value_missing');
}
/** Whether a step runs in this frame: always, unless its when does not hold. */
export const stepRuns = (step, frame) => step.when === undefined || passes(step.when, frame);
/** The items a forEach step runs over, in order: a list within its max, or a refusal. */
export function forEachItems(step, frame) {
  const list = evaluate(step.forEach.over, frame);
  if (!Array.isArray(list)) refuse('each_list');
  if (list.length > step.forEach.max) refuse('each_too_long');
  return list;
}

// ---- step data ------------------------------------------------------------------------------------------------------------------------
/**
 * What expressions read as a step's data, from its answers in order ({status, headers, data}): one answer's data; a forEach step's list of
 * answers; a paged step's page.items lists joined, at most page.max pages and 1,000 items together. More refuses: Fabric never cuts a list
 * short. A page that lacks the list holds none (Gmail leaves an empty list out); one that holds anything else refuses.
 */
export function stepData(step, answers) {
  if (step.forEach !== undefined) return answers.map(answer => answer.data);
  if (step.page === undefined) return answers[0]?.data;
  if (answers.length > step.page.max) refuse('too_many_pages');
  const items = [];
  for (const answer of answers) {
    const list = resolvePointer(answer.data, step.page.items) ?? [];
    if (!Array.isArray(list)) refuse('page_items');
    items.push(...list);
    if (items.length > MAX_ITEMS) refuse('too_many_items');
  }
  return items;
}
/**
 * The cursor of the page after `answer`, the `pages`-th of a paged step, as {cursor}, or null when the list ends (page.while is not true, or
 * there is no next cursor). A next page after page.max pages refuses. Link paging reads the next page number through ids.linkPage@1 from the
 * Link header of an answer to `url`, never the URL itself.
 */
export function nextPage(step, answer, {pages, job, url = null}) {
  const page = step.page;
  if (page.while !== undefined && resolvePointer(answer.data, page.while) !== true) return null;
  let cursor;
  if (page.next.pointer !== undefined) cursor = resolvePointer(answer.data, page.next.pointer);
  else {
    const link = answer.headers?.link;
    if (typeof link !== 'string' || !link) return null;
    try { cursor = job.transform('ids.linkPage@1', {link, url, param: page.next.param}).page; }
    catch (error) { if (error instanceof TransformError) refuse(error.code, {transform: 'ids.linkPage@1'}); throw error; }
  }
  if (cursor === undefined || cursor === null || cursor === '') return null;
  if (typeof cursor !== 'string' && !Number.isSafeInteger(cursor)) refuse('page_cursor');
  if (pages >= page.max) refuse('too_many_pages');
  return {cursor};
}

// ---- choice lists (part o) -------------------------------------------------------------------------------------------------------------
/**
 * Part o: one page of a directory choice source for POST /v1/options. `args` holds its arguments' values (constants and the choice's
 * configured values); the page cursor goes where page.into says, and search text reaches the provider only as its reviewed text
 * transform's output (spec line 672), where search.into says. A typed-operation source gives {operation, args}, the arguments its operation
 * takes; a request template gives {input}, the request as the proxy takes one ({method, path, query?, body?}): path arguments in the path
 * (each one piece of text, a number or true or false), the others in the query of a GET or the body of a POST. ProxyPolicy.decide() then
 * normalizes and decides it like any proxied request. Anything it cannot send refuses (action_refused, its reason in details.reason).
 */
export function choiceRequest(source, {args = {}, cursor = null, query = null, transforms = TRANSFORMS} = {}) {
  const extras = [];
  if (cursor !== null) extras.push([source.page.into, cursor]);
  if (query !== null && source.search?.mode === 'provider') {
    let text;
    try { text = resolvePointer(runIn(transforms, source.search.transform, {[source.search.argument]: query}), source.search.pick); }
    catch (error) { if (error instanceof TransformError) refuse(error.code, {transform: source.search.transform}); throw error; }
    if (typeof text !== 'string') refuse('query_value');
    extras.push([source.search.into, text]);
  }
  if (typeof source.read.operation === 'string') return {operation: source.read.operation, args: {...args, ...Object.fromEntries(extras.map(([into, value]) => [into.query, String(value)]))}};
  const [method] = source.read.request.split(' '), names = new Set();
  const segments = parseTemplate(source.read.request).segments.map(segment => {
    if (segment.kind === 'literal') return segment.value;
    names.add(segment.name);
    const value = args[segment.name];
    if (!scalar(value) || value === '') refuse('path_value');
    if (segment.kind === 'rest') return String(value).split('/').map(encodeURIComponent).join('/');
    return encodeURIComponent(String(value)) + (segment.kind === 'verb' ? segment.suffix : '');
  });
  const rest = Object.entries(args).filter(([name]) => !names.has(name)), params = method === 'GET' ? Object.fromEntries(rest.map(([name, value]) => [name, queryValue(value)])) : {};
  let body = method === 'POST' ? Object.fromEntries(rest) : undefined;
  for (const [into, value] of extras) {
    if (typeof into.query === 'string') params[into.query] = String(value);
    else body = withPointer(body ?? {}, into.body, value);
  }
  return {input: {method, path: `/${segments.join('/')}`, ...(Object.keys(params).length ? {query: params} : {}), ...(body !== undefined ? {body} : {})}};
}
/** Part o: the cursor of the page after the `pages`-th page of a directory choice source (nextPage(), Link paging through ids.linkPage@1),
 *  or null when the list ends or the source's page.max pages were read. */
export function choiceNext(source, answer, {pages, url = null, transforms = TRANSFORMS} = {}) {
  if (!source.page || pages >= source.page.max) return null;
  return nextPage({page: source.page}, answer, {pages, url, job: {transform: (id, args) => runIn(transforms, id, args)}})?.cursor ?? null;
}

// ---- the request ----------------------------------------------------------------------------------------------------------------------
/** A query value as the proxy takes one: text, with numbers and true or false written as text, or a list of them, which the normalizer
 *  accepts only for the app's array parameters. */
function queryValue(value) {
  if (scalar(value)) return String(value);
  if (Array.isArray(value) && value.every(scalar)) return value.map(String);
  return refuse('query_value');
}
/**
 * F10.19 part 1 (docs/F10.19-BUILD-MAP.md question 13): a body field one app's proxy settings reserve that the app's action steps may still
 * write, and the one constant it may hold there. Notion's Restore sends {in_trash: false}, which the validator allows (lib/actions.mjs
 * bodyKeys()) and the body route sends to the trash row. Anywhere in such a body the field must be exactly that constant, else the request is
 * refused request_invalid before it is sent; every other reserved field still refuses, and the proxy's own requests keep the whole list.
 */
export const STEP_BODY_CONSTANTS = Object.freeze({notion: Object.freeze({in_trash: false})});
/** True when every key of `constants` in the JSON value, at any depth, holds exactly its constant. */
function constantsHold(value, constants) {
  if (Array.isArray(value)) return value.every(item => constantsHold(item, constants));
  if (!record(value)) return true;
  return Object.entries(value).every(([key, item]) => (!Object.hasOwn(constants, key) || item === constants[key]) && constantsHold(item, constants));
}
/** `body` with `value` at `pointer`, objects made on the way. The validator keeps the pointer off every key the body writes. */
function withPointer(body, pointer, value) {
  const out = structuredClone(record(body) ? body : {}), tokens = pointer.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~'));
  let current = out;
  for (const token of tokens.slice(0, -1)) { if (!record(current[token])) current[token] = {}; current = current[token]; }
  current[tokens.at(-1)] = value;
  return out;
}
/**
 * The exact request one run of a step sends. `frame` holds the job, the inputs, the answers so far and, in a forEach run, the item; `pinned`
 * the file's pinnedParameters; `cursor` the next page's, put where page.into says. Each path value is one piece of text, a number or true or
 * false ({+x} spans segments, anything else is one segment), query values are text, a header is one string, and a value left out is
 * dropped. The request is then normalized as the proxy normalizes one (normalizeProxyRequest()), with the network's 1 MiB body cap, and
 * Fabric's added headers come from the proxy's addedHeaders() over the reviewed `provider` headers. With the job's credential context known,
 * the bytes are checked for the credential. Returns {request, added, parts}: parts is {params, query, headers, body} as checkRequest() reads it.
 */
export function buildRequest(entry, step, frame, {config, pinned = {}, provider = {}, cursor = null, timeoutMs} = {}) {
  if (!record(config)) throw new Error('Building a request needs the app\'s proxy settings.');
  const params = {}, query = {}, headers = {};
  const segments = parseTemplate(`${step.method} ${step.path}`).segments.map(segment => {
    if (segment.kind === 'literal') return segment.value;
    const node = step.params?.[segment.name], value = node === undefined ? pinned[segment.name] : evaluate(node, frame);
    if (value === ABSENT || !scalar(value) || value === '') refuse('path_value');
    params[segment.name] = value;
    if (segment.kind === 'rest') return String(value).split('/').map(encodeURIComponent).join('/');
    return `${encodeURIComponent(String(value))}${segment.kind === 'verb' ? segment.suffix : ''}`;
  });
  for (const [name, node] of Object.entries(step.query ?? {})) {
    const value = evaluate(node, frame);
    if (value !== ABSENT) query[name] = queryValue(value);
  }
  for (const [name, node] of Object.entries(step.headers ?? {})) {
    const value = evaluate(node, frame);
    if (value === ABSENT) continue;
    if (typeof value !== 'string') refuse('header_value');
    headers[name] = value;
  }
  let body = step.body === undefined ? ABSENT : evaluate(step.body, frame);
  if (cursor !== null && typeof step.page?.into?.query === 'string') query[step.page.into.query] = String(cursor);
  if (cursor !== null && typeof step.page?.into?.body === 'string') body = withPointer(body === ABSENT ? {} : body, step.page.into.body, cursor);
  const input = {method: step.method, path: `/${segments.join('/')}`, ...(Object.keys(query).length ? {query} : {}), ...(Object.keys(headers).length ? {headers} : {}), ...(body !== ABSENT ? {body} : {})};
  // F10.19: an app's step-body constants: each such field holds only its constant, and only then is it left out of the reserved list.
  const constants = Object.hasOwn(STEP_BODY_CONSTANTS, config.appId) ? STEP_BODY_CONSTANTS[config.appId] : null;
  if (constants && body !== ABSENT && !constantsHold(body, constants)) refuse('request_invalid', {problem: 'parameter_not_allowed'});
  const settings = constants ? {...config, reservedBodyFields: (config.reservedBodyFields ?? []).filter(name => !Object.hasOwn(constants, name))} : config;
  let request;
  try { request = normalizeProxyRequest(input, settings, {maxBodyBytes: REQUEST_BODY_BYTES, ...(timeoutMs !== undefined ? {timeoutMs} : {})}); }
  catch (error) { refuse('request_invalid', {problem: typeof error?.code === 'string' ? error.code : 'invalid_request'}); }
  if (frame.job.credentials) assertNoCredential([request.url, ...Object.values(request.headers), request.body], frame.job.credentials);
  return {request, added: addedHeaders(request, provider), parts: {params, query, headers, ...(body !== ABSENT ? {body} : {})}};
}
/**
 * Runs before any built request is sent, and refuses it unless it lands, as the proxy routes it, on the step's own reviewed member in the
 * step's own row (placeRequest(): a literal sibling or a body route moves nothing), fits no template of a row Fabric locks (fitsLocked(),
 * T4), holds only a scalar wherever the file placed raw step data (checkRequest(), I6), and fits no typed operation now set stricter for the
 * account than the step was decided (c4 on the concrete request: `typed` is the app's typed templates, typedMode(capability) its mode now,
 * `stepMode` the step's). Returns `built`.
 */
export function checkConcrete(entry, stepId, built, {definition, config, map = null, typed = [], typedMode = () => 'deny', stepMode = 'allow'} = {}) {
  const placement = entry.placements.find(item => item.stepId === stepId), {request} = built;
  if (!placement) refuse('not_on_member');
  try { placeRequest(placement, {method: request.method, segments: request.segments, body: request.body}, {definition, config, map, where: stepId}); }
  catch { refuse('not_on_member'); }
  const templates = templatesFor(definition, config, map);
  if (!templates || fitsLocked(templates, request, {style: config.style})) refuse('locked');
  // A choice lookup sends only constants, the input's value and configured values: it has no raw position to hold (lib/actions.mjs).
  try { if (placement.phase !== 'lookup') checkRequest(entry, stepId, built.parts); } catch { refuse('raw_value'); }
  for (const {capability, template} of typed) {
    if (fitsTemplate(template, request, {style: config.style}) && (STRICT[typedMode(capability)] ?? 2) > STRICT[stepMode]) refuse('stricter_typed');
  }
  return built;
}
/** Runs one guard ({transform, args, refuse}): its transform's refusal refuses the action with the guard's own code, the transform's beside it. */
export function checkGuard(guard, frame) {
  const args = argsOf(guard.args, frame);
  try { frame.job.transform(guard.transform, args); }
  catch (error) { if (error instanceof TransformError) refuse(guard.refuse, {transform: guard.transform, transformReason: error.code}); throw error; }
}
/** The action's output from its answers, a member left out dropped, held to its closed outputSchema within 1 MiB (checkOutput()). */
export function buildOutput(entry, frame) {
  const output = {};
  for (const [name, node] of Object.entries(entry.action.output)) { const value = evaluate(node, frame); if (value !== ABSENT) output[name] = value; }
  try { return checkOutput(entry, output); } catch { return refuse('output_invalid'); }
}
/** The card's preview values in order, each text or a number or left out (checkPreview()), text cut to its line's truncate. */
export function buildPreview(entry, frame) {
  const values = entry.action.preview.map(line => {
    const value = evaluate(line.expr, frame);
    if (value === ABSENT) return undefined;
    return typeof value === 'string' && line.truncate !== undefined ? [...value].slice(0, line.truncate).join('') : value;
  });
  try { return checkPreview(entry, values); } catch { return refuse('preview_invalid'); }
}

// ---- credentials ----------------------------------------------------------------------------------------------------------------------
/** The credential context of one fetch (lib/redaction.mjs): refused when there is none, or one is too short to look for safely. */
export function credentialContext(headers) {
  const values = credentialValues(headers);
  if (!values.length || values.some(value => value.length < MIN_SECRET)) refuse('credential_short');
  return secretContext(values);
}
/** A provider answer with every credential spelling scrubbed from its headers and data, before any expression reads it. */
export function scrubAnswer(answer, context) {
  return {...answer, headers: Object.fromEntries(Object.entries(answer.headers ?? {}).map(([name, value]) => [name, scrubString(value, context)])), data: scrubValue(answer.data, context)};
}
// A run of base64 or base64url characters, with the line breaks a MIME body wraps it in; one long enough to hide 8 characters is decoded.
const BASE64_RUN = /[A-Za-z0-9+/_-]+(?:\s+[A-Za-z0-9+/_-]+)*={0,2}/g;
/** Each text a base64 run of `text` decodes to, at each of the four alignments: together at most three times the text's length. */
function* decodedRuns(text) {
  for (const run of text.match(BASE64_RUN) ?? []) {
    const compact = run.replace(/\s+/g, '');
    if (compact.length < 11) continue;
    for (let offset = 0; offset < 4; offset++) {
      yield Buffer.from(compact.slice(offset), 'base64').toString('latin1');
    }
  }
}
/** True when text holds a credential: any spelling scrubString() knows, or inside base64 at any alignment, which redaction never spells, or
 *  inside base64 that base64 decodes to (a MIME body inside Gmail's base64url raw, docs/F10.15-BUILD-MAP.md section 10, difference 14). It
 *  reads two layers and never a third, so a 1 MiB text costs at most about 12 MiB of decoding. */
function textHolds(text, context) {
  if (scrubString(text, {values: context.values, forms: context.forms, count: 0}) !== text) return true;
  const found = decoded => context.values.some(value => decoded.includes(value));
  for (const decoded of decodedRuns(text)) {
    if (found(decoded)) return true;
    for (const inner of decodedRuns(decoded)) if (found(inner)) return true;
  }
  return false;
}
/** True when a value (text, JSON text or plain JSON, keys included) holds the credential in any spelling. JSON text is read parsed too, so an
 *  escaped line break inside base64 hides nothing. */
export function holdsCredential(value, context) {
  if (typeof value === 'string') {
    if (textHolds(value, context)) return true;
    if (/^\s*[[{"]/.test(value)) { try { return holdsCredential(JSON.parse(value), context); } catch { return false; } }
    return false;
  }
  if (Array.isArray(value)) return value.some(item => holdsCredential(item, context));
  if (record(value)) return Object.entries(value).some(([key, item]) => textHolds(key, context) || holdsCredential(item, context));
  return false;
}
/** Refuses a value that holds the credential: the perform bytes, and every transform output. Returns the value. */
export function assertNoCredential(value, context) {
  if (holdsCredential(value, context)) refuse('credential_in_request');
  return value;
}

// ---- parts h, i and j: preparing, sending and checking an action ------------------------------------------------------------------------
/** An action job's prepared bytes and phase 1 answers (one row per job, removed when the job settles or its window lapses), and the records
 *  Fabric made, which askUnless reads. Both are erased with their end user (lib/tenant/users.mjs). */
export const PREPARED = 'actionPrepared', RECORDS = 'actionRecords';
/** Open question 5: each stop's approval window, never past the job's deadline (25 minutes in a designated store, lib/runtime.mjs). */
export const WINDOW_MS = 10 * 60_000;
const RESPONSE_HEADERS = Object.freeze(['content-type', ...STEP_HEADERS]);
const READ_PHASES = new Set(['schema', 'lookup', 'prepare']);
const SUMMARY = Object.freeze(['stepId', 'index', 'method', 'url', 'headers', 'added', 'bodySha256', 'bodyBytes']);
/** The fixed words of how an action job ends, beside the refusals (REFUSAL_WORDS). Each ends in a full stop and names no value. */
export const RUN_WORDS = Object.freeze({
  prepared_changed: 'The prepared request no longer matches what was approved. Nothing was sent.',
  input_schema_changed: 'The fields of this resource changed after they were read. Nothing was sent: read them again and ask again.',
  invalid_values: 'The values do not fit the fields this resource has now. Nothing was sent.',
  changed: 'This action no longer matches its reviewed file, so it was not run.',
  account_changed: 'The account changed before sending. Nothing was sent.',
  unreachable: 'This account is not granted the app\'s reviewed API address. Nothing was sent.',
  restarted: 'Fabric restarted before this finished. Nothing was sent.',
  restarted_sent: 'Fabric restarted after a change was sent. Its outcome is uncertain: check it before trying again.',
  failed: 'The provider did not complete this request. Nothing was changed.',
  limited: 'The provider is limiting requests. Nothing was changed, and Fabric did not retry it.',
  not_sent: 'The request could not be sent. Nothing was changed.',
  uncertain: 'A change was sent, but its effect was not confirmed. Check it before trying again; Fabric did not retry it.',
  unverified: 'The change was sent, but reading it back did not confirm it. Check it before trying again; Fabric did not retry it.',
  write_in_progress: 'Another change is in progress for this account. Nothing was sent.',
  authority_changed: 'The account, its permissions or the action changed while this ran, so its result was withheld.',
  card_after_write: 'A change was already sent, so Fabric does not stop to ask now. Its outcome is uncertain: check it before trying again.',
  approval_required: 'This step needs its own exact approval. Nothing was sent.',
  policy_denied: 'This action is not permitted now. Nothing was sent.',
  content_changed: 'It changed after Fabric read it, so nothing was changed. Read it again and ask again.',
  not_shared: 'This page may not be shared with Fabric. Nothing was changed. Share it in Notion, or use Share more pages.',
  capability_off: 'Notion has turned this capability off for Fabric\'s integration. Nothing was changed. Turn it back on in Notion\'s integration settings.',
  // F10.21: Slack's ok: false, a reason beside the code (lib/api-success.mjs).
  api_error: 'Slack refused this request, so nothing was changed.',
  missing_scope: 'This account lacks the access this needs, so nothing was changed. Use Add access on the permission that needs it.',
});
/** F10.13 part 1: the answer a content-bound write gets when the content changed after Fabric read it (an etag-bound 412, a sha-bound 409).
 *  It is a reason beside the code, never a code, so every surface keeps one error shape; GitHub's sha writes (step 17) reuse it. */
const CONTENT_CHANGED = Object.freeze({etag: 412, sha: 409});
/**
 * F10.19 part 1: a provider's own refusal that says why, by app, status and the answer's /code, read as a reason beside the code exactly as
 * content_changed is, so every surface keeps one error shape. Notion answers 404 object_not_found for a page not shared with the integration
 * and 403 restricted_resource for a capability turned off for it. Any other 404 or 403 keeps http_status.
 */
const PROVIDER_REASONS = Object.freeze({notion: Object.freeze({404: Object.freeze({code: 'object_not_found', reason: 'not_shared'}),
  403: Object.freeze({code: 'restricted_resource', reason: 'capability_off'})})});
/** The reason PROVIDER_REASONS gives one answer of one app, or null. */
function providerReason(appId, answer) {
  const rules = Object.hasOwn(PROVIDER_REASONS, appId) ? PROVIDER_REASONS[appId] : null, rule = rules && Object.hasOwn(rules, answer.status) ? rules[answer.status] : null;
  return rule && record(answer.data) && answer.data.code === rule.code ? rule.reason : null;
}
/** F10.15 (spec line 1121): the reasons of the limit answers a provider sends as a 403, by app, as Google documents them in its error shape
 *  ({error: {errors: [{reason}]}}). Such a 403 ends as a 429 does: limited words, never retried. Any other 403 keeps the failed words. Calendar
 *  answers with the same reasons; it joins this list with step 14's evidence (docs/F10.15-BUILD-MAP.md open question 6). */
export const LIMIT_REASONS = Object.freeze({gmail: Object.freeze(['dailyLimitExceeded', 'userRateLimitExceeded', 'rateLimitExceeded'])});
const limited = (appId, answer) => {
  const errors = answer.data?.error?.errors, reasons = LIMIT_REASONS[appId] ?? [];
  return answer.status === 403 && Array.isArray(errors) && errors.some(item => record(item) && reasons.includes(item.reason));
};
const sha256 = text => createHash('sha256').update(text).digest('hex');
const same = (a, b) => canonicalHash([a]) === canonicalHash([b]);
const stricter = (a, b) => (STRICT[a] ?? 2) >= (STRICT[b] ?? 2) ? a : b;
/** An error that ends an action job: its code and fixed words, and what the job keeps (outcome, reason, providerStatus, retryAfterSeconds). */
const ending = (code, words, extra = {}) => Object.assign(new Error(words), {code, ...extra});
const changedBytes = () => ending('fabric_failed', RUN_WORDS.prepared_changed, {reason: 'prepared_changed'});
/** What a job and its digest hold of a request: everything sent but the credential and the body, which its sha256 binds. A read whose bytes
 *  are not known yet is {stepId, template}. */
export const summaryOf = request => request.template !== undefined ? {stepId: request.stepId, template: request.template} : Object.fromEntries(SUMMARY.map(key => [key, request[key]]));
const stepsOf = entry => [...(entry.action.resolvedInputs ?? []).flatMap(input => input.schema.steps), ...entry.action.prepare, ...entry.action.perform, ...(entry.action.verify?.requests ?? [])];
const stepOf = (entry, id) => stepsOf(entry).find(step => step.id === id);
/** True when any slot of a step reads a step's answer, so its bytes are known only after that step ran. */
const readsAnswer = value => Array.isArray(value) ? value.some(readsAnswer) : record(value) && (typeof value.step === 'string' || Object.values(value).some(readsAnswer));
const answerSlots = step => [step.params, step.query, step.headers, step.body, step.when, step.forEach?.over, step.requiresScope?.when];
/** The id of the record askUnless reads: one account, one kind, one provider id. */
export const recordId = (connectionId, kind, id) => canonicalHash({kind: 'fabric-action-record', connectionId, recordKind: kind, id: String(id)});

/** One exact request as it is stored and shown: everything sent but the credential, its body whole, and what a dispatch check reads again. */
function exactOf(stepId, index, built, step) {
  const {request, added, parts} = built;
  return {stepId, index, method: request.method, url: request.url, headers: {...request.headers}, added, bodySha256: request.bodyHash, bodyBytes: request.bodyBytes, body: request.body,
    segments: [...request.segments], parts, timeoutMs: request.timeoutMs, maxBytes: step.maxResponseBytes ?? BOUNDS.responseBytes};
}
/** A stored exact request as the sender takes it. Its body's sha256 and size are computed again from the stored body, never read back. */
const builtOf = exact => ({request: {method: exact.method, url: exact.url, segments: exact.segments, headers: exact.headers, body: exact.body, timeoutMs: exact.timeoutMs,
  bodyHash: exact.body === null ? null : sha256(exact.body), bodyBytes: exact.body === null ? 0 : Buffer.byteLength(exact.body)}, added: exact.added, parts: exact.parts, maxBytes: exact.maxBytes});
const rehashed = exact => summaryOf({...exact, bodySha256: builtOf(exact).request.bodyHash, bodyBytes: builtOf(exact).request.bodyBytes});

/**
 * Part h: the digest an approval of an action names, one form per phase, over the job's identity and window and the exact bytes of that
 * phase. Phase reads: each read the stop shows (exact, or its template when an earlier answer fills it), the resolving write it gates (or
 * null), the resolved schema hashes and the job's one clock reading. Phase final: every perform request, the hash of the prepared row, the
 * schema hashes, the clock reading, the job keys and the steps a when left out.
 */
export function actionDigest(job) {
  const a = job?.action;
  if (!record(a)) return null;
  const base = {id: job.id, connectionId: job.connectionId, capabilityHash: job.capabilityHash, identityHash: job.identityHash, connectionBindingHash: job.connectionBindingHash,
    permissionHash: job.permissionHash, args: job.args, ...(job.executionRequestHash ? {executionRequestHash: job.executionRequestHash} : {}), expires: job.approvalExpiresAt};
  return a.phase === 'final'
    ? canonicalHash({...base, phase: 'final', perform: a.perform, preparedHash: a.preparedHash, schemaHashes: a.schemaHashes, now: a.now, jobKeys: a.jobKeys, skipped: a.skipped})
    : canonicalHash({...base, phase: 'reads', reads: a.reads, resolving: a.resolving, schemaHashes: a.schemaHashes, now: a.now});
}

/** The inputs of an action that do not depend on a resource, checked before any call; a resource-dependent input is an object until its
 *  schema is read (effectiveInputSchema()). Returns the inputs. */
export function staticInputs(entry, args) {
  const schema = entry.action.inputSchema, names = new Set((entry.action.resolvedInputs ?? []).map(input => input.input));
  if (!names.size) return validateInput(schema, args);
  const properties = Object.fromEntries(Object.entries(schema.properties).filter(([name]) => !names.has(name)));
  validateInput({...schema, properties, required: (schema.required ?? []).filter(name => !names.has(name))}, record(args) ? Object.fromEntries(Object.entries(args).filter(([name]) => !names.has(name))) : args);
  for (const name of names) {
    if (!Object.hasOwn(args, name) ? (schema.required ?? []).includes(name) : !record(args[name])) throw new Error(`$input.${name}: expected object`);
  }
  return args;
}

/** True when Fabric recorded making this object on this account for this owner (D3): askUnless asks for anything else. */
function madeByFabric(runtime, connectionId, kind, id, owner) {
  if (!(typeof id === 'string' && id) && !Number.isSafeInteger(id)) return false;
  const row = runtime.store.get(RECORDS, recordId(connectionId, kind, id));
  return Boolean(row) && row.connectionId === connectionId && row.kind === kind && row.objectId === String(id) && (runtime.deployment?.kind === 'tenant' ? Boolean(owner) && ownedBy(row, owner, runtime.deployment) : true);
}
/** The fixed warning codes a stop shows, from Fabric's own decision. */
function warningsOf(job, phase) {
  const a = job.action, kept = (job.preview?.warnings ?? []).filter(code => code === 'reaches_people');
  return [...new Set([...kept, ...(job.effect === 'delete' ? ['delete'] : []), ...(a.duplicateOfUncertain ? ['duplicate_of_uncertain'] : []), ...(a.askUnless ? ['not_made_by_fabric'] : []),
    ...(phase === 'reads' ? ['prepares_first'] : [])])];
}
const windowOf = (runtime, job) => {
  const deadline = Date.parse(job.executionRequest?.deadline ?? '');
  return new Date(Math.min(runtime.clock() + WINDOW_MS, Number.isFinite(deadline) ? deadline : Infinity)).toISOString();
};

/** The run-time state of one action job: its catalog entry, its account's route, its run-time job and frame (from its prepared row when it
 *  resumes after a stop), its request and byte budgets and its lock. */
function stateOf(runtime, job) {
  const catalog = runtime.actions, cap = runtime.store.get('capabilities', job.capabilityId), item = catalog?.entryOf?.(cap);
  if (!item) throw ending('capability_changed', RUN_WORDS.changed);
  const route = runtime.proxyPolicy.route(job.connectionId), row = runtime.store.get(PREPARED, job.id), content = record(row?.content) ? row.content : null;
  const run = createJob({jobId: job.id, entry: item.entry, appId: cap.appId, identity: route.connection.identity ?? {}, clock: runtime.clock, transforms: catalog.transforms,
    resolved: new Map(Object.entries(content?.resolved ?? {})), now: job.action.now ?? null, runs: Array.isArray(content?.runs) ? content.runs : []});
  return {runtime, job, catalog, cap, item, entry: item.entry, route, run, frame: newFrame(run, job.args, new Map(Object.entries(content?.answers ?? {}))), content,
    typed: runtime.proxyPolicy.typedTemplates(route), sent: [], choices: [...(content?.choices ?? [])], schemas: {...(content?.schemas ?? {})}, requests: 0, bytes: 0, secrets: secretContext([]), lockKey: null,
    // F10.21: the app's success rule, from its reviewed definition first (lib/api-success.mjs), and a missing_scope a readback heard.
    apiRule: apiRuleOf(cap.appId, catalog.identityOf?.(cap.appId) ?? null), narrow: null};
}
const build = (state, step, frame, cursor = null) => buildRequest(state.entry, step, frame, {config: state.route.config, pinned: state.item.capability.action.pinnedParameters ?? {},
  provider: providerHeaders(state.runtime, state.cap.appId), cursor});
/** checkConcrete() with the account's rows, map and typed operations; `mode` is the mode the step runs under. */
const concrete = (state, stepId, built, mode) => checkConcrete(state.entry, stepId, built, {definition: state.route.definition, config: state.route.config, map: state.route.map,
  typed: state.typed, typedMode: capability => state.runtime.proxyPolicy.typed(state.route.connection, capability).mode, stepMode: mode});
/** The account's write lock, taken once and held while the job runs, never across a wait for approval. A read action takes none. */
function lock(state) {
  if (state.job.effect === 'read' || state.lockKey) return;
  const key = `account:${state.job.connectionId}`;
  if (state.runtime.writeLocks.has(key)) throw ending('write_in_progress', RUN_WORDS.write_in_progress, {reason: 'write_in_progress'});
  state.runtime.writeLocks.add(key);
  state.lockKey = key;
}
function persist(state) {
  const {runtime, job} = state;
  // A job whose end user was deleted while it ran is never written back (F03.5).
  if (runtime.deployment?.kind === 'tenant' && !runtime.store.get('jobs', job.id)) throw ending('fabric_failed', RUN_WORDS.not_sent, {reason: 'removed'});
  job.updatedAt = runtime.now();
  runtime.store.put('jobs', job);
}

/**
 * Part i, the outcome table, for one answer: null when it passed, else the error that ends the job. `write` says this request is a write
 * and `earlier` that a write was sent before it. An answer in expect.status passes when its require holds (a reviewed alternative such as
 * Slack's already_reacted is one branch of it). A status the action lists as definitive, a 429 or a 2xx whose require fails changed
 * nothing, so the job fails unless an earlier write was sent (A7); any other answer fails only when nothing could have changed.
 */
function judge(state, step, answer, frame, {write, earlier}) {
  const status = answer.status, at = {providerStatus: status};
  const end = (changed, reason, words = RUN_WORDS.failed, extra = {}) => changed
    ? ending('outcome_uncertain', RUN_WORDS.uncertain, {outcome: 'uncertain', reason, ...at, ...extra})
    : ending('provider_failed', words, {outcome: 'failed', reason, ...at, ...extra});
  if (answer.redirected || answer.notModified) return end(write || earlier, answer.notModified ? 'not_modified' : 'redirect_not_followed');
  if (status === 429 || limited(state.cap.appId, answer)) {
    const value = answer.headers?.['retry-after'], retry = typeof value === 'string' && /^[0-9]{1,7}$/.test(value.trim()) ? Number(value.trim()) : null;
    return end(earlier, 'http_status', RUN_WORDS.limited, {retryAfterSeconds: retry});
  }
  if (!step.expect.status.includes(status)) {
    const changed = CONTENT_CHANGED[step.bindContent] === status;
    // F10.19 part 1: a provider's own reason (Notion's not_shared or capability_off) sits beside the code with its own words.
    const known = changed ? null : providerReason(state.cap.appId, answer);
    if (known) return end(state.entry.action.definitive.includes(status) ? earlier : write || earlier, known, RUN_WORDS[known]);
    return end(state.entry.action.definitive.includes(status) ? earlier : write || earlier, changed ? 'content_changed' : 'http_status', changed ? RUN_WORDS.content_changed : RUN_WORDS.failed);
  }
  const refused = status >= 200 && status < 300 ? ruleFails(state, step, answer, frame) : null;
  if (refused) return end(earlier, 'api_error', RUN_WORDS[refused.error === 'missing_scope' ? 'missing_scope' : 'api_error'], {details: providerDetails(refused), verdict: refused});
  if (status >= 200 && status < 300 && !step.expect.require.every(node => holds(node, frame, answer))) return end(earlier, 'require_failed');
  return null;
}
/** F10.21: an /error branch with a constant: the one form of a reviewed alternative to an app's success rule (Slack's already_reacted). */
const errorBranch = branch => Object.keys(branch).length === 1 && record(branch.equals) && branch.equals.pointer === '/error' && record(branch.equals.value) && Object.hasOwn(branch.equals.value, 'const');
/**
 * F10.21: a 2xx of an app with apiSuccessRequire is held to that rule whatever the step's own require says, so the rule never rests on the
 * validator. It stands only when the rule holds, or when a top-level anyOf of the step's require has an /error branch that holds (a reviewed
 * alternative). Returns the verdict of a refused answer, or null.
 */
function ruleFails(state, step, answer, frame) {
  if (!state.apiRule) return null;
  const verdict = apiVerdict(state.apiRule, answer.data);
  if (verdict.state === 'ok' || step.expect.require.some(node => Object.hasOwn(node, 'anyOf') && node.anyOf.some(branch => errorBranch(branch) && holds(branch, frame, answer)))) return null;
  return verdict;
}

/**
 * Part i: one assertion of a verify block or an expect.require (with `own`, the step's own answer) over a frame: equals, contains, present,
 * absent, statusIn, listHas, listLacks, test and anyOf; an assertion whose when does not hold is not asked. A missing list lacks everything
 * and has nothing; a value that is left out never equals or is contained. A test is one {equals} of the when grammar, for a comparison only
 * a transform can make; its step must have run.
 */
export function holds(node, frame, own = null) {
  if (Object.hasOwn(node, 'when') && !passes(node.when, frame)) return true;
  if (Object.hasOwn(node, 'anyOf')) return node.anyOf.some(item => holds(item, frame, own));
  const answer = own ?? frame.steps.get(node.step);
  if (!answer) return false;
  if (Object.hasOwn(node, 'statusIn')) return node.statusIn.includes(answer.status);
  if (Object.hasOwn(node, 'test')) return passes(node.test, frame);
  const at = pointer => resolvePointer(answer.data, pointer);
  if (Object.hasOwn(node, 'present')) return at(node.present.pointer) !== undefined;
  if (Object.hasOwn(node, 'absent')) return at(node.absent.pointer) === undefined;
  const fits = (kind, actual, expected) => actual !== undefined && expected !== ABSENT && (kind === 'equals' ? same(actual, expected) : contains(actual, expected));
  for (const kind of ['equals', 'contains']) if (Object.hasOwn(node, kind)) return fits(kind, at(node[kind].pointer), evaluate(node[kind].value, frame));
  const kind = Object.hasOwn(node, 'listHas') ? 'listHas' : 'listLacks', list = at(node[kind].list) ?? (kind === 'listLacks' ? [] : undefined);
  if (!Array.isArray(list)) return false;
  const match = element => node[kind].where.every(condition => {
    const test = Object.hasOwn(condition, 'equals') ? 'equals' : 'contains';
    return fits(test, resolvePointer(element, condition.field), evaluate(condition[test], frame));
  });
  return kind === 'listHas' ? list.some(match) : !list.some(match);
}
function contains(actual, expected) {
  if (Array.isArray(actual)) return (Array.isArray(expected) ? expected : [expected]).every(item => actual.some(entry => same(entry, item)));
  return typeof actual === 'string' && typeof expected === 'string' && actual.includes(expected);
}

/**
 * Part j: the authority one request of an action job runs under, checked again before every send. The job's capability, account, binding
 * and policy hash are what it was accepted under; the mode of its gate (prepare, resolve or perform) is the stricter of the one recorded at
 * acceptance (with c7 and askUnless) and the current one; an Ask gate needs the single-action approval of exactly this stop (phase, digest
 * and window), and a perform under Allow the standing binding of exactly these bytes. In a designated store the accepted request is checked
 * too, with this stop's approval record. `window: false` checks everything but the window, after an answer came back.
 */
export function assertActionAuthorization(runtime, job, gate = job.action?.phase === 'final' ? 'perform' : 'prepare', {window = true} = {}) {
  if (!runtime.store.authorityEnabled) runtime.authorizeSource(job);
  let decision;
  // What the job was accepted under no longer holds (a setting, the account or the action changed): every such refusal keeps a code.
  try { decision = runtime.store.authorityEnabled ? runtime.assertAcceptedAuthority(job) : runtime.validateJob(job); }
  catch (error) { if (error && typeof error === 'object' && typeof error.code !== 'string') error.code = 'authority_changed'; throw error; }
  const {cap, connection, permission} = decision, a = job.action;
  if (canonicalHash(cap) !== job.capabilityHash || canonicalHash(connection.identity || {}) !== job.identityHash) throw ending('authority_changed', 'Capability or account changed since this job was prepared.');
  if (permission.bindingHash !== job.connectionBindingHash || permission.policyHash !== job.permissionHash) throw ending('authority_changed', 'Connection authorization or permission setting changed. Create a new request.');
  const current = {prepare: permission.prepareMode, resolve: permission.resolveMode, perform: permission.performMode}[gate], mode = stricter(a.modes[gate] ?? 'deny', current ?? 'deny');
  if (mode === 'deny') throw ending('policy_denied', RUN_WORDS.policy_denied);
  const phase = gate === 'perform' ? 'final' : 'reads', open = !window || Date.parse(job.approvalExpiresAt) > runtime.clock(), bound = Boolean(job.approvedAt) && job.approvalDigest === actionDigest(job) && open;
  if (mode === 'ask' && !(bound && job.approvedBy === 'single-action' && a.approvedPhase === phase && a.phase === phase)) throw ending('approval_required', RUN_WORDS.approval_required);
  if (mode === 'allow' && gate === 'perform' && !(bound && a.phase === 'final')) throw ending('approval_required', RUN_WORDS.approval_required);
  if (runtime.store.authorityEnabled) {
    assertDispatchable({request: decision.request, now: runtime.now(), current: {...decision.current, policy: {...decision.current.policy, decision: mode}}, ...(mode === 'ask' && job.executionApproval ? {approval: job.executionApproval} : {})});
  }
  return {...decision, mode};
}

/**
 * Sends one built request of the job. Credentials are fetched right before it, the account's identity and the job's authority are checked
 * again after the fetch, the call's inputs as typed and the bytes are checked for the credential (an input read before any transform encodes
 * it, so encoded-words that split it hide nothing: docs/F10.15-BUILD-MAP.md section 10, difference 15), Fabric's added headers are recomputed
 * only to compare them with the ones shown (a difference is prepared_changed, and nothing is sent), writesSent is saved before a write, and
 * the bytes go out unchanged. Returns the answer with every credential spelling scrubbed. Nothing is retried. F10.17: a write first waits out
 * its app's gap since the account's last write (lib/write-spacing.mjs), so every check below is decided after the wait; reads never wait.
 * What the last answer's grant header said is applied before this request is decided (settleGrant()), and the header is taken off this
 * answer before anything holds it.
 */
async function send(state, built, {stepId, write, gate}) {
  const {runtime, job} = state, {request} = built, spacing = {appId: state.cap.appId, connectionId: job.connectionId};
  if (++state.requests > BOUNDS.requests) refuse('too_many_requests');
  if (write) await spaceWrite(runtime, spacing);
  settleGrant(state);
  const authority = await runtime.connections.credentials(job.connectionId), context = credentialContext(authority.headers);
  state.secrets = context;
  state.run.useCredentials(context);
  assertNoCredential(job.args, context);
  assertNoCredential([request.url, ...Object.values(request.headers), request.body], context);
  const current = runtime.store.get('connections', job.connectionId);
  if (!current || current.status === 'revoked' || canonicalHash(current.identity || {}) !== job.identityHash) throw ending('authority_changed', RUN_WORDS.account_changed);
  assertActionAuthorization(runtime, job, gate);
  const base = proxyBase(state.route.config.apiBase);
  const providerId = providerOf(runtime, current), grantHeader = grantHeaderOf(providerId);
  if (!Array.isArray(authority.allowedOrigins) || !authority.allowedOrigins.includes(base.origin)) throw ending('fabric_failed', RUN_WORDS.unreachable, {reason: 'proxy_unavailable'});
  const {Authorization: credential, Accept: _accept, ...provider} = authority.headers;
  if (canonicalHash(addedHeaders(request, provider)) !== canonicalHash(built.added)) throw changedBytes();
  const headers = {...request.headers, ...provider, ...(credential ? {Authorization: credential} : {}), Accept: request.headers.Accept || 'application/json',
    ...(request.body !== null ? {'Content-Type': 'application/json; charset=utf-8'} : {})};
  const earlier = job.action.writesSent.length > 0;
  // F10.21: Slack's limit for a distributed app, held before anything is sent (lib/slack-limits.mjs).
  const paced = paceCheck(runtime, current, request);
  if (paced) throw ending(paced.code, paced.words, {outcome: earlier ? 'uncertain' : 'failed', reason: paced.reason, ...(paced.retryAfterSeconds === undefined ? {} : {retryAfterSeconds: paced.retryAfterSeconds})});
  if (write) noteWrite(runtime, spacing);
  if (write) { job.action.writesSent.push(stepId); persist(state); }
  let response;
  try {
    response = await runtime.request({url: request.url, method: request.method, headers, ...(request.body !== null ? {body: request.body} : {}), allowedOrigins: [base.origin],
      timeoutMs: request.timeoutMs, maxBytes: built.maxBytes ?? BOUNDS.responseBytes, responseType: 'json', redirect: 'report', responseHeaders: [...RESPONSE_HEADERS, ...(grantHeader ? [grantHeader] : [])]});
  } catch (error) {
    const sent = error?.sent !== false;
    if (write && !sent) { job.action.writesSent.pop(); persist(state); }
    // F10.12: a refusal at the network seam (the live guard of a certification Fabric) keeps its code, words and details: nothing was sent.
    if (!sent && error?.code === ACTION_REFUSED && record(error.details)) throw ending(ACTION_REFUSED, String(error.message), {outcome: earlier ? 'uncertain' : 'failed', reason: 'live_guard', details: structuredClone(error.details)});
    const reason = /timed out/i.test(error?.message) ? 'timeout' : /size limit/i.test(error?.message) ? 'response_too_large' : 'connection_failed';
    if (sent && (write || earlier)) throw ending('outcome_uncertain', RUN_WORDS.uncertain, {outcome: 'uncertain', reason});
    throw ending(sent ? 'provider_failed' : 'fabric_failed', RUN_WORDS.not_sent, {outcome: earlier ? 'uncertain' : 'failed', reason});
  }
  const taken = takeGrantHeader(response.headers, providerId);
  const answer = scrubAnswer({status: response.status, headers: taken.headers, data: response.data ?? null, ...(response.redirected ? {redirected: true} : {}), ...(response.notModified ? {notModified: true} : {})}, context);
  // F10.17: applied before the job's next request, or when it settles or stops, so the answer that showed a narrowing is kept (lib/grant-drift.mjs).
  state.grantSeen = {connection: current, providerId, value: taken.value, status: answer.status, data: answer.data};
  state.bytes += Buffer.byteLength(JSON.stringify(answer.data));
  const url = new URL(request.url);
  runtime.store.audit({type: 'action.request', jobId: job.id, stepId, gate, method: request.method, origin: url.origin, pathHash: sha256(url.pathname), status: answer.status,
    bodyHash: request.bodyHash, ...(runtime.attribution ? runtime.attribution(job) : {})});
  if (state.bytes > BOUNDS.jobBytes) refuse('too_much_data');
  return {answer, earlier};
}

/** F10.17: what the last answer said about the account's grant (lib/grant-drift.mjs), applied once. */
function settleGrant(state) {
  const seen = state.grantSeen;
  state.grantSeen = null;
  if (seen) observeGrant(state.runtime, seen.connection, seen);
}

/** Runs one read step (phase 1, a perform read or a verify request): each forEach item and each page, every built request placed again
 *  first. `approved` holds the exact reads a phase reads digest bound: a read built with other bytes is not sent (prepared_changed). */
async function readStep(state, step, {gate, mode, approved = null, verify = false}) {
  const items = step.forEach !== undefined ? forEachItems(step, state.frame) : [undefined], answers = [];
  for (const [index, item] of items.entries()) {
    const frame = item === undefined ? state.frame : {...state.frame, item};
    let cursor = null, pages = 0;
    for (;;) {
      const built = concrete(state, step.id, build(state, step, frame, cursor), mode), exact = exactOf(step.id, index, built, step);
      const bound = pages === 0 && approved ? approved.find(entry => entry.stepId === step.id && entry.index === index && entry.template === undefined) : null;
      if (bound && !same(summaryOf(exact), bound)) throw changedBytes();
      const {answer, earlier} = await send(state, built, {stepId: step.id, write: false, gate});
      if (pages === 0) state.sent.push(exact);
      const verdict = verify ? null : judge(state, step, answer, frame, {write: false, earlier});
      if (verdict) throw verdict;
      answers.push(answer);
      pages++;
      const next = step.page !== undefined && !verify ? nextPage(step, answer, {pages, job: state.run, url: built.request.url}) : null;
      if (!next) break;
      cursor = next.cursor;
    }
  }
  state.frame.steps.set(step.id, {status: answers.at(-1).status, headers: answers.at(-1).headers, data: stepData(step, answers)});
  return answers;
}
/** A choice lookup as a read step: its source's template, the input's value where the source reads it ({value: true}, for each item of a
 *  list input), its constants and the choice's configured arguments; path arguments in the path, the others in the query or the body. */
export function lookupStep(state, input) {
  const lookup = state.entry.lookups[input], choice = state.entry.action.choices.find(item => item.input === input), list = Array.isArray(state.job.args[input]);
  let method = lookup.method, path = typeof lookup.template === 'string' ? lookup.template.slice(lookup.template.indexOf(' ') + 1) : null;
  if (path === null) {
    const operation = (state.route.map?.operations ?? []).find(item => item?.id === lookup.operation);
    method = typeof operation?.method === 'string' ? operation.method.toUpperCase() : null;
    path = typeof operation?.path === 'string' ? operation.path : null;
  }
  if (!method || !path) refuse('not_on_member');
  const names = new Set([...path.matchAll(/\{\+?([A-Za-z0-9_]+)\}/g)].map(match => match[1])), params = {}, rest = {};
  for (const [name, argument] of Object.entries(lookup.args)) {
    const node = argument.value === true ? (list ? {item: ''} : {input: `/${input.replace(/~/g, '~0').replace(/\//g, '~1')}`}) : Object.hasOwn(argument, 'const') ? {const: argument.const} : choice?.args?.[name];
    if (node) (names.has(name) ? params : rest)[name] = node;
  }
  return {id: `choice:${input}`, method, path, params, ...(Object.keys(rest).length ? method === 'GET' ? {query: rest} : {body: {object: rest}} : {}),
    ...(list ? {forEach: {over: {input: `/${input}`}, max: BOUNDS.forEach}} : {}), expect: {status: [200], require: []}};
}
/** Runs one choice lookup when its input is given, and keeps "label (id)" for the card from Fabric's own read only. */
async function runLookup(state, input, approved) {
  if (state.job.args[input] === undefined) return;
  const step = lookupStep(state, input), lookup = state.entry.lookups[input];
  const answers = await readStep(state, step, {gate: 'prepare', mode: state.job.action.modes.prepare, approved});
  const values = Array.isArray(state.job.args[input]) ? state.job.args[input] : [state.job.args[input]];
  answers.forEach((answer, index) => {
    const id = resolvePointer(answer.data, lookup.value), label = lookup.label.map(pointer => resolvePointer(answer.data, pointer)).filter(value => typeof value === 'string' && value).join(' ');
    if (id !== undefined && String(id) === String(values[index]) && label) state.choices.push({input, id: String(id), label});
  });
}
/** A resource-dependent input's schema, derived from its own schema steps' answers; its hash binds the approval (part j of F10.9). */
function derive(state, input) {
  const {derive: call} = input.schema, args = {};
  for (const [name, node] of Object.entries(call.args)) { const value = evaluate(node, state.frame); if (value !== ABSENT) args[name] = value; }
  let pair;
  try { pair = structuredClone(state.run.transform(call.transform, args)); } catch (error) { if (error instanceof TransformError) refuse(error.code, {transform: call.transform}); throw error; }
  const resource = Object.fromEntries(input.dependsOn.map(name => [name, state.job.args[name]]));
  return {pair, hash: resolvedSchemaHash({resource, transform: call.transform, codeHash: state.catalog.pins?.[call.transform], schema: pair?.schema, bindings: pair?.bindings})};
}

/** Part h: the reads a stop at acceptance will send, built with no network call: exact where their bytes are known from inputs, the account,
 *  the clock or a resolved schema, and as their template when an earlier answer fills them. */
function knownReads(state) {
  const {entry, job} = state, skipped = new Set(job.action.plan.skipped), reads = [], base = proxyBase(state.route.config.apiBase);
  for (const placement of entry.placements) {
    if (!READ_PHASES.has(placement.phase) || skipped.has(placement.stepId)) continue;
    const step = placement.phase === 'lookup' ? (job.args[placement.stepId.slice('choice:'.length)] === undefined ? null : lookupStep(state, placement.stepId.slice('choice:'.length))) : stepOf(entry, placement.stepId);
    if (!step) continue;
    if (answerSlots(step).some(readsAnswer)) { reads.push({stepId: step.id, template: `${step.method} ${step.path}`, method: step.method, url: `${base.origin}${base.basePath}${step.path}`}); continue; }
    if (!stepRuns(step, state.frame)) continue;
    const items = step.forEach !== undefined ? forEachItems(step, state.frame) : [undefined];
    items.forEach((item, index) => reads.push(exactOf(step.id, index, concrete(state, step.id, build(state, step, item === undefined ? state.frame : {...state.frame, item}), job.action.modes.prepare), step)));
  }
  return reads;
}

/**
 * Part h: decides an accepted action job with no network call. Its phase modes are the decision's, with c7 already in them and askUnless
 * added to perform (D3: editing an object Fabric did not make on this account, for this owner, asks); its plan, write rows (for c7) and
 * resolving step are kept on the job. Under an Allow prepare mode the job is queued in phase prepare; otherwise it waits in phase reads,
 * with each read it will send (and its resolving write, when its bytes are known and resolveMode asks) bound by the digest. Returns the
 * prepared row to store beside a waiting job, or null.
 */
export function acceptAction(runtime, {job, cap, connection, permission, owner = null}) {
  const item = runtime.actions.entryOf(cap), entry = item.entry, ask = entry.action.askUnless?.createdByFabric;
  const askUnless = Boolean(ask) && !madeByFabric(runtime, connection.id, ask.kind, job.args[ask.input], owner);
  const byStep = new Map(permission.steps.map(step => [step.stepId, step]));
  const plan = runPlan(entry, {accessOf: placement => byStep.get(placement.stepId)?.providerAccess ?? 'unknown', modeOf: placement => byStep.get(placement.stepId)?.mode ?? 'deny'});
  const modes = {prepare: permission.prepareMode, resolve: permission.resolveMode, perform: askUnless ? stricter(permission.performMode, 'ask') : permission.performMode};
  job.action = {version: 1, phase: modes.prepare === 'allow' ? 'prepare' : 'reads', twoPhase: entry.twoPhase, modes, duplicateOfUncertain: permission.duplicateOfUncertain === true, askUnless,
    plan: {run: [...plan.run], skipped: [...plan.skipped]}, writeRows: [...new Set(entry.placements.filter(placement => placement.phase === 'perform' && placement.effect !== 'read').map(placement => `group:${placement.groupId}`))],
    resolvingStepId: entry.action.perform.find(step => step.resolves === true)?.id ?? null, readsDone: false, reads: [], resolving: null, perform: null, skipped: [], now: null, jobKeys: {},
    schemaHashes: {}, preparedHash: null, writesSent: [], approvedPhase: null, decisions: [], approvals: []};
  job.preview.warnings = warningsOf(job, job.action.phase);
  if (job.action.phase === 'prepare') { job.status = 'queued'; return null; }
  const state = stateOf(runtime, job), reads = knownReads(state), resolving = entry.action.perform.find(step => step.resolves === true);
  const known = resolving && modes.resolve === 'ask' && !answerSlots(resolving).some(readsAnswer) && stepRuns(resolving, state.frame);
  const exact = known ? exactOf(resolving.id, 0, concrete(state, resolving.id, build(state, resolving, state.frame), modes.resolve), resolving) : null;
  job.status = 'awaiting_approval';
  job.approvalExpiresAt = windowOf(runtime, job);
  job.action.reads = reads.map(summaryOf);
  job.action.resolving = exact ? summaryOf(exact) : null;
  return save(state, 'reads', {reads, resolving: exact});
}

/** Stores the job's prepared row for this phase (its clock reading, job keys, transform runs, phase 1 answers, resolved schemas, and the
 *  exact requests the stop shows), records its hash and the schema hashes on the job and computes the stop's digest. Returns the row. */
function save(state, phase, {reads = state.sent, resolving = null, perform = null, fields = []} = {}) {
  const {runtime, job, run, frame} = state, snapshot = run.snapshot(), a = job.action;
  a.now = snapshot.now;
  a.jobKeys = snapshot.jobKeys;
  a.schemaHashes = Object.fromEntries(Object.entries(state.schemas).map(([input, read]) => [input, read.hash]));
  const content = {phase, now: snapshot.now, jobKeys: snapshot.jobKeys, runs: run.runsOf(), answers: Object.fromEntries(frame.steps), resolved: Object.fromEntries(run.resolved), schemas: state.schemas,
    reads, resolving, perform, fields, choices: state.choices};
  a.preparedHash = canonicalHash(content);
  const row = {id: job.id, connectionId: job.connectionId, ...(job.userRecordId ? stampOwner({}, {subjectId: job.ownership.owner.id, userRecordId: job.userRecordId}) : {}), expiresAt: job.approvalExpiresAt, content};
  runtime.store.put(PREPARED, row);
  job.approvalDigest = actionDigest(job);
  return row;
}
/**
 * Part j: a stop for an approval after phase 1 ran: a second phase reads stop before the resolving write, or phase final. A job that sent a
 * perform write other than its resolving write never stops: it ends uncertain with no card (the contract refuses the same transition).
 */
function stop(state, phase, extra) {
  const {runtime, job} = state, a = job.action;
  if (a.writesSent.some(stepId => stepId !== a.resolvingStepId)) throw ending('outcome_uncertain', RUN_WORDS.card_after_write, {outcome: 'uncertain', reason: 'card_after_write'});
  assertStateTransition('running', 'awaiting_approval', {effect: job.effect, kind: 'action', writesSent: [...a.writesSent], resolvingStepId: a.resolvingStepId});
  a.phase = phase;
  a.approvedPhase = null;
  job.approvedAt = null;
  job.approvedBy = null;
  job.approvalExpiresAt = windowOf(runtime, job);
  if (phase === 'reads') { a.reads = state.sent.map(summaryOf); a.resolving = summaryOf(extra.resolving); }
  save(state, phase, extra);
  job.status = 'awaiting_approval';
  job.preview.warnings = warningsOf(job, phase);
  return 'stopped';
}

/**
 * Part h: phase 1 of an action job, inside execute(). Guards without `after` first; then its schema, lookup and prepare reads in runPlan()
 * order, each guard after its step and each resource-dependent input derived after its last schema step; then, for a two-phase action,
 * its resolving write, sent only under resolveMode (a stop shows its exact bytes when that asks) with writesSent saved first and the
 * account's lock taken; then the perform bytes, built once with their card fields, and stored in actionPrepared. Returns 'stopped' when
 * the job now waits for an approval, else 'prepared'.
 */
export async function prepareAction(runtime, job, state) {
  const {entry} = state, a = job.action, skipped = new Set(a.plan.skipped);
  if (!a.readsDone) {
    const approved = a.approvedPhase === 'reads' ? a.reads : null;
    for (const guard of entry.action.guards) if (guard.after === undefined) checkGuard(guard, state.frame);
    const lastSchema = new Map((entry.action.resolvedInputs ?? []).map(input => [input.schema.steps.at(-1).id, input]));
    const resolved = {};
    for (const placement of entry.placements) {
      if (!READ_PHASES.has(placement.phase) || skipped.has(placement.stepId)) continue;
      if (placement.phase === 'lookup') { await runLookup(state, placement.stepId.slice('choice:'.length), approved); continue; }
      const step = stepOf(entry, placement.stepId);
      if (stepRuns(step, state.frame)) await readStep(state, step, {gate: 'prepare', mode: a.modes.prepare, approved});
      else a.skipped.push(step.id);
      for (const guard of entry.action.guards) if (guard.after === step.id) checkGuard(guard, state.frame);
      const input = lastSchema.get(step.id);
      if (input) {
        const {pair, hash} = derive(state, input);
        state.run.resolved.set(input.input, pair);
        resolved[input.input] = pair;
        // Kept beside the run, never on the job: the stop being run is bound by its own digest until save() binds the next one.
        state.schemas[input.input] = {readAt: runtime.now(), hash};
      }
    }
    if (entry.action.resolvedInputs?.length) {
      try { validateInput(effectiveInputSchema(entry, resolved), job.args); } catch { throw ending('invalid_arguments', RUN_WORDS.invalid_values, {reason: 'values_invalid'}); }
    }
    a.readsDone = true;
  } else state.sent = [...(state.content?.reads ?? [])].filter(read => read.template === undefined);
  // The resolving write (R2): its exact bytes approved, or bound under standing Allow, before it is sent.
  const resolving = entry.action.perform.find(step => step.resolves === true && !skipped.has(step.id));
  if (resolving && !a.writesSent.includes(resolving.id) && stepRuns(resolving, state.frame)) {
    const built = concrete(state, resolving.id, build(state, resolving, state.frame), a.modes.resolve), exact = exactOf(resolving.id, 0, built, resolving);
    if (a.modes.resolve === 'ask') {
      if (!(a.phase === 'reads' && a.approvedPhase === 'reads' && a.resolving !== null)) return stop(state, 'reads', {reads: state.sent, resolving: exact});
      if (!same(summaryOf(exact), a.resolving)) throw changedBytes();
    }
    lock(state);
    const {answer, earlier} = await send(state, built, {stepId: resolving.id, write: true, gate: 'resolve'});
    const verdict = judge(state, resolving, answer, state.frame, {write: true, earlier});
    if (verdict) throw verdict;
    state.frame.steps.set(resolving.id, {status: answer.status, headers: answer.headers, data: answer.data});
  }
  // The perform bytes, built once: dispatch sends exactly these and never builds them again.
  const perform = [];
  for (const step of entry.action.perform) {
    if (step.resolves === true) continue;
    if (skipped.has(step.id) || !stepRuns(step, state.frame)) { a.skipped.push(step.id); continue; }
    if (step.requiresScope !== undefined && (step.requiresScope.when === undefined || passes(step.requiresScope.when, state.frame)) && state.route.connection.authMethod === 'oauth'
      && !runtime.permissions.grantedScopes(state.route.connection).includes(step.requiresScope.scope)) refuse('scope_missing');
    const items = step.forEach !== undefined ? forEachItems(step, state.frame) : [undefined];
    items.forEach((item, index) => perform.push(exactOf(step.id, index, concrete(state, step.id, build(state, step, item === undefined ? state.frame : {...state.frame, item}), a.modes.perform), step)));
  }
  a.perform = perform.map(summaryOf);
  const values = buildPreview(entry, state.frame), fields = entry.action.preview.map((line, index) => ({label: line.label, value: values[index]})).filter(field => field.value !== undefined);
  state.final = {reads: state.sent, perform, fields};
  return 'prepared';
}

/** Phase 2 at dispatch: the resource-dependent inputs' schema steps sent again with the same bytes, refused input_schema_changed before
 *  any write when a derived schema hash moved. F10.19 part 1: a schema step its when skipped at prepare is skipped again, never refused
 *  as prepared_changed; when the fresh answers would run a step that was skipped, or skip one that ran, the resource changed shape, and the
 *  job ends input_schema_changed before that step or any write is sent. */
async function recheckSchemas(state, content) {
  const {entry, job} = state, a = job.action;
  for (const input of entry.action.resolvedInputs ?? []) {
    for (const step of input.schema.steps) {
      if (a.plan.skipped.includes(step.id)) continue;
      const ran = !a.skipped.includes(step.id);
      if (ran !== stepRuns(step, state.frame)) throw ending('input_schema_changed', RUN_WORDS.input_schema_changed, {reason: 'input_schema_changed'});
      if (!ran) continue;
      const exact = (content.reads ?? []).find(read => read.stepId === step.id && read.template === undefined);
      if (!exact) throw changedBytes();
      const built = concrete(state, step.id, builtOf(exact), job.action.modes.perform);
      const {answer, earlier} = await send(state, built, {stepId: step.id, write: false, gate: 'perform'});
      const verdict = judge(state, step, answer, state.frame, {write: false, earlier});
      if (verdict) throw verdict;
      state.frame.steps.set(step.id, {status: answer.status, headers: answer.headers, data: answer.data});
    }
    if (derive(state, input).hash !== job.action.schemaHashes[input.input]) throw ending('input_schema_changed', RUN_WORDS.input_schema_changed, {reason: 'input_schema_changed'});
  }
}

/**
 * Part i: phase 2. The prepared row must hash to what the digest bound; the schema steps run again with the same bytes; then each stored
 * perform request is compared with its approved entry (its body hashed again), placed again and sent unchanged, under the account's lock.
 * A paged read continues from its stored first page. Then the readback, the checked output (withheld when authority changed by the last
 * answer) and, after a verified write, the record askUnless reads.
 */
export async function executeAction(runtime, job, state) {
  const {entry} = state, a = job.action;
  assertActionAuthorization(runtime, job, 'perform');
  const row = runtime.store.get(PREPARED, job.id), content = row?.content;
  if (!record(content) || canonicalHash(content) !== a.preparedHash || content.phase !== 'final' || !Array.isArray(content.perform) || content.perform.length !== a.perform.length) throw changedBytes();
  await recheckSchemas(state, content);
  lock(state);
  const byStep = new Map();
  for (const [index, exact] of content.perform.entries()) {
    if (!same(rehashed(exact), a.perform[index])) throw changedBytes();
    const step = stepOf(entry, exact.stepId), placement = entry.placements.find(item => item.stepId === step.id), write = placement.effect !== 'read';
    const frame = step.forEach !== undefined ? {...state.frame, item: forEachItems(step, state.frame)[exact.index]} : state.frame;
    let built = concrete(state, step.id, builtOf(exact), a.modes.perform), pages = 0;
    const answers = byStep.get(step.id) ?? [];
    for (;;) {
      const {answer, earlier} = await send(state, built, {stepId: step.id, write, gate: 'perform'});
      const verdict = judge(state, step, answer, frame, {write, earlier});
      if (verdict) throw verdict;
      answers.push(answer);
      pages++;
      const next = step.page !== undefined ? nextPage(step, answer, {pages, job: state.run, url: built.request.url}) : null;
      if (!next) break;
      built = concrete(state, step.id, build(state, step, frame, next.cursor), a.modes.perform);
    }
    byStep.set(step.id, answers);
    state.frame.steps.set(step.id, {status: answers.at(-1).status, headers: answers.at(-1).headers, data: stepData(step, answers)});
  }
  const verification = await verifyAction(runtime, job, state);
  let output;
  try { output = buildOutput(entry, state.frame); }
  catch (error) {
    // Once a write went out, an output a transform refuses must never say nothing was sent.
    if (!transformRefused(error) || !a.writesSent.length) throw error;
    throw ending('outcome_uncertain', RUN_WORDS.unverified, {outcome: 'uncertain', reason: 'not_verified'});
  }
  try { assertActionAuthorization(runtime, job, 'perform', {window: false}); }
  catch { throw ending('authority_changed', RUN_WORDS.authority_changed, {outcome: a.writesSent.length ? 'uncertain' : 'failed', reason: 'authority_changed'}); }
  const verified = entry.effect === 'read' || verification.status === 'verified';
  const keep = retentionOf(state.cap.appId);
  // F10.21 (lib/retention.mjs): an app with a shorter retention keeps the data until keepUntil, and the job says so for the sweep.
  job.result = {data: scrubValue(output, state.secrets), verification, ...(keep === null ? {} : {keepUntil: new Date(runtime.clock() + keep).toISOString()})};
  if (keep !== null) job.retention = state.cap.appId;
  job.status = verified ? 'succeeded' : 'uncertain';
  Object.assign(job, verified ? {errorCode: null, error: null, reason: null} : {errorCode: 'outcome_uncertain', error: RUN_WORDS.unverified, reason: 'not_verified'});
  if (verified && entry.action.records !== undefined) rememberMade(state);
  // F10.19: a full Search of an app's shared pages notes their count on the account (lib/connection-notes.mjs); any other job notes nothing.
  if (verified) notePages(runtime.store, job, {appId: state.cap.appId, key: entry.key}, job.result.data, runtime.now());
}
/** After a verified write: Fabric made this object on this account, for this owner, as the readback identity read it. */
function rememberMade(state) {
  const {runtime, job, entry} = state, {kind, pointer} = entry.action.records;
  const identity = entry.action.verify.identity.find(item => item.kind === 'readback' && item.pointer === pointer), value = resolvePointer(state.frame.steps.get(identity.step)?.data, pointer);
  if (!(typeof value === 'string' && value) && !Number.isSafeInteger(value)) return;
  const owner = job.userRecordId ? {subjectId: job.ownership.owner.id, userRecordId: job.userRecordId} : null;
  runtime.store.put(RECORDS, {id: recordId(job.connectionId, kind, value), connectionId: job.connectionId, kind, objectId: String(value), actionId: entry.id, jobId: job.id, createdAt: runtime.now(),
    ...(owner ? stampOwner({}, owner) : {})});
}

/** Part i: one identity of a verify block over the frame: a readback pointer equal to what a perform step answered or sent, the address
 *  read back gone (404 or 410), or membership in a list the readback holds, for each item of a forEach perform step when it names one. */
export function identityHolds(entry, item, frame) {
  const answer = frame.steps.get(item.step);
  if (!answer) return false;
  if (item.kind === 'readback') { const actual = resolvePointer(answer.data, item.pointer), expected = evaluate(item.equals, frame); return actual !== undefined && expected !== ABSENT && same(actual, expected); }
  if (item.kind === 'address') return answer.status === 404 || answer.status === 410;
  const kind = Object.hasOwn(item, 'listHas') ? 'listHas' : 'listLacks', node = {step: item.step, [kind]: item[kind]};
  if (item.forEach === undefined) return holds(node, frame);
  return forEachItems(stepOf(entry, item.forEach), frame).every(element => holds(node, {...frame, item: element}));
}
/**
 * Part i: the readback. Each verify request that runs is built from the answers, placed again and sent; its answer must be in its
 * expect.status with its require holding. Then every identity (readback, address, membership, per forEach item) and every assertion.
 * All pass is verified; anything else, a provider answer or a lost connection included, is unverified. A read action has no readback: its
 * answer is observed.
 */
export async function verifyAction(runtime, job, state) {
  const verify = state.entry.action.verify, checkedAt = () => runtime.now();
  if (!verify) return {kind: 'provider-response', status: 'observed', checkedAt: checkedAt()};
  let passed = true;
  for (const step of verify.requests) {
    if (!stepRuns(step, state.frame)) continue;
    try {
      const [answer] = await readStep(state, step, {gate: 'perform', mode: job.action.modes.perform, verify: true});
      // F10.21: a readback the app's rule refuses never verifies; a missing_scope narrows the account once the job is written.
      const refused = answer.status >= 200 && answer.status < 300 ? ruleFails(state, step, answer, state.frame) : null;
      if (refused?.error === 'missing_scope') state.narrow = refused;
      if (answer.redirected || answer.notModified || !step.expect.status.includes(answer.status) || (answer.status >= 200 && answer.status < 300 && !step.expect.require.every(node => holds(node, state.frame, answer)))) { passed = false; break; }
      if (refused) { passed = false; break; }
    } catch (error) {
      // F10.21: a readback Slack's pace refused before sending leaves the write unverified, never failed (lib/slack-limits.mjs).
      if (error?.code === 'rate_limited') { passed = false; break; }
      if (!['outcome_uncertain', 'provider_failed'].includes(error?.code)) throw error;
      passed = false;
      break;
    }
  }
  // F10.15: an action with paths reads each path's write back with that path's own verify requests, so an identity is asked when its
  // request ran, as an assertion is asked when its when holds; the validator gives every path with a write at least one identity.
  const ran = new Set(verify.requests.filter(step => stepRuns(step, state.frame)).map(step => step.id)), asked = verify.identity.filter(item => ran.has(item.step));
  // A read-back a transform refuses confirms nothing, like a refused read: the write stands unverified, its words true and its output kept.
  let ok = false;
  try { ok = passed && asked.length > 0 && asked.every(item => identityHolds(state.entry, item, state.frame)) && verify.assert.every(node => holds(node, state.frame)); }
  catch (error) { if (!transformRefused(error)) throw error; }
  return {kind: 'action-readback', status: ok ? 'verified' : 'unverified', checkedAt: checkedAt()};
}

/**
 * Runs one queued action job from where it stands (execute()): phase 1 when its reads have not run or its resolving write waits, then
 * phase 2 straight on under a standing Allow (bound to exactly these bytes) or a stop for the final bytes. Every ending follows the outcome
 * table: failed while no write was sent, uncertain once one was. The lock is released and the prepared row removed when the job settles.
 */
export async function runAction(runtime, job) {
  const {store} = runtime, id = job.id, tenant = runtime.deployment?.kind === 'tenant';
  if (!record(job.action) || !Array.isArray(job.action.writesSent)) job.action = {...(record(job.action) ? job.action : {}), writesSent: Array.isArray(job.action?.writesSent) ? job.action.writesSent : []};
  runtime.running.add(id);
  let state = null, narrow = null;
  try {
    if (!record(job.action.modes)) throw ending('fabric_failed', RUN_WORDS.changed, {reason: 'job_invalid'});
    state = stateOf(runtime, job);
    job.status = 'running';
    persist(state);
    if (job.action.phase !== 'final') {
      if (await prepareAction(runtime, job, state) === 'stopped') return job;
      if (job.action.modes.perform === 'ask') { stop(state, 'final', state.final); return job; }
      // Standing Allow binds exactly these bytes: a digest over them, made by Fabric, checked again before every send.
      job.action.phase = 'final';
      job.action.approvedPhase = null;
      job.approvalExpiresAt = windowOf(runtime, job);
      save(state, 'final', state.final);
      job.approvedAt = runtime.now();
      job.approvedBy = 'standing-policy';
    }
    await executeAction(runtime, job, state);
  } catch (error) {
    // The outcome table decided it where it could (a definitive refusal of the first write changed nothing); otherwise a sent write is uncertain.
    const status = error?.outcome === 'failed' || error?.outcome === 'uncertain' ? error.outcome : job.action.writesSent.length > 0 ? 'uncertain' : 'failed';
    job.status = status;
    job.result = null;
    job.errorCode = status === 'uncertain' && error?.code !== 'authority_changed' ? 'outcome_uncertain' : typeof error?.code === 'string' ? error.code : 'fabric_failed';
    // A refusal's words, and a failed send's, were written for a request that never left. Once a write went out the job must say so, however it
    // ended: a false "Nothing was sent" invites a second send. The code, reason and details stay.
    const stale = status === 'uncertain' && job.action.writesSent.length > 0 && (error?.code === ACTION_REFUSED || error?.message === RUN_WORDS.not_sent);
    job.error = scrubString(String((stale ? RUN_WORDS.uncertain : error?.message) || 'The action could not be completed.'), state?.secrets ?? secretContext([])).slice(0, 600);
    job.reason = typeof error?.reason === 'string' ? error.reason : null;
    for (const key of ['providerStatus', 'retryAfterSeconds']) if (error?.[key] !== undefined) job[key] = error[key];
    if (record(error?.details)) job.details = structuredClone(error.details);
    if (error?.verdict?.error === 'missing_scope') narrow = error.verdict;
  } finally {
    if (state) settleGrant(state);
    const gone = tenant && !store.get('jobs', id), settled = job.status !== 'awaiting_approval';
    if (!gone) { job.updatedAt = runtime.now(); store.put('jobs', job); }
    // F10.21 part b: only once the job's own record is written, Slack's missing_scope narrows the account.
    if (!gone && (narrow ?? state?.narrow)) narrowOnMissingScope(runtime, job.connectionId, narrow ?? state.narrow);
    runtime.running.delete(id);
    if (state?.lockKey) runtime.writeLocks.delete(state.lockKey);
    if (settled) store.delete(PREPARED, id);
    if (!gone && settled) {
      store.audit({type: 'job.completed', jobId: id, status: job.status, capabilityId: job.capabilityId, connectionId: job.connectionId, ...(runtime.attribution ? runtime.attribution(job) : {})});
      const stats = store.get('capabilityStats', job.capabilityId) || {id: job.capabilityId, runs: 0, succeeded: 0, failed: 0, uncertain: 0};
      stats.runs++; stats[job.status] = (stats[job.status] || 0) + 1; stats.lastRunAt = job.updatedAt;
      store.put('capabilityStats', stats);
    }
  }
  return job;
}

// F10.12 part 2 (docs/F10.12-BUILD-MAP.md part 2): the live-test runner, its plans and its evidence. scripts/live-certify.mjs starts a
// certification Fabric (lib/certification.mjs) and gives runLiveTests() a port: the fabric/0.1 client calls on one grant per test, and
// read-only lookups. The port has no approve, decide, set, reset or promote member, and this file imports no owner-side module, so the
// runner can only send what an agent sends and wait: the owner approves every card on Fabric's own page and changes every row on the app
// page. checkPlan() checks a plan (catalog/live-tests/<appId>.json, its format in catalog/live-tests/README.md); evidenceRecords() and
// writeEvidence() turn a run into docs/live-evidence/<appId>/actions.json, which evidencePasses() reads, after assertEvidenceSafe() has
// refused anything secret. Nothing here sends a request itself.
import {createHash, createHmac} from 'node:crypto';
import {chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {placeRequest} from './action-placement.mjs';
import {PERMISSION_GROUPS} from './permission-groups.mjs';
import {PROXY_CONFIGS} from './proxy-config.mjs';
import {proxyBase} from './proxy-request.mjs';
import {codeHash, harnessHash, PINS, ROOT} from './transform-pins.mjs';
import {addDays, offsetAt, validDate, validZone, zonedInstant} from './live-guard.mjs';

/** The plan's fixed limits: the run window's days (the guard's), each test grant's life, the waits. */
export const PLAN_LIMITS = Object.freeze({firstDay: 7, lastDay: 13, grantSeconds: 4 * 60 * 60, pollMs: 1000, untilMs: 5 * 60_000, ownerWaitMs: 30 * 60_000, tests: 50, steps: 20, checks: 20, requests: 5, goneReads: 5});
/** Token-shaped prefixes no evidence may hold: Google, GitHub, Slack and Notion credentials. */
export const TOKEN_PREFIXES = Object.freeze(['ya29.', '1//', 'gho_', 'ghp_', 'ghu_', 'ghr_', 'ghs_', 'github_pat_', 'xoxp-', 'xoxb-', 'xoxe-', 'ntn_', 'secret_']);
export const STEP_KINDS = Object.freeze(['call', 'race', 'read', 'owner', 'oneTimeAsk', 'ask']);
export const PLACEHOLDERS = Object.freeze(['$text', '$saved', '$recorded', '$day', '$at', '$local', '$owner', '$branch', '$in']);
/** F10.17: the step kinds an undo's steps take. An ask step changes no row, so it may undo (H9's branches); a one-time Ask may not. */
const UNDO_KINDS = Object.freeze(['call', 'read', 'owner', 'ask']);

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const TEST_ID = /^[A-Za-z][A-Za-z0-9-]{0,15}$/, NAME = /^[A-Za-z][A-Za-z0-9]{0,39}$/, ROW = /^[a-z0-9][a-z0-9.-]{0,127}$/, APP = /^[a-z][a-z0-9-]{1,63}$/;
const ACTION = /^([a-z][a-z0-9-]{0,63})@([1-9][0-9]{0,3})$/, TIME = /^([01][0-9]|2[0-3]):([0-5][0-9])$/, POINTER = /^(?:\/[^\u0000-\u001f]*)?$/;
const SLOT = /\{(\+?)([A-Za-z][A-Za-z0-9_]{0,39})\}/g, METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const EMAIL_IN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/;
const sha256 = text => createHash('sha256').update(text).digest('hex');
const words = (value, max = 500) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
const listWords = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} or ${items.at(-1)}`;
/** F10.17: a $branch suffix, after fabric/test-<runId>-. */
const BRANCH_SUFFIX = /^[a-z0-9]{1,16}$/;
const sortKeys = value => Array.isArray(value) ? value.map(sortKeys) : record(value) ? Object.fromEntries(Object.keys(value).sort().map(name => [name, sortKeys(value[name])])) : value;
const deepFreeze = value => { if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) { Object.freeze(value); for (const item of Object.values(value)) deepFreeze(item); } return value; };

// ---- the plan ---------------------------------------------------------------------------------------------------------------------
const CHECK_WORDS = 'a check is one of {status}, {pointer, equals}, {pointer, present}, {pointer, count}, {pointer, oneOf}, {pointer, where, field, equals} or {gone}';
/** The closed form of each part of a plan, by its name in the refusal words. */
const FIELDS = Object.freeze({
  'a live test plan': ['schemaVersion', 'appId', 'note', 'recorded', 'readRows', 'timeZone', 'gone', 'tests'],
  'a test': ['id', 'name', 'cleanup', 'steps', 'undo'], undo: ['test', 'steps', 'none'],
  call: ['action', 'args', 'expect', 'save', 'checks'], race: ['action', 'args', 'status', 'readback'], read: ['method', 'path', 'params', 'query', 'checks', 'save'],
  owner: ['words', 'until'], until: ['path', 'params', 'query', 'checks'], oneTimeAsk: ['row', 'requests'], ask: ['row', 'requests'], request: ['method', 'path', 'params', 'query'],
  readback: ['path', 'params', 'query', 'pointer', 'output'], timeZone: ['path', 'pointer'], gone: ['pointer', 'equals'],
});

/** The structure of a plan, with no catalog: closed fields, test ids, step kinds, checks, placeholders, paths, days and names saved before
 *  use. Returns a frozen copy, or throws `Live test plan <appId>: <where>: <what>`. The command runs it before anything opens. */
export function checkPlanShape(plan) {
  const appId = record(plan) && APP.test(plan.appId ?? '') ? plan.appId : '(no app)';
  const fail = (where, what) => { throw new Error(`Live test plan ${appId}: ${where}: ${what}`); };
  const closed = (value, kind, where) => {
    if (!record(value)) fail(where, `${kind} is an object`);
    for (const key of Object.keys(value)) if (!FIELDS[kind].includes(key)) fail(where, `${key} is not a field of ${kind}`);
  };
  closed(plan, 'a live test plan', 'plan');
  if (plan.schemaVersion !== 1) fail('plan', 'schemaVersion is 1');
  if (!APP.test(plan.appId ?? '')) fail('appId', 'an app id is lowercase letters, digits and hyphens');
  if (!words(plan.note, 1000)) fail('note', 'a note says what the plan covers, in at most 1,000 characters');
  if (!record(plan.recorded) || Object.keys(plan.recorded).length > 20) fail('recorded', 'recorded names at most 20 values Muse records before the run');
  for (const [name, said] of Object.entries(plan.recorded)) if (!NAME.test(name) || !words(said)) fail(`recorded.${name}`, 'a recorded value has a short name and words that say what it is');
  if (!Array.isArray(plan.readRows) || plan.readRows.length > 10 || plan.readRows.some(row => typeof row !== 'string' || !ROW.test(row)) || new Set(plan.readRows).size !== plan.readRows.length) {
    fail('readRows', 'readRows lists at most 10 distinct row ids');
  }
  if (plan.timeZone !== undefined) {
    closed(plan.timeZone, 'timeZone', 'timeZone');
    checkPath(plan.timeZone.path, undefined, 'timeZone.path', fail);
    if (typeof plan.timeZone.pointer !== 'string' || !POINTER.test(plan.timeZone.pointer)) fail('timeZone.pointer', 'a pointer is empty or starts with /');
  }
  if (plan.gone !== undefined) {
    closed(plan.gone, 'gone', 'gone');
    if (typeof plan.gone.pointer !== 'string' || !POINTER.test(plan.gone.pointer) || plan.gone.equals === undefined) fail('gone', 'gone is {pointer, equals}');
  }
  if (!Array.isArray(plan.tests) || plan.tests.length < 1 || plan.tests.length > PLAN_LIMITS.tests) fail('tests', `a plan has 1 to ${PLAN_LIMITS.tests} tests`);
  const ids = new Set(), saved = new Set(), recorded = new Set(Object.keys(plan.recorded));
  const use = (value, where) => placeholders(value, where, {saved, recorded, fail});
  for (const [index, item] of plan.tests.entries()) {
    const where = `tests[${index}]`;
    closed(item, 'a test', where);
    if (typeof item.id !== 'string' || !TEST_ID.test(item.id)) fail(where, 'a test id is a short name such as C2');
    if (ids.has(item.id)) fail(where, `test id ${item.id} is used twice`);
    ids.add(item.id);
    if (!words(item.name, 200)) fail(where, 'a test has a name of at most 200 characters');
    if (!Array.isArray(item.steps) || item.steps.length < 1 || item.steps.length > PLAN_LIMITS.steps) fail(where, `a test has 1 to ${PLAN_LIMITS.steps} steps`);
    for (const [at, step] of item.steps.entries()) checkStep(step, `${where}.steps[${at}]`, {use, saved, fail, closed, kinds: STEP_KINDS});
    // A cleanup test only tidies what the run left (the owner's steps, a one-time Ask's deletes, reads): it calls no action and undoes
    // nothing, so leaving it out (--leave) never touches an action's evidence; and cleanup comes last, so leaving it out skips no real test.
    if (item.cleanup !== undefined) {
      if (item.cleanup !== true) fail(`${where}.cleanup`, 'cleanup is true or absent');
      if (item.steps.some(step => step.call !== undefined || step.race !== undefined)) fail(where, `${item.id} is cleanup, so it calls no action`);
      if (item.undo !== undefined && item.undo.none === undefined) fail(`${where}.undo`, `${item.id} is cleanup, so it undoes nothing`);
    } else if (plan.tests.slice(0, index).some(other => other.cleanup === true)) fail(where, `${item.id} comes after a cleanup test: cleanup tests come last`);
    if (item.undo !== undefined) {
      closed(item.undo, 'undo', `${where}.undo`);
      const kinds = Object.keys(item.undo);
      if (kinds.length !== 1) fail(`${where}.undo`, 'undo is exactly one of test, steps or none');
      if (kinds[0] === 'none' && !words(item.undo.none)) fail(`${where}.undo.none`, 'none says why nothing is undone');
      if (kinds[0] === 'test' && (typeof item.undo.test !== 'string' || !TEST_ID.test(item.undo.test))) fail(`${where}.undo.test`, 'test names a later test');
      if (kinds[0] === 'steps') {
        if (!Array.isArray(item.undo.steps) || item.undo.steps.length < 1 || item.undo.steps.length > PLAN_LIMITS.steps) fail(`${where}.undo.steps`, `an undo has 1 to ${PLAN_LIMITS.steps} steps`);
        for (const [at, step] of item.undo.steps.entries()) checkStep(step, `${where}.undo.steps[${at}]`, {use, saved, fail, closed, kinds: UNDO_KINDS});
      }
    }
  }
  for (const [index, item] of plan.tests.entries()) {
    if (item.undo?.test === undefined) continue;
    const later = plan.tests.findIndex(other => other.id === item.undo.test);
    if (later <= index) fail(`tests[${index}]`, `${item.id}: undo names ${item.undo.test}, which is not a later test`);
  }
  return deepFreeze(structuredClone(plan));
}

/** One step: exactly one kind, closed fields, its placeholders known and its names saved before use; then its own saves. */
function checkStep(step, where, {use, saved, fail, closed, kinds}) {
  if (!record(step) || Object.keys(step).length !== 1 || !kinds.includes(Object.keys(step)[0])) fail(where, `a step is exactly one of ${listWords(kinds)}`);
  const [kind] = Object.keys(step), body = step[kind];
  closed(body, kind, where);
  const at = `${where}.${kind}`;
  if (kind === 'call' || kind === 'race') {
    if (typeof body.action !== 'string' || !ACTION.test(body.action)) fail(at, 'an action is named key@version, such as list-calendars@1');
    if (body.args !== undefined && !record(body.args)) fail(at, 'args is an object');
    use(body.args ?? {}, `${at}.args`);
  }
  if (kind === 'call') {
    const failing = body.expect !== undefined && body.expect !== 'succeeded';
    if (failing && (!record(body.expect) || Object.keys(body.expect).join() !== 'failed' || !Number.isSafeInteger(body.expect.failed) || body.expect.failed < 400 || body.expect.failed > 599)) {
      fail(at, 'expect is succeeded or {failed: <HTTP status>}');
    }
    if (failing && (body.save !== undefined || body.checks !== undefined)) fail(at, 'a call expected to fail has no output to save or check');
    checkChecks(body.checks, at, {use, fail, call: true});
    checkSaves(body.save, at, {saved, fail});
  }
  if (kind === 'race') {
    if (!Number.isSafeInteger(body.status) || body.status < 400 || body.status > 599) fail(at, 'status is the HTTP status the losing job fails with');
    closed(body.readback, 'readback', `${at}.readback`);
    checkPath(body.readback.path, body.readback.params, `${at}.readback`, fail);
    use(body.readback.params ?? {}, `${at}.readback.params`);
    use(body.readback.query ?? {}, `${at}.readback.query`);
    checkQuery(body.readback.query, `${at}.readback`, fail);
    for (const name of ['pointer', 'output']) if (typeof body.readback[name] !== 'string' || !POINTER.test(body.readback[name])) fail(`${at}.readback.${name}`, 'a pointer is empty or starts with /');
  }
  if (kind === 'read') {
    if (body.method !== undefined && body.method !== 'GET') fail(at, 'a read is a GET');
    checkPath(body.path, body.params, at, fail);
    use(body.params ?? {}, `${at}.params`);
    use(body.query ?? {}, `${at}.query`);
    checkQuery(body.query, at, fail);
    checkChecks(body.checks, at, {use, fail});
    checkSaves(body.save, at, {saved, fail});
  }
  if (kind === 'owner') {
    if (!words(body.words)) fail(at, 'words tell Muse what to do, in at most 500 characters');
    if (body.until !== undefined) {
      closed(body.until, 'until', `${at}.until`);
      checkPath(body.until.path, body.until.params, `${at}.until`, fail);
      use(body.until.params ?? {}, `${at}.until.params`);
      use(body.until.query ?? {}, `${at}.until.query`);
      checkQuery(body.until.query, `${at}.until`, fail);
      if (!Array.isArray(body.until.checks) || !body.until.checks.length) fail(`${at}.until`, 'until has the checks its read waits for');
      checkChecks(body.until.checks, `${at}.until`, {use, fail});
    }
  }
  if (kind === 'oneTimeAsk' || kind === 'ask') {
    if (typeof body.row !== 'string' || !ROW.test(body.row)) fail(at, kind === 'ask' ? 'row is the id of the row that already reads Ask' : 'row is the id of the Never row the owner opens once');
    if (!Array.isArray(body.requests) || body.requests.length < 1 || body.requests.length > PLAN_LIMITS.requests) fail(at, `${kind === 'ask' ? 'an ask step' : 'a one-time Ask'} sends 1 to ${PLAN_LIMITS.requests} requests`);
    for (const [index, request] of body.requests.entries()) {
      closed(request, 'request', `${at}.requests[${index}]`);
      if (!METHODS.has(request.method)) fail(`${at}.requests[${index}]`, 'method is GET, POST, PUT, PATCH or DELETE');
      checkPath(request.path, request.params, `${at}.requests[${index}]`, fail);
      use(request.params ?? {}, `${at}.requests[${index}].params`);
      use(request.query ?? {}, `${at}.requests[${index}].query`);
      checkQuery(request.query, `${at}.requests[${index}]`, fail);
    }
  }
}
function checkSaves(save, at, {saved, fail}) {
  if (save === undefined) return;
  if (!record(save) || Object.keys(save).length > 10) fail(`${at}.save`, 'save names at most 10 values, each to a pointer');
  for (const [name, pointer] of Object.entries(save)) {
    if (!NAME.test(name) || typeof pointer !== 'string' || !POINTER.test(pointer)) fail(`${at}.save.${name}`, 'a saved value has a short name and a pointer');
    saved.add(name);
  }
}
function checkQuery(query, at, fail) {
  if (query === undefined) return;
  if (!record(query) || Object.keys(query).length > 20 || Object.keys(query).some(name => !/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(name))) fail(`${at}.query`, 'query names at most 20 parameters');
}
/** A path template: starts with /, at most 400 characters, each {slot} or {+slot} filled by exactly one params entry. */
function checkPath(template, params, at, fail) {
  if (typeof template !== 'string' || !template.startsWith('/') || template.length > 400 || /[?#\s]/.test(template)) fail(at, 'a path starts with / and holds no query');
  const slots = [...template.matchAll(SLOT)].map(match => match[2]);
  if (params !== undefined && !record(params)) fail(at, 'params is an object');
  for (const slot of slots) if (!Object.hasOwn(params ?? {}, slot)) fail(at, `{${slot}} has no params entry`);
  for (const name of Object.keys(params ?? {})) if (!slots.includes(name)) fail(at, `params.${name} fills no slot of the path`);
  if (template.replace(SLOT, 'x').includes('{') || template.replace(SLOT, 'x').includes('}')) fail(at, 'a slot is {name} or {+name}');
}
function checkChecks(checks, at, {use, fail, call = false}) {
  if (checks === undefined) return;
  if (!Array.isArray(checks) || checks.length > PLAN_LIMITS.checks) fail(`${at}.checks`, `checks lists at most ${PLAN_LIMITS.checks} checks`);
  for (const [index, check] of checks.entries()) {
    const where = `${at}.checks[${index}]`, keys = record(check) ? Object.keys(check).sort().join() : '';
    const pointer = () => typeof check.pointer === 'string' && POINTER.test(check.pointer);
    let fits;
    if (keys === 'status') fits = Number.isSafeInteger(check.status) || (Array.isArray(check.status) && check.status.length > 0 && check.status.every(Number.isSafeInteger));
    else if (keys === 'gone') fits = check.gone === true;
    else if (keys === 'equals,pointer') { fits = pointer() && check.equals !== undefined; use(check.equals, where); }
    else if (keys === 'pointer,present') fits = pointer() && typeof check.present === 'boolean';
    else if (keys === 'count,pointer') fits = pointer() && Number.isSafeInteger(check.count) && check.count >= 0;
    else if (keys === 'oneOf,pointer') { fits = pointer() && Array.isArray(check.oneOf) && check.oneOf.length > 0 && check.oneOf.length <= 20; use(check.oneOf, where); }
    else if (keys === 'equals,field,pointer,where') {
      fits = pointer() && record(check.where) && Object.keys(check.where).length > 0 && Object.keys(check.where).every(item => POINTER.test(item) && item !== '') && typeof check.field === 'string' && POINTER.test(check.field) && check.equals !== undefined;
      use(check.where, where);
      use(check.equals, where);
    } else fits = false;
    if (!fits) fail(where, CHECK_WORDS);
    if (call && (keys === 'status' || keys === 'gone')) fail(where, 'a call checks its output: status and gone are for reads');
  }
}
/** The closed placeholder set, wherever a value may stand: each known, each name saved earlier or recorded, each day inside the window. */
function placeholders(value, where, {saved, recorded, fail}) {
  if (Array.isArray(value)) { value.forEach((item, index) => placeholders(item, `${where}[${index}]`, {saved, recorded, fail})); return; }
  if (!record(value)) return;
  const keys = Object.keys(value), marked = keys.filter(key => key.startsWith('$'));
  if (!marked.length) { for (const key of keys) placeholders(value[key], `${where}.${key}`, {saved, recorded, fail}); return; }
  if (keys.length !== 1 || !PLACEHOLDERS.includes(marked[0])) fail(where, `${marked[0]} is not a placeholder: use one of ${PLACEHOLDERS.join(', ')}, alone in its object`);
  const [name] = keys, given = value[name];
  // F10.13 (map question 13): $text may name a day of the window, whose date stands where {date} does (Calendar's quick add reads it).
  if (name === '$text' && record(given)) {
    if (Object.keys(given).sort().join() !== 'day,words' || !words(given.words, 200)) fail(where, '$text is words, or {words, day}');
    if (given.words.split('{date}').length !== 2) fail(where, '$text: words hold {date} once');
    if (!inDays(given.day)) fail(where, `$text: day is ${PLAN_LIMITS.firstDay} to ${PLAN_LIMITS.lastDay}`);
  } else if (name === '$text' && !words(given, 200)) fail(where, '$text holds the words after the synthetic marker');
  if (name === '$saved' && (typeof given !== 'string' || !saved.has(given))) fail(where, `$saved: ${given} is used before a step saves it`);
  if (name === '$recorded' && (typeof given !== 'string' || !recorded.has(given))) fail(where, `$recorded: ${given} is not declared in recorded`);
  if (name === '$day' && !inDays(given)) fail(where, `$day is ${PLAN_LIMITS.firstDay} to ${PLAN_LIMITS.lastDay}`);
  if (name === '$at' || name === '$local') {
    if (!record(given) || Object.keys(given).sort().join() !== 'day,time') fail(where, `${name} is {day, time}`);
    if (!inDays(given.day)) fail(where, `${name}: day is ${PLAN_LIMITS.firstDay} to ${PLAN_LIMITS.lastDay}`);
    if (typeof given.time !== 'string' || !TIME.test(given.time)) fail(where, `${name}: time is HH:MM`);
  }
  if (name === '$owner' && !['email', 'timeZone'].includes(given)) fail(where, '$owner is email or timeZone');
  // F10.21 (part 2): Slack takes instants, so a schedule time or a status expiry is a number of minutes after the step runs.
  if (name === '$in' && !(record(given) && Object.keys(given).join() === 'minutes' && Number.isSafeInteger(given.minutes) && given.minutes >= 1 && given.minutes <= 1440)) {
    fail(where, '$in is {minutes}, 1 to 1,440 whole minutes after the step runs');
  }
  if (name === '$branch' && (typeof given !== 'string' || (given !== '' && !BRANCH_SUFFIX.test(given)))) fail(where, '$branch is "" or 1 to 16 lowercase letters or digits');
}
const inDays = day => Number.isSafeInteger(day) && day >= PLAN_LIMITS.firstDay && day <= PLAN_LIMITS.lastDay;

/**
 * A plan against its app: its structure (checkPlanShape()), then every key@version a current action of `entries` (the app's validated
 * actions) and never a superseded one, readRows read rows of `groups`, a one-time Ask on a row Fabric does not lock, every test that
 * writes with an undo, every action called by some call or race, read paths inside the app's proxy prefixes (`config`), and every write
 * placement of a called action fitting a method and path on the guard's list for the app (`rules`, lib/live-guard.mjs RULES). The guard,
 * not this check, decides content. Returns {appId, plan, actions (key@version to {id, definitionHash, effect}), rows (row id to label)}.
 */
export function checkPlan(plan, {entries, superseded = [], groups, config, rules} = {}) {
  const shape = checkPlanShape(plan), appId = shape.appId;
  const fail = (where, what) => { throw new Error(`Live test plan ${appId}: ${where}: ${what}`); };
  const rule = record(rules) && Object.hasOwn(rules, appId) ? rules[appId] : null;
  if (!rule || !Array.isArray(rule.allowlist)) fail('plan', `${appId} has no live-test rules, so the guard would send nothing`);
  if (!Array.isArray(entries) || entries.some(entry => typeof entry?.id !== 'string' || !entry.id.startsWith(`${appId}.action.`))) fail('plan', 'the entries are not this plan\'s app');
  if (!record(groups) || !Array.isArray(groups.groups)) fail('plan', `${appId} has no permission rows`);
  if (!record(config) || typeof config.apiBase !== 'string') fail('plan', `${appId} has no reviewed proxy settings`);
  const actions = new Map(entries.map(entry => [`${entry.key}@${entry.version}`, entry])), rows = new Map(groups.groups.map(group => [group.id, group]));
  const retired = new Set([...superseded].map(id => /\.action\.([a-z][a-z0-9-]*)\.v([0-9]+)\./.exec(String(id))).filter(Boolean).map(match => `${match[1]}@${match[2]}`));
  for (const row of shape.readRows) if (rows.get(row)?.effect !== 'read') fail('readRows', `${row} is not a read row of ${appId}`);
  const prefixes = config.pathPrefixes?.length ? config.pathPrefixes : ['/'];
  const inside = template => prefixes.some(prefix => prefix === '/' || template === prefix || template.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`));
  const called = new Set();
  const action = (key, where) => {
    if (actions.has(key)) { called.add(key); return actions.get(key); }
    return fail(where, retired.has(key) ? `${key} is superseded: name the action that replaced it` : `${key} is not an action of ${appId}`);
  };
  const steps = item => [...item.steps.map(step => [step, false]), ...(item.undo?.steps ?? []).map(step => [step, true])];
  for (const [index, item] of shape.tests.entries()) {
    let writes = false;
    for (const [at, [step]] of steps(item).entries()) {
      const where = `tests[${index}].steps[${at}]`, [kind] = Object.keys(step), body = step[kind];
      if (kind === 'call' || kind === 'race') { if (action(body.action, where).effect !== 'read') writes = true; }
      if (kind === 'oneTimeAsk' || kind === 'ask') {
        writes = true;
        const row = rows.get(body.row);
        if (!row) fail(where, `${body.row} is not a row of ${appId}`);
        if (row.locked) fail(where, kind === 'ask' ? `${body.row} is locked by Fabric, so no ask step can use it` : `${body.row} is locked by Fabric, so no one-time Ask can open it`);
        // F10.17: an ask step changes no row, so its row must already ask; a Never row is opened only by the one-time Ask, which resets it.
        if (kind === 'ask' && row.defaultMode === 'deny') fail(where, `${body.row} is Never by default: an ask step opens no row, so it takes a oneTimeAsk`);
      }
      for (const path of [body.path, body.readback?.path, body.until?.path, ...(body.requests ?? []).map(request => request.path)].filter(Boolean)) if (!inside(path)) fail(where, `${path} is outside ${appId}'s proxy prefixes`);
    }
    if (writes && item.undo === undefined) fail(`tests[${index}]`, `${item.id} writes, so it needs an undo`);
  }
  if (shape.timeZone && !inside(shape.timeZone.path)) fail('timeZone', `${shape.timeZone.path} is outside ${appId}'s proxy prefixes`);
  for (const key of actions.keys()) if (!called.has(key)) fail('plan', `${key} is called by no test, so it would get no evidence`);
  for (const key of called) {
    for (const placement of actions.get(key).placements) {
      if (placement.effect === 'read') continue;
      if (!rule.allowlist.some(pair => pair.method === placement.method && fits(pathOf(placement.template), config.apiBase, pair.path, rule.base))) {
        fail('plan', `${key}: ${placement.template} fits nothing on the live guard's list for ${appId}`);
      }
    }
  }
  const labels = new Map([...rows].map(([id, row]) => [id, row.label]));
  return Object.freeze({appId, plan: shape, actions: new Map([...called].map(key => [key, Object.freeze({id: actions.get(key).id, definitionHash: actions.get(key).definitionHash, effect: actions.get(key).effect})])), rows: labels});
}
/** The path of a reviewed template, "METHOD /path". */
const pathOf = template => template.slice(template.indexOf(' ') + 1);
/** A placement's template below its proxy base fits a guard pattern below the rule's base: same origin; a guard literal only an equal
 *  literal, a :name any one segment, a +name one or more; a {slot} of the template fits any one guard segment, a {+slot} only a +name. */
function fits(template, apiBase, pattern, ruleBase) {
  let api, rule;
  try { api = new URL(apiBase); rule = new URL(ruleBase); } catch { return false; }
  if (api.origin !== rule.origin) return false;
  const split = text => text.split('/').filter(Boolean);
  const left = [...split(api.pathname), ...split(template)], right = [...split(rule.pathname), ...split(pattern)];
  for (let index = 0; index < right.length; index++) {
    const part = right[index];
    if (part.startsWith('+')) return left.length > index;
    const segment = left[index];
    if (segment === undefined || /^\{\+/.test(segment)) return false;
    if (part.startsWith(':') || /^\{[^+]/.test(segment)) continue;
    let decoded;
    try { decoded = decodeURIComponent(segment); } catch { return false; }
    if (decoded !== part) return false;
  }
  return left.length === right.length;
}

// ---- placeholders, paths and checks at run time --------------------------------------------------------------------------------------
/** RFC 3339 for a wall time on a day in a zone, with that day's offset. A wall time a daylight-saving change skips is refused. */
function rfc3339(date, time, zone) {
  const [hour, minute] = time.split(':').map(Number), ms = zonedInstant(date, {hour, minute, second: 0}, zone), offset = offsetAt(ms, zone) / 60_000;
  if (new Date(ms + offset * 60_000).toISOString().slice(0, 16) !== `${date}T${time}`) throw failure(`${date} ${time} does not exist in ${zone}: a daylight-saving change skips it.`);
  const sign = offset < 0 ? '-' : '+', size = Math.abs(offset);
  return `${date}T${time}:00${sign}${String(Math.floor(size / 60)).padStart(2, '0')}:${String(size % 60).padStart(2, '0')}`;
}
/** The date (YYYY-MM-DD) an instant falls on in a zone. */
export function runDateOf(ms, zone) {
  if (!validZone(zone)) throw new Error('The run\'s time zone must be an IANA time zone name.');
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', {timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit'}).formatToParts(new Date(ms)).map(part => [part.type, part.value]));
  return `${parts.year}-${parts.month}-${parts.day}`;
}
/** A plan value with each placeholder filled for this test of this run. `ctx` is {run: {runId, runDate, timeZone, saved, recorded}, account}. */
export function fillPlaceholders(value, ctx, test) { return fill(value, ctx, test); }
function fill(value, ctx, test) {
  if (Array.isArray(value)) return value.map(item => fill(item, ctx, test));
  if (!record(value)) return value;
  const keys = Object.keys(value);
  if (keys.length !== 1 || !keys[0].startsWith('$')) return Object.fromEntries(keys.map(key => [key, fill(value[key], ctx, test)]));
  const [name] = keys, given = value[name], run = ctx.run;
  if (name === '$text') return `[SYNTHETIC] Fabric ${test.id} ${run.runId} ${record(given) ? given.words.replace('{date}', addDays(run.runDate, given.day)) : given}`;
  if (name === '$saved') { if (!Object.hasOwn(run.saved, given)) throw failure(`$saved: ${given} was never saved in this run.`); return structuredClone(run.saved[given]); }
  if (name === '$recorded') { if (!Object.hasOwn(run.recorded, given)) throw failure(`$recorded: ${given} was not given for this run.`); return run.recorded[given]; }
  if (name === '$day') return addDays(run.runDate, given);
  if (name === '$at') return rfc3339(addDays(run.runDate, given.day), given.time, run.timeZone);
  // F10.13 (map question 13): the same wall time without its offset, as Calendar's actions take local times in the owner's zone.
  if (name === '$local') return rfc3339(addDays(run.runDate, given.day), given.time, run.timeZone).slice(0, 19);
  // F10.21 (part 2): the UTC instant that many minutes after the step runs, in whole seconds, from the run's clock.
  if (name === '$in') {
    if (typeof ctx.clock !== 'function') throw failure('$in needs the run\'s clock.');
    return new Date(Math.floor((ctx.clock() + given.minutes * 60_000) / 1000) * 1000).toISOString().replace('.000Z', 'Z');
  }
  // F10.17: this run's own branch, which the GitHub guard lets a live test create, write, merge into and delete.
  if (name === '$branch') return `fabric/test-${run.runId}${given === '' ? '' : `-${given}`}`;
  if (name === '$owner') {
    if (given === 'timeZone') return run.timeZone;
    if (!ctx.account.email) throw failure('$owner: this account has no email address Fabric can read.');
    return ctx.account.email;
  }
  throw failure(`${name} is not a placeholder.`);
}
/** A path template filled: {slot} percent-encoded whole, {+slot} each segment encoded. */
function fillPath(template, params, ctx, test) {
  const values = fill(params ?? {}, ctx, test);
  return template.replace(SLOT, (_, rest, slot) => {
    const value = values[slot];
    if (!['string', 'number'].includes(typeof value) || String(value) === '') throw failure(`{${slot}} has no value to send.`);
    return rest ? String(value).split('/').map(encodeURIComponent).join('/') : encodeURIComponent(String(value));
  });
}
const fillQuery = (query, ctx, test) => query === undefined ? undefined : Object.fromEntries(Object.entries(fill(query, ctx, test)).map(([name, value]) => [name, String(value)]));
/** The value at a JSON pointer, or undefined. */
function at(value, pointer) {
  if (pointer === '') return value;
  let current = value;
  for (const raw of pointer.slice(1).split('/')) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (Array.isArray(current) ? !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= current.length : !record(current) || !Object.hasOwn(current, key)) return undefined;
    current = current[key];
  }
  return current;
}
const same = (a, b) => JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
/** One check's name, which the evidence keeps; never a value. */
function checkName(step, check) {
  if (Object.hasOwn(check, 'status')) return `step ${step}: status`;
  if (Object.hasOwn(check, 'gone')) return `step ${step}: gone`;
  if (Object.hasOwn(check, 'where')) return `step ${step}: ${check.pointer} entry ${check.field} equals`;
  const kind = ['equals', 'present', 'count', 'oneOf'].find(item => Object.hasOwn(check, item));
  return `step ${step}: ${check.pointer} ${kind === 'oneOf' ? 'one of' : kind}`;
}
/** Whether a check holds on a response {status, body}: a call's output is the body, with no status. */
function holds(check, response, ctx, test) {
  const {status, body} = response;
  if (Object.hasOwn(check, 'status')) return [check.status].flat().includes(status);
  if (Object.hasOwn(check, 'gone')) return status === 404 || status === 410 || (status === 200 && Boolean(ctx.plan.gone) && same(at(body, ctx.plan.gone.pointer), fill(ctx.plan.gone.equals, ctx, test)));
  const value = at(body, check.pointer);
  if (Object.hasOwn(check, 'equals') && !Object.hasOwn(check, 'where')) return value !== undefined && same(value, fill(check.equals, ctx, test));
  if (Object.hasOwn(check, 'present')) return (value !== undefined && value !== null) === check.present;
  if (Object.hasOwn(check, 'count')) return Array.isArray(value) && value.length === check.count;
  if (Object.hasOwn(check, 'oneOf')) return value !== undefined && fill(check.oneOf, ctx, test).some(option => same(option, value));
  if (!Array.isArray(value)) return false;
  const where = fill(check.where, ctx, test), chosen = value.filter(entry => Object.entries(where).every(([pointer, wanted]) => same(at(entry, pointer), wanted)));
  return chosen.length === 1 && same(at(chosen[0], check.field), fill(check.equals, ctx, test));
}

// ---- the run state ---------------------------------------------------------------------------------------------------------------
/** The run's own file beside the guard's: <folder>/live-certify/<appId>-<runId>.json, mode 600, local, never committed. */
export const runStateFile = (folder, appId, runId) => path.join(folder, 'live-certify', `${appId}-${runId}.json`);
/** Writes a file the owner alone can read, whole or not at all. */
function writeSecret(file, value) {
  const next = `${file}.${process.pid}.tmp`;
  writeFileSync(next, `${JSON.stringify(value, null, 1)}\n`, {mode: 0o600});
  chmodSync(next, 0o600);
  renameSync(next, file);
}
/**
 * The run state of one run: its id, date, time zone and recorded values (fixed for the run), the values its steps saved, each request id
 * with its job id once accepted, the grants it holds now, each test's result in the order tests ran, the rows it opened and why it
 * stopped. Never the HMAC key and never a token. With `fresh` ({runDate, timeZone, recorded}) a new run starts; without it the file must
 * exist (a resume). Returns {file, data, save()}.
 */
export function openRunState(folder, appId, runId, fresh) {
  const file = runStateFile(folder, appId, runId), directory = path.dirname(file);
  mkdirSync(directory, {recursive: true, mode: 0o700});
  let data;
  if (existsSync(file)) {
    data = JSON.parse(readFileSync(file, 'utf8'));
    if (!record(data) || data.schemaVersion !== 1 || data.appId !== appId || data.runId !== runId || !record(data.results) || !record(data.saved) || !record(data.requests) || !Array.isArray(data.order) || !Array.isArray(data.rows)) {
      throw new Error('The run state of this run is not one the live-test runner wrote.');
    }
  } else if (fresh) {
    if (!validDate(fresh.runDate) || !validZone(fresh.timeZone)) throw new Error('A new run needs its run date and time zone.');
    data = {schemaVersion: 1, appId, runId, runDate: fresh.runDate, timeZone: fresh.timeZone, recorded: {...(fresh.recorded ?? {})}, startedAt: null, finishedAt: null, saved: {}, requests: {},
      grant: null, askGrant: null, results: {}, order: [], rows: [], stopped: null, left: []};
  } else throw new Error(`No run ${runId} of ${appId} in this folder to resume.`);
  const state = {file, data, save: () => writeSecret(file, data)};
  state.save();
  return state;
}

// ---- running the tests -------------------------------------------------------------------------------------------------------------
/** A failure of the test being run: its words become the test's words. */
const failure = text => Object.assign(new Error(text), {liveTest: true});
const PENDING = new Set(['awaiting_approval', 'queued', 'running']);

/**
 * Runs a checked plan (checkPlan()) through `port`, one test at a time, as the spec's flow says (spec lines 994-1001): a grant for the test
 * only, each call by its request id, each card's prepared bytes checked by the guard before its approve link is printed, a wait for the
 * owner, the outcome, the readbacks, the undo, the grant revoked. The first failed test stops the run, and every stop resets the rows that
 * left Never and offers the pending undos. `state` is openRunState()'s; `from` resumes at a test. With `leave` (the owner's choice, 2026-10-29:
 * a test account may keep what a run made) the cleanup tests are not run and are listed as left; nothing they would delete is touched.
 * Returns the run (state.data).
 */
export async function runLiveTests(port, checked, {guard, state, prompt, say = line => console.log(line), clock = Date.now, wait = ms => new Promise(resolve => setTimeout(resolve, ms)), from, leave = false} = {}) {
  const plan = checked.plan, run = state.data;
  if (run.appId !== plan.appId || run.runId !== guard.runId || guard.appId !== plan.appId) throw new Error('The plan, the guard and the run state are not one run.');
  const account = port.account(plan.appId);
  if (!account) throw new Error(`No ready ${plan.appId} account: connect one first.`);
  const ctx = {port, checked, plan, guard, state, run, prompt, say, clock, wait, account, leave, counters: new Map(), printed: new Map(), now: () => new Date(clock()).toISOString()};
  // A resume: the grants of the run that stopped are revoked first, so an earlier process's token can never send again.
  for (const name of ['grant', 'askGrant']) if (run[name]) { port.revokeGrant(run[name]); run[name] = null; }
  run.startedAt ??= ctx.now();
  run.stopped = null;
  run.left = [];
  state.save();
  const start = from ? plan.tests.findIndex(item => item.id === from) : plan.tests.findIndex(item => run.results[item.id]?.passed !== true);
  if (from && start < 0) throw new Error(`${from} is not a test of this plan.`);
  for (const item of start < 0 ? [] : plan.tests.slice(start)) {
    if (leave && item.cleanup) { leftByChoice(ctx, item); continue; }
    const result = await runTest(ctx, item);
    if (!result.passed) { run.stopped = {test: item.id, words: result.words ?? 'A check did not hold.'}; break; }
  }
  // Any stop, in this order: the rows that left Never first, then the pending undos. A run that finished checks its rows too.
  await resetRows(ctx);
  if (run.stopped) await offerUndos(ctx);
  run.finishedAt = ctx.now();
  state.save();
  return run;
}

/** One test: its grant, its steps, its undo steps, its grant revoked. */
async function runTest(ctx, test) {
  const {guard, run, state} = ctx;
  const undo = test.undo === undefined ? {kind: 'none', why: 'The test changes nothing.'} : test.undo.test !== undefined ? {kind: 'test', test: test.undo.test} : test.undo.none !== undefined ? {kind: 'none', why: test.undo.none}
    : {kind: 'steps', ran: false, passed: null, from: null, calls: [], proxies: [], reads: [], checks: []};
  const result = {id: test.id, passed: false, words: null, startedAt: ctx.now(), finishedAt: null, calls: [], proxies: [], reads: [], checks: [], undo};
  run.results[test.id] = result;
  if (!run.order.includes(test.id)) run.order.push(test.id);
  state.save();
  ctx.say(`${test.id}: ${test.name}`);
  for (const key of [...ctx.counters.keys()]) if (key.startsWith(`${test.id}.`)) ctx.counters.delete(key);
  guard.begin(test.id);
  let thrown = null;
  try {
    const grant = bind(ctx, test, [...test.steps, ...(test.undo?.steps ?? [])], ctx.plan.readRows, 'grant');
    for (const [index, step] of test.steps.entries()) await runStep(ctx, test, step, index + 1, result, grant);
    if (undo.kind === 'steps') await runUndo(ctx, test, undo, grant);
  } catch (error) {
    thrown = error;
  } finally {
    unbind(ctx, 'grant');
    guard.end();
  }
  result.passed = thrown === null && result.checks.every(check => check.passed) && (undo.kind !== 'steps' || undo.passed === true);
  result.words = thrown ? String(thrown.message).slice(0, 600) : result.passed ? null : 'A check did not hold.';
  result.finishedAt = ctx.now();
  state.save();
  ctx.say(`${test.id}: ${result.passed ? 'passed' : `failed: ${result.words}`}`);
  return result;
}
async function runUndo(ctx, test, undo, grant) {
  undo.ran = true;
  undo.from = ctx.guard.trace(test.id).length;
  for (const [index, step] of test.undo.steps.entries()) await runStep(ctx, test, step, index + 1, undo, grant);
  undo.passed = undo.checks.every(check => check.passed);
  ctx.state.save();
}
/** A grant for this test only: its actions on the run's account and `rows` as proxy rows, for at most 4 hours. Its id goes to the run state. */
function bind(ctx, test, steps, rows, slot) {
  const actions = [...new Set(steps.flatMap(step => step.call ? [step.call.action] : step.race ? [step.race.action] : []))].map(key => ctx.checked.actions.get(key).id);
  if (!actions.length && !rows.length) return null;
  const grant = ctx.port.grant({name: `Live test ${test.id} ${ctx.run.runId}${slot === 'askGrant' ? ' one-time Ask' : ''}`, connectionId: ctx.account.connectionId, actions, rows: [...rows], expiresInSeconds: PLAN_LIMITS.grantSeconds});
  ctx.run[slot] = grant.id;
  ctx.state.save();
  return grant;
}
function unbind(ctx, slot) {
  if (!ctx.run[slot]) return;
  ctx.port.revokeGrant(ctx.run[slot]);
  ctx.run[slot] = null;
  ctx.state.save();
}
/** `<runId>.<test>.<n>`: the same ids in the same order each time a test runs, so a resume finds the jobs an earlier attempt made. The
 *  one-time Ask's requests count apart (`a<n>`), and so do undo steps run during a stop (`u<n>`). Reads whose number varies from one
 *  attempt to the next count apart too, so they never move a later call's id: a gone read's re-reads (`r<n>`) and an owner step's polls
 *  (`p<n>`). */
const nextRequestId = (ctx, test, kind = '') => {
  const space = `${ctx.space ?? ''}${kind}`, key = `${test.id}.${space}`, n = (ctx.counters.get(key) ?? 0) + 1;
  ctx.counters.set(key, n);
  return `${ctx.run.runId}.${test.id}.${space}${n}`;
};

async function runStep(ctx, test, step, n, into, grant) {
  const [kind] = Object.keys(step), body = step[kind];
  if (kind === 'call') return callStep(ctx, test, body, n, into, grant);
  if (kind === 'race') return raceStep(ctx, test, body, n, into, grant);
  if (kind === 'read') return readStep(ctx, test, body, n, into, grant);
  if (kind === 'owner') return ownerStep(ctx, test, body, n, into, grant);
  if (kind === 'ask') return askStep(ctx, test, body, n, into);
  return oneTimeAsk(ctx, test, body, n, into);
}

/** A stored job of this request id: reused when it ended with an answer, waited for when it is still going, sent again only when it
 *  ended with nothing sent, and a stop when its outcome is uncertain. One that asked for something else stops the test. Returns the job,
 *  or null to send. */
async function reuse(ctx, requestId, matches) {
  const job = ctx.port.jobFor(requestId);
  if (!job) return null;
  if (!matches(job)) throw failure(`${requestId} named another request in an earlier attempt, so nothing was sent.`);
  if (job.status === 'uncertain') throw failure(`An earlier attempt of ${requestId} ended uncertain: check it by hand before you run this test again.`);
  ctx.run.requests[requestId] = job.id;
  ctx.state.save();
  if (PENDING.has(job.status) || job.status === 'succeeded' || answered(job)) return job;
  return null;
}
/** Whether a job that ended failed had a provider answer, or sent a change: its outcome stands and it is never sent again. */
const answered = job => job.providerStatus !== undefined || (job.action?.writesSent?.length ?? 0) > 0 || Number.isSafeInteger(job.result?.response?.status);
/** calls.create with this test's next request id, written to the run state before the call and with its job id once accepted. */
async function createCall(ctx, test, grant, params) {
  const requestId = nextRequestId(ctx, test);
  const stored = await reuse(ctx, requestId, job => job.capabilityId === params.capabilityId && job.connectionId === params.connectionId && same(job.args, params.args));
  if (stored) return stored.id;
  ctx.run.requests[requestId] = null;
  ctx.state.save();
  const answer = await ctx.port.call(grant.id, 'calls.create', params, requestId);
  if (answer.error) throw failure(`Fabric refused the call (${answer.error.code}): ${answer.error.message}`);
  ctx.run.requests[requestId] = answer.result.id;
  ctx.state.save();
  return answer.result.id;
}
/** The guard checks a waiting card's prepared bytes; only a card it passes gets its approve link, printed once per stop. */
function show(ctx, jobId) {
  const job = ctx.port.job(jobId);
  if (job?.status !== 'awaiting_approval') return;
  const stop = `${job.action?.phase ?? 'proxy'}:${job.action?.decisions?.length ?? 0}`, printed = ctx.printed.get(jobId) ?? new Set();
  if (printed.has(stop)) return;
  for (const request of ctx.port.prepared(jobId)) {
    const verdict = ctx.guard.check(request);
    if (!verdict.allowed) {
      ctx.say(`Reject this card: ${verdict.words}`);
      throw failure(`Reject this card: ${verdict.words}`);
    }
  }
  ctx.say(`Approve: ${ctx.port.link(jobId)}`);
  printed.add(stop);
  ctx.printed.set(jobId, printed);
}
/** Waits, once a second, until the job leaves awaiting_approval, queued and running; a card that lapses fails the test. */
async function settle(ctx, jobId) {
  for (;;) {
    const job = ctx.port.job(jobId);
    if (!job) throw failure('The job is gone from this Fabric.');
    if (!PENDING.has(job.status)) return job;
    if (job.status === 'awaiting_approval') {
      show(ctx, jobId);
      if (!(Date.parse(job.approvalExpiresAt) > ctx.clock())) throw failure('The card lapsed before it was approved, so the test fails.');
    }
    await ctx.wait(PLAN_LIMITS.pollMs);
  }
}
function expected(ctx, into, n, key, job, expect) {
  const passed = expect === 'succeeded' ? job.status === 'succeeded' : job.status === 'failed' && job.providerStatus === expect.failed;
  into.checks.push({name: `step ${n}: ${key} ${expect === 'succeeded' ? 'succeeded' : `failed with ${expect.failed}`}`, passed});
  ctx.state.save();
  if (!passed) throw failure(`${key} ended ${job.status}${job.errorCode ? ` (${job.errorCode})` : ''}, not as the plan expects.`);
}
function saves(ctx, into, n, save, body) {
  for (const [name, pointer] of Object.entries(save ?? {})) {
    const value = at(body, pointer), passed = value !== undefined && value !== null;
    into.checks.push({name: `step ${n}: saves ${name}`, passed});
    if (!passed) throw failure(`${pointer} is not in the answer, so ${name} cannot be saved.`);
    ctx.run.saved[name] = structuredClone(value);
  }
  ctx.state.save();
}
function checks(ctx, test, into, n, list, response) {
  for (const check of list ?? []) into.checks.push({name: checkName(n, check), passed: holds(check, response, ctx, test)});
  ctx.state.save();
}

async function callStep(ctx, test, body, n, into, grant) {
  const action = ctx.checked.actions.get(body.action);
  const jobId = await createCall(ctx, test, grant, {connectionId: ctx.account.connectionId, capabilityId: action.id, definitionHash: action.definitionHash, args: fill(body.args ?? {}, ctx, test)});
  into.calls.push({action: body.action, actionId: action.id, jobs: [jobId]});
  ctx.state.save();
  const job = await settle(ctx, jobId);
  expected(ctx, into, n, body.action, job, body.expect ?? 'succeeded');
  saves(ctx, into, n, body.save, job.result?.data);
  checks(ctx, test, into, n, body.checks, {status: undefined, body: job.result?.data});
}

async function raceStep(ctx, test, body, n, into, grant) {
  const action = ctx.checked.actions.get(body.action), args = fill(body.args ?? {}, ctx, test);
  const params = {connectionId: ctx.account.connectionId, capabilityId: action.id, definitionHash: action.definitionHash, args};
  // Both are prepared before either card is shown, so both read the same version.
  const ids = [await createCall(ctx, test, grant, params), await createCall(ctx, test, grant, params)];
  into.calls.push({action: body.action, actionId: action.id, jobs: ids});
  ctx.state.save();
  for (const id of ids) show(ctx, id);
  const jobs = [];
  for (const id of ids) jobs.push(await settle(ctx, id));
  const landed = jobs.filter(job => job.status === 'succeeded'), refused = jobs.filter(job => job.status === 'failed' && job.providerStatus === body.status);
  const passed = landed.length === 1 && refused.length === 1;
  into.checks.push({name: `step ${n}: one job succeeded and one failed with ${body.status}`, passed});
  ctx.state.save();
  if (!passed) throw failure(`In a race, one job must succeed and one must fail with ${body.status}; these ended ${jobs.map(job => job.status).join(' and ')}.`);
  const response = await proxyRead(ctx, test, grant, body.readback, into);
  const value = at(response.body, body.readback.pointer), wanted = at(landed[0].result?.data, body.readback.output);
  into.checks.push({name: `step ${n}: the readback equals the job that landed`, passed: response.status >= 200 && response.status < 300 && value !== undefined && same(value, wanted)});
  ctx.state.save();
}

/** A request sent with proxy.request on a grant, by this test's next request id: {jobId, status, body}. A change already sent under this
 *  request id is never sent again. */
async function proxySend(ctx, test, grant, request, kind = '') {
  const requestId = nextRequestId(ctx, test, kind);
  if (request.method !== 'GET') {
    const stored = await reuse(ctx, requestId, job => job.kind === 'proxy' && job.connectionId === ctx.account.connectionId && same(job.args?.request, request));
    if (stored) {
      const job = PENDING.has(stored.status) ? await settle(ctx, stored.id) : stored;
      return {jobId: job.id, status: job.result?.response?.status ?? null, body: null};
    }
  }
  ctx.run.requests[requestId] = null;
  ctx.state.save();
  const answer = await ctx.port.call(grant.id, 'proxy.request', {connectionId: ctx.account.connectionId, request}, requestId);
  if (answer.error) throw failure(`Fabric refused the request (${answer.error.code}): ${answer.error.message}`);
  const jobId = answer.result.id;
  ctx.run.requests[requestId] = jobId;
  ctx.state.save();
  let result = answer.result;
  if (PENDING.has(result.status)) {
    await settle(ctx, jobId);
    const read = await ctx.port.call(grant.id, 'calls.get', {callId: jobId}, `${requestId}.get`);
    if (read.error) throw failure(`Fabric could not read the request back (${read.error.code}).`);
    result = read.result;
  }
  return {jobId, status: result.result?.response?.status ?? null, body: result.result?.response?.body ?? null};
}
async function proxyRead(ctx, test, grant, read, into, kind = '') {
  if (!grant) throw failure('This test has no grant to read with: name its read rows in readRows.');
  const request = {method: 'GET', path: fillPath(read.path, read.params, ctx, test), ...(read.query ? {query: fillQuery(read.query, ctx, test)} : {})};
  into.reads.push({method: 'GET', path: read.path});
  return proxySend(ctx, test, grant, request, kind);
}
/** Whether a check asks that something is gone: {gone}, or a status of 404 or 410, alone or as a list of only those. */
const absence = check => Object.hasOwn(check, 'gone') || (Object.hasOwn(check, 'status') && [check.status].flat().every(status => status === 404 || status === 410));
/** A read and its checks. One that checks something is gone asks again, a poll apart, up to PLAN_LIMITS.goneReads reads in all: Google
 *  answers a calendar it has just deleted for a moment (live run MBIDCUUG, C13). Any other read is checked once, so a wrong answer fails. */
async function readStep(ctx, test, body, n, into, grant) {
  let response = await proxyRead(ctx, test, grant, body, into);
  for (let reads = 1; reads < PLAN_LIMITS.goneReads && response.status !== null && (body.checks ?? []).some(absence) && !body.checks.every(check => holds(check, response, ctx, test)); reads++) {
    await ctx.wait(PLAN_LIMITS.pollMs);
    response = await proxyRead(ctx, test, grant, body, into, 'r');
  }
  if (response.status === null) throw failure('The read was not answered.');
  saves(ctx, into, n, body.save, response.body);
  checks(ctx, test, into, n, body.checks, response);
}
async function ownerStep(ctx, test, body, n, into, grant) {
  await ctx.prompt(body.words);
  if (!body.until) return;
  const deadline = ctx.clock() + PLAN_LIMITS.untilMs;
  for (;;) {
    const response = await proxyRead(ctx, test, grant, body.until, into, 'p');
    if (body.until.checks.every(check => holds(check, response, ctx, test))) { into.checks.push({name: `step ${n}: what Muse did reads back`, passed: true}); ctx.state.save(); return; }
    if (ctx.clock() >= deadline) {
      into.checks.push({name: `step ${n}: what Muse did reads back`, passed: false});
      ctx.state.save();
      throw failure('What Muse was asked to do did not happen within 5 minutes.');
    }
    await ctx.wait(PLAN_LIMITS.pollMs);
  }
}

// ---- the one-time Ask on a Never row (spec lines 1002-1008) -----------------------------------------------------------------------
/** The run's record of a row it asks the owner to open: when Ask (or Allow) was read, and when Never was read again. */
function rowRecord(ctx, row) {
  let entry = ctx.run.rows.find(item => item.row === row && item.connectionId === ctx.account.connectionId);
  if (!entry) {
    entry = {row, label: ctx.checked.rows.get(row) ?? row, connectionId: ctx.account.connectionId, askSeenAt: null, allowSeenAt: null, neverSeenAt: null};
    ctx.run.rows.push(entry);
    ctx.state.save();
  }
  return entry;
}
async function oneTimeAsk(ctx, test, body, n, into) {
  const entry = rowRecord(ctx, body.row);
  entry.neverSeenAt = null;
  ctx.say(`Set "${entry.label}" to Ask: ${ctx.port.appLink(ctx.plan.appId)}`);
  const deadline = ctx.clock() + PLAN_LIMITS.ownerWaitMs;
  for (;;) {
    const mode = ctx.port.rowMode(ctx.account.connectionId, body.row);
    if (mode === 'allow') {
      entry.allowSeenAt = ctx.now();
      ctx.state.save();
      ctx.say('Set it to Ask, not Allow.');
      throw failure(`"${entry.label}" was set to Allow, not Ask, so the run stopped.`);
    }
    if (mode === 'ask') { entry.askSeenAt = ctx.now(); ctx.state.save(); break; }
    if (ctx.clock() >= deadline) throw failure(`"${entry.label}" was not set to Ask within 30 minutes.`);
    await ctx.wait(PLAN_LIMITS.pollMs);
  }
  ctx.guard.beginOneTimeAsk(body.row);
  try {
    await sendOnRow(ctx, test, body, n, into);
  } finally {
    ctx.guard.endOneTimeAsk();
  }
  await resetRow(ctx, entry);
}
/** Sends a one-time Ask's or an ask step's requests on a grant of its one row, each approved like any proxied write. */
async function sendOnRow(ctx, test, body, n, into) {
  try {
    const grant = bind(ctx, test, [], [body.row], 'askGrant');
    for (const request of body.requests) {
      const sent = {method: request.method, path: fillPath(request.path, request.params, ctx, test), ...(request.query ? {query: fillQuery(request.query, ctx, test)} : {})};
      into.reads.push({method: request.method, path: request.path});
      const response = await proxySend(ctx, test, grant, sent, 'a');
      into.proxies.push(response.jobId);
      const passed = Number.isSafeInteger(response.status) && response.status >= 200 && response.status < 300;
      into.checks.push({name: `step ${n}: ${request.method} ${request.path} answered`, passed});
      ctx.state.save();
      if (!passed) throw failure(`${request.method} ${request.path} was not answered with success (${response.status ?? 'no answer'}).`);
    }
  } finally {
    unbind(ctx, 'askGrant');
  }
}
/**
 * F10.17: an ask step, for a proxied write on a row that already reads Ask (deleting a run's branches on "Push code and manage
 * repositories"): its requests on a grant of that one row, each approved like any proxied write. It changes no row and asks the owner to
 * change none: a row read as Never refuses the step, and Allow stops the run, as a one-time Ask does, with nothing sent.
 */
async function askStep(ctx, test, body, n, into) {
  const label = ctx.checked.rows.get(body.row) ?? body.row, mode = ctx.port.rowMode(ctx.account.connectionId, body.row);
  if (mode === 'deny') throw failure(`"${label}" is Never, so this step was refused and nothing was sent.`);
  if (mode !== 'ask') throw failure(`"${label}" is ${mode === 'allow' ? 'Allow' : 'not set'}, not Ask, so the run stopped and nothing was sent.`);
  await sendOnRow(ctx, test, body, n, into);
}
/** Prints Reset and waits until the row reads Never, then records when. */
async function resetRow(ctx, entry) {
  ctx.say(`Reset "${entry.label}" to Never`);
  const deadline = ctx.clock() + PLAN_LIMITS.ownerWaitMs;
  for (;;) {
    if (ctx.port.rowMode(entry.connectionId, entry.row) === 'deny') { entry.neverSeenAt = ctx.now(); ctx.state.save(); return true; }
    if (ctx.clock() >= deadline) { ctx.say(`"${entry.label}" still is not Never. Set it to Never on the app page now.`); return false; }
    await ctx.wait(PLAN_LIMITS.pollMs);
  }
}
/** Stop step 1: every row this run opened that does not read Never now is reset, and Never is read and recorded, before anything else. */
async function resetRows(ctx) {
  for (const entry of ctx.run.rows) {
    if (!entry.askSeenAt && !entry.allowSeenAt) continue;
    if (ctx.port.rowMode(entry.connectionId, entry.row) === 'deny') { entry.neverSeenAt ??= ctx.now(); continue; }
    await resetRow(ctx, entry);
  }
  ctx.state.save();
}

// ---- stop step 2: the pending undos -----------------------------------------------------------------------------------------------
/** Whether a test's steps sent a change that may still stand. */
function changed(ctx, result) {
  return result.proxies.length > 0 || result.calls.some(call => call.jobs.some(id => { const job = ctx.port.job(id); return job && job.effect !== 'read' && ['succeeded', 'uncertain'].includes(job.status); }));
}
/** The later undo tests not yet run, and the undo steps of a test that stopped before them, newest test first: a later change is undone
 *  before what it was made in, so an event is moved back and cancelled before its calendar is deleted (live run TOQJPGEU deleted the
 *  calendars first, and the event undos then found nothing). */
export function pendingUndos(ctx) {
  const pending = [];
  for (const id of ctx.run.order) {
    const result = ctx.run.results[id];
    if (result.undo.kind === 'test' && !ctx.run.results[result.undo.test] && !pending.some(item => item.id === result.undo.test)) pending.push({kind: 'test', id: result.undo.test, of: id, words: `${result.undo.test} (it undoes ${id})`});
    if (result.undo.kind === 'steps' && !result.undo.ran && changed(ctx, result)) pending.push({kind: 'steps', id, of: id, words: `the undo of ${id}`});
  }
  return pending.reverse();
}
/** What the run made whose undo has not run: a test with no result, undo steps not run, or an undo test not run. */
const madeAndStanding = ctx => ctx.guard.created().filter(item => {
  const result = ctx.run.results[item.test];
  return !result || (result.undo.kind === 'steps' ? !result.undo.ran : result.undo.kind === 'test' ? !ctx.run.results[result.undo.test] : false);
}).map(item => `a ${item.kind} made in ${item.test}`);
/** A cleanup test the owner chose to leave: named once in the leftovers, never run. */
function leftByChoice(ctx, test) {
  const words = `${test.id} (${test.name}) was not run: the owner chose to leave what this run made.`;
  if (!ctx.run.left.includes(words)) { ctx.run.left.push(words); ctx.say(`Left in place: ${words}`); ctx.state.save(); }
}
async function offerUndos(ctx) {
  const cleanup = item => item.kind === 'test' && ctx.plan.tests.find(test => test.id === item.id)?.cleanup === true;
  if (ctx.leave) for (const item of pendingUndos(ctx).filter(cleanup)) leftByChoice(ctx, ctx.plan.tests.find(test => test.id === item.id));
  const pending = pendingUndos(ctx).filter(item => !(ctx.leave && cleanup(item))), made = madeAndStanding(ctx);
  if (!pending.length) {
    const standing = made.map(item => `${item} is still there.`);
    ctx.run.left.push(...standing);
    for (const item of standing) ctx.say(`Left in place: ${item}`);
    ctx.state.save();
    return;
  }
  for (const item of pending) ctx.say(`Pending undo: ${item.words}`);
  const answer = await ctx.prompt('Run the pending undos now? Type yes or no.');
  if (/^\s*y(es)?\s*$/i.test(String(answer ?? ''))) {
    // An undo test may be undone by a later test in turn (Gmail's G1 and G2 by G11), so what running one leaves pending runs too, until
    // nothing new is pending. An undo that fails is named, with what the run made that still stands.
    const tried = new Set(), failed = [];
    for (let next = pending; next.length; next = pendingUndos(ctx).filter(item => !tried.has(`${item.kind} ${item.id}`) && !(ctx.leave && cleanup(item)))) {
      for (const item of next) {
        tried.add(`${item.kind} ${item.id}`);
        const test = ctx.plan.tests.find(candidate => candidate.id === item.id);
        if (item.kind === 'test') await runTest(ctx, test);
        else await runUndoAfterStop(ctx, test);
        const result = ctx.run.results[item.id];
        if (item.kind === 'test' ? result?.passed !== true : result?.undo.passed !== true) failed.push(`${item.words} failed.`);
      }
    }
    const standing = [...failed, ...madeAndStanding(ctx).map(item => `${item} is still there.`)];
    ctx.run.left.push(...standing);
    for (const item of standing) ctx.say(`Left in place: ${item}`);
    ctx.state.save();
    return;
  }
  const standing = [...pending.map(item => `${item.words} was not run.`), ...made.map(item => `${item} is still there.`)];
  ctx.run.left.push(...standing);
  for (const item of standing) ctx.say(`Left in place: ${item}`);
  ctx.state.save();
}
/** The undo steps of a test that stopped, run like a test: inside the guard's test of that id, on a new grant, each after its approval. */
async function runUndoAfterStop(ctx, test) {
  const result = ctx.run.results[test.id];
  ctx.guard.begin(test.id);
  ctx.space = 'u';
  try {
    const grant = bind(ctx, test, test.undo.steps, ctx.plan.readRows, 'grant');
    result.undo.ran = true;
    result.undo.from = ctx.guard.trace(test.id).length;
    for (const [index, step] of test.undo.steps.entries()) await runStep(ctx, test, step, index + 1, result.undo, grant);
    result.undo.passed = result.undo.checks.every(check => check.passed);
  } catch (error) {
    result.undo.passed = false;
    ctx.say(`The undo of ${test.id} failed: ${String(error.message).slice(0, 300)}`);
  } finally {
    ctx.space = '';
    unbind(ctx, 'grant');
    ctx.guard.end();
    ctx.state.save();
  }
}

// ---- the evidence -----------------------------------------------------------------------------------------------------------------
const ROUTE = template => template.split('/').filter(Boolean);
/** Whether a request's decoded segments fit a plan template ({slot} one segment, {+slot} one or more). */
function fitsTemplate(template, segments) {
  const parts = ROUTE(template);
  for (const [index, part] of parts.entries()) {
    if (/^\{\+/.test(part)) return segments.length > index;
    if (index >= segments.length) return false;
    if (!/^\{/.test(part) && part !== segments[index]) return false;
  }
  return parts.length === segments.length;
}
/**
 * The evidence of a run: one record per action a test called, under its id (the one evidencePasses() and check 6 read), and a `run` key
 * with the run's own facts, the tests that call no action and the owner's row changes. Each test lists its jobs (status, error code and
 * each approval's phase and time), its requests from the guard's trace (method, the path template a placement or the plan fits, the body
 * HMAC, the provider status and the created identity), its checks by name and its undo. A request that fits nothing fails its test. Each
 * transform the action names carries the code hash computed now; the record passes only when each equals its pin and every test and undo
 * that used the action passed. Email-shaped strings are HMACs under `key`. `trace(testId)` and `job(jobId)` read the guard and the port.
 */
export function evidenceRecords(run, {key, entries, trace, job, root = ROOT, pins = PINS?.transforms ?? {}, codeHashes = ids => Object.fromEntries(ids.map(id => [id, codeHash(root, id)])),
  groups = PERMISSION_GROUPS, configs = PROXY_CONFIGS, maps = new Map()} = {}) {
  if (!(key instanceof Uint8Array) || key.length < 32) throw new Error('The evidence needs the run\'s HMAC key.');
  const appId = run.appId, definition = groups.get(appId), config = configs.get(appId), map = maps.get(appId) ?? null, base = proxyBase(config.apiBase);
  const byId = new Map(entries.map(entry => [entry.id, entry]));
  const mac = value => `hmac:${createHmac('sha256', Buffer.from(key)).update(value).digest('hex').slice(0, 32)}`;
  const scrub = value => typeof value === 'string' && EMAIL_IN.test(value) ? mac(value) : value;
  const harness = harnessHash(root), runtime = {node: process.versions.node, tz: process.versions.tz ?? null, icu: process.versions.icu ?? null, unicode: process.versions.unicode ?? null};
  const segmentsOf = pathname => {
    if (pathname !== base.basePath && !pathname.startsWith(`${base.basePath}/`)) return null;
    try { return pathname.slice(base.basePath.length).split('/').filter(Boolean).map(decodeURIComponent); } catch { return null; }
  };
  const templateOf = (item, used, reads) => {
    const segments = segmentsOf(item.path);
    if (!segments) return null;
    for (const entry of used) for (const placement of entry.placements) {
      try { placeRequest(placement, {method: item.method, segments, body: null}, {definition, config, map}); return pathOf(placement.template); } catch { /* the next one */ }
    }
    // The trace keeps a body's keyed hash, never its bytes, so a step a body route moved (Notion's Restore, by in_trash) cannot be placed above:
    // its own template stands in, and the runtime and the guard placed the request with its bytes when it was sent. No other step gets this.
    for (const entry of used) for (const placement of entry.placements) if (placement.routedFrom && placement.method === item.method && fitsTemplate(pathOf(placement.template), segments)) return pathOf(placement.template);
    return reads.find(read => read.method === item.method && fitsTemplate(read.path, segments))?.path ?? null;
  };
  const requestsOf = (list, used, reads) => {
    const requests = list.map(item => ({method: item.method, template: templateOf(item, used, reads), bodyHmac: item.bodyHmac ?? null, status: item.status ?? null, identity: scrub(item.identity ?? null)}));
    return {requests, fits: requests.every(item => item.template !== null)};
  };
  const jobsOf = ids => ids.map(id => job(id)).filter(Boolean).map(item => ({id: item.id, status: item.status, errorCode: item.errorCode ?? null,
    approvals: item.kind === 'action' ? (item.action?.decisions ?? []).filter(decision => decision.decision === 'approved').map(decision => ({phase: decision.phase, at: decision.at}))
      : item.approvedAt && item.approvedBy === 'single-action' ? [{phase: 'proxy', at: item.approvedAt}] : []}));
  const usedBy = calls => calls.map(call => byId.get(call.actionId)).filter(Boolean);
  const testRecord = (result, actionId) => {
    const all = trace(result.id), undo = result.undo, cut = undo.kind === 'steps' && Number.isSafeInteger(undo.from) ? undo.from : all.length;
    const used = usedBy([...result.calls, ...(undo.calls ?? [])]), own = requestsOf(all.slice(0, cut), used, result.reads);
    const ids = calls => calls.filter(call => actionId === null || call.actionId === actionId).flatMap(call => call.jobs);
    let shown;
    if (undo.kind === 'test') shown = {test: undo.test};
    else if (undo.kind === 'none') shown = {none: undo.why};
    else {
      const later = requestsOf(all.slice(cut), used, undo.reads);
      shown = {passed: undo.passed === true && later.fits, jobs: jobsOf(undo.calls.flatMap(call => call.jobs)), requests: later.requests, checks: undo.checks.map(({name, passed}) => ({name, passed}))};
    }
    return {test: result.id, passed: result.passed === true && own.fits, jobs: jobsOf([...ids(result.calls), ...(actionId === null ? result.proxies : [])]), requests: own.requests,
      checks: result.checks.map(({name, passed}) => ({name, passed})), undo: shown};
  };
  const ran = run.order.map(id => run.results[id]).filter(Boolean);
  const records = {};
  for (const entry of entries) {
    const tests = ran.filter(result => [...result.calls, ...(result.undo.calls ?? [])].some(call => call.actionId === entry.id)).map(result => testRecord(result, entry.id));
    if (!tests.length) continue;
    const hashes = entry.transforms.length ? codeHashes([...entry.transforms]) : {};
    const transforms = Object.fromEntries(entry.transforms.map(id => [id, hashes?.[id] ?? null]));
    const pinned = entry.transforms.every(id => typeof pins[id] === 'string' && transforms[id] === pins[id]);
    records[entry.id] = {schemaVersion: 1, passed: pinned && tests.every(item => item.passed && item.undo.passed !== false), definitionHash: entry.definitionHash, runId: run.runId,
      ranAt: run.finishedAt ?? null, transforms, harnessHash: harness, runtime, tests};
  }
  const alone = ran.filter(result => ![...result.calls, ...(result.undo.calls ?? [])].length).map(result => testRecord(result, null));
  const rows = run.rows.map(item => ({row: item.row, label: item.label, askSeenAt: item.askSeenAt ?? null, allowSeenAt: item.allowSeenAt ?? null, neverSeenAt: item.neverSeenAt ?? null}));
  return {records, run: {runId: run.runId, appId, startedAt: run.startedAt ?? null, finishedAt: run.finishedAt ?? null, harnessHash: harness, runtime, tests: alone, rows}};
}

/**
 * Refuses evidence text that holds a known address (any case), the sha256 of one as given or lowercased (whole or cut short), any email-shaped string, a
 * bodySha256 key, a Bearer credential, a token-shaped prefix (TOKEN_PREFIXES) or a known token. Throws; returns nothing.
 */
export function assertEvidenceSafe(text, {emails = [], tokens = []} = {}) {
  const refuse = what => { throw new Error(`The evidence holds ${what}, so it was not written.`); };
  const lower = String(text).toLowerCase();
  for (const email of emails) {
    if (typeof email !== 'string' || !email) continue;
    if (lower.includes(email.toLowerCase())) refuse('a known address');
    // Any hash of it starting with the first 16 hex characters of its sha256: the whole digest, or the start of one cut short.
    for (const form of new Set([email, email.toLowerCase(), email.trim(), email.trim().toLowerCase()])) if (lower.includes(sha256(form).slice(0, 16))) refuse('the sha256 hash of a known address');
  }
  if (EMAIL_IN.test(text)) refuse('an email address');
  if (/bodysha256/i.test(text)) refuse('a body hash');
  if (/\bbearer\b/i.test(text)) refuse('a bearer credential');
  for (const prefix of TOKEN_PREFIXES) if (text.includes(prefix)) refuse('a token');
  for (const token of tokens) if (typeof token === 'string' && token && text.includes(token)) refuse('a token');
}
/**
 * Writes docs/live-evidence/<appId>/actions.json under `root`: this run's records replace those of the same action ids, others are kept,
 * and `run` is replaced. Sorted keys, a one-space indent and a final newline, checked by assertEvidenceSafe() before anything is written.
 * Returns the text. Muse commits it only with the owner's OK.
 */
export function writeEvidence(root, appId, evidence, {emails = [], tokens = []} = {}) {
  if (!APP.test(appId)) throw new Error('The evidence names its app.');
  const file = path.join(root, 'docs', 'live-evidence', appId, 'actions.json');
  let kept = {};
  if (existsSync(file)) {
    try { kept = JSON.parse(readFileSync(file, 'utf8')); } catch { throw new Error(`${path.relative(root, file)} is not JSON, so it was left as it is.`); }
    if (!record(kept)) throw new Error(`${path.relative(root, file)} is not a JSON object, so it was left as it is.`);
  }
  const merged = {...kept, ...evidence.records, run: evidence.run};
  const text = `${JSON.stringify(sortKeys(merged), null, 1)}\n`;
  assertEvidenceSafe(text, {emails, tokens});
  mkdirSync(path.dirname(file), {recursive: true});
  writeFileSync(file, text);
  return text;
}

/** F10.19 (spec line 1174, N0): the fields of docs/live-evidence/<appId>/introspection.json, in this order. */
export const INTROSPECTION_FIELDS = Object.freeze(['schemaVersion', 'appId', 'runId', 'at', 'active', 'scope', 'listsCapabilities']);
/**
 * Writes docs/live-evidence/<appId>/introspection.json under `root`: the run's one token introspection as exactly {schemaVersion: 1, appId,
 * runId, at, active, scope (a string or null), listsCapabilities}, whatever else `record` holds (never the token, iat or a request id).
 * Sorted keys, a one-space indent and a final newline, checked by assertEvidenceSafe() before anything is written. Returns the text.
 */
export function writeIntrospection(root, appId, record, {emails = [], tokens = []} = {}) {
  if (!APP.test(appId)) throw new Error('The evidence names its app.');
  const picked = {schemaVersion: 1, appId, runId: String(record?.runId ?? ''), at: String(record?.at ?? ''), active: record?.active === true,
    scope: typeof record?.scope === 'string' ? record.scope : null, listsCapabilities: record?.listsCapabilities === true};
  const text = `${JSON.stringify(sortKeys(picked), null, 1)}\n`;
  assertEvidenceSafe(text, {emails, tokens});
  const file = path.join(root, 'docs', 'live-evidence', appId, 'introspection.json');
  mkdirSync(path.dirname(file), {recursive: true});
  writeFileSync(file, text);
  return text;
}

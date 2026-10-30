// F10.9 parts f to h (docs/F10.9-BUILD-MAP.md parts f, g and h; spec lines 709-786 and section 8; R2, R4, R7, R9, R11, R12 and R13;
// open points Important 2, 3, 5, 6 and 8, and Minor 1, 2, 3 and 6): the action file validator. validateActionFile() reads one app's
// reviewed action file against that app's rows, proxy settings, application map, transform registry and pins, choice sources and
// reviewed sign-in. It returns each action as written, frozen, with what F10.11 needs beside it: its id, computed from its content and
// checked against the stored one, and its definition hash; its step placements, its paths, whether it is sensitive or two-phase, the
// lookups it runs (R12) and the request positions checkRequest() holds to a scalar at run time; and, for a read action a polling trigger
// can reuse, its poll hash. Every expression is read through lib/action-expressions.mjs (part d) and every step is placed through
// lib/action-placement.mjs (part e). actionCapability() is the capability an action becomes, a candidate that no http path accepts (I2,
// I8); loadActions() reads a folder of action files; jobKey() is the per-job key an expression's {jobKey} reads. checkOutput(),
// checkPreview() and checkRequest() are the run-time halves of the static rules; runPlan() says which steps run when an optional scope is
// missing. Nothing here reads a store, runs a transform or sends a request.
import {readdirSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalHash, checkSchema, validateInput, credentialName, exchangeField, secretParameter} from './compiler.mjs';
import {secretKey} from './redaction.mjs';
import {parseTemplate, memberKey, memberData, PERMISSION_GROUPS} from './permission-groups.mjs';
import {PROXY_CONFIGS} from './proxy-config.mjs';
import {reservedQueryName, CALLER_HEADERS} from './proxy-request.mjs';
import {checkExpression, checkTest, checkCall, assertPerformSources, newBudget, checkPointer, readsOnly, PERFORM_SOURCES} from './action-expressions.mjs';
import {placeStep, actionEffect, accessOf, RESOLVING_WRITES} from './action-placement.mjs';
import {OPTION_SOURCES} from './option-sources.mjs';
import {checkChoices, loadChoiceSources, sourceById} from './choice-sources.mjs';
import {capabilityPermissionHash} from './permissions.mjs';
import {TRANSFORMS} from './transforms/index.mjs';
import {bindingsFit} from './transforms/run.mjs';
import {PINS, validDate} from './transform-pins.mjs';
import {definitionFor, reviewedProviderIds} from './providers/definitions.mjs';

const deepFreeze = value => { if (value !== null && typeof value === 'object') { Object.freeze(value); for (const item of Object.values(value)) deepFreeze(item); } return value; };

/** R2: the reviewed resolving writes, kept with placement (lib/action-placement.mjs) and read here. */
export {RESOLVING_WRITES};
/**
 * F10.8 open point Minor 5: the members whose prepared answer may give rfc5322.build@1 its sender, by app. Only the account's own
 * profile read: the address and display name in any other prepared answer (a parent message, a draft) were written by someone else.
 */
export const SENDER_SOURCES = deepFreeze({gmail: ['gmail.users.getProfile']});
/** The transform arguments the sender rule holds, by transform. */
export const SENDER_ARGUMENTS = deepFreeze({'rfc5322.build@1': ['from']});
/**
 * Spec line 748: members in write rows whose readback may be the address itself, by app: removals that leave nothing to read back
 * but the absence. A delete needs no entry. Open point Minor 6: there are no singletons; Set out-of-office reply reads its settings
 * back with a readback pointer equal to what it sent.
 */
export const REMOVALS = deepFreeze({slack: ['POST /chat.deleteScheduledMessage', 'POST /reactions.remove']});
/** Spec line 715: the action's own refusal codes for guards, in fixed words. The guard transform's code is kept beside as the reason. */
export const REFUSALS = deepFreeze({
  wrong_kind: 'This action works only on one kind of item, and this item is another kind.',
  wrong_state: 'This item is not in a state this action changes.',
  time_window: 'The time given is outside the window this action allows.',
});
/** Spec lines 722 and 752: codes that mean "failed, nothing changed" when no earlier write was sent: lib/runtime.mjs:20, plus 409 and 429. */
export const DEFINITIVE_CODES = Object.freeze([400, 401, 403, 404, 405, 406, 409, 410, 411, 412, 413, 414, 415, 416, 417, 422, 428, 429, 431]);
/** Headers an action step never sends: Fabric sends them itself, or they carry a credential (spec line 741). */
export const FABRIC_HEADERS = Object.freeze(['Authorization', 'Notion-Version', 'X-GitHub-Api-Version', 'User-Agent', 'Content-Type']);
/** Spec line 751 and open question 10: the Notion fields an action body never writes as a key. in_trash is only the constant false. */
export const NOTION_RESERVED = Object.freeze(['erase_content', 'allow_deleting_content', 'is_locked', 'display_name', 'archived', 'is_archived']);
/** I7: the bounds of one action. */
export const BOUNDS = Object.freeze({steps: 8, perform: 3, verifyPerPath: 2, forEach: 25, pages: 10, requests: 64, responseBytes: 2 * 1024 * 1024,
  jobBytes: 16 * 1024 * 1024, preparedBytes: 4 * 1024 * 1024, outputBytes: 1024 * 1024});
/**
 * Section 8 (part h): the cursor kinds a read action's poll block names, each with its version for the engine (I07). `slot` is where its
 * one {cursor} slot sits in the poll step: 'request' (the query or the body), the conditional header it fills, or null for a snapshot,
 * which re-reads the list and compares its ids. `header` is the response header its value is. `compare` lists the pinned transforms that
 * may order its values (F10.8 map part m); a kind with none goes back to the provider as it came. `overlap` marks a high-water mark,
 * which may take the latest item time and re-read an overlap; `excludes` marks a sync token, whose step never sends the names it lists.
 */
export const CURSOR_KINDS = deepFreeze({
  'history-id@1': {slot: 'request', compare: ['time.decimalCompare@1']},
  'sync-token@1': {slot: 'request', compare: [], excludes: true},
  'high-water-time@1': {slot: 'request', compare: ['time.rfc3339ToEpochSeconds@1', 'time.decimalCompare@1'], overlap: true},
  'high-water-ts@1': {slot: 'request', compare: ['time.slackTs@1'], overlap: true},
  'etag@1': {slot: 'If-None-Match', header: 'etag', compare: []},
  'last-modified@1': {slot: 'If-Modified-Since', header: 'last-modified', compare: []},
  'snapshot@1': {slot: null, compare: ['collections.diff@1']},
});
/** Section 8 (part h; spec lines 663-668): each item time format, with the pinned F10.8 transform that orders its values. */
export const ITEM_TIME_FORMATS = Object.freeze({rfc3339: 'time.rfc3339ToEpochSeconds@1', 'epoch-ms-string': 'time.decimalCompare@1', 'epoch-seconds': 'time.decimalCompare@1', 'slack-ts': 'time.slackTs@1'});

const APP_ID = /^[a-z][a-z0-9-]{0,63}$/, KEY = /^[a-z][a-z0-9-]{0,47}$/, STEP_ID = /^[a-z][A-Za-z0-9]{0,31}$/, NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const KIND = /^[a-z][a-z0-9-]{0,31}$/, HASH = /^[a-f0-9]{64}$/, SEGMENT = /^[A-Za-z0-9._~-]{1,200}$/, QUERY_NAME = /^[\w.~:[\]-]{1,128}$/;
const EFFECTS = ['read', 'write', 'delete'], RANK = {read: 0, write: 1, delete: 2};
const SCALARS = new Set(['string', 'integer', 'number', 'boolean']);
// Part k: the phases of a trigger's read steps, which ActionState checks for lib/triggers.mjs.
const TRIGGER_PHASES = ['poll', 'seed', 'enrich'];
const RAW_KINDS = new Set(['step', 'item', 'var', 'pick']);
const STEP_FIELDS = ['params', 'query', 'headers', 'body', 'when', 'forEach', 'page', 'optional', 'fallbackFor', 'resolves', 'maxResponseBytes', 'requiresScope', 'bindContent'];
const ACTION_FIELDS = ['id', 'key', 'version', 'name', 'description', 'effect', 'row', 'hints', 'inputSchema', 'outputSchema', 'guards', 'prepare', 'perform', 'output', 'preview', 'definitive'];
const ACTION_OPTIONAL = ['choices', 'resolvedInputs', 'verify', 'askUnless', 'records', 'poll', 'servesSource', 'certified'];
const ASSERTIONS = ['equals', 'contains', 'present', 'absent', 'statusIn', 'listHas', 'listLacks', 'test', 'anyOf'];
const POLL_FIELDS = ['step', 'items', 'itemId', 'itemVersion', 'order', 'cursors', 'resync', 'resourceKey', 'filterInputs', 'minIntervalSeconds'];
// The capability's action block (part g): what F10.11 runs, beside its key, pinned parameters and steps, in this order when present.
const CAPABILITY_FIELDS = ['verify', 'guards', 'output', 'preview', 'askUnless', 'records', 'definitive', 'hints', 'choices', 'resolvedInputs'];
// The name rule of {jobKey} (lib/action-expressions.mjs).
const JOB_KEY_NAME = /^[a-z][A-Za-z0-9-]{0,63}$/;
const NOTION_APP = 'notion', NOTION_TITLE_FROM = 'text.chunk@1', NOTION_VALUES = 'notion.propertyValues@1', LINK_PAGES = 'ids.linkPage@1';
// Section 9: a resource-dependent input in inputSchema, before its schema is derived at run time; the sources a schema step reads.
const PLACEHOLDER = Object.freeze({type: 'object', properties: Object.freeze({}), additionalProperties: false});
const SCHEMA_STEP_SOURCES = new Set(['constant', 'input', 'account', 'schema']);
const TRANSFORM_ID = /^[a-z][a-z0-9]*\.[a-z][A-Za-z0-9]*@[1-9][0-9]*$/, UNSAFE_NAMES = new Set(['__proto__', 'prototype', 'constructor']);
const MEBI = 1024 * 1024;

const fail = message => { throw new Error(message); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const methodEffect = method => method === 'GET' ? 'read' : method === 'DELETE' ? 'delete' : 'write';
const stronger = (a, b) => RANK[a] >= RANK[b] ? a : b;
const bytes = value => String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
const listWords = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
const canonical = value => JSON.stringify(value, (key, item) => record(item) ? Object.fromEntries(Object.keys(item).sort().map(name => [name, item[name]])) : item);
/** The value has exactly the `required` keys and no keys outside `optional`. */
const shaped = (value, required, optional = []) => record(value) && required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const text = (value, max) => typeof value === 'string' && value.trim().length > 0 && [...value].length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const codes = value => Array.isArray(value) && value.length >= 1 && value.length <= 16 && new Set(value).size === value.length && value.every(code => Number.isSafeInteger(code) && code >= 100 && code <= 599);
const pointerOf = tokens => tokens.map(token => `/${String(token).replace(/~/g, '~0').replace(/\//g, '~1')}`).join('');
const tokensOf = pointer => pointer ? pointer.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~')) : [];
const an = word => /^[aeiou]/.test(word) ? 'an' : 'a';
/** The closed schema at a pointer's tokens, or null: an object's declared property, a list's items at an index. */
function schemaIn(schema, tokens) {
  let current = schema;
  for (const token of tokens) {
    if (current?.type === 'object' && Object.hasOwn(current.properties ?? {}, token)) current = current.properties[token];
    else if (current?.type === 'array' && /^(?:0|[1-9][0-9]*)$/.test(token)) current = current.items;
    else return null;
  }
  return current ?? null;
}

/** Every fact a fact is built from, depth first (the facts lib/action-expressions.mjs returns). */
function* walk(result) {
  if (!record(result)) return;
  yield result;
  for (const key of ['members', 'args']) if (result[key] instanceof Map) for (const item of result[key].values()) yield* walk(item);
  for (const key of ['items', 'parts', 'branches', 'tests']) if (Array.isArray(result[key])) for (const item of result[key]) yield* walk(item);
  for (const key of ['then', 'test', 'list', 'do', 'operand', 'of']) if (record(result[key]) && result[key].sources instanceof Set) yield* walk(result[key]);
}
/**
 * The expressions a perform step sends as they are, by canonical text, so an identity can be compared with what was sent: each value
 * placed in a path parameter, a query value or the body, and the values inside objects, lists, a {when}'s kept value, an {either}'s
 * branches and an {each}'s do. A transform's arguments and a test's operands are not sent; the transform's result and the pick are.
 */
function sentNodes(node, out) {
  if (!record(node) || Object.hasOwn(node, 'const')) return out;
  out.add(canonical(node));
  if (record(node.object)) for (const value of Object.values(node.object)) sentNodes(value, out);
  if (Array.isArray(node.array)) for (const item of node.array) sentNodes(item, out);
  if (Array.isArray(node.either)) for (const branch of node.either) sentNodes(branch, out);
  if (Object.hasOwn(node, 'when')) sentNodes(node.then, out);
  if (Object.hasOwn(node, 'each')) sentNodes(node.do, out);
  return out;
}

/** The reviewed sign-in of each app, by app id, read from catalog/auth once and only when a caller passes none. */
let defaultIdentities = null;
function identitiesOf() {
  if (!defaultIdentities) {
    defaultIdentities = new Map();
    for (const provider of reviewedProviderIds()) for (const app of definitionFor(provider).apps) defaultIdentities.set(app.appId, definitionFor(provider));
  }
  return defaultIdentities;
}
const mapIn = (maps, appId) => maps instanceof Map ? maps.get(appId) ?? null : record(maps) ? maps[appId] ?? null : null;
const sourcesIn = (choices, appId) => {
  const entry = choices instanceof Map ? choices.get(appId) : record(choices) ? choices[appId] : null;
  return Array.isArray(entry) ? entry : Array.isArray(entry?.sources) ? entry.sources : [];
};
/** Part i: an app's version 1 option sources, which a choice may name by id (section 9). */
const optionsIn = (options, appId) => { const entry = options instanceof Map ? options.get(appId) : record(options) ? options[appId] : null; return Array.isArray(entry) ? entry : []; };

// ---- schemas -------------------------------------------------------------------------------------------------------------------------
/** I3: no input name at any depth is a credential, a credential exchange field or a credential parameter (spec line 742). */
function credentialInputs(schema, path, where) {
  if (schema.type === 'object') for (const [name, sub] of Object.entries(schema.properties)) {
    if (credentialName(name) || exchangeField(name) || secretParameter(name)) fail(`${where}: the input ${path}.${name} is named like a credential: an action input never carries one (I3).`);
    credentialInputs(sub, `${path}.${name}`, where);
  }
  if (schema.type === 'array') credentialInputs(schema.items, `${path}[]`, where);
}
/** F10.11 part d: the field names lib/mcp-adapter.mts redacts from every result beyond the secret names, in any case. */
const MCP_REDACTED = /^(?:preview|tokenHash|approvalDigest)$/i;
/** R11: no output field at any depth carries a secret by its name, or a name MCP would silently redact (F10.11 part d). */
function secretOutputs(schema, path, where) {
  if (schema.type === 'object') for (const [name, sub] of Object.entries(schema.properties)) {
    if (secretKey(name)) fail(`${where}: outputSchema declares ${path}.${name}, a field that carries a secret (R11).`);
    if (MCP_REDACTED.test(name)) fail(`${where}: outputSchema declares ${path}.${name}, a field name MCP removes from every result, so an agent would never see it.`);
    secretOutputs(sub, `${path}.${name}`, where);
  }
  if (schema.type === 'array') secretOutputs(schema.items, `${path}[]`, where);
}
/** Each property of an input schema as its path of names, a list's items as '*'. */
function inputPaths(schema, prefix = [], out = []) {
  if (schema.type === 'object') for (const [name, sub] of Object.entries(schema.properties)) { out.push([...prefix, name]); inputPaths(sub, [...prefix, name], out); }
  if (schema.type === 'array') inputPaths(schema.items, [...prefix, '*'], out);
  return out;
}
/** An input pointer read as a path of names over the schema: a list index becomes '*'. */
function readPath(schema, pointer) {
  const tokens = pointer.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~')), path = [];
  let current = schema;
  for (const token of tokens) {
    if (current?.type === 'array') { path.push('*'); current = current.items; } else { path.push(token); current = current?.properties?.[token]; }
  }
  return path;
}
const prefixOf = (a, b) => a.length <= b.length && a.every((name, index) => name === b[index]);

// ---- the validator -------------------------------------------------------------------------------------------------------------------
/**
 * Validates one app's action file (docs/F10.9-BUILD-MAP.md parts f to h) and returns {appId, actions}, frozen. Each action entry is
 * {key, version, id, definitionHash, effect, row, action, placements, unplaced, sensitive, twoPhase, paths, lookups, transforms, rawAt,
 * pollHash, pollTransforms}: `action` is the action as written; the rest is computed beside it, never inside it. Its stored id must equal
 * the id its content hashes to, and a certified definition hash the one computed (part g). `deps`: {groups, configs, maps, transforms,
 * pins, choices, identities}: the validated rows and proxy settings by app (the shipped ones by default), the stored application maps by
 * app (Gmail and Calendar place only through one; without it their actions are unplaced, valid in shape and never runnable), the
 * transform registry and its pins (open point Minor 2; the shipped lib/transforms/pins.json by default), the choice sources by app (part
 * i), and each app's reviewed sign-in. Throws an Error naming the action, the position and the rule.
 */
export function validateActionFile(file, deps = {}) {
  return readActionFile(file, deps, true);
}
/**
 * Part g: the id and definition hash each action of `file` must carry, by `<key> v<version>`. The file is validated as
 * validateActionFile() validates it, except that a stored id, and a certified definition hash, may be stale: this is what an author
 * runs to write them, and a review then sees every change.
 */
export function actionIds(file, deps = {}) {
  const {actions} = readActionFile(file, deps, false);
  return new Map(actions.map(entry => [`${entry.key} v${entry.version}`, Object.freeze({id: entry.id, definitionHash: entry.definitionHash})]));
}
function readActionFile(file, deps, stored) {
  const {groups = PERMISSION_GROUPS, configs = PROXY_CONFIGS, maps = new Map(), transforms = TRANSFORMS, pins = PINS?.transforms ?? {}, choices = new Map(), options = OPTION_SOURCES,
    identities = identitiesOf()} = deps;
  if (!record(file)) fail('Actions: an action file is an object.');
  const appId = file.appId, at = `Actions for ${appId}`;
  if (!shaped(file, ['schemaVersion', 'appId', 'specVersion', 'reviewStatus', 'pinnedParameters', 'actions'], ['superseded'])) fail(`${at}: an action file holds exactly schemaVersion, appId, specVersion, reviewStatus, pinnedParameters and actions, and may hold superseded.`);
  if (file.schemaVersion !== 1) fail(`${at}: schemaVersion is 1.`);
  if (typeof appId !== 'string' || !APP_ID.test(appId)) fail(`${at}: appId is an app id.`);
  const definition = groups.get(appId), config = configs.get(appId);
  if (!definition || !config) fail(`${at}: the app has no reviewed permission rows and proxy settings.`);
  if (file.specVersion !== 'fabric/0.2') fail(`${at}: specVersion is fabric/0.2.`);
  if (!['reviewed', 'candidate'].includes(file.reviewStatus)) fail(`${at}: reviewStatus is reviewed or candidate.`);
  if (!record(file.pinnedParameters) || Object.entries(file.pinnedParameters).some(([name, value]) => !NAME.test(name) || typeof value !== 'string' || !SEGMENT.test(value))) {
    fail(`${at}: pinnedParameters maps names to constant path segments.`);
  }
  if (!Array.isArray(file.actions) || !file.actions.length || file.actions.length > 100) fail(`${at}: actions holds 1 to 100 actions.`);
  const identity = identities instanceof Map ? identities.get(appId) ?? null : null;
  let access = null;
  try { access = identity ? accessOf(identity, appId) : null; } catch { access = null; }
  const ctx = {at, appId, file, definition, config, map: mapIn(maps, appId), transforms, pins, sources: sourcesIn(choices, appId), options: optionsIn(options, appId), identity, access, stored};
  const seen = new Set(), actions = file.actions.map((action, index) => {
    const entry = checkAction(action, index, ctx), pair = `${entry.key} v${entry.version}`;
    if (seen.has(pair)) fail(`${at}: ${pair} is declared twice.`);
    seen.add(pair);
    return entry;
  });
  if (file.superseded !== undefined) checkSuperseded(file, actions, at);
  return Object.freeze({appId, actions: Object.freeze(actions)});
}

/** R9: old ids no longer in actions, keyed by the old id, each pointing at a current action, with a reason and the date the old id stops. */
function checkSuperseded(file, actions, at) {
  if (!Array.isArray(file.superseded) || !file.superseded.length || file.superseded.length > 100) fail(`${at}: superseded holds 1 to 100 entries.`);
  const listed = new Set(), id = new RegExp(`^${file.appId.replace(/-/g, '\\-')}\\.action\\.[a-z][a-z0-9-]{0,47}\\.v[1-9][0-9]{0,3}\\.[a-f0-9]{24}$`);
  file.superseded.forEach((entry, index) => {
    const where = `${at}: superseded[${index}]`;
    if (!shaped(entry, ['id', 'replacedBy', 'reason', 'stopsAfter']) || !shaped(entry.replacedBy, ['key', 'version'])) fail(`${where} is {id, replacedBy: {key, version}, reason, stopsAfter}.`);
    if (typeof entry.id !== 'string' || !id.test(entry.id)) fail(`${where}.id is not an action id of ${file.appId}.`);
    const current = actions.find(action => action.id === entry.id);
    if (current) fail(`${where}.id is the current id of ${current.key} v${current.version}: a superseded id is no longer in actions.`);
    if (!actions.some(action => action.key === entry.replacedBy.key && action.version === entry.replacedBy.version)) fail(`${where}.replacedBy names no action of this file.`);
    if (!['safety', 'change'].includes(entry.reason)) fail(`${where}.reason is safety or change.`);
    if (!validDate(entry.stopsAfter)) fail(`${where}.stopsAfter is a real date, YYYY-MM-DD.`);
    if (listed.has(entry.id)) fail(`${at}: superseded lists ${entry.id} twice.`);
    listed.add(entry.id);
  });
}

function checkAction(action, index, ctx) {
  const {at, appId, definition, config} = ctx;
  if (!record(action)) fail(`${at}: actions[${index}] is an object.`);
  if (!shaped(action, ACTION_FIELDS, ACTION_OPTIONAL)) fail(`${at}: actions[${index}]: an action holds exactly ${listWords(ACTION_FIELDS)}, and may hold ${listWords(ACTION_OPTIONAL)}.`);
  if (typeof action.key !== 'string' || !KEY.test(action.key)) fail(`${at}: actions[${index}]: key is 1 to 48 lowercase letters, digits and hyphens, starting with a letter.`);
  if (!Number.isSafeInteger(action.version) || action.version < 1 || action.version > 9999) fail(`${at}: actions[${index}]: version is a whole number from 1 to 9999.`);
  const where = `${at}: ${action.key} v${action.version}`;
  if (typeof action.id !== 'string' || !new RegExp(`^${appId.replace(/-/g, '\\-')}\\.action\\.${action.key.replace(/-/g, '\\-')}\\.v${action.version}\\.[a-f0-9]{24}$`).test(action.id)) {
    fail(`${where}: id is ${appId}.action.${action.key}.v${action.version}.<24 hex characters>.`);
  }
  if (!text(action.name, 100)) fail(`${where}: name is 1 to 100 characters on one line.`);
  if (!text(action.description, 1000)) fail(`${where}: description is 1 to 1,000 characters on one line.`);
  if (!EFFECTS.includes(action.effect)) fail(`${where}: effect is read, write or delete.`);
  const row = definition.groups.find(group => group.id === action.row);
  if (!row) fail(`${where}: row names a row of ${appId}.`);
  if (!shaped(action.hints, ['readOnly', 'destructive', 'idempotent', 'openWorld']) || !Object.values(action.hints).every(value => typeof value === 'boolean')) {
    fail(`${where}: hints is {readOnly, destructive, idempotent, openWorld}, each true or false.`);
  }
  // Inputs and outputs: closed (I3), no credential-shaped input, no secret-named output (R11).
  try { checkSchema(action.inputSchema, '$input'); } catch (error) { fail(`${where}: inputSchema: ${error.message}`); }
  if (action.inputSchema.type !== 'object') fail(`${where}: inputSchema is a closed object schema.`);
  credentialInputs(action.inputSchema, '$input', where);
  try { checkSchema(action.outputSchema, '$output'); } catch (error) { fail(`${where}: outputSchema: ${error.message}`); }
  if (action.outputSchema.type !== 'object') fail(`${where}: outputSchema is a closed object schema.`);
  secretOutputs(action.outputSchema, '$output', where);
  if (!record(action.output) || Object.keys(action.output).sort().join() !== Object.keys(action.outputSchema.properties).sort().join()) {
    fail(`${where}: output names exactly the properties of outputSchema: ${listWords(Object.keys(action.outputSchema.properties))}.`);
  }
  // A read changes nothing, so it has nothing to read back or record; a write is read back (spec line 748).
  if (action.effect === 'read' && action.verify !== undefined) fail(`${where}: a read action has no verify block: nothing changed to read back.`);
  if (action.effect === 'read' && action.records !== undefined) fail(`${where}: a read action makes nothing, so it records nothing.`);
  if (action.effect !== 'read' && action.verify === undefined) fail(`${where}: a write needs a verify block with an identity (spec line 748).`);
  if (action.verify !== undefined) {
    if (!shaped(action.verify, ['requests', 'identity', 'assert'])) fail(`${where}: verify is {requests, identity, assert}.`);
    if (!Array.isArray(action.verify.requests) || !action.verify.requests.length) fail(`${where}: verify.requests holds the read steps that read a write back (spec line 748).`);
    if (!Array.isArray(action.verify.identity) || !action.verify.identity.length || action.verify.identity.length > 4) fail(`${where}: verify.identity names 1 to 4 identities: a write is read back by what it is (spec line 748).`);
    if (!Array.isArray(action.verify.assert) || action.verify.assert.length > 16) fail(`${where}: verify.assert holds at most 16 assertions.`);
  }
  for (const [field, words] of [['guards', 'guards'], ['prepare', 'prepare steps'], ['perform', 'perform steps'], ['preview', 'preview lines']]) {
    if (!Array.isArray(action[field])) fail(`${where}: ${field} is a list of ${words}.`);
  }
  if (!action.perform.length) fail(`${where}: perform holds at least one step.`);
  if (!Array.isArray(action.definitive) || !action.definitive.every(code => DEFINITIVE_CODES.includes(code)) || new Set(action.definitive).size !== action.definitive.length) {
    fail(`${where}: definitive lists distinct codes of DEFINITIVE_CODES, client errors that mean nothing changed (spec line 752).`);
  }
  const state = new ActionState(action, where, ctx);
  state.steps();
  state.paths();
  state.guards();
  state.output();
  state.poll();
  state.preview();
  state.verification();
  state.declared(row);
  state.choices();
  state.inputsUsed();
  state.pinned();
  return state.entry();
}

/**
 * The checks of one action, in order: its steps (schema steps, choice lookups, prepare, perform, then verify requests, each read,
 * placed and recorded), its paths (R4), its guards, output, poll block, preview and verification, its declared fields, its choices, the
 * inputs it uses and the pins of the transforms it names; then its id and definition hash. One node budget serves every expression of
 * the action (I7). Exported for lib/triggers.mjs (part k), which checks a trigger's poll, seed and enrich steps and its cursors with the
 * same step rules (phases poll, seed and enrich).
 */
export class ActionState {
  constructor(action, where, ctx) {
    Object.assign(this, {action, where, ctx, budget: newBudget(), seen: new Map(), placements: [], used: [], transforms: new Set(), lookups: {}, rawAt: {}, calls: [],
      stepsOf: new Map(), sent: new Set(), prepareSnapshots: new Map(), resolving: [], overOf: new Map(), outputFacts: new Map(), pollSlots: [], pollTransforms: new Set()});
    this.resolvedInputs = (action.resolvedInputs ?? []).map(entry => entry?.input);
    const poll = record(action.poll) ? action.poll : null;
    this.pollStep = action.effect === 'read' && typeof poll?.step === 'string' ? poll.step : null;
    this.cursors = Array.isArray(poll?.cursors) ? poll.cursors.filter(record).map(cursor => cursor.name).filter(name => typeof name === 'string') : [];
  }
  scope(slot, where, extra = {}) {
    const {ctx, action} = this;
    return {where, slot, transforms: ctx.transforms, inputSchema: action.inputSchema, resolvedInputs: this.resolvedInputs, identity: ctx.identity?.identity ?? null,
      steps: new Map(this.seen), budget: this.budget, ...extra};
  }
  /** Records a fact: its transforms, every transform call in it (part i's exclusions read them), and its inputs as used when `uses` is true. */
  note(result, uses) {
    for (const id of result.transforms) this.transforms.add(id);
    if (uses) for (const pointer of result.inputs) this.used.push(pointer);
    for (const node of walk(result)) if (node.kind === 'transform') this.calls.push(node);
    return result;
  }
  expr(node, slot, where, {uses = false, ...extra} = {}) { return this.note(checkExpression(node, this.scope(slot, where, extra)), uses); }
  test(node, slot, where, {uses = false, ...extra} = {}) { return this.note(checkTest(node, this.scope(slot, where, extra)), uses); }

  // ---- steps -----------------------------------------------------------------------------------------------------------------------
  steps() {
    const {action, where} = this, declared = [];
    if (action.resolvedInputs !== undefined) {
      if (!Array.isArray(action.resolvedInputs) || action.resolvedInputs.length > 4) fail(`${where}: resolvedInputs holds at most 4 inputs.`);
      action.resolvedInputs.forEach((entry, index) => {
        if (!shaped(entry, ['input', 'dependsOn', 'schema', 'maxProperties']) || !shaped(entry.schema, ['steps', 'derive']) || !Array.isArray(entry.schema.steps) || !entry.schema.steps.length || entry.schema.steps.length > 2
          || !Object.hasOwn(action.inputSchema.properties, entry.input)) {
          fail(`${where}: resolvedInputs[${index}] is {input, dependsOn, schema: {steps, derive}, maxProperties}, for a declared input, with 1 or 2 schema steps (section 9).`);
        }
        entry.schema.steps.forEach((step, position) => declared.push({step, phase: 'schema', label: `resolvedInputs[${index}].schema.steps[${position}]`}));
      });
    }
    const lookups = this.lookupSteps();
    if (action.resolvedInputs !== undefined) this.resolvedRules();
    for (const [phase, list, label] of [['prepare', action.prepare, 'prepare'], ['perform', action.perform, 'perform'], ['verify', action.verify?.requests ?? [], 'verify.requests']]) {
      list.forEach((step, position) => declared.push({step, phase, label: `${label}[${position}]`}));
    }
    this.pairing(declared);
    const total = declared.length + lookups.length;
    if (total > BOUNDS.steps) fail(`${this.where}: declares ${total} steps; an action holds at most 8, counting schema steps and choice lookups (I7).`);
    for (const lookup of lookups) this.placeLookup(lookup);
    const ids = new Set();
    for (const item of declared) {
      const id = item.step?.id;
      if (typeof id !== 'string' || !STEP_ID.test(id)) fail(`${this.where}: ${item.label}: a step id is 1 to 32 letters and digits, starting with a lowercase letter.`);
      if (ids.has(id)) fail(`${this.where}: ${item.label}: the step id ${id} is used twice.`);
      ids.add(id);
    }
    // Schema steps first, each resolved input's derive right after its own steps, then prepare, perform and verify.
    let derived = 0;
    for (const item of declared) {
      this.step(item);
      if (item.phase === 'schema') {
        const entry = action.resolvedInputs.find(candidate => candidate.schema.steps.at(-1) === item.step);
        if (entry) this.derive(entry, derived++);
      }
    }
  }
  derive(entry, index) {
    const derive = entry.schema.derive, label = `${this.where}: resolvedInputs[${index}].schema.derive`;
    if (!shaped(derive, ['transform', 'args'])) fail(`${label} is {transform, args}.`);
    const result = this.note(checkCall(derive.transform, derive.args, this.scope('guard', label), ['schema']), false);
    // Part j: the derived schema is the resource's own, built from this input's schema steps (part d requires the step-data argument)
    // and nothing an agent or another read chose.
    const own = entry.schema.steps.map(step => step.id);
    const foreign = [...[...result.steps].filter(id => !own.includes(id)), ...[...result.sources].filter(source => source !== 'schema' && source !== 'constant')];
    if (foreign.length) fail(`${label} reads only constants and its own schema steps (${listWords(own)}), so its schema is the resource's: it reads ${listWords(foreign)}.`);
  }
  /**
   * Part j (section 9; R14): each resource-dependent input is listed once, is exactly the empty closed object in inputSchema (its fields
   * come from the resource at run time, I3), depends on 1 to 3 required inputs of its own action that are not resource-dependent
   * themselves, holds at most maxProperties (1 to 100) derived properties, and is read by schema steps that run once.
   */
  resolvedRules() {
    const {action, where} = this, properties = action.inputSchema.properties, required = action.inputSchema.required ?? [], listed = new Set();
    action.resolvedInputs.forEach((entry, index) => {
      const at = `${where}: resolvedInputs[${index}]`;
      if (listed.has(entry.input)) fail(`${at}: ${entry.input} is listed twice.`);
      listed.add(entry.input);
      if (canonical(properties[entry.input]) !== canonical(PLACEHOLDER)) {
        fail(`${at}: ${entry.input} is a resource-dependent input, so inputSchema declares it exactly as {type: 'object', properties: {}, additionalProperties: false}: its fields come from the resource at run time (section 9, I3).`);
      }
      const depends = entry.dependsOn;
      if (!Array.isArray(depends) || !depends.length || depends.length > 3 || new Set(depends).size !== depends.length || !depends.every(name => typeof name === 'string' && name !== entry.input && Object.hasOwn(properties, name))) {
        fail(`${at}.dependsOn names 1 to 3 distinct declared inputs other than ${entry.input}.`);
      }
      for (const name of depends) {
        if (this.resolvedInputs.includes(name)) fail(`${at}: ${entry.input} depends on ${name}, another resource-dependent input: none depends on another (section 9).`);
        if (!required.includes(name)) fail(`${at}: ${entry.input} depends on ${name}, which is optional: the resource it names is required (section 9).`);
      }
      if (!Number.isSafeInteger(entry.maxProperties) || entry.maxProperties < 1 || entry.maxProperties > 100) fail(`${at}.maxProperties is 1 to 100.`);
      entry.schema.steps.forEach((step, position) => {
        if (record(step) && step.forEach !== undefined) fail(`${at}.schema.steps[${position}] (${step.id}): a schema step runs once: no forEach (section 9).`);
      });
    });
  }
  /**
   * Part j: a schema step reads only constants, the account, the inputs its entry depends on and its own earlier schema steps, so the
   * resolved schema hash's resource names everything the read was built from, and the read runs again with the same bytes at dispatch.
   */
  schemaSlots(step, where, slots) {
    const entry = this.action.resolvedInputs.find(item => item.schema.steps.includes(step)), own = entry.schema.steps.map(item => item.id);
    for (const [name, result] of slots) {
      const inputs = [...result.inputs].filter(pointer => !entry.dependsOn.some(input => pointer === `/${input}` || pointer.startsWith(`/${input}/`)));
      if (inputs.length || [...result.sources].some(source => !SCHEMA_STEP_SOURCES.has(source)) || [...result.steps].some(id => !own.includes(id))) {
        fail(`${where}.${name}: a schema step reads only constants, the account, the inputs ${entry.input} depends on (${listWords(entry.dependsOn)}) and its own earlier schema steps (section 9).`);
      }
    }
  }
  /** R12: each choice with a lookup is a get-by-id read of a choice source, run as a prepare step on the owner's account. */
  lookupSteps() {
    const {action, where, ctx} = this;
    if (action.choices === undefined) return [];
    if (!Array.isArray(action.choices) || action.choices.length > 32) fail(`${where}: choices holds at most 32 entries (section 9).`);
    const out = [];
    action.choices.forEach((choice, index) => {
      if (!shaped(choice, ['input', 'source'], ['dependsOn', 'args', 'lookup']) || !Object.hasOwn(action.inputSchema.properties, choice.input)) {
        fail(`${where}: choices[${index}] is {input, source} for a declared input and may hold dependsOn, args and lookup (section 9).`);
      }
      if (choice.lookup === undefined) return;
      const source = ctx.sources.find(candidate => record(candidate) && candidate.id === choice.lookup && candidate.kind === 'lookup');
      if (!source || !record(source.read)) fail(`${where}: choices[${index}] names the lookup source ${choice.lookup}, which ${ctx.appId}'s choice sources do not hold as a lookup (R12).`);
      out.push({input: choice.input, source});
    });
    return out;
  }
  placeLookup({input, source}) {
    const {ctx} = this, label = `${this.where}: the lookup of ${input}`, stepId = `choice:${input}`;
    let method = null, path = null;
    const request = source.read.request;
    if (typeof request === 'string') { const space = request.indexOf(' '); method = request.slice(0, space); path = request.slice(space + 1); }
    else {
      const operation = Array.isArray(ctx.map?.operations) ? ctx.map.operations.find(entry => entry?.id === source.read.operation) : undefined;
      if (operation) ({method, path} = operation);
    }
    // F10.10 (open question 6): a lookup sends only its source's constant arguments, the choice's closed input value and configured values
    // (lib/choice-sources.mjs), so it is built from reads, and a lookup on a reviewed-read POST places as a read. Choice-source loading
    // keeps its own reviewedReads check.
    const placement = method === null
      ? Object.freeze({stepId, phase: 'lookup', method: null, template: null, member: null, groupId: null, rowEffect: null, effect: null, fromReads: false, reviewedRead: false, routedFrom: null, unplaced: true})
      : placeStep({id: stepId, method, path}, {definition: ctx.definition, config: ctx.config, map: ctx.map, phase: 'lookup', fromReads: true, where: label});
    if (!placement.unplaced && (placement.effect !== 'read' || placement.groupId !== source.row)) fail(`${label}: a lookup is a read in its source's row ${source.row}, and it lands in ${placement.groupId} with effect ${placement.effect} (R12).`);
    this.placements.push(placement);
    this.stepsOf.set(stepId, {step: {id: stepId, method, path, maxResponseBytes: BOUNDS.responseBytes}, phase: 'lookup', placement});
    this.lookups[input] = deepFreeze({source: source.id, method, template: source.read.request ?? null, operation: source.read.operation ?? null, row: source.row,
      args: structuredClone(source.args ?? {}), items: source.items, value: source.value, label: structuredClone(source.label)});
  }

  /** One step: its shape, its expressions at each slot, its placement, and what later expressions may read of it. */
  step({step, phase, label}) {
    const {action, ctx} = this, where = `${this.where}: ${label} (${step.id})`;
    if (!shaped(step, ['id', 'method', 'path', 'expect'], STEP_FIELDS)) fail(`${where}: a step holds id, method, path and expect, and may hold ${listWords(STEP_FIELDS)}.`);
    const perform = phase === 'perform';
    if (step.resolves !== undefined && !perform) fail(`${where}: resolves marks only a perform step (R2).`);
    if (step.bindContent !== undefined && !perform) fail(`${where}: bindContent is only on a perform step.`);
    if (step.maxResponseBytes !== undefined && (!Number.isSafeInteger(step.maxResponseBytes) || step.maxResponseBytes < 1 || step.maxResponseBytes > BOUNDS.responseBytes)) {
      fail(`${where}: maxResponseBytes is 1 to 2,097,152.`);
    }
    if (step.forEach !== undefined && step.page !== undefined) fail(`${where}: a step repeats with forEach or pages, never both, so its data is one list (open point Important 5).`);
    // Expressions, each at its slot, seeing the steps before this one. A forEach element is {item} in every slot of the step.
    const slots = [];
    let item = null;
    if (step.forEach !== undefined) {
      if (!shaped(step.forEach, ['over', 'max']) || !Number.isSafeInteger(step.forEach.max) || step.forEach.max < 1 || step.forEach.max > BOUNDS.forEach) fail(`${where}: forEach is {over, max}, with a max of 1 to 25 (I7).`);
      const over = this.expr(step.forEach.over, 'forEach', `${where}.forEach.over`, {uses: true});
      if (over.type !== null && over.type.type !== 'array') fail(`${where}.forEach.over: forEach walks a list.`);
      slots.push(['forEach.over', over]);
      this.overOf.set(step.id, over);
      item = {from: 'forEach', list: over};
    }
    const cursors = this.pollStep === step.id ? this.cursors : [];
    const extra = {uses: true, item, cursors};
    this.parameters(step, where, slots, extra);
    const query = record(step.query) ? step.query : step.query === undefined ? {} : fail(`${where}: query maps names to expressions.`);
    for (const [name, node] of Object.entries(query)) {
      if (!QUERY_NAME.test(name)) fail(`${where}.query: query names are 1 to 128 letters, digits and _ . ~ : [ ] -.`);
      if (reservedQueryName(name, ctx.config)) fail(`${where}.query.${name}: ${name} is a reserved query name: an action step never sends it (spec line 740).`);
      const result = this.expr(node, 'query', `${where}.query.${name}`, extra);
      this.queryValue(result, name, `${where}.query.${name}`);
      slots.push([`query.${name}`, result]);
    }
    const headers = record(step.headers) ? step.headers : step.headers === undefined ? {} : fail(`${where}: headers maps names to expressions.`);
    for (const [name, node] of Object.entries(headers)) slots.push([`headers.${name}`, this.header(name, node, `${where}.headers.${name}`, extra)]);
    let body = null;
    if (step.body !== undefined) {
      body = this.expr(step.body, 'body', `${where}.body`, extra);
      if (body.raw) fail(`${where}.body: a body is built in the file or by a transform, never a raw step-data value (I6, T4).`);
      this.bodyKeys(body, `${where}.body`);
      slots.push(['body', body]);
    }
    if (step.when !== undefined) slots.push(['when', this.test(step.when, 'when', `${where}.when`, extra)]);
    if (step.requiresScope !== undefined) {
      if (!shaped(step.requiresScope, ['scope', 'when']) || typeof step.requiresScope.scope !== 'string') fail(`${where}.requiresScope is {scope, when}.`);
      slots.push(['requiresScope.when', this.test(step.requiresScope.when, 'when', `${where}.requiresScope.when`, extra)]);
    }
    this.page(step, where, body);
    this.expect(step.expect, `${where}.expect`, {item});
    // F10.10 (I5): every slot that decides what the step sends, or whether and how often it runs, reads only constants, closed inputs,
    // the account, the clock, a resolved schema, a poll cursor and earlier steps that are themselves reads built from reads. Only then
    // may a reviewed-read POST count as a read (lib/action-placement.mjs stepEffect()).
    const fromReads = slots.every(([, fact]) => readsOnly(fact, id => this.stepsOf.get(id)?.fromReads === true));
    // Placement (part e), then the phase's own rules.
    const placement = placeStep(step, {definition: ctx.definition, config: ctx.config, map: ctx.map, phase, body, access: ctx.access, fromReads, where});
    this.placements.push(placement);
    const effect = placement.unplaced ? methodEffect(step.method) : placement.effect;
    if ((phase === 'prepare' || phase === 'schema') && effect !== 'read') fail(`${where}: a ${phase} step is a read (spec line 711), and ${step.method} ${step.path} is a ${effect === 'delete' ? 'delete' : 'write'}.`);
    if (TRIGGER_PHASES.includes(phase) && effect !== 'read') fail(`${where}: ${an(phase)} ${phase} step's computed effect is ${effect}: a trigger polls with reads only, and a reviewed-read POST is a read only when everything it sends is built from reads (F10.10, I5).`);
    // A step's effect is never weaker than its row's (lib/action-placement.mjs stepEffect()), so a read sits in a read row.
    if (phase === 'verify' && effect !== 'read') fail(`${where}: a verify request is a read in a read row (spec line 748).`);
    if (step.page !== undefined && effect !== 'read') fail(`${where}: page is only on a read step, and ${step.method} ${step.path} is a write.`);
    if (record(step.page?.into) && typeof step.page.into.body === 'string' && !placement.unplaced) this.pageRoutes(step.page.into.body, `${where}.page.into`, placement);
    if (perform) this.performRules(step, where, slots, placement, body);
    if (step.requiresScope !== undefined && !placement.unplaced) {
      const scopes = this.rowOf(placement)?.conditionalScopes ?? {};
      if (!Object.hasOwn(scopes, step.requiresScope.scope)) fail(`${where}.requiresScope: requiresScope names ${step.requiresScope.scope}, which is not a conditional scope of ${this.rowOf(placement).id}.`);
    }
    if (phase === 'schema') this.schemaSlots(step, where, slots);
    this.rawAt[step.id] = Object.freeze(this.rawPositions(slots, step));
    if (step.id === this.pollStep) this.pollSlots = slots;
    if (phase === 'perform') for (const node of [...Object.values(record(step.params) ? step.params : {}), ...Object.values(record(step.query) ? step.query : {}), step.body]) sentNodes(node, this.sent);
    const source = phase === 'schema' ? 'schema' : phase === 'prepare' ? 'prepare' : phase === 'verify' ? 'verify' : step.resolves === true ? 'resolving' : effect === 'read' ? 'perform-read' : 'perform-write';
    const once = step.forEach === undefined || (slots[0]?.[1].type?.minItems ?? 0) >= 1;
    this.seen.set(step.id, {source, skippable: step.optional === true || step.fallbackFor !== undefined || step.when !== undefined || !once});
    // F10.10: a step's answer is built from reads only when the step is itself a read built from reads.
    this.stepsOf.set(step.id, {step, phase, placement, effect, fromReads: fromReads && effect === 'read', label: where});
    if (phase === 'prepare') this.prepareSnapshots.set(step.id, new Map(this.seen));
    this.successRule(step.expect, `${where}.expect`);
  }
  rowOf(placement) { return this.ctx.definition.groups.find(group => group.id === (placement.routedFrom?.groupId ?? placement.groupId)); }

  /** Spec line 740: every path parameter is filled exactly once, by params or pinnedParameters; a pinned name never by a step. */
  parameters(step, where, slots, extra) {
    const {ctx} = this;
    let parsed;
    try { parsed = parseTemplate(`${step.method} ${step.path}`); } catch { return; }
    const names = parsed.segments.filter(segment => segment.kind !== 'literal').map(segment => segment.name);
    const params = step.params === undefined ? {} : record(step.params) ? step.params : fail(`${where}: params maps path parameters to expressions.`);
    for (const name of Object.keys(params)) {
      if (Object.hasOwn(ctx.file.pinnedParameters, name)) fail(`${where}.params.${name}: ${name} is a pinned parameter, filled only by pinnedParameters, never by a step (spec line 740).`);
      if (!names.includes(name)) fail(`${where}.params.${name} names no parameter of ${step.method} ${step.path}.`);
    }
    for (const name of names) {
      if (!Object.hasOwn(params, name) && !Object.hasOwn(ctx.file.pinnedParameters, name)) fail(`${where}: the path parameter ${name} is filled neither by params nor by pinnedParameters.`);
    }
    for (const [name, node] of Object.entries(params)) {
      const result = this.expr(node, 'path', `${where}.params.${name}`, extra);
      if (result.type !== null && !SCALARS.has(result.type.type)) fail(`${where}.params.${name}: a path parameter is one string, number or boolean.`);
      if (reservedQueryName(name, ctx.config) && result.sources.has('input')) fail(`${where}.params.${name}: ${name} is reserved: it never comes from an input (spec line 740).`);
      slots.push([`params.${name}`, result]);
    }
  }
  queryValue(result, name, where) {
    const type = result.type, list = this.ctx.config.arrayParameters ?? [];
    if (type === null || SCALARS.has(type.type)) return;
    if (type.type === 'array' && list.includes(name) && (type.items === null || type.items === undefined || SCALARS.has(type.items.type))) return;
    fail(`${where}: a query value is a string, a number, a boolean or, for one of the app's array parameters (${list.join(', ') || 'none'}), a list of them.`);
  }
  /** Spec line 741: only the caller headers, each from its own sources. Part d already keeps inputs, the account and perform data out. */
  header(name, node, where, extra) {
    if (FABRIC_HEADERS.includes(name)) fail(`${where}: ${name} is never a step header: Fabric sends it itself, or it carries a credential.`);
    if (!CALLER_HEADERS.includes(name)) fail(`${where}: ${name} is not a header an action step sends: only ${listWords(CALLER_HEADERS)}.`);
    const result = this.expr(node, 'header', where, extra), accept = this.ctx.config.acceptTypes ?? [];
    if (name === 'Accept' && !(result.kind === 'const' && accept.includes(result.value))) fail(`${where}: Accept is one of the app's accept types: ${accept.join(', ')}.`);
    if ((name === 'If-Match' || name === 'If-Unmodified-Since') && [...result.sources].some(source => source !== 'prepare')) fail(`${where}: ${name} comes only from a prepare step's answer.`);
    if ((name === 'If-None-Match' || name === 'If-Modified-Since') && [...result.sources].some(source => source !== 'prepare' && source !== 'cursor')) fail(`${where}: ${name} comes only from a prepare step's answer or a poll cursor.`);
    if (result.type !== null && !SCALARS.has(result.type.type)) fail(`${where}: a header value is one string.`);
    return result;
  }
  /** Spec line 751 and the proxy's reserved body fields: keys an action body never writes, at any depth; Notion's /properties rule. */
  bodyKeys(body, where) {
    const {appId, config} = this.ctx, notion = appId === NOTION_APP;
    const reserved = new Set([...(config.reservedBodyFields ?? []), ...(notion ? NOTION_RESERVED : [])]);
    // One key written in the file: `value` is the constant there, or undefined when the run time fills it.
    const key = (name, value, at) => {
      if (notion && name === 'in_trash') { if (value !== false) fail(`${at}.in_trash: in_trash is only the constant false (spec line 751).`); }
      else if (reserved.has(name)) fail(`${at}.${name}: the body writes ${name}, a field ${appId} reserves: an action body never writes it, at any depth (spec line 751).`);
    };
    const constant = (value, at) => {
      if (Array.isArray(value)) value.forEach((item, index) => constant(item, `${at}[${index}]`));
      else if (record(value)) for (const [name, item] of Object.entries(value)) { key(name, item, at); constant(item, `${at}.${name}`); }
    };
    const visit = (result, at) => {
      if (result.kind === 'const') return constant(result.value, at);
      if (result.kind === 'object') for (const [name, member] of result.members) { key(name, member.kind === 'const' ? member.value : undefined, at); visit(member, `${at}.${name}`); }
      for (const [index, item] of (result.kind === 'array' ? result.items : []).entries()) visit(item, `${at}[${index}]`);
      if (result.kind === 'each') visit(result.do, `${at}.do`);
      if (result.kind === 'when') visit(result.then, at);
      if (result.kind === 'either') for (const branch of result.branches) visit(branch, at);
    };
    visit(body, where);
    if (!notion) return;
    // Open question 10 and open point Important 8: the keys under /properties are never chosen by a caller, on every branch of the body.
    const roots = [], rootsOf = result => { if (result.kind === 'either') result.branches.forEach(rootsOf); else if (result.kind === 'when') rootsOf(result.then); else roots.push(result); };
    rootsOf(body);
    for (const root of roots) {
      const properties = root.kind === 'object' ? root.members.get('properties') : root.kind === 'const' && record(root.value) && Object.hasOwn(root.value, 'properties') ? root : undefined;
      if (properties === undefined) continue;
      const values = properties.kind === 'transform' && properties.transform === NOTION_VALUES;
      const title = properties.kind === 'object' && properties.members.size === 1 && properties.members.has('title')
        && properties.members.get('title').kind !== 'const' && properties.members.get('title').transforms.has(NOTION_TITLE_FROM) && !properties.members.get('title').raw;
      if (!values && !title) fail(`${where}.properties: Notion's /properties takes only ${NOTION_VALUES}'s whole result, or the one constant key title built from ${NOTION_TITLE_FROM} (open question 10, open point Important 8).`);
    }
  }
  /**
   * Open point Important 5: a paged read names the list each page holds; its data is the pages' lists joined. F10.10 made a paged POST
   * reachable (a reviewed read built from reads), so the provider's next cursor goes into the body only at a field the step itself never
   * writes, never at a field the app reserves and never as the whole body; pageRoutes() keeps it off the member's body routes, and
   * rawPositions() holds it to a scalar at run time.
   */
  page(step, where, body = null) {
    if (step.page === undefined) return;
    const page = step.page;
    if (!shaped(page, ['next', 'into', 'items', 'max'], ['while']) || !Number.isSafeInteger(page.max) || page.max < 1 || page.max > BOUNDS.pages) {
      fail(`${where}: page is {next, into, items, max} and may hold while, with a max of 1 to 10 (I7).`);
    }
    if (shaped(page.next, ['pointer'])) checkPointer(page.next.pointer, `${where}.page.next`);
    else if (shaped(page.next, ['link', 'param']) && page.next.link === 'next' && typeof page.next.param === 'string' && QUERY_NAME.test(page.next.param)) {
      if (!this.ctx.transforms.has(LINK_PAGES)) fail(`${where}.page.next: Link paging reads the next page through ${LINK_PAGES}, which the registry does not hold.`);
      this.transforms.add(LINK_PAGES);
    } else fail(`${where}.page.next is {pointer} or {link: 'next', param}.`);
    if (shaped(page.into, ['query'])) {
      if (typeof page.into.query !== 'string' || !QUERY_NAME.test(page.into.query)) fail(`${where}.page.into: query names are 1 to 128 letters, digits and _ . ~ : [ ] -.`);
      if (reservedQueryName(page.into.query, this.ctx.config)) fail(`${where}.page.into: ${page.into.query} is a reserved query name: an action step never sends it (spec line 740).`);
      if (record(step.query) && Object.hasOwn(step.query, page.into.query)) fail(`${where}.page.into: the step already sends ${page.into.query}.`);
    } else if (shaped(page.into, ['body'])) this.pageBody(step, page.into.body, `${where}.page.into`, body);
    else fail(`${where}.page.into is {query} or {body}.`);
    checkPointer(page.items, `${where}.page.items`);
    if (page.while !== undefined) checkPointer(page.while, `${where}.page.while`);
  }
  /** F10.10: where a paged step's body takes the provider's next cursor. The words of the reserved rule are choice sources' own. */
  pageBody(step, pointer, where, body) {
    const tokens = checkPointer(pointer, where), {appId, config} = this.ctx;
    if (step.method === 'GET') fail(`${where}: a GET has no body: it pages into the query.`);
    const reserved = [...(config.reservedBodyFields ?? []), ...(appId === NOTION_APP ? [...NOTION_RESERVED, 'in_trash'] : [])];
    if (!tokens.length || tokens.some(token => reserved.includes(token))) fail(`${where}: ${pointer} names a body field the app reserves, or the body itself.`);
    const keys = body ? this.topKeys(body) : new Set();
    if (keys === null) fail(`${where}: ${pointer} takes a field of the body, so the body is an object whose keys are known on every branch: built in the file, or a whole input or transform result of a closed object schema (F10.10).`);
    if (keys.has(tokens[0])) fail(`${where}: ${pointer} lands on ${tokens[0]}, a key the step's body writes: the provider's next cursor never replaces what the step sends (F10.10).`);
  }
  /**
   * The keys a body writes at its top level: an object's members, a constant object's keys, the properties a closed object schema names
   * for a whole input or a transform result (F10.10 check), and those of every branch of an {either}. Null when a branch is not an object
   * whose keys are known (a scalar, a list, an outputFrom or outputMap result), so the provider's next cursor has no field of its own
   * there. A {when} never sits at the top of a body.
   */
  topKeys(result, out = new Set()) {
    if (result.kind === 'either') return result.branches.every(branch => this.topKeys(branch, out) !== null) ? out : null;
    let keys = null;
    if (result.kind === 'object') keys = [...result.members.keys()];
    else if (result.kind === 'const') keys = record(result.value) ? Object.keys(result.value) : null;
    else if (result.type?.type === 'object' && result.type.additionalProperties === false && record(result.type.properties)) keys = Object.keys(result.type.properties);
    if (keys === null) return null;
    for (const key of keys) out.add(key);
    return out;
  }
  /** F10.10 (spec line 738): the cursor sits on, above or below no body-route pointer of the step's member, so a value the provider
   *  sends back never decides the row a request lands in. Placement knows the member, so this runs after it. */
  pageRoutes(pointer, where, placement) {
    const row = this.rowOf(placement), tokens = tokensOf(pointer);
    for (const route of (row.bodyRoutes ?? []).filter(item => memberKey(item.member) === memberKey(placement.member))) {
      const other = tokensOf(route.pointer), shared = Math.min(tokens.length, other.length);
      if (tokens.slice(0, shared).every((token, index) => token === other[index])) {
        fail(`${where}: ${pointer} sits on, above or below ${route.pointer}, which ${row.id} routes to ${route.to}: the provider's next cursor never decides where a step lands (spec line 738).`);
      }
    }
  }
  expect(expect, where, extra) {
    if (!shaped(expect, ['status', 'require'])) fail(`${where} is {status, require}.`);
    if (!codes(expect.status)) fail(`${where}.status holds 1 to 16 HTTP status codes.`);
    if (!Array.isArray(expect.require) || expect.require.length > 8) fail(`${where}.require holds at most 8 assertions.`);
    expect.require.forEach((assertion, index) => {
      if (record(assertion) && Object.hasOwn(assertion, 'step')) fail(`${where}.require[${index}]: expect.require reads the step's own answer: its assertions name no step.`);
      this.assertion(assertion, `${where}.require[${index}]`, {own: true, extra});
    });
  }

  /**
   * F10.21 (lib/api-success.mjs): on an app whose reviewed sign-in sets apiSuccessRequire (Slack answers its errors inside a 2xx), every step
   * requires each fact at the top of expect.require, or as the first branch of a top-level anyOf whose other branches each test /error
   * against a constant (a reviewed alternative such as already_reacted). The runtime holds the rule too, so this is the reviewer's view of it.
   */
  successRule(expect, where) {
    const facts = this.ctx.identity?.apiSuccessRequire;
    if (!Array.isArray(facts) || !facts.length) return;
    const nodes = facts.map(({pointer, equals}) => canonical({equals: {pointer, value: {const: equals}}})), require = Array.isArray(expect?.require) ? expect.require : [];
    const errorBranch = branch => shaped(branch, ['equals']) && shaped(branch.equals, ['pointer', 'value']) && branch.equals.pointer === '/error' && shaped(branch.equals.value, ['const'])
      && typeof branch.equals.value.const === 'string';
    const words = `${where}.require: ${this.ctx.appId} answers its errors inside a 2xx, so every step requires ${facts.map(({pointer, equals}) => `${pointer} to be ${JSON.stringify(equals)}`).join(' and ')}: `
      + 'at the top of expect.require, or as the first branch of an anyOf whose other branches each test /error against a constant (F10.21).';
    const leads = node => record(node) && Array.isArray(node.anyOf) && node.anyOf.length > 0 && nodes.includes(canonical(node.anyOf[0]));
    if (require.some(node => leads(node) && !node.anyOf.slice(1).every(errorBranch))) fail(words);
    if (!nodes.every(fact => require.some(node => canonical(node) === fact || (leads(node) && canonical(node.anyOf[0]) === fact)))) fail(words);
  }
  /** T5 and R2: a perform step's bytes read only PERFORM_SOURCES; then the resolving rules, content binding and the sender. */
  performRules(step, where, slots, placement, body) {
    const failed = slots.filter(([, result]) => { try { assertPerformSources(result, 'x'); return false; } catch { return true; } });
    if (failed.length) {
      const names = failed.map(([name]) => name);
      assertPerformSources(failed[0][1], `${where}: ${names.length > 1 ? `each of ${listWords(names)}` : names[0]}`);
    }
    if (step.resolves === true) {
      if (this.resolving.length) fail(`${where}: an action holds at most one resolving step (R2).`);
      if (step.forEach !== undefined || step.page !== undefined) fail(`${where}: a resolving step carries no forEach or page (R2).`);
      if (!step.expect.require.length) fail(`${where}: a resolving step's expect requires the resolved value, so its answer is checked before a later step reads it (R2).`);
      this.resolving.push(step.id);
    }
    this.binding(step, where, placement, body, slots);
    for (const [, result] of slots) this.sender(result, where);
  }
  /** Spec line 749 (T5): a write on a bound member carries exactly the etag, sha or content a prepare step read. */
  binding(step, where, placement, body, slots) {
    if (placement.unplaced) return;
    const row = this.rowOf(placement), bind = memberData(row, placement.member).bindContent;
    if (!bind) {
      if (step.bindContent !== undefined) fail(`${where}: bindContent on a member its row does not list (spec line 749).`);
      return;
    }
    if (step.bindContent !== bind.kind) fail(`${where}: its member is listed in ${row.id}'s bindContent, so the step declares bindContent: '${bind.kind}' (spec line 749, T5).`);
    let value;
    if (bind.at === 'header:If-Match') value = slots.find(([name]) => name === 'headers.If-Match')?.[1];
    else {
      value = body;
      for (const token of checkPointer(bind.at.slice(5), `${where}.bindContent`)) value = value?.kind === 'object' ? value.members.get(token) : undefined;
    }
    const prepared = result => result !== undefined && ((result.kind === 'step' && this.seen.get(result.step)?.source === 'prepare'
      && (bind.kind === 'etag' ? result.header === 'etag' || /\/etag$/.test(result.pointer ?? '') : result.pointer !== undefined))
      || (result.kind === 'item' && result.data && result.sources.size === 1 && result.sources.has('prepare')));
    const sha = bind.kind === 'sha' && value?.kind === 'when' && value.test.kind === 'present' && prepared(value.then) && canonical(nodeOfStep(value.test.operand)) === canonical(nodeOfStep(value.then));
    if (!prepared(value) && !sha) fail(`${where}: bindContent ${bind.kind} puts at ${bind.at} exactly what a prepare step read, unchanged, and this value is something else (spec line 749, T5).`);
  }
  /** F10.8 open point Minor 5: rfc5322.build@1's from reads only the account's address or the prepared profile, through object and pick. */
  sender(result, where) {
    for (const call of walk(result)) {
      if (call.kind !== 'transform' || !Object.hasOwn(SENDER_ARGUMENTS, call.transform)) continue;
      for (const name of SENDER_ARGUMENTS[call.transform]) {
        const argument = call.args.get(name);
        if (argument && !this.senderOnly(argument)) {
          fail(`${where}: ${call.transform}'s ${name} reads only {account: 'email'} or the answer of a prepare step on a member of SENDER_SOURCES, through object and pick: an agent never chooses the sender (F10.8 open point Minor 5).`);
        }
      }
    }
  }
  senderOnly(result) {
    if (result.kind === 'account') return result.field === 'email';
    if (result.kind === 'object') return result.members.size > 0 && [...result.members.values()].every(member => this.senderOnly(member));
    if (result.kind === 'pick') return this.senderOnly(result.of);
    if (result.kind !== 'step' || result.pointer === undefined) return false;
    const step = this.stepsOf.get(result.step);
    if (step?.phase !== 'prepare') return false;
    // An unplaced step (an app reviewed by operation id, without its map) is never runnable; the rule is read again once it places.
    return step.placement.unplaced || (SENDER_SOURCES[this.ctx.appId] ?? []).includes(memberKey(step.placement.member));
  }
  /**
   * Open point Important 2: each request position where a raw step-data value sits, which checkRequest() holds to a scalar at run time;
   * each poll cursor's slot (part h), since a cursor's value is a provider value too, so nothing it carries sits below its slot; and, from
   * F10.10, a paged step's body continuation, where the provider's next cursor goes (the query continuation is sent as a string).
   */
  rawPositions(slots, step = null) {
    const out = [];
    const visit = (result, tokens) => {
      if ((result.raw && RAW_KINDS.has(result.kind)) || result.kind === 'cursor') { out.push(pointerOf(tokens)); return; }
      if (result.kind === 'object') for (const [key, member] of result.members) visit(member, [...tokens, key]);
      // An item that can be left out (a {when}, a cursor) moves every item after it, so from there on a position is every element.
      let moved = false;
      if (result.kind === 'array') result.items.forEach((item, index) => { visit(item, [...tokens, moved ? '*' : index]); moved ||= item.optional; });
      if (result.kind === 'each') visit(result.do, [...tokens, '*']);
      if (result.kind === 'when') visit(result.then, tokens);
      if (result.kind === 'either') { for (const branch of result.branches) visit(branch, tokens); }
    };
    for (const [name, result] of slots) {
      const [slot, key] = name.split(/\.(.*)/s);
      if (slot === 'params' || slot === 'query' || slot === 'headers') visit(result, [slot, key]);
      if (slot === 'body') visit(result, ['body']);
    }
    if (typeof step?.page?.into?.body === 'string') out.push(`/body${step.page.into.body}`);
    return [...new Set(out)];
  }
  /** R7: each optional step has exactly one fallback, declared after it; a fallback names an optional step declared before it. */
  pairing(declared) {
    const optional = new Map();
    for (const {step, phase, label} of declared) {
      if (!record(step)) continue;
      if ((step.optional !== undefined || step.fallbackFor !== undefined) && !(phase === 'prepare' || (phase === 'perform' && this.action.effect === 'read'))) {
        fail(`${this.where}: ${label} (${step.id}): optional and fallbackFor mark only a prepare step, or a perform step of a read action (R7).`);
      }
      if (step.optional === true) optional.set(step.id, {label, fallbacks: 0});
      if (step.fallbackFor !== undefined) {
        const target = optional.get(step.fallbackFor);
        if (!target) fail(`${this.where}: ${label} (${step.id}): fallbackFor names ${step.fallbackFor}, which is not an optional step declared before it (R7).`);
        if (++target.fallbacks > 1) fail(`${this.where}: the optional step ${step.fallbackFor} has two fallbacks: each optional step has exactly one (R7).`);
      }
    }
    for (const [id, {label, fallbacks}] of optional) if (!fallbacks) fail(`${this.where}: ${label} (${id}): the optional step ${id} has no fallback: each optional step has exactly one, declared after it (R7).`);
  }

  // ---- paths (R4) and bounds (I7) --------------------------------------------------------------------------------------------------
  /** {input, values} when a when test reads one closed enum input against its values, else null. */
  enumTest(node) {
    const properties = this.action.inputSchema.properties;
    if (!record(node)) return null;
    if (Array.isArray(node.equals) && node.equals.length === 2 && shaped(node.equals[0], ['input']) && typeof node.equals[0].input === 'string') {
      const name = node.equals[0].input.slice(1);
      if (!/^\/[^/~]+$/.test(node.equals[0].input) || !Array.isArray(properties[name]?.enum)) return null;
      return {input: name, values: new Set([node.equals[1].const])};
    }
    if (Array.isArray(node.anyOf)) {
      const parts = node.anyOf.map(part => this.enumTest(part));
      if (!parts.length || parts.some(part => part === null || part.input !== parts[0].input)) return null;
      return {input: parts[0].input, values: new Set(parts.flatMap(part => [...part.values]))};
    }
    return null;
  }
  paths() {
    const {action, where} = this, perform = action.perform, verify = action.verify?.requests ?? [];
    const tests = new Map(perform.map(step => [step.id, step.when === undefined ? null : this.enumTest(step.when)]));
    const inputs = new Set([...tests.values()].filter(Boolean).map(test => test.input));
    if (inputs.size > 1) fail(`${where}: perform steps choose their path by when tests over one closed enum input; these read ${listWords([...inputs])} (R4).`);
    const shapedWhen = (node, label) => {
      if (node === undefined) return null;
      const test = this.enumTest(node);
      if (!test || (inputs.size && !inputs.has(test.input))) fail(`${where}: ${label}.when: a verify request or assertion takes a when only over the closed enum input its perform steps choose by (R4).`);
      inputs.add(test.input);
      return test;
    };
    const verifyTests = new Map(verify.map((step, index) => [step.id, shapedWhen(step.when, `verify.requests[${index}] (${step.id})`)]));
    (action.verify?.assert ?? []).forEach((assertion, index) => shapedWhen(record(assertion) ? assertion.when : undefined, `verify.assert[${index}]`));
    const [input] = inputs, schema = input === undefined ? null : action.inputSchema.properties[input];
    const values = input === undefined ? [null] : [...schema.enum, ...((action.inputSchema.required ?? []).includes(input) ? [] : [null])];
    const holds = (test, value) => test === null || (value !== null && test.values.has(value));
    this.pathList = values.map(value => Object.freeze({input: input ?? null, value: input === undefined ? null : value,
      perform: Object.freeze(perform.filter(step => holds(tests.get(step.id), value)).map(step => step.id)),
      verify: Object.freeze(verify.filter(step => holds(verifyTests.get(step.id), value)).map(step => step.id))}));
    const words = path => path.input === null ? 'on its one path,' : path.value === null ? `on the path where ${path.input} is absent,` : `on the path where ${path.input} is ${path.value},`;
    const which = path => path.input === null ? '' : `${words(path)} `;
    const writes = path => path.perform.some(id => this.stepsOf.get(id).effect !== 'read');
    for (const path of this.pathList) {
      if (path.perform.length > BOUNDS.perform) fail(`${where}: ${words(path)} ${path.perform.length} perform steps can run; at most 3 on any one path (R4).`);
      if (path.verify.length > BOUNDS.verifyPerPath) fail(`${where}: ${words(path)} ${path.verify.length} verify requests can run; a write is read back by 1 or 2 (spec line 748).`);
      if (action.effect !== 'read' && writes(path) && !path.verify.length) fail(`${where}: ${words(path)} no verify request reads back the write: each path with a write is read back by 1 or 2 (spec line 748).`);
    }
    // I7: worst-case requests and response bytes on any path; prepared data in all.
    const times = ({step}) => (step.forEach?.max ?? 1) * (step.page?.max ?? 1);
    const size = item => (item.step.maxResponseBytes ?? BOUNDS.responseBytes) * times(item);
    const before = [...this.stepsOf.values()].filter(item => ['lookup', 'schema', 'prepare'].includes(item.phase));
    const prepared = before.reduce((sum, item) => sum + size(item), 0);
    if (prepared > BOUNDS.preparedBytes) fail(`${where}: prepares ${bytes(prepared)} bytes in the worst case; at most 4 MiB (I7). Declare a smaller maxResponseBytes.`);
    for (const path of this.pathList) {
      const on = [...before, ...[...path.perform, ...path.verify].map(id => this.stepsOf.get(id))];
      const requests = on.reduce((sum, item) => sum + times(item), 0), total = on.reduce((sum, item) => sum + size(item), 0);
      if (requests > BOUNDS.requests) fail(`${where}: ${which(path)}can send ${requests} provider requests in the worst case; at most 64 (I7).`);
      if (total > BOUNDS.jobBytes) fail(`${where}: ${which(path)}can read ${bytes(total)} bytes of responses in the worst case; at most 16 MiB (I7). A step that repeats declares a smaller maxResponseBytes.`);
    }
  }

  // ---- guards, output, preview and verification ----------------------------------------------------------------------------------
  /** Spec line 715 (R16, R20): a guard entry with the action's own code; without after it reads inputs and the account only. */
  guards() {
    this.action.guards.forEach((guard, index) => {
      const where = `${this.where}: guards[${index}]`;
      if (!shaped(guard, ['transform', 'args', 'refuse'], ['after'])) fail(`${where}: a guard is {transform, args, refuse} and may hold after.`);
      if (!Object.hasOwn(REFUSALS, guard.refuse)) fail(`${where}.refuse: refuse is one of the action's codes in REFUSALS: ${Object.keys(REFUSALS).join(', ')}.`);
      let steps = new Map();
      if (guard.after !== undefined) {
        steps = this.prepareSnapshots.get(guard.after);
        if (!steps) fail(`${where}.after names a prepare step.`);
      }
      this.note(checkCall(guard.transform, guard.args, {...this.scope('guard', where), steps}, ['guard']), true);
    });
  }
  /** I6, I9 (R11, open point Important 2): every raw step-data value in the output sits at a scalar position of outputSchema. */
  output() {
    const schema = this.action.outputSchema;
    for (const [name, node] of Object.entries(this.action.output)) {
      const where = `${this.where}: output.${name}`, result = this.expr(node, 'output', where, {member: true});
      this.outputFacts.set(name, result);
      this.scalars(result, schema.properties[name], where);
      // Open point Important 6: an input that reaches the output through a transform over step data is used.
      for (const call of walk(result)) {
        const entry = call.kind === 'transform' ? this.ctx.transforms.get(call.transform) : null;
        if (entry && Object.keys(entry.stepData).some(argument => call.args.has(argument))) for (const pointer of call.inputs) this.used.push(pointer);
      }
    }
  }
  scalars(result, schema, where) {
    if (result.raw && RAW_KINDS.has(result.kind)) {
      if (!SCALARS.has(schema?.type)) fail(`${where}: copies step data whole: a raw step-data value sits only at a string, integer, number or boolean of outputSchema, and this one sits at ${schema?.type === 'array' ? 'an array' : `an ${schema?.type ?? 'undeclared field'}`} (I6, I9).`);
      return;
    }
    if (result.kind === 'object') {
      for (const [key, member] of result.members) {
        if (schema?.type !== 'object' || !Object.hasOwn(schema.properties, key)) fail(`${where}.${key} is not a field of outputSchema.`);
        this.scalars(member, schema.properties[key], `${where}.${key}`);
      }
    }
    if (result.kind === 'array') result.items.forEach((item, index) => this.scalars(item, schema?.type === 'array' ? schema.items : undefined, `${where}[${index}]`));
    if (result.kind === 'each') this.scalars(result.do, schema?.type === 'array' ? schema.items : undefined, `${where}.do`);
    if (result.kind === 'when') this.scalars(result.then, schema, where);
    if (result.kind === 'either') for (const branch of result.branches) this.scalars(branch, schema, where);
  }
  // ---- the poll block (part h) -------------------------------------------------------------------------------------------------------
  /**
   * Section 8: what a polling trigger reads from a read action, validated beside it and kept out of its id and definition hash; its poll
   * hash binds it. The poll step is one of the action's own reads, whose list the items come from; the items, their id, version and time
   * resolve in the closed output schema; each cursor names a versioned kind and takes its value only from the poll step's answer; and
   * each has exactly one {cursor} slot there, alone where a value can be left out, so an ordinary call, which binds no cursor, sends what
   * the action sends without its poll block.
   */
  poll() {
    const {action, where, ctx} = this, poll = action.poll;
    if (poll === undefined) return;
    if (action.effect !== 'read') fail(`${where}: poll is only on a read action: a polling trigger reuses a read (section 8).`);
    if (!shaped(poll, POLL_FIELDS, ['itemTime'])) fail(`${where}: poll is {${POLL_FIELDS.join(', ')}} and may hold itemTime (section 8).`);
    const step = this.stepsOf.get(poll.step);
    if (!step || !['prepare', 'perform'].includes(step.phase)) fail(`${where}: poll.step names ${poll.step}, which is not a prepare or perform step of this action.`);
    if (step.effect !== 'read') fail(`${where}: poll.step ${poll.step}'s computed effect is ${step.effect}: a poll step is a read, and a reviewed-read POST is a read only when everything it sends is built from reads (F10.10, I5).`);
    // The items: a list of objects in the closed output schema, from the poll step's list; each item is read in the poll-item scope.
    const tokens = typeof poll.items === 'string' ? checkPointer(poll.items, `${where}: poll.items`) : [], list = schemaIn(action.outputSchema, tokens);
    if (!tokens.length || list?.type !== 'array' || list.items?.type !== 'object') fail(`${where}: poll.items (${poll.items}) points at a list of objects in outputSchema.`);
    let read = this.outputFacts.get(tokens[0]);
    for (const token of tokens.slice(1)) {
      while (read?.kind === 'when') read = read.then;
      if (read?.kind !== 'object' || !read.members.has(token)) break;
      read = read.members.get(token);
    }
    if (!read?.steps.has(poll.step)) fail(`${where}: poll.items (${poll.items}) never reads ${poll.step}, the poll step: the items a poll sees are the list its poll step reads.`);
    const items = {...read, type: list}, item = list.items;
    const itemId = checkExpression(poll.itemId, this.scope('poll', `${where}: poll.itemId`, {steps: new Map(), item: {from: 'poll', list: items}}));
    for (const id of itemId.transforms) this.pollTransforms.add(id);
    if (!['string', 'integer'].includes(itemId.type?.type)) fail(`${where}: poll.itemId is a string or an integer.`);
    // The dedupe key of each change (spec line 1676): built from the item, and the same on every poll. Constants, inputs and the account
    // are fixed for one subscription; a job key is new for every job and the clock moves, so either would store the same item again.
    if (![...walk(itemId)].some(node => node.kind === 'item')) fail(`${where}: poll.itemId reads the poll item: each item's id comes from the item, so two items never share one (section 8).`);
    if (itemId.sources.has('clock') || itemId.sources.has('jobKey')) fail(`${where}: poll.itemId never reads the clock or a job key: an item keeps its id from one poll to the next, so each change is stored once (section 8).`);
    const field = (pointer, at) => typeof pointer === 'string' ? schemaIn(item, checkPointer(pointer, at)) : null;
    if (poll.itemVersion !== null && !['string', 'integer'].includes(field(poll.itemVersion, `${where}: poll.itemVersion`)?.type)) {
      fail(`${where}: poll.itemVersion is null or a pointer to a string or integer field of each item.`);
    }
    if (poll.itemTime !== undefined) {
      const time = poll.itemTime, format = shaped(time, ['pointer', 'format']) && Object.hasOwn(ITEM_TIME_FORMATS, time.format) ? time.format : null;
      const type = format === null ? null : field(time.pointer, `${where}: poll.itemTime.pointer`)?.type;
      if (!(type === 'string' || (type === 'integer' && format === 'epoch-seconds'))) {
        fail(`${where}: poll.itemTime is {pointer, format}: a string field of each item, in one of the formats ${listWords(Object.keys(ITEM_TIME_FORMATS))}, and an integer only for epoch-seconds.`);
      }
      this.pollTransforms.add(ITEM_TIME_FORMATS[format]);
    }
    if (!['asc', 'desc', 'unordered'].includes(poll.order)) fail(`${where}: poll.order is asc, desc or unordered.`);
    if (!Array.isArray(poll.cursors) || !poll.cursors.length || poll.cursors.length > 4) fail(`${where}: poll.cursors holds 1 to 4 cursors.`);
    const names = new Set();
    poll.cursors.forEach((cursor, index) => this.cursor(cursor, `${where}: poll.cursors[${index}]`, {poll, step, names}));
    this.cursorSlots(poll);
    const statusIn = record(poll.resync) ? poll.resync.statusIn : undefined;
    if (!shaped(poll.resync, ['statusIn']) || !Array.isArray(statusIn) || new Set(statusIn).size !== statusIn.length || !statusIn.every(code => code === 404 || code === 410)) {
      fail(`${where}: poll.resync is {statusIn}, holding 404, 410, both or neither.`);
    }
    // One cursor per connection and resource (spec line 1675): the inputs that pick the resource, and those that only narrow it.
    const keyed = [poll.resourceKey, poll.filterInputs];
    if (!keyed.every(Array.isArray) || new Set(keyed.flat()).size !== keyed.flat().length || !keyed.flat().every(name => typeof name === 'string' && Object.hasOwn(action.inputSchema.properties, name))) {
      fail(`${where}: poll.resourceKey and poll.filterInputs name inputs of the action, each at most once between them.`);
    }
    if (!Number.isSafeInteger(poll.minIntervalSeconds) || poll.minIntervalSeconds < 30 || poll.minIntervalSeconds > 86_400) fail(`${where}: poll.minIntervalSeconds is 30 to 86,400 (I7).`);
    // Decision 4 and open point Minor 2: every transform the block names is in the registry and pinned, so its poll hash binds its code.
    for (const id of [...this.pollTransforms].sort()) {
      if (!ctx.transforms.has(id)) fail(`${where}: poll names ${id}, which the registry does not hold.`);
      if (typeof ctx.pins?.[id] !== 'string') fail(`${where}: poll names ${id}, which has no pin, so the poll hash could not bind its code (decision 4).`);
    }
  }
  /** One cursor of the poll block: a versioned kind, never an input, its next value from the poll step's answer, its compare pinned. */
  cursor(cursor, at, {poll, step, names}) {
    if (!shaped(cursor, ['name', 'kind'], ['next', 'compare', 'lastPageOnly', 'overlapSeconds', 'excludes'])) fail(`${at} is {name, kind} and may hold next, compare, lastPageOnly, overlapSeconds and excludes.`);
    if (typeof cursor.name !== 'string' || !STEP_ID.test(cursor.name)) fail(`${at}.name is 1 to 32 letters and digits, starting with a lowercase letter.`);
    if (names.has(cursor.name)) fail(`${this.where}: poll.cursors names ${cursor.name} twice.`);
    names.add(cursor.name);
    // Spec line 1663: cursors come only from provider responses, never from an input.
    if (Object.hasOwn(this.action.inputSchema.properties, cursor.name)) fail(`${at}.name ${cursor.name} is also an input: a cursor never comes from an input (spec line 1663).`);
    const rule = typeof cursor.kind === 'string' && Object.hasOwn(CURSOR_KINDS, cursor.kind) ? CURSOR_KINDS[cursor.kind] : null;
    if (!rule) fail(`${at}.kind is one of ${listWords(Object.keys(CURSOR_KINDS))}: a cursor kind carries its version.`);
    if (rule.compare.length) {
      if (!rule.compare.includes(cursor.compare)) fail(`${at}.compare names how ${cursor.kind} values are ordered: one of ${listWords(rule.compare)}.`);
      this.pollTransforms.add(cursor.compare);
    } else if (cursor.compare !== undefined) fail(`${at}: ${an(cursor.kind)} ${cursor.kind} cursor goes back to the provider as it came, so it names no compare.`);
    // Its next value: the poll step's answer (spec line 1661), or, for a high-water mark, the latest item time.
    const fromStep = record(cursor.next) && cursor.next.step === poll.step;
    if (rule.slot === null) {
      if (cursor.next !== undefined) fail(`${at}: a snapshot re-reads the list and compares its ids, so it has no next.`);
    } else if (rule.header) {
      if (!shaped(cursor.next, ['step', 'header']) || !fromStep || cursor.next.header !== rule.header) fail(`${at}.next is {step: '${poll.step}', header: '${rule.header}'}: ${an(cursor.kind)} ${cursor.kind} cursor is the ${rule.header} the poll step answered.`);
    } else if (rule.overlap && shaped(cursor.next, ['max']) && cursor.next.max === 'itemTime') {
      if (poll.itemTime === undefined) fail(`${at}.next is the latest item time, so poll.itemTime is declared.`);
      const ordered = ITEM_TIME_FORMATS[poll.itemTime.format];
      if (cursor.compare !== ordered) fail(`${at}.compare is ${ordered}, the transform that orders ${poll.itemTime.format} item times.`);
    } else if (shaped(cursor.next, ['step', 'pointer']) && fromStep) checkPointer(cursor.next.pointer, `${at}.next`);
    else fail(`${at}.next is {step: '${poll.step}', pointer}${rule.overlap ? ' or {max: \'itemTime\'}' : ''}: a cursor value comes only from the poll step's answer (spec line 1661).`);
    if (cursor.lastPageOnly !== undefined && !(cursor.lastPageOnly === true && fromStep && step.step.page !== undefined)) {
      fail(`${at}.lastPageOnly is true or absent, and only for a value read from the answer of a poll step that pages.`);
    }
    if (cursor.overlapSeconds !== undefined && !(rule.overlap && Number.isSafeInteger(cursor.overlapSeconds) && cursor.overlapSeconds >= 1 && cursor.overlapSeconds <= 3_600)) {
      fail(`${at}.overlapSeconds is 1 to 3,600 seconds, and only on a high-water mark.`);
    }
    if (cursor.excludes !== undefined) {
      const list = cursor.excludes;
      if (!rule.excludes || !Array.isArray(list) || !list.length || list.length > 32 || new Set(list).size !== list.length || !list.every(name => typeof name === 'string' && QUERY_NAME.test(name))) {
        fail(`${at}.excludes lists 1 to 32 distinct query names, and only on a sync token.`);
      }
      // A sync token's step never sends what the provider refuses beside one (Calendar's orderBy): not in its query, not as its page parameter.
      const sent = [...Object.keys(record(step.step.query) ? step.step.query : {}), ...(typeof step.step.page?.into?.query === 'string' ? [step.step.page.into.query] : [])];
      const clash = sent.find(name => list.includes(name));
      if (clash !== undefined) fail(`${this.where}: the poll step ${poll.step} sends ${clash}, which the sync token ${cursor.name} excludes (section 8).`);
    }
  }
  /**
   * Each cursor's {cursor} slots in the poll step (part d keeps them to the poll step's query, headers and body, where a value can be
   * left out): exactly one, or none for a snapshot; in its conditional header for an etag or last-modified cursor, else in the query or
   * the body; and never a transform argument, so the slot holds the cursor alone and its value sits at one request position.
   */
  cursorSlots(poll) {
    const found = new Map(poll.cursors.map(cursor => [cursor.name, []]));
    for (const [slot, result] of this.pollSlots) {
      for (const node of walk(result)) {
        if (node.kind === 'transform' && node.cursors.size) {
          fail(`${this.where}: the cursor ${[...node.cursors][0]} is a transform argument: a cursor slot holds the cursor alone, so an ordinary call leaves it out and the engine's value sits at one request position.`);
        }
        if (node.kind === 'cursor') found.get(node.name).push(slot);
      }
    }
    for (const cursor of poll.cursors) {
      const rule = CURSOR_KINDS[cursor.kind], slots = found.get(cursor.name), expected = rule.slot === null ? 0 : 1;
      if (slots.length !== expected) {
        fail(`${this.where}: the cursor ${cursor.name} has ${slots.length} {cursor} slots in the poll step ${poll.step}; ${an(cursor.kind)} ${cursor.kind} cursor has ${expected ? 'exactly one' : 'none: it re-reads the list'} (section 8).`);
      }
      if (!expected) continue;
      if (rule.header && slots[0] !== `headers.${rule.slot}`) fail(`${this.where}: the ${cursor.kind} cursor ${cursor.name} sits in the ${rule.slot} header of the poll step.`);
      if (!rule.header && slots[0] !== 'body' && !slots[0].startsWith('query.')) fail(`${this.where}: the ${cursor.kind} cursor ${cursor.name} sits in the query or the body of the poll step, never a header.`);
    }
  }
  /** Open point Important 4 (F10.8): a preview shows a string or a number, from what exists before the owner approves the perform bytes. */
  preview() {
    this.action.preview.forEach((line, index) => {
      const where = `${this.where}: preview[${index}]`;
      if (!shaped(line, ['label', 'expr'], ['truncate']) || !text(line.label, 80) || (line.truncate !== undefined && (!Number.isSafeInteger(line.truncate) || line.truncate < 1 || line.truncate > 10_000))) {
        fail(`${where} is {label, expr} and may hold truncate: a label of 1 to 80 characters, and 1 to 10,000 characters shown.`);
      }
      const result = this.expr(line.expr, 'preview', `${where} (${line.label})`);
      for (const source of result.sources) if (!PERFORM_SOURCES.includes(source)) fail(`${where} (${line.label}): a preview shows only what exists before the owner approves the perform bytes (T5).`);
      if (result.type !== null && !['string', 'integer', 'number'].includes(result.type.type)) fail(`${where} (${line.label}): a preview shows a string or a number: a list reaches it as one string through text.joinList@1.`);
    });
  }
  /** Spec line 748: closed assertions over a step's answer. `own` reads the step's own answer (expect.require). */
  assertion(node, where, {own = false, nested = false, extra = {}} = {}) {
    const kinds = record(node) ? ASSERTIONS.filter(kind => Object.hasOwn(node, kind)) : [];
    if (kinds.length !== 1) fail(`${where}: an assertion is one of ${listWords(ASSERTIONS)}.`);
    const [kind] = kinds, allowed = [kind, ...(own || kind === 'anyOf' ? [] : ['step']), ...(own || nested ? [] : ['when'])];
    if (Object.keys(node).some(key => !allowed.includes(key))) fail(`${where}: an assertion is one of ${listWords(ASSERTIONS)}, ${own ? 'over the step\'s own answer' : 'with the step it reads'}${own || nested ? '' : ' and an optional when'}.`);
    if (kind === 'anyOf') {
      if (nested) fail(`${where}: an anyOf never nests.`);
      if (!Array.isArray(node.anyOf) || node.anyOf.length < 2 || node.anyOf.length > 4) fail(`${where}: anyOf holds 2 to 4 assertions.`);
      node.anyOf.forEach((item, index) => this.assertion(item, `${where}.anyOf[${index}]`, {own, nested: true, extra}));
      return;
    }
    if (!own) {
      if (typeof node.step !== 'string') fail(`${where}: an assertion names the step it reads.`);
      if (!this.seen.has(node.step)) fail(`${where} names step ${node.step}, which has not run before this point.`);
    }
    const value = (expression, at) => this.expr(expression, 'assert', at, extra);
    if (kind === 'test') {
      if (own) fail(`${where}: a test reads the frame, not one answer, so it has no place in expect.require.`);
      // Every other kind reads the step's answer by its shape. A test is one comparison over what the step it names answered: anything wider
      // could prove nothing, or rebuild the when that R4 refuses.
      if (!shaped(node.test, ['equals'])) fail(`${where}: a test is one {equals} of an expression with a {const}.`);
      if (!this.test(node.test, 'assert', `${where}.test`, extra).steps.has(node.step)) fail(`${where}: a test reads the step it names, or it proves nothing about the read-back.`);
      return;
    }
    if (kind === 'statusIn') { if (!codes(node.statusIn)) fail(`${where}: statusIn holds 1 to 16 HTTP status codes.`); return; }
    if (kind === 'present' || kind === 'absent') {
      if (!shaped(node[kind], ['pointer'])) fail(`${where}: ${kind} is {pointer}.`);
      checkPointer(node[kind].pointer, `${where}.${kind}`);
      return;
    }
    if (kind === 'equals' || kind === 'contains') {
      if (!shaped(node[kind], ['pointer', 'value'])) fail(`${where}: ${kind} is {pointer, value}.`);
      checkPointer(node[kind].pointer, `${where}.${kind}`);
      value(node[kind].value, `${where}.${kind}.value`);
      return;
    }
    this.membership(node[kind], `${where}.${kind}`, value);
  }
  membership(list, where, value) {
    if (!shaped(list, ['list', 'where'])) fail(`${where} is {list, where}.`);
    checkPointer(list.list, `${where}.list`);
    if (!Array.isArray(list.where) || list.where.length < 1 || list.where.length > 3) fail(`${where}: where holds 1 to 3 conditions.`);
    return list.where.map((condition, index) => {
      const kind = shaped(condition, ['field', 'equals']) ? 'equals' : shaped(condition, ['field', 'contains']) ? 'contains' : fail(`${where}.where[${index}] is {field, equals} or {field, contains}.`);
      checkPointer(condition.field, `${where}.where[${index}].field`);
      return {node: condition[kind], result: value(condition[kind], `${where}.where[${index}].${kind}`)};
    });
  }
  verification() {
    const verify = this.action.verify;
    if (!verify) return;
    verify.assert.forEach((node, index) => {
      const where = `${this.where}: verify.assert[${index}]`;
      if (record(node) && node.when !== undefined) this.test(node.when, 'when', `${where}.when`);
      this.assertion(node, where);
    });
    const verifyIds = new Set(verify.requests.map(step => step.id));
    verify.identity.forEach((identity, index) => this.identity(identity, `${this.where}: verify.identity[${index}]`, verifyIds));
    // Every path with a write is read back by an identity of one of its own verify requests.
    for (const path of this.pathList) {
      if (!path.perform.some(id => this.stepsOf.get(id).effect !== 'read')) continue;
      if (!verify.identity.some(identity => path.verify.includes(identity.step))) fail(`${this.where}: on ${path.input === null ? 'its one path' : `the path where ${path.input} is ${path.value ?? 'absent'}`}, no identity reads back the write (spec line 748).`);
    }
  }
  /** Spec line 748: a readback pointer equal to perform data, the address itself, or membership in a list the readback holds. */
  identity(identity, where, verifyIds) {
    const kinds = ['readback', 'address', 'membership'];
    if (!record(identity) || !kinds.includes(identity.kind)) fail(`${where}: an identity is readback, address or membership.`);
    if (!verifyIds.has(identity.step)) fail(`${where}.step names a verify request.`);
    const performs = new Map(this.action.perform.map(step => [step.id, step]));
    const constant = result => ![...result.sources].some(source => source !== 'constant');
    const sent = (node, result) => ['perform-read', 'perform-write', 'resolving'].some(source => result.sources.has(source)) || this.sent.has(canonical(node));
    const only = () => fail(`${where} reads only constants: it reads what a perform step answered, or equals an expression a perform step sent (spec line 748).`);
    const none = () => fail(`${where} neither reads what a perform step answered nor equals an expression a perform step sent (spec line 748).`);
    if (identity.kind === 'readback') {
      if (!shaped(identity, ['kind', 'step', 'pointer', 'equals'])) fail(`${where}: a readback identity is {kind, step, pointer, equals}.`);
      checkPointer(identity.pointer, `${where}.pointer`);
      const result = this.expr(identity.equals, 'assert', `${where}.equals`);
      if (constant(result)) only();
      if (!sent(identity.equals, result)) none();
      return;
    }
    if (identity.kind === 'address') {
      if (!shaped(identity, ['kind', 'step', 'of'])) fail(`${where}: an address identity is {kind, step, of}.`);
      const perform = performs.get(identity.of), check = this.stepsOf.get(identity.step).step;
      if (!perform) fail(`${where}.of names a perform step.`);
      const placed = this.stepsOf.get(perform.id);
      const removal = !placed.placement.unplaced && (REMOVALS[this.ctx.appId] ?? []).includes(memberKey(placed.placement.member));
      if (placed.effect !== 'delete' && !removal) fail(`${where}: address identity is only for a delete or a member of REMOVALS (spec line 748).`);
      // REST: the same path with the same parameters. RPC: each argument the readback sends is the one the removal sent.
      const rpc = this.ctx.config.style === 'rpc', arguments_ = step => ({...(record(step.query) ? step.query : {}), ...(record(step.body?.object) ? step.body.object : {})});
      const same = rpc
        ? Object.keys(arguments_(check)).length > 0 && Object.entries(arguments_(check)).every(([name, node]) => Object.hasOwn(arguments_(perform), name) && canonical(arguments_(perform)[name]) === canonical(node))
        : check.path === perform.path && canonical(check.params ?? {}) === canonical(perform.params ?? {});
      if (!same) fail(`${where}: address identity reads the same path with the same parameters as ${perform.id}.`);
      return;
    }
    const kind = shaped(identity, ['kind', 'step', 'listHas'], ['forEach']) ? 'listHas' : shaped(identity, ['kind', 'step', 'listLacks'], ['forEach']) ? 'listLacks' : null;
    if (!kind) fail(`${where}: a membership identity is {kind, step, listHas | listLacks} and may hold forEach.`);
    let item = null;
    if (identity.forEach !== undefined) {
      const over = this.overOf.get(identity.forEach);
      if (!performs.has(identity.forEach) || !over) fail(`${where}.forEach names a perform step that repeats with forEach.`);
      item = {from: 'forEach', list: over};
    }
    const conditions = this.membership(identity[kind], `${where}.${kind}`, (node, at) => this.expr(node, 'assert', at, {item}));
    if (conditions.every(({result}) => constant(result))) only();
    if (!conditions.some(({node, result}) => !constant(result) && sent(node, result))) none();
  }

  // ---- declared fields -------------------------------------------------------------------------------------------------------------
  declared(row) {
    const {action, where, placements} = this;
    const unplaced = placements.some(placement => placement.unplaced);
    const counted = [...this.stepsOf.values()].filter(item => item.phase === 'prepare' || item.phase === 'perform');
    if (unplaced) {
      // An unplaced action is valid in shape and never runnable; its declared effect is still never weaker than its methods say. A
      // reviewed read on an app reviewed by operation id (Calendar's freebusy.query) places only through its method table, so until then
      // it counts by its method here and its read action waits (F10.10, open question 7).
      const floor = counted.reduce((effect, item) => stronger(effect, methodEffect(item.step.method)), 'read');
      if (RANK[action.effect] < RANK[floor]) fail(`${where}: declares effect ${action.effect}, but its methods say at least ${floor} (spec line 750).`);
    } else {
      const effect = actionEffect(placements);
      if (effect !== action.effect) fail(`${where}: declares effect ${action.effect}, but its steps compute ${effect} (spec line 750).`);
      for (const path of this.pathList) {
        const last = path.perform.at(-1);
        if (last === undefined) continue;
        const landed = this.stepsOf.get(last).placement.groupId;
        if (landed !== row.id) fail(`${where}: the last perform step on every path lands in its row: ${last} lands in ${landed}, not ${row.id} (spec line 713).`);
      }
    }
    // Hints (decision 6).
    const hints = action.hints;
    if (hints.readOnly !== (action.effect === 'read')) fail(`${where}: hints.readOnly is true exactly when the effect is read.`);
    // A step a body route moves into a delete row has effect delete, so the action's effect is delete too.
    if (hints.destructive !== (action.effect === 'delete')) fail(`${where}: hints.destructive is true exactly when the effect is delete or a step is routed into a delete row.`);
    if (hints.openWorld !== true) fail(`${where}: hints.openWorld is true: an action reaches a provider.`);
    const writes = this.action.perform.map(step => this.stepsOf.get(step.id)).filter(item => item.effect !== 'read');
    const repeatable = writes.every(({step}) => step.method === 'PUT' || step.method === 'DELETE' || step.bindContent === 'etag' || step.bindContent === 'sha' || step.resolves === true);
    if (hints.idempotent && !repeatable) fail(`${where}: hints.idempotent may be true only when every write that can run is a PUT, a DELETE, bound by If-Match or a sha, or a resolving write; a job key is new for every job.`);
    // askUnless (spec line 1219) and records.
    if (action.askUnless !== undefined) {
      const ask = action.askUnless.createdByFabric;
      if (!shaped(action.askUnless, ['createdByFabric']) || !shaped(ask, ['kind', 'input']) || typeof ask.kind !== 'string' || !KIND.test(ask.kind)) fail(`${where}: askUnless is {createdByFabric: {kind, input}}, with a kind of lowercase letters, digits and hyphens.`);
      const node = canonical({input: `/${ask.input}`}), required = (action.inputSchema.required ?? []).includes(ask.input);
      const fills = this.pathList.filter(path => path.perform.length).every(path => Object.values(this.stepsOf.get(path.perform.at(-1)).step.params ?? {}).some(value => canonical(value) === node));
      if (!required || !fills) fail(`${where}: askUnless.createdByFabric.input is a required input that fills a path parameter of the last perform step on every path (spec line 1219).`);
    }
    if (action.records !== undefined) {
      if (!shaped(action.records, ['kind', 'pointer']) || typeof action.records.kind !== 'string' || !KIND.test(action.records.kind)) fail(`${where}: records is {kind, pointer}.`);
      if (!action.verify.identity.some(identity => identity.kind === 'readback' && identity.pointer === action.records.pointer)) {
        fail(`${where}: records.pointer is the pointer of a readback identity: what Fabric records as made by it is what it verified.`);
      }
    }
    if (action.certified !== undefined) {
      if (!shaped(action.certified, ['evidence', 'definitionHash']) || typeof action.certified.definitionHash !== 'string' || !HASH.test(action.certified.definitionHash)) {
        fail(`${where}: certified is {evidence, definitionHash}, with a definition hash of 64 hex characters.`);
      }
      if (action.certified.evidence !== `docs/live-evidence/${this.ctx.appId}/actions.json`) fail(`${where}: certified.evidence is docs/live-evidence/${this.ctx.appId}/actions.json.`);
    }
  }
  /**
   * Part i (section 9; R10): each choice names a choice source of the app, or a version 1 option source by id, and follows
   * checkChoices(); a read action that declares servesSource lists with exactly that source's read.
   */
  choices() {
    const {action, ctx} = this;
    if (action.choices !== undefined) checkChoices(action.choices, {where: this.where, appId: ctx.appId, inputSchema: action.inputSchema, sources: ctx.sources, options: ctx.options, calls: this.calls});
    if (action.servesSource === undefined) return;
    if (action.effect !== 'read') fail(`${this.where}: servesSource is only on a read action: it names the list a read serves (section 9).`);
    const source = typeof action.servesSource === 'string' ? sourceById(action.servesSource, ctx.sources, ctx.options) : null;
    if (!source) fail(`${this.where}: servesSource names ${action.servesSource}, which is neither a choice source nor a version 1 option source of ${ctx.appId} (section 9).`);
    const reads = source.read.operation ?? source.read.request;
    for (const path of this.pathList) {
      const last = path.perform.at(-1), placement = last === undefined ? null : this.stepsOf.get(last).placement;
      // An unplaced step (an app reviewed by operation id, without its map) never runs; the rule is read again once it places.
      if (!placement || placement.unplaced) continue;
      if (memberKey(placement.member) !== memberKey(reads) || placement.groupId !== source.row) {
        fail(`${this.where}: servesSource ${source.id} reads ${reads}, and the list step ${last} reads ${placement.member}: an agent's listing is the same read (section 9).`);
      }
    }
  }
  /** Spec line 742 and open point Important 6: every input property, at every depth, is used. */
  inputsUsed() {
    const schema = this.action.inputSchema, reads = this.used.map(pointer => readPath(schema, pointer));
    for (const path of inputPaths(schema)) {
      if (path.at(-1) === '*') continue;
      if (!reads.some(read => prefixOf(read, path) || prefixOf(path, read))) {
        fail(`${this.where}: the input ${pointerOf(path.filter(name => name !== '*'))} is never used: every input reaches a request, a guard, a step's when, forEach.over or requiresScope.when, or the output through a transform over step data (spec line 742).`);
      }
    }
  }
  /** Decision 4 and open point Minor 2: every transform the action names has a pin, so its id binds its code. */
  pinned() {
    for (const id of [...this.transforms].sort()) if (typeof this.ctx.pins?.[id] !== 'string') fail(`${this.where}: names ${id}, which has no pin, so its id could not bind its code (decision 4).`);
  }
  entry() {
    const {action, placements, ctx} = this;
    // Unknown (null) while any step is unplaced, as actionEffect() is: such an action never runs until it places.
    const unplaced = placements.some(placement => placement.unplaced);
    const sensitive = unplaced ? null : placements.some(placement => memberData(this.rowOf(placement), placement.member).sensitive === 'secrets');
    // Part g (spec line 753; decision 4; R12): the id hashes the content without its lifecycle fields (id, certified) and its poll block,
    // with the pin of every transform it names and the resolved request of every lookup. reviewStatus and superseded are file-level.
    const content = {...action};
    delete content.id;
    delete content.certified;
    delete content.poll;
    const transforms = Object.fromEntries([...this.transforms].sort().map(name => [name, ctx.pins[name]]));
    const hash = canonicalHash({kind: 'fabric-action', schemaVersion: ctx.file.schemaVersion, appId: ctx.appId, specVersion: ctx.file.specVersion,
      pinnedParameters: ctx.file.pinnedParameters, action: content, transforms, lookups: this.lookups});
    const id = `${ctx.appId}.action.${action.key}.v${action.version}.${hash.slice(0, 24)}`;
    if (ctx.stored && action.id !== id) fail(`${this.where}: id is ${action.id}, but its content hashes to ${id}: a changed action gets a new id (spec line 753).`);
    // What grants bind: never certified, the poll block or placements, so certifying or tuning a poll moves nothing a grant holds.
    const definitionHash = capabilityPermissionHash(actionCapability(ctx.file, {...action, id}));
    if (ctx.stored && action.certified !== undefined && action.certified.definitionHash !== definitionHash) {
      fail(`${this.where}: certified.definitionHash is not ${definitionHash}, the hash of the definition grants bind: evidence certifies exactly that definition.`);
    }
    const frozen = deepFreeze(structuredClone(action)), pollTransforms = Object.freeze([...this.pollTransforms].sort());
    return Object.freeze({key: action.key, version: action.version, id, definitionHash, effect: action.effect, row: action.row, action: frozen,
      placements: Object.freeze([...placements]), unplaced, sensitive, twoPhase: this.resolving.length > 0, paths: Object.freeze(this.pathList),
      lookups: Object.freeze(this.lookups), transforms: Object.freeze([...this.transforms].sort()), rawAt: Object.freeze(this.rawAt),
      pollHash: pollHash({key: action.key, id, action: frozen, pollTransforms}, ctx.pins), pollTransforms});
  }
}
/** The node a {step} fact was read from, so two reads of one datum compare equal. */
const nodeOfStep = result => result?.kind === 'step' ? {step: result.step, ...(result.pointer !== undefined ? {pointer: result.pointer} : {header: result.header})} : null;

// ---- the capability, the poll hash, job keys and the loader (parts g and h) -------------------------------------------------------------
const ownAction = action => record(action?.action) ? action.action : action;
/**
 * Part g: the capability an action becomes, from its file and the action (as written, or its validated entry). Always a candidate,
 * whatever the file's reviewStatus (I8), with driver and kind `action`, which no http path accepts (I2): validateCapability() and
 * saveCandidates() refuse it, effectOf() throws on it, and decision() refuses it on any connection. Its definition hash is
 * capabilityPermissionHash() of this; certified, the poll block and the placements are never in it, and the placements, paths,
 * sensitivity, two-phase mark and poll hash come back beside it from validateActionFile().
 */
export function actionCapability(file, action) {
  const own = ownAction(action), block = {key: own.key, pinnedParameters: file.pinnedParameters, steps: {prepare: own.prepare, perform: own.perform}};
  for (const field of CAPABILITY_FIELDS) if (own[field] !== undefined) block[field] = own[field];
  return structuredClone({id: own.id, specVersion: 'fabric/0.2', version: own.version, appId: file.appId, kind: 'action', driver: 'action', name: own.name, description: own.description,
    effect: own.effect, status: 'candidate', inputSchema: own.inputSchema, outputSchema: own.outputSchema, action: block, provenance: {kind: 'reviewed-action', file: `catalog/actions/${file.appId}.json`}});
}
/**
 * Part h (section 8): the hash a trigger that reuses a read action binds beside the action's id: kind fabric-action-poll over the
 * action id, its poll block and the pin of every transform the block names (open point Minor 2: `pins`, the shipped ones by default). A
 * poll edit or a re-pin moves it and never the action id. Takes a validated entry; null when the action has no poll block.
 */
export function pollHash(entry, pins = PINS?.transforms ?? {}) {
  const poll = entry?.action?.poll;
  if (poll === undefined) return null;
  const transforms = Object.fromEntries((entry.pollTransforms ?? []).map(name => [name, pins[name]]));
  for (const [name, pin] of Object.entries(transforms)) if (typeof pin !== 'string') fail(`${entry.key}: poll names ${name}, which has no pin, so the poll hash could not bind its code (decision 4).`);
  return canonicalHash({kind: 'fabric-action-poll', version: 1, actionId: entry.id, poll, transforms});
}
/**
 * Part g (spec line 735): the value of {jobKey: name} in one job of one action: the first 32 hex characters of a hash of the job id, the
 * action id and the name. Pure: the same within a job (a Calendar Meet requestId fixed per job), new for every job, so it never makes a
 * POST idempotent; the built value is part of the prepared bytes the approval digest binds.
 */
export function jobKey(jobId, actionId, name) {
  if (typeof jobId !== 'string' || !jobId || jobId.length > 256 || typeof actionId !== 'string' || !actionId || actionId.length > 256 || typeof name !== 'string' || !JOB_KEY_NAME.test(name)) {
    fail('jobKey() takes a job id, an action id and a key name.');
  }
  return canonicalHash({kind: 'fabric-job-key', jobId, actionId, name}).slice(0, 32);
}
/**
 * Part g: the reviewed action files of a folder (catalog/actions by default), by app: each *.json is named after its appId and validated
 * with `deps`, so Gmail and Calendar files are unplaced without their maps. Anything else (the README) is ignored, and a missing folder
 * is empty. It reads files and nothing else: no store, no network. It is not called at import. Without deps.choices it loads the apps'
 * choice sources through loadChoiceSources() (part i) from the choices folder beside the actions folder: catalog/choices for
 * catalog/actions. F10.11 part p: no server imports this file. The servers and the operator's command load the folder one app at a time
 * through lib/action-catalog.mjs, reached only through lib/action-gate.mjs loadActionsSafely(), the one guarded import of an action module.
 */
export function loadActions(directory = new URL('../catalog/actions/', import.meta.url), deps = {}) {
  const base = directory instanceof URL ? fileURLToPath(directory) : String(directory), byApp = new Map();
  let files = [];
  try { files = readdirSync(base).filter(name => name.endsWith('.json')).sort(); } catch { return byApp; }
  const own = deps.choices === undefined && files.length ? {...deps, choices: loadChoiceSources(path.join(base, '..', 'choices'), deps)} : deps;
  for (const name of files) {
    const file = JSON.parse(readFileSync(path.join(base, name), 'utf8'));
    if (!record(file) || `${file.appId}.json` !== name) throw new Error(`Action file ${name} must be named after its appId.`);
    byApp.set(file.appId, validateActionFile(file, own));
  }
  return byApp;
}

// ---- resource-dependent inputs (part j) ---------------------------------------------------------------------------------------------------
/**
 * Part j (section 9; R14; open point Important 7): the hash of one resolved input's schema, which the approval binds and the agent sends
 * beside the definition hash: kind fabric-resolved-input over the resource (the values of the inputs it depends on), the derive transform
 * and its pinned code hash, the derived closed schema and its bindings (sorted by id). Never the raw provider answer, whose volatile
 * fields would move it, and never an action id or input name: the job binds those beside it, so a describe answer and every action that
 * consumes the same resource through the same derive agree on one value. A re-pin of the derive transform moves it.
 */
export function resolvedSchemaHash(args) {
  if (!shaped(args, ['resource', 'transform', 'codeHash', 'schema', 'bindings'])) fail('resolvedSchemaHash() takes exactly resource, transform, codeHash, schema and bindings.');
  const {resource, transform, codeHash, schema, bindings} = args;
  if (!record(resource) || !Object.keys(resource).length || Object.keys(resource).length > 3
    || !Object.values(resource).every(value => (typeof value === 'string' && value.length > 0 && [...value].length <= 1_000) || Number.isSafeInteger(value))) {
    fail('resolvedSchemaHash(): the resource is 1 to 3 input values, each a string or an integer, by input name.');
  }
  if (typeof transform !== 'string' || !TRANSFORM_ID.test(transform)) fail('resolvedSchemaHash(): transform is a transform id, family.name@version.');
  if (typeof codeHash !== 'string' || !HASH.test(codeHash)) fail('resolvedSchemaHash(): codeHash is the derive transform\'s pin, 64 hex characters.');
  try { checkSchema(schema, '$derived'); } catch (error) { fail(`resolvedSchemaHash(): ${error.message}`); }
  if (schema.type !== 'object' || !bindingsFit(schema, bindings)) fail('resolvedSchemaHash(): the schema is a closed object, and the bindings name each property of the schema once, with a unique id and a type.');
  const sorted = [...bindings].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return canonicalHash({kind: 'fabric-resolved-input', version: 1, resource, derive: {transform, codeHash}, schema, bindings: sorted});
}
/** The first property name, at any depth of a schema, that no object key or hash may hold, or null. */
function unsafeName(schema) {
  for (const [name, sub] of Object.entries(record(schema?.properties) ? schema.properties : {})) {
    if (UNSAFE_NAMES.has(name)) return name;
    const deeper = unsafeName(sub);
    if (deeper) return deeper;
  }
  return schema?.type === 'array' ? unsafeName(schema.items) : null;
}
/**
 * Part j (section 9; R14, I3): an action's input schema with each resource-dependent input's derived schema in place of its placeholder.
 * `resolved` holds one {schema, bindings} per resource-dependent input of the action (as written, or its validated entry). Each derived
 * schema names no unsafe property, passes checkSchema() as a closed object of at most the entry's maxProperties properties, and its
 * bindings fit it, all before any value is checked against it. Returns the schema, frozen.
 */
export function effectiveInputSchema(action, resolved) {
  const own = ownAction(action), entries = own.resolvedInputs ?? [], names = entries.map(entry => entry.input);
  if (!record(resolved) || Object.keys(resolved).sort().join() !== [...names].sort().join()) {
    fail(`${own.key}: effectiveInputSchema() takes one derived {schema, bindings} for each resource-dependent input: ${listWords(names) || 'none'}.`);
  }
  const properties = {...own.inputSchema.properties};
  for (const entry of entries) {
    const pair = resolved[entry.input], where = `${own.key}: the derived schema of ${entry.input}`;
    if (!shaped(pair, ['schema', 'bindings'])) fail(`${where} is {schema, bindings}.`);
    const bad = unsafeName(pair.schema);
    if (bad) fail(`${where} names ${bad}: never __proto__, prototype or constructor, which no hash or object key can hold.`);
    try { checkSchema(pair.schema, '$derived'); } catch (error) { fail(`${where}: ${error.message}`); }
    if (pair.schema.type !== 'object') fail(`${where} is a closed object schema.`);
    const count = Object.keys(pair.schema.properties).length;
    if (count > entry.maxProperties) fail(`${where} holds ${count} properties; at most ${entry.maxProperties} (maxProperties).`);
    if (!bindingsFit(pair.schema, pair.bindings)) fail(`${where}: its bindings name each property once, with a unique id and a type.`);
    properties[entry.input] = structuredClone(pair.schema);
  }
  return deepFreeze(structuredClone({...own.inputSchema, properties}));
}

// ---- run time --------------------------------------------------------------------------------------------------------------------------
/** I6, I9: the output F10.11 built, held to the closed outputSchema within 1 MiB of JSON, before anyone sees it. Returns it. */
export function checkOutput(action, output) {
  const own = ownAction(action);
  let size;
  try { size = Buffer.byteLength(JSON.stringify(output)); } catch { fail(`${own.key}: the output is not JSON.`); }
  if (size > BOUNDS.outputBytes) fail(`${own.key}: the output is ${bytes(size)} bytes; at most 1 MiB (I7).`);
  try { validateInput(own.outputSchema, output); } catch (error) { fail(`${own.key}: the output does not fit its outputSchema (${error.message.replace(/^\$input/, '$output')}).`); }
  return output;
}
/** Open point Important 4 (F10.8): each preview value is a string or a number, or absent, before the card is built. Returns them. */
export function checkPreview(action, values) {
  const own = ownAction(action);
  if (!Array.isArray(values) || values.length !== own.preview.length) fail(`${own.key}: checkPreview() takes one value per preview line: ${own.preview.length}, not ${Array.isArray(values) ? values.length : 0}.`);
  values.forEach((value, index) => {
    if (value === undefined || typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))) return;
    const kind = value === null ? 'null' : Array.isArray(value) ? 'a list' : typeof value === 'boolean' ? 'a boolean' : typeof value === 'object' ? 'an object' : `a ${typeof value}`;
    fail(`${own.key}: preview[${index}] (${own.preview[index].label}) is ${kind}: a preview shows a string or a number.`);
  });
  return values;
}
/**
 * Open point Important 2: one built request ({params, query, headers, body}, the body parsed) of a validated action's step. Every
 * position where the file placed a raw step-data value, or a poll cursor (part h), holds a string, a number, a boolean or null, never a
 * whole provider object or list (I6, T4). F10.11 calls it when the perform bytes are built, and I07's engine on every poll request it
 * builds. Returns the request.
 */
export function checkRequest(action, stepId, request) {
  const positions = action?.rawAt?.[stepId];
  if (!positions) fail(`${action?.key}: ${action?.key} has no step ${stepId}.`);
  const resolve = (value, tokens, at) => {
    if (!tokens.length) return [[value, at]];
    const [token, ...rest] = tokens;
    if (token === '*') return Array.isArray(value) ? value.flatMap((item, index) => resolve(item, rest, [...at, index])) : [];
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, token)) return [];
    return resolve(value[token], rest, [...at, token]);
  };
  for (const position of positions) {
    const tokens = position.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~'));
    for (const [value, at] of resolve(request, tokens, [])) {
      if (value === undefined || value === null || typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) continue;
      fail(`${action.key}: ${stepId} copies a whole provider value at ${pointerOf(at)}: only a string, a number, a boolean or null sits there (I6, T4).`);
    }
  }
  return request;
}
/**
 * Open point Minor 3 (R7, T8): which steps of a validated action run. `accessOf(placement)` is a member's provider access ('granted',
 * 'missing', 'unknown' or 'unavailable'); `modeOf(placement)` its row's mode ('allow', 'ask' or 'deny'). Any row at Never refuses the
 * action before any call, a skipped optional step's row included; verify rows count, as T8 reads (open question 2's default), and so do
 * choice lookups. An optional step whose member is missing or unavailable is skipped and its fallback runs; otherwise the fallback is
 * skipped. Access is 'unavailable' when a step that runs can never work through a sign-in (F10.11 part e), else 'missing' when one is.
 */
export function runPlan(action, {accessOf: accessFor, modeOf}) {
  const steps = new Map(), own = ownAction(action);
  for (const step of [...(own.resolvedInputs ?? []).flatMap(entry => entry.schema.steps), ...own.prepare, ...own.perform, ...(own.verify?.requests ?? [])]) steps.set(step.id, step);
  const never = action.placements.find(placement => modeOf(placement) === 'deny');
  const skipped = new Set();
  for (const placement of action.placements) {
    const step = steps.get(placement.stepId);
    if (step?.optional === true && ['missing', 'unavailable'].includes(accessFor(placement))) skipped.add(step.id);
  }
  for (const step of steps.values()) if (step.fallbackFor !== undefined && !skipped.has(step.fallbackFor)) skipped.add(step.id);
  const run = action.placements.filter(placement => !skipped.has(placement.stepId));
  const states = run.map(placement => accessFor(placement));
  const access = states.includes('unavailable') ? 'unavailable' : states.includes('missing') ? 'missing' : states.includes('unknown') ? 'unknown' : 'granted';
  return Object.freeze({refused: never ? `${never.groupId} is Never, so the action is refused before any call, even where its step would be skipped (R7, T8).` : null, access,
    run: Object.freeze(run.map(placement => placement.stepId)), skipped: Object.freeze([...skipped])});
}

// F10.9 part k (docs/F10.9-BUILD-MAP.md part k and section 8; R6, R8, R9 and R11; open points Important 4 and 5, Minor 2): the trigger
// format. A trigger names its delivery method (polling, webhook, watch with renewal, live connection or built-in schedule),
// what it polls (its own read steps, or a read action's poll block), the resource it keys one cursor on, its duplicate key and its event
// shape (spec line 702). validateTriggerFile() checks one app's trigger file against its rows, proxy settings, application map, the
// transform registry and its pins, its choice sources and its reviewed action file, and returns each trigger with its id, its step
// placements and its rows beside it. lib/action-catalog.mjs loads catalog/triggers/ through it (I07 part 1c), and server.mjs does not
// reach this file. Nothing here runs a poll: the engine is step 2 of docs/I07-BUILD-MAP.md.
//
// Poll, seed and enrich steps follow the action step rules (lib/actions.mjs ActionState, phases poll, seed and enrich): reviewed read
// rows, a computed effect of read, never Other, locked or unavailable, cursors as part h keeps them. Register and teardown steps land
// only on a member of REGISTRATION_MEMBERS (R6), placed through placeRegistration(): the one carve-out from spec line 737, by member,
// never by row, run only by Fabric's engine after the owner approved the subscription. Nothing here runs a step or a transform.
import {canonicalHash, checkSchema, validateValue, credentialName, exchangeField, secretParameter} from './compiler.mjs';
import {PERMISSION_GROUPS, parseTemplate, memberKey} from './permission-groups.mjs';
import {PROXY_CONFIGS} from './proxy-config.mjs';
import {checkPointer, fits} from './action-expressions.mjs';
import {placeRegistration} from './action-placement.mjs';
import {ActionState, validateActionFile, ITEM_TIME_FORMATS} from './actions.mjs';
import {OPTION_SOURCES} from './option-sources.mjs';
import {checkChoices} from './choice-sources.mjs';
import {TRANSFORMS} from './transforms/index.mjs';
import {PINS, validDate} from './transform-pins.mjs';
import {definitionFor, reviewedProviderIds} from './providers/definitions.mjs';

const deepFreeze = value => { if (value !== null && typeof value === 'object') { Object.freeze(value); for (const item of Object.values(value)) deepFreeze(item); } return value; };

/**
 * R6 (section 8): the reviewed registration members, by app. A register step lands only on a register member and a teardown step only on
 * a teardown member; each sits in its app's locked row. `destination` is the body pointer that holds exactly {receiver: <appId>}, `secret`
 * the body pointer that holds exactly {secret: <name>}, and `ids` the registration id slots (a path parameter or a body pointer), each of
 * which holds exactly {kept: <name>} of a value the subscription's own register step kept, so the engine only ever stops or deletes a
 * channel or hook its own subscription made (T4). Gmail has none: Sami chose polling (docs/MASTER-PLAN.md:249). A new entry is a
 * reviewed code change.
 */
export const REGISTRATION_MEMBERS = deepFreeze({
  'google-calendar': [
    {member: 'calendar.events.watch', role: 'register', destination: '/address', secret: '/token', ids: []},
    {member: 'calendar.calendarList.watch', role: 'register', destination: '/address', secret: '/token', ids: []},
    {member: 'calendar.channels.stop', role: 'teardown', destination: null, secret: null, ids: [{body: '/id'}, {body: '/resourceId'}]},
  ],
  github: [
    {member: 'POST /repos/{owner}/{repo}/hooks', role: 'register', destination: '/config/url', secret: '/config/secret', ids: []},
    {member: 'DELETE /repos/{owner}/{repo}/hooks/{hook_id}', role: 'teardown', destination: null, secret: null, ids: [{path: 'hook_id'}]},
  ],
});
/** Section 8 (part k): the bounds of one poll (spec lines 1681-1682), a worst-case event (spec line 1687), a backfill and a Slack channel list. */
export const TRIGGER_BOUNDS = Object.freeze({pages: 10, items: 500, pollSeconds: 10, eventBytes: 8_192, backfill: 25, slackChannels: 20});

const METHODS = ['polling', 'webhook', 'watch', 'live', 'builtin'];
// Each admission scheme, with the delivery it admits; a handshake is one of these.
const SCHEMES = Object.freeze({'hmac-sha256-header': 'webhook-api', 'channel-token': 'watch', 'notion-signature': 'webhook-operator', 'slack-v0': 'webhook-operator', 'socket-authenticated': 'live'});
const SCHEME_WORDS = Object.freeze({'webhook-api': 'a webhook with registration api', watch: 'a watch', 'webhook-operator': 'a webhook with registration operator', live: 'a live trigger'});
const HANDSHAKES = ['github-ping', 'notion-verification-token', 'slack-url-verification', 'google-sync'];
const TRIGGER_FIELDS = ['id', 'key', 'version', 'name', 'description', 'delivery', 'inputSchema', 'resource', 'poll', 'dedupe', 'event', 'backfill', 'retention', 'bounds', 'rows'];
const TRIGGER_OPTIONAL = ['choices', 'filter', 'certified'];
const OWN_POLL = ['source', 'items', 'itemId', 'itemVersion', 'order', 'cursors', 'resync', 'minIntervalSeconds'];
const READ_STEP_FIELDS = ['params', 'query', 'headers', 'body', 'page', 'maxResponseBytes'];
const REGISTRATION_SOURCES = new Set(['constant', 'receiver', 'secret', 'kept', 'subscriptionKey']);
const APP_ID = /^[a-z][a-z0-9-]{0,63}$/, KEY = /^[a-z][a-z0-9-]{0,47}$/, STEP_ID = /^[a-z][A-Za-z0-9]{0,31}$/, NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const KEPT_NAME = /^[a-z][A-Za-z0-9-]{0,63}$/, SEGMENT = /^[A-Za-z0-9._~-]{1,200}$/, HEADER_NAME = /^[a-z0-9-]{1,64}$/, EVENT_NAME = /^[a-z][a-z0-9_.]{0,63}$/;

const fail = message => { throw new Error(message); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const shaped = (value, required, optional = []) => record(value) && required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const text = (value, max) => typeof value === 'string' && value.trim().length > 0 && [...value].length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const listWords = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
const bytes = value => String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
const an = word => /^[aeiou]/.test(word) ? 'an' : 'a';
const firstToken = pointer => pointer.slice(1).split('/')[0].replace(/~1/g, '/').replace(/~0/g, '~');
const integer = (value, low, high) => Number.isSafeInteger(value) && value >= low && value <= high;
/** Every fact a fact is built from, depth first (the facts lib/action-expressions.mjs returns). */
function* walk(result) {
  if (!record(result)) return;
  yield result;
  for (const key of ['members', 'args']) if (result[key] instanceof Map) for (const item of result[key].values()) yield* walk(item);
  for (const key of ['items', 'parts', 'branches', 'tests']) if (Array.isArray(result[key])) for (const item of result[key]) yield* walk(item);
  for (const key of ['then', 'test', 'list', 'do', 'operand', 'of']) if (record(result[key]) && result[key].sources instanceof Set) yield* walk(result[key]);
}
/** Every object node of a JSON value as written, depth first. */
function* nodes(value) {
  if (Array.isArray(value)) for (const item of value) yield* nodes(item);
  else if (record(value)) { yield value; for (const item of Object.values(value)) yield* nodes(item); }
}
/** The fact at a body pointer of REGISTRATION_MEMBERS (reviewed, plain tokens), through {object} members only, or undefined. */
function factAt(body, pointer) {
  let current = body;
  for (const token of pointer.slice(1).split('/')) current = current?.kind === 'object' ? current.members.get(token) : undefined;
  return current;
}
/** The closed schema at a pointer's tokens, through declared properties and list items, or null. */
function schemaAt(schema, tokens) {
  let current = schema;
  for (const token of tokens) {
    if (current?.type === 'object' && Object.hasOwn(current.properties ?? {}, token)) current = current.properties[token];
    else if (current?.type === 'array' && /^(?:0|[1-9][0-9]*)$/.test(token)) current = current.items;
    else return null;
  }
  return current ?? null;
}
/** The most bytes a value of a closed schema can take as JSON: 6 bytes a character (an escape), 24 for a number. */
function worstBytes(schema) {
  if (Array.isArray(schema.enum)) return Math.max(...schema.enum.map(value => Buffer.byteLength(JSON.stringify(value))));
  if (Object.hasOwn(schema, 'const')) return Buffer.byteLength(JSON.stringify(schema.const));
  if (schema.type === 'string') return schema.maxLength === undefined ? Infinity : 2 + 6 * schema.maxLength;
  if (schema.type === 'integer' || schema.type === 'number') return 24;
  if (schema.type === 'boolean') return 5;
  if (schema.type === 'null') return 4;
  if (schema.type === 'array') return schema.maxItems === undefined ? Infinity : 2 + schema.maxItems * (worstBytes(schema.items) + 1);
  return 2 + Object.entries(schema.properties).reduce((sum, [key, sub]) => sum + Buffer.byteLength(JSON.stringify(key)) + 2 + worstBytes(sub), 0);
}

let defaultIdentities = null;
/** The reviewed sign-in of each app, by app id, read from catalog/auth once and only when a caller passes none. */
function identitiesOf() {
  if (!defaultIdentities) {
    defaultIdentities = new Map();
    for (const provider of reviewedProviderIds()) for (const app of definitionFor(provider).apps) defaultIdentities.set(app.appId, definitionFor(provider));
  }
  return defaultIdentities;
}
const byApp = (value, appId) => value instanceof Map ? value.get(appId) : record(value) ? value[appId] : undefined;

/**
 * The step checks of lib/actions.mjs for a trigger: every expression reads in a trigger scope (registration names only where a step
 * says so, and the variable a resource.each binds), and an enrich step reads the poll item.
 */
class TriggerState extends ActionState {
  scope(slot, where, extra = {}) {
    const scope = {...super.scope(slot, where, extra), trigger: true, vars: this.vars ?? new Map()};
    if (this.enrichItem && !scope.item) scope.item = this.enrichItem;
    return scope;
  }
}

/**
 * Validates one app's trigger file (docs/F10.9-BUILD-MAP.md section 8) and returns {appId, triggers}, frozen. Each entry is {key, version,
 * id, trigger, placements, rows, unplaced, transforms, rawAt, sources, reviewed, status}: `trigger` as written; `rows` the read rows its
 * poll, seed and enrich steps land in (null while any is unplaced); `rawAt` each read step's cursor and raw step-data positions, which
 * I07's engine holds to a scalar with checkRequest(); `sources` the read action it reuses, with its id and poll hash; `reviewed` true only
 * when its file and that action's file are reviewed; `status` always candidate (I8). Its stored id must equal the computed one. `deps`:
 * {groups, configs, maps, transforms, pins, choices, options, identities, actions}, as validateActionFile() takes them, plus the apps' raw
 * action files by app. Throws an Error naming the trigger, the position and the rule.
 */
export function validateTriggerFile(file, deps = {}) {
  return readTriggerFile(file, deps, true);
}
/** The id each trigger of `file` must carry, by `<key> v<version>`: validated as validateTriggerFile() validates it, a stale stored id aside. */
export function triggerIds(file, deps = {}) {
  const {triggers} = readTriggerFile(file, deps, false);
  return new Map(triggers.map(entry => [`${entry.key} v${entry.version}`, entry.id]));
}

function readTriggerFile(file, deps, stored) {
  const {groups = PERMISSION_GROUPS, configs = PROXY_CONFIGS, maps = new Map(), transforms = TRANSFORMS, pins = PINS?.transforms ?? {}, choices = new Map(), options = OPTION_SOURCES,
    identities = identitiesOf(), actions = new Map()} = deps;
  if (!record(file)) fail('Triggers: a trigger file is an object.');
  const appId = file.appId, at = `Triggers for ${appId}`;
  if (!shaped(file, ['schemaVersion', 'appId', 'specVersion', 'reviewStatus', 'pinnedParameters', 'triggers'], ['superseded'])) {
    fail(`${at}: a trigger file holds exactly schemaVersion, appId, specVersion, reviewStatus, pinnedParameters and triggers, and may hold superseded.`);
  }
  if (file.schemaVersion !== 1) fail(`${at}: schemaVersion is 1.`);
  if (typeof appId !== 'string' || !APP_ID.test(appId)) fail(`${at}: appId is an app id.`);
  const definition = groups.get(appId), config = configs.get(appId);
  if (!definition || !config) fail(`${at}: the app has no reviewed permission rows and proxy settings.`);
  if (file.specVersion !== 'fabric/0.2') fail(`${at}: specVersion is fabric/0.2.`);
  if (!['reviewed', 'candidate'].includes(file.reviewStatus)) fail(`${at}: reviewStatus is reviewed or candidate.`);
  if (!record(file.pinnedParameters) || Object.entries(file.pinnedParameters).some(([name, value]) => !NAME.test(name) || typeof value !== 'string' || !SEGMENT.test(value))) {
    fail(`${at}: pinnedParameters maps names to constant path segments.`);
  }
  if (!Array.isArray(file.triggers) || !file.triggers.length || file.triggers.length > 100) fail(`${at}: triggers holds 1 to 100 triggers.`);
  const sources = byApp(choices, appId), identity = identities instanceof Map ? identities.get(appId) ?? null : null;
  const ctx = {at, appId, file, definition, config, map: byApp(maps, appId) ?? null, transforms, pins, identity, access: null, stored,
    sources: Array.isArray(sources) ? sources : Array.isArray(sources?.sources) ? sources.sources : [], options: Array.isArray(byApp(options, appId)) ? byApp(options, appId) : [],
    actionFile: byApp(actions, appId) ?? null, deps: {groups, configs, maps, transforms, pins, choices, options, identities}};
  const seen = new Set(), triggers = file.triggers.map((trigger, index) => {
    const entry = checkTrigger(trigger, index, ctx), pair = `${entry.key} v${entry.version}`;
    if (seen.has(pair)) fail(`${at}: ${pair} is declared twice.`);
    seen.add(pair);
    return entry;
  });
  if (file.superseded !== undefined) checkSuperseded(file, triggers, at);
  return Object.freeze({appId, triggers: Object.freeze(triggers)});
}

/** R9: old trigger ids no longer in the file, keyed by the old id, each pointing at a current trigger. */
function checkSuperseded(file, triggers, at) {
  if (!Array.isArray(file.superseded) || !file.superseded.length || file.superseded.length > 100) fail(`${at}: superseded holds 1 to 100 entries.`);
  const listed = new Set(), id = new RegExp(`^${file.appId.replace(/-/g, '\\-')}\\.trigger\\.[a-z][a-z0-9-]{0,47}\\.v[1-9][0-9]{0,3}\\.[a-f0-9]{24}$`);
  file.superseded.forEach((entry, index) => {
    const where = `${at}: superseded[${index}]`;
    if (!shaped(entry, ['id', 'replacedBy', 'reason', 'stopsAfter']) || !shaped(entry.replacedBy, ['key', 'version'])) fail(`${where} is {id, replacedBy: {key, version}, reason, stopsAfter}.`);
    if (typeof entry.id !== 'string' || !id.test(entry.id)) fail(`${where}.id is not a trigger id of ${file.appId}.`);
    const current = triggers.find(trigger => trigger.id === entry.id);
    if (current) fail(`${where}.id is the current id of ${current.key} v${current.version}: a superseded id is no longer in triggers.`);
    if (!triggers.some(trigger => trigger.key === entry.replacedBy.key && trigger.version === entry.replacedBy.version)) fail(`${where}.replacedBy names no trigger of this file.`);
    if (!['safety', 'change'].includes(entry.reason)) fail(`${where}.reason is safety or change.`);
    if (!validDate(entry.stopsAfter)) fail(`${where}.stopsAfter is a real date, YYYY-MM-DD.`);
    if (listed.has(entry.id)) fail(`${at}: superseded lists ${entry.id} twice.`);
    listed.add(entry.id);
  });
}

function checkTrigger(trigger, index, ctx) {
  const {at, appId} = ctx;
  if (!record(trigger)) fail(`${at}: triggers[${index}] is an object.`);
  if (typeof trigger.key !== 'string' || !KEY.test(trigger.key)) fail(`${at}: triggers[${index}]: key is 1 to 48 lowercase letters, digits and hyphens, starting with a letter.`);
  if (!integer(trigger.version, 1, 9999)) fail(`${at}: triggers[${index}]: version is a whole number from 1 to 9999.`);
  const where = `${at}: ${trigger.key} v${trigger.version}`;
  if (Object.hasOwn(trigger, 'resolvedInputs')) fail(`${where}: a trigger holds no resource-dependent inputs: their schema steps would have to run again before every poll, and the engine runs no schema step.`);
  if (!shaped(trigger, TRIGGER_FIELDS, TRIGGER_OPTIONAL)) fail(`${where}: a trigger holds exactly ${listWords(TRIGGER_FIELDS)}, and may hold ${listWords(TRIGGER_OPTIONAL)}.`);
  if (typeof trigger.id !== 'string' || !new RegExp(`^${appId.replace(/-/g, '\\-')}\\.trigger\\.${trigger.key.replace(/-/g, '\\-')}\\.v${trigger.version}\\.[a-f0-9]{24}$`).test(trigger.id)) {
    fail(`${where}: id is ${appId}.trigger.${trigger.key}.v${trigger.version}.<24 hex characters>.`);
  }
  if (!text(trigger.name, 100)) fail(`${where}: name is 1 to 100 characters on one line.`);
  if (!text(trigger.description, 1000)) fail(`${where}: description is 1 to 1,000 characters on one line.`);
  // Inputs: closed, never credential-shaped (I3).
  try { checkSchema(trigger.inputSchema, '$input'); } catch (error) { fail(`${where}: inputSchema: ${error.message}`); }
  if (trigger.inputSchema.type !== 'object') fail(`${where}: inputSchema is a closed object schema.`);
  for (const name of Object.keys(trigger.inputSchema.properties)) {
    if (credentialName(name) || exchangeField(name) || secretParameter(name)) fail(`${where}: the input $input.${name} is named like a credential: a trigger input never carries one (I3).`);
  }
  const resource = resourceOf(trigger, where, ctx);
  // The step checks: the poll step (the last of the trigger's own read steps) holds the cursor slots.
  const own = record(trigger.poll) && record(trigger.poll.source) && Array.isArray(trigger.poll.source.steps);
  const pollStep = own ? trigger.poll.source.steps.at(-1)?.id : null, cursors = own && Array.isArray(trigger.poll.cursors) ? trigger.poll.cursors : [];
  const state = new TriggerState({inputSchema: trigger.inputSchema, effect: 'read', poll: {step: pollStep, cursors}}, where, ctx);
  state.ids = new Set();
  state.vars = resource.each ? new Map([[resource.as, state.expr({input: resource.each}, 'poll', `${where}: resource.each`)]]) : new Map();
  delivery(trigger, state, ctx, where, resource);
  const polled = own ? ownPoll(trigger, state, ctx, where) : actionPoll(trigger, state, ctx, where);
  resourceRead(trigger, polled, where, resource);
  // What each item becomes: its filter, duplicate key and event.
  if (trigger.filter !== undefined) {
    if (!Array.isArray(trigger.filter) || !trigger.filter.length || trigger.filter.length > 8) fail(`${where}: filter holds 1 to 8 tests over the item.`);
    trigger.filter.forEach((node, position) => state.test(node, 'poll', `${where}: filter[${position}]`, {item: polled.item, steps: polled.enriched, uses: true}));
  }
  dedupe(trigger, state, where, polled);
  event(trigger, state, where, polled);
  limits(trigger, state, where, ctx);
  const rows = rowsOf(trigger, state, where, ctx, polled);
  if (trigger.choices !== undefined) checkChoices(trigger.choices, {where, appId, inputSchema: trigger.inputSchema, sources: ctx.sources, options: ctx.options, calls: state.calls, lookups: false});
  // Spec line 742: every input reaches a read step, a reused action's arguments, a registration path or a filter.
  for (const name of Object.keys(trigger.inputSchema.properties)) {
    if (!state.used.some(pointer => firstToken(pointer) === name) && resource.each !== `/${name}`) fail(`${where}: the input /${name} is never used: every input reaches a poll, seed or enrich request, a reused action's arguments, a registration path or a filter (spec line 742).`);
  }
  if (trigger.certified !== undefined && !(shaped(trigger.certified, ['evidence']) && trigger.certified.evidence === `docs/live-evidence/${appId}/triggers.json`)) {
    fail(`${where}: certified is {evidence: 'docs/live-evidence/${appId}/triggers.json'}: lifecycle data, never hashed.`);
  }
  // Decision 4 and open point Minor 2: every transform the trigger names, in an expression, a cursor's compare, an item time format or
  // Link paging, is in the registry and pinned, so its id binds the code.
  const named = [...new Set([...state.transforms, ...state.pollTransforms])].sort();
  for (const id of named) {
    if (!ctx.transforms.has(id)) fail(`${where}: names ${id}, which the registry does not hold.`);
    if (typeof ctx.pins?.[id] !== 'string') fail(`${where}: names ${id}, which has no pin, so its id could not bind its code (decision 4).`);
  }
  // Section 8: the id hashes the content without its id and certified, the pins of the transforms it names, and each reused action's id
  // and poll hash, so an action edit, a poll edit or a re-pin gives a new trigger id. reviewStatus and superseded are file-level.
  const content = {...trigger};
  delete content.id;
  delete content.certified;
  const reused = polled.source ? [Object.freeze({key: polled.source.key, version: polled.source.version, id: polled.source.id, pollHash: polled.source.pollHash})] : [];
  const hash = canonicalHash({kind: 'fabric-trigger', schemaVersion: ctx.file.schemaVersion, appId, specVersion: ctx.file.specVersion, pinnedParameters: ctx.file.pinnedParameters,
    trigger: content, transforms: Object.fromEntries(named.map(id => [id, ctx.pins[id]])), actions: Object.fromEntries(reused.map(item => [`${item.key} v${item.version}`, {id: item.id, pollHash: item.pollHash}]))});
  const id = `${appId}.trigger.${trigger.key}.v${trigger.version}.${hash.slice(0, 24)}`;
  if (ctx.stored && trigger.id !== id) fail(`${where}: id is ${trigger.id}, but its content hashes to ${id}: a changed trigger gets a new id (section 8).`);
  const unplaced = state.placements.some(placement => placement.unplaced) || polled.unplaced === true;
  return Object.freeze({key: trigger.key, version: trigger.version, id, trigger: deepFreeze(structuredClone(trigger)), placements: Object.freeze([...state.placements]), rows, unplaced,
    transforms: Object.freeze(named), rawAt: Object.freeze({...state.rawAt}), sources: Object.freeze(reused),
    reviewed: ctx.file.reviewStatus === 'reviewed' && (!polled.source || polled.source.reviewed), status: 'candidate'});
}

/** Section 8: the inputs that pick the resource, one cursor per (connection, resource): a list of required inputs, or each element of one list. */
function resourceOf(trigger, where, ctx) {
  const resource = trigger.resource, properties = trigger.inputSchema.properties, required = trigger.inputSchema.required ?? [];
  let names = [], each = null, as = null;
  if (Array.isArray(resource)) {
    if (resource.length > 8 || new Set(resource).size !== resource.length || !resource.every(name => typeof name === 'string' && Object.hasOwn(properties, name) && required.includes(name))) {
      fail(`${where}: resource lists at most 8 distinct required inputs that pick the resource (section 8).`);
    }
    names = resource;
  } else if (shaped(resource, ['each', 'as']) && typeof resource.each === 'string' && /^\/[^/~]+$/.test(resource.each) && typeof resource.as === 'string' && STEP_ID.test(resource.as)) {
    const name = resource.each.slice(1), list = properties[name];
    if (list?.type !== 'array' || !required.includes(name) || Object.hasOwn(properties, resource.as)) fail(`${where}: resource.each names a required list input, and resource.as a name that is not an input.`);
    each = resource.each;
    as = resource.as;
  } else fail(`${where}: resource is a list of input names, or {each: '/<list input>', as} (section 8).`);
  // Spec line 1674: Slack subscriptions name their channels, up to a maximum.
  if (ctx.appId === 'slack' && !(each && integer(trigger.inputSchema.properties[each.slice(1)].maxItems, 1, TRIGGER_BOUNDS.slackChannels))) {
    fail(`${where}: resource: a Slack trigger names its channels: resource is {each: '/<list input>', as} over a required list of at most ${TRIGGER_BOUNDS.slackChannels} (spec line 1674).`);
  }
  return {names, each, as};
}

// ---- delivery (section 8) ---------------------------------------------------------------------------------------------------------------
function delivery(trigger, state, ctx, where, resource) {
  const block = trigger.delivery, at = `${where}: delivery`;
  if (!record(block) || !METHODS.includes(block.method)) fail(`${at}.method is polling, webhook, watch, live or builtin (spec line 702).`);
  if (block.method === 'polling') {
    if (!shaped(block, ['method', 'intervalSeconds'])) fail(`${at}: a polling trigger holds intervalSeconds.`);
    interval(block.intervalSeconds, at);
    return null;
  }
  if (block.method === 'builtin') {
    const timed = shaped(block, ['method', 'kind', 'timeZone', 'intervalSeconds']) && integer(block.intervalSeconds, 30, 86_400);
    const cron = shaped(block, ['method', 'kind', 'timeZone', 'cron']) && typeof block.cron === 'string' && /^\S{1,32}( \S{1,32}){4}$/.test(block.cron);
    if ((!timed && !cron) || block.kind !== 'schedule' || !text(block.timeZone, 64)) fail(`${at}: a built-in schedule is {kind: 'schedule', intervalSeconds (30 to 86,400) or cron, timeZone}.`);
    return null;
  }
  if (block.method === 'live') {
    if (['register', 'teardown', 'open', 'step'].some(key => Object.hasOwn(block, key))) fail(`${at}: a live trigger holds no step: the engine opens the socket with the operator's app-level token, and apps.connections.open stays unavailable to a sign-in.`);
    if (!shaped(block, ['method', 'transport', 'fallback', 'admission'], ['alternative'])) fail(`${at}: a live trigger holds transport, admission and fallback, and may hold alternative.`);
    if (block.transport !== 'slack-socket-mode') fail(`${at}.transport is slack-socket-mode.`);
    fallback(block, at);
    admission(block.admission, 'live', `${at}.admission`, trigger, {keep: [], secret: null});
    if (block.alternative !== undefined) {
      if (!shaped(block.alternative, ['method', 'registration', 'admission']) || block.alternative.method !== 'webhook' || block.alternative.registration !== 'operator') {
        fail(`${at}.alternative is {method: 'webhook', registration: 'operator', admission}: the recorded Events API alternative.`);
      }
      admission(block.alternative.admission, 'webhook-operator', `${at}.alternative.admission`, trigger, {keep: [], secret: null});
    }
    return null;
  }
  if (block.method === 'webhook' && block.registration === 'operator') {
    if (!shaped(block, ['method', 'registration', 'fallback', 'admission'])) fail(`${at}: a webhook with registration operator holds admission and fallback, and no step: the operator sets it up in the integration's settings.`);
    fallback(block, at);
    admission(block.admission, 'webhook-operator', `${at}.admission`, trigger, {keep: [], secret: null});
    return null;
  }
  if (block.method === 'webhook') {
    if (block.registration !== 'api') fail(`${at}.registration is api or operator.`);
    if (!shaped(block, ['method', 'registration', 'fallback', 'register', 'teardown', 'admission'])) fail(`${at}: a webhook with registration api holds register, teardown, admission and fallback.`);
  } else if (!shaped(block, ['method', 'fallback', 'register', 'renew', 'teardown', 'admission'])) fail(`${at}: a watch holds register, renew, teardown, admission and fallback.`);
  fallback(block, at);
  // The register step, the values it keeps, renewal for a watch, and the teardown that reads them.
  if (!shaped(block.register, ['step', 'keep'])) fail(`${at}.register is {step, keep}.`);
  const keep = block.register.keep;
  if (!record(keep) || !Object.keys(keep).length || Object.keys(keep).length > 8 || !Object.keys(keep).every(name => KEPT_NAME.test(name))) {
    fail(`${at}.register.keep takes 1 to 8 values from the register response, each {name: pointer}: the ids a teardown, a renewal and a route read.`);
  }
  for (const [name, pointer] of Object.entries(keep)) checkPointer(pointer, `${at}.register.keep.${name}`);
  const kept = Object.keys(keep), registered = registrationStep(block.register.step, 'register', state, ctx, `${at}.register.step`, resource, kept);
  if (block.method === 'watch') renew(block.renew, `${at}.renew`, kept);
  if (!shaped(block.teardown, ['step', 'onFailure']) || block.teardown.onFailure !== 'record-leftover') fail(`${at}.teardown is {step, onFailure: 'record-leftover'}.`);
  registrationStep(block.teardown.step, 'teardown', state, ctx, `${at}.teardown.step`, resource, kept);
  admission(block.admission, block.method === 'watch' ? 'watch' : 'webhook-api', `${at}.admission`, trigger, {keep: kept, secret: registered.secret});
  return registered;
}
function interval(value, at) {
  if (!shaped(value, ['default', 'min']) || !integer(value.min, 30, 86_400) || !integer(value.default, value.min, 86_400)) {
    fail(`${at}.intervalSeconds is {default, min}: a min of 30 to 86,400 seconds and a default from min to 86,400.`);
  }
}
function fallback(block, at) {
  if (block.fallback !== 'polling') fail(`${at}.fallback is polling: every push names its polling fallback, as reviewed data (docs/MASTER-PLAN.md:249).`);
}
function renew(block, at, kept) {
  if (!shaped(block, ['lifetime', 'at', 'order', 'onMiss'])) fail(`${at} is {lifetime, at, order, onMiss}.`);
  if (shaped(block.lifetime, ['kept', 'format']) && ['epoch-ms-string', 'rfc3339'].includes(block.lifetime.format)) {
    if (!kept.includes(block.lifetime.kept)) fail(`${at}.lifetime reads the kept value ${block.lifetime.kept}, which register.keep does not take.`);
  } else if (!(shaped(block.lifetime, ['seconds']) && integer(block.lifetime.seconds, 60, 2_592_000))) fail(`${at}.lifetime is {kept, format: 'epoch-ms-string' | 'rfc3339'} or {seconds} (60 to 2,592,000).`);
  if (typeof block.at !== 'number' || !(block.at > 0 && block.at <= 0.9)) fail(`${at}.at is above 0 and at most 0.9: renewal runs before the registration lapses.`);
  if (block.order !== 'new-then-stop-old' || block.onMiss !== 'resync') fail(`${at} renews new-then-stop-old, and resyncs on a miss.`);
}

/**
 * R6: one register or teardown step. It lands on a reviewed registration member of its role; its path takes only resource inputs and
 * constants, and {kept} values only in a registration id slot; its body holds only constants, {receiver}, {secret}, {kept} and
 * {subscriptionKey}, with exactly {receiver: <appId>} at the member's destination, exactly {secret} at its secret, and exactly a kept
 * value of the register step's at each id slot. A register step reads no kept value: it makes them.
 */
function registrationStep(step, role, state, ctx, where, resource, kept) {
  const label = `${where} (${record(step) ? step.id : undefined})`;
  if (!shaped(step, ['id', 'method', 'path', 'expect'], ['params', 'body'])) fail(`${label}: a registration step holds id, method, path and expect, and may hold params and body.`);
  stepId(step, label, state);
  const members = (REGISTRATION_MEMBERS[ctx.appId] ?? []).filter(entry => entry.role === role);
  const placement = placeRegistration(step, {definition: ctx.definition, config: ctx.config, map: ctx.map, phase: role, members: members.map(entry => entry.member), where: label});
  state.placements.push(placement);
  const member = placement.unplaced ? null : members.find(entry => entry.member === memberKey(placement.member));
  const extra = {registration: true, steps: new Map()};
  const slot = (result, at, words) => {
    if (result?.kind === 'kept' && !kept.includes(result.name)) fail(`${at}: ${words} reads the kept value ${result.name}, which register.keep does not take.`);
    if (result?.kind !== 'kept') fail(`${at}: ${words} is a registration id slot: it holds exactly {kept: <name>} of a value register.keep takes, so a teardown acts only on what this subscription made (R6, T4).`);
  };
  // The path: each parameter filled once, by params or pinnedParameters.
  let segments = [];
  try { segments = parseTemplate(`${step.method} ${step.path}`).segments; } catch { segments = []; }
  const names = segments.filter(segment => segment.kind !== 'literal').map(segment => segment.name);
  const params = step.params === undefined ? {} : record(step.params) ? step.params : fail(`${label}: params maps path parameters to expressions.`);
  for (const name of names) if (!Object.hasOwn(params, name) && !Object.hasOwn(ctx.file.pinnedParameters, name)) fail(`${label}: the path parameter ${name} is filled neither by params nor by pinnedParameters.`);
  // A path id slot is the segment at its place in the member's reviewed template, whatever the step names it there: a parameter that
  // params fills, never a literal or a pinned parameter, so a teardown never stops or deletes a channel or hook the file fixed (R6, T4).
  const slots = new Map();
  for (const item of member ? member.ids.filter(entry => entry.path) : []) {
    const place = parseTemplate(placement.template).segments.findIndex(segment => segment.kind === 'param' && segment.name === item.path), own = segments[place];
    if (own?.kind !== 'param' || !Object.hasOwn(params, own.name)) {
      fail(`${label}: the registration id slot ${item.path} is a path parameter the step fills in params with exactly {kept: <name>}: never a literal, a pinned parameter or a constant (R6, T4).`);
    }
    slots.set(own.name, item.path);
  }
  for (const [name, node] of Object.entries(params)) {
    if (!names.includes(name) || Object.hasOwn(ctx.file.pinnedParameters, name)) fail(`${label}.params.${name} names no parameter of ${step.method} ${step.path} that a step fills.`);
    const result = state.expr(node, 'path', `${label}.params.${name}`, {...extra, uses: true});
    if (role === 'register' && result.sources.has('kept')) fail(`${label}: a register step reads no kept value: it makes them.`);
    if (slots.has(name)) { slot(result, `${label}.params.${name}`, slots.get(name)); continue; }
    if ([...result.sources].some(source => source !== 'constant' && source !== 'input') || [...result.inputs].some(pointer => !resource.names.includes(firstToken(pointer)))) {
      fail(`${label}.params.${name}: a registration path takes only inputs the trigger lists in resource, or constants (R6).`);
    }
  }
  let secret = null;
  if (step.body !== undefined) {
    const body = state.expr(step.body, 'body', `${label}.body`, extra), found = [...walk(body)];
    state.bodyKeys(body, `${label}.body`);
    if (role === 'register' && body.sources.has('kept')) fail(`${label}: a register step reads no kept value: it makes them.`);
    if (member) {
      if (member.destination) {
        const value = factAt(body, member.destination);
        if (value?.kind !== 'receiver' || value.name !== ctx.appId) fail(`${label}: the destination ${member.destination} holds exactly {receiver: '${ctx.appId}'}: a constant URL or an input never chooses where the owner's events go (R6, T4).`);
      }
      if (found.filter(node => node.kind === 'receiver').length !== (member.destination ? 1 : 0)) fail(`${label}: {receiver} sits only at the destination ${member.destination ?? 'of a register step'}.`);
      if (member.secret) {
        const value = factAt(body, member.secret);
        if (value?.kind !== 'secret') fail(`${label}: the secret ${member.secret} holds exactly {secret: <name>}: Fabric generates it and keeps it in the vault, and never shows it (section 8).`);
        secret = value.name;
      }
      if (found.filter(node => node.kind === 'secret').length !== (member.secret ? 1 : 0)) fail(`${label}: {secret} sits only at the secret ${member.secret ?? 'of a register step'}.`);
      for (const item of member.ids.filter(entry => entry.body)) slot(factAt(body, item.body), label, item.body);
    } else {
      // Unplaced (no map): the member is not known yet, so only the one {secret} the body sends is recorded for the admission check.
      const secrets = found.filter(node => node.kind === 'secret');
      secret = secrets.length === 1 ? secrets[0].name : null;
    }
    if ([...body.sources].some(source => !REGISTRATION_SOURCES.has(source))) fail(`${label}.body: a registration body holds only constants, {receiver}, {secret}, {kept} and {subscriptionKey}: never an input (R6).`);
  } else if (member && (member.destination || member.ids.some(entry => entry.body))) fail(`${label}: ${placement.member} takes a body with its ${member.destination ? 'destination' : 'registration ids'}.`);
  state.expect(step.expect, `${label}.expect`, {});
  return {secret};
}
function stepId(step, label, state) {
  if (typeof step.id !== 'string' || !STEP_ID.test(step.id)) fail(`${label}: a step id is 1 to 32 letters and digits, starting with a lowercase letter.`);
  if (state.ids.has(step.id)) fail(`${label}: the step id ${step.id} is used twice.`);
  state.ids.add(step.id);
}

/** How a push is let in (section 8): a scheme that fits the delivery, doorbell trust, routing only by kept ids or the signed-in identity. */
function admission(block, kind, at, trigger, {keep, secret}) {
  if (!shaped(block, ['scheme', 'trust', 'route'], ['handshake', 'header', 'prefix', 'secret', 'wake', 'collapse', 'events'])) {
    fail(`${at} is {scheme, trust, route} and may hold handshake, header, prefix, secret, wake, collapse and events.`);
  }
  if (SCHEMES[block.scheme] !== kind) fail(`${at}.scheme: ${SCHEME_WORDS[kind]} is admitted by ${listWords(Object.keys(SCHEMES).filter(scheme => SCHEMES[scheme] === kind))}.`);
  if (block.trust !== 'doorbell') fail(`${at}.trust is doorbell: a push only wakes the same cursor poll, and its payload is never stored or trusted (spec line 1657).`);
  if (block.handshake !== undefined && !HANDSHAKES.includes(block.handshake)) fail(`${at}.handshake is one of ${listWords(HANDSHAKES)}.`);
  if (block.header !== undefined && (typeof block.header !== 'string' || !HEADER_NAME.test(block.header))) fail(`${at}.header is a lowercase header name.`);
  if (block.prefix !== undefined && !text(block.prefix, 32)) fail(`${at}.prefix is 1 to 32 characters.`);
  const registered = kind === 'watch' || kind === 'webhook-api';
  if (registered && block.secret !== secret) fail(`${at}.secret is ${secret}, the {secret} the register step sends.`);
  if (kind === 'webhook-operator' && (typeof block.secret !== 'string' || !/^operator:[a-z][a-z0-9-]{0,63}$/.test(block.secret))) fail(`${at}.secret is operator:<name>, a secret the operator keeps.`);
  if (kind === 'live' && block.secret !== undefined) fail(`${at}: a socket is authenticated by the operator's app-level token: it names no secret.`);
  // Route keys come only from ids kept at registration, or from the connection's signed-in identity.
  if (registered) {
    for (const route of Array.isArray(block.route) ? block.route : [block.route]) {
      const name = shaped(route, ['header', 'equals']) && typeof route.header === 'string' && HEADER_NAME.test(route.header) && shaped(route.equals, ['kept']) ? route.equals.kept : null;
      if (!keep.includes(name) || (Array.isArray(block.route) && (!block.route.length || block.route.length > 4))) fail(`${at}.route: a push is routed only by an id kept at registration (${name ?? 'none'} is not kept) or the signed-in identity.`);
    }
  } else {
    const pointers = shaped(block.route, ['pointer', 'to']) ? [block.route.pointer] : shaped(block.route, ['pointers', 'to']) && Array.isArray(block.route.pointers) && block.route.pointers.length >= 1 && block.route.pointers.length <= 4 ? block.route.pointers : null;
    if (!pointers || block.route.to !== 'identity') fail(`${at}.route: a push is routed only by an id kept at registration or the signed-in identity: {pointer, to: 'identity'} or {pointers, to: 'identity'}.`);
    pointers.forEach((pointer, index) => checkPointer(pointer, `${at}.route.pointers[${index}]`));
  }
  if (block.wake !== undefined) {
    const test = shaped(block.wake, ['pointer', 'equals']) ? block.wake.equals : shaped(block.wake, ['pointer', 'in']) ? block.wake.in : null;
    if (!shaped(test, ['input']) || typeof test.input !== 'string' || !Object.hasOwn(trigger.inputSchema.properties, test.input.slice(1)) || !test.input.startsWith('/')) fail(`${at}.wake is {pointer, equals | in: {input}}: a push wakes only the subscription whose input it names.`);
    checkPointer(block.wake.pointer, `${at}.wake`);
  }
  if (block.collapse !== undefined) {
    if (shaped(block.collapse, ['pointer'])) checkPointer(block.collapse.pointer, `${at}.collapse`);
    else if (!(shaped(block.collapse, ['header']) && typeof block.collapse.header === 'string' && HEADER_NAME.test(block.collapse.header))) fail(`${at}.collapse is {header} or {pointer}.`);
  }
  if (block.events !== undefined && (!Array.isArray(block.events) || !block.events.length || block.events.length > 16 || !block.events.every(name => typeof name === 'string' && EVENT_NAME.test(name)))) {
    fail(`${at}.events lists 1 to 16 provider event names.`);
  }
}

// ---- the poll (section 8; part h's cursor rules) ----------------------------------------------------------------------------------------
/** One read step of the trigger (poll, seed or enrich): the action step rules, in a trigger scope (lib/actions.mjs ActionState). */
function readStep(step, phase, label, state) {
  if (!shaped(step, ['id', 'method', 'path', 'expect'], READ_STEP_FIELDS)) {
    fail(`${state.where}: ${label} (${record(step) ? step.id : undefined}): a trigger's read step holds id, method, path and expect, and may hold ${listWords(READ_STEP_FIELDS)}.`);
  }
  stepId(step, `${state.where}: ${label} (${step.id})`, state);
  state.step({step, phase, label});
}
/** A poll of the trigger's own read steps: the last is the poll step, whose list the items read; part h's cursor rules; seed and enrich. */
function ownPoll(trigger, state, ctx, where) {
  const poll = trigger.poll, at = `${where}: poll`;
  if (!shaped(poll, OWN_POLL, ['itemTime', 'seed', 'enrich'])) fail(`${at} is {${OWN_POLL.join(', ')}} and may hold itemTime, seed and enrich, or {source: {action, args}} (section 8).`);
  const steps = poll.source.steps;
  if (!shaped(poll.source, ['steps']) || !steps.length || steps.length > 3) fail(`${at}.source is {steps: [1 to 3 read steps]}, or {action, args} (section 8).`);
  steps.forEach((step, index) => readStep(step, 'poll', `poll.source.steps[${index}]`, state));
  const id = steps.at(-1).id, pollStep = state.stepsOf.get(id);
  // The items: the list the poll step reads (open point Important 5: a paged step's data is its pages' lists joined).
  const items = state.expr(poll.items, 'poll', `${at}.items`);
  if (!items.steps.has(id)) fail(`${at}.items reads ${id}, the poll step: the items a poll sees are the list its last step reads.`);
  if (items.type !== null && items.type.type !== 'array') fail(`${at}.items is a list.`);
  const item = {from: 'poll', list: items};
  // Each item's id, version and time (open point Important 4: the poll-item scope).
  const itemId = state.expr(poll.itemId, 'poll', `${at}.itemId`, {item, steps: new Map()});
  if (itemId.type !== null && !['string', 'integer'].includes(itemId.type.type)) fail(`${at}.itemId is a string or an integer.`);
  if (![...walk(itemId)].some(node => node.kind === 'item')) fail(`${at}.itemId reads the poll item: each item's id comes from the item, so two items never share one (section 8).`);
  if (itemId.sources.has('clock') || itemId.sources.has('jobKey')) fail(`${at}.itemId never reads the clock or a job key: an item keeps its id from one poll to the next, so each change is stored once (section 8).`);
  if (poll.itemVersion !== null) checkPointer(poll.itemVersion, `${at}.itemVersion`);
  if (poll.itemTime !== undefined) {
    if (!shaped(poll.itemTime, ['pointer', 'format']) || !Object.hasOwn(ITEM_TIME_FORMATS, poll.itemTime.format)) fail(`${at}.itemTime is {pointer, format}, in one of the formats ${listWords(Object.keys(ITEM_TIME_FORMATS))}.`);
    checkPointer(poll.itemTime.pointer, `${at}.itemTime`);
    state.pollTransforms.add(ITEM_TIME_FORMATS[poll.itemTime.format]);
  }
  if (!['asc', 'desc', 'unordered'].includes(poll.order)) fail(`${at}.order is asc, desc or unordered.`);
  // Cursors (part h): versioned kinds, never an input, next values from the poll step's answer, one slot each in the poll step.
  if (!Array.isArray(poll.cursors) || !poll.cursors.length || poll.cursors.length > 4) fail(`${at}.cursors holds 1 to 4 cursors.`);
  const block = {step: id, cursors: poll.cursors, itemTime: poll.itemTime}, names = new Set();
  poll.cursors.forEach((cursor, index) => state.cursor(cursor, `${at}.cursors[${index}]`, {poll: block, step: pollStep, names}));
  state.cursorSlots(block);
  if (!shaped(poll.resync, ['statusIn']) || !Array.isArray(poll.resync.statusIn) || new Set(poll.resync.statusIn).size !== poll.resync.statusIn.length || !poll.resync.statusIn.every(code => code === 404 || code === 410)) {
    fail(`${at}.resync is {statusIn}, holding 404, 410, both or neither.`);
  }
  if (!integer(poll.minIntervalSeconds, 30, 86_400)) fail(`${at}.minIntervalSeconds is 30 to 86,400 (I7).`);
  // The seed read gives a cursor its first value at subscribe time; enrich reads run once per item, for at most `max` items.
  if (poll.seed !== undefined) {
    if (!shaped(poll.seed, ['step', 'cursor']) || !shaped(poll.seed.cursor, ['name', 'pointer'])) fail(`${at}.seed is {step, cursor: {name, pointer}}.`);
    readStep(poll.seed.step, 'seed', 'poll.seed.step', state);
    if (!names.has(poll.seed.cursor.name)) fail(`${at}.seed.cursor.name names ${poll.seed.cursor.name}, which is not a cursor of the poll.`);
    checkPointer(poll.seed.cursor.pointer, `${at}.seed.cursor`);
  }
  if (poll.enrich !== undefined) {
    if (!shaped(poll.enrich, ['max', 'steps']) || !integer(poll.enrich.max, 1, 25) || !Array.isArray(poll.enrich.steps) || !poll.enrich.steps.length || poll.enrich.steps.length > 3) {
      fail(`${at}.enrich is {max, steps}: 1 to 3 read steps, run for at most 1 to 25 items (I7).`);
    }
    state.enrichItem = item;
    poll.enrich.steps.forEach((step, index) => readStep(step, 'enrich', `poll.enrich.steps[${index}]`, state));
    state.enrichItem = null;
  }
  // I07 section 2.6: what the filter, dedupe.fields and the event may read by id, beside the item. The poll and seed steps stay out of it.
  const enriched = new Map((poll.enrich?.steps ?? []).map(step => [step.id, {source: 'perform-read', skippable: false}]));
  return {item, itemVersion: poll.itemVersion, steps, source: null, enriched};
}
/** A poll that reuses a read action's poll block: the action, its arguments, and the item its output lists. */
function actionPoll(trigger, state, ctx, where) {
  const poll = trigger.poll, at = `${where}: poll`;
  if (!shaped(poll, ['source']) || !shaped(poll.source, ['action', 'args']) || !shaped(poll.source.action, ['key', 'version']) || !record(poll.source.args)) {
    fail(`${at} is {source: {action, args}} for a trigger that reuses a read action: its poll block holds the rest (section 8).`);
  }
  const {key, version} = poll.source.action;
  const file = ctx.actionFile, entry = file ? validateActionFile(file, ctx.deps).actions.find(item => item.key === key && item.version === version) : undefined;
  if (!entry) fail(`${at}.source.action names ${key} v${version}, which ${ctx.appId}'s action file does not hold.`);
  if (entry.effect !== 'read' || entry.pollHash === null) fail(`${at}.source.action: ${key} v${version} is not a read action with a poll block (section 8).`);
  const action = entry.action, properties = action.inputSchema.properties;
  for (const [name, node] of Object.entries(poll.source.args)) {
    if (!Object.hasOwn(properties, name)) fail(`${at}.source.args.${name} names no input of ${key} v${version}.`);
    const result = state.expr(node, 'poll', `${at}.source.args.${name}`, {uses: true, steps: new Map()});
    if (result.value !== undefined) {
      try { validateValue(properties[name], result.value, '$value'); } catch { fail(`${at}.source.args.${name}: the constant does not fit ${key} v${version}'s ${name}.`); }
    } else if (!fits(result.type, properties[name])) fail(`${at}.source.args.${name}: its type does not fit ${key} v${version}'s ${name}.`);
  }
  for (const name of action.inputSchema.required ?? []) if (!Object.hasOwn(poll.source.args, name)) fail(`${at}.source.args: ${key} v${version} needs ${name}.`);
  // The item: an element of the list the action's poll.items points at in its closed output schema, with the provenance of a read.
  const list = schemaAt(action.outputSchema, checkPointer(action.poll.items, `${at}.source.action`));
  const read = state.expr({step: 'source', pointer: ''}, 'poll', `${at}.source.action`, {steps: new Map([['source', {source: 'perform-read'}]])});
  return {item: {from: 'poll', list: {...read, type: list}}, itemVersion: action.poll.itemVersion, steps: [], enriched: new Map(), unplaced: entry.unplaced, placements: entry.placements,
    source: {key, version, id: entry.id, pollHash: entry.pollHash, reviewed: file.reviewStatus === 'reviewed', resourceKey: action.poll.resourceKey}};
}
/** R6: each resource input, and the variable resource.each binds, is read by a poll step's path or query, or by an argument the reused action keys its cursor on. */
function resourceRead(trigger, polled, where, resource) {
  const read = polled.source
    ? Object.entries(trigger.poll.source.args).filter(([name]) => polled.source.resourceKey.includes(name)).map(([, node]) => node)
    : polled.steps.flatMap(step => [...Object.values(record(step.params) ? step.params : {}), ...Object.values(record(step.query) ? step.query : {})]);
  const found = [...nodes(read)];
  for (const name of resource.names) {
    if (!found.some(node => typeof node.input === 'string' && node.input.startsWith('/') && firstToken(node.input) === name)) {
      fail(`${where}: resource: ${name} is read by no poll step: a registration targets exactly the resource the owner's read rows let the trigger poll (R6).`);
    }
  }
  if (resource.as && !found.some(node => node.var === resource.as)) fail(`${where}: resource: ${resource.as}, which resource.each binds, is read by no poll step (section 8).`);
}

// ---- the item, the event and the limits ------------------------------------------------------------------------------------------------
function dedupe(trigger, state, where, polled) {
  const block = trigger.dedupe;
  if (!record(block) || !['id', 'id+version', 'content-hash'].includes(block.kind) || !shaped(block, ['kind'], block.kind === 'content-hash' ? ['fields', 'knownBy'] : [])) fail(`${where}: dedupe is {kind: 'id' | 'id+version'} or {kind: 'content-hash', fields}.`);
  if (block.kind === 'id+version' && polled.itemVersion === null) fail(`${where}: dedupe: id+version needs an itemVersion, and the poll's is null.`);
  if (block.kind === 'content-hash') {
    if (!Array.isArray(block.fields) || !block.fields.length || block.fields.length > 8) fail(`${where}: dedupe.fields holds 1 to 8 expressions over the item.`);
    block.fields.forEach((node, index) => state.expr(node, 'poll', `${where}: dedupe.fields[${index}]`, {item: polled.item, steps: polled.enriched}));
    if (block.knownBy !== undefined) knownBy(block.knownBy, state, where, polled);
  }
}
/**
 * I07 section 2.6: how a content-hash trigger tells a change from a new item, since Google gives no change kind. The first present value
 * must already have a seen row, so a create stays silent. A key is looked up again on every poll, so it holds to what an item id holds to,
 * and it is read before any enrich step runs.
 */
function knownBy(list, state, where, polled) {
  if (!Array.isArray(list) || !list.length || list.length > 2) fail(`${where}: dedupe.knownBy holds 1 or 2 expressions over the item.`);
  list.forEach((node, index) => {
    const at = `${where}: dedupe.knownBy[${index}]`, key = state.expr(node, 'poll', at, {item: polled.item, steps: new Map()});
    if (key.type !== null && !['string', 'integer'].includes(key.type.type)) fail(`${at} is a string or an integer.`);
    if (![...walk(key)].some(part => part.kind === 'item')) fail(`${at} reads the poll item: an item is known by a value of its own (section 2.6).`);
    if (key.sources.has('clock') || key.sources.has('jobKey')) fail(`${at} never reads the clock or a job key: a seen row is found again by the same value on every poll (section 2.6).`);
  });
}
function event(trigger, state, where, polled) {
  const block = trigger.event, item = {item: polled.item, steps: polled.enriched};
  if (!shaped(block, ['schema', 'id', 'occurredAt', 'fields', 'summary'])) fail(`${where}: event is {schema, id, occurredAt, fields, summary}.`);
  try { checkSchema(block.schema, '$event'); } catch (error) { fail(`${where}: event.schema: ${error.message}`); }
  if (block.schema.type !== 'object') fail(`${where}: event.schema is a closed object schema.`);
  const size = worstBytes(block.schema);
  if (size > TRIGGER_BOUNDS.eventBytes) fail(`${where}: event.schema: a worst-case event is ${size === Infinity ? 'unbounded' : `${bytes(size)} bytes`}; at most 8,192 (spec line 1687).`);
  for (const [field, words] of [['id', 'event.id'], ['occurredAt', 'event.occurredAt']]) {
    const result = state.expr(block[field], 'poll', `${where}: ${words}`, item);
    if (result.type !== null && !['string', 'integer'].includes(result.type.type)) fail(`${where}: ${words} is a string or an integer.`);
  }
  const properties = block.schema.properties;
  if (!record(block.fields) || Object.keys(block.fields).sort().join() !== Object.keys(properties).sort().join()) fail(`${where}: event.fields names exactly the properties of event.schema: ${listWords(Object.keys(properties))}.`);
  for (const [name, node] of Object.entries(block.fields)) {
    const at = `${where}: event.fields.${name}`;
    eventValue(state.expr(node, 'poll', at, {...item, member: true}), properties[name], at);
  }
  if (!Array.isArray(block.summary) || block.summary.length > 8) fail(`${where}: event.summary holds at most 8 lines.`);
  block.summary.forEach((line, index) => {
    const at = `${where}: event.summary[${index}]`;
    if (!shaped(line, ['label', 'expr'], ['truncate']) || !text(line.label, 80) || (line.truncate !== undefined && !integer(line.truncate, 1, 1_000))) fail(`${at} is {label, expr} and may hold truncate: a label of 1 to 80 characters, and 1 to 1,000 characters shown.`);
    const result = state.expr(line.expr, 'poll', `${at} (${line.label})`, item);
    if (result.type !== null && !['string', 'integer', 'number'].includes(result.type.type)) fail(`${at} (${line.label}): a summary line shows a string or a number.`);
  });
}
/** I6, I9: a raw step-data value in an event field sits at a scalar of event.schema (the engine checks the event against it); a known type is the field's. */
function eventValue(result, schema, at) {
  const raw = result.raw && ['step', 'item', 'var', 'pick'].includes(result.kind);
  if (raw && !['string', 'integer', 'number', 'boolean'].includes(schema?.type)) fail(`${at}: copies step data whole: a raw step-data value sits only at a string, integer, number or boolean of event.schema, and this one sits at ${an(schema?.type ?? 'undeclared field')} ${schema?.type ?? 'undeclared field'} (I6, I9).`);
  if (result.kind === 'object') for (const [key, member] of result.members) eventValue(member, schema?.type === 'object' ? schema.properties[key] : undefined, `${at}.${key}`);
  if (result.kind === 'when') eventValue(result.then, schema, at);
  if (!raw && result.type !== null && schema && result.type.type !== schema.type && !(result.type.type === 'integer' && schema.type === 'number')) fail(`${at} is ${an(result.type.type)} ${result.type.type}, and event.schema declares ${an(schema.type)} ${schema.type}.`);
}
function limits(trigger, state, where, ctx) {
  const {backfill, retention, bounds} = trigger;
  if (!shaped(backfill, ['default', 'max']) || backfill.default !== 0 || !integer(backfill.max, 0, TRIGGER_BOUNDS.backfill)) fail(`${where}: backfill is {default: 0, max}, with a max of 0 to 25: a subscription starts with no backfill unless the owner asks (section 8).`);
  const days = shaped(retention, ['days']) && integer(retention.days, 1, 7), hours = shaped(retention, ['hours']) && integer(retention.hours, 1, 24);
  if (ctx.appId === 'slack' && !hours) fail(`${where}: retention: Slack events are kept at most 24 hours: {hours: 1 to 24} (spec line 1676).`);
  if (!days && !hours) fail(`${where}: retention is {days: 1 to 7} or {hours: 1 to 24} (spec line 1676).`);
  if (!shaped(bounds, ['pages', 'items', 'pollSeconds']) || !integer(bounds.pages, 1, TRIGGER_BOUNDS.pages) || !integer(bounds.items, 1, TRIGGER_BOUNDS.items) || !integer(bounds.pollSeconds, 1, TRIGGER_BOUNDS.pollSeconds)) {
    fail(`${where}: bounds is {pages, items, pollSeconds}: at most 10 pages, 500 items and 10 seconds per poll (spec lines 1681-1682).`);
  }
  for (const [index, step] of (record(trigger.poll?.source) && Array.isArray(trigger.poll.source.steps) ? trigger.poll.source.steps : []).entries()) {
    if (step.page && step.page.max > bounds.pages) fail(`${where}: poll.source.steps[${index}] (${step.id}) pages up to ${step.page.max} times, past bounds.pages ${bounds.pages}.`);
  }
}
/** The declared rows equal the read rows the poll, seed and enrich steps (or the reused action's steps) land in; null while any is unplaced. */
function rowsOf(trigger, state, where, ctx, polled) {
  const declared = trigger.rows, reads = new Set(ctx.definition.groups.filter(group => group.effect === 'read').map(group => group.id));
  if (!Array.isArray(declared) || !declared.length || new Set(declared).size !== declared.length || !declared.every(id => reads.has(id))) fail(`${where}: rows lists the distinct read rows the trigger's poll, seed and enrich steps land in.`);
  const placements = polled.source ? polled.placements : state.placements.filter(placement => ['poll', 'seed', 'enrich'].includes(placement.phase));
  if (polled.unplaced || placements.some(placement => placement.unplaced)) return null;
  const computed = [...new Set(placements.map(placement => placement.groupId))].sort();
  if ([...declared].sort().join() !== computed.join()) fail(`${where}: rows lists ${listWords(declared)}, and its poll, seed and enrich steps land in ${listWords(computed)}.`);
  return Object.freeze(computed);
}

// ---- feeds and lenses (docs/I07-BUILD-MAP.md sections 2.1 and 2.2) ------------------------------------------------------------------------
/** A copy of a part of a trigger with each resource value written {resource: <index>}, so two triggers that send the same request match. A constant is data, and stays as written. */
function bound(value, resource) {
  if (Array.isArray(value)) return value.map(part => bound(part, resource));
  if (!record(value) || Object.hasOwn(value, 'const')) return value;
  const at = !shaped(value, ['input']) && !shaped(value, ['var']) ? -1 : Array.isArray(resource) ? resource.findIndex(name => value.input === `/${name}`) : value.var === resource.as ? 0 : -1;
  return at === -1 ? Object.fromEntries(Object.entries(value).map(([key, part]) => [key, bound(part, resource)])) : {resource: at};
}
/**
 * The key of the poll a trigger runs: triggers with one key share one feed per resource value, which gives the 24 polls of the 35 drafts.
 * It hashes what the poll sends and how its cursor walks, bound by bound(), with the pin of each transform those name, and for a poll that
 * reuses an action, that action's id and poll hash. What an item becomes is the lens's, not the poll's. It stays out of the trigger id.
 */
export function triggerPollHash(file, entry, pins) {
  const {trigger, sources, transforms} = entry, {poll, resource} = trigger, named = new Set(poll.itemTime ? [ITEM_TIME_FORMATS[poll.itemTime.format]] : []);
  const read = {source: poll.source, seed: poll.seed ?? null, cursors: poll.cursors ?? null, resync: poll.resync ?? null, order: poll.order ?? null, itemTime: poll.itemTime ?? null};
  for (const node of nodes(read)) {
    for (const id of [node.transform, node.compare]) if (typeof id === 'string') named.add(id);
    if (node.link === 'next') named.add('ids.linkPage@1');
  }
  return canonicalHash({kind: 'fabric-trigger-poll', appId: file.appId, pinnedParameters: file.pinnedParameters, ...bound(read, resource), actions: sources,
    transforms: Object.fromEntries(transforms.filter(id => named.has(id)).map(id => [id, pins[id]]))});
}
/**
 * The fields that say how a trigger reads a feed, and the inputs outside its resource those read: its lens differs by their values alone. A feed
 * holds one resource value, so only an input of a resource list is fixed there. The list behind {each} is not: a feed is one element of it, and
 * two subscriptions that share that element can hold different lists.
 */
function lensParts(trigger) {
  const {poll, resource} = trigger, inside = Array.isArray(resource) ? resource : [];
  const parts = {items: poll.items ?? null, itemId: poll.itemId ?? null, itemVersion: poll.itemVersion ?? null, filter: trigger.filter ?? null, dedupe: trigger.dedupe, enrich: poll.enrich ?? null};
  const read = [...nodes(parts)].filter(node => shaped(node, ['input']) && typeof node.input === 'string').map(node => firstToken(node.input));
  return {parts: bound(parts, resource), inputs: [...new Set(read)].filter(name => !inside.includes(name)).sort()};
}
/** Section 2.2: how one trigger reads one feed. `args` are a subscription's: only an input outside the resource that lensParts() found moves it. */
export function triggerLens(entry, args = {}) {
  const {parts, inputs} = lensParts(entry.trigger);
  return canonicalHash({kind: 'fabric-trigger-lens', ...parts, values: Object.fromEntries(inputs.map(name => [name, args[name] ?? null]))}).slice(0, 16);
}
/** The lens a trigger gives with no subscription, for a feed to track from its baseline: none when its lens hangs on a subscription's input. */
export function triggerLenses(entry) {
  return lensParts(entry.trigger).inputs.length ? [] : [triggerLens(entry)];
}
/**
 * The inputs a trigger's poll reads beyond its resource. A feed holds one resource value, so two subscriptions with different values of such an input would share
 * one feed and one request, and only one of them would be read. The format allows it and no draft does it, so the scheduler refuses it at attach(). A read below a resource input
 * is the feed's own value: bound() rewrites only a whole input, and Gmail's search is an object, read part by part.
 */
export function triggerPollInputs(entry) {
  const {poll, resource} = entry.trigger, read = bound({source: poll.source, seed: poll.seed ?? null, cursors: poll.cursors ?? null, resync: poll.resync ?? null}, resource);
  const own = new Set(Array.isArray(resource) ? resource : []);
  return [...new Set([...nodes(read)].filter(node => shaped(node, ['input']) && typeof node.input === 'string').map(node => firstToken(node.input)))].filter(name => !own.has(name)).sort();
}

// ---- run time ---------------------------------------------------------------------------------------------------------------------------
/** What a value is, in the words of a refusal. */
const kindOf = value => value === null ? 'null' : Array.isArray(value) ? 'a list' : typeof value === 'object' ? 'an object' : typeof value === 'boolean' ? 'a boolean' : `a ${typeof value}`;
/**
 * I6, I9 (section 8): one poll item as I07's engine built it, before it stores or shows any of it: {itemId, id, occurredAt, fields,
 * summary}. The item id, the event id and its time are each a string or an integer; the fields fit the closed event.schema, whose worst
 * case validateTriggerFile() holds to 8,192 bytes; each summary line is a string or a number, or absent. So a raw item value the file
 * placed in any of them is never a whole provider object or list, as checkOutput() and checkPreview() hold an action's. `trigger` is
 * the trigger as written, or an entry validateTriggerFile() returned. Returns the event.
 */
export function checkEvent(trigger, event) {
  const own = record(trigger?.trigger) ? trigger.trigger : trigger;
  if (!record(own?.event) || !Array.isArray(own.event.summary)) fail('checkEvent() takes a trigger, or an entry validateTriggerFile() returned.');
  const at = `${own.key} v${own.version}`;
  if (!shaped(event, ['itemId', 'id', 'occurredAt', 'fields', 'summary'])) fail(`${at}: an event is {itemId, id, occurredAt, fields, summary}.`);
  for (const [field, words, what] of [['itemId', 'the item id', 'an item id'], ['id', 'event.id', 'an event id'], ['occurredAt', 'event.occurredAt', 'an event time']]) {
    const value = event[field];
    if (typeof value !== 'string' && !Number.isSafeInteger(value)) fail(`${at}: ${words} is ${kindOf(value)}: ${what} is a string or an integer (I6, I9).`);
  }
  try { validateValue(own.event.schema, event.fields, '$event'); } catch (error) { fail(`${at}: event.fields does not fit event.schema (${error.message}).`); }
  const lines = own.event.summary;
  if (!Array.isArray(event.summary) || event.summary.length !== lines.length) fail(`${at}: checkEvent() takes one value per summary line: ${lines.length}, not ${Array.isArray(event.summary) ? event.summary.length : 0}.`);
  event.summary.forEach((value, index) => {
    if (value === undefined || typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))) return;
    fail(`${at}: event.summary[${index}] (${lines[index].label}) is ${kindOf(value)}: a summary line shows a string or a number (I6, I9).`);
  });
  return event;
}

// F10.9 part d (docs/F10.9-BUILD-MAP.md part d; R1, R2, R11 and R14; open points Important 4 and Minor 7): the one closed expression
// grammar that action and trigger files share. checkExpression() and checkTest() read a node at a position the caller describes (its
// scope) and return a fact about it: its type, its provenance (the sources it reads), the inputs, steps, cursors and transforms it
// reads, the exclusions that survive to it and its node count. checkCall() reads a guard, or a resolved input's derive, the same way.
// Nothing here runs a transform, reads a store or sends a request. Parts e to k build their rules on the facts, and F10.10's
// readsOnly() reads them to say whether a step is built from reads.
//
// A node is an object with exactly one grammar key and its named fields:
//   {const}, {input}, {step, pointer}, {step, header}, {item}, {pick, pointer}, {each, as, do, max}, {var}, {account},
//   {transform, args}, {object}, {array}, {concat, max}, {when, then}, {either}, {now: {}}, {jobKey}, {cursor}, {resolved},
//   and, in a trigger's register, renew and teardown steps only, {receiver}, {secret}, {kept} and {subscriptionKey}.
// A test is {present}, {absent}, {nonEmpty}, {equals: [expr, {const}]}, {status: {step, in}} or {anyOf: [test]}, at most 2 deep.
//
// A scope says where the expression sits and what it may read:
//   slot           path, query, header, body, guard, when, forEach, output, preview, assert or poll;
//   where          the label each refusal starts with;
//   transforms     the transform registry (F10.8's TRANSFORMS unless a test passes its own);
//   inputSchema    the closed input schema; resolvedInputs, the names of its resource-dependent inputs (section 9);
//   identity       the app's reviewed identity definition (the identity block of catalog/auth/<provider>.json), for {account};
//   steps          a Map of the steps that ran before this point, id to {source, skippable}. The source is what the step's data is:
//                  prepare, schema, perform-read, perform-write, resolving or verify. A step is skippable when it is optional, has a
//                  when, or is a forEach that may run zero times. Part f builds this per position;
//   item           {from: 'forEach' | 'poll', list}: the fact of the list whose element {item} reads, inside a forEach step or in a
//                  poll item field (POLL_ITEM_FIELDS, open point Important 4);
//   vars           a Map of the names a trigger's resource.as binds, name to the fact of the list;
//   cursors        the cursor names a read action's poll step may read here (part h);
//   member         true when the expression is a member of an object the caller builds (an output or event field), so a {when}
//                  may leave it out;
//   trigger, registration   a trigger file, and its register, renew or teardown steps (part k);
//   budget         a node counter from newBudget(), shared by the expressions of one action, so together they hold at most 2,000.
import {canonicalHash, validateValue} from './compiler.mjs';
import {secretKey} from './redaction.mjs';
import {TRANSFORMS} from './transforms/index.mjs';

/** Grammar depth, counting grammar nodes and the levels inside a constant alike (I7). */
export const MAX_DEPTH = 16;
/** Nodes per action, counting every node inside a constant and an {each} as max times its do (I7). */
export const MAX_NODES = 2_000;
/** The largest {each}.max. */
export const MAX_EACH = 100;
/** The largest {concat}.max, in characters. */
export const MAX_CONCAT = 65_536;
const MAX_CONST_DEPTH = 8, MAX_CONST_BYTES = 16_384, MAX_CONST_STRING = 4_096, MAX_POINTER_TOKENS = 32;

/** The positions an expression can sit in. */
export const SLOTS = Object.freeze(['path', 'query', 'header', 'body', 'guard', 'when', 'forEach', 'output', 'preview', 'assert', 'poll']);
const REQUEST_SLOTS = new Set(['path', 'query', 'header', 'body']);
const CURSOR_SLOTS = new Set(['query', 'header', 'body']);
/** What a step's answer is, as part f names it per step. */
export const STEP_SOURCES = Object.freeze(['prepare', 'schema', 'perform-read', 'perform-write', 'resolving', 'verify']);
/** Every source a fact can carry. {item} and {var} have none of their own: each carries the sources of the list it iterates. */
export const SOURCES = Object.freeze(['constant', 'input', 'account', 'clock', 'jobKey', 'cursor', 'resolved', ...STEP_SOURCES, 'receiver', 'secret', 'kept', 'subscriptionKey']);
/**
 * What a perform step's path, query, headers, body, forEach.over, page and when may read, directly or through transforms, pick, each,
 * object, array, concat, when and either (part f; R2; open question 41). Each exists, and can be shown, before the owner approves the
 * perform bytes (T5): the clock is read once when they are built, a cursor only in a read action's poll step, and the one resolving
 * step's answer only after its own approval.
 */
export const PERFORM_SOURCES = Object.freeze(['constant', 'input', 'account', 'jobKey', 'prepare', 'schema', 'resolved', 'clock', 'cursor', 'resolving']);
/**
 * F10.10 (I5): the sources a reviewed-read POST may read and still count as a read, besides the answers of earlier steps, which
 * readsOnly() judges by step id. A job key is left out on purpose: it is new for every job, so it marks a request that makes something.
 * So are the four registration names (receiver, secret, kept, subscriptionKey): they belong to a trigger's own subscription, never a read.
 */
export const READ_SOURCES = Object.freeze(['constant', 'input', 'account', 'clock', 'cursor', 'resolved']);
/**
 * F10.10 (I5): true when a fact reads only READ_SOURCES and step answers, and every step it reads passes `stepIsRead`. A step's answer
 * is judged by its step id alone, never by its source label, which is what makes the rule transitive: a verify read of the id a write
 * made is not built from reads, and neither is anything that reads it.
 */
export function readsOnly(fact, stepIsRead) {
  return [...fact.sources].every(source => READ_SOURCES.includes(source) || STEP_SOURCES.includes(source)) && [...fact.steps].every(id => stepIsRead(id));
}
const HEADER_SOURCES = new Set(['constant', 'prepare', 'cursor']);
const SOURCE_WORDS = Object.freeze({'perform-read': 'another perform step\'s answer', 'perform-write': 'a write step\'s answer', verify: 'a verify step\'s answer',
  receiver: 'Fabric\'s receiver', secret: 'a subscription secret', kept: 'a kept registration value', subscriptionKey: 'a subscription key'});
/** The response headers an expression may read. F10.11's requester keeps every one of them (open point Minor 7). */
export const STEP_HEADERS = Object.freeze(['etag', 'last-modified', 'link', 'location', 'retry-after']);
const REQUEST_ONLY_HEADERS = new Set(['link', 'location']);
/** The fields of the connection's verified identity {account} reads, each only when the app's reviewed identity yields it. */
export const ACCOUNT_FIELDS = Object.freeze(['id', 'email', 'workspaceId', 'userId']);
// The types F10.11 holds each account value to before any call; an address is at most 254 characters (lib/actions-runtime.mjs).
export const ACCOUNT_TYPES = deepFreeze({id: {type: 'string', minLength: 1, maxLength: 1000}, email: {type: 'string', minLength: 3, maxLength: 254},
  workspaceId: {type: 'string', minLength: 1, maxLength: 1000}, userId: {type: 'string', minLength: 1, maxLength: 1000}});
const NOW_TYPE = deepFreeze({type: 'integer', minimum: 0, maximum: 8_640_000_000_000_000});
const JOB_KEY_TYPE = deepFreeze({type: 'string', minLength: 32, maxLength: 32});
/** The poll fields that read the poll item with {item}, the poll-item scope (open point Important 4). Parts h and k set scope.item there. */
export const POLL_ITEM_FIELDS = Object.freeze(['itemId', 'filter', 'event.id', 'event.occurredAt', 'event.fields', 'event.summary', 'dedupe.fields']);
/** The nodes only a trigger's registration steps read (section 8). */
export const REGISTRATION_NAMES = Object.freeze(['receiver', 'secret', 'kept', 'subscriptionKey']);

const NAME = /^[a-z][A-Za-z0-9]{0,31}$/;
const KEY_NAME = /^[a-z][A-Za-z0-9-]{0,63}$/;
const INDEX = /^(?:0|[1-9][0-9]*)$/;
const UNSAFE = new Set(['__proto__', 'prototype', 'constructor']);
const PICKABLE = new Set(['transform', 'step', 'item', 'var', 'pick']);
const STEP_DATA_KINDS = new Set(['step', 'pick', 'item', 'var']);
const SHAPES = new Map([
  ['const', [['const']]], ['input', [['input']]], ['step', [['step', 'pointer'], ['step', 'header']]], ['item', [['item']]], ['pick', [['pick', 'pointer']]],
  ['each', [['each', 'as', 'do', 'max']]], ['var', [['var']]], ['account', [['account']]], ['transform', [['transform', 'args']]], ['object', [['object']]],
  ['array', [['array']]], ['concat', [['concat', 'max']]], ['when', [['when', 'then']]], ['either', [['either']]], ['now', [['now']]], ['jobKey', [['jobKey']]],
  ['cursor', [['cursor']]], ['resolved', [['resolved']]], ['receiver', [['receiver']]], ['secret', [['secret']]], ['kept', [['kept']]], ['subscriptionKey', [['subscriptionKey']]]]);
const TEST_SHAPES = new Map([['present', [['present']]], ['absent', [['absent']]], ['nonEmpty', [['nonEmpty']]], ['equals', [['equals']]], ['status', [['status']]], ['anyOf', [['anyOf']]]]);

const fail = message => { throw new Error(message); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const passes = check => { try { check(); return true; } catch { return false; } };
const exactly = (value, names) => record(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const same = (a, b) => canonicalHash([a]) === canonicalHash([b]);
const fromSteps = sources => [...sources].some(source => STEP_SOURCES.includes(source));
function deepFreeze(value) {
  if (value !== null && typeof value === 'object') { Object.freeze(value); for (const item of Object.values(value)) deepFreeze(item); }
  return value;
}

/** A fresh node counter for the expressions of one action. */
export const newBudget = () => ({nodes: 0});

// ---- facts -------------------------------------------------------------------------------------------------------------------------
// A fact: {kind, type, keyed, value?, optional, raw, data, sources, inputs, steps, cursors, transforms, excludes, nodes} plus what its
// kind holds (members, items, args, then, test, list, do, operand, tests). `type` is a closed schema, or null when only the run time
// knows it (step data). `keyed` marks an outputFrom or outputMap result. `raw` marks a raw step-data value: a {step, pointer}, or an
// {item}, {var} or {pick} whose type is unknown and whose sources hold step data. `data` marks a value that is exactly what a step
// answered: a {step}, or a {pick}, {item} or {var} of unknown type whose base, or whose list, is itself one. A built object or list, a
// transform result and an {either} never are, and neither is any element of one (F10.8 open point Minor 14). `excludes` are the values
// the whole fact, or a field of it, never holds, as F10.8's entries declare them ({pointer, items, values, fold}).
function fact(kind, fields = {}) {
  return {kind, type: null, keyed: null, optional: false, raw: false, data: false, sources: new Set(), inputs: new Set(), steps: new Set(), cursors: new Set(),
    transforms: new Set(), excludes: [], nodes: 1, ...fields};
}
/** Adds what each child reads, and its nodes, to `target`. */
function absorb(target, ...children) {
  for (const child of children) {
    for (const key of ['sources', 'inputs', 'steps', 'cursors', 'transforms']) for (const value of child[key]) target[key].add(value);
    target.nodes += child.nodes;
  }
  return target;
}
const isFact = value => record(value) && value.sources instanceof Set && value.steps instanceof Set && Array.isArray(value.excludes);

// ---- types -------------------------------------------------------------------------------------------------------------------------
/** The exact type of a constant: a scalar is its own enum. A list's items are left to the value check. */
function constType(value) {
  if (typeof value === 'string') { const length = [...value].length; return {type: 'string', enum: [value], minLength: length, maxLength: length}; }
  if (typeof value === 'number') return {type: Number.isSafeInteger(value) ? 'integer' : 'number', enum: [value], minimum: value, maximum: value};
  if (typeof value === 'boolean') return {type: 'boolean', enum: [value]};
  if (value === null) return {type: 'null'};
  if (Array.isArray(value)) return {type: 'array', minItems: value.length, maxItems: value.length, items: null};
  return {type: 'object', properties: Object.fromEntries(Object.entries(value).map(([key, item]) => [key, constType(item)])), required: Object.keys(value), additionalProperties: false};
}
/** True for a schema with no unknown (null) part. */
function complete(schema) {
  if (!record(schema)) return false;
  if (schema.type === 'array') return complete(schema.items);
  if (schema.type === 'object') return record(schema.properties) && Object.values(schema.properties).every(complete);
  return true;
}
/** The schema at a pointer's tokens: {found, type}. Below an unknown (null) part everything is found and unknown. */
function schemaAt(schema, tokens) {
  let current = schema;
  for (const token of tokens) {
    if (current === null) return {found: true, type: null};
    if (current.type === 'object' && record(current.properties) && Object.hasOwn(current.properties, token)) current = current.properties[token];
    else if (current.type === 'array' && INDEX.test(token) && Number(token) < (current.maxItems ?? 10_000)) current = current.items ?? null;
    else return {found: false, type: null};
  }
  return {found: true, type: current ?? null};
}
/** True when `out` is unknown (the registry checks it at run time), or when every value it allows, `into` allows too. */
export function fits(out, into) {
  if (out === null || out === undefined) return true;
  if (!record(out) || !record(into) || (out.type !== into.type && !(out.type === 'integer' && into.type === 'number'))) return false;
  if (Object.hasOwn(into, 'const') && !(Array.isArray(out.enum) && out.enum.every(value => same(value, into.const)))) return false;
  if (into.enum && !(Array.isArray(out.enum) && out.enum.every(value => into.enum.some(other => same(value, other))))) return false;
  if (into.type === 'string') return (out.maxLength ?? 1_000_000) <= (into.maxLength ?? 1_000_000) && (out.minLength ?? 0) >= (into.minLength ?? 0) && (!into.format || into.format === out.format);
  if (into.type === 'integer' || into.type === 'number') {
    const low = Math.max(out.minimum ?? -Infinity, out.exclusiveMinimum ?? -Infinity), high = Math.min(out.maximum ?? Infinity, out.exclusiveMaximum ?? Infinity);
    return (into.minimum === undefined || low >= into.minimum) && (into.maximum === undefined || high <= into.maximum)
      && (into.exclusiveMinimum === undefined || low > into.exclusiveMinimum) && (into.exclusiveMaximum === undefined || high < into.exclusiveMaximum);
  }
  if (into.type === 'array') return (out.maxItems ?? 10_000) <= (into.maxItems ?? 10_000) && (out.minItems ?? 0) >= (into.minItems ?? 0) && fits(out.items ?? null, into.items);
  if (into.type === 'object') {
    return Object.entries(out.properties ?? {}).every(([key, schema]) => Object.hasOwn(into.properties, key) && fits(schema, into.properties[key]))
      && (into.required ?? []).every(key => (out.required ?? []).includes(key));
  }
  return true;
}
/** fits() for a fact: a constant by its value, a built object or list member by member. */
function fitsFact(argument, schema) {
  if (argument.value !== undefined) return passes(() => validateValue(schema, argument.value, '$value'));
  if (argument.kind === 'when') return fitsFact(argument.then, schema);
  if (argument.kind === 'object') {
    if (schema.type !== 'object') return false;
    for (const [key, member] of argument.members) if (!Object.hasOwn(schema.properties, key) || !fitsFact(member, schema.properties[key])) return false;
    return (schema.required ?? []).every(key => argument.members.has(key) && !argument.members.get(key).optional);
  }
  if (argument.kind === 'array') {
    const kept = argument.items.filter(item => !item.optional).length;
    return schema.type === 'array' && argument.items.length <= (schema.maxItems ?? 10_000) && kept >= (schema.minItems ?? 0) && argument.items.every(item => fitsFact(item, schema.items));
  }
  return fits(argument.type, schema);
}
/** The type both branches of an {either} share: the type itself when they are equal, a scalar with the wider bounds, or unknown. */
function widen(a, b) {
  if (a === null || b === null) return null;
  if (same(a, b)) return a;
  if (a.type !== b.type) return null;
  const wider = (low, high) => Object.fromEntries([[low, a[low] === undefined || b[low] === undefined ? undefined : Math.min(a[low], b[low])],
    [high, a[high] === undefined || b[high] === undefined ? undefined : Math.max(a[high], b[high])]].filter(([, value]) => value !== undefined));
  if (a.type === 'string') return {type: 'string', ...wider('minLength', 'maxLength')};
  if (a.type === 'integer' || a.type === 'number') return {type: a.type, ...wider('minimum', 'maximum')};
  if (a.type === 'boolean') return {type: 'boolean'};
  return null;
}
/** The fact of one element of a list: its item type, its sources and steps, whether the list is step data, and an exclusion that held for every item. */
function elementOf(list) {
  return {type: list.type?.type === 'array' ? list.type.items ?? null : null, sources: list.sources, steps: list.steps, data: list.data === true,
    excludes: list.excludes.filter(rule => rule.pointer === '' && rule.items).map(rule => ({...rule, items: false}))};
}
/**
 * The exclusions that survive a projection at `pointer` (R1): one on exactly that field, re-rooted to the picked value, or one on a list
 * of strings when the pointer picks one of its items. Any other field drops them all.
 */
function reroot(excludes, pointer) {
  const kept = [];
  for (const rule of excludes) {
    if (rule.pointer === pointer) kept.push({...rule, pointer: ''});
    else if (rule.items && pointer.startsWith(`${rule.pointer}/`) && INDEX.test(pointer.slice(rule.pointer.length + 1))) kept.push({...rule, pointer: '', items: false});
  }
  return kept;
}
/** A field of `base` at `pointer`: typed from base's schema when it has one, which must declare the field. */
function project(kind, base, tokens, pointer, where) {
  let type = base.type;
  if (type !== null && tokens.length) {
    const found = schemaAt(type, tokens);
    if (!found.found) fail(`${where}: ${pointer} names no declared field of the value it picks from.`);
    type = found.type;
  }
  const result = fact(kind, {type, pointer, sources: new Set(base.sources), steps: new Set(base.steps), excludes: tokens.length ? reroot(base.excludes, pointer) : base.excludes.map(rule => ({...rule}))});
  result.raw = type === null && fromSteps(result.sources);
  result.data = base.data === true && type === null;
  return result;
}
/** True for a bare {var} over step data, alone or as a branch of an {either}: it copies a whole element of the list. */
const bareVar = value => value.kind === 'var' ? value.raw : value.kind === 'either' && value.branches.some(bareVar);

// ---- pointers ----------------------------------------------------------------------------------------------------------------------
const badPointer = (pointer, where) => fail(`${where}: ${JSON.stringify(pointer)} is not a JSON pointer of at most 32 non-empty tokens.`);
/** The unescaped tokens of an RFC 6901 pointer: '' or '/'-separated, non-empty tokens, at most 32. */
function tokensOf(pointer, where) {
  if (typeof pointer !== 'string' || pointer.length > 1_000 || (pointer !== '' && (!pointer.startsWith('/') || /~(?![01])/.test(pointer)))) badPointer(pointer, where);
  const tokens = pointer === '' ? [] : pointer.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~'));
  if (tokens.length > MAX_POINTER_TOKENS || tokens.some(token => token === '')) badPointer(pointer, where);
  if (tokens.some(token => UNSAFE.has(token))) fail(`${where}: a pointer never reads __proto__, prototype or constructor.`);
  return tokens;
}
/** The tokens of a pointer that reads provider data: no token may name a field that carries a secret (R11). */
function providerTokens(pointer, where) {
  const tokens = tokensOf(pointer, where);
  for (const token of tokens) if (secretKey(token)) fail(`${where}: the pointer ${pointer} reads ${token}, a field that carries a secret, so it is refused wherever it appears (R11).`);
  return tokens;
}
const escapeToken = token => token.replace(/~/g, '~0').replace(/\//g, '~1');

// ---- the grammar -------------------------------------------------------------------------------------------------------------------
function kindOf(node, shapes, where, test) {
  if (!record(node)) fail(`${where}: ${test ? 'a test is an object with one test key' : 'an expression is an object with one grammar key'}.`);
  const keys = Object.keys(node), named = keys.filter(key => shapes.has(key));
  if (named.length !== 1) fail(`${where}: ${test ? 'a test has exactly one test key' : 'an expression has exactly one grammar key'}; this one has ${named.length}.`);
  const [kind] = named, forms = shapes.get(kind);
  if (!forms.some(fields => fields.length === keys.length && fields.every(field => Object.hasOwn(node, field)))) fail(`${where}: {${kind}} takes exactly ${forms.map(fields => fields.join(' and ')).join(', or ')}.`);
  return kind;
}
/** The context of a child node: one level deeper, never droppable, placeable or a direct transform argument unless the parent says so. */
function child(ctx, suffix, changes = {}) {
  return {...ctx, where: `${ctx.where}${suffix}`, depth: ctx.depth + 1, droppable: false, placeable: false, argOf: null, schemaFrom: null, resolvedValue: null, ...changes};
}
function expression(node, ctx) {
  if (ctx.depth > MAX_DEPTH) fail(`${ctx.where}: nests deeper than ${MAX_DEPTH} levels (I7).`);
  const kind = kindOf(node, SHAPES, ctx.where, false);
  return NODES[kind](node, ctx);
}

/** Measures a plain JSON constant: its depth (a scalar is 0), its nodes and its longest string or key. */
function measure(value) {
  if (value === null || typeof value !== 'object') return {depth: 0, nodes: 1, longest: typeof value === 'string' ? [...value].length : 0};
  let depth = 0, nodes = 1, longest = 0;
  for (const [key, item] of Object.entries(value)) {
    const inner = measure(item);
    depth = Math.max(depth, inner.depth);
    nodes += inner.nodes;
    longest = Math.max(longest, inner.longest, Array.isArray(value) ? 0 : [...key].length);
  }
  return {depth: depth + 1, nodes, longest};
}

function registration(kind) {
  return (node, ctx) => {
    if (!ctx.s.trigger) fail(`${ctx.where}: {${kind}} belongs to trigger registration; it is refused in an action.`);
    if (!ctx.s.registration) fail(`${ctx.where}: {${kind}} is read only in a trigger's register, renew or teardown step.`);
    if (typeof node[kind] !== 'string' || !KEY_NAME.test(node[kind])) fail(`${ctx.where}: {${kind}} names ${kind === 'receiver' ? 'an app id' : 'a key of 1 to 64 letters, digits and hyphens'}.`);
    return fact(kind, {name: node[kind], sources: new Set([kind])});
  };
}

const NODES = {
  const(node, ctx) {
    const value = node.const;
    if (!passes(() => canonicalHash(value))) fail(`${ctx.where}: a constant is plain JSON.`);
    const size = measure(value);
    if (size.depth > MAX_CONST_DEPTH) fail(`${ctx.where}: a constant nests at most ${MAX_CONST_DEPTH} levels (I7).`);
    if (ctx.depth + size.depth > MAX_DEPTH) fail(`${ctx.where}: nests deeper than ${MAX_DEPTH} levels (I7).`);
    if (size.longest > MAX_CONST_STRING) fail(`${ctx.where}: a string in a constant holds at most 4,096 characters (I7).`);
    if (Buffer.byteLength(JSON.stringify(value)) > MAX_CONST_BYTES) fail(`${ctx.where}: a constant holds at most 16 KiB (I7).`);
    return fact('const', {type: constType(value), value, sources: new Set(['constant']), nodes: 1 + size.nodes});
  },
  input(node, ctx) {
    if (ctx.s.slot === 'header') fail(`${ctx.where}: a header value never comes from an input.`);
    const tokens = tokensOf(node.input, ctx.where);
    if (!tokens.length) fail(`${ctx.where}: {input} reads one declared input: its pointer is never empty.`);
    const [name] = tokens, read = {sources: new Set(['input']), inputs: new Set([node.input])};
    if (ctx.s.resolvedInputs.has(name)) {
      if (ctx.resolvedValue !== name || tokens.length !== 1) fail(`${ctx.where}: ${name} is a resource-dependent input: it is read only whole, as a resolvedValues argument beside {resolved: '${name}'} in the same transform call (R14).`);
      return fact('input', read);
    }
    const found = ctx.s.inputSchema ? schemaAt(ctx.s.inputSchema, tokens) : {found: false};
    if (!found.found) fail(`${ctx.where}: the input schema declares no ${node.input}.`);
    return fact('input', {...read, type: found.type});
  },
  step(node, ctx) {
    const info = typeof node.step === 'string' ? ctx.s.steps.get(node.step) : undefined;
    if (!info) fail(`${ctx.where}: reads step ${JSON.stringify(node.step)}, which has not run before this point.`);
    const read = {step: node.step, data: true, sources: new Set([info.source]), steps: new Set([node.step])};
    if (Object.hasOwn(node, 'header')) {
      if (!STEP_HEADERS.includes(node.header)) fail(`${ctx.where}: a step header is one of etag, last-modified, link, location and retry-after.`);
      if (REQUEST_ONLY_HEADERS.has(node.header) && !(REQUEST_SLOTS.has(ctx.s.slot) && ctx.inTransform)) fail(`${ctx.where}: the ${node.header} header is read only inside a request, as a transform argument: a redirect Location can carry a signed token.`);
      if (ctx.s.slot === 'header' && info.source !== 'prepare') fail(`${ctx.where}: a header value reads only a prepare step's answer.`);
      return fact('step', {...read, header: node.header});
    }
    providerTokens(node.pointer, ctx.where);
    if (ctx.s.slot === 'header' && info.source !== 'prepare') fail(`${ctx.where}: a header value reads only a prepare step's answer.`);
    return fact('step', {...read, pointer: node.pointer, raw: true});
  },
  item(node, ctx) {
    if (!ctx.s.item) fail(`${ctx.where}: {item} is read only inside a forEach step, or in a poll item field (itemId, filter, event and dedupe fields).`);
    return project('item', elementOf(ctx.s.item.list), providerTokens(node.item, ctx.where), node.item, ctx.where);
  },
  pick(node, ctx) {
    const inner = expression(node.pick, child(ctx, '.pick', {placeable: 'pick'}));
    if (!PICKABLE.has(inner.kind) || inner.header !== undefined) fail(`${ctx.where}: {pick} takes one field of a transform result, step data, an item or a var.`);
    if (inner.keyed) fail(`${ctx.where}: an ${inner.keyed.form} result has no declared field, so nothing picks into it: it is placed whole at one request body position.`);
    const tokens = providerTokens(node.pointer, ctx.where);
    if (!tokens.length) fail(`${ctx.where}: {pick} names one field: its pointer is never empty.`);
    const result = absorb(project('pick', inner, tokens, node.pointer, ctx.where), inner);
    result.of = inner;
    return result;
  },
  each(node, ctx) {
    if (!Number.isSafeInteger(node.max) || node.max < 1 || node.max > MAX_EACH) fail(`${ctx.where}: {each} takes a max of 1 to ${MAX_EACH}; a longer list refuses, never truncates.`);
    if (typeof node.as !== 'string' || !NAME.test(node.as)) fail(`${ctx.where}: {each} binds a name of 1 to 32 letters and digits, starting with a lowercase letter.`);
    if (ctx.vars.has(node.as)) fail(`${ctx.where}: {each} binds ${node.as}, which an enclosing {each} or the trigger's resource already binds.`);
    const list = expression(node.each, child(ctx, '.each'));
    if (list.type !== null && list.type.type !== 'array') fail(`${ctx.where}: {each} walks a list.`);
    const body = expression(node.do, child(ctx, '.do', {vars: new Map(ctx.vars).set(node.as, list)}));
    if (body.kind === 'var' && body.raw) fail(`${ctx.where}: an {each} over step data copies no element whole: its do picks fields (I6, I9).`);
    if (body.kind === 'either' && bareVar(body)) fail(`${ctx.where}: an {each} over step data copies no element whole, not even through an {either}: each branch picks fields (I6, I9).`);
    const result = absorb(fact('each', {type: {type: 'array', maxItems: node.max, items: body.type}, list, do: body,
      excludes: body.excludes.filter(rule => rule.pointer === '' && !rule.items).map(rule => ({...rule, items: true}))}), list, body);
    result.nodes = 1 + list.nodes + node.max * body.nodes;
    return result;
  },
  var(node, ctx) {
    const list = typeof node.var === 'string' ? ctx.vars.get(node.var) : undefined;
    if (!list) fail(`${ctx.where}: {var: '${node.var}'} is read only inside the {each} that binds it, or in a trigger's poll when its resource.as binds it.`);
    return project('var', elementOf(list), [], '', ctx.where);
  },
  account(node, ctx) {
    if (!ACCOUNT_FIELDS.includes(node.account)) fail(`${ctx.where}: {account} is one of id, email, workspaceId and userId.`);
    if (ctx.s.slot === 'header') fail(`${ctx.where}: {account} is never a header value.`);
    const identity = ctx.s.identity, attributes = record(identity?.attributes) ? identity.attributes : {};
    const yields = node.account === 'id' || (node.account === 'email' ? typeof identity?.email === 'string' : Object.hasOwn(attributes, node.account) && typeof attributes[node.account] === 'string');
    if (!yields) fail(`${ctx.where}: {account: '${node.account}'} needs the app's reviewed identity to yield ${node.account}, and this app's does not.`);
    return fact('account', {field: node.account, type: ACCOUNT_TYPES[node.account], sources: new Set(['account'])});
  },
  transform(node, ctx) {
    const result = call(node.transform, node.args, ctx, ['map', 'guard']);
    if (result.keyed && ctx.placeable !== true && ctx.placeable !== 'pick') fail(`${ctx.where}: an ${result.keyed.form} result is placed whole at one request body position, never ${ctx.s.slot === 'body' ? 'inside another expression' : `in the ${ctx.s.slot}`}.`);
    return result;
  },
  object(node, ctx) {
    if (!record(node.object)) fail(`${ctx.where}: {object} maps constant keys to expressions; a key is never computed.`);
    const result = fact('object', {members: new Map()}), properties = {}, required = [];
    for (const [key, value] of Object.entries(node.object)) {
      if (!key.length || key.length > 256 || UNSAFE.has(key)) fail(`${ctx.where}: an object key is 1 to 256 characters and never __proto__, prototype or constructor.`);
      const member = expression(value, child(ctx, `.${key}`, {droppable: true, placeable: ctx.placeable === true}));
      result.members.set(key, member);
      absorb(result, member);
      properties[key] = member.type;
      if (!member.optional) required.push(key);
    }
    result.type = {type: 'object', properties, required, additionalProperties: false};
    if ([...result.members.values()].every(member => member.value !== undefined)) result.value = Object.fromEntries([...result.members].map(([key, member]) => [key, member.value]));
    return result;
  },
  array(node, ctx) {
    if (!Array.isArray(node.array)) fail(`${ctx.where}: {array} holds a list of expressions.`);
    const result = fact('array', {items: node.array.map((item, index) => expression(item, child(ctx, `[${index}]`, {droppable: true, placeable: ctx.placeable === true})))});
    absorb(result, ...result.items);
    const types = result.items.map(item => item.type);
    result.type = {type: 'array', minItems: result.items.filter(item => !item.optional).length, maxItems: result.items.length,
      items: types.length && types.every(type => type !== null && same(type, types[0])) ? types[0] : null};
    if (result.items.every(item => item.value !== undefined)) result.value = result.items.map(item => item.value);
    return result;
  },
  concat(node, ctx) {
    if (!Number.isSafeInteger(node.max) || node.max < 1 || node.max > MAX_CONCAT) fail(`${ctx.where}: {concat} takes a max of 1 to 65,536 characters.`);
    if (!Array.isArray(node.concat) || !node.concat.length) fail(`${ctx.where}: {concat} joins at least one part.`);
    const parts = node.concat.map((part, index) => expression(part, child(ctx, `.concat[${index}]`)));
    for (const part of parts) if (part.type !== null && part.type.type !== 'string' && part.type.type !== 'integer') fail(`${ctx.where}: {concat} joins strings and safe integers written in plain decimal.`);
    return absorb(fact('concat', {type: {type: 'string', maxLength: node.max}, parts}), ...parts);
  },
  when(node, ctx) {
    if (ctx.droppable !== true) fail(`${ctx.where}: {when} sits only where a value can be left out: an object member, an array item, a transform argument that is not required, or a query value.`);
    const test = testNode(node.when, child(ctx, '.when'), 1), then = expression(node.then, child(ctx, '.then'));
    return absorb(fact('when', {type: then.type, optional: true, raw: then.raw, test, then}), test, then);
  },
  either(node, ctx) {
    if (!Array.isArray(node.either) || node.either.length !== 2) fail(`${ctx.where}: {either} takes two expressions.`);
    const [first, second] = node.either.map((branch, index) => expression(branch, child(ctx, `.either[${index}]`)));
    if (![...first.steps].some(id => ctx.s.steps.get(id)?.skippable === true)) fail(`${ctx.where}: the first branch of {either} must read a step that can be skipped: an optional step, a step with when, or a forEach that may run zero times.`);
    if (first.type !== null && second.type !== null && first.type.type !== second.type.type) fail(`${ctx.where}: both branches of {either} have the same type.`);
    return absorb(fact('either', {type: widen(first.type, second.type), raw: first.raw || second.raw, branches: [first, second]}), first, second);
  },
  now(node, ctx) {
    if (!exactly(node.now, [])) fail(`${ctx.where}: {now} takes {}.`);
    if (!ctx.argOf) fail(`${ctx.where}: {now} is only an argument of a transform that declares usesClock (spec line 734).`);
    if (ctx.argOf.entry.usesClock !== true) fail(`${ctx.where}: ${ctx.argOf.id} does not declare usesClock, so it never takes {now}.`);
    return fact('now', {type: NOW_TYPE, sources: new Set(['clock'])});
  },
  jobKey(node, ctx) {
    if (typeof node.jobKey !== 'string' || !KEY_NAME.test(node.jobKey)) fail(`${ctx.where}: {jobKey} names a key of 1 to 64 letters, digits and hyphens, starting with a lowercase letter.`);
    return fact('jobKey', {name: node.jobKey, type: JOB_KEY_TYPE, sources: new Set(['jobKey'])});
  },
  cursor(node, ctx) {
    if (typeof node.cursor !== 'string' || !ctx.s.cursors.has(node.cursor)) fail(`${ctx.where}: {cursor: '${node.cursor}'} is read only in the poll step of a read action whose poll block names that cursor.`);
    if (!CURSOR_SLOTS.has(ctx.s.slot)) fail(`${ctx.where}: a cursor sits only in a query, a header or the body of its poll step.`);
    if (!ctx.droppable) fail(`${ctx.where}: a cursor is dropped when none is bound, so it sits only where a value can be left out.`);
    return fact('cursor', {name: node.cursor, optional: true, sources: new Set(['cursor']), cursors: new Set([node.cursor])});
  },
  resolved(node, ctx) {
    if (typeof node.resolved !== 'string' || !ctx.s.resolvedInputs.has(node.resolved)) fail(`${ctx.where}: {resolved} names a resource-dependent input of this action.`);
    if (ctx.schemaFrom !== node.resolved) fail(`${ctx.where}: {resolved} is only the schema argument of a transform that declares resolvedValues (R14).`);
    return fact('resolved', {name: node.resolved, sources: new Set(['resolved'])});
  },
  receiver: registration('receiver'),
  secret: registration('secret'),
  kept: registration('kept'),
  subscriptionKey: registration('subscriptionKey'),
};

/**
 * A transform call: a registered entry of one of `kinds`, its arguments named by the entry and each checked by its kind (F10.8's
 * entry, its part b). A closed argument is checked against the entry's input schema when its type is known, and by the registry at run
 * time when it is not. A pointer argument is a constant pointer whose tokens name no secret (R11). A step-data argument is step data of
 * an earlier step (F10.8 open point Minor 14). A resolvedValues argument and its schemaFrom argument are the pair {input: '/<x>'} and
 * {resolved: '<x>'} of one resource-dependent input (R14).
 */
function call(id, args, ctx, kinds) {
  const entry = typeof id === 'string' ? ctx.s.transforms.get(id) : undefined;
  if (!entry) fail(`${ctx.where}: names the transform ${id}, which the registry does not hold.`);
  if (!kinds.includes(entry.kind)) fail(`${ctx.where}: ${id} is a ${entry.kind} entry; here only ${kinds.join(' or ')} entries run.`);
  if (!record(args)) fail(`${ctx.where}: transform arguments are an object of expressions.`);
  const closed = entry.input.properties, stepData = entry.stepData, resolved = entry.resolvedValues;
  const required = new Set([...(entry.input.required ?? []), ...Object.keys(stepData), ...Object.keys(resolved)]);
  for (const name of Object.keys(args)) if (!Object.hasOwn(closed, name) && !Object.hasOwn(stepData, name) && !Object.hasOwn(resolved, name)) fail(`${ctx.where}: ${id} has no argument ${name}.`);
  for (const name of required) if (!Object.hasOwn(args, name)) fail(`${ctx.where}: ${id} needs the argument ${name}.`);
  const schemaOf = new Map(), valuesOf = new Map();
  for (const [name, rule] of Object.entries(resolved)) {
    const schema = args[rule.schemaFrom], values = args[name];
    const input = exactly(schema, ['resolved']) && typeof schema.resolved === 'string' ? schema.resolved : null;
    if (input === null) fail(`${ctx.where}.args.${rule.schemaFrom}: takes only {resolved} of the resource-dependent input that ${name} takes the values of (R14).`);
    if (!exactly(values, ['input']) || values.input !== `/${escapeToken(input)}`) fail(`${ctx.where}.args.${name}: takes only {input: '/${input}'}, the input whose {resolved} ${rule.schemaFrom} takes (R14).`);
    schemaOf.set(rule.schemaFrom, input);
    valuesOf.set(name, input);
  }
  const result = fact('transform', {transform: id, refuses: [...entry.refuses], args: new Map()});
  result.transforms.add(id);
  for (const [name, value] of Object.entries(args)) {
    const at = `${ctx.where}.args.${name}`;
    const argument = expression(value, child(ctx, `.args.${name}`, {inTransform: true, argOf: {id, entry}, droppable: !required.has(name),
      schemaFrom: schemaOf.get(name) ?? null, resolvedValue: valuesOf.get(name) ?? null}));
    if (entry.pointerArgs.includes(name)) {
      if (argument.kind !== 'const' || typeof argument.value !== 'string') fail(`${at}: ${id}'s ${name} holds a pointer into step data, so it takes only a constant written in the file (R11).`);
      providerTokens(argument.value, at);
    }
    if (Object.hasOwn(stepData, name) && !schemaOf.has(name)
      && (!STEP_DATA_KINDS.has(argument.kind) || argument.type !== null || !argument.sources.size || ![...argument.sources].every(source => STEP_SOURCES.includes(source))
        || argument.data !== true)) {
      fail(`${at}: ${id}'s ${name} takes step data of an earlier step: a {step, pointer}, a pick of one, or an item or var over step data; never an input, a constant, a built object or a transform result (F10.8 open point Minor 14).`);
    }
    if (Object.hasOwn(closed, name)) {
      if (argument.value !== undefined) {
        try { validateValue(closed[name], argument.value, '$value'); }
        catch (error) { fail(`${at}: the constant does not fit ${id}'s ${name} (${error.message.replace(/^\$value:?\s*/, '')}).`); }
      } else if (!fitsFact(argument, closed[name])) fail(`${at}: its type does not fit ${id}'s ${name}.`);
    }
    result.args.set(name, argument);
    absorb(result, argument);
  }
  if (Object.hasOwn(entry, 'output')) result.type = entry.output;
  if (Object.hasOwn(entry, 'outputFrom')) result.keyed = {form: 'outputFrom', argument: entry.outputFrom.argument, input: schemaOf.get(entry.outputFrom.argument)};
  if (Object.hasOwn(entry, 'outputMap')) result.keyed = {form: 'outputMap', value: entry.outputMap.value};
  result.excludes = entry.excludes.map(rule => ({pointer: rule.pointer, items: rule.items === true, values: [...rule.values], fold: rule.fold}));
  return result;
}

function testNode(node, ctx, level) {
  if (level > 2) fail(`${ctx.where}: tests nest at most 2 deep.`);
  if (ctx.depth > MAX_DEPTH) fail(`${ctx.where}: nests deeper than ${MAX_DEPTH} levels (I7).`);
  const kind = kindOf(node, TEST_SHAPES, ctx.where, true), result = fact(kind);
  if (kind === 'anyOf') {
    if (!Array.isArray(node.anyOf) || !node.anyOf.length || node.anyOf.length > 8) fail(`${ctx.where}: {anyOf} holds 1 to 8 tests.`);
    result.tests = node.anyOf.map((test, index) => testNode(test, child(ctx, `.anyOf[${index}]`), level + 1));
    return absorb(result, ...result.tests);
  }
  if (kind === 'status') {
    const status = node.status, info = exactly(status, ['step', 'in']) && typeof status.step === 'string' ? ctx.s.steps.get(status.step) : undefined;
    if (!info || !Array.isArray(status.in) || !status.in.length || status.in.length > 16 || new Set(status.in).size !== status.in.length
      || !status.in.every(code => Number.isSafeInteger(code) && code >= 100 && code <= 599)) fail(`${ctx.where}: {status} names an earlier step and 1 to 16 HTTP status codes.`);
    // Its literal {step, in: [...]} counts two levels, as the levels inside a constant do.
    if (ctx.depth + 2 > MAX_DEPTH) fail(`${ctx.where}: nests deeper than ${MAX_DEPTH} levels (I7).`);
    Object.assign(result, {step: status.step, in: [...status.in], nodes: 2 + status.in.length});
    result.sources.add(info.source);
    result.steps.add(status.step);
    return result;
  }
  if (kind === 'equals') {
    if (!Array.isArray(node.equals) || node.equals.length !== 2 || !exactly(node.equals[1], ['const'])) fail(`${ctx.where}: {equals} compares an expression with a {const}.`);
    const operand = expression(node.equals[0], child(ctx, '.equals[0]')), constant = expression(node.equals[1], child(ctx, '.equals[1]'));
    if (complete(operand.type) && !passes(() => validateValue(operand.type, constant.value, '$value'))) fail(`${ctx.where}: {equals} can never hold: the constant is outside the type of what it compares.`);
    return absorb(Object.assign(result, {operand, value: constant.value}), operand, constant);
  }
  const operand = expression(node[kind], child(ctx, `.${kind}`));
  return absorb(Object.assign(result, {operand}), operand);
}

// ---- entry points ------------------------------------------------------------------------------------------------------------------
function scopeOf(scope) {
  if (!record(scope)) throw new Error('An expression needs a scope.');
  if (!SLOTS.includes(scope.slot)) throw new Error(`An expression scope names one slot of ${SLOTS.join(', ')}.`);
  const steps = scope.steps ?? new Map(), vars = scope.vars ?? new Map(), budget = scope.budget ?? newBudget();
  if (!(steps instanceof Map) || !(vars instanceof Map)) throw new Error('An expression scope\'s steps and vars are Maps.');
  for (const [id, info] of steps) if (!record(info) || !STEP_SOURCES.includes(info.source)) throw new Error(`An expression scope's step ${id} names its source, one of ${STEP_SOURCES.join(', ')}.`);
  for (const [name, list] of vars) if (!isFact(list)) throw new Error(`An expression scope's var ${name} is the fact of the list it iterates.`);
  if (scope.item != null && !(record(scope.item) && ['forEach', 'poll'].includes(scope.item.from) && isFact(scope.item.list))) throw new Error('An expression scope\'s item.from is forEach or poll, and its item.list is the fact of that list.');
  if (scope.registration === true && scope.trigger !== true) throw new Error('An expression scope\'s registration is only in a trigger scope.');
  if (!record(budget) || !Number.isSafeInteger(budget.nodes)) throw new Error('An expression scope\'s budget comes from newBudget().');
  return {where: typeof scope.where === 'string' ? scope.where : '$expression', slot: scope.slot, transforms: scope.transforms ?? TRANSFORMS, inputSchema: scope.inputSchema ?? null,
    resolvedInputs: new Set(scope.resolvedInputs ?? []), identity: scope.identity ?? null, steps, item: scope.item ?? null, vars, cursors: new Set(scope.cursors ?? []),
    member: scope.member === true, trigger: scope.trigger === true, registration: scope.registration === true, budget};
}
function rootOf(s) {
  // A query value, and a member of an object the caller builds, may be left out; a header may be left out only when its cursor is unbound.
  return {s, where: s.where, depth: 1, droppable: s.slot === 'query' || s.member ? true : s.slot === 'header' ? 'cursor' : false, placeable: s.slot === 'body',
    inTransform: false, argOf: null, schemaFrom: null, resolvedValue: null, vars: s.vars};
}
function spend(s, result) {
  if (s.budget.nodes + result.nodes > MAX_NODES) fail(`${s.where}: the expressions of one action hold at most 2,000 nodes, an {each} counting max times its do (I7).`);
  s.budget.nodes += result.nodes;
  return result;
}

/** Checks one expression at the position `scope` describes and returns its fact. Throws an Error that names the position and the rule. */
export function checkExpression(node, scope) {
  const s = scopeOf(scope), result = expression(node, rootOf(s));
  if (s.slot === 'header') for (const source of result.sources) if (!HEADER_SOURCES.has(source)) fail(`${s.where}: a header value comes only from constants, a prepare step's answer or a poll cursor (spec line 741).`);
  return spend(s, result);
}
/** Checks one test (a step's when, a {when} node's test, a poll filter, a requiresScope.when) and returns its fact. */
export function checkTest(node, scope) {
  const s = scopeOf(scope);
  return spend(s, testNode(node, {...rootOf(s), droppable: false, placeable: false}, 1));
}
/** Checks a call outside an expression: a guard ({transform, args}, kinds ['guard']) or a resolved input's derive (kinds ['schema']). */
export function checkCall(transform, args, scope, kinds = ['guard']) {
  const s = scopeOf(scope);
  return spend(s, call(transform, args, {...rootOf(s), droppable: false, placeable: false}, kinds));
}
/**
 * R11 for a pointer that reads provider data outside an expression: an assertion's pointer, a list and field of listHas and listLacks,
 * and a page block's pointers (part f), and a choice source's pointers (part i). It is RFC 6901, at most 32 non-empty tokens, never
 * __proto__, prototype or constructor, and no token names a field that carries a secret. Returns its tokens.
 */
export const checkPointer = (pointer, where) => providerTokens(pointer, where);
/**
 * The perform-step source rule (part f; R2; open question 41): throws when a fact a perform step's bytes are built from reads any
 * source outside PERFORM_SOURCES, such as another perform step's answer, a write's answer or a verify step's. `where` names the slot.
 */
export function assertPerformSources(result, where) {
  for (const source of result.sources) {
    if (!PERFORM_SOURCES.includes(source)) fail(`${where} reads ${SOURCE_WORDS[source] ?? `the ${source}`}, which a perform step's bytes never read: they come only from what exists before the owner approves them (T5, R2).`);
  }
}

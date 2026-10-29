// F10.9 part i (docs/F10.9-BUILD-MAP.md part i and section 9; R10, R11 and R12): choice sources, the options version 2 format, in their
// own folder (catalog/choices/<appId>.json) and their own map. A choice source says which governed, paged, searchable read lists the
// values an action input may take, with the label beside each id: a typed operation or a reviewed request template of a read row, the
// arguments it sends (constants, configured values and, on a lookup, the one value it reads), where the value and label sit in the
// answer, how it pages and searches, and which values it never offers. Version 1 (catalog/options, lib/option-sources.mjs) keeps its
// bytes, its loader and its readers: a version 2 file never reaches OPTION_SOURCES, sourceFor() or POST /v1/options, and a choice source
// has no serves field, so it never fills an input by name. Actions and triggers name a source by id (checkChoices()).
//
// validateChoiceSources() checks one app's file against its rows, proxy settings, application map and the transform registry;
// loadChoiceSources() reads a folder of them into a map (the CHOICE_SOURCES map of section 9), and is not called at import:
// loadActions() calls it. Nothing here reads a store, runs a transform or sends a request.
import {readdirSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {secretParameter} from './compiler.mjs';
import {PERMISSION_GROUPS, memberKey, memberData, parseTemplate} from './permission-groups.mjs';
import {PROXY_CONFIGS} from './proxy-config.mjs';
import {reservedQueryName} from './proxy-request.mjs';
import {checkPointer} from './action-expressions.mjs';
import {placeStep} from './action-placement.mjs';
import {TRANSFORMS} from './transforms/index.mjs';

const NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/, QUERY_NAME = /^[\w.~:[\]-]{1,128}$/, REQUEST = /^(GET|POST) (\/\S*)$/;
const SOURCE_FIELDS = ['id', 'kind', 'read', 'row', 'args', 'items', 'value', 'valueType', 'label', 'page', 'search', 'maxItems'], SOURCE_OPTIONAL = ['detail', 'exclude'];
const VALUE_TYPES = ['string', 'integer'];
/** The registry entry Link paging reads the next page number through (F10.8 map part k). */
const LINK_PAGES = 'ids.linkPage@1';
/** Spec line 751 and open question 10: Notion fields an action body never writes, which no choice source body writes either. */
const NOTION_RESERVED = ['erase_content', 'allow_deleting_content', 'is_locked', 'display_name', 'archived', 'is_archived', 'in_trash'];

const fail = message => { throw new Error(message); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const deepFreeze = value => { if (value !== null && typeof value === 'object') { Object.freeze(value); for (const item of Object.values(value)) deepFreeze(item); } return value; };
const shaped = (value, required, optional = []) => record(value) && required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const listWords = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
const fold = text => text.replace(/[A-Z]/g, char => String.fromCharCode(char.charCodeAt(0) + 32));
const scalar = value => (typeof value === 'string' && [...value].length <= 1_000) || Number.isSafeInteger(value) || typeof value === 'boolean';
/** The closed schema at a pointer's tokens, through declared object properties only. */
function fieldOf(schema, tokens) {
  let current = schema;
  for (const token of tokens) current = current?.type === 'object' && record(current.properties) && Object.hasOwn(current.properties, token) ? current.properties[token] : null;
  return current;
}

/**
 * Checks one app's choice source file (docs/F10.9-BUILD-MAP.md section 9) and returns its sources, each frozen and field for field as
 * written. `deps`: {groups, configs, maps, transforms}: the validated rows and proxy settings by app (the shipped ones by default), the
 * stored application maps by app, and the transform registry. A request source of an app reviewed by operation id is placed only through
 * its map; without one it is checked against its row's members alone, as an action step without its map is unplaced. Throws an Error
 * naming the source, the field and the rule.
 */
export function validateChoiceSources(file, {groups = PERMISSION_GROUPS, configs = PROXY_CONFIGS, maps = new Map(), transforms = TRANSFORMS} = {}) {
  const at = `Choice sources for ${record(file) ? file.appId : undefined}`;
  if (!shaped(file, ['schemaVersion', 'appId', 'reviewed', 'sources']) || file.schemaVersion !== 2 || typeof file.reviewed !== 'string' || !file.reviewed.trim()) {
    fail(`${at}: a choice source file holds exactly schemaVersion 2, appId, reviewed and sources.`);
  }
  const definition = groups instanceof Map ? groups.get(file.appId) : undefined, config = configs instanceof Map ? configs.get(file.appId) : undefined;
  if (!definition || !config) fail(`${at}: the app has no reviewed permission rows and proxy settings.`);
  if (!Array.isArray(file.sources) || !file.sources.length || file.sources.length > 20) fail(`${at}: a choice source file holds 1 to 20 sources.`);
  const map = maps instanceof Map ? maps.get(file.appId) ?? null : record(maps) ? maps[file.appId] ?? null : null;
  const ctx = {at, appId: file.appId, definition, config, map, transforms}, ids = new Set();
  return Object.freeze(file.sources.map(source => {
    checkSource(source, ctx);
    if (ids.has(source.id)) fail(`${at}: the choice source id ${source.id} is used twice.`);
    ids.add(source.id);
    return deepFreeze(structuredClone(source));
  }));
}

function checkSource(source, ctx) {
  const {at, definition, config} = ctx;
  if (!record(source)) fail(`${at}: each choice source is an object.`);
  if (typeof source.id !== 'string' || !NAME.test(source.id)) fail(`${at}: a choice source id is 1 to 64 letters, digits, _, . and -, starting with a letter.`);
  const where = `${at}: ${source.id}`;
  if (Object.hasOwn(source, 'serves')) fail(`${where}: a choice source fills no input by name, so it has no serves field: an action names it by id (R10).`);
  if (!shaped(source, SOURCE_FIELDS, SOURCE_OPTIONAL)) fail(`${where}: a choice source holds exactly ${listWords(SOURCE_FIELDS)}, and may hold ${listWords(SOURCE_OPTIONAL)}.`);
  if (!['directory', 'lookup'].includes(source.kind)) fail(`${where}: kind is directory or lookup.`);
  if (!VALUE_TYPES.includes(source.valueType)) fail(`${where}: valueType is string or integer: the type of every value it offers.`);
  const lookup = source.kind === 'lookup';
  // The row: a read row of the app.
  const row = definition.groups.find(group => group.id === source.row);
  if (!row) fail(`${where}: row names no row of ${ctx.appId}.`);
  if (row.effect !== 'read') fail(`${where}: a choice source reads a read row, and ${row.id} is a ${row.effect} row.`);
  // The read: a typed operation of the row, or a reviewed request template that lands on its own member there (part e).
  const read = readOf(source, row, where, ctx);
  // Arguments: constants, configured values, and on a lookup exactly one {value: true}; every path parameter filled, no reserved name.
  if (!record(source.args)) fail(`${where}: args maps argument names to {const}, {configured: <name>} or, on a lookup, {value: true}.`);
  const path = read.template ? parseTemplate(read.template).segments.filter(segment => segment.kind !== 'literal').map(segment => segment.name) : [];
  let values = 0;
  for (const [name, argument] of Object.entries(source.args)) {
    const label = `${where}.args.${name}`;
    if (!QUERY_NAME.test(name)) fail(`${label}: an argument name is 1 to 128 letters, digits and _ . ~ : [ ] -.`);
    const kind = shaped(argument, ['const']) && scalar(argument.const) ? 'const' : shaped(argument, ['configured']) && typeof argument.configured === 'string' && NAME.test(argument.configured) ? 'configured'
      : shaped(argument, ['value']) && argument.value === true ? 'value' : null;
    if (!kind) fail(`${label} is {const}, {configured: <name>} or, on a lookup, {value: true}: a choice source's arguments never come from anywhere else.`);
    if (kind === 'value' && !lookup) fail(`${label}: {value: true} is the one argument of a lookup, the id it reads; a directory source lists without one.`);
    if (kind === 'value') values++;
    if (path.includes(name)) continue;
    if (secretParameter(name) || (read.into === 'query' ? reservedQueryName(name, config) : reserved(name, ctx))) fail(`${label}: ${name} is reserved: a choice source never sends it (spec line 740).`);
  }
  for (const name of path) if (!Object.hasOwn(source.args, name)) fail(`${where}: the path parameter ${name} is filled by no argument.`);
  // Where the items, the value and the label sit (R11: no token names a secret).
  checkPointer(source.items, `${where}.items`);
  checkPointer(source.value, `${where}.value`);
  for (const [field, optional] of [['label', false], ['detail', true]]) {
    if (optional && source[field] === undefined) continue;
    if (!Array.isArray(source[field]) || !source[field].length || source[field].length > 3) fail(`${where}: ${field} holds 1 to 3 pointers.`);
    source[field].forEach((pointer, index) => checkPointer(pointer, `${where}.${field}[${index}]`));
  }
  if (lookup) {
    if (source.page !== null || source.search !== null) fail(`${where}: a lookup reads one item by its id: no paging and no search.`);
    if (values !== 1) fail(`${where}: a lookup takes exactly one {value: true} argument, the id it reads.`);
  }
  if (source.page !== null) page(source, read, where, ctx);
  if (source.search !== null) search(source, read, where, ctx);
  if (source.exclude !== undefined) {
    const list = source.exclude;
    if (!Array.isArray(list) || !list.length || list.length > 50 || new Set(list).size !== list.length
      || !list.every(value => source.valueType === 'string' ? typeof value === 'string' && value.length > 0 && [...value].length <= 1_000 : Number.isSafeInteger(value))) {
      fail(`${where}: exclude lists 1 to 50 distinct ${source.valueType} values.`);
    }
  }
  if (!Number.isSafeInteger(source.maxItems) || source.maxItems < 1 || source.maxItems > 1000) fail(`${where}: maxItems is 1 to 1000.`);
}
/** A body field the app reserves: its proxy's reserved body fields, and for Notion the fields an action body never writes. */
const reserved = (name, ctx) => (ctx.config.reservedBodyFields ?? []).includes(name) || (ctx.appId === 'notion' && NOTION_RESERVED.includes(name));

/** The source's read: {template, method, into}, where `into` says where its arguments go (the query of a GET, the body of a POST). */
function readOf(source, row, where, ctx) {
  const read = source.read;
  const operation = shaped(read, ['operation']) && typeof read.operation === 'string', request = shaped(read, ['request']) && typeof read.request === 'string' && REQUEST.test(read.request);
  if (!operation && !request) fail(`${where}: read is {operation} or {request: 'GET /template' | 'POST /template'}.`);
  if (operation) {
    // Version 1's rule (lib/option-sources.mjs:23): an operation of the named read row.
    if (!row.operations.includes(read.operation)) fail(`${where}: ${read.operation} is not an operation of the read row ${row.id}.`);
    usable(row, read.operation, where);
    return {template: null, method: 'GET', into: 'query'};
  }
  const [, method, template] = REQUEST.exec(read.request);
  try { parseTemplate(read.request); } catch (error) { fail(`${where}: ${read.request} is not a path template (${error.message})`); }
  const placement = placeStep({id: 'source', method, path: template}, {definition: ctx.definition, config: ctx.config, map: ctx.map, phase: 'lookup', where});
  if (!placement.unplaced) {
    if (placement.groupId !== row.id) fail(`${where}: ${read.request} lands in ${placement.groupId}, not its row ${row.id}.`);
  } else if (!row.requests.some(member => memberKey(member) === memberKey(read.request))) fail(`${where}: ${read.request} is not a member of ${row.id}.`);
  const member = placement.unplaced ? read.request : placement.member;
  usable(row, member, where);
  // A POST is a read only when its row reviews it as one (lib/permission-groups.mjs reviewedReads); its body then holds only the source's
  // own arguments, page cursor and search text, and no body route of the row may read it.
  if (method === 'POST' && !row.reviewedReads.some(item => memberKey(item) === memberKey(member))) {
    fail(`${where}: ${read.request} is a POST its row does not list in reviewedReads: a choice source reads only a reviewed read (section 9).`);
  }
  if ((row.bodyRoutes ?? []).some(route => memberKey(route.member) === memberKey(member))) fail(`${where}: ${read.request} has body routes, so what a choice source sends could move it to another row.`);
  return {template: read.request, method, into: method === 'GET' ? 'query' : 'body'};
}
/** Never an unavailable member, and never one whose answer can carry a secret (part c): a choice list shows its labels to the owner. */
function usable(row, member, where) {
  const data = memberData(row, member);
  if (data.unavailable) fail(`${where}: ${member} is unavailable, so it never fills a choice list.`);
  if (data.sensitive === 'secrets') fail(`${where}: ${member} is marked sensitive: its answer can carry a secret, so it never fills a choice list.`);
}
/** The page block: the next page from a body pointer or a Link header's page number (never a URL, I4), into a query name or a body pointer. */
function page(source, read, where, ctx) {
  const block = source.page;
  if (!shaped(block, ['next', 'into', 'max']) || !Number.isSafeInteger(block.max) || block.max < 1 || block.max > 10) fail(`${where}: page is null or {next, into, max}, with a max of 1 to 10 (I7).`);
  if (shaped(block.next, ['pointer'])) checkPointer(block.next.pointer, `${where}.page.next`);
  else if (shaped(block.next, ['link', 'param']) && block.next.link === 'next' && typeof block.next.param === 'string' && QUERY_NAME.test(block.next.param)) {
    if (!(ctx.transforms instanceof Map) || !ctx.transforms.has(LINK_PAGES)) fail(`${where}.page.next: Link paging reads the next page through ${LINK_PAGES}, which the registry does not hold.`);
  } else fail(`${where}.page.next is {pointer} or {link: 'next', param}: Link paging takes only the named page parameter, from a next URL on the same origin and path, and never follows the URL (I4).`);
  into(block.into, source, read, `${where}.page.into`, ctx);
}
/** Where a page cursor or search text goes: a query name the source does not already send and the app does not reserve, or a body pointer of a POST. */
function into(target, source, read, where, ctx) {
  if (shaped(target, ['query']) && typeof target.query === 'string' && QUERY_NAME.test(target.query)) {
    if (read.into !== 'query') fail(`${where}: a POST sends its arguments in the body: it pages and searches into the body.`);
    if (secretParameter(target.query) || reservedQueryName(target.query, ctx.config)) fail(`${where}: ${target.query} is reserved: a choice source never sends it (spec line 740).`);
    if (Object.hasOwn(source.args, target.query)) fail(`${where}: the source already sends ${target.query} as an argument.`);
    return;
  }
  if (shaped(target, ['body'])) {
    if (read.into !== 'body') fail(`${where}: a GET has no body: it pages into the query.`);
    const tokens = checkPointer(target.body, where);
    if (!tokens.length || tokens.some(token => reserved(token, ctx) || secretParameter(token))) fail(`${where}: ${target.body} names a body field the app reserves, or the body itself.`);
    if (Object.hasOwn(source.args, tokens[0])) fail(`${where}: the source already sends ${tokens[0]} as an argument.`);
    return;
  }
  fail(`${where} is {query: <name>} or {body: <pointer>}.`);
}
/** Search: local filtering, or provider search text that reaches the provider only as a reviewed text transform's output (spec line 672). */
function search(source, read, where, ctx) {
  const block = source.search;
  if (shaped(block, ['mode']) && block.mode === 'local') return;
  if (!shaped(block, ['mode', 'into', 'transform', 'argument', 'pick']) || block.mode !== 'provider') {
    fail(`${where}.search: provider search text reaches the provider only as the output of a reviewed text transform (spec line 672): {mode: 'provider', into, transform, argument, pick}, or {mode: 'local'}.`);
  }
  const entry = typeof block.transform === 'string' && /^text\./.test(block.transform) && ctx.transforms instanceof Map ? ctx.transforms.get(block.transform) : undefined;
  if (!entry || entry.kind !== 'map' || !entry.output) fail(`${where}.search: ${block.transform} is not a text transform the registry holds, with a closed output.`);
  if (typeof block.argument !== 'string' || entry.input.properties?.[block.argument]?.type !== 'string' || Object.keys(entry.stepData).includes(block.argument)) {
    fail(`${where}.search.argument: ${block.transform} takes no string argument ${block.argument}.`);
  }
  if ((entry.input.required ?? []).some(name => name !== block.argument)) fail(`${where}.search: ${block.transform} needs more than the search text, so it cannot build a provider query from it alone.`);
  const tokens = checkPointer(block.pick, `${where}.search.pick`);
  if (!tokens.length || fieldOf(entry.output, tokens)?.type !== 'string') fail(`${where}.search.pick: ${block.pick} is not a string field of ${block.transform}'s output.`);
  into(block.into, source, read, `${where}.search.into`, ctx);
}

/**
 * Part i: the choice sources of a folder (catalog/choices by default), by app: each *.json is named after its appId and validated with
 * `deps` (validateChoiceSources()). Anything else (the README) is ignored, and a missing folder is empty. It reads files and nothing else,
 * is not called at import, and server.mjs does not reach it; loadActions() calls it.
 */
export function loadChoiceSources(directory = new URL('../catalog/choices/', import.meta.url), deps = {}) {
  const base = directory instanceof URL ? fileURLToPath(directory) : String(directory), byApp = new Map();
  let files = [];
  try { files = readdirSync(base).filter(name => name.endsWith('.json')).sort(); } catch { return byApp; }
  for (const name of files) {
    const file = JSON.parse(readFileSync(path.join(base, name), 'utf8'));
    if (!record(file) || `${file.appId}.json` !== name) throw new Error(`Choice source file ${name} must be named after its appId.`);
    byApp.set(file.appId, validateChoiceSources(file, deps));
  }
  return byApp;
}

/**
 * The source a choice names by id: a choice source of the app first, else a version 1 option source (section 9), read as a directory
 * source of its operation that offers strings, with no exclude and no search. Null when neither holds it.
 */
export function sourceById(id, sources = [], options = []) {
  const own = (sources ?? []).find(source => record(source) && source.id === id);
  if (own) return own;
  const old = (options ?? []).find(source => record(source) && source.id === id);
  if (!old) return null;
  return Object.freeze({id: old.id, kind: 'directory', read: Object.freeze({operation: old.operation}), row: old.row, args: Object.freeze(Object.fromEntries(Object.entries(old.args ?? {}).map(([name, value]) => [name, {const: value}]))),
    items: old.items, value: old.value, valueType: 'string', label: old.label, page: old.pageToken ? {next: {pointer: old.pageToken.response}, into: {query: old.pageToken.parameter}, max: 10} : null, search: null,
    maxItems: old.maxItems, version: 1});
}

/**
 * Part i (section 9): the `choices` of an action or a trigger. Each names a source by id (sourceById()); its value type is the input's,
 * or its item type for a list; no enum or constant input takes choices; dependsOn names 1 to 3 other declared inputs, with no cycle and
 * no chain deeper than 3; args fill only configured arguments of the source, each from a constant or an input it depends on; a lookup
 * gives the input's type; and the source's exclude covers the excludes of every transform call that consumes the input, so a picker
 * never offers what the action refuses. `calls` are the transform facts of the file's expressions (lib/action-expressions.mjs);
 * `lookups` false refuses a lookup (a trigger has no prepare step to run one in).
 */
export function checkChoices(choices, {where, appId, inputSchema, sources = [], options = [], calls = [], lookups = true}) {
  if (!Array.isArray(choices) || choices.length > 32) fail(`${where}: choices holds at most 32 entries (section 9).`);
  const properties = inputSchema.properties, byInput = new Map();
  choices.forEach((choice, index) => {
    const at = `${where}: choices[${index}]`;
    if (!shaped(choice, ['input', 'source'], ['dependsOn', 'args', 'lookup']) || typeof choice.input !== 'string' || !Object.hasOwn(properties, choice.input)) {
      fail(`${at} is {input, source} for a declared input and may hold dependsOn, args and lookup (section 9).`);
    }
    if (byInput.has(choice.input)) fail(`${at}: ${choice.input} has its choices listed twice.`);
    byInput.set(choice.input, {choice, index});
    const source = typeof choice.source === 'string' ? sourceById(choice.source, sources, options) : null;
    if (!source) fail(`${at} names ${choice.source}, which is neither a choice source nor a version 1 option source of ${appId} (section 9).`);
    const schema = properties[choice.input], item = schema.type === 'array' ? schema.items : schema;
    if (Object.hasOwn(item, 'enum') || Object.hasOwn(item, 'const')) fail(`${at}: ${choice.input} is an enum or a constant: it takes no choices.`);
    if (item.type !== source.valueType) fail(`${at} offers ${choice.input} from ${source.id}, whose values are ${source.valueType}, and ${choice.input} takes ${item.type} values.`);
    if (choice.lookup !== undefined) {
      if (!lookups) fail(`${at}: a trigger's choices take no lookup: it has no prepare step to run one in.`);
      const lookup = sourceById(choice.lookup, sources, []);
      if (lookup?.kind !== 'lookup') fail(`${at} names the lookup source ${choice.lookup}, which ${appId}'s choice sources do not hold as a lookup (R12).`);
      if (lookup.valueType !== item.type) fail(`${at}.lookup ${lookup.id} gives ${lookup.valueType} values, and ${choice.input} takes ${item.type} values.`);
    }
    // dependsOn: other declared inputs, at most 3.
    const depends = choice.dependsOn ?? [];
    if (choice.dependsOn !== undefined && (!Array.isArray(depends) || !depends.length || depends.length > 3 || new Set(depends).size !== depends.length
      || !depends.every(name => typeof name === 'string' && name !== choice.input && Object.hasOwn(properties, name)))) {
      fail(`${at}.dependsOn names 1 to 3 distinct declared inputs other than ${choice.input}.`);
    }
    // args: only the source's configured arguments, each from a constant or an input this choice depends on.
    const configured = new Set(Object.entries(source.args ?? {}).filter(([, argument]) => Object.hasOwn(argument, 'configured')).map(([name]) => name));
    if (choice.args !== undefined) {
      if (!record(choice.args)) fail(`${at}.args maps configured arguments of ${source.id} to {const} or {input}.`);
      for (const [name, argument] of Object.entries(choice.args)) {
        if (!configured.has(name)) fail(`${at}.args.${name} names no configured argument of ${source.id}.`);
        const fromInput = shaped(argument, ['input']) && typeof argument.input === 'string' && depends.some(input => argument.input === `/${input.replace(/~/g, '~0').replace(/\//g, '~1')}`);
        if (!fromInput && !(shaped(argument, ['const']) && scalar(argument.const))) fail(`${at}.args.${name} takes {const} or {input} of an input ${choice.input} depends on.`);
      }
    }
    // Exclusions match refusals: every value a transform consuming the input refuses, the source never offers.
    for (const call of calls) {
      if (![...call.inputs].some(pointer => firstToken(pointer) === choice.input)) continue;
      for (const rule of call.excludes ?? []) {
        const offered = (source.exclude ?? []).map(value => rule.fold === 'ascii' ? fold(String(value)) : value);
        const missing = rule.values.filter(value => !offered.includes(rule.fold === 'ascii' ? fold(value) : value));
        if (missing.length) fail(`${at} offers ${choice.input} from ${source.id}, which does not exclude ${listWords(missing)}, values ${call.transform} refuses: a picker never offers what the action refuses (section 9).`);
      }
    }
  });
  // No cycle, and no chain deeper than 3, over the inputs that have choices.
  const depth = new Map(), active = [];
  const visit = input => {
    if (depth.has(input)) return depth.get(input);
    const cycle = active.indexOf(input);
    if (cycle !== -1) fail(`${where}: choices: ${listWords(active.slice(cycle))} depend on each other: dependsOn forms no cycle.`);
    active.push(input);
    const own = byInput.get(input)?.choice.dependsOn ?? [];
    const value = own.length ? 1 + Math.max(...own.map(visit)) : 0;
    active.pop();
    depth.set(input, value);
    return value;
  };
  for (const input of byInput.keys()) if (visit(input) > 3) fail(`${where}: choices: ${input} depends on a chain ${depth.get(input)} deep: dependsOn chains at most 3 deep.`);
}
const firstToken = pointer => pointer.slice(1).split('/')[0].replace(/~1/g, '/').replace(/~0/g, '~');

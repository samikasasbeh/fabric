import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {OPTION_SOURCES, sourceFor, validateOptionSources} from '../lib/option-sources.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {validateChoiceSources, loadChoiceSources, sourceById, checkChoices} from '../lib/choice-sources.mjs';
import {validatePermissionGroups} from '../lib/permission-groups.mjs';
import {validateActionFile, actionIds, loadActions, resolvedSchemaHash, effectiveInputSchema} from '../lib/actions.mjs';
import {validateInput} from '../lib/compiler.mjs';
import {runEntry} from '../lib/transforms/run.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {fixtureChoices, fixtureGroups, fixtureConfigs, fixtureMap, fixtureOptions, fixtureActions, fixtureRows, withIds, actionSchema} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS as SHIPPED} from '../lib/transforms/index.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';

// F10.9 parts i and j (docs/F10.9-BUILD-MAP.md section 9 and section 4): choice sources (options version 2) in their own folder and map,
// and inputs whose fields depend on the chosen resource. Zero churn for version 1 is pinned (R10): the version 2 format can never reach
// OPTION_SOURCES, sourceFor() or POST /v1/options through the version 1 loader.
const OPTIONS = new URL('../catalog/options/', import.meta.url);

test('R10: both shipped version 1 options files validate unchanged, and the version 1 loader refuses a version 2 file', () => {
  const files = readdirSync(OPTIONS).filter(name => name.endsWith('.json')).sort();
  assert.deepEqual(files, ['gmail.json', 'google-calendar.json']);
  for (const name of files) {
    const file = JSON.parse(readFileSync(new URL(name, OPTIONS), 'utf8'));
    assert.deepEqual(validateOptionSources(file), OPTION_SOURCES.get(file.appId), name);
  }
  const choices = fixtureChoices(), groups = fixtureGroups();
  assert.equal(choices.schemaVersion, 2);
  assert.throws(() => validateOptionSources(choices, groups), /exactly appId, reviewed, schemaVersion 1 and sources/, 'the fixture choices file');
  assert.throws(() => validateOptionSources({...fixtureOptions(), schemaVersion: 2}, groups), /schemaVersion 1/, 'a version 1 file marked version 2');
  assert.doesNotThrow(() => validateOptionSources(fixtureOptions(), groups), 'the fixture\'s own version 1 file');
});

// ---- part i: choice sources and choices -----------------------------------------------------------------------------------------------
// The fixture app's dependencies, and the shipped apps' with F10.7's synthetic Gmail and Calendar maps (test/actions-placement.test.mjs
// says why they are not Google's paths).
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const FIXTURE_DEPS = (() => {
  const groups = fixtureGroups();
  return {groups, configs: fixtureConfigs(groups), maps: new Map([['fixture', fixtureMap()]]), transforms: TRANSFORMS, pins: PINS, choices: new Map([['fixture', fixtureChoices().sources]])};
})();
const SOURCE_DEPS = {groups: FIXTURE_DEPS.groups, configs: FIXTURE_DEPS.configs, maps: FIXTURE_DEPS.maps, transforms: TRANSFORMS};
const SYNTHETIC = json('./fixtures/access/f10-7-bindings.before.json').maps;
const GMAIL_MAP = {...SYNTHETIC.gmail, operations: SYNTHETIC.gmail.operations.map(operation => operation.id === 'gmail.users.getProfile' ? {...operation, method: 'GET'} : operation)};
const APP_DEPS = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, maps: new Map([['gmail', GMAIL_MAP], ['google-calendar', SYNTHETIC['google-calendar']]]), transforms: TRANSFORMS, pins: PINS,
  choices: new Map(), identities: new Map([['gmail', definitionFor('google')], ['google-calendar', definitionFor('google')]])};
// Part l: validate() keeps a copy of every file the validator accepts, for the schema test at the end of this file.
const ACCEPTED = [];
const validate = (file, deps = FIXTURE_DEPS) => {
  const written = withIds(file, deps), result = validateActionFile(written, deps);
  ACCEPTED.push(structuredClone(written));
  return result;
};
const entryOf = (file, deps) => validate(file, deps).actions[0];
const refusedFile = (file, pattern, deps = FIXTURE_DEPS, message) => assert.throws(() => validate(file, deps), pattern, message);
/** The fixture file holding only the action `key`, edited in place by `edit`, without the superseded list. */
function edited(key, edit = () => {}) {
  const {superseded, ...file} = fixtureActions();
  void superseded;
  const action = structuredClone(file.actions.find(entry => entry.key === key));
  edit(action);
  return {...file, actions: [action]};
}
/** One fixture choice source, a fresh copy. */
const sourceOf = id => structuredClone(fixtureChoices().sources.find(source => source.id === id));
/** FIXTURE_DEPS with the fixture's choice sources changed by `change` (given a fresh copy of each). */
const withSources = change => ({...FIXTURE_DEPS, choices: new Map([['fixture', fixtureChoices().sources.map(source => change(structuredClone(source)))]])});
const loads = (sources, appId = 'fixture', deps = SOURCE_DEPS) => validateChoiceSources({schemaVersion: 2, appId, reviewed: 'A test file.', sources}, deps);
const loadRefused = (sources, pattern, message, appId, deps) => assert.throws(() => loads(sources, appId, deps), pattern, message);
const closed = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
const OK = {status: [200], require: []};
const WRITE_HINTS = {readOnly: false, destructive: false, idempotent: false, openWorld: true}, READ_HINTS = {readOnly: true, destructive: false, idempotent: true, openWorld: true};
const ZEROS = '0'.repeat(24);
const fileOf = (appId, actions, more = {}) => ({schemaVersion: 1, appId, specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {}, ...more, actions});
const actionOf = (appId, key, fields) => ({id: `${appId}.action.${key}.v1.${ZEROS}`, key, version: 1, name: key, description: `The ${key} test action.`, guards: [], prepare: [],
  preview: [], definitive: [400], ...fields});
/** Files under `root`, reached through relative imports from `start`. */
function reached(start) {
  const seen = new Set(), queue = [start];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const text = readFileSync(file, 'utf8');
    for (const match of text.matchAll(/(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(['"])(\.{1,2}\/[^'"]+)\1/g)) if (/\.m?[jt]s$/.test(match[2])) queue.push(path.resolve(path.dirname(file), match[2]));
  }
  return seen;
}

test('part i: zero churn (R10): a choices folder with a Gmail version 2 file loads through loadChoiceSources(), and the version 1 readers answer exactly as before', t => {
  const before = JSON.stringify([...OPTION_SOURCES]), labels = sourceFor('gmail', 'labelIds'), calendars = sourceFor('google-calendar', 'calendarId');
  const groups = new Map([...PERMISSION_GROUPS, ...fixtureGroups()]), configs = new Map([...PROXY_CONFIGS, ...fixtureConfigs(fixtureGroups())]);
  const loaded = loadChoiceSources(new URL('./fixtures/actions/choices/', import.meta.url), {groups, configs, maps: new Map([['fixture', fixtureMap()]]), transforms: TRANSFORMS});
  assert.deepEqual([...loaded.keys()], ['fixture', 'gmail']);
  const [gmail] = loaded.get('gmail');
  assert.deepEqual([gmail.id, gmail.read.operation, Object.hasOwn(gmail, 'serves')], ['user-labels', 'gmail.users.labels.list', false]);
  assert.ok(Object.isFrozen(loaded.get('gmail')) && Object.isFrozen(gmail) && Object.isFrozen(gmail.exclude));
  // The version 1 readers are untouched: the same sources, by name; a version 2 source fills no input by name.
  assert.equal(JSON.stringify([...OPTION_SOURCES]), before);
  assert.equal(sourceFor('gmail', 'labelIds'), labels);
  assert.equal(sourceFor('google-calendar', 'calendarId'), calendars);
  assert.equal(sourceFor('gmail', 'user-labels'), null);
  // POST /v1/options reads only the version 1 readers: lib/tenant/options.mjs reaches lib/option-sources.mjs and never lib/choice-sources.mjs.
  const root = fileURLToPath(new URL('..', import.meta.url)), graph = reached(path.join(root, 'lib/tenant/options.mjs'));
  assert.ok(graph.has(path.join(root, 'lib/option-sources.mjs')));
  assert.ok(!graph.has(path.join(root, 'lib/choice-sources.mjs')), 'the options route never reads choice sources');
  // The loader: one *.json per app, named after it; README.md ignored; a missing or empty folder is empty.
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-choices-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  assert.equal(loadChoiceSources(path.join(dir, 'missing'), SOURCE_DEPS).size, 0);
  const folder = path.join(dir, 'choices');
  mkdirSync(folder);
  writeFileSync(path.join(folder, 'README.md'), 'Reviewed choice sources, one file per app.\n');
  assert.equal(loadChoiceSources(folder, SOURCE_DEPS).size, 0);
  writeFileSync(path.join(folder, 'fixture.json'), JSON.stringify(fixtureChoices()));
  assert.deepEqual([...loadChoiceSources(folder, SOURCE_DEPS).get('fixture')], [...validateChoiceSources(fixtureChoices(), SOURCE_DEPS)]);
  writeFileSync(path.join(folder, 'other.json'), JSON.stringify(fixtureChoices()));
  assert.throws(() => loadChoiceSources(folder, SOURCE_DEPS), /Choice source file other\.json must be named after its appId/);
  // The shipped folder holds only its README, and loadActions() loads it when no choice sources are given.
  assert.deepEqual(readdirSync(new URL('../catalog/choices/', import.meta.url)), ['README.md']);
  assert.equal(loadChoiceSources().size, 0);
  assert.equal(loadActions(path.join(dir, 'no-actions')).size, 0);
  // loadActions() without choice sources loads the choices folder beside its actions folder, as catalog/actions sits beside catalog/choices.
  const catalog = path.join(dir, 'catalog'), actions = path.join(catalog, 'actions'), beside = path.join(catalog, 'choices');
  mkdirSync(actions, {recursive: true});
  mkdirSync(beside);
  writeFileSync(path.join(actions, 'fixture.json'), JSON.stringify(fixtureActions()));
  const {choices, ...withoutChoices} = FIXTURE_DEPS;
  void choices;
  assert.throws(() => loadActions(actions, withoutChoices), /list-items v1: choices\[0\] names the lookup source label, which fixture's choice sources do not hold as a lookup/);
  writeFileSync(path.join(beside, 'fixture.json'), JSON.stringify(fixtureChoices()));
  assert.deepEqual(loadActions(actions, withoutChoices).get('fixture'), validateActionFile(fixtureActions(), FIXTURE_DEPS));
});

test('part i: a valid choice source file comes back frozen, field for field, with its kind, read, row and arguments', () => {
  const sources = validateChoiceSources(fixtureChoices(), SOURCE_DEPS);
  assert.ok(Object.isFrozen(sources) && sources.every(Object.isFrozen));
  assert.deepEqual(sources.map(source => [source.id, source.kind, source.valueType, source.row]), [
    ['items', 'directory', 'string', 'fixture.items.read'], ['labels', 'directory', 'string', 'fixture.items.read'], ['label', 'lookup', 'string', 'fixture.items.read'], ['found', 'directory', 'string', 'fixture.items.read']]);
  assert.deepEqual(JSON.parse(JSON.stringify(sources)), fixtureChoices().sources);
  // The RPC twin: a GET in a read row, and a reviewed-read POST.
  const rpc = {id: 'messages', kind: 'directory', read: {request: 'GET /messages.list'}, row: 'fixture-rpc.messages.read', args: {limit: {const: 100}}, items: '/messages', value: '/ts',
    valueType: 'string', label: ['/text'], page: {next: {pointer: '/response_metadata/next_cursor'}, into: {query: 'cursor'}, max: 5}, search: null, maxItems: 500};
  assert.equal(loads([rpc, {...rpc, id: 'canvases', read: {request: 'POST /canvases.read'}, page: null, args: {}}], 'fixture-rpc')[1].read.request, 'POST /canvases.read');
  // Without its map the fixture's request templates cannot be placed, so a request source is checked against its row's members only.
  const unmapped = {...SOURCE_DEPS, maps: new Map()};
  assert.doesNotThrow(() => loads([sourceOf('labels')], 'fixture', unmapped));
  loadRefused([{...sourceOf('labels'), read: {request: 'GET /keys'}}], /labels: GET \/keys is not a member of fixture\.items\.read/, 'unplaced, still a member of its row', 'fixture', unmapped);
  loadRefused([{...sourceOf('labels'), read: {request: 'GET /items/{item_id}/history'}, args: {item_id: {configured: 'itemId'}}}], /labels: GET \/items\/\{item_id\}\/history is unavailable, so it never fills a choice list/,
    'unplaced, an unavailable member', 'fixture', unmapped);
  // A member whose row routes its body could be moved to another row by what the source sends.
  const rows = fixtureRows();
  rows.groups.find(group => group.id === 'fixture.items.read').bodyRoutes = [{member: 'POST /items/search', pointer: '/scope', equals: 'all', to: 'fixture.keys.read'}];
  const routed = {...SOURCE_DEPS, groups: new Map([...SOURCE_DEPS.groups, ['fixture', validatePermissionGroups(rows)]])};
  loadRefused([sourceOf('found')], /found: POST \/items\/search has body routes, so what a choice source sends could move it to another row/, 'a routed member', 'fixture', routed);
});

test('part i: choice sources refused at load: rows, members, reads and arguments (section 9)', () => {
  const labels = sourceOf('labels');
  for (const [label, source, pattern] of [
    ['a template not a member of the named row', {...labels, read: {request: 'GET /keys'}}, /labels: GET \/keys lands in fixture\.keys\.read, not its row fixture\.items\.read/],
    ['a GET landing in Other', {...labels, read: {request: 'GET /nowhere'}}, /labels: GET \/nowhere lands in Other reads: an action step runs only on a reviewed member of a reviewed row/],
    ['a POST landing in Other', {...labels, read: {request: 'POST /nowhere'}}, /lands in Other changes/],
    ['a locked row', {...labels, read: {request: 'POST /hooks'}}, /lands in Give access to other people or services, a row Fabric locks/],
    ['an unavailable member', {...labels, read: {request: 'GET /items/{item_id}/history'}, args: {item_id: {configured: 'itemId'}}}, /which is unavailable/],
    ['a write row', {...labels, read: {request: 'POST /labels'}, row: 'fixture.labels.write'}, /labels: a choice source reads a read row, and fixture\.labels\.write is a write row/],
    ['a row of no app', {...labels, row: 'fixture.nothing'}, /labels: row names no row of fixture/],
    ['a POST not in reviewedReads', {...labels, read: {request: 'POST /items/export'}}, /labels: POST \/items\/export is a POST its row does not list in reviewedReads: a choice source reads only a reviewed read \(section 9\)/],
    ['a sensitive member', {...labels, read: {request: 'GET /keys/{key_id}'}, row: 'fixture.keys.read', args: {key_id: {configured: 'keyId'}}}, /labels: GET \/keys\/\{key_id\} is marked sensitive: its answer can carry a secret, so it never fills a choice list/],
    ['a POST paged into the query', {...sourceOf('found'), page: {next: {pointer: '/next_cursor'}, into: {query: 'cursor'}, max: 3}}, /found\.page\.into: a POST sends its arguments in the body: it pages and searches into the body/],
    ['a page parameter the source already sends', {...labels, page: {next: {pointer: '/next'}, into: {query: 'type'}, max: 3}}, /labels\.page\.into: the source already sends type as an argument/],
    ['search text into a reserved body field', {...sourceOf('found'), search: {...sourceOf('found').search, into: {body: '/erase_content'}}}, /found\.search\.into: \/erase_content names a body field the app reserves, or the body itself/],
    ['search text as the whole body', {...sourceOf('found'), search: {...sourceOf('found').search, into: {body: ''}}}, /found\.search\.into:  names a body field the app reserves, or the body itself/],
    ['search text into a body field an argument sends', {...sourceOf('found'), search: {...sourceOf('found').search, into: {body: '/kind'}}}, /found\.search\.into: the source already sends kind as an argument/],
    ['an operation of another row', {...labels, read: {operation: 'fixture.items.list'}, row: 'fixture.keys.read'}, /labels: fixture\.items\.list is not an operation of the read row fixture\.keys\.read/],
    ['a read of both kinds', {...labels, read: {request: 'GET /labels', operation: 'fixture.items.list'}}, /labels: read is \{operation\} or \{request: 'GET \/template' \| 'POST \/template'\}/],
    ['a PUT', {...labels, read: {request: 'PUT /labels'}}, /read is \{operation\} or \{request/],
    ['a path parameter left open', {...labels, read: {request: 'GET /labels/{label_id}'}, args: {}}, /labels: the path parameter label_id is filled by no argument/],
  ]) loadRefused([source], pattern, label);
  // Arguments: constants, configured values, and on a lookup one {value: true}; never a reserved or credential-shaped name.
  for (const [label, source, pattern] of [
    ['quotaUser', {...labels, args: {quotaUser: {const: 'q'}}}, /labels\.args\.quotaUser: quotaUser is reserved: a choice source never sends it \(spec line 740\)/],
    ['key', {...labels, args: {key: {const: 'k'}}}, /labels\.args\.key: key is reserved/],
    ['a credential name', {...labels, args: {access_token: {const: 'x'}}}, /labels\.args\.access_token: access_token is reserved/],
    ['a reserved body field', {...sourceOf('found'), args: {erase_content: {const: true}}}, /found\.args\.erase_content: erase_content is reserved/],
    ['an argument of another shape', {...labels, args: {type: {input: '/kind'}}}, /labels\.args\.type is \{const\}, \{configured: <name>\} or, on a lookup, \{value: true\}/],
    ['a value on a directory source', {...labels, args: {type: {value: true}}}, /labels\.args\.type: \{value: true\} is the one argument of a lookup/],
  ]) loadRefused([source], pattern, label);
  const rpc = {id: 'messages', kind: 'directory', read: {request: 'GET /messages.list'}, row: 'fixture-rpc.messages.read', args: {token: {const: 'xoxp'}}, items: '/messages', value: '/ts', valueType: 'string',
    label: ['/text'], page: null, search: null, maxItems: 500};
  loadRefused([rpc], /messages\.args\.token: token is reserved/, 'Slack token', 'fixture-rpc');
  loadRefused([{...rpc, read: {request: 'POST /canvases.read'}}], /messages\.args\.token: token is reserved/, 'Slack token in a body', 'fixture-rpc');
});

test('part i: choice sources refused at load: pointers (R11), paging, search, lookups, bounds and fields', () => {
  const labels = sourceOf('labels'), label = sourceOf('label'), found = sourceOf('found');
  for (const [name, source, pattern] of [
    ['a value pointer with a secret token', {...labels, value: '/temp_clone_token'}, /labels\.value: the pointer \/temp_clone_token reads temp_clone_token, a field that carries a secret, so it is refused wherever it appears \(R11\)/],
    ['a label pointer', {...labels, label: ['/name', '/owner/access_token']}, /labels\.label\[1\]: the pointer \/owner\/access_token reads access_token/],
    ['a detail pointer', {...labels, detail: ['/client_secret']}, /labels\.detail\[0\]: the pointer \/client_secret reads client_secret/],
    ['an items pointer', {...labels, items: '/private_key'}, /labels\.items: the pointer \/private_key reads private_key/],
    ['four labels', {...labels, label: ['/a', '/b', '/c', '/d']}, /labels: label holds 1 to 3 pointers/],
    ['Link paging without param', {...labels, page: {next: {link: 'next'}, into: {query: 'page'}, max: 3}}, /labels\.page\.next is \{pointer\} or \{link: 'next', param\}: Link paging takes only the named page parameter/],
    ['eleven pages', {...labels, page: {next: {pointer: '/next'}, into: {query: 'pageToken'}, max: 11}}, /labels: page is null or \{next, into, max\}, with a max of 1 to 10 \(I7\)/],
    ['a reserved page parameter', {...labels, page: {next: {pointer: '/next'}, into: {query: 'quotaUser'}, max: 3}}, /labels\.page\.into: quotaUser is reserved/],
    ['a GET paged into a body', {...labels, page: {next: {pointer: '/next'}, into: {body: '/cursor'}, max: 3}}, /labels\.page\.into: a GET has no body: it pages into the query/],
    ['provider search without a transform', {...labels, search: {mode: 'provider', into: {query: 'q'}}}, /labels\.search: provider search text reaches the provider only as the output of a reviewed text transform \(spec line 672\): \{mode: 'provider', into, transform, argument, pick\}/],
    ['a POST body fed raw by search text', {...found, search: {mode: 'provider', into: {body: '/query'}}}, /found\.search: provider search text reaches the provider only as the output of a reviewed text transform/],
    ['a transform that is not a text transform', {...found, search: {...found.search, transform: 'collections.oneOf@1', argument: 'value', pick: '/value'}}, /found\.search: collections\.oneOf@1 is not a text transform the registry holds/],
    ['a map transform of another family', {...found, search: {...found.search, transform: 'encoding.base64Encode@1', argument: 'text', pick: '/encoded'}}, /found\.search: encoding\.base64Encode@1 is not a text transform the registry holds/],
    ['an unknown transform', {...found, search: {...found.search, transform: 'text.nothing@1'}}, /found\.search: text\.nothing@1 is not a text transform the registry holds/],
    ['an argument the transform does not take', {...found, search: {...found.search, argument: 'nothing'}}, /found\.search\.argument: text\.gmailQuery@1 takes no string argument nothing/],
    ['a pick of no output field', {...found, search: {...found.search, pick: '/nothing'}}, /found\.search\.pick: \/nothing is not a string field of text\.gmailQuery@1's output/],
    ['a lookup that pages', {...label, page: {next: {pointer: '/next'}, into: {query: 'pageToken'}, max: 3}}, /label: a lookup reads one item by its id: no paging and no search/],
    ['a lookup that searches', {...label, search: {mode: 'local'}}, /label: a lookup reads one item by its id: no paging and no search/],
    ['a lookup with no {value: true}', {...label, args: {label_id: {const: 'x'}}}, /label: a lookup takes exactly one \{value: true\} argument, the id it reads/],
    ['maxItems 0', {...labels, maxItems: 0}, /labels: maxItems is 1 to 1000/],
    ['maxItems 1001', {...labels, maxItems: 1001}, /labels: maxItems is 1 to 1000/],
    ['an unknown key', {...labels, extra: true}, /labels: a choice source holds exactly id, kind, read, row, args, items, value, valueType, label, page, search and maxItems, and may hold detail and exclude/],
    ['a serves field', {...labels, serves: ['labelIds']}, /labels: a choice source fills no input by name, so it has no serves field: an action names it by id \(R10\)/],
    ['a value type of another kind', {...labels, valueType: 'boolean'}, /labels: valueType is string or integer/],
    ['an exclude of another type', {...labels, exclude: [7]}, /labels: exclude lists 1 to 50 distinct string values/],
    ['51 excludes', {...labels, exclude: Array.from({length: 51}, (_, index) => `L${index}`)}, /exclude lists 1 to 50/],
    ['an unknown kind', {...labels, kind: 'search'}, /labels: kind is directory or lookup/],
  ]) loadRefused([source], pattern, name);
  // Link paging reads the next page number through ids.linkPage@1 (a step 17 transform, a stub in the fixture registry).
  const linked = {...labels, page: {next: {link: 'next', param: 'page'}, into: {query: 'page'}, max: 3}};
  assert.doesNotThrow(() => loads([linked]), 'Link paging with its transform');
  loadRefused([linked], /labels\.page\.next: Link paging reads the next page through ids\.linkPage@1, which the registry does not hold/, 'without it', 'fixture', {...SOURCE_DEPS, transforms: SHIPPED});
  loadRefused([labels, {...sourceOf('items'), id: 'labels'}], /fixture: the choice source id labels is used twice/, 'a repeated id');
  assert.throws(() => validateChoiceSources({...fixtureChoices(), schemaVersion: 1}, SOURCE_DEPS), /Choice sources for fixture: a choice source file holds exactly schemaVersion 2, appId, reviewed and sources/);
  assert.throws(() => validateChoiceSources({...fixtureChoices(), appId: 'nothing'}, SOURCE_DEPS), /Choice sources for nothing: the app has no reviewed permission rows and proxy settings/);
  assert.throws(() => validateChoiceSources({...fixtureChoices(), sources: []}, SOURCE_DEPS), /holds 1 to 20 sources/);
});

test('part i: choices name a source by id, typed, with closed dependsOn and arguments; servesSource is the same read', () => {
  // The fixture file's choices validate whole (part f's test checks it); each refusal below changes one choice.
  assert.doesNotThrow(() => validate(fixtureActions()));
  for (const [label, file, pattern] of [
    ['an unknown source', edited('update-item', action => { action.choices[0].source = 'nothing'; }), /update-item v1: choices\[0\] names nothing, which is neither a choice source nor a version 1 option source of fixture \(section 9\)/],
    ['a source of another app', edited('update-item', action => { action.choices[0].source = 'calendars'; }), /choices\[0\] names calendars, which is neither a choice source nor a version 1 option source of fixture/],
    ['choices on an enum input', edited('update-item', action => { action.choices.push({input: 'change', source: 'items'}); }), /update-item v1: choices\[2\]: change is an enum or a constant: it takes no choices/],
    ['an input listed twice', edited('update-item', action => { action.choices.push({input: 'itemId', source: 'items'}); }), /update-item v1: choices\[2\]: itemId has its choices listed twice/],
    ['dependsOn naming an undeclared input', edited('update-item', action => { action.choices[1].dependsOn = ['nothing']; }), /update-item v1: choices\[1\]\.dependsOn names 1 to 3 distinct declared inputs other than labels/],
    ['dependsOn naming itself', edited('update-item', action => { action.choices[1].dependsOn = ['labels']; }), /choices\[1\]\.dependsOn names 1 to 3 distinct declared inputs other than labels/],
    ['four dependsOn', edited('update-item', action => { action.choices[1].dependsOn = ['itemId', 'change', 'name', 'itemId']; }), /choices\[1\]\.dependsOn names 1 to 3 distinct declared inputs/],
    ['a dependsOn cycle', edited('update-item', action => { action.choices[0].dependsOn = ['labels']; }), /update-item v1: choices: itemId and labels depend on each other: dependsOn forms no cycle/],
    ['args mapping an input outside dependsOn', edited('update-item', action => { action.choices[1].source = 'found'; action.choices[1].args = {kind: {input: '/name'}}; }), /update-item v1: choices\[1\]\.args\.kind takes \{const\} or \{input\} of an input labels depends on/],
    ['args naming a source argument that is not configured', edited('update-item', action => { action.choices[1].args = {type: {const: 'user'}}; }), /update-item v1: choices\[1\]\.args\.type names no configured argument of labels/],
    ['servesSource on another read', edited('list-items', action => { action.servesSource = 'labels'; }), /list-items v1: servesSource labels reads GET \/labels, and the list step list reads fixture\.items\.list: an agent's listing is the same read \(section 9\)/],
    ['servesSource of no source', edited('list-items', action => { action.servesSource = 'nothing'; }), /list-items v1: servesSource names nothing, which is neither a choice source nor a version 1 option source of fixture/],
    ['servesSource on a write', edited('update-item', action => { action.servesSource = 'items'; }), /update-item v1: servesSource is only on a read action: it names the list a read serves/],
  ]) refusedFile(file, pattern, FIXTURE_DEPS, label);
  // A source's value type is the input's, or its item type for a list.
  refusedFile(edited('update-item'), /update-item v1: choices\[1\] offers labels from labels, whose values are integer, and labels takes string values/, withSources(source => source.id === 'labels' ? {...source, valueType: 'integer', exclude: undefined} : source));
  // A configured argument takes a constant or a dependsOn input; a lookup's value type is checked too.
  assert.equal(entryOf(edited('update-item', action => { action.choices[1].source = 'found'; action.choices[1].args = {kind: {input: '/itemId'}}; }), withSources(source => source.id === 'found' ? {...source, exclude: ['SENT', 'DRAFT', 'TRASH', 'SPAM']} : source)).key, 'update-item');
  refusedFile(edited('list-items'), /list-items v1: choices\[0\]\.lookup label gives integer values, and labelId takes string values/, withSources(source => source.id === 'label' ? {...source, valueType: 'integer'} : source));
  // dependsOn chains at most 3 deep.
  const chained = depth => fileOf('fixture', [actionOf('fixture', 'chained', {effect: 'read', row: 'fixture.items.read', hints: READ_HINTS,
    inputSchema: closed(Object.fromEntries(['a', 'b', 'c', 'd', 'e'].map(name => [name, words(64)]))), outputSchema: closed({count: {type: 'integer', minimum: 0, maximum: 1000}}),
    choices: ['a', 'b', 'c', 'd', 'e'].slice(0, depth + 1).map((name, index, names) => ({input: name, source: 'items', ...(index ? {dependsOn: [names[index - 1]]} : {})})),
    perform: [{id: 'list', method: 'GET', path: '/items', query: Object.fromEntries(['a', 'b', 'c', 'd', 'e'].map(name => [name, {input: `/${name}`}])), expect: OK}],
    output: {count: {step: 'list', pointer: '/count'}}})], {pinnedParameters: {account: 'me'}});
  assert.equal(entryOf(chained(3)).key, 'chained');
  refusedFile(chained(4), /chained v1: choices: e depends on a chain 4 deep: dependsOn chains at most 3 deep/);
  // A version 1 source by id serves a Calendar action unchanged (no exclude, no search).
  const calendar = fileOf('google-calendar', [actionOf('google-calendar', 'find-events', {effect: 'read', row: 'google-calendar.events.read', hints: READ_HINTS,
    inputSchema: closed({calendarId: words(200)}), outputSchema: closed({count: {type: 'integer', minimum: 0, maximum: 250}}),
    choices: [{input: 'calendarId', source: 'calendars'}],
    perform: [{id: 'events', method: 'GET', path: '/events/list', query: {calendarId: {input: '/calendarId'}}, expect: OK}], output: {count: {step: 'events', pointer: '/count'}}})]);
  assert.equal(entryOf(calendar, APP_DEPS).key, 'find-events');
  assert.equal(sourceById('calendars', [], OPTION_SOURCES.get('google-calendar')).read.operation, OPTION_SOURCES.get('google-calendar')[0].operation);
  assert.deepEqual(sourceById('items', fixtureChoices().sources, [{...OPTION_SOURCES.get('google-calendar')[0], id: 'items'}]).read, {operation: 'fixture.items.list'}, 'a choice source comes before a version 1 source');
  // checkChoices() on its own: a lookup names a lookup source (part f refuses it first in an action), and triggers take no lookup.
  const own = {where: '$c', appId: 'fixture', inputSchema: closed({labelId: words(64)}), sources: fixtureChoices().sources};
  assert.throws(() => checkChoices([{input: 'labelId', source: 'labels', lookup: 'labels'}], own), /\$c: choices\[0\] names the lookup source labels, which fixture's choice sources do not hold as a lookup \(R12\)/);
  assert.throws(() => checkChoices([{input: 'labelId', source: 'labels', lookup: 'label'}], {...own, lookups: false}), /\$c: choices\[0\]: a trigger's choices take no lookup/);
  assert.doesNotThrow(() => checkChoices([{input: 'labelId', source: 'labels', lookup: 'label'}], own));
  for (const choice of [{input: 'nothing', source: 'labels'}, {input: 'labelId', source: 'labels', extra: 1}, {input: 7, source: 'labels'}]) {
    assert.throws(() => checkChoices([choice], own), /\$c: choices\[0\] is \{input, source\} for a declared input and may hold dependsOn, args and lookup \(section 9\)/, JSON.stringify(choice));
  }
  assert.throws(() => checkChoices(Array.from({length: 33}, () => ({input: 'labelId', source: 'labels'})), own), /\$c: choices holds at most 32 entries/);
});

test('part i: lookups (R12): a lookup source\'s request is part of the action id, a list-only source is not, and a lookup counts as a step', () => {
  const list = fixtureActions().actions[0].id, idOf = deps => actionIds(edited('list-items'), deps).get('list-items v1').id;
  assert.equal(idOf(FIXTURE_DEPS), list);
  for (const [label, change] of [
    ['its template and row', source => ({...source, read: {request: 'GET /keys/{key_id}'}, row: 'fixture.keys.read', args: {key_id: {value: true}}})],
    ['its arguments', source => ({...source, args: {...source.args, view: {const: 'full'}}})],
    ['its value pointer', source => ({...source, value: '/labelId'})],
    ['its label pointers', source => ({...source, label: ['/name', '/color']})],
    ['its items pointer', source => ({...source, items: '/label'})]]) {
    assert.notEqual(idOf(withSources(source => source.id === 'label' ? change(source) : source)), list, `editing the lookup source's ${label}`);
  }
  for (const [label, change] of [['exclude', source => ({...source, exclude: ['TRASH']})], ['maxItems', source => ({...source, maxItems: 100})], ['its label', source => ({...source, label: ['/title']})]]) {
    assert.equal(idOf(withSources(source => source.id === 'labels' ? change(source) : source)), list, `editing a list-only source's ${label}`);
  }
  refusedFile(edited('list-items', action => {
    for (const id of ['a', 'b', 'c', 'd', 'e', 'f']) action.prepare.push({id, method: 'GET', path: '/labels', maxResponseBytes: 1_024, expect: OK});
  }), /list-items v1: declares 9 steps; an action holds at most 8, counting schema steps and choice lookups \(I7\)/);
});

// F10.10 (open question 6): a lookup sends only its source's constant arguments, the choice's closed input value and configured values, so
// a lookup on a reviewed-read POST is a read built from reads, in its source's row. Choice-source loading keeps its own reviewedReads check.
test('F10.10: a choice lookup on a reviewed-read POST places as a read in its source\'s row; a lookup source on a POST that is not listed is still refused at load', () => {
  const searched = withSources(source => source.id === 'label' ? {...source, read: {request: 'POST /items/search'}, args: {id: {value: true}}} : source);
  const entry = entryOf(edited('list-items'), searched), lookup = entry.placements.find(placement => placement.stepId === 'choice:labelId');
  assert.deepEqual([lookup.phase, lookup.member, lookup.groupId, lookup.reviewedRead, lookup.fromReads, lookup.effect], ['lookup', 'POST /items/search', 'fixture.items.read', true, true, 'read']);
  assert.deepEqual([entry.effect, entry.lookups.labelId.template], ['read', 'POST /items/search']);
  loadRefused([{...sourceOf('label'), read: {request: 'POST /items/export'}, args: {id: {value: true}}}],
    /label: POST \/items\/export is a POST its row does not list in reviewedReads: a choice source reads only a reviewed read \(section 9\)/, 'a lookup on a POST that is not listed');
});

test('part i: adversarial: a choice never offers a value the action refuses: a source\'s exclude covers the excludes of every transform that consumes the input', () => {
  // The fixture's labels source excludes SENT, DRAFT, TRASH and SPAM, which collections.labelIds@1 refuses: accepted. Folded as the transform folds.
  assert.equal(entryOf(edited('update-item'), withSources(source => source.id === 'labels' ? {...source, exclude: ['sent', 'Draft', 'TRASH', 'spam']} : source)).key, 'update-item');
  refusedFile(edited('update-item'), /update-item v1: choices\[1\] offers labels from labels, which does not exclude SENT, DRAFT, TRASH and SPAM, values collections\.labelIds@1 refuses: a picker never offers what the action refuses \(section 9\)/,
    withSources(source => source.id === 'labels' ? {...source, exclude: undefined} : source));
  refusedFile(edited('update-item'), /which does not exclude SENT, DRAFT and SPAM, values collections\.labelIds@1 refuses/, withSources(source => source.id === 'labels' ? {...source, exclude: ['TRASH']} : source));
  // A version 1 source excludes nothing, so it never serves an input such a transform consumes.
  const v1 = {...FIXTURE_DEPS, options: new Map([['fixture', [{...validateOptionSources(fixtureOptions(), FIXTURE_DEPS.groups)[0], id: 'oldLabels'}]]])};
  refusedFile(edited('update-item', action => { action.choices[1].source = 'oldLabels'; }), /choices\[1\] offers labels from oldLabels, which does not exclude SENT, DRAFT, TRASH and SPAM/, v1);
  // Organize email on Gmail: the shipped version 1 labels source offers TRASH, SPAM, SENT and DRAFT; a choice source that excludes them serves it.
  const organize = source => fileOf('gmail', [actionOf('gmail', 'organize-email', {effect: 'write', row: 'gmail.messages.mark', hints: WRITE_HINTS,
    inputSchema: closed({messageId: words(64), labels: {type: 'array', maxItems: 25, items: words(100)}}), outputSchema: closed({id: words(64)}),
    choices: [{input: 'labels', source}],
    prepare: [{id: 'labels', method: 'GET', path: '/gmail/v1/users/{userId}/labels/list', expect: OK}],
    perform: [{id: 'modify', method: 'POST', path: '/gmail/v1/users/{userId}/messages/batchModify',
      body: {object: {ids: {array: [{input: '/messageId'}]}, addLabelIds: {pick: {transform: 'collections.labelIds@1', args: {list: {step: 'labels', pointer: ''}, names: {input: '/labels'}}}, pointer: '/ids'}, removeLabelIds: {const: []}}},
      expect: {status: [204], require: []}}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/gmail/v1/users/{userId}/messages/get', query: {id: {input: '/messageId'}}, expect: OK}],
      identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {input: '/messageId'}}], assert: []},
    output: {id: {step: 'check', pointer: '/id'}}})], {pinnedParameters: {userId: 'me'}});
  refusedFile(organize('labels'), /organize-email v1: choices\[0\] offers labels from labels, which does not exclude SENT, DRAFT, TRASH and SPAM, values collections\.labelIds@1 refuses/, APP_DEPS);
  const gmailChoices = json('./fixtures/actions/choices/gmail.json');
  assert.equal(entryOf(organize('user-labels'), {...APP_DEPS, choices: new Map([['gmail', validateChoiceSources(gmailChoices, APP_DEPS)]])}).key, 'organize-email');
});

// ---- part j: resource-dependent inputs (section 9; R14) ----------------------------------------------------------------------------
const PLACEHOLDER = {type: 'object', properties: {}, additionalProperties: false};
const addRow = (edit = () => {}) => edited('add-row', edit);
const SCHEMA_STUB = TRANSFORMS.get('notion.schema@1'), VALUES_STUB = TRANSFORMS.get('notion.propertyValues@1');
/** A fake Notion data source: a title, a select with two options, a number and a read-only creation time. */
const DATA_SOURCE = () => ({id: 'ds-1', last_edited_time: '2026-10-20T10:00:00.000Z', properties: {Name: {id: 'title', type: 'title'}, Status: {id: 'a%3Bb', type: 'select', select: {options: [{name: 'Open'}, {name: 'Done'}]}},
  Cost: {id: 'c1', type: 'number'}, Created: {id: 'c%40', type: 'created_time'}}});
const HASH_ARGS = (derived, more = {}) => ({resource: {tableId: 'ds-1'}, transform: 'notion.schema@1', codeHash: PINS['notion.schema@1'], schema: derived.schema, bindings: derived.bindings, ...more});

test('part j: the fixture\'s Add a row validates: one resource-dependent input, its schema step and derive, and the typed slot beside {resolved} (R14)', () => {
  const entry = entryOf(addRow());
  assert.deepEqual(entry.placements.map(placement => [placement.stepId, placement.phase]), [['table', 'schema'], ['add', 'perform'], ['check', 'verify']]);
  assert.deepEqual(entry.transforms, ['notion.propertyValues@1', 'notion.schema@1']);
  assert.deepEqual(fixtureActions().actions[6].inputSchema.properties.values, PLACEHOLDER);
});

test('part j: resource-dependent inputs refused: the placeholder, dependsOn, schema steps and the derive (section 9)', () => {
  for (const [label, file, pattern] of [
    ['a placeholder with properties', addRow(action => { action.inputSchema.properties.values = closed({a: words()}, []); }), /add-row v1: resolvedInputs\[0\]: values is a resource-dependent input, so inputSchema declares it exactly as \{type: 'object', properties: \{\}, additionalProperties: false\}/],
    ['a placeholder with additionalProperties true', addRow(action => { action.inputSchema.properties.values = {type: 'object', properties: {}, additionalProperties: true}; }), /add-row v1: inputSchema: \$input\.properties\.values: objects require properties and additionalProperties:false/],
    ['a missing dependsOn', addRow(action => { delete action.resolvedInputs[0].dependsOn; }), /add-row v1: resolvedInputs\[0\] is \{input, dependsOn, schema: \{steps, derive\}, maxProperties\}/],
    ['an empty dependsOn', addRow(action => { action.resolvedInputs[0].dependsOn = []; }), /add-row v1: resolvedInputs\[0\]\.dependsOn names 1 to 3 distinct declared inputs other than values/],
    ['an optional dependsOn', addRow(action => { action.inputSchema.required = ['values']; }), /add-row v1: resolvedInputs\[0\]: values depends on tableId, which is optional: the resource it names is required \(section 9\)/],
    ['a dependsOn on itself', addRow(action => { action.resolvedInputs[0].dependsOn = ['values']; }), /resolvedInputs\[0\]\.dependsOn names 1 to 3 distinct declared inputs other than values/],
    ['maxProperties 101', addRow(action => { action.resolvedInputs[0].maxProperties = 101; }), /add-row v1: resolvedInputs\[0\]\.maxProperties is 1 to 100/],
    ['an input listed twice', addRow(action => { action.resolvedInputs.push(structuredClone(action.resolvedInputs[0])); action.resolvedInputs[1].schema.steps[0].id = 'again'; }), /add-row v1: resolvedInputs\[1\]: values is listed twice/],
    ['a schema step that writes', addRow(action => { action.resolvedInputs[0].schema.steps[0] = {id: 'table', method: 'POST', path: '/items', body: {object: {id: {input: '/tableId'}}}, expect: OK}; }), /resolvedInputs\[0\]\.schema\.steps\[0\] \(table\): a schema step is a read \(spec line 711\), and POST \/items is a write/],
    ['a schema step landing in Other', addRow(action => { action.resolvedInputs[0].schema.steps[0].path = '/tables/{item_id}'; }), /resolvedInputs\[0\]\.schema\.steps\[0\] \(table\): GET \/tables\/\{item_id\} lands in Other reads/],
    ['a schema step with forEach', addRow(action => { action.resolvedInputs[0].schema.steps[0].forEach = {over: {array: [{input: '/tableId'}]}, max: 1}; action.resolvedInputs[0].schema.steps[0].params.item_id = {item: ''}; }), /add-row v1: resolvedInputs\[0\]\.schema\.steps\[0\] \(table\): a schema step runs once: no forEach \(section 9\)/],
    ['three schema steps', addRow(action => { const [step] = action.resolvedInputs[0].schema.steps; action.resolvedInputs[0].schema.steps.push({...step, id: 'b'}, {...step, id: 'c'}); }), /resolvedInputs\[0\] is \{input, dependsOn, schema: \{steps, derive\}, maxProperties\}, for a declared input, with 1 or 2 schema steps \(section 9\)/],
    ['nine declared steps counting schema steps', addRow(action => { for (const id of ['a', 'b', 'c', 'd', 'e', 'f']) action.prepare.push({id, method: 'GET', path: '/labels', maxResponseBytes: 1_024, expect: OK}); }), /add-row v1: declares 9 steps; an action holds at most 8, counting schema steps and choice lookups \(I7\)/],
    ['an unknown derive transform', addRow(action => { action.resolvedInputs[0].schema.derive.transform = 'notion.nothing@1'; }), /resolvedInputs\[0\]\.schema\.derive: names the transform notion\.nothing@1, which the registry does not hold/],
    ['a derive that is not a schema entry', addRow(action => { action.resolvedInputs[0].schema.derive = {transform: 'text.truncate@1', args: {text: {step: 'table', pointer: '/title'}, max: {const: 100}}}; }), /resolvedInputs\[0\]\.schema\.derive: text\.truncate@1 is a map entry; here only schema entries run/],
    ['a schema step reading an input outside dependsOn', addRow(action => { action.inputSchema.properties.note = words(); action.inputSchema.required.push('note'); action.resolvedInputs[0].schema.steps[0].query = {view: {input: '/note'}}; }), /add-row v1: resolvedInputs\[0\]\.schema\.steps\[0\] \(table\)\.query\.view: a schema step reads only constants, the account, the inputs values depends on \(tableId\) and its own earlier schema steps/],
    ['a schema step reading a job key', addRow(action => { action.resolvedInputs[0].schema.steps[0].query = {view: {jobKey: 'view'}}; }), /resolvedInputs\[0\]\.schema\.steps\[0\] \(table\)\.query\.view: a schema step reads only constants, the account, the inputs values depends on/],
    ['a derive that reads a step not yet run', addRow(action => { action.resolvedInputs[0].schema.derive.args.dataSource = {step: 'other', pointer: ''}; }), /resolvedInputs\[0\]\.schema\.derive\.args\.dataSource: reads step "other", which has not run before this point/],
  ]) refusedFile(file, pattern, FIXTURE_DEPS, label);
  // Read raw, passed to an argument the entry does not declare under resolvedValues, paired with another input's {resolved}: part d's grammar.
  for (const [label, file, pattern] of [
    ['raw in a body', addRow(action => { action.perform[0].body.object.extra = {input: '/values'}; }), /values is a resource-dependent input: it is read only whole, as a resolvedValues argument beside \{resolved: 'values'\} in the same transform call \(R14\)/],
    ['raw in a path', addRow(action => { action.perform[0].path = '/items/{item_id}'; action.perform[0].method = 'PATCH'; action.perform[0].params = {item_id: {input: '/values'}}; }), /values is a resource-dependent input: it is read only whole/],
    ['raw in a query', addRow(action => { action.verify.requests[0].query = {v: {input: '/values'}}; }), /values is a resource-dependent input: it is read only whole/],
    ['raw in a header', addRow(action => { action.perform[0].headers = {'If-Match': {input: '/values'}}; }), /a header value never comes from an input/],
    ['an argument not under resolvedValues', addRow(action => { action.preview.push({label: 'Values', expr: {pick: {transform: 'text.joinList@1', args: {items: {input: '/values'}}}, pointer: '/text'}}); }), /values is a resource-dependent input: it is read only whole, as a resolvedValues argument/],
  ]) refusedFile(file, pattern, FIXTURE_DEPS, label);
  // Two resource-dependent inputs: one paired with the other's {resolved}, and one that depends on the other.
  const two = edit => addRow(action => {
    action.inputSchema.properties.more = structuredClone(PLACEHOLDER);
    action.inputSchema.required.push('more');
    action.resolvedInputs.push({input: 'more', dependsOn: ['tableId'], schema: {steps: [{...structuredClone(action.resolvedInputs[0].schema.steps[0]), id: 'other'}],
      derive: {transform: 'notion.schema@1', args: {dataSource: {step: 'other', pointer: ''}}}}, maxProperties: 10});
    action.perform[0].body.object.more = {transform: 'notion.propertyValues@1', args: {schema: {resolved: 'more'}, values: {input: '/more'}}};
    edit(action);
  });
  assert.equal(entryOf(two(() => {})).key, 'add-row', 'two resource-dependent inputs, each with its own schema step');
  refusedFile(two(action => { action.perform[0].body.object.more.args.values = {input: '/values'}; }), /args\.values: takes only \{input: '\/more'\}, the input whose \{resolved\} schema takes \(R14\)/);
  refusedFile(two(action => { action.resolvedInputs[1].dependsOn = ['values']; }), /add-row v1: resolvedInputs\[1\]: more depends on values, another resource-dependent input: none depends on another \(section 9\)/);
  refusedFile(two(action => { action.resolvedInputs[1].schema.derive.args.dataSource = {step: 'table', pointer: ''}; }), /add-row v1: resolvedInputs\[1\]\.schema\.derive reads only constants and its own schema steps \(other\), so its schema is the resource's: it reads table/);
  refusedFile(two(action => { action.resolvedInputs[1].schema.steps[0].params.item_id = {step: 'table', pointer: '/id'}; }), /resolvedInputs\[1\]\.schema\.steps\[0\] \(other\)\.params\.item_id: a schema step reads only constants, the account, the inputs more depends on \(tableId\) and its own earlier schema steps/);
});

test('part j: the typed slot (R14): F10.8\'s runEntry() types the resolvedValues argument by the derived schema, and checks a schema entry\'s own result', () => {
  const derived = runEntry(SCHEMA_STUB, {dataSource: DATA_SOURCE()});
  assert.deepEqual(Object.keys(derived.schema.properties).sort(), ['Cost', 'Name', 'Status']);
  assert.deepEqual(runEntry(VALUES_STUB, {schema: derived, values: {Status: 'Open', Cost: 3}}), {'a%3Bb': {select: {name: 'Open'}}, c1: {number: 3}});
  for (const values of [{Status: 'Nope'}, {Unknown: 'x'}, {Cost: 'three'}]) {
    assert.throws(() => runEntry(VALUES_STUB, {schema: derived, values}), error => error instanceof TransformError && error.code === 'input_invalid', JSON.stringify(values));
  }
  // A schema entry whose result fails checkSchema refuses output_invalid; one over its byte cap refuses output_too_large.
  const open = {...SCHEMA_STUB, run: () => ({schema: {type: 'object', properties: {}, additionalProperties: true}, bindings: []})};
  assert.throws(() => runEntry(open, {dataSource: DATA_SOURCE()}), error => error instanceof TransformError && error.code === 'output_invalid');
  const unbound = {...SCHEMA_STUB, run: () => ({schema: closed({a: words()}, []), bindings: []})};
  assert.throws(() => runEntry(unbound, {dataSource: DATA_SOURCE()}), error => error instanceof TransformError && error.code === 'output_invalid', 'bindings that miss a property');
  assert.throws(() => runEntry({...SCHEMA_STUB, maxOutputBytes: 64}, {dataSource: DATA_SOURCE()}), error => error instanceof TransformError && error.code === 'output_too_large');
});

test('part j: resolvedSchemaHash() binds the resource, the derived schema, the bindings and the derive\'s code hash, and nothing a provider changes without meaning it (open point Important 7)', () => {
  const derived = runEntry(SCHEMA_STUB, {dataSource: DATA_SOURCE()}), hash = resolvedSchemaHash(HASH_ARGS(derived));
  assert.match(hash, /^[a-f0-9]{64}$/);
  // It moves with the resource value, the derived schema, the bindings and the transform's code hash.
  assert.notEqual(resolvedSchemaHash(HASH_ARGS(derived, {resource: {tableId: 'ds-2'}})), hash, 'the resource');
  const renamed = DATA_SOURCE();
  renamed.properties.State = renamed.properties.Status;
  delete renamed.properties.Status;
  assert.notEqual(resolvedSchemaHash(HASH_ARGS(runEntry(SCHEMA_STUB, {dataSource: renamed}))), hash, 'a renamed property');
  const option = DATA_SOURCE();
  option.properties.Status.select.options.push({name: 'Blocked'});
  assert.notEqual(resolvedSchemaHash(HASH_ARGS(runEntry(SCHEMA_STUB, {dataSource: option}))), hash, 'a new option: the derived schema');
  const moved = DATA_SOURCE();
  moved.properties.Cost.id = 'c2';
  assert.notEqual(resolvedSchemaHash(HASH_ARGS(runEntry(SCHEMA_STUB, {dataSource: moved}))), hash, 'a new property id: the bindings');
  assert.notEqual(resolvedSchemaHash(HASH_ARGS(derived, {codeHash: 'f'.repeat(64)})), hash, 'a re-pin of the derive transform');
  // It does not move with key order, with the order the provider lists properties in, or with fields the derived schema drops.
  const reordered = DATA_SOURCE();
  reordered.properties = Object.fromEntries(Object.entries(reordered.properties).reverse());
  assert.equal(resolvedSchemaHash(HASH_ARGS(runEntry(SCHEMA_STUB, {dataSource: reordered}))), hash, 'the provider\'s property order');
  const volatile = {...DATA_SOURCE(), last_edited_time: '2026-10-21T09:00:00.000Z'};
  volatile.properties.Edited = {id: 'e1', type: 'last_edited_time'};
  assert.equal(resolvedSchemaHash(HASH_ARGS(runEntry(SCHEMA_STUB, {dataSource: volatile}))), hash, 'a volatile field and a read-only property');
  const args = HASH_ARGS(derived);
  assert.equal(resolvedSchemaHash({bindings: args.bindings, schema: args.schema, codeHash: args.codeHash, transform: args.transform, resource: args.resource}), hash, 'argument order');
  // Open point Important 7: no action id or input name, so a describe answer and every action that consumes the resource agree on one value.
  assert.throws(() => resolvedSchemaHash({...args, actionId: 'fixture.action.add-row.v1.000000000000000000000000'}), /resolvedSchemaHash\(\) takes exactly resource, transform, codeHash, schema and bindings/);
  for (const [label, change, pattern] of [
    ['an empty resource', {resource: {}}, /the resource is 1 to 3 input values/],
    ['a resource object', {resource: {tableId: {id: 'ds-1'}}}, /the resource is 1 to 3 input values/],
    ['a transform id', {transform: 'notion.schema'}, /transform is a transform id/],
    ['a code hash', {codeHash: 'abc'}, /codeHash is the derive transform's pin, 64 hex characters/],
    ['an open schema', {schema: {type: 'object', properties: {}, additionalProperties: true}}, /objects require properties and additionalProperties:false/],
    ['bindings that miss a property', {bindings: []}, /the bindings name each property of the schema once/],
  ]) assert.throws(() => resolvedSchemaHash({...args, ...change}), pattern, label);
});

test('part j: effectiveInputSchema() puts each derived schema in place of its placeholder, checked before any value is (R14, I3)', () => {
  const [entry] = validate(addRow()).actions, derived = runEntry(SCHEMA_STUB, {dataSource: DATA_SOURCE()});
  const schema = effectiveInputSchema(entry, {values: derived});
  assert.ok(Object.isFrozen(schema) && Object.isFrozen(schema.properties.values));
  assert.deepEqual(schema.properties.values, derived.schema);
  assert.deepEqual(schema.properties.tableId, entry.action.inputSchema.properties.tableId);
  assert.deepEqual(effectiveInputSchema(fixtureActions().actions[6], {values: derived}), schema, 'the action as written or its validated entry');
  // A matching values object passes; an unknown option or an unknown property fails.
  assert.doesNotThrow(() => validateInput(schema, {tableId: 'ds-1', values: {Status: 'Open', Cost: 3, Name: 'Row'}}));
  assert.throws(() => validateInput(schema, {tableId: 'ds-1', values: {Status: 'Nope'}}), /value is not in enum/);
  assert.throws(() => validateInput(schema, {tableId: 'ds-1', values: {Owner: 'x'}}), /undeclared property/);
  // Refused before any value is checked.
  const bad = change => ({values: {...derived, ...change}});
  for (const [label, resolved, pattern] of [
    ['additionalProperties true', bad({schema: {type: 'object', properties: {}, additionalProperties: true}}), /add-row: the derived schema of values: \$derived: objects require properties and additionalProperties:false/],
    ['an unknown keyword', bad({schema: {...derived.schema, patternProperties: {}}}), /\$derived: unsupported schema keyword patternProperties/],
    ['257 enum values', bad({schema: closed({Status: {type: 'string', enum: Array.from({length: 257}, (_, index) => `o${index}`)}}, []), bindings: [{name: 'Status', id: 'a', type: 'select'}]}), /\$derived\.properties\.Status\.enum: must be a nonempty bounded array/],
    ['a property named constructor', bad({schema: JSON.parse('{"type": "object", "properties": {"constructor": {"type": "string"}}, "additionalProperties": false}'), bindings: [{name: 'constructor', id: 'x', type: 'rich_text'}]}), /add-row: the derived schema of values names constructor: never __proto__, prototype or constructor/],
    ['a nested property named prototype', bad({schema: closed({Address: {type: 'array', maxItems: 2, items: closed({prototype: words()}, [])}}, []), bindings: [{name: 'Address', id: 'ad', type: 'rich_text'}]}),
      /add-row: the derived schema of values names prototype: never __proto__, prototype or constructor/],
    ['a list, not an object', bad({schema: {type: 'array', items: {type: 'string'}}}), /add-row: the derived schema of values is a closed object schema/],
    ['more properties than maxProperties', {values: {schema: closed(Object.fromEntries(Array.from({length: 101}, (_, index) => [`p${index}`, words()])), []),
      bindings: Array.from({length: 101}, (_, index) => ({name: `p${index}`, id: `i${index}`, type: 'rich_text'}))}}, /add-row: the derived schema of values holds 101 properties; at most 100 \(maxProperties\)/],
    ['bindings that miss a property', bad({bindings: []}), /add-row: the derived schema of values: its bindings name each property once/],
    ['a schema without its bindings', {values: {schema: derived.schema}}, /add-row: the derived schema of values is \{schema, bindings\}/],
    ['a missing input', {}, /add-row: effectiveInputSchema\(\) takes one derived \{schema, bindings\} for each resource-dependent input: values/],
    ['an input that is not resource-dependent', {values: derived, tableId: derived}, /takes one derived \{schema, bindings\} for each resource-dependent input: values/],
  ]) assert.throws(() => effectiveInputSchema(entry, resolved), pattern, label);
});

// ---- part l: the action schema -----------------------------------------------------------------------------------------------------
test('part l: every action file this suite accepts, choices and resource-dependent inputs included, passes schemas/action.schema.json under ajv', () => {
  const check = actionSchema();
  for (const [index, file] of [fixtureActions(), ...ACCEPTED].entries()) assert.ok(check(file), `file ${index} (${file?.appId}): ${JSON.stringify(check.errors?.slice(0, 3))}`);
  for (const [label, file] of [
    ['a choice with an unknown field', edited('list-items', action => { action.choices[0].label = 'Label'; })],
    ['a choice argument that is neither an input nor a constant', edited('list-items', action => { action.choices[0].args = {parent: {step: 'profile', pointer: '/id'}}; })],
    ['a resource-dependent input with 3 schema steps', edited('add-row', action => { const [step] = action.resolvedInputs[0].schema.steps; action.resolvedInputs[0].schema.steps = [step, step, step]; })],
    ['maxProperties over 100', edited('add-row', action => { action.resolvedInputs[0].maxProperties = 101; })],
  ]) assert.equal(check(file), false, label);
});

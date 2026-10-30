import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {loadActionCatalog, seedActions, evidencePasses, STATUS_WORDS} from '../lib/action-catalog.mjs';
import {loadActions, validateActionFile, actionCapability, runPlan} from '../lib/actions.mjs';
import {capabilityPermissionHash} from '../lib/permissions.mjs';
import {Store} from '../lib/store.mjs';
import {fixtureGroups, fixtureConfigs, fixtureMap, fixtureChoices, fixtureActions, fixtureSignIn, withIds} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';
import {loadActionsSafely, demoteActions, gateCatalog} from '../lib/action-gate.mjs';
import {DiscoveryEngine} from '../lib/discovery.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {main as tenantMain, seedActionsInPlatform, discoverToPlatform} from '../scripts/tenant-admin.mjs';
import {developerHarness} from './fixtures/actions/developer-fixture.mjs';
import {createDeveloperApp} from '../developer-server.mjs';
import {OWNER} from './fixtures/actions/runtime-fixture.mjs';
import {shippedFolder, ownerApp, accounts} from './fixtures/actions/owner-fixture.mjs';
import {fixture as signInFixture} from './fixtures/signin-fixture.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// F10.11 part c (docs/F10.11-BUILD-MAP.md part c and section 3): the action catalog, loaded and seeded, not yet wired. loadActionCatalog()
// reads one app's files at a time, so a bad file refuses only its app; an action is active only when its file is reviewed, it is
// certified, every step places, every transform it names still has its pinned code and its live evidence passes; seedActions() writes
// exactly the capability each one is, and nothing else. Nothing here reaches a provider. Part p (at the end): both servers and the
// operator's command load it through lib/action-gate.mjs, write its statuses before any recovery, and fail closed when it will not load.
const GROUPS = fixtureGroups(), CONFIGS = fixtureConfigs(GROUPS);
const DEPS = {groups: GROUPS, configs: CONFIGS, transforms: TRANSFORMS, pins: PINS, identities: new Map([['fixture', fixtureSignIn()], ['fixture-rpc', fixtureSignIn('fixture-rpc')]])};
const MAPS = () => new Map([['fixture', fixtureMap()]]);
const CHOICES = () => new Map([['fixture', fixtureChoices().sources]]);
/** The code each transform has now: its pin, unless `changed` names it. */
const hashes = (changed = []) => ids => Object.fromEntries(ids.map(id => [id, changed.includes(id) ? 'f'.repeat(64) : PINS[id]]));
const LIST = 'list-items v1', UPDATE = 'update-item v1';
const keyOf = entry => `${entry.key} v${entry.version}`;
/** The validated entries of a file, by "<key> v<version>", as the validator gives them with the fixture's map and choices. */
const entriesOf = file => new Map(validateActionFile(file, {...DEPS, maps: MAPS(), choices: CHOICES()}).actions.map(entry => [keyOf(entry), entry]));
/** A passing live record for one validated entry: passed, the pins of its transforms and its definition hash. */
const passing = entry => ({passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS[id]])), definitionHash: entry.definitionHash});

/** The fixture action file, reviewed, with List items and Update item certified (each certified hash written as an author writes it). */
function reviewedFile(change = () => {}) {
  const file = fixtureActions();
  file.reviewStatus = 'reviewed';
  file.actions.find(action => action.key === 'update-item').certified = {evidence: 'docs/live-evidence/fixture/actions.json', definitionHash: '0'.repeat(64)};
  change(file);
  return withIds(file, {...DEPS, maps: MAPS(), choices: CHOICES()});
}
/** A small reviewed file of the RPC twin: Read a canvas, a reviewed-read POST. */
function rpcFile(change = () => {}) {
  const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
  const file = {schemaVersion: 1, appId: 'fixture-rpc', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: [{id: `fixture-rpc.action.read-canvas.v1.${'0'.repeat(24)}`,
    key: 'read-canvas', version: 1, name: 'Read a canvas', description: 'Reads one canvas.', effect: 'read', row: 'fixture-rpc.messages.read', hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true},
    inputSchema: closed({canvasId: {type: 'string', minLength: 1, maxLength: 64}}), outputSchema: closed({title: {type: 'string', maxLength: 200}}), guards: [], prepare: [],
    perform: [{id: 'canvas', method: 'POST', path: '/canvases.read', body: {object: {canvas_id: {input: '/canvasId'}}}, expect: {status: [200], require: []}}],
    output: {title: {step: 'canvas', pointer: '/title'}}, preview: [], definitive: [400]}]};
  change(file);
  return withIds(file, DEPS);
}
/**
 * A temp repository root with catalog/actions (and its README), catalog/choices and the fixture's live evidence. `files` are written as
 * JSON unless one is {name, text}; `evidence(entries)` gives the evidence file's content (passing records for List items and Update item by
 * default), and a string is written as it is.
 */
function folder(t, {files = [reviewedFile()], choices = [fixtureChoices()], evidence} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-action-catalog-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const directory = path.join(root, 'catalog', 'actions'), choiceDir = path.join(root, 'catalog', 'choices'), live = path.join(root, 'docs', 'live-evidence', 'fixture');
  for (const dir of [directory, choiceDir, live]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(directory, 'README.md'), 'Not an action file.');
  const write = (dir, {name, text, ...file}) => writeFileSync(path.join(dir, name ?? `${file.appId}.json`), text ?? JSON.stringify(file));
  for (const file of files) write(directory, file);
  for (const file of choices) write(choiceDir, file);
  const fixture = files.find(file => file.appId === 'fixture' && Array.isArray(file.actions));
  const entries = fixture ? entriesOf(fixture) : new Map();
  const content = evidence ? evidence(entries) : Object.fromEntries([LIST, UPDATE].filter(key => entries.has(key)).map(key => [entries.get(key).id, passing(entries.get(key))]));
  writeFileSync(path.join(live, 'actions.json'), typeof content === 'string' ? content : JSON.stringify(content));
  return {root, directory, entries};
}
const load = (where, options = {}) => loadActionCatalog({directory: where.directory, evidenceRoot: where.root, maps: MAPS(), deps: DEPS, codeHashes: hashes(), ...options});
const byKey = (catalog, key) => [...catalog.entries.values()].find(item => keyOf(item.entry) === key);
const statusOf = (catalog, key) => { const item = byKey(catalog, key); return [item.status, item.reason]; };

// ---- loading ------------------------------------------------------------------------------------------------------------------------
test('for a valid folder the catalog holds what loadActions() validates, with each capability, its superseded ids resolved and its choices', t => {
  const where = folder(t), catalog = load(where), expected = loadActions(where.directory, {...DEPS, maps: MAPS()}).get('fixture').actions;
  assert.deepEqual([...catalog.entries.keys()], expected.map(entry => entry.id));
  for (const entry of expected) {
    const item = catalog.entries.get(entry.id);
    assert.deepEqual(item.entry, entry);
    assert.deepEqual([item.appId, item.file], ['fixture', 'fixture.json']);
    assert.deepEqual(item.capability, {...actionCapability(reviewedFile(), entry), status: item.status});
    assert.equal(capabilityPermissionHash(item.capability), entry.definitionHash);
    assert.ok(Object.isFrozen(item));
  }
  assert.deepEqual(Object.fromEntries(catalog.superseded), {'fixture.action.list-items.v1.0123456789abcdef01234567':
    {appId: 'fixture', replacedBy: expected.find(entry => entry.key === 'list-items').id, reason: 'change', stopsAfter: '2026-12-31'}});
  assert.deepEqual(catalog.choices.get('fixture'), fixtureChoices().sources);
  assert.deepEqual(Object.fromEntries(catalog.refused), {});
  assert.equal(catalog.runPlan, runPlan, 'runPlan() reaches server code only through the catalog');
});

test('a bad app file or choices file refuses only its own app, with its words; so does a file not named after its app and a choice source holding a superseded id', t => {
  const rpc = rpcFile();
  // A bad RPC twin file: the fixture still loads.
  let catalog = load(folder(t, {files: [reviewedFile(), {appId: 'fixture-rpc', text: '{not json'}]}));
  assert.ok(byKey(catalog, LIST), 'the good app loads');
  assert.match(catalog.refused.get('fixture-rpc'), /^Action file fixture-rpc\.json is not JSON\.$/);
  catalog = load(folder(t, {files: [reviewedFile(), rpcFile(file => { file.actions[0].effect = 'write'; })]}));
  assert.match(catalog.refused.get('fixture-rpc'), /^Actions for fixture-rpc: read-canvas v1: /);
  assert.deepEqual([...catalog.entries.values()].map(item => item.appId).filter(appId => appId !== 'fixture'), []);
  // A bad choices file refuses its app only.
  catalog = load(folder(t, {files: [reviewedFile(), rpc], choices: [{appId: 'fixture', text: JSON.stringify({...fixtureChoices(), sources: []})}]}));
  assert.match(catalog.refused.get('fixture'), /^Choice sources for fixture: a choice source file holds 1 to 20 sources\.$/);
  assert.deepEqual([...catalog.entries.values()].map(item => item.appId), ['fixture-rpc']);
  assert.equal(catalog.choices.has('fixture'), false);
  // A file not named after its app is refused under its own name.
  catalog = load(folder(t, {files: [reviewedFile(), {...rpc, name: 'other.json'}]}));
  assert.equal(catalog.refused.get('other'), 'Action file other.json must be named after its appId.');
  assert.ok(byKey(catalog, LIST));
  // A choice source named like a superseded action id of its app (F10.9 map section 9 hook): the app is refused.
  const stale = fixtureChoices();
  stale.sources.push({...stale.sources[1], id: 'fixture.action.list-items.v1.0123456789abcdef01234567'});
  catalog = load(folder(t, {files: [reviewedFile(), rpc], choices: [stale]}));
  assert.match(catalog.refused.get('fixture'), /fixture\.action\.list-items\.v1\.0123456789abcdef01234567 is a superseded action id: a choice names a current source/);
  assert.deepEqual([...catalog.entries.values()].map(item => item.appId), ['fixture-rpc']);
});

test('entryOf() answers only for the catalog\'s own id and definition: status is review state, any other field is another definition', t => {
  const catalog = load(folder(t)), item = byKey(catalog, LIST);
  assert.equal(catalog.entryOf(item.capability), item);
  assert.equal(catalog.entryOf({...item.capability, status: 'candidate'}), item, 'the definition hash ignores status');
  for (const [label, capability] of [['another description', {...item.capability, description: 'Changed.'}], ['another effect', {...item.capability, effect: 'write'}],
    ['an unknown id', {...item.capability, id: 'fixture.action.gone.v1.0123456789abcdef0123ffff'}], ['the superseded id', {...item.capability, id: 'fixture.action.list-items.v1.0123456789abcdef01234567'}],
    ['nothing', null], ['a cycle', (() => { const loop = {...item.capability}; loop.self = loop; return loop; })()]]) assert.equal(catalog.entryOf(capability), null, label);
});

// F10.13 listed churn (docs/F10.13-BUILD-MAP.md part 2): Calendar ships the first action file. With Google's recorded map its 13 actions
// load as candidates; without one the file is refused, since Find free time's reviewed-read POST counts as a write until it places (F10.10).
// F10.15, F10.17, F10.19 and F10.21 listed churn: Gmail's 13 load as candidates, placed with its map and unplaced without one, never
// refused; GitHub's 15, Notion's 16 and Slack's 13 place with no map (request templates, or method and path), so they load with or without
// one. None joins a row or an agent's list until its live evidence. F10.14 listed churn: step 14's live pass certified Calendar's 13, so with
// Google's map they are active; F10.16's certified Gmail's 13 the same way. Step 18's live pass (run 5XBI3UND) certified GitHub's 15 and step
// 20's (run X4G5USDP) Notion's 16, which place with no map, so they are active with or without one. Slack stays a candidate until its own pass.
test('the shipped folders load Calendar\'s 13, Gmail\'s 13, GitHub\'s 15 and Notion\'s 16 active, Slack\'s 13 candidates with their maps, no refusal and no superseded id; without the maps Calendar alone is refused', () => {
  const catalog = loadActionCatalog({maps: new Map(['google-calendar', 'gmail'].map(appId => [appId, googleMap(appId)]))}), apps = item => item.appId;
  assert.deepEqual([catalog.entries.size, catalog.superseded.size, catalog.choices.size, catalog.refused.size], [70, 0, 0, 0]);
  assert.deepEqual([...catalog.entries.values()].map(apps).sort(), [...Array(15).fill('github'), ...Array(13).fill('gmail'), ...Array(13).fill('google-calendar'), ...Array(16).fill('notion'), ...Array(13).fill('slack')]);
  assert.ok([...catalog.entries.values()].every(item => item.status === (['google-calendar', 'gmail', 'github', 'notion'].includes(item.appId) ? 'active' : 'candidate')));
  const bare = loadActionCatalog();
  assert.deepEqual([bare.entries.size, [...bare.refused.keys()]], [57, ['google-calendar']]);
  assert.ok([...bare.entries.values()].every(item => ['github', 'gmail', 'notion', 'slack'].includes(item.appId) && item.status === (['github', 'notion'].includes(item.appId) ? 'active' : 'candidate')));
  assert.ok([...bare.entries.values()].filter(item => item.appId === 'gmail').every(item => item.entry.unplaced === true));
  assert.match(bare.refused.get('google-calendar'), /find-free-time v1: declares effect read, but its methods say at least write/);
});

// ---- status ---------------------------------------------------------------------------------------------------------------------------
test('status: active only when the file is reviewed, the action certified, every step placed, every transform pinned and its evidence passes', t => {
  const where = folder(t), catalog = load(where);
  assert.deepEqual(statusOf(catalog, LIST), ['active', null]);
  assert.deepEqual(statusOf(catalog, UPDATE), ['active', null]);
  assert.deepEqual(statusOf(catalog, 'remove-labels v1'), ['candidate', STATUS_WORDS.uncertified], 'a reviewed file\'s uncertified action stays a candidate');
  // Each condition alone.
  assert.deepEqual(statusOf(load(folder(t, {files: [reviewedFile(file => { file.reviewStatus = 'candidate'; })]})), LIST), ['candidate', STATUS_WORDS.unreviewed]);
  assert.deepEqual(statusOf(load(folder(t, {files: [reviewedFile(file => { delete file.actions[0].certified; })]})), LIST), ['candidate', STATUS_WORDS.uncertified]);
  assert.deepEqual(statusOf(load(where, {maps: new Map()}), LIST), ['candidate', STATUS_WORDS.unplaced]);
  // A changed transform, the poll block's included: its words name it.
  assert.deepEqual(statusOf(load(where, {codeHashes: hashes(['time.rfc3339ToEpochSeconds@1'])}), LIST), ['candidate', STATUS_WORDS.repinned(['time.rfc3339ToEpochSeconds@1'])]);
  assert.deepEqual(statusOf(load(where, {codeHashes: hashes(['text.joinList@1', 'collections.oneOf@1'])}), UPDATE), ['candidate', STATUS_WORDS.repinned(['collections.oneOf@1', 'text.joinList@1'])]);
  assert.match(STATUS_WORDS.repinned(['a.b@1']), /a\.b@1/);
  assert.deepEqual(statusOf(load(where, {codeHashes: () => { throw new Error('no such file'); }}), LIST), ['candidate', STATUS_WORDS.repinned(['time.rfc3339ToEpochSeconds@1'])], 'code that cannot be hashed is not its pin');
  // The evidence: none, failed, other pins, another definition, not JSON.
  const without = (key, edit) => entries => { const records = Object.fromEntries([...entries.values()].filter(entry => [LIST, UPDATE].includes(keyOf(entry))).map(entry => [entry.id, passing(entry)])); edit(records[entries.get(key).id]); return records; };
  for (const [label, evidence] of [['no file content for it', entries => ({[entries.get(UPDATE).id]: passing(entries.get(UPDATE))})],
    ['passed false', without(LIST, record => { record.passed = false; })], ['another definition hash', without(LIST, record => { record.definitionHash = 'a'.repeat(64); })],
    ['an extra pin', without(LIST, record => { record.transforms['text.truncate@1'] = PINS['text.truncate@1']; })], ['a record that is not an object', entries => ({[entries.get(LIST).id]: 'passed'})],
    ['evidence that is not JSON', () => '{nope'], ['an empty file', () => '']]) {
    assert.deepEqual(statusOf(load(folder(t, {evidence})), LIST), ['candidate', STATUS_WORDS.evidence], label);
  }
  assert.deepEqual(statusOf(load(folder(t, {evidence: without(UPDATE, record => { record.transforms['text.joinList@1'] = 'b'.repeat(64); })})), UPDATE), ['candidate', STATUS_WORDS.evidence], 'a pin the record does not hold');
  // reload() places the app again with its map: List items turns active once the map is stored.
  const unplaced = load(where, {maps: new Map()});
  assert.equal(unplaced.reload('fixture', fixtureMap()), unplaced, 'the same catalog object, so whoever holds it sees the reload');
  assert.deepEqual(statusOf(unplaced, LIST), ['active', null]);
});

test('evidencePasses(): passed, the current pins of exactly the action\'s transforms, and its definition hash when the record names one; never a throw', t => {
  const entry = folder(t).entries.get(UPDATE), pins = PINS, good = passing(entry);
  assert.equal(evidencePasses(entry, good, pins), true);
  const {definitionHash, ...unhashed} = good;
  void definitionHash;
  assert.equal(evidencePasses(entry, unhashed, pins), true, 'a record from before definition hashes passes on its pins');
  for (const [label, record] of [['null', null], ['a list', [good]], ['a string', 'passed'], ['passed missing', {...good, passed: undefined}], ['passed as a string', {...good, passed: 'true'}],
    ['no transforms', {...good, transforms: undefined}], ['a missing pin', {...good, transforms: {}}], ['another pin', {...good, transforms: {...good.transforms, 'text.joinList@1': 'c'.repeat(64)}}],
    ['another definition', {...good, definitionHash: 'd'.repeat(64)}]]) assert.equal(evidencePasses(entry, record, pins), false, label);
  assert.equal(evidencePasses(entry, good, {...pins, 'text.joinList@1': 'e'.repeat(64)}), false, 'pins that moved since the run');
});

// ---- seeding ------------------------------------------------------------------------------------------------------------------------------
async function store(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-seed-')), own = new Store({dataDir: dir});
  t.after(() => { own.close(); rmSync(dir, {recursive: true, force: true}); });
  return own;
}
const HTTP = {id: 'fixture.items.c0ffee0000000000000000aa', specVersion: 'fabric/0.1', version: 1, appId: 'fixture', name: 'List items', description: 'Compiled.', driver: 'http', effect: 'read', status: 'active',
  inputSchema: {type: 'object', properties: {}, additionalProperties: false}, request: {method: 'GET', url: 'https://api.fixture.test/items', headers: {Accept: 'application/json'}, pathParameters: [], queryParameters: []},
  provenance: {kind: 'openapi', fingerprint: 'f', source: 'uploaded', operationId: 'listItems', path: '/items', method: 'GET'}, verification: {kind: 'response', description: 'Observed only.'}};
const audits = own => own.list('activity').filter(row => row.type === 'action.status');

test('seedActions(): each stored record is the action\'s capability with its status, hashing to its definition hash; other records keep their bytes', async t => {
  const own = await store(t), catalog = load(folder(t));
  own.put('capabilities', HTTP);
  const before = JSON.stringify(own.get('capabilities', HTTP.id));
  const written = seedActions(own, catalog);
  assert.equal(written.length, catalog.entries.size);
  for (const [id, item] of catalog.entries) {
    const stored = own.get('capabilities', id);
    assert.deepEqual(stored, {...actionCapability(reviewedFile(), item.entry), status: item.status});
    assert.equal(capabilityPermissionHash(stored), item.entry.definitionHash);
    assert.deepEqual(Object.keys(stored).filter(key => ['reason', 'placements', 'superseded', 'replacedBy', 'certified'].includes(key)), [], 'lifecycle data stays in the catalog');
  }
  assert.equal(JSON.stringify(own.get('capabilities', HTTP.id)), before, 'a non-action record keeps its bytes');
  const rows = audits(own);
  assert.deepEqual(rows.map(row => [row.capabilityId, row.status, row.definitionHash, row.reason]), [...catalog.entries.values()].map(item => [item.entry.id, item.status, item.entry.definitionHash, 'missing']));
});

test('seedActions(): superseded and orphaned ids become disabled, a refused app\'s active actions become candidates, a tampered record is repaired; nothing is deleted', async t => {
  const own = await store(t), where = folder(t), catalog = load(where), list = byKey(catalog, LIST);
  const old = {...list.capability, id: 'fixture.action.list-items.v1.0123456789abcdef01234567', status: 'active'};
  const orphan = {...list.capability, id: 'fixture.action.gone.v1.0123456789abcdef0123ffff', status: 'candidate'};
  const rpcActive = {...list.capability, id: 'fixture-rpc.action.read-canvas.v1.0123456789abcdef01234567', appId: 'fixture-rpc', status: 'active'};
  const rpcDisabled = {...rpcActive, id: 'fixture-rpc.action.old.v1.0123456789abcdef01234567', status: 'disabled'};
  for (const record of [old, orphan, rpcActive, rpcDisabled, {...list.capability, status: 'active', description: 'Tampered.'}]) own.put('capabilities', record);
  let deleted = 0;
  const remove = own.delete.bind(own);
  own.delete = (...args) => { deleted++; return remove(...args); };
  const refused = load(folder(t, {files: [reviewedFile(), {appId: 'fixture-rpc', text: '{'}]}));
  seedActions(own, refused);
  assert.equal(own.get('capabilities', old.id).status, 'disabled', 'a superseded id stops');
  assert.deepEqual(refused.superseded.get(old.id).replacedBy, list.entry.id, 'its notice stays in the catalog');
  assert.equal(own.get('capabilities', orphan.id).status, 'disabled', 'an id no file lists any more');
  assert.equal(own.get('capabilities', rpcActive.id).status, 'candidate', 'an active action of a refused app is demoted');
  assert.equal(own.get('capabilities', rpcDisabled.id).status, 'disabled', 'a disabled one stays disabled');
  assert.deepEqual(own.get('capabilities', list.entry.id), {...list.capability}, 'the tampered record is repaired');
  assert.equal(deleted, 0, 'seeding never deletes');
  const reasons = Object.fromEntries(audits(own).map(row => [row.capabilityId, [row.status, row.reason]]));
  assert.deepEqual([reasons[old.id], reasons[orphan.id], reasons[rpcActive.id], reasons[list.entry.id]], [['disabled', 'superseded'], ['disabled', 'orphaned'], ['candidate', 'app_refused'], ['active', 'changed']]);
  assert.equal(reasons[rpcDisabled.id], undefined, 'nothing written, nothing audited');
  // When the app loads again, its candidate is written as the file says.
  seedActions(own, load(folder(t, {files: [reviewedFile(), rpcFile()]})));
  assert.equal(own.get('capabilities', rpcActive.id).status, 'disabled', 'not in the file, so an orphan');
});

test('seedActions(): a non-action record holding an action id is never overwritten; a second run writes nothing; seeding sends nothing and runs no transform', async t => {
  const own = await store(t), catalog = load(folder(t)), list = byKey(catalog, LIST), taken = {...HTTP, id: list.entry.id};
  own.put('capabilities', taken);
  const fetches = [], realFetch = globalThis.fetch;
  globalThis.fetch = async (...args) => { fetches.push(args); throw new Error('no network in this test'); };
  t.after(() => { globalThis.fetch = realFetch; });
  const runs = [];
  const watched = new Map([...TRANSFORMS].map(([id, entry]) => [id, {...entry, run: (...args) => { runs.push(id); return entry.run(...args); }}]));
  const watchedCatalog = loadActionCatalog({directory: folder(t).directory, maps: MAPS(), deps: {...DEPS, transforms: watched}, codeHashes: hashes()});
  seedActions(own, watchedCatalog);
  assert.deepEqual(own.get('capabilities', list.entry.id), taken, 'the http record keeps its bytes');
  assert.deepEqual(audits(own).filter(row => row.capabilityId === list.entry.id).map(row => row.reason), ['action_id_taken']);
  let writes = 0;
  const put = own.put.bind(own);
  own.put = (...args) => { writes++; return put(...args); };
  seedActions(own, watchedCatalog);
  assert.equal(writes, 1, 'a second run writes only the id_taken audit row again');
  own.delete('capabilities', list.entry.id);
  writes = 0;
  seedActions(own, watchedCatalog);
  seedActions(own, watchedCatalog);
  assert.equal(writes, 2, 'once free, the id is written once with its audit row, and the run after writes nothing');
  assert.deepEqual([fetches.length, runs.length], [0, 0]);
});

// ---- part p: startup loading (lib/action-gate.mjs, server.mjs, developer-server.mjs, scripts/tenant-admin.mjs) ---------------------------
const actionAudits = store => store.list('activity').filter(row => row.type === 'action.status');

test('part p: storing the fixture map through DiscoveryEngine onMapStored() reloads and re-seeds the app, so List items turns active', async t => {
  const where = folder(t), catalog = load(where, {maps: new Map()}), store = new Store({dataDir: path.join(where.root, 'data')});
  t.after(() => store.close());
  catalog.seed(store);
  const list = byKey(catalog, LIST).entry.id;
  assert.deepEqual([statusOf(catalog, LIST), store.get('capabilities', list).status], [['candidate', STATUS_WORDS.unplaced], 'candidate'], 'with no map its read cannot be placed');
  // The fake app's interface, discovered: the one operation of the fixture map.
  const document = {openapi: '3.0.3', info: {title: 'Fixture', version: '1'}, servers: [{url: 'https://api.fixture.test'}], paths: {'/items': {get: {operationId: 'fixture.items.list', responses: {200: {description: 'Items'}}}}}};
  const apps = [{id: 'fixture', name: 'Fixture', discovery: {kind: 'openapi', url: 'https://docs.example.com/fixture/openapi.json'}, apiOrigins: ['https://api.fixture.test']}];
  const stored = [];
  const discovery = new DiscoveryEngine({store, catalog: apps, acquisition: {saveCandidates: () => {}}, request: async () => ({status: 200, headers: {}, data: document}),
    onMapStored: appId => { stored.push([appId, store.get('applicationMaps', appId)?.operations.map(operation => operation.id)]); catalog.reload(appId, store.get('applicationMaps', appId)); catalog.seed(store, {appId}); }});
  await discovery.discover({appId: 'fixture'});
  assert.deepEqual(stored, [['fixture', ['fixture.items.list']]], 'called once the map is stored');
  assert.deepEqual([statusOf(catalog, LIST), store.get('capabilities', list).status], [['active', null], 'active']);
  assert.deepEqual(actionAudits(store).filter(row => row.capabilityId === list).map(row => [row.status, row.reason]), [['candidate', 'missing'], ['active', 'changed']]);
  // The operator's discover command does the same for the platform catalog: the map stored, the app's actions placed on it and written.
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-action-platform-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  await discoverToPlatform({root, appId: 'fixture', apps, request: async () => ({status: 200, headers: {}, data: document}), actions: {directory: where.directory, evidenceRoot: where.root, deps: DEPS, codeHashes: hashes()}});
  const platform = new PlatformStore({root});
  assert.deepEqual([platform.get('capabilities', list).status, platform.activity().filter(row => row.type === 'platform.action_seeded' && row.capabilityId === list).map(row => [row.status, row.reason])], ['active', [['active', 'missing']]]);
  platform.close();
  // The owner's server does the same when a map is stored there: Calendar's List my calendars places only on Calendar's map.
  const ownerDir = mkdtempSync(path.join(tmpdir(), 'fabric-action-owner-'));
  t.after(() => rmSync(ownerDir, {recursive: true, force: true}));
  const owner = await ownerApp(t, shippedFolder(t), {dir: ownerDir}), app = owner.app, calendars = [...app.actions.entries.values()].find(item => item.entry.key === 'list-calendars').entry.id;
  assert.deepEqual([app.actions.entries.get(calendars).status, app.store.get('capabilities', calendars).status], ['candidate', 'candidate']);
  app.store.put('applicationMaps', {id: 'google-calendar', ...googleMap('google-calendar')});
  app.discovery.onMapStored('google-calendar');
  assert.deepEqual([app.actions.entries.get(calendars).status, app.store.get('capabilities', calendars).status], ['active', 'active']);
  // And a start over a store that holds the map loads the catalog with it.
  await owner.close();
  const again = (await ownerApp(t, shippedFolder(t), {dir: ownerDir, mode: 'require', start: false})).app;
  assert.equal(again.actions.entries.get(calendars).status, 'active');
  // seed() with an app names only that app's actions, and a second run writes nothing.
  let writes = 0;
  const put = store.put.bind(store);
  store.put = (...args) => { writes++; return put(...args); };
  catalog.seed(store, {appId: 'fixture'});
  assert.equal(writes, 0);
});

test('part p: server.mjs seeds actions before runtime.recover() and continuations.recover(); a waiting job and a hold on an action demoted at restart are refused or closed', async t => {
  const where = shippedFolder(t), dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-owner-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const first = await ownerApp(t, where, {dir});
  const dm = first.app.store.get('capabilities', where.idOf('send-dm v1')), gists = first.app.store.get('capabilities', where.idOf('list-gists v1'));
  assert.deepEqual([dm.status, gists.status, first.app.actions.entries.size], ['active', 'active', 4], 'seeded active from the reviewed, certified files');
  accounts(first.app);
  // A direct message waiting for its first stop, and an agent's hold on List my gists waiting for the owner to choose an account.
  const waiting = await first.call('POST', '/api/jobs', {connectionId: 'slack-account', capabilityId: dm.id, args: {email: 'grace@example.com', text: 'Lunch?'}});
  assert.deepEqual([waiting.status, waiting.body.status, waiting.body.action.phase], [201, 'awaiting_approval', 'reads']);
  const created = await first.call('POST', '/api/clients', {name: 'Agent', bindings: [], requestable: [{capabilityId: gists.id}]});
  const held = (await first.protocol(created.body.token, 'calls.create', {appId: 'github', capabilityId: gists.id, definitionHash: created.body.client.requestable[0].definitionHash, args: {}})).result;
  assert.equal(first.app.store.get('continuations', held.id).status, 'awaiting_owner');
  await first.close();
  // Restart with the live evidence no longer passing: both actions are candidates before anything recovers, so the hold closes as its
  // operation retired while recovery reads it, and the waiting call can no longer be approved.
  where.pass(false);
  // Read as createApp() left it, before any request: no later read may have closed the hold.
  const second = await ownerApp(t, where, {dir, mode: 'require', start: false});
  assert.deepEqual([second.app.store.get('capabilities', dm.id).status, second.app.store.get('capabilities', gists.id).status], ['candidate', 'candidate']);
  const hold = second.app.store.get('continuations', held.id);
  assert.deepEqual([hold.status, hold.outcome.code], ['failed', 'capability_retired'], 'closed during recovery, so seeding ran first');
  const job = second.app.store.get('jobs', waiting.body.id);
  await assert.rejects(second.app.runtime.approve(job.id, job.approvalDigest, OWNER));
  assert.deepEqual([second.app.store.get('jobs', job.id).status === 'succeeded', second.slack.calls.length], [false, 0], 'nothing was sent');
});

test('part p: a transform example that throws leaves the catalog null; both servers start; stored active action records become candidates with a catalog_failed audit row; /v1/capabilities shows none as active or certified', async t => {
  const where = shippedFolder(t), dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-owner-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const broken = async () => { throw new Error('A transform example threw.'); };
  assert.equal(await loadActionsSafely(where.options, {importer: broken}), null, 'the guarded import answers null, never throws');
  const first = await ownerApp(t, where, {dir});
  const dm = where.idOf('send-dm v1'), old = `slack.action.send-dm.v0.${'ab'.repeat(12)}`;
  first.app.store.put('capabilities', {...first.app.store.get('capabilities', dm), id: old, status: 'disabled'});
  await first.close();
  const second = await ownerApp(t, where, {dir, mode: 'require', importer: broken});
  assert.equal(second.app.actions, null);
  const records = second.app.store.list('capabilities').filter(capability => capability.driver === 'action');
  assert.deepEqual(records.map(capability => [capability.id, capability.status]).sort(), [[old, 'disabled'], ...[where.idOf('find-person v1'), where.idOf('list-gists v1'), dm, where.idOf('list-calendars v1')].map(id => [id, 'candidate'])].sort(),
    'a disabled record stays disabled');
  assert.deepEqual(actionAudits(second.app.store).filter(row => row.reason === 'catalog_failed').map(row => row.capabilityId).sort(), [where.idOf('find-person v1'), where.idOf('list-gists v1'), dm].sort());
  // A second failed start finds nothing left to demote.
  assert.deepEqual(demoteActions(second.app.store), []);
  // The developer server: its platform catalog holds the actions as active, and with no catalog it serves none as active or certified.
  const d = await developerHarness(t, {load: broken});
  assert.equal(d.app.runtimes.actions, null);
  assert.ok(d.repo().list('capabilities').filter(capability => capability.driver === 'action').every(capability => capability.status === 'candidate'));
  const listed = (await d.call(d.keys.standard, 'GET', '/v1/capabilities?appId=slack')).body.capabilities;
  assert.deepEqual(listed.filter(entry => entry.kind === 'action' || entry.certified), []);
});

test('part p: tenant catalog actions writes the same statuses into the platform catalog; unknown verbs still print usage; an environment can never write an action', async t => {
  const where = shippedFolder(t), root = mkdtempSync(path.join(tmpdir(), 'fabric-action-platform-')), shipped = mkdtempSync(path.join(tmpdir(), 'fabric-action-shipped-'));
  t.after(() => { rmSync(root, {recursive: true, force: true}); rmSync(shipped, {recursive: true, force: true}); });
  // The shipped folder holds Calendar's file (F10.13), Gmail's (F10.15), GitHub's (F10.17), Notion's (F10.19) and Slack's (F10.21). A fresh
  // root stores no Calendar map, so Calendar is refused; Gmail's 13 load unplaced without its map and GitHub's 15, Notion's 16 and Slack's 13
  // place with none, so the command seeds those 57 once into a root of their own: GitHub's 15 and Notion's 16 active on their live evidence,
  // the rest as candidates (Gmail's placed only with its map, Slack with no evidence yet). A second run writes nothing.
  const first = (await tenantMain(['catalog', 'actions', '--root', shipped])).seeded, kind = prefix => first.filter(id => id.startsWith(prefix)).length;
  assert.deepEqual([first.length, kind('gmail.action.'), kind('github.action.'), kind('notion.action.'), kind('slack.action.')], [57, 13, 15, 16, 13]);
  assert.deepEqual(await tenantMain(['catalog', 'actions', '--root', shipped]), {seeded: []});
  const seededShipped = new PlatformStore({root: shipped});
  assert.ok(seededShipped.list('capabilities').filter(capability => capability.driver === 'action').every(capability => capability.status === (/^(github|notion)\.action\./.test(capability.id) ? 'active' : 'candidate')));
  seededShipped.close();
  const seeded = await seedActionsInPlatform({root, actions: where.options});
  const expected = new Store({dataDir: path.join(where.root, 'expected')});
  t.after(() => expected.close());
  (await loadActionsSafely(where.options)).seed(expected, {audit: () => {}});
  const platform = new PlatformStore({root});
  const statuses = store => store.list('capabilities').filter(capability => capability.driver === 'action').map(capability => [capability.id, capability.status, capabilityPermissionHash(capability)]).sort();
  assert.deepEqual(statuses(platform), statuses(expected));
  assert.deepEqual(seeded.seeded.sort(), statuses(expected).map(([id]) => id));
  assert.deepEqual(platform.activity().filter(row => row.type === 'platform.action_seeded').map(row => [row.capabilityId, row.status, row.definitionHash, row.reason]).sort(),
    statuses(expected).map(([id, status, hash]) => [id, status, hash, 'missing']));
  platform.close();
  assert.deepEqual((await seedActionsInPlatform({root, actions: where.options})).seeded, [], 'a second run writes nothing');
  // One app only: another app's records are left alone, an orphan of Slack included, until a run over every app.
  const orphan = `slack.action.gone.v1.${'cd'.repeat(12)}`, operator = new PlatformStore({root});
  operator.put('capabilities', {...operator.get('capabilities', where.idOf('find-person v1')), id: orphan});
  operator.close();
  where.pass(false);
  assert.deepEqual((await seedActionsInPlatform({root, appId: 'github', actions: where.options})).seeded, [where.idOf('list-gists v1')]);
  assert.deepEqual((await seedActionsInPlatform({root, appId: 'slack', actions: where.options})).seeded.sort(), [where.idOf('send-dm v1'), where.idOf('find-person v1'), orphan].sort());
  // A catalog that will not load makes the command demote every active record, audited the same way.
  where.pass(true);
  await seedActionsInPlatform({root, actions: where.options});
  assert.deepEqual((await seedActionsInPlatform({root, actions: {...where.options, importer: async () => { throw new Error('pins are not JSON'); }}})).seeded.sort(),
    [where.idOf('send-dm v1'), where.idOf('find-person v1'), where.idOf('list-gists v1')].sort());
  const demoted = new PlatformStore({root});
  assert.equal(demoted.activity().filter(row => row.type === 'platform.action_seeded' && row.reason === 'catalog_failed').length, 3);
  // The developer server loads its catalog with the platform's maps: with Calendar's stored, List my calendars places and is active.
  demoted.put('applicationMaps', {id: 'google-calendar', ...googleMap('google-calendar')});
  demoted.close();
  await seedActionsInPlatform({root, actions: where.options});
  const developer = await createDeveloperApp({dataRoot: root, port: 0, actions: where.options});
  t.after(() => developer.close());
  assert.equal(developer.runtimes.actions.entries.get(where.idOf('list-calendars v1')).status, 'active');
  await assert.rejects(tenantMain(['catalog', 'retire', 'slack', '--root', root]), /Usage/);
  await assert.rejects(tenantMain(['catalog', 'actions']), /Usage/);
  // An environment reads the platform's action records and can never write one, not even its own copy of one.
  const d = await developerHarness(t), find = d.capability('find-person v1');
  assert.equal(find.status, 'active');
  for (const record of [find, {...find, status: 'candidate'}, {...find, id: 'slack.action.mine.v1.0123456789abcdef01234567'}]) assert.throws(() => d.repo().put('capabilities', record), {code: 'platform_read_only'});
});

test('part p: the owner\'s per-operation Add access reads an action\'s steps: List my gists asks for gist, the scope its read needs', async t => {
  const where = shippedFolder(t), f = await signInFixture(t, {actions: where.options});
  // GitHub at full access with gist unticked: List my gists reads a row that needs it.
  const response = await f.owned('POST', '/api/oauth/github/start', {appId: 'github', writeAccess: true});
  const started = {body: await response.json(), flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie'))[1]};
  assert.equal((await f.callback(started, {grant: {omit: ['gist']}})).location, '/?oauth=connected');
  const account = f.connections().find(connection => connection.status === 'ready'), gists = where.idOf('list-gists v1');
  const decision = (await f.json('GET', '/api/connectors/github')).body.permissionsByConnection[account.id].find(item => item.capabilityId === gists);
  assert.deepEqual([decision.kind, decision.providerAccess, decision.addAccess], ['action', 'missing', {providerId: 'github', body: {connectionId: account.id, level: 'full', scopes: ['gist']}}]);
});

test('part p: the developer start gate serves a changed action as a candidate, never a stored candidate as active, serves an orphan as disabled, serves every action as a candidate with a null catalog, and leaves non-action records byte-identical', t => {
  const where = folder(t), catalog = load(where), list = byKey(catalog, LIST), update = byKey(catalog, UPDATE);
  const typed = {id: 'fixture.items-list.0123', appId: 'fixture', driver: 'http', status: 'active', request: {method: 'GET', url: 'https://api.fixture.test/items'}};
  const orphan = {...list.capability, id: 'fixture.action.gone.v1.0123456789abcdef01234567'}, disabled = {...list.capability, id: 'fixture.action.list-items.v1.0123456789abcdef01234567', status: 'disabled'};
  const records = new Map([[list.entry.id, list.capability], [update.entry.id, {...update.capability, status: 'candidate'}], [orphan.id, orphan], [disabled.id, disabled], [typed.id, typed]]);
  const reader = {get: (collection, id) => collection === 'capabilities' ? structuredClone(records.get(id) ?? null) : {collection, id}, list: collection => collection === 'capabilities' ? [...records.values()].map(item => structuredClone(item)) : [{collection}], close: () => {}};
  const gated = gateCatalog(reader, catalog);
  assert.deepEqual(gated.get('capabilities', list.entry.id), list.capability, 'the current, active action as stored');
  assert.equal(gated.get('capabilities', update.entry.id).status, 'candidate', 'a stored candidate is never served active');
  records.set(update.entry.id, {...update.capability, description: 'Changed after review.'});
  assert.equal(gated.get('capabilities', update.entry.id).status, 'candidate', 'an active record that is not the catalog\'s definition');
  assert.deepEqual([gated.get('capabilities', orphan.id).status, gated.get('capabilities', disabled.id).status, gated.get('capabilities', 'nothing')], ['disabled', 'disabled', null]);
  assert.deepEqual(gated.list('capabilities').map(item => [item.id, item.status]), [[list.entry.id, 'active'], [update.entry.id, 'candidate'], [orphan.id, 'disabled'], [disabled.id, 'disabled'], [typed.id, 'active']]);
  assert.deepEqual(gated.get('capabilities', typed.id), typed, 'a non-action record passes through');
  assert.equal(JSON.stringify(gated.list('capabilities').at(-1)), JSON.stringify(typed));
  assert.deepEqual([gated.get('applicationMaps', 'fixture'), gated.list('applicationMaps')], [{collection: 'applicationMaps', id: 'fixture'}, [{collection: 'applicationMaps'}]], 'other collections pass through');
  // A catalog that computes a candidate demotes a stored active record of it.
  const uncertified = load(folder(t, {evidence: () => ({})}));
  assert.equal(gateCatalog(reader, uncertified).get('capabilities', list.entry.id).status, 'candidate');
  // With no catalog, every action is a candidate, and a disabled one stays disabled.
  const none = gateCatalog(reader, null);
  assert.deepEqual(none.list('capabilities').map(item => item.status), ['candidate', 'candidate', 'candidate', 'disabled', 'active']);
  assert.equal(gateCatalog(null, catalog), null, 'no platform catalog, nothing to gate');
});

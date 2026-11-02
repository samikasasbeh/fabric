import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {loadActionCatalog, triggerEvidencePasses, TRIGGER_STATUS_WORDS} from '../lib/action-catalog.mjs';
import {validateTriggerFile, triggerIds, triggerLens, triggerPollHash} from '../lib/triggers.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {fixtureGroups, fixtureConfigs, fixtureMap, fixtureChoices, fixtureActions, fixtureSignIn} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// Iteration 9 part 1c (docs/I07-BUILD-MAP.md part 1c): the trigger files through loadActionCatalog(). A trigger file loads beside its app's
// actions and never takes them down; a bad one refuses that app's triggers only. A trigger is active only when its file is reviewed, it is
// certified, every step places, every named transform has its pinned code and its live evidence carries the proof of one write. Each item
// also carries the feed key (pollHash) and the lens of sections 2.1 and 2.2. Nothing here runs a poll or reaches a provider.
const FIXTURE_GROUPS = fixtureGroups(), FIXTURE_CONFIGS = fixtureConfigs(FIXTURE_GROUPS);
const DEPS = {groups: new Map([...PERMISSION_GROUPS, ...FIXTURE_GROUPS]), configs: new Map([...PROXY_CONFIGS, ...FIXTURE_CONFIGS]), transforms: TRANSFORMS, pins: PINS,
  identities: new Map([['fixture', fixtureSignIn()], ['fixture-rpc', fixtureSignIn('fixture-rpc')], ['google-calendar', definitionFor('google')]])};
const MAPS = () => new Map([['fixture', fixtureMap()]]);
const VALIDATE = () => ({...DEPS, maps: MAPS(), choices: new Map([['fixture', fixtureChoices().sources]]), actions: new Map([['fixture', fixtureActions()]])});
/** The code each transform has now: its pin, unless `changed` names it. */
const hashes = (changed = []) => ids => Object.fromEntries(ids.map(id => [id, changed.includes(id) ? 'f'.repeat(64) : PINS[id]]));
const closed = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
const OK = {status: [200], require: []};
const ZEROS = '0'.repeat(24);
const EVENT = {schema: closed({id: words(64), name: words(200)}), id: {item: '/id'}, occurredAt: {item: '/updated'},
  fields: {id: {item: '/id'}, name: {pick: {transform: 'text.truncate@1', args: {text: {item: '/name'}, max: {const: 200}}}, pointer: '/text'}}, summary: [{label: 'Item', expr: {item: '/name'}, truncate: 120}]};
const EVIDENCE = 'docs/live-evidence/fixture/triggers.json';

/** A fixture trigger on GET /items with a high-water mark, in the shape of the 35 drafts. */
function itemTrigger(key, edit = () => {}) {
  const trigger = {id: `fixture.trigger.${key}.v1.${ZEROS}`, key, version: 1, name: 'An item changed', description: 'Tells you when one of your items changes.',
    delivery: {method: 'polling', intervalSeconds: {default: 120, min: 60}}, inputSchema: closed({kind: {type: 'string', enum: ['all', 'open']}}), resource: ['kind'],
    poll: {source: {steps: [{id: 'list', method: 'GET', path: '/items', query: {kind: {input: '/kind'}, updatedAfter: {cursor: 'since'}},
      page: {next: {pointer: '/nextPageToken'}, into: {query: 'pageToken'}, items: '/items', max: 3}, maxResponseBytes: 262_144, expect: OK}]},
    items: {step: 'list', pointer: ''}, itemId: {item: '/id'}, itemVersion: '/updated', itemTime: {pointer: '/updated', format: 'rfc3339'}, order: 'desc',
    cursors: [{name: 'since', kind: 'high-water-time@1', next: {max: 'itemTime'}, compare: 'time.rfc3339ToEpochSeconds@1', overlapSeconds: 60}],
    resync: {statusIn: []}, minIntervalSeconds: 60},
    dedupe: {kind: 'id+version'}, event: structuredClone(EVENT), backfill: {default: 0, max: 25}, retention: {days: 7}, bounds: {pages: 10, items: 500, pollSeconds: 10}, rows: ['fixture.items.read']};
  edit(trigger);
  return trigger;
}
/** A fixture trigger on a history-id@1 cursor, the kind that owes a resync proof. */
const historyTrigger = (key = 'item-logged', edit = () => {}) => itemTrigger(key, trigger => {
  trigger.poll.source.steps[0].query = {kind: {input: '/kind'}, start: {cursor: 'history'}};
  Object.assign(trigger.poll, {order: 'asc', itemVersion: null, cursors: [{name: 'history', kind: 'history-id@1', next: {step: 'list', pointer: '/historyId'}, compare: 'time.decimalCompare@1', lastPageOnly: true}], resync: {statusIn: [404]}});
  delete trigger.poll.itemTime;
  trigger.dedupe = {kind: 'id'};
  edit(trigger);
});
/** A fixture trigger that reuses List items' poll block. */
const reusedTrigger = (key = 'listed-item') => ({...itemTrigger(key), inputSchema: closed({}), resource: [], poll: {source: {action: {key: 'list-items', version: 1}, args: {kind: {const: 'all'}}}}, dedupe: {kind: 'id+version'}});
/** One app's trigger file with each computed id written, as an author writes it. A file triggerIds() refuses comes back as it is. */
function fileOf(triggers, change = () => {}, deps = VALIDATE()) {
  const file = {schemaVersion: 1, appId: 'fixture', specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {account: 'me'}, triggers};
  change(file);
  let ids;
  try { ids = triggerIds(file, deps); } catch { return file; }
  return {...file, triggers: file.triggers.map(trigger => ({...trigger, id: ids.get(`${trigger.key} v${trigger.version}`)}))};
}
const reviewed = file => { file.reviewStatus = 'reviewed'; for (const trigger of file.triggers) trigger.certified = {evidence: EVIDENCE}; };
const PROOF = {baseline: 0, afterWrite: 1, repoll: 0};
const RESYNC = {...PROOF, resync: {status: 404, gapEvents: 1, duplicates: 0}};
/** A passing live record of one validated trigger: the pins of its transforms and one test with `proof`. */
const passing = (entry, proof = PROOF) => ({passed: true, transforms: Object.fromEntries(entry.transforms.map(id => [id, PINS[id]])), tests: [{test: 'TR1', passed: true, proof}]});
const entriesOf = (file, deps = VALIDATE()) => validateTriggerFile(file, deps).triggers;

/**
 * A temp repository root with catalog/actions, catalog/choices and catalog/triggers. Each of `triggers`, `actions` and `choices` holds files,
 * written as JSON unless one is {name, text}. `evidence` maps an app to the content of its docs/live-evidence/<appId>/triggers.json, and
 * `evidenceFile` is the name it goes under.
 */
function folder(t, {triggers = [], actions = [fixtureActions()], choices = [fixtureChoices()], evidence = {}, evidenceFile = 'triggers.json'} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-trigger-catalog-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const directory = path.join(root, 'catalog', 'actions'), choiceDir = path.join(root, 'catalog', 'choices'), triggerDir = path.join(root, 'catalog', 'triggers');
  for (const dir of [directory, choiceDir, triggerDir]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(triggerDir, 'README.md'), 'Not a trigger file.');
  const write = (dir, {name, text, ...file}) => writeFileSync(path.join(dir, name ?? `${file.appId}.json`), text ?? JSON.stringify(file));
  for (const file of actions) write(directory, file);
  for (const file of choices) write(choiceDir, file);
  for (const file of triggers) write(triggerDir, file);
  for (const [appId, content] of Object.entries(evidence)) {
    mkdirSync(path.join(root, 'docs', 'live-evidence', appId), {recursive: true});
    writeFileSync(path.join(root, 'docs', 'live-evidence', appId, evidenceFile), typeof content === 'string' ? content : JSON.stringify(content));
  }
  return {root, directory};
}
const load = (where, options = {}) => loadActionCatalog({directory: where.directory, evidenceRoot: where.root, maps: MAPS(), deps: DEPS, codeHashes: hashes(), ...options});
const byKey = (catalog, key) => [...catalog.triggers.values()].find(item => item.entry.key === key);

// ---- loading ----------------------------------------------------------------------------------------------------------------------------
test('a candidate file loads as candidates beside its app\'s actions: each item holds its validated entry, status, reason, pinned parameters, feed key and lenses, frozen', t => {
  const file = fileOf([itemTrigger('item-changed'), itemTrigger('item-gone', trigger => { trigger.filter = [{present: {item: '/deleted'}}]; })]);
  const catalog = load(folder(t, {triggers: [file]})), entries = entriesOf(file);
  assert.deepEqual([...catalog.triggers.keys()], entries.map(entry => entry.id));
  for (const entry of entries) {
    const item = catalog.triggers.get(entry.id);
    assert.deepEqual(Object.keys(item).sort(), ['appId', 'entry', 'lenses', 'pinnedParameters', 'pollHash', 'reason', 'status']);
    assert.deepEqual(item.entry, entry);
    assert.deepEqual([item.appId, item.status, item.reason, item.pinnedParameters], ['fixture', 'candidate', TRIGGER_STATUS_WORDS.unreviewed, {account: 'me'}]);
    assert.match(item.pollHash, /^[a-f0-9]{64}$/);
    assert.deepEqual(item.lenses, [triggerLens(entry)]);
    assert.match(item.lenses[0], /^[a-f0-9]{16}$/);
    assert.ok(Object.isFrozen(item) && Object.isFrozen(item.entry) && Object.isFrozen(item.pinnedParameters) && Object.isFrozen(item.lenses));
    assert.equal(catalog.triggerOf(entry.id), item);
  }
  assert.ok(catalog.entries.size > 0, 'the app\'s actions load too');
  assert.deepEqual(Object.fromEntries(catalog.refused), {});
  assert.deepEqual(Object.fromEntries(catalog.triggersRefused), {});
  assert.equal(catalog.triggerOf('fixture.trigger.nothing.v1.000'), null);
  assert.equal(catalog.triggerOf(undefined), null);
});

test('an app with a trigger file and no action file loads, because the trigger folder adds its name; a README is no trigger file, and the shipped folder refuses nothing', t => {
  const file = fileOf([itemTrigger('item-changed')]), catalog = load(folder(t, {triggers: [file], actions: [], choices: []}));
  assert.equal(catalog.entries.size, 0);
  assert.equal(byKey(catalog, 'item-changed').status, 'candidate');
  assert.deepEqual([...catalog.triggersRefused.keys()], []);
  assert.deepEqual([...catalog.refused.keys()], [], 'a trigger file names no action file, so none is refused');
  assert.deepEqual([...loadActionCatalog().triggersRefused], [], 'catalog/triggers holds nothing that is refused');
});

test('a bad trigger file refuses that app\'s triggers only, with its words: its actions stay loaded and another app\'s triggers load', t => {
  const good = fileOf([itemTrigger('item-changed')]);
  const calendar = JSON.parse(readFileSync(new URL('./fixtures/triggers/google-calendar.json', import.meta.url), 'utf8'));
  for (const [label, bad, words] of [
    ['a stored id that is not the computed one', {...good, triggers: [{...good.triggers[0], id: `fixture.trigger.item-changed.v1.${ZEROS}`}]}, /^Triggers for fixture: item-changed v1: id is fixture\.trigger\.item-changed\.v1\.0{24}, but its content hashes to /],
    ['one bad trigger beside a good one', {...good, triggers: [...good.triggers, itemTrigger('item-gone')]}, /^Triggers for fixture: item-gone v1: id is fixture\.trigger\.item-gone\.v1\.0{24}, but its content hashes to /],
    ['a file that is not JSON', {appId: 'fixture', text: '{not json'}, /^Trigger file fixture\.json is not JSON\.$/],
  ]) {
    const catalog = load(folder(t, {triggers: [bad, calendar]}));
    assert.match(catalog.triggersRefused.get('fixture'), words, label);
    assert.deepEqual([...catalog.triggers.values()].map(item => item.appId), ['google-calendar'], `${label}: no trigger of the app stays, and the other app's loads`);
    assert.ok(catalog.entries.size > 0, `${label}: the actions stay`);
    assert.deepEqual([...catalog.refused.keys()], [], `${label}: the app itself is not refused`);
  }
});

test('a file not named after its app is refused under its own name, and a file named after an app with no rows is refused without touching anything else', t => {
  const file = fileOf([itemTrigger('item-changed')]);
  let catalog = load(folder(t, {triggers: [{...file, name: 'other.json'}]}));
  assert.equal(catalog.triggersRefused.get('other'), 'Trigger file other.json must be named after its appId.');
  assert.equal(catalog.triggers.size, 0, 'a misnamed file never fires under either name');
  assert.ok(catalog.entries.size > 0);
  assert.deepEqual([...catalog.refused.keys()], []);
  catalog = load(folder(t, {triggers: [{name: 'list.json', text: '[]'}]}));
  assert.equal(catalog.triggersRefused.get('list'), 'Trigger file list.json must be named after its appId.');
  catalog = load(folder(t, {triggers: [{...file, name: 'nothing.json', appId: 'nothing'}]}));
  assert.match(catalog.triggersRefused.get('nothing'), /^Triggers for nothing: the app has no reviewed permission rows and proxy settings\.$/);
});

test('a bad action file refuses the app\'s actions and leaves its own-step triggers loaded; a bad choices file refuses both, since a trigger\'s choices read it', t => {
  const file = fileOf([itemTrigger('item-changed')]);
  let catalog = load(folder(t, {triggers: [file], actions: [{appId: 'fixture', text: '{not json'}]}));
  assert.match(catalog.refused.get('fixture'), /^Action file fixture\.json is not JSON\.$/);
  assert.equal(catalog.entries.size, 0);
  assert.equal(byKey(catalog, 'item-changed').status, 'candidate');
  assert.deepEqual([...catalog.triggersRefused.keys()], []);
  catalog = load(folder(t, {triggers: [file], choices: [{appId: 'fixture', text: '{not json'}]}));
  assert.match(catalog.refused.get('fixture'), /^Choice source file fixture\.json is not JSON\.$/);
  assert.match(catalog.triggersRefused.get('fixture'), /^Choice source file fixture\.json is not JSON\.$/);
  assert.equal(catalog.triggers.size, 0);
});

test('a trigger that reuses a read action validates against the raw action file beside it, and is reviewed only when that file is', t => {
  const file = fileOf([reusedTrigger()]);
  let catalog = load(folder(t, {triggers: [file]}));
  const item = byKey(catalog, 'listed-item');
  assert.deepEqual(item.entry.sources.map(source => source.key), ['list-items']);
  assert.match(item.pollHash, /^[a-f0-9]{64}$/);
  assert.equal(item.lenses.length, 1);
  catalog = load(folder(t, {triggers: [{...file, reviewStatus: 'reviewed'}]}));
  assert.equal(byKey(catalog, 'listed-item').reason, TRIGGER_STATUS_WORDS.unreviewed, 'its action file is a candidate');
  const reviewedActions = {...fixtureActions(), reviewStatus: 'reviewed'};
  catalog = load(folder(t, {triggers: [{...file, reviewStatus: 'reviewed'}], actions: [reviewedActions]}));
  assert.equal(byKey(catalog, 'listed-item').reason, TRIGGER_STATUS_WORDS.uncertified, 'both files reviewed, so the next rule answers');
  catalog = load(folder(t, {triggers: [file], actions: []}));
  assert.match(catalog.triggersRefused.get('fixture'), /listed-item v1: poll\.source\.action names list-items v1, which fixture's action file does not hold/);
});

test('a trigger\'s choices read the app\'s own choice sources, from the choices folder or from deps.choices, and a source no file holds refuses the file', t => {
  const offered = itemTrigger('item-labelled', trigger => {
    trigger.inputSchema = closed({labelId: words(64)});
    trigger.resource = ['labelId'];
    trigger.poll.source.steps[0].query.kind = {input: '/labelId'};
    trigger.choices = [{input: 'labelId', source: 'labels'}];
  });
  const file = fileOf([offered]);
  assert.equal(byKey(load(folder(t, {triggers: [file]})), 'item-labelled').status, 'candidate');
  const given = load(folder(t, {triggers: [file], choices: []}), {deps: {...DEPS, choices: new Map([['fixture', fixtureChoices().sources]])}});
  assert.equal(byKey(given, 'item-labelled').status, 'candidate');
  const none = load(folder(t, {triggers: [file], actions: [], choices: []}));
  assert.match(none.triggersRefused.get('fixture'), /item-labelled v1: choices\[0\] names labels, which is neither a choice source nor a version 1 option source of fixture/);
});

test('reload after a map arrives places Google triggers: unplaced before it, placed after it, active once its evidence passes, and reload without one takes it back', t => {
  const calendar = JSON.parse(readFileSync(new URL('./fixtures/triggers/google-calendar.json', import.meta.url), 'utf8'));
  reviewed(calendar);
  calendar.triggers[0].certified = {evidence: 'docs/live-evidence/google-calendar/triggers.json'};
  const placed = entriesOf(calendar, {...DEPS, maps: new Map([['google-calendar', googleMap('google-calendar')]])})[0];
  assert.equal(placed.unplaced, false);
  const where = folder(t, {triggers: [calendar], evidence: {'google-calendar': {[placed.id]: passing(placed)}}}), catalog = load(where);
  let item = catalog.triggerOf(placed.id);
  assert.deepEqual([item.entry.unplaced, item.entry.rows, item.status, item.reason], [true, null, 'candidate', TRIGGER_STATUS_WORDS.unplaced]);
  assert.equal(catalog.reload('google-calendar', googleMap('google-calendar')), catalog, 'reload returns the catalog');
  item = catalog.triggerOf(placed.id);
  assert.deepEqual([item.entry.unplaced, item.entry.rows, item.status, item.reason], [false, ['google-calendar.events.read'], 'active', null]);
  catalog.reload('google-calendar', null);
  assert.deepEqual([catalog.triggerOf(placed.id).status, catalog.triggerOf(placed.id).reason], ['candidate', TRIGGER_STATUS_WORDS.unplaced]);
});

test('reload reads the trigger file again: a file gone leaves no item and a file turned bad moves to triggersRefused, and a repaired one clears it', t => {
  const file = fileOf([itemTrigger('item-changed')]), where = folder(t, {triggers: [file]}), catalog = load(where), name = path.join(where.root, 'catalog', 'triggers', 'fixture.json');
  assert.equal(catalog.triggers.size, 1);
  writeFileSync(name, '{not json');
  catalog.reload('fixture', fixtureMap());
  assert.equal(catalog.triggers.size, 0);
  assert.match(catalog.triggersRefused.get('fixture'), /is not JSON/);
  assert.ok(catalog.entries.size > 0, 'the actions reload beside them');
  writeFileSync(name, JSON.stringify(file));
  catalog.reload('fixture', fixtureMap());
  assert.equal(catalog.triggers.size, 1);
  assert.deepEqual([...catalog.triggersRefused.keys()], []);
  rmSync(name);
  catalog.reload('fixture', fixtureMap());
  assert.equal(catalog.triggers.size, 0);
  assert.deepEqual([...catalog.triggersRefused.keys()], []);
});

// ---- the status rule --------------------------------------------------------------------------------------------------------------------
test('the status rule, in order: file reviewed, certified, every step placed, each transform at its pin, then the evidence; only then active', t => {
  const file = fileOf([itemTrigger('item-changed')], reviewed), [entry] = entriesOf(file), evidence = {fixture: {[entry.id]: passing(entry)}};
  const statusOf = (catalog, id = entry.id) => [catalog.triggerOf(id).status, catalog.triggerOf(id).reason];
  assert.deepEqual(statusOf(load(folder(t, {triggers: [file], evidence}))), ['active', null]);
  assert.deepEqual(statusOf(load(folder(t, {triggers: [{...file, reviewStatus: 'candidate'}], evidence}))), ['candidate', TRIGGER_STATUS_WORDS.unreviewed], 'a candidate file, whatever else it holds');
  const uncertified = {...file, triggers: file.triggers.map(({certified, ...trigger}) => trigger)};
  assert.deepEqual(statusOf(load(folder(t, {triggers: [uncertified], evidence}))), ['candidate', TRIGGER_STATUS_WORDS.uncertified], 'not certified, with evidence that passes');
  assert.deepEqual(statusOf(load(folder(t, {triggers: [file], evidence}), {maps: new Map()})), ['candidate', TRIGGER_STATUS_WORDS.unplaced], 'fixture.items.list has no map');
  assert.deepEqual(statusOf(load(folder(t, {triggers: [file], evidence}), {codeHashes: hashes(['text.truncate@1'])})), ['candidate', TRIGGER_STATUS_WORDS.repinned(['text.truncate@1'])]);
  assert.deepEqual(statusOf(load(folder(t, {triggers: [file]}))), ['candidate', TRIGGER_STATUS_WORDS.evidence], 'no evidence file');
  // Each rule is read before the next one: an unreviewed file that also has no map reads unreviewed.
  assert.deepEqual(statusOf(load(folder(t, {triggers: [{...file, reviewStatus: 'candidate'}]}), {maps: new Map()})), ['candidate', TRIGGER_STATUS_WORDS.unreviewed]);
  assert.deepEqual(statusOf(load(folder(t, {triggers: [file], evidence}), {maps: new Map(), codeHashes: hashes(['text.truncate@1'])})), ['candidate', TRIGGER_STATUS_WORDS.unplaced]);
  assert.deepEqual(statusOf(load(folder(t, {triggers: [uncertified]}), {maps: new Map()})), ['candidate', TRIGGER_STATUS_WORDS.uncertified]);
});

test('a changed pin makes a candidate: a transform read only by a cursor or an item time counts, a code hash that cannot be read counts, and pinned() says the same', t => {
  const file = fileOf([itemTrigger('item-changed')], reviewed), [entry] = entriesOf(file), evidence = {fixture: {[entry.id]: passing(entry)}};
  assert.deepEqual([...entry.transforms], ['text.truncate@1', 'time.rfc3339ToEpochSeconds@1']);
  const moved = load(folder(t, {triggers: [file], evidence}), {codeHashes: hashes(['time.rfc3339ToEpochSeconds@1'])}).triggerOf(entry.id);
  assert.deepEqual([moved.status, moved.reason], ['candidate', 'The code of time.rfc3339ToEpochSeconds@1 changed since it was pinned, so this trigger waits for a reviewed re-pin.']);
  const unread = load(folder(t, {triggers: [file], evidence}), {codeHashes: () => { throw new Error('no pins'); }}).triggerOf(entry.id);
  assert.deepEqual([unread.status, unread.reason], ['candidate', TRIGGER_STATUS_WORDS.repinned(['text.truncate@1', 'time.rfc3339ToEpochSeconds@1'])]);
  const good = load(folder(t, {triggers: [file], evidence})), bad = load(folder(t, {triggers: [file], evidence}), {codeHashes: hashes(['time.rfc3339ToEpochSeconds@1'])});
  assert.equal(good.pinned(good.triggerOf(entry.id)), true);
  assert.equal(bad.pinned(bad.triggerOf(entry.id)), false);
  // A transform the actions name is still read from the actions' hashes: the two sets never overwrite each other.
  const action = [...bad.entries.values()].find(item => item.entry.transforms.length && !item.entry.transforms.includes('time.rfc3339ToEpochSeconds@1'));
  assert.equal(bad.pinned(action), true);
});

test('pinned() reads an item\'s own hashes: a read that failed for the actions stays failed, whatever the trigger file read, and the other way round', t => {
  const joined = {pick: {transform: 'text.joinList@1', args: {items: {array: [{item: '/name'}]}}}, pointer: '/text'};
  const file = fileOf([itemTrigger('item-joined', trigger => { trigger.event.fields.name = {pick: {transform: 'text.truncate@1', args: {text: joined, max: {const: 200}}}, pointer: '/text'}; })]);
  const reading = failing => ids => { if (ids.includes(failing)) throw new Error('that code cannot be read'); return hashes()(ids); };
  // collections.oneOf@1 is named by an action alone, so only the actions' read fails; text.truncate@1 by the trigger alone, so only the trigger's.
  const action = catalog => [...catalog.entries.values()].find(item => item.entry.key === 'remove-labels'), trigger = catalog => byKey(catalog, 'item-joined');
  assert.deepEqual(action(load(folder(t, {triggers: [file]}))).entry.transforms, ['text.joinList@1'], 'the trigger names this transform too');
  let catalog = load(folder(t, {triggers: [file]}), {codeHashes: reading('collections.oneOf@1')});
  assert.equal(catalog.pinned(action(catalog)), false, 'the action\'s code was not read, and the trigger\'s read does not vouch for it');
  assert.equal(catalog.pinned(trigger(catalog)), true);
  catalog = load(folder(t, {triggers: [file]}), {codeHashes: reading('text.truncate@1')});
  assert.equal(catalog.pinned(trigger(catalog)), false);
  assert.equal(catalog.pinned(action(catalog)), true);
});

test('passing evidence: passed true with no proof stays a candidate; one test must show one event after a write and none on the re-poll, and a history-id trigger also a clean resync', t => {
  const [own] = entriesOf(fileOf([itemTrigger('item-changed')])), [history] = entriesOf(fileOf([historyTrigger()]));
  const record = (entry, tests) => ({passed: true, transforms: passing(entry).transforms, tests});
  for (const [label, entry, value, expected] of [
    ['one write proved', own, record(own, [{proof: PROOF}]), true],
    ['the proof in a later test', own, record(own, [{test: 'TR0'}, {proof: {afterWrite: 0, repoll: 0}}, {proof: PROOF}]), true],
    ['passed true with no tests', own, {passed: true, transforms: passing(own).transforms}, false],
    ['tests that are not a list', own, record(own, {proof: PROOF}), false],
    ['an empty list of tests', own, record(own, []), false],
    ['a test with no proof', own, record(own, [{test: 'TR1', passed: true}]), false],
    ['a proof that is not an object', own, record(own, [{proof: 1}, null]), false],
    ['no event after the write', own, record(own, [{proof: {afterWrite: 0, repoll: 0}}]), false],
    ['two events after the write', own, record(own, [{proof: {afterWrite: 2, repoll: 0}}]), false],
    ['an event on the re-poll', own, record(own, [{proof: {afterWrite: 1, repoll: 1}}]), false],
    ['no re-poll', own, record(own, [{proof: {afterWrite: 1}}]), false],
    ['two tests that each prove half', own, record(own, [{proof: {afterWrite: 1, repoll: 1}}, {proof: {afterWrite: 0, repoll: 0}}]), false],
    ['numbers as text', own, record(own, [{proof: {afterWrite: '1', repoll: '0'}}]), false],
    ['evidencePasses() fails: passed false', own, {...record(own, [{proof: PROOF}]), passed: false}, false],
    ['evidencePasses() fails: a stale pin', own, {...record(own, [{proof: PROOF}]), transforms: {...passing(own).transforms, 'text.truncate@1': 'f'.repeat(64)}}, false],
    ['evidencePasses() fails: a transform short', own, {...record(own, [{proof: PROOF}]), transforms: {'text.truncate@1': PINS['text.truncate@1']}}, false],
    ['nothing', own, undefined, false],
    ['history: a write and a resync in one test', history, record(history, [{proof: RESYNC}]), true],
    ['history: a write and a resync in two tests', history, record(history, [{proof: PROOF}, {proof: {resync: RESYNC.resync}}]), true],
    ['history: no resync test', history, record(history, [{proof: PROOF}]), false],
    ['history: no gap', history, record(history, [{proof: PROOF}, {proof: {resync: {status: 404, gapEvents: 0, duplicates: 0}}}]), false],
    ['history: two gaps', history, record(history, [{proof: PROOF}, {proof: {resync: {status: 404, gapEvents: 2, duplicates: 0}}}]), false],
    ['history: a duplicate', history, record(history, [{proof: PROOF}, {proof: {resync: {status: 404, gapEvents: 1, duplicates: 1}}}]), false],
    ['history: a resync that is not an object', history, record(history, [{proof: PROOF}, {proof: {resync: 1}}]), false],
    ['history: a resync and no write', history, record(history, [{proof: {resync: RESYNC.resync}}]), false],
    ['own steps owe no resync', own, record(own, [{proof: {...PROOF, resync: {gapEvents: 0}}}]), true],
  ]) assert.equal(triggerEvidencePasses(entry, value, PINS), expected, label);
});

test('a trigger\'s evidence is read from docs/live-evidence/<appId>/triggers.json, by its own id: an action record, a file of the wrong shape and a passed record with no proof do not count', t => {
  const file = fileOf([itemTrigger('item-changed'), itemTrigger('item-gone', trigger => { trigger.filter = [{present: {item: '/deleted'}}]; })], reviewed);
  const [first, second] = entriesOf(file), statuses = catalog => [catalog.triggerOf(first.id).status, catalog.triggerOf(second.id).status];
  assert.deepEqual(statuses(load(folder(t, {triggers: [file], evidence: {fixture: {[first.id]: passing(first), [second.id]: passing(second)}}}))), ['active', 'active']);
  assert.deepEqual(statuses(load(folder(t, {triggers: [file], evidence: {fixture: {[first.id]: passing(first)}}}))), ['active', 'candidate'], 'one record certifies one id');
  assert.deepEqual(statuses(load(folder(t, {triggers: [file], evidence: {fixture: {[first.id]: passing(first), [second.id]: passing(second)}}, evidenceFile: 'actions.json'}))), ['candidate', 'candidate'], 'the same records under the actions file');
  const {tests, ...noProof} = passing(first);
  assert.deepEqual(statuses(load(folder(t, {triggers: [file], evidence: {fixture: {[first.id]: noProof}}}))), ['candidate', 'candidate'], 'passed true with no proof');
  for (const content of ['{not json', '[]', 'null']) assert.deepEqual(statuses(load(folder(t, {triggers: [file], evidence: {fixture: content}}))), ['candidate', 'candidate'], content);
});

// ---- the feed key and the lens -------------------------------------------------------------------------------------------------------------
test('pollHash: triggers with one bound poll share it, whatever they name their resource input, and triggersOnPoll() answers all of them on that app only', t => {
  const named = itemTrigger('item-named', trigger => {
    trigger.inputSchema = closed({state: {type: 'string', enum: ['all', 'open']}});
    trigger.resource = ['state'];
    trigger.poll.source.steps[0].query.kind = {input: '/state'};
  });
  const each = itemTrigger('item-each', trigger => {
    trigger.inputSchema = closed({kinds: {type: 'array', minItems: 1, maxItems: 5, items: words(10)}});
    trigger.resource = {each: '/kinds', as: 'kind'};
    trigger.poll.source.steps[0].query.kind = {var: 'kind'};
  });
  const filtered = itemTrigger('item-gone', trigger => { trigger.filter = [{present: {item: '/deleted'}}]; });
  const other = itemTrigger('item-other', trigger => { trigger.poll.source.steps[0].query.extra = {const: 'yes'}; });
  const catalog = load(folder(t, {triggers: [fileOf([itemTrigger('item-changed'), named, each, filtered, other])]}));
  const hash = byKey(catalog, 'item-changed').pollHash;
  assert.deepEqual(['item-named', 'item-each', 'item-gone'].map(key => byKey(catalog, key).pollHash), [hash, hash, hash]);
  assert.notEqual(byKey(catalog, 'item-other').pollHash, hash);
  assert.deepEqual(catalog.triggersOnPoll('fixture', hash).map(item => item.entry.key).sort(), ['item-changed', 'item-each', 'item-gone', 'item-named']);
  assert.deepEqual(catalog.triggersOnPoll('fixture', byKey(catalog, 'item-other').pollHash).map(item => item.entry.key), ['item-other']);
  assert.deepEqual(catalog.triggersOnPoll('google-calendar', hash), []);
  assert.deepEqual(catalog.triggersOnPoll('fixture', 'a'.repeat(64)), []);
});

test('pollHash moves with what a poll sends and how its cursor walks, and with the pin of a transform those name; never with what an item becomes', t => {
  const hashOf = (trigger, {pins = PINS, change = () => {}} = {}) => {
    const deps = {...VALIDATE(), pins}, file = fileOf([trigger], change, deps);
    return byKey(load(folder(t, {triggers: [file]}), {deps: {...DEPS, pins}}), trigger.key).pollHash;
  };
  const base = hashOf(itemTrigger('item-changed'));
  for (const [label, trigger] of [
    ['a constant of the request', itemTrigger('item-changed', trigger => { trigger.poll.source.steps[0].query.extra = {const: 'yes'}; })],
    ['the page size of a step', itemTrigger('item-changed', trigger => { trigger.poll.source.steps[0].maxResponseBytes = 65_536; })],
    ['a seed', itemTrigger('item-changed', trigger => { trigger.poll.seed = {step: {id: 'seed', method: 'GET', path: '/labels', expect: OK}, cursor: {name: 'since', pointer: '/now'}}; })],
    ['a cursor overlap', itemTrigger('item-changed', trigger => { trigger.poll.cursors[0].overlapSeconds = 120; })],
    ['the resync statuses', itemTrigger('item-changed', trigger => { trigger.poll.resync.statusIn = [410]; })],
    ['the order the cursor walks', itemTrigger('item-changed', trigger => { trigger.poll.order = 'asc'; })],
    ['the item time the cursor reads', itemTrigger('item-changed', trigger => { trigger.poll.itemTime.pointer = '/created'; })],
  ]) assert.notEqual(hashOf(trigger), base, label);
  assert.notEqual(hashOf(itemTrigger('item-changed'), {change: file => { file.pinnedParameters = {account: 'other'}; }}), base, 'the file\'s pinned parameters');
  assert.notEqual(hashOf(itemTrigger('item-changed'), {pins: {...PINS, 'time.rfc3339ToEpochSeconds@1': 'f'.repeat(64)}}), base, 'the pin of the cursor\'s compare');
  for (const [label, trigger] of [
    ['a filter', itemTrigger('item-changed', trigger => { trigger.filter = [{present: {item: '/deleted'}}]; })],
    ['an enrich step', itemTrigger('item-changed', trigger => { trigger.poll.enrich = {max: 5, steps: [{id: 'more', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, expect: OK}]}; })],
    ['the duplicate rule', itemTrigger('item-changed', trigger => { trigger.dedupe = {kind: 'content-hash', fields: [{item: '/name'}]}; })],
    ['the item id', itemTrigger('item-changed', trigger => { trigger.poll.itemId = {item: '/key'}; })],
    ['the event', itemTrigger('item-changed', trigger => { trigger.event.summary = []; })],
    ['the interval', itemTrigger('item-changed', trigger => { trigger.delivery.intervalSeconds.default = 300; trigger.poll.minIntervalSeconds = 120; })],
    ['the words', itemTrigger('item-changed', trigger => { trigger.name = 'Another name'; })],
  ]) assert.equal(hashOf(trigger), base, label);
  assert.equal(hashOf(itemTrigger('item-changed'), {pins: {...PINS, 'text.truncate@1': 'f'.repeat(64)}}), base, 'a pin only the event reads');
  assert.equal(hashOf(itemTrigger('item-changed'), {change: reviewed}), base, 'lifecycle data');
});

test('pollHash holds its app and the action a poll reuses: one poll in another app, or on another version of that action, is another feed', () => {
  const file = fileOf([itemTrigger('item-changed')]), [entry] = entriesOf(file), hash = triggerPollHash(file, entry, PINS);
  assert.equal(triggerPollHash(file, entry, PINS), hash, 'the same poll, the same key');
  assert.notEqual(triggerPollHash({...file, appId: 'fixture-rpc'}, entry, PINS), hash, 'its app');
  const reused = fileOf([reusedTrigger()]), [action] = entriesOf(reused), key = triggerPollHash(reused, action, PINS);
  assert.equal(action.sources.length, 1);
  assert.notEqual(triggerPollHash(reused, {...action, sources: [{...action.sources[0], pollHash: 'f'.repeat(64)}]}, PINS), key, 'the reused action\'s poll hash');
});

test('a Link paging step and a transform in a request bind their pins too, and a constant that only looks like a resource stays data', t => {
  const hashOf = (trigger, pins = PINS) => {
    const catalog = load(folder(t, {triggers: [fileOf([trigger], undefined, {...VALIDATE(), pins})]}), {deps: {...DEPS, pins}});
    assert.deepEqual([...catalog.triggersRefused], []);
    return byKey(catalog, trigger.key).pollHash;
  };
  const link = itemTrigger('item-changed', trigger => { trigger.poll.source.steps[0].page.next = {link: 'next', param: 'page'}; trigger.poll.source.steps[0].page.into = {query: 'page'}; });
  assert.notEqual(hashOf(link, {...PINS, 'ids.linkPage@1': 'f'.repeat(64)}), hashOf(link), 'Link paging');
  const hashed = itemTrigger('item-changed', trigger => { trigger.poll.source.steps[0].query.note = {pick: {transform: 'text.truncate@1', args: {text: {const: 'note'}, max: {const: 200}}}, pointer: '/text'}; });
  assert.notEqual(hashOf(hashed, {...PINS, 'text.truncate@1': 'f'.repeat(64)}), hashOf(hashed), 'a transform in a request');
  // A compare and an item time can name the same transform, so a history cursor shows each alone.
  const history = historyTrigger(), dated = historyTrigger('item-logged', trigger => { trigger.poll.itemTime = {pointer: '/updated', format: 'rfc3339'}; });
  assert.notEqual(hashOf(history, {...PINS, 'time.decimalCompare@1': 'f'.repeat(64)}), hashOf(history), 'a cursor\'s compare');
  assert.notEqual(hashOf(dated, {...PINS, 'time.rfc3339ToEpochSeconds@1': 'f'.repeat(64)}), hashOf(dated), 'the transform that reads the item time');
  const constant = value => itemTrigger('item-changed', trigger => { trigger.poll.source.steps[0].expect = {status: [200], require: [{equals: {pointer: '/mode', value: {const: value}}}]}; });
  assert.notEqual(hashOf(constant({input: '/kind'})), hashOf(constant({resource: 0})), 'a constant is never read as a node');
});

test('lenses: a trigger with no input outside its resource has one fixed lens; two triggers read a feed alike only when items, id, version, filter, dedupe and enrich all match', t => {
  const more = {max: 5, steps: [{id: 'more', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, expect: OK}]};
  const lensOf = edit => { const trigger = itemTrigger('item-changed', edit); return byKey(load(folder(t, {triggers: [fileOf([trigger])]})), 'item-changed').lenses[0]; };
  const base = lensOf();
  assert.equal(lensOf(trigger => { trigger.event.summary = []; trigger.name = 'Other'; }), base, 'the event is not how a trigger reads the feed');
  assert.equal(lensOf(trigger => { trigger.poll.cursors[0].overlapSeconds = 120; }), base, 'nor is the cursor');
  assert.equal(lensOf(trigger => { trigger.inputSchema = closed({state: {type: 'string', enum: ['all', 'open']}}); trigger.resource = ['state']; trigger.poll.source.steps[0].query.kind = {input: '/state'}; }), base, 'nor the name of the resource input');
  // A resource value inside the lens's own fields is still no input of the lens: one trigger keeps one fixed lens, whatever it names that input.
  const scoped = name => trigger => {
    trigger.inputSchema = closed({[name]: {type: 'string', enum: ['all', 'open']}});
    trigger.resource = [name];
    trigger.poll.source.steps[0].query.kind = {input: `/${name}`};
    trigger.poll.itemId = {concat: [{input: `/${name}`}, {const: ':'}, {item: '/id'}], max: 200};
  };
  assert.notEqual(lensOf(scoped('kind')), undefined, 'a resource input in the item id leaves one fixed lens');
  assert.equal(lensOf(scoped('kind')), lensOf(scoped('state')));
  for (const [label, edit] of [
    ['the items', trigger => { trigger.poll.items = {step: 'list', pointer: '/rows'}; }],
    ['the item id', trigger => { trigger.poll.itemId = {item: '/key'}; }],
    ['the item version', trigger => { trigger.poll.itemVersion = '/etag'; }],
    ['a filter', trigger => { trigger.filter = [{present: {item: '/deleted'}}]; }],
    ['the duplicate rule', trigger => { trigger.dedupe = {kind: 'content-hash', fields: [{item: '/name'}]}; }],
    ['an enrich step', trigger => { trigger.poll.enrich = more; }],
    ['another enrich step', trigger => { trigger.poll.enrich = {...more, steps: [{...more.steps[0], maxResponseBytes: 65_536}]}; }],
  ]) assert.notEqual(lensOf(edit), base, label);
});

test('the list behind an each resource is no resource value: a lens that reads it has no fixed lens, since two subscriptions can share an element and hold different lists', t => {
  const listed = edit => itemTrigger('item-listed', trigger => {
    trigger.inputSchema = closed({kinds: {type: 'array', minItems: 1, maxItems: 5, items: words(10)}});
    trigger.resource = {each: '/kinds', as: 'kind'};
    trigger.poll.source.steps[0].query.kind = {var: 'kind'};
    edit(trigger);
  });
  const quiet = byKey(load(folder(t, {triggers: [fileOf([listed(trigger => { trigger.filter = [{equals: [{var: 'kind'}, {const: 'a'}]}]; })])]})), 'item-listed');
  assert.equal(quiet.lenses.length, 1, 'the element a feed is keyed on leaves one fixed lens');
  const item = byKey(load(folder(t, {triggers: [fileOf([listed(trigger => { trigger.filter = [{equals: [{input: '/kinds/0'}, {const: 'a'}]}]; })])]})), 'item-listed');
  assert.deepEqual(item.lenses, [], 'a feed tracks this lens only for a live subscription');
  const lens = triggerLens(item.entry, {kinds: ['a', 'b']});
  assert.notEqual(triggerLens(item.entry, {kinds: ['b', 'a']}), lens, 'one feed, one element, and a filter that reads each list differently');
  assert.equal(triggerLens(item.entry, {kinds: ['a', 'b']}), lens);
});

test('a trigger whose filter or enrich step reads an input outside its resource has no fixed lens: triggerLens() takes the subscription\'s value, and a resource value never changes it', t => {
  const labelled = where => itemTrigger('item-labelled', trigger => {
    trigger.inputSchema = closed({kind: {type: 'string', enum: ['all', 'open']}, labelId: words(64)});
    if (where === 'filter') trigger.filter = [{equals: [{input: '/labelId'}, {const: 'L1'}]}];
    if (where === 'enrich') trigger.poll.enrich = {max: 5, steps: [{id: 'label', method: 'GET', path: '/labels/{label_id}', params: {label_id: {input: '/labelId'}}, expect: OK}]};
  });
  for (const where of ['filter', 'enrich']) {
    const file = fileOf([labelled(where)]), catalog = load(folder(t, {triggers: [file]})), item = byKey(catalog, 'item-labelled');
    assert.deepEqual(item.lenses, [], `${where}: a feed tracks this lens only for a live subscription`);
    const lens = triggerLens(item.entry, {kind: 'all', labelId: 'L1'});
    assert.match(lens, /^[a-f0-9]{16}$/);
    assert.notEqual(triggerLens(item.entry, {kind: 'all', labelId: 'L2'}), lens, `${where}: another value of that input`);
    assert.equal(triggerLens(item.entry, {kind: 'open', labelId: 'L1'}), lens, `${where}: another resource value`);
    assert.notEqual(triggerLens(item.entry, {}), lens, `${where}: an input left out`);
  }
});

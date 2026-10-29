import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {compileOpenApi, validateCapability, canonicalHash} from '../lib/compiler.mjs';
import {Store} from '../lib/store.mjs';
import {PermissionManager, sameRoute, permissionEffect, capabilityPermissionHash} from '../lib/permissions.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {EnvironmentRuntimes} from '../lib/tenant/runtime-bundle.mjs';
import {AdapterFactory} from '../lib/adapter-factory.mjs';
import {HeartbeatScheduler} from '../lib/heartbeat.mjs';
import {PERMISSION_GROUPS, UNAVAILABLE_REASONS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {lockedRowOf, memberRoutes, rowMemberOf, actionSteps, LOCK_WORDS} from '../lib/row-locks.mjs';
import {uncertainRows, unresolvedUncertain, prepareProxyJob} from '../lib/proxy-runtime.mjs';
import {loadActionCatalog} from '../lib/action-catalog.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {actionHarness, certifiedFile, EVIDENCE} from './fixtures/actions/runtime-fixture.mjs';
import {fixtureGroups, fixtureConfigs, fixtureMap, fixtureSignIn, withIds} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';

// F10.11 parts e and f (docs/F10.11-BUILD-MAP.md parts e and f, section 3): the permission decision for actions (T8), and locks, routes
// and c7 from placements. An action's mode is the strictest of its own record and of every row, ceiling and typed operation its steps
// touch, in every phase; its own default is drawn from every perform and verify row; a sensitive step asks before any secret is read.
// Run on the fake app's run harness (test/fixtures/actions/runtime-fixture.mjs): nothing here sends a request.

// ---- the extra actions these cases need, beside the fixture file's seven ---------------------------------------------------------------
const OK = {status: [200], require: []};
const WRITE_HINTS = {readOnly: false, destructive: false, idempotent: false, openWorld: true}, READ_HINTS = {readOnly: true, destructive: false, idempotent: true, openWorld: true};
const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
const action = (key, fields) => ({id: `fixture.action.${key}.v1.${'0'.repeat(24)}`, key, version: 1, name: key, description: `The ${key} action of these tests.`, guards: [], prepare: [],
  definitive: [400], certified: {evidence: EVIDENCE, definitionHash: '0'.repeat(64)}, ...fields});
const LABEL = {id: 'label', method: 'POST', path: '/labels', body: {object: {name: {input: '/name'}}}, expect: OK};
const LABEL_VERIFY = {requests: [{id: 'check', method: 'GET', path: '/labels/{label_id}', params: {label_id: {step: 'label', pointer: '/id'}}, expect: OK}],
  identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'label', pointer: '/id'}}], assert: []};
/** Add a label: one write in fixture.labels.write, a row that stays in the account and defaults to Allow. */
const createLabel = () => action('create-label', {effect: 'write', row: 'fixture.labels.write', hints: WRITE_HINTS, inputSchema: closed({name: words()}),
  outputSchema: closed({id: {type: 'string', maxLength: 64}}), perform: [LABEL], verify: LABEL_VERIFY, output: {id: {step: 'label', pointer: '/id'}},
  preview: [{label: 'Label', expr: {input: '/name'}}]});
/** Note and label: POST /messages (fixture.messages.send, which reaches people), then POST /labels, declared in fixture.labels.write. */
const noteAndLabel = () => ({...createLabel(), id: `fixture.action.note-and-label.v1.${'0'.repeat(24)}`, key: 'note-and-label', inputSchema: closed({text: words(), name: words()}),
  perform: [{id: 'note', method: 'POST', path: '/messages', body: {object: {text: {input: '/text'}}}, expect: OK}, LABEL],
  preview: [{label: 'Note', expr: {input: '/text'}}, {label: 'Label', expr: {input: '/name'}}]});
/** Read a key, then list: the prepare step reads GET /keys/{key_id}, a member its row marks sensitive: 'secrets'. */
const keyThenList = () => action('key-then-list', {effect: 'read', row: 'fixture.items.read', hints: READ_HINTS, inputSchema: closed({keyId: words(64)}),
  outputSchema: closed({first: {type: 'string', maxLength: 64}}), prepare: [{id: 'key', method: 'GET', path: '/keys/{key_id}', params: {key_id: {input: '/keyId'}}, expect: OK}],
  perform: [{id: 'list', method: 'GET', path: '/items', expect: OK}], output: {first: {step: 'list', pointer: '/items/0/id'}}, preview: [{label: 'Key', expr: {input: '/keyId'}}]});
/** Trash an item: PATCH /items/{item_id} with in_trash, which a body route of fixture.items.edit moves to fixture.items.delete. */
const trashItem = () => action('trash-item', {effect: 'delete', row: 'fixture.items.delete', hints: {readOnly: false, destructive: true, idempotent: false, openWorld: true},
  inputSchema: closed({itemId: words(64)}), outputSchema: closed({id: {type: 'string', maxLength: 64}}),
  perform: [{id: 'trash', method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, body: {object: {in_trash: {const: true}}}, expect: OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, expect: OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {input: '/itemId'}}], assert: []},
  output: {id: {step: 'trash', pointer: '/id'}}, preview: [{label: 'Item', expr: {input: '/itemId'}}]});
const ZONE = {either: [{step: 'zone', pointer: '/value'}, {step: 'primary', pointer: '/name'}]};
/** Find with an optional read (R7): GET /keys needs the sign-in's optional scope; GET /labels is its fallback. */
const findWithZone = () => action('find-with-zone', {effect: 'read', row: 'fixture.items.read', hints: READ_HINTS, inputSchema: closed({kind: {type: 'string', enum: ['all', 'open']}}),
  outputSchema: closed({zone: {type: 'string', maxLength: 100}}),
  prepare: [{id: 'zone', method: 'GET', path: '/keys', optional: true, expect: OK}, {id: 'primary', method: 'GET', path: '/labels', fallbackFor: 'zone', expect: OK}],
  perform: [{id: 'list', method: 'GET', path: '/items', query: {kind: {input: '/kind'}, zone: ZONE}, expect: OK}], output: {zone: ZONE}, preview: [{label: 'Show', expr: {input: '/kind'}}]});
/** The fixture file, reviewed and certified, with these extra actions added. */
const withActions = (...extra) => certifiedFile(file => { file.actions.push(...extra.map(make => make())); });
/** The rows and sign-in an optional step needs: GET /keys needs fixture:keys, which the sign-in asks for only as an optional scope. */
const OPTIONAL_ROWS = rows => ({...rows, groups: rows.groups.map(group => group.id === 'fixture.keys.read' ? {...group, scopeSets: [['fixture:keys']]}
  : group.id === 'fixture.items.read' ? {...group, scopeSets: [['fixture:all']]} : group)});
function optionalSignIn() {
  const definition = structuredClone(fixtureSignIn());
  definition.apps[0].access.levels.full.optional = ['fixture:keys'];
  return definition;
}

// ---- typed operations of the fixture app, for c4 -------------------------------------------------------------------------------------
const P = name => [{name, in: 'path', required: true, schema: {type: 'string'}}], DONE = {200: {description: 'Done'}};
/** One typed http operation of the fixture app, compiled on a public host and moved to the fixture's API base, active. */
function typedOne(route, method, operationId) {
  const parameters = [...route.matchAll(/\{(\w+)\}/g)].map(([, name]) => P(name)[0]);
  const [cap] = compileOpenApi({appId: 'fixture', document: {openapi: '3.1.0', info: {title: 'Fixture', version: '1'}, servers: [{url: 'https://api.example.com'}],
    paths: {[route]: {[method]: {operationId, parameters, responses: DONE}}}}}).capabilities;
  return {...cap, status: 'active', request: {...cap.request, url: cap.request.url.replace('https://api.example.com', 'https://api.fixture.test')}};
}
/** Typed http operations of the fixture app, compiled on a public host and moved to the fixture's API base, active. */
function typedCaps() {
  const document = {openapi: '3.1.0', info: {title: 'Fixture', version: '1'}, servers: [{url: 'https://api.example.com'}], paths: {
    '/items': {get: {operationId: 'deleteItems', responses: DONE}},
    '/items/{itemId}': {patch: {operationId: 'updateItem', parameters: P('itemId'), requestBody: {content: {'application/json': {schema: {type: 'object'}}}}, responses: DONE}},
    '/accounts/{account}/profile': {get: {operationId: 'getProfile', parameters: P('account'), responses: DONE}},
    '/labels/{labelId}': {get: {operationId: 'getLabelApiKey', parameters: P('labelId'), responses: DONE}}}};
  return Object.fromEntries(compileOpenApi({appId: 'fixture', document}).capabilities.map(cap => [cap.name,
    {...cap, status: 'active', request: {...cap.request, url: cap.request.url.replace('https://api.example.com', 'https://api.fixture.test')}}]));
}

// ---- helpers ---------------------------------------------------------------------------------------------------------------------------
const decide = (h, key, options) => h.permissions.decision(h.store.get('connections', h.account), h.capability(key), undefined, options);
const setRow = (h, groupId, mode, account = h.account) => h.proxyPolicy.set({connectionId: account, row: `group:${groupId}`, mode, confirmAllow: true});
/** A permission manager and proxy over the harness store with other rows or a ceiling, wired as the Runtime wires them. */
function manager(h, {groups = h.groups, configs = fixtureConfigs(groups), ceilingOf = null, catalog = h.catalog} = {}) {
  const permissions = new PermissionManager({store: h.store, groups, configs, ceilingOf});
  const proxyPolicy = new ProxyPolicy({store: h.store, permissions, groups, configs});
  new Runtime({store: h.store, permissions, proxyPolicy, actions: catalog, connections: h.connections, request: async () => { throw new Error('no request in a decision test'); }});
  return {permissions, proxyPolicy, decide: (key, account = h.account) => permissions.decision(h.store.get('connections', account), h.capability(key))};
}
/** The catalog of the harness folder read again with changed rows, as the next start reads it after a rows slice. */
function catalogWith(h, groups) {
  return loadActionCatalog({directory: h.directory, evidenceRoot: h.root, maps: h.maps, deps: {...h.deps, groups, configs: fixtureConfigs(groups)}, codeHashes: h.codeHashes});
}

test('part e: each driver-comparison site accepts an action on an http connection and refuses it on a browser one', t => {
  const h = actionHarness(t), {store, permissions} = h, list = h.capability('list-items v1');
  store.put('connections', {id: 'fixture-browser', appId: 'fixture', driver: 'browser', transport: 'helper', status: 'session_ready', label: 'Fixture in a browser', identity: {id: 'acct-1'}, createdAt: new Date(h.now).toISOString()});
  const http = store.get('connections', h.account), browser = store.get('connections', 'fixture-browser');
  // sameRoute(): the same app; an action on its app's http connection; anything else keeps driver equality and the transport rule.
  assert.deepEqual([sameRoute(http, list), sameRoute(browser, list), sameRoute({...http, appId: 'fixture-rpc'}, list)], [true, false, false]);
  const saved = {id: 'b', appId: 'fixture', driver: 'browser', transport: 'persistent'};
  assert.deepEqual([sameRoute(browser, saved), sameRoute({...browser, transport: 'persistent'}, saved), sameRoute(http, saved), sameRoute(http, {id: 'h', appId: 'fixture', driver: 'http'})],
    [false, true, false, true]);
  // decision() (lib/permissions.mjs 244 and 258): read on its own steps, not refused by driver.
  const onHttp = permissions.decision(http, list);
  assert.deepEqual([onHttp.status, onHttp.mode, onHttp.executable, onHttp.effect, onHttp.groupId], ['active', 'allow', true, 'read', 'fixture.items.read']);
  const onBrowser = permissions.decision(browser, list);
  assert.deepEqual([onBrowser.executable, onBrowser.reason], [false, 'The capability belongs to a different application or connection route.']);
  // list() (274): an http account lists the app's actions; a browser connection of the same app does not.
  assert.ok(permissions.list(h.account).some(decision => decision.capabilityId === list.id));
  assert.ok(!permissions.list('fixture-browser').some(decision => decision.capabilityId === list.id));
  // set() (280): an action's own record is written on its http account, refused on a browser connection.
  const set = permissions.set({connectionId: h.account, capabilityId: list.id, mode: 'ask'});
  assert.deepEqual([set.mode, set.policySource], ['ask', 'saved']);
  assert.throws(() => permissions.set({connectionId: 'fixture-browser', capabilityId: list.id, mode: 'ask'}), /Capability does not belong to this application and connection route\./);
  // permissionEffect() is the action's own effect; every other driver reads as before.
  assert.deepEqual(['list-items v1', 'update-item v1', 'remove-labels v1'].map(key => permissionEffect(h.capability(key))), ['read', 'write', 'delete']);
  assert.deepEqual([permissionEffect({driver: 'http', request: {method: 'GET'}}), permissionEffect({driver: 'device'}), permissionEffect({driver: 'unknown'})], ['read', 'read', 'write']);
});

test('part e: c3, c4, c8, heartbeats, validateCapability() and the adapter factory keep refusing actions', async t => {
  const h = actionHarness(t), {store, proxyPolicy} = h, update = h.capability('update-item v1'), list = h.capability('list-items v1');
  for (const capability of [update, list]) h.permissions.set({connectionId: h.account, capabilityId: capability.id, mode: 'deny'});
  const context = proxyPolicy.route(h.account);
  // c4 reads typed http operations only: no action becomes a typed template, so an action's Never caps no proxied request.
  assert.ok(proxyPolicy.typedTemplates(context).every(({capability}) => capability.driver === 'http'));
  const patch = proxyPolicy.decide(h.account, {method: 'PATCH', path: '/items/abc', body: {name: 'x'}});
  assert.ok(patch.mode !== 'deny' && !patch.clamps.includes('c4_typed_operation'), 'c4');
  // c3 reads typed reads only: Other reads keep the read rows' modes.
  const other = proxyPolicy.decide(h.account, {method: 'GET', path: '/somewhere'});
  assert.ok(other.mode !== 'deny' && !other.clamps.includes('c3_typed_reads'), 'c3');
  // c8, developer environments: a row's members are its typed operations, never its actions.
  const floor = new ProxyPolicy({store, permissions: h.permissions, groups: h.groups, configs: h.configs, rowFloor: true});
  assert.deepEqual(floor.members(floor.route(h.account), 'fixture.items.edit'), []);
  assert.ok(floor.decide(h.account, {method: 'PATCH', path: '/items/abc', body: {name: 'x'}}).mode !== 'deny', 'c8');
  // A heartbeat refuses an active read action before effectOf() (part d).
  h.permissions.set({connectionId: h.account, capabilityId: list.id, mode: 'allow'});
  const scheduler = new HeartbeatScheduler({store, runtime: h.runtime, checkConnection: async () => ({ok: true})});
  assert.throws(() => scheduler.create({name: 'Watch items', intervalSeconds: 60, connectionId: h.account, capabilityId: list.id, args: {kind: 'all'}}), /Actions run only when asked/);
  // validateCapability() refuses an action record, so the adapter factory, which validates every candidate it lists, refuses one too.
  assert.throws(() => validateCapability(list), /unsupported field kind/);
  const document = {openapi: '3.1.0', info: {title: 'Fixture', version: '1'}, paths: {}};
  const map = {appId: 'fixture', sourceUrl: 'https://api.example.com/openapi.json', sourceKind: 'openapi', fingerprint: canonicalHash(document),
    operations: [{id: 'listItems', method: 'GET', path: '/items', support: 'candidate', capabilityId: list.id}]};
  store.put('discoverySources', {id: `fixture:${map.fingerprint}`, appId: 'fixture', sourceUrl: map.sourceUrl, fingerprint: map.fingerprint, document});
  const factory = new AdapterFactory({store, catalog: () => [{id: 'fixture', discovery: {kind: 'openapi', url: map.sourceUrl}, apiOrigins: ['https://api.fixture.test']}],
    discovery: {discover: async () => { store.put('applicationMaps', {id: 'fixture', ...map}); return store.get('applicationMaps', 'fixture'); }}, acquisition: {}, runtime: h.runtime});
  const report = await factory.build({appId: 'fixture'});
  assert.equal(report.status, 'blocked');
  assert.match(report.error, /unsupported field kind/);
});

test('part e: statuses: active, candidate with its reason, removed for a disabled or superseded id with replacedBy, unsupported while unplaced or with no catalog', t => {
  const h = actionHarness(t), list = h.capability('list-items v1'), account = h.store.get('connections', h.account);
  assert.deepEqual([decide(h, 'list-items v1').status, decide(h, 'list-items v1').executable], ['active', true]);
  // No catalog: every action reads unsupported and never runs.
  const bare = manager(h, {catalog: null});
  assert.deepEqual([bare.decide('list-items v1').status, bare.decide('list-items v1').executable, bare.decide('list-items v1').reason],
    ['unsupported', false, 'Actions are not loaded in this Fabric, so this action cannot run.']);
  // A candidate keeps the catalog's reason, even with a stored record that says active.
  const uncertified = actionHarness(t, {file: certifiedFile(file => { delete file.actions[0].certified; })});
  const candidate = decide(uncertified, 'list-items v1');
  assert.deepEqual([candidate.status, candidate.executable, candidate.reason], ['candidate', false, 'This action names no live evidence yet, so it stays a candidate (I8).']);
  const forced = uncertified.permissions.decision(uncertified.store.get('connections', uncertified.account), {...uncertified.capability('list-items v1'), status: 'active'});
  assert.deepEqual([forced.status, forced.executable], ['candidate', false], 'a record marked active by hand stays the catalog\'s candidate');
  // And an active action whose stored record was demoted (a failed load, part p) is a candidate until it is seeded again.
  const demoted = h.permissions.decision(account, {...list, status: 'candidate'});
  assert.deepEqual([demoted.status, demoted.executable, demoted.reason], ['candidate', false, 'This action is a candidate: only a reviewed file with live evidence makes it active (I8).']);
  // A stored record that differs from the reviewed definition is not the catalog's action.
  const tampered = {...list, description: 'Changed by hand.'};
  assert.deepEqual([h.permissions.decision(account, tampered).status, h.permissions.decision(account, tampered).executable], ['unsupported', false]);
  // The superseded id, stored as seeding leaves it (disabled), is removed and names its replacement; an orphan is removed.
  const [old] = h.catalog.superseded.keys();
  const gone = h.permissions.decision(account, {...list, id: old, status: 'disabled'});
  assert.deepEqual([gone.status, gone.executable, gone.replacedBy, gone.reason], ['removed', false, list.id, 'This action was replaced by a newer version. Use the action it names instead.']);
  const orphan = h.permissions.decision(account, {...list, id: 'fixture.action.gone.v1.000000000000000000000000', status: 'disabled'});
  assert.deepEqual([orphan.status, orphan.executable, orphan.replacedBy], ['removed', false, undefined]);
  // Unplaced (no stored map, so the step on fixture.items.list cannot place): unsupported, never executable.
  const unplaced = actionHarness(t, {map: null}), placed = unplaced.capability('list-items v1');
  const decision = unplaced.permissions.decision(unplaced.store.get('connections', unplaced.account), placed);
  assert.deepEqual([decision.status, decision.executable], ['unsupported', false]);
  assert.match(decision.reason, /cannot be placed/);
});

test('part e: critique test 6: a saved proxy-row Never blocks; a stale record reads Ask; a record following a default Ask adds nothing', t => {
  const h = actionHarness(t, {file: withActions(createLabel)});
  assert.equal(decide(h, 'list-items v1').mode, 'allow');
  setRow(h, 'fixture.items.read', 'deny');
  const never = decide(h, 'list-items v1');
  assert.deepEqual([never.mode, never.executable, never.prepareMode, never.performMode], ['deny', false, 'deny', 'deny']);
  assert.match(never.reason, /"Access items" is set to Never/);
  // A record whose binding no longer matches its row reads Ask, never a standing Allow.
  const id = h.proxyPolicy.policyId(h.account, 'group:fixture.items.read');
  h.store.put('permissions', {...h.store.get('permissions', id), mode: 'allow', bindingHash: 'f'.repeat(64)});
  assert.deepEqual([decide(h, 'list-items v1').mode, decide(h, 'list-items v1').executable], ['ask', true]);
  assert.equal(setRow(h, 'fixture.items.read', 'allow').source, 'default');
  // fixture.labels.write is a write row, so the proxy's own default there is Ask: a clamp on unreviewed bodies, not the owner's choice.
  // With no record, and with a record that follows that default, the action keeps its own default Allow.
  assert.deepEqual([decide(h, 'create-label v1').defaultMode, decide(h, 'create-label v1').mode], ['allow', 'allow']);
  assert.equal(setRow(h, 'fixture.labels.write', 'ask').source, 'default');
  assert.equal(decide(h, 'create-label v1').mode, 'allow', 'a record following a default Ask adds nothing');
  setRow(h, 'fixture.labels.write', 'deny');
  assert.equal(decide(h, 'create-label v1').mode, 'deny');
});

test('part e: a step a body route moved counts the row it came from too', t => {
  const h = actionHarness(t, {file: withActions(trashItem)}), trash = h.capability('trash-item v1');
  const placed = decide(h, 'trash-item v1');
  assert.deepEqual(placed.steps.map(step => [step.stepId, step.groupId]), [['trash', 'fixture.items.delete'], ['check', 'fixture.items.read']]);
  assert.deepEqual(placed.rows, ['Delete items', 'Edit items', 'Access items']);
  h.permissions.set({connectionId: h.account, capabilityId: trash.id, mode: 'allow'});
  assert.equal(decide(h, 'trash-item v1').mode, 'allow', 'c1 is a proxy clamp on raw requests; the owner allowed this exact action');
  setRow(h, 'fixture.items.edit', 'deny');
  const never = decide(h, 'trash-item v1');
  assert.deepEqual([never.mode, never.executable], ['deny', false]);
  assert.match(never.reason, /"Delete items" is set to Never/, 'the step\'s row names it; the Never came from the row it was moved from');
});

test('part e: critique test 6: a typed operation\'s saved Never blocks; an unsupported typed member does not (mode, not status)', t => {
  const typed = typedCaps();
  const map = {...fixtureMap(), operations: [...fixtureMap().operations, {id: 'fixture.profile.get', method: 'GET', path: '/accounts/{account}/profile', capabilityId: typed.getProfile.id, support: 'unsupported'}]};
  const h = actionHarness(t, {map});
  for (const name of ['updateItem', 'getProfile']) h.store.put('capabilities', typed[name]);
  // c4 reads each typed operation whose template fits a step's own template: PATCH /items/{itemId} fits both perform steps of update-item,
  // and caps them at its mode, its default Ask included.
  h.permissions.set({connectionId: h.account, capabilityId: h.capability('update-item v1').id, mode: 'allow'});
  assert.equal(decide(h, 'update-item v1').mode, 'ask');
  h.permissions.set({connectionId: h.account, capabilityId: typed.updateItem.id, mode: 'allow'});
  assert.equal(decide(h, 'update-item v1').mode, 'allow');
  h.permissions.set({connectionId: h.account, capabilityId: typed.updateItem.id, mode: 'deny'});
  const blocked = decide(h, 'update-item v1');
  assert.deepEqual([blocked.mode, blocked.executable, blocked.performMode, blocked.prepareMode], ['deny', false, 'deny', 'allow']);
  assert.deepEqual(blocked.steps.filter(step => step.mode === 'deny').map(step => step.stepId), ['rename', 'label']);
  // The profile read's typed operation is unsupported by the map: c4 reads its mode, not its status, so it does not block List items.
  const profile = h.permissions.decision(h.store.get('connections', h.account), typed.getProfile);
  assert.deepEqual([profile.status, profile.mode], ['unsupported', 'allow']);
  assert.deepEqual([decide(h, 'list-items v1').mode, decide(h, 'list-items v1').executable], ['allow', true]);
  h.permissions.set({connectionId: h.account, capabilityId: typed.getProfile.id, mode: 'deny'});
  assert.equal(decide(h, 'list-items v1').mode, 'deny', 'its saved Never still blocks');
});

test('part e: critique test 6: a developer ceiling on any step row caps, the verify row included', t => {
  const h = actionHarness(t), ceilings = {};
  const {decide: ceiled} = manager(h, {ceilingOf: (appId, groupId) => appId === 'fixture' ? ceilings[groupId] ?? null : null});
  assert.equal(ceiled('list-items v1').mode, 'allow');
  ceilings['fixture.items.read'] = 'ask';
  assert.equal(ceiled('list-items v1').mode, 'ask');
  // Remove labels: its only perform step is in fixture.items.delete; fixture.items.read holds only its verify request. No row has a record.
  ceilings['fixture.items.read'] = 'deny';
  const removed = ceiled('remove-labels v1');
  assert.deepEqual([removed.mode, removed.executable, removed.performMode], ['deny', false, 'deny']);
  assert.deepEqual(removed.steps.map(step => [step.stepId, step.phase, step.mode]), [['unlabel', 'perform', 'allow'], ['check', 'verify', 'deny']], 'Ask is the action\'s own default, not a row\'s');
});

test('part e: a Never verify row, and the Never row of a skipped optional step, refuse', t => {
  const h = actionHarness(t);
  setRow(h, 'fixture.items.read', 'deny');
  const removed = decide(h, 'remove-labels v1');
  assert.deepEqual([removed.mode, removed.executable], ['deny', false]);
  // An optional step whose scope the account lacks is skipped, and its row's Never still refuses the action before any call.
  const optional = actionHarness(t, {file: withActions(findWithZone), rows: OPTIONAL_ROWS, signIn: optionalSignIn()});
  optional.store.put('connections', {...optional.store.get('connections', optional.account), id: 'fixture-oauth', authMethod: 'oauth', scopes: ['fixture:all']});
  const find = () => optional.permissions.decision(optional.store.get('connections', 'fixture-oauth'), optional.capability('find-with-zone v1'));
  assert.deepEqual([find().mode, find().providerAccess, find().executable], ['allow', 'granted', true], 'zone is skipped: its fallback runs');
  // An optional step whose member can never work through a sign-in is skipped as a missing one is; it never makes the action unavailable.
  const gone = fixtureGroups(rows => { const changed = OPTIONAL_ROWS(rows); return {...changed, groups: changed.groups.map(group => group.id === 'fixture.keys.read' ? {...group, unavailable: {'GET /keys': 'no-oauth-scope'}} : group)}; });
  const skipped = manager(optional, {groups: gone}).permissions.decision(optional.store.get('connections', 'fixture-oauth'), optional.capability('find-with-zone v1'));
  assert.deepEqual([skipped.providerAccess, skipped.executable, skipped.steps[0].providerAccess], ['granted', true, 'unavailable']);
  setRow(optional, 'fixture.keys.read', 'deny', 'fixture-oauth');
  assert.deepEqual([find().mode, find().executable, find().prepareMode], ['deny', false, 'deny']);
});

test('part e: critique test 7: a step on a secrets member defaults to Ask in the sensitive row; a saved Allow goes stale when a member becomes sensitive or a step moves rows', t => {
  const h = actionHarness(t, {file: withActions(keyThenList)});
  const key = decide(h, 'key-then-list v1');
  assert.deepEqual([key.sensitivity, key.defaultMode, key.mode, key.groupId], ['secrets', 'ask', 'ask', 'fixture.items.read']);
  // A typed operation with a sensitive verdict that a step reaches makes the action sensitive too, and a saved Allow made before goes stale.
  h.permissions.set({connectionId: h.account, capabilityId: h.capability('update-item v1').id, mode: 'allow'});
  const before = decide(h, 'update-item v1');
  assert.deepEqual([before.mode, before.policySource, before.sensitivity], ['allow', 'saved', null]);
  h.store.put('capabilities', typedOne('/items/{itemId}', 'get', 'getItemApiKey'));
  const marked = decide(h, 'update-item v1');
  assert.deepEqual([marked.sensitivity, marked.stale, marked.mode, marked.policySource], ['secrets', true, 'ask', 'stale']);
  assert.notEqual(marked.bindingHash, before.bindingHash);
  assert.equal(h.permissions.sensitivityOf(h.capability('update-item v1')), 'secrets', 'sensitivityOf() answers from the same steps');
  // A member marked secrets by a later rows slice: the next start reads the catalog again, and the saved Allow goes stale.
  const fresh = actionHarness(t);
  fresh.permissions.set({connectionId: fresh.account, capabilityId: fresh.capability('update-item v1').id, mode: 'allow'});
  assert.equal(decide(fresh, 'update-item v1').policySource, 'saved');
  const secret = fixtureGroups(rows => ({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.read' ? {...group, sensitive: {'GET /items/{item_id}': 'secrets'}} : group)}));
  const sensitive = manager(fresh, {groups: secret, catalog: catalogWith(fresh, secret)}).decide('update-item v1');
  assert.deepEqual([sensitive.sensitivity, sensitive.stale, sensitive.mode], ['secrets', true, 'ask']);
  // A step that moves rows (the item read moves to fixture.keys.read): the placements are in the binding, so the saved Allow is stale.
  const moved = fixtureGroups(rows => ({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.read' ? {...group, requests: group.requests.filter(member => member !== 'GET /items/{item_id}')}
    : group.id === 'fixture.keys.read' ? {...group, requests: [...group.requests, 'GET /items/{item_id}']} : group)}));
  const movedCatalog = catalogWith(fresh, moved);
  assert.deepEqual([...movedCatalog.entries.values()].find(item => item.entry.key === 'update-item').entry.placements.filter(placement => placement.groupId === 'fixture.keys.read').map(placement => placement.stepId), ['item', 'check']);
  const stale = manager(fresh, {groups: moved, catalog: movedCatalog}).decide('update-item v1');
  assert.deepEqual([stale.stale, stale.mode, stale.policySource], [true, 'ask', 'stale']);
});

test('part e: a prepare step on a secrets member in an Allow read row makes prepareMode Ask, and so does a lookup step whose template matches a typed operation with a sensitive verdict', t => {
  const h = actionHarness(t, {file: withActions(keyThenList)});
  setRow(h, 'fixture.keys.read', 'allow');
  h.permissions.set({connectionId: h.account, capabilityId: h.capability('key-then-list v1').id, mode: 'ask'});
  const key = decide(h, 'key-then-list v1');
  assert.deepEqual([key.prepareMode, key.performMode], ['ask', 'ask']);
  assert.deepEqual(key.steps.map(step => [step.stepId, step.mode]), [['key', 'allow'], ['list', 'allow']], 'the rows themselves allow: the ask comes from the action\'s own mode');
  // List items looks its label up with GET /labels/{label_id}; a typed GET /labels/{labelId} named getLabelApiKey is classified secrets.
  // Saved at Allow, it adds Allow through c4: the lookup asks because it is sensitive, as usable() keeps only secrets members out.
  assert.equal(decide(h, 'list-items v1').prepareMode, 'allow');
  const secret = typedCaps().getLabelApiKey;
  h.store.put('capabilities', secret);
  h.permissions.set({connectionId: h.account, capabilityId: secret.id, mode: 'allow'});
  const list = decide(h, 'list-items v1');
  assert.deepEqual([list.sensitivity, list.prepareMode, list.mode], ['secrets', 'ask', 'ask']);
  assert.deepEqual(list.steps.map(step => [step.stepId, step.mode]), [['choice:labelId', 'allow'], ['profile', 'allow'], ['list', 'allow']]);
});

test('part e: own default over every step row: POST /messages then POST /labels, declared in fixture.labels.write (stayInAccount, default Allow), defaults to Ask because fixture.messages.send reaches people', t => {
  const h = actionHarness(t, {file: withActions(createLabel, noteAndLabel)});
  const alone = decide(h, 'create-label v1'), both = decide(h, 'note-and-label v1');
  assert.deepEqual([alone.groupId, alone.defaultMode, alone.mode, alone.audience], ['fixture.labels.write', 'allow', 'allow', undefined]);
  assert.deepEqual([both.groupId, both.defaultMode, both.mode, both.requiresApproval, both.audience], ['fixture.labels.write', 'ask', 'ask', true, true]);
  assert.deepEqual(both.rows, ['Manage labels', 'Send messages and change shared files', 'Access items'], 'own row first, then every other step row');
});

/** Add a label, read back from the key list: its verify step sits in fixture.keys.read, a read row whose default is Ask. */
const labelCheckedByKeys = () => action('label-checked-by-keys', {effect: 'write', row: 'fixture.labels.write', hints: WRITE_HINTS, inputSchema: closed({name: words()}),
  outputSchema: closed({id: {type: 'string', maxLength: 64}}), perform: [LABEL],
  verify: {requests: [{id: 'check', method: 'GET', path: '/keys', expect: OK}],
    identity: [{kind: 'membership', step: 'check', listHas: {list: '/keys', where: [{field: '/name', equals: {step: 'label', pointer: '/name'}}]}}], assert: []},
  output: {id: {step: 'label', pointer: '/id'}}, preview: [{label: 'Label', expr: {input: '/name'}}]});

test('part e: own default over every step row, the verify row included: a readback in fixture.keys.read (default Ask) makes the own default Ask', t => {
  const h = actionHarness(t, {file: withActions(createLabel, labelCheckedByKeys)});
  const alone = decide(h, 'create-label v1'), checked = decide(h, 'label-checked-by-keys v1');
  assert.deepEqual([alone.defaultMode, alone.mode], ['allow', 'allow']);
  assert.deepEqual(checked.steps.map(step => [step.stepId, step.phase, step.groupId, step.mode]), [['label', 'perform', 'fixture.labels.write', 'allow'], ['check', 'verify', 'fixture.keys.read', 'allow']],
    'a row that follows its default adds nothing as a contribution');
  assert.deepEqual([checked.groupId, checked.defaultMode, checked.performMode, checked.mode, checked.requiresApproval], ['fixture.labels.write', 'ask', 'ask', 'ask', true]);
});

test('part e: access answers unavailable when a non-optional step\'s member is unavailable, a lookup step included', t => {
  const h = actionHarness(t);
  const lookup = fixtureGroups(rows => ({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.read' ? {...group, unavailable: {...group.unavailable, 'GET /labels/{label_id}': 'no-oauth-scope'}} : group)}));
  const {permissions, decide: marked} = manager(h, {groups: lookup});
  const list = marked('list-items v1');
  assert.deepEqual([list.providerAccess, list.unavailable, list.executable, list.reason], ['unavailable', 'no-oauth-scope', false, UNAVAILABLE_REASONS['no-oauth-scope']]);
  assert.equal(list.steps.find(step => step.stepId === 'choice:labelId').providerAccess, 'unavailable');
  assert.equal(permissions.unavailableOf(h.capability('list-items v1')), 'no-oauth-scope');
  assert.equal(marked('update-item v1').providerAccess, 'unknown', 'an action that reads no unavailable member');
  // runPlan() itself: an unavailable step that runs makes the action unavailable; an optional one is skipped like a missing one.
  const entry = h.catalog.entries.get(h.capability('list-items v1').id).entry, allow = () => 'allow';
  assert.equal(h.catalog.runPlan(entry, {accessOf: placement => placement.phase === 'lookup' ? 'unavailable' : 'missing', modeOf: allow}).access, 'unavailable');
  assert.equal(h.catalog.runPlan(entry, {accessOf: placement => placement.phase === 'lookup' ? 'unavailable' : 'granted', modeOf: allow}).access, 'unavailable', 'a choice lookup counts');
  assert.equal(permissions.unavailableOf(h.capability('update-item v1')), null);
});

test('part e: changing a proxy row or typed record and changing it back moves the policy hash (it reads every revision)', t => {
  const typed = typedCaps(), h = actionHarness(t);
  h.store.put('capabilities', typed.updateItem);
  h.permissions.set({connectionId: h.account, capabilityId: h.capability('update-item v1').id, mode: 'allow'});
  const first = decide(h, 'update-item v1');
  setRow(h, 'fixture.items.read', 'deny'); setRow(h, 'fixture.items.read', 'allow');
  const row = decide(h, 'update-item v1');
  assert.deepEqual([row.mode, row.bindingHash], [first.mode, first.bindingHash]);
  assert.notEqual(row.policyHash, first.policyHash, 'a proxy row changed and changed back');
  h.permissions.set({connectionId: h.account, capabilityId: typed.updateItem.id, mode: 'deny'}); h.permissions.set({connectionId: h.account, capabilityId: typed.updateItem.id, mode: 'ask'});
  const back = decide(h, 'update-item v1');
  assert.equal(back.mode, first.mode);
  assert.notEqual(back.policyHash, row.policyHash, 'a typed record changed and changed back');
  // Every ceiling it read is in the hash too, even one that changes no mode: here the perform steps already ask through the typed record.
  let ceiling = null;
  const {decide: ceiled} = manager(h, {ceilingOf: (appId, groupId) => groupId === 'fixture.items.edit' ? ceiling : null});
  const open = ceiled('update-item v1');
  ceiling = 'ask';
  const capped = ceiled('update-item v1'), modes = decision => [decision.mode, decision.prepareMode, decision.performMode, ...decision.steps.map(step => step.mode)];
  assert.deepEqual(modes(capped), modes(open));
  assert.notEqual(capped.policyHash, open.policyHash);
});
test('part h: a job prepared before a proxy row or typed record changed and changed back refuses at dispatch', async t => {
  for (const change of ['row', 'typed']) {
    const typed = typedCaps(), h = actionHarness(t);
    h.store.put('capabilities', typed.updateItem);
    for (const item of h.simulator.data.items) item.status = 'open';
    // Fabric did not make I1, so the job stops for its final bytes; the setting changes and changes back while it waits.
    const job = await h.runtime.createJob({connectionId: h.account, capabilityId: h.idOf('update-item v1'), args: {itemId: 'I1', change: 'label', labels: ['Work']}}, null);
    assert.deepEqual([job.status, job.action.phase], ['awaiting_approval', 'final'], change);
    if (change === 'row') { setRow(h, 'fixture.items.read', 'deny'); setRow(h, 'fixture.items.read', 'allow'); }
    else { h.permissions.set({connectionId: h.account, capabilityId: typed.updateItem.id, mode: 'deny'}); h.permissions.set({connectionId: h.account, capabilityId: typed.updateItem.id, mode: 'ask'}); }
    assert.equal(decide(h, 'update-item v1').mode, 'ask', 'the mode is as it was');
    const done = await h.runtime.approve(job.id, job.approvalDigest, null);
    assert.deepEqual([done.status, done.errorCode, done.error, h.simulator.writes().length], ['failed', 'authority_changed', 'Connection authorization or permission setting changed. Create a new request.', 0], change);
  }
});

// ---- part f: c7, locks and routes from placements --------------------------------------------------------------------------------------
test('part f: critique test 8: after an uncertain action write the same action under Allow asks with duplicate_of_uncertain, a proxy request into that row asks too, and after 24 hours neither does', t => {
  const h = actionHarness(t, {file: withActions(createLabel), designated: true}), label = h.capability('create-label v1');
  const at = () => new Date(h.now).toISOString();
  setRow(h, 'fixture.labels.write', 'allow');
  const rows = () => uncertainRows(h.store, h.account, h.now);
  const allowed = decide(h, 'create-label v1', {uncertainRows: rows()});
  assert.deepEqual([allowed.mode, allowed.duplicateOfUncertain], ['allow', undefined]);
  // An uncertain action write, as part i stores one: its write rows are recorded on the job. Typed jobs stay out of c7.
  h.store.put('jobs', {id: 'typed-1', connectionId: h.account, capabilityId: 'fixture.typed', effect: 'write', status: 'uncertain', updatedAt: at()});
  assert.deepEqual([...rows()], []);
  h.store.put('jobs', {id: 'action-1', kind: 'action', connectionId: h.account, capabilityId: label.id, effect: 'write', status: 'uncertain', updatedAt: at(), action: {writeRows: ['group:fixture.labels.write']}});
  assert.deepEqual([...rows()], ['group:fixture.labels.write']);
  const asked = decide(h, 'create-label v1', {uncertainRows: rows()});
  assert.deepEqual([asked.mode, asked.performMode, asked.duplicateOfUncertain, asked.requiresApproval], ['ask', 'ask', true, true]);
  assert.equal(asked.policyHash, allowed.policyHash, 'c7 is decided at acceptance and stays out of the policy hash');
  // c7 asks again only before a write: a read action whose rows have an uncertain write still runs.
  assert.equal(decide(h, 'list-items v1', {uncertainRows: new Set(['group:fixture.items.read', 'group:fixture.labels.write'])}).mode, 'allow');
  // The proxy counts the action's write: a request into that row asks, with the same warning.
  assert.equal(unresolvedUncertain(h.store, h.account, 'group:fixture.labels.write', h.now), true);
  const proxied = prepareProxyJob(h.runtime, {connectionId: h.account, request: {method: 'POST', path: '/labels', body: {name: 'x'}}}, h.owner);
  assert.equal(proxied.status, 'awaiting_approval');
  assert.ok(proxied.proxy.clamps.includes('c7_unresolved_uncertain') && proxied.preview.warnings.includes('duplicate_of_uncertain'));
  // And each counts the other: an uncertain proxy write into the row makes the action ask.
  h.store.delete('jobs', 'action-1');
  h.store.put('jobs', {...proxied, status: 'uncertain', updatedAt: at()});
  assert.equal(decide(h, 'create-label v1', {uncertainRows: rows()}).mode, 'ask');
  // After 24 hours neither does.
  h.store.put('jobs', {id: 'action-1', kind: 'action', connectionId: h.account, capabilityId: label.id, effect: 'write', status: 'uncertain', updatedAt: at(), action: {writeRows: ['group:fixture.labels.write']}});
  h.advance(24 * 60 * 60 * 1000);
  assert.deepEqual([...rows()], []);
  assert.equal(decide(h, 'create-label v1', {uncertainRows: rows()}).mode, 'allow');
  const later = prepareProxyJob(h.runtime, {connectionId: h.account, request: {method: 'POST', path: '/labels', body: {name: 'y'}}}, h.owner);
  assert.deepEqual([later.status, later.proxy.duplicateOfUncertain], ['queued', false]);
});

test('part f: a step meeting a locked template is locked; row locks and routes answer from placements with an explicit catalog, and null without one', t => {
  // A locked literal sibling of PATCH /items/{item_id}: Update an item's steps place on their own member, and still meet the lock.
  const rows = rows => ({...rows, groups: rows.groups.map(group => group.id === 'fixture.access.grant' ? {...group, requests: [...group.requests, 'PATCH /items/special']} : group)});
  const h = actionHarness(t, {rows}), update = h.capability('update-item v1'), list = h.capability('list-items v1'), map = fixtureMap();
  assert.equal(h.catalog.entries.get(update.id).status, 'active', 'the steps place on fixture.items.edit, as before');
  const locked = decide(h, 'update-item v1');
  assert.deepEqual([locked.mode, locked.locked, locked.executable, locked.defaultMode, locked.reason], ['deny', true, false, 'deny', LOCK_WORDS]);
  assert.equal(h.permissions.lockOf(update), 'fabric');
  assert.deepEqual([decide(h, 'list-items v1').locked, h.permissions.lockOf(list)], [undefined, null]);
  assert.throws(() => h.permissions.set({connectionId: h.account, capabilityId: update.id, mode: 'allow'}), error => error.code === 'mode_not_allowed' && error.locked === true);
  assert.equal(lockedRowOf(h.groups, h.configs, update, null, map, h.catalog)?.id, 'fixture.access.grant');
  assert.equal(lockedRowOf(h.groups, h.configs, update, null, map), null, 'no catalog, no answer: the action is already unsupported');
  // An Allow saved before the lock decides Never, with the lock words, and its binding does not move: the lock is a clamp.
  const before = actionHarness(t);
  before.permissions.set({connectionId: before.account, capabilityId: before.capability('update-item v1').id, mode: 'allow'});
  const was = decide(before, 'update-item v1'), lockedGroups = fixtureGroups(rows);
  const now = manager(before, {groups: lockedGroups, catalog: catalogWith(before, lockedGroups)}).decide('update-item v1');
  assert.deepEqual([was.mode, now.mode, now.locked, now.policySource, now.bindingHash === was.bindingHash, now.reason], ['allow', 'deny', true, 'saved', true, LOCK_WORDS]);
  // A step whose own template cannot be read meets every locked row (fail closed); actionSteps() says so with a null request.
  const lookup = {placements: [{stepId: 'choice:x', phase: 'lookup', member: 'GET /labels/{label_id}', groupId: 'fixture.items.read', routedFrom: null}], lookups: {x: {template: null, operation: 'fixture.labels.get'}},
    action: {prepare: [], perform: [], key: 'odd'}, effect: 'read'};
  const odd = {entryOf: capability => capability.id === 'fixture.action.odd.v1.000000000000000000000000' ? {entry: lookup} : null};
  assert.equal(actionSteps(lookup, map)[0].request, null);
  assert.equal(lockedRowOf(h.groups, h.configs, {id: 'fixture.action.odd.v1.000000000000000000000000', appId: 'fixture', driver: 'action'}, null, map, odd)?.id, 'fixture.access.grant');
  // Routes: an action's routes are its steps' routes, so its binding carries them; its row member is its last perform step's.
  const plain = actionHarness(t), edit = plain.capability('update-item v1');
  assert.deepEqual(memberRoutes(plain.groups, plain.configs, edit, null, map, plain.catalog), [
    'fixture.items.edit|PATCH /items/{item_id}|/in_trash|present|true|fixture.items.delete',
    'fixture.items.edit|PATCH /items/{item_id}|/labels|contains|"TRASH"|fixture.items.delete',
    'fixture.items.edit|PATCH /items/{item_id}|/share/to|present|true|fixture.access.grant']);
  assert.deepEqual(memberRoutes(plain.groups, plain.configs, edit, null, map), []);
  // A step member that gains a route needs fresh consent: the routes are in the action's binding.
  plain.permissions.set({connectionId: plain.account, capabilityId: edit.id, mode: 'allow'});
  const routed = fixtureGroups(rows => ({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.edit' ? {...group, bodyRoutes: [...group.bodyRoutes,
    {member: 'PATCH /items/{item_id}', pointer: '/archived', present: true, to: 'fixture.items.delete'}]} : group)}));
  const rerouted = manager(plain, {groups: routed, catalog: catalogWith(plain, routed)}).decide('update-item v1');
  assert.deepEqual([decide(plain, 'update-item v1').policySource, rerouted.stale, rerouted.mode], ['saved', true, 'ask']);
  const member = rowMemberOf(plain.groups, plain.configs, edit, null, map, plain.catalog);
  assert.deepEqual([member?.group.id, member?.member], ['fixture.items.edit', 'PATCH /items/{item_id}']);
  assert.equal(rowMemberOf(plain.groups, plain.configs, edit, null, map), null);
  assert.deepEqual([plain.permissions.lockOf(edit), plain.permissions.unavailableOf(edit), plain.permissions.routedBody(edit, {name: 'x'})], [null, null, null]);
});

test('part e: the runtime wires the catalog and the proxy into its permission manager, and a developer bundle passes the same catalog', t => {
  const h = actionHarness(t);
  assert.equal(h.permissions.actions, h.catalog);
  assert.equal(h.permissions.proxy, h.proxyPolicy);
  const bare = new Runtime({store: h.store, permissions: new PermissionManager({store: h.store})});
  assert.deepEqual([bare.permissions.actions, bare.permissions.proxy === bare.proxyPolicy], [null, true]);
  // A developer environment's bundle: every environment's runtime and permission manager read the one catalog given at start.
  const env = {scope: {kind: 'tenant', environmentId: 'env_actions'}, repository: h.store, vault: {}};
  const runtimes = new EnvironmentRuntimes({stores: {open: () => env}, registry: {now: () => new Date(h.now).toISOString(), get: () => null}, providerApps: {credentials: () => null},
    origin: 'https://fabric.example.com', actions: h.catalog});
  const bundle = runtimes.bundle(env.scope);
  assert.deepEqual([bundle.runtime.actions === h.catalog, bundle.permissions.actions === h.catalog, bundle.permissions.proxy === bundle.runtime.proxyPolicy], [true, true, true]);
  const none = new EnvironmentRuntimes({stores: {open: () => ({...env, scope: {kind: 'tenant', environmentId: 'env_none'}})}, registry: {now: () => new Date(h.now).toISOString(), get: () => null},
    providerApps: {credentials: () => null}, origin: 'https://fabric.example.com'});
  assert.equal(none.bundle({kind: 'tenant', environmentId: 'env_none'}).permissions.actions, null);
});

// ---- the resolving write: resolveMode -------------------------------------------------------------------------------------------------
const SLACK_OK = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]};
/** Slack Send a direct message: find the person, open the direct message (the resolving write), post to it. */
const directMessage = () => ({schemaVersion: 1, appId: 'slack', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: [{
  id: `slack.action.send-dm.v1.${'0'.repeat(24)}`, key: 'send-dm', version: 1, name: 'Send a direct message', description: 'Sends one direct message to a person found by email.',
  effect: 'write', row: 'slack.messages.send', hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true},
  inputSchema: closed({email: {type: 'string', minLength: 3, maxLength: 254}, text: words(4000)}),
  outputSchema: closed({channel: {type: 'string', maxLength: 64}, ts: {type: 'string', maxLength: 64}}), guards: [],
  prepare: [{id: 'person', method: 'GET', path: '/users.lookupByEmail', query: {email: {input: '/email'}}, expect: SLACK_OK}],
  perform: [
    {id: 'open', method: 'POST', path: '/conversations.open', body: {object: {users: {step: 'person', pointer: '/user/id'}}}, resolves: true,
      expect: {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}, {present: {pointer: '/channel/id'}}]}},
    {id: 'post', method: 'POST', path: '/chat.postMessage', body: {object: {channel: {step: 'open', pointer: '/channel/id'},
      text: {pick: {transform: 'text.slackEscape@1', args: {text: {input: '/text'}}}, pointer: '/text'}}}, expect: SLACK_OK}],
  verify: {requests: [{id: 'link', method: 'GET', path: '/chat.getPermalink', query: {channel: {step: 'post', pointer: '/channel'}, message_ts: {step: 'post', pointer: '/ts'}}, expect: SLACK_OK}],
    identity: [{kind: 'readback', step: 'link', pointer: '/channel', equals: {step: 'post', pointer: '/channel'}}], assert: []},
  output: {channel: {step: 'post', pointer: '/channel'}, ts: {step: 'post', pointer: '/ts'}},
  preview: [{label: 'To', expr: {step: 'person', pointer: '/user/real_name'}}, {label: 'Message', expr: {input: '/text'}}], definitive: [400],
  certified: {evidence: 'docs/live-evidence/slack/actions.json', definitionHash: '0'.repeat(64)}}]});
/** The shipped Slack rows with the Send a direct message action active, on one ready Slack account. */
function slack(t, {ceilingOf = null} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-action-slack-')), store = new Store({dataDir: path.join(root, 'data')});
  t.after(() => { store.close(); rmSync(root, {recursive: true, force: true}); });
  const deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, transforms: TRANSFORMS, pins: PINS, choices: new Map(), identities: new Map([['slack', definitionFor('slack')]])};
  const file = withIds(directMessage(), {...deps, maps: new Map()}), directory = path.join(root, 'catalog', 'actions');
  for (const dir of [directory, path.join(root, 'docs', 'live-evidence', 'slack')]) mkdirSync(dir, {recursive: true});
  writeFileSync(path.join(directory, 'slack.json'), JSON.stringify(file));
  const [{id, definitionHash}] = file.actions;
  writeFileSync(path.join(root, 'docs', 'live-evidence', 'slack', 'actions.json'), JSON.stringify({[id]: {passed: true, transforms: {'text.slackEscape@1': PINS['text.slackEscape@1']}, definitionHash}}));
  const catalog = loadActionCatalog({directory, evidenceRoot: root, deps, codeHashes: ids => Object.fromEntries(ids.map(name => [name, PINS[name]]))});
  const capability = catalog.entries.get(id).capability;
  store.put('capabilities', capability);
  store.put('connections', {id: 'slack-account', appId: 'slack', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'Slack', identity: {id: 'T1:U1'}, allowedOrigins: ['https://slack.com'], createdAt: '2026-10-23T09:00:00.000Z'});
  const permissions = new PermissionManager({store, ceilingOf}), proxyPolicy = new ProxyPolicy({store, permissions});
  new Runtime({store, permissions, proxyPolicy, actions: catalog});
  return {store, permissions, proxyPolicy, capability, decide: options => permissions.decision(store.get('connections', 'slack-account'), capability, undefined, options),
    setRow: (groupId, mode) => proxyPolicy.set({connectionId: 'slack-account', row: `group:${groupId}`, mode, confirmAllow: true})};
}

test('part e: resolveMode, for a two-phase action, is the strictest of the resolving step, c7 on its row and the own mode', t => {
  const ceilings = {}, s = slack(t, {ceilingOf: (appId, groupId) => appId === 'slack' ? ceilings[groupId] ?? null : null});
  assert.equal(s.capability.status, 'active');
  s.permissions.set({connectionId: 'slack-account', capabilityId: s.capability.id, mode: 'allow'});
  const allowed = s.decide();
  assert.deepEqual([allowed.status, allowed.prepareMode, allowed.resolveMode, allowed.performMode, allowed.mode], ['active', 'allow', 'allow', 'allow', 'allow']);
  assert.deepEqual(allowed.steps.map(step => [step.stepId, step.phase, step.groupId]), [['person', 'prepare', 'slack.workspace.read'], ['open', 'perform', 'slack.conversations.mark'],
    ['post', 'perform', 'slack.messages.send'], ['link', 'verify', 'slack.messages.read']]);
  // The conversations.open row capped at Ask gates the resolving write, and nothing else.
  ceilings['slack.conversations.mark'] = 'ask';
  const gated = s.decide();
  assert.deepEqual([gated.prepareMode, gated.resolveMode, gated.performMode, gated.mode], ['allow', 'ask', 'allow', 'ask']);
  delete ceilings['slack.conversations.mark'];
  // Its proxy row at Never refuses the action.
  s.setRow('slack.conversations.mark', 'deny');
  assert.deepEqual([s.decide().resolveMode, s.decide().mode, s.decide().executable], ['deny', 'deny', false]);
  s.setRow('slack.conversations.mark', 'ask');
  assert.equal(s.decide().resolveMode, 'allow', 'Ask is that write row\'s proxy default, which adds nothing');
  // c7 on the resolving step's row asks before the resolving write, and only there.
  const c7 = s.decide({uncertainRows: new Set(['group:slack.conversations.mark'])});
  assert.deepEqual([c7.resolveMode, c7.performMode, c7.duplicateOfUncertain], ['ask', 'allow', true]);
  // The own mode at Ask asks before it too.
  s.permissions.set({connectionId: 'slack-account', capabilityId: s.capability.id, mode: 'ask'});
  assert.deepEqual([s.decide().prepareMode, s.decide().resolveMode, s.decide().performMode], ['allow', 'ask', 'ask']);
  // A one-phase action has no resolveMode.
  const h = actionHarness(t);
  assert.equal(decide(h, 'update-item v1').resolveMode, null);
});

test('parts e and f: typed and proxy-row bindings do not move', t => {
  // Recorded at f79e92c, before part e: a typed decision's binding and policy hash, each proxy row's binding and mode, and three proxy
  // decisions, on the run harness's account with the actions seeded and three typed operations stored.
  const h = actionHarness(t), typed = typedCaps();
  for (const name of ['updateItem', 'getProfile', 'getLabelApiKey']) h.store.put('capabilities', typed[name]);
  const connection = h.store.get('connections', h.account);
  const now = Object.fromEntries(['updateItem', 'getProfile', 'getLabelApiKey'].map(name => { const decision = h.permissions.decision(connection, typed[name]); return [name, [decision.bindingHash, decision.policyHash, decision.mode]]; }));
  assert.deepEqual(now, {
    updateItem: ['b815183186a4616714db7307502303fad56d4c5b82ade52d786ff1d1a4e09109', 'c0d49b20ac0a02cb860195e47733a37aef02f5fd2d10d0153ebf4be40ca75b43', 'ask'],
    getProfile: ['8f349c92f0f9b7c1575b0f6caf08f297e1e056aff06be5012a2aa6dc84a35293', '4ffa6df2c14326e0686901478a86b99c117e3014c2e74b7db7aa59f93afb8cd0', 'allow'],
    getLabelApiKey: ['f84ecf603a303b9b823e411cb58937ed3cb014dcc5843b636b3346883fa7b707', '188c2c54790b54fd0e8f40a38b9068fb777fb5adcdda10f8bd4e4f4d8d4d61a4', 'ask']});
  const context = h.proxyPolicy.route(h.account);
  assert.deepEqual(Object.fromEntries(h.proxyPolicy.rows(context).map(entry => [entry.row, [h.proxyPolicy.binding(context, entry.row), h.proxyPolicy.base(context, entry).mode]])), {
    'group:fixture.items.read': ['ad70d37ae24ac26ad0e691b6766e7af7b7ea16c35c4e657de6b8833a03221769', 'allow'],
    'group:fixture.keys.read': ['bc0b1ef4e6678bdd8fa88f6f02abe170dd05d55e71464752190b67e3ba3310d5', 'ask'],
    'group:fixture.labels.write': ['e722ce36ac5aaa499b153fb10f87674b1a93884619129b8f5a98650dcd7db7d6', 'ask'],
    'group:fixture.items.edit': ['b6ff35c901a9b0ea860c4b11fb98fdd7fe3fe04ebedb984d8b31b4b8561d21af', 'ask'],
    'group:fixture.messages.send': ['a86ad49ceafea50d7de652a0ef31d36ce4865d3704675214bcd2dc5b04338782', 'ask'],
    'group:fixture.items.delete': ['34859535eb7cd7eac49cb2fa471f68bc0709afc828b4e00eea698a569343e265', 'ask'],
    'group:fixture.access.grant': ['09f77a06b8d691183c886e2990a8196de7387b3134662cdab4115d80bcaff060', 'deny'],
    'other-reads': ['b09bcd4cf940343df14c8b63540c52dfa8395e7cea31f9ff2141ddf5c3f11fd9', 'ask'],
    'other-changes': ['6bb30ba68ab90e7b073b7a53c48285006face74b86c6d1ecbc6bd8081163a69d', 'ask'],
    'other-deletes': ['a669eeb24e070954680235e3456682a93f65ed1e9cb241f555d15ca0b9250a5a', 'deny'],
    graphql: ['3851c2e57eb329ca35000631b082a84e24a82f9076e1e14b8cc64ff1ca8308e3', 'deny']});
  const proxied = [{method: 'PATCH', path: '/items/abc', body: {name: 'x'}}, {method: 'GET', path: '/labels'}, {method: 'POST', path: '/labels', body: {name: 'x'}}]
    .map(request => { const decision = h.proxyPolicy.decide(h.account, request); return [decision.policyHash, decision.mode]; });
  assert.deepEqual(proxied, [['12d654c69e789d8f94c499b8b0f44469a3fe8318a5574bd5345d6e434f69792b', 'ask'], ['c8c45506d75611d3ad8b695793ee42463acbafa32a6f4ac38c6d3a761da3cb81', 'allow'],
    ['e49def241634bc271cb7c9845c239c6267683e6a0066d25fe0fe4a2d97825d1c', 'ask']]);
  // An action's definition hash is its capability's, so the grant hash an agent binds is the file's.
  assert.equal(capabilityPermissionHash(h.capability('list-items v1')), h.catalog.entries.get(h.capability('list-items v1').id).entry.definitionHash);
});

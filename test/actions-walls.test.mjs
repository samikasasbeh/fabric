import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {AcquisitionEngine} from '../lib/acquisition.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {Store} from '../lib/store.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {HeartbeatScheduler} from '../lib/heartbeat.mjs';
import {AppDetailService} from '../lib/app-detail.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {actionCapability, validateActionFile} from '../lib/actions.mjs';
import {promoteInPlatform} from '../scripts/tenant-admin.mjs';
import {createApp} from '../server.mjs';
import {freePort} from './fixtures/signin-fixture.mjs';
import {fixtureActions, fixtureGroups, fixtureConfigs, fixtureMap, fixtureChoices, fixtureSignIn} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';

// F10.11 parts c and d (docs/F10.11-BUILD-MAP.md parts c and d, section 3): the walls. Nothing but a reviewed action file with live
// evidence makes an action active: no promotion path, no heartbeat and no generated or imported record can promote, schedule or take an
// action, and no checked output names a field MCP would silently redact.
function engine(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-walls-')), store = new Store({dataDir: dir});
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  return {store, engine: new AcquisitionEngine({store, catalog: () => [{id: 'fixture', apiOrigins: ['https://api.example.com']}], modelUrl: null, modelKey: null, modelName: null,
    request: async () => { throw new Error('no network in this test'); }})};
}

test('part c: saveCandidates() refuses an id in the <appId>.action. namespace before saving anything; compiled ids are untouched', t => {
  const {store, engine: acquisition} = engine(t);
  const document = name => ({openapi: '3.1.0', info: {title: 'Fixture', version: '1'}, servers: [{url: 'https://api.example.com'}],
    paths: {'/items': {get: {operationId: name, responses: {200: {description: 'Items'}}}}}});
  // An operation named "action" compiles to <appId>.action.<hash>, three dot parts, which no reviewed action id has: it is kept.
  const [compiled] = compileOpenApi({appId: 'fixture', document: document('action')}).capabilities;
  assert.match(compiled.id, /^fixture\.action\.[a-f0-9]{24}$/);
  assert.equal(acquisition.saveCandidates('fixture', [compiled])[0].id, compiled.id);
  // validateCapability() holds an id to <appId>. and the content's hash at its end, and nothing between: an id shaped like an action's
  // passes it, so saveCandidates() refuses the namespace itself.
  const [other] = compileOpenApi({appId: 'fixture', document: document('other')}).capabilities, digest = other.id.slice(-24);
  for (const id of [`fixture.action.list-items.v1.${digest}`, `fixture.action.x.${digest}`]) {
    assert.throws(() => acquisition.saveCandidates('fixture', [other, {...other, id}]), /belongs to a reviewed action file: generated and imported operations never take an action id/, id);
    assert.equal(store.get('capabilities', other.id), null, `${id}: the whole batch is refused before anything is saved`);
  }
});

// ---- part d: the walls --------------------------------------------------------------------------------------------------------------------
const ROW_WORDS = 'Set this action with its permission row.';
const PROMOTE_WORDS = 'Actions become active only from a reviewed file with live evidence.';
const HEARTBEAT_WORDS = 'Actions run only when asked. Watching for changes comes with triggers.';
/** The fixture's List items action as the capability it becomes (a read action), with `status`. */
const listItems = (status = 'candidate') => ({...actionCapability(fixtureActions(), fixtureActions().actions[0]), status});
/** A compiled http candidate of the fixture app, for the control cases. */
const compiled = () => compileOpenApi({appId: 'fixture', document: {openapi: '3.1.0', info: {title: 'Fixture', version: '1'}, servers: [{url: 'https://api.example.com'}],
  paths: {'/items': {get: {operationId: 'listItems', responses: {200: {description: 'Items'}}}}}}}).capabilities[0];
function plainStore(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-walls-')), store = new Store({dataDir: dir});
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  store.put('connections', {id: 'acct', appId: 'fixture', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'Fixture', identity: {id: 'u'}, allowedOrigins: ['https://api.example.com'], createdAt: '2026-10-23T09:00:00.000Z'});
  return store;
}

test('part d: critique test 5: setRow() never promotes a candidate action, even on Allow with review, while an http candidate of the same row still is', t => {
  const store = plainStore(t), action = listItems(), http = compiled(), sets = [];
  for (const capability of [action, http]) store.put('capabilities', capability);
  // Actions join rows only from part k, so the row is given as part k will build it: both members, with the review the row asks for.
  // Part k checks every action of the row against the catalog first, so the stub's catalog holds this one's reviewed definition.
  const service = new AppDetailService({store, runtime: {permissions: {set: record => sets.push(record), actions: {entryOf: capability => capability.id === action.id ? {entry: {unplaced: false}} : null}}, proxyPolicy: null},
    catalog: () => [{id: 'fixture', name: 'Fixture'}]});
  const decision = {effect: 'read', defaultMode: 'allow', sensitivity: null};
  service.rows = () => [{id: 'fixture.items.read', label: 'Access items', effect: 'read', sensitive: null, members: [{capability: action, decision}, {capability: http, decision}],
    view: {etag: 'row-etag', allowedModes: ['allow', 'ask', 'deny'], reviewRequired: true}}];
  service.view = () => 'the page';
  assert.equal(service.setRow('fixture', 'acct', {groupId: 'fixture.items.read', mode: 'allow', etag: 'row-etag', review: true, confirmAllow: true}), 'the page');
  assert.deepEqual(sets.map(record => [record.capabilityId, record.mode]), [[action.id, 'allow'], [http.id, 'allow']], 'both members get the row\'s record');
  assert.equal(store.get('capabilities', action.id).status, 'candidate', 'the action stays a candidate');
  assert.equal(store.get('capabilities', http.id).status, 'active', 'the control: a reviewed http member is promoted as before');
  assert.deepEqual(store.list('activity').filter(row => row.type === 'capability.promoted').map(row => row.capabilityId), [http.id]);
});

test('part d: the per-capability permission route refuses an action with the row words, and /promote refuses it before changing anything', async t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-walls-app-')), port = await freePort();
  const app = await createApp({dataDir: dir, port, request: async () => { throw new Error('no network in this test'); }});
  await app.start();
  t.after(async () => { await app.close(); rmSync(dir, {recursive: true, force: true}); });
  const boot = await fetch(`${app.origin}/api/state`), cookie = boot.headers.get('set-cookie').split(';')[0], {csrfToken} = await boot.json();
  const post = async (route, data) => { const response = await fetch(`${app.origin}${route}`, {method: 'POST', headers: {'Content-Type': 'application/json', Cookie: cookie, 'X-Fabric-CSRF': csrfToken}, body: JSON.stringify(data)}); return [response.status, await response.json()]; };
  const action = listItems();
  app.store.put('capabilities', action);
  app.store.put('connections', {id: 'acct', appId: 'fixture', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', label: 'Fixture', identity: {id: 'u'}, allowedOrigins: ['https://api.example.com'], createdAt: '2026-10-23T09:00:00.000Z'});
  for (const mode of ['allow', 'ask', 'deny']) {
    const [status, body] = await post('/api/connections/acct/permissions', {capabilityId: action.id, mode, review: true});
    assert.deepEqual([status, body.error], [400, ROW_WORDS], mode);
  }
  assert.deepEqual([app.store.list('permissions').length, app.store.get('capabilities', action.id).status], [0, 'candidate'], 'no record, no promotion');
  const [status, body] = await post(`/api/capabilities/${encodeURIComponent(action.id)}/promote`, {});
  assert.deepEqual([status, body.error], [400, PROMOTE_WORDS]);
  assert.deepEqual(app.store.get('capabilities', action.id), action, 'nothing changed');
  assert.equal(app.store.list('activity').some(row => row.type === 'capability.promoted'), false);
});

test('part d: critique test 5: promoteInPlatform() refuses an action before changing anything, whatever else the list names', t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-action-walls-platform-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const action = listItems(), http = compiled(), platform = new PlatformStore({root});
  platform.put('capabilities', action);
  platform.put('capabilities', http);
  platform.close();
  assert.throws(() => promoteInPlatform({root, appId: 'fixture', capabilityIds: [http.id, action.id]}), new RegExp(`^Error: ${action.id.replace(/\./g, '\\.')}: ${PROMOTE_WORDS.replace(/\./g, '\\.')}$`));
  const after = new PlatformStore({root});
  try { assert.deepEqual([after.get('capabilities', http.id).status, after.get('capabilities', action.id).status], ['candidate', 'candidate']); } finally { after.close(); }
  assert.deepEqual(promoteInPlatform({root, appId: 'fixture', capabilityIds: [http.id]}), [http.id], 'the control: the http candidate alone is promoted');
});

test('part d: a heartbeat on a read action is refused at create and at tick, before effectOf()', async t => {
  const store = plainStore(t), action = listItems('active');
  store.put('capabilities', action);
  let jobs = 0;
  const runtime = new Runtime({store, connections: {credentials: async () => { throw new Error('no credentials in this test'); }}, request: async () => { throw new Error('no network in this test'); }});
  runtime.createJob = async () => { jobs++; throw new Error('no job may start'); };
  const scheduler = new HeartbeatScheduler({store, runtime, checkConnection: async () => { throw new Error('no check'); }, clock: () => Date.parse('2026-10-23T10:00:00.000Z')});
  assert.throws(() => scheduler.create({name: 'Watch items', intervalSeconds: 60, connectionId: 'acct', capabilityId: action.id, args: {}}), new RegExp(`^Error: ${HEARTBEAT_WORDS.replace(/\./g, '\\.')}$`));
  assert.equal(store.list('heartbeats').length, 0);
  // A heartbeat stored before the wall (or written by hand) is refused at its tick, and no job starts.
  store.put('heartbeats', {id: 'hb-1', name: 'Watch items', intervalSeconds: 60, connectionId: 'acct', capabilityId: action.id, permissionBindingHash: 'x', args: {}, enabled: true,
    nextRunAt: '2026-10-23T09:59:00.000Z', lastRunAt: null, lastResult: null, runs: 0, createdAt: '2026-10-23T09:00:00.000Z'});
  await scheduler.tick();
  assert.deepEqual(store.get('heartbeats', 'hb-1').lastResult, {status: 'failed', error: HEARTBEAT_WORDS});
  assert.equal(jobs, 0);
});

test('part d: the validator refuses an action output named preview, tokenHash or approvalDigest, in any case and at any depth, which MCP would silently redact', () => {
  const groups = fixtureGroups(), deps = {groups, configs: fixtureConfigs(groups), maps: new Map([['fixture', fixtureMap()]]), transforms: TRANSFORMS, pins: PINS,
    choices: new Map([['fixture', fixtureChoices().sources]]), identities: new Map([['fixture', fixtureSignIn()]])};
  assert.doesNotThrow(() => validateActionFile(fixtureActions(), deps), 'no fixture output uses these names, so no fixture id moves');
  for (const [name, nested] of [['preview', false], ['tokenHash', false], ['approvalDigest', false], ['Preview', false], ['TOKENHASH', true], ['approvaldigest', true]]) {
    const file = fixtureActions(), action = file.actions[0], field = {type: 'string', maxLength: 64};
    if (nested) action.outputSchema.properties.items.items.properties[name] = field;
    else { action.outputSchema.properties[name] = field; action.outputSchema.required = [...(action.outputSchema.required ?? [])]; action.output[name] = {const: 'x'}; }
    const where = nested ? `$output.items[].${name}` : `$output.${name}`;
    assert.throws(() => validateActionFile(file, deps), new RegExp(`list-items v1: outputSchema declares ${where.replace(/[.$[\]]/g, '\\$&')}, a field name MCP removes from every result, so an agent would never see it`), name);
  }
});

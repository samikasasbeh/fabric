import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {Store} from '../lib/store.mjs';
import {appEntry, checkSigned, dataHash, readGolden, REVIEW_PATH, ROOT} from '../scripts/defaults-golden.mjs';
import {actionIds, validateActionFile} from '../lib/actions.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// F10.13 (docs/F10.13-BUILD-MAP.md sections 3 and 6, test/f10-13-churn.test.mjs): what step 13 must not move. Part 1 adds one field to one
// row: "Create, edit and invite people to events" binds calendar.events.patch and calendar.events.update to the etag read first (spec
// line 1334, F10.9 open question 1). Nothing that decides a request reads bindContent (lib/proxy-policy.mjs hashes templates and the
// config, typed records hash the capability, a row etag folds member states that leave it out), so only Calendar's defaults table, and
// so its data hash, moves: Sami signs Calendar again (S13.1). The snapshots compared with are F10.9's, recorded before its part b.
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const LOADERS = json('./fixtures/access/f10-9-loaders.before.json');
const BEFORE = json('./fixtures/access/f10-9-bindings.before.json');
const F107 = json('./fixtures/access/f10-7-bindings.before.json');
const ROW = 'google-calendar.events.write';
const BINDING = Object.freeze({'calendar.events.patch': {kind: 'etag', at: 'header:If-Match'}, 'calendar.events.update': {kind: 'etag', at: 'header:If-Match'}});
/** Sami's sign-off of Calendar's defaults, 2026-10-20: the table before step 13. */
const SIGNED = Object.freeze({by: 'Sami', date: '2026-10-20', dataHash: '5cee8759b2526fe0316d600270d3206ddc34d5bec6af4f1d5187803deff7809d'});
// F10.15 and F10.17 listed churn: steps 15 and 17 move Gmail's and GitHub's rows and data hashes on purpose, so their facts are
// test/f10-15-churn.test.mjs's and test/f10-17-churn.test.mjs's.
const OTHERS = ['notion', 'slack'];
const SIX = ['calendar.events', 'calendar.calendarlist', 'calendar.calendars', 'calendar.acls', 'calendar.settings.readonly', 'calendar.freebusy'].map(name => `https://www.googleapis.com/auth/${name}`);
const plain = value => JSON.parse(JSON.stringify(value));
const raw = () => JSON.parse(readFileSync(path.join(ROOT, 'catalog', 'permissions', 'google-calendar.json'), 'utf8'));
/** Calendar's shipped rows with the content binding taken out: the rows Sami signed. */
function unbound() {
  const file = raw();
  delete file.groups.find(group => group.id === ROW).bindContent;
  return validatePermissionGroups(file);
}

function temporaryStore(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-f10-13-churn-')), store = new Store({dataDir: dir, localAuthority: 'new'});
  t.after(() => {store.close(); rmSync(dir, {recursive: true, force: true});});
  return store;
}
/** Every proxy-row binding of one account, over the recorded synthetic map, as F10.9's snapshot was recorded. */
function proxyRowsOf(connection, groups = PERMISSION_GROUPS) {
  const config = PROXY_CONFIGS.get(connection.appId), definition = groups.get(connection.appId), policy = new ProxyPolicy({store: null});
  const templates = templatesFor(definition, config, F107.maps[connection.appId]);
  return Object.fromEntries(policy.rows({config, definition}).map(({row}) => [row, policy.binding({connection, config, templates, definition}, row)]));
}
/** The typed binding hash of every capability of the recorded synthetic map, as F10.9's snapshot compiled them. */
function typedOf(t, connection, groups = PERMISSION_GROUPS) {
  const operations = F107.maps[connection.appId].operations, paths = {};
  for (const operation of operations) paths[operation.path] = {...paths[operation.path], [operation.method.toLowerCase()]: {operationId: operation.id,
    parameters: [...operation.path.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'ok'}}}};
  const caps = compileOpenApi({appId: connection.appId, document: {openapi: '3.0.3', info: {title: connection.appId, version: '1'}, servers: [{url: 'https://www.googleapis.com/calendar/v3'}], paths}})
    .capabilities.map(cap => ({...cap, status: 'active'}));
  const store = temporaryStore(t);
  store.put('connections', connection);
  for (const cap of caps) store.put('capabilities', cap);
  store.put('applicationMaps', {id: connection.appId, appId: connection.appId, operations: operations.map(operation => ({...operation, capabilityId: caps.find(cap => cap.name === operation.id).id}))});
  const permissions = new PermissionManager({store, groups}), stored = store.get('connections', connection.id);
  return Object.fromEntries(caps.map(cap => [cap.name, permissions.decision(stored, cap).bindingHash]).sort(([a], [b]) => a < b ? -1 : 1));
}
/** A ready Calendar account with the six scopes on a store holding Google's recorded method map, decided under `groups`. */
function calendarPolicy(t, groups) {
  const store = temporaryStore(t), map = googleMap('google-calendar');
  store.put('connections', {...BEFORE.connections['google-calendar'], scopes: SIX});
  store.put('applicationMaps', {...map, id: 'google-calendar'});
  const permissions = new PermissionManager({store, groups}), policy = new ProxyPolicy({store, permissions, groups, configs: PROXY_CONFIGS});
  return {policy, store, map, connectionId: BEFORE.connections['google-calendar'].id};
}
/** Every reviewed Calendar method as one concrete raw request (a body on writes), decided; a refusal is kept as its code. */
function decisions(t, groups) {
  const {policy, map, connectionId} = calendarPolicy(t, groups);
  return Object.fromEntries(map.operations.map(operation => {
    const request = {method: operation.method, path: operation.path.replace(/\{\+?(\w+)\}/g, (_, name) => `${name}-1`), ...(['POST', 'PATCH', 'PUT'].includes(operation.method) ? {body: {summary: 'x'}} : {})};
    try { return [operation.id, plain(policy.decide(connectionId, request))]; } catch (error) { return [operation.id, {refused: error.code ?? error.message}]; }
  }));
}
/** Every member state of every Calendar row (the row etag folds them), keyed by row and member. */
function memberStates(t, groups) {
  const {policy, connectionId} = calendarPolicy(t, groups), context = policy.route(connectionId), rows = policy.rows(context);
  return Object.fromEntries(context.templates.filter(template => !template.unreviewed && template.groupId).map(template => {
    const entry = rows.find(item => item.group?.id === template.groupId);
    return [`${template.groupId} ${template.member}`, plain(policy.memberState(context, entry, template.member))];
  }));
}

test('Calendar\'s rows load to F10.9\'s recorded output plus exactly bindContent on "Create, edit and invite people to events"; notion and slack load unchanged', () => {
  const expected = structuredClone(LOADERS.permissionGroups['google-calendar']);
  expected.groups.find(group => group.id === ROW).bindContent = BINDING;
  assert.deepStrictEqual(plain(PERMISSION_GROUPS.get('google-calendar')), expected);
  for (const appId of OTHERS) assert.deepStrictEqual(plain(PERMISSION_GROUPS.get(appId)), LOADERS.permissionGroups[appId], `${appId} rows`);
  assert.deepStrictEqual(plain(unbound()), LOADERS.permissionGroups['google-calendar'], 'without the binding, the rows Sami signed');
  const file = raw();
  assert.deepEqual(file.groups.filter(group => group.bindContent !== undefined || group.sensitive !== undefined).map(group => group.id), [ROW], 'no other row binds content, and none is marked sensitive');
});

test('no proxy-row binding, typed binding, member state (the row etag folds them), policy hash or connection generation moves', t => {
  const connection = BEFORE.connections['google-calendar'];
  assert.deepEqual(proxyRowsOf(connection), BEFORE.proxyRows['google-calendar'], 'proxy-row bindings, as F10.9 recorded them');
  assert.deepEqual(typedOf(t, connection), BEFORE.typed['google-calendar'], 'typed bindings, as F10.9 recorded them');
  for (const appId of OTHERS) assert.deepEqual(proxyRowsOf(BEFORE.connections[appId]), BEFORE.proxyRows[appId], `${appId} proxy-row bindings`);
  // With the binding and without it, on Google's own method map: every member state and every decision is the same, connection
  // generation and policy revision included.
  const before = new Map([...PERMISSION_GROUPS, ['google-calendar', unbound()]]);
  assert.deepEqual(memberStates(t, PERMISSION_GROUPS), memberStates(t, before));
  const now = decisions(t, PERMISSION_GROUPS), then = decisions(t, before);
  assert.deepEqual(now, then);
  assert.equal(Object.keys(now).length, 38, 'every reviewed Calendar method');
  assert.ok(Object.values(now).every(decision => decision.refused === undefined && decision.connectionGeneration === 1), 'each decided, on generation 1');
});

test('a raw proxy PATCH or PUT on an event is decided exactly as before: the same row, mode, policy hash and binding hash', t => {
  for (const [method, member] of [['PATCH', 'calendar.events.patch'], ['PUT', 'calendar.events.update']]) {
    const request = {method, path: '/calendars/primary/events/abc123', body: {summary: 'Moved', start: {dateTime: '2026-11-02T10:00:00-05:00'}, end: {dateTime: '2026-11-02T10:30:00-05:00'}}};
    const decide = groups => { const {policy, connectionId} = calendarPolicy(t, groups); return plain(policy.decide(connectionId, request)); };
    const now = decide(PERMISSION_GROUPS), then = decide(new Map([...PERMISSION_GROUPS, ['google-calendar', unbound()]]));
    assert.deepEqual([now.row, now.mode, now.requiresApproval, now.audience, now.match.groupId], [`group:${ROW}`, 'ask', true, true, ROW], member);
    assert.deepEqual(now, then, member);
  }
});

test('notion and slack keep their signed data hashes; Calendar\'s table differs from the one Sami signed only by the binding, so it waits for his sign-off', () => {
  const golden = readGolden();
  for (const appId of OTHERS) {
    const now = appEntry(ROOT, appId).dataHash;
    assert.equal(now, BEFORE.dataHashes[appId], `${appId} data hash`);
    assert.equal(golden.apps[appId].signedOff.dataHash, now, `${appId} is signed for it`);
  }
  assert.deepEqual(checkSigned().filter(problem => !['google-calendar', 'gmail', 'github'].some(appId => problem.startsWith(`${appId}: `))), [], 'the golden is current and the other apps stay signed (Gmail and GitHub: their own churn tests)');
  const calendar = appEntry(ROOT, 'google-calendar'), recorded = golden.apps['google-calendar'];
  assert.equal(BEFORE.dataHashes['google-calendar'], SIGNED.dataHash);
  assert.equal(recorded.dataHash, calendar.dataHash, 'the golden records the table the data gives now');
  assert.notEqual(calendar.dataHash, SIGNED.dataHash, 'the binding moves Calendar\'s data hash');
  const table = structuredClone(calendar.table), row = table.rows.find(item => item.id === ROW);
  assert.deepEqual(row.bindContent, [{member: 'calendar.events.patch', kind: 'etag', at: 'header:If-Match'}, {member: 'calendar.events.update', kind: 'etag', at: 'header:If-Match'}]);
  delete row.bindContent;
  assert.equal(dataHash('google-calendar', table), SIGNED.dataHash, 'without its bindContent entry the table hashes to what Sami signed');
  // His 2026-10-20 sign-off is kept as the previous one. Until S13.1 there is no current one; after it the current one binds the new table.
  assert.deepEqual(recorded.previousSignedOff, SIGNED);
  if (recorded.signedOff === null) assert.deepEqual(checkSigned().filter(problem => problem.startsWith('google-calendar: ')), ['google-calendar: the defaults table is not signed yet']);
  else assert.equal(recorded.signedOff.dataHash, calendar.dataHash);
  // The review document shows the two lines Sami reads before he signs.
  const review = readFileSync(path.join(ROOT, REVIEW_PATH), 'utf8');
  for (const member of ['calendar.events.patch', 'calendar.events.update']) {
    assert.ok(review.includes(`- \`${member}\` (Create, edit and invite people to events): the version tag read first, sent in the If-Match header.`), member);
  }
});

// Part 2: the shipped ids are checked here, not in test/actions-google-calendar.test.mjs, which recomputes them (withIds()) so a seeded fault
// inside the file reaches behaviour instead of tripping the id check.
test('Calendar\'s shipped action file holds current ids: each stored id is the one its content hashes to, and the file validates with them', () => {
  const file = JSON.parse(readFileSync(path.join(ROOT, 'catalog', 'actions', 'google-calendar.json'), 'utf8'));
  const deps = {identities: new Map([['google-calendar', definitionFor('google')]]), maps: new Map([['google-calendar', googleMap('google-calendar')]])};
  const ids = actionIds(file, deps);
  assert.deepEqual(file.actions.map(action => action.id), file.actions.map(action => ids.get(`${action.key} v${action.version}`).id));
  assert.equal(validateActionFile(file, deps).actions.length, 13);
});

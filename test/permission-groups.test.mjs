import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, writeFile, mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {Store} from '../lib/store.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {PermissionManager, groupDefault} from '../lib/permissions.mjs';
import {validatePermissionGroups, loadPermissionGroups, groupFor, reviewedRead, PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';

// UI-2 permission groups: reviewed data, product-rule defaults, and the engine using them.
const base = {schemaVersion: 1, appId: 'fixture', groups: [
  {id: 'fixture.items.read', label: 'See items', effect: 'read', defaultMode: 'allow', requests: ['GET /items']},
  {id: 'fixture.items.draft', label: 'Draft items', effect: 'write', defaultMode: 'allow', stayInAccount: true, requests: ['POST /items']},
  {id: 'fixture.items.delete', label: 'Delete items permanently', effect: 'delete', defaultMode: 'deny', requests: ['DELETE /items/{id}']},
]};

test('group definitions enforce the product rules for defaults and membership', () => {
  assert.equal(validatePermissionGroups(base).groups.length, 3);
  const bad = (change, pattern) => assert.throws(() => validatePermissionGroups({...base, groups: change(structuredClone(base.groups))}), pattern);
  bad(groups => { groups[1].stayInAccount = false; return groups; }, /cannot default to Allow/);
  bad(groups => { groups[2].defaultMode = 'allow'; return groups; }, /can never default to Allow/);
  bad(groups => { groups[1].requests = ['GET /items']; return groups; }, /is in both/);
  bad(groups => { groups[0].id = groups[1].id; return groups; }, /repeated/);
  bad(groups => { groups[0].label = 'x'.repeat(61); return groups; }, /at most 60/);
  bad(groups => { groups[0].requests = ['FETCH /items']; return groups; }, /needs operations or/);
  bad(groups => { groups[0].requests = []; return groups; }, /needs operations or/);
  bad(groups => { groups[0].effect = 'execute'; return groups; }, /unknown effect/);
  assert.equal(validatePermissionGroups({...base, schemaVersion: 2}).schemaVersion, 2, 'F10.3: version 2 rows load');
  assert.throws(() => validatePermissionGroups({...base, schemaVersion: 3}), /schemaVersion 1 or 2/);
});

test('loading refuses a file not named after its app, and the shipped catalog definitions are valid', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-groups-')); t.after(() => rm(dir, {recursive: true, force: true}));
  await mkdir(path.join(dir, 'p')); await writeFile(path.join(dir, 'p', 'other.json'), JSON.stringify(base));
  assert.throws(() => loadPermissionGroups(pathToFileURL(`${path.join(dir, 'p')}/`)), /must be named after its appId/);
  assert.equal(loadPermissionGroups(pathToFileURL(`${path.join(dir, 'missing')}/`)).size, 0, 'no directory, no groups');
  for (const [appId, definition] of PERMISSION_GROUPS) assert.equal(definition.appId, appId);
});

test('an operation joins its group by provider method id or by method and path', () => {
  const definitions = new Map([['fixture', validatePermissionGroups({...base, groups: [...base.groups, {id: 'fixture.by.id', label: 'By id', effect: 'read', defaultMode: 'allow', operations: ['fixture.things.list']}]})]]);
  assert.equal(groupFor(definitions, 'fixture', {id: 'whatever', method: 'get', path: '/items'}).id, 'fixture.items.read');
  assert.equal(groupFor(definitions, 'fixture', {id: 'fixture.things.list', method: 'GET', path: '/things'}).id, 'fixture.by.id');
  assert.equal(groupFor(definitions, 'fixture', {id: 'x', method: 'GET', path: '/other'}), null);
  assert.equal(groupFor(definitions, 'nope', {id: 'x', method: 'GET', path: '/items'}), null);
});

test('a group default is never looser than the operation itself allows', () => {
  const http = {driver: 'http'}, browser = {driver: 'browser'};
  const draft = {defaultMode: 'allow', effect: 'write', stayInAccount: true};
  assert.equal(groupDefault(draft, http, 'write'), 'allow');
  assert.equal(groupDefault(draft, http, 'delete'), 'ask', 'a deleting member of a draft row still asks');
  assert.equal(groupDefault({defaultMode: 'allow', effect: 'read'}, http, 'write'), 'ask', 'a writing member of a read row asks');
  assert.equal(groupDefault(draft, browser, 'write'), 'ask', 'browser actions always ask');
  assert.equal(groupDefault({defaultMode: 'deny', effect: 'delete'}, browser, 'delete'), 'deny');
  assert.equal(groupDefault(null, http, 'read'), 'allow'); assert.equal(groupDefault(null, http, 'write'), 'ask');
  // F10.3 (T4): a locked row is Never for every member, browser and secrets included; a row that reaches other people never allows.
  const locked = {defaultMode: 'deny', effect: 'write', locked: 'fabric'};
  assert.deepEqual([groupDefault(locked, http, 'write'), groupDefault(locked, browser, 'write'), groupDefault(locked, http, 'write', {sensitive: 'secrets'})], ['deny', 'deny', 'deny']);
  assert.equal(groupDefault({...locked, defaultMode: 'allow', effect: 'read'}, http, 'read', {reviewedAsRead: true}), 'deny', 'even hand-built with an Allow default');
  assert.equal(groupDefault({defaultMode: 'ask', effect: 'write', audience: true}, http, 'write'), 'ask');
  assert.equal(groupDefault({defaultMode: 'allow', effect: 'write', stayInAccount: true, audience: true}, http, 'write'), 'ask', 'hand-built, an audience row still never allows');
  assert.equal(groupDefault({defaultMode: 'allow', effect: 'read', audience: true}, http, 'read'), 'ask');
});

async function engine(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-groups-engine-')), store = new Store({dataDir: dir});
  t.after(async () => { store.close(); await rm(dir, {recursive: true, force: true}); });
  const document = {openapi: '3.0.3', info: {title: 'Groups', version: '1'}, servers: [{url: 'https://api.example.com'}], paths: {
    '/items': {get: {operationId: 'listItems', responses: {200: {description: 'ok'}}}, post: {operationId: 'createItem', requestBody: {content: {'application/json': {schema: {type: 'object'}}}}, responses: {201: {description: 'ok'}}}},
    '/items/{id}': {delete: {operationId: 'deleteItem', parameters: [{name: 'id', in: 'path', required: true, schema: {type: 'string'}}], responses: {204: {description: 'ok'}}}}}};
  const caps = compileOpenApi({appId: 'fixture', document}).capabilities.map(cap => ({...cap, status: 'active'}));
  for (const cap of caps) store.put('capabilities', cap);
  store.put('applicationMaps', {id: 'fixture', operations: caps.map(cap => ({id: cap.id, capabilityId: cap.id, method: cap.request.method, path: new URL(cap.request.url).pathname.replace(/%7B/g, '{').replace(/%7D/g, '}')}))});
  const connection = {id: 'acct', appId: 'fixture', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', identity: {id: 'u'}, allowedOrigins: ['https://api.example.com'], createdAt: new Date().toISOString()};
  store.put('connections', connection);
  const permissions = new PermissionManager({store, groups: new Map([['fixture', validatePermissionGroups(base)]])});
  const runtime = new Runtime({store, permissions, connections: {credentials: async () => ({headers: {}, allowedOrigins: ['https://api.example.com']})}, request: async () => ({status: 201, data: {id: 'i'}})});
  const by = method => caps.find(cap => cap.request.method === method);
  return {store, permissions, runtime, connection, read: by('GET'), write: by('POST'), del: by('DELETE')};
}

test('the engine uses each row\'s reviewed default and reports its group', async t => {
  const {permissions, connection, read, write, del} = await engine(t);
  const decision = cap => permissions.decision(connection, cap);
  assert.deepEqual([decision(read).mode, decision(write).mode, decision(del).mode], ['allow', 'allow', 'deny']);
  assert.equal(decision(write).groupId, 'fixture.items.draft'); assert.equal(decision(write).groupLabel, 'Draft items');
  assert.equal(decision(write).defaultMode, 'allow'); assert.equal(decision(del).executable, false, 'a Never default blocks execution');
});

test('returning to the default after Deny never revives an approval made before it', async t => {
  const {permissions, runtime, connection, read, store} = await engine(t);
  // Ask is not this read's default; Deny, then the default (Allow), then Ask again must all invalidate it.
  permissions.set({connectionId: connection.id, capabilityId: read.id, mode: 'ask'});
  const job = await runtime.createJob({connectionId: connection.id, capabilityId: read.id, args: {}});
  assert.equal(job.status, 'awaiting_approval');
  permissions.set({connectionId: connection.id, capabilityId: read.id, mode: 'deny'});
  permissions.set({connectionId: connection.id, capabilityId: read.id, mode: 'allow'});
  permissions.set({connectionId: connection.id, capabilityId: read.id, mode: 'ask'});
  const approved = await runtime.approve(job.id, job.approvalDigest);
  assert.equal(approved.status, 'failed'); assert.match(approved.error, /permission setting changed/);
  const again = await runtime.createJob({connectionId: connection.id, capabilityId: read.id, args: {}});
  permissions.set({connectionId: connection.id, capabilityId: read.id, mode: 'deny'});
  permissions.reset({connectionId: connection.id});
  permissions.set({connectionId: connection.id, capabilityId: read.id, mode: 'ask'});
  assert.equal((await runtime.approve(again.id, again.approvalDigest)).status, 'failed', 'a reset between them changes nothing for an old approval');
  assert.equal(store.list('permissions').length, 1, 'one record, rewritten each time and never deleted');
  permissions.reset({connectionId: connection.id});
  assert.equal(store.list('permissions')[0].followsDefault, true, 'a reset follows the default through a fresh record');
});

test('the shipped Gmail rows match the Muse screen the product owner set as the bar', () => {
  const gmail = PERMISSION_GROUPS.get('gmail');
  const rows = Object.fromEntries(gmail.groups.map(group => [group.label, group]));
  for (const label of ['Access drafts', 'Access emails', 'Search emails']) assert.equal(rows[label].defaultMode, 'allow', label);
  assert.equal(rows['Draft emails'].defaultMode, 'allow'); assert.equal(rows['Draft emails'].stayInAccount, true, 'drafts stay in the account and can be undone');
  assert.equal(rows['Send emails'].defaultMode, 'ask');
  assert.equal(rows['Move emails to or from trash'].defaultMode, 'ask');
  assert.equal(rows['Mark as read or unread, archive or label emails'].defaultMode, 'ask', 'modify can also trash or spam-mark mail');
  // F10.7: the delete split. Drafts, labels and filters deletes Ask in their own row; deleting mail for good stays Never.
  assert.equal(rows['Delete drafts, labels or filters'].defaultMode, 'ask');
  assert.equal(rows['Permanently delete emails'].defaultMode, 'deny');
  assert.ok(rows['Send emails'].operations.includes('gmail.users.drafts.send') && rows['Send emails'].operations.includes('gmail.users.messages.send'));
  assert.ok(!rows['Draft emails'].operations.some(id => id.endsWith('.send') || id.endsWith('.delete')), 'nothing that sends or deletes defaults to Allow');
});

test('every shipped definition loads, and reviewed reads are only POST queries in read rows', () => {
  assert.deepEqual([...PERMISSION_GROUPS.keys()].sort(), ['github', 'gmail', 'google-calendar', 'notion', 'slack']);
  for (const [, definition] of PERMISSION_GROUPS) for (const group of definition.groups) {
    if (group.reviewedReads.length) assert.equal(group.effect, 'read', group.id);
    for (const read of group.reviewedReads) assert.ok(!/^(DELETE|PUT|PATCH) /.test(read), `${read} cannot be a reviewed read`);
  }
  assert.ok(PERMISSION_GROUPS.get('notion').groups.every(group => !Object.hasOwn(group, 'scopes')), 'Notion capabilities are not OAuth scopes, and version 2 rows carry no decorative scopes (F10.7)');
  const slackAdmin = PERMISSION_GROUPS.get('slack').groups.find(group => group.id === 'slack.admin');
  for (const request of ['GET /auth.revoke', 'GET /apps.uninstall', 'GET /views.publish']) assert.ok(slackAdmin.requests.includes(request), `${request} is a state change despite GET, so it is Never`);
});

test('a POST member reviewed as read-only gets its read row\'s default; any other POST still asks', () => {
  const definition = validatePermissionGroups({schemaVersion: 1, appId: 'fixture', groups: [{id: 'fixture.search', label: 'Search', effect: 'read', defaultMode: 'allow', requests: ['POST /search', 'POST /other'], reviewedReads: ['POST /search']}]});
  const group = definition.groups[0], http = {driver: 'http'};
  assert.equal(reviewedRead(group, {id: 'x', method: 'post', path: '/search'}), true);
  assert.equal(reviewedRead(group, {id: 'x', method: 'POST', path: '/other'}), false);
  assert.equal(groupDefault(group, http, 'write', {reviewedAsRead: true}), 'allow');
  assert.equal(groupDefault(group, http, 'write', {reviewedAsRead: false}), 'ask');
  assert.equal(groupDefault({...group, effect: 'write'}, http, 'write', {reviewedAsRead: true}), 'ask', 'only a read row can treat a member as a read');
  assert.throws(() => validatePermissionGroups({schemaVersion: 1, appId: 'fixture', groups: [{id: 'w', label: 'W', effect: 'write', defaultMode: 'ask', requests: ['POST /x'], reviewedReads: ['POST /x']}]}), /not a read row/);
  assert.throws(() => validatePermissionGroups({schemaVersion: 1, appId: 'fixture', groups: [{id: 'r', label: 'R', effect: 'read', defaultMode: 'allow', requests: ['GET /x'], reviewedReads: ['POST /y']}]}), /not a member/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {readdirSync, readFileSync} from 'node:fs';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {validatePermissionGroups, resolvePointer, bodyRouteHits, PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {validateProxyConfig, PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {Store} from '../lib/store.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {templatesFor, matchRequest} from '../lib/proxy-match.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {createApp} from '../server.mjs';
import {freePort} from './fixtures/signin-fixture.mjs';
import {fixture as handoffFixture, owner as LOCAL_OWNER} from './fixtures/continuation-fixture.mjs';
import {CONTINUATIONS} from '../lib/continuations.mjs';

// F10.3 (docs/F10-FIVE-APPS-DEEP.md section F10.3, docs/F10.3-BUILD-MAP.md section 4): locked rows, audience rows and
// body routes. Fixture definitions only, no network. The validator only ever tightens: a route goes to a row at least as
// strict, a locked row is Never, and a row that reaches other people never defaults to Allow.
const V2 = {schemaVersion: 2, appId: 'fixture', groups: [
  {id: 'fixture.items.read', label: 'See items', effect: 'read', defaultMode: 'allow', requests: ['GET /items']},
  {id: 'fixture.items.draft', label: 'Draft items', effect: 'write', defaultMode: 'allow', stayInAccount: true, requests: ['POST /drafts']},
  {id: 'fixture.items.tag', label: 'Tag items', effect: 'write', defaultMode: 'ask', requests: ['POST /items/{id}/tags']},
  {id: 'fixture.items.edit', label: 'Edit items', effect: 'write', defaultMode: 'ask', audience: true, requests: ['PATCH /items/{id}', 'POST /items/{+path}'], bodyRoutes: [
    {member: 'PATCH /items/{id}', pointer: '/in_trash', present: true, to: 'fixture.items.trash'},
    {member: 'PATCH /items/{id}', pointer: '/labels', contains: 'TRASH', to: 'fixture.items.trash'},
    {member: 'PATCH /items/{id}', pointer: '/type', equals: 'replace_content', to: 'fixture.items.trash'},
    {member: 'POST /items/{path}', pointer: '/share/with', present: true, to: 'fixture.access.grant'}]},
  {id: 'fixture.items.trash', label: 'Trash items', effect: 'delete', defaultMode: 'ask', requests: ['DELETE /items/{id}']},
  {id: 'fixture.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', locked: 'fabric', requests: ['PUT /items/{id}/share']},
]};
const NINE = ['id', 'label', 'effect', 'defaultMode', 'stayInAccount', 'operations', 'requests', 'scopes', 'reviewedReads'];
const at = (groups, id) => groups.find(group => group.id === id);
const bad = (change, pattern, message) => {
  const groups = structuredClone(V2.groups); change(groups, at.bind(null, groups));
  assert.throws(() => validatePermissionGroups({...V2, groups}), pattern, message);
};
const route = (extra = {}) => ({member: 'PATCH /items/{id}', pointer: '/in_trash', present: true, to: 'fixture.items.trash', ...extra});

// ---- validator --------------------------------------------------------------------------------------------------------
test('a version 2 file keeps its locked, audience and body-route fields, frozen; the output names the file\'s version', () => {
  const definition = validatePermissionGroups(V2), groups = definition.groups;
  assert.equal(definition.schemaVersion, 2);
  assert.equal(at(groups, 'fixture.access.grant').locked, 'fabric'); assert.equal(at(groups, 'fixture.items.edit').audience, true);
  assert.deepEqual(at(groups, 'fixture.items.edit').bodyRoutes, V2.groups[3].bodyRoutes);
  assert.ok(Object.isFrozen(at(groups, 'fixture.items.edit').bodyRoutes) && at(groups, 'fixture.items.edit').bodyRoutes.every(Object.isFrozen));
  assert.deepEqual(Object.keys(at(groups, 'fixture.items.read')), NINE.filter(key => key !== 'scopes'), 'a row without the new fields keeps the fields of version 1 but scopes, a version 1 field (F10.7)');
  assert.ok(!('locked' in at(groups, 'fixture.items.edit')) && !('audience' in at(groups, 'fixture.access.grant')) && !('bodyRoutes' in at(groups, 'fixture.items.trash')));
  const routes = structuredClone(V2.groups); routes[3].bodyRoutes = Array.from({length: 50}, () => route());
  assert.equal(validatePermissionGroups({...V2, groups: routes}).groups[3].bodyRoutes.length, 50, 'fifty routes on one row');
});

test('a locked row is exactly "fabric", defaults to Never, and carries nothing that loosens it', () => {
  bad((groups, of) => {of('fixture.access.grant').defaultMode = 'ask';}, /locked by Fabric, so it must default to Never/);
  bad((groups, of) => {Object.assign(of('fixture.access.grant'), {effect: 'read', defaultMode: 'allow'});}, /locked by Fabric, so it must default to Never/);
  bad((groups, of) => {of('fixture.access.grant').locked = 'yes';}, /locked must be "fabric"/);
  bad((groups, of) => {of('fixture.access.grant').locked = true;}, /locked must be "fabric"/);
  bad((groups, of) => {of('fixture.access.grant').stayInAccount = true;}, /locked by Fabric, so it cannot/);
  bad((groups, of) => {Object.assign(of('fixture.access.grant'), {effect: 'read', requests: ['POST /items/{id}/share'], reviewedReads: ['POST /items/{id}/share']});}, /locked by Fabric, so it cannot/);
  bad((groups, of) => {of('fixture.access.grant').bodyRoutes = [{member: 'PUT /items/{id}/share', pointer: '/x', present: true, to: 'fixture.items.trash'}];}, /locked by Fabric, so it cannot/);
});

test('an audience row is a boolean flag, never defaults to Allow and never stays in the account as reversible', () => {
  bad((groups, of) => {of('fixture.items.edit').audience = 'true';}, /audience must be a boolean/);
  bad((groups, of) => {of('fixture.items.read').audience = true;}, /reaches other people, so it can never default to Allow/);
  bad((groups, of) => {of('fixture.items.draft').audience = true;}, /reaches other people/);
  bad((groups, of) => {of('fixture.items.tag').stayInAccount = true; of('fixture.items.tag').audience = true;}, /reaches other people, so it cannot/);
  const groups = structuredClone(V2.groups); at(groups, 'fixture.items.tag').audience = false;
  assert.equal(at(validatePermissionGroups({...V2, groups}).groups, 'fixture.items.tag').audience, false);
});

test('a version 1 file may not carry the version 2 fields, and a version 2 file may carry no unknown field', () => {
  const v1 = structuredClone(V2.groups).filter(group => !group.locked).map(({audience, bodyRoutes, ...group}) => group);
  assert.equal(validatePermissionGroups({...V2, schemaVersion: 1, groups: v1}).schemaVersion, 1);
  // F10.6: the row scope data keys are version 2 too.
  for (const [key, value] of [['locked', 'fabric'], ['audience', true], ['bodyRoutes', [route()]], ['scopeSets', [['items.write']]], ['memberScopeSets', {'PATCH /items/{id}': [['items.write']]}],
    ['unavailable', {'PATCH /items/{id}': 'not-requested'}], ['conditions', {'PATCH /items/{id}': ['beta']}], ['conditionalScopes', {'items.admin': 'Only for some items.'}], ['unsupported', {'PATCH /items/{id}': 'It cannot do this.'}]]) {
    const groups = structuredClone(v1); at(groups, 'fixture.items.edit')[key] = value;
    assert.throws(() => validatePermissionGroups({...V2, schemaVersion: 1, groups}), /needs schemaVersion 2/, key);
  }
  bad((groups, of) => {of('fixture.items.read').extra = true;}, /unknown field extra/);
  const dropped = structuredClone(v1); dropped[0].note = 'reviewed';
  assert.deepEqual(Object.keys(validatePermissionGroups({...V2, schemaVersion: 1, groups: dropped}).groups[0]), NINE, 'version 1 still drops other keys, as before F10.3');
});

test('a body route names a member of its own row, another row of the app, and exactly one test', () => {
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [route({member: 'DELETE /items/{id}'})];}, /not a member of fixture\.items\.edit/);
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [route({to: 'fixture.nope'})];}, /not another row/);
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [route({to: 'fixture.items.edit'})];}, /not another row/);
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [route({contains: 'TRASH'})];}, /exactly one of contains, equals or present/);
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [{member: 'PATCH /items/{id}', pointer: '/x', contains: 'a', equals: 'b', to: 'fixture.items.trash'}];}, /exactly one of contains, equals or present/);
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [{member: 'PATCH /items/{id}', pointer: '/x', to: 'fixture.items.trash'}];}, /exactly one of contains, equals or present/);
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [route({extra: 1})];}, /exactly one of contains, equals or present/);
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [route({present: false})];}, /present must be true/);
  for (const value of [{}, ['TRASH'], Infinity, undefined]) {
    bad((groups, of) => {const {present, ...rest} = route(); of('fixture.items.edit').bodyRoutes = [{...rest, contains: value}];}, /JSON scalar/, String(value));
    bad((groups, of) => {const {present, ...rest} = route(); of('fixture.items.edit').bodyRoutes = [{...rest, equals: value}];}, /JSON scalar/, String(value));
  }
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [];}, /between 1 and 50/);
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = Array.from({length: 51}, () => route());}, /between 1 and 50/);
  bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [null];}, /exactly one of contains, equals or present/);
});

test('a body route pointer is RFC 6901 with 1 to 32 non-empty tokens, at most 200 characters and no __proto__', () => {
  for (const pointer of ['', 'a', '/__proto__', '/a/__proto__', '/a'.repeat(33), '/a//b', '/', '/a~2', '/a~', `/${'x'.repeat(200)}`, 7, null]) {
    bad((groups, of) => {of('fixture.items.edit').bodyRoutes = [route({pointer})];}, /pointer/, String(pointer));
  }
  for (const pointer of ['/a'.repeat(32), '/a~1b/m~0n', '/0', `/${'x'.repeat(199)}`, '/__proto', '/constructor']) {
    const groups = structuredClone(V2.groups); at(groups, 'fixture.items.edit').bodyRoutes = [route({pointer})];
    assert.equal(validatePermissionGroups({...V2, groups}).groups[3].bodyRoutes[0].pointer, pointer);
  }
});

test('a body route only ever tightens: to a locked row, or to a row as strong in effect and default that reaches people when its source does', () => {
  const groups = () => {const copy = structuredClone(V2.groups); return {copy, of: key => at(copy, key)};};
  bad((copy, of) => {of('fixture.items.trash').bodyRoutes = [{member: 'DELETE /items/{id}', pointer: '/x', present: true, to: 'fixture.items.tag'}];}, /looser/);
  bad((copy, of) => {of('fixture.items.tag').bodyRoutes = [{member: 'POST /items/{id}/tags', pointer: '/x', present: true, to: 'fixture.items.draft'}];}, /looser/);
  bad((copy, of) => {of('fixture.items.edit').bodyRoutes = [route({to: 'fixture.items.tag'})];}, /looser/);
  bad((copy, of) => {of('fixture.items.tag').defaultMode = 'deny'; of('fixture.items.tag').bodyRoutes = [{member: 'POST /items/{id}/tags', pointer: '/x', present: true, to: 'fixture.items.trash'}];}, /looser/);
  const fine = [
    ['fixture.items.tag', {member: 'POST /items/{id}/tags', pointer: '/x', present: true, to: 'fixture.items.edit'}],
    ['fixture.items.tag', {member: 'POST /items/{id}/tags', pointer: '/x', present: true, to: 'fixture.items.trash'}],
    ['fixture.items.read', {member: 'GET /items', pointer: '/x', present: true, to: 'fixture.access.grant'}],
    ['fixture.items.draft', {member: 'POST /drafts', pointer: '/x', equals: 3, to: 'fixture.items.tag'}],
  ];
  for (const [source, entry] of fine) {
    const {copy, of} = groups(); of(source).bodyRoutes = [entry];
    assert.ok(validatePermissionGroups({...V2, groups: copy}), `${source} to ${entry.to}`);
  }
  const {copy, of} = groups(); of('fixture.items.tag').audience = true; of('fixture.items.tag').bodyRoutes = [{member: 'POST /items/{id}/tags', pointer: '/x', present: true, to: 'fixture.items.edit'}];
  assert.ok(validatePermissionGroups({...V2, groups: copy}), 'an audience source may route to an audience row');
});

test('every shipped version 1 file loads exactly as before F10.3', () => {
  const directory = new URL('../catalog/permissions/', import.meta.url);
  const before = raw => ({schemaVersion: 1, appId: raw.appId, groups: raw.groups.map(group => ({id: group.id, label: group.label.trim(), effect: group.effect, defaultMode: group.defaultMode, stayInAccount: group.stayInAccount === true,
    operations: [...(group.operations ?? [])], requests: [...(group.requests ?? [])], scopes: [...(group.scopes || [])], reviewedReads: [...(group.reviewedReads ?? [])]}))});
  let count = 0;
  for (const name of readdirSync(directory).filter(file => file.endsWith('.json'))) {
    const raw = JSON.parse(readFileSync(new URL(name, directory), 'utf8'));
    if (raw.schemaVersion !== 1) continue;
    assert.equal(JSON.stringify(validatePermissionGroups(raw)), JSON.stringify(before(raw)), name);
    assert.equal(JSON.stringify(PERMISSION_GROUPS.get(raw.appId)), JSON.stringify(before(raw)), name);
    count++;
  }
  const v1 = {schemaVersion: 1, appId: 'fixture', groups: structuredClone(V2.groups).filter(group => !group.locked).map(({audience, bodyRoutes, ...group}) => group)};
  assert.equal(JSON.stringify(validatePermissionGroups(v1)), JSON.stringify(before(v1)), 'a fixture keeps the check meaningful once the catalog is version 2');
  assert.ok(count === 0 || count === PERMISSION_GROUPS.size, 'the catalog moves to version 2 in one commit');
});

// ---- pointers and route hits ------------------------------------------------------------------------------------------
test('resolvePointer reads own properties and canonical array indexes only', () => {
  const body = {a: [10, {b: null}], 'x/y': {'m~n': 'v'}, flag: false, nested: {deep: {list: ['TRASH']}}};
  assert.equal(resolvePointer(body, '/a/0'), 10); assert.equal(resolvePointer(body, '/a/1/b'), null, 'a present null');
  assert.equal(resolvePointer(body, '/x~1y/m~0n'), 'v'); assert.equal(resolvePointer(body, '/flag'), false);
  assert.deepEqual(resolvePointer(body, '/nested/deep/list'), ['TRASH']); assert.equal(resolvePointer(body, ''), body);
  for (const pointer of ['/a/01', '/a/-', '/a/2', '/a/+1', '/a/ 1', '/a/length', '/toString', '/constructor', '/__proto__', '/a/0/x', '/flag/x', '/nope', 'a', '/x~2y', '/a~'])
    assert.equal(resolvePointer(body, pointer), undefined, pointer);
  assert.equal(resolvePointer(JSON.parse('{"__proto__": {"x": 1}}'), '/__proto__/x'), 1, 'a parsed own __proto__ key is data');
  for (const value of [null, 'text', 7, undefined]) assert.equal(resolvePointer(value, '/a'), undefined);
});

test('bodyRouteHits: the routes of one member a parsed body matches, strings folded in ASCII only, a scalar a one-item list', () => {
  const group = validatePermissionGroups(V2).groups[3], hits = (member, body) => bodyRouteHits(group, member, body).map(entry => `${entry.pointer}->${entry.to}`);
  assert.deepEqual(hits('PATCH /items/{id}', {labels: ['STARRED', 'TRASH']}), ['/labels->fixture.items.trash']);
  assert.deepEqual(hits('PATCH /items/{id}', {labels: ['trash']}), ['/labels->fixture.items.trash'], 'ASCII case folding');
  assert.deepEqual(hits('PATCH /items/{id}', {labels: 'Trash'}), ['/labels->fixture.items.trash'], 'a scalar counts as a one-item list');
  assert.deepEqual(hits('PATCH /items/{id}', {labels: ['TRAſH', 'KTRASH', 'STARRED', {name: 'TRASH'}, ['TRASH']]}), [], 'no Unicode folding, no objects or nested lists');
  assert.deepEqual(hits('PATCH /items/{id}', {type: 'REPLACE_CONTENT'}), ['/type->fixture.items.trash']);
  assert.deepEqual(hits('PATCH /items/{id}', {type: ['replace_content']}), [], 'equals compares the value itself');
  assert.deepEqual(hits('PATCH /items/{id}', {in_trash: null}), ['/in_trash->fixture.items.trash'], 'present means the key is there');
  assert.deepEqual(hits('PATCH /items/{id}', {in_trash: false, labels: ['TRASH']}), ['/in_trash->fixture.items.trash', '/labels->fixture.items.trash']);
  assert.deepEqual(hits('POST /items/{+path}', {share: {with: 'someone'}}), ['/share/with->fixture.access.grant'], 'members compare as their member key');
  assert.deepEqual(hits('POST /items/{path}', {share: {with: 'someone'}}), ['/share/with->fixture.access.grant']);
  assert.deepEqual(hits('POST /items/{path}', {in_trash: true}), [], 'only the routes of that member');
  for (const body of [undefined, null, 'in_trash', 7, [], {}]) assert.deepEqual(hits('PATCH /items/{id}', body), [], JSON.stringify(body));
  assert.deepEqual(bodyRouteHits(null, 'PATCH /items/{id}', {in_trash: true}), []); assert.deepEqual(bodyRouteHits(validatePermissionGroups(V2).groups[0], 'GET /items', {in_trash: true}), []);
  const numbers = validatePermissionGroups({...V2, groups: V2.groups.map(entry => entry.id === 'fixture.items.draft' ? {...entry, bodyRoutes: [{member: 'POST /drafts', pointer: '/n', equals: 1, to: 'fixture.items.tag'}, {member: 'POST /drafts', pointer: '/b', contains: true, to: 'fixture.items.tag'}]} : entry)}).groups[1];
  assert.deepEqual([bodyRouteHits(numbers, 'POST /drafts', {n: 1}).length, bodyRouteHits(numbers, 'POST /drafts', {n: '1'}).length, bodyRouteHits(numbers, 'POST /drafts', {b: [false, true]}).length, bodyRouteHits(numbers, 'POST /drafts', {b: 'true'}).length], [1, 0, 1, 0]);
});

// ---- proxy settings ---------------------------------------------------------------------------------------------------
const CONFIG = {schemaVersion: 1, appId: 'fixture', apiBase: 'https://api.example.com', style: 'rest', pathPrefixes: ['/'], acceptTypes: ['application/json'], reservedParameters: [], reservedBodyFields: [], arrayParameters: [],
  aliases: [], inheritFamilies: [], documentedRoutes: null, proxyAllowable: [], typedOnly: []};
const settings = (groups, change = {}) => validateProxyConfig({...CONFIG, ...change}, {groups: new Map([['fixture', {schemaVersion: 2, appId: 'fixture', groups}]]), allowedOrigins: ['https://api.example.com']});
const row = (id, fields = {}) => ({id, label: id, effect: 'write', defaultMode: 'ask', stayInAccount: true, operations: [], requests: [`POST /${id}`], scopes: [], reviewedReads: [], ...fields});

test('validateProxyConfig: a locked row or one that reaches other people is never proxyAllowable, even hand-built as staying in the account', () => {
  assert.ok(settings([row('plain')], {proxyAllowable: ['plain']}), 'the control row is Allow-able');
  for (const fields of [{locked: 'fabric', defaultMode: 'deny'}, {locked: 'fabric'}, {audience: true}])
    assert.throws(() => settings([row('plain', fields)], {proxyAllowable: ['plain']}), /cannot be proxyAllowable/, JSON.stringify(fields));
  assert.ok(settings([row('plain', {audience: false})], {proxyAllowable: ['plain']}));
});

test('validateProxyConfig: a body route never carries a request into a proxyAllowable row from one that is not', () => {
  const into = [row('source', {stayInAccount: false, bodyRoutes: [{member: 'POST /source', pointer: '/x', present: true, to: 'target'}]}), row('target')];
  assert.ok(settings(into), 'neither row Allow-able');
  assert.throws(() => settings(into, {proxyAllowable: ['target']}), /routes requests into target/);
  const both = [row('source', {bodyRoutes: [{member: 'POST /source', pointer: '/x', present: true, to: 'target'}]}), row('target')];
  assert.ok(settings(both, {proxyAllowable: ['source', 'target']}), 'from one Allow-able row into another');
  assert.ok(settings(both, {proxyAllowable: ['source']}), 'out of an Allow-able row');
});

test('validateProxyConfig: no body routes on an RPC app, whose GET requests carry their arguments in the query', () => {
  const routed = [row('source', {bodyRoutes: [{member: 'POST /source', pointer: '/x', present: true, to: 'target'}]}), row('target', {effect: 'delete', stayInAccount: false})];
  assert.ok(settings(routed));
  assert.throws(() => settings(routed, {style: 'rpc'}), /RPC app/);
  assert.ok(settings(routed.map(({bodyRoutes, ...entry}) => entry), {style: 'rpc'}));
});

test('validateProxyConfig: two templates with one loose shape in different rows are refused, alias forms included', () => {
  const aliases = [{from: '/repos/{owner}/{repo}', to: '/repositories/{repository_id}'}];
  const groups = [row('code', {requests: ['PATCH /repos/{owner}/{repo}']}), row('admin', {requests: ['PATCH /repositories/{id}']})];
  assert.ok(settings(groups), 'without the alias they never meet');
  assert.throws(() => settings(groups, {aliases}), /PATCH \/repositories\/\{id\} routes the same requests as a template in code/);
  assert.ok(settings([row('code', {requests: ['PATCH /repos/{owner}/{repo}', 'PATCH /repositories/{id}']})], {aliases}), 'one row may hold both forms');
  assert.ok(settings([row('code', {requests: ['GET /repos/{owner}/{repo}/a/{+path}']}), row('other', {requests: ['GET /repositories/{id}/b/{+path}']})], {aliases}));
  assert.throws(() => settings([row('code', {requests: ['GET /repos/{owner}/{repo}/a/{+path}']}), row('other', {requests: ['GET /repositories/{id}/a/{x}']})], {aliases}), /routes the same requests/, '{+x} reads as {x}');
  assert.deepEqual([...PROXY_CONFIGS.keys()].sort(), ['github', 'gmail', 'google-calendar', 'notion', 'slack'], 'the shipped settings still load');
});

// ---- typed decisions (part d) -----------------------------------------------------------------------------------------
const LOCK = /Fabric keeps this off: it gives access to other people or services\. No setting can turn it on\./;
const P = name => [{name, in: 'path', required: true, schema: {type: 'string'}}], BODY = {content: {'application/json': {schema: {type: 'object'}}}}, OK = {200: {description: 'ok'}};
const described = (base, paths) => ({openapi: '3.0.3', info: {title: 'Items', version: '1'}, servers: [{url: base}], paths});
const ITEMS = described('https://api.example.com', {
  '/items': {get: {operationId: 'listItems', responses: OK}},
  '/items/{id}': {patch: {operationId: 'editItem', parameters: P('id'), requestBody: BODY, responses: OK}, delete: {operationId: 'deleteItem', parameters: P('id'), responses: OK}},
  '/items/{id}/share': {put: {operationId: 'shareItem', parameters: P('id'), requestBody: BODY, responses: OK}},
  '/items/{id}/hooks': {post: {operationId: 'addHook', parameters: P('id'), requestBody: BODY, responses: OK}},
  '/items/{id}/notes': {post: {operationId: 'addNote', parameters: P('id'), requestBody: BODY, responses: OK}}});
// Imported straight from a description, so no map operation places them.
const IMPORTS = [described('https://api.example.com', {
  '/items/{x}/hooks': {post: {operationId: 'importHook', parameters: P('x'), requestBody: BODY, responses: OK}},
  '/items/{x}/share': {put: {operationId: 'importShare', parameters: P('x'), requestBody: BODY, responses: OK}},
  '/items/{item}': {patch: {operationId: 'importEdit', parameters: P('item'), requestBody: BODY, responses: OK}},
  '/items/{x}/comments': {post: {operationId: 'importComment', parameters: P('x'), requestBody: BODY, responses: OK}}}),
described('https://uploads.example.com', {'/items/{x}/files': {post: {operationId: 'importUpload', parameters: P('x'), requestBody: BODY, responses: OK}}})];
const READ = {id: 'fixture.items.read', label: 'See items', effect: 'read', defaultMode: 'allow', requests: ['GET /items']};
const TRASH = {id: 'fixture.items.trash', label: 'Trash items', effect: 'delete', defaultMode: 'ask', requests: ['DELETE /items/{id}']};
const SHARED = ['PUT /items/{id}/share', 'POST /items/{item_id}/hooks'];
const BEFORE = {schemaVersion: 1, appId: 'fixture', groups: [READ, {id: 'fixture.items.edit', label: 'Edit items', effect: 'write', defaultMode: 'ask', requests: ['PATCH /items/{id}']}, TRASH,
  {id: 'fixture.items.share', label: 'Share items', effect: 'write', defaultMode: 'ask', requests: SHARED}]};
const LOCKED = {schemaVersion: 2, appId: 'fixture', groups: [READ, {id: 'fixture.items.edit', label: 'Edit items', effect: 'write', defaultMode: 'ask', audience: true, requests: ['PATCH /items/{id}'], bodyRoutes: [
  {member: 'PATCH /items/{id}', pointer: '/labels', contains: 'TRASH', to: 'fixture.items.trash'}, {member: 'PATCH /items/{id}', pointer: '/share', present: true, to: 'fixture.access.grant'}]}, TRASH,
  {id: 'fixture.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', locked: 'fabric', requests: SHARED}]};
const AUDIENCE = {...BEFORE, schemaVersion: 2, groups: BEFORE.groups.map(group => group.id === 'fixture.items.edit' ? {...group, audience: true} : group)};

async function typed(t, connection = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-locked-rows-')), store = new Store({dataDir: dir});
  t.after(async () => { store.close(); await rm(dir, {recursive: true, force: true}); });
  const mapped = compileOpenApi({appId: 'fixture', document: ITEMS}).capabilities.map(cap => ({...cap, status: 'active'}));
  const imported = IMPORTS.flatMap(entry => compileOpenApi({appId: 'fixture', document: entry}).capabilities).map(cap => ({...cap, status: 'active'}));
  for (const cap of [...mapped, ...imported]) store.put('capabilities', cap);
  const scopes = {shareItem: ['items.share'], addHook: ['items.share']};
  store.put('applicationMaps', {id: 'fixture', appId: 'fixture', operations: mapped.map(cap => ({id: cap.name, capabilityId: cap.id, method: cap.request.method, path: cap.provenance.path, requiredScopes: scopes[cap.name] || ['items.read']}))});
  const account = {id: 'acct', appId: 'fixture', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', identity: {id: 'u'}, allowedOrigins: ['https://api.example.com'], createdAt: '2026-10-17T00:00:00.000Z', ...connection};
  store.put('connections', account);
  const manager = (groups, extra = {}) => new PermissionManager({store, groups: new Map([['fixture', validatePermissionGroups(groups)]]), configs: new Map([['fixture', CONFIG]]), ...extra});
  const cap = name => [...mapped, ...imported].find(item => item.name === name);
  return {store, account, manager, cap, set: (permissions, name, mode) => permissions.set({connectionId: account.id, capabilityId: cap(name).id, mode}), decide: (permissions, name) => permissions.decision(account, cap(name))};
}

test('T4 typed: an Allow saved before a member was locked decides Never, with the lock flag and words, and its binding does not move', async t => {
  const {manager, set, decide, cap} = await typed(t), before = manager(BEFORE), after = manager(LOCKED);
  set(before, 'shareItem', 'allow');
  const was = decide(before, 'shareItem');
  assert.deepEqual([was.mode, was.executable, was.policySource], ['allow', true, 'saved']);
  const now = decide(after, 'shareItem');
  assert.deepEqual([now.mode, now.executable, now.locked, now.defaultMode, now.policySource, now.stale, now.groupId], ['deny', false, true, 'deny', 'saved', false, 'fixture.access.grant']);
  assert.match(now.reason, LOCK);
  assert.equal(now.bindingHash, was.bindingHash, 'no lock term in the typed binding: the clamp holds the lock');
  // Correction 6: a map operation whose path names its parameter differently still meets the locked row's template.
  const hook = decide(after, 'addHook');
  assert.deepEqual([hook.mode, hook.executable, hook.locked, hook.defaultMode], ['deny', false, true, 'deny']); assert.match(hook.reason, LOCK);
  assert.deepEqual([after.lockOf(cap('shareItem')), after.lockOf(cap('addHook')), before.lockOf(cap('shareItem'))], ['fabric', 'fabric', null]);
});

test('T4 typed: set refuses Ask and Allow on a locked member before writing anything; Never follows the default and a reset keeps it', async t => {
  const {store, manager, set, decide} = await typed(t), permissions = manager(LOCKED);
  for (const mode of ['ask', 'allow']) for (const name of ['shareItem', 'addHook']) {
    assert.throws(() => set(permissions, name, mode), error => error.code === 'mode_not_allowed' && error.locked === true && LOCK.test(error.message), `${name} ${mode}`);
  }
  assert.equal(store.list('permissions').length, 0, 'nothing was written');
  set(permissions, 'shareItem', 'deny'); set(permissions, 'addHook', 'deny');
  assert.ok(store.list('permissions').every(record => record.followsDefault === true && record.mode === 'deny'), 'Never is the default of a locked member');
  assert.deepEqual([decide(permissions, 'shareItem').mode, decide(permissions, 'shareItem').policySource], ['deny', 'default']);
  permissions.reset({connectionId: 'acct'});
  assert.deepEqual([decide(permissions, 'shareItem').mode, decide(permissions, 'addHook').mode], ['deny', 'deny']);
});

test('T4 typed: the lock words come before the missing-scope and reconnect advice', async t => {
  const oauth = await typed(t, {authMethod: 'oauth', scopes: ['items.read']}), decision = oauth.decide(oauth.manager(LOCKED), 'shareItem');
  assert.equal(decision.providerAccess, 'missing'); assert.match(decision.reason, LOCK);
  assert.match(oauth.decide(oauth.manager(BEFORE), 'shareItem').reason, /does not have a required provider scope/, 'the control: unlocked, it would suggest reconnecting');
  const broken = await typed(t, {status: 'reconnect_required'});
  assert.match(broken.decide(broken.manager(LOCKED), 'shareItem').reason, LOCK);
});

test('T4 typed: unlocked members keep byte-identical binding and policy hashes; audience is reported but never hashed', async t => {
  const {manager, decide} = await typed(t), before = manager(BEFORE), after = manager(LOCKED), audience = manager(AUDIENCE);
  for (const name of ['listItems', 'deleteItem', 'addNote', 'importComment']) {
    const was = decide(before, name), now = decide(after, name);
    assert.deepEqual([now.bindingHash, now.policyHash, now.mode], [was.bindingHash, was.policyHash, was.mode], name);
    assert.ok(!('locked' in now) && !('audience' in now), `${name} carries neither key`);
  }
  const plain = decide(before, 'editItem'), flagged = decide(audience, 'editItem');
  assert.equal(flagged.audience, true); assert.ok(!('audience' in plain));
  assert.deepEqual([flagged.bindingHash, flagged.policyHash, flagged.mode], [plain.bindingHash, plain.policyHash, plain.mode], 'audience never enters a hash');
});

test('T4 typed: a member that gains body routes needs fresh consent (correction 4); Never stays Never, members without routes keep their records', async t => {
  const {manager, set, decide, cap} = await typed(t);
  // Saved before the member had routes. Under Iteration 8's lock file a row could be set to Allow while the file held a member.
  const before = manager(BEFORE);
  set(before, 'editItem', 'allow'); set(before, 'deleteItem', 'deny');
  assert.deepEqual([decide(before, 'editItem').mode, decide(before, 'editItem').policySource, before.lockOf(cap('editItem'))], ['allow', 'saved', null]);
  // The member now routes some bodies elsewhere: the old Allow is not silently in force.
  const routed = manager(LOCKED), edit = decide(routed, 'editItem');
  assert.deepEqual([edit.mode, edit.stale, edit.policySource, routed.lockOf(cap('editItem'))], ['ask', true, 'stale', null]);
  assert.notEqual(edit.bindingHash, decide(before, 'editItem').bindingHash);
  assert.deepEqual([decide(routed, 'deleteItem').mode, decide(routed, 'deleteItem').policySource], ['deny', 'saved'], 'a route target keeps its own binding');
  set(before, 'editItem', 'deny');
  assert.deepEqual([decide(routed, 'editItem').mode, decide(routed, 'editItem').stale], ['deny', true], 'Never stays Never');
  // Saved while the routes are in force, a setting binds them and stands: set() and decision() read the same routes.
  for (const name of ['editItem', 'importEdit']) {
    set(routed, name, 'allow');
    assert.deepEqual([decide(routed, name).mode, decide(routed, name).stale, decide(routed, name).policySource], ['allow', false, 'saved'], name);
  }
});

test('T4 typed: map-less capabilities are placed by request shape, and fail closed when they cannot be placed', async t => {
  const {manager, decide, cap} = await typed(t), before = manager(BEFORE), after = manager(LOCKED);
  for (const name of ['importHook', 'importShare', 'importUpload']) {
    const decision = decide(after, name);
    assert.deepEqual([decision.mode, decision.executable, decision.locked], ['deny', false, true], name); assert.match(decision.reason, LOCK, name);
    assert.equal(after.lockOf(cap(name)), 'fabric', name);
    assert.notEqual(decide(before, name).mode, 'deny', `${name}: the control, before the lock`);
  }
  const ordinary = decide(after, 'importComment'), was = decide(before, 'importComment');
  assert.deepEqual([ordinary.mode, ordinary.bindingHash, ordinary.policyHash], [was.mode, was.bindingHash, was.policyHash], 'an ordinary import keeps its decision');
  assert.equal(after.lockOf(cap('importComment')), null); assert.equal(after.lockOf(cap('listItems')), null); assert.equal(before.lockOf(cap('importHook')), null);
});

test('T4 typed: placed by shape, a request meets a locked template through a parameter on either side and through the app\'s path aliases', async t => {
  const {store, account, manager} = await typed(t);
  const extra = compileOpenApi({appId: 'fixture', document: described('https://api.example.com', {
    '/items/{x}/{action}': {put: {operationId: 'importAnyPut', parameters: [...P('x'), ...P('action')], requestBody: BODY, responses: OK}},
    '/items/fixed/hooks': {post: {operationId: 'importFixedHook', requestBody: BODY, responses: OK}},
    '/things/{x}/share': {put: {operationId: 'importAliasShare', parameters: P('x'), requestBody: BODY, responses: OK}},
    '/things/{x}/notes': {put: {operationId: 'importAliasNote', parameters: P('x'), requestBody: BODY, responses: OK}}})}).capabilities.map(cap => ({...cap, status: 'active'}));
  for (const cap of extra) store.put('capabilities', cap);
  const of = name => extra.find(cap => cap.name === name), plain = manager(LOCKED);
  const aliased = manager(LOCKED, {configs: new Map([['fixture', {...CONFIG, aliases: [{from: '/items/{id}', to: '/things/{thing_id}'}]}]])});
  // A parameter on either side could carry the locked segment's value, so no argument reaches a locked endpoint.
  for (const name of ['importAnyPut', 'importFixedHook']) assert.deepEqual([plain.decision(account, of(name)).mode, plain.lockOf(of(name))], ['deny', 'fabric'], name);
  const share = aliased.decision(account, of('importAliasShare'));
  assert.deepEqual([share.mode, share.locked, aliased.lockOf(of('importAliasShare'))], ['deny', true, 'fabric'], 'the alias form of a locked member');
  assert.deepEqual([plain.lockOf(of('importAliasShare')), aliased.lockOf(of('importAliasNote')), aliased.decision(account, of('importAliasNote')).mode], [null, null, 'ask'], 'the controls: no alias, and an alias form of no locked member');
});

test('T4 typed: a read that cannot be placed keeps its decision, so Other reads are not held at Never, unless a read could be locked', async t => {
  const {store, account, manager, decide} = await typed(t);
  const [download] = compileOpenApi({appId: 'fixture', document: described('https://uploads.example.com', {'/items/{x}/files/{f}': {get: {operationId: 'getFile', parameters: [...P('x'), ...P('f')], responses: OK}}})}).capabilities.map(cap => ({...cap, status: 'active'}));
  store.put('capabilities', download);
  const before = manager(BEFORE), after = manager(LOCKED), was = before.decision(account, download), now = after.decision(account, download);
  assert.deepEqual([now.mode, now.bindingHash, now.policyHash, 'locked' in now, after.lockOf(download)], ['allow', was.bindingHash, was.policyHash, false, null]);
  // c3: every typed read caps an "Other reads" request, so one read held at Never would hold them all, with no setting to undo it.
  const configs = new Map([['fixture', validateProxyConfig(CONFIG, {groups: after.groups, allowedOrigins: ['https://api.example.com']})]]);
  const proxied = new ProxyPolicy({store, permissions: after, groups: after.groups, configs}).decide(account.id, {method: 'GET', path: '/elsewhere'});
  assert.deepEqual([proxied.row, proxied.mode, proxied.clamps], ['other-reads', 'ask', []]);
  // A write that cannot be placed stays held; so does a read when a locked member reads, or in an RPC app, whose method names no endpoint.
  assert.equal(decide(after, 'importUpload').mode, 'deny');
  const reads = manager({...LOCKED, groups: LOCKED.groups.map(group => group.locked ? {...group, requests: [...group.requests, 'GET /items/{id}/share']} : group)});
  const rpc = manager(LOCKED, {configs: new Map([['fixture', {...CONFIG, style: 'rpc'}]])});
  for (const [name, permissions] of [['a locked read', reads], ['RPC', rpc]]) assert.deepEqual([permissions.decision(account, download).mode, permissions.lockOf(download)], ['deny', 'fabric'], name);
});

test('T4 typed: an app reviewed by operation id fails closed only for writes and deletes while its map cannot place the locked operations (correction 10)', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-locked-ops-')), store = new Store({dataDir: dir});
  t.after(async () => { store.close(); await rm(dir, {recursive: true, force: true}); });
  const caps = compileOpenApi({appId: 'opfix', document: described('https://ops.example.com', {
    '/v1/items/{id}/share': {post: {operationId: 'share', parameters: P('id'), requestBody: BODY, responses: OK}},
    '/v1/items/{id}/tag': {post: {operationId: 'tag', parameters: P('id'), requestBody: BODY, responses: OK}, delete: {operationId: 'untag', parameters: P('id'), responses: OK}},
    '/v1/items/{id}/audit': {get: {operationId: 'audit', parameters: P('id'), responses: OK}}})}).capabilities.map(cap => ({...cap, status: 'active'}));
  for (const cap of caps) store.put('capabilities', cap);
  const account = {id: 'ops', appId: 'opfix', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', identity: {id: 'u'}, createdAt: '2026-10-17T00:00:00.000Z'};
  store.put('connections', account);
  const groups = validatePermissionGroups({schemaVersion: 2, appId: 'opfix', groups: [{id: 'opfix.items.read', label: 'See items', effect: 'read', defaultMode: 'allow', operations: ['opfix.items.list']},
    {id: 'opfix.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', locked: 'fabric', operations: ['opfix.items.share']}]});
  const permissions = new PermissionManager({store, groups: new Map([['opfix', groups]]), configs: new Map([['opfix', {...CONFIG, appId: 'opfix', apiBase: 'https://ops.example.com'}]])});
  const mode = name => permissions.decision(account, caps.find(cap => cap.name === name)).mode;
  assert.deepEqual(['share', 'tag', 'untag', 'audit'].map(mode), ['deny', 'deny', 'deny', 'allow'], 'no map: writes and deletes are held, reads keep their decision');
  store.put('applicationMaps', {id: 'opfix', appId: 'opfix', operations: [{id: 'opfix.items.list', method: 'GET', path: '/v1/items'}, {id: 'opfix.items.share', method: 'POST', path: '/v1/items/{itemId}/share'}]});
  assert.deepEqual(['share', 'tag', 'untag', 'audit'].map(mode), ['deny', 'ask', 'ask', 'allow'], 'a complete map places them by shape');
});

test('bodyRouteOf: the strictest row a typed body is routed to, found by the member\'s row or by its request', async t => {
  const {manager, cap} = await typed(t), permissions = manager(LOCKED);
  for (const name of ['editItem', 'importEdit']) {
    const trash = permissions.bodyRouteOf(cap(name), {labels: ['TRASH'], title: 'x'});
    assert.deepEqual(trash, {groupId: 'fixture.items.trash', label: 'Trash items', locked: false}, name); assert.ok(Object.isFrozen(trash));
    assert.deepEqual(permissions.bodyRouteOf(cap(name), {labels: 'trash', share: {with: 'someone'}}), {groupId: 'fixture.access.grant', label: 'Give access to other people or services', locked: true}, `${name}: the locked target is the strictest`);
    for (const body of [{title: 'x'}, {labels: ['STARRED']}, undefined, null, 'TRASH']) assert.equal(permissions.bodyRouteOf(cap(name), body), null, `${name} ${JSON.stringify(body)}`);
  }
  assert.equal(permissions.bodyRouteOf(cap('importComment'), {labels: ['TRASH']}), null, 'a member without routes');
  assert.equal(manager(BEFORE).bodyRouteOf(cap('editItem'), {labels: ['TRASH']}), null, 'no routes before version 2');
});

test('T4 typed: a job on a locked member is refused with a code in the single-owner runtime too, before anything is sent', async t => {
  const {store, manager, cap} = await typed(t), sent = [];
  const runtime = new Runtime({store, permissions: manager(LOCKED), connections: {credentials: async () => ({headers: {}, allowedOrigins: ['https://api.example.com']})}, request: async req => { sent.push(req); return {status: 200, data: {}}; }});
  await assert.rejects(runtime.createJob({connectionId: 'acct', capabilityId: cap('shareItem').id, args: {id: 'i1', body: {}}}), error => error.code === 'permission_denied' && error.locked === true && LOCK.test(error.message));
  assert.deepEqual([sent.length, store.list('jobs').length], [0, 0]);
});

// ---- owner rows (part e) ----------------------------------------------------------------------------------------------
const HUB = described('https://api.github.com', {
  '/user/repos': {get: {operationId: 'listRepos', responses: OK}},
  '/repos/{owner}/{repo}/issues': {post: {operationId: 'createIssue', parameters: [...P('owner'), ...P('repo')], requestBody: BODY, responses: OK}},
  '/repos/{owner}/{repo}/hooks': {post: {operationId: 'createHook', parameters: [...P('owner'), ...P('repo')], requestBody: BODY, responses: OK}},
  '/repos/{owner}/{repo}/tokens': {post: {operationId: 'createToken', parameters: [...P('owner'), ...P('repo')], requestBody: BODY, responses: OK}},
  '/repos/{owner}/{repo}/collaborators/{username}': {put: {operationId: 'addCollaborator', parameters: [...P('owner'), ...P('repo'), ...P('username')], requestBody: BODY, responses: OK}}});
// The locked row is declared before the issues row, so only its own order sorts it last.
const HUB_ROWS = {schemaVersion: 2, appId: 'github', groups: [{id: 'github.repos.read', label: 'See repositories', effect: 'read', defaultMode: 'allow', requests: ['GET /user/repos']},
  {id: 'github.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', locked: 'fabric', requests: ['POST /repos/{owner}/{repo}/hooks', 'PUT /repos/{owner}/{repo}/collaborators/{username}']},
  {id: 'github.issues.write', label: 'Create issues', effect: 'write', defaultMode: 'ask', audience: true, requests: ['POST /repos/{owner}/{repo}/issues']}]};

async function owner(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-locked-owner-')), app = await createApp({dataDir: dir, port: await freePort(), request: async () => ({status: 200, data: {}})});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); });
  const caps = compileOpenApi({appId: 'github', document: HUB}).capabilities.map(cap => ({...cap, status: cap.name === 'createHook' ? 'candidate' : 'active'}));
  for (const cap of caps) app.store.put('capabilities', cap);
  const cap = name => caps.find(item => item.name === name);
  // createHook and createToken return keys, so the classifier puts them with "Changes that return keys or secrets"; the lock
  // keeps createHook in its row, and createToken, in no row, stays in the sensitive one.
  const meta = {createHook: ['secrets', ['admin:repo_hook']], createToken: ['secrets', ['repo']], addCollaborator: [null, ['admin:org']], createIssue: [null, ['repo']], listRepos: [null, []]};
  app.store.put('applicationMaps', {id: 'github', appId: 'github', classifierVersion: SENSITIVITY_VERSION, operations: caps.map(item => ({id: item.name, capabilityId: item.id, method: item.request.method, path: item.provenance.path, sensitive: meta[item.name][0], requiredScopes: meta[item.name][1]}))});
  const account = {id: 'gh-acct', appId: 'github', driver: 'http', authMethod: 'oauth', authRevision: 'r1', status: 'ready', identity: {id: '42', displayName: 'octo'}, scopes: ['repo'], allowedOrigins: ['https://api.github.com'], createdAt: '2026-10-17T00:00:00.000Z'};
  app.store.put('connections', account);
  app.runtime.permissions.groups = new Map([['github', validatePermissionGroups(HUB_ROWS)]]);
  const first = await fetch(`${app.origin}/api/state`), session = {cookie: first.headers.get('set-cookie').split(';')[0], csrf: (await first.json()).csrfToken};
  const json = async (method, route, data) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {'content-type': 'application/json', 'x-fabric-csrf': session.csrf, cookie: session.cookie}, ...(data !== undefined ? {body: JSON.stringify(data)} : {})}); return {status: response.status, body: await response.json()}; };
  const view = async () => (await json('GET', `/api/ui/apps/github?account=${account.id}`)).body, rowOf = (detail, id) => detail.sections.flatMap(section => section.rows).find(item => item.groupId === id);
  return {app, cap, account, json, view, rowOf};
}

test('owner rows: a locked member stays in its locked row whatever its sensitivity; the row offers Never only, sorts last and offers no Add access', async t => {
  const {app, cap, account, view, rowOf} = await owner(t), detail = await view();
  assert.deepEqual(detail.sections.map(section => [section.label, section.rows.map(item => item.groupId)]), [['Read permissions', ['github.repos.read']], ['Write and delete permissions', ['github.issues.write', 'sensitive.secrets.write', 'github.access.grant']]]);
  assert.equal(rowOf(detail, 'sensitive.secrets.write').operations, 1, 'the "Changes that return keys or secrets" row holds only the unlocked member');
  const locked = rowOf(detail, 'github.access.grant');
  assert.deepEqual({locked: locked.locked, allowedModes: locked.allowedModes, mode: locked.mode, defaultMode: locked.defaultMode, access: locked.access, operations: locked.operations},
    {locked: true, allowedModes: ['deny'], mode: 'deny', defaultMode: 'deny', access: 'missing', operations: 2});
  assert.equal(locked.blockedReason, 'Fabric keeps this off: it gives access to other people or services.');
  assert.ok(!('addAccess' in locked) && !('addBlocked' in locked) && !('sensitive' in locked) && !('audience' in locked));
  assert.equal(rowOf(detail, 'github.issues.write').audience, true); assert.ok(!('locked' in rowOf(detail, 'github.issues.write')));
  assert.ok(!('locked' in rowOf(detail, 'github.repos.read')) && !('audience' in rowOf(detail, 'github.repos.read')));
  assert.equal(app.runtime.permissions.decision(account, cap('createHook')).sensitivity, 'secrets', 'the member keeps its own classification');
});

test('owner rows: setRow refuses Ask and Allow on a locked row and accepts Never, which promotes nothing; the per-operation route refuses Ask', async t => {
  const {app, cap, account, json, view, rowOf} = await owner(t), path = `/api/ui/apps/github/accounts/${account.id}/permissions`;
  const locked = rowOf(await view(), 'github.access.grant');
  for (const mode of ['ask', 'allow']) {
    const refused = await json('POST', path, {groupId: locked.groupId, mode, etag: locked.etag, review: true, confirmAllow: true});
    assert.deepEqual([refused.status, refused.body.code, refused.body.error], [400, 'invalid_request', 'Fabric keeps this off: it gives access to other people or services.'], mode);
  }
  assert.equal(app.store.list('permissions').length, 0);
  const done = await json('POST', path, {groupId: locked.groupId, mode: 'deny', etag: locked.etag});
  assert.equal(done.status, 200); assert.equal(rowOf(done.body, 'github.access.grant').mode, 'deny');
  assert.equal(app.store.get('capabilities', cap('createHook').id).status, 'candidate', 'Never promotes nothing');
  assert.ok(app.store.list('permissions').every(record => record.mode === 'deny' && record.followsDefault === true));
  const direct = await json('POST', `/api/connections/${account.id}/permissions`, {capabilityId: cap('addCollaborator').id, mode: 'ask'});
  assert.equal(direct.status, 400); assert.equal(direct.body.code, 'mode_not_allowed'); assert.match(direct.body.error, LOCK);
});

// ---- the proxy (part f) -----------------------------------------------------------------------------------------------
// A request-reviewed fixture app on the proxy with no typed capability stored, so no typed decision (c3, c4) caps a request
// and every clamp below is the lock's own. OPEN is the same app before the lock: the controls.
const FENCED = {schemaVersion: 2, appId: 'fixture', groups: [READ, {id: 'fixture.items.edit', label: 'Edit items', effect: 'write', defaultMode: 'ask', audience: true, requests: ['PATCH /items/{id}', 'PUT /items/special/share']},
  TRASH, {id: 'fixture.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', locked: 'fabric', requests: SHARED}]};
const OPEN = {...FENCED, groups: FENCED.groups.map(({locked, audience, ...group}) => group.id === 'fixture.access.grant' ? {...group, defaultMode: 'ask'} : group)};
const MUTATION = {query: 'mutation { share(id: "1", with: "someone") { id } }'};

async function proxied(t, definition, {config = CONFIG, Policy = ProxyPolicy} = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-locked-proxy-')), store = new Store({dataDir: dir});
  t.after(async () => { store.close(); await rm(dir, {recursive: true, force: true}); });
  const groups = new Map([['fixture', validatePermissionGroups(definition)]]), configs = new Map([['fixture', validateProxyConfig(config, {groups, allowedOrigins: ['https://api.example.com']})]]);
  store.put('connections', {id: 'acct', appId: 'fixture', driver: 'http', authMethod: 'token', authRevision: 'r1', status: 'ready', identity: {id: 'u'}, allowedOrigins: ['https://api.example.com'], createdAt: '2026-10-17T00:00:00.000Z'});
  const policy = new Policy({store, permissions: new PermissionManager({store, groups, configs}), groups, configs});
  return {store, policy, decide: (method, route, body) => policy.decide('acct', {method, path: route, ...(body !== undefined ? {body} : {})}), entry: row => policy.rows(policy.route('acct')).find(item => item.row === row)};
}

test('T4 proxy: a locked row offers Never only, Ask is refused in Fabric\'s words, and a forged saved Ask reads as Never', async t => {
  const {store, policy, decide, entry} = await proxied(t, FENCED), row = 'group:fixture.access.grant';
  assert.deepEqual([entry(row).allowedModes, entry(row).defaultMode, entry(row).locked, entry(row).audience], [['deny'], 'deny', true, false]);
  assert.deepEqual([entry('group:fixture.items.edit').allowedModes, entry('group:fixture.items.edit').locked, entry('group:fixture.items.edit').audience], [['ask', 'deny'], false, true]);
  for (const mode of ['ask', 'allow']) assert.throws(() => policy.set({connectionId: 'acct', row, mode, confirmAllow: true}), error => error.code === 'invalid_request' && LOCK.test(error.message), mode);
  assert.equal(store.list('permissions').length, 0, 'nothing was saved');
  store.put('permissions', {id: policy.policyId('acct', row), kind: 'proxy-row', connectionId: 'acct', row, mode: 'ask', bindingHash: policy.binding(policy.route('acct'), row), revision: 'forged', updatedAt: '2026-10-17T00:00:00.000Z'});
  const decided = decide('PUT', '/items/1/share', {with: 'someone'});
  assert.deepEqual([decided.row, decided.mode, decided.executable, decided.locked], [row, 'deny', false, true]);
  assert.match(decided.reason, LOCK); assert.doesNotMatch(decided.reason, /developer environments/);
  const view = policy.view('acct'), shown = id => view.find(item => item.row === id);
  assert.deepEqual([shown(row).locked, shown(row).mode, shown(row).allowedModes, 'audience' in shown(row)], [true, 'deny', ['deny'], false]);
  assert.deepEqual([shown('group:fixture.items.edit').audience, 'locked' in shown('group:fixture.items.edit')], [true, false]);
  assert.ok(!('locked' in shown('group:fixture.items.read')) && !('audience' in shown('group:fixture.items.read')) && !('locked' in shown('graphql')));
  policy.set({connectionId: 'acct', row, mode: 'deny'});
  assert.equal(store.get('permissions', policy.policyId('acct', row)).followsDefault, true, 'Never follows the default of a locked row');
});

test('T4 proxy: a request that fits a locked template is Never wherever it best matches (t4_locked), alias forms included', async t => {
  const fenced = await proxied(t, FENCED), open = await proxied(t, OPEN);
  const special = fenced.decide('PUT', '/items/special/share', {with: 'someone'});
  assert.deepEqual([special.row, special.mode, special.clamps, special.locked], ['group:fixture.items.edit', 'deny', ['t4_locked'], true]);
  assert.match(special.reason, LOCK);
  const control = open.decide('PUT', '/items/special/share', {with: 'someone'});
  assert.deepEqual([control.row, control.mode, control.clamps, 'locked' in control], ['group:fixture.items.edit', 'ask', [], false]);
  assert.equal(open.decide('PUT', '/items/1/share', {}).mode, 'ask', 'the control: the same row before the lock');
  for (const route of ['/items/1/share', '/items/1/hooks']) {
    const method = route.endsWith('share') ? 'PUT' : 'POST', direct = fenced.decide(method, route, {});
    assert.deepEqual([direct.row, direct.mode, direct.locked], ['group:fixture.access.grant', 'deny', true], route);
  }
  const unlocked = open.decide('PATCH', '/items/1', {title: 'x'}), plain = fenced.decide('PATCH', '/items/1', {title: 'x'});
  assert.deepEqual([plain.mode, plain.clamps, 'locked' in plain, plain.audience], ['ask', [], false, true]);
  assert.equal(unlocked.policyHash, plain.policyHash, 'locked and audience stay out of the policy hash of an unlocked row');
  const aliased = await proxied(t, FENCED, {config: {...CONFIG, aliases: [{from: '/items/{id}', to: '/things/{thing_id}'}]}});
  const viaAlias = aliased.decide('PUT', '/things/1/share', {});
  assert.deepEqual([viaAlias.row, viaAlias.mode, viaAlias.locked], ['group:fixture.access.grant', 'deny', true]);
  const templates = aliased.policy.route('acct').templates.filter(template => !template.unreviewed);
  assert.deepEqual(templates.filter(template => template.locked).map(template => template.request).sort(), ['POST /items/{item_id}/hooks', 'PUT /items/{id}/share', 'PUT /things/{thing_id}/share']);
  assert.ok(templates.every(template => typeof template.locked === 'boolean'));
});

test('T4 proxy: an app with a locked row keeps its GraphQL row Never in every deployment; an app without one still offers Ask', async t => {
  const fenced = await proxied(t, FENCED), open = await proxied(t, OPEN);
  assert.deepEqual([fenced.entry('graphql').allowedModes, fenced.entry('graphql').defaultMode], [['deny'], 'deny']);
  assert.deepEqual(open.entry('graphql').allowedModes, ['ask', 'deny']);
  const locked = fenced.decide('POST', '/graphql', MUTATION);
  assert.deepEqual([locked.row, locked.mode, locked.executable, locked.locked], ['graphql', 'deny', false, true]); assert.match(locked.reason, LOCK);
  assert.throws(() => fenced.policy.set({connectionId: 'acct', row: 'graphql', mode: 'ask'}), error => error.code === 'invalid_request');
  open.policy.set({connectionId: 'acct', row: 'graphql', mode: 'ask'});
  const asked = open.decide('POST', '/graphql', MUTATION);
  assert.deepEqual([asked.mode, 'locked' in asked], ['ask', false]);
});

test('T4 proxy: an exact tie between a locked template and a delete template lands in the locked row, wherever it is listed', () => {
  const trash = {id: 'x.trash', label: 'Trash', effect: 'delete', operations: [], requests: ['DELETE /items/{id}'], reviewedReads: []};
  const grant = {id: 'x.grant', label: 'Grant', effect: 'write', locked: 'fabric', operations: [], requests: ['DELETE /items/{item}'], reviewedReads: []};
  const edit = {id: 'x.edit', label: 'Edit', effect: 'write', operations: [], requests: ['DELETE /items/{key}'], reviewedReads: []};
  const land = groups => matchRequest(templatesFor({groups}, {style: 'rest'}), {method: 'DELETE', segments: ['items', '1']});
  for (const groups of [[trash, grant, edit], [grant, trash, edit], [trash, edit, grant]]) {
    const match = land(groups);
    assert.deepEqual([match.groupId, match.effect, match.ambiguous], ['x.grant', 'delete', true], groups.map(group => group.id).join());
  }
  assert.equal(land([trash, {...grant, locked: undefined}, edit]).groupId, 'x.trash', 'the control: without the lock the strongest effect wins');
});

// ---- grants, holds and handoffs (part h) ------------------------------------------------------------------------------
// The shared handoff fixture (GitHub on a synthetic provider) with its rows injected into the runtime: the createIssue request
// moves into a locked row, or gains a route, so a grant or a handoff made before can be compared with one made after.
const ISSUE = 'POST /repos/{owner}/{repo}/issues', AGENT_WORDS = 'Fabric never lets agents run this operation: it gives access to other people or services.';
const githubRows = change => {
  const raw = JSON.parse(JSON.stringify(PERMISSION_GROUPS.get('github')));
  return new Map([...PERMISSION_GROUPS, ['github', validatePermissionGroups({...raw, schemaVersion: 2, groups: change(raw.groups)})]]);
};
// The request joins GitHub's locked row (the shipped one, with its members).
const LOCK_ISSUES = githubRows(groups => [...groups.filter(group => group.id !== 'github.access.grant').map(group => ({...group, requests: group.requests.filter(request => request !== ISSUE)})),
  {id: 'github.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', locked: 'fabric', requests: [...(groups.find(group => group.id === 'github.access.grant')?.requests ?? []), ISSUE]}]);
const ROUTE_ISSUES = githubRows(groups => groups.map(group => group.requests.includes(ISSUE) ? {...group, bodyRoutes: [{member: ISSUE, pointer: '/title', equals: 'delete everything', to: 'github.permanent.delete'}]} : group));
const ROUTED_WORDS = 'This change belongs to "Permanently delete repos, comments, releases and gists". Use that operation instead. Nothing was sent.';
const useRows = (f, groups) => { f.runtime.permissions.groups = groups; f.runtime.proxyPolicy.groups = groups; };

test('T4 grants: no client grant takes a locked binding, request-only entry or proxy row; one made before the lock lists the member unavailable', async t => {
  const f = await handoffFixture(t);
  f.account('acct-a', '101');
  const before = f.grant({bindings: [{connectionId: 'acct-a', capabilityId: f.write.id}]});
  useRows(f, LOCK_ISSUES);
  const refused = (data, words) => assert.throws(() => f.protocol.createClient({name: 'Agent', bindings: [], ...data}, LOCAL_OWNER), error => error.code === 'permission_denied' && error.message === words, JSON.stringify(data));
  refused({bindings: [{connectionId: 'acct-a', capabilityId: f.write.id}]}, 'Fabric keeps this off: it gives access to other people or services. No setting can turn it on.');
  refused({requestable: [{capabilityId: f.write.id}]}, AGENT_WORDS);
  refused({proxy: [{connectionId: 'acct-a', rows: ['group:github.access.grant']}]}, 'Fabric keeps this off: it gives access to other people or services. No setting can turn it on.');
  assert.equal(f.store.list('clientGrants').length, 1, 'nothing more was granted');
  assert.ok(f.protocol.createClient({name: 'Reader', bindings: [{connectionId: 'acct-a', capabilityId: f.read.id}], requestable: [{capabilityId: f.read.id}], proxy: [{connectionId: 'acct-a', rows: ['group:github.issues.write']}]}, LOCAL_OWNER).token, 'the controls');
  const listed = (await f.invoke(before.token, 'capabilities.list')).result.capabilities, of = connectionId => listed.find(item => item.id === f.write.id && item.connectionId === connectionId);
  assert.deepEqual([of('acct-a').status, of('acct-a').reason], ['unavailable', 'permission_denied'], 'the binding');
  assert.deepEqual([of(null).status, of(null).reason], ['unavailable', 'permission_denied'], 'the request-only entry');
  assert.equal(listed.find(item => item.id === f.read.id).status, 'connection_required');
});

test('T4 handoffs: a locked operation or a routed body makes no handoff; an open handoff whose operation becomes locked closes as policy_denied', async t => {
  const f = await handoffFixture(t);
  const {client, token} = f.grant(), args = {owner: 'o', repo: 'r', body: {title: 't'}};
  const open = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'before')).result;
  assert.equal(open.status, 'awaiting_connection');
  useRows(f, ROUTE_ISSUES);
  assert.deepEqual((await f.invoke(token, 'calls.create', f.ask(client, f.write, {...args, body: {title: 'Delete Everything'}}), 'routed')).error, {code: 'invalid_request', message: ROUTED_WORDS});
  assert.equal((await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'not-routed')).result.status, 'awaiting_connection', 'the control: an ordinary body');
  useRows(f, LOCK_ISSUES);
  assert.deepEqual((await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'locked')).error, {code: 'permission_denied', message: AGENT_WORDS});
  assert.deepEqual(f.store.list('protocolRequests').map(entry => entry.requestId).sort(), ['before', 'not-routed'], 'a refused request reserves nothing');
  const closed = (await f.invoke(token, 'calls.get', {callId: open.id})).result;
  assert.deepEqual([closed.status, closed.handoff.state, closed.handoff.outcome, closed.handoff.url], ['failed', 'closed', 'policy_denied', null]);
  assert.deepEqual([f.store.get(CONTINUATIONS, open.id).status, f.store.get(CONTINUATIONS, open.id).outcome.code], ['failed', 'policy_denied']);
  assert.equal(f.service.ownerList().filter(row => row.status === 'awaiting_owner').length, 0, 'the owner has nothing left to answer');
  assert.deepEqual([f.jobs().length, f.calls.length], [0, 0]);
});

test('T4 handoffs: a route or a lock met only when the account is bound closes the handoff as policy_denied, never authority_changed', async t => {
  const f = await handoffFixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const routed = (await f.invoke(token, 'calls.create', f.ask(client, f.write, {owner: 'o', repo: 'r', body: {title: 'delete everything'}}), 'routed')).result;
  const locked = (await f.invoke(token, 'calls.create', f.ask(client, f.write, {owner: 'o', repo: 'r', body: {title: 't'}}), 'locked')).result;
  useRows(f, ROUTE_ISSUES);
  await assert.rejects(f.select(routed.id, 'acct-a'), error => error.code === 'policy_denied');
  assert.equal(f.store.get(CONTINUATIONS, routed.id).outcome.code, 'policy_denied');
  // A lock refusal is read by its mark (permission_denied with locked), not its words: they name no permission.
  f.runtime.prepareJob = async () => { throw Object.assign(new Error('Fabric keeps this off: it gives access to other people or services. No setting can turn it on.'), {code: 'permission_denied', locked: true}); };
  await assert.rejects(f.select(locked.id, 'acct-a'), error => error.code === 'policy_denied');
  assert.equal(f.store.get(CONTINUATIONS, locked.id).outcome.code, 'policy_denied');
  assert.deepEqual([f.jobs().length, f.calls.length], [0, 0]);
});

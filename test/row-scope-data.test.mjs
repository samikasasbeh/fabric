import test from 'node:test';
import assert from 'node:assert/strict';
import {readdirSync, readFileSync} from 'node:fs';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {validatePermissionGroups, memberOf, memberData, UNAVAILABLE_REASONS, CONDITION_WORDS, PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PermissionManager, providerAccessOf, scopeSetsOf, scopeAlternatives} from '../lib/permissions.mjs';
import * as closures from '../lib/access-closure.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {Store} from '../lib/store.mjs';
import {LOCK_WORDS} from '../lib/row-locks.mjs';
import {validateAuthDefinition, normalizeAuthApp, effectiveScopes} from '../contracts/auth-definition.mts';
import {fixture, owner} from './fixtures/continuation-fixture.mjs';
import {CONTINUATIONS} from '../lib/continuations.mjs';
import {definitions, definitionOf, rows, stripped, FIXTURE_APPS, F10_6_KEYS} from './fixtures/access/f10-6-fixtures.mjs';

// F10.6 row scope data (docs/F10-FIVE-APPS-DEEP.md section F10.6, T3; docs/F10.6-BUILD-MAP.md section 4 and its corrections). Every
// row can say which scopes its members need and which members can never work through a sign-in. The loader (part b), the one
// reading of member access (part c), typed and proxied decisions (parts d and e) and the closure (part j) run on fixture rows and
// the shipped markers. Fixture rows and definitions from test/fixtures/access/f10-6-fixtures.mjs, synthetic accounts, no network:
// every case counts what was sent.
const G = 'https://www.googleapis.com/auth/', GMAIL = 'https://gmail.googleapis.com';
const FACTS = JSON.parse(readFileSync(new URL('./fixtures/access/google-method-scopes.json', import.meta.url), 'utf8'));
// F10.7: a version 2 row has the version 1 fields but the decorative scopes, which is a version 1 field only.
const EIGHT = ['id', 'label', 'effect', 'defaultMode', 'stayInAccount', 'operations', 'requests', 'reviewedReads'];
const at = (definition, id) => definition.groups.find(group => group.id === id);

// ---- the loader (part b) ------------------------------------------------------------------------------------------------
const ROWS = {schemaVersion: 2, appId: 'fixture', groups: [
  {id: 'fixture.items.read', label: 'See items', effect: 'read', defaultMode: 'allow', operations: ['items.list'], requests: ['GET /items/{id}', 'GET /files/{+path}']},
  {id: 'fixture.items.edit', label: 'Edit items', effect: 'write', defaultMode: 'ask', requests: ['PATCH /items/{id}', 'POST /items'], bodyRoutes: [{member: 'PATCH /items/{id}', pointer: '/share', present: true, to: 'fixture.access.grant'}]},
  {id: 'fixture.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', locked: 'fabric', requests: ['PUT /items/{id}/share']}]};
const DATA = {scopeSets: [['items.read', 'items.read'], ['items', 'all']], memberScopeSets: {'items.list': [['items.list']], 'GET /files/{+path}': [[]]}, unavailable: {'GET /items/{id}': 'not-requested'},
  conditions: {'items.list': ['plan-dependent', 'beta', 'beta']}, conditionalScopes: {'files.write': 'Needed only to change files.'}, unsupported: {'GET /files/{path}': 'It cannot carry a whole file.'}};
const SAMPLE = {'scopeSets': [['a']], memberScopeSets: {'items.list': [['a']]}, unavailable: {'items.list': 'not-requested'}, conditions: {'items.list': ['beta']}, conditionalScopes: {b: 'Sometimes.'}, unsupported: {'items.list': 'No.'}};
const withData = (data, id = 'fixture.items.read', definition = ROWS) => ({...definition, groups: definition.groups.map(group => group.id === id ? {...group, ...structuredClone(data)} : group)});
const bad = (data, pattern, message = JSON.stringify(data), id = 'fixture.items.read') => assert.throws(() => validatePermissionGroups(withData(data, id)), pattern, message);

test('each F10.6 key needs schemaVersion 2', () => {
  const v1 = {schemaVersion: 1, appId: 'fixture', groups: ROWS.groups.filter(group => !group.locked).map(({bodyRoutes, ...group}) => group)};
  assert.equal(validatePermissionGroups(v1).schemaVersion, 1);
  for (const key of F10_6_KEYS) assert.throws(() => validatePermissionGroups(withData({[key]: SAMPLE[key]}, 'fixture.items.read', v1)), /needs schemaVersion 2/, key);
});

test('a version 2 row keeps every F10.6 key, checked, frozen and keyed by member key, before its body routes', () => {
  const definition = validatePermissionGroups(withData({unavailable: {'POST /items': 'no-oauth-scope'}}, 'fixture.items.edit', withData(DATA))), read = at(definition, 'fixture.items.read');
  assert.deepEqual(Object.keys(read), [...EIGHT, ...F10_6_KEYS]);
  assert.deepEqual(read.scopeSets, [['items.read'], ['all', 'items']], 'each alternative de-duplicated and sorted, the alternatives in their order');
  assert.deepEqual(read.memberScopeSets, {'items.list': [['items.list']], 'GET /files/{path}': [[]]}, '[[]] is "no scope; the provider decides"');
  assert.deepEqual([read.unavailable, read.conditions, read.conditionalScopes, read.unsupported], [{'GET /items/{id}': 'not-requested'}, {'items.list': ['beta', 'plan-dependent']},
    {'files.write': 'Needed only to change files.'}, {'GET /files/{path}': 'It cannot carry a whole file.'}]);
  assert.ok(!Object.hasOwn(read, 'scopes'), 'no scopes are derived from the sets (correction 7), and version 2 emits none (F10.7)');
  const frozen = value => Object.isFrozen(value) && Object.values(value).every(item => item === null || typeof item !== 'object' || frozen(item));
  assert.ok(frozen(read), 'deeply frozen');
  assert.deepEqual(Object.keys(at(definition, 'fixture.items.edit')), [...EIGHT, 'unavailable', 'bodyRoutes'], 'the extras come before bodyRoutes');
  const locked = at(validatePermissionGroups(withData({unavailable: {'PUT /items/{id}/share': 'service-account-only'}, scopeSets: [['items.share']]}, 'fixture.access.grant')), 'fixture.access.grant');
  assert.deepEqual(Object.keys(locked), [...EIGHT, 'locked', 'scopeSets', 'unavailable']);
  assert.deepEqual(Object.keys(at(validatePermissionGroups(ROWS), 'fixture.items.read')), EIGHT, 'a row without the new keys keeps its exact output');
  assert.equal(at(validatePermissionGroups(withData({scopeSets: [[]]})), 'fixture.items.read').scopeSets[0].length, 0);
  assert.deepEqual(at(validatePermissionGroups(withData({scopeSets: Array.from({length: 32}, (_, index) => Array.from({length: 32}, (__, scope) => `s${index}.${scope}`))})), 'fixture.items.read').scopeSets.length, 32, '32 alternatives of 32 scopes');
});

test('the loader refuses scope data it cannot read one way', () => {
  for (const scopeSets of [[], 'a', [['a', '']], [['x'.repeat(501)]], [[7]], [['a'], 'b'], Array.from({length: 33}, () => ['a']), [Array.from({length: 33}, (_, index) => `s${index}`)], null])
    bad({scopeSets}, /scopeSets must list 1 to 32 alternatives/);
  bad({memberScopeSets: {'items.list': []}}, /memberScopeSets for items\.list must list 1 to 32 alternatives/);
  for (const key of ['memberScopeSets', 'unavailable', 'conditions', 'unsupported']) {
    for (const value of [{}, [], null, 'items.list']) bad({[key]: value}, new RegExp(`${key} must name at least one member`), `${key} ${JSON.stringify(value)}`);
    bad({[key]: {'GET /other': SAMPLE[key]['items.list']}}, /GET \/other is in fixture\.items\.read .* but is not a member of fixture\.items\.read/, key);
    bad({[key]: {'GET /files/{+path}': SAMPLE[key]['items.list'], 'GET /files/{path}': SAMPLE[key]['items.list']}}, /names GET \/files\/\{path\} twice/, key);
  }
  for (const reason of ['bot-only', '', 7, ['not-requested'], 'NOT-REQUESTED', 'toString', '__proto__']) bad({unavailable: {'items.list': reason}}, /marks items\.list unavailable for an unknown reason/, String(reason));
  for (const conditions of [[], ['beta', 'gamma'], 'beta', [7], null]) bad({conditions: {'items.list': conditions}}, /conditions for items\.list must be a list drawn from beta and plan-dependent/, JSON.stringify(conditions));
  for (const words of ['', '   ', 'x'.repeat(201), 7, null]) {
    bad({unsupported: {'items.list': words}}, /needs a reason of 1 to 200 characters/, JSON.stringify(words));
    bad({conditionalScopes: {'files.write': words}}, /needs a reason of 1 to 200 characters/, JSON.stringify(words));
  }
  for (const value of [{}, [], null, Object.fromEntries(Array.from({length: 17}, (_, index) => [`s${index}`, 'Sometimes.']))]) bad({conditionalScopes: value}, /conditionalScopes must name 1 to 16 scopes/);
  for (const scope of ['x'.repeat(501), '']) bad({conditionalScopes: {[scope]: 'Sometimes.'}}, /conditionalScopes must name 1 to 16 scopes/);
  bad({scopeSets: [['a'], ['files.write']], conditionalScopes: {'files.write': 'Sometimes.'}}, /lists files\.write as conditional, but its scope sets already ask for it/);
  bad({memberScopeSets: {'items.list': [['files.write', 'x']]}, conditionalScopes: {'files.write': 'Sometimes.'}}, /already ask for it/);
  bad({conditionalScopes: {'items.share': 'Sometimes.'}}, /locked by Fabric, so it has no conditional scopes/, 'a locked row', 'fixture.access.grant');
  for (const other of [{unsupported: {'GET /items/{id}': 'No.'}}, {memberScopeSets: {'GET /items/{id}': [['a']]}}, {conditions: {'GET /items/{id}': ['beta']}}])
    bad({unavailable: {'GET /items/{id}': 'not-requested'}, ...other}, /GET \/items\/\{id\} is unavailable in fixture\.items\.read, so it cannot also be unsupported, have scope sets or carry conditions/, JSON.stringify(other));
});

test('F10.7: scopes is a version 1 field; a version 2 row refuses it in any form and never emits it, and the catalog carries none', () => {
  for (const scopes of [['a'], [], 'a', [7], null]) bad({scopes}, /fixture\.items\.read carries scopes, but scopes is a version 1 field/, JSON.stringify(scopes));
  bad({scopes: ['a'], scopeSets: [['a']]}, /scopes is a version 1 field/, 'beside scope sets');
  bad({scopes: ['a'], memberScopeSets: {'items.list': [['a']]}}, /scopes is a version 1 field/, 'beside member scope sets');
  bad({scopes: [], unavailable: {'items.list': 'not-requested'}}, /scopes is a version 1 field/, 'beside markers alone');
  bad({scopes: ['a']}, /scopes is a version 1 field/, 'on a locked row', 'fixture.access.grant');
  // A version 1 file keeps the field: checked as strings and emitted in its place, as before F10.3.
  const v1 = {schemaVersion: 1, appId: 'fixture', groups: ROWS.groups.filter(group => !group.locked).map(({bodyRoutes, ...group}) => group)};
  const kept = at(validatePermissionGroups({...v1, groups: v1.groups.map((group, index) => index ? group : {...group, scopes: ['b', 'a', 'a']})}), 'fixture.items.read');
  assert.deepEqual([Object.keys(kept), kept.scopes], [['id', 'label', 'effect', 'defaultMode', 'stayInAccount', 'operations', 'requests', 'scopes', 'reviewedReads'], ['b', 'a', 'a']]);
  assert.deepEqual(at(validatePermissionGroups(v1), 'fixture.items.edit').scopes, [], 'a version 1 row without scopes still emits an empty list');
  for (const scopes of [[7], 'a', [''], null]) assert.throws(() => validatePermissionGroups({...v1, groups: v1.groups.map((group, index) => index ? group : {...group, scopes})}), /fixture\.items\.read scopes must be strings/, JSON.stringify(scopes));
  // The 63 decorative keys left the five shipped rows files; nothing loaded carries the field.
  const directory = new URL('../catalog/permissions/', import.meta.url);
  for (const name of readdirSync(directory).filter(file => file.endsWith('.json'))) {
    const raw = JSON.parse(readFileSync(new URL(name, directory), 'utf8'));
    assert.equal(raw.schemaVersion, 2, name);
    assert.deepEqual(raw.groups.filter(group => Object.hasOwn(group, 'scopes')).map(group => group.id), [], `${name} carries no decorative scopes`);
  }
  for (const [appId, definition] of PERMISSION_GROUPS) assert.ok(definition.groups.every(group => !Object.hasOwn(group, 'scopes')), appId);
});

test('correction 7: what the loader returns loads again to the same thing, for every fixture app and the shipped catalog', () => {
  const again = definition => {const once = validatePermissionGroups(definition); assert.equal(JSON.stringify(validatePermissionGroups(once)), JSON.stringify(once), definition.appId); return once;};
  again(withData(DATA)); again(ROWS);
  for (const appId of FIXTURE_APPS) {
    const definition = again(rows(appId));
    assert.ok(definition.groups.every(group => !Object.hasOwn(group, 'scopes')), `${appId}: no derived scopes, and no decorative scopes in version 2 output`);
    assert.equal(JSON.stringify(again(stripped(rows(appId))).groups.map(group => group.id)), JSON.stringify(definition.groups.map(group => group.id)));
  }
  for (const [appId, definition] of PERMISSION_GROUPS) assert.equal(JSON.stringify(validatePermissionGroups(definition)), JSON.stringify(definition), appId);
});

test('memberOf and memberData: one member key for every reader; a member\'s own sets, else its row\'s', () => {
  const definition = validatePermissionGroups(withData(DATA)), read = at(definition, 'fixture.items.read'), plain = at(definition, 'fixture.items.edit');
  assert.equal(memberOf(read, {id: 'items.list', method: 'GET', path: '/items'}), 'items.list', 'a member by operation id');
  assert.equal(memberOf(read, {id: 'whatever', method: 'get', path: '/files/{+path}'}), 'GET /files/{path}', 'a member by request, as its member key');
  assert.equal(memberOf(read, {id: 'whatever'}), null); assert.equal(memberOf(null, {id: 'items.list'}), null); assert.equal(memberOf(read, null), null);
  assert.deepEqual(memberData(read, 'items.list'), {scopeSets: [['items.list']], unavailable: null, unsupported: null, conditions: ['beta', 'plan-dependent']});
  assert.deepEqual(memberData(read, 'GET /files/{+path}'), {scopeSets: [[]], unavailable: null, unsupported: 'It cannot carry a whole file.', conditions: null});
  assert.deepEqual(memberData(read, 'GET /items/{id}'), {scopeSets: [['items.read'], ['all', 'items']], unavailable: 'not-requested', unsupported: null, conditions: null});
  for (const member of ['__proto__', 'constructor', 'toString', 7, null]) assert.deepEqual(memberData(read, member), {scopeSets: read.scopeSets, unavailable: null, unsupported: null, conditions: null}, String(member));
  assert.deepEqual(memberData(plain, 'POST /items'), {scopeSets: null, unavailable: null, unsupported: null, conditions: null});
  assert.deepEqual(memberData(null, 'POST /items'), {scopeSets: null, unavailable: null, unsupported: null, conditions: null});
  assert.deepEqual(Object.keys(UNAVAILABLE_REASONS).sort(), ['bot-token-only', 'client-credentials-only', 'no-oauth-scope', 'not-requested', 'service-account-only', 'workspace-cse-only']);
  assert.equal(UNAVAILABLE_REASONS['service-account-only'], 'Google allows this only for a service account acting for a whole domain. A sign-in can never use it.');
  assert.equal(UNAVAILABLE_REASONS['not-requested'], 'Fabric never asks for the permission this needs.');
  assert.deepEqual(CONDITION_WORDS, {beta: 'In beta at the provider. It may change or stop working.', 'plan-dependent': 'Works only on some of the provider\'s plans.'});
  assert.ok(Object.isFrozen(UNAVAILABLE_REASONS) && Object.isFrozen(CONDITION_WORDS));
});

test('the fixture definitions are valid version 2 definitions, and the fixture rows load', () => {
  for (const [providerId, definition] of Object.entries(definitions)) assert.equal(validateAuthDefinition(definitionOf(providerId)).schemaVersion, 2, providerId);
  assert.ok(Object.isFrozen(definitions.github.apps[0].access.levels.full.optional));
  const counts = Object.fromEntries(FIXTURE_APPS.map(appId => [appId, validatePermissionGroups(rows(appId)).groups.flatMap(group => Object.values(group.unavailable ?? {})).length]));
  // F10.7 part e: GitHub's never-requested deletes and locked-row members, and Slack's admin and app-setup methods, say why.
  assert.deepEqual(counts, {gmail: 24, 'google-calendar': 0, github: 68, notion: 3, slack: 182});
});

// ---- one reading of member access (part c) ----------------------------------------------------------------------------
test('providerAccessOf: granted when a named alternative is held, unknown for a zero-scope alternative or no OAuth grant, else missing', () => {
  const oauth = {authMethod: 'oauth'};
  assert.equal(providerAccessOf(oauth, [['a'], ['b', 'c']], ['b', 'c']), 'granted');
  assert.equal(providerAccessOf(oauth, [['a'], ['b', 'c']], ['b']), 'missing', 'an alternative counts only whole');
  assert.equal(providerAccessOf(oauth, [['a'], []], ['b']), 'unknown', 'a zero-scope alternative is not evidence of consent');
  assert.equal(providerAccessOf(oauth, [['a'], []], ['a']), 'granted');
  for (const sets of [[[]], [], null, undefined]) assert.equal(providerAccessOf(oauth, sets, ['a']), 'unknown', JSON.stringify(sets));
  for (const connection of [{authMethod: 'token'}, {authMethod: 'browser'}, {}, null]) assert.equal(providerAccessOf(connection, [['a']], ['a']), 'unknown', JSON.stringify(connection));
  // The account's scopes are read only when they decide something: a token account or no data never asks for them.
  let reads = 0;
  const held = list => () => {reads++; return list;};
  assert.equal(providerAccessOf({authMethod: 'token'}, [['a']], held(['a'])), 'unknown');
  assert.equal(providerAccessOf(oauth, [], held(['a'])), 'unknown');
  assert.equal(reads, 0);
  assert.equal(providerAccessOf(oauth, [['a']], held(['a'])), 'granted'); assert.equal(providerAccessOf(oauth, [['b']], held(['a'])), 'missing');
  assert.equal(reads, 2);
});

test('scopeSetsOf: Discovery wins wherever the map has scope data, malformed data included; row sets only where it is silent', () => {
  const row = {scopeSets: [['row.scope']]};
  assert.deepEqual(scopeSetsOf({requiredScopes: ['b', 'a', 'a']}, row), {requiredScopes: ['a', 'b'], scopeSets: [['a'], ['b']], invalid: false});
  assert.deepEqual(scopeSetsOf({scopeSets: [['y', 'x']]}, row), scopeAlternatives({scopeSets: [['y', 'x']]}));
  assert.deepEqual(scopeSetsOf({requiredScopes: 'repo'}, row), {requiredScopes: [], scopeSets: [], invalid: true}, 'malformed Discovery is never read around');
  assert.deepEqual(scopeSetsOf({scopeSets: [['a', 7]]}, row).invalid, true);
  for (const operation of [{}, {requiredScopes: []}, {scopeSets: []}, null, undefined]) assert.deepEqual(scopeSetsOf(operation, row), {requiredScopes: [], scopeSets: [['row.scope']], invalid: false}, JSON.stringify(operation));
  assert.deepEqual(scopeSetsOf({}, {scopeSets: [[]]}).scopeSets, [[]]);
  for (const data of [null, undefined, {scopeSets: null}, {}]) assert.deepEqual(scopeSetsOf({}, data), {requiredScopes: [], scopeSets: [], invalid: false}, JSON.stringify(data));
  const frozen = memberData(at(validatePermissionGroups(withData(DATA)), 'fixture.items.read'), 'GET /items/{id}'), copy = scopeSetsOf(null, frozen).scopeSets;
  copy[0].push('changed'); copy.push(['changed']);
  assert.deepEqual(frozen.scopeSets, [['items.read'], ['all', 'items']], 'a caller gets copies');
});

test('decision() reads provider access the one way, through the account\'s grant with what a granted parent grants (F10.5)', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-row-scope-')), store = new Store({dataDir: dir});
  t.after(async () => {store.close(); await rm(dir, {recursive: true, force: true});});
  const caps = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
    '/user/orgs': {get: {operationId: 'listOrgs', responses: {200: {description: 'ok'}}}}, '/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'ok'}}}}}}}).capabilities.map(cap => ({...cap, status: 'active'}));
  for (const cap of caps) store.put('capabilities', cap);
  const orgs = caps.find(cap => cap.name === 'listOrgs'), repos = caps.find(cap => cap.name === 'listRepos');
  store.put('applicationMaps', {id: 'github', operations: [{id: 'GET /user/orgs', capabilityId: orgs.id, method: 'GET', path: '/user/orgs', requiredScopes: ['read:org']},
    {id: 'GET /user/repos', capabilityId: repos.id, method: 'GET', path: '/user/repos', scopeSets: [[]]}]});
  const account = extra => store.put('connections', {id: 'hub', appId: 'github', driver: 'http', authMethod: 'oauth', status: 'ready', authRevision: 'r1', identity: {id: 'u'}, allowedOrigins: ['https://api.github.com'], createdAt: '2026-10-18T00:00:00.000Z', ...extra});
  const reading = normalizeAuthApp(definitions.github, definitions.github.apps[0]);
  const implied = new PermissionManager({store, scopesOf: connection => effectiveScopes(reading, connection.scopes)}), literal = new PermissionManager({store});
  account({scopes: ['read:user', 'admin:org']});
  const decide = (manager, cap) => manager.decision(store.get('connections', 'hub'), cap);
  assert.deepEqual([decide(implied, orgs).providerAccess, decide(implied, orgs).executable], ['granted', true], 'admin:org grants read:org');
  assert.deepEqual([decide(literal, orgs).providerAccess, decide(literal, orgs).executable], ['missing', false], 'read literally, it does not');
  assert.equal(decide(implied, repos).providerAccess, 'unknown', 'a zero-scope alternative');
  account({scopes: ['read:org']});
  assert.equal(decide(literal, orgs).providerAccess, 'granted');
  account({authMethod: 'token', scopes: []});
  assert.deepEqual([decide(implied, orgs).providerAccess, decide(implied, orgs).executable], ['unknown', true], 'a token account says nothing about scopes');
});

// ---- typed decisions on fixture rows (part d) ------------------------------------------------------------------------------
// Gmail is reviewed by operation id, so the stored map is the one recorded for F10.3 (every reviewed operation) with the real
// paths of the members these cases run, their Discovery scopes from the facts fixture, and messages.modify left without any.
const RECORDED = JSON.parse(readFileSync(new URL('./fixtures/access/f10-3-bindings.before.json', import.meta.url), 'utf8')).maps.gmail.operations;
const REAL = {'gmail.users.settings.delegates.list': ['GET', '/gmail/v1/users/{userId}/settings/delegates'], 'gmail.users.settings.cse.identities.list': ['GET', '/gmail/v1/users/{userId}/settings/cse/identities'],
  'gmail.users.settings.updateAutoForwarding': ['PUT', '/gmail/v1/users/{userId}/settings/autoForwarding'], 'gmail.users.labels.create': ['POST', '/gmail/v1/users/{userId}/labels'],
  'gmail.users.drafts.create': ['POST', '/gmail/v1/users/{userId}/drafts'], 'gmail.users.messages.modify': ['POST', '/gmail/v1/users/{userId}/messages/{id}/modify'],
  'gmail.users.messages.trash': ['POST', '/gmail/v1/users/{userId}/messages/{id}/trash']};
const SILENT = ['gmail.users.messages.modify', 'gmail.users.messages.trash'];
const P = name => ({name, in: 'path', required: true, schema: {type: 'string'}});

async function world(t) {
  const f = await fixture(t), paths = {};
  for (const [id, [method, route]] of Object.entries(REAL)) paths[route] = {...paths[route], [method.toLowerCase()]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => P(match[1])),
    ...(method === 'GET' ? {} : {requestBody: {content: {'application/json': {schema: {type: 'object'}}}}}), responses: {200: {description: 'ok'}}}};
  const caps = Object.fromEntries(compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: GMAIL}], paths}}).capabilities.map(cap => [cap.name, {...cap, status: 'active'}]));
  for (const cap of Object.values(caps)) f.store.put('capabilities', cap);
  f.store.put('applicationMaps', {id: 'gmail', appId: 'gmail', operations: RECORDED.map(operation => {
    if (!caps[operation.id]) return operation;
    const [method, route] = REAL[operation.id];
    return {id: operation.id, capabilityId: caps[operation.id].id, method, path: route, ...(SILENT.includes(operation.id) ? {} : {requiredScopes: FACTS.apps.gmail.methods[operation.id]})};
  })});
  const created = new Date(f.now).toISOString();
  const account = (id, appId, origin, scopes, extra = {}) => f.store.put('connections', {id, appId, driver: 'http', authMethod: 'oauth', authRevision: `consent-${id}`, status: 'ready', label: id, identity: {id}, allowedOrigins: [origin], scopes, createdAt: created, ...extra});
  account('mail', 'gmail', GMAIL, [`${G}gmail.readonly`]);
  account('hub', 'github', 'https://api.github.com', ['read:user', 'repo']);
  account('chat', 'slack', 'https://slack.com', ['im:write']);
  account('pages', 'notion', 'https://api.notion.com', []);
  const use = (changes = {}) => {
    const groups = new Map([...PERMISSION_GROUPS, ...Object.entries(changes).map(([appId, definition]) => [appId, validatePermissionGroups(definition)])]);
    Object.assign(f.runtime.permissions, {groups}); Object.assign(f.runtime.proxyPolicy, {groups});
  };
  const w = {f, caps, use, account,
    scopes: (id, scopes) => f.store.put('connections', {...f.store.get('connections', id), scopes}),
    decide: (name, id = 'mail') => f.runtime.permissions.decision(f.store.get('connections', id), caps[name]),
    proxy: (id, request) => f.runtime.proxyPolicy.decide(id, request),
    accept: (id, request) => f.runtime.createProxyJob({connectionId: id, request}, owner)};
  return w;
}
const looserRow = (definition, id, change) => ({...definition, groups: definition.groups.map(group => group.id === id ? {...group, ...change} : group)});

test('decision(): an unavailable member under its row\'s default Allow is never executable and says why; Discovery alone would grant it', async t => {
  const w = await world(t);
  w.use({gmail: stripped(rows('gmail'))});
  const control = w.decide('gmail.users.settings.delegates.list');
  assert.deepEqual([control.providerAccess, control.executable, control.mode], ['granted', true, 'allow'], 'Discovery lists gmail.readonly for it');
  assert.ok(!('unavailable' in control));
  w.use({gmail: rows('gmail')});
  const decision = w.decide('gmail.users.settings.delegates.list');
  assert.deepEqual([decision.providerAccess, decision.executable, decision.mode, decision.defaultMode, decision.unavailable], ['unavailable', false, 'allow', 'allow', 'service-account-only']);
  assert.equal(decision.reason, UNAVAILABLE_REASONS['service-account-only']);
  assert.notEqual(decision.policyHash, control.policyHash, 'listed churn: providerAccess is hashed');
  assert.equal(decision.bindingHash, control.bindingHash, 'row data never enters a binding');
  // Grants and holds ask before an account exists: the reason code through the map, no connection needed.
  assert.deepEqual([w.f.runtime.permissions.unavailableOf(w.caps['gmail.users.settings.delegates.list']), w.f.runtime.permissions.unavailableOf(w.caps['gmail.users.labels.create'])], ['service-account-only', null]);
  // Every auth method (open question 8), and a connection that is not ready says the member can never work first.
  w.account('mail', 'gmail', GMAIL, [], {authMethod: 'token'});
  assert.deepEqual([w.decide('gmail.users.settings.delegates.list').providerAccess, w.decide('gmail.users.settings.delegates.list').executable], ['unavailable', false]);
  w.account('mail', 'gmail', GMAIL, [`${G}gmail.readonly`], {status: 'reconnect_required'});
  assert.equal(w.decide('gmail.users.settings.delegates.list').reason, UNAVAILABLE_REASONS['service-account-only']);
  assert.equal(w.decide('gmail.users.settings.cse.identities.list').reason, UNAVAILABLE_REASONS['workspace-cse-only']);
});

test('decision(): a member that is locked and unavailable keeps the lock words', async t => {
  const w = await world(t);
  w.use({gmail: rows('gmail')});
  const decision = w.decide('gmail.users.settings.updateAutoForwarding');
  assert.deepEqual([decision.locked, decision.mode, decision.executable, decision.providerAccess, decision.unavailable], [true, 'deny', false, 'unavailable', 'service-account-only']);
  assert.equal(decision.reason, LOCK_WORDS);
});

test('decision(): a row\'s unsupported member is unsupported with the row\'s words, and its capability keeps its bytes and id (I1)', async t => {
  const w = await world(t), cap = w.caps['gmail.users.drafts.create'], before = structuredClone(w.f.store.get('capabilities', cap.id));
  // F10.15's draft marker, which the shipped rows do not carry yet (F10.7 open question 20).
  const words = 'It cannot carry a whole message, and an update without one can blank the draft.', marked = looserRow(rows('gmail'), 'gmail.drafts.write', {unsupported: {'gmail.users.drafts.create': words}});
  w.scopes('mail', [`${G}gmail.modify`]);
  w.use({gmail: stripped(rows('gmail'))});
  assert.deepEqual([w.decide('gmail.users.drafts.create').status, w.decide('gmail.users.drafts.create').executable], ['active', true]);
  w.use({gmail: marked});
  const decision = w.decide('gmail.users.drafts.create');
  assert.deepEqual([decision.status, decision.executable, decision.capabilityId], ['unsupported', false, cap.id]);
  assert.equal(decision.reason, words);
  assert.deepEqual(w.f.store.get('capabilities', cap.id), before);
});

test('decision(): Discovery wins over row sets, and row sets apply only where the map is silent', async t => {
  const w = await world(t);
  w.use({gmail: rows('gmail')});
  w.scopes('mail', [`${G}gmail.labels`]);
  assert.deepEqual([w.decide('gmail.users.labels.create').providerAccess, w.decide('gmail.users.labels.create').scopeSets.length], ['granted', FACTS.apps.gmail.methods['gmail.users.labels.create'].length],
    'the row says gmail.modify, Discovery also takes gmail.labels');
  w.scopes('mail', [`${G}gmail.readonly`]);
  assert.deepEqual([w.decide('gmail.users.messages.modify').providerAccess, w.decide('gmail.users.messages.modify').scopeSets], ['missing', [[`${G}gmail.modify`]]], 'the map is silent: the row\'s sets');
  w.scopes('mail', [`${G}gmail.modify`]);
  assert.equal(w.decide('gmail.users.messages.modify').providerAccess, 'granted');
  w.use({gmail: stripped(rows('gmail'))});
  assert.deepEqual([w.decide('gmail.users.messages.modify').providerAccess, w.decide('gmail.users.messages.modify').scopeSets], ['unknown', []], 'no data anywhere');
});

test('decision(): a capability with no map entry reads the data of the member its request is, the most specific template winning (correction 3)', async t => {
  const w = await world(t), get = (operationId, ...names) => ({get: {operationId, parameters: names.map(P), responses: {200: {description: 'ok'}}}});
  const caps = Object.fromEntries(compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
    '/user/repos': get('listRepos'), '/user/{username}': get('getUser', 'username'), '/repositories/{id}/notifications': get('repoNotifications', 'id'),
    '/users/{username}/attestations/{attestation_id}': {delete: {operationId: 'deleteAttestation', parameters: [P('username'), P('attestation_id')], responses: {204: {description: 'gone'}}}}}}})
    .capabilities.map(cap => [cap.name, {...cap, status: 'active'}]));
  for (const cap of Object.values(caps)) w.f.store.put('capabilities', cap);
  const permissions = w.f.runtime.permissions, decide = name => permissions.decision(w.f.store.get('connections', 'hub'), caps[name]);
  w.use({github: rows('github')});
  w.scopes('hub', ['read:user']);
  assert.deepEqual([decide('listRepos').providerAccess, decide('listRepos').scopeSets], ['missing', [['repo']]], 'GET /user/repos, never the broader GET /user/{account_id}');
  assert.deepEqual([decide('getUser').providerAccess, decide('getUser').scopeSets], ['granted', [['read:user']]], 'a parameter fits only a parameter');
  assert.deepEqual([decide('repoNotifications').providerAccess, decide('repoNotifications').scopeSets], ['missing', [['notifications'], ['repo']]], 'an alias form is its member');
  const gone = decide('deleteAttestation');
  assert.deepEqual([gone.providerAccess, gone.executable, gone.unavailable, gone.reason], ['unavailable', false, 'no-oauth-scope', UNAVAILABLE_REASONS['no-oauth-scope']]);
  assert.deepEqual([permissions.unavailableOf(caps.deleteAttestation), permissions.unavailableOf(caps.listRepos)], ['no-oauth-scope', null]);
  assert.deepEqual([decide('listRepos').groupId, decide('listRepos').defaultMode], [null, 'allow'], 'only the row data is placed; the row and default stay the map\'s, as before');
  w.use({github: stripped(rows('github'))});
  assert.deepEqual([decide('listRepos').providerAccess, decide('listRepos').scopeSets, decide('deleteAttestation').providerAccess], ['unknown', [], 'unknown'], 'no row data: as today');
});

test('runtime.prepareJob() refuses an unavailable member with permission_denied before any request is sent', async t => {
  const w = await world(t);
  w.use({gmail: rows('gmail')});
  await assert.rejects(w.f.runtime.prepareJob({connectionId: 'mail', capabilityId: w.caps['gmail.users.settings.delegates.list'].id, args: {userId: 'me'}}, owner),
    error => error.code === 'permission_denied' && error.message === UNAVAILABLE_REASONS['service-account-only']);
  assert.deepEqual([w.f.jobs().length, w.f.calls.length], [0, 0]);
});

// ---- grants and handoffs (part i): an operation that can never work through a sign-in is never asked for ---------------------
// The shared handoff fixture (GitHub on a synthetic provider, a token account): its createIssue request, which has no map entry,
// sits in its row by its request, and that row marks it unavailable. A grant or a handoff made before is compared with one after.
const ISSUE = 'POST /repos/{owner}/{repo}/issues';
const issuesUnavailable = () => {
  const raw = JSON.parse(JSON.stringify(PERMISSION_GROUPS.get('github')));
  return new Map([...PERMISSION_GROUPS, ['github', validatePermissionGroups({...raw, groups: raw.groups.map(group => group.requests.includes(ISSUE) ? {...group, unavailable: {[ISSUE]: 'no-oauth-scope'}} : group)})]]);
};

test('grants and handoffs: an unavailable operation is never granted, offered or handed off, and an open handoff on one closes as policy_denied', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant({bindings: [{connectionId: 'acct-a', capabilityId: f.write.id}]}), args = {owner: 'o', repo: 'r', body: {title: 't'}}, words = UNAVAILABLE_REASONS['no-oauth-scope'];
  const open = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'before')).result, bound = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'bound')).result;
  assert.deepEqual([open.status, bound.status], ['awaiting_connection', 'awaiting_connection'], 'asked before the marker');
  const groups = issuesUnavailable();
  Object.assign(f.runtime.permissions, {groups}); Object.assign(f.runtime.proxyPolicy, {groups});
  assert.equal(f.runtime.permissions.unavailableOf(f.write), 'no-oauth-scope', 'by its request: it has no map entry');
  assert.throws(() => f.protocol.createClient({name: 'Agent', bindings: [], requestable: [{capabilityId: f.write.id}]}, owner), error => error.code === 'permission_denied' && error.message === words);
  assert.ok(f.protocol.createClient({name: 'Reader', bindings: [], requestable: [{capabilityId: f.read.id}]}, owner).token, 'the control');
  const listed = (await f.invoke(token, 'capabilities.list')).result.capabilities, of = connectionId => listed.find(item => item.id === f.write.id && item.connectionId === connectionId);
  assert.deepEqual([of('acct-a').status, of('acct-a').reason, of(null).status, of(null).reason], ['unavailable', 'permission_denied', 'unavailable', 'permission_denied']);
  assert.equal(listed.find(item => item.id === f.read.id && item.connectionId === null).status, 'connection_required');
  assert.deepEqual((await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'after')).error, {code: 'permission_denied', message: words});
  assert.deepEqual(f.store.list('protocolRequests').map(entry => entry.requestId).sort(), ['before', 'bound'], 'a refused request reserves nothing');
  // The open handoff closes the first time it is read. One that meets the refusal only when the account is bound (the rows put back,
  // the job's own check refusing) is policy_denied too, never authority_changed: the refusal is read by its mark, not its words.
  const closed = (await f.invoke(token, 'calls.get', {callId: open.id})).result;
  assert.deepEqual([closed.status, closed.handoff.outcome, f.store.get(CONTINUATIONS, open.id).outcome.code], ['failed', 'policy_denied', 'policy_denied']);
  Object.assign(f.runtime.permissions, {groups: PERMISSION_GROUPS}); Object.assign(f.runtime.proxyPolicy, {groups: PERMISSION_GROUPS});
  f.runtime.prepareJob = async () => { throw Object.assign(new Error(UNAVAILABLE_REASONS['workspace-cse-only']), {code: 'permission_denied', unavailable: true}); };
  await assert.rejects(f.select(bound.id, 'acct-a'), error => error.code === 'policy_denied');
  assert.equal(f.store.get(CONTINUATIONS, bound.id).outcome.code, 'policy_denied');
  assert.deepEqual([f.jobs().length, f.calls.length], [0, 0]);
});

// ---- proxied requests on fixture rows (part e) ------------------------------------------------------------------------------
test('proxy: GitHub gists need gist; without it the request is missing and refused at acceptance, with it granted', async t => {
  const w = await world(t);
  w.use({github: stripped(rows('github'))});
  assert.equal(w.proxy('hub', {method: 'GET', path: '/gists'}).providerAccess, 'unknown', 'no row data: unknown, as today');
  w.use({github: rows('github')});
  const gists = w.proxy('hub', {method: 'GET', path: '/gists'});
  assert.deepEqual([gists.providerAccess, gists.executable], ['missing', false]);
  await assert.rejects(w.accept('hub', {method: 'GET', path: '/gists'}), error => error.code === 'provider_access_missing');
  assert.equal(w.f.calls.length, 0);
  w.scopes('hub', ['read:user', 'repo', 'gist']);
  assert.deepEqual([w.proxy('hub', {method: 'GET', path: '/gists'}).providerAccess, w.proxy('hub', {method: 'GET', path: '/gists'}).executable], ['granted', true]);
  assert.equal(w.proxy('hub', {method: 'GET', path: '/user/repos'}).providerAccess, 'granted');
});

test('proxy: an attestation delete can never work through sign-in: Never with its words, refused at acceptance, and the {+subject_digest} form matches its marker', async t => {
  const w = await world(t);
  w.use({github: rows('github')});
  for (const request of [{method: 'DELETE', path: '/users/octo/attestations/digest/sha256:abc'}, {method: 'DELETE', path: '/users/octo/attestations/42'}]) {
    const decision = w.proxy('hub', request);
    assert.deepEqual([decision.providerAccess, decision.mode, decision.executable, decision.unavailable], ['unavailable', 'deny', false, 'no-oauth-scope'], request.path);
    assert.equal(decision.reason, UNAVAILABLE_REASONS['no-oauth-scope']);
    await assert.rejects(w.accept('hub', request), error => error.code === 'policy_denied' && error.message === UNAVAILABLE_REASONS['no-oauth-scope']);
  }
  assert.equal(w.f.calls.length, 0);
  assert.notEqual(w.proxy('hub', {method: 'DELETE', path: '/gists/g1'}).providerAccess, 'unavailable', 'only the marked members');
});

test('proxy: a /repositories/{id} alias request reads the same member\'s data as its /repos/{owner}/{repo} form', async t => {
  const w = await world(t);
  w.use({github: rows('github')});
  w.scopes('hub', ['read:user']);
  for (const path of ['/repos/o/r/notifications', '/repositories/7/notifications']) assert.equal(w.proxy('hub', {method: 'GET', path}).providerAccess, 'missing', `${path}: the member's own sets, not the row's read:user`);
  w.scopes('hub', ['read:user', 'repo']);
  for (const path of ['/repos/o/r/notifications', '/repositories/7/notifications']) assert.equal(w.proxy('hub', {method: 'GET', path}).providerAccess, 'granted', path);
});

test('proxy: a body-routed request reads its source member\'s data, never the target row\'s', async t => {
  const w = await world(t);
  // A looser target row, test only, so reading it would be visible.
  w.use({gmail: looserRow(rows('gmail'), 'gmail.messages.trash', {scopeSets: [[`${G}gmail.readonly`]]})});
  const routed = w.proxy('mail', {method: 'POST', path: '/gmail/v1/users/me/messages/m1/modify', body: {addLabelIds: ['TRASH']}});
  assert.equal(routed.routedFrom?.groupId, 'gmail.messages.mark');
  assert.equal(routed.providerAccess, 'missing', 'messages.modify needs gmail.modify by its own row');
  assert.equal(w.proxy('mail', {method: 'POST', path: '/gmail/v1/users/me/messages/m1/trash'}).providerAccess, 'granted', 'the control: the trash row itself');
});

test('proxy: Slack conversations.mark is granted by any one of its OR sets; Notion\'s [[]] stays unknown', async t => {
  const w = await world(t);
  w.use({slack: rows('slack'), notion: rows('notion')});
  assert.deepEqual([w.proxy('chat', {method: 'POST', path: '/conversations.mark', body: {channel: 'D1', ts: '1.2'}}).providerAccess], ['granted'], 'im:write alone');
  w.scopes('chat', ['channels:read']);
  assert.equal(w.proxy('chat', {method: 'POST', path: '/conversations.mark', body: {channel: 'D1', ts: '1.2'}}).providerAccess, 'missing');
  assert.equal(w.proxy('pages', {method: 'GET', path: '/v1/pages/p1'}).providerAccess, 'unknown');
});

test('proxy: an unavailable member of a row at default Allow is clamped to Never and refused at acceptance with its words, on every auth method; nothing is sent', async t => {
  const w = await world(t), policy = w.f.runtime.proxyPolicy;
  w.use({gmail: rows('gmail')});
  const request = {method: 'GET', path: '/gmail/v1/users/me/settings/delegates'};
  for (const authMethod of ['oauth', 'token']) {
    w.account('mail', 'gmail', GMAIL, [`${G}gmail.readonly`], {authMethod});
    const decision = w.proxy('mail', request);
    assert.deepEqual([decision.providerAccess, decision.mode, decision.defaultMode, decision.executable, decision.unavailable, decision.clamps], ['unavailable', 'deny', 'allow', false, 'service-account-only', ['unavailable']], authMethod);
    assert.equal(decision.reason, UNAVAILABLE_REASONS['service-account-only']);
    await assert.rejects(w.accept('mail', request), error => error.code === 'policy_denied' && error.message === UNAVAILABLE_REASONS['service-account-only'], authMethod);
  }
  // The app page reads the member the same way, and the row's other members are untouched.
  const context = policy.display(w.f.store.get('connections', 'mail')), entry = policy.rows(context).find(item => item.row === 'group:gmail.labels.read');
  assert.deepEqual(['gmail.users.settings.delegates.list', 'gmail.users.labels.list'].map(member => policy.memberState(context, entry, member)).map(state => [state.mode, state.clamps]), [['deny', ['unavailable']], ['allow', []]]);
  assert.deepEqual([w.f.jobs().length, w.f.calls.length], [0, 0]);
});

test('proxy: a map operation whose scope metadata is malformed reads unknown, as before F10.6 and as its typed decision reads it; row sets never stand in for it', async t => {
  const w = await world(t), map = w.f.store.get('applicationMaps', 'gmail'), policy = w.f.runtime.proxyPolicy, id = 'gmail.users.labels.create';
  w.use({gmail: rows('gmail')});
  w.f.store.put('applicationMaps', {...map, operations: map.operations.map(operation => operation.id === id ? {...operation, requiredScopes: [`${G}gmail.labels`], scopeSets: 'malformed'} : operation)});
  const request = {method: 'POST', path: '/gmail/v1/users/me/labels', body: {name: 'Receipts'}};
  for (const scopes of [[`${G}gmail.readonly`], [`${G}gmail.labels`], [`${G}gmail.modify`]]) {
    w.scopes('mail', scopes);
    const context = policy.display(w.f.store.get('connections', 'mail')), state = policy.memberState(context, policy.rows(context).find(item => item.row === 'group:gmail.labels.manage'), id);
    assert.deepEqual([w.proxy('mail', request).providerAccess, state.providerAccess, w.decide(id).providerAccess, w.decide(id).status], ['unknown', 'unknown', 'unknown', 'unsupported'], scopes.join(' '));
  }
});

test('display() and memberState(): each reviewed member reads for the app page without the ready check, as a decision with its effect, row data and own hash (correction 8)', async t => {
  const w = await world(t), policy = w.f.runtime.proxyPolicy, connection = id => w.f.store.get('connections', id);
  w.use({github: rows('github'), notion: rows('notion'), gmail: rows('gmail')});
  w.account('hub', 'github', 'https://api.github.com', ['read:user', 'repo'], {status: 'reconnect_required'});
  assert.throws(() => policy.route('hub'), error => error.code === 'proxy_unavailable', 'changes and decisions still need a ready account');
  const state = (id, groupId, member, definition = undefined) => {
    const context = policy.display(connection(id), definition);
    return policy.memberState(context, policy.rows(context).find(entry => entry.row === `group:${groupId}`), member);
  };
  const gists = state('hub', 'github.gists.read', 'GET /gists');
  assert.deepEqual([gists.member, gists.groupId, gists.effect, gists.sensitivity, gists.reviewedAsRead, gists.status, gists.mode, gists.defaultMode, gists.policySource],
    ['GET /gists', 'github.gists.read', 'read', null, false, 'active', 'allow', 'allow', 'default']);
  assert.deepEqual([gists.providerAccess, gists.scopeSets, gists.executable], ['missing', [['gist']], false]);
  assert.match(gists.policyHash, /^[0-9a-f]{64}$/);
  assert.ok(!('unavailable' in gists) && !('conditions' in gists) && !('capabilityId' in gists));
  const purge = state('hub', 'github.permanent.delete', 'DELETE /users/{username}/attestations/digest/{+subject_digest}');
  assert.deepEqual([purge.member, purge.providerAccess, purge.unavailable, purge.mode, purge.effect], ['DELETE /users/{username}/attestations/digest/{subject_digest}', 'unavailable', 'no-oauth-scope', 'deny', 'delete']);
  // The hash moves with what the member shows: its provider access, and its row's record.
  w.scopes('hub', ['read:user', 'repo', 'gist']);
  const granted = state('hub', 'github.gists.read', 'GET /gists');
  assert.equal(granted.providerAccess, 'granted'); assert.notEqual(granted.policyHash, gists.policyHash);
  const labels = state('mail', 'gmail.labels.read', 'gmail.users.labels.list');
  policy.set({connectionId: 'mail', row: 'group:gmail.labels.read', mode: 'ask'});
  const asked = state('mail', 'gmail.labels.read', 'gmail.users.labels.list');
  assert.deepEqual([asked.mode, asked.policySource], ['ask', 'saved']); assert.notEqual(asked.policyHash, labels.policyHash);
  assert.deepEqual([state('mail', 'gmail.messages.send', 'gmail.users.messages.send').mode, state('mail', 'gmail.messages.send', 'gmail.users.messages.send').clamps], ['deny', ['typed_only']], 'a member that runs only typed');
  assert.equal(state('mail', 'gmail.labels.read', 'gmail.users.settings.delegates.list').providerAccess, 'unavailable');
  // A POST reviewed as a read is a read, and conditions are notes on a member that still runs.
  const search = state('pages', 'notion.search.read', 'POST /v1/search');
  assert.deepEqual([search.effect, search.reviewedAsRead, search.mode, search.providerAccess], ['read', true, 'allow', 'unknown']);
  assert.deepEqual(state('pages', 'notion.agents.read', 'POST /v1/agents/query').conditions, ['beta', 'plan-dependent']);
  // The definition the app page passes is the one read, and no context exists where the proxy could never route.
  assert.equal(state('hub', 'github.gists.read', 'GET /gists', validatePermissionGroups(stripped(rows('github')))).providerAccess, 'unknown');
  assert.equal(policy.display({...connection('pages'), allowedOrigins: ['https://example.com']}), null);
  assert.equal(policy.display({...connection('pages'), driver: 'browser'}), null);
  assert.equal(policy.display({...connection('pages'), appId: 'no-such-app'}), null);
  assert.equal(policy.memberState(policy.display(connection('pages')), policy.rows(policy.display(connection('pages')))[0], 'GET /not-a-member'), null);
});

test('proxy: the shipped delegates.list marker refuses a request at acceptance with its words, and nothing is sent', async t => {
  const w = await world(t);
  const request = {method: 'GET', path: '/gmail/v1/users/me/settings/delegates'}, decision = w.proxy('mail', request);
  assert.deepEqual([decision.providerAccess, decision.mode, decision.defaultMode, decision.executable, decision.unavailable], ['unavailable', 'deny', 'allow', false, 'service-account-only']);
  assert.ok(decision.clamps.includes('unavailable'));
  assert.equal(decision.reason, UNAVAILABLE_REASONS['service-account-only']);
  await assert.rejects(w.accept('mail', request), error => error.code === 'policy_denied' && error.message === UNAVAILABLE_REASONS['service-account-only']);
  assert.deepEqual([w.f.jobs().length, w.f.calls.length], [0, 0]);
});

// ---- the shipped catalog (part l) -------------------------------------------------------------------------------------------
/** What F10.6 ships (open question 2): the fixture's markers that are provider facts, and Notion's conditions. Scope sets, conditional
 *  scopes, unsupported members and the not-requested and bot-token-only markers land with F10.7. */
const PROVIDER_FACTS = ['service-account-only', 'workspace-cse-only', 'client-credentials-only', 'no-oauth-scope'];
test('the shipped rows keep every F10.6 provider-fact marker and Notion\'s conditions, and carry F10.7\'s scope data and exactly F10.15\'s four unsupported markers', () => {
  // F10.6 as shipped (test/fixtures/access/f10-6-rows.snapshot.json): its 26 markers stay on the same members, whatever row they sit in
  // now (the Gmail delete split moved rows, not markers), and only Notion carries conditions.
  const before = JSON.parse(readFileSync(new URL('./fixtures/access/f10-6-rows.snapshot.json', import.meta.url), 'utf8')).apps;
  const byMember = groups => Object.fromEntries(groups.flatMap(group => Object.entries(group.unavailable ?? {})));
  for (const appId of FIXTURE_APPS) {
    const shipped = PERMISSION_GROUPS.get(appId).groups, f106 = validatePermissionGroups(before[appId]).groups, now = byMember(shipped);
    for (const [member, reason] of Object.entries(byMember(f106))) assert.equal(now[member], reason, `${appId} ${member}`);
    const conditions = groups => groups.flatMap(group => Object.entries(group.conditions ?? {}).map(([member, list]) => [member, [...list]]));
    assert.deepEqual(conditions(shipped), conditions(f106), `${appId} conditions`);
  }
  // F10.15 (spec line 1106): Gmail's typed drafts.create, drafts.update, drafts.send and messages.import are unsupported, and nothing else is.
  const unsupported = [...PERMISSION_GROUPS.values()].flatMap(definition => definition.groups.flatMap(group => Object.keys(group.unsupported ?? {}).map(member => `${definition.appId} ${group.id} ${member}`)));
  assert.deepEqual(unsupported, ['gmail gmail.drafts.write gmail.users.drafts.create', 'gmail gmail.drafts.write gmail.users.drafts.update', 'gmail gmail.messages.send gmail.users.drafts.send',
    'gmail gmail.messages.import gmail.users.messages.import']);
  // Every reason by app: F10.6's 26 provider facts, and part e's not-requested, bot-only, app-credential and retired methods.
  const counts = Object.fromEntries([...PERMISSION_GROUPS].map(([appId, definition]) => [appId, definition.groups.flatMap(group => Object.values(group.unavailable ?? {}))
    .reduce((out, reason) => ({...out, [reason]: (out[reason] ?? 0) + 1}), {})]));
  assert.deepEqual(counts, {github: {'not-requested': 66, 'no-oauth-scope': 2}, gmail: {'service-account-only': 10, 'workspace-cse-only': 11, 'not-requested': 3}, 'google-calendar': {},
    notion: {'client-credentials-only': 3}, slack: {'not-requested': 132, 'client-credentials-only': 22, 'bot-token-only': 16, 'no-oauth-scope': 12}});
  assert.deepEqual(PROVIDER_FACTS.map(reason => Object.values(byMember([...PERMISSION_GROUPS.values()].filter(definition => definition.appId !== 'slack').flatMap(definition => definition.groups))).filter(item => item === reason).length), [10, 11, 3, 2]);
});

test('scope implications: a GitHub account holding admin:org reads granted for a [[read:org]] member, typed and proxied alike (open question 20)', async t => {
  const w = await world(t), reading = normalizeAuthApp(definitions.github, definitions.github.apps[0]);
  w.use({github: rows('github')});
  w.f.runtime.permissions.scopesOf = connection => effectiveScopes(reading, Array.isArray(connection?.scopes) ? connection.scopes : []);
  // A typed operation with no map entry sits in its row by its request (correction 3).
  const [orgs] = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
    '/user/orgs': {get: {operationId: 'listOrgs', responses: {200: {description: 'ok'}}}}}}}).capabilities.map(cap => ({...cap, status: 'active'}));
  w.f.store.put('capabilities', orgs);
  const both = () => [w.f.runtime.permissions.decision(w.f.store.get('connections', 'hub'), orgs).providerAccess, w.proxy('hub', {method: 'GET', path: '/user/orgs'}).providerAccess];
  assert.deepEqual(both(), ['missing', 'missing']);
  w.scopes('hub', ['read:user', 'repo', 'admin:org']);
  assert.deepEqual(both(), ['granted', 'granted'], 'admin:org grants read:org');
});

// ---- the closure (part j) ---------------------------------------------------------------------------------------------------
const GMAIL_FULL = definitions.google.apps.find(app => app.appId === 'gmail'), GITHUB_FULL = definitions.github.apps[0];
const levelScopes = app => [...app.access.levels.full.required, ...app.access.levels.full.optional, ...app.access.levels.full.inContext.map(entry => entry.scope)];

test('closure: unavailable members are listed apart and use no scope; a conditional scope is used; locked rows justify nothing', () => {
  const gmail = validatePermissionGroups(rows('gmail')).groups;
  const report = closures.rowCoverage({groups: gmail, operations: closures.operationsFromRows(gmail, FACTS.apps.gmail.methods), granted: levelScopes(GMAIL_FULL), neverRequest: GMAIL_FULL.neverRequest});
  const labels = report.rows.find(row => row.id === 'gmail.labels.read');
  assert.deepEqual(labels.unavailable.map(item => item.member).sort(), ['gmail.users.settings.cse.identities.get', 'gmail.users.settings.cse.identities.list', 'gmail.users.settings.cse.keypairs.get',
    'gmail.users.settings.cse.keypairs.list', 'gmail.users.settings.delegates.get', 'gmail.users.settings.delegates.list']);
  assert.ok(labels.unavailable.every(item => item.reason === at(rows('gmail'), 'gmail.labels.read').unavailable[item.member]));
  assert.deepEqual(report.rows.flatMap(row => row.cannotWork), [], 'every member that can never work is marked');
  assert.equal(report.rows.find(row => row.id === 'gmail.access.grant').status, 'locked');
  // F10.7: "Permanently delete emails" holds only members no sign-in can use, so the row is unavailable.
  assert.deepEqual([report.summary.works, report.summary.locked, report.summary.unavailable, report.summary.unavailableMembers], [12, 1, 1, 24]);
  assert.deepEqual(report.unjustified, []);
  // GitHub: workflow is used only as a conditional scope, and that counts (T3).
  const github = validatePermissionGroups(rows('github')).groups, granted = levelScopes(GITHUB_FULL);
  assert.deepEqual(closures.rowCoverage({groups: github, operations: closures.operationsFromRows(github), granted}).unjustified, []);
  const unconditional = validatePermissionGroups(looserRow(rows('github'), 'github.code.write', {conditionalScopes: undefined})).groups;
  assert.deepEqual(closures.rowCoverage({groups: unconditional, operations: closures.operationsFromRows(unconditional), granted}).unjustified, ['workflow']);
  // A scope only a locked row's members use justifies nothing, and neither does one only unavailable members name.
  const locked = validatePermissionGroups({schemaVersion: 2, appId: 'fixture', groups: [{id: 'fixture.read', label: 'Read', effect: 'read', defaultMode: 'allow', requests: ['GET /items'], scopeSets: [['read']]},
    {id: 'fixture.purge', label: 'Purge', effect: 'delete', defaultMode: 'deny', requests: ['DELETE /items/{id}'], scopeSets: [['purge']], unavailable: {'DELETE /items/{id}': 'not-requested'}},
    {id: 'fixture.access.grant', label: 'Give access', effect: 'write', defaultMode: 'deny', locked: 'fabric', requests: ['PUT /items/{id}/share'], scopeSets: [['admin']]}]}).groups;
  const small = closures.rowCoverage({groups: locked, operations: closures.operationsFromRows(locked), granted: ['read', 'admin', 'purge']});
  assert.deepEqual([small.unjustified, small.rows.map(row => row.status)], [['admin', 'purge'], ['works', 'unavailable', 'locked']]);
});

test('closure: Notion\'s [[]] rows work, a row of only unavailable members is unavailable, and {+...} members find their markers', () => {
  const notion = validatePermissionGroups(rows('notion')).groups, report = closures.rowCoverage({groups: notion, operations: closures.operationsFromRows(notion), granted: []});
  assert.equal(report.rows.find(row => row.id === 'notion.content.read').status, 'works');
  assert.equal(report.rows.find(row => row.id === 'notion.connection.manage').status, 'unavailable');
  assert.deepEqual([report.summary.works, report.summary.unavailable, report.summary.unavailableMembers], [12, 1, 3]);
  const github = validatePermissionGroups(rows('github')).groups, granted = levelScopes(GITHUB_FULL);
  const purge = closures.rowCoverage({groups: github, operations: closures.operationsFromRows(github), granted}).rows.find(row => row.id === 'github.permanent.delete');
  assert.ok(purge.unavailable.some(item => item.member === 'DELETE /users/{username}/attestations/digest/{subject_digest}' && item.reason === 'no-oauth-scope'), 'one member key for the marker and the lookup');
  const {['DELETE /users/{username}/attestations/digest/{+subject_digest}']: marker, ...others} = at(rows('github'), 'github.permanent.delete').unavailable;
  assert.equal(marker, 'no-oauth-scope');
  const unmarked = validatePermissionGroups(looserRow(rows('github'), 'github.permanent.delete', {unavailable: others})).groups;
  const without = closures.rowCoverage({groups: unmarked, operations: closures.operationsFromRows(unmarked), granted}).rows.find(row => row.id === 'github.permanent.delete');
  assert.ok(!without.unavailable.some(item => item.member.includes('subject_digest')), 'without its marker the member is measured by its row\'s sets');
});

// ---- consistency: row data is only ever stricter than Discovery --------------------------------------------------------------
/** Gmail and Calendar members whose row data claims less than Discovery: a row alternative that holds no whole Discovery alternative. */
const looser = (appId, definition) => definition.groups.flatMap(group => [...group.operations, ...group.requests].flatMap(member => {
  const {scopeSets, unavailable} = memberData(group, member), documented = FACTS.apps[appId]?.methods[member];
  if (!scopeSets || !documented || unavailable) return [];
  return scopeSets.filter(set => !documented.some(scope => set.includes(scope))).map(set => `${member} [${set.join(' ')}]`);
}));
/** Members every one of whose alternatives needs a never-request scope, with no unavailable marker. */
const unmarked = (appId, definition, never) => definition.groups.flatMap(group => [...group.operations, ...group.requests].filter(member => {
  const data = memberData(group, member), documented = FACTS.apps[appId]?.methods[member];
  const alternatives = documented ? documented.map(scope => [scope]) : data.scopeSets ?? [];
  return !data.unavailable && alternatives.length && alternatives.every(set => set.some(scope => never.includes(scope)));
}));
const NEVER = {gmail: GMAIL_FULL.neverRequest, 'google-calendar': definitions.google.apps.find(app => app.appId === 'google-calendar').neverRequest, github: GITHUB_FULL.neverRequest,
  notion: definitions.notion.apps[0].neverRequest, slack: definitions.slack.apps[0].neverRequest};

test('consistency: row data never claims less than Discovery, and every member that only a never-request scope could run is marked', () => {
  for (const appId of FIXTURE_APPS) {
    assert.deepEqual(looser(appId, validatePermissionGroups(rows(appId))), [], `${appId} fixture rows`);
    assert.deepEqual(unmarked(appId, validatePermissionGroups(rows(appId)), NEVER[appId]), [], `${appId} fixture rows`);
  }
  for (const [appId, definition] of PERMISSION_GROUPS) assert.deepEqual(looser(appId, definition), [], `${appId} shipped rows`);
  // Adversarial (spec line 531): a send row that claims gmail.readonly is enough fails, and so does an unmarked delete.
  assert.deepEqual(looser('gmail', validatePermissionGroups(looserRow(rows('gmail'), 'gmail.messages.send', {scopeSets: [[`${G}gmail.readonly`]]}))), [`gmail.users.messages.send [${G}gmail.readonly]`, `gmail.users.drafts.send [${G}gmail.readonly]`]);
  assert.deepEqual(looser('gmail', validatePermissionGroups(looserRow(rows('gmail'), 'gmail.messages.read', {scopeSets: [[]]}))).length, 5, 'a row that claims no scope is looser too');
  const purge = at(rows('gmail'), 'gmail.permanent.delete'), {['gmail.users.messages.delete']: dropped, ...kept} = purge.unavailable;
  assert.equal(dropped, 'not-requested');
  assert.deepEqual(unmarked('gmail', validatePermissionGroups(looserRow(rows('gmail'), 'gmail.permanent.delete', {unavailable: kept})), NEVER.gmail), ['gmail.users.messages.delete']);
});

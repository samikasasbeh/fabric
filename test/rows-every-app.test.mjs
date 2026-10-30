import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {validatePermissionGroups, PERMISSION_GROUPS, UNAVAILABLE_REASONS, CONDITION_WORDS} from '../lib/permission-groups.mjs';
import {leastPrivilegedExtra, scopeAlternatives} from '../lib/permissions.mjs';
import {permissionRow} from '../lib/ui-contracts.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager, catalog} from '../lib/connections.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {AppDetailService, NOT_OFFERED as NOT_OFFERED_WORDS} from '../lib/app-detail.mjs';
import {offeredLevels, heldLevel} from '../lib/access-levels.mjs';
import {operationScopes} from '../lib/continuations.mjs';
import {describeApp, needsConfirm, confirmText, confirmedRowRequest, rowRequest, NOTE_WORDS} from '../public/hosted-app.js';
import {baseFor} from '../public/hosted-base.js';
import {fixture, owner, noShippedActions} from './fixtures/signin-fixture.mjs';
import {fixture as handoffFixture} from './fixtures/continuation-fixture.mjs';
import {SIMULATORS} from './fixtures/oauth-simulators.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';
import {definitionOf, rows} from './fixtures/access/f10-6-fixtures.mjs';

// F10.6 (docs/F10-FIVE-APPS-DEEP.md section F10.6; docs/F10.6-BUILD-MAP.md section 4 and corrections 1, 3, 4, 8, 9 and 10): rows for
// every app, one owner control for typed and proxy records, and Add access that asks only for usable scopes. GitHub, Notion and
// Slack accounts list their reviewed rows from the proxy's view of the account, and a row change writes the row's proxy record
// too. The single-owner server runs the shipped (version 1) definitions; the version 2 cases bind the fixture definitions the way
// test/partial-grant.test.mjs does.
// Simulators and synthetic accounts only: every case counts what was sent.
const G = 'https://www.googleapis.com/auth/', GMAIL = 'https://gmail.googleapis.com';
const MODIFY = `${G}gmail.modify`, READONLY = `${G}gmail.readonly`, COMPOSE = `${G}gmail.compose`, SETTINGS = `${G}gmail.settings.basic`, LABELS = `${G}gmail.labels`, MAILBOX = 'https://mail.google.com/';
const FACTS = JSON.parse(readFileSync(new URL('./fixtures/access/google-method-scopes.json', import.meta.url), 'utf8'));
const RECORDED = JSON.parse(readFileSync(new URL('./fixtures/access/f10-3-bindings.before.json', import.meta.url), 'utf8')).maps.gmail.operations;
const GITHUB_ORDER = PERMISSION_GROUPS.get('github').groups.map(group => group.id);
const NOT_OFFERED = 'Not offered';
const P = name => ({name, in: 'path', required: true, schema: {type: 'string'}});
const rowsOf = page => page.sections.flatMap(section => section.rows);
const rowIn = (page, groupId) => rowsOf(page).find(item => item.groupId === groupId);

/** Gmail operations with their real paths, compiled, in a stored map that holds every reviewed Gmail operation (the proxy needs
 *  them all), each with its Discovery scopes from the facts fixture unless `silent`. */
const GMAIL_PATHS = {'gmail.users.drafts.create': ['POST', '/gmail/v1/users/{userId}/drafts'], 'gmail.users.drafts.update': ['PUT', '/gmail/v1/users/{userId}/drafts/{id}'],
  'gmail.users.labels.create': ['POST', '/gmail/v1/users/{userId}/labels'], 'gmail.users.labels.update': ['PUT', '/gmail/v1/users/{userId}/labels/{id}'], 'gmail.users.labels.patch': ['PATCH', '/gmail/v1/users/{userId}/labels/{id}'],
  'gmail.users.labels.list': ['GET', '/gmail/v1/users/{userId}/labels'], 'gmail.users.messages.modify': ['POST', '/gmail/v1/users/{userId}/messages/{id}/modify'],
  'gmail.users.messages.batchModify': ['POST', '/gmail/v1/users/{userId}/messages/batchModify'], 'gmail.users.threads.modify': ['POST', '/gmail/v1/users/{userId}/threads/{id}/modify'],
  'gmail.users.messages.trash': ['POST', '/gmail/v1/users/{userId}/messages/{id}/trash'], 'gmail.users.messages.import': ['POST', '/gmail/v1/users/{userId}/messages/import'],
  // F10.15 listed churn: messages.import is unsupported, so "Import emails" offers its Add through messages.insert.
  'gmail.users.messages.insert': ['POST', '/gmail/v1/users/{userId}/messages'],
  'gmail.users.labels.delete': ['DELETE', '/gmail/v1/users/{userId}/labels/{id}'], 'gmail.users.messages.delete': ['DELETE', '/gmail/v1/users/{userId}/messages/{id}'],
  'gmail.users.settings.delegates.list': ['GET', '/gmail/v1/users/{userId}/settings/delegates']};
function seedGmail(store, {silent = []} = {}) {
  const paths = {};
  for (const [id, [method, route]] of Object.entries(GMAIL_PATHS)) paths[route] = {...paths[route], [method.toLowerCase()]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => P(match[1])),
    ...(['GET', 'DELETE'].includes(method) ? {} : {requestBody: {content: {'application/json': {schema: {type: 'object'}}}}}), responses: {200: {description: 'ok'}}}};
  const caps = Object.fromEntries(compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: GMAIL}], paths}}).capabilities.map(cap => [cap.name, {...cap, status: 'active'}]));
  for (const cap of Object.values(caps)) store.put('capabilities', cap);
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', operations: RECORDED.map(operation => {
    if (!caps[operation.id]) return operation;
    const [method, route] = GMAIL_PATHS[operation.id];
    return {id: operation.id, capabilityId: caps[operation.id].id, method, path: route, ...(silent.includes(operation.id) ? {} : {requiredScopes: FACTS.apps.gmail.methods[operation.id]})};
  })});
  return caps;
}
const account = (store, id, appId, origin, extra = {}) => store.put('connections', {id, appId, driver: 'http', authMethod: 'token', authRevision: `consent-${id}`, status: 'ready', label: id, identity: {id, displayName: id},
  allowedOrigins: [origin], createdAt: '2026-10-11T10:00:00.000Z', ...extra});

// ---- the single-owner server (shipped rows, version 1 definitions) -------------------------------------------------------
async function local(t, {shipped = false} = {}) {
  const f = await fixture(t, shipped ? {} : {actions: await noShippedActions(t)}), store = f.app.store;
  // No map, no typed operation and, unless `shipped`, no action: every GitHub row comes from the proxy's view of the account. With
  // `shipped`, GitHub's certified actions join their rows (the last test of this file).
  store.delete('applicationMaps', 'github'); store.delete('capabilities', f.read.id); store.delete('capabilities', f.write.id);
  account(store, 'tok', 'github', 'https://api.github.com');
  const view = async (appId = 'github', ref = 'tok') => f.json('GET', `/api/ui/apps/${appId}?account=${encodeURIComponent(ref)}`);
  const post = (verb, body, appId = 'github', ref = 'tok') => f.json('POST', `/api/ui/apps/${appId}/accounts/${encodeURIComponent(ref)}/${verb}`, body);
  const proxyRow = (ref, row) => f.app.runtime.proxyPolicy.view(ref).find(entry => entry.row === row);
  const record = (ref, row) => store.get('permissions', f.app.runtime.proxyPolicy.policyId(ref, row));
  return {f, store, view, post, proxyRow, record};
}

test('a GitHub token account with no map lists its 13 reviewed rows in catalog order; the locked row is last, Never only, with no Add', async t => {
  const {view} = await local(t), {status, body: page} = await view();
  assert.equal(status, 200);
  const listed = rowsOf(page);
  assert.equal(listed.length, 13);
  assert.deepEqual(page.sections.map(section => section.id), ['read', 'write']);
  assert.deepEqual(listed.map(item => item.groupId), [...GITHUB_ORDER.filter(id => ['read'].includes(PERMISSION_GROUPS.get('github').groups.find(group => group.id === id).effect)),
    ...GITHUB_ORDER.filter(id => PERMISSION_GROUPS.get('github').groups.find(group => group.id === id).effect !== 'read')]);
  const grant = listed.at(-1);
  assert.deepEqual([grant.groupId, grant.locked, grant.mode, grant.allowedModes], ['github.access.grant', true, 'deny', ['deny']]);
  assert.ok(!('addAccess' in grant) && !('addBlocked' in grant));
  // Each row reads the proxy's setting for it: its mode, default and the modes the owner may choose.
  assert.deepEqual([rowIn(page, 'github.repos.read').mode, rowIn(page, 'github.repos.read').defaultMode, rowIn(page, 'github.repos.read').access], ['allow', 'allow', 'unknown']);
  assert.deepEqual(rowIn(page, 'github.issues.write').allowedModes, ['ask', 'deny'], 'a write row that is not proxyAllowable offers Ask and Never only');
  assert.deepEqual(rowIn(page, 'github.notifications.manage').allowedModes, ['allow', 'ask', 'deny']);
  assert.deepEqual(page.discovery, {state: 'missing', message: 'These permissions apply to raw requests now. Discovering the app adds typed operations.'});
  for (const leak of ['bindingHash', 'policyHash', 'authRevision', 'revision']) assert.ok(!JSON.stringify(page.sections).includes(leak), leak);
});

test('a reconnect_required account still lists its rows; a change answers invalid_request and writes nothing (open question 16)', async t => {
  const {store, view, post} = await local(t);
  store.put('connections', {...store.get('connections', 'tok'), status: 'reconnect_required'});
  const page = (await view()).body, repos = rowIn(page, 'github.repos.read');
  assert.equal(rowsOf(page).length, 13);
  const answer = await post('permissions', {groupId: 'github.repos.read', mode: 'deny', etag: repos.etag});
  assert.deepEqual([answer.status, answer.body.code], [400, 'invalid_request']);
  assert.equal(store.list('permissions').length, 0);
});

test('Never on "Push code and manage repositories" writes its proxy record, and a proxied contents PUT is then refused', async t => {
  const {f, view, post, proxyRow} = await local(t), code = rowIn((await view()).body, 'github.code.write');
  assert.equal(proxyRow('tok', 'group:github.code.write').mode, 'ask');
  const set = await post('permissions', {groupId: 'github.code.write', mode: 'deny', etag: code.etag});
  assert.equal(set.status, 200);
  assert.deepEqual([rowIn(set.body, 'github.code.write').mode, rowIn(set.body, 'github.code.write').policySource], ['deny', 'saved']);
  assert.deepEqual([proxyRow('tok', 'group:github.code.write').mode, proxyRow('tok', 'group:github.code.write').source], ['deny', 'saved']);
  await assert.rejects(f.app.runtime.createProxyJob({connectionId: 'tok', request: {method: 'PUT', path: '/repos/o/r/contents/a/b.md', body: {message: 'm', content: 'YQ=='}}}, owner), error => error.code === 'policy_denied');
  assert.equal(f.api.length, 0);
});

test('reset returns typed and proxy records to their defaults with fresh revisions, and canReset counts a saved proxy record', async t => {
  const {view, post, record} = await local(t);
  assert.equal((await view()).body.canReset, false);
  await post('permissions', {groupId: 'github.code.write', mode: 'deny', etag: rowIn((await view()).body, 'github.code.write').etag});
  const saved = record('tok', 'group:github.code.write');
  assert.equal((await view()).body.canReset, true, 'a saved proxy record is something to reset');
  const reset = await post('reset', {});
  assert.equal(reset.status, 200); assert.equal(reset.body.canReset, false);
  const after = record('tok', 'group:github.code.write');
  assert.deepEqual([after.followsDefault, after.revision !== saved.revision], [true, true]);
  assert.equal(rowIn(reset.body, 'github.code.write').mode, 'ask');
});

test('the etag covers the proxy record: a change through ProxyPolicy.set() between the view and the row change answers view_changed', async t => {
  const {f, view, post, record} = await local(t), code = rowIn((await view()).body, 'github.code.write');
  f.app.runtime.proxyPolicy.set({connectionId: 'tok', row: 'group:github.code.write', mode: 'deny'});
  const before = record('tok', 'group:github.code.write');
  const answer = await post('permissions', {groupId: 'github.code.write', mode: 'ask', etag: code.etag});
  assert.deepEqual([answer.status, answer.body.code], [409, 'view_changed']);
  assert.deepEqual(record('tok', 'group:github.code.write'), before, 'nothing was written');
});

test('correction 3: a map-less typed capability sits in its row by request shape, and the one control sets it with the proxy record', async t => {
  const {f, store, view, post, proxyRow} = await local(t);
  store.put('capabilities', f.read);
  const repos = rowIn((await view()).body, 'github.repos.read');
  assert.equal(repos.operations, 1, 'GET /user/repos is a member of "Access repositories and code"');
  const set = await post('permissions', {groupId: 'github.repos.read', mode: 'ask', etag: repos.etag});
  assert.equal(set.status, 200);
  assert.deepEqual([f.app.runtime.permissions.decision(store.get('connections', 'tok'), f.read).mode, proxyRow('tok', 'group:github.repos.read').mode], ['ask', 'ask']);
});

test('correction 9: when the proxy cannot route the account, a row change writes typed records only, and nothing else', async t => {
  const {f, store, view, post} = await local(t);
  store.put('capabilities', f.read);
  store.put('connections', {...store.get('connections', 'tok'), allowedOrigins: ['https://uploads.github.com']});
  const repos = rowIn((await view()).body, 'github.repos.read');
  assert.equal((await post('permissions', {groupId: 'github.repos.read', mode: 'deny', etag: repos.etag})).status, 200);
  assert.deepEqual(store.list('permissions').map(entry => entry.kind ?? 'typed'), ['typed']);
});

test('correction 9: a row change that waits for rediscovery writes nothing, the proxy record included', async t => {
  const {f, store, view, post, record} = await local(t);
  // A GET /user/repos made by older rules: its id no longer matches its content.
  store.put('capabilities', {...f.read, id: `${f.read.id.slice(0, -24)}${'0'.repeat(24)}`});
  const repos = rowIn((await view()).body, 'github.repos.read');
  const refused = await post('permissions', {groupId: 'github.repos.read', mode: 'ask', etag: repos.etag});
  assert.equal(refused.body.code, 'rediscover_required'); assert.match(refused.body.error, /Nothing was changed/);
  assert.equal(record('tok', 'group:github.repos.read') ?? null, null);
  assert.equal(store.list('permissions').length, 0);
});

// Gmail on the same server: typed members whose proxy row differs.
async function gmailLocal(t) {
  const h = await local(t), caps = seedGmail(h.store);
  account(h.store, 'mail', 'gmail', GMAIL);
  return {...h, caps};
}

test('raw requests still ask: "Draft emails" says so at defaults; Allow keeps the typed Allow and leaves the proxy record alone (correction 10)', async t => {
  const {store, view, post, proxyRow} = await gmailLocal(t), drafts = rowIn((await view('gmail', 'mail')).body, 'gmail.drafts.write');
  assert.deepEqual([drafts.mode, drafts.defaultMode], ['allow', 'allow']);
  assert.ok(drafts.notes.includes('raw_requests_ask'), 'typed Allow, proxy Ask: the row says raw requests still ask');
  assert.deepEqual([proxyRow('mail', 'group:gmail.drafts.write').mode, proxyRow('mail', 'group:gmail.drafts.write').allowedModes], ['ask', ['ask', 'deny']]);
  const set = await post('permissions', {groupId: 'gmail.drafts.write', mode: 'allow', etag: drafts.etag}, 'gmail', 'mail');
  assert.equal(set.status, 200, 'Allow at the typed default needs no confirm, and the proxy record follows its own default');
  assert.deepEqual([proxyRow('mail', 'group:gmail.drafts.write').mode, proxyRow('mail', 'group:gmail.drafts.write').source], ['ask', 'default']);
  assert.equal(store.list('permissions').filter(entry => entry.kind === 'proxy-row').length, 0, 'a record equal to the current one is not written');
});

test('confirm on proxy widening: Allow on "Manage labels" needs confirmAllow, writes nothing without it, and with it both records are Allow', async t => {
  const {store, view, post, proxyRow} = await gmailLocal(t), labels = rowIn((await view('gmail', 'mail')).body, 'gmail.labels.manage');
  assert.deepEqual([labels.mode, proxyRow('mail', 'group:gmail.labels.manage').mode], ['allow', 'ask']);
  const refused = await post('permissions', {groupId: 'gmail.labels.manage', mode: 'allow', etag: labels.etag}, 'gmail', 'mail');
  assert.deepEqual([refused.status, refused.body.code], [409, 'confirm_required']);
  assert.match(refused.body.error, /^Allow lets the agent do this without asking/, 'the row\'s own rule refuses it, before the proxy is asked');
  assert.equal(store.list('permissions').length, 0, 'nothing was written');
  const set = await post('permissions', {groupId: 'gmail.labels.manage', mode: 'allow', etag: labels.etag, confirmAllow: true}, 'gmail', 'mail');
  assert.equal(set.status, 200);
  assert.deepEqual([proxyRow('mail', 'group:gmail.labels.manage').mode, proxyRow('mail', 'group:gmail.labels.manage').source], ['allow', 'saved']);
  assert.equal(rowIn(set.body, 'gmail.labels.manage').mode, 'allow');
});

test('correction 4: the owner page asks for the new confirm too: after Ask, Allow on "Manage labels" needs confirming', async t => {
  const {view, post} = await gmailLocal(t);
  let labels = rowIn((await view('gmail', 'mail')).body, 'gmail.labels.manage');
  assert.equal(labels.allowNeedsConfirm, true, 'Allow would turn the proxy record on above its default');
  labels = rowIn((await post('permissions', {groupId: 'gmail.labels.manage', mode: 'ask', etag: labels.etag}, 'gmail', 'mail')).body, 'gmail.labels.manage');
  assert.equal(needsConfirm(labels, 'allow'), 'allow');
  assert.equal(needsConfirm(labels, 'ask'), null);
  assert.equal(rowIn((await view('gmail', 'mail')).body, 'gmail.drafts.write').allowNeedsConfirm, false, 'Allow there changes no record above its default');
});

test('a row with typed members folds its proxy record into its etag, and a saved proxy record alone is something to reset', async t => {
  const {f, view, post, record} = await gmailLocal(t), first = (await view('gmail', 'mail')).body, labels = rowIn(first, 'gmail.labels.manage');
  assert.equal(first.canReset, false);
  // The proxy record moves on its own (the callback wall, or a developer's proxy: true); the typed members stay at their defaults.
  f.app.runtime.proxyPolicy.set({connectionId: 'mail', row: 'group:gmail.labels.manage', mode: 'deny'});
  const before = record('mail', 'group:gmail.labels.manage'), page = (await view('gmail', 'mail')).body;
  assert.deepEqual([rowIn(page, 'gmail.labels.manage').policySource, page.canReset], ['default', true]);
  assert.notEqual(rowIn(page, 'gmail.labels.manage').etag, labels.etag);
  const answer = await post('permissions', {groupId: 'gmail.labels.manage', mode: 'ask', etag: labels.etag}, 'gmail', 'mail');
  assert.deepEqual([answer.status, answer.body.code], [409, 'view_changed']);
  assert.deepEqual(record('mail', 'group:gmail.labels.manage'), before, 'nothing was written');
});

// ---- permissionRow ----------------------------------------------------------------------------------------------------------
const decided = (capabilityId, extra = {}) => ({capabilityId, policyHash: `h-${capabilityId}`, mode: 'allow', defaultMode: 'allow', policySource: 'default', providerAccess: 'granted', status: 'active', ...extra});

test('permissionRow: "N of M work" over members that can work, the reasons as notes, unavailable rows, and no empty row is granted', () => {
  const markers = {'gmail.users.settings.delegates.get': 'service-account-only', 'gmail.users.settings.delegates.list': 'service-account-only', 'gmail.users.settings.cse.identities.get': 'workspace-cse-only',
    'gmail.users.settings.cse.identities.list': 'workspace-cse-only', 'gmail.users.settings.cse.keypairs.get': 'workspace-cse-only', 'gmail.users.settings.cse.keypairs.list': 'workspace-cse-only'};
  const members = PERMISSION_GROUPS.get('gmail').groups.find(group => group.id === 'gmail.labels.read').operations;
  assert.equal(members.length, 21);
  const decisions = members.map(id => decided(id, markers[id] ? {providerAccess: 'unavailable', unavailable: markers[id]} : {}));
  const row = permissionRow({id: 'gmail.labels.read', label: 'Access labels, filters and settings', effect: 'read', decisions});
  assert.deepEqual([row.access, row.working, row.total], ['granted', 15, 21]);
  assert.ok(row.notes.includes('service-account-only') && row.notes.includes('workspace-cse-only'), 'both reasons');
  const only = permissionRow({id: 'x', label: 'X', effect: 'read', decisions: decisions.filter(decision => decision.unavailable === 'service-account-only')});
  assert.equal(only.access, 'unavailable');
  assert.ok(JSON.stringify(only).includes(UNAVAILABLE_REASONS['service-account-only']), 'with the members\' reason');
  assert.ok(!('working' in only) && !('total' in only), 'nothing works, so no count');
  assert.notEqual(permissionRow({id: 'y', label: 'Y', effect: 'read', decisions: []}).access, 'granted', 'a row with no members is never granted');
  const plain = permissionRow({id: 'z', label: 'Z', effect: 'read', decisions: [decided('a')]});
  assert.ok(!('notes' in plain) && !('working' in plain) && !('total' in plain), 'a plain row keeps its keys');
});

test('permissionRow: a member that cannot do its job here says why and never decides the row\'s access', () => {
  const words = 'It cannot carry a message.', unsupported = decided('b', {status: 'unsupported', providerAccess: 'missing', reason: words});
  const mixed = permissionRow({id: 'w', label: 'W', effect: 'write', decisions: [decided('a'), unsupported]});
  assert.deepEqual([mixed.access, mixed.working, mixed.total], ['granted', 1, 2]);
  const none = permissionRow({id: 'v', label: 'V', effect: 'write', decisions: [unsupported]});
  assert.deepEqual([none.access, none.accessReason, 'addBlocked' in none], ['unavailable', words, false]);
});

test('correction 8: proxy members carry effect, sensitivity and reviewedAsRead, and a per-member hash the row etag folds in', t => {
  const h = signIn(t, 'github');
  account(h.store, 'pages', 'notion', 'https://api.notion.com');
  const listed = h.service.rows(h.service.app('notion'), h.store.get('connections', 'pages')), search = listed.find(item => item.id === 'notion.search.read');
  assert.equal(listed.length, 13);
  const [member] = search.members;
  assert.deepEqual([member.capability, member.member, member.reviewedAsRead, member.decision.effect, member.decision.sensitivity], [null, 'POST /v1/search', true, 'read', null]);
  assert.match(member.decision.policyHash, /^[0-9a-f]{64}$/);
  assert.deepEqual([search.view.mode, search.view.defaultMode], ['allow', 'allow'], 'a POST reviewed as a read may Allow by default');
});

// ---- Add access on version 2 definitions (part f) -------------------------------------------------------------------------------
const CLIENT = {clientId: 'rows-client', clientSecret: 'rows-secret'};
const REDIRECT = {google: 'http://127.0.0.1:59999/api/oauth/google/callback', github: 'http://127.0.0.1:59999/api/oauth/github/callback', slack: 'https://connect.example.com/oauth/slack/4320'};
const OWNER = {schemaVersion: 1, id: 'rows-owner', kind: 'local_owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'rows-owner'}};
/** A designated store with a ConnectionManager, a version 2 adapter for `providerId` and the app page service, wired the way
 *  server.mjs wires them; `groups` replaces the reviewed rows of some apps in both runtimes. */
function signIn(t, providerId, {groups = {}, definition = definitionOf(providerId)} = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-rows-every-app-')), clock = () => Date.UTC(2026, 9, 18, 12);
  const sim = new SIMULATORS[providerId]({...CLIENT, clock}), store = new Store({dataDir: directory, clock, localAuthority: 'new'}), vault = new Vault(directory);
  const request = async req => sim.request(req);
  const connections = new ConnectionManager({store, vault, request, clock});
  const provider = new OAuth2Provider(definition, {store, vault, connections, request, clock, ...CLIENT, publishing: 'testing', redirectUri: REDIRECT[providerId], allowHostedRedirect: REDIRECT[providerId].startsWith('https:')});
  connections.setOAuthProvider(provider);
  const runtime = new Runtime({store, connections, clock, ownerPrincipal: OWNER});
  const reviewed = new Map([...PERMISSION_GROUPS, ...Object.entries(groups).map(([appId, definition]) => [appId, validatePermissionGroups(definition)])]);
  Object.assign(runtime.permissions, {groups: reviewed}); Object.assign(runtime.proxyPolicy, {groups: reviewed});
  const access = appId => provider.access(provider.app(appId));
  const service = new AppDetailService({store, runtime, catalog: () => catalog, oauthProviderFor: () => provider, accessLevels: appId => offeredLevels(access(appId)), accessLevelOf: connection => heldLevel(access(connection.appId), connection.scopes)});
  connections.setUpgradeGuard((previous, next, confirmed) => service.pinUnconfirmed(previous, next, confirmed));
  t.after(() => {store.close(); rmSync(directory, {recursive: true, force: true});});
  const h = {store, sim, provider, runtime, service, connections,
    oauth: (id, appId, origin, scopes) => account(store, id, appId, origin, {authMethod: 'oauth', providerId, scopes}),
    page: (appId, ref) => service.view(appId, ref),
    async finish(started, grant) {const consent = sim.consent(started.authorizationUrl, {grant}); return provider.callback({state: consent.state, code: consent.code, flowId: started.flowId});}};
  return h;
}
const addOf = (page, groupId) => rowIn(page, groupId)?.addAccess?.body.scopes ?? null;

test('Add on Manage labels, Mark, Trash, Import and the labels.delete member asks for exactly gmail.modify (spec line 525)', t => {
  const h = signIn(t, 'google');
  seedGmail(h.store);
  h.oauth('mail', 'gmail', GMAIL, [READONLY, COMPOSE]);
  const page = h.page('gmail', 'mail');
  // F10.7: labels.delete sits in "Delete drafts, labels or filters" since the delete split.
  for (const groupId of ['gmail.labels.manage', 'gmail.messages.mark', 'gmail.messages.trash', 'gmail.messages.import', 'gmail.items.delete']) assert.deepEqual(addOf(page, groupId), [MODIFY], groupId);
  // leastPrivilegedExtra itself is unchanged: under a predicate that admits everything it still picks the full mailbox.
  assert.deepEqual(leastPrivilegedExtra(scopeAlternatives({requiredScopes: FACTS.apps.gmail.methods['gmail.users.labels.create']}).scopeSets, [READONLY, COMPOSE]), [MAILBOX]);
});

test('Add: the full-mailbox deletes are never offered, so their row offers no Add; the deletes split out of it add gmail.modify (spec lines 533 and 1170)', t => {
  // F10.7: messages.delete, batchDelete and threads.delete are marked not-requested, and drafts, labels and filters deletes left
  // "Permanently delete emails" for their own row.
  const h = signIn(t, 'google');
  seedGmail(h.store);
  h.oauth('mail', 'gmail', GMAIL, [READONLY, COMPOSE]);
  assert.deepEqual(addOf(h.page('gmail', 'mail'), 'gmail.items.delete'), [MODIFY]);
  h.oauth('mail', 'gmail', GMAIL, [MODIFY]);
  const purge = rowIn(h.page('gmail', 'mail'), 'gmail.permanent.delete'), items = rowIn(h.page('gmail', 'mail'), 'gmail.items.delete');
  assert.equal(purge.access, 'unavailable');
  assert.ok(!('addAccess' in purge) && !('addBlocked' in purge));
  assert.deepEqual([items.access, 'addAccess' in items], ['granted', false], 'gmail.modify covers the typed labels delete of its new row');
});

test('Add never offers gmail.labels or gmail.readonly on a full account, even where the map documents them (spec line 534)', t => {
  const h = signIn(t, 'google');
  seedGmail(h.store);
  h.oauth('mail', 'gmail', GMAIL, [SETTINGS]);
  const asked = rowsOf(h.page('gmail', 'mail')).flatMap(item => item.addAccess?.body.scopes ?? []);
  assert.ok(asked.length > 0);
  assert.ok(!asked.includes(LABELS) && !asked.includes(READONLY) && !asked.includes(MAILBOX), asked.join(' '));
  assert.deepEqual([...new Set(asked)], [MODIFY]);
});

const CONV_WRITE = [['channels:write'], ['groups:write'], ['im:write'], ['mpim:write']], HISTORY = [['channels:history'], ['groups:history'], ['im:history'], ['mpim:history']];
/** Add access for one member that lacks provider access, asked for by its own reviewed row, as the page asks for it. */
const addFor = (h, appId, ref, groupId, scopeSets) => h.service.addAccess(h.service.app(appId), h.store.get('connections', ref), [{decision: {providerAccess: 'missing', scopeSets, groupId}}]);

test('usable scopes: the full level and the in-context scopes of the member\'s own row only, never read-level or never-request; version 1 unchanged', t => {
  const slack = signIn(t, 'slack', {groups: {slack: rows('slack')}}), on = groupId => slack.provider.usableFor(slack.provider.app('slack'), groupId);
  assert.deepEqual(['im:write', 'mpim:write', 'channels:write', 'groups:write', 'admin', 'search:read.public', 'channels:manage', 7].map(on('slack.conversations.mark')), [true, true, false, false, false, false, false, false]);
  assert.deepEqual(['channels:write', 'groups:write'].map(on('slack.channels.manage')), [true, true], 'an in-context scope, on the row it names');
  slack.oauth('chat', 'slack', 'https://slack.com', ['channels:read', 'channels:history', 'users:read', 'chat:write']);
  assert.deepEqual(addFor(slack, 'slack', 'chat', 'slack.conversations.mark', CONV_WRITE).addAccess.body.scopes, ['im:write'], 'Mark as read never asks for channels:write');
  assert.deepEqual(addFor(slack, 'slack', 'chat', 'slack.channels.manage', CONV_WRITE).addAccess.body.scopes, ['channels:write']);
  assert.deepEqual(addFor(slack, 'slack', 'chat', 'slack.conversations.mark', [['channels:write'], ['groups:write']]), {addBlocked: NOT_OFFERED_WORDS}, 'nothing usable is left to ask for');
  assert.equal(NOT_OFFERED_WORDS, `Not offered: ${UNAVAILABLE_REASONS['not-requested']}`);
  // Open question 23: an account holding no history scope is offered exactly one (im:history is required, so a version 2 account holds it).
  slack.oauth('quiet', 'slack', 'https://slack.com', ['channels:read', 'users:read']);
  const history = addFor(slack, 'slack', 'quiet', 'slack.messages.read', HISTORY).addAccess.body.scopes;
  assert.equal(history.length, 1); assert.ok(HISTORY.flat().includes(history[0]), history.join(' '));
  // start() checks level membership only, since it knows no row: an in-context scope passes by name, and the card gates a widening start.
  assert.doesNotThrow(() => slack.provider.plan({connectionId: 'chat', scopes: ['channels:write']}));
  // An account request plans by the member's own row the same way.
  const map = {id: 'slack', operations: [{id: 'POST /conversations.join', capabilityId: 'join', method: 'POST', path: '/conversations.join'}, {id: 'POST /conversations.mark', capabilityId: 'mark', method: 'POST', path: '/conversations.mark'}]};
  const reviewed = slack.runtime.permissions.groups, narrowed = rows('slack');
  narrowed.groups.find(group => group.id === 'slack.conversations.mark').scopeSets = [['channels:write'], ['groups:write']];
  assert.deepEqual(operationScopes(slack.provider, 'slack', map, 'join', 'full', reviewed), {scopes: ['channels:write'], grantable: true});
  assert.deepEqual(operationScopes(slack.provider, 'slack', map, 'mark', 'full', reviewed), {scopes: [], grantable: true}, 'im:write is required, so the level covers it');
  assert.deepEqual(operationScopes(slack.provider, 'slack', map, 'mark', 'full', new Map([['slack', validatePermissionGroups(narrowed)]])), {scopes: [], grantable: false}, 'another row\'s in-context scope');
  // GitHub "Access gists" asks for gist (spec line 526), and an attestation delete plans no grantable sign-in.
  const hub = signIn(t, 'github', {groups: {github: rows('github')}}), hubMap = {id: 'github', operations: [{id: 'GET /gists', capabilityId: 'gists', method: 'GET', path: '/gists'},
    {id: 'DELETE /users/{username}/attestations/{attestation_id}', capabilityId: 'gone', method: 'DELETE', path: '/users/{username}/attestations/{attestation_id}'}]};
  hub.oauth('hub', 'github', 'https://api.github.com', ['read:user', 'repo']);
  assert.deepEqual(addFor(hub, 'github', 'hub', 'github.gists.read', [['gist']]).addAccess.body.scopes, ['gist']);
  assert.deepEqual([operationScopes(hub.provider, 'github', hubMap, 'gists', 'full', hub.runtime.permissions.groups), operationScopes(hub.provider, 'github', hubMap, 'gone', 'full', hub.runtime.permissions.groups)],
    [{scopes: ['gist'], grantable: true}, {scopes: [], grantable: false}]);
  // Gmail: the read level and the never list are never usable, and start() refuses a read-level scope by name.
  const google = signIn(t, 'google');
  assert.deepEqual([MODIFY, SETTINGS, READONLY, LABELS, MAILBOX].map(google.provider.usableFor(google.provider.app('gmail'), 'gmail.labels.manage')), [true, true, false, false, false]);
  google.oauth('mail', 'gmail', GMAIL, [MODIFY]);
  assert.throws(() => google.provider.plan({connectionId: 'mail', scopes: [READONLY]}), {code: 'invalid_scope'});
  // Version 1 has no usable-scope rule: its map-documented rule, and one member blocking its row, stay as they are (open question 1).
  const v1 = signIn(t, 'github', {definition: v1Definition('github')});
  assert.equal(v1.provider.usableFor(v1.provider.app('github'), 'github.gists.read'), null);
  v1.oauth('old', 'github', 'https://api.github.com', ['repo']);
  assert.deepEqual(addFor(v1, 'github', 'old', 'github.gists.read', [['gist']]), {addBlocked: 'This permission is not available through sign-in for this app.'}, 'no map documents gist here');
});

test('Slack: Add on "Mark as read and open direct messages" asks for im:write, never channels:write; "Manage channels" offers channels:write (spec line 535)', t => {
  const h = signIn(t, 'slack', {groups: {slack: rows('slack')}});
  h.oauth('chat', 'slack', 'https://slack.com', ['channels:read', 'channels:history', 'users:read', 'chat:write']);
  const page = h.page('slack', 'chat');
  assert.deepEqual(addOf(page, 'slack.conversations.mark'), ['im:write']);
  assert.ok(addOf(page, 'slack.channels.manage').includes('channels:write'), 'an in-context scope, on the row it names');
  // The start still takes it by name (plan() checks level membership only); the upgrade card is what gates a widening start.
  assert.doesNotThrow(() => h.provider.plan({connectionId: 'chat', scopes: ['channels:write']}));
});

/** GitHub at the 'required' consent policy: a sign-in asks for the level's required scopes and the ones it names, so Add asks only for
 *  what its row needs. The fixture's 'full' policy asks for the whole full level every time. */
const asked = () => ({...definitionOf('github'), consentPolicy: {testing: 'required', production: 'required'}});
test('Add on fixture GitHub "Access gists" asks for gist; its card lists the row as a proxy row, and the confirmed start asks for exactly read:user, repo and gist', t => {
  const h = signIn(t, 'github', {groups: {github: rows('github')}, definition: asked()});
  h.oauth('hub', 'github', 'https://api.github.com', ['read:user', 'repo']);
  const gists = rowIn(h.page('github', 'hub'), 'github.gists.read');
  assert.deepEqual([gists.access, gists.addAccess?.body.scopes], ['missing', ['gist']]);
  assert.deepEqual(gists.upgrade.rows.find(item => item.groupId === 'github.gists.read'), {groupId: 'github.gists.read', label: 'Access gists', typed: false, proxy: true});
  const card = h.service.upgradeFor(h.provider, gists.addAccess.body);
  assert.equal(card.etag, gists.upgrade.etag);
  const started = h.provider.start(gists.addAccess.body, {upgrade: {etag: card.etag, scopes: card.scopes}});
  assert.deepEqual(new URL(started.authorizationUrl).searchParams.get('scope').split(' ').sort(), ['gist', 'read:user', 'repo']);
});

test('correction 1: a reconnect_required account\'s Add access lists the proxy row it turns on and needs the confirm', t => {
  const h = signIn(t, 'github', {groups: {github: rows('github')}});
  h.oauth('hub', 'github', 'https://api.github.com', ['read:user', 'repo']);
  h.store.put('connections', {...h.store.get('connections', 'hub'), status: 'reconnect_required'});
  const card = h.service.upgradeFor(h.provider, {connectionId: 'hub', scopes: ['gist']});
  assert.ok(card.rows.some(item => item.groupId === 'github.gists.read' && item.proxy === true && item.typed === false));
});

test('the callback wall: a GitHub grant beyond the confirmed card saves "Access profiles" at Ask; the confirmed row stays at its default', async t => {
  const h = signIn(t, 'github', {groups: {github: rows('github')}, definition: asked()});
  const first = h.provider.start({appId: 'github', level: 'full'});
  const connection = await h.finish(first);
  assert.deepEqual([...connection.scopes].sort(), ['read:user', 'repo'], 'the level\'s required scopes only');
  const gists = rowIn(h.page('github', connection.id), 'github.gists.read'), card = h.service.upgradeFor(h.provider, gists.addAccess.body);
  const started = h.provider.start(gists.addAccess.body, {upgrade: {etag: card.etag, scopes: card.scopes}});
  await h.finish(started, {add: ['read:org']});
  const proxy = row => h.runtime.proxyPolicy.view(connection.id).find(entry => entry.row === row);
  assert.deepEqual([proxy('group:github.profile.read').mode, proxy('group:github.profile.read').source], ['ask', 'saved'], 'read:org was not on the confirmed card');
  assert.deepEqual([proxy('group:github.gists.read').mode, proxy('group:github.gists.read').source], ['allow', 'default']);
});

test('correction 1: the wall counts a proxy row as confirmed only when the card listed it; planned scopes alone confirm nothing', t => {
  const h = signIn(t, 'github', {groups: {github: rows('github')}});
  const proxy = (ref, row) => h.runtime.proxyPolicy.view(ref).find(entry => entry.row === row);
  // The same grant, confirmed with the same scopes: an account whose card could read its proxy rows listed "Access gists" on it, and
  // one connected for no API address could not, so its card listed nothing for the proxy.
  for (const [ref, origins, expected] of [['shown', ['https://api.github.com'], ['allow', 'default']], ['unseen', [], ['ask', 'saved']]]) {
    h.oauth(ref, 'github', 'https://api.github.com', ['read:user', 'repo', 'gist']);
    const next = h.store.get('connections', ref);
    h.service.pinUnconfirmed({...next, scopes: ['read:user', 'repo'], allowedOrigins: origins}, next, ['read:user', 'repo', 'gist']);
    assert.deepEqual([proxy(ref, 'group:github.gists.read').mode, proxy(ref, 'group:github.gists.read').source], expected, ref);
  }
  // No card confirmed at all: every proxy row the grant turns on at its default Allow waits at Ask.
  h.oauth('bare', 'github', 'https://api.github.com', ['read:user', 'repo', 'gist']);
  h.service.pinUnconfirmed({...h.store.get('connections', 'bare'), scopes: ['read:user', 'repo']}, h.store.get('connections', 'bare'), undefined);
  assert.equal(proxy('bare', 'group:github.gists.read').mode, 'ask');
});

test('the wall reads a typed operation with no map entry by the row its request sits in (correction 3)', t => {
  const h = signIn(t, 'github', {groups: {github: rows('github')}});
  const [gists] = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {'/gists': {get: {operationId: 'listGists', responses: {200: {description: 'ok'}}}}}}})
    .capabilities.map(cap => ({...cap, status: 'active'}));
  h.store.put('capabilities', gists);
  h.oauth('hub', 'github', 'https://api.github.com', ['read:user', 'repo', 'gist']);
  const next = h.store.get('connections', 'hub'), decide = () => h.runtime.permissions.decision(h.store.get('connections', 'hub'), gists);
  assert.deepEqual([decide().providerAccess, decide().mode, decide().policySource], ['granted', 'allow', 'default']);
  h.service.pinUnconfirmed({...next, scopes: ['read:user', 'repo']}, next, ['read:user', 'repo']);
  assert.deepEqual([decide().mode, decide().policySource], ['ask', 'saved'], 'gist was granted beyond what was confirmed');
});

// ---- continuations (part f) ------------------------------------------------------------------------------------------------
test('continuations: an unavailable member plans no grantable sign-in, and a pending account for it is blocked', async t => {
  const h = signIn(t, 'google', {groups: {gmail: rows('gmail')}}), caps = seedGmail(h.store);
  const map = h.store.get('applicationMaps', 'gmail'), reviewed = h.runtime.permissions.groups;
  assert.deepEqual(operationScopes(h.provider, 'gmail', map, caps['gmail.users.settings.delegates.list'].id, 'full', reviewed), {scopes: [], grantable: false});
  assert.deepEqual(operationScopes(h.provider, 'gmail', map, caps['gmail.users.labels.list'].id, 'full', reviewed), {scopes: [], grantable: true}, 'the control: gmail.modify covers it');
  assert.deepEqual(operationScopes(h.provider, 'gmail', map, caps['gmail.users.settings.delegates.list'].id), operationScopes(h.provider, 'gmail', map, caps['gmail.users.settings.delegates.list'].id, 'full', PERMISSION_GROUPS), 'the shipped rows are the default');
  const f = await handoffFixture(t);
  const handoffCaps = seedGmail(f.store);
  account(f.store, 'mail', 'gmail', GMAIL, {authMethod: 'oauth', scopes: [MODIFY]});
  const groups = new Map([...PERMISSION_GROUPS, ['gmail', validatePermissionGroups(rows('gmail'))]]);
  Object.assign(f.runtime.permissions, {groups});
  const pending = cap => f.service.pendingView({pendingConnection: {connectionId: 'mail', identity: {id: 'mail'}, scopes: [MODIFY]}}, cap).afterConfirm;
  assert.equal(pending(handoffCaps['gmail.users.settings.delegates.list']), 'blocked');
  assert.equal(pending(handoffCaps['gmail.users.labels.list']), 'runs_now');
});

test('continuations: a held operation with no map entry plans its sign-in from the row its request sits in, as its decision reads it (correction 3)', async t => {
  const hub = signIn(t, 'github', {groups: {github: rows('github')}}), f = await handoffFixture(t);
  const caps = Object.fromEntries(compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
    '/gists': {get: {operationId: 'listGists', responses: {200: {description: 'ok'}}}},
    '/users/{username}/attestations/{attestation_id}': {delete: {operationId: 'deleteAttestation', parameters: [P('username'), P('attestation_id')], responses: {204: {description: 'gone'}}}}}}})
    .capabilities.map(cap => [cap.name, {...cap, status: 'active'}]));
  for (const cap of Object.values(caps)) f.store.put('capabilities', cap);
  Object.assign(f.runtime.permissions, {groups: hub.runtime.permissions.groups});
  assert.equal(f.store.get('applicationMaps', 'github') ?? null, null, 'GitHub is reviewed by request, with no map');
  const plan = cap => f.service.signInPlan({grantEntry: {appId: 'github', capabilityId: cap.id}}, hub.provider);
  assert.deepEqual([plan(caps.listGists), plan(caps.deleteAttestation)], [{scopes: ['gist'], grantable: true}, {scopes: [], grantable: false}]);
  account(f.store, 'hub', 'github', 'https://api.github.com', {authMethod: 'oauth', scopes: ['read:user', 'repo']});
  const decide = cap => f.runtime.permissions.decision(f.store.get('connections', 'hub'), cap);
  assert.deepEqual([decide(caps.listGists).providerAccess, decide(caps.listGists).scopeSets, decide(caps.deleteAttestation).providerAccess], ['missing', [['gist']], 'unavailable'], 'the decision reads the same row data');
  // Without the capability nothing places it: as before, no row data.
  assert.deepEqual(operationScopes(hub.provider, 'github', null, caps.listGists.id, 'full', hub.runtime.permissions.groups), {scopes: [], grantable: true});
});

// ---- the page model (part k) ------------------------------------------------------------------------------------------------
test('the page model: a row that needs access keeps its options beside Add; locked rows have none; notes, counts and "Not offered" render', () => {
  const base = {groupId: 'g', label: 'Manage labels', effect: 'write', mode: 'allow', defaultMode: 'allow', allowedModes: ['allow', 'ask', 'deny'], policySource: 'default', reviewRequired: false, operations: 3, etag: 'e'};
  const detail = {app: {id: 'gmail', name: 'Gmail'}, accounts: [{accountRef: 'mail', displayName: 'Mail', initial: 'M', status: 'ready'}], selectedAccountRef: 'mail', connectionState: 'connected', sections: [{id: 'write', label: 'Write', rows: [
    {...base, access: 'missing', addAccess: {providerId: 'google', body: {connectionId: 'mail', scopes: [MODIFY]}}, working: 2, total: 3, notes: ['raw_requests_ask', 'service-account-only', 'beta']},
    {...base, groupId: 'locked', locked: true, mode: 'deny', allowedModes: ['deny']},
    {...base, groupId: 'blocked', access: 'missing', addBlocked: 'Not offered: Fabric never asks for the permission this needs.'}]}]};
  const [needs, locked, blocked] = describeApp(detail).sections[0].rows;
  assert.deepEqual(needs.options.map(option => option.mode), ['allow', 'ask', 'deny']);
  assert.ok(needs.add && needs.needsAccess);
  assert.deepEqual(locked.options, []);
  const text = JSON.stringify(needs);
  for (const words of ['2 of 3 work', 'Raw requests still ask', UNAVAILABLE_REASONS['service-account-only'], 'In beta at the provider. It may change or stop working.']) assert.ok(text.includes(words), words);
  assert.ok(JSON.stringify(blocked).includes(NOT_OFFERED));
});

test('the page\'s note words are the engine\'s own: every unavailable reason, every condition, and raw requests that still ask', () => {
  assert.deepEqual(Object.keys(NOTE_WORDS).sort(), [...Object.keys(UNAVAILABLE_REASONS), ...Object.keys(CONDITION_WORDS), 'raw_requests_ask'].sort());
  for (const [code, words] of Object.entries({...UNAVAILABLE_REASONS, ...CONDITION_WORDS})) assert.equal(NOTE_WORDS[code], words, code);
  assert.ok(Object.isFrozen(NOTE_WORDS));
});

test('the page model: a row nothing in can work says why once and keeps its choice; a row with no Add says why; a note the page does not know is not shown', () => {
  const base = {label: 'Row', effect: 'read', mode: 'allow', defaultMode: 'allow', allowedModes: ['allow', 'ask', 'deny'], policySource: 'default', reviewRequired: false, operations: 3, etag: 'e'};
  const detail = {app: {id: 'notion', name: 'Notion'}, accounts: [], selectedAccountRef: 'pages', connectionState: 'connected', sections: [{id: 'read', label: 'Read', rows: [
    {...base, groupId: 'one', access: 'unavailable', accessReason: UNAVAILABLE_REASONS['client-credentials-only'], notes: ['client-credentials-only']},
    {...base, groupId: 'two', access: 'unavailable', accessReason: 'None of these can work through a sign-in.', notes: ['no-oauth-scope', 'workspace-cse-only']},
    {...base, groupId: 'person', access: 'missing', addBlocked: 'Ask the app for a link to add this access.'},
    {...base, groupId: 'never', access: 'missing', addBlocked: NOT_OFFERED_WORDS},
    {...base, groupId: 'plain', access: 'granted', notes: ['a-later-code']}]}]};
  const [one, two, person, never, plain] = describeApp(detail).sections[0].rows;
  assert.deepEqual([one.needsAccess, one.accessNote, one.noteText, one.options.length], [false, UNAVAILABLE_REASONS['client-credentials-only'], [], 3], 'its reason once, and the choice stays');
  assert.deepEqual([two.accessNote, two.noteText], ['None of these can work through a sign-in.', [UNAVAILABLE_REASONS['no-oauth-scope'], UNAVAILABLE_REASONS['workspace-cse-only']]]);
  assert.deepEqual([person.needsAccess, person.add, person.accessNote, person.addNote], [true, null, 'Needs more access', 'Ask the app for a link to add this access.']);
  assert.equal(never.addNote, UNAVAILABLE_REASONS['not-requested'], '"Not offered" is the label, so the note says only why');
  assert.deepEqual([plain.accessNote, plain.noteText, plain.count, plain.addNote], [null, [], null, null]);
});

/** Just enough of the DOM for the row code of public/hosted-app.js: children, attributes, text, change listeners and after(). */
class PageNode {
  constructor(tag, attrs = {}, ...children) {Object.assign(this, {tag, attrs, listeners: {}, next: null, children: children.flat(Infinity).filter(child => child !== null && child !== undefined && child !== false)});}
  addEventListener(type, run) {this.listeners[type] = run;}
  after(node) {this.next = node;}
  get textContent() {return this.children.map(child => child instanceof PageNode ? child.textContent : String(child)).join(' ');}
  all() {return [this, ...this.children.filter(child => child instanceof PageNode).flatMap(child => child.all())];}
}
/** The page's own rowNode(), run with the exported page functions and a stand-in DOM; every action it sends lands in `sent`. */
function pageRowNode(detail, sent) {
  const page = readFileSync(new URL('../public/hosted-app.js', import.meta.url), 'utf8'), code = page.slice(page.indexOf('  function rowNode('), page.indexOf('  function render('));
  return runInNewContext(`${code}; rowNode`, {el: (tag, attrs, ...children) => new PageNode(tag, attrs, ...children), detail, base: baseFor('/connectors/gmail'),
    act: action => sent.push(action), confirmFirst: action => sent.push(action), confirmBox: (text, label, run) => ({text, label, run}), needsConfirm, confirmText, confirmedRowRequest, rowRequest});
}

test('the page shows a row that needs access with its choice beside Add, "Needs more access", its notes and its count; "Not offered" says why', () => {
  const base = {label: 'Manage labels', effect: 'write', mode: 'ask', defaultMode: 'allow', allowedModes: ['allow', 'ask', 'deny'], policySource: 'saved', reviewRequired: false, operations: 3, etag: 'e', allowNeedsConfirm: true};
  const detail = {app: {id: 'gmail', name: 'Gmail'}, accounts: [{accountRef: 'mail', displayName: 'Mail', initial: 'M', status: 'ready'}], selectedAccountRef: 'mail', connectionState: 'connected', sections: [{id: 'write', label: 'Write', rows: [
    {...base, groupId: 'needs', access: 'missing', addAccess: {providerId: 'google', body: {connectionId: 'mail', scopes: [MODIFY]}}, working: 2, total: 3, notes: ['raw_requests_ask', 'service-account-only', 'beta']},
    {...base, groupId: 'locked', locked: true, mode: 'deny', allowedModes: ['deny']},
    {...base, groupId: 'blocked', access: 'missing', addBlocked: NOT_OFFERED_WORDS},
    {...base, groupId: 'gone', access: 'unavailable', accessReason: UNAVAILABLE_REASONS['workspace-cse-only'], notes: ['workspace-cse-only']}]}]};
  const sent = [], model = describeApp(detail), rowNode = pageRowNode(detail, sent), [needs, locked, blocked, gone] = model.sections[0].rows.map(row => rowNode(model, row));
  const select = needs.all().find(node => node.tag === 'select');
  assert.deepEqual(select.children.map(option => option.attrs.value), ['allow', 'ask', 'deny'], 'the choice stays beside Add');
  assert.ok(needs.all().some(node => node.tag === 'button' && node.textContent === 'Add'));
  for (const words of ['Needs more access', '2 of 3 work', 'Raw requests still ask', UNAVAILABLE_REASONS['service-account-only'], CONDITION_WORDS.beta]) assert.ok(needs.textContent.includes(words), words);
  assert.ok(!needs.textContent.includes('Needs additional access'));
  // Allow there is confirmed by the row's own flag (correction 4), and the confirm sends confirmAllow.
  select.value = 'allow'; select.listeners.change();
  assert.equal(needs.next.label, 'Allow without asking');
  needs.next.run();
  assert.deepEqual(JSON.parse(JSON.stringify(sent.at(-1).request)), {path: '/api/ui/apps/gmail/accounts/mail/permissions', body: {groupId: 'needs', mode: 'allow', etag: 'e', confirmAllow: true}});
  assert.ok(locked.textContent.includes('Never. Fabric keeps this off.') && !locked.all().some(node => node.tag === 'select'), 'a locked row is as it was');
  assert.ok(blocked.textContent.includes('Not offered') && blocked.textContent.includes(UNAVAILABLE_REASONS['not-requested']) && !blocked.textContent.includes('Not available'));
  assert.ok(!blocked.all().some(node => node.tag === 'button') && blocked.all().some(node => node.tag === 'select'), 'no Add, and still a choice');
  assert.ok(gone.textContent.includes(UNAVAILABLE_REASONS['workspace-cse-only']) && gone.all().some(node => node.tag === 'select'));
  assert.equal(gone.textContent.split(UNAVAILABLE_REASONS['workspace-cse-only']).length, 2, 'its reason is said once');
});

test('correction 4: the owner page\'s confirm follows the row\'s own flag, in its words and in the confirmAllow a review sends', async t => {
  const review = {groupId: 'g', label: 'Manage labels', effect: 'write', mode: 'ask', defaultMode: 'allow', allowedModes: ['allow', 'ask', 'deny'], etag: 'e', reviewRequired: true, allowNeedsConfirm: true};
  const detail = {app: {id: 'gmail'}, selectedAccountRef: 'mail'};
  assert.equal(needsConfirm(review, 'allow'), 'review');
  assert.match(confirmText(review, 'allow', 'review'), /generated from the provider's documentation\. .*Manage labels: Allow means/, 'the old rule (a write at a default Allow) would not have said it');
  assert.deepEqual(confirmedRowRequest(detail, review, 'allow', 'review').body, {groupId: 'g', mode: 'allow', etag: 'e', review: true, confirmAllow: true});
  const quiet = {...review, effect: 'read', defaultMode: 'ask', sensitive: 'secrets', allowNeedsConfirm: false};
  assert.doesNotMatch(confirmText(quiet, 'allow', 'review'), /Allow means/, 'the flag wins over the earlier rule');
  assert.deepEqual(confirmedRowRequest(detail, quiet, 'allow', 'review').body, {groupId: 'g', mode: 'allow', etag: 'e', review: true});
  assert.deepEqual(confirmedRowRequest(detail, review, 'allow', 'allow').body, {groupId: 'g', mode: 'allow', etag: 'e', confirmAllow: true});
  // A row without the flag keeps the earlier rule.
  assert.match(confirmText({...review, allowNeedsConfirm: undefined, defaultMode: 'ask'}, 'allow', 'review'), /Allow means/);
  assert.deepEqual(confirmedRowRequest(detail, {...review, allowNeedsConfirm: undefined}, 'allow', 'review').body, {groupId: 'g', mode: 'allow', etag: 'e', review: true});
  // Through the owner's own server: after Ask, the confirmed request the page builds for "Manage labels" is taken, and both records are Allow.
  const {view, post, proxyRow} = await gmailLocal(t);
  let labels = rowIn((await view('gmail', 'mail')).body, 'gmail.labels.manage');
  const page = (await post('permissions', {groupId: 'gmail.labels.manage', mode: 'ask', etag: labels.etag}, 'gmail', 'mail')).body;
  labels = rowIn(page, 'gmail.labels.manage');
  const request = confirmedRowRequest(page, labels, 'allow', needsConfirm(labels, 'allow'));
  assert.equal(request.path, '/api/ui/apps/gmail/accounts/mail/permissions');
  assert.equal((await post('permissions', request.body, 'gmail', 'mail')).status, 200);
  assert.deepEqual([proxyRow('mail', 'group:gmail.labels.manage').mode, proxyRow('mail', 'group:gmail.labels.manage').source], ['allow', 'saved']);
});

test('the owner workspace says "Not offered" for an operation no sign-in can run: after a lock, before missing access, whatever its mode', () => {
  const flow = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8'), code = flow.slice(flow.indexOf('function operationAvailability('), flow.indexOf('function permissionRow('));
  const availability = runInNewContext(`${code}; operationAvailability`, {browserConnectionState: () => ({canTest: true, label: ''})}), said = (...args) => [...availability(...args)];
  const ready = {id: 'mail', driver: 'http', status: 'ready'}, operation = {capabilityId: 'c', status: 'active', mode: 'allow', executable: false, providerAccess: 'unavailable', unavailable: 'service-account-only'};
  assert.deepEqual(said(operation, ready), ['Not offered', 'neutral']);
  assert.deepEqual(said({...operation, mode: 'deny'}, ready), ['Not offered', 'neutral']);
  assert.deepEqual(said({...operation, locked: true}, ready), ['Fabric keeps this off', 'neutral'], 'a lock keeps its words');
  assert.deepEqual(said({...operation, providerAccess: 'missing', unavailable: undefined}, ready), ['Needs access', 'warn']);
});

// ---- the shipped markers on the page (part l) -------------------------------------------------------------------------------
test('the shipped markers reach the owner page: Gmail settings reads say how many work and why the rest cannot; Notion says what is beta and what no sign-in can do', async t => {
  const {store, view} = await gmailLocal(t), shown = page => describeApp(page).sections.flatMap(section => section.rows);
  const gmail = (await view('gmail', 'mail')).body, labels = rowIn(gmail, 'gmail.labels.read');
  assert.deepEqual([labels.working, labels.total, labels.notes], [1, 2, ['service-account-only']], 'labels.list works; delegates.list never can');
  assert.deepEqual(shown(gmail).filter(row => row.groupId === 'gmail.labels.read').map(row => [row.count, row.noteText]), [['1 of 2 work', [UNAVAILABLE_REASONS['service-account-only']]]]);
  account(store, 'pages', 'notion', 'https://api.notion.com');
  const notion = (await view('notion', 'pages')).body, connection = rowIn(notion, 'notion.connection.manage'), agents = rowIn(notion, 'notion.agents.read');
  assert.deepEqual([connection.access, connection.accessReason, connection.notes], ['unavailable', UNAVAILABLE_REASONS['client-credentials-only'], ['client-credentials-only']]);
  assert.deepEqual([agents.access, agents.notes], ['unknown', ['beta', 'plan-dependent']]);
  const [manage] = shown(notion).filter(row => row.groupId === 'notion.connection.manage'), [beta] = shown(notion).filter(row => row.groupId === 'notion.agents.read');
  assert.deepEqual([manage.accessNote, manage.noteText, manage.needsAccess], [UNAVAILABLE_REASONS['client-credentials-only'], [], false]);
  assert.deepEqual(beta.noteText, [CONDITION_WORDS.beta, CONDITION_WORDS['plan-dependent']]);
});

// ---- F10.18: GitHub's certified actions on their rows ------------------------------------------------------------------------
// Step 18's live pass certified GitHub's 15 actions, which place with no map. Each joins the row it declares (F10.11 part k): a write
// row with actions offers Allow for them behind the standing consent, while the row's raw requests keep the proxy's own choices.
test('F10.18: with GitHub\'s certified actions, a write row offers Allow for its actions, raw requests on it still ask, and the page drops the raw-requests-only notice', async t => {
  const {f, store, view, post, proxyRow} = await local(t, {shipped: true}), page = (await view()).body;
  assert.equal(rowsOf(page).length, 13);
  assert.deepEqual(page.discovery, {state: 'ready'}, 'reviewed actions are typed operations, so the page never says raw requests only');
  const issues = rowIn(page, 'github.issues.write');
  assert.deepEqual([issues.mode, issues.allowedModes, issues.allowNeedsConfirm], ['ask', ['allow', 'ask', 'deny'], true]);
  assert.deepEqual(rowIn(page, 'github.gists.write').allowedModes, ['ask', 'deny'], 'a write row no action joins offers what its raw requests may');
  assert.equal((await post('permissions', {groupId: 'github.issues.write', mode: 'allow', etag: issues.etag})).body.code, 'confirm_required');
  const set = await post('permissions', {groupId: 'github.issues.write', mode: 'allow', etag: issues.etag, confirmAllow: true});
  assert.equal(set.status, 200);
  assert.deepEqual([rowIn(set.body, 'github.issues.write').mode, rowIn(set.body, 'github.issues.write').notes], ['allow', ['raw_requests_ask']]);
  const connection = store.get('connections', 'tok'), actions = store.list('capabilities').filter(capability => capability.driver === 'action' && capability.appId === 'github');
  assert.equal(actions.length, 15);
  const issueActions = actions.filter(capability => ['create-issue', 'update-issue', 'update-labels'].some(key => capability.id.startsWith(`github.action.${key}.`)));
  assert.deepEqual(issueActions.map(capability => f.app.runtime.permissions.decision(connection, capability).mode), ['allow', 'allow', 'allow']);
  assert.deepEqual([proxyRow('tok', 'group:github.issues.write').mode, proxyRow('tok', 'group:github.issues.write').allowedModes], ['ask', ['ask', 'deny']]);
  const job = await f.app.runtime.createProxyJob({connectionId: 'tok', request: {method: 'POST', path: '/repos/o/r/issues', body: {title: 't'}}}, owner);
  assert.deepEqual([job.status, f.api.length], ['awaiting_approval', 0], 'a raw request on the row still asks, and nothing was sent');
});

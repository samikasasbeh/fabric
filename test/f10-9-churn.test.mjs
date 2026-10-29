import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {OPTION_SOURCES} from '../lib/option-sources.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';
import {canonicalHash, compileOpenApi} from '../lib/compiler.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {appEntry, ROOT} from '../scripts/defaults-golden.mjs';
import {validateAuthDefinition} from '../contracts/auth-definition.mts';
import {SIMULATORS} from './fixtures/oauth-simulators.mjs';

// F10.9 listed churn (docs/F10.9-BUILD-MAP.md section 6, part c, R5, open points Important 1 and Minor 8). Two snapshots recorded at
// F10.9's base, before part b: test/fixtures/access/f10-9-loaders.before.json holds what the shipped permission-row, option-source and
// proxy loaders return, and test/fixtures/access/f10-9-bindings.before.json every proxy-row binding, every typed binding over the
// synthetic Gmail and Calendar maps, and each app's defaults data hash. F10.9 moves none of them: the new row fields and loaders are
// declared by no shipped file, and bindings leave out the Slack identity's new userId, which only repeats the second part of its id.
const LOADERS = JSON.parse(readFileSync(new URL('./fixtures/access/f10-9-loaders.before.json', import.meta.url), 'utf8'));
const BEFORE = JSON.parse(readFileSync(new URL('./fixtures/access/f10-9-bindings.before.json', import.meta.url), 'utf8'));
const F107 = JSON.parse(readFileSync(new URL('./fixtures/access/f10-7-bindings.before.json', import.meta.url), 'utf8'));
const SERVERS = {gmail: 'https://gmail.googleapis.com', 'google-calendar': 'https://www.googleapis.com/calendar/v3'};
const CLIENT = {clientId: 'f109-client', clientSecret: 'f109-secret'};
const APPS = ['github', 'gmail', 'google-calendar', 'notion', 'slack'];
const plain = value => JSON.parse(JSON.stringify(value));
// F10.13 listed churn (docs/F10.13-BUILD-MAP.md part 1): step 13 adds one bindContent block, on purpose, to Calendar's "Create, edit and
// invite people to events". The recorded fixture is not rewritten: Calendar's rows are the recorded ones plus exactly that block, and
// Calendar's data hash, which the block moves, is left to test/f10-13-churn.test.mjs.
const CALENDAR_BINDING = {'calendar.events.patch': {kind: 'etag', at: 'header:If-Match'}, 'calendar.events.update': {kind: 'etag', at: 'header:If-Match'}};
// F10.15 listed churn (docs/F10.15-BUILD-MAP.md part 1): step 15 adds row data, on purpose, to three Gmail rows: four unsupported markers and
// one content binding. Gmail's rows are the recorded ones plus exactly that data, and Gmail's data hash is left to test/f10-15-churn.test.mjs.
const DRAFT_WORDS = 'Fabric\'s plain form of this operation cannot carry a whole message, so it would save an empty draft or blank one. Fabric writes drafts through its reviewed Gmail actions.';
const GMAIL_DATA = {'gmail.drafts.write': {unsupported: {'gmail.users.drafts.create': DRAFT_WORDS, 'gmail.users.drafts.update': DRAFT_WORDS}},
  'gmail.messages.send': {unsupported: {'gmail.users.drafts.send': 'It sends a draft by its id alone, so a draft changed after approval would go out. Fabric sends drafts through its reviewed Send draft action, which binds the message.'},
    bindContent: {'gmail.users.drafts.send': {kind: 'resend', at: 'body:/message/raw'}}},
  'gmail.messages.import': {unsupported: {'gmail.users.messages.import': 'Fabric\'s plain form of this operation cannot carry a message, so it would import nothing. No reviewed action imports email.'}}};
// F10.17 listed churn (docs/F10.17-BUILD-MAP.md part 1): step 17 adds two bindContent blocks, on purpose, to GitHub's "Open and merge pull
// requests" (the merge) and "Push code and manage repositories" (the contents PUT). GitHub's rows are the recorded ones plus exactly those
// blocks, and GitHub's data hash, which they move, is left to test/f10-17-churn.test.mjs.
const BINDINGS = {'google-calendar': {'google-calendar.events.write': CALENDAR_BINDING},
  github: {'github.pulls.write': {'PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge': {kind: 'sha', at: 'body:/sha'}},
    'github.code.write': {'PUT /repos/{owner}/{repo}/contents/{path}': {kind: 'sha', at: 'body:/sha'}}}};
const recordedRows = appId => {
  const rows = structuredClone(LOADERS.permissionGroups[appId]);
  for (const [id, binding] of Object.entries(BINDINGS[appId] ?? {})) rows.groups.find(group => group.id === id).bindContent = binding;
  if (appId === 'gmail') for (const [id, data] of Object.entries(GMAIL_DATA)) Object.assign(rows.groups.find(group => group.id === id), structuredClone(data));
  return rows;
};

function temporaryStore(t, options = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-f10-9-churn-')), store = new Store({dataDir: dir, ...options});
  t.after(() => {store.close(); rmSync(dir, {recursive: true, force: true});});
  return {dir, store};
}
/** Every proxy-row binding of one account, over the recorded synthetic maps, as the snapshot was recorded. */
function proxyRowsOf(connection) {
  const config = PROXY_CONFIGS.get(connection.appId), definition = PERMISSION_GROUPS.get(connection.appId), policy = new ProxyPolicy({store: null});
  const templates = templatesFor(definition, config, F107.maps[connection.appId] ?? null);
  assert.ok(templates, `${connection.appId}: the recorded map still covers every reviewed operation`);
  return Object.fromEntries(policy.rows({config, definition}).map(({row}) => [row, policy.binding({connection, config, templates}, row)]));
}
/** A typed capability for every operation of the recorded map (or the given paths), compiled as the snapshot compiled them. */
function compiled(appId, operations, server = SERVERS[appId]) {
  const paths = {};
  for (const operation of operations) paths[operation.path] = {...paths[operation.path], [operation.method.toLowerCase()]: {operationId: operation.id,
    parameters: [...operation.path.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'ok'}}}};
  return compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: server}], paths}}).capabilities.map(cap => ({...cap, status: 'active'}));
}
/** The typed binding hash of every capability, for one account, on a store holding the map. */
function typedOf(t, connection, operations, server) {
  const {store} = temporaryStore(t), caps = compiled(connection.appId, operations, server);
  store.put('connections', connection);
  for (const cap of caps) store.put('capabilities', cap);
  store.put('applicationMaps', {id: connection.appId, appId: connection.appId, operations: operations.map(operation => ({...operation, capabilityId: caps.find(cap => cap.name === operation.id).id}))});
  const permissions = new PermissionManager({store}), stored = store.get('connections', connection.id);
  return Object.fromEntries(caps.map(cap => [cap.name, permissions.decision(stored, cap).bindingHash]).sort(([a], [b]) => a < b ? -1 : 1));
}

// ---- the loaders --------------------------------------------------------------------------------------------------------------
test('the recorded snapshots cover the five shipped apps', () => {
  for (const key of ['permissionGroups', 'proxyConfigs']) assert.deepEqual(Object.keys(LOADERS[key]).sort(), APPS, key);
  assert.deepEqual(Object.keys(LOADERS.optionSources).sort(), ['gmail', 'google-calendar']);
  assert.deepEqual([...PROXY_CONFIGS.keys()].sort(), APPS);
  for (const key of ['connections', 'proxyRows', 'dataHashes']) assert.deepEqual(Object.keys(BEFORE[key]).sort(), APPS, key);
  assert.deepEqual(Object.keys(BEFORE.typed).sort(), ['gmail', 'google-calendar']);
  assert.deepEqual(BEFORE.connections.slack.identity, {id: 'T0001:U000A', displayName: 'alice', workspaceId: 'T0001', workspaceName: 'Fixture Team'}, 'recorded as a sign-in stored it before F10.9');
});

test('every shipped permissions, version 1 options and proxy file loads to the recorded output', () => {
  for (const appId of APPS) assert.deepStrictEqual(plain(PERMISSION_GROUPS.get(appId)), recordedRows(appId), `${appId} permission rows`);
  assert.deepEqual([...OPTION_SOURCES.keys()].sort(), Object.keys(LOADERS.optionSources).sort());
  for (const [appId, sources] of OPTION_SOURCES) assert.deepStrictEqual(plain(sources), LOADERS.optionSources[appId], `${appId} option sources`);
  for (const appId of APPS) {
    const config = plain(PROXY_CONFIGS.get(appId));
    assert.deepStrictEqual({...config, documented: {count: config.documented.length, hash: canonicalHash(config.documented)}}, LOADERS.proxyConfigs[appId], `${appId} proxy settings`);
  }
});

// ---- bindings and the signed tables (open point Minor 8: compared with F10.9's own base, so no CHURN table is needed) --------------
test('no proxy-row binding, typed binding or defaults data hash moves', t => {
  for (const appId of APPS) assert.deepEqual(proxyRowsOf(BEFORE.connections[appId]), BEFORE.proxyRows[appId], `${appId} proxy-row bindings`);
  for (const appId of Object.keys(BEFORE.typed)) assert.deepEqual(typedOf(t, BEFORE.connections[appId], F107.maps[appId].operations), BEFORE.typed[appId], `${appId} typed bindings`);
  for (const appId of APPS.filter(appId => !BINDINGS[appId] && appId !== 'gmail')) assert.equal(appEntry(ROOT, appId).dataHash, BEFORE.dataHashes[appId], `${appId} defaults data hash`);
});

// ---- the Slack user id (R5) -----------------------------------------------------------------------------------------------------
/** The identity a shipped definition gives for the simulator's account a, read through observeIdentity() as a sign-in reads it. */
async function observed(providerId, appId, scopes, extra = () => ({})) {
  const sim = new SIMULATORS[providerId]({...CLIENT, clock: () => Date.UTC(2026, 9, 20, 12)});
  const provider = new OAuth2Provider(definitionFor(providerId), {store: {get: () => null}, vault: {}, connections: {request: req => sim.request(req)}, ...CLIENT});
  return provider.observeIdentity({appId, accessToken: sim.issue('a', scopes, {refreshable: false, extra: extra(sim)}).accessToken});
}

test('the shipped Slack definition records userId, the bare user id, beside the unchanged id; the other identities do not change', async () => {
  assert.deepEqual(await observed('slack', 'slack', ['channels:read']), {id: 'T0001:U000A', displayName: 'alice', workspaceId: 'T0001', workspaceName: 'Fixture Team', userId: 'U000A'});
  assert.deepEqual(await observed('google', 'gmail', ['openid', 'email', 'https://www.googleapis.com/auth/gmail.modify']), {id: 'google-sub-a', displayName: 'a@example.com', email: 'a@example.com'});
  assert.deepEqual(await observed('github', 'github', ['read:user']), {id: '101', displayName: 'octo-a'});
  assert.deepEqual(await observed('notion', 'notion', [], sim => ({bot: sim.issueBot('a')})), {id: 'ws-a:notion-user-a', displayName: 'Avery A', email: 'avery@a.example', workspaceName: 'Workspace A'});
  for (const providerId of ['google', 'github', 'notion']) assert.ok(!Object.hasOwn(definitionFor(providerId).identity.attributes, 'userId'), `${providerId} has no userId attribute`);
});

test('the auth contract takes userId only from one of the id pointers, so it never carries anything the id does not', () => {
  const raw = () => JSON.parse(readFileSync(new URL('../catalog/auth/slack.json', import.meta.url), 'utf8')), withUser = pointer => {const value = raw(); value.identity.attributes.userId = pointer; return value;};
  assert.equal(validateAuthDefinition(raw()).identity.attributes.userId, '/user_id');
  assert.doesNotThrow(() => validateAuthDefinition(withUser('/team_id')), 'another id pointer');
  for (const pointer of ['/user', '/team', '/authed_user/id', '/user_id/x']) assert.throws(() => validateAuthDefinition(withUser(pointer)), /attributes\.userId must read one of the id pointers/, pointer);
  // An alternate id makes the account id whenever a primary pointer is absent (lib/providers/oauth2.mjs), so userId must read a pointer of
  // both keys: otherwise an account keyed by the alternate id could carry a userId its id does not, which bindings would then leave out.
  const alternate = pointers => {const value = raw(); value.identity.alternateId = {pointers, separator: pointers.length > 1 ? ':' : ''}; return value;};
  for (const pointers of [['/team_id'], ['/id'], ['/team_id', '/bot_id']]) {
    assert.throws(() => validateAuthDefinition(alternate(pointers)), /attributes\.userId must also read one of the alternate id pointers/, pointers.join());
  }
  for (const pointers of [['/user_id'], ['/team_id', '/user_id']]) assert.equal(validateAuthDefinition(alternate(pointers)).identity.attributes.userId, '/user_id', pointers.join());
  const other = raw();
  other.identity.attributes.teamId = '/team_id';
  assert.throws(() => validateAuthDefinition(other), /attributes\.teamId is not allowed/);
});

test('a Slack account whose stored identity gains userId keeps every proxy-row and typed binding', t => {
  const before = BEFORE.connections.slack, after = {...before, identity: {...before.identity, userId: 'U000A'}};
  assert.deepEqual(proxyRowsOf(after), BEFORE.proxyRows.slack);
  const operations = [{id: 'conversations.history', method: 'GET', path: '/conversations.history'}, {id: 'chat.postMessage', method: 'POST', path: '/chat.postMessage'}];
  assert.deepEqual(typedOf(t, after, operations, 'https://slack.com/api'), typedOf(t, before, operations, 'https://slack.com/api'));
  // Typed bindings of the other apps leave out a userId too, though no other identity has one.
  const gmail = BEFORE.connections.gmail;
  assert.deepEqual(typedOf(t, {...gmail, identity: {...gmail.identity, userId: 'u1'}}, F107.maps.gmail.operations), BEFORE.typed.gmail);
});

test('open point Important 1: a Slack record that gains userId keeps its connection generation; other identity fields still move it', t => {
  const {store} = temporaryStore(t, {localAuthority: 'new'}), record = {...BEFORE.connections.slack};
  store.put('connections', record);
  assert.equal(store.connectionGeneration(record.id), 1);
  store.put('connections', {...record, identity: {...record.identity, userId: 'U000A'}});
  assert.equal(store.connectionGeneration(record.id), 1, 'userId only repeats the second part of the reviewed id');
  store.put('connections', {...record, identity: {...record.identity, userId: 'U000A', workspaceId: 'T0002'}});
  assert.equal(store.connectionGeneration(record.id), 2, 'workspaceId is still authority');
  store.put('connections', {...record, identity: {...record.identity, id: 'T0001:U000B', userId: 'U000B'}});
  assert.equal(store.connectionGeneration(record.id), 3, 'the id is still authority');
});

test('a Slack account signed in before F10.9 keeps its generation, saved settings and bindings when a health check records userId', async t => {
  let now = Date.UTC(2026, 9, 20, 12);
  const clock = () => now, {dir, store} = temporaryStore(t, {clock, localAuthority: 'new'}), vault = new Vault(dir), sim = new SIMULATORS.slack({...CLIENT, clock});
  const request = req => sim.request(req), connections = new ConnectionManager({store, vault, request, clock});
  const provider = new OAuth2Provider(definitionFor('slack'), {store, vault, connections, request, clock, ...CLIENT, redirectUri: 'https://connect.example.com/oauth/slack/4320', allowHostedRedirect: true});
  connections.setOAuthProvider(provider);
  const started = provider.start({appId: 'slack'}), grant = sim.consent(started.authorizationUrl, {account: 'a'});
  const {id} = await provider.callback({state: grant.state, code: grant.code, flowId: started.flowId});
  // As F10.9's base stored it: the same identity without userId.
  const {userId, ...base} = store.get('connections', id).identity;
  void userId;
  store.put('connections', {...store.get('connections', id), identity: base});
  const generation = store.connectionGeneration(id);
  const permissions = new PermissionManager({store}), policy = new ProxyPolicy({store, permissions});
  policy.set({connectionId: id, row: 'group:slack.conversations.mark', mode: 'allow', confirmAllow: true});
  const [cap] = compiled('slack', [{id: 'conversations.history', method: 'GET', path: '/conversations.history'}], 'https://slack.com/api');
  store.put('capabilities', cap);
  const typedBefore = permissions.decision(store.get('connections', id), cap).bindingHash, rowsBefore = proxyRowsOf(store.get('connections', id));

  now += 60_000;
  await connections.check(id);
  const after = store.get('connections', id);
  assert.deepEqual(after.identity, {...base, userId: 'U000A'}, 'the health check records the bare user id');
  assert.equal(store.connectionGeneration(id), generation, 'the generation stays');
  const row = policy.view(id).find(entry => entry.row === 'group:slack.conversations.mark');
  assert.deepEqual([row.mode, row.source], ['allow', 'saved'], 'the saved Allow stays saved, not stale');
  assert.equal(permissions.decision(after, cap).bindingHash, typedBefore, 'the typed binding stays');
  assert.deepEqual(proxyRowsOf(after), rowsBefore, 'every proxy-row binding stays');
});

// ---- the scope wall ---------------------------------------------------------------------------------------------------------
/** The relative modules a file imports statically, resolved against it. F10.11 part p (listed churn): the one guarded import() of the
 *  action catalog, in lib/action-gate.mjs, is not a static import; test/f10-11-churn.test.mjs counts the dynamic ones. */
function importsOf(file) {
  const text = readFileSync(file, 'utf8'), found = new Set();
  for (const match of text.matchAll(/(?:\bfrom\s*|\bimport\s+)(['"])(\.{1,2}\/[^'"]+)\1/g)) found.add(path.resolve(path.dirname(file), match[2]));
  return [...found];
}

test('server.mjs and developer-server.mjs reach none of lib/actions.mjs, lib/action-expressions.mjs, lib/action-placement.mjs, lib/choice-sources.mjs and lib/triggers.mjs through any static import', () => {
  const root = fileURLToPath(new URL('..', import.meta.url)), seen = new Set(), queue = [path.join(root, 'server.mjs'), path.join(root, 'developer-server.mjs')];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    for (const next of importsOf(file)) if (/\.m?[jt]s$/.test(next)) queue.push(next);
  }
  assert.ok(seen.size > 20, 'the walk follows the import graph');
  for (const name of ['lib/actions.mjs', 'lib/action-expressions.mjs', 'lib/action-placement.mjs', 'lib/choice-sources.mjs', 'lib/triggers.mjs']) assert.ok(!seen.has(path.join(root, name)), `${name} is not reachable from server.mjs`);
});

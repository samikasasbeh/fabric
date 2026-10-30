import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID, createHash} from 'node:crypto';
import {compileOpenApi} from '../lib/compiler.mjs';
import {fixture, noShippedActions} from './fixtures/signin-fixture.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {AppDetailService} from '../lib/app-detail.mjs';
import {permissionRow} from '../lib/ui-contracts.mjs';
import {catalog} from '../lib/connections.mjs';
import {offeredLevels, heldLevel} from '../lib/access-levels.mjs';

// F10.4 (T7, critique test 13): the upgrade card. Before a sign-in that widens what the owner approved, Fabric lists every
// row, typed or proxy, that would run at Allow afterwards: a member the account lacks access for now gains it, and its
// mode afterwards is a default Allow (a saved or stale setting becomes Ask under the new authorization, and Never stays
// Never). When that list is not empty, the start must carry confirmRows equal to the card's etag. The callback wall saves
// at Ask whatever an upgrade granted beyond the card. GitHub's reviewed rows on a designated app with the GitHub simulator;
// nothing leaves the process.
const param = name => ({name, in: 'path', required: true, schema: {type: 'string'}});
const post = {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {name: {type: 'string'}}, required: ['name']}}}}, responses: {201: {description: 'Created'}}};
const doc = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
  '/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}},
  '/issues': {get: {operationId: 'listIssues', responses: {200: {description: 'Issues'}}}},
  '/gists': {get: {operationId: 'listGists', responses: {200: {description: 'Gists'}}}},
  '/repos/{owner}/{repo}/issues': {post: {operationId: 'createIssue', parameters: [param('owner'), param('repo')], ...post}},
  '/repos/{owner}/{repo}/hooks': {post: {operationId: 'createHook', parameters: [param('owner'), param('repo')], ...post}}}};
// Map operations are named by their request, so the proxy rows find their members the way decide() does (by id).
const OPERATIONS = [['listRepos', 'GET', '/user/repos', ['repo']], ['listIssues', 'GET', '/issues', ['repo']], ['listGists', 'GET', '/gists', ['gist']],
  ['createIssue', 'POST', '/repos/{owner}/{repo}/issues', ['repo']], ['createHook', 'POST', '/repos/{owner}/{repo}/hooks', ['repo']]];
const REPOS = 'github.repos.read', ISSUES = 'github.issues.read', GISTS = 'github.gists.read', PROFILE = 'github.profile.read';
// F10.7: under GitHub's full consent policy every sign-in asks for the whole full level, so every Add access of the account below has
// one card: the organization reads of the profile row (proxy only), and repositories, issues and gists, typed and proxied.
const FULL = ['gist', 'read:org', 'read:user', 'repo', 'workflow'], CARD = [[PROFILE, false, true], [REPOS, true, true], [ISSUES, true, true], [GISTS, true, true]];

async function setup(t) {
  const f = await fixture(t, {actions: await noShippedActions(t)}), store = f.app.store;
  // Only this synthetic GitHub's operations (and none of GitHub's certified actions, which would join its rows): the fixture's own two would sit in their rows by request (F10.6), with the rows' scope data.
  for (const capability of [f.read, f.write]) store.delete('capabilities', capability.id);
  const caps = Object.fromEntries(compileOpenApi({appId: 'github', document: doc}).capabilities.map(cap => [cap.name, {...cap, status: 'active'}]));
  for (const cap of Object.values(caps)) store.put('capabilities', cap);
  store.put('applicationMaps', {id: 'github', operations: OPERATIONS.map(([name, method, route, requiredScopes]) => ({id: `${method} ${route}`, capabilityId: caps[name].id, method, path: route, requiredScopes}))});
  const start = async body => {
    const response = await f.owned('POST', '/api/oauth/github/start', body);
    return {status: response.status, body: await response.json(), flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie') || '')?.[1]};
  };
  // F10.7: GitHub signs in at full access (version 2). The cases start from an account from before step 7, as version 1's read level
  // left it: read:user only, so repositories, issues and gists all need more access.
  const id = randomUUID(), stamp = new Date(f.now).toISOString(), {accessToken} = f.sim.issue('a', ['read:user'], {refreshable: false});
  store.put('connections', {id, appId: 'github', providerId: 'github', driver: 'http', status: 'ready', authMethod: 'oauth', label: 'octo-a', identity: {id: '101', displayName: 'octo-a'},
    allowedOrigins: ['https://api.github.com'], scopes: ['read:user'], grantCeiling: ['read:user'], authRevision: randomUUID(), signInRevision: randomUUID(), createdAt: stamp, updatedAt: stamp});
  f.app.vault.set(id, {accessToken, expiresAt: null, scopes: ['read:user']});
  const view = async () => (await f.json('GET', '/api/ui/apps/github')).body;
  const row = (page, groupId) => page.sections.flatMap(section => section.rows).find(item => item.groupId === groupId);
  const decision = name => f.app.runtime.permissions.decision(store.get('connections', id), caps[name]);
  const mode = name => [decision(name).mode, decision(name).policySource];
  const listed = card => card.rows.map(entry => [entry.groupId, entry.typed, entry.proxy]);
  const flowOf = started => store.get('oauthFlows', createHash('sha256').update(new URL(started.body.authorizationUrl).searchParams.get('state')).digest('hex'));
  return {f, store, caps, id, start, view, row, decision, mode, listed, flowOf, record: () => store.get('connections', id)};
}

test('the card lists exactly the rows whose members go from missing to granted at a default Allow, typed and proxy', async t => {
  const {f, id, view, row, listed, caps} = await setup(t);
  let page = await view();
  const repos = row(page, REPOS);
  assert.deepEqual(repos.addAccess, {providerId: 'github', body: {connectionId: id, level: 'full', scopes: ['repo']}});
  // The full level turns on every read row at its default Allow. Create issues defaults to Ask, and the webhook row is locked (T4).
  assert.deepEqual(listed(repos.upgrade), CARD);
  // The page's "Upgrade to full access" asks for the same set, so it shows the same rows.
  assert.deepEqual([page.upgrade.label, listed(page.upgrade)], ['Upgrade to full access', CARD]);
  assert.deepEqual(Object.keys(repos.upgrade).sort(), ['etag', 'rows']); assert.match(repos.upgrade.etag, /^[0-9a-f]{64}$/);
  assert.deepEqual(Object.keys(repos.upgrade.rows[0]).sort(), ['groupId', 'label', 'proxy', 'typed']);
  assert.deepEqual(listed(row(page, GISTS).upgrade), CARD);
  for (const leak of ['bindingHash', 'policyHash', 'authRevision', 'signInRevision', 'grantCeiling', 'read:user']) assert.ok(!JSON.stringify(repos.upgrade).includes(leak), leak);
  // Following the default is still a default; a saved Ask on the typed member leaves the proxy row on the card.
  f.app.runtime.permissions.set({connectionId: id, capabilityId: caps.listRepos.id, mode: 'allow'});
  f.app.runtime.permissions.set({connectionId: id, capabilityId: caps.listIssues.id, mode: 'ask'});
  page = await view();
  assert.deepEqual(listed(row(page, REPOS).upgrade), [[PROFILE, false, true], [REPOS, true, true], [ISSUES, false, true], [GISTS, true, true]]);
  // Saved rows become Ask and Never stays Never, so neither runs at Allow afterwards.
  f.app.runtime.proxyPolicy.set({connectionId: id, row: `group:${ISSUES}`, mode: 'ask'});
  f.app.runtime.permissions.set({connectionId: id, capabilityId: caps.listRepos.id, mode: 'deny'});
  f.app.runtime.proxyPolicy.set({connectionId: id, row: `group:${REPOS}`, mode: 'deny'});
  f.app.runtime.permissions.set({connectionId: id, capabilityId: caps.listGists.id, mode: 'deny'});
  for (const groupId of [GISTS, PROFILE]) f.app.runtime.proxyPolicy.set({connectionId: id, row: `group:${groupId}`, mode: 'deny'});
  page = await view();
  assert.equal('upgrade' in row(page, REPOS), false, 'an empty card is not shown');
  assert.ok(row(page, REPOS).addAccess, 'Add access is still offered');
});

test('a saved Allow is left out, typed or proxy: the new authorization turns it into Ask', async t => {
  const {f, id, store, start, view, row, listed, mode, caps} = await setup(t);
  // A typed Allow saved over a row whose default is Ask, and a proxy Allow saved as a record of its own (as before rows followed
  // their default), each on a member the upgrade would grant.
  f.app.runtime.permissions.set({connectionId: id, capabilityId: caps.createIssue.id, mode: 'allow'});
  const policy = f.app.runtime.proxyPolicy, issuesRow = `group:${ISSUES}`;
  store.put('permissions', {id: policy.policyId(id, issuesRow), kind: 'proxy-row', connectionId: id, row: issuesRow, mode: 'allow', bindingHash: policy.binding(policy.route(id), issuesRow), revision: randomUUID(), updatedAt: new Date().toISOString()});
  assert.deepEqual([mode('createIssue'), policy.view(id).find(entry => entry.row === issuesRow).source], [['allow', 'saved'], 'saved']);
  const repos = row(await view(), REPOS);
  assert.deepEqual(listed(repos.upgrade), [[PROFILE, false, true], [REPOS, true, true], [ISSUES, true, false], [GISTS, true, true]]);
  assert.equal((await f.callback(await start({...repos.addAccess.body, confirmRows: repos.upgrade.etag}))).location, '/?oauth=connected');
  assert.deepEqual([mode('createIssue'), (({mode: shown, source}) => [shown, source])(policy.view(id).find(entry => entry.row === issuesRow))], [['ask', 'stale'], ['ask', 'stale']]);
});

test('a full-level reconnect that widens the ceiling needs the card too, the same card as Add access for the same set', async t => {
  const {f, id, start, view, row} = await setup(t);
  const repos = row(await view(), REPOS);
  for (const body of [{connectionId: id, writeAccess: true}, {connectionId: id, level: 'full'}]) {
    const refused = await start(body);
    assert.equal(refused.status, 409); assert.equal(refused.body.code, 'confirm_required');
    assert.deepEqual(refused.body.upgrade, repos.upgrade, 'the card is about what the sign-in asks for, not how it was asked');
  }
  const started = await start({connectionId: id, level: 'full', confirmRows: repos.upgrade.etag});
  assert.equal(started.status, 200);
  assert.equal((await f.callback(started)).location, '/?oauth=connected');
});

test('rows a ceiling clamps are left out, so their start needs no confirm', async t => {
  const {f, view, row, listed, start} = await setup(t);
  f.app.runtime.permissions.ceilingOf = (appId, groupId) => groupId === GISTS ? 'ask' : null;
  assert.deepEqual(listed(row(await view(), GISTS).upgrade), CARD.filter(([groupId]) => groupId !== GISTS));
  // With every row the full level turns on clamped to Ask, nothing runs at Allow afterwards: no card, and no confirm.
  f.app.runtime.permissions.ceilingOf = (appId, groupId) => [PROFILE, REPOS, ISSUES, GISTS].includes(groupId) ? 'ask' : null;
  const gists = row(await view(), GISTS);
  assert.equal('upgrade' in gists, false);
  assert.equal((await start(gists.addAccess.body)).status, 200);
});

test('a start that widens the ceiling without the matching confirmRows answers 409 with the card; the matching etag starts it', async t => {
  const {f, id, start, view, row, store, flowOf} = await setup(t);
  const repos = row(await view(), REPOS), flows = store.list('oauthFlows').length;
  for (const body of [repos.addAccess.body, {...repos.addAccess.body, confirmRows: 'f'.repeat(64)}, {...repos.addAccess.body, confirmRows: 42}]) {
    const refused = await start(body);
    assert.equal(refused.status, 409); assert.equal(refused.body.code, 'confirm_required');
    assert.deepEqual(refused.body.upgrade, repos.upgrade, 'the same card the app page shows, in a fixed shape');
    assert.equal(refused.flowId, undefined);
  }
  assert.equal(store.list('oauthFlows').length, flows, 'nothing started');
  const started = await start({...repos.addAccess.body, confirmRows: repos.upgrade.etag});
  assert.equal(started.status, 200);
  assert.deepEqual(new URL(started.body.authorizationUrl).searchParams.get('scope').split(' ').sort(), FULL);
  assert.deepEqual(flowOf(started).upgrade, {etag: repos.upgrade.etag, scopes: FULL}, 'the flow carries what was confirmed');
  // A reconnect within the ceiling is a renewal: no card, no confirm. (This account's ceiling, read:user, holds no full level, so it is
  // widened by hand here, as an earlier upgrade would have widened it.)
  store.put('connections', {...store.get('connections', id), grantCeiling: FULL});
  const renewal = await start({connectionId: id});
  assert.equal(renewal.status, 200); assert.equal(flowOf(renewal).upgrade, undefined);
  // The start route takes confirmRows and nothing new besides.
  assert.equal((await start({connectionId: id, confirm: true})).status, 400);
  assert.equal((await f.json('POST', '/api/oauth/github/start', {connectionId: randomUUID(), scopes: ['repo']})).status, 400);
});

test('a sign-in after a disconnect is a first sign-in, so it needs no card', async t => {
  const {f, id, start, flowOf} = await setup(t);
  assert.equal((await f.json('POST', `/api/connections/${id}/revoke`, {})).status, 200);
  const started = await start({connectionId: id, scopes: ['repo']});
  assert.equal(started.status, 200); assert.equal(flowOf(started).upgrade, undefined);
});

test('the etag changes with a row\'s policy, the authorization, the sign-in and the requested set', async t => {
  const {f, id, start, view, row, caps, store, record} = await setup(t);
  const etag = async () => row(await view(), REPOS).upgrade.etag, seen = new Set([await etag()]);
  const changed = async message => { const next = await etag(); assert.ok(!seen.has(next), message); seen.add(next); };
  f.app.runtime.permissions.set({connectionId: id, capabilityId: caps.listIssues.id, mode: 'deny'});
  await changed('a listed row\'s typed policy');
  f.app.runtime.proxyPolicy.set({connectionId: id, row: `group:${REPOS}`, mode: 'ask'});
  await changed('a listed row\'s proxy policy');
  f.app.runtime.proxyPolicy.reset({connectionId: id});
  await changed('back to the default is a new revision');
  // A renewal: the same account signing in again within the ceiling writes a new sign-in revision. Every sign-in through the start
  // route asks for the full level, wider than this account approved, so the renewal comes through establishOAuth directly.
  const before = record(), issued = f.sim.issue('a', ['read:user'], {refreshable: false});
  await f.app.connections.establishOAuth({connectionId: id, appId: 'github', tokens: {...issued, expiresAt: null, scopes: ['read:user']}});
  assert.notEqual(record().signInRevision, before.signInRevision); assert.equal(record().authRevision, before.authRevision);
  await changed('the sign-in');
  store.put('connections', {...record(), authRevision: randomUUID()});
  await changed('the authorization');
  // Under GitHub's full consent policy any set within the full level asks for the whole level: one card, one etag.
  const both = await start({connectionId: id, scopes: ['repo', 'gist']});
  assert.equal(both.status, 409); assert.equal(both.body.upgrade.etag, await etag(), 'the same requested set');
  assert.deepEqual(both.body.upgrade.rows.map(entry => entry.groupId), [PROFILE, REPOS, ISSUES, GISTS]);
});

test('a confirmed upgrade lands: the listed rows run at Allow, a saved Allow becomes Ask and Never stays Never', async t => {
  const {f, id, start, view, row, mode, caps, record} = await setup(t);
  f.app.runtime.permissions.set({connectionId: id, capabilityId: caps.createIssue.id, mode: 'allow'});
  f.app.runtime.permissions.set({connectionId: id, capabilityId: caps.listGists.id, mode: 'deny'});
  const before = record(), repos = row(await view(), REPOS);
  assert.equal((await f.callback(await start({...repos.addAccess.body, confirmRows: repos.upgrade.etag}))).location, '/?oauth=connected');
  assert.notEqual(record().authRevision, before.authRevision);
  assert.deepEqual(record().grantCeiling, FULL);
  assert.deepEqual([mode('listRepos'), mode('listIssues'), mode('createIssue'), mode('listGists')], [['allow', 'default'], ['allow', 'default'], ['ask', 'stale'], ['deny', 'stale']]);
  assert.equal(f.app.store.list('activity').filter(event => event.type === 'connection.upgraded' && event.connectionId === id).length, 1);
  await assert.rejects(f.app.connections.establishOAuth({tokens: {accessToken: 'unused', scopes: []}, appId: 'github', upgrade: {etag: 'a'.repeat(64), scopes: []}}), {code: 'invalid_input'}, 'an upgrade is always a reconnect');
});

test('callback wall: what a provider grants beyond the confirmed card lands at Ask', async t => {
  const {f, store, start, view, row, mode, decision} = await setup(t);
  // The full level asks for every scope the shipped rows name, so this map says the typed gists list takes notifications, which no level
  // asks for; GitHub returns it anyway (an earlier authorization of the same app, say).
  const map = store.get('applicationMaps', 'github');
  store.put('applicationMaps', {...map, operations: map.operations.map(operation => operation.id === 'GET /gists' ? {...operation, requiredScopes: ['notifications']} : operation)});
  const repos = row(await view(), REPOS), started = await start({...repos.addAccess.body, confirmRows: repos.upgrade.etag});
  f.sim.grantedScopes = params => [...params.scope.split(' '), 'notifications'];
  assert.equal((await f.callback(started)).location, '/?oauth=connected');
  assert.equal(decision('listGists').providerAccess, 'granted');
  assert.deepEqual([mode('listRepos'), mode('listIssues'), mode('listGists')], [['allow', 'default'], ['allow', 'default'], ['ask', 'saved']]);
});

test('callback wall: an upgrade no card was confirmed for lands every member it newly granted at a default Allow at Ask', async t => {
  const {f, id, mode, caps} = await setup(t);
  f.app.runtime.permissions.set({connectionId: id, capabilityId: caps.listGists.id, mode: 'allow'});
  // The provider adapter itself, not the start route: the gate lives in the entry points, the wall behind every one of them.
  const flow = f.app.connections.oauthProvider(f.app.store.get('connections', id)).start({connectionId: id, scopes: ['repo', 'gist']}), grant = f.sim.consent(flow.authorizationUrl);
  await f.app.connections.oauthProvider(f.app.store.get('connections', id)).callback({state: grant.state, code: grant.code, flowId: flow.flowId});
  assert.deepEqual([mode('listRepos'), mode('listIssues'), mode('listGists'), mode('createIssue')], [['ask', 'saved'], ['ask', 'saved'], ['ask', 'saved'], ['ask', 'default']],
    'a member that follows its default Allow is pinned too; Ask rows are left alone');
});

// ---- version 2: the full upgrade on the app page (dormant until F10.7, when the definitions move) -------------------------
const level = (required, optional = []) => ({required, optional, inContext: []});
const githubV2 = () => ({...v1Definition('github'), schemaVersion: 2, scopeImplications: {}, consentPolicy: {testing: 'full', production: 'full'},
  apps: [{appId: 'github', accessProbe: null, access: {default: 'full', grant: 'scope', levels: {full: level(['read:user', 'repo'], ['read:org', 'gist', 'workflow']), read: null}}, neverRequest: ['delete_repo', 'user']}]});

function v2Harness(t, scopes) {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-upgrade-card-'));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  const store = new Store({dataDir: directory}), vault = new Vault(directory);
  const provider = new OAuth2Provider(githubV2(), {store, vault, connections: {}, clientId: 'fixture-client', clientSecret: 'fixture-secret', redirectUri: 'http://127.0.0.1:59999/api/oauth/github/callback'});
  const permissions = new PermissionManager({store}), access = () => provider.access(provider.app('github'));
  const service = new AppDetailService({store, runtime: {permissions, proxyPolicy: new ProxyPolicy({store, permissions})}, catalog: () => catalog.filter(app => app.id === 'github'), oauthProviderFor: () => provider,
    accessLevels: () => offeredLevels(access()), accessLevelOf: connection => heldLevel(access(), connection.scopes)});
  const caps = Object.fromEntries(compileOpenApi({appId: 'github', document: doc}).capabilities.map(cap => [cap.name, {...cap, status: 'active'}]));
  for (const cap of Object.values(caps)) store.put('capabilities', cap);
  store.put('applicationMaps', {id: 'github', operations: OPERATIONS.map(([name, method, route, requiredScopes]) => ({id: `${method} ${route}`, capabilityId: caps[name].id, method, path: route, requiredScopes}))});
  store.put('connections', {id: 'gh', appId: 'github', providerId: 'github', driver: 'http', authMethod: 'oauth', status: 'ready', authRevision: 'consent-1', signInRevision: 'sign-in-1', identity: {id: '101', displayName: 'octo'},
    allowedOrigins: ['https://api.github.com'], scopes, createdAt: '2026-10-11T10:00:00.000Z'});
  return {store, provider, service};
}

test('version 2: a partial account offers "Upgrade to full access" with its card; a full account does not', t => {
  const {service, provider, store} = v2Harness(t, ['read:user', 'repo']);
  const page = service.view('github');
  assert.deepEqual(page.accounts[0].accessLevel, 'partial');
  assert.deepEqual({...page.upgrade, rows: page.upgrade.rows.map(entry => [entry.groupId, entry.typed, entry.proxy])},
    // F10.7 (correction 2): the body names an explicit full upgrade, which asks for the whole level under any consent policy.
    {label: 'Upgrade to full access', providerId: 'github', body: {connectionId: 'gh', level: 'full', fullUpgrade: true}, rows: [[PROFILE, false, true], [GISTS, true, true]], etag: page.upgrade.etag});
  assert.match(page.upgrade.etag, /^[0-9a-f]{64}$/);
  // The start gate computes the same card from the same body.
  const gate = service.upgradeFor(provider, page.upgrade.body);
  assert.deepEqual([gate.rows, gate.etag, gate.scopes], [page.upgrade.rows, page.upgrade.etag, ['gist', 'read:org', 'read:user', 'repo', 'workflow']]);
  store.put('connections', {...store.get('connections', 'gh'), scopes: ['read:user', 'repo', 'read:org', 'gist', 'workflow']});
  assert.equal('upgrade' in service.view('github'), false);
});

test('version 2: a full upgrade within the ceiling is a renewal, offered with an empty card and no etag', t => {
  const {service, provider, store} = v2Harness(t, ['read:user', 'repo']);
  store.put('connections', {...store.get('connections', 'gh'), grantCeiling: ['gist', 'read:org', 'read:user', 'repo', 'workflow']});
  assert.deepEqual([service.view('github').upgrade.rows, service.view('github').upgrade.etag], [[], null]);
  assert.equal(service.upgradeFor(provider, {connectionId: 'gh', level: 'full'}), null);
});

test('identity scopes never make a reconnect an upgrade, in whatever form the provider reported them', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-upgrade-card-'));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  const store = new Store({dataDir: directory}), G = 'https://www.googleapis.com/auth/';
  const provider = new OAuth2Provider(v1Definition('google'), {store, vault: new Vault(directory), connections: {}, clientId: 'fixture-client', clientSecret: 'fixture-secret', redirectUri: 'http://127.0.0.1:59999/api/oauth/google/callback'});
  const service = new AppDetailService({store, runtime: {permissions: new PermissionManager({store})}, catalog: () => catalog, oauthProviderFor: () => provider, accessLevels: () => [], accessLevelOf: () => 'custom'});
  // Google asks for openid and email and reports them back as openid and userinfo.email.
  store.put('connections', {id: 'gm', appId: 'gmail', providerId: 'google', driver: 'http', authMethod: 'oauth', status: 'ready', authRevision: 'consent-1', identity: {id: 'sub-1'},
    allowedOrigins: ['https://gmail.googleapis.com'], scopes: [`${G}gmail.readonly`, `${G}userinfo.email`, 'openid'], createdAt: '2026-10-11T10:00:00.000Z'});
  assert.deepEqual(provider.plan({connectionId: 'gm'}).scopes, ['openid', 'email', `${G}gmail.readonly`]);
  assert.equal(service.upgradeFor(provider, {connectionId: 'gm'}), null);
  store.put('applicationMaps', {id: 'gmail', operations: [{requiredScopes: [`${G}gmail.send`]}]});
  assert.deepEqual(service.upgradeFor(provider, {connectionId: 'gm', scopes: [`${G}gmail.send`]}).scopes, [`${G}gmail.readonly`, `${G}gmail.send`]);
  // What the owner confirmed travels only with a reconnect, in its exact shape, and only from in-process callers.
  for (const [input, upgrade] of [[{appId: 'gmail'}, {etag: 'a'.repeat(64), scopes: []}], [{connectionId: 'gm'}, {etag: 'not-an-etag', scopes: []}], [{connectionId: 'gm'}, {etag: 'a'.repeat(64), scopes: [1]}], [{connectionId: 'gm'}, null]])
    assert.throws(() => provider.start(input, {upgrade}), {code: 'invalid_input'});
  assert.ok(provider.start({connectionId: 'gm'}, {upgrade: {etag: 'a'.repeat(64), scopes: [`${G}gmail.readonly`]}}).authorizationUrl.startsWith('https://accounts.google.com/'));
});

test('a permission row carries the card only next to its Add access', () => {
  const decisions = [{capabilityId: 'a', mode: 'allow', defaultMode: 'allow', policySource: 'default', providerAccess: 'missing', status: 'active', policyHash: 'h'}];
  const upgrade = {rows: [{groupId: 'g', label: 'See things', typed: true, proxy: false}], etag: 'e'.repeat(64)}, addAccess = {providerId: 'p', body: {connectionId: 'c', scopes: ['s']}};
  assert.deepEqual(permissionRow({id: 'g', label: 'See things', effect: 'read', decisions, addAccess, upgrade}).upgrade, upgrade);
  assert.equal('upgrade' in permissionRow({id: 'g', label: 'See things', effect: 'read', decisions, addBlocked: 'No', upgrade}), false);
  assert.equal('upgrade' in permissionRow({id: 'g', label: 'See things', effect: 'read', decisions, addAccess, upgrade, locked: true}), false);
  assert.equal(JSON.stringify(permissionRow({id: 'g', label: 'See things', effect: 'read', decisions, addAccess, upgrade: null})), JSON.stringify(permissionRow({id: 'g', label: 'See things', effect: 'read', decisions, addAccess})));
});

test('F10.6: a row with no typed member is listed as a proxy row, never as a typed one', async t => {
  const {f, store, id, start} = await setup(t);
  // GET /user/orgs is documented by the map but compiled into no typed operation: only the proxy can send it.
  const map = store.get('applicationMaps', 'github');
  store.put('applicationMaps', {...map, operations: [...map.operations, {id: 'GET /user/orgs', method: 'GET', path: '/user/orgs', requiredScopes: ['read:org']}]});
  const refused = await start({connectionId: id, scopes: ['read:org']});
  assert.equal(refused.status, 409);
  assert.deepEqual(refused.body.upgrade.rows.find(entry => entry.groupId === PROFILE), {groupId: PROFILE, label: 'Access profiles, activity and notifications', typed: false, proxy: true});
  assert.equal(f.connections().length, 1);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {compileOpenApi} from '../lib/compiler.mjs';
import {validatePermissionGroups} from '../lib/permission-groups.mjs';
import {fixture} from './fixtures/signin-fixture.mjs';
import {describeApp, needsConfirm, rowRequest, decide, MODE_LABEL, confirmedRequest} from '../public/hosted-app.js';
import {errorOf} from '../public/hosted-base.js';

// UI-2: the app detail screen. Designated app on a loopback port, GitHub OAuth simulator, a real
// OAuth-connected account, and reviewed groups injected for the synthetic operations.
const doc = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
  '/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}},
  '/user/orgs': {get: {operationId: 'listOrgs', responses: {200: {description: 'Orgs'}}}},
  '/repos/{owner}/{repo}/issues': {post: {operationId: 'createIssue', parameters: [{name: 'owner', in: 'path', required: true, schema: {type: 'string'}}, {name: 'repo', in: 'path', required: true, schema: {type: 'string'}}],
    requestBody: {content: {'application/json': {schema: {type: 'object', properties: {title: {type: 'string'}}, required: ['title']}}}}, responses: {201: {description: 'Created'}}}}}};
const groups = validatePermissionGroups({schemaVersion: 1, appId: 'github', groups: [
  {id: 'github.repos.read', label: 'See repositories', effect: 'read', defaultMode: 'allow', requests: ['GET /user/repos']},
  {id: 'github.orgs.read', label: 'See organizations', effect: 'read', defaultMode: 'allow', requests: ['GET /user/orgs']},
  {id: 'github.issues.write', label: 'Create issues', effect: 'write', defaultMode: 'ask', requests: ['POST /repos/{owner}/{repo}/issues']},
]});

async function setup(t) {
  const f = await fixture(t);
  const caps = compileOpenApi({appId: 'github', document: doc}).capabilities.map(cap => ({...cap, status: 'active'}));
  for (const cap of caps) f.app.store.put('capabilities', cap);
  const by = id => caps.find(cap => cap.name === id || cap.id.includes(id.toLowerCase()));
  // listOrgs documents two alternatives: admin:org (outside GitHub's reviewed upgrades) or read:org.
  const ops = [['listRepos', 'GET', '/user/repos', []], ['listOrgs', 'GET', '/user/orgs', ['admin:org', 'read:org']], ['createIssue', 'POST', '/repos/{owner}/{repo}/issues', ['repo']]]
    .map(([id, method, path, requiredScopes]) => ({id, capabilityId: caps.find(cap => cap.request.method === method && new URL(cap.request.url).pathname.replace(/%7B/g, '{').replace(/%7D/g, '}') === path).id, method, path, requiredScopes}));
  f.app.store.put('applicationMaps', {id: 'github', operations: ops});
  f.app.runtime.permissions.groups = new Map([['github', groups]]);
  // A real OAuth account through the ordinary sign-in route. F10.7: GitHub signs in at full access (version 2), and the person
  // unticks read:org, so the organizations row still needs more access.
  const response = await f.owned('POST', '/api/oauth/github/start', {appId: 'github', writeAccess: true});
  const started = {body: await response.json(), flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie'))[1]};
  assert.equal((await f.callback(started, {grant: {omit: ['read:org']}})).location, '/?oauth=connected');
  const account = f.connections().find(connection => connection.status === 'ready');
  const detail = async (query = '') => f.json('GET', `/api/ui/apps/github${query}`);
  const row = (view, groupId) => view.sections.flatMap(section => section.rows).find(item => item.groupId === groupId);
  const post = (verb, body, ref = account.id) => f.json('POST', `/api/ui/apps/github/accounts/${encodeURIComponent(ref)}/${verb}`, body);
  return {f, caps, account, detail, row, post, by};
}

test('the detail view shows labelled rows and a closed account row with no secrets', async t => {
  const {f, account, detail, row} = await setup(t);
  const {status, body: view} = await detail();
  assert.equal(status, 200);
  assert.equal(view.selectedAccountRef, account.id);
  assert.equal(view.accessSummary, 'Full access at sign-in. You control each permission below.');
  // The unticked box is the account's attention line (F10.5).
  assert.deepEqual(Object.keys(view.accounts[0]).sort(), ['accessLabel', 'accessLevel', 'accountRef', 'attention', 'connectedAt', 'displayName', 'initial', 'status']);
  assert.equal(view.accounts[0].accessLevel, 'partial');
  assert.equal(view.accounts[0].accessLabel, 'Partial access (1 permission not granted)', 'full access only when every scope of the level is held');
  assert.deepEqual(view.sections.map(section => [section.label, section.rows.map(item => item.label)]), [['Read permissions', ['See repositories', 'See organizations']], ['Write and delete permissions', ['Create issues']]]);
  assert.deepEqual([row(view, 'github.repos.read').mode, row(view, 'github.issues.write').mode], ['allow', 'ask']);
  assert.match(row(view, 'github.repos.read').etag, /^[0-9a-f]{32}$/);
  assert.equal(view.canReset, false); assert.deepEqual(view.addAccount, {kind: 'oauth', providerId: 'github', body: {appId: 'github', level: 'full'}});
  const wire = JSON.stringify(view), secret = f.app.vault.get(account.id).accessToken;
  for (const leak of [secret, 'authRevision', 'allowedOrigins', 'bindingHash', 'policyHash', 'connectionGeneration', 'vault']) assert.ok(!wire.includes(leak), `leaked ${leak}`);
  // The account's granted scopes never appear; only a row's Add request names the scopes it would ask for.
  assert.ok(!JSON.stringify(view.accounts).includes('repo') && !JSON.stringify(view.accounts).includes('scopes'));
});

// Live check of 2026-10-29: with Google's access removed from the test account, every Gmail account read "Reconnect needed" and its notice
// said "sign in again. Your settings stay as they are", but the page offered only "Add account", which makes a new account with none
// of them. The selected account that must sign in again now offers exactly that, a renewal on the same account.
test('an account that must sign in again offers "Sign in again": a renewal on the same account that keeps its settings, never a new account', async t => {
  const {f, account, detail, row, post} = await setup(t);
  assert.equal((await detail()).body.renew, undefined, 'a ready account has nothing to sign in again');
  const before = row((await detail()).body, 'github.repos.read');
  assert.equal((await post('permissions', {groupId: 'github.repos.read', mode: 'deny', etag: before.etag})).status, 200);
  for (const status of ['reconnect_required', 'expired']) {
    f.app.store.put('connections', {...f.app.store.get('connections', account.id), status});
    const view = (await detail()).body;
    assert.deepEqual(view.renew, {label: 'Sign in again', providerId: 'github', body: {appId: 'github', connectionId: account.id}}, status);
    assert.deepEqual(describeApp(view).renew, {label: 'Sign in again', request: {path: '/api/oauth/github/start', body: {appId: 'github', connectionId: account.id}}, signIn: {providerId: 'github'}});
  }
  // The renewal: the same sign-in the account held (read:org still unticked), on the same account.
  let response = await f.owned('POST', '/api/oauth/github/start', (await detail()).body.renew.body), body = await response.json();
  if (response.status === 409) { response = await f.owned('POST', '/api/oauth/github/start', {...(await detail()).body.renew.body, confirmRows: body.upgrade.etag}); body = await response.json(); }
  assert.equal(response.status, 200, JSON.stringify(body));
  const started = {body, flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie'))[1]};
  assert.equal((await f.callback(started, {grant: {omit: ['read:org']}})).location, '/?oauth=connected');
  assert.deepEqual(f.connections().map(connection => [connection.id, connection.status]), [[account.id, 'ready']], 'the same account, ready again, and no new one');
  assert.ok(f.app.store.list('activity').some(event => event.type === 'connection.reconsented' && event.connectionId === account.id), 'logged as a renewal');
  const after = (await detail()).body;
  assert.deepEqual([row(after, 'github.repos.read').mode, after.renew], ['deny', undefined], 'the saved setting stayed, and the account needs nothing more');
});

test('a row the account lacks provider access for offers the exact least-privileged Add through sign-in', async t => {
  const {f, account, detail, row} = await setup(t);
  const orgs = row((await detail()).body, 'github.orgs.read');
  assert.equal(orgs.access, 'missing');
  assert.deepEqual(orgs.addAccess, {providerId: 'github', body: {connectionId: account.id, level: 'full', scopes: ['read:org']}});
  // F10.4 (T7): read:org turns this row on at its default Allow, so the start needs the row's upgrade card confirmed.
  assert.equal((await f.owned('POST', `/api/oauth/github/start`, orgs.addAccess.body)).status, 409);
  const started = await f.owned('POST', `/api/oauth/github/start`, {...orgs.addAccess.body, confirmRows: orgs.upgrade.etag});
  assert.equal(started.status, 200);
  const url = new URL((await started.json()).authorizationUrl);
  // Under GitHub's full consent policy the sign-in asks for the whole full level, read:org included.
  assert.deepEqual(url.searchParams.get('scope').split(' ').sort(), ['gist', 'read:org', 'read:user', 'repo', 'workflow']);
});

test('F10.4: the page sends Add access with the card it shows; a card that changed comes back on the 409 and is confirmed from there', async t => {
  const {f, detail} = await setup(t);
  const orgs = describeApp((await detail()).body).sections.flatMap(section => section.rows).find(item => item.groupId === 'github.orgs.read');
  assert.match(orgs.add.card.etag, /^[0-9a-f]{64}$/); assert.deepEqual(orgs.add.card.rows.map(item => item.label), ['See organizations']);
  const send = async request => { const response = await f.owned('POST', request.path, request.body), data = await response.json(); if (!response.ok) throw errorOf(data, response.status); return data; };
  const assigned = [], deps = {send, assign: url => assigned.push(url), oauthProviders: {github: {authorizationOrigin: 'https://github.com'}}};
  const refused = await decide(orgs.add, deps).catch(error => error);
  assert.deepEqual([refused.code, refused.upgrade], ['confirm_required', orgs.add.card], 'unconfirmed, the start answers with the card');
  assert.equal((await decide(confirmedRequest(orgs.add, 'f'.repeat(64)), deps).catch(error => error)).code, 'confirm_required', 'another etag is no confirm');
  await decide(confirmedRequest(orgs.add, refused.upgrade.etag), deps);
  assert.equal(new URL(assigned[0]).origin, 'https://github.com');
});

test('setting a row is bound to what was shown; Allow on a write needs the standing-consent confirmation', async t => {
  const {f, detail, row, post} = await setup(t);
  let view = (await detail()).body;
  const issues = row(view, 'github.issues.write');
  assert.equal((await post('permissions', {groupId: issues.groupId, mode: 'allow', etag: issues.etag})).body.code, 'confirm_required');
  const stale = await post('permissions', {groupId: issues.groupId, mode: 'deny', etag: 'f'.repeat(32)});
  assert.equal(stale.status, 409); assert.equal(stale.body.code, 'view_changed'); assert.ok(stale.body.view.sections);
  const set = await post('permissions', {groupId: issues.groupId, mode: 'allow', etag: issues.etag, confirmAllow: true});
  assert.equal(set.status, 200);
  view = set.body;
  assert.equal(row(view, 'github.issues.write').mode, 'allow'); assert.equal(row(view, 'github.issues.write').policySource, 'saved'); assert.equal(view.canReset, true);
  assert.equal((await post('permissions', {groupId: issues.groupId, mode: 'allow', etag: issues.etag, confirmAllow: true})).body.code, 'view_changed', 'the old token no longer applies');
  for (const body of [{groupId: issues.groupId, mode: 'allow', etag: row(view, 'github.issues.write').etag, extra: 1}, {groupId: issues.groupId, mode: 'always', etag: row(view, 'github.issues.write').etag}]) assert.equal((await post('permissions', body)).status, 400);
  assert.equal((await post('permissions', {groupId: 'nope', mode: 'ask', etag: 'x'})).status, 404);
  const audit = f.app.store.list('activity').filter(event => event.type === 'permission.updated');
  assert.equal(audit.at(-1).mode, 'allow');
});

test('reset to defaults returns every row to its reviewed default', async t => {
  const {detail, row, post} = await setup(t);
  const view = (await detail()).body;
  await post('permissions', {groupId: 'github.repos.read', mode: 'deny', etag: row(view, 'github.repos.read').etag});
  const reset = await post('reset', {});
  assert.equal(reset.status, 200);
  assert.equal(row(reset.body, 'github.repos.read').mode, 'allow'); assert.equal(row(reset.body, 'github.repos.read').policySource, 'default'); assert.equal(reset.body.canReset, false);
  assert.equal((await post('reset', {groupIds: 'all'})).status, 400);
});

test('background sync off stops unattended reads for that account, and on restores them', async t => {
  const {f, account, post, caps} = await setup(t);
  const read = caps.find(cap => cap.request.method === 'GET' && cap.request.url.endsWith('/user/repos'));
  const create = () => f.json('POST', '/api/heartbeats', {name: 'Repos', intervalSeconds: 60, connectionId: account.id, capabilityId: read.id, args: {}});
  const off = await post('background', {mode: 'deny'});
  assert.equal(off.body.background.mode, 'deny');
  assert.match((await create()).body.error, /Background actions are turned off/);
  assert.equal((await post('background', {mode: 'allow'})).body.background.mode, 'allow');
  const heartbeat = (await create()).body;
  await post('background', {mode: 'deny'});
  f.advance(61_000); await f.app.heartbeats.tick();
  const ran = f.app.store.get('heartbeats', heartbeat.id);
  assert.equal(ran.lastResult.status, 'failed'); assert.match(ran.lastResult.error, /turned off/);
  assert.equal(f.api.length, 0, 'nothing reached the provider');
  assert.equal((await post('background', {mode: 'sometimes'})).status, 400);
});

test('disconnect revokes the selected account at the provider and answers one shape', async t => {
  const {f, account, post, detail} = await setup(t);
  const result = await post('disconnect', {});
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body).sort(), ['account', 'message', 'remoteRevoked']);
  assert.equal(result.body.account.status, 'revoked'); assert.equal(result.body.remoteRevoked, true); assert.equal(typeof result.body.message, 'string');
  assert.equal(f.app.store.get('connections', account.id).status, 'revoked');
  assert.deepEqual((await detail()).body.accounts, [], 'a revoked account is no longer listed');
});

test('owner routes refuse cross-site calls, unknown apps and accounts of another app', async t => {
  const {f, account, post} = await setup(t);
  assert.equal((await f.owned('GET', '/api/ui/apps/github', undefined)).status, 200);
  const cross = await fetch(`${f.app.origin}/api/ui/apps/github`, {headers: {'sec-fetch-site': 'cross-site'}});
  assert.equal(cross.status, 400);
  assert.equal((await f.json('GET', '/api/ui/apps/nope')).status, 404);
  assert.equal((await f.json('GET', `/api/ui/apps/notion?account=${account.id}`)).status, 404);
  assert.equal((await post('reset', {}, 'missing-account')).status, 404);
  const page = await fetch(`${f.app.origin}/connectors/github`);
  assert.equal(page.status, 200); assert.match(await page.text(), /src="\/hosted-app\.js"/);
});

test('the page model maps every action to its exact request', () => {
  const detail = {app: {id: 'github', name: 'GitHub', displayName: 'GitHub', tagline: 't', iconUrl: '/api/icons/github'}, accessSummary: 's', selectedAccountRef: 'a-1',
    accounts: [{accountRef: 'a-1', displayName: 'octo', email: 'o@example.test', initial: 'O', status: 'ready'}, {accountRef: 'a-2', displayName: 'bot', workspaceName: 'Acme', initial: 'A', status: 'reconnect_required'}],
    addAccount: {kind: 'oauth', providerId: 'github', body: {appId: 'github', writeAccess: true}},
    sections: [{label: 'Read permissions', rows: [{groupId: 'g.read', label: 'See repositories', effect: 'read', mode: 'allow', defaultMode: 'allow', allowedModes: ['allow', 'ask', 'deny'], access: 'granted', policySource: 'default', reviewRequired: false, etag: 'e1'},
      {groupId: 'g.orgs', label: 'See organizations', effect: 'read', mode: 'allow', defaultMode: 'allow', allowedModes: ['allow', 'ask', 'deny'], access: 'missing', addAccess: {providerId: 'github', body: {connectionId: 'a-1', scopes: ['read:org']}}, policySource: 'default', reviewRequired: false, etag: 'e2'}]},
      {label: 'Write and delete permissions', rows: [{groupId: 'g.write', label: 'Create issues', effect: 'write', mode: 'mixed', defaultMode: 'ask', allowedModes: ['ask', 'deny'], access: 'unknown', policySource: 'saved', reviewRequired: true, etag: 'e3'}]}],
    background: {mode: 'allow', allowedEffects: ['read'], runsWhile: 'runtime_running'}, canReset: true, discovery: {state: 'ready'}};
  const model = describeApp(detail);
  assert.deepEqual(model.accounts.map(account => [account.name, account.detail, account.note, account.selected]), [['o@example.test', '', null, true], ['Acme', 'bot', 'Reconnect needed', false]]);
  assert.deepEqual(model.disconnect.request, {path: '/api/ui/apps/github/accounts/a-1/disconnect', body: {}});
  assert.deepEqual(model.addAccount, {request: {path: '/api/oauth/github/start', body: {appId: 'github', writeAccess: true}}, signIn: {providerId: 'github'}});
  const [read, orgs] = model.sections[0].rows, write = model.sections[1].rows[0];
  assert.equal(read.needsAccess, false); assert.equal(orgs.needsAccess, true);
  assert.deepEqual(orgs.add, {request: {path: '/api/oauth/github/start', body: {connectionId: 'a-1', scopes: ['read:org']}}, signIn: {providerId: 'github'}});
  assert.deepEqual(write.options.map(option => option.label), ['Ask', 'Never'], 'Allow is not offered where it is blocked');
  assert.equal(write.modeLabel, 'Mixed'); assert.equal(write.providerNote, 'Permission enforced by the provider');
  assert.deepEqual(rowRequest(detail, read, 'ask'), {path: '/api/ui/apps/github/accounts/a-1/permissions', body: {groupId: 'g.read', mode: 'ask', etag: 'e1'}});
  assert.deepEqual(rowRequest(detail, write, 'ask', {review: true}).body, {groupId: 'g.write', mode: 'ask', etag: 'e3', review: true});
  assert.deepEqual(model.background.request('deny'), {path: '/api/ui/apps/github/accounts/a-1/background', body: {mode: 'deny'}});
  assert.deepEqual(model.reset, {path: '/api/ui/apps/github/accounts/a-1/reset', body: {}});
  assert.equal(MODE_LABEL.deny, 'Never');
});

test('F10.3: a row Fabric locks shows as Never with no options and no Add, apart from a row that needs more access', () => {
  const detail = {app: {id: 'github', name: 'GitHub'}, selectedAccountRef: 'a-1', accounts: [], sections: [{label: 'Write and delete permissions', rows: [
    {groupId: 'github.access.grant', label: 'Give access to other people or services', effect: 'write', locked: true, mode: 'deny', defaultMode: 'deny', allowedModes: ['deny'],
      blockedReason: 'Fabric keeps this off: it gives access to other people or services.', access: 'missing', policySource: 'default', reviewRequired: false, etag: 'e9'},
    {groupId: 'github.issues.write', label: 'Create issues', effect: 'write', audience: true, mode: 'ask', defaultMode: 'ask', allowedModes: ['allow', 'ask', 'deny'], access: 'granted', policySource: 'default', reviewRequired: false, etag: 'e8'}]}]};
  const [locked, issues] = describeApp(detail).sections[0].rows;
  assert.deepEqual([locked.locked, locked.needsAccess, locked.options, locked.add, locked.modeLabel], [true, false, [], null, 'Never']);
  assert.deepEqual([issues.locked, issues.needsAccess, issues.options.map(option => option.mode)], [false, false, ['allow', 'ask', 'deny']]);
});

test('confirmations: review for generated operations, standing consent for Allow on writes', () => {
  const write = {effect: 'write', defaultMode: 'ask', reviewRequired: false}, draft = {effect: 'write', defaultMode: 'allow', reviewRequired: false};
  assert.equal(needsConfirm(write, 'allow'), 'allow'); assert.equal(needsConfirm(write, 'ask'), null);
  assert.equal(needsConfirm(draft, 'allow'), null, 'a reviewed in-account default needs no extra confirmation');
  assert.equal(needsConfirm({effect: 'read', defaultMode: 'allow', reviewRequired: true}, 'allow'), 'review');
  assert.equal(needsConfirm({effect: 'read', defaultMode: 'allow', reviewRequired: true}, 'deny'), null, 'turning something off never needs review');
});

test('decide follows sign-in only to the declared origin', async () => {
  const assigned = [];
  const deps = {send: async () => ({authorizationUrl: 'https://github.com/login/oauth/authorize?x=1'}), assign: url => assigned.push(url), oauthProviders: {github: {authorizationOrigin: 'https://github.com'}}};
  await decide({request: {path: '/x', body: {}}, signIn: {providerId: 'github'}}, deps);
  assert.deepEqual(assigned, ['https://github.com/login/oauth/authorize?x=1']);
  await assert.rejects(decide({request: {path: '/x', body: {}}, signIn: {providerId: 'github'}}, {...deps, send: async () => ({authorizationUrl: 'https://evil.example/'})}), /Unexpected sign-in destination/);
  await decide({request: {path: '/x', body: {}}}, deps);
  assert.equal(assigned.length, 1);
});

test('an app nothing is connected to says so, and promises no access it cannot give here', async t => {
  const {f} = await setup(t);
  const gmail = (await f.json('GET', '/api/ui/apps/gmail')).body;
  assert.equal(gmail.connectionState, 'not_connected'); assert.deepEqual(gmail.accounts, []);
  assert.equal(gmail.accessSummary, null, 'Google sign-in is not configured here, so no access level is promised');
  assert.equal(gmail.addAccount, null, 'no button that cannot work');
  assert.equal(gmail.connectBlocked, "Gmail can't be connected here yet: Google sign-in has not been set up by whoever runs this Fabric.");
  assert.deepEqual(gmail.sections, []);
  const github = (await f.json('GET', '/api/ui/apps/github')).body;
  assert.equal(github.connectionState, 'connected'); assert.equal(github.connectBlocked, undefined);
  const model = describeApp(gmail);
  assert.equal(model.connected, false); assert.equal(model.addAccount, null); assert.match(model.connectBlocked, /Google sign-in has not been set up/);
});

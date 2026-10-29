import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {DEVELOPER_ACCOUNT_FIELDS} from '../lib/tenant/views.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {createHash} from 'node:crypto';

// F03.5a: a developer's end users and their accounts, against a simulated GitHub (token-scoped revocation) and a
// simulated Google (revocation covers the whole grant, so Fabric's shared app never asks Google to revoke: D4).
const SETTINGS = {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}, google: {clientId: 'g-client', clientSecret: 'g-secret'}};

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-users-'));
  const sim = {calls: [], tokens: new Map(), next: null, issued: 0, refuse: new Set()};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://github.com/login/oauth/access_token') { const token = `gho_${++sim.issued}`; sim.tokens.set(token, sim.next.identity); return {status: 200, headers: {}, data: {access_token: token, token_type: 'bearer', scope: sim.next.scope.split(' ').join(',')}}; }
    if (req.url === 'https://api.github.com/user') { const token = String(req.headers.Authorization).slice(7); if (sim.refuse.has(token)) return {status: 401, headers: {}, data: {message: 'Bad credentials'}}; const who = sim.tokens.get(token); return {status: 200, headers: {}, data: {id: who.id, login: who.login, name: who.name, email: who.email}}; }
    if (req.url === 'https://oauth2.googleapis.com/token') { const token = `ya29.${++sim.issued}`; sim.tokens.set(token, sim.next.identity); return {status: 200, headers: {}, data: {access_token: token, refresh_token: `1//r${sim.issued}`, token_type: 'Bearer', expires_in: 3600, scope: sim.next.scope}}; }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') { const who = sim.tokens.get(String(req.headers.Authorization).slice(7)); return {status: 200, headers: {}, data: {sub: who.id, email: who.email, name: who.name}}; }
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) { const who = sim.tokens.get(String(req.headers.Authorization).slice(7)); return {status: 200, headers: {}, data: {emailAddress: who.email}}; }
    if (req.url.startsWith('https://www.googleapis.com/calendar/v3/users/me/calendarList')) return {status: 200, headers: {}, data: {kind: 'calendar#calendarList'}};
    if (req.url === 'https://api.github.com/applications/gh-client/token') return {status: 204, headers: {}, data: null};
    if (req.url === 'https://oauth2.googleapis.com/revoke') return {status: 200, headers: {}, data: {}};
    throw new Error(`unexpected request ${req.url}`);
  };
  const traced = async req => { try { return await request(req); } catch (error) { sim.unexpected = req.url; throw error; } };
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: SETTINGS, request: traced});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const customer = (name, preset = 'full') => {
    const org = app.registry.createOrganization({name}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
    const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
    return {dev, scope: app.registry.scopeOf(dev), key: app.keys.mint({environmentId: dev.id, preset}).token};
  };
  const call = async (key, method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  // One person connects one account through the real path: link, open, start, provider callback, confirm.
  const connect = async (who, externalUserId, appId, identity) => {
    const created = (await call(who.key, 'POST', '/v1/connect-sessions', {externalUserId, appId})).body;
    const binding = `browser-${created.id}`, secret = new URL(created.connectUrl).hash.slice(3);
    app.sessions.claim(created.id, secret, binding);
    const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl);
    sim.next = {identity, scope: url.searchParams.get('scope')};
    const {finish, failed} = await app.sessions.callback(appId === 'github' ? 'github' : 'google', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
    if (failed) throw Object.assign(new Error(`sign-in failed: ${failed}`), {code: failed});
    return app.sessions.confirm(created.id, binding, finish).result.accountRef;
  };
  const revokes = provider => sim.calls.filter(line => provider === 'google' ? line.includes('oauth2.googleapis.com/revoke') : line.includes('/applications/gh-client/token')).length;
  return {app, root, sim, customer, call, connect, revokes};
}
const OCTO = {id: 7, login: 'octo', name: 'Octo Cat', email: 'octo@example.com'}, HUB = {id: 8, login: 'hubber', name: 'Hub', email: 'hub@example.com'};
const files = dir => { const out = []; const walk = folder => { for (const entry of readdirSync(folder, {withFileTypes: true})) { const full = path.join(folder, entry.name); if (entry.isDirectory()) walk(full); else out.push(full); } }; walk(dir); return out; };

test('an account row is the closed DeveloperAccountRow: no scopes, tokens, identity ids, origins or client id', async t => {
  const {customer, call, connect} = await setup(t);
  const acme = customer('Acme');
  const ref = await connect(acme, 'aura-user-1', 'github', OCTO);
  const listed = (await call(acme.key, 'GET', '/v1/users/aura-user-1/accounts')).body.accounts;
  assert.equal(listed.length, 1);
  const row = listed[0];
  for (const key of Object.keys(row)) assert.ok(DEVELOPER_ACCOUNT_FIELDS.includes(key), `unexpected field ${key}`);
  for (const key of ['accountRef', 'appId', 'displayName', 'status', 'healthy', 'accessLevel', 'accessLabel', 'providerApp', 'isDefault', 'connectedAt']) assert.ok(key in row, `missing ${key}`);
  assert.deepEqual({ref: row.accountRef, app: row.appId, name: row.displayName, email: row.email, status: row.status, healthy: row.healthy, provider: row.providerApp, isDefault: row.isDefault}, {ref, app: 'github', name: 'octo', email: undefined, status: 'ready', healthy: true, provider: {kind: 'shared'}, isDefault: true});
  assert.match(row.connectedAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  const text = JSON.stringify(listed);
  for (const secret of ['gho_', 'scopes', 'repo', '"7"', 'gh-client', 'allowedOrigins', 'authRevision']) assert.equal(text.includes(secret), false, secret);
  assert.deepEqual((await call(acme.key, 'GET', `/v1/users/aura-user-1/accounts/${ref}`)).body, row);
  const anywhere = (await call(acme.key, 'GET', `/v1/accounts/${ref}`)).body;
  assert.deepEqual(anywhere, {...row, externalUserId: 'aura-user-1'});
});

test('end users list with stable paging, an honest total and a prefix search; one user shows their accounts', async t => {
  const {app, customer, call, connect} = await setup(t);
  const acme = customer('Acme');
  for (const id of ['team:a', 'team:b', 'team:c', 'other-1', 'other-2']) await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: id});
  await connect(acme, 'team:c', 'github', OCTO);
  const first = (await call(acme.key, 'GET', '/v1/users?limit=2')).body;
  assert.equal(first.pageInfo.totalCount, 5); assert.equal(first.users.length, 2); assert.ok(first.pageInfo.endCursor);
  // Even the very user the cursor names may be deleted between pages; the next page still starts right after it.
  await call(acme.key, 'DELETE', `/v1/users/${encodeURIComponent(first.users[1].externalUserId)}`);
  const second = (await call(acme.key, 'GET', `/v1/users?limit=2&after=${first.pageInfo.endCursor}`)).body;
  const third = (await call(acme.key, 'GET', `/v1/users?limit=2&after=${second.pageInfo.endCursor}`)).body;
  assert.deepEqual([...first.users, ...second.users, ...third.users].map(user => user.externalUserId), ['team:a', 'team:b', 'team:c', 'other-1', 'other-2']);
  assert.equal(second.pageInfo.totalCount, 4, 'the total counts what exists now');
  assert.equal(third.pageInfo.endCursor, undefined);
  const searched = (await call(acme.key, 'GET', '/v1/users?q=team:')).body;
  assert.deepEqual(searched.users.map(user => user.externalUserId), ['team:a', 'team:c']);
  assert.deepEqual(searched.users.map(user => user.accounts), [0, 1]);
  const one = (await call(acme.key, 'GET', '/v1/users/team%3Ac')).body.user;
  assert.equal(one.externalUserId, 'team:c'); assert.equal(one.accounts.length, 1); assert.ok(one.lastConnectedAt);
  assert.equal((await call(acme.key, 'GET', '/v1/users/nobody')).body.error.code, 'not_found');
  assert.deepEqual((await call(acme.key, 'GET', '/v1/users/nobody/accounts')).body, {accounts: []}, 'a list route for an unknown user is empty');
  assert.equal((await call(acme.key, 'GET', '/v1/users/a%20b')).body.error.code, 'invalid_external_user_id');
  assert.equal((await call(acme.key, 'GET', '/v1/users?after=bogus')).status, 400);
  void app;
});

test('another end user, another environment and an unknown ref all get the same not_found; scopes are checked first', async t => {
  const {app, customer, call, connect} = await setup(t);
  const acme = customer('Acme'), beta = customer('Beta'), narrow = customer('Narrow', 'connect-only');
  const mine = await connect(acme, 'u1', 'github', OCTO), theirs = await connect(acme, 'u2', 'github', HUB), elsewhere = await connect(beta, 'u1', 'github', OCTO);
  const body = response => JSON.stringify({...response.body, error: {...response.body.error, requestId: 'x'}});
  const unknown = await call(acme.key, 'GET', '/v1/accounts/00000000-0000-4000-8000-000000000000');
  assert.equal(unknown.status, 404);
  for (const route of [`/v1/accounts/${elsewhere}`, `/v1/users/u1/accounts/${theirs}`, `/v1/users/u1/accounts/${elsewhere}`, '/v1/users/u1/accounts/not-a-ref']) {
    const response = await call(acme.key, 'GET', route);
    assert.equal(response.status, 404, route); assert.equal(body(response), body(unknown), route);
  }
  for (const route of [`/v1/accounts/${elsewhere}/disconnect`, `/v1/users/u1/accounts/${theirs}/disconnect`, `/v1/users/u2/accounts/${mine}/check`]) {
    const response = await call(acme.key, 'POST', route, {});
    assert.equal(response.status, 404, route); assert.equal(body(response), body(unknown), route);
  }
  assert.equal((await call(acme.key, 'PUT', '/v1/users/u1/apps/github/default-account', {accountRef: theirs})).body.error.code, 'not_found');
  assert.equal((await call(acme.key, 'GET', `/v1/users/u1/accounts/${mine}`)).status, 200, 'still there');
  // The environment-wide list shows only this environment's accounts, each with its own end user.
  const all = (await call(acme.key, 'GET', '/v1/accounts')).body;
  assert.deepEqual(all.accounts.map(row => [row.externalUserId, row.accountRef]).sort(), [['u1', mine], ['u2', theirs]].sort());
  assert.equal(all.pageInfo.totalCount, 2);
  assert.deepEqual((await call(acme.key, 'GET', '/v1/accounts?externalUserId=u2')).body.accounts.map(row => row.accountRef), [theirs]);
  // Environment-wide routes take the owner from the stored record and fail closed: a record with no owner, or whose
  // end user is no longer active, is not_found everywhere.
  const repo = app.stores.open(acme.scope).repository, stray = '11111111-1111-4111-8111-111111111111', orphan = '22222222-2222-4222-8222-222222222222';
  repo.put('connections', {...repo.get('connections', mine), id: stray, ownership: undefined, userRecordId: undefined});
  repo.put('connections', {...repo.get('connections', mine), id: orphan, userRecordId: 'usr_' + 'z'.repeat(26)});
  for (const ref of [stray, orphan]) {
    assert.equal(body(await call(acme.key, 'GET', `/v1/accounts/${ref}`)), body(unknown), ref);
    assert.equal(body(await call(acme.key, 'POST', `/v1/accounts/${ref}/disconnect`, {})), body(unknown), ref);
  }
  assert.equal((await call(acme.key, 'GET', '/v1/accounts')).body.pageInfo.totalCount, 2, 'neither is listed');
  // A key without the scope learns nothing, before any lookup.
  assert.equal((await call(narrow.key, 'POST', `/v1/accounts/${mine}/disconnect`, {})).body.error.code, 'forbidden_scope');
  assert.equal((await call(narrow.key, 'GET', '/v1/users')).body.error.code, 'forbidden_scope');
  assert.equal((await call(narrow.key, 'DELETE', '/v1/users/u1')).body.error.code, 'forbidden_scope');
});

test('disconnect: GitHub revokes the token it holds; shared Google is erased here only and says why (D4); remote:true is refused', async t => {
  const {app, customer, call, connect, revokes} = await setup(t);
  const acme = customer('Acme'), env = () => app.stores.open(acme.scope);
  const github = await connect(acme, 'u1', 'github', OCTO), gmail = await connect(acme, 'u1', 'gmail', {id: 'g-1', email: 'one@example.com', name: 'One'});
  const refused = await call(acme.key, 'POST', `/v1/users/u1/accounts/${gmail}/disconnect`, {remote: true});
  assert.equal(refused.status, 422); assert.equal(refused.body.error.code, 'remote_unavailable');
  assert.equal(env().repository.get('connections', gmail).status, 'ready', 'a refused disconnect changes nothing');
  assert.equal((await call(acme.key, 'POST', `/v1/users/u1/accounts/${gmail}/disconnect`, {extra: 1})).status, 400);
  const google = await call(acme.key, 'POST', `/v1/users/u1/accounts/${gmail}/disconnect`, {});
  assert.equal(google.status, 200); assert.equal(google.body.remoteRevoked, false);
  assert.match(google.body.message, /every other app that uses Fabric's shared Google sign-in/);
  assert.equal(google.body.account.status, 'revoked'); assert.equal(google.body.account.healthy, false);
  assert.equal(revokes('google'), 0, 'Google is never asked to revoke on the shared app');
  assert.equal(env().vault.get(gmail), null, 'Fabric\'s copy is erased');
  const hub = await call(acme.key, 'POST', `/v1/accounts/${github}/disconnect`);
  assert.equal(hub.body.remoteRevoked, true); assert.equal(revokes('github'), 1);
  assert.deepEqual((await call(acme.key, 'GET', '/v1/users/u1/accounts')).body.accounts, []);
  assert.equal((await call(acme.key, 'GET', `/v1/accounts/${github}`)).status, 404, 'a disconnected account is gone from every route');
  // remote:false disconnects here only, even where the provider could revoke.
  const again = await connect(acme, 'u1', 'github', HUB);
  const local = await call(acme.key, 'POST', `/v1/users/u1/accounts/${again}/disconnect`, {remote: false});
  assert.equal(local.body.remoteRevoked, false); assert.equal(revokes('github'), 1);
});

test('a check asks the provider who the account is; a refused credential shows reconnect_required with the reason', async t => {
  const {sim, app, customer, call, connect} = await setup(t);
  const acme = customer('Acme');
  const ref = await connect(acme, 'u1', 'github', OCTO);
  const fine = await call(acme.key, 'POST', `/v1/users/u1/accounts/${ref}/check`);
  assert.equal(fine.status, 200); assert.equal(fine.body.status, 'ready'); assert.ok(fine.body.lastCheckedAt);
  sim.refuse.add(app.stores.open(acme.scope).vault.get(ref).accessToken);
  const broken = (await call(acme.key, 'POST', `/v1/users/u1/accounts/${ref}/check`)).body;
  assert.equal(broken.status, 'reconnect_required'); assert.equal(broken.healthy, false); assert.match(broken.attention, /Reconnect/);
});

test('the default account per app is the developer\'s choice among the user\'s own accounts', async t => {
  const {customer, call, connect} = await setup(t);
  const acme = customer('Acme');
  const first = await connect(acme, 'u1', 'github', OCTO), second = await connect(acme, 'u1', 'github', HUB);
  const flags = async () => Object.fromEntries((await call(acme.key, 'GET', '/v1/users/u1/accounts?appId=github')).body.accounts.map(row => [row.accountRef, row.isDefault]));
  assert.deepEqual(await flags(), {[first]: true, [second]: false});
  assert.deepEqual((await call(acme.key, 'PUT', '/v1/users/u1/apps/github/default-account', {accountRef: second})).body, {appId: 'github', accountRef: second});
  assert.deepEqual(await flags(), {[first]: false, [second]: true});
  assert.equal((await call(acme.key, 'PUT', '/v1/users/u1/apps/gmail/default-account', {accountRef: second})).body.error.code, 'not_found', 'an account of another app');
  await call(acme.key, 'POST', `/v1/users/u1/accounts/${second}/disconnect`, {});
  assert.deepEqual(await flags(), {[first]: true}, 'a disconnected default falls back to the first ready account');
});

test('deleting an end user disconnects and erases everything they own, keeps a usr_-only tombstone, and leaves the other user untouched', async t => {
  const {app, root, customer, call, connect, revokes} = await setup(t);
  const acme = customer('Acme'), env = () => app.stores.open(acme.scope), repo = () => env().repository;
  const gh1 = await connect(acme, 'user-one', 'github', OCTO), g1 = await connect(acme, 'user-one', 'gmail', {id: 'g-one', email: 'one-secret@example.com', name: 'Person One'});
  const gh2 = await connect(acme, 'user-two', 'github', HUB);
  // User one also has an open link with a sign-in under way, a stored permission, background setting, job and proxy response.
  const open = (await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'user-one', appId: 'github'})).body;
  app.sessions.claim(open.id, new URL(open.connectUrl).hash.slice(3), 'browser-open-binding-1');
  const started = app.sessions.start(open.id, 'browser-open-binding-1');
  const one = repo().list('endUsers').find(user => user.subjectId === 'user-one'), two = repo().list('endUsers').find(user => user.subjectId === 'user-two');
  const owner1 = {subjectId: 'user-one', userRecordId: one.id};
  repo().put('permissions', {id: `${gh1}:cap`, connectionId: gh1, capabilityId: 'cap', mode: 'allow'});
  repo().put('backgroundPolicies', {id: g1, connectionId: g1, mode: 'deny'});
  repo().put('jobs', stampOwner({id: 'job-1', status: 'awaiting_approval', connectionId: gh1}, owner1));
  repo().put('proxyResponses', {id: 'job-1', connectionId: gh1, body: 'one-secret-body'});
  repo().put('permissions', {id: `${gh2}:cap`, connectionId: gh2, capabilityId: 'cap', mode: 'ask'});
  // A credential left behind by an earlier, interrupted disconnect is erased too.
  const leftover = '33333333-3333-4333-8333-333333333333';
  repo().put('connections', {...repo().get('connections', gh1), id: leftover, status: 'revoked'}); env().vault.set(leftover, {accessToken: 'gho_leftover'});
  const twoBefore = JSON.stringify([repo().get('connections', gh2), repo().get('endUsers', two.id), repo().get('permissions', `${gh2}:cap`), env().vault.get(gh2)]);
  const vaultFiles = () => files(path.join(env().folder, 'vault')).filter(file => file.endsWith('.enc')).length;
  const githubBefore = revokes('github');
  assert.ok(app.registry.get('flowRoutes', createHash('sha256').update(new URL(started.authorizationUrl).searchParams.get('state')).digest('hex')), 'the sign-in route exists before the delete');
  assert.ok(files(root).some(file => readFileSync(file).includes('one-secret@example.com')), 'the email is on disk before the delete');

  const deleted = await call(acme.key, 'DELETE', '/v1/users/user-one');
  assert.equal(deleted.status, 200); assert.equal(deleted.body.deleted, true);
  assert.deepEqual(deleted.body.accounts.map(item => [item.accountRef, item.appId, item.remoteRevoked]).sort(), [[g1, 'gmail', false], [gh1, 'github', true]].sort());
  assert.equal(revokes('google'), 0, 'deleting a user never revokes at Google on the shared app');
  assert.equal(revokes('github'), githubBefore + 1);
  for (const [collection, id] of [['connections', gh1], ['connections', g1], ['connectSessions', open.id], ['permissions', `${gh1}:cap`], ['backgroundPolicies', g1], ['jobs', 'job-1'], ['proxyResponses', 'job-1']]) assert.equal(repo().get(collection, id), null, `${collection} ${id}`);
  assert.equal(repo().list('oauthFlows').length, 0, 'the open sign-in is gone');
  assert.equal(app.registry.get('sessionRoutes', open.id), null); const routeId = createHash('sha256').update(new URL(started.authorizationUrl).searchParams.get('state')).digest('hex');
  assert.equal(app.registry.get('flowRoutes', routeId), null, 'the open sign-in\'s route is gone');
  for (const id of [gh1, g1, leftover]) assert.equal(env().vault.get(id), null);
  assert.equal(vaultFiles(), 1, 'only user two\'s credential is left in the vault');
  assert.deepEqual(Object.keys(repo().get('endUsers', one.id)).sort(), ['deletedAt', 'id', 'scope', 'status']);
  assert.equal(JSON.stringify([repo().get('connections', gh2), repo().get('endUsers', two.id), repo().get('permissions', `${gh2}:cap`), env().vault.get(gh2)]), twoBefore, 'no byte of user two changed');
  // Fabric's files lose the data: the external id, email and stored bodies are not left in any file.
  for (const file of files(root)) { const bytes = readFileSync(file); for (const needle of ['user-one', 'one-secret@example.com', 'Person One', 'one-secret-body']) assert.equal(bytes.includes(needle), false, `${needle} in ${path.relative(root, file)}`); }
  // The same external id later is a new person who inherits nothing; the old link cannot be used.
  assert.equal((await call(acme.key, 'GET', '/v1/users/user-one')).body.error.code, 'not_found');
  assert.throws(() => app.sessions.view(open.id, 'browser-open-binding-1'), {code: 'not_found'});
  await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'user-one'});
  const again = (await call(acme.key, 'GET', '/v1/users/user-one')).body.user;
  assert.deepEqual(again.accounts, []);
  assert.notEqual(repo().list('endUsers').find(user => user.subjectId === 'user-one').id, one.id);
});

test('a sign-in that lands after its link was cancelled is dropped; on shared Google nothing is revoked at Google', async t => {
  const {app, sim, customer, call, revokes} = await setup(t);
  const acme = customer('Acme'), env = () => app.stores.open(acme.scope);
  const created = (await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'gmail'})).body;
  app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), 'browser-cancel-binding');
  const started = app.sessions.start(created.id, 'browser-cancel-binding'), url = new URL(started.authorizationUrl);
  await call(acme.key, 'POST', `/v1/connect-sessions/${created.id}/cancel`);
  sim.next = {identity: {id: 'g-x', email: 'x@example.com', name: 'X'}, scope: url.searchParams.get('scope')};
  await assert.rejects(app.sessions.callback('google', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId}), {code: 'invalid_state'});
  assert.equal(env().repository.list('connections').length, 0, 'no account is left behind');
  assert.equal((await call(acme.key, 'GET', `/v1/connect-sessions/${created.id}`)).body.state, 'cancelled', 'the cancelled link stays cancelled');
  assert.equal(revokes('google'), 0);
});

test('Fabric\'s shared Testing-mode Google client takes at most 10 Google accounts per environment; the 11th is refused', async t => {
  const {app, customer, call, connect} = await setup(t);
  const acme = customer('Acme'), env = () => app.stores.open(acme.scope);
  for (let i = 1; i <= 10; i++) await connect(acme, `u${i}`, 'gmail', {id: `g-${i}`, email: `p${i}@example.com`, name: `P${i}`});
  await connect(acme, 'u1', 'google-calendar', {id: 'g-1', email: 'p1@example.com', name: 'P1'});
  await assert.rejects(connect(acme, 'u11', 'gmail', {id: 'g-11', email: 'p11@example.com', name: 'P11'}), {code: 'user_cap_reached'});
  assert.equal(env().repository.list('connections').filter(connection => connection.identity?.id === 'g-11').length, 0);
  const session = env().repository.list('connectSessions').find(item => item.state === 'failed');
  assert.equal(session.result.errorCode, 'user_cap_reached');
  void call;
});

test('the revocation choke point: an adapter on Fabric\'s shared Google app never sends a revoke, on any path (N9)', async t => {
  const {app, sim, customer} = await setup(t);
  const acme = customer('Acme');
  const google = app.sessions.adapterFor(acme.scope, 'google').adapter, github = app.sessions.adapterFor(acme.scope, 'github').adapter;
  assert.equal(google.revocationPolicy, 'local_only'); assert.equal(github.revocationPolicy, 'provider');
  assert.equal(await google.revokeTokens({accessToken: 'ya29.x', refreshToken: '1//x'}), false);
  assert.equal(sim.calls.length, 0, 'no request left Fabric');
  assert.equal(await github.revokeTokens({accessToken: 'gho_x'}), true);
  assert.equal(sim.calls.length, 1);
});

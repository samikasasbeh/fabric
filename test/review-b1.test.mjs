import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {EnvironmentStores, EnvironmentError} from '../lib/tenant/environments.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';

// The security review of the developer layer (docs/F03-SECURITY-REVIEW.md), group b1: an environment is opened before
// it is pinned, and stays pinned across every provider call, so other environments' traffic can never close its store
// and vault under work in flight (ISO-1, ISO-2, ROB-1, ROB-2, secrets-2). Environments with work in flight never lock
// every other environment out (ISO-3). Each test here failed before its fix.
const GMAIL = 'https://gmail.googleapis.com';
const REVOKE = 'https://api.github.com/applications/';
const PROVIDERS = {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}};
const TYPED = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send']];
function seed(root) {
  const paths = {};
  for (const [id, method, route] of TYPED) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: GMAIL}], paths}}).capabilities;
  const store = new PlatformStore({root});
  const operations = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => ({id, method: id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`, sensitive: null}));
  for (const [id, method, route] of TYPED) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `${GMAIL}${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations[operations.findIndex(op => op.id === id)] = {id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null};
  }
  for (const [id, route] of [['gmail.users.labels.list', '/gmail/v1/users/{userId}/labels'], ['gmail.users.labels.create', '/gmail/v1/users/{userId}/labels']]) operations[operations.findIndex(op => op.id === id)].path = route;
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

/** One developer server with `environments` development environments (each its own organization); u1 exists in the first. */
async function setup(t, {environments = 1} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review-b1-'));
  seed(root);
  const now = Date.UTC(2026, 9, 17, 9), clock = () => now;
  // `before` is where a test holds a provider request; `answer` is a test's own reply. Every gate opens when the test ends.
  const sim = {calls: [], gates: [], gate: null, issued: 0, before: null, answer: null};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    await sim.before?.(req);
    const custom = await sim.answer?.(req);
    if (custom) return custom;
    if (req.url === 'https://github.com/login/oauth/access_token') { await sim.gate; return {status: 200, headers: {}, data: {access_token: `gho_review_${++sim.issued}`, token_type: 'bearer', scope: sim.scope ?? 'read:user,repo'}}; }
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: {id: 100, login: 'octo100', name: 'Octo 100'}};
    if (req.url.startsWith(REVOKE)) return {status: 204, headers: {}, data: null};
    const data = req.url.includes('/labels') ? {labels: [{id: 'INBOX'}]} : {id: 'm-1', snippet: 'hello'};
    return req.responseType === 'buffer' ? {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(data))} : {status: 200, headers: {}, data};
  };
  const apps = [];
  const start = async () => { const app = await createDeveloperApp({dataRoot: root, port: 0, clock, request, providerSettings: PROVIDERS}); apps.push(app); return app; };
  const s = {sim, root, now: () => now, app: await start()};
  t.after(async () => {
    sim.release?.(); for (const open of sim.gates) open();
    for (const app of apps) { await app.sessions.settled(); await app.close(); }
    rmSync(root, {recursive: true, force: true});
  });
  s.envs = [];
  for (let i = 0; i < environments; i++) {
    const org = s.app.registry.createOrganization({name: `Org ${i}`}), project = s.app.registry.createProject({organizationId: org.id, name: `P${i}`});
    const dev = s.app.registry.createEnvironment({projectId: project.id, kind: 'development'}, s.app.stores);
    s.envs.push({dev, scope: s.app.registry.scopeOf(dev), key: s.app.keys.mint({environmentId: dev.id, preset: 'full'}).token});
  }
  [{dev: s.dev, scope: s.scope, key: s.key}] = s.envs;
  s.call = async (method, route, body, token = s.key, headers = {}) => {
    const response = await fetch(`${s.app.origin}${route}`, {method, headers: {Authorization: `Bearer ${token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: response.status === 204 ? null : await response.json()};
  };
  s.repo = () => s.app.stores.open(s.scope).repository;
  let counter = 0;
  s.agent = async (token, method, params) => {
    const response = await fetch(`${s.app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id: `r${++counter}`, method, params})});
    return {status: response.status, headers: response.headers, body: await response.json()};
  };
  /** A gate a provider request waits at until the test opens it. */
  s.gate = () => { let open; const shut = new Promise(resolve => { open = resolve; }); sim.gates.push(open); return {shut, open}; };
  /** Waits (a little) for something a request in flight does. */
  s.until = async (ready, what = 'the request in flight') => { for (let i = 0; i < 400 && !ready(); i++) await new Promise(resolve => setTimeout(resolve, 5)); assert.ok(ready(), `${what} never got there`); };
  /** Every other environment makes one ordinary call: enough to evict any environment nothing keeps open. */
  s.crowd = async () => { for (const other of s.envs.slice(1)) assert.equal((await s.call('GET', '/v1/users', undefined, other.key)).status, 200); };
  s.restart = async () => { await s.app.close(); s.app = await start(); };
  /** A ready Gmail account for u1 in one environment. */
  s.gmail = async (env = s.envs[0]) => {
    await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1'}, env.key);
    const handle = s.app.stores.open(env.scope), user = handle.repository.list('endUsers').find(item => item.subjectId === 'u1'), id = randomUUID(), stamp = s.app.registry.now();
    handle.repository.put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: 'g-1', displayName: 'one@example.com'}, allowedOrigins: [GMAIL],
      scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.labels'], createdAt: stamp, updatedAt: stamp, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: 'u1', userRecordId: user.id}));
    handle.vault.set(id, {accessToken: 'ya29.review', refreshToken: '1//r', expiresAt: Date.parse(stamp) + 3600_000});
    return id;
  };
  /** A ready GitHub account for u1 in the first environment, on Fabric's shared app (its token is revoked at GitHub). */
  s.github = tokens => {
    const handle = s.app.stores.open(s.scope), user = handle.repository.list('endUsers').find(item => item.subjectId === 'u1'), id = randomUUID(), stamp = s.app.registry.now();
    handle.repository.put('connections', stampOwner({id, appId: 'github', providerId: 'github', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: '100', displayName: 'octo100'}, allowedOrigins: ['https://api.github.com'],
      scopes: ['read:user', 'repo'], createdAt: stamp, updatedAt: stamp, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: 'u1', userRecordId: user.id}));
    handle.vault.set(id, tokens);
    return id;
  };
  /** A sign-in through the real GitHub path for u1, stopped before confirm. */
  s.signIn = async (session = null) => {
    const created = session ?? (await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body, binding = `browser-${created.id}-binding`;
    s.app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
    const started = s.app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl);
    sim.scope = (url.searchParams.get('scope') || '').split(' ').filter(Boolean).join(',');
    const back = await s.app.sessions.callback('github', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
    return {...back, id: created.id, confirm: () => s.app.sessions.confirm(created.id, binding, back.finish), reject: () => s.app.sessions.reject(created.id, binding)};
  };
  await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1'});
  return s;
}
/** An agent token for u1 that may read Gmail through one account. */
async function agentToken(s) {
  const account = await s.gmail(), read = (await s.call('GET', '/v1/capabilities?appId=gmail')).body.capabilities.find(item => item.id.includes('messages-get'));
  return (await s.call('POST', '/v1/users/u1/agent-tokens', {name: 'Helper', bindings: [{accountRef: account, capabilityId: read.id}]})).body.token;
}

test('ISO-1, ROB-2: an agent call opens its environment before pinning it, so it answers after an eviction and after a restart', async t => {
  const s = await setup(t);
  const token = await agentToken(s);
  assert.equal((await s.agent(token, 'fabric.discover', {})).status, 200);
  // What an eviction does: nothing holds the environment open now.
  s.app.stores.close(s.scope);
  const listed = await s.agent(token, 'capabilities.list', {});
  assert.equal(listed.status, 200, JSON.stringify(listed.body)); assert.equal(listed.body.protocol, 'fabric/0.1');
  assert.equal(s.app.stores.close(s.scope), true, 'the call left nothing pinned');
  // A wrong secret on a live route, while the environment is closed, reads like every other unusable token.
  const wrong = `${token.slice(0, -1)}${token.endsWith('A') ? 'B' : 'A'}`, refused = await s.agent(wrong, 'fabric.discover', {});
  assert.deepEqual([refused.status, refused.body.protocol, refused.body.error?.code], [401, 'fabric/0.1', 'unauthorized']);
  // A restart opens no environment until something asks for one.
  await s.restart();
  assert.equal(s.app.stores.isOpen(s.scope), false);
  const again = await s.agent(token, 'fabric.discover', {});
  assert.equal(again.status, 200, JSON.stringify(again.body)); assert.equal(again.body.protocol, 'fabric/0.1');
  assert.equal((await s.agent(token, 'capabilities.list', {})).status, 200);
});

test('ISO-1: an agent call that finds every environment busy is told to come back, in the protocol\'s own shape', async t => {
  const s = await setup(t);
  const token = await agentToken(s);
  s.app.stores.close(s.scope);
  // What the store cache does at its hard ceiling.
  s.app.stores.open = () => { throw new EnvironmentError('too_many_open', 'Every open environment has work in flight; try again shortly.'); };
  let busy;
  try { busy = await s.agent(token, 'fabric.discover', {}); } finally { delete s.app.stores.open; }
  assert.deepEqual([busy.status, busy.body.protocol, busy.body.error?.code], [503, 'fabric/0.1', 'unavailable']);
  assert.equal(busy.headers.get('retry-after'), '1');
  assert.equal((await s.agent(token, 'fabric.discover', {})).status, 200, 'it answers once a slot is free');
});

test('secrets-2: an environment stays open while a sign-in waits on the provider, so the new account is kept', async t => {
  const s = await setup(t, {environments: 17});
  const created = (await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body;
  s.sim.gate = new Promise(resolve => { s.sim.release = resolve; });
  const pending = s.signIn(created);
  await new Promise(resolve => setTimeout(resolve, 50));
  for (const other of s.envs.slice(1)) await s.call('GET', '/v1/users', undefined, other.key);
  assert.equal(s.app.stores.isOpen(s.scope), true, 'the environment was not evicted mid sign-in');
  s.sim.release(); s.sim.gate = null;
  const back = await pending;
  assert.equal(back.failed, undefined); assert.ok(back.finish);
  assert.equal(back.confirm().state, 'connected');
  assert.equal(s.app.registry.list('flowRoutes').length, 0, 'the used flow left no route');
});

test('ROB-1: an account check keeps its environment open while GitHub rotates the refresh token, so the new pair is saved', async t => {
  const s = await setup(t, {environments: 17});
  const valid = new Set(['ghr_1']), held = s.gate();
  let rotated = 0;
  s.sim.answer = async req => {
    if (req.url !== 'https://github.com/login/oauth/access_token') return null;
    // Single use: the old refresh token stops working the moment GitHub issues the next one.
    if (!valid.delete(new URLSearchParams(req.body).get('refresh_token'))) return {status: 200, headers: {}, data: {error: 'bad_refresh_token'}};
    const next = `ghr_${++rotated + 1}`;
    valid.add(next);
    await held.shut;
    return {status: 200, headers: {}, data: {access_token: `gho_new_${rotated}`, refresh_token: next, expires_in: 28800, refresh_token_expires_in: 15_000_000, token_type: 'bearer'}};
  };
  const ref = s.github({accessToken: 'gho_old', refreshToken: 'ghr_1', expiresAt: s.now() - 1000});
  const pending = s.call('POST', `/v1/users/u1/accounts/${ref}/check`);
  await s.until(() => rotated === 1, 'the refresh');
  await s.crowd();
  assert.equal(s.app.stores.isOpen(s.scope), true, 'the environment was not evicted mid refresh');
  held.open();
  const checked = await pending;
  assert.equal(checked.status, 200, JSON.stringify(checked.body)); assert.equal(checked.body.status, 'ready');
  assert.equal(s.app.stores.open(s.scope).vault.get(ref).refreshToken, 'ghr_2', 'the rotated pair was saved');
});

test('ROB-1, ISO-2: a disconnect keeps its environment open while GitHub revokes the token, and answers', async t => {
  const s = await setup(t, {environments: 17});
  const ref = s.github({accessToken: 'gho_live', refreshToken: 'ghr_1', expiresAt: s.now() + 3600_000}), held = s.gate();
  s.sim.before = req => req.url.startsWith(REVOKE) ? held.shut : null;
  const pending = s.call('POST', `/v1/users/u1/accounts/${ref}/disconnect`, {});
  await s.until(() => s.sim.calls.some(line => line.includes(REVOKE)), 'the revoke');
  await s.crowd();
  assert.equal(s.app.stores.isOpen(s.scope), true, 'the environment was not evicted mid revoke');
  held.open();
  const done = await pending;
  assert.equal(done.status, 200, JSON.stringify(done.body)); assert.equal(done.body.remoteRevoked, true);
  assert.equal(s.repo().get('connections', ref).status, 'revoked');
  assert.ok(s.repo().list('activity').some(row => row.type === 'tenant.account_disconnected' && row.accountRef === ref), 'the disconnect was recorded');
});

test('ROB-1, ISO-2: deleting a user keeps the environment open across the provider revokes, and finishes', async t => {
  const s = await setup(t, {environments: 17});
  const ref = s.github({accessToken: 'gho_live', refreshToken: 'ghr_1', expiresAt: s.now() + 3600_000}), held = s.gate();
  s.sim.before = req => req.url.startsWith(REVOKE) ? held.shut : null;
  const pending = s.call('DELETE', '/v1/users/u1');
  await s.until(() => s.sim.calls.some(line => line.includes(REVOKE)), 'the revoke');
  await s.crowd();
  assert.equal(s.app.stores.isOpen(s.scope), true, 'the environment was not evicted mid delete');
  held.open();
  const done = await pending;
  assert.equal(done.status, 200, JSON.stringify(done.body)); assert.equal(done.body.deleted, true);
  assert.deepEqual(done.body.accounts.map(item => [item.accountRef, item.remoteRevoked]), [[ref, true]]);
  assert.equal(s.repo().get('connections', ref), null, 'the account was erased');
  assert.equal(s.repo().list('endUsers').some(user => user.subjectId === 'u1'), false, 'only the tombstone is left');
});

test('ISO-2, secrets-2: cancelling a link whose account waits on the confirm screen keeps the environment open while GitHub revokes it', async t => {
  const s = await setup(t, {environments: 17});
  const signed = await s.signIn(), pendingRef = s.repo().get('connectSessions', signed.id).pendingAccountRef;
  assert.ok(pendingRef, 'an account waits on the confirm screen');
  const held = s.gate();
  s.sim.before = req => req.url.startsWith(REVOKE) ? held.shut : null;
  const pending = s.call('POST', `/v1/connect-sessions/${signed.id}/cancel`);
  await s.until(() => s.sim.calls.some(line => line.includes(REVOKE)), 'the revoke');
  await s.crowd();
  assert.equal(s.app.stores.isOpen(s.scope), true, 'the environment was not evicted mid release');
  held.open();
  const cancelled = await pending;
  assert.equal(cancelled.status, 200, JSON.stringify(cancelled.body)); assert.equal(cancelled.body.state, 'cancelled');
  assert.equal(s.repo().get('connections', pendingRef), null, 'the waiting account was erased');
  assert.equal(s.app.stores.open(s.scope).vault.get(pendingRef), null, 'and its tokens');
});

test('ISO-2, secrets-2: turning the account down on the confirm screen keeps the environment open while GitHub revokes it', async t => {
  const s = await setup(t, {environments: 17});
  const signed = await s.signIn(), pendingRef = s.repo().get('connectSessions', signed.id).pendingAccountRef;
  assert.ok(pendingRef, 'an account waits on the confirm screen');
  const held = s.gate();
  s.sim.before = req => req.url.startsWith(REVOKE) ? held.shut : null;
  const pending = signed.reject();
  await s.until(() => s.sim.calls.some(line => line.includes(REVOKE)), 'the revoke');
  await s.crowd();
  assert.equal(s.app.stores.isOpen(s.scope), true, 'the environment was not evicted mid drop');
  held.open();
  assert.equal((await pending).state, 'opened');
  assert.equal(s.repo().get('connections', pendingRef), null, 'the turned-down account was erased');
  assert.equal(s.app.stores.open(s.scope).vault.get(pendingRef), null, 'and its tokens');
});

test('ISO-3: while every open environment has work in flight another one still opens, up to four times maxOpen', t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review-b1-stores-'));
  const stores = new EnvironmentStores({root, maxOpen: 2});
  t.after(() => { try { stores.closeAll(); } catch {} rmSync(root, {recursive: true, force: true}); });
  const scopes = Array.from({length: 9}, (_, i) => ({organizationId: `org${i}`, projectId: 'agent', environmentId: 'development'}));
  for (const scope of scopes.slice(0, 2)) { stores.open(scope); stores.pin(scope); }
  assert.ok(stores.open(scopes[2]), 'a third environment opens while both slots are busy');
  stores.pin(scopes[2]);
  for (const scope of scopes.slice(3, 8)) { stores.open(scope); stores.pin(scope); }
  assert.equal(scopes.slice(0, 8).every(scope => stores.isOpen(scope)), true, 'nothing busy was closed');
  assert.throws(() => stores.open(scopes[8]), {code: 'too_many_open'}, 'a hard ceiling still holds');
  for (const scope of scopes.slice(0, 8)) stores.unpin(scope);
  stores.open(scopes[8]);
  assert.equal(scopes.filter(scope => stores.isOpen(scope)).length, 2, 'back to maxOpen once the work settled');
  assert.equal(stores.isOpen(scopes[8]), true);
});

test('ISO-3: sixteen environments with calls in flight do not lock a seventeenth out', async t => {
  const s = await setup(t, {environments: 17});
  const held = s.gate();
  s.sim.before = req => req.url.startsWith(GMAIL) ? held.shut : null;
  for (const env of s.envs.slice(1)) {
    await s.gmail(env);
    const read = (await s.call('GET', '/v1/capabilities?appId=gmail', undefined, env.key)).body.capabilities.find(item => item.id.includes('messages-get'));
    const run = await s.call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}}, env.key, {'Idempotency-Key': randomUUID()});
    assert.equal(run.status, 202, JSON.stringify(run.body));
  }
  await s.until(() => s.sim.calls.filter(line => line.includes(GMAIL)).length === 16, 'sixteen provider calls');
  assert.equal(s.app.stores.isOpen(s.scope), false, 'the seventeenth environment was closed meanwhile');
  const users = await s.call('GET', '/v1/users');
  assert.equal(users.status, 200, JSON.stringify(users.body));
  assert.equal((await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u2'})).status, 201);
  held.open();
});

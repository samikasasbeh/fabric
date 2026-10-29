import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {Vault} from '../lib/vault.mjs';
import {TenantVault} from '../lib/tenant/environments.mjs';
import {applyBrand} from '../public/hosted-base.js';

// Exit check 9 (docs/F03-DEVELOPER-LAYER.md section 9): guards that were in the code but that no test pinned, found by
// running the seeded-fault registry (test/faults/registry.mjs). Each test below fails when its guard is removed.
const GMAIL = 'https://gmail.googleapis.com';
const TYPED = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send'],
  // An operation in no reviewed row: a proxied request it routes lands in "Other changes", where only clamp c4 sees it.
  ['gmail.users.experimental.poke', 'post', '/gmail/v1/users/{userId}/experimental/poke']];
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
    const entry = {id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null}, at = operations.findIndex(op => op.id === id);
    if (at >= 0) operations[at] = entry; else operations.push(entry);
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  const [repo] = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {'/repos/{owner}/{repo}': {get: {operationId: 'repos/get', parameters: ['owner', 'repo'].map(name => ({name, in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'OK'}}}}}}}).capabilities;
  store.put('capabilities', {...repo, status: 'active'});
  store.put('applicationMaps', {id: 'github', appId: 'github', classifierVersion: SENSITIVITY_VERSION, operations: [{id: 'repos/get', capabilityId: repo.id, method: 'GET', path: '/repos/{owner}/{repo}', sensitive: null}]});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-guards-'));
  seed(root);
  const sim = {calls: [], held: null, issued: 0};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://github.com/login/oauth/access_token') return {status: 200, headers: {}, data: {access_token: `gho_${++sim.issued}`, token_type: 'bearer', scope: 'read:user,repo'}};
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: {id: 77, login: 'octo', name: 'Octo'}};
    if (req.url.startsWith(`${GMAIL}/`)) { if (sim.held) await sim.held; return {status: 200, headers: {'content-type': 'application/json'}, data: {id: 'm-1'}}; }
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { sim.release?.(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'});
  const environment = name => {
    const project = app.registry.createProject({organizationId: org.id, name}), dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
    const key = app.keys.mint({environmentId: dev.id, preset: 'full'}), scope = app.registry.scopeOf(dev);
    const call = async (method, route, body, headers = {}) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key.token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})}); return {status: response.status, body: response.status === 204 ? null : await response.json()}; };
    const repo = () => app.stores.open(scope).repository;
    const gmail = async externalUserId => {
      await call('POST', '/v1/connect-sessions', {externalUserId});
      const user = repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), id = randomUUID(), now = app.registry.now();
      repo().put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: `g-${externalUserId}`, displayName: `${externalUserId}@example.com`}, allowedOrigins: [GMAIL],
        scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.compose', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: now, updatedAt: now, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: externalUserId, userRecordId: user.id}));
      app.stores.open(scope).vault.set(id, {accessToken: `ya29.${id}`, refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000});
      return {id, owner: {subjectId: externalUserId, userRecordId: user.id}};
    };
    return {dev, key, scope, call, repo, gmail};
  };
  const caps = async env => (await env.call('GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  return {app, sim, environment, caps};
}
const run = (env, cap, externalUserId = 'u1', args = {userId: 'me', id: 'm-1'}) => env.call('POST', '/v1/executions', {externalUserId, capabilityId: cap.id, definitionHash: cap.definitionHash, args}, {'Idempotency-Key': randomUUID()});

test('the vault binds each record to its environment: a record copied into another environment does not open, even under one master key', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-vault-aad-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const shared = new Vault(dir), a = new TenantVault(shared, 'scope-a'), b = new TenantVault(shared, 'scope-b');
  a.set('account-1', {accessToken: 'secret-of-a'});
  copyFileSync(shared.path('scope-a:account-1'), shared.path('scope-b:account-1'));
  assert.throws(() => b.get('account-1'), /cannot be decrypted/);
  assert.deepEqual(a.get('account-1'), {accessToken: 'secret-of-a'});
});

test('scopes come from the key alone: a header naming scopes grants nothing', async t => {
  const {app, environment} = await setup(t);
  const env = environment('Agent'), narrow = app.keys.mint({environmentId: env.dev.id, scopes: ['connect:write']});
  for (const header of ['x-fabric-scopes', 'x-fabric-scope', 'scope']) {
    const response = await fetch(`${app.origin}/v1/users`, {headers: {Authorization: `Bearer ${narrow.token}`, [header]: 'users:read users:write'}});
    assert.equal(response.status, 403, header); assert.equal((await response.json()).error.code, 'forbidden_scope');
  }
});

test('ownership before state: another person\'s call is not_found to cancel or decide, settled or expired', async t => {
  const {app, environment, caps} = await setup(t);
  const env = environment('Agent');
  await env.gmail('u1'); const two = await env.gmail('u2');
  const send = (await caps(env)).find(item => item.id.includes('messages-send'));
  const runtime = app.runtimes.bundle(env.scope).runtime, stranger = {kind: 'product_user', ...two.owner};
  const waiting = async () => (await run(env, send, 'u1', {userId: 'me', body: {raw: 'eA'}})).body.callRef;
  const settled = await waiting(), expired = await waiting();
  env.repo().put('jobs', {...env.repo().get('jobs', settled), status: 'succeeded'});
  env.repo().put('jobs', {...env.repo().get('jobs', expired), approvalExpiresAt: new Date(Date.parse(app.registry.now()) - 1000).toISOString()});
  for (const callRef of [settled, expired]) {
    const job = env.repo().get('jobs', callRef);
    assert.throws(() => runtime.cancel(callRef, stranger), {code: 'not_found'}, `cancel ${job.status}`);
    assert.throws(() => runtime.decideWaiting(callRef, job.approvalDigest, stranger, {decision: 'approved', decidedIn: 'developer_app', at: app.registry.now()}), {code: 'not_found'}, `decide ${job.status}`);
  }
});

test('N1: the minute sweep opens only environments with an account waiting on a confirm screen', async t => {
  const {app, environment} = await setup(t);
  const a = environment('A'), b = environment('B');
  const inA = (await a.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body;
  await b.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'});
  app.registry.put('sessionRoutes', {...app.registry.get('sessionRoutes', inA.id), pendingSince: app.registry.now()});
  app.stores.closeAll();
  const opened = [], open = app.stores.open.bind(app.stores);
  app.stores.open = scope => { opened.push(scope.environmentId); return open(scope); };
  try { await app.sessions.sweep(); } finally { app.stores.open = open; }
  assert.ok(opened.includes(a.dev.id)); assert.equal(opened.includes(b.dev.id), false, 'the environment with nothing due stayed closed');
});

test('each environment has its own sign-in adapters: a sign-in in one environment never lands in another', async t => {
  const {app, environment} = await setup(t);
  const a = environment('A'), b = environment('B'), links = {};
  for (const env of [a, b]) links[env.dev.id] = (await env.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body;
  for (const env of [a, b]) app.runtimes.bundle(env.scope);
  const signIn = async env => {
    const link = links[env.dev.id], binding = `browser-${link.id}-binding`;
    app.sessions.claim(link.id, new URL(link.connectUrl).hash.slice(3), binding);
    const started = app.sessions.start(link.id, binding), state = new URL(started.authorizationUrl).searchParams.get('state');
    const back = await app.sessions.callback('github', {state, code: 'c', flowId: started.flowId});
    return app.sessions.confirm(link.id, binding, back.finish).result.accountRef;
  };
  const ref = await signIn(a);
  assert.ok(a.repo().get('connections', ref), 'the account is in its own environment');
  assert.equal(b.repo().get('connections', ref), null); assert.equal(b.repo().list('connections').length, 0, 'nothing reached the other environment');
});

test('a ceiling only lowers: Ask on a row the person set to Never keeps it Never', async t => {
  const {environment, caps} = await setup(t);
  const env = environment('Agent'), one = await env.gmail('u1');
  const view = (await env.call('GET', `/v1/users/u1/apps/gmail?account=${one.id}`)).body;
  const row = view.sections.flatMap(section => section.rows).find(item => item.groupId === 'gmail.messages.read');
  assert.equal((await env.call('POST', `/v1/users/u1/accounts/${one.id}/permissions`, {groupId: row.groupId, mode: 'deny', etag: row.etag})).status, 200);
  assert.equal((await env.call('PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.messages.read': 'ask'}})).status, 200);
  const read = (await caps(env)).find(item => item.id.includes('messages-get'));
  const runnable = (await env.call('GET', '/v1/users/u1/capabilities?appId=gmail')).body.capabilities.map(item => item.id);
  assert.equal(runnable.includes(read.id), false, 'still Never');
  assert.equal((await run(env, read)).body.error.code, 'permission_denied');
});

test('a held call replayed with its Idempotency-Key still carries no link', async t => {
  const {app, environment} = await setup(t);
  const env = environment('Agent');
  await env.call('POST', '/v1/connect-sessions', {externalUserId: 'u9'});
  const repoCap = (await env.call('GET', '/v1/capabilities?appId=github')).body.capabilities[0], idem = randomUUID();
  const hold = () => env.call('POST', '/v1/executions', {externalUserId: 'u9', capabilityId: repoCap.id, definitionHash: repoCap.definitionHash, args: {owner: 'o', repo: 'r'}, onMissingAccess: 'hold'}, {'Idempotency-Key': idem});
  const first = await hold(), replay = await hold();
  assert.equal(first.status, 202); assert.equal(replay.status, 202);
  assert.equal(replay.body.handoff.connectSessionId, first.body.handoff.connectSessionId);
  for (const body of [first.body, replay.body]) { assert.equal('connectUrl' in body, false); assert.equal(JSON.stringify(body).includes(app.origin), false, 'no link to Fabric'); }
});

test('c4 holds on the /v1 proxy too: a typed operation set to Never caps the request it routes, even in an Other row', async t => {
  const {app, sim, environment, caps} = await setup(t);
  const env = environment('Agent'), one = await env.gmail('u1');
  const poke = (await caps(env)).find(item => item.id.includes('experimental-poke'));
  app.runtimes.bundle(env.scope).permissions.set({connectionId: one.id, capabilityId: poke.id, mode: 'deny'});
  const before = sim.calls.length;
  const answer = await env.call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'gmail', accountRef: one.id, request: {method: 'POST', path: '/gmail/v1/users/me/experimental/poke', body: {raw: 'x'}}}, {'Idempotency-Key': randomUUID()});
  assert.equal(answer.status, 403); assert.equal(answer.body.error.code, 'permission_denied');
  assert.equal(sim.calls.length, before, 'nothing was sent');
});

test('a job in flight keeps its environment pinned: it cannot be closed under it', async t => {
  const {app, sim, environment, caps} = await setup(t);
  const env = environment('Agent');
  await env.gmail('u1');
  const read = (await caps(env)).find(item => item.id.includes('messages-get'));
  sim.held = new Promise(resolve => { sim.release = resolve; });
  const started = await env.call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}, waitMs: 0}, {'Idempotency-Key': randomUUID()});
  assert.equal(started.status, 202);
  assert.throws(() => app.stores.close(env.scope), {code: 'pinned'});
  sim.release(); sim.held = null;
  await app.runtimes.drain();
  assert.equal(env.repo().get('jobs', started.body.callRef).status, 'succeeded');
});

test('the shared base applies the developer\'s colours token by token through the CSS object model, never as style text', () => {
  const set = [], removed = [];
  const style = {setProperty: (name, value) => set.push([name, value]), removeProperty: name => removed.push(name)};
  Object.defineProperty(style, 'cssText', {get: () => '', set: () => assert.fail('cssText must never be written')});
  const media = {matches: false, addEventListener: () => {}};
  applyBrand({light: {'--accent': '#5b21b6', '--on-accent': 'red; background: url(x)', '--evil': '#000000', '--ink': '#123'}}, {root: {style}, media});
  assert.deepEqual(set, [['--accent', '#5b21b6']]);
  assert.ok(removed.includes('--accent') && removed.includes('--ink'), 'Fabric\'s own values come back first');
});

test('the page API answers only its listed actions: anything else under a link is the plain not_found', async t => {
  const {app, environment} = await setup(t);
  const env = environment('Agent');
  const link = (await env.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body;
  for (const action of ['export', 'credentials', 'token', 'debug', 'admin', 'raw', 'apps', 'approvals', 'accounts/x', 'view/extra']) {
    for (const method of ['GET', 'POST']) {
      const response = await fetch(`${app.origin}/connect/${link.id}/v1/${action}`, {method, headers: {'Sec-Fetch-Site': 'same-origin', Origin: app.origin, 'Content-Type': 'application/json'}, ...(method === 'POST' ? {body: '{}'} : {})});
      assert.equal(response.status, 404, `${method} ${action}`); assert.equal((await response.json()).error.code, 'not_found');
    }
  }
});

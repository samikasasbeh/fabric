import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';

// F03.7 slice 1 (docs/F03.7-BUILD-MAP.md): one runtime per developer environment. Jobs run detached while their
// environment is pinned; write locks and token refreshes are shared; ceilings are read live; a stored job without its
// owner fails closed; outcomes follow the governed proxy's table; a user deleted mid-run stays deleted.
// F10.15 listed churn: the write is "Manage labels" labels.create, a write at Allow that stays in the account; Gmail's typed drafts.create is
// unsupported (its plain form carries no message).
const OPS = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.labels.create', 'post', '/gmail/v1/users/{userId}/labels']];
function seed(root) {
  const paths = {};
  for (const [id, method, route] of OPS) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {name: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities;
  const store = new PlatformStore({root}), ids = {}, operations = [];
  for (const [id, method, route] of OPS) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `https://gmail.googleapis.com${route}`);
    store.put('capabilities', {...capability, status: 'active'}); ids[id] = capability.id;
    operations.push({id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null});
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
  return ids;
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-bundle-'));
  const ids = seed(root);
  const sim = {calls: [], refreshes: 0, held: null, status: 200, unsent: false};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://oauth2.googleapis.com/token') { sim.refreshes++; await new Promise(resolve => setTimeout(resolve, 30)); return {status: 200, headers: {}, data: {access_token: `ya29.fresh${sim.refreshes}`, token_type: 'Bearer', expires_in: 3600, scope: 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose'}}; }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') return {status: 200, headers: {}, data: {sub: 'g-1', email: 'one@example.com', name: 'One'}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) return {status: 200, headers: {}, data: {emailAddress: 'one@example.com'}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/')) {
      if (sim.unsent) throw Object.assign(new Error('Request origin is outside the connection grant.'), {sent: false});
      if (sim.held) await sim.held;
      return {status: sim.status, headers: {}, data: {id: 'm-1'}};
    }
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  await fetch(`${app.origin}/v1/connect-sessions`, {method: 'POST', headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify({externalUserId: 'u1'})});
  const repo = () => app.stores.open(scope).repository;
  const user = repo().list('endUsers').find(item => item.subjectId === 'u1'), owner = {subjectId: 'u1', userRecordId: user.id}, principal = {kind: 'product_user', ...owner};
  // A ready Gmail account for u1 whose token is still valid for an hour unless a test says otherwise.
  const account = randomUUID(), now = new Date(Date.parse(app.registry.now())).toISOString();
  repo().put('connections', stampOwner({id: account, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: 'g-1', displayName: 'one@example.com'}, allowedOrigins: ['https://gmail.googleapis.com'],
    scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.compose', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: now, updatedAt: now, authRevision: randomUUID(), refreshAvailable: true}, owner));
  app.stores.open(scope).vault.set(account, {accessToken: 'ya29.old', refreshToken: '1//r', expiresAt: Date.parse(app.registry.now()) + 3600_000, scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.compose', 'https://www.googleapis.com/auth/gmail.modify']});
  const caps = Object.fromEntries(repo().list('capabilities').map(cap => [cap.request.method, cap.id]));
  const source = {kind: 'service', serviceClientId: 'svc_x', keyId: 'key_x'};
  const job = (method, args = method === 'GET' ? {userId: 'me', id: 'm-1'} : {userId: 'me', body: {name: 'x'}}) => app.runtimes.bundle(scope).runtime.prepareJob({connectionId: account, capabilityId: caps[method], args, source}, principal);
  const hold = () => { let release; sim.held = new Promise(resolve => { release = resolve; }); return () => { sim.held = null; release(); }; };
  return {app, root, sim, scope, repo, account, owner, principal, job, hold, user, key, ids};
}

test('one bundle per environment: the same runtime, connections and permission engine on every call; the adapters are the bundle\'s', async t => {
  const {app, scope} = await setup(t);
  const one = app.runtimes.bundle(scope), two = app.runtimes.bundle(scope);
  assert.equal(one, two); assert.equal(one.runtime, two.runtime);
  assert.equal(app.sessions.adapterFor(scope, 'google').adapter, one.adapters.get('google'), 'sign-in and execution share one adapter');
  assert.throws(() => app.sessions.adapterFor(scope, 'github'), {code: 'setup_required'}, 'no operator settings, no adapter');
});

test('a stored job whose owner stamp is missing fails closed at dispatch; nothing reaches the provider', async t => {
  const {app, sim, scope, repo, job} = await setup(t);
  const queued = await job('GET');
  const {ownership, userRecordId, ...stripped} = repo().get('jobs', queued.id);
  repo().put('jobs', stripped);
  const settled = await app.runtimes.dispatch(scope, queued.id);
  assert.equal(settled.status, 'failed'); assert.equal(settled.errorCode, 'not_found');
  assert.equal(sim.calls.filter(line => line.includes('/messages/')).length, 0);
});

test('two writes on one account at once: one is sent, the other is refused before sending (one write lock per environment)', async t => {
  const {app, sim, scope, job, hold} = await setup(t);
  const first = await job('POST'), second = await job('POST');
  assert.equal(first.status, 'queued', 'Manage labels is a write row whose default is Allow');
  const release = hold();
  const running = app.runtimes.dispatch(scope, first.id);
  await new Promise(resolve => setTimeout(resolve, 20));
  const refused = await app.runtimes.dispatch(scope, second.id);
  release();
  const done = await running;
  assert.equal(refused.status, 'failed'); assert.match(refused.error, /Another write is in progress/);
  assert.equal(done.status, 'uncertain', 'a sent write without a readback is never reported as done');
  assert.equal(sim.calls.filter(line => line.startsWith('POST https://gmail.googleapis.com')).length, 1);
});

test('two calls with a token about to expire make exactly one refresh (the environment shares one adapter)', async t => {
  const {app, sim, scope, account, job} = await setup(t);
  const vault = app.stores.open(scope).vault;
  vault.set(account, {...vault.get(account), expiresAt: Date.parse(app.registry.now()) + 10_000});
  const a = await job('GET'), b = await job('GET');
  const [one, two] = await Promise.all([app.runtimes.dispatch(scope, a.id), app.runtimes.dispatch(scope, b.id)]);
  assert.equal(one.status, 'succeeded'); assert.equal(two.status, 'succeeded');
  assert.equal(sim.refreshes, 1);
});

test('a developer ceiling set after the bundle was built applies to the very next decision', async t => {
  const {app, scope, job} = await setup(t);
  assert.equal((await job('GET')).status, 'queued');
  const environment = app.registry.get('environments', scope.environmentId);
  app.registry.put('environments', {...environment, apps: {...(environment.apps || {}), gmail: {ceilings: {'gmail.messages.read': 'ask'}}}});
  assert.equal((await job('GET')).status, 'awaiting_approval');
  app.registry.put('environments', {...environment, apps: {...(environment.apps || {}), gmail: {ceilings: {'gmail.messages.read': 'deny'}}}});
  await assert.rejects(job('GET'), {code: 'permission_denied'});
});

test('outcomes follow the governed proxy\'s table: unsent fails, a definite refusal fails, a 503 on a write is uncertain', async t => {
  const {app, sim, scope, job} = await setup(t);
  sim.unsent = true;
  const unsent = await app.runtimes.dispatch(scope, (await job('POST')).id);
  assert.deepEqual([unsent.status, unsent.errorCode], ['failed', 'fabric_failed'], 'a write that never left is not uncertain');
  sim.unsent = false; sim.status = 404;
  const refused = await app.runtimes.dispatch(scope, (await job('POST')).id);
  assert.deepEqual([refused.status, refused.errorCode, refused.providerStatus], ['failed', 'provider_failed', 404]);
  sim.status = 503;
  const unknown = await app.runtimes.dispatch(scope, (await job('POST')).id);
  assert.deepEqual([unknown.status, unknown.errorCode, unknown.providerStatus], ['uncertain', 'outcome_uncertain', 503]);
  const read = await app.runtimes.dispatch(scope, (await job('GET')).id);
  assert.deepEqual([read.status, read.errorCode], ['failed', 'provider_failed']);
});

test('a row switched to Never while a read is in flight: the response is withheld', async t => {
  const {app, scope, account, job, hold} = await setup(t);
  const queued = await job('GET'), release = hold();
  const running = app.runtimes.dispatch(scope, queued.id);
  await new Promise(resolve => setTimeout(resolve, 20));
  const bundle = app.runtimes.bundle(scope), cap = bundle.env.repository.get('capabilities', queued.capabilityId);
  bundle.permissions.set({connectionId: account, capabilityId: cap.id, mode: 'deny'});
  release();
  const settled = await running;
  assert.equal(settled.status, 'failed'); assert.equal(settled.errorCode, 'authority_changed'); assert.equal(settled.result, null);
});

test('an end user deleted while their job runs stays deleted: the finished job is not written back', async t => {
  const {app, scope, repo, key, job, hold} = await setup(t);
  const queued = await job('GET'), release = hold();
  const running = app.runtimes.dispatch(scope, queued.id);
  await new Promise(resolve => setTimeout(resolve, 20));
  const deleting = fetch(`${app.origin}/v1/users/u1`, {method: 'DELETE', headers: {Authorization: `Bearer ${key}`}});
  await new Promise(resolve => setTimeout(resolve, 20));
  release();
  await running; await deleting;
  assert.equal(repo().get('jobs', queued.id), null);
  assert.equal(repo().list('activity').some(event => event.type === 'job.completed' && event.jobId === queued.id), false);
});

test('a second request in the environment never flips a running job to uncertain; shutdown waits for it to settle', async t => {
  const {app, scope, repo, job, hold} = await setup(t);
  const queued = await job('GET'), release = hold();
  const running = app.runtimes.dispatch(scope, queued.id);
  await new Promise(resolve => setTimeout(resolve, 20));
  app.runtimes.bundle(scope);
  assert.equal(repo().get('jobs', queued.id).status, 'running');
  let closed = false;
  const closing = app.close().then(() => { closed = true; });
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(closed, false, 'close waits for the job');
  release();
  await closing; await running;
  assert.equal(closed, true);
});

test('activity rows name the end user\'s usr_ id and the key behind the call (N3, N13)', async t => {
  const {app, scope, repo, user, job} = await setup(t);
  const queued = await job('GET');
  await app.runtimes.dispatch(scope, queued.id);
  const rows = repo().list('activity').filter(event => event.jobId === queued.id);
  assert.deepEqual(rows.map(event => event.type).sort(), ['job.completed', 'job.created']);
  for (const event of rows) assert.deepEqual([event.userRecordId, event.serviceClientId, event.keyId], [user.id, 'svc_x', 'key_x']);
});

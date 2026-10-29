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
import {MAX_WAITERS} from '../lib/tenant/executions.mjs';

// F03.7b: a developer's server runs reviewed operations on one end user's account over /v1, with Idempotency-Key,
// bounded waiting and append-only usage records (docs/F03-DEVELOPER-LAYER.md section 5.10, docs/F03.7-BUILD-MAP.md).
// F10.15 listed churn: the plain write is "Manage labels" labels.create; Gmail's typed drafts.create is unsupported (it carries no message).
const OPS = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.labels.create', 'post', '/gmail/v1/users/{userId}/labels'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send']];
function seed(root) {
  const paths = {};
  for (const [id, method, route] of OPS) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}, name: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities;
  const store = new PlatformStore({root}), operations = [];
  for (const [id, method, route] of OPS) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `https://gmail.googleapis.com${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations.push({id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null});
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-exec-'));
  seed(root);
  const sim = {calls: [], held: null};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/')) { if (sim.held) await sim.held; return {status: 200, headers: {}, data: {id: 'm-1', snippet: 'hello'}}; }
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  // A held provider call is always released at the end, so a failed assertion never leaves requests open and app.close() waiting forever.
  t.after(async () => { sim.held = null; sim.release?.(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const environment = name => {
    const org = app.registry.createOrganization({name}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
    const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
    return {dev, scope, key: app.keys.mint({environmentId: dev.id, preset: 'standard'}).token, other: app.keys.mint({environmentId: dev.id, preset: 'standard'}).token};
  };
  const acme = environment('Acme');
  const call = async (key, method, route, body, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, headers: response.headers, body: await response.json()};
  };
  const repo = (scope = acme.scope) => app.stores.open(scope).repository;
  const account = async (env, externalUserId, identity = 'g-1') => {
    await call(env.key, 'POST', '/v1/connect-sessions', {externalUserId});
    const user = repo(env.scope).list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), id = randomUUID(), now = app.registry.now();
    repo(env.scope).put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: identity, displayName: `${identity}@example.com`}, allowedOrigins: ['https://gmail.googleapis.com'],
      scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.compose', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: now, updatedAt: now, authRevision: randomUUID()}, {subjectId: externalUserId, userRecordId: user.id}));
    app.stores.open(env.scope).vault.set(id, {accessToken: 'ya29.x', refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000});
    return id;
  };
  const u1 = await account(acme, 'u1'), u2 = await account(acme, 'u2', 'g-2');
  const caps = (await call(acme.key, 'GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  const op = name => caps.find(item => item.name === name || item.id.includes(name.replace(/\./g, '-')));
  const read = op('gmail.users.messages.get'), label = op('gmail.users.labels.create'), send = op('gmail.users.messages.send');
  const run = (key, body, idem = randomUUID(), extra = {}) => call(key, 'POST', '/v1/executions', body, {'Idempotency-Key': idem, ...extra});
  const readBody = (extra = {}) => ({externalUserId: 'u1', capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}, ...extra});
  const jobs = (scope = acme.scope) => repo(scope).list('jobs');
  const usage = (scope = acme.scope) => repo(scope).list('usageEvents');
  const hold = () => { let release; sim.held = new Promise(resolve => { release = resolve; }); sim.release = release; return () => { sim.held = null; release(); }; };
  // Waits until the given number of read-backs are registered as waiting, instead of guessing with a fixed sleep (flaky under load).
  // Waits until the key is at its waiting limit (a probe read-back is turned away with 429), instead of guessing with a fixed sleep,
  // which was flaky under the full suite's load.
  const waitingReach = async (key, callRef) => { for (let tries = 0; tries < 500; tries++) { if ((await call(key, 'GET', `/v1/executions/${callRef}?waitMs=1`)).status === 429) return; await new Promise(resolve => setTimeout(resolve, 10)); } assert.fail('the waiting read-backs never registered'); };
  return {app, sim, acme, environment, call, repo, account, u1, u2, read, label, send, run, readBody, jobs, usage, hold, waitingReach};
}

test('a read runs on the end user\'s own account and returns within waitMs: observed evidence, one usage record', async t => {
  const {acme, run, readBody, usage, u1} = await setup(t);
  const done = await run(acme.key, readBody({waitMs: 5000}));
  assert.equal(done.status, 200);
  assert.deepEqual({status: done.body.status, evidence: done.body.evidence, account: done.body.accountRef, result: done.body.result}, {status: 'succeeded', evidence: 'observed', account: u1, result: {id: 'm-1', snippet: 'hello'}});
  assert.deepEqual(Object.keys(done.body).sort(), ['accountRef', 'appId', 'callRef', 'capabilityId', 'createdAt', 'evidence', 'result', 'status', 'updatedAt']);
  const rows = usage();
  assert.equal(rows.length, 1); assert.equal(rows[0].id, `exec.${done.body.callRef}`); assert.equal(rows[0].kind, 'execution');
  assert.equal(JSON.stringify(rows).includes('u1'), false, 'usage holds the usr_ id, never the external id');
});

test('Idempotency-Key: the same request replays the same execution; a different body conflicts; keys never cross clients or environments', async t => {
  const {acme, environment, account, run, readBody, jobs, usage, sim, call} = await setup(t);
  const key = 'order-42';
  const first = await run(acme.key, readBody({waitMs: 5000}), key);
  const again = await run(acme.key, readBody({waitMs: 5000}), key);
  assert.equal(again.body.callRef, first.body.callRef);
  assert.equal(jobs().length, 1); assert.equal(usage().length, 1, 'a replay is never counted'); assert.equal(sim.calls.length, 1, 'and never sent again');
  const conflict = await run(acme.key, readBody({args: {userId: 'me', id: 'm-2'}}), key);
  assert.equal(conflict.status, 409); assert.equal(conflict.body.error.code, 'idempotency_conflict');
  // Another service client in the same environment, and another environment, each have their own key space.
  const otherClient = await run(acme.other, readBody({waitMs: 5000}), key);
  assert.notEqual(otherClient.body.callRef, first.body.callRef);
  const beta = environment('Beta'); await account(beta, 'u1');
  const betaCaps = (await call(beta.key, 'GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  assert.ok(betaCaps.length);
  const elsewhere = await run(beta.key, readBody(), key);
  assert.equal(elsewhere.status, 202); assert.notEqual(elsewhere.body.callRef, first.body.callRef);
  assert.equal((await run(acme.key, readBody(), '')).body.error.code, 'invalid_request', 'the header is required');
  assert.equal((await call(acme.key, 'POST', '/v1/executions', readBody())).body.error.code, 'invalid_request');
});

test('another end user\'s account, an unknown user and an unknown operation are not_found, with nothing created, sent or counted', async t => {
  const {acme, run, readBody, jobs, usage, sim, u2} = await setup(t);
  for (const body of [readBody({accountRef: u2}), readBody({externalUserId: 'nobody'}), readBody({capabilityId: 'gmail.nothing.000000000000000000000000'})]) {
    const refused = await run(acme.key, body);
    assert.equal(refused.status, 404, JSON.stringify(body)); assert.equal(refused.body.error.code, 'not_found');
  }
  assert.equal(jobs().length, 0); assert.equal(usage().length, 0); assert.equal(sim.calls.length, 0);
});

test('a stale definitionHash is capability_changed; Never is permission_denied with no job; Ask waits for approval with no link', async t => {
  const {app, acme, run, readBody, send, jobs, usage, u1} = await setup(t);
  const stale = await run(acme.key, readBody({definitionHash: 'f'.repeat(64)}), 'stale-1');
  assert.equal(stale.status, 409); assert.equal(stale.body.error.code, 'capability_changed');
  assert.equal((await run(acme.key, readBody({definitionHash: 'f'.repeat(64)}), 'stale-1')).body.error.code, 'capability_changed', 'a refusal replays as the same answer');
  const bundle = app.runtimes.bundle(acme.scope);
  bundle.permissions.set({connectionId: u1, capabilityId: readBody().capabilityId, mode: 'deny'});
  const denied = await run(acme.key, readBody());
  assert.equal(denied.status, 403); assert.equal(denied.body.error.code, 'permission_denied');
  assert.equal(jobs().length, 0); assert.equal(usage().length, 0);
  const asked = await run(acme.key, {externalUserId: 'u1', capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'x'}}, waitMs: 200});
  assert.equal(asked.status, 202); assert.equal(asked.body.status, 'awaiting_approval');
  assert.deepEqual(Object.keys(asked.body.approval).sort(), ['callRef', 'expiresAt']);
  assert.equal(/\/approve\/|\/continue\/|http/.test(JSON.stringify(asked.body)), false, 'no link for anyone to follow');
});

test('a write is never reported as done without proof: uncertain, no evidence, the error says why and whose it is', async t => {
  const {acme, run, label} = await setup(t);
  const sent = await run(acme.key, {externalUserId: 'u1', capabilityId: label.id, definitionHash: label.definitionHash, args: {userId: 'me', body: {name: 'x'}}, waitMs: 5000});
  assert.equal(sent.body.status, 'uncertain'); assert.equal(sent.body.evidence, 'none');
  assert.deepEqual({code: sent.body.error.code, attribution: sent.body.error.attribution, retryable: sent.body.error.retryable}, {code: 'outcome_uncertain', attribution: 'provider', retryable: false});
});

test('waitMs is bounded; a call can be read back and waited on later; the 17th waiting request is told to come back', async t => {
  const {acme, run, readBody, call, hold, waitingReach} = await setup(t);
  assert.equal((await run(acme.key, readBody({waitMs: 25_001}))).status, 400);
  const release = hold();
  const started = await run(acme.key, readBody({waitMs: 0}));
  assert.equal(started.status, 202); assert.ok(['queued', 'running'].includes(started.body.status));
  const waiters = Array.from({length: MAX_WAITERS}, () => call(acme.key, 'GET', `/v1/executions/${started.body.callRef}?waitMs=5000`));
  await waitingReach(acme.key, started.body.callRef);
  const turnedAway = await call(acme.key, 'GET', `/v1/executions/${started.body.callRef}?waitMs=5000`);
  assert.equal(turnedAway.status, 429); assert.equal(turnedAway.body.error.code, 'rate_limited'); assert.equal(turnedAway.headers.get('retry-after'), '1');
  release();
  const answers = await Promise.all(waiters);
  assert.ok(answers.every(answer => answer.status === 200 && answer.body.status === 'succeeded'));
});

test('without an accountRef: the only account, then the developer\'s default; several and no default is a question, never a guess', async t => {
  const {acme, account, run, readBody, call, u1} = await setup(t);
  assert.equal((await run(acme.key, readBody({waitMs: 5000}))).body.accountRef, u1);
  const second = await account(acme, 'u1', 'g-3');
  const choose = await run(acme.key, readBody());
  assert.equal(choose.status, 409); assert.equal(choose.body.error.code, 'account_choice_required'); assert.deepEqual(choose.body.error.details.accountRefs.sort(), [u1, second].sort());
  await call(acme.key, 'PUT', '/v1/users/u1/apps/gmail/default-account', {accountRef: second});
  assert.equal((await run(acme.key, readBody({waitMs: 5000}))).body.accountRef, second);
  const none = await run(acme.key, readBody({externalUserId: 'u3'}));
  assert.equal(none.status, 404, 'an unknown end user');
  await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'u3'});
  const noAccount = await run(acme.key, readBody({externalUserId: 'u3'}));
  assert.equal(noAccount.status, 409); assert.equal(noAccount.body.error.code, 'connection_required'); assert.equal(noAccount.body.error.details.appId, 'gmail');
  assert.equal((await run(acme.key, readBody({source: {kind: 'user'}}))).status, 400, 'the body never names the source');
  const unsafe = await call(acme.key, 'POST', '/v1/executions', JSON.parse(JSON.stringify(readBody()).replace('"args":{', '"args":{"__proto__":{"x":1},')), {'Idempotency-Key': 'unsafe-1'});
  assert.equal(unsafe.status, 400, 'an unsafe name is a clean refusal, never a 500'); assert.equal(unsafe.body.error.details.code, 'unsafe_property');
  assert.equal((await run(acme.key, readBody({onMissingAccess: 'hold', waitMs: 5000}))).body.status, 'succeeded', 'hold matters only when the person has no account');
  assert.equal((await run(acme.key, readBody({externalUserId: 'u3', onMissingAccess: 'refuse'}))).body.error.code, 'connection_required');
});

test('cancel a call waiting for approval, once; reads of another environment\'s call are not_found; results are withheld after Never', async t => {
  const {app, acme, environment, account, run, readBody, send, call, u1} = await setup(t);
  const asked = await run(acme.key, {externalUserId: 'u1', capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'x'}}});
  const cancelled = await call(acme.key, 'POST', `/v1/executions/${asked.body.callRef}/cancel`);
  assert.equal(cancelled.body.status, 'cancelled');
  assert.equal((await call(acme.key, 'POST', `/v1/executions/${asked.body.callRef}/cancel`)).body.error.code, 'not_cancellable');
  const beta = environment('Beta'); await account(beta, 'u1');
  assert.equal((await call(beta.key, 'GET', `/v1/executions/${asked.body.callRef}`)).status, 404);
  assert.equal((await call(acme.key, 'GET', '/v1/executions/not-a-call')).status, 404);
  const done = await run(acme.key, readBody({waitMs: 5000}));
  assert.ok(done.body.result);
  app.runtimes.bundle(acme.scope).permissions.set({connectionId: u1, capabilityId: readBody().capabilityId, mode: 'deny'});
  const later = (await call(acme.key, 'GET', `/v1/executions/${done.body.callRef}`)).body;
  assert.equal(later.result, undefined); assert.equal(later.resultWithheld, true);
});

test('an approval nobody gave in time reads as failed with approval_expired', async t => {
  const {app, acme, run, send, call, repo} = await setup(t);
  const asked = await run(acme.key, {externalUserId: 'u1', capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'x'}}});
  const job = repo().get('jobs', asked.body.callRef);
  repo().put('jobs', {...job, approvalExpiresAt: new Date(Date.parse(app.registry.now()) - 1000).toISOString()});
  const read = (await call(acme.key, 'GET', `/v1/executions/${asked.body.callRef}`)).body;
  assert.deepEqual([read.status, read.error.code, read.error.attribution], ['failed', 'approval_expired', 'policy']);
});

test('usage records are append-only and survive a user delete with the usr_ id only; the delete erases the user\'s keys and calls', async t => {
  const {acme, run, readBody, usage, repo, call} = await setup(t);
  const done = await run(acme.key, readBody({waitMs: 5000}), 'keep-me');
  const row = usage()[0];
  assert.throws(() => repo().put('usageEvents', {...row, kind: 'tampered'}), {code: 'append_only'});
  assert.throws(() => repo().delete('usageEvents', row.id), {code: 'append_only'});
  assert.equal(repo().list('idempotencyKeys').length, 1);
  assert.equal((await call(acme.key, 'DELETE', '/v1/users/u1')).status, 200);
  assert.equal(repo().list('idempotencyKeys').length, 0); assert.equal(repo().get('jobs', done.body.callRef), null);
  assert.deepEqual(usage().map(item => item.id), [row.id], 'the month\'s history stays');
});

// F03.7 review fixes.
test('review fixes: an accepted call is never refused after the fact; a user deleted mid-wait is not_found; bad path values are invalid_arguments', async t => {
  const {app, acme, run, readBody, call, hold, jobs, waitingReach} = await setup(t);
  const release = hold();
  const first = await run(acme.key, readBody({waitMs: 0}));
  const waiters = Array.from({length: 16}, () => call(acme.key, 'GET', `/v1/executions/${first.body.callRef}?waitMs=3000`));
  await waitingReach(acme.key, first.body.callRef);
  const accepted = await run(acme.key, readBody({args: {userId: 'me', id: 'm-2'}, waitMs: 3000}));
  assert.equal(accepted.status, 202, 'accepted and answered at once, never 429'); assert.ok(accepted.body.callRef);
  assert.equal((await call(acme.key, 'GET', `/v1/executions/${first.body.callRef}?waitMs=3000`)).status, 429, 'a 17th read-back is still told to come back');
  const deleting = call(acme.key, 'DELETE', '/v1/users/u1');
  await deleting; release();
  assert.deepEqual([...new Set((await Promise.all(waiters)).map(answer => answer.status))], [404], 'requests waiting when the user was deleted answer not_found, never 500');
  const late = await call(acme.key, 'GET', `/v1/executions/${accepted.body.callRef}?waitMs=1000`);
  assert.equal(late.status, 404);
  const bad = await run(acme.key, readBody({externalUserId: 'u2', args: {userId: 'me', id: '..'}}), 'bad-path');
  assert.equal(bad.status, 400); assert.equal(bad.body.error.code, 'invalid_arguments');
  assert.equal((await run(acme.key, readBody({externalUserId: 'u2', args: {userId: 'me', id: '..'}}), 'bad-path')).body.error.code, 'invalid_arguments', 'the key replays the same answer');
  void app; void jobs;
});

test('review fixes: an expired approval is not cancelled after it read as failed; an app turned off runs nothing; a key held for another user is never replayed', async t => {
  const {app, acme, run, readBody, send, call, repo, u1} = await setup(t);
  const asked = await run(acme.key, {externalUserId: 'u1', capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'x'}}});
  repo().put('jobs', {...repo().get('jobs', asked.body.callRef), approvalExpiresAt: new Date(Date.now() - 1000).toISOString()});
  assert.equal((await call(acme.key, 'GET', `/v1/executions/${asked.body.callRef}`)).body.error.code, 'approval_expired');
  const cancel = await call(acme.key, 'POST', `/v1/executions/${asked.body.callRef}/cancel`);
  assert.equal(cancel.status, 409); assert.equal(cancel.body.error.code, 'not_cancellable');
  const done = await run(acme.key, readBody({waitMs: 3000}), 'held-key');
  assert.equal(done.body.status, 'succeeded');
  // The key's record now names another end user (as when a deleted user's external id comes back): never replayed.
  const record = repo().list('idempotencyKeys').find(item => item.callRef === done.body.callRef);
  repo().put('idempotencyKeys', {...record, userRecordId: `usr_${'a'.repeat(26)}`});
  const replay = await run(acme.key, readBody({waitMs: 3000}), 'held-key');
  assert.equal(replay.status, 409); assert.equal(replay.body.error.code, 'idempotency_conflict');
  // A sign-in the provider revoked reads as the documented connection_required, attributed to the credential.
  repo().put('jobs', {...repo().get('jobs', done.body.callRef), status: 'failed', errorCode: 'reconnect_required', result: undefined});
  const revoked = (await call(acme.key, 'GET', `/v1/executions/${done.body.callRef}`)).body.error;
  assert.deepEqual([revoked.code, revoked.attribution], ['connection_required', 'credential']);
  const environment = app.registry.get('environments', acme.scope.environmentId);
  app.registry.put('environments', {...environment, apps: {gmail: {enabled: false}}});
  const off = await run(acme.key, readBody());
  assert.equal(off.status, 422); assert.equal(off.body.error.code, 'app_disabled');
  void u1;
});

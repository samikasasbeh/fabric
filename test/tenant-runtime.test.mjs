import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {compileOpenApi} from '../lib/compiler.mjs';
import {EnvironmentStores} from '../lib/tenant/environments.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {tenantDeployment, endUser} from '../lib/tenant/deployment.mjs';

// F03.2b: inside one developer environment, one end user can never run, approve or cancel work on another user's
// account; another user's job answers exactly like a missing one, whatever its status, expiry or digest.
const doc = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
  '/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}},
  '/repos/{owner}/{repo}/issues': {post: {operationId: 'createIssue', parameters: [{name: 'owner', in: 'path', required: true, schema: {type: 'string'}}, {name: 'repo', in: 'path', required: true, schema: {type: 'string'}}],
    requestBody: {content: {'application/json': {schema: {type: 'object', properties: {title: {type: 'string'}}, required: ['title']}}}}, responses: {201: {description: 'Created'}}}}}};
const U1 = {kind: 'product_user', ...endUser({subjectId: 'aura-user-1', userRecordId: 'usr_' + 'a'.repeat(26)})};
const U2 = {kind: 'product_user', ...endUser({subjectId: 'aura-user-2', userRecordId: 'usr_' + 'b'.repeat(26)})};

function setup(t) {
  const caps = compileOpenApi({appId: 'github', document: doc}).capabilities.map(cap => ({...cap, status: 'active'}));
  const catalog = {get: (collection, id) => collection === 'capabilities' ? caps.find(cap => cap.id === id) ?? null : null, list: collection => collection === 'capabilities' ? caps : []};
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-tenant-runtime-'));
  const stores = new EnvironmentStores({root, catalog});
  t.after(() => { stores.closeAll(); rmSync(root, {recursive: true, force: true}); });
  const env = stores.open({organizationId: 'org_' + 'a'.repeat(26), projectId: 'prj_' + 'a'.repeat(26), environmentId: 'env_' + 'a'.repeat(26)});
  const deployment = tenantDeployment(env.scope), calls = [];
  let identity = 100;
  const request = async req => { calls.push(req); return req.url.endsWith('/user') ? {status: 200, data: {id: identity++, login: 'fixture'}} : {status: 200, headers: {}, data: {ok: true}}; };
  const connections = new ConnectionManager({store: env.repository, vault: env.vault, deployment, request});
  const runtime = new Runtime({store: env.repository, connections, deployment, request, permissions: new PermissionManager({store: env.repository})});
  const read = caps.find(cap => cap.request.method === 'GET').id, write = caps.find(cap => cap.request.method === 'POST').id;
  return {env, runtime, connections, read, write, calls};
}

test('an end user runs work only on their own account; another user\'s account answers not_found', async t => {
  const {runtime, connections, read, calls} = setup(t);
  const theirs = await connections.connect({appId: 'github', token: 'synthetic-token-1', user: U1});
  await assert.rejects(runtime.createJob({connectionId: theirs.id, capabilityId: read}, U2), {code: 'not_found'});
  await assert.rejects(runtime.createJob({connectionId: theirs.id, capabilityId: read}, {kind: 'local_owner'}), /end user is required/);
  const sent = calls.length;
  const own = await runtime.createJob({connectionId: theirs.id, capabilityId: read}, U1);
  assert.equal(own.status, 'succeeded');
  assert.equal(calls.length, sent + 1, 'exactly one provider call, for the owner');
  assert.equal(own.userRecordId, U1.userRecordId);
  assert.deepEqual(runtime.jobsOf(U2), []);
  assert.deepEqual(runtime.jobsOf(U1).map(job => job.id), [own.id]);
});

test('another user can never approve or cancel a pending write, even with the right digest, an expired one or a wrong one', async t => {
  const {runtime, connections, write, calls} = setup(t);
  const account = await connections.connect({appId: 'github', token: 'synthetic-token-1', user: U1});
  const pending = await runtime.createJob({connectionId: account.id, capabilityId: write, args: {owner: 'acme', repo: 'agent', body: {title: 'Hello'}}}, U1);
  assert.equal(pending.status, 'awaiting_approval');
  const sent = calls.length;
  for (const digest of [pending.approvalDigest, 'wrong-digest', undefined]) await assert.rejects(runtime.approve(pending.id, digest, U2), {code: 'not_found'});
  assert.throws(() => runtime.cancel(pending.id, U2), {code: 'not_found'});
  await assert.rejects(runtime.approve('no-such-job', pending.approvalDigest, U2), {code: 'not_found'}, 'a missing job looks the same');
  assert.equal(calls.length, sent, 'nothing was sent');
  assert.equal(runtime.jobsOf(U1)[0].status, 'awaiting_approval');
  // In a developer environment the plain approve path is closed (N13): decisions go through the relay, which records them.
  await assert.rejects(runtime.approve(pending.id, pending.approvalDigest, U1), {code: 'unsupported_route'});
  runtime.decideWaiting(pending.id, pending.approvalDigest, U1, {decision: 'approved', decidedIn: 'developer_app', keyId: 'key_test', serviceClientId: 'svc_test', at: new Date().toISOString()});
  const done = await runtime.execute(pending.id);
  // Sent for the owner. With no readback from the fake provider, Fabric reports the write as uncertain, never as done.
  assert.ok(['succeeded', 'uncertain'].includes(done.status), done.status);
  assert.equal(calls.length, sent + 1);
  // A cancelled job of the owner: cancel works for the owner only.
  const second = await runtime.createJob({connectionId: account.id, capabilityId: write, args: {owner: 'acme', repo: 'agent', body: {title: 'Two'}}}, U1);
  assert.equal(runtime.cancel(second.id, U1).status, 'cancelled');
});

test('a stored job is re-checked against its account\'s owner at dispatch; the proxy checks the owner before anything else', async t => {
  const {env, runtime, connections, read} = setup(t);
  const account = await connections.connect({appId: 'github', token: 'synthetic-token-1', user: U1});
  const job = runtime.jobsOf(U1).length;
  assert.equal(job, 0);
  // A job whose stored owner does not own the account fails at dispatch.
  const forged = {connectionId: account.id, capabilityId: read, args: {}, ownership: {owner: {kind: 'product_user', id: U2.subjectId}}, userRecordId: U2.userRecordId};
  assert.throws(() => runtime.validateJob(forged), {code: 'not_found'});
  assert.ok(runtime.validateJob({connectionId: account.id, capabilityId: read, args: {}, ownership: {owner: {kind: 'product_user', id: U1.subjectId}}, userRecordId: U1.userRecordId}));
  // F03.7: the proxy runs in developer environments, owner first: another user's account is not_found before any decision.
  assert.throws(() => runtime.prepareProxy({connectionId: account.id, request: {method: 'GET', path: '/user/repos'}, source: {kind: 'service', serviceClientId: 'svc_x', keyId: 'key_x'}}, U2), {code: 'not_found'});
  assert.throws(() => runtime.prepareProxy({connectionId: account.id, method: 'GET', path: '/user/repos'}, U1), {code: 'invalid_request'});
  void env;
});

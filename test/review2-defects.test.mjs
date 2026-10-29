import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../server.mjs';
import {CONTINUATIONS} from '../lib/continuations.mjs';
import {ENV, fixture, freePort} from './fixtures/signin-fixture.mjs';
import {owner, fixture as serviceFixture} from './fixtures/continuation-fixture.mjs';

// Regression tests for the seven code defects the review-2 test agents found (one test each).
// Isolated designated apps on loopback ports, GitHub simulator only.
const GITHUB_REVOKE = `https://api.github.com/applications/${ENV.FABRIC_GITHUB_CLIENT_ID}/token`;
const revocations = f => f.sim.calls.filter(req => req.method === 'DELETE' && req.url === GITHUB_REVOKE).length;
const mapWith = (f, readOperation) => f.app.store.put('applicationMaps', {id: 'github', operations: [{capabilityId: f.read.id, ...readOperation}, {capabilityId: f.write.id, requiredScopes: ['repo']}]});

test('1: GitHub read:-prefixed scopes rank as read-only, so read:org wins over gist', async t => {
  const f = await fixture(t);
  mapWith(f, {requiredScopes: ['gist', 'read:org'], scopeSets: [['read:org'], ['gist']]});
  const {id} = await f.ask();
  assert.deepEqual((await f.view(id)).signIn.scopes, ['read:org']);
});

test('2: sign-in is not offered when no requestable alternative could ever let the operation run', async t => {
  const f = await fixture(t);
  mapWith(f, {requiredScopes: ['admin:enterprise']}); // outside GitHub's reviewed upgrade scopes
  const {id} = await f.ask();
  const view = await f.view(id);
  assert.equal(view.signIn.available, false); assert.match(view.signIn.reason, /cannot grant the permission this operation needs/);
  assert.ok(!view.actions.includes('sign_in'));
  assert.equal((await f.json('POST', `/api/continuations/${id}/sign-in`, {viewDigest: view.viewDigest})).body.code, 'signin_unavailable');
  assert.equal(f.app.store.get(CONTINUATIONS, id).attempts, 0, 'no attempt was used up');
});

test('3: tokens dropped after a mid-exchange decline are recorded in the handoff outcome, not only the audit', async t => {
  for (const fails of [false, true]) {
    await t.test(fails ? 'provider revocation fails' : 'provider revocation confirmed', async t => {
      const f = await fixture(t);
      const {id} = await f.ask(), started = await f.signIn(id);
      let release;
      f.hooks.token = () => new Promise(resolve => { release = resolve; f.hooks.token = null; });
      const back = f.callback(started);
      while (!release) await new Promise(resolve => setTimeout(resolve, 5));
      await f.json('POST', `/api/continuations/${id}/decline`, {});
      f.sim.revokeFails = fails;
      release(); await back;
      const outcome = f.app.store.get(CONTINUATIONS, id).outcome;
      assert.equal(outcome.code, 'owner_declined');
      assert.equal(outcome.providerGrant, fails ? 'may_remain' : 'revoked');
      assert.equal(outcome.providerGrantMayRemain, fails);
      assert.equal((await f.view(id)).outcome.providerGrant, outcome.providerGrant, 'the owner sees it too');
    });
  }
});

test('4: reject with an edited pointer still revokes the handoff\'s own quarantined account at once', async t => {
  const f = await fixture(t);
  f.app.store.put('connections', {id: 'ready-a', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'c', status: 'ready', label: 'Ready', identity: {id: '101', displayName: 'octo-a'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date(f.now).toISOString()});
  const {id} = await f.ask();
  await f.callback(await f.signIn(id), {account: 'b'});
  const record = f.app.store.get(CONTINUATIONS, id), real = record.pendingConnection.connectionId;
  f.app.store.put(CONTINUATIONS, {...record, pendingConnection: {...record.pendingConnection, connectionId: 'ready-a'}});
  assert.equal((await f.json('POST', `/api/continuations/${id}/reject-account`, {})).body.code, 'authority_changed');
  assert.equal(f.app.store.get('connections', real).status, 'revoked'); assert.equal(f.app.vault.get(real), null);
  assert.equal(f.app.store.get('connections', 'ready-a').status, 'ready');
});

test('5: a confirm refused because the account drifted out of quarantine revokes that account', async t => {
  const f = await fixture(t);
  const {id} = await f.ask();
  await f.callback(await f.signIn(id));
  const view = await f.view(id), cid = view.pendingConnection.connectionId;
  f.app.store.put('connections', {...f.app.store.get('connections', cid), status: 'reconnect_required'});
  assert.equal((await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: view.confirmDigest})).body.code, 'authority_changed');
  assert.equal(f.app.store.get('connections', cid).status, 'revoked'); assert.equal(f.app.vault.get(cid), null);
  const next = await f.ask();
  assert.ok(!(await f.view(next.id)).accounts.some(account => account.connectionId === cid), 'never offered to a later request');
});

test('6: recovery never cancels a job that another handoff created', async t => {
  const f = await serviceFixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant(), args = {owner: 'o', repo: 'r', body: {title: 't'}};
  const p = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'p')).result;
  const q = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'q')).result;
  const jobP = (await f.select(p.id, 'acct-a')).derived.jobId; await f.select(q.id, 'acct-a');
  const record = f.store.get(CONTINUATIONS, q.id);
  f.store.put(CONTINUATIONS, {...record, status: 'binding', binding: {...record.binding, jobId: jobP, derivedRequestHash: null}});
  f.reopen();
  assert.equal(f.store.get('jobs', jobP).status, 'awaiting_approval', 'P\'s job is untouched');
  const failed = f.store.get(CONTINUATIONS, q.id);
  assert.equal(failed.status, 'failed'); assert.equal(failed.outcome.code, 'authority_changed');
  assert.equal(f.store.get(CONTINUATIONS, p.id).status, 'resumed');
});

test('7: a legacy store refuses request-only grants before any other body check', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-review2-legacy-')), port = await freePort();
  const app = await createApp({dataDir: dir, port, request: async () => ({status: 200, data: {}})});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); });
  const first = await fetch(`${app.origin}/api/state`), state = await first.json(), cookie = first.headers.get('set-cookie').split(';')[0];
  const post = body => fetch(`${app.origin}/api/clients`, {method: 'POST', headers: {'content-type': 'application/json', 'x-fabric-csrf': state.csrfToken, cookie}, body: JSON.stringify(body)});
  for (const body of [{bindings: [], requestable: [{capabilityId: 'x'}]}, {name: 'A', bindings: [], requestable: [{capabilityId: 'x'}], extra: 1}, {name: 'A', bindings: [], requestable: [{capabilityId: 'x'}], expiresInSeconds: 1}]) {
    const response = await post(body);
    assert.equal(response.status, 404, JSON.stringify(body)); assert.equal((await response.json()).code, 'unsupported_route');
  }
  assert.equal((await post({name: 'A', bindings: []})).status, 400, 'an ordinary bad body without requestable is still 400');
  assert.ok(owner);
});

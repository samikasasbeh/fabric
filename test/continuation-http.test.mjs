import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {createApp} from '../server.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {FABRIC_PROTOCOL} from '../lib/fabric-protocol.mjs';

// F02.3a owner routes over HTTP: isolated designated store, loopback port, synthetic provider.
const owner = {schemaVersion: 1, id: 'fixture-owner', kind: 'local_owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'fixture-owner'}};
const doc = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {'/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}}}};
async function freePort() { const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const {port} = server.address(); await new Promise(resolve => server.close(resolve)); return port; }

async function fixture(t, {designated = true} = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-continuation-http-')), port = await freePort();
  let now = Date.parse('2026-10-11T10:00:00.000Z');
  const calls = [];
  const app = await createApp({dataDir: dir, port, clock: () => now, request: async req => { calls.push(req); return {status: 200, data: [{id: 1}]}; },
    ...(designated ? {localAuthority: {mode: 'new', ownerPrincipal: owner}} : {})});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); });
  const cap = {...compileOpenApi({appId: 'github', document: doc}).capabilities[0], status: 'active'};
  app.store.put('capabilities', cap);
  app.store.put('connections', {id: 'acct-a', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'consent-a', status: 'ready', label: 'GitHub octo', identity: {id: '101', displayName: 'octo'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date(now).toISOString()});
  app.vault.set('acct-a', {accessToken: 'synthetic-only-token'});
  const first = await fetch(`${app.origin}/api/state`), state = await first.json(), cookie = first.headers.get('set-cookie').split(';')[0];
  const call = (method, route, data, headers = {}) => fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'content-type': 'application/json', 'x-fabric-csrf': state.csrfToken, cookie, ...headers}, ...(data !== undefined ? {body: JSON.stringify(data)} : {})});
  const protocol = (token, method, params, id = `req-${Math.random().toString(36).slice(2, 9)}`) => fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {'content-type': 'application/json', authorization: `Bearer ${token}`}, body: JSON.stringify({protocol: FABRIC_PROTOCOL, id, method, params})}).then(response => response.json());
  return {app, cap, calls, call, protocol, state, advance: ms => { now += ms; }};
}

async function handoff(f) {
  const created = await (await f.call('POST', '/api/clients', {name: 'Agent', bindings: [], requestable: [{capabilityId: f.cap.id}]})).json();
  const definitionHash = created.client.requestable[0].definitionHash;
  const response = await f.protocol(created.token, 'calls.create', {appId: 'github', capabilityId: f.cap.id, definitionHash, args: {}});
  return {token: created.token, client: created.client, view: response.result};
}

test('the handoff link opens the owner page and the owner can view, list and select an exact account', async t => {
  const f = await fixture(t);
  const {token, view} = await handoff(f);
  assert.equal(view.handoff.url, `${f.app.origin}/continue/${view.id}`);
  const page = await fetch(view.handoff.url);
  assert.equal(page.status, 200); assert.match(page.headers.get('content-type'), /text\/html/);
  assert.equal((await fetch(`${f.app.origin}/continue/not-a-handoff`)).status, 404);
  const list = await (await f.call('GET', '/api/continuations')).json();
  assert.equal(list.continuations[0].id, view.id);
  assert.equal((await (await f.call('GET', '/api/state')).json()).pendingHandoffs, 1);
  const owned = await (await f.call('GET', `/api/continuations/${view.id}`)).json();
  assert.equal(owned.accounts[0].connectionId, 'acct-a'); assert.equal(owned.accounts[0].afterSelection, 'runs_now');
  const selected = await f.call('POST', `/api/continuations/${view.id}/select`, {connectionId: 'acct-a', viewDigest: owned.viewDigest});
  assert.equal(selected.status, 200); assert.equal((await selected.json()).status, 'resumed');
  await f.app.continuations.settled(view.id);
  const status = await f.protocol(token, 'calls.get', {callId: view.id});
  assert.equal(status.result.status, 'succeeded'); assert.equal(f.calls.length, 1);
  const again = await f.call('POST', `/api/continuations/${view.id}/select`, {connectionId: 'acct-a', viewDigest: owned.viewDigest});
  assert.equal(again.status, 409); assert.equal((await again.json()).code, 'invalid_transition');
});

test('owner routes require the session and CSRF, exact bodies and current views', async t => {
  const f = await fixture(t);
  const {token, view} = await handoff(f);
  const owned = await (await f.call('GET', `/api/continuations/${view.id}`)).json();
  assert.equal((await f.call('POST', `/api/continuations/${view.id}/select`, {connectionId: 'acct-a', viewDigest: owned.viewDigest}, {'x-fabric-csrf': 'wrong'})).status, 403);
  const bearer = await fetch(`${f.app.origin}/api/continuations/${view.id}/select`, {method: 'POST', headers: {'content-type': 'application/json', authorization: `Bearer ${token}`}, body: JSON.stringify({connectionId: 'acct-a', viewDigest: owned.viewDigest})});
  assert.notEqual(bearer.status, 200, 'a client token never authenticates an owner route');
  for (const extra of [{principal: owner}, {decidedBy: 'owner'}, {generation: 1}, {source: {kind: 'user'}}, {clientId: 'x'}]) {
    const response = await f.call('POST', `/api/continuations/${view.id}/select`, {connectionId: 'acct-a', viewDigest: owned.viewDigest, ...extra});
    assert.equal(response.status, 400);
  }
  for (const site of ['cross-site', 'same-site']) {
    assert.equal((await f.call('GET', '/api/continuations', undefined, {'sec-fetch-site': site})).status, 400, `GET ${site}`);
    assert.equal((await f.call('POST', `/api/continuations/${view.id}/decline`, {}, {'sec-fetch-site': site})).status, 400, `POST ${site}`);
  }
  assert.equal((await f.call('POST', `/api/continuations/${view.id}/decline`, {}, {origin: 'https://evil.example'})).status, 400);
  const stale = await f.call('POST', `/api/continuations/${view.id}/select`, {connectionId: 'acct-a', viewDigest: 'stale'});
  assert.equal(stale.status, 409); const body = await stale.json();
  assert.equal(body.code, 'view_changed'); assert.equal(body.view.viewDigest, owned.viewDigest);
  assert.equal((await f.call('POST', `/api/continuations/${view.id}/select`, {connectionId: 'nope', viewDigest: owned.viewDigest})).status, 400);
  assert.equal((await f.call('GET', '/api/continuations/00000000-0000-4000-8000-000000000000')).status, 404);
  assert.equal((await f.call('POST', `/api/continuations/${view.id}/decline`, {reason: 'x'})).status, 400);
  assert.equal((await f.call('POST', '/api/jobs', {connectionId: 'acct-a', capabilityId: f.cap.id, jobId: '33333333-3333-4333-8333-333333333333'})).status, 400);
  assert.equal(f.calls.length, 0);
});

test('expired handoffs answer 410 and declined ones close for the client', async t => {
  const f = await fixture(t);
  const first = await handoff(f), second = await handoff(f);
  const declined = await f.call('POST', `/api/continuations/${second.view.id}/decline`, {});
  assert.equal(declined.status, 200);
  assert.equal((await f.protocol(second.token, 'calls.get', {callId: second.view.id})).result.handoff.outcome, 'owner_declined');
  f.advance(31 * 60_000);
  const expired = await f.call('POST', `/api/continuations/${first.view.id}/select`, {connectionId: 'acct-a', viewDigest: 'x'});
  assert.equal(expired.status, 410); assert.equal((await expired.json()).code, 'continuation_expired');
  assert.equal((await f.protocol(first.token, 'calls.get', {callId: first.view.id})).result.status, 'expired');
});

test('legacy deployments expose no handoff routes', async t => {
  const f = await fixture(t, {designated: false});
  const response = await f.call('GET', '/api/continuations');
  assert.equal(response.status, 404); assert.equal((await response.json()).code, 'unsupported_route');
  const granted = await f.call('POST', '/api/clients', {name: 'Agent', bindings: [], requestable: [{capabilityId: f.cap.id}]});
  assert.equal(granted.status, 404); assert.equal((await granted.json()).code, 'unsupported_route');
  // Legacy answers unsupported before it looks at the body, and the handoff link opens nothing.
  const id = '00000000-0000-4000-8000-000000000000';
  for (const [verb, body] of [['select', {connectionId: 'acct-a', viewDigest: 'x', extra: 1}], ['decline', {reason: 'x'}], ['sign-in', {extra: 1}], ['confirm', {extra: 1}], ['reject-account', {extra: 1}]]) {
    const response = await f.call('POST', `/api/continuations/${id}/${verb}`, body);
    assert.equal(response.status, 404, verb); assert.equal((await response.json()).code, 'unsupported_route', verb);
  }
  assert.equal((await fetch(`${f.app.origin}/continue/${id}`)).status, 404);
});

test('shutdown waits for a derived job still running after the owner\'s response', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-continuation-drain-')), port = await freePort();
  let release, entered;
  const gate = new Promise(resolve => { release = resolve; }), started = new Promise(resolve => { entered = resolve; });
  const app = await createApp({dataDir: dir, port, request: async () => { entered(); await gate; return {status: 200, data: [{id: 1}]}; }, localAuthority: {mode: 'new', ownerPrincipal: owner}});
  await app.start();
  t.after(() => rm(dir, {recursive: true, force: true}));
  const cap = {...compileOpenApi({appId: 'github', document: doc}).capabilities[0], status: 'active'};
  app.store.put('capabilities', cap);
  app.store.put('connections', {id: 'acct-a', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'consent-a', status: 'ready', label: 'GitHub octo', identity: {id: '101', displayName: 'octo'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date().toISOString()});
  app.vault.set('acct-a', {accessToken: 'synthetic-only-token'});
  const created = app.protocol.createClient({name: 'Agent', bindings: [], requestable: [{capabilityId: cap.id}]}, owner);
  const handoff = (await app.protocol.handle(`Bearer ${created.token}`, {protocol: FABRIC_PROTOCOL, id: 'drain', method: 'calls.create', params: {appId: 'github', capabilityId: cap.id, definitionHash: created.client.requestable[0].definitionHash, args: {}}})).result;
  const unhandled = [], listener = reason => unhandled.push(reason);
  process.on('unhandledRejection', listener); t.after(() => process.off('unhandledRejection', listener));
  await app.continuations.select(handoff.id, {connectionId: 'acct-a', viewDigest: app.continuations.ownerView(handoff.id).viewDigest}, owner);
  await started;
  let closed = false;
  const closing = app.close().then(() => { closed = true; });
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(closed, false, 'the store stays open while the derived job is in flight');
  release();
  await closing;
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(unhandled, []);
});

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
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';

// F03.7c: the governed proxy over /v1 for one end user's account. Every refusal of the reviewed normaliser and every
// clamp holds through the developer API, a full url must sit exactly on the reviewed base, the owner is checked
// before anything is decided, and responses are kept per end user.
const TYPED = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.labels.create', 'post', '/gmail/v1/users/{userId}/labels']];
function seed(root) {
  const paths = {};
  for (const [id, method, route] of TYPED) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {name: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities;
  const store = new PlatformStore({root});
  // Gmail is reviewed by operation id: every reviewed operation must be in the stored map (as in test/proxy-policy.test.mjs).
  const operations = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => ({id, method: id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`, sensitive: null}));
  for (const [id, method, route] of TYPED) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `https://gmail.googleapis.com${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations[operations.findIndex(op => op.id === id)] = {id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null};
  }
  // Real Gmail paths for the members the review fixes exercise.
  for (const [id, path] of [['gmail.users.messages.list', '/gmail/v1/users/{userId}/messages'], ['gmail.users.threads.get', '/gmail/v1/users/{userId}/threads/{id}'], ['gmail.users.getProfile', '/gmail/v1/users/{userId}/profile'], ['gmail.users.drafts.list', '/gmail/v1/users/{userId}/drafts']]) {
    const at = operations.findIndex(op => op.id === id);
    operations[at] = {...operations[at], path};
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-proxy-'));
  seed(root);
  const sim = {calls: []};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/')) return {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify({messages: [{id: 'm-1'}], token: 'ya29.secret-token-value'}))};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  const call = async (method, route, body, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  const account = async (externalUserId, identity) => {
    await call('POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), id = randomUUID(), now = app.registry.now();
    repo().put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: identity, displayName: `${identity}@example.com`}, allowedOrigins: ['https://gmail.googleapis.com'],
      scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: now, updatedAt: now, authRevision: randomUUID()}, {subjectId: externalUserId, userRecordId: user.id}));
    app.stores.open(scope).vault.set(id, {accessToken: 'ya29.secret-token-value', refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000});
    return {id, user};
  };
  const one = await account('u1', 'g-1'), two = await account('u2', 'g-2');
  const proxy = (request, extra = {}, idem = randomUUID()) => call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'gmail', request, ...extra}, {'Idempotency-Key': idem});
  const nothing = () => ({jobs: repo().list('jobs').length, usage: repo().list('usageEvents').length, sent: sim.calls.length});
  return {app, sim, scope, key, call, repo, one, two, proxy, nothing};
}
const get = (pathname, extra = {}) => ({method: 'GET', path: pathname, ...extra});

test('a proxied read on the end user\'s own account: observed, the response kept for that user only, credentials scrubbed', async t => {
  const {repo, one, proxy} = await setup(t);
  const done = await proxy(get('/gmail/v1/users/me/messages', {query: {maxResults: '5'}}), {waitMs: 5000});
  assert.equal(done.status, 200);
  assert.deepEqual([done.body.kind, done.body.status, done.body.evidence, done.body.accountRef, done.body.result.status], ['proxy', 'succeeded', 'observed', one.id, 200]);
  assert.deepEqual(done.body.result.body.messages, [{id: 'm-1'}]);
  assert.equal(JSON.stringify(done.body).includes('ya29.secret-token-value'), false, 'the account\'s own token never comes back');
  const kept = repo().get('proxyResponses', done.body.callRef);
  assert.equal(kept.holder, `user:${one.user.id}`); assert.equal(kept.userRecordId, one.user.id);
  const usage = repo().list('usageEvents');
  assert.deepEqual(usage.map(row => [row.id, row.kind]), [[`proxy.${done.body.callRef}`, 'proxy']]);
});

test('the reviewed normaliser\'s adversarial cases hold through /v1: each refusal names its code, and nothing is stored, sent or counted', async t => {
  const {app, scope, call, proxy, nothing} = await setup(t);
  const before = nothing();
  const refused = async (request, code, label) => {
    const answer = await proxy(request);
    assert.equal(answer.status, 400, `${label}: ${JSON.stringify(answer.body)}`); assert.equal(answer.body.error.code, 'invalid_request', label); assert.equal(answer.body.error.details?.code, code, label);
  };
  for (const p of ['/%EF%BB%BF', '/gmail/v1/users/me/../../x', '/gmail/v1/%2e%2e/x', '/gmail/v1/%2E%2e/x', '/.', '/./x', '/..;/x', '/gmail/v1/a%252e%252e', '/gmail/v1/a%c0%ae%c0%ae', '/gmail/v1/a\\b', '/gmail/v1/a\tb',
    '/gmail/v1/a b', '/gmail/v1/users/a%2Fb', '/gmail/v1/a%5Cb', '//gmail.googleapis.com/gmail/v1/users', '/gmail/v1//x', '/gmail/v1/users/', 'https://evil.example/x', 'gmail/v1/x', '/gmail/v1/a?b=1', '/gmail/v1/a#x', '/gmail/v1/a%zz',
    '/gmail/v1/a/%00', '/gmail/v1/a/%E2%80%AE', '/gmail/v1/__proto__', '', '/upload/gmail/v1/users/me/messages', '/gmail/v1']) await refused(get(p), 'invalid_path', JSON.stringify(p));
  for (const name of ['Authorization', 'Cookie', 'Proxy-Authorization', 'X-Api-Key', 'Host', 'X-Forwarded-Host', 'Forwarded', 'X-Original-URL', 'X-HTTP-Method-Override', 'Content-Type']) await refused(get('/gmail/v1/users/me/messages', {headers: {[name]: 'v'}}), 'header_not_allowed', name);
  await refused(get('/gmail/v1/users/me/messages', {headers: {'If-Match': 'a\r\nX: y'}}), 'header_not_allowed', 'header injection');
  for (const name of ['access_token', 'oauth_token', 'api_key', 'client_secret', 'callback', '_method', '$key', 'alt', 'uploadType', 'key', 'quotaUser', 'a b']) await refused(get('/gmail/v1/users/me/messages', {query: {[name]: 'v'}}), 'parameter_not_allowed', name);
  // __proto__ never reaches the normaliser: the request's fingerprint refuses it first, as a clean 400 (found by this test).
  await refused(get('/gmail/v1/users/me/messages', {query: JSON.parse('{"__proto__": "v"}')}), 'unsafe_property', '__proto__ in the query');
  await refused(get('/gmail/v1/users/me/messages', {query: {q: 'a\u0000'}}), 'parameter_not_allowed', 'control character');
  for (const method of ['HEAD', 'OPTIONS', 'TRACE', 'get', '']) await refused({method, path: '/gmail/v1/users/me/messages'}, 'method_not_allowed', JSON.stringify(method));
  await refused({method: 'GET', path: '/gmail/v1/users/me/messages', body: {}}, 'unsupported_body', 'a GET with a body');
  await refused({method: 'POST', path: '/gmail/v1/users/me/labels', body: JSON.parse('{"__proto__": {"x": 1}}')}, 'unsafe_property', '__proto__ in the body');
  await refused({method: 'POST', path: '/gmail/v1/users/me/labels', body: {a: 'x'.repeat(65_536)}}, 'request_too_large', 'body over 64 KiB');
  await refused(get(`/gmail/v1/${Array.from({length: 33}, () => 'a').join('/')}`), 'request_too_large', '33 segments');
  // 60 refusals a minute per service client: the last two cases go through a second key.
  assert.equal((await proxy(get('/gmail/v1/users/me/messages', {extra: 1}))).body.error.code, 'rate_limited', 'the 61st refusal in a minute');
  const fresh = app.keys.mint({environmentId: scope.environmentId, preset: 'standard'}).token;
  const other = (request, extra = {}) => call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'gmail', request, ...extra}, {'Idempotency-Key': randomUUID(), Authorization: `Bearer ${fresh}`});
  assert.equal((await other(get('/gmail/v1/users/me/messages', {extra: 1}))).body.error.details?.code, 'invalid_request');
  assert.equal((await other(get('/gmail/v1/users/me/messages'), {timeoutMs: 999})).body.error.details?.code, 'invalid_request');
  assert.deepEqual(nothing(), before);
});

test('limits per service client: 60 refused requests a minute, and at most 20 proxied requests waiting for approval', async t => {
  const {app, scope, call, proxy, nothing} = await setup(t);
  for (let i = 0; i < 60; i++) assert.equal((await proxy(get('/gmail/v1/a b'))).status, 400);
  const limited = await proxy(get('/gmail/v1/users/me/messages'));
  assert.equal(limited.status, 429); assert.equal(limited.body.error.code, 'rate_limited');
  const fresh = app.keys.mint({environmentId: scope.environmentId, preset: 'standard'}).token;
  const asFresh = (request, extra = {}) => call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'gmail', request, ...extra}, {'Idempotency-Key': randomUUID(), Authorization: `Bearer ${fresh}`});
  for (let i = 0; i < 20; i++) assert.equal((await asFresh({method: 'POST', path: '/gmail/v1/users/me/labels', body: {name: `l${i}`}})).body.status, 'awaiting_approval');
  const full = await asFresh({method: 'POST', path: '/gmail/v1/users/me/labels', body: {name: 'l20'}});
  assert.equal(full.status, 429); assert.equal(full.body.error.code, 'pending_limit');
  assert.equal(nothing().sent, 0, 'nothing waiting was sent');
});

test('a full url must sit exactly on the reviewed base: traversal, other hosts, userinfo, fragments and mixed forms are refused before sending', async t => {
  const {proxy, nothing} = await setup(t);
  const done = await proxy({method: 'GET', url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=5&labelIds=INBOX'}, {waitMs: 5000});
  assert.equal(done.body.status, 'succeeded');
  const before = nothing();
  for (const url of ['https://gmail.googleapis.com.evil.example/gmail/v1/users/me/messages', 'https://gmail.googleapis.com@evil.example/gmail/v1/x', 'https://www.googleapis.com/drive/v3/files', 'http://gmail.googleapis.com/gmail/v1/users/me/messages',
    'https://gmail.googleapis.com/gmail/v1/users/me/messages#x', 'https://gmail.googleapis.com', 'https://GMAIL.googleapis.com/gmail/v1/users/me/messages', 42]) {
    const answer = await proxy({method: 'GET', url});
    assert.equal(answer.status, 422, String(url)); assert.equal(answer.body.error.code, 'origin_not_reviewed', String(url));
  }
  for (const url of ['https://gmail.googleapis.com/gmail/v1/users/me/../../../gmail/v1/users/other/messages', 'https://gmail.googleapis.com/gmail/v1/users/me/%2e%2e/other/messages', 'https://gmail.googleapis.com/gmail/v1/../../drive/v3/files', 'https://gmail.googleapis.com/gmail/v1/%2e%2e/%2e%2e/drive/v3/files', 'https://gmail.googleapis.com/upload/gmail/v1/users/me/messages']) {
    const answer = await proxy({method: 'GET', url});
    assert.equal(answer.status, 400, url); assert.equal(answer.body.error.details?.code, 'invalid_path', url);
  }
  assert.equal((await proxy({method: 'GET', url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages', path: '/gmail/v1/users/me/messages'})).status, 400, 'url and path together');
  assert.equal((await proxy({method: 'GET', url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages?q=a', query: {q: 'b'}})).status, 400, 'the query in two places');
  assert.deepEqual(nothing(), before);
});

test('clamps and ceilings hold through /v1: a typed operation set to Never caps its endpoint (c4); a developer ceiling refuses a proxied change', async t => {
  const {app, scope, repo, one, proxy, nothing} = await setup(t);
  const typedRead = repo().list('capabilities').find(cap => cap.request.method === 'GET');
  app.runtimes.bundle(scope).permissions.set({connectionId: one.id, capabilityId: typedRead.id, mode: 'deny'});
  const before = nothing();
  const c4 = await proxy(get('/gmail/v1/users/me/messages/m-1'));
  assert.equal(c4.status, 403); assert.equal(c4.body.error.code, 'permission_denied');
  assert.deepEqual(nothing(), before, 'no job, nothing sent, nothing counted');
  const labels = {method: 'POST', path: '/gmail/v1/users/me/labels', body: {name: 'x'}};
  const asked = await proxy(labels);
  assert.equal(asked.body.status, 'awaiting_approval', 'a change waits for approval by default (c6)');
  const environment = app.registry.get('environments', scope.environmentId);
  app.registry.put('environments', {...environment, apps: {gmail: {ceilings: {'gmail.labels.manage': 'deny'}}}});
  const capped = await proxy(labels);
  assert.equal(capped.status, 403); assert.equal(capped.body.error.code, 'permission_denied');
  // A row with no typed operation in the catalog: only the proxy's own ceiling can refuse it (no c4 to lean on).
  const drafts = get('/gmail/v1/users/me/drafts');
  assert.equal((await proxy(drafts, {waitMs: 5000})).body.status, 'succeeded', 'Read drafts is Allow by default');
  app.registry.put('environments', {...environment, apps: {gmail: {ceilings: {'gmail.drafts.read': 'deny'}}}});
  const ceiling = await proxy(drafts);
  assert.equal(ceiling.status, 403); assert.equal(ceiling.body.error.code, 'permission_denied');
});

test('a proxied result is withheld once the row it landed in is set to Never', async t => {
  const {app, scope, call, one, proxy} = await setup(t);
  const done = await proxy(get('/gmail/v1/users/me/messages'), {waitMs: 5000});
  assert.ok(done.body.result.body);
  const runtime = app.runtimes.bundle(scope).runtime, row = runtime.proxyPolicy.decide(one.id, get('/gmail/v1/users/me/messages')).row;
  runtime.proxyPolicy.set({connectionId: one.id, row, mode: 'deny'});
  const later = (await call('GET', `/v1/executions/${done.body.callRef}`)).body;
  assert.equal(later.result, undefined); assert.equal(later.resultWithheld, true);
});

test('the owner comes first: another user\'s account is not_found with no record of any kind; one account is used, several need a choice', async t => {
  const {call, repo, two, proxy, nothing} = await setup(t);
  const activityBefore = repo().list('activity').length, before = nothing();
  const other = await proxy(get('/gmail/v1/users/me/messages'), {accountRef: two.id});
  assert.equal(other.status, 404); assert.equal(other.body.error.code, 'not_found');
  assert.deepEqual(nothing(), before);
  assert.equal(repo().list('activity').length, activityBefore, 'not even an audit row');
  const used = await proxy(get('/gmail/v1/users/me/messages'), {waitMs: 5000});
  assert.equal(used.body.status, 'succeeded');
  const second = randomUUID(), owned = repo().get('connections', used.body.accountRef);
  repo().put('connections', {...owned, id: second, identity: {id: 'g-9', displayName: 'nine@example.com'}});
  const choose = await proxy(get('/gmail/v1/users/me/messages'));
  assert.equal(choose.status, 409); assert.equal(choose.body.error.code, 'account_choice_required');
  assert.equal((await call('POST', '/v1/proxy/requests', {externalUserId: 'u1', request: get('/gmail/v1/users/me/messages')}, {'Idempotency-Key': 'x1'})).status, 400, 'without an accountRef, appId is required');
});

test('replays, cancels and deletes: the same Idempotency-Key never sends twice; a user delete erases their proxy calls and kept responses', async t => {
  const {call, repo, proxy, sim} = await setup(t);
  const first = await proxy(get('/gmail/v1/users/me/messages'), {waitMs: 5000}, 'same-key');
  const again = await proxy(get('/gmail/v1/users/me/messages'), {waitMs: 5000}, 'same-key');
  assert.equal(again.body.callRef, first.body.callRef); assert.equal(sim.calls.length, 1);
  assert.equal((await proxy(get('/gmail/v1/users/me/messages/x'), {}, 'same-key')).body.error.code, 'idempotency_conflict');
  const asked = await proxy({method: 'POST', path: '/gmail/v1/users/me/labels', body: {name: 'x'}});
  assert.equal((await call('POST', `/v1/executions/${asked.body.callRef}/cancel`)).body.status, 'cancelled');
  assert.equal((await call('GET', `/v1/executions/${first.body.callRef}`)).body.kind, 'proxy');
  assert.ok(repo().get('proxyResponses', first.body.callRef));
  await call('DELETE', '/v1/users/u1');
  assert.equal(repo().get('proxyResponses', first.body.callRef), null); assert.equal(repo().get('jobs', first.body.callRef), null);
  assert.equal(repo().list('usageEvents').length, 2, 'usage history stays');
});

// F03.7 review fix: the person's Never on a row reaches every proxied request in it (c8), and a row with no typed
// operation can be set for the proxy itself.
test('a row set to Never through the relay stops proxied requests anywhere in that row; proxy-only rows can be set too', async t => {
  const {call, one, proxy, sim} = await setup(t);
  const page = async () => (await call('GET', `/v1/users/u1/apps/gmail?account=${one.id}`)).body;
  const row = (await page()).sections.flatMap(section => section.rows).find(item => item.groupId === 'gmail.messages.read');
  assert.equal((await call('POST', `/v1/users/u1/accounts/${one.id}/permissions`, {groupId: 'gmail.messages.read', mode: 'deny', etag: row.etag})).status, 200);
  for (const p of ['/gmail/v1/users/me/threads/t-1', '/gmail/v1/users/me/profile']) {
    const refused = await proxy(get(p));
    assert.equal(refused.status, 403, p); assert.equal(refused.body.error.code, 'permission_denied');
  }
  assert.equal((await proxy(get('/gmail/v1/users/me/messages'), {waitMs: 3000})).body.status, 'succeeded', 'another row is untouched');
  const drafts = (await page()).proxyRows.find(item => item.groupId === 'gmail.drafts.read');
  assert.deepEqual([drafts.mode, drafts.effect], ['allow', 'read']);
  assert.equal((await proxy(get('/gmail/v1/users/me/drafts'), {waitMs: 3000})).body.status, 'succeeded');
  const set = await call('POST', `/v1/users/u1/accounts/${one.id}/permissions`, {groupId: 'gmail.drafts.read', mode: 'deny', etag: drafts.etag, proxy: true});
  assert.equal(set.status, 200); assert.equal(set.body.mode, 'deny');
  assert.equal((await call('POST', `/v1/users/u1/accounts/${one.id}/permissions`, {groupId: 'gmail.drafts.read', mode: 'allow', etag: drafts.etag, proxy: true})).body.error.code, 'etag_mismatch', 'the etag is single-use');
  const before = sim.calls.length;
  assert.equal((await proxy(get('/gmail/v1/users/me/drafts'))).status, 403);
  assert.equal(sim.calls.length, before, 'nothing was sent');
});

// c8 on its own. Since F10.6 the row control above also writes the row's proxy record, so that test passes without c8. A typed
// record written with no proxy record (the control while the proxy could not route the account, F10.6 correction 9, or a store
// from before F10.6) must still reach every proxied request in its row, not only the one its own operation routes (c4).
test('c8: a Never saved on one typed operation, with no proxy record, stops proxied requests anywhere in its row', async t => {
  const {app, scope, sim, one, proxy} = await setup(t);
  const {permissions} = app.runtimes.bundle(scope), typed = permissions.list(one.id).find(decision => decision.name === 'gmail.users.messages.get');
  assert.equal(typed.groupId, 'gmail.messages.read');
  permissions.set({connectionId: one.id, capabilityId: typed.capabilityId, mode: 'deny'});
  const before = sim.calls.length;
  for (const p of ['/gmail/v1/users/me/threads/t-1', '/gmail/v1/users/me/profile']) {
    const refused = await proxy(get(p));
    assert.equal(refused.status, 403, p); assert.equal(refused.body.error.code, 'permission_denied', p);
  }
  assert.equal(sim.calls.length, before, 'nothing was sent');
  assert.equal((await proxy(get('/gmail/v1/users/me/messages'), {waitMs: 3000})).body.status, 'succeeded', 'another row is untouched');
});

// F10.3 (map correction 1): the relay re-checks a typed call before it queues it. A proxied call has no typed capability
// (its capabilityId is proxy:<row>), so it is left to the re-decision at dispatch, and approving one still runs it.
test('a waiting proxied change approved through the relay runs once, detached; it is decided again only at dispatch', async t => {
  const {app, scope, sim, call, proxy, repo} = await setup(t);
  const relay = {Authorization: `Bearer ${app.keys.mint({environmentId: scope.environmentId, preset: 'full'}).token}`};
  const asked = await proxy({method: 'POST', path: '/gmail/v1/users/me/labels', body: {name: 'x'}});
  assert.equal(asked.body.status, 'awaiting_approval');
  const [item] = (await call('GET', '/v1/users/u1/approvals', undefined, relay)).body.approvals;
  assert.equal(item.callRef, asked.body.callRef);
  const decided = await call('POST', `/v1/users/u1/approvals/${item.callRef}/decision`, {decision: 'approve', digest: item.digest}, relay);
  assert.ok([200, 202].includes(decided.status), JSON.stringify(decided.body));
  const done = await call('GET', `/v1/executions/${item.callRef}?waitMs=5000`, undefined, relay);
  assert.deepEqual([done.body.kind, done.body.status, done.body.decision.decision], ['proxy', 'uncertain', 'approved'], 'a change that was sent is never reported as done');
  assert.equal(sim.calls.filter(line => line === 'POST https://gmail.googleapis.com/gmail/v1/users/me/labels').length, 1);
  assert.equal(repo().list('activity').filter(event => event.type === 'job.approved' && event.jobId === item.callRef).length, 1);
});

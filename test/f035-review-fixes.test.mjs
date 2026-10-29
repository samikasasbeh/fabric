import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {SHARED_GOOGLE_IDENTITY_BUDGET} from '../lib/tenant/provider-apps.mjs';

// The independent security review of F03.5 (7 findings), each shown by a failing test before its fix. Findings 3 and 4 of
// the Python adapter are in test/connect-broker-review.test.mjs, next to the adapter's other tests.

function seed(root, appId, server, ops) {
  const paths = {};
  for (const [id, method, route] of ops) paths[route] = {...(paths[route] || {}), [method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method !== 'get' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {q: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: server}], paths}}).capabilities;
  const store = new PlatformStore({root}), operations = [], ids = {};
  for (const [id, method, route, status = 'active', support] of ops) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `${server}${route}`);
    store.put('capabilities', {...capability, status}); ids[id] = capability.id;
    operations.push({id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null, ...(support ? {support} : {})});
  }
  store.put('applicationMaps', {id: appId, appId, classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
  return ids;
}

async function setup(t, {seedWith, request} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-r035-'));
  seedWith?.(root);
  const sim = {calls: [], tokens: new Map(), issued: 0};
  const simulated = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://github.com/login/oauth/access_token') { const token = `gho_${++sim.issued}`; sim.tokens.set(token, sim.next); return {status: 200, headers: {}, data: {access_token: token, token_type: 'bearer', scope: 'read:user,repo'}}; }
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: sim.tokens.get(String(req.headers.Authorization).slice(7))};
    if (req.url === 'https://api.github.com/applications/gh-client/token') { sim.revoked = JSON.parse(req.body).access_token; return {status: 204, headers: {}, data: null}; }
    if (req.url === 'https://oauth2.googleapis.com/token') { const token = `ya29.${++sim.issued}`; sim.tokens.set(token, sim.next); return {status: 200, headers: {}, data: {access_token: token, refresh_token: `1//r${sim.issued}`, token_type: 'Bearer', expires_in: 3600, scope: sim.scope}}; }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') { const who = sim.tokens.get(String(req.headers.Authorization).slice(7)); return {status: 200, headers: {}, data: {sub: who.id, email: who.email, name: who.name}}; }
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) return {status: 200, headers: {}, data: {emailAddress: sim.tokens.get(String(req.headers.Authorization).slice(7)).email}};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request: request ?? simulated, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}, google: {clientId: 'g-client', clientSecret: 'g-secret'}, notion: {clientId: 'n-client', clientSecret: 'n-secret', relayReady: true}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
  const scope = app.registry.scopeOf(dev), full = app.keys.mint({environmentId: dev.id, preset: 'full'}).token, standard = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  const call = async (key, method, route, body) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})}); return {status: response.status, body: await response.json()}; };
  const repo = () => app.stores.open(scope).repository;
  /** A ready account placed straight in the environment, owned by the named end user. */
  const plant = async (externalUserId, fields) => {
    await call(full, 'POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), now = new Date().toISOString(), id = randomUUID();
    repo().put('connections', stampOwner({id, driver: 'http', status: 'ready', authMethod: 'oauth', createdAt: now, updatedAt: now, authRevision: randomUUID(), allowedOrigins: [], ...fields}, {subjectId: externalUserId, userRecordId: user.id}));
    return id;
  };
  /** One sign-in through the real path, stopped before confirm. */
  const signIn = async (externalUserId, appId, identity) => {
    const created = (await call(full, 'POST', '/v1/connect-sessions', {externalUserId, appId})).body, binding = `browser-${created.id}`;
    app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
    const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl);
    sim.next = identity; sim.scope = url.searchParams.get('scope');
    const back = await app.sessions.callback(appId === 'github' ? 'github' : 'google', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
    return {...back, id: created.id, confirm: () => app.sessions.confirm(created.id, binding, back.finish)};
  };
  return {app, root, sim, scope, full, standard, call, repo, plant, signIn};
}
const rowOf = (view, groupId) => view.sections.flatMap(section => section.rows).find(row => row.groupId === groupId);

test('1. a write operation inside a read row is still a decision; a reviewed read inside it is not', async t => {
  const NOTION = [['notion.pages.get', 'get', '/v1/pages/{page_id}'], ['notion.views.queries.create', 'post', '/v1/views/{view_id}/queries'], ['notion.search', 'post', '/v1/search']];
  let ids;
  const {full, standard, call, plant} = await setup(t, {seedWith: root => { ids = seed(root, 'notion', 'https://api.notion.com', NOTION); }});
  const ref = await plant('u1', {appId: 'notion', providerId: 'notion', label: 'Notion', identity: {id: 'ws1:user1', displayName: 'User One'}, allowedOrigins: ['https://api.notion.com']});
  const view = (await call(full, 'GET', '/v1/users/u1/apps/notion')).body, content = rowOf(view, 'notion.content.read');
  assert.equal(content.effect, 'read');
  const relay = (key, extra = {}) => call(key, 'POST', `/v1/users/u1/accounts/${ref}/permissions`, {groupId: 'notion.content.read', mode: 'allow', etag: content.etag, ...extra});
  assert.equal((await relay(standard)).body.error.code, 'decision_not_permitted', 'a key without the decision power cannot Allow the write member');
  assert.equal((await relay(full)).body.error.code, 'confirm_required');
  assert.equal((await relay(full, {confirmAllow: true})).status, 200);
  // Reset without the power: the write member goes back to Ask, the reviewed-read search row keeps its Allow default.
  const reset = (await call(standard, 'POST', `/v1/users/u1/accounts/${ref}/permissions/reset`, {})).body.rows;
  assert.equal(reset.find(row => row.groupId === 'notion.search.read').mode, 'allow', 'a reviewed read is not clamped');
  const runnable = (await call(full, 'GET', '/v1/users/u1/capabilities?appId=notion')).body.capabilities;
  assert.equal(runnable.find(item => item.id === ids['notion.views.queries.create']).mode, 'ask', 'the write member is back at Ask');
  assert.equal(runnable.find(item => item.id === ids['notion.search']).mode, 'allow');
});

test('2. the shared Google budget counts sign-ins held unconfirmed, and is checked again at confirm', async t => {
  const {repo, plant, signIn} = await setup(t);
  for (let i = 1; i < SHARED_GOOGLE_IDENTITY_BUDGET; i++) await plant(`held-${i}`, {appId: 'gmail', providerId: 'google', identity: {id: `g-${i}`, displayName: `G${i}`}});
  const first = await signIn('a', 'gmail', {id: 'g-a', email: 'a@example.com', name: 'A'});
  assert.equal(first.failed, undefined);
  const second = await signIn('b', 'gmail', {id: 'g-b', email: 'b@example.com', name: 'B'});
  assert.equal(second.failed, 'user_cap_reached', 'the unconfirmed sign-in already holds the last place');
  // If a tenth account appears before the confirm, the confirm refuses rather than going over.
  await plant('late', {appId: 'gmail', providerId: 'google', identity: {id: 'g-late', displayName: 'Late'}});
  assert.throws(() => first.confirm(), {code: 'user_cap_reached'});
  const ready = new Set(repo().list('connections').filter(item => item.providerId === 'google' && item.status === 'ready').map(item => item.identity.id));
  assert.equal(ready.size, SHARED_GOOGLE_IDENTITY_BUDGET);
  assert.equal(repo().list('connections').some(item => item.identity?.id === 'g-a'), false, 'the refused account is erased');
  assert.equal(repo().get('connectSessions', first.id).result.errorCode, 'user_cap_reached');
});

test('4. the developer server refuses dot segments in any spelling instead of resolving them into another route', async t => {
  const {app, full, plant} = await setup(t);
  await plant('u1', {appId: 'github', providerId: 'github', identity: {id: '1', displayName: 'one'}});
  for (const raw of ['/v1/users/../accounts', '/v1/users/%2e%2e/accounts', '/v1/users/.%2E/accounts', '/v1/users/./accounts', '/v1/users/%2E/accounts?x=1']) {
    const status = await new Promise((resolve, reject) => {
      const req = http.request({host: '127.0.0.1', port: app.port, path: raw, headers: {Host: `127.0.0.1:${app.port}`, Authorization: `Bearer ${full}`}}, res => { res.resume(); resolve(res.statusCode); });
      req.on('error', reject); req.end();
    });
    assert.equal(status, 404, raw);
  }
});

test('5. a row with an operation Fabric has not reviewed can only be set to Never, and a refusal changes nothing', async t => {
  const OPS = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.attachments.get', 'get', '/gmail/v1/users/{userId}/messages/{messageId}/attachments/{id}', 'candidate', 'unsupported']];
  const {full, call, plant, repo} = await setup(t, {seedWith: root => seed(root, 'gmail', 'https://gmail.googleapis.com', OPS)});
  const ref = await plant('u1', {appId: 'gmail', providerId: 'google', identity: {id: 'g-1', displayName: 'One'}, allowedOrigins: ['https://gmail.googleapis.com']});
  const before = repo().list('permissions').length;
  const row = rowOf((await call(full, 'GET', '/v1/users/u1/apps/gmail')).body, 'gmail.messages.read');
  // F03.10: review is refused in tenants (N6), so the row offers Never only instead of asking for a review.
  assert.equal(row.reviewRequired, false); assert.deepEqual(row.allowedModes, ['deny']);
  const refused = await call(full, 'POST', `/v1/users/u1/accounts/${ref}/permissions`, {groupId: 'gmail.messages.read', mode: 'allow', etag: row.etag, confirmAllow: true});
  assert.equal(refused.status, 409); assert.equal(refused.body.error.code, 'mode_not_allowed');
  assert.equal(repo().list('permissions').length, before, 'nothing was saved');
  assert.equal((await call(full, 'POST', `/v1/users/u1/accounts/${ref}/permissions`, {groupId: 'gmail.messages.read', mode: 'deny', etag: row.etag})).status, 200);
});

test('6. the end-user list\'s cursor carries nothing the developer does not already have', async t => {
  const {full, call, repo} = await setup(t);
  for (const id of ['a1', 'a2', 'a3']) await call(full, 'POST', '/v1/connect-sessions', {externalUserId: id});
  const page = (await call(full, 'GET', '/v1/users?limit=1')).body;
  const decoded = Buffer.from(page.pageInfo.endCursor, 'base64url').toString();
  for (const user of repo().list('endUsers')) assert.equal(decoded.includes(user.id), false, 'no usr_ id in the cursor');
  const next = (await call(full, 'GET', `/v1/users?limit=5&after=${page.pageInfo.endCursor}`)).body.users.map(user => user.externalUserId);
  assert.deepEqual(next, ['a2', 'a3']);
});

test('7. signing the same GitHub account in again revokes the old token Fabric no longer holds', async t => {
  const {app, sim, repo, signIn} = await setup(t);
  const one = await signIn('u1', 'github', {id: 42, login: 'octo'});
  const ref = one.confirm().result.accountRef, oldToken = app.stores.open(app.registry.scopeOf(app.registry.list('environments')[0])).vault.get(ref).accessToken;
  const two = await signIn('u1', 'github', {id: 42, login: 'octo'});
  assert.equal(two.confirm().result.accountRef, ref, 'one account');
  await app.sessions.settled();
  assert.equal(sim.revoked, oldToken, 'the replaced token was revoked at GitHub');
  assert.ok(repo().list('activity').some(event => event.type === 'connection.replaced_token_revoked' && event.remoteRevoked === true));
});

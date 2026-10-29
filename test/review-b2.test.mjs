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
import * as connectSessions from '../lib/tenant/connect-sessions.mjs';
import {SlackSimulator} from './fixtures/oauth-simulators.mjs';

// The developer layer's security review (docs/F03-SECURITY-REVIEW.md), group b2: Connect sessions and sign-in. Each
// confirmed finding has a test here that failed before its fix.
const START_LIMIT = connectSessions.START_LIMIT ?? 20, ROUTE_GRACE_MS = connectSessions.ROUTE_GRACE_MS ?? 3_600_000;
const INVALID_STATE = 'This sign-in has expired, was already used, or belongs to another browser. Start again from the app.';
const secretOf = connectUrl => new URL(connectUrl).hash.slice(3);
const GMAIL = 'https://gmail.googleapis.com';
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
  const [repo] = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {'/repos/{owner}/{repo}': {get: {operationId: 'repos/get', parameters: ['owner', 'repo'].map(name => ({name, in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'OK'}}}}}}}).capabilities;
  store.put('capabilities', {...repo, status: 'active'});
  store.put('applicationMaps', {id: 'github', appId: 'github', classifierVersion: SENSITIVITY_VERSION, operations: [{id: 'repos/get', capabilityId: repo.id, method: 'GET', path: '/repos/{owner}/{repo}', sensitive: null}]});
  store.close();
}

/** One development environment with Fabric's shared GitHub and Google apps, a Gmail account for u1, and a GitHub simulator. */
async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review-b2-'));
  seed(root);
  let now = Date.UTC(2026, 9, 17, 9);
  // `omit`: boxes the person unticks at GitHub (F10.7: GitHub signs in at full, so a narrower account declines an optional scope).
  const sim = {calls: [], issued: 0, identity: 100, extraScope: '', omit: [], userFails: false, revokeGate: null};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://github.com/login/oauth/access_token') return {status: 200, headers: {}, data: {access_token: `gho_b2_${++sim.issued}`, token_type: 'bearer', scope: `${(sim.scope ?? 'read:user,repo').split(',').filter(scope => !sim.omit.includes(scope)).join(',')}${sim.extraScope}`}};
    if (req.url === 'https://api.github.com/user') return sim.userFails ? {status: 401, headers: {}, data: {message: 'Bad credentials'}} : {status: 200, headers: {}, data: {id: sim.identity, login: `octo${sim.identity}`, name: `Octo ${sim.identity}`}};
    if (req.url.startsWith('https://api.github.com/applications/')) { await sim.revokeGate; return {status: 204, headers: {}, data: null}; }
    if (req.url.startsWith('https://api.github.com/repos/')) return {status: 200, headers: {}, data: {id: 7, full_name: 'o/r'}};
    const data = req.url.includes('/labels') ? {labels: [{id: 'INBOX'}]} : {id: 'm-1', snippet: 'hello'};
    return req.responseType === 'buffer' ? {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(data))} : {status: 200, headers: {}, data};
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, clock: () => now, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { sim.releaseRevoke?.(); await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'P'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev), key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body, token = key) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: response.status === 204 ? null : await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u1'});
  const user = repo().list('endUsers').find(item => item.subjectId === 'u1'), stamp = app.registry.now(), gmail = randomUUID();
  repo().put('connections', stampOwner({id: gmail, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: 'g-1', displayName: 'one@example.com'}, allowedOrigins: [GMAIL],
    scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.labels', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: stamp, updatedAt: stamp, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: 'u1', userRecordId: user.id}));
  app.stores.open(scope).vault.set(gmail, {accessToken: 'ya29.b2', refreshToken: '1//r', expiresAt: Date.parse(stamp) + 3600_000});
  const caps = (await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  const read = caps.find(item => item.id.includes('messages-get')), send = caps.find(item => item.id.includes('messages-send'));
  const repoCap = (await call('GET', '/v1/capabilities?appId=github')).body.capabilities[0];
  let counter = 0;
  const agent = async (token, method, params) => {
    const response = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id: `r${++counter}`, method, params})});
    return {status: response.status, body: await response.json()};
  };
  const mint = async () => (await call('POST', '/v1/users/u1/agent-tokens', {name: 'Helper', bindings: [{accountRef: gmail, capabilityId: read.id}, {accountRef: gmail, capabilityId: send.id}],
    proxy: [{accountRef: gmail, rows: ['group:gmail.labels.read', 'group:gmail.labels.manage']}], requestable: [{capabilityId: repoCap.id}]})).body;
  /** A GitHub sign-in through the real path for u1, stopped before confirm. */
  const signIn = async ({session = null, level} = {}) => {
    const created = session ?? (await call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body, binding = `browser-${created.id}-binding`;
    app.sessions.claim(created.id, secretOf(created.connectUrl), binding);
    const started = app.sessions.start(created.id, binding, undefined, level), url = new URL(started.authorizationUrl);
    sim.scope = (url.searchParams.get('scope') || '').split(' ').filter(Boolean).join(',');
    const back = await app.sessions.callback('github', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
    return {...back, id: created.id, binding, confirm: () => app.sessions.confirm(created.id, binding, back.finish)};
  };
  return {app, sim, dev, scope, key, call, repo, agent, mint, repoCap, signIn, advance: ms => { now += ms; }};
}

/** A browser cookie jar with real path rules (RFC 6265 5.1.4): kept by name and Path, every matching path sent, most specific first. */
function pathBrowser(origin) {
  const jar = new Map();
  let csrf = null;
  const under = (cookiePath, requestPath) => requestPath === cookiePath || (requestPath.startsWith(cookiePath) && (cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/'));
  const remember = line => {
    const [pair, ...attributes] = line.split(';').map(part => part.trim()), at = pair.indexOf('='), name = pair.slice(0, at), value = pair.slice(at + 1);
    const cookiePath = attributes.find(item => /^path=/i.test(item))?.slice(5) || '/';
    if (attributes.some(item => /^max-age=0$/i.test(item))) jar.delete(`${name}\0${cookiePath}`); else jar.set(`${name}\0${cookiePath}`, {name, value, path: cookiePath});
  };
  return {
    /** What a page on another 127.0.0.1 port can do: set a cookie by name on any path, without knowing anything. */
    plant(name, value, cookiePath = '/') { jar.set(`${name}\0${cookiePath}`, {name, value, path: cookiePath}); },
    value(name, cookiePath) { return jar.get(`${name}\0${cookiePath}`)?.value; },
    async call(method, route, body, headers = {}) {
      const requestPath = new URL(route, origin).pathname;
      const cookie = [...jar.values()].filter(item => under(item.path, requestPath)).sort((a, b) => b.path.length - a.path.length).map(item => `${item.name}=${item.value}`).join('; ');
      const response = await fetch(`${origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(cookie ? {Cookie: cookie} : {}),
        ...(body !== undefined ? {'Content-Type': 'application/json', Origin: origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      const setCookies = response.headers.getSetCookie();
      for (const line of setCookies) remember(line);
      const text = await response.text();
      let parsed = null;
      try { parsed = JSON.parse(text); } catch { parsed = text; }
      if (typeof parsed?.csrf === 'string') csrf = parsed.csrf;
      return {status: response.status, body: parsed, setCookies, location: response.headers.get('location')};
    },
  };
}

test('secrets-1: a wider sign-in waits at the upgrade card; refused without it and then closed, it is revoked at a token-scoped provider once', async t => {
  const s = await setup(t);
  const revokes = () => s.sim.calls.filter(line => line.startsWith('DELETE https://api.github.com/applications/')).length;
  // F10.7: the narrower account declines gist; the wider sign-in grants the whole full level.
  s.sim.omit = ['gist'];
  const narrow = await s.signIn();
  s.sim.omit = [];
  const wide = await s.signIn();
  narrow.confirm();
  const before = revokes();
  // F10.4 (T7): the wider sign-in is an upgrade of the account just confirmed; without the card nothing changes.
  assert.throws(() => wide.confirm(), {code: 'confirm_required'});
  assert.equal(revokes(), before, 'a refused confirm drops nothing');
  await s.app.sessions.close(wide.id, wide.binding);
  await s.app.sessions.settled();
  assert.equal(revokes() - before, 1, 'the dropped token was revoked at GitHub');
  assert.equal(s.repo().list('connections').filter(item => item.appId === 'github').length, 1, 'the existing account stays as it was');
});

test('ROB-3: "Not this account" never reopens a link the developer cancelled while the account was being dropped', async t => {
  const s = await setup(t);
  const back = await s.signIn();
  assert.equal((await s.call('GET', `/v1/connect-sessions/${back.id}`)).body.state, 'awaiting_confirmation');
  s.sim.revokeGate = new Promise(resolve => { s.sim.releaseRevoke = resolve; });
  const rejecting = s.app.sessions.reject(back.id, back.binding);
  await new Promise(resolve => setTimeout(resolve, 20));
  const cancelled = await s.call('POST', `/v1/connect-sessions/${back.id}/cancel`, {});
  assert.equal(cancelled.body.state, 'cancelled');
  s.sim.releaseRevoke(); s.sim.revokeGate = null;
  assert.equal((await rejecting).state, 'cancelled', 'the turn-down reports how the link ended');
  assert.equal((await s.call('GET', `/v1/connect-sessions/${back.id}`)).body.state, 'cancelled', 'the developer\'s cancel stands');
  assert.throws(() => s.app.sessions.start(back.id, back.binding), {code: 'already_finished'}, 'the cancelled link starts no sign-in');
});

/** Slack keeps one user token per person per app and adds scopes to it on a repeat authorization (the review's assumption). */
class StableSlack extends SlackSimulator {
  constructor(options) { super(options); this.stable = {}; this.revoked = []; }
  handle(req) {
    if (req.url === 'https://slack.com/api/auth.revoke') this.revoked.push(new URLSearchParams(req.body).get('token'));
    const out = super.handle(req);
    if (req.url === 'https://slack.com/api/oauth.v2.access' && out.data?.ok && out.data.authed_user) {
      const issued = out.data.authed_user.access_token, entry = this.access.get(issued);
      this.access.delete(issued);
      const stable = this.stable[entry.account] ??= issued, prior = this.access.get(stable)?.scopes ?? [];
      this.access.set(stable, {...entry, scopes: [...new Set([...prior, ...entry.scopes])]});
      out.data.authed_user.access_token = stable;
    }
    return out;
  }
}
/** A developer's own Slack app through the relay, in one development environment. */
async function slackSetup(t, Simulator = StableSlack) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review-b2-slack-'));
  const sim = new Simulator({clientId: 'dev-slack-client', clientSecret: 'dev-slack-secret', clock: Date.now});
  const app = await createDeveloperApp({dataRoot: root, port: 0, relay: {base: 'https://connect.example.com', appsReady: true}, request: async req => sim.request(req)});
  t.after(async () => { await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev), key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: response.status === 204 ? null : await response.json()};
  };
  const {providerApp} = (await call('POST', '/v1/provider-apps', {providerId: 'slack', clientId: 'dev-slack-client', clientSecret: 'dev-slack-secret', consentScreenName: 'Acme Agent'})).body;
  assert.equal((await call('PUT', '/v1/environment/apps/slack', {providerApp: providerApp.id, enabled: true})).status, 200);
  // F10.7: Slack signs in at full (version 2); a narrower sign-in unticks an optional box (`omit`).
  sim.userOptional = new Set(['files:read']);
  const signIn = async (externalUserId, {omit = []} = {}) => {
    const created = (await call('POST', '/v1/connect-sessions', {externalUserId, appId: 'slack'})).body, binding = `browser-${created.id}-binding`;
    app.sessions.claim(created.id, secretOf(created.connectUrl), binding);
    const started = app.sessions.start(created.id, binding), consent = sim.consent(started.authorizationUrl, {account: 'a', grant: omit.length ? {omit} : 'all'});
    const back = await app.sessions.callback('slack', {state: consent.state, code: consent.code, flowId: started.flowId}, providerApp.id);
    return {...back, id: created.id, binding, confirm: () => app.sessions.confirm(created.id, binding, back.finish)};
  };
  return {app, sim, call, signIn, vault: () => app.stores.open(scope).vault, repo: () => app.stores.open(scope).repository};
}

for (const ending of ['close', 'reject', 'wider, closed at the card', 'wider, confirm refused', 'another user disconnects', 'another user is deleted']) {
  test(`SIGNIN-1: ${ending} never revokes the token u1's live Slack account still holds`, async t => {
    const s = await slackSetup(t);
    // Both sign-ins wait on their confirm screens together for 'wider, confirm refused'; otherwise the first is live first.
    const NARROW = {omit: ['files:read']};
    const first = await s.signIn('u1', NARROW), together = ending === 'wider, confirm refused' ? await s.signIn('u1') : null;
    const live = first.confirm().result.accountRef, token = s.vault().get(live).accessToken;
    const second = together ?? (ending.startsWith('another user') ? await s.signIn('u2', NARROW) : await s.signIn('u1', ending.startsWith('wider') ? {} : NARROW));
    if (ending === 'close') await s.app.sessions.close(second.id, second.binding);
    if (ending === 'reject') await s.app.sessions.reject(second.id, second.binding);
    // F10.4 (T7): a wider sign-in waits at the upgrade card. Closed there, its sign-in is dropped; a confirm without the card changes nothing.
    if (ending === 'wider, closed at the card') { assert.ok(s.app.sessions.view(second.id, second.binding, undefined, second.finish).upgrade); await s.app.sessions.close(second.id, second.binding); }
    if (ending === 'wider, confirm refused') assert.throws(() => second.confirm(), {code: 'confirm_required'});
    if (ending.startsWith('another user')) {
      const theirs = second.confirm().result.accountRef;
      assert.equal(s.vault().get(theirs).accessToken, token, 'the same Slack person, the same token');
      const done = ending.endsWith('disconnects') ? await s.call('POST', `/v1/users/u2/accounts/${theirs}/disconnect`, {}) : await s.call('DELETE', '/v1/users/u2');
      assert.ok(done.status < 300, JSON.stringify(done.body));
    }
    await s.app.sessions.settled();
    assert.equal(s.sim.revoked.includes(token), false, 'the live token was never sent to auth.revoke');
    assert.equal((await s.call('POST', `/v1/users/u1/accounts/${live}/check`)).body.status, 'ready', 'u1\'s account still works');
  });
}

test('SIGNIN-1: a token no other account holds is still revoked when its sign-in is dropped', async t => {
  const s = await slackSetup(t, SlackSimulator);
  const back = await s.signIn('u1'), pending = s.repo().get('connectSessions', back.id).pendingAccountRef, token = s.vault().get(pending).accessToken;
  await s.app.sessions.close(back.id, back.binding);
  await s.app.sessions.settled();
  assert.equal(s.sim.access.has(token), false, 'Slack revoked the dropped token');
});

test('SIGNIN-1: a renewal that replaces u1\'s token never revokes the old one while u2\'s account still holds it', async t => {
  // F10.7: the wider sign-ins above now wait at the card, so none of them merges a new token into a live account. Here a renewal
  // does: u1 and u2 hold the same Slack token, then Slack gives u1 a new one, and the old one must stay with u2.
  const s = await slackSetup(t), NARROW = {omit: ['files:read']};
  const mine = (await s.signIn('u1', NARROW)).confirm().result.accountRef, token = s.vault().get(mine).accessToken;
  const theirs = (await s.signIn('u2', NARROW)).confirm().result.accountRef;
  assert.equal(s.vault().get(theirs).accessToken, token, 'the same Slack person, the same token');
  delete s.sim.stable.a;
  const renewal = await s.signIn('u1', NARROW);
  assert.equal(renewal.confirm().result.accountRef, mine, 'within what u1 approved: a renewal of the same account');
  assert.notEqual(s.vault().get(mine).accessToken, token, 'u1 now holds the new token');
  await s.app.sessions.settled();
  assert.equal(s.sim.revoked.includes(token), false, 'the token u2 still holds was never sent to auth.revoke');
  assert.equal((await s.call('POST', `/v1/users/u2/accounts/${theirs}/check`)).body.status, 'ready', 'u2\'s account still works');
});

test('SIGNIN-2: signing in again an account that needs reconnecting renews it in place, and a wider one upgrades it in place through the card', async t => {
  const s = await setup(t);
  const rows = async () => (await s.call('GET', '/v1/users/u1/accounts?appId=github')).body.accounts;
  const broken = async ref => { s.sim.userFails = true; await s.call('POST', `/v1/users/u1/accounts/${ref}/check`); s.sim.userFails = false; assert.equal(s.repo().get('connections', ref).status, 'reconnect_required'); };
  // F10.7: the account declines gist; signing in the same way again is within what it approved.
  s.sim.omit = ['gist'];
  const ref = (await s.signIn()).confirm().result.accountRef;
  assert.equal((await s.call('PUT', '/v1/users/u1/apps/github/default-account', {accountRef: ref})).status, 200);
  await broken(ref);
  const again = await s.signIn();
  assert.equal(again.confirm().result.accountRef, ref, 'the same identity is the same account');
  assert.deepEqual((await rows()).map(row => [row.accountRef, row.status, row.isDefault]), [[ref, 'ready', true]], 'never a second row; the default stays put');
  await broken(ref);
  s.sim.omit = [];
  const wider = await s.signIn();
  const card = s.app.sessions.view(wider.id, wider.binding, undefined, wider.finish).upgrade;
  assert.ok(card, 'T7 sees the held account whatever its health: the wider sign-in is an upgrade, with its card');
  assert.throws(() => wider.confirm(), {code: 'confirm_required'});
  assert.equal(s.app.sessions.confirm(wider.id, wider.binding, wider.finish, {confirmRows: card.etag}).result.accountRef, ref);
  assert.deepEqual((await rows()).map(row => [row.accountRef, row.status, row.isDefault]), [[ref, 'ready', true]], 'one account, upgraded in place');
});

test('SIGNIN-3: Fabric\'s shared Notion app is not offered while it cannot sign anyone in', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review-b2-notion-'));
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: {notion: {clientId: 'n-client', clientSecret: 'n-secret', relayReady: true}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), prod = app.registry.createEnvironment({projectId: project.id, kind: 'production'}, app.stores);
  app.registry.enableProduction(prod.id);
  for (const environment of [dev, prod]) {
    const key = app.keys.mint({environmentId: environment.id, preset: 'full'}).token;
    const response = await fetch(`${app.origin}/v1/connect-sessions`, {method: 'POST', headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify({externalUserId: 'u1', appId: 'notion'})});
    assert.equal(response.status, 422, environment.kind);
    assert.equal((await response.json()).error.code, 'setup_required', environment.kind);
    const any = await (await fetch(`${app.origin}/v1/connect-sessions`, {method: 'POST', headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify({externalUserId: 'u1'})})).json();
    app.sessions.claim(any.id, secretOf(any.connectUrl), `browser-${any.id}-binding`);
    assert.equal(app.sessions.view(any.id, `browser-${any.id}-binding`).apps.some(item => item.id === 'notion'), false, `${environment.kind}: the page does not offer it`);
  }
});

test('SIGNIN-4: one link keeps one live sign-in, starts a bounded number, and expired sign-in routes leave the registry', async t => {
  const s = await setup(t);
  const created = (await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body, binding = `browser-${created.id}-binding`;
  s.app.sessions.claim(created.id, secretOf(created.connectUrl), binding);
  const routes = () => s.app.registry.list('flowRoutes').filter(route => route.environmentId === s.dev.id).length;
  const starts = [];
  for (let i = 0; i < 5; i++) starts.push(s.app.sessions.start(created.id, binding));
  assert.equal(routes(), 1, 'one route per link'); assert.equal(s.repo().list('oauthFlows').length, 1, 'one flow per link');
  const first = new URL(starts[0].authorizationUrl).searchParams.get('state');
  await assert.rejects(s.app.sessions.callback('github', {state: first, code: 'abc', flowId: starts[0].flowId}), {code: 'invalid_state'}, 'an earlier sign-in of the link is over');
  for (let i = 5; i < START_LIMIT; i++) s.app.sessions.start(created.id, binding);
  assert.throws(() => s.app.sessions.start(created.id, binding), {code: 'rate_limited'});
  s.advance(10 * 60_000 + ROUTE_GRACE_MS + 1000);
  await s.app.sessions.sweep();
  assert.equal(routes(), 0, 'the minute sweep removed the expired route');
});

test('ISO-5 and ROB-6: a link that ends unopened, or long past its end, leaves no route, and the sweep opens no environment for it', async t => {
  const s = await setup(t);
  const link = async (extra = {}) => (await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github', ...extra})).body;
  const route = id => s.app.registry.get('sessionRoutes', id);
  const unopened = await link();
  assert.equal((await s.call('POST', `/v1/connect-sessions/${unopened.id}/cancel`, {})).body.state, 'cancelled');
  assert.equal(route(unopened.id), null, 'a cancelled link nobody opened has no route');
  const opened = await link(), binding = `browser-${opened.id}-binding`;
  s.app.sessions.claim(opened.id, secretOf(opened.connectUrl), binding);
  await s.call('POST', `/v1/connect-sessions/${opened.id}/cancel`, {});
  assert.equal(s.app.sessions.view(opened.id, binding).state, 'cancelled', 'an open page still says how its link ended');
  const short = await link({expiresInSeconds: 60}), long = await link();
  s.advance(60_000 + ROUTE_GRACE_MS + 1000);
  s.app.stores.closeAll();
  const touched = [], open = s.app.stores.open.bind(s.app.stores);
  s.app.stores.open = scope => { touched.push(scope.environmentId); return open(scope); };
  try { await s.app.sessions.sweep(); } finally { s.app.stores.open = open; }
  assert.equal(route(short.id), null, 'the expired link\'s route is gone');
  assert.ok(route(long.id), 'a link still inside its time keeps its route');
  assert.deepEqual(touched, [], 'no environment was opened to prune routes');
});

test('agent-3 (routes): an agent\'s withdrawn account request leaves no link route behind', async t => {
  const s = await setup(t);
  const token = (await s.mint()).token, params = {appId: 'github', capabilityId: s.repoCap.id, definitionHash: s.repoCap.definitionHash, args: {owner: 'o', repo: 'r'}};
  const routes = () => s.app.registry.list('sessionRoutes').length, baseline = routes();
  const asked = (await s.agent(token, 'calls.create', params)).body.result;
  assert.equal(asked.status, 'awaiting_connection'); assert.equal(routes(), baseline + 1);
  assert.equal((await s.agent(token, 'calls.cancel', {callId: asked.id})).body.result?.status, 'cancelled');
  assert.equal(routes(), baseline, 'the closed request\'s link route is gone');
});

test('authz-4: a key that may not read sessions gets the same answer from /link for any id', async t => {
  const s = await setup(t);
  const existing = (await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body.id;
  for (const scopes of [['connect:approve'], ['connect:manage']]) {
    const narrow = s.app.keys.mint({environmentId: s.dev.id, scopes}).token;
    const known = await s.call('POST', `/v1/connect-sessions/${existing}/link`, {}, narrow);
    const unknown = await s.call('POST', `/v1/connect-sessions/cs_${'a'.repeat(26)}/link`, {}, narrow);
    const answer = ({status, body}) => [status, body?.error?.code, body?.error?.message];
    assert.deepEqual(answer(known), answer(unknown), scopes[0]);
    assert.equal(known.status, 404, scopes[0]);
  }
});

test('BRW-2: a session cookie planted from another 127.0.0.1 port is expired, so the link keeps working', async t => {
  const s = await setup(t);
  const created = (await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body, id = created.id, own = `/connect/${id}`;
  const person = pathBrowser(s.app.origin);
  person.plant('fabric_t_session', 'planted-by-another-port');
  person.plant('fabric_t_finish', 'planted-too', '/connect');
  const claimed = await person.call('POST', `${own}/v1/claim`, {secret: secretOf(created.connectUrl)});
  assert.equal(claimed.status, 200);
  assert.ok(claimed.setCookies.includes('fabric_t_session=; Path=/; Max-Age=0'), 'the claim expires the planted copy');
  assert.equal(person.value('fabric_t_finish', '/connect'), undefined);
  const view = await person.call('GET', `${own}/v1/view`);
  assert.equal(view.status, 200, JSON.stringify(view.body)); assert.equal(view.body.state, 'opened');
  // Planted again while the page is open: the refusal expires it and never Fabric's own cookie; the next request works.
  person.plant('fabric_t_session', 'planted-again');
  const refused = await person.call('GET', `${own}/v1/view`);
  assert.equal(refused.status, 400);
  assert.ok(refused.setCookies.includes('fabric_t_session=; Path=/; Max-Age=0'));
  assert.equal(refused.setCookies.some(line => line.includes(`Path=${own};`)), false, 'Fabric\'s own cookie is never expired');
  assert.equal((await person.call('GET', `${own}/v1/view`)).status, 200);
  // Another local app's cookies, nameless or repeated, are not Fabric's to refuse.
  const mine = person.value('fabric_t_session', own);
  assert.equal((await person.call('GET', `${own}/v1/view`, undefined, {Cookie: `justavalue; theme=a; theme=b; fabric_t_session=${mine}`})).status, 200);
  // The link is not burned: the same browser signs in, and a flow cookie planted on the callback's path is expired too.
  const started = await person.call('POST', `${own}/v1/start`, {});
  assert.equal(started.status, 200, JSON.stringify(started.body));
  const url = new URL(started.body.authorizationUrl), back = `/api/oauth/github/callback?${new URLSearchParams({state: url.searchParams.get('state'), code: 'abc'})}`;
  s.sim.scope = (url.searchParams.get('scope') || '').split(' ').filter(Boolean).join(',');
  person.plant('fabric_t_oauth', 'planted-flow');
  const blocked = await person.call('GET', back);
  assert.equal(blocked.status, 400);
  assert.ok(blocked.setCookies.includes('fabric_t_oauth=; Path=/; Max-Age=0'));
  const finished = await person.call('GET', back);
  assert.equal(finished.status, 303); assert.equal(finished.location, `${own}/finish`);
});

test('the sign-in callback never echoes an internal error code', async t => {
  const s = await setup(t);
  const callback = s.app.sessions.callback;
  s.app.sessions.callback = async () => { throw Object.assign(new Error('This environment has work in flight and cannot close.'), {code: 'pinned', status: 409}); };
  try {
    const response = await fetch(`${s.app.origin}/api/oauth/github/callback?state=x&code=c`, {redirect: 'manual'});
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), {error: {code: 'invalid_state', message: INVALID_STATE}});
  } finally { s.app.sessions.callback = callback; }
});

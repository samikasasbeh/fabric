import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';

// F03.4 security review fixes: the confirming browser must be the one that came back from the provider; a planted
// session cookie never becomes a binding; suspended customers serve no page or sign-in; a sign-in never outlives its
// link; the same account signed in again carries the new credential's facts.
async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review-'));
  const sim = {tokens: new Map(), next: {id: 7, login: 'octo'}, issued: 0, noRefresh: false};
  const request = async req => {
    if (req.url === 'https://github.com/login/oauth/access_token') { const token = `gho_${++sim.issued}`; sim.tokens.set(token, sim.next); return {status: 200, headers: {}, data: {access_token: token, token_type: 'bearer', scope: 'read:user,repo'}}; }
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: sim.tokens.get(String(req.headers.Authorization).slice(7))};
    if (req.url === 'https://oauth2.googleapis.com/token') { const token = `ya29.${++sim.issued}`; sim.tokens.set(token, sim.next); return {status: 200, headers: {}, data: {access_token: token, ...(sim.noRefresh ? {} : {refresh_token: `1//r${sim.issued}`}), token_type: 'Bearer', expires_in: sim.noRefresh ? 1800 : 3600, scope: sim.scope}}; }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') { const who = sim.tokens.get(String(req.headers.Authorization).slice(7)); return {status: 200, headers: {}, data: {sub: who.id, email: who.email, name: who.name}}; }
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) return {status: 200, headers: {}, data: {emailAddress: sim.tokens.get(String(req.headers.Authorization).slice(7)).email}};
    throw new Error(`unexpected request ${req.url}`);
  };
  let now = Date.UTC(2026, 9, 13, 12);
  const app = await createDeveloperApp({dataRoot: root, port: 0, clock: () => now, request, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}, google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const link = async (externalUserId, extra = {}) => {
    const created = await (await fetch(`${app.origin}/v1/connect-sessions`, {method: 'POST', headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify({externalUserId, appId: 'github', ...extra})})).json();
    return {id: created.id, secret: new URL(created.connectUrl).hash.slice(3)};
  };
  // A browser with its own cookie jar, talking to Fabric's page like connect.js does.
  const browser = () => {
    const jar = new Map();
    const remember = response => { for (const line of response.headers.getSetCookie()) { const [pair] = line.split(';'), at = pair.indexOf('='); const value = pair.slice(at + 1); if (value) jar.set(pair.slice(0, at), value); else jar.delete(pair.slice(0, at)); } };
    const cookie = () => [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
    let csrf = null;
    return {jar, async call(method, route, body) {
      const response = await fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(jar.size ? {Cookie: cookie()} : {}), ...(body !== undefined ? {'Content-Type': 'application/json', Origin: app.origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      remember(response);
      const type = response.headers.get('content-type') || '', parsed = type.includes('json') ? await response.json() : await response.text();
      if (typeof parsed?.csrf === 'string') csrf = parsed.csrf;
      return {status: response.status, headers: response.headers, body: parsed};
    }};
  };
  return {app, org, dev, link, browser, sim, scope: app.registry.scopeOf(dev), advance: ms => { now += ms; }};
}
const stateOf = url => new URL(url).searchParams.get('state');

test('a sign-in finished in someone else\'s browser can never be confirmed by the link\'s own browser (login CSRF)', async t => {
  const {app, link, browser} = await setup(t);
  const {id, secret} = await link('attacker-user');
  const attacker = browser(), victim = browser();
  await attacker.call('POST', `/connect/${id}/v1/claim`, {secret});
  const started = (await attacker.call('POST', `/connect/${id}/v1/start`, {})).body;
  // The flow cookie is planted in the victim's browser (any 127.0.0.1 port can set it), and the victim consents.
  victim.jar.set('fabric_t_oauth', attacker.jar.get('fabric_t_oauth'));
  const back = await victim.call('GET', `/api/oauth/github/callback?state=${encodeURIComponent(stateOf(started.authorizationUrl))}&code=abc`);
  assert.equal(back.status, 303);
  assert.ok(victim.jar.get('fabric_t_finish'), 'the finish value went to the browser that came back');
  // The link's own browser cannot even see which account the other browser signed in with.
  const peek = (await attacker.call('GET', `/connect/${id}/v1/view`)).body;
  assert.equal(peek.state, 'awaiting_confirmation'); assert.equal(peek.finishElsewhere, true); assert.equal(peek.pendingAccount, undefined);
  assert.equal(JSON.stringify(peek).includes('octo'), false, 'no name of the victim\'s account');
  const refused = await attacker.call('POST', `/connect/${id}/v1/confirm`, {});
  assert.equal(refused.status, 403); assert.equal(refused.body.error.code, 'finish_mismatch');
  assert.equal((await victim.call('POST', `/connect/${id}/v1/confirm`, {})).body.error.code, 'not_found', 'nor can the victim\'s browser, which never opened the link');
  assert.equal(app.stores.open(app.registry.scopeOf(app.registry.list('environments')[0])).repository.list('connections').filter(item => item.status === 'ready').length, 0, 'no account was activated');
});

test('the normal path still confirms in one browser, and the finish value is spent', async t => {
  const {link, browser} = await setup(t);
  const {id, secret} = await link('aura-user-1');
  const person = browser();
  await person.call('POST', `/connect/${id}/v1/claim`, {secret});
  const started = (await person.call('POST', `/connect/${id}/v1/start`, {})).body;
  const back = await person.call('GET', `/api/oauth/github/callback?state=${encodeURIComponent(stateOf(started.authorizationUrl))}&code=abc`);
  const line = back.headers.getSetCookie().find(item => item.startsWith('fabric_t_finish='));
  for (const attribute of ['HttpOnly', 'SameSite=Strict', `Path=/connect/${id};`]) assert.ok(line.includes(attribute), `${attribute} in ${line}`);
  assert.equal((await person.call('POST', `/connect/${id}/v1/confirm`, {})).body.state, 'connected');
  assert.equal(person.jar.has('fabric_t_finish'), false, 'the finish cookie is cleared');
});

test('a session cookie the browser already carried never becomes the binding of a first claim (fixation)', async t => {
  const {app, link, browser} = await setup(t);
  const {id, secret} = await link('aura-user-1');
  const planted = 'p'.repeat(43), person = browser();
  person.jar.set('fabric_t_session', planted);
  assert.equal((await person.call('POST', `/connect/${id}/v1/claim`, {secret})).status, 200);
  assert.notEqual(person.jar.get('fabric_t_session'), planted, 'Fabric replaced it with its own fresh value');
  assert.throws(() => app.sessions.view(id, planted), {code: 'not_found'}, 'the planted value opens nothing');
  // The same browser coming back with Fabric's value is recognised; a different value is another browser.
  assert.equal((await person.call('POST', `/connect/${id}/v1/claim`, {secret})).status, 200);
  assert.equal((await person.call('GET', `/connect/${id}/v1/view`)).body.state, 'opened');
  const stranger = browser(); stranger.jar.set('fabric_t_session', planted);
  assert.equal((await stranger.call('POST', `/connect/${id}/v1/claim`, {secret})).body.error.code, 'session_in_use');
});

test('a suspended environment or organization serves no Connect page and finishes no sign-in', async t => {
  const {app, org, dev, link, browser} = await setup(t);
  const one = await link('u1'), two = await link('u2');
  const person = browser();
  await person.call('POST', `/connect/${one.id}/v1/claim`, {secret: one.secret});
  const started = (await person.call('POST', `/connect/${one.id}/v1/start`, {})).body;
  for (const [collection, id] of [['environments', dev.id], ['organizations', org.id]]) {
    app.registry.setStatus(collection, id, 'suspended');
    assert.equal((await browser().call('POST', `/connect/${two.id}/v1/claim`, {secret: two.secret})).body.error.code, 'not_found', collection);
    assert.equal((await person.call('GET', `/connect/${one.id}/v1/view`)).body.error.code, 'not_found', collection);
    const back = await person.call('GET', `/api/oauth/github/callback?state=${encodeURIComponent(stateOf(started.authorizationUrl))}&code=abc`);
    assert.equal(back.status, 400, collection); assert.equal(back.body.error.code, 'invalid_state');
    app.registry.setStatus(collection, id, 'active');
  }
  // Reactivated, the same sign-in finishes: refusing it while suspended did not burn it.
  assert.equal((await person.call('GET', `/api/oauth/github/callback?state=${encodeURIComponent(stateOf(started.authorizationUrl))}&code=abc`)).status, 303);
});

test('a sign-in never outlives its link, and signing the same account in again carries the new credential\'s facts', async t => {
  const {app, sim, link, scope} = await setup(t);
  const short = await link('u1', {expiresInSeconds: 120});
  app.sessions.claim(short.id, short.secret, 'browser-short-binding');
  const flow = app.sessions.start(short.id, 'browser-short-binding');
  const session = app.stores.open(scope).repository.get('connectSessions', short.id);
  const route = app.registry.get('flowRoutes', createHash('sha256').update(new URL(flow.authorizationUrl).searchParams.get('state')).digest('hex'));
  assert.equal(route.expiresAt, session.expiresAt, 'the provider flow ends when the link does, not ten minutes later');
  // Same Google account twice: the second sign-in has no refresh credential and a shorter expiry.
  const connectGmail = async binding => {
    const created = await (await fetch(`${app.origin}/v1/connect-sessions`, {method: 'POST', headers: {Authorization: `Bearer ${app.keys.mint({environmentId: scope.environmentId, preset: 'full'}).token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({externalUserId: 'u2', appId: 'gmail'})})).json();
    app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
    const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl);
    sim.scope = url.searchParams.get('scope');
    const {finish} = await app.sessions.callback('google', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
    return app.sessions.confirm(created.id, binding, finish).result.accountRef;
  };
  sim.next = {id: 'g-7', email: 'seven@example.com', name: 'Seven'};
  const ref = await connectGmail('browser-gmail-one');
  const before = app.stores.open(scope).repository.get('connections', ref);
  assert.equal(before.refreshAvailable, true);
  sim.noRefresh = true;
  assert.equal(await connectGmail('browser-gmail-two'), ref, 'one account');
  const after = app.stores.open(scope).repository.get('connections', ref);
  assert.equal(after.refreshAvailable, false, 'it no longer claims a refresh credential it does not have');
  assert.notEqual(after.expiresAt, before.expiresAt);
  // F10.4 (T7): the same scopes again is a renewal, which keeps the authorization; the new sign-in revision is what stops a
  // check started under the old credential from certifying the new one.
  assert.notEqual(after.signInRevision, before.signInRevision, 'a check started under the old credential cannot certify the new one');
  assert.equal(after.authRevision, before.authRevision, 'a renewal keeps the authorization');
});

test('a link that expires while the person is confirming activates nothing', async t => {
  const {app, link, scope, advance} = await setup(t);
  const {id, secret} = await link('u1', {expiresInSeconds: 120});
  app.sessions.claim(id, secret, 'browser-expiry-binding');
  const started = app.sessions.start(id, 'browser-expiry-binding'), url = new URL(started.authorizationUrl);
  const {finish} = await app.sessions.callback('github', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
  advance(121_000);
  assert.throws(() => app.sessions.confirm(id, 'browser-expiry-binding', finish), {code: 'expired'});
  assert.equal(app.stores.open(scope).repository.list('connections').filter(item => item.status === 'ready').length, 0);
});

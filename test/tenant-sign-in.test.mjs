import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp, strictCookies} from '../developer-server.mjs';
import {tenantDeployment} from '../lib/tenant/deployment.mjs';

// F03.4b: sign-in inside a developer environment, against a simulated GitHub. The account belongs to the end user the
// flow was started for, never to whichever browser finishes it; it activates only when that browser confirms.
async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-signin-'));
  const tokens = new Map();
  let issued = 0;
  const request = async req => {
    if (req.url === 'https://github.com/login/oauth/access_token') { const token = `gho_${++issued}`; tokens.set(token, req.body?.includes?.('code=same') ? 42 : 100 + issued); return {status: 200, headers: {}, data: {access_token: token, token_type: 'bearer', scope: 'read:user,repo'}}; }
    if (req.url === 'https://api.github.com/user') { const token = String(req.headers.Authorization).slice(7); return {status: 200, headers: {}, data: {id: tokens.get(token) ?? 1, login: 'octo', name: 'Octo'}}; }
    throw new Error(`unexpected request ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}, request});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
  app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token, scope = app.registry.scopeOf(dev);
  const api = async (method, route, body) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body ? {'Content-Type': 'application/json'} : {})}, ...(body ? {body: JSON.stringify(body)} : {})}); return response.json(); };
  const link = async (user, extra = {}) => { const created = await api('POST', '/v1/connect-sessions', {externalUserId: user, appId: 'github', ...extra}); return {id: created.id, secret: new URL(created.connectUrl).hash.slice(3)}; };
  const callback = async (state, code, cookie) => {
    const response = await fetch(`${app.origin}/api/oauth/github/callback?state=${encodeURIComponent(state)}&code=${code}`, {redirect: 'manual', headers: cookie === undefined ? {} : {Cookie: cookie}});
    const finish = response.headers.getSetCookie().find(line => line.startsWith('fabric_t_finish='))?.split(';')[0].slice('fabric_t_finish='.length);
    return {status: response.status, location: response.headers.get('location'), finish, body: response.status === 303 ? null : await response.json()};
  };
  return {app, api, link, callback, scope, env: () => app.stores.open(scope)};
}
const stateOf = url => new URL(url).searchParams.get('state');

test('the full path: link, open, start, provider callback, confirm; the account is the end user\'s and the developer reads the result', async t => {
  const {app, api, link, callback, scope, env} = await setup(t);
  const DEVELOPER = 'http://localhost:5173/done?app=x&ok=1&flag&q=a%20b&next=/inbox/1&sig=k~Z(1)';
  const {id, secret} = await link('aura-user-1', {successRedirectUri: DEVELOPER});
  app.sessions.claim(id, secret, 'browser-a-binding-value');
  const started = app.sessions.start(id, 'browser-a-binding-value');
  const url = new URL(started.authorizationUrl);
  assert.equal(url.origin, 'https://github.com'); assert.equal(url.searchParams.get('client_id'), 'gh-client');
  assert.equal(url.searchParams.get('redirect_uri'), `${app.origin}/api/oauth/github/callback`);
  const back = await callback(stateOf(started.authorizationUrl), 'abc', `fabric_t_oauth=${started.flowId}`);
  assert.equal(back.status, 303); assert.equal(back.location, `/connect/${id}/finish`); assert.match(back.finish, /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await api('GET', `/v1/connect-sessions/${id}`)).state, 'awaiting_confirmation');
  const pending = env().repository.list('connections');
  assert.equal(pending.length, 1); assert.equal(pending[0].status, 'pending_confirmation'); assert.equal(pending[0].ownership.owner.id, 'aura-user-1');
  assert.throws(() => app.sessions.confirm(id, 'browser-a-binding-value'), {code: 'finish_mismatch'}, 'the claiming browser alone is not enough');
  const confirmed = app.sessions.confirm(id, 'browser-a-binding-value', back.finish);
  assert.equal(confirmed.state, 'connected');
  // The developer's own query comes back byte for byte (no re-encoding of %20, bare flags, '/', '~' or brackets), with Fabric's result appended.
  assert.equal(confirmed.redirect, `${DEVELOPER}&fabric_session=${id}&fabric_state=connected&fabric_app=github&fabric_account=${confirmed.result.accountRef}`);
  const result = (await api('GET', `/v1/connect-sessions/${id}`)).result;
  assert.equal(result.appId, 'github');
  const account = env().repository.get('connections', result.accountRef);
  assert.equal(account.status, 'ready'); assert.equal(account.origin, undefined);
  assert.equal(env().vault.get(result.accountRef).accessToken.startsWith('gho_'), true);
  void scope; void tenantDeployment;
});

test('a callback from the wrong browser, a replay, or a login swap never creates an account for anyone else', async t => {
  const {app, link, callback, env} = await setup(t);
  const one = await link('aura-user-1'), two = await link('aura-user-2');
  app.sessions.claim(one.id, one.secret, 'browser-one-binding'); app.sessions.claim(two.id, two.secret, 'browser-two-binding');
  const startOne = app.sessions.start(one.id, 'browser-one-binding'), startTwo = app.sessions.start(two.id, 'browser-two-binding');
  // Login swap: user two's browser (its own flow cookie) finishing user one's state.
  assert.equal((await callback(stateOf(startOne.authorizationUrl), 'abc', `fabric_t_oauth=${startTwo.flowId}`)).body.error.code, 'invalid_state');
  assert.equal((await callback(stateOf(startOne.authorizationUrl), 'abc')).body.error.code, 'invalid_state', 'no flow cookie');
  assert.equal(env().repository.list('connections').length, 0);
  // The real browser still finishes (a wrong-browser attempt did not burn the route), and only once.
  const finished = await callback(stateOf(startOne.authorizationUrl), 'abc', `fabric_t_oauth=${startOne.flowId}`);
  assert.equal(finished.status, 303);
  assert.equal((await callback(stateOf(startOne.authorizationUrl), 'abc', `fabric_t_oauth=${startOne.flowId}`)).body.error.code, 'invalid_state', 'replay');
  const {createHash} = await import('node:crypto');
  assert.equal(app.registry.get('flowRoutes', createHash('sha256').update(stateOf(startOne.authorizationUrl)).digest('hex')), null, 'a used route is removed');
  const accounts = env().repository.list('connections');
  assert.equal(accounts.length, 1); assert.equal(accounts[0].ownership.owner.id, 'aura-user-1');
  // Only the browser that opened the link can confirm, and nothing confirms twice.
  assert.throws(() => app.sessions.confirm(one.id, 'browser-two-binding', finished.finish), {code: 'not_found'});
  assert.throws(() => app.sessions.confirm(two.id, 'browser-two-binding', finished.finish), {code: 'already_finished'}, 'nothing to confirm for user two');
  assert.throws(() => app.sessions.confirm(one.id, 'browser-one-binding', 'x'.repeat(43)), {code: 'finish_mismatch'});
  assert.equal(app.sessions.confirm(one.id, 'browser-one-binding', finished.finish).state, 'connected');
  assert.throws(() => app.sessions.confirm(one.id, 'browser-one-binding', finished.finish), {code: 'already_finished'});
  // Duplicate or nameless cookies are refused outright.
  // A planted copy plus the real one: a last-one-wins parser would accept it; the strict parser refuses the header.
  assert.equal((await callback(stateOf(startTwo.authorizationUrl), 'abc', `fabric_t_oauth=planted; fabric_t_oauth=${startTwo.flowId}`)).status, 400);
  assert.equal(env().repository.list('connections').filter(account => account.ownership.owner.id === 'aura-user-2').length, 0);
  assert.throws(() => strictCookies('=x'), /nameless/);
});

test('start needs the claiming browser and the session\'s own app; the same account signed in twice stays one account', async t => {
  const {app, link, callback, env} = await setup(t);
  const first = await link('aura-user-1');
  app.sessions.claim(first.id, first.secret, 'browser-one-binding');
  assert.throws(() => app.sessions.start(first.id, 'other-browser-binding'), {code: 'not_found'});
  assert.throws(() => app.sessions.start(first.id, 'browser-one-binding', 'gmail'), {code: 'invalid_request'});
  const run = async session => { const started = app.sessions.start(session.id, 'browser-one-binding'); const back = await callback(stateOf(started.authorizationUrl), 'same', `fabric_t_oauth=${started.flowId}`); return app.sessions.confirm(session.id, 'browser-one-binding', back.finish).result.accountRef; };
  const accountRef = await run(first);
  const second = await link('aura-user-1');
  app.sessions.claim(second.id, second.secret, 'browser-one-binding');
  assert.equal(await run(second), accountRef, 'same identity, same account');
  assert.equal(env().repository.list('connections').length, 1);
});

test('a quarantined account needs a real Connect session origin, and only in a developer environment', async t => {
  const {env} = await setup(t);
  const {ConnectionManager} = await import('../lib/connections.mjs');
  const {LOCAL_DEPLOYMENT} = await import('../lib/tenant/deployment.mjs');
  const user = {subjectId: 'aura-user-1', userRecordId: 'usr_' + 'a'.repeat(26)};
  const tenant = new ConnectionManager({store: env().repository, vault: env().vault, deployment: tenantDeployment(env().scope)});
  await assert.rejects(tenant.establishOAuth({tokens: {accessToken: 't'}, appId: 'github', initialStatus: 'pending_confirmation', origin: {kind: 'connect_session', sessionId: 'cs_bad'}, user}), /Invalid quarantined/);
  await assert.rejects(tenant.establishOAuth({tokens: {accessToken: 't'}, appId: 'github', initialStatus: 'pending_confirmation', origin: {kind: 'something_else'}, user}), /Invalid quarantined/);
  const local = new ConnectionManager({store: env().repository, vault: env().vault, deployment: LOCAL_DEPLOYMENT});
  await assert.rejects(local.establishOAuth({tokens: {accessToken: 't'}, appId: 'github', initialStatus: 'pending_confirmation', origin: {kind: 'connect_session', sessionId: 'cs_' + 'a'.repeat(26)}}), /Invalid quarantined/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {offeredLevels} from '../lib/access-levels.mjs';
import {signInOf} from '../lib/tenant/views.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {sharedAppId} from '../lib/tenant/provider-apps.mjs';

// F03.8 slice 2 (docs/F03.8-BUILD-MAP.md): sign-in through a developer's own provider app. Every account keeps the app
// that issued it (D8): refresh and revoke use that client, never the environment's current default; a missing secret
// refuses everything with nothing sent and no fallback to the machine's environment (N11); N9 still decides revokes.
const SHARED = {github: {clientId: 'gh-shared', clientSecret: 'gh-shared-secret'}, google: {clientId: 'g-shared', clientSecret: 'g-shared-secret'}};

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-dev-signin-'));
  const sim = {calls: [], grant: '', identity: 'octo-1'};
  const record = req => sim.calls.push({url: req.url, method: req.method || 'GET', headers: req.headers || {}, body: typeof req.body === 'string' ? req.body : ''});
  const request = async req => {
    record(req);
    if (req.url === 'https://github.com/login/oauth/access_token') {
      if (sim.tokenHeld) await sim.tokenHeld;
      if (sim.tokenFail) return {status: 400, headers: {}, data: {error: 'bad_verification_code'}};
      return {status: 200, headers: {}, data: {access_token: `gho_${randomUUID()}`, token_type: 'bearer', scope: sim.grant}};
    }
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: {id: sim.identity, login: 'octo', name: 'Octo'}};
    if (req.url.startsWith('https://api.github.com/applications/')) return {status: 204, headers: {}, data: null};
    if (req.url === 'https://oauth2.googleapis.com/token') return {status: 200, headers: {}, data: {access_token: `ya29.${randomUUID()}`, refresh_token: '1//refresh', token_type: 'Bearer', expires_in: 3600, scope: sim.grant}};
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') return {status: 200, headers: {}, data: {sub: sim.identity, email: 'one@example.com', name: 'One'}};
    if (req.url.startsWith('https://gmail.googleapis.com/') || req.url.startsWith('https://www.googleapis.com/calendar/')) return {status: 200, headers: {}, data: {emailAddress: 'one@example.com', kind: 'calendar#calendarList'}};
    if (req.url === 'https://oauth2.googleapis.com/revoke') return {status: 200, headers: {}, data: {}};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: SHARED, request});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'});
  const environment = () => {
    const project = app.registry.createProject({organizationId: org.id, name: 'Agent'}), dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
    const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token, scope = app.registry.scopeOf(dev);
    const call = async (method, route, body) => {
      const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      const text = await response.text();
      return {status: response.status, body: text ? JSON.parse(text) : null};
    };
    const register = async (clientId, providerId = 'github', secret = `${clientId}-secret`) => (await call('POST', '/v1/provider-apps', {providerId, clientId, clientSecret: secret, consentScreenName: 'Acme Agent'})).body.providerApp.id;
    const choose = (appId, providerApp) => call('PUT', `/v1/environment/apps/${appId}`, {providerApp, enabled: true});
    /** Link, open, start, come back on the started callback path, confirm. */
    const signIn = async (user, appId, {confirm = true, callback = true} = {}) => {
      const created = (await call('POST', '/v1/connect-sessions', {externalUserId: user, appId})).body, binding = `browser-${created.id}`;
      app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
      const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl), definition = definitionFor(started.providerId);
      sim.grant = (url.searchParams.get('scope') || '').split(definition.authorization.scopeSeparator).filter(Boolean).join(definition.token.scopeSeparator);
      if (!callback) return {created, started, url, binding};
      const back = await fetch(`${app.origin}${started.callbackPath}?state=${encodeURIComponent(url.searchParams.get('state'))}&code=c`, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${started.flowId}`}});
      const finish = back.headers.getSetCookie().find(line => line.startsWith('fabric_t_finish='))?.split(';')[0].slice('fabric_t_finish='.length);
      if (!confirm) return {created, started, url, back, finish, binding};
      return {...app.sessions.confirm(created.id, binding, finish).result, url, started};
    };
    return {dev, key, scope, call, register, choose, signIn, repo: () => app.stores.open(scope).repository, vault: () => app.stores.open(scope).vault};
  };
  return {app, sim, environment};
}
const tokenCalls = (sim, url) => sim.calls.filter(call => call.url === url);

test('a sign-in through the developer\'s app uses its client and address; the account keeps that app after the default changes (D8)', async t => {
  const {sim, environment} = await setup(t);
  const a = environment();
  const one = await a.register('dev-one'), two = await a.register('dev-two');
  assert.equal((await a.choose('github', one)).body.providerApp.id, one);
  const first = await a.signIn('u1', 'github');
  assert.equal(first.url.searchParams.get('client_id'), 'dev-one');
  assert.equal(first.url.searchParams.get('redirect_uri'), `${new URL(first.url.searchParams.get('redirect_uri')).origin}/api/oauth/github/apps/${one}/callback`);
  assert.match(tokenCalls(sim, 'https://github.com/login/oauth/access_token').at(-1).body, /client_id=dev-one&client_secret=dev-one-secret/);
  const account = a.repo().get('connections', first.accountRef);
  assert.deepEqual([account.status, account.providerApp], ['ready', {kind: 'developer', id: one}]);
  assert.deepEqual((await a.call('GET', `/v1/users/u1/accounts/${first.accountRef}`)).body.providerApp, {kind: 'developer', id: one});
  // The environment switches to app two, then to Fabric's shared app: nobody reconnects.
  await a.choose('github', two);
  const second = await a.signIn('u1', 'github');
  assert.equal(second.url.searchParams.get('client_id'), 'dev-two', 'new sign-ins use the new app');
  assert.notEqual(second.accountRef, first.accountRef, 'the same person through another app is a second account, never merged');
  await a.choose('github', 'shared');
  assert.equal(a.repo().get('connections', first.accountRef).status, 'ready');
  // Disconnect revokes with the issuing app's own client: GitHub's token endpoint names app one, with its basic auth.
  const before = sim.calls.length;
  const out = await a.call('POST', `/v1/accounts/${first.accountRef}/disconnect`, {});
  assert.equal(out.status, 200);
  const revoke = sim.calls.slice(before).find(call => call.url.startsWith('https://api.github.com/applications/'));
  assert.equal(revoke.url, 'https://api.github.com/applications/dev-one/token');
  assert.equal(revoke.headers.Authorization, `Basic ${Buffer.from('dev-one:dev-one-secret').toString('base64')}`);
});

test('refresh after the default changes still uses the issuing app\'s client; developer Google never revokes the grant (N9)', async t => {
  const {app, sim, environment} = await setup(t);
  const a = environment();
  const google = await a.register('dev-google.apps', 'google');
  await a.choose('gmail', google);
  const signed = await a.signIn('u1', 'gmail');
  assert.deepEqual(a.repo().get('connections', signed.accountRef).providerApp, {kind: 'developer', id: google});
  await a.choose('gmail', 'shared');
  a.vault().set(signed.accountRef, {...a.vault().get(signed.accountRef), expiresAt: Date.now() - 1000});
  const before = sim.calls.length;
  assert.equal((await a.call('POST', `/v1/users/u1/accounts/${signed.accountRef}/check`)).status, 200);
  const refresh = sim.calls.slice(before).find(call => call.url === 'https://oauth2.googleapis.com/token');
  assert.match(refresh.body, /grant_type=refresh_token/); assert.match(refresh.body, /client_id=dev-google\.apps&client_secret=dev-google\.apps-secret/);
  const mark = sim.calls.length;
  await a.call('POST', `/v1/accounts/${signed.accountRef}/disconnect`, {});
  assert.equal(sim.calls.slice(mark).some(call => call.url === 'https://oauth2.googleapis.com/revoke'), false, 'a grant-wide revoke is never sent before F10.4');
  void app;
});

test('a developer app without its secret refuses start, refresh and revoke with nothing sent and no fallback to the machine\'s environment', async t => {
  const {app, sim, environment} = await setup(t);
  const a = environment();
  const slackless = await a.register('dev-google-2', 'google');
  await a.choose('gmail', slackless);
  const signed = await a.signIn('u1', 'gmail');
  const saved = {};
  for (const name of ['FABRIC_GOOGLE_CLIENT_ID', 'FABRIC_GOOGLE_CLIENT_SECRET', 'FABRIC_GOOGLE_PUBLISHING']) { saved[name] = process.env[name]; process.env[name] = name === 'FABRIC_GOOGLE_PUBLISHING' ? 'production' : `canary-${name}`; }
  t.after(() => { for (const [name, value] of Object.entries(saved)) if (value === undefined) delete process.env[name]; else process.env[name] = value; });
  a.vault().delete(`providerApp:${slackless}`);
  a.vault().set(signed.accountRef, {...a.vault().get(signed.accountRef), expiresAt: Date.now() - 1000});
  const before = sim.calls.length;
  const refused = await a.call('POST', '/v1/connect-sessions', {externalUserId: 'u2', appId: 'gmail'});
  assert.equal(refused.status, 422, 'not even a link: the chosen app cannot sign anyone in'); assert.equal(refused.body.error.code, 'setup_required');
  assert.equal((await a.call('GET', '/v1/environment/apps')).body.apps.find(item => item.appId === 'gmail').availability.state, 'setup_required');
  const checked = await a.call('POST', `/v1/users/u1/accounts/${signed.accountRef}/check`);
  assert.equal(checked.body.error?.code ?? checked.body.status, 'setup_required');
  assert.equal(a.repo().get('connections', signed.accountRef).status, 'ready', 'a missing app secret is not the account\'s fault');
  await assert.rejects(app.runtimes.bundle(a.scope).connections.credentials(signed.accountRef), error => error.code === 'setup_required');
  const out = await a.call('POST', `/v1/accounts/${signed.accountRef}/disconnect`, {});
  assert.equal(out.status, 200); assert.equal(a.repo().get('connections', signed.accountRef).status, 'revoked', 'erased here');
  assert.equal(sim.calls.length, before, 'nothing was sent anywhere');
  assert.equal(JSON.stringify(sim.calls).includes('canary-'), false);
});

test('a sign-in comes back only on its own app\'s address; developer Google accounts do not use the shared budget', async t => {
  const {app, environment} = await setup(t);
  const a = environment();
  const own = await a.register('dev-gh-3');
  await a.choose('github', own);
  const developer = await a.signIn('u1', 'github', {callback: false});
  // The developer app's state presented on the shared address (and the reverse) is refused and not used up.
  const state = developer.url.searchParams.get('state');
  const wrong = await fetch(`${app.origin}/api/oauth/github/callback?state=${encodeURIComponent(state)}&code=c`, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${developer.started.flowId}`}});
  assert.equal(wrong.status, 400);
  const other = await fetch(`${app.origin}/api/oauth/github/apps/pa_${'b'.repeat(26)}/callback?state=${encodeURIComponent(state)}&code=c`, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${developer.started.flowId}`}});
  assert.equal(other.status, 400);
  const right = await fetch(`${app.origin}${developer.started.callbackPath}?state=${encodeURIComponent(state)}&code=c`, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${developer.started.flowId}`}});
  assert.equal(right.status, 303, 'the wrong addresses used nothing up: its own address still works');
  // Ten shared Google identities fill Fabric's shared budget; a developer Google sign-in is not counted against it.
  await a.call('POST', '/v1/connect-sessions', {externalUserId: 'filler'});
  const filler = a.repo().list('endUsers').find(item => item.subjectId === 'filler');
  for (let i = 0; i < 10; i++) a.repo().put('connections', stampOwner({id: randomUUID(), appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', providerApp: {kind: 'shared'}, identity: {id: `shared-${i}`}, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()}, {subjectId: 'filler', userRecordId: filler.id}));
  const google = await a.register('dev-google-3', 'google');
  await a.choose('gmail', google);
  const signed = await a.signIn('u1', 'gmail');
  assert.ok(signed.accountRef, 'the developer\'s own Google app has its own limits');
});

test('choosing a provider app: only this environment\'s own, for the same provider; a shared app\'s id is refused', async t => {
  const {environment} = await setup(t);
  const a = environment(), b = environment();
  const slack = await a.register('dev-slack', 'slack'), theirs = await b.register('dev-b');
  assert.equal((await a.choose('github', `pa_${'c'.repeat(26)}`)).body.error.code, 'not_found');
  const foreign = await a.choose('github', theirs), unknown = await a.choose('github', `pa_${'d'.repeat(26)}`);
  assert.deepEqual([foreign.status, foreign.body.error.code, foreign.body.error.message], [unknown.status, unknown.body.error.code, unknown.body.error.message]);
  assert.equal((await a.choose('github', slack)).body.error.code, 'provider_mismatch');
  assert.equal((await a.choose('github', sharedAppId('github'))).status, 400, 'only the literal shared selects Fabric\'s app (L6)');
  // A developer Slack app needs the relay, which is not ready here: chosen, but it cannot be turned on.
  const relayless = await a.choose('slack', slack);
  assert.equal(relayless.body.error.code, 'unavailable');
});

test('T6: a developer app\'s sign-in address is the single-owner one for the same client, apart from state, challenge and callback', async t => {
  const {app, environment} = await setup(t);
  const a = environment(), local = mkdtempSync(path.join(tmpdir(), 'fabric-dev-t6-'));
  const store = new Store({dataDir: local}), vault = new Vault(local);
  t.after(() => { store.close(); rmSync(local, {recursive: true, force: true}); });
  let compared = 0;
  for (const [providerId, clientId] of [['github', 'dev-t6-github'], ['google', 'dev-t6-google']]) {
    const id = await a.register(clientId, providerId);
    const single = new OAuth2Provider(definitionFor(providerId), {store, vault, connections: new ConnectionManager({store, vault}), clientId, clientSecret: `${clientId}-secret`, redirectUri: `http://127.0.0.1:4188/api/oauth/${providerId}/callback`, publishing: 'testing'});
    for (const entry of definitionFor(providerId).apps) {
      await a.choose(entry.appId, id);
      for (const level of offeredLevels(signInOf(entry.appId).access)) {
        const created = (await a.call('POST', '/v1/connect-sessions', {externalUserId: 't6', appId: entry.appId})).body, binding = `browser-${created.id}`;
        app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
        const b = new URL(app.sessions.start(created.id, binding, undefined, level).authorizationUrl);
        const s = new URL(single.start({appId: entry.appId, level: level === 'read' ? 'read' : 'full'}).authorizationUrl);
        const strip = url => Object.fromEntries([...url.searchParams].filter(([name]) => !['state', 'code_challenge', 'redirect_uri'].includes(name)).sort());
        assert.deepEqual(strip(b), strip(s), `${entry.appId} ${level}`);
        assert.equal(b.searchParams.get('redirect_uri'), `${app.origin}/api/oauth/${providerId}/apps/${id}/callback`);
        compared++;
      }
    }
  }
  assert.ok(compared >= 4, `compared ${compared}`);
});

// F03.8 slice 3, N8: one provider client, one environment. A client id is proven by its first full sign-in.
const back = (app, started, url) => fetch(`${app.origin}${started.callbackPath}?state=${encodeURIComponent(url.searchParams.get('state'))}&code=c`, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${started.flowId}`}});
const statusOf = async (env, id) => (await env.call('GET', '/v1/provider-apps')).body.providerApps.find(item => item.id === id)?.status;

test('N8: an attacker\'s pending registration never blocks the victim; the victim\'s first sign-in disables it', async t => {
  const {app, sim, environment} = await setup(t);
  const attacker = environment(), victim = environment(), third = environment();
  const theirs = await attacker.register('victim-client'), mine = await victim.register('victim-client');
  assert.deepEqual([await statusOf(attacker, theirs), await statusOf(victim, mine)], ['unverified', 'unverified']);
  await attacker.choose('github', theirs); await victim.choose('github', mine);
  // The attacker opened a sign-in before the victim proved the client.
  const early = await attacker.signIn('mallory', 'github', {callback: false});
  await victim.signIn('alice', 'github');
  assert.equal(await statusOf(victim, mine), 'verified');
  assert.equal(await statusOf(attacker, theirs), 'disabled');
  // The attacker's waiting sign-in comes back to a disabled app: nothing is exchanged, and the page says how it ended.
  const exchanges = tokenCalls(sim, 'https://github.com/login/oauth/access_token').length;
  const late = await back(app, early.started, early.url);
  assert.equal(late.status, 303); assert.equal(tokenCalls(sim, 'https://github.com/login/oauth/access_token').length, exchanges);
  assert.equal((await attacker.call('GET', `/v1/connect-sessions/${early.created.id}`)).body.result?.errorCode, 'provider_app_disabled');
  assert.equal(attacker.repo().list('connections').length, 0);
  // A new sign-in in the attacker's environment is refused before anything is sent.
  const before = sim.calls.length;
  assert.equal((await attacker.call('POST', '/v1/connect-sessions', {externalUserId: 'mallory', appId: 'github'})).body.error.code, 'setup_required');
  assert.equal(sim.calls.length, before);
  // A third environment cannot even register the proven client, and is not told where it lives.
  const third409 = await third.call('POST', '/v1/provider-apps', {providerId: 'github', clientId: 'victim-client', clientSecret: 'x-secret', consentScreenName: 'Other'});
  assert.deepEqual([third409.status, third409.body.error.code, third409.body.error.message], [409, 'client_already_registered', 'This client id is already registered.']);
});

test('N8: two environments racing at the token exchange: exactly one proves, the other\'s account is dropped; a failed exchange proves nothing', async t => {
  const {app, sim, environment} = await setup(t);
  const a = environment(), b = environment();
  const ida = await a.register('race-client'), idb = await b.register('race-client');
  await a.choose('github', ida); await b.choose('github', idb);
  // A failed exchange proves nothing.
  sim.tokenFail = true;
  const failed = await a.signIn('u1', 'github', {callback: false});
  await back(app, failed.started, failed.url);
  sim.tokenFail = false;
  assert.equal(await statusOf(a, ida), 'unverified'); assert.equal(app.registry.list('clientIds').filter(row => row.owner !== 'fabric').length, 0);
  // Both sign-ins wait at the provider's token endpoint, then finish together.
  const sa = await a.signIn('u1', 'github', {callback: false}), sb = await b.signIn('u2', 'github', {callback: false});
  let release; sim.tokenHeld = new Promise(resolve => { release = resolve; });
  const pa = back(app, sa.started, sa.url), pb = back(app, sb.started, sb.url);
  await new Promise(resolve => setTimeout(resolve, 50));
  sim.tokenHeld = null; release();
  await Promise.all([pa, pb]);
  const statuses = [await statusOf(a, ida), await statusOf(b, idb)].sort();
  assert.deepEqual(statuses, ['disabled', 'verified']);
  const waiting = [a, b].map(env => env.repo().list('connections').filter(record => record.status === 'pending_confirmation').length).sort();
  assert.deepEqual(waiting, [0, 1], 'only the winner has an account waiting for confirmation');
  assert.equal(app.registry.list('clientIds').filter(row => row.owner !== 'fabric').length, 1);
});

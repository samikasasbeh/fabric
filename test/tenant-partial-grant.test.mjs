import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {createHash, randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {GitHubSimulator, GoogleSimulator} from './fixtures/oauth-simulators.mjs';
import {githubV2, googleV2, GITHUB_SETTINGS} from './fixtures/auth-v2/definitions.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';
import {NOTICE_WORDS, scopesSubject} from '../lib/connection-notices.mjs';

// F10.5 partial grants in developer environments (T1, T2; docs/F10.5-BUILD-MAP.md section 4 and corrections 1 to 3). Each case
// swaps in a twin with the same client values: Fabric's shared GitHub adapter in bundle.adapters (and bound on the bundle's
// connections), or a developer's own provider app adapter in bundle.developer under `${id}:${revision}`. This is a test-only move;
// no production seam is added (open question 11). F10.7: the catalog is version 2, so the twins are the auth-v2 builders, and a case
// that needs an account from before step 7 signs it in through a version 1 twin (test/fixtures/auth-v1) first.
// The provider simulators stand in for GitHub and Google; nothing leaves the process.
const SHARED = {github: {clientId: 'gh-shared', clientSecret: 'gh-shared-secret'}};
const DEV_GOOGLE = 'dev-google.apps', MAILBOX = 'https://mail.google.com/';
const GITHUB_REVOKE = `https://api.github.com/applications/${SHARED.github.clientId}/token`, GOOGLE_REVOKE = 'https://oauth2.googleapis.com/revoke';
const sha = value => createHash('sha256').update(value).digest('hex');
// [method, path, documented scope alternatives]: the map ids are the requests, as GitHub's reviewed rows name their members.
const GITHUB = [['GET', '/user/repos', ['repo']], ['GET', '/gists', ['gist']], ['POST', '/gists', ['gist']], ['GET', '/user/orgs', ['read:org']]];

function seed(root) {
  const paths = {};
  for (const [method, route] of GITHUB) paths[route] = {...paths[route], [method.toLowerCase()]: {operationId: `${method} ${route}`.replace(/[^A-Za-z0-9]+/g, '_'),
    ...(method === 'GET' ? {} : {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {description: {type: 'string'}}}}}}}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths}}).capabilities;
  const store = new PlatformStore({root}), ids = {};
  store.put('applicationMaps', {id: 'github', appId: 'github', classifierVersion: SENSITIVITY_VERSION, operations: GITHUB.map(([method, route, requiredScopes]) => {
    const capability = compiled.find(item => item.request.method === method && item.request.url === `https://api.github.com${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    ids[`${method} ${route}`] = capability.id;
    return {id: `${method} ${route}`, capabilityId: capability.id, method, path: route, requiredScopes, sensitive: null};
  })});
  store.close();
  return ids;
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-tenant-partial-')), ids = seed(root);
  const github = new GitHubSimulator({...SHARED.github, clock: Date.now}), google = new GoogleSimulator({clientId: DEV_GOOGLE, clientSecret: `${DEV_GOOGLE}-secret`, clock: Date.now});
  const request = async req => {
    if (/^https:\/\/(api\.)?github\.com\//.test(req.url)) return github.request(req);
    if (/^https:\/\/[a-z0-9.]*google(apis)?\.com\//.test(req.url)) return google.request(req);
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: SHARED});
  t.after(async () => { await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token, linker = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body, token = key, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    const text = await response.text();
    return {status: response.status, body: text ? JSON.parse(text) : null};
  };
  const repo = () => app.stores.open(scope).repository, vault = () => app.stores.open(scope).vault, bundle = () => app.runtimes.bundle(scope);
  /** A twin of Fabric's shared GitHub adapter (version 2 unless another definition is named), with its client values and revocation policy. */
  const twin = (definition = githubV2()) => {
    const shared = bundle().adapters.get('github');
    const adapter = new OAuth2Provider(definition, {store: bundle().env.repository, vault: bundle().env.vault, connections: bundle().connections, request, clientId: shared.clientId, clientSecret: shared.clientSecret,
      redirectUri: shared.redirectUri, publishing: 'testing', consentDays: null, revocationPolicy: shared.revocationPolicy});
    bundle().adapters.set('github', adapter); bundle().connections.setOAuthProvider(adapter);
    return adapter;
  };
  /** A link claimed by one browser. signIn starts it from Fabric's page, consents at the simulator and comes back. */
  const link = (id, secret) => {
    const binding = `browser-${id}`;
    app.sessions.claim(id, secret, binding);
    const self = {id, binding,
      view: finish => app.sessions.view(id, binding, undefined, finish),
      start: confirmRows => app.sessions.start(id, binding, undefined, undefined, confirmRows),
      async signIn({grant = 'all', confirmRows, started = self.start(confirmRows), sim = github} = {}) {
        const consent = sim.consent(started.authorizationUrl, {grant});
        const back = await app.sessions.callback(started.providerId, {state: consent.state, code: consent.code, flowId: started.flowId}, started.callbackPath.match(/\/apps\/(pa_[a-z2-7]{26})\//)?.[1] ?? null);
        return {...back, started, view: () => self.view(back.finish), confirm: extra => app.sessions.confirm(id, binding, back.finish, extra)};
      }};
    return self;
  };
  const open = async (body, user = 'u1') => {
    const created = await call('POST', '/v1/connect-sessions', {externalUserId: user, ...body});
    assert.equal(created.status, 201, JSON.stringify(created.body));
    return link(created.body.id, new URL(created.body.connectUrl).hash.slice(3));
  };
  const flowOf = started => repo().get('oauthFlows', sha(new URL(started.authorizationUrl).searchParams.get('state')));
  const calls = (sim, url, method) => sim.calls.filter(req => req.url === url && (!method || req.method === method)).length;
  return {app, github, google, request, scope, key, linker, ids, call, repo, vault, bundle, twin, link, open, flowOf, calls};
}

test('a Connect sign-in on shared GitHub whose grant carries user fails with never_requested: no account, one token revoke', async t => {
  const s = await setup(t);
  s.twin();
  const link = await s.open({appId: 'github', errorRedirectUri: 'http://localhost:5173/failed'}), started = link.start();
  assert.match(new URL(started.authorizationUrl).searchParams.get('scope'), /\bgist\b/, 'the version 2 twin signs in');
  const back = await link.signIn({grant: {add: ['user']}, started});
  assert.equal(back.failed, 'never_requested');
  const session = s.repo().get('connectSessions', link.id);
  assert.deepEqual([session.state, session.result], ['failed', {errorCode: 'never_requested'}]);
  const view = link.view(), redirect = new URL(view.redirect);
  assert.equal(view.errorCode, 'never_requested');
  assert.equal(redirect.searchParams.get('error'), 'never_requested');
  assert.match(redirect.searchParams.get('error_description'), /never holds/);
  assert.match(readFileSync(new URL('../public/connect.js', import.meta.url), 'utf8'), /\bnever_requested: view =>/, 'the hosted page has words for it');
  assert.deepEqual(s.repo().list('connections'), [], 'no account and no pending account');
  assert.equal(s.calls(s.github, GITHUB_REVOKE, 'DELETE'), 1);
});

test('on a developer\'s own Google app (revocation policy provider) a refusal still sends no Google revoke', async t => {
  const s = await setup(t);
  const id = (await s.call('POST', '/v1/provider-apps', {providerId: 'google', clientId: DEV_GOOGLE, clientSecret: `${DEV_GOOGLE}-secret`, consentScreenName: 'Acme Agent'})).body.providerApp.id;
  assert.equal((await s.call('PUT', '/v1/environment/apps/gmail', {providerApp: id, enabled: true})).status, 200);
  // Correction 3: the developer's adapter lives in bundle.developer under `${id}:${revision}`; its twin keeps the app id,
  // the client values and the provider policy, which may revoke at Google only when the person asks (F10.4).
  const adapter = s.app.runtimes.developerAdapter(s.scope, id), cached = [...s.bundle().developer.keys()].find(item => item.startsWith(`${id}:`));
  assert.equal(adapter.revocationPolicy, 'provider');
  s.bundle().developer.set(cached, new OAuth2Provider(googleV2(), {store: s.bundle().env.repository, vault: s.bundle().env.vault, connections: s.bundle().connections, request: s.request, clientId: adapter.clientId,
    clientSecret: adapter.clientSecret, redirectUri: adapter.redirectUri, allowHostedRedirect: adapter.redirectUri.startsWith('https:'), publishing: adapter.publishing, consentDays: adapter.consentDays,
    revocationPolicy: 'provider', providerAppId: id}));
  const link = await s.open({appId: 'gmail'}), started = link.start();
  assert.match(new URL(started.authorizationUrl).searchParams.get('scope'), /gmail\.modify/, 'the version 2 twin signs in');
  const back = await link.signIn({grant: {add: [MAILBOX]}, started, sim: s.google});
  // The refusal is the adapter's, with the environment's store and policy; the session keeps its code.
  assert.equal(back.failed, 'never_requested');
  assert.equal(s.repo().get('connectSessions', link.id).result.errorCode, 'never_requested');
  assert.equal(s.calls(s.google, GOOGLE_REVOKE), 0);
  assert.deepEqual(s.repo().list('connections'), []);
  assert.deepEqual(s.repo().list('activity').filter(event => event.type === 'connection.scope_refused').map(event => [event.appId, event.providerGrant, event.scopes]), [['gmail', 'may_remain', [MAILBOX]]]);
});

test('T2: a Connect sign-in that declines an optional scope parks the account and passes down what it asked for and did not get', async t => {
  const s = await setup(t);
  s.twin();
  const seen = [], connections = s.bundle().connections, establish = connections.establishOAuth.bind(connections);
  connections.establishOAuth = input => { seen.push(input); return establish(input); };
  const back = await (await s.open({appId: 'github'})).signIn({grant: {omit: ['gist']}});
  assert.equal(back.failed, undefined);
  assert.deepEqual(seen.map(input => [input.initialStatus, input.origin.kind, input.grant]), [['pending_confirmation', 'connect_session', {level: 'full', missing: ['gist']}]]);
  assert.deepEqual(s.repo().list('connections').map(item => item.status), ['pending_confirmation']);
});

test('a partial grant through a Connect link: confirm stores the grant, and the person\'s page names their rows that need it', async t => {
  const s = await setup(t);
  s.twin();
  const back = await (await s.open({appId: 'github'})).signIn({grant: {omit: ['gist']}});
  assert.equal(back.failed, undefined);
  const ref = back.confirm().result.accountRef, account = s.repo().get('connections', ref);
  assert.deepEqual([account.status, account.grant], ['ready', {level: 'full', missing: ['gist']}]);
  const page = (await s.call('GET', `/v1/users/u1/apps/github?account=${ref}`)).body, notice = page.notices.find(item => item.kind === 'not_granted');
  assert.deepEqual([notice.accountRef, notice.count], [ref, 1]);
  // F10.7: the shipped rows say gist serves the gist reads, writes and deletes.
  assert.deepEqual(notice.rows.map(row => row.groupId), ['github.gists.read', 'github.gists.write', 'github.permanent.delete']);
  assert.match(notice.message, /not granted at sign-in/);
  // Correction 11: the developer's account row of a ready account gains the derived notice's attention line.
  assert.equal(page.accounts.find(row => row.accountRef === ref).attention, NOTICE_WORDS.not_granted);
  assert.equal(JSON.stringify(page.accounts).includes('missing'), false, 'the grant itself never leaves the store');
  // Another person of the environment sees nothing of it.
  const other = await s.open({appId: 'github'}, 'u2');
  await s.call('POST', `/v1/connect-sessions/${other.id}/cancel`);
  assert.deepEqual((await s.call('GET', '/v1/users/u2/apps/github')).body.notices, []);
});

test('a reconnect that is a partial renewal: the merged account carries the new sign-in\'s grant, never the old one', async t => {
  const s = await setup(t);
  s.twin();
  const ref = (await (await s.open({appId: 'github'})).signIn()).confirm().result.accountRef;
  assert.deepEqual(s.repo().get('connections', ref).grant, {level: 'full', missing: []});
  const back = await (await s.open({purpose: 'reconnect', accountRef: ref})).signIn({grant: {omit: ['gist']}});
  assert.equal('upgrade' in back.view(), false, 'within the ceiling: a renewal');
  const done = back.confirm();
  assert.deepEqual([done.result.accountRef, done.result.renewal], [ref, true]);
  const merged = s.repo().get('connections', ref);
  assert.deepEqual(merged.grant, {level: 'full', missing: ['gist']});
  assert.equal(merged.scopes.includes('gist'), false);
  assert.deepEqual(s.repo().list('activity').filter(event => event.type === 'connection.health' && event.kind === 'grant_narrowed'), [], 'the declined box explains the lost scope');
});

test('a partial renewal says the grant narrowed only for a lost scope it did not decline, and a later version 1 renewal keeps no grant', async t => {
  const s = await setup(t);
  const narrowed = () => s.repo().list('activity').filter(event => event.type === 'connection.health' && event.kind === 'grant_narrowed');
  s.twin();
  // GitHub also returns admin:repo_hook, which no level asks for: held now, and never carried into the next sign-in.
  const ref = (await (await s.open({appId: 'github'})).signIn({grant: {add: ['admin:repo_hook']}})).confirm().result.accountRef;
  assert.ok(s.repo().get('connections', ref).scopes.includes('admin:repo_hook'));
  const done = (await (await s.open({purpose: 'reconnect', accountRef: ref})).signIn({grant: {omit: ['gist']}})).confirm();
  assert.deepEqual([done.result.accountRef, done.result.renewal], [ref, true]);
  assert.deepEqual(s.repo().get('connections', ref).grant, {level: 'full', missing: ['gist']});
  // gist was declined, which the not-granted notice explains; admin:repo_hook was simply not asked for again.
  assert.deepEqual(narrowed().map(event => event.subjectKey), [scopesSubject(['admin:repo_hook'])]);
  // On a version 1 adapter, which carries the scopes held and passes no grant down: the old one does not survive.
  s.twin(v1Definition('github'));
  const again = (await (await s.open({purpose: 'reconnect', accountRef: ref})).signIn()).confirm();
  assert.deepEqual([again.result.accountRef, again.result.renewal], [ref, true]);
  assert.equal(Object.hasOwn(s.repo().get('connections', ref), 'grant'), false);
  assert.deepEqual((await s.call('GET', `/v1/users/u1/apps/github?account=${ref}`)).body.notices.filter(item => item.kind === 'not_granted'), []);
});

test('an Add access link whose added scope is declined fails with insufficient_scope and leaves the account as it was', async t => {
  const s = await setup(t);
  // Connected through a version 1 twin (read:user and repo), then read through the version 2 twin, where gist is a full-level scope.
  s.twin(v1Definition('github'));
  const ref = (await (await s.open({appId: 'github'})).signIn()).confirm().result.accountRef;
  s.twin();
  const before = s.repo().get('connections', ref), tokens = s.vault().get(ref);
  const link = await s.open({purpose: 'add_access', accountRef: ref, groupId: 'github.gists.read'}), card = link.view().upgrade;
  const started = link.start(card?.etag);
  assert.ok(new URL(started.authorizationUrl).searchParams.get('scope').split(' ').includes('gist'));
  const back = await link.signIn({grant: {omit: ['gist']}, started});
  assert.equal(back.failed, 'insufficient_scope');
  assert.equal(s.repo().get('connectSessions', link.id).result.errorCode, 'insufficient_scope');
  const after = s.repo().get('connections', ref);
  assert.deepEqual([after.authRevision, after.signInRevision, after.scopes, after.grantCeiling], [before.authRevision, before.signInRevision, before.scopes, before.grantCeiling]);
  assert.deepEqual(s.vault().get(ref), tokens);
  assert.equal(s.repo().list('connections').length, 1);
});

test('correction 1: a held call whose operation needs an optional scope sends it as a required scope, so declining it connects nothing', async t => {
  const s = await setup(t);
  // People exist once a link was made for them.
  const made = await s.open({appId: 'github'});
  await s.call('POST', `/v1/connect-sessions/${made.id}/cancel`);
  const cap = (await s.call('GET', '/v1/capabilities?appId=github')).body.capabilities.find(item => item.id === s.ids['GET /gists']);
  const held = await s.call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: cap.id, definitionHash: cap.definitionHash, args: {}, onMissingAccess: 'hold'}, s.key, {'Idempotency-Key': randomUUID()});
  assert.equal(held.status, 202, JSON.stringify(held.body));
  const sessionId = held.body.handoff.connectSessionId, minted = (await s.call('POST', `/v1/connect-sessions/${sessionId}/link`, undefined, s.linker)).body;
  s.twin(v1Definition('github'));
  const link = s.link(sessionId, new URL(minted.connectUrl).hash.slice(3)), before = link.start();
  // Version 1 signs a held call in as it always did (T6): the same scopes as a plain sign-in, and no required list.
  assert.deepEqual([new URL(before.authorizationUrl).searchParams.get('scope'), Object.hasOwn(s.flowOf(before), 'required')], ['read:user repo', false]);
  s.twin();
  const started = link.start();
  // Under the full consent policy gist is asked for anyway; the hold makes it required, which a plain sign-in does not.
  assert.ok(s.flowOf(started).required.includes('gist'));
  assert.deepEqual(s.flowOf(started).required, ['read:user', 'repo', 'gist']);
  const back = await link.signIn({grant: {omit: ['gist']}, started});
  assert.equal(back.failed, 'insufficient_scope');
  assert.deepEqual(s.repo().list('connections'), []);
});

test('correction 10: the Connect view carries the definition\'s settingsUrl, and the hosted page\'s never_requested words use it', async t => {
  const s = await setup(t);
  const script = readFileSync(new URL('../public/connect.js', import.meta.url), 'utf8'), from = script.indexOf('const appNameOf = '), to = script.indexOf('\n', script.indexOf('const wordsFor = '));
  const wordsFor = vm.runInNewContext(`${script.slice(from, to)}\nwordsFor;`, {});
  // F10.7: the shipped GitHub definition names the address; a version 1 twin, as the catalog was before, names none.
  assert.equal((await s.open({appId: 'github'})).view().settingsUrl, GITHUB_SETTINGS);
  s.twin(v1Definition('github'));
  const before = (await s.open({appId: 'github'})).view();
  assert.equal(Object.hasOwn(before, 'settingsUrl'), false, 'a version 1 definition sets none');
  assert.equal(wordsFor('never_requested', before), 'GitHub granted a permission Fabric never holds, so nothing was connected. You can remove the app in your GitHub account settings, then connect again.');
  s.twin();
  const view = (await s.open({appId: 'github'})).view();
  assert.equal(view.settingsUrl, GITHUB_SETTINGS);
  assert.equal(wordsFor('never_requested', view), `GitHub granted a permission Fabric never holds, so nothing was connected. You can remove the app at ${GITHUB_SETTINGS}, then connect again.`);
  assert.equal(wordsFor('never_requested', {}), 'The provider granted a permission Fabric never holds, so nothing was connected. You can remove the app in your provider account settings, then connect again.');
  // A link for no one app names no provider, so it names no address either.
  assert.equal(Object.hasOwn((await s.open({})).view(), 'settingsUrl'), false);
});

test('correction 2: a developer upgrade whose provider returns admin:org lists the organization row on the confirm card', async t => {
  const s = await setup(t);
  s.twin(v1Definition('github'));
  const ref = (await (await s.open({appId: 'github'})).signIn()).confirm().result.accountRef;
  s.twin();
  const link = await s.open({purpose: 'reconnect', accountRef: ref}), card = link.view().upgrade;
  assert.ok(card.rows.some(row => row.groupId === 'github.profile.read'), 'the plan asks for read:org');
  const back = await link.signIn({grant: {add: ['admin:org']}, confirmRows: card.etag});
  assert.equal(back.failed, undefined);
  assert.equal(s.repo().get('connections', s.repo().get('connectSessions', link.id).pendingAccountRef).scopes.includes('read:org'), false, 'GitHub returned the parent only');
  const confirm = back.view().upgrade;
  assert.ok(confirm.rows.some(row => row.groupId === 'github.profile.read'), JSON.stringify(confirm.rows));
  assert.equal(back.confirm({confirmRows: confirm.etag}).result.accountRef, ref);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager, catalog} from '../lib/connections.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {AppDetailService} from '../lib/app-detail.mjs';
import {offeredLevels, heldLevel, levelLabel} from '../lib/access-levels.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {PermissionManager, splitCeiling} from '../lib/permissions.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {SPLIT_ROWS, UNAVAILABLE_REASONS} from '../lib/permission-groups.mjs';
import {describeApp} from '../public/hosted-app.js';
import {LOCK_WORDS} from '../lib/row-locks.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SIMULATORS} from './fixtures/oauth-simulators.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';
import {googleV2, githubV2} from './fixtures/auth-v2/definitions.mjs';
import {fixture as signinFixture} from './fixtures/signin-fixture.mjs';

// F10.7 part g (docs/F10.7-BUILD-MAP.md section 3 part g, decisions 1 and 9, corrections 1, 2 and 13): the engine changes that go
// with full access, in the single-owner runtime. The engine cases bind the version 2 fixtures of test/fixtures/auth-v2 the way
// test/partial-grant.test.mjs does, against the provider simulators, on a designated store; the start route and account-request
// cases run on the owner's own server (test/fixtures/signin-fixture.mjs). The flip commit (parts e, f and h) adds the cases that read
// the shipped definitions and rows, and decision 6 (the Gmail delete split). Nothing leaves the process.
const G = 'https://www.googleapis.com/auth/', MODIFY = `${G}gmail.modify`, SETTINGS = `${G}gmail.settings.basic`, READONLY = `${G}gmail.readonly`, MAILBOX = 'https://mail.google.com/';
const CLIENT = {clientId: 'f107-client', clientSecret: 'f107-secret'};
const OWNER = {schemaVersion: 1, id: 'f107-owner', kind: 'local_owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'f107-owner'}};
const REDIRECT = {google: 'http://127.0.0.1:59999/api/oauth/google/callback', github: 'http://127.0.0.1:59999/api/oauth/github/callback', slack: 'https://connect.example.com/oauth/slack/4320',
  notion: 'https://connect.example.com/oauth/notion/4320'};
const URLS = {token: 'https://oauth2.googleapis.com/token', revoke: 'https://oauth2.googleapis.com/revoke', userinfo: 'https://openidconnect.googleapis.com/v1/userinfo'};
const sha = value => createHash('sha256').update(value).digest('hex');
/** The fixed words of decision 1: a record that holds a scope Fabric now never requests. Never a scope name, never a revoke. */
const NEVER_HELD = 'Google access on this account includes a permission Fabric no longer holds. Reconnect the account to drop it. Fabric did not ask Google to revoke anything.';

/** A designated single-owner store with a real ConnectionManager, one version 2 adapter and the app page service, wired as server.mjs
 *  wires them (the callback wall included). */
function harness(t, definition, {publishing = 'testing'} = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-f107-'));
  let now = Date.UTC(2026, 9, 18, 12);
  const clock = () => now, providerId = definition.providerId, sim = new SIMULATORS[providerId]({...CLIENT, clock});
  const store = new Store({dataDir: directory, clock, localAuthority: 'new'}), vault = new Vault(directory);
  const request = req => sim.request(req), connections = new ConnectionManager({store, vault, request, clock});
  const provider = new OAuth2Provider(definition, {store, vault, connections, request, clock, ...CLIENT, publishing, redirectUri: REDIRECT[providerId], allowHostedRedirect: REDIRECT[providerId].startsWith('https:')});
  connections.setOAuthProvider(provider);
  const runtime = new Runtime({store, connections, clock, ownerPrincipal: OWNER}), access = appId => provider.access(provider.app(appId));
  const service = new AppDetailService({store, runtime, catalog: () => catalog, oauthProviderFor: () => provider, accessLevels: appId => offeredLevels(access(appId)),
    accessLevelOf: connection => heldLevel(access(connection.appId), connection.scopes)});
  connections.setUpgradeGuard((previous, next, confirmed) => service.pinUnconfirmed(previous, next, confirmed));
  t.after(() => { store.close(); rmSync(directory, {recursive: true, force: true}); });
  const h = {
    sim, store, vault, connections, runtime, provider, service, caps: {}, now: () => now, advance: ms => { now += ms; },
    record: id => store.get('connections', id),
    calls: url => sim.calls.filter(req => req.url === url).length,
    audits: type => store.list('activity').filter(event => event.type === type),
    notices: (id, kind) => store.list('activity').filter(event => event.type === 'connection.health' && event.connectionId === id && event.kind === kind),
    flowOf: started => store.get('oauthFlows', sha(new URL(started.authorizationUrl).searchParams.get('state'))),
    asked: started => (new URL(started.authorizationUrl).searchParams.get('scope') || '').split(' ').filter(scope => !definition.authorization.identityScopes.includes(scope)).filter(Boolean).sort(),
    async signIn(input, options = {}) {
      const started = provider.start(input), grant = sim.consent(started.authorizationUrl, options);
      return provider.callback({state: grant.state, code: grant.code, error: grant.error, flowId: started.flowId});
    },
    decision: (id, member) => runtime.permissions.decision(store.get('connections', id), store.get('capabilities', h.caps[member])),
    proxy: (id, row) => runtime.proxyPolicy.view(id).find(entry => entry.row === `group:${row}`),
  };
  return h;
}

/** A Gmail account from before step 7, as version 1 code left it (S4.2's full-mailbox Add access): the record and its credential. */
function oldGmail(h, {scopes = ['openid', 'email', READONLY, MAILBOX], ceiling, issued = scopes, expired = false, pending = false} = {}) {
  const tokens = h.sim.issue('a', issued, {refreshable: true}), expiresAt = expired ? h.now() - 1000 : h.now() + 3_000_000;
  h.store.put('connections', {id: 'old-gmail', appId: 'gmail', providerId: 'google', driver: 'http', authMethod: 'oauth', status: 'ready', label: 'Gmail', identity: {id: 'google-sub-a', displayName: 'A'},
    allowedOrigins: ['https://gmail.googleapis.com'], scopes, ...(ceiling ? {grantCeiling: ceiling} : {}), expiresAt, refreshAvailable: true, authRevision: 'consent-old', signInRevision: 'sign-in-old',
    createdAt: '2026-10-01T10:00:00.000Z', updatedAt: '2026-10-01T10:00:00.000Z'});
  h.vault.set('old-gmail', {accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, expiresAt, scopes, ...(pending ? {identityPending: true} : {})});
  return 'old-gmail';
}

// ---- g1, decision 1 and correction 13: records that hold a scope Fabric now never requests ------------------------------------
test('g1: an unexpired credential holding a never-requested scope is not delivered; the account must reconnect and nothing is revoked', async t => {
  const h = harness(t, googleV2()), id = oldGmail(h), tokens = h.vault.get(id);
  await assert.rejects(h.connections.credentials(id), {code: 'reconnect_required', message: NEVER_HELD});
  const record = h.record(id);
  assert.deepEqual([record.status, record.error], ['reconnect_required', NEVER_HELD]);
  assert.deepEqual(h.vault.get(id), tokens, 'the credential is kept as it was, for the reconnect');
  assert.deepEqual([h.calls(URLS.token), h.calls(URLS.userinfo), h.calls(URLS.revoke)], [0, 0, 0], 'no refresh, no identity call and never a revoke');
  assert.equal(h.notices(id, 'reconnect_required').length, 1);
  assert.equal((await h.connections.check(id)).status, 'reconnect_required', 'a check meets the same wall');
  assert.equal(h.calls(URLS.revoke), 0);
});

test('g1: the refusal comes before the identity-pending path and before any refresh', async t => {
  const pending = harness(t, googleV2()), id = oldGmail(pending, {pending: true});
  await assert.rejects(pending.connections.credentials(id), {code: 'reconnect_required', message: NEVER_HELD});
  assert.deepEqual([pending.calls(URLS.userinfo), pending.calls(URLS.token)], [0, 0], 'a pending pair is not verified, let alone delivered');
  assert.equal(pending.vault.get(id).identityPending, true);
  const expired = harness(t, googleV2()), other = oldGmail(expired, {expired: true});
  await assert.rejects(expired.connections.credentials(other), {code: 'reconnect_required', message: NEVER_HELD});
  assert.equal(expired.calls(URLS.token), 0, 'an expired credential is not renewed either');
  assert.equal(expired.record(other).status, 'reconnect_required');
});

test('g1: a renewal that brings a never-requested scope back within the ceiling is not delivered or recorded', async t => {
  const h = harness(t, googleV2()), held = ['openid', 'email', MODIFY, SETTINGS];
  const id = oldGmail(h, {scopes: held, ceiling: [...held, MAILBOX].sort(), issued: [...held, MAILBOX], expired: true}), tokens = h.vault.get(id);
  await assert.rejects(h.connections.credentials(id), {code: 'reconnect_required', message: NEVER_HELD});
  assert.equal(h.calls(URLS.token), 1);
  assert.deepEqual([h.record(id).status, h.record(id).scopes], ['reconnect_required', held], 'the wider scopes are not recorded');
  assert.deepEqual(h.vault.get(id), tokens);
  assert.equal(h.calls(URLS.revoke), 0);
});

test('g1: the reconnect drops the never-requested scope with exactly one audit; version 1 records keep working until the flip', async t => {
  const h = harness(t, googleV2()), id = oldGmail(h);
  await assert.rejects(h.connections.credentials(id), {code: 'reconnect_required'});
  const started = h.provider.start({connectionId: id, appId: 'gmail', level: 'full'});
  assert.deepEqual(h.asked(started), [MODIFY, SETTINGS], 'the full level, without the mailbox');
  assert.deepEqual(h.audits('connection.scope_dropped').map(event => [event.connectionId, event.scopes]), [[id, [MAILBOX]]]);
  // A version 1 definition never refuses a scope, so a record from before step 7 is delivered as it was (T6).
  const v1 = harness(t, v1Definition('google')), old = oldGmail(v1);
  assert.equal((await v1.connections.credentials(old)).headers.Authorization, `Bearer ${v1.vault.get(old).accessToken}`);
});

// ---- g6 and correction 2: the full-upgrade flag --------------------------------------------------------------------------------
const GITHUB_DOC = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
  '/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}}, '/gists': {get: {operationId: 'listGists', responses: {200: {description: 'Gists'}}}}}};
/** Typed GitHub members named by their requests, so the proxy rows read their scopes from the map by id as decide() does. */
function seedGitHub(h) {
  const caps = Object.fromEntries(compileOpenApi({appId: 'github', document: GITHUB_DOC}).capabilities.map(cap => [cap.name, {...cap, status: 'active'}]));
  for (const cap of Object.values(caps)) h.store.put('capabilities', cap);
  h.store.put('applicationMaps', {id: 'github', operations: [['listRepos', 'GET', '/user/repos', ['repo']], ['listGists', 'GET', '/gists', ['gist']]].map(([name, method, route, requiredScopes]) =>
    ({id: `${method} ${route}`, capabilityId: caps[name].id, method, path: route, requiredScopes}))});
  Object.assign(h.caps, {repos: caps.listRepos.id, gists: caps.listGists.id});
}
/** GitHub under a consent policy that asks only for the required scopes in production. */
const githubRequired = () => ({...githubV2(), consentPolicy: {testing: 'full', production: 'required'}});
const partialGitHub = h => h.store.put('connections', {id: 'gh', appId: 'github', providerId: 'github', driver: 'http', authMethod: 'oauth', status: 'ready', label: 'GitHub', identity: {id: '1001', displayName: 'octo'},
  allowedOrigins: ['https://api.github.com'], scopes: ['read:user', 'repo'], authRevision: 'consent-1', signInRevision: 'sign-in-1', createdAt: '2026-10-11T10:00:00.000Z'});

test('g6: under a production policy the full upgrade asks for the whole full level, and its card reads the same set as the sign-in', t => {
  const h = harness(t, githubRequired(), {publishing: 'production'});
  seedGitHub(h); partialGitHub(h);
  const page = h.service.view('github');
  assert.deepEqual(page.upgrade.body, {connectionId: 'gh', level: 'full', fullUpgrade: true});
  // The shipped rows give the organization reads read:org (F10.7 part e), so the profile row turns on too.
  assert.deepEqual(page.upgrade.rows.map(row => row.groupId), ['github.profile.read', 'github.gists.read']);
  const card = h.service.upgradeFor(h.provider, page.upgrade.body), started = h.provider.start(page.upgrade.body);
  assert.deepEqual(card.scopes, ['gist', 'read:org', 'read:user', 'repo', 'workflow']);
  assert.deepEqual(h.asked(started), card.scopes, 'the card and the authorization URL use one scope set');
  assert.deepEqual(h.flowOf(started).required, ['read:user', 'repo'], 'what is required is still the level\'s required list');
  // A plain sign-in keeps the policy: production asks for what the app needs, and that is within what the account holds.
  assert.deepEqual(h.asked(h.provider.start({connectionId: 'gh', level: 'full'})), ['read:user', 'repo']);
  assert.equal(h.service.upgradeFor(h.provider, {connectionId: 'gh', level: 'full'}), null);
  // Testing asks for the whole level anyway, so the flag changes nothing there.
  const testing = harness(t, githubRequired());
  seedGitHub(testing); partialGitHub(testing);
  assert.deepEqual(testing.asked(testing.provider.start({connectionId: 'gh', level: 'full', fullUpgrade: true})), testing.asked(testing.provider.start({connectionId: 'gh', level: 'full'})));
});

test('g6: the full-upgrade flag names an account, the full level and no scopes, or nothing starts', t => {
  const h = harness(t, githubRequired(), {publishing: 'production'});
  partialGitHub(h);
  for (const input of [{appId: 'github', level: 'full', fullUpgrade: true}, {connectionId: 'gh', fullUpgrade: true}, {connectionId: 'gh', level: 'read', fullUpgrade: true},
    {connectionId: 'gh', level: 'full', scopes: ['gist'], fullUpgrade: true}, {connectionId: 'gh', level: 'full', fullUpgrade: 'yes'}, {connectionId: 'gh', level: 'full', fullUpgrade: 1}]) {
    assert.throws(() => h.provider.start(input), {code: 'invalid_input'}, JSON.stringify(input));
    assert.throws(() => h.provider.plan(input), {code: 'invalid_input'}, JSON.stringify(input));
  }
  assert.equal(h.store.list('oauthFlows').length, 0);
  assert.deepEqual(h.asked(h.provider.start({connectionId: 'gh', level: 'full', fullUpgrade: false})), ['read:user', 'repo']);
});

test('g6: the owner start route accepts the full-upgrade flag and refuses any other unknown field', async t => {
  const f = await signinFixture(t);
  const start = async body => {
    const response = await f.owned('POST', '/api/oauth/github/start', body);
    return {status: response.status, body: await response.json(), flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie') || '')?.[1]};
  };
  assert.equal((await f.callback(await start({appId: 'github'}))).location, '/?oauth=connected');
  const id = f.connections().find(connection => connection.status === 'ready').id;
  // The shipped GitHub definition is version 1 until the flip: the flag reaches plan(), which asks for the whole level anyway.
  const flagged = await start({connectionId: id, level: 'full', fullUpgrade: true}), plain = await start({connectionId: id, level: 'full'});
  assert.ok([200, 409].includes(flagged.status), JSON.stringify(flagged.body));
  assert.deepEqual([flagged.status, flagged.body.upgrade ?? null], [plain.status, plain.body.upgrade ?? null], 'the same card as the plain start');
  const refused = await start({connectionId: id, level: 'full', fullUpgrade: true, extra: 1});
  assert.deepEqual([refused.status, refused.body.error], [400, 'Only the account, label, access level, application, scopes, full upgrade and confirmed rows are accepted.']);
  assert.equal((await start({appId: 'github', fullUpgrade: true})).status, 400, 'a full upgrade names an account');
});

// ---- g7, decision 9 and correction 1: unrequested extras at a first sign-in -----------------------------------------------------
const RECORDED = JSON.parse(readFileSync(new URL('./fixtures/access/f10-3-bindings.before.json', import.meta.url), 'utf8')).maps.gmail.operations;
const FACTS = JSON.parse(readFileSync(new URL('./fixtures/access/google-method-scopes.json', import.meta.url), 'utf8')).apps.gmail.methods;
/** A full Gmail map (the proxy needs every reviewed operation), each with the scopes Google documents for it. */
const seedGmail = h => h.store.put('applicationMaps', {id: 'gmail', appId: 'gmail', operations: RECORDED.map(operation => ({...operation, requiredScopes: FACTS[operation.id]}))});

test('g7: a plain first Gmail sign-in writes no setting: the raw read rows still run at their default Allow', async t => {
  const h = harness(t, googleV2());
  seedGmail(h);
  const connection = await h.signIn({appId: 'gmail', level: 'full'});
  assert.equal(connection.status, 'ready');
  assert.deepEqual(h.store.list('permissions'), [], 'what the sign-in asked for is its card: nothing to pin');
  for (const row of ['gmail.drafts.read', 'gmail.labels.read', 'gmail.messages.read', 'gmail.messages.search']) assert.deepEqual([h.proxy(connection.id, row).mode, h.proxy(connection.id, row).source], ['allow', 'default'], row);
  assert.deepEqual(h.audits('connection.connected').map(event => event.connectionId), [connection.id]);
});

test('g7: what a first sign-in granted beyond what it asked for starts at Ask, typed and raw; what it asked for keeps its default', async t => {
  // A GitHub sign-in that does not ask for gist, while GitHub returns it anyway (an earlier authorization of the same app, say).
  const definition = githubV2();
  definition.apps[0].access.levels.full.optional = ['read:org', 'workflow'];
  const h = harness(t, definition);
  seedGitHub(h);
  const connection = await h.signIn({appId: 'github', level: 'full'}, {grant: {add: ['gist']}});
  assert.ok(h.record(connection.id).scopes.includes('gist'));
  assert.deepEqual([h.decision(connection.id, 'gists').mode, h.decision(connection.id, 'gists').policySource], ['ask', 'saved']);
  assert.deepEqual([h.proxy(connection.id, 'github.gists.read').mode, h.proxy(connection.id, 'github.gists.read').source], ['ask', 'saved']);
  assert.deepEqual([h.decision(connection.id, 'repos').mode, h.decision(connection.id, 'repos').policySource], ['allow', 'default']);
  assert.deepEqual([h.proxy(connection.id, 'github.repos.read').mode, h.proxy(connection.id, 'github.repos.read').source], ['allow', 'default']);
  assert.deepEqual(h.audits('connection.upgraded'), [], 'a first sign-in, not an upgrade');
  // The same sign-in that asks for gist pins nothing.
  const asked = harness(t, githubV2());
  seedGitHub(asked);
  const plain = await asked.signIn({appId: 'github', level: 'full'});
  assert.deepEqual(asked.store.list('permissions'), []);
  assert.deepEqual([asked.decision(plain.id, 'gists').mode, asked.proxy(plain.id, 'github.gists.read').mode], ['allow', 'allow']);
});

test('g7: an account request\'s first sign-in pins at Ask what the provider granted beyond what it asked for, once the owner confirms it', async t => {
  // The owner's own server on the shipped GitHub definition, with a typed gists member beside the fixture's repository members. The
  // repository read needs repo, which every full sign-in asks for, so it shows what the plan confirms. The full level asks for every
  // scope the shipped rows name, so this map says the gists read takes notifications, which no level asks for: what GitHub returns
  // from an earlier authorization of the same app.
  const f = await signinFixture(t), gists = {...compileOpenApi({appId: 'github', document: GITHUB_DOC}).capabilities.find(cap => cap.name === 'listGists'), status: 'active'};
  f.app.store.put('capabilities', gists);
  f.app.store.put('applicationMaps', {id: 'github', operations: [['GET', '/user/repos', f.read, ['repo']], ['POST', '/repos/{owner}/{repo}/issues', f.write, ['repo']], ['GET', '/gists', gists, ['notifications']]].map(([method, route, cap, requiredScopes]) =>
    ({id: `${method} ${route}`, capabilityId: cap.id, method, path: route, requiredScopes}))});
  const typed = (id, cap) => { const decision = f.app.runtime.permissions.decision(f.app.store.get('connections', id), cap); return [decision.mode, decision.policySource]; };
  const raw = (id, row) => { const entry = f.app.runtime.proxyPolicy.view(id).find(item => item.row === `group:${row}`); return [entry.mode, entry.source]; };
  const confirmed = async ({grant = 'all'} = {}) => {
    const {id} = await f.ask();
    await f.callback(await f.signIn(id), {grant});
    const pending = await f.view(id), connectionId = pending.pendingConnection.connectionId;
    assert.deepEqual(f.app.store.list('permissions').filter(item => item.connectionId === connectionId), [], 'nothing is written while the account waits');
    const done = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: pending.confirmDigest});
    assert.equal(done.body.status, 'resumed', JSON.stringify(done.body));
    await f.app.continuations.settled(id);
    return connectionId;
  };
  // GitHub returns notifications, which the sign-in did not ask for (an earlier authorization of the same app, say).
  const extra = await confirmed({grant: {add: ['notifications']}});
  assert.ok(f.app.store.get('connections', extra).scopes.includes('notifications'));
  // The typed member starts at Ask. The raw gists row keeps its default: the plan itself (gist) turns that row on, and what a sign-in
  // asked for is its card (decision 9).
  assert.deepEqual([typed(extra, gists), raw(extra, 'github.gists.read')], [['ask', 'saved'], ['allow', 'default']]);
  assert.deepEqual([typed(extra, f.read), raw(extra, 'github.repos.read')], [['allow', 'default'], ['allow', 'default']], 'what it asked for keeps its default');
  assert.equal(f.api.length, 1, 'the request itself ran on its own default');
  // A plain account-request sign-in pins nothing.
  const plain = await confirmed();
  assert.notEqual(plain, extra);
  assert.deepEqual(f.app.store.list('permissions').filter(item => item.connectionId === plain), []);
  assert.equal(f.api.length, 2);
});

// ---- the flip commit: the shipped definitions and rows (docs/F10.7-BUILD-MAP.md section 4) ---------------------------------------
const shipped = (t, providerId, options) => harness(t, definitionFor(providerId), options);
const flows = h => h.store.list('oauthFlows').length;

test('T1 at the start: a never-requested scope is refused with no flow stored; a scope outside the full level is invalid; read needs a read level', t => {
  for (const [providerId, appId, scope] of [['google', 'gmail', MAILBOX], ['google', 'gmail', `${G}gmail.metadata`], ['google', 'google-calendar', `${G}calendar`], ['github', 'github', 'user'],
    ['github', 'github', 'delete_repo'], ['slack', 'slack', 'search:read.public']]) {
    const h = shipped(t, providerId);
    assert.throws(() => h.provider.start({appId, level: 'full', scopes: [scope]}), {code: 'never_requested'}, scope);
    assert.equal(flows(h), 0, scope);
  }
  const google = shipped(t, 'google'), github = shipped(t, 'github');
  assert.throws(() => google.provider.start({appId: 'gmail', level: 'full', scopes: [READONLY]}), {code: 'invalid_scope'}, 'gmail.readonly is the read level, not the full one');
  assert.throws(() => github.provider.start({appId: 'github', level: 'full', scopes: ['user:email']}), {code: 'invalid_scope'});
  for (const [providerId, appId] of [['google', 'google-calendar'], ['github', 'github'], ['slack', 'slack'], ['notion', 'notion']]) {
    const h = shipped(t, providerId);
    assert.throws(() => h.provider.start({appId, level: 'read'}), {code: 'invalid_input'}, appId);
    assert.equal(flows(h), 0, appId);
  }
  assert.ok(google.provider.start({appId: 'gmail', level: 'read'}).authorizationUrl, 'Gmail keeps an advanced read level');
});

test('T1 at the callback: Google never revokes a grant holding the full mailbox; GitHub revokes a grant holding user once and names its settings page', async t => {
  for (const appId of ['gmail', 'google-calendar']) {
    const h = shipped(t, 'google');
    await assert.rejects(h.signIn({appId, level: 'full'}, {grant: {add: [MAILBOX]}}), error => error.code === 'never_requested' && error.providerGrant === 'may_remain', appId);
    assert.deepEqual([h.calls(URLS.revoke), h.store.list('connections').length], [0, 0], appId);
  }
  const github = shipped(t, 'github');
  await assert.rejects(github.signIn({appId: 'github', level: 'full'}, {grant: {add: ['user']}}), error => error.code === 'never_requested' && error.message.includes('https://github.com/settings/applications'));
  assert.equal(github.sim.calls.filter(req => req.method === 'DELETE' && req.url.includes('/applications/')).length, 1);
  assert.equal(github.store.list('connections').length, 0);
  // write:org grants read:org (section 5.3), so an account GitHub answers with the parent holds the full level.
  const parent = shipped(t, 'github'), connection = await parent.signIn({appId: 'github', level: 'full'}, {grant: {add: ['write:org']}});
  assert.equal(levelLabel(heldLevel(parent.provider.access(parent.provider.app('github')), parent.record(connection.id).scopes)), 'Full access');
});

test('T2 partial grants on the shipped definitions: a declined optional scope narrows the account; a missing required one connects nothing', async t => {
  const label = (h, appId, id) => levelLabel(heldLevel(h.provider.access(h.provider.app(appId)), h.record(id).scopes));
  const gmail = shipped(t, 'google'), partial = await gmail.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [SETTINGS]}});
  const notices = gmail.service.view('gmail', partial.id).notices.filter(notice => notice.kind === 'not_granted');
  assert.deepEqual([partial.status, label(gmail, 'gmail', partial.id), notices.length], ['ready', 'Partial access (1 permission not granted)', 1]);
  const none = shipped(t, 'google');
  await assert.rejects(none.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [MODIFY]}}), {code: 'insufficient_scope'});
  assert.equal(none.store.list('connections').length, 0);
  const calendar = shipped(t, 'google'), busy = await calendar.signIn({appId: 'google-calendar', level: 'full'}, {grant: {omit: [`${G}calendar.freebusy`]}});
  assert.equal(label(calendar, 'google-calendar', busy.id), 'Partial access (1 permission not granted)');
  const github = shipped(t, 'github'), narrow = await github.signIn({appId: 'github', level: 'full'}, {grant: {omit: ['read:org', 'gist', 'workflow']}});
  assert.equal(label(github, 'github', narrow.id), 'Partial access (3 permissions not granted)');
  const slack = shipped(t, 'slack');
  slack.sim.userOptional = new Set(['files:read']);
  const chat = await slack.signIn({appId: 'slack', level: 'full'}, {grant: {omit: ['files:read']}});
  assert.equal(label(slack, 'slack', chat.id), 'Partial access (1 permission not granted)');
});

test('records from before step 7 read Custom, Read-only, Partial or Pages you shared, never a level they do not hold', () => {
  const reading = (providerId, appId) => { const definition = definitionFor(providerId); return heldLevel.bind(null, (h => h)(normalize(definition, appId))); };
  const normalize = (definition, appId) => new OAuth2Provider(definition, {store: {get: () => null}, vault: {}, connections: {}, ...CLIENT}).access({appId});
  const label = (providerId, appId, scopes) => levelLabel(reading(providerId, appId)(scopes));
  assert.equal(label('google', 'gmail', ['openid', 'email', READONLY, `${G}gmail.compose`]), 'Custom', 'version 1 read and write');
  assert.equal(label('google', 'gmail', ['openid', 'email', READONLY]), 'Read-only');
  assert.equal(label('google', 'google-calendar', ['openid', 'email', `${G}calendar.calendarlist.readonly`, `${G}calendar.events`]), 'Custom');
  assert.equal(label('github', 'github', ['read:user']), 'Custom');
  assert.equal(label('github', 'github', ['read:user', 'repo']), 'Partial access (3 permissions not granted)');
  assert.equal(label('slack', 'slack', ['channels:read', 'channels:history', 'users:read', 'chat:write']), 'Custom');
  assert.equal(label('notion', 'notion', []), 'Pages you shared');
});

test('g1 on the shipped Google definition: a Gmail record holding the full mailbox is not delivered, and its reconnect drops the scope once', async t => {
  const h = shipped(t, 'google'), id = oldGmail(h);
  await assert.rejects(h.connections.credentials(id), {code: 'reconnect_required', message: NEVER_HELD});
  assert.equal(h.calls(URLS.revoke), 0);
  assert.deepEqual(h.asked(h.provider.start({connectionId: id, appId: 'gmail', level: 'full'})), [MODIFY, SETTINGS]);
  assert.deepEqual(h.audits('connection.scope_dropped').map(event => [event.connectionId, event.scopes]), [[id, [MAILBOX]]]);
});

/** One reviewed member that lacks provider access, asked for through its own row, as the app page asks for it (rows-every-app). */
const addFor = (h, appId, connectionId, groupId, scopeSets) => h.service.addAccess(h.service.app(appId), h.store.get('connections', connectionId), [{decision: {providerAccess: 'missing', scopeSets, groupId}}]);
const put = (h, id, appId, providerId, origin, scopes) => h.store.put('connections', {id, appId, providerId, driver: 'http', authMethod: 'oauth', status: 'ready', label: id, identity: {id}, allowedOrigins: [origin], scopes,
  authRevision: `consent-${id}`, signInRevision: `sign-in-${id}`, createdAt: '2026-10-11T10:00:00.000Z'});

test('Add access on the shipped definitions asks for exactly the scope a row needs, at the full level, never the full mailbox', t => {
  const google = shipped(t, 'google');
  put(google, 'mail', 'gmail', 'google', 'https://gmail.googleapis.com', ['openid', 'email', READONLY, `${G}gmail.compose`]);
  const labels = addFor(google, 'gmail', 'mail', 'gmail.labels.manage', FACTS['gmail.users.labels.create'].map(scope => [scope]));
  assert.deepEqual(labels, {addAccess: {providerId: 'google', body: {connectionId: 'mail', level: 'full', scopes: [MODIFY]}}});
  // The new delete row: gmail.modify for drafts and labels, gmail.settings.basic for filters.
  assert.deepEqual(addFor(google, 'gmail', 'mail', 'gmail.items.delete', FACTS['gmail.users.settings.filters.delete'].map(scope => [scope])).addAccess.body.scopes, [SETTINGS]);
  // A member no sign-in can use is not offered, and does not hold back the rest of its row.
  assert.deepEqual(google.service.addAccess(google.service.app('gmail'), google.store.get('connections', 'mail'), [{decision: {providerAccess: 'missing', scopeSets: [[MAILBOX]], groupId: 'gmail.permanent.delete'}},
    {decision: {providerAccess: 'missing', scopeSets: [[MODIFY]], groupId: 'gmail.items.delete'}}]).addAccess.body.scopes, [MODIFY]);
  // Testing asks for the whole full level besides.
  assert.deepEqual(google.asked(google.provider.start(labels.addAccess.body)), [MODIFY, SETTINGS]);
  const github = shipped(t, 'github');
  put(github, 'hub', 'github', 'github', 'https://api.github.com', ['read:user', 'repo']);
  assert.deepEqual(addFor(github, 'github', 'hub', 'github.gists.read', [['gist']]).addAccess.body, {connectionId: 'hub', level: 'full', scopes: ['gist']});
  const slack = shipped(t, 'slack');
  put(slack, 'chat', 'slack', 'slack', 'https://slack.com', ['channels:read', 'channels:history', 'users:read', 'chat:write']);
  assert.deepEqual(addFor(slack, 'slack', 'chat', 'slack.conversations.mark', [['im:write'], ['mpim:write']]).addAccess.body.scopes, ['im:write']);
  assert.deepEqual(addFor(slack, 'slack', 'chat', 'slack.channels.manage', [['channels:write'], ['groups:write']]).addAccess.body.scopes, ['channels:write'], 'an in-context scope, on the row it names');
});

const PROXY_TOKEN = 'proxy-token-f107';
/** A ready account whose credential the proxy can read, for proxied decisions. */
const proxied = (h, id, appId, providerId, origin, scopes) => { put(h, id, appId, providerId, origin, scopes); h.vault.set(id, {accessToken: PROXY_TOKEN, expiresAt: null, scopes}); };

test('adversarial routing on the shipped rows: watch and hooks land in a locked Never row; deleting a repository is unavailable', t => {
  const google = shipped(t, 'google');
  proxied(google, 'mail', 'gmail', 'google', 'https://gmail.googleapis.com', ['openid', 'email', MODIFY, SETTINGS]);
  seedGmail(google);
  const watch = google.runtime.proxyPolicy.decide('mail', {method: 'POST', path: '/gmail/v1/users/me/watch', body: {topicName: 'projects/x/topics/y'}});
  assert.deepEqual([watch.row, watch.mode, watch.locked, watch.executable, watch.reason], ['group:gmail.access.grant', 'deny', true, false, LOCK_WORDS]);
  const github = shipped(t, 'github');
  proxied(github, 'hub', 'github', 'github', 'https://api.github.com', ['read:user', 'repo', 'read:org', 'gist', 'workflow']);
  for (const path of ['/repos/x/y/hooks', '/repositories/9/hooks']) {
    const hook = github.runtime.proxyPolicy.decide('hub', {method: 'POST', path, body: {name: 'web', config: {url: 'https://example.invalid'}}});
    assert.deepEqual([hook.row, hook.mode, hook.locked], ['group:github.access.grant', 'deny', true], path);
  }
  for (const path of ['/repos/x/y', '/repositories/9']) {
    const removal = github.runtime.proxyPolicy.decide('hub', {method: 'DELETE', path});
    assert.deepEqual([removal.row, removal.providerAccess, removal.unavailable, removal.mode, removal.executable, removal.reason],
      ['group:github.permanent.delete', 'unavailable', 'not-requested', 'deny', false, UNAVAILABLE_REASONS['not-requested']], path);
  }
});

test('the Gmail delete split and the Slack moves, on the shipped rows', t => {
  const google = shipped(t, 'google');
  proxied(google, 'mail', 'gmail', 'google', 'https://gmail.googleapis.com', ['openid', 'email', MODIFY, SETTINGS]);
  seedGmail(google);
  const rows = Object.fromEntries(google.runtime.proxyPolicy.view('mail').map(entry => [entry.row, entry]));
  assert.deepEqual([rows['group:gmail.items.delete'].label, rows['group:gmail.items.delete'].effect, rows['group:gmail.items.delete'].defaultMode], ['Delete drafts, labels or filters', 'delete', 'ask']);
  assert.deepEqual([rows['group:gmail.permanent.delete'].label, rows['group:gmail.permanent.delete'].defaultMode], ['Permanently delete emails', 'deny']);
  // The recorded map's synthetic routes (test/fixtures/access/f10-3-bindings.before.json): each delete is a POST to <resource>/delete.
  for (const path of ['/gmail/v1/users/me/drafts/delete', '/gmail/v1/users/me/labels/delete', '/gmail/v1/users/me/settings/filters/delete']) {
    const decision = google.runtime.proxyPolicy.decide('mail', {method: 'POST', path, body: {}});
    assert.deepEqual([decision.row, decision.mode, decision.providerAccess], ['group:gmail.items.delete', 'ask', 'granted'], path);
  }
  for (const path of ['/gmail/v1/users/me/messages/delete', '/gmail/v1/users/me/threads/delete']) {
    const decision = google.runtime.proxyPolicy.decide('mail', {method: 'POST', path, body: {}});
    assert.deepEqual([decision.row, decision.providerAccess, decision.unavailable, decision.mode], ['group:gmail.permanent.delete', 'unavailable', 'not-requested', 'deny'], path);
  }
  const slack = shipped(t, 'slack'), full = definitionFor('slack').apps[0].access.levels.full;
  proxied(slack, 'chat', 'slack', 'slack', 'https://slack.com', [...full.required, ...full.optional]);
  for (const [path, reason] of [['/files.remote.share', 'not-requested'], ['/conversations.declineSharedInvite', 'bot-token-only']]) {
    const decision = slack.runtime.proxyPolicy.decide('chat', {method: 'GET', path});
    assert.deepEqual([decision.row, decision.mode, decision.unavailable], ['group:slack.admin', 'deny', reason], path);
  }
  for (const path of ['/assistant.search.context', '/assistant.search.info']) assert.equal(slack.runtime.proxyPolicy.decide('chat', {method: 'POST', path, body: {}}).unavailable, 'not-requested', path);
  // After a full sign-in "Manage channels" lacks exactly the two members only an in-context scope covers.
  const lacking = ['POST /conversations.create', 'POST /conversations.join', 'POST /conversations.leave', 'POST /usergroups.create'].filter(request => {
    const [method, path] = request.split(' ');
    return slack.runtime.proxyPolicy.decide('chat', {method, path, body: {}}).providerAccess === 'missing';
  });
  assert.deepEqual(lacking, ['POST /conversations.create', 'POST /conversations.join']);
});

test('the owner page shows each account\'s access label, and Gmail\'s advanced read-only sign-in', t => {
  const h = shipped(t, 'google');
  put(h, 'mail', 'gmail', 'google', 'https://gmail.googleapis.com', ['openid', 'email', MODIFY, SETTINGS]);
  const model = describeApp(h.service.view('gmail', 'mail'));
  assert.deepEqual(model.accounts.map(account => account.access), ['Full access']);
  assert.deepEqual(model.addReadOnlyAccount, {label: 'Advanced: read-only access', request: {path: '/api/oauth/google/start', body: {appId: 'gmail', level: 'read'}}, signIn: {providerId: 'google'}});
  assert.equal(model.accessSummary, 'Full access at sign-in. You control each permission below.');
  const calendar = describeApp(h.service.view('google-calendar'));
  assert.equal(calendar.addReadOnlyAccount, null, 'Calendar has no read level');
});

// ---- decision 6: the Gmail delete split keeps Never for existing accounts ------------------------------------------------------
const DELETES = {'gmail.users.drafts.delete': ['DELETE', '/gmail/v1/users/{userId}/drafts/{id}'], 'gmail.users.labels.delete': ['DELETE', '/gmail/v1/users/{userId}/labels/{id}']};
function seedDeletes(h) {
  const paths = {};
  for (const [id, [method, route]] of Object.entries(DELETES)) paths[route] = {[method.toLowerCase()]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'ok'}}}};
  const caps = Object.fromEntries(compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities.map(cap => [cap.name, {...cap, status: 'active'}]));
  for (const cap of Object.values(caps)) h.store.put('capabilities', cap);
  h.store.put('applicationMaps', {id: 'gmail', appId: 'gmail', operations: RECORDED.map(operation => caps[operation.id] ? {id: operation.id, capabilityId: caps[operation.id].id, method: DELETES[operation.id][0], path: DELETES[operation.id][1],
    requiredScopes: FACTS[operation.id]} : {...operation, requiredScopes: FACTS[operation.id]})});
  Object.assign(h.caps, {drafts: caps['gmail.users.drafts.delete'].id, labels: caps['gmail.users.labels.delete'].id});
}

test('decision 6: a developer ceiling on "Permanently delete emails" also covers the row split out of it, typed and raw; the stricter ceiling wins', t => {
  assert.deepEqual(SPLIT_ROWS, {gmail: {'gmail.items.delete': 'gmail.permanent.delete'}});
  const ceilings = {}, ceilingOf = splitCeiling((appId, groupId) => ceilings[groupId] ?? null);
  ceilings['gmail.permanent.delete'] = 'deny';
  assert.deepEqual([ceilingOf('gmail', 'gmail.items.delete'), ceilingOf('gmail', 'gmail.messages.send'), ceilingOf('github', 'gmail.items.delete')], ['deny', null, null]);
  ceilings['gmail.permanent.delete'] = 'ask'; ceilings['gmail.items.delete'] = 'deny';
  assert.equal(ceilingOf('gmail', 'gmail.items.delete'), 'deny', 'its own ceiling when stricter');
  ceilings['gmail.permanent.delete'] = 'deny'; ceilings['gmail.items.delete'] = 'ask';
  assert.equal(ceilingOf('gmail', 'gmail.items.delete'), 'deny', 'the old row\'s when stricter');
  // Through the engines: a typed decision and the proxy row both read it.
  const h = shipped(t, 'google');
  proxied(h, 'mail', 'gmail', 'google', 'https://gmail.googleapis.com', ['openid', 'email', MODIFY, SETTINGS]);
  seedDeletes(h);
  const permissions = new PermissionManager({store: h.store, ceilingOf: (appId, groupId) => groupId === 'gmail.permanent.delete' ? 'deny' : null}), policy = new ProxyPolicy({store: h.store, permissions});
  const decision = permissions.decision(h.record('mail'), h.store.get('capabilities', h.caps.drafts));
  assert.deepEqual([decision.groupId, decision.defaultMode, decision.mode], ['gmail.items.delete', 'ask', 'deny']);
  assert.equal(policy.decide('mail', {method: 'DELETE', path: '/gmail/v1/users/me/labels/l1'}).mode, 'deny');
  assert.equal(h.runtime.proxyPolicy.decide('mail', {method: 'DELETE', path: '/gmail/v1/users/me/labels/l1'}).mode, 'ask', 'without a ceiling the new row asks');
});

test('decision 6: a record that followed the old row\'s Never becomes a saved Never once, at start; new and saved records stay as they are', t => {
  const h = shipped(t, 'google');
  proxied(h, 'mail', 'gmail', 'google', 'https://gmail.googleapis.com', ['openid', 'email', MODIFY, SETTINGS]);
  seedDeletes(h);
  const id = capability => h.runtime.permissions.policyId('mail', h.caps[capability]), binding = capability => h.runtime.permissions.binding(h.record('mail'), h.store.get('capabilities', h.caps[capability]));
  // As version 1 rows left them: drafts.delete followed its row's default Never; labels.delete was saved at Never by hand.
  h.store.put('permissions', {id: id('drafts'), connectionId: 'mail', capabilityId: h.caps.drafts, mode: 'deny', followsDefault: true, bindingHash: binding('drafts'), revision: 'r-drafts', updatedAt: '2026-10-01T00:00:00.000Z'});
  h.store.put('permissions', {id: id('labels'), connectionId: 'mail', capabilityId: h.caps.labels, mode: 'deny', bindingHash: binding('labels'), revision: 'r-labels', updatedAt: '2026-10-01T00:00:00.000Z'});
  const labelsBefore = h.store.get('permissions', id('labels'));
  assert.equal(h.decision('mail', 'drafts').mode, 'ask', 'before the migration the record follows the new row\'s Ask');
  h.runtime.recover();
  const drafts = h.store.get('permissions', id('drafts'));
  assert.deepEqual([drafts.mode, drafts.followsDefault, drafts.splitFrom, drafts.revision !== 'r-drafts'], ['deny', undefined, 'gmail.permanent.delete', true]);
  assert.deepEqual([h.decision('mail', 'drafts').mode, h.decision('mail', 'drafts').policySource], ['deny', 'saved']);
  assert.deepEqual(h.store.get('permissions', id('labels')), labelsBefore, 'a saved Never is already kept');
  assert.equal(h.audits('permission.updated').filter(event => event.source === 'split').length, 1);
  // Idempotent, and a reset follows the new row's default afterwards: the marked record is never converted again.
  assert.equal(h.runtime.permissions.migrateSplitRows(), 0);
  h.runtime.permissions.reset({connectionId: 'mail'});
  h.runtime.recover();
  assert.deepEqual([h.decision('mail', 'drafts').mode, h.decision('mail', 'drafts').policySource], ['ask', 'default']);
  // A record that follows the new default (Ask) is not touched either.
  h.store.put('permissions', {...h.store.get('permissions', id('labels')), mode: 'ask', followsDefault: true, revision: 'r-ask'});
  assert.equal(h.runtime.permissions.migrateSplitRows(), 0);
  assert.equal(h.store.get('permissions', id('labels')).revision, 'r-ask');
});

test('decision 6: the migration runs once per store, so a Never the owner resets after the split follows the new Ask at every later start', t => {
  const h = shipped(t, 'google');
  proxied(h, 'mail', 'gmail', 'google', 'https://gmail.googleapis.com', ['openid', 'email', MODIFY, SETTINGS]);
  seedDeletes(h);
  // The first start on this code finds nothing from before the split.
  h.runtime.recover();
  // After the split the owner saves Never on drafts.delete, then resets it: the record follows the new row's Ask and still stores deny.
  h.runtime.permissions.set({connectionId: 'mail', capabilityId: h.caps.drafts, mode: 'deny'});
  h.runtime.permissions.reset({connectionId: 'mail'});
  assert.deepEqual([h.decision('mail', 'drafts').mode, h.decision('mail', 'drafts').policySource], ['ask', 'default']);
  // A later start never turns the owner's reset back into a saved Never.
  h.runtime.recover();
  assert.deepEqual([h.decision('mail', 'drafts').mode, h.decision('mail', 'drafts').policySource], ['ask', 'default']);
  assert.equal(h.audits('permission.updated').filter(event => event.source === 'split').length, 0);
});

test('decision 6: a record that followed the old row\'s Never keeps Never whatever mode a reset left stored in it', t => {
  const h = shipped(t, 'google');
  proxied(h, 'mail', 'gmail', 'google', 'https://gmail.googleapis.com', ['openid', 'email', MODIFY, SETTINGS]);
  seedDeletes(h);
  const id = capability => h.runtime.permissions.policyId('mail', h.caps[capability]), binding = capability => h.runtime.permissions.binding(h.record('mail'), h.store.get('capabilities', h.caps[capability]));
  // Before the split the owner saved Ask on labels.delete and reset it: the record followed the old row's Never, and stores ask.
  h.store.put('permissions', {id: id('labels'), connectionId: 'mail', capabilityId: h.caps.labels, mode: 'ask', followsDefault: true, bindingHash: binding('labels'), revision: 'r-labels', updatedAt: '2026-10-01T00:00:00.000Z'});
  assert.equal(h.decision('mail', 'labels').mode, 'ask', 'before the migration the record follows the new row\'s Ask');
  h.runtime.recover();
  const labels = h.store.get('permissions', id('labels'));
  assert.deepEqual([labels.mode, labels.followsDefault, labels.splitFrom], ['deny', undefined, 'gmail.permanent.delete']);
  assert.deepEqual([h.decision('mail', 'labels').mode, h.decision('mail', 'labels').policySource], ['deny', 'saved']);
});

test('open question 19: the workspace\'s operation list carries, for each operation an account lacks access for, the exact Add body the app page computes', async t => {
  // The owner's own server on the shipped GitHub definition, with a GitHub account from before step 7 (read:user only).
  const f = await signinFixture(t), stamp = new Date(f.now).toISOString();
  f.app.store.put('connections', {id: 'old-hub', appId: 'github', providerId: 'github', driver: 'http', status: 'ready', authMethod: 'oauth', label: 'octo-a', identity: {id: '101', displayName: 'octo-a'},
    allowedOrigins: ['https://api.github.com'], scopes: ['read:user'], grantCeiling: ['read:user'], authRevision: 'consent-old', signInRevision: 'sign-in-old', createdAt: stamp, updatedAt: stamp});
  f.app.store.put('connections', {...f.app.store.get('connections', 'old-hub'), id: 'full-hub', identity: {id: '202', displayName: 'octo-b'}, scopes: ['read:user', 'repo', 'read:org', 'gist', 'workflow']});
  const detail = await f.json('GET', '/api/connectors/github'), of = (ref, cap) => detail.body.permissionsByConnection[ref].find(item => item.capabilityId === cap.id);
  assert.equal(detail.status, 200);
  // Both operations need repo (the repositories read through its row's data): the body asks for exactly that, at the full level.
  for (const cap of [f.read, f.write]) assert.deepEqual([of('old-hub', cap).providerAccess, of('old-hub', cap).addAccess], ['missing', {providerId: 'github', body: {connectionId: 'old-hub', level: 'full', scopes: ['repo']}}]);
  // An account with access carries no body.
  for (const cap of [f.read, f.write]) assert.deepEqual([of('full-hub', cap).providerAccess, 'addAccess' in of('full-hub', cap)], ['granted', false]);
});

test('the owner\'s server says what each sign-in asks for: the connect option\'s words and the consent mode the workspace dialog reads', async t => {
  const f = await signinFixture(t), state = (await f.json('GET', '/api/state')).body;
  const option = id => state.catalog.find(app => app.id === id).connectionOptions.find(item => item.method === 'oauth');
  assert.equal(option('github').limitations[0], 'Full access at sign-in. You control each permission below. What GitHub grants and Fabric\'s operation settings are separate.');
  assert.deepEqual([state.settings.oauthProviders.github.consentMode, state.settings.oauthProviders.github.authorizationOrigin], ['full', 'https://github.com']);
  // Google is not configured here, and its option still says what its sign-in asks for under Testing.
  assert.match(option('gmail').limitations[0], /^Full access at sign-in\. /);
});

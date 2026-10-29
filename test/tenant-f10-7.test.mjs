import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {createHash, randomUUID} from 'node:crypto';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {ProviderApps} from '../lib/tenant/provider-apps.mjs';
import {reconnectLevel} from '../lib/tenant/connect-sessions.mjs';
import {requestedLevel, offeredLevels} from '../lib/access-levels.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {validateAuthDefinition, normalizeAuthApp} from '../contracts/auth-definition.mts';
import {GitHubSimulator, GoogleSimulator} from './fixtures/oauth-simulators.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';
import {githubV2, googleV2} from './fixtures/auth-v2/definitions.mjs';

// F10.7 part g in developer environments (docs/F10.7-BUILD-MAP.md section 3 part g, decision 9, corrections 3 and 12): a custom
// account reconnects at full on a version 2 app (g3), the consent sheet says what the sign-in app it names asks for (g4), a
// developer's read_write names full access for one release (g5), and the confirm merge pins what a first sign-in granted beyond
// what it asked for (decision 9). The level rules are checked on the normalized version 2 fixtures, and the sign-ins that need another
// shape go through a twin of Fabric's shared GitHub adapter (test/tenant-partial-grant.test.mjs). The flip commit's cases run on the
// shipped definitions, version 2 since then. GitHub and Google are simulated.
const SHARED = {github: {clientId: 'gh-f107', clientSecret: 'gh-f107-secret'}};
const GITHUB = [['GET', '/user/repos', ['repo']], ['GET', '/gists', ['gist']]];
const reading = (definition, appId) => { const checked = validateAuthDefinition(definition); return normalizeAuthApp(checked, checked.apps.find(app => app.appId === appId)); };

function seed(root) {
  const paths = {};
  for (const [method, route] of GITHUB) paths[route] = {[method.toLowerCase()]: {operationId: `${method} ${route}`.replace(/[^A-Za-z0-9]+/g, '_'), responses: {200: {description: 'OK'}}}};
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
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-tenant-f107-')), ids = seed(root);
  const github = new GitHubSimulator({...SHARED.github, clock: Date.now});
  const request = async req => { if (/^https:\/\/(api\.)?github\.com\//.test(req.url)) return github.request(req); throw new Error(`unexpected ${req.url}`); };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: SHARED});
  t.after(async () => { await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    const text = await response.text();
    return {status: response.status, body: text ? JSON.parse(text) : null};
  };
  const repo = () => app.stores.open(scope).repository, bundle = () => app.runtimes.bundle(scope);
  /** A version 2 twin of Fabric's shared GitHub adapter, with its client values and revocation policy. */
  const twin = (definition = githubV2()) => {
    const shared = bundle().adapters.get('github');
    const adapter = new OAuth2Provider(definition, {store: bundle().env.repository, vault: bundle().env.vault, connections: bundle().connections, request, clientId: shared.clientId, clientSecret: shared.clientSecret,
      redirectUri: shared.redirectUri, publishing: 'testing', consentDays: null, revocationPolicy: shared.revocationPolicy});
    bundle().adapters.set('github', adapter); bundle().connections.setOAuthProvider(adapter);
    return adapter;
  };
  const open = async (body, user = 'u1') => {
    const created = await call('POST', '/v1/connect-sessions', {externalUserId: user, ...body});
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const id = created.body.id, binding = `browser-${id}`;
    app.sessions.claim(id, new URL(created.body.connectUrl).hash.slice(3), binding);
    const self = {id, binding, view: (chosen, finish) => app.sessions.view(id, binding, chosen, finish), start: confirmRows => app.sessions.start(id, binding, undefined, undefined, confirmRows),
      async signIn({grant = 'all', confirmRows} = {}) {
        const started = self.start(confirmRows), consent = github.consent(started.authorizationUrl, {grant});
        const back = await app.sessions.callback(started.providerId, {state: consent.state, code: consent.code, flowId: started.flowId}, null);
        return {...back, started, confirm: extra => app.sessions.confirm(id, binding, back.finish, extra)};
      }};
    return self;
  };
  return {app, github, scope, ids, call, repo, bundle, twin, open};
}

// ---- g3 and correction 12 -----------------------------------------------------------------------------------------------------
test('g3: a custom account reconnects at full on a version 2 app, and still at read on a version 1 app with a read level', () => {
  const gmail2 = reading(googleV2(), 'gmail'), gmail1 = reading(v1Definition('google'), 'gmail'), github2 = reading(githubV2(), 'github'), github1 = reading(v1Definition('github'), 'github');
  assert.deepEqual(['custom', 'read', 'full', 'partial'].map(level => reconnectLevel(gmail2, level)), ['full', 'read', 'full', 'full']);
  assert.deepEqual(['custom', 'read', 'read_write'].map(level => reconnectLevel(gmail1, level)), ['read', 'read', 'full'], 'version 1 asks for the read set as before (T6)');
  assert.equal(reconnectLevel(github2, 'custom'), 'full');
  assert.equal(reconnectLevel(github1, 'custom'), 'read');
  // The end-to-end version 1 case, a custom Gmail account reconnecting through Fabric's shared Google app at gmail.readonly, is
  // test/tenant-renewal-upgrade.test.mjs ("a reconnect or Add access sheet offers only the level its link signs in at").
});

// ---- g5 -----------------------------------------------------------------------------------------------------------------------
test('g5: for one release a developer\'s read_write names full access where sign-in offers full; nothing else is renamed', () => {
  const v2 = offeredLevels(reading(googleV2(), 'gmail')), calendar = offeredLevels(reading(googleV2(), 'google-calendar')), v1 = offeredLevels(reading(v1Definition('google'), 'gmail'));
  assert.deepEqual([v2, calendar, v1], [['full', 'read'], ['full'], ['read', 'read_write']]);
  assert.deepEqual(['read_write', 'full', 'read', undefined].map(level => requestedLevel(level, v2)), ['full', 'full', 'read', undefined]);
  assert.equal(requestedLevel('read', calendar), 'read', 'read stays read, and is refused where no read level exists');
  assert.equal(requestedLevel('read_write', v1), 'read_write', 'a version 1 app keeps its own level');
  assert.equal(requestedLevel('read_write', ['pages']), 'read_write', 'a page grant is never called full access');
});

// ---- g4 and correction 3 ------------------------------------------------------------------------------------------------------
test('g4: a sign-in app asks under the definition\'s policy for its publishing state; Fabric\'s shared app signs in under Testing', () => {
  const google = validateAuthDefinition(googleV2()), apps = new ProviderApps({definitions: () => google});
  assert.equal(apps.consentMode('google', null), 'full');
  assert.equal(apps.consentMode('google', {kind: 'developer', publishing: 'production'}), 'required');
  assert.equal(apps.consentMode('google', {kind: 'developer', publishing: 'testing'}), 'full');
  assert.equal(new ProviderApps({definitions: () => validateAuthDefinition(v1Definition('google'))}).consentMode('google', {kind: 'developer', publishing: 'production'}), 'full', 'a version 1 definition always asks for the whole level');
  assert.equal(new ProviderApps().consentMode('google', {kind: 'developer', publishing: 'production'}), 'required', 'the shipped Google definition is version 2');
});

test('g4: the sheet of an app on a developer\'s own Google app in production reads that app\'s policy; on Fabric\'s shared app, Testing', async t => {
  const s = await setup(t);
  const created = await s.call('POST', '/v1/provider-apps', {providerId: 'google', clientId: 'dev-f107.apps', clientSecret: 'dev-f107-secret', consentScreenName: 'Acme Agent', publishing: 'production'});
  assert.equal(created.status, 201, JSON.stringify(created.body));
  assert.equal((await s.call('PUT', '/v1/environment/apps/gmail', {providerApp: created.body.providerApp.id, enabled: true})).status, 200);
  const environment = s.app.registry.get('environments', s.scope.environmentId);
  assert.equal(s.app.providerApps.sheetConsentMode(s.scope, environment, 'gmail'), 'required', 'the shipped definition reads the developer app\'s policy');
  // The developer API's sheet says so: in production, sign-in asks for what the app needs to work.
  const sheet = await s.call('GET', '/v1/apps/gmail/consent-sheet');
  assert.equal(sheet.body.accessLine, 'Sign-in asks for what this app needs to work. Add the rest from the permission that needs it, below.');
  const v2 = new ProviderApps({registry: s.app.registry, stores: s.app.stores, definitions: id => id === 'google' ? validateAuthDefinition(googleV2()) : definitionFor(id)});
  assert.equal(v2.sheetConsentMode(s.scope, environment, 'gmail'), 'required');
  assert.equal(v2.sheetConsentMode(s.scope, {...environment, apps: {}}, 'gmail'), 'full');
  assert.equal(v2.sheetConsentMode(s.scope, environment, 'no-such-app'), 'full');
});

test('g4: each of the five consent sheets asks the sign-in app it names for its consent mode, once', async t => {
  const s = await setup(t);
  const asked = [], original = s.app.providerApps.consentMode.bind(s.app.providerApps);
  s.app.providerApps.consentMode = (providerId, record) => { asked.push(`${providerId}:${record?.kind ?? 'shared'}`); return original(providerId, record); };
  const sheets = () => { const count = asked.length; return () => asked.slice(count); };
  // A link for one app, and one that lets the person choose.
  let since = sheets();
  assert.ok((await s.open({appId: 'github'})).view().sheet);
  assert.ok((await s.open({})).view('github').sheet);
  assert.deepEqual(since(), ['github:shared', 'github:shared']);
  // The developer API's sheet.
  since = sheets();
  assert.equal((await s.call('GET', '/v1/apps/github/consent-sheet')).status, 200);
  assert.deepEqual(since(), ['github:shared']);
  // A held call's sheet (F03.9d): Fabric makes the session; here it is opened with a secret the test sets.
  const user = s.repo().list('endUsers').find(item => item.subjectId === 'u1'), secret = 'f107-handoff-secret';
  const handoff = s.app.sessions.createHandoff(s.scope, {owner: {subjectId: user.subjectId, userRecordId: user.id}, appId: 'github', callRef: randomUUID(), createdBy: {keyId: 'key-f107', serviceClientId: 'client-f107'},
    expiresAt: new Date(Date.now() + 600_000).toISOString()});
  s.repo().put('connectSessions', {...s.repo().get('connectSessions', handoff.id), secretHash: createHash('sha256').update(secret).digest('hex')});
  s.app.sessions.claim(handoff.id, secret, `browser-${handoff.id}`);
  since = sheets();
  assert.ok(s.app.sessions.view(handoff.id, `browser-${handoff.id}`).sheet);
  assert.deepEqual(since(), ['github:shared']);
  // A reconnect sheet names the account's own sign-in app.
  const ref = (await (await s.open({appId: 'github'})).signIn()).confirm().result.accountRef, reconnect = await s.open({purpose: 'reconnect', accountRef: ref});
  since = sheets();
  assert.ok(reconnect.view().sheet);
  assert.deepEqual(since(), ['github:shared']);
});

// ---- decision 9 and correction 1: the developer confirm merge ------------------------------------------------------------------
test('decision 9: confirming a first sign-in pins at Ask what it granted beyond what it asked for, typed and raw, and nothing else', async t => {
  const s = await setup(t);
  // A sign-in that does not ask for gist, while GitHub returns it anyway.
  const definition = githubV2();
  definition.apps[0].access.levels.full.optional = ['read:org', 'workflow'];
  s.twin(definition);
  const back = await (await s.open({appId: 'github'})).signIn({grant: {add: ['gist']}});
  assert.equal(back.failed, undefined);
  assert.deepEqual(s.repo().list('permissions'), [], 'nothing is written while the account waits');
  const ref = back.confirm().result.accountRef, account = s.repo().get('connections', ref), {permissions, runtime} = s.bundle();
  assert.ok(account.scopes.includes('gist'));
  assert.equal(Object.hasOwn(account, 'planned'), false, 'what the sign-in asked for does not outlive the confirm');
  const typed = member => { const decision = permissions.decision(account, s.repo().get('capabilities', s.ids[member])); return [decision.mode, decision.policySource]; };
  const raw = row => { const entry = runtime.proxyPolicy.view(ref).find(item => item.row === `group:${row}`); return [entry.mode, entry.source]; };
  assert.deepEqual([typed('GET /gists'), raw('github.gists.read')], [['ask', 'saved'], ['ask', 'saved']]);
  assert.deepEqual([typed('GET /user/repos'), raw('github.repos.read')], [['allow', 'default'], ['allow', 'default']]);
});

test('decision 9: a plain first Connect sign-in writes no setting, and a sign-in merged into the person\'s account is not pinned again', async t => {
  const s = await setup(t);
  s.twin();
  const ref = (await (await s.open({appId: 'github'})).signIn()).confirm().result.accountRef;
  assert.deepEqual(s.repo().list('permissions'), []);
  assert.equal(Object.hasOwn(s.repo().get('connections', ref), 'planned'), false);
  // The same person signing in again within what they approved is a renewal: nothing to pin, and no plan kept on the account.
  const again = (await (await s.open({appId: 'github'})).signIn()).confirm();
  assert.deepEqual([again.result.accountRef, again.result.renewal], [ref, true]);
  assert.deepEqual(s.repo().list('permissions'), []);
  assert.deepEqual(s.repo().list('connections').map(item => Object.hasOwn(item, 'planned')), [false]);
});

// ---- the flip commit: end to end on the shipped definitions -------------------------------------------------------------------
test('the shipped definitions: tenant cards offer version 2 levels; read_write signs in at full, and read is refused where no read level exists', async t => {
  const s = await setup(t);
  const cards = Object.fromEntries((await s.call('GET', '/v1/apps?limit=100')).body.apps.map(card => [card.id, card.accessLevels]));
  assert.deepEqual(['gmail', 'google-calendar', 'github', 'slack', 'notion'].map(id => [id, cards[id]]), [['gmail', ['full', 'read']], ['google-calendar', ['full']], ['github', ['full']], ['slack', ['full']], ['notion', ['pages']]]);
  // The developer API's sheet: read_write names full for one release (g5); read is refused where the app has no read level.
  const legacy = await s.call('GET', '/v1/apps/github/consent-sheet?level=read_write');
  assert.deepEqual([legacy.status, legacy.body.levels.map(item => [item.level, item.isDefault])], [200, [['full', true]]]);
  for (const appId of ['google-calendar', 'github', 'slack']) assert.equal((await s.call('GET', `/v1/apps/${appId}/consent-sheet?level=read`)).status, 400, appId);
  assert.equal((await s.call('GET', '/v1/apps/gmail/consent-sheet?level=read')).status, 200, 'Gmail has an advanced read level');
  // Fabric's page: a start at read_write asks GitHub for the full level; read is refused and starts nothing.
  const link = await s.open({appId: 'github'}), start = level => s.app.sessions.start(link.id, link.binding, undefined, level);
  assert.throws(() => start('read'), error => error.status === 400 && error.code === 'invalid_request');
  assert.deepEqual(new URL(start('read_write').authorizationUrl).searchParams.get('scope').split(' '), ['read:user', 'repo', 'read:org', 'gist', 'workflow']);
});

const G = 'https://www.googleapis.com/auth/', GMAIL = 'https://gmail.googleapis.com';
const RECORDED = readFileSync(new URL('./fixtures/access/f10-3-bindings.before.json', import.meta.url), 'utf8');
const FACTS = JSON.parse(readFileSync(new URL('./fixtures/access/google-method-scopes.json', import.meta.url), 'utf8')).apps.gmail.methods;
test('a reconnect link of a Gmail account from before step 7 signs in at full, with the card for the rows it turns on', async t => {
  // Fabric's shared Google app in a development environment, a full Gmail map with Discovery's scopes, and "Manage labels" typed.
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-tenant-f107-gmail-')), store = new PlatformStore({root});
  const labels = {...compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: GMAIL}], paths: {'/gmail/v1/users/{userId}/labels': {post: {operationId: 'gmail.users.labels.create',
    parameters: [{name: 'userId', in: 'path', required: true, schema: {type: 'string'}}], requestBody: {content: {'application/json': {schema: {type: 'object'}}}}, responses: {200: {description: 'OK'}}}}}}}).capabilities[0], status: 'active'};
  store.put('capabilities', labels);
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations: JSON.parse(RECORDED).maps.gmail.operations.map(operation => ({...operation, requiredScopes: FACTS[operation.id],
    ...(operation.id === 'gmail.users.labels.create' ? {capabilityId: labels.id} : {}), sensitive: null}))});
  store.close();
  const google = new GoogleSimulator({clientId: 'g-f107', clientSecret: 'g-f107-secret', clock: Date.now});
  const app = await createDeveloperApp({dataRoot: root, port: 0, request: async req => google.request(req), providerSettings: {google: {clientId: 'g-f107', clientSecret: 'g-f107-secret'}}});
  t.after(async () => { await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev), key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify(body)}); return {status: response.status, body: await response.json()}; };
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u1'});
  const repo = app.stores.open(scope).repository, user = repo.list('endUsers').find(item => item.subjectId === 'u1'), now = app.registry.now(), id = randomUUID();
  // Version 1's read-and-write Gmail grant, as an account signed in before step 7 holds it.
  const held = ['openid', 'email', `${G}gmail.readonly`, `${G}gmail.compose`], tokens = google.issue('a', held, {refreshable: true});
  repo.put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: 'google-sub-a', displayName: 'a@example.com'}, label: 'a@example.com',
    allowedOrigins: [GMAIL], scopes: held, grantCeiling: [...held].sort(), createdAt: now, updatedAt: now, authRevision: randomUUID(), signInRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: 'u1', userRecordId: user.id}));
  app.stores.open(scope).vault.set(id, {accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, expiresAt: Date.parse(now) + 3600_000, scopes: held});
  const created = await call('POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'reconnect', accountRef: id});
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const binding = `browser-${created.body.id}`;
  app.sessions.claim(created.body.id, new URL(created.body.connectUrl).hash.slice(3), binding);
  const view = app.sessions.view(created.body.id, binding);
  assert.deepEqual(view.sheet.levels.map(item => [item.level, item.isDefault]), [['full', true]], 'a custom account reconnects at full (g3)');
  assert.ok(view.upgrade?.rows.some(row => row.groupId === 'gmail.labels.manage' && row.typed === true), JSON.stringify(view.upgrade));
  assert.throws(() => app.sessions.start(created.body.id, binding), {code: 'confirm_required'});
  const started = app.sessions.start(created.body.id, binding, undefined, undefined, view.upgrade.etag), asked = new URL(started.authorizationUrl).searchParams.get('scope').split(' ');
  assert.deepEqual(asked, ['openid', 'email', `${G}gmail.modify`, `${G}gmail.settings.basic`], 'the full level, and none of the version 1 scopes it held');
});

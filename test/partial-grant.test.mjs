import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import {validateAuthDefinition, normalizeAuthApp, impliedClosure, effectiveScopes, refusedScopes} from '../contracts/auth-definition.mts';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager, catalog} from '../lib/connections.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {AppDetailService} from '../lib/app-detail.mjs';
import {ContinuationService} from '../lib/continuations.mjs';
import {describeHandoff} from '../public/continue.js';
import {offeredLevels, heldLevel} from '../lib/access-levels.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {current, raise, shownNotice, scopesSubject, NOTICE_KINDS, NOTICE_WORDS, DERIVED_KINDS} from '../lib/connection-notices.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SIMULATORS, GoogleSimulator, GitHubSimulator, SlackSimulator} from './fixtures/oauth-simulators.mjs';
import {v1Definition, PROVIDERS} from './fixtures/auth-v1/urls.mjs';
import {googleV2, githubV2, notionV2, slackV2, GITHUB_SETTINGS, level} from './fixtures/auth-v2/definitions.mjs';
import {fixture as signinFixture, ENV as SIGNIN_ENV} from './fixtures/signin-fixture.mjs';

// F10.5 partial grants (T1, T2; docs/F10-FIVE-APPS-DEEP.md, docs/F10.5-BUILD-MAP.md section 4). Unticking an optional box at
// the provider narrows the connection instead of failing the sign-in, and a token carrying a scope Fabric never holds is
// refused without hurting any other connection. The catalog stays version 1 until F10.7, so every behaviour case runs on the
// version 2 fixtures in test/fixtures/auth-v2 against the provider simulators, on a designated store; nothing leaves the
// process.
const G = 'https://www.googleapis.com/auth/', MODIFY = `${G}gmail.modify`, SETTINGS = `${G}gmail.settings.basic`, READONLY = `${G}gmail.readonly`, CALENDAR = `${G}calendar`;
const MAILBOX = 'https://mail.google.com/';
const CLIENT = {clientId: 'partial-client', clientSecret: 'partial-secret'};
const OWNER = {schemaVersion: 1, id: 'partial-owner', kind: 'local_owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'partial-owner'}};
const REDIRECT = {google: 'http://127.0.0.1:59999/api/oauth/google/callback', github: 'http://127.0.0.1:59999/api/oauth/github/callback', slack: 'https://connect.example.com/oauth/slack/4320', notion: 'https://connect.example.com/oauth/notion/4320'};
const REVOKE = {google: 'https://oauth2.googleapis.com/revoke', github: `https://api.github.com/applications/${CLIENT.clientId}/token`, slack: 'https://slack.com/api/auth.revoke'};
const IDENTITY = {google: 'https://openidconnect.googleapis.com/v1/userinfo', github: 'https://api.github.com/user', slack: 'https://slack.com/api/auth.test'};
const TOKEN = {google: 'https://oauth2.googleapis.com/token', github: 'https://github.com/login/oauth/access_token', slack: 'https://slack.com/api/oauth.v2.access'};
const sha = value => createHash('sha256').update(value).digest('hex');
const ajv = new Ajv2020({strict: true, allErrors: true});
addFormats(ajv);
const schema = ajv.compile(JSON.parse(readFileSync(new URL('../contracts/auth-definition.schema.json', import.meta.url))));

// Synthetic maps: [operation id (or null for a request-named member), method, path, documented scope alternatives].
const MAPS = {
  gmail: {server: 'https://gmail.googleapis.com', operations: [['gmail.users.messages.get', 'GET', '/gmail/v1/users/{userId}/messages/{id}', [READONLY, MODIFY]],
    ['gmail.users.messages.modify', 'POST', '/gmail/v1/users/{userId}/messages/{id}/modify', [MODIFY]], ['gmail.users.settings.updateVacation', 'PUT', '/gmail/v1/users/{userId}/settings/vacation', [SETTINGS]]]},
  github: {server: 'https://api.github.com', operations: [[null, 'GET', '/user/repos', ['repo']], [null, 'GET', '/gists', ['gist']], [null, 'POST', '/gists', ['gist']], [null, 'GET', '/user/orgs', ['read:org']]]},
};
const GMAIL_SETTINGS_ROW = 'gmail.settings.write', GMAIL_MARK_ROW = 'gmail.messages.mark', GISTS_READ = 'github.gists.read', GISTS_WRITE = 'github.gists.write', PROFILES = 'github.profile.read';
function seed(store, appId, operations = MAPS[appId].operations) {
  const {server} = MAPS[appId], paths = {};
  for (const [id, method, route] of operations) paths[route] = {...paths[route], [method.toLowerCase()]: {operationId: (id ?? `${method} ${route}`).replace(/[^A-Za-z0-9]+/g, '_'),
    parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'GET' ? {} : {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {name: {type: 'string'}}}}}}}), responses: {200: {description: 'OK'}}}};
  const capabilities = compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: server}], paths}}).capabilities;
  const ids = {};
  store.put('applicationMaps', {id: appId, operations: operations.map(([id, method, route, requiredScopes]) => {
    const capability = capabilities.find(item => item.request.method === method && item.request.url === `${server}${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    ids[id ?? `${method} ${route}`] = capability.id;
    return {id: id ?? `${method} ${route}`, capabilityId: capability.id, method, path: route, requiredScopes};
  })});
  return ids;
}

/** A designated single-owner store with a real ConnectionManager, the version 2 adapter bound the way
 *  test/sibling-disconnect.test.mjs binds one, and the app page service wired as server.mjs wires it. */
function harness(t, definition, {publishing = 'testing', revocationPolicy, maps = []} = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), 'fabric-partial-grant-'));
  let now = Date.UTC(2026, 9, 11, 12);
  const clock = () => now, providerId = definition.providerId, sim = new SIMULATORS[providerId]({...CLIENT, clock}), responses = [];
  const store = new Store({dataDir: directory, clock, localAuthority: 'new'}), vault = new Vault(directory);
  const request = async req => { const response = await sim.request(req); responses.push({url: req.url, data: response.data}); return response; };
  const connections = new ConnectionManager({store, vault, request, clock});
  const adapter = options => new OAuth2Provider(definition, {store, vault, connections, request, clock, ...CLIENT, publishing, redirectUri: REDIRECT[providerId], allowHostedRedirect: REDIRECT[providerId].startsWith('https:'),
    ...(revocationPolicy ? {revocationPolicy} : {}), ...options});
  const runtime = new Runtime({store, connections, clock, ownerPrincipal: OWNER});
  const h = {
    directory, sim, store, vault, connections, runtime, responses, provider: null, caps: {},
    advance: ms => { now += ms; },
    /** Binds a fresh adapter for this definition, for instance under the other consent policy. */
    use(options = {}) { h.provider = adapter(options); connections.setOAuthProvider(h.provider); return h.provider; },
    start: (input, trusted) => h.provider.start(input, trusted),
    flowOf: started => store.get('oauthFlows', sha(new URL(started.authorizationUrl).searchParams.get('state'))),
    consent: (started, options) => sim.consent(started.authorizationUrl, options),
    finish: (started, grant, trusted) => h.provider.callback({state: grant.state, code: grant.code, error: grant.error, flowId: started.flowId}, trusted),
    async signIn(input, options = {}) { const started = h.start(input), grant = h.consent(started, options); return {started, grant, connection: await h.finish(started, grant)}; },
    record: id => store.get('connections', id),
    accounts: appId => store.list('connections').filter(item => item.appId === appId),
    vaultFiles: () => readdirSync(vault.dir).filter(name => name.endsWith('.enc')).length,
    calls: url => sim.calls.filter(req => req.url === url),
    audits: type => store.list('activity').filter(event => event.type === type),
    notices: (id, kind) => store.list('activity').filter(event => event.type === 'connection.health' && event.connectionId === id && (!kind || event.kind === kind)),
    decision: (id, member) => runtime.permissions.decision(store.get('connections', id), store.get('capabilities', h.caps[member])),
    view: (appId, accountRef) => h.service.view(appId, accountRef),
    row: (page, groupId) => page.sections.flatMap(section => section.rows).find(item => item.groupId === groupId),
  };
  h.use();
  const access = appId => h.provider.access(h.provider.app(appId));
  h.service = new AppDetailService({store, runtime, catalog: () => catalog, oauthProviderFor: () => h.provider, accessLevels: appId => offeredLevels(access(appId)),
    accessLevelOf: connection => heldLevel(access(connection.appId), connection.scopes)});
  connections.setUpgradeGuard((previous, next, confirmed) => h.service.pinUnconfirmed(previous, next, confirmed));
  // Part e's trusted hook, installed the way server.mjs installs it once it exists.
  connections.setAccessExplainer?.((appId, scopes) => h.service.rowsNeeding(appId, scopes));
  for (const appId of maps) Object.assign(h.caps, seed(store, appId));
  t.after(() => { store.close(); rmSync(directory, {recursive: true, force: true}); });
  return h;
}
const issuedToken = (h, providerId) => { const answer = h.responses.filter(item => item.url === TOKEN[providerId]).at(-1)?.data; return answer?.authed_user?.access_token ?? answer?.access_token; };
const closed = () => Object.assign(new Error('This account request is no longer waiting for this sign-in.'), {code: 'continuation_closed'});

// ---- part a: the simulators -------------------------------------------------------------------------------------------------
test('simulators: partial grants by name; Google granular consent, GitHub edited scopes with parents returned, Slack user_optional', () => {
  const clock = () => Date.UTC(2026, 9, 11, 12), url = (base, params) => { const value = new URL(base); for (const [key, item] of Object.entries(params)) value.searchParams.set(key, item); return value.href; };
  const granted = (sim, consent) => sim.codes.get(consent.code).granted;
  const google = new GoogleSimulator({...CLIENT, clock}), googleUrl = scope => url('https://accounts.google.com/o/oauth2/v2/auth', {client_id: CLIENT.clientId, response_type: 'code', redirect_uri: REDIRECT.google, scope, state: 's'});
  assert.deepEqual(granted(google, google.consent(googleUrl(`openid email ${MODIFY} ${SETTINGS}`), {grant: {omit: [SETTINGS]}})), ['openid', 'email', MODIFY]);
  assert.deepEqual(granted(google, google.consent(googleUrl(`openid email ${CALENDAR}`), {grant: {add: [MAILBOX]}})), ['openid', 'email', CALENDAR, MAILBOX]);
  assert.deepEqual(granted(google, google.consent(googleUrl(`openid email ${MODIFY} ${SETTINGS}`), {grant: 'partial'})), ['openid', 'email', MODIFY], 'a string keeps its meaning');
  assert.deepEqual(granted(google, google.consent(googleUrl(`openid email ${MODIFY}`))), ['openid', 'email', MODIFY]);
  assert.throws(() => google.consent(googleUrl(`openid email ${MODIFY}`), {grant: {omit: ['email']}}), /no box for email/);
  assert.throws(() => google.consent(googleUrl(`openid email ${MODIFY}`), {grant: {omit: [SETTINGS]}}), /was not asked for/);
  assert.throws(() => google.consent(googleUrl(`openid email ${MODIFY}`), {grant: {drop: [MODIFY]}}), /grant is all, a string, or \{omit, add\}/);

  const github = new GitHubSimulator({...CLIENT, clock}), githubUrl = scope => url('https://github.com/login/oauth/authorize', {client_id: CLIENT.clientId, redirect_uri: REDIRECT.github, scope, state: 's'});
  const asked = 'read:user repo read:org gist workflow';
  assert.deepEqual(granted(github, github.consent(githubUrl(asked), {grant: {omit: ['gist']}})), ['read:user', 'repo', 'read:org', 'workflow']);
  assert.deepEqual(granted(github, github.consent(githubUrl(asked), {grant: {add: ['admin:org']}})), ['read:user', 'repo', 'gist', 'workflow', 'admin:org'], 'a returned parent hides read:org');
  assert.deepEqual(granted(github, github.consent(githubUrl(asked), {grant: {add: ['write:org']}})), ['read:user', 'repo', 'gist', 'workflow', 'write:org'], 'write:org implies read:org');
  assert.deepEqual(granted(github, github.consent(githubUrl(asked), {grant: {add: ['user']}})), ['repo', 'read:org', 'gist', 'workflow', 'user'], 'and user hides read:user');
  assert.deepEqual(granted(github, github.consent(githubUrl('repo admin:repo_hook read:repo_hook'))), ['repo', 'admin:repo_hook']);
  assert.deepEqual(granted(github, github.consent(githubUrl(asked), {grant: 'partial'})), ['read:user', 'repo', 'read:org', 'gist']);

  const slack = new SlackSimulator({...CLIENT, clock}), slackUrl = userScope => url('https://slack.com/oauth/v2/authorize', {client_id: CLIENT.clientId, redirect_uri: REDIRECT.slack, user_scope: userScope, state: 's'});
  assert.throws(() => slack.consent(slackUrl('channels:read,users:read,chat:write'), {grant: {omit: ['chat:write']}}), /only user_optional scopes can be declined, not chat:write/);
  slack.userOptional = new Set(['chat:write']);
  assert.deepEqual(granted(slack, slack.consent(slackUrl('channels:read,users:read,chat:write'), {grant: {omit: ['chat:write']}})), ['channels:read', 'users:read']);
  assert.throws(() => slack.consent(slackUrl('channels:read,users:read,chat:write'), {grant: {omit: ['users:read']}}), /not users:read/);
  assert.deepEqual(granted(slack, slack.consent(slackUrl('channels:read,users:read'), {grant: {add: ['admin']}})), ['channels:read', 'users:read', 'admin']);
});

test('the Slack simulator reissues the same user token with the union of its scopes when asked, and never a revoked one', async () => {
  const slack = new SlackSimulator({...CLIENT, clock: () => Date.UTC(2026, 9, 11, 12)});
  const consent = userScope => { const url = new URL('https://slack.com/oauth/v2/authorize'); for (const [key, value] of Object.entries({client_id: CLIENT.clientId, redirect_uri: REDIRECT.slack, user_scope: userScope, state: 's'})) url.searchParams.set(key, value); return slack.consent(url.href).code; };
  const exchange = async code => (await slack.request({url: TOKEN.slack, method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams({code, redirect_uri: REDIRECT.slack, client_id: CLIENT.clientId, client_secret: CLIENT.clientSecret}).toString()})).data.authed_user;
  const first = await exchange(consent('channels:read,users:read')), fresh = await exchange(consent('channels:read'));
  assert.notEqual(fresh.access_token, first.access_token, 'a new token by default');
  slack.reuseUserToken = true;
  const again = await exchange(consent('channels:read,chat:write'));
  assert.equal(again.access_token, fresh.access_token);
  assert.equal(again.scope, 'channels:read,chat:write');
  assert.deepEqual(slack.access.get(fresh.access_token).scopes, ['channels:read', 'chat:write']);
  const wider = await exchange(consent('admin'));
  assert.deepEqual([wider.access_token, wider.scope], [fresh.access_token, 'channels:read,chat:write,admin']);
  await slack.request({url: REVOKE.slack, method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams({token: fresh.access_token}).toString()});
  const after = await exchange(consent('channels:read'));
  assert.notEqual(after.access_token, fresh.access_token); assert.equal(after.scope, 'channels:read');
});

// ---- part b: the contract helpers --------------------------------------------------------------------------------------------
test('implications close over chains; a version 2 app reads its definition\'s closure, a version 1 app implies nothing', () => {
  assert.deepEqual({...impliedClosure({a: ['b'], b: ['c', 'd'], c: ['d']})}, {a: ['b', 'c', 'd'], b: ['c', 'd'], c: ['d']});
  assert.deepEqual({...impliedClosure(undefined)}, {});
  assert.deepEqual({...impliedClosure({a: ['b'], b: ['a']})}, {a: ['b'], b: ['a']}, 'pure: a cycle is the validator\'s to refuse, never a loop');
  assert.throws(() => validateAuthDefinition({...githubV2(), scopeImplications: {a: ['b'], b: ['a']}}), /definition.scopeImplications.a grants itself through b/);
  assert.throws(() => validateAuthDefinition({...githubV2(), scopeImplications: {a: ['a']}}), /definition.scopeImplications.a cannot grant itself/);
  const github = validateAuthDefinition(githubV2()), app = normalizeAuthApp(github, github.apps[0]);
  assert.deepEqual([app.implies['admin:org'], app.implies['write:org'], app.implies['admin:repo_hook'], app.implies.repo],
    [['write:org', 'read:org'], ['read:org'], ['write:repo_hook', 'read:repo_hook'], ['public_repo', 'repo:status', 'repo_deployment', 'repo:invite', 'security_events']]);
  assert.ok(Object.isFrozen(app.implies) && Object.isFrozen(app.implies.repo));
  const google = validateAuthDefinition(googleV2());
  for (const entry of google.apps) assert.deepEqual({...normalizeAuthApp(google, entry).implies}, {});
  for (const providerId of PROVIDERS) { const v1 = validateAuthDefinition(v1Definition(providerId)); for (const entry of v1.apps) assert.deepEqual({...normalizeAuthApp(v1, entry).implies}, {}, `${providerId}/${entry.appId}`); }
});

test('effective scopes: what was granted plus every scope a granted parent grants; version 1 reads the grant unchanged', () => {
  const github = validateAuthDefinition(githubV2()), app = normalizeAuthApp(github, github.apps[0]);
  assert.deepEqual(effectiveScopes(app, ['read:user', 'repo', 'admin:org']), ['read:user', 'repo', 'admin:org', 'public_repo', 'repo:status', 'repo_deployment', 'repo:invite', 'security_events', 'write:org', 'read:org']);
  assert.deepEqual(effectiveScopes(app, ['write:org']), ['write:org', 'read:org'], 'correction 9: write:org grants read:org');
  assert.deepEqual(effectiveScopes(app, ['read:org', 'admin:org', 'read:org']), ['read:org', 'admin:org', 'write:org']);
  assert.deepEqual(effectiveScopes(app, []), []);
  const google = validateAuthDefinition(v1Definition('google')), gmail = normalizeAuthApp(google, google.apps[1]), granted = [READONLY, 'openid', READONLY];
  assert.deepEqual(effectiveScopes(gmail, granted), granted);
  assert.notEqual(effectiveScopes(gmail, granted), granted, 'a copy, never the caller\'s list');
});

test('refused scopes: granted ones on a never list, directly or through what they grant, sorted and once each', () => {
  const github = validateAuthDefinition(githubV2()), {implies} = normalizeAuthApp(github, github.apps[0]);
  assert.deepEqual(refusedScopes(['delete_repo', 'user', 'write:public_key'], implies, ['repo', 'user', 'admin:public_key', 'user', 'gist']), ['admin:public_key', 'user']);
  assert.deepEqual(refusedScopes(['delete_repo', 'user'], implies, ['read:user', 'repo', 'admin:org']), []);
  assert.deepEqual(refusedScopes(['read:org'], implies, ['admin:org', 'write:org']), ['admin:org', 'write:org'], 'the closure reaches through a chain');
  assert.deepEqual(refusedScopes([], {}, ['anything']), []);
});

test('revocation.settingsUrl: optional in both versions; a public HTTPS page without query or fragment, at most 200 characters', () => {
  for (const make of [() => v1Definition('github'), githubV2]) {
    const value = make();
    value.revocation = {...value.revocation, settingsUrl: GITHUB_SETTINGS};
    assert.equal(validateAuthDefinition(value).revocation.settingsUrl, GITHUB_SETTINGS);
    assert.ok(schema(value), JSON.stringify(schema.errors));
    for (const bad of ['http://github.com/settings/applications', `${GITHUB_SETTINGS}?tab=oauth`, `${GITHUB_SETTINGS}#oauth`, `https://github.com/${'a'.repeat(190)}`, 'https://user@github.com/settings', 'github.com/settings', 7, null]) {
      const refused = make();
      refused.revocation = {...refused.revocation, settingsUrl: bad};
      assert.throws(() => validateAuthDefinition(refused), /definition.revocation.settingsUrl/, String(bad));
      assert.equal(schema(refused), false, String(bad));
    }
    // Semantic rules belong to the validator alone, as for the revocation URL.
    for (const bad of ['https://localhost/settings', 'https://github.local/settings', 'https://GitHub.com/settings']) {
      const refused = make();
      refused.revocation = {...refused.revocation, settingsUrl: bad};
      assert.throws(() => validateAuthDefinition(refused), /definition.revocation.settingsUrl/, bad);
    }
  }
  // F10.7: GitHub's definition names it; the others do not (Google's words already say where to remove Fabric, open question 10).
  for (const providerId of PROVIDERS) assert.equal(definitionFor(providerId).revocation?.settingsUrl, providerId === 'github' ? GITHUB_SETTINGS : undefined, providerId);
});

test('correction 4: no app\'s level scope, or a scope it grants, sits in another app\'s neverRequest', () => {
  const refuse = (mutate, pattern) => { const value = googleV2(); mutate(value); assert.throws(() => validateAuthDefinition(value), error => error.code === 'invalid_definition' && pattern.test(error.message), pattern.source); };
  refuse(value => { value.apps[0].neverRequest = [SETTINGS]; }, /definition.apps\[0\].neverRequest lists https:\/\/www.googleapis.com\/auth\/gmail.settings.basic, which the gmail app's access asks for or grants/);
  refuse(value => { value.apps[0].neverRequest = [READONLY]; }, /neverRequest lists .*gmail.readonly, which the gmail app/);
  refuse(value => { value.apps[1].access.levels.full.inContext = [{scope: `${G}gmail.labels`, rows: ['gmail.labels.manage']}]; value.apps[0].neverRequest = [`${G}gmail.labels`]; }, /gmail.labels, which the gmail app/);
  refuse(value => { value.apps[1].neverRequest = [...value.apps[1].neverRequest, CALENDAR]; }, /definition.apps\[1\].neverRequest lists .*auth\/calendar, which the google-calendar app/);
  refuse(value => { value.scopeImplications = {[MODIFY]: [`${G}gmail.labels`]}; value.apps[0].neverRequest = [`${G}gmail.labels`]; }, /gmail.labels, which the gmail app's access asks for or grants/);
  // Another app's never list may hold a scope no app's access reaches; the union then refuses it everywhere.
  const value = googleV2(); value.apps[0].neverRequest = [MAILBOX];
  assert.ok(validateAuthDefinition(value));
});

// ---- part c: the engine readers and the flow record ----------------------------------------------------------------------
test('the engine reads implications per app and the never lists of every app on the provider, with their closure', t => {
  const github = harness(t, githubV2()).provider;
  assert.deepEqual(github.effectiveScopes('github', ['admin:org']), ['admin:org', 'write:org', 'read:org']);
  assert.deepEqual(github.effectiveScopes('github', undefined), []);
  assert.throws(() => github.effectiveScopes('gmail', []), {code: 'invalid_input'});
  assert.deepEqual(github.refused(['read:user', 'repo', 'user', 'delete_repo']), ['delete_repo', 'user']);
  assert.deepEqual(github.refused(undefined), []);
  const closure = githubV2(); closure.apps[0].neverRequest = ['delete_repo', 'user', 'write:public_key'];
  assert.deepEqual(harness(t, closure).provider.refused(['repo', 'admin:public_key']), ['admin:public_key']);
  // Open question 6: Gmail's never list holds for a Calendar grant too.
  const google = harness(t, googleV2()).provider;
  assert.deepEqual(google.refused(['openid', 'email', CALENDAR, MAILBOX]), [MAILBOX]);
  assert.deepEqual(google.effectiveScopes('google-calendar', ['openid', CALENDAR]), ['openid', CALENDAR]);
  // Version 1 never-requests nothing and implies nothing.
  const v1 = harness(t, v1Definition('google')).provider;
  assert.deepEqual(v1.refused([MAILBOX, `${G}gmail.settings.sharing`]), []);
  assert.deepEqual(v1.effectiveScopes('gmail', [READONLY, READONLY]), [READONLY, READONLY]);
});

test('a version 2 flow records the level it asked for and the scopes it requires; optional and carried scopes are not required', t => {
  const h = harness(t, googleV2()), flow = input => h.flowOf(h.start(input)), shape = record => ({level: record.level, required: record.required});
  assert.deepEqual(shape(flow({appId: 'gmail', level: 'full'})), {level: 'full', required: [MODIFY]});
  assert.deepEqual(flow({appId: 'gmail', level: 'full'}).scopes, ['openid', 'email', MODIFY, SETTINGS], 'the optional scope is asked for, not required');
  assert.deepEqual(shape(flow({appId: 'gmail', writeAccess: true})), {level: 'full', required: [MODIFY]});
  assert.deepEqual(shape(flow({appId: 'gmail', level: 'read'})), {level: 'read', required: [READONLY]});
  assert.deepEqual(shape(flow({appId: 'google-calendar'})), {level: 'full', required: [CALENDAR]});
  // Open question 1: what is explicitly requested (Add access, account-request extras) must be granted.
  assert.deepEqual(shape(flow({appId: 'gmail', level: 'full', scopes: [SETTINGS]})), {level: 'full', required: [MODIFY, SETTINGS]});
  h.store.put('connections', {id: 'gm', appId: 'gmail', providerId: 'google', authMethod: 'oauth', status: 'ready', authRevision: 'a-1', signInRevision: 's-1', identity: {id: 'google-sub-a'}, scopes: ['openid', 'email', MODIFY, SETTINGS]});
  assert.deepEqual(shape(flow({connectionId: 'gm'})), {level: 'full', required: [MODIFY]}, 'a carried optional scope narrows when declined');
  assert.deepEqual(shape(flow({connectionId: 'gm', scopes: [SETTINGS]})), {level: 'full', required: [MODIFY, SETTINGS]});
  const production = harness(t, googleV2(), {publishing: 'production'});
  assert.deepEqual([production.flowOf(production.start({appId: 'gmail', level: 'full'})).scopes, production.flowOf(production.start({appId: 'gmail', level: 'full'})).required], [['openid', 'email', MODIFY], [MODIFY]]);
  assert.deepEqual(production.flowOf(production.start({appId: 'gmail', level: 'full', scopes: [SETTINGS]})).required, [MODIFY, SETTINGS]);
  // A user-credential app's level lists user scopes, so they are in the same list; a page grant requires nothing.
  const slack = harness(t, slackV2());
  assert.deepEqual(shape(slack.flowOf(slack.start({appId: 'slack', level: 'full'}))), {level: 'full', required: ['channels:read', 'users:read']});
  assert.deepEqual(slack.flowOf(slack.start({appId: 'slack', level: 'full', scopes: ['channels:history']})).required, ['channels:read', 'users:read', 'channels:history']);
  const notion = harness(t, notionV2());
  assert.deepEqual(shape(notion.flowOf(notion.start({appId: 'notion'}))), {level: 'full', required: []});
  const github = harness(t, githubV2());
  assert.deepEqual(shape(github.flowOf(github.start({appId: 'github', scopes: ['gist']}))), {level: 'full', required: ['read:user', 'repo', 'gist']});
});

test('T6: a version 1 flow record is unchanged, with no level and no required list, and version 2 authorization URLs do not move', t => {
  for (const providerId of PROVIDERS) {
    const h = harness(t, v1Definition(providerId));
    for (const app of v1Definition(providerId).apps) for (const input of [{appId: app.appId}, {appId: app.appId, writeAccess: true}]) {
      const record = h.flowOf(h.start(input));
      assert.deepEqual(Object.keys(record).sort(), ['appId', 'connectionAuthority', 'connectionId', 'connectionSignIn', 'connectionVersion', 'expiresAt', 'flowIdHash', 'id', 'label', 'providerId', 'scopes', ...(record.userScopes ? ['userScopes'] : [])].sort(), `${providerId}/${app.appId}`);
    }
  }
  const h = harness(t, googleV2()), url = new URL(h.start({appId: 'gmail', level: 'full'}).authorizationUrl);
  assert.deepEqual([url.searchParams.get('scope'), url.searchParams.get('access_type'), url.searchParams.get('prompt')], [`openid email ${MODIFY} ${SETTINGS}`, 'offline', 'consent']);
});

// ---- guards that hold today and through every part ----------------------------------------------------------------------
test('a Gmail grant without gmail.modify activates nothing: no connection, no vault entry left, the flow spent', async t => {
  const h = harness(t, googleV2(), {maps: ['gmail']}), files = h.vaultFiles();
  const started = h.start({appId: 'gmail', level: 'full'}), grant = h.consent(started, {grant: {omit: [MODIFY]}});
  assert.equal(h.vaultFiles(), files + 1, 'the flow\'s own verifier');
  await assert.rejects(h.finish(started, grant), {code: 'insufficient_scope'});
  assert.deepEqual(h.store.list('connections'), []);
  assert.equal(h.vaultFiles(), files);
  assert.deepEqual(h.store.list('oauthFlows'), []);
  assert.deepEqual(h.calls(IDENTITY.google), [], 'nothing is verified for a grant that cannot activate');
  await assert.rejects(h.finish(started, grant), {code: 'invalid_state'});
});

test('open question 1: a declined Add access is insufficient_scope and changes nothing on the account', async t => {
  // Production consent asks for gmail.modify only, so the account is ready without the settings scope.
  const h = harness(t, googleV2(), {publishing: 'production'});
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'});
  const before = h.record(connection.id), tokens = h.vault.get(connection.id), generation = h.store.connectionGeneration(connection.id), files = h.vaultFiles();
  const started = h.start({connectionId: connection.id, level: 'full', scopes: [SETTINGS]});
  assert.deepEqual(h.flowOf(started).required, [MODIFY, SETTINGS]);
  await assert.rejects(h.finish(started, h.consent(started, {grant: {omit: [SETTINGS]}})), {code: 'insufficient_scope'});
  const after = h.record(connection.id);
  assert.deepEqual([after.authRevision, after.signInRevision, after.scopes, after.grantCeiling], [before.authRevision, before.signInRevision, before.scopes, before.grantCeiling]);
  assert.deepEqual(h.vault.get(connection.id), tokens);
  assert.equal(h.store.connectionGeneration(connection.id), generation);
  assert.equal(h.vaultFiles(), files);
});

test('a flow stored before F10.5, with no required list, keeps the old rule: every scope it asked for is required', async t => {
  const h = harness(t, googleV2());
  const started = h.start({appId: 'gmail', level: 'full'}), {level, required, ...old} = h.flowOf(started);
  assert.deepEqual([level, required], ['full', [MODIFY]]);
  h.store.put('oauthFlows', old);
  await assert.rejects(h.finish(started, h.consent(started, {grant: {omit: [SETTINGS]}})), {code: 'insufficient_scope'});
  assert.deepEqual(h.store.list('connections'), []);
});

test('correction 5: a version 1 sign-in keeps its insufficient_scope words, with the access explainer installed', async t => {
  // The settings row documents the declined scope, so an explainer read for a version 1 flow would have a row to name here.
  const h = harness(t, v1Definition('google'), {maps: ['gmail']}), words = 'Google did not grant all the requested application permissions. No connection was activated.';
  const first = h.start({appId: 'gmail', writeAccess: true});
  await assert.rejects(h.finish(first, h.consent(first, {grant: 'partial'})), error => error.code === 'insufficient_scope' && error.message === words);
  const {connection} = await h.signIn({appId: 'gmail', writeAccess: true}), before = h.record(connection.id);
  const started = h.start({connectionId: connection.id, scopes: [SETTINGS]});
  assert.equal(Object.hasOwn(h.flowOf(started), 'required'), false);
  await assert.rejects(h.finish(started, h.consent(started, {grant: {omit: [SETTINGS]}})), error => error.code === 'insufficient_scope' && error.message === words);
  assert.deepEqual([h.record(connection.id).scopes, h.record(connection.id).signInRevision], [before.scopes, before.signInRevision]);
});

test('Slack: a declined user_optional scope that the level requires is insufficient_scope', async t => {
  const h = harness(t, slackV2());
  h.sim.userOptional = new Set(['channels:read', 'chat:write']);
  const started = h.start({appId: 'slack', level: 'full'});
  await assert.rejects(h.finish(started, h.consent(started, {grant: {omit: ['channels:read']}})), {code: 'insufficient_scope'});
  assert.deepEqual(h.store.list('connections'), []);
});

// ---- parts e to h: partial grants narrow the connection ------------------------------------------------------------------
test('Gmail without gmail.settings.basic: ready and narrowed; the settings row needs more access, Add asks for exactly it, and the account says so', async t => {
  const h = harness(t, googleV2(), {maps: ['gmail']});
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [SETTINGS]}});
  const record = h.record(connection.id);
  assert.equal(record.status, 'ready');
  assert.deepEqual([record.scopes.includes(SETTINGS), record.grantCeiling.includes(SETTINGS)], [false, false]);
  assert.deepEqual(record.grant, {level: 'full', missing: [SETTINGS]});
  assert.equal(Object.hasOwn(connection, 'grant'), false, 'the grant never leaves the store');
  const page = h.view('gmail', connection.id), settings = h.row(page, GMAIL_SETTINGS_ROW);
  assert.equal(settings.access, 'missing');
  assert.deepEqual(settings.addAccess.body, {connectionId: connection.id, level: 'full', scopes: [SETTINGS]});
  assert.equal(h.row(page, GMAIL_MARK_ROW).access, 'granted');
  assert.equal(page.notices.length, 1);
  const [notice] = page.notices;
  assert.deepEqual(Object.keys(notice).sort(), ['accountRef', 'count', 'kind', 'message', 'rows', 'since']);
  assert.deepEqual([notice.kind, notice.accountRef, notice.count, notice.rows], ['not_granted', connection.id, 1, [{groupId: GMAIL_SETTINGS_ROW, label: 'Change mail settings, filters and vacation reply'}]]);
  assert.match(notice.message, /^1 permission.* not granted at sign-in: Change mail settings, filters and vacation reply\./);
  assert.equal(page.accounts[0].accessLabel, 'Partial access (1 permission not granted)');
  assert.match(page.accounts[0].attention, /not granted at sign-in/);
  assert.deepEqual(h.notices(connection.id), [], 'derived, never stored');
});

test('a Gmail grant without gmail.modify names the permissions that need it', async t => {
  const h = harness(t, googleV2(), {maps: ['gmail']});
  const started = h.start({appId: 'gmail', level: 'full'});
  await assert.rejects(h.finish(started, h.consent(started, {grant: {omit: [MODIFY]}})),
    error => error.code === 'insufficient_scope' && /Mark as read or unread, archive or label emails/.test(error.message) && /No connection was activated\./.test(error.message) && !error.message.includes(MODIFY));
  const again = h.start({appId: 'gmail', level: 'full'});
  await assert.rejects(h.finish(again, h.consent(again, {grant: {omit: [MODIFY]}})), {message: 'Google did not grant permissions that Gmail needs: Mark as read or unread, archive or label emails. No connection was activated.'});
  // Live session 1 (S5.6): operations just discovered are candidates until someone turns them on, and they sit on the page's rows all
  // the same, so they are named too; a disabled one is not.
  for (const capability of h.store.list('capabilities').filter(item => item.appId === 'gmail')) h.store.put('capabilities', {...capability, status: 'candidate'});
  const fresh = h.start({appId: 'gmail', level: 'full'});
  await assert.rejects(h.finish(fresh, h.consent(fresh, {grant: {omit: [MODIFY]}})), {message: 'Google did not grant permissions that Gmail needs: Mark as read or unread, archive or label emails. No connection was activated.'});
  for (const capability of h.store.list('capabilities').filter(item => item.appId === 'gmail')) h.store.put('capabilities', {...capability, status: 'disabled'});
  const off = h.start({appId: 'gmail', level: 'full'});
  await assert.rejects(h.finish(off, h.consent(off, {grant: {omit: [MODIFY]}})), {message: 'Google did not grant all the requested application permissions. No connection was activated.'});
});

// ---- part e: required or nothing, and the grant (T2) -----------------------------------------------------------------------
test('T2: a required scope that a granted parent grants is held, so GitHub returning admin:org for a required read:org activates', async t => {
  const definition = githubV2(); definition.apps[0].access.levels.full = level(['read:user', 'repo', 'read:org'], ['gist', 'workflow']);
  const h = harness(t, definition), started = h.start({appId: 'github'});
  assert.deepEqual(h.flowOf(started).required, ['read:user', 'repo', 'read:org']);
  const connection = await h.finish(started, h.consent(started, {grant: {add: ['admin:org']}})), record = h.record(connection.id);
  assert.equal(record.status, 'ready');
  assert.deepEqual([record.scopes.includes('read:org'), record.scopes.includes('admin:org')], [false, true], 'GitHub returned the parent only');
  // A flow from before F10.5 keeps every asked scope required, and reads implications the same way.
  const old = h.start({appId: 'github'}), {level: chosen, required, ...stored} = h.flowOf(old);
  assert.deepEqual([chosen, required], ['full', ['read:user', 'repo', 'read:org']]);
  h.store.put('oauthFlows', stored);
  assert.equal(h.record((await h.finish(old, h.consent(old, {grant: {add: ['admin:org']}}))).id).status, 'ready');
});

test('T2: the callback passes down what the sign-in asked for and did not get, after implications; nothing for version 1 or a page grant', async t => {
  const passed = h => { const seen = [], establish = h.connections.establishOAuth.bind(h.connections); h.connections.establishOAuth = input => { seen.push(input); return establish(input); }; return seen; };
  const gmail = harness(t, googleV2()), gmailSeen = passed(gmail);
  await gmail.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [SETTINGS]}});
  await gmail.signIn({appId: 'gmail', level: 'read'});
  await gmail.signIn({appId: 'google-calendar'});
  assert.deepEqual(gmailSeen.map(input => input.grant), [{level: 'full', missing: [SETTINGS]}, {level: 'read', missing: []}, {level: 'full', missing: []}]);
  const github = harness(t, githubV2()), githubSeen = passed(github);
  await github.signIn({appId: 'github'}, {grant: {omit: ['gist', 'workflow']}});
  await github.signIn({appId: 'github'}, {grant: {add: ['admin:org']}});
  assert.deepEqual(githubSeen.map(input => input.grant), [{level: 'full', missing: ['gist', 'workflow']}, {level: 'full', missing: []}], 'admin:org holds read:org');
  const slack = harness(t, slackV2()), slackSeen = passed(slack);
  slack.sim.userOptional = new Set(['chat:write']);
  await slack.signIn({appId: 'slack', level: 'full'}, {grant: {omit: ['chat:write']}});
  assert.deepEqual(slackSeen[0].grant, {level: 'full', missing: ['chat:write']});
  const notion = harness(t, notionV2()), notionSeen = passed(notion);
  await notion.signIn({appId: 'notion'});
  assert.equal(Object.hasOwn(notionSeen[0], 'grant'), false, 'a page grant names no scopes');
  const v1 = harness(t, v1Definition('google')), v1Seen = passed(v1);
  await v1.signIn({appId: 'gmail', writeAccess: true});
  assert.equal(Object.hasOwn(v1Seen[0], 'grant'), false, 'version 1 stores nothing new');
});

test('correction 5: the insufficient_scope words name at most five permissions and how many more, and fall back to the plain words', async t => {
  const h = harness(t, googleV2(), {maps: ['gmail']}), plain = 'Google did not grant all the requested application permissions. No connection was activated.', asked = [];
  const refused = async grant => { const started = h.start({appId: 'gmail', level: 'full'}); let failure; await h.finish(started, h.consent(started, {grant})).catch(error => { failure = error; }); assert.equal(failure?.code, 'insufficient_scope'); return failure.message; };
  h.connections.setAccessExplainer((appId, scopes) => { asked.push([appId, scopes]); return Array.from({length: 7}, (_, index) => ({groupId: `row.${index}`, label: `Row ${index + 1}`})); });
  assert.equal(await refused({omit: [MODIFY]}), 'Google did not grant permissions that Gmail needs: Row 1; Row 2; Row 3; Row 4; Row 5 and 2 more. No connection was activated.');
  assert.deepEqual(asked, [['gmail', [MODIFY]]], 'only the missing required scopes, never the declined optional ones');
  h.connections.setAccessExplainer(() => [{groupId: 'a', label: 'Same\u0007 row'}, {groupId: 'b', label: 'Same row'}, {label: 7}, null]);
  assert.equal(await refused({omit: [MODIFY, SETTINGS]}), 'Google did not grant permissions that Gmail needs: Same row. No connection was activated.');
  h.connections.setAccessExplainer(() => { throw new Error('the explainer failed'); });
  assert.equal(await refused({omit: [MODIFY]}), plain);
  h.connections.setAccessExplainer(() => []);
  assert.equal(await refused({omit: [MODIFY]}), plain);
  assert.deepEqual(h.store.list('connections'), []);
});

test('the permissions a missing scope leaves without access: no alternative avoids it, locked rows left out, in row order', t => {
  const h = harness(t, googleV2());
  Object.assign(h.caps, seed(h.store, 'gmail', [...MAPS.gmail.operations, ['gmail.users.settings.sendAs.create', 'POST', '/gmail/v1/users/{userId}/settings/sendAs', [SETTINGS]], [null, 'GET', '/gmail/v1/users/{userId}/unlisted', [SETTINGS]], [null, 'POST', '/gmail/v1/users/{userId}/unlisted', [SETTINGS]]]));
  const mark = {groupId: GMAIL_MARK_ROW, label: 'Mark as read or unread, archive or label emails'}, settings = {groupId: GMAIL_SETTINGS_ROW, label: 'Change mail settings, filters and vacation reply'};
  // An unlisted Gmail write sits in the row Fabric locks (F10.3), so only the unlisted read reaches an Other row.
  assert.deepEqual(h.service.rowsNeeding('gmail', [SETTINGS, MODIFY]), [mark, settings, {groupId: 'other.read', label: 'Other reads'}], 'never the row Fabric locks');
  assert.deepEqual(h.service.rowsNeeding('gmail', [MODIFY]), [mark], 'reading an email can use gmail.readonly instead');
  assert.deepEqual(h.service.rowsNeeding('gmail', [READONLY, MODIFY]), [{groupId: 'gmail.messages.read', label: 'Access emails'}, mark]);
  assert.deepEqual(h.service.rowsNeeding('gmail', [CALENDAR]), []);
  assert.throws(() => h.service.rowsNeeding('no-such-app', [MODIFY]), {code: 'not_found'});
});

test('Gmail under the required consent policy asks for gmail.modify only: nothing was declined, and the label still counts what full access lacks', async t => {
  const h = harness(t, googleV2(), {publishing: 'production', maps: ['gmail']});
  const {started, connection} = await h.signIn({appId: 'gmail', level: 'full'});
  assert.equal(new URL(started.authorizationUrl).searchParams.get('scope'), `openid email ${MODIFY}`);
  assert.deepEqual(h.record(connection.id).grant, {level: 'full', missing: []});
  const page = h.view('gmail', connection.id);
  assert.deepEqual(page.notices, []);
  assert.equal(page.accounts[0].accessLabel, 'Partial access (1 permission not granted)', 'open question 18');
});

test('GitHub: an edited grant without gist narrows the gist rows; a returned parent counts as its children everywhere', async t => {
  const h = harness(t, githubV2(), {maps: ['github']});
  const {connection: edited} = await h.signIn({appId: 'github'}, {grant: {omit: ['gist']}});
  assert.equal(h.record(edited.id).status, 'ready');
  assert.deepEqual(h.record(edited.id).grant, {level: 'full', missing: ['gist']});
  let page = h.view('github', edited.id);
  assert.deepEqual([h.row(page, GISTS_READ).access, h.row(page, GISTS_WRITE).access], ['missing', 'missing']);
  assert.deepEqual(h.row(page, GISTS_READ).addAccess.body.scopes, ['gist']);
  h.connections.revoke(edited.id);
  // GitHub returns admin:org in place of read:org: read:org is held, not missing, and nothing asks for it again.
  const {connection} = await h.signIn({appId: 'github'}, {grant: {add: ['admin:org']}}), record = h.record(connection.id);
  assert.equal(record.status, 'ready');
  assert.deepEqual(record.grant, {level: 'full', missing: []});
  assert.deepEqual([record.scopes.includes('admin:org'), record.grantCeiling.includes('admin:org'), record.scopes.includes('read:org')], [true, true, false]);
  assert.equal(heldLevel(h.provider.access(h.provider.app('github')), record.scopes), 'full');
  page = h.view('github', connection.id);
  assert.equal(h.row(page, PROFILES).access, 'granted');
  assert.equal(Object.hasOwn(h.row(page, PROFILES), 'addAccess'), false);
  assert.equal(h.decision(connection.id, 'GET /user/orgs').providerAccess, 'granted');
  assert.equal(page.accounts.find(item => item.accountRef === connection.id).accessLabel, 'Full access');
});

test('correction 9: a GitHub grant of write:org in place of read:org is ready with nothing missing', async t => {
  const h = harness(t, githubV2(), {maps: ['github']});
  const {connection} = await h.signIn({appId: 'github'}, {grant: {add: ['write:org']}});
  assert.deepEqual(h.record(connection.id).grant, {level: 'full', missing: []});
  assert.equal(h.row(h.view('github', connection.id), PROFILES).access, 'granted');
});

test('Slack: declining a user_optional scope narrows the connection', async t => {
  const h = harness(t, slackV2());
  h.sim.userOptional = new Set(['chat:write']);
  const {connection} = await h.signIn({appId: 'slack', level: 'full'}, {grant: {omit: ['chat:write']}}), record = h.record(connection.id);
  assert.equal(record.status, 'ready');
  assert.deepEqual(record.scopes, ['channels:read', 'users:read']);
  assert.deepEqual(record.grant, {level: 'full', missing: ['chat:write']});
});

test('a partial renewal keeps the authorization and the ceiling, says what was declined once, and granting it back is still a renewal', async t => {
  const h = harness(t, googleV2(), {maps: ['gmail']});
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'}), first = h.record(connection.id);
  assert.deepEqual(first.grant, {level: 'full', missing: []});
  await h.signIn({connectionId: connection.id}, {grant: {omit: [SETTINGS]}});
  const narrowed = h.record(connection.id);
  assert.deepEqual([narrowed.authRevision, narrowed.grantCeiling], [first.authRevision, first.grantCeiling]);
  assert.notEqual(narrowed.signInRevision, first.signInRevision);
  assert.notEqual(h.store.connectionGeneration(connection.id), 1, 'the scopes changed');
  assert.deepEqual(narrowed.grant, {level: 'full', missing: [SETTINGS]});
  assert.equal(h.audits('connection.reconsented').length, 1);
  assert.deepEqual(h.notices(connection.id, 'grant_narrowed'), [], 'the declined box explains the lost scope');
  assert.deepEqual(h.view('gmail', connection.id).notices.map(notice => [notice.kind, notice.count]), [['not_granted', 1]]);
  await h.signIn({connectionId: connection.id});
  const restored = h.record(connection.id);
  assert.deepEqual([restored.authRevision, restored.grant], [first.authRevision, {level: 'full', missing: []}]);
  assert.equal(h.audits('connection.reconsented').length, 2);
  assert.deepEqual(h.view('gmail', connection.id).notices, []);
});

test('T7: granting a declined scope later is an upgrade; a saved Allow becomes Ask, Never stays Never, and the notice goes', async t => {
  const h = harness(t, googleV2(), {maps: ['gmail']});
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [SETTINGS]}}), before = h.record(connection.id);
  // A saved Allow on a member whose default is Ask (following a default Allow is still a default), and a saved Never.
  h.runtime.permissions.set({connectionId: connection.id, capabilityId: h.caps['gmail.users.messages.modify'], mode: 'allow'});
  h.runtime.permissions.set({connectionId: connection.id, capabilityId: h.caps['gmail.users.settings.updateVacation'], mode: 'deny'});
  const added = h.row(h.view('gmail', connection.id), GMAIL_SETTINGS_ROW).addAccess.body;
  await h.signIn(added);
  const after = h.record(connection.id);
  assert.notEqual(after.authRevision, before.authRevision);
  assert.ok(after.grantCeiling.includes(SETTINGS));
  assert.deepEqual(after.grant, {level: 'full', missing: []});
  assert.equal(h.audits('connection.upgraded').length, 1);
  const allowed = h.decision(connection.id, 'gmail.users.messages.modify');
  assert.deepEqual([allowed.mode, allowed.policySource], ['ask', 'stale']);
  assert.equal(h.decision(connection.id, 'gmail.users.settings.updateVacation').mode, 'deny');
  assert.deepEqual(h.view('gmail', connection.id).notices, []);
});

test('HEALTH: two renewals with the same scopes but a different asked set keep the generation', async t => {
  const h = harness(t, googleV2());
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [SETTINGS]}});
  assert.deepEqual(h.record(connection.id).grant, {level: 'full', missing: [SETTINGS]});
  const generation = h.store.connectionGeneration(connection.id);
  h.use({publishing: 'production'});
  await h.signIn({connectionId: connection.id});
  assert.deepEqual(h.record(connection.id).grant, {level: 'full', missing: []});
  assert.equal(h.store.connectionGeneration(connection.id), generation);
});

test('the refresh that shrinks scopes: narrowed, the ceiling kept, one grant_narrowed, not marked, and the grant untouched', async t => {
  const h = harness(t, googleV2());
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'}), before = h.record(connection.id);
  assert.deepEqual(before.grant, {level: 'full', missing: []});
  h.sim.refresh.get(h.vault.get(connection.id).refreshToken).scopes = ['openid', 'email', MODIFY];
  h.advance(3600 * 1000);
  await assert.rejects(h.connections.credentials(connection.id), {code: 'connection_changed'});
  const after = h.record(connection.id);
  assert.deepEqual([after.status, after.scopes, after.grantCeiling, after.grant], ['ready', ['openid', 'email', MODIFY], before.grantCeiling, before.grant]);
  assert.equal(h.notices(connection.id, 'grant_narrowed').length, 1);
});

// ---- part f: the grant on the record ---------------------------------------------------------------------------------------
test('establishOAuth takes a grant only as {level, missing}: full or read, scopes sorted and once each, bounded like scopes', async t => {
  const h = harness(t, googleV2()), many = Array.from({length: 1001}, (_, index) => `scope-${String(index).padStart(4, '0')}`);
  for (const grant of [null, 'full', [], {missing: []}, {level: 'partial', missing: []}, {level: 'full'}, {level: 'full', missing: [], extra: true}, {level: 'full', missing: 'a'}, {level: 'full', missing: ['b', 'a']},
    {level: 'full', missing: ['a', 'a']}, {level: 'full', missing: ['']}, {level: 'full', missing: [7]}, {level: 'full', missing: ['x'.repeat(2001)]}, {level: 'full', missing: many}])
    await assert.rejects(h.connections.establishOAuth({tokens: {accessToken: 'synthetic-access', expiresAt: null, scopes: [MODIFY]}, appId: 'gmail', providerId: 'google', grant}), {code: 'invalid_input'}, JSON.stringify(grant)?.slice(0, 60));
  assert.deepEqual([h.store.list('connections'), h.sim.calls], [[], []], 'refused before the identity call');
});

test('a sign-in that carries no grant drops the old one: a flow stored before F10.5 renews the account, and its notice goes', async t => {
  const h = harness(t, googleV2(), {maps: ['gmail']});
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [SETTINGS]}});
  assert.equal(h.view('gmail', connection.id).notices.length, 1);
  h.use({publishing: 'production'});
  const started = h.start({connectionId: connection.id}), {level: chosen, required, ...old} = h.flowOf(started);
  assert.deepEqual([chosen, required], ['full', [MODIFY]]);
  h.store.put('oauthFlows', old);
  await h.finish(started, h.consent(started));
  const record = h.record(connection.id);
  assert.deepEqual([Object.hasOwn(record, 'grant'), record.scopes, h.audits('connection.reconsented').length], [false, ['openid', 'email', MODIFY], 1]);
  assert.deepEqual(h.view('gmail', connection.id).notices, []);
});

test('a renewal says the provider gave less only for the scopes the sign-in did not decline', async t => {
  const h = harness(t, googleV2()), LABELS = `${G}gmail.labels`;
  // Google granted one scope more than was asked for at the first sign-in (open question 10); a reconnect never asks for it.
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'}, {grant: {add: [LABELS]}}), first = h.record(connection.id);
  assert.ok(first.grantCeiling.includes(LABELS));
  await h.signIn({connectionId: connection.id}, {grant: {omit: [SETTINGS]}});
  const record = h.record(connection.id);
  assert.deepEqual([record.authRevision, record.grant, h.audits('connection.reconsented').length], [first.authRevision, {level: 'full', missing: [SETTINGS]}, 1]);
  assert.deepEqual(h.notices(connection.id, 'grant_narrowed').map(notice => notice.subjectKey), [scopesSubject([LABELS])], 'the declined box explains only the scope it declined');
});

// ---- part g: implications wherever access is read --------------------------------------------------------------------------
test('one reading of what an account holds: PermissionManager reads scopes through scopesOf, ConnectionManager through the definition', t => {
  const plain = new PermissionManager({store: {}}), through = new PermissionManager({store: {}, scopesOf: connection => connection.id === 'none' ? undefined : [...connection.scopes, 'implied']});
  assert.deepEqual([plain.grantedScopes({scopes: ['a', 'b']}), through.grantedScopes({id: 'x', scopes: ['a']}), through.grantedScopes({id: 'none', scopes: ['a']})], [['a', 'b'], ['a', 'implied'], ['a']]);
  for (const scopes of [undefined, null, 'a', ['a', 7], ['a', ''], ['x'.repeat(1001)]]) assert.deepEqual(plain.grantedScopes({scopes}), [], String(scopes));
  const h = harness(t, githubV2()), record = {id: 'gh', appId: 'github', providerId: 'github', authMethod: 'oauth', scopes: ['repo', 'admin:org']};
  assert.deepEqual(h.connections.effectiveScopes(record), ['repo', 'admin:org', 'public_repo', 'repo:status', 'repo_deployment', 'repo:invite', 'security_events', 'write:org', 'read:org']);
  assert.deepEqual(h.runtime.permissions.grantedScopes(record), h.connections.effectiveScopes(record), 'the runtime\'s own manager reads it');
  for (const other of [{...record, authMethod: 'token'}, {...record, appId: 'no-such-app'}, {...record, providerId: 'slack'}]) assert.deepEqual(h.connections.effectiveScopes(other), record.scopes, 'anything else, or a failure: the scopes as stored');
  assert.equal(h.connections.effectiveScopes({...record, scopes: undefined}), undefined);
  const v1 = harness(t, v1Definition('github'));
  assert.deepEqual(v1.connections.effectiveScopes({...record, scopes: ['repo', 'admin:org', 'repo']}), ['repo', 'admin:org', 'repo'], 'version 1 implies nothing');
});

test('the held level counts what a granted parent grants, and calls an account read-only by what it was granted', () => {
  const definition = githubV2(); definition.apps[0].access.levels.read = {required: ['repo'], optional: []};
  const github = validateAuthDefinition(definition), app = normalizeAuthApp(github, github.apps[0]);
  assert.deepEqual(heldLevel(app, ['read:user', 'repo', 'admin:org']), {level: 'partial', notGranted: 2}, 'read:org is held');
  assert.equal(heldLevel(app, ['read:user', 'repo', 'admin:org', 'gist', 'workflow']), 'full');
  assert.equal(heldLevel(app, ['repo']), 'read', 'a read scope\'s own children never make it custom');
  assert.equal(heldLevel(app, ['repo', 'admin:org']), 'custom');
});

test('a returned parent counts in proxy decisions too: a proxy read of /user/orgs on an account holding admin:org has provider access', async t => {
  const h = harness(t, githubV2(), {maps: ['github']});
  const {connection} = await h.signIn({appId: 'github'}, {grant: {add: ['admin:org']}});
  assert.deepEqual(['groupId', 'providerAccess'].map(key => h.runtime.proxyPolicy.decide(connection.id, {method: 'GET', path: '/user/orgs'})[key]), [PROFILES, 'granted']);
  const {connection: edited} = await h.signIn({appId: 'github'}, {account: 'b', grant: {omit: ['read:org']}});
  assert.equal(h.runtime.proxyPolicy.decide(edited.id, {method: 'GET', path: '/user/orgs'}).providerAccess, 'missing');
});

test('Add access asks only for what the account does not already hold through a granted parent', async t => {
  const h = harness(t, githubV2(), {maps: ['github']}), map = h.store.get('applicationMaps', 'github');
  // A member that needs gist and read:org together.
  h.store.put('applicationMaps', {...map, operations: map.operations.map(operation => operation.id === 'POST /gists' ? {...operation, requiredScopes: ['gist', 'read:org'], scopeSets: [['gist', 'read:org']]} : operation)});
  const {connection} = await h.signIn({appId: 'github'}, {grant: {omit: ['gist'], add: ['admin:org']}});
  assert.deepEqual(h.row(h.view('github', connection.id), GISTS_WRITE).addAccess.body.scopes, ['gist']);
});

test('correction 2: the upgrade card and the callback wall read implications in what the account holds and will hold', async t => {
  const h = harness(t, githubV2(), {maps: ['github']});
  const {connection: holder} = await h.signIn({appId: 'github'}, {account: 'b', grant: {add: ['admin:org']}}), held = h.record(holder.id);
  const card = (account, scopes) => h.service.upgradeCard(account, h.service.rows(h.service.app('github'), account), scopes).rows.map(row => row.groupId);
  assert.equal(card(held, [...held.scopes, 'read:org']).includes(PROFILES), false, 'already held through admin:org');
  const {connection} = await h.signIn({appId: 'github'}, {grant: {omit: ['read:org']}}), previous = h.record(connection.id);
  assert.ok(card(previous, ['read:user', 'repo', 'admin:org']).includes(PROFILES), 'admin:org turns the organization row on');
  assert.ok(card(previous, ['read:user', 'repo', 'read:org']).includes(PROFILES));
  assert.equal(card(previous, ['read:user', 'repo', 'gist']).includes(PROFILES), false);
  // The provider granted admin:org: a confirmed card that holds it covers the organization row; one that confirmed less does not.
  h.store.put('connections', {...previous, scopes: [...previous.scopes, 'admin:org']});
  h.service.pinUnconfirmed(previous, h.record(connection.id), ['admin:org']);
  assert.equal(h.decision(connection.id, 'GET /user/orgs').policySource, 'default');
  h.service.pinUnconfirmed(previous, h.record(connection.id), ['read:user']);
  assert.deepEqual(['policySource', 'mode'].map(key => h.decision(connection.id, 'GET /user/orgs')[key]), ['saved', 'ask']);
});

test('correction 8: ceilings stay raw, so a parent in the ceiling does not cover its child; the wall keeps what the parent already ran', async t => {
  const h = harness(t, githubV2(), {maps: ['github']});
  const {connection} = await h.signIn({appId: 'github'}, {grant: {add: ['admin:org']}}), before = h.record(connection.id);
  assert.deepEqual([before.grantCeiling.includes('admin:org'), before.grantCeiling.includes('read:org')], [true, false]);
  // GitHub now returns read:org itself: outside the raw ceiling, so an upgrade (T7), though admin:org granted it before.
  await h.signIn({connectionId: connection.id});
  const after = h.record(connection.id);
  assert.notEqual(after.authRevision, before.authRevision);
  assert.deepEqual([h.audits('connection.upgraded').length, after.grantCeiling.includes('read:org'), after.grantCeiling.includes('admin:org')], [1, true, true]);
  // The callback wall reads what the account held through admin:org, so the organization row keeps running at its default.
  assert.deepEqual(['providerAccess', 'policySource', 'mode'].map(key => h.decision(connection.id, 'GET /user/orgs')[key]), ['granted', 'default', 'allow']);
});

// ---- part h: the not-granted notice ----------------------------------------------------------------------------------------
test('the not-granted notice is derived from the current sign-in, never stored, after every stored notice, and gone once held', t => {
  const h = harness(t, googleV2()), at = '2026-10-11T12:00:00.000Z';
  const account = {id: 'gm', appId: 'gmail', providerId: 'google', authMethod: 'oauth', status: 'ready', authRevision: 'a-1', signInRevision: 's-1', signedInAt: at, createdAt: '2026-10-01T00:00:00.000Z', scopes: ['openid', MODIFY], grant: {level: 'full', missing: [SETTINGS]}};
  const [notice] = current(h.store, account);
  assert.deepEqual(notice, {id: notice.id, type: 'connection.health', kind: 'not_granted', connectionId: 'gm', appId: 'gmail', signInRevision: 's-1', count: 1, createdAt: at});
  assert.notEqual(current(h.store, {...account, signInRevision: 's-2'})[0].id, notice.id, 'one per sign-in');
  assert.equal(current(h.store, {...account, signedInAt: undefined})[0].createdAt, account.createdAt);
  assert.deepEqual(current(h.store, {...account, grant: {level: 'full', missing: [READONLY, SETTINGS]}}).map(item => item.count), [2]);
  for (const other of [{...account, scopes: ['openid', MODIFY, SETTINGS]}, {...account, grant: {level: 'full', missing: []}}, {...account, grant: undefined}, {...account, status: 'pending_confirmation'}, {...account, status: 'revoked'}])
    assert.deepEqual(current(h.store, other), [], JSON.stringify(other));
  // An account that needs a sign-in is more urgent than one that lacks some optional access.
  const marked = {...account, status: 'reconnect_required'};
  raise(h.store, {connection: marked, kind: 'reconnect_required'}); raise(h.store, {connection: marked, kind: 'grant_narrowed', subjectKey: scopesSubject([READONLY])});
  assert.deepEqual(current(h.store, marked).map(item => item.kind), ['reconnect_required', 'grant_narrowed', 'not_granted']);
  assert.throws(() => raise(h.store, {connection: account, kind: 'not_granted'}), /Unknown connection notice/);
  assert.deepEqual([NOTICE_KINDS, DERIVED_KINDS], [['reconnect_required', 'grant_narrowed', 'org_restricted', 'consent_expiring'], ['not_granted']]);
  assert.deepEqual(h.store.list('activity').filter(event => event.kind === 'not_granted'), []);
});

test('correction 6: a shown not-granted notice says how many, and with the selected account\'s words and rows copies them; stored notices keep four keys', () => {
  const derived = {id: 'n', type: 'connection.health', kind: 'not_granted', connectionId: 'gm', appId: 'gmail', signInRevision: 's-1', count: 2, createdAt: '2026-10-11T12:00:00.000Z'};
  assert.deepEqual(shownNotice(derived), {kind: 'not_granted', accountRef: 'gm', message: NOTICE_WORDS.not_granted, since: derived.createdAt, count: 2});
  const rows = [{groupId: GMAIL_SETTINGS_ROW, label: 'Change mail settings, filters and vacation reply', members: ['dropped']}], shown = shownNotice({...derived, message: 'Own words.', rows});
  assert.deepEqual(Object.keys(shown).sort(), ['accountRef', 'count', 'kind', 'message', 'rows', 'since']);
  assert.deepEqual([shown.message, shown.rows], ['Own words.', [{groupId: GMAIL_SETTINGS_ROW, label: 'Change mail settings, filters and vacation reply'}]]);
  assert.notEqual(shown.rows[0], rows[0], 'copied, never the caller\'s row');
  assert.deepEqual(shownNotice({...derived, kind: 'grant_narrowed', message: 'Injected.', rows}), {kind: 'grant_narrowed', accountRef: 'gm', message: NOTICE_WORDS.grant_narrowed, since: derived.createdAt});
  assert.match(NOTICE_WORDS.not_granted, /^Some permissions were not granted at sign-in\./);
  assert.doesNotMatch(NOTICE_WORDS.not_granted, /disconnect/i);
});

test('the app page names rows only on the selected account\'s notice; another account\'s notice says how many', async t => {
  const h = harness(t, googleV2(), {maps: ['gmail']});
  const {connection: first} = await h.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [SETTINGS]}});
  const {connection: second} = await h.signIn({appId: 'gmail', level: 'full'}, {account: 'b', grant: {omit: [SETTINGS]}});
  const page = h.view('gmail', second.id), mine = page.notices.find(item => item.accountRef === second.id), other = page.notices.find(item => item.accountRef === first.id);
  assert.deepEqual([Object.keys(mine).sort(), Object.keys(other).sort()], [['accountRef', 'count', 'kind', 'message', 'rows', 'since'], ['accountRef', 'count', 'kind', 'message', 'since']]);
  assert.equal(mine.message, '1 permission was not granted at sign-in: Change mail settings, filters and vacation reply. Add it from that permission below.');
  assert.deepEqual([other.count, other.message], [1, NOTICE_WORDS.not_granted]);
  for (const account of page.accounts) assert.equal(account.attention, NOTICE_WORDS.not_granted);
  // Without an application map no permission can be named, and the words still say how many.
  const bare = harness(t, googleV2()), {connection} = await bare.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [SETTINGS]}});
  assert.deepEqual(['message', 'rows'].map(key => bare.view('gmail', connection.id).notices[0][key]), ['1 permission was not granted at sign-in.', []]);
});

test('the notice names the typed and proxy rows the declined scopes would turn on, in row order, and never a row Fabric locks', async t => {
  const h = harness(t, googleV2());
  // An unlisted Gmail write sits in the row Fabric locks (F10.3); an unlisted read sits in Other reads.
  Object.assign(h.caps, seed(h.store, 'gmail', [...MAPS.gmail.operations, [null, 'GET', '/gmail/v1/users/{userId}/unlisted', [SETTINGS]], [null, 'POST', '/gmail/v1/users/{userId}/unlisted', [SETTINGS]]]));
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'}, {grant: {omit: [SETTINGS]}}), [notice] = h.view('gmail', connection.id).notices;
  assert.deepEqual(notice.rows, [{groupId: GMAIL_SETTINGS_ROW, label: 'Change mail settings, filters and vacation reply'}, {groupId: 'other.read', label: 'Other reads'}]);
  assert.equal(notice.message, '1 permission was not granted at sign-in: Change mail settings, filters and vacation reply; Other reads. Add it from those permissions below.');
  // A proxy row whose member the map documents but no typed operation carries.
  const github = harness(t, githubV2());
  seed(github.store, 'github', [[null, 'GET', '/user/repos', ['repo']]]);
  const map = github.store.get('applicationMaps', 'github');
  github.store.put('applicationMaps', {...map, operations: [...map.operations, {id: 'GET /gists', method: 'GET', path: '/gists', requiredScopes: ['gist']}]});
  const {connection: edited} = await github.signIn({appId: 'github'}, {grant: {omit: ['gist']}});
  // F10.7: the shipped rows say gist serves the gist writes and the gist deletes too, so their proxy rows are named as well.
  assert.deepEqual(github.view('github', edited.id).notices[0].rows, [{groupId: GISTS_READ, label: 'Access gists'}, {groupId: 'github.gists.write', label: 'Create and edit gists'},
    {groupId: 'github.permanent.delete', label: 'Permanently delete repos, comments, releases and gists'}]);
});

// ---- part d: never-request refusals at the callback (T1) ------------------------------------------------------------------
test('critique test 1: a Google grant with the unrequested mail.google.com is refused; no revoke, Calendar untouched, nothing written', async t => {
  const h = harness(t, googleV2());
  const {connection: calendar} = await h.signIn({appId: 'google-calendar'});
  const before = h.record(calendar.id), tokens = h.vault.get(calendar.id), generation = h.store.connectionGeneration(calendar.id), files = h.vaultFiles();
  const started = h.start({appId: 'gmail', level: 'full'}), grant = h.consent(started, {grant: {add: [MAILBOX]}}), sent = h.sim.calls.length;
  let failure;
  await h.finish(started, grant).catch(error => { failure = error; });
  assert.deepEqual([failure?.code, failure?.providerGrant], ['never_requested', 'may_remain']);
  assert.ok(!JSON.stringify({...failure, message: failure.message}).includes(issuedToken(h, 'google')), 'the tokens are dropped, never attached');
  assert.deepEqual(h.sim.calls.slice(sent).map(req => req.url), [TOKEN.google], 'the exchange, then nothing: no identity call and no revoke');
  assert.deepEqual(h.calls(REVOKE.google), []);
  const after = h.record(calendar.id);
  assert.deepEqual([after.status, after.authRevision, after.signInRevision], ['ready', before.authRevision, before.signInRevision]);
  assert.equal(h.store.connectionGeneration(calendar.id), generation);
  assert.deepEqual(h.vault.get(calendar.id), tokens);
  assert.ok(h.sim.access.has(tokens.accessToken), 'Calendar still reads');
  assert.deepEqual(h.accounts('gmail'), []);
  assert.equal(h.vaultFiles(), files);
  assert.deepEqual(h.store.list('oauthFlows'), []);
  await assert.rejects(h.finish(started, grant), {code: 'invalid_state'});
  const [audit] = h.audits('connection.scope_refused');
  assert.deepEqual({providerId: audit.providerId, appId: audit.appId, connectionId: audit.connectionId, providerGrant: audit.providerGrant, scopes: audit.scopes},
    {providerId: 'google', appId: 'gmail', connectionId: null, providerGrant: 'may_remain', scopes: [MAILBOX]});
  assert.match(failure.message, /Google granted a permission Fabric never holds for Gmail, so nothing was connected\./);
  assert.doesNotMatch(failure.message, /mail\.google\.com/);
});

test('critique test 1, reconnect: the refused sign-in leaves the Gmail account\'s tokens, scopes and generation as they were', async t => {
  const h = harness(t, googleV2());
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'}), before = h.record(connection.id), tokens = h.vault.get(connection.id), generation = h.store.connectionGeneration(connection.id);
  const started = h.start({connectionId: connection.id});
  await assert.rejects(h.finish(started, h.consent(started, {grant: {add: [MAILBOX]}})), {code: 'never_requested', providerGrant: 'may_remain'});
  assert.deepEqual(h.record(connection.id), before);
  assert.deepEqual(h.vault.get(connection.id), tokens);
  assert.equal(h.store.connectionGeneration(connection.id), generation);
  assert.equal(h.audits('connection.scope_refused')[0].connectionId, connection.id);
  assert.deepEqual(h.calls(REVOKE.google), []);
});

test('open question 6: a Calendar grant carrying mail.google.com is refused too', async t => {
  const h = harness(t, googleV2());
  const started = h.start({appId: 'google-calendar'});
  await assert.rejects(h.finish(started, h.consent(started, {grant: {add: [MAILBOX]}})), {code: 'never_requested', providerGrant: 'may_remain'});
  assert.deepEqual([h.store.list('connections'), h.calls(REVOKE.google)], [[], []]);
});

test('an account-request sign-in refused for a never-request scope sends no Google revoke and parks nothing', async t => {
  const h = harness(t, googleV2()), admitted = [];
  const started = h.start({appId: 'gmail', level: 'full'}, {continuation: {id: randomUUID(), notAfter: new Date(Date.UTC(2026, 9, 11, 13)).toISOString()}});
  await assert.rejects(h.finish(started, h.consent(started, {grant: {add: [MAILBOX]}}), {admitContinuation: flow => admitted.push(flow.id)}), {code: 'never_requested', providerGrant: 'may_remain'});
  assert.equal(admitted.length, 1, 'refused before anything would be persisted');
  assert.deepEqual([h.store.list('connections'), h.calls(REVOKE.google)], [[], []]);
});

test('the closure: a grant of a parent of a never-request scope is refused', async t => {
  const definition = githubV2(); definition.apps[0].neverRequest = ['delete_repo', 'user', 'write:public_key'];
  const h = harness(t, definition), started = h.start({appId: 'github'});
  await assert.rejects(h.finish(started, h.consent(started, {grant: {add: ['admin:public_key']}})), {code: 'never_requested', providerGrant: 'revoked'});
  assert.deepEqual(h.audits('connection.scope_refused')[0].scopes, ['admin:public_key']);
  assert.deepEqual(h.store.list('connections'), []);
});

test('GitHub user: refused, the new token revoked once with Basic client auth, and the words name github.com/settings/applications', async t => {
  const h = harness(t, githubV2()), files = h.vaultFiles();
  const started = h.start({appId: 'github'}), grant = h.consent(started, {grant: {add: ['user']}});
  let failure;
  await h.finish(started, grant).catch(error => { failure = error; });
  assert.deepEqual([failure?.code, failure?.providerGrant], ['never_requested', 'revoked']);
  assert.match(failure.message, /github\.com\/settings\/applications/);
  const revokes = h.calls(REVOKE.github), issued = issuedToken(h, 'github');
  assert.equal(revokes.length, 1);
  assert.equal(revokes[0].method, 'DELETE');
  assert.equal(Buffer.from(String(revokes[0].headers.Authorization).replace(/^Basic /, ''), 'base64').toString(), `${CLIENT.clientId}:${CLIENT.clientSecret}`);
  assert.equal(JSON.parse(revokes[0].body).access_token, issued);
  assert.equal(h.sim.access.has(issued), false);
  assert.deepEqual(h.calls(IDENTITY.github), []);
  assert.deepEqual([h.store.list('connections'), h.store.list('oauthFlows')], [[], []]);
  assert.equal(h.vaultFiles(), files);
});

test('GitHub user, variants: an unconfirmed revoke, a local_only adapter, and a definition without settingsUrl', async t => {
  const refuse = async (h, check) => { const started = h.start({appId: 'github'}); await assert.rejects(h.finish(started, h.consent(started, {grant: {add: ['user']}})), check); };
  const failing = harness(t, githubV2());
  failing.sim.revokeFails = true;
  await refuse(failing, error => error.code === 'never_requested' && error.providerGrant === 'may_remain' && /github\.com\/settings\/applications/.test(error.message));
  assert.equal(failing.calls(REVOKE.github).length, 1);
  const local = harness(t, githubV2(), {revocationPolicy: 'local_only'});
  await refuse(local, error => error.code === 'never_requested' && error.providerGrant === 'may_remain');
  assert.equal(local.calls(REVOKE.github).length, 0);
  const plain = githubV2(); delete plain.revocation.settingsUrl;
  await refuse(harness(t, plain), error => error.code === 'never_requested' && /in your GitHub account settings/.test(error.message) && !/github\.com\/settings/.test(error.message));
});

test('the refusal comes first: a grant that also lacks a required scope is never_requested, its token revoked, and the words say what happened', async t => {
  const h = harness(t, githubV2()), started = h.start({appId: 'github'});
  let failure;
  await h.finish(started, h.consent(started, {grant: {omit: ['repo'], add: ['user']}})).catch(error => { failure = error; });
  assert.deepEqual([failure?.code, failure?.providerGrant, h.calls(REVOKE.github).length], ['never_requested', 'revoked', 1]);
  assert.equal(failure.message, `GitHub granted a permission Fabric never holds for GitHub, so nothing was connected. Fabric revoked the new GitHub token. GitHub keeps that permission on Fabric's authorization. Remove Fabric at ${GITHUB_SETTINGS}, then connect again.`);
  assert.deepEqual(Object.keys(failure).sort(), ['code', 'providerGrant'], 'the tokens are never attached');
  const shared = harness(t, slackV2());
  await shared.signIn({appId: 'slack', level: 'full'});
  shared.sim.reuseUserToken = true;
  const again = shared.start({appId: 'slack', level: 'full'});
  await assert.rejects(shared.finish(again, shared.consent(again, {grant: {add: ['admin']}})), {code: 'never_requested', providerGrant: 'shared',
    message: 'Slack granted a permission Fabric never holds for Slack, so nothing was connected. Fabric left the new Slack token alone, because an account here still uses it. Slack keeps that permission on Fabric\'s authorization. Remove Fabric in your Slack account settings, then connect again.'});
  const local = harness(t, githubV2(), {revocationPolicy: 'local_only'}), quiet = local.start({appId: 'github'});
  await assert.rejects(local.finish(quiet, local.consent(quiet, {grant: {add: ['user']}})), {message: /Fabric did not ask GitHub to revoke the new token\./});
  const failing = harness(t, githubV2()), unconfirmed = failing.start({appId: 'github'});
  failing.sim.revokeFails = true;
  await assert.rejects(failing.finish(unconfirmed, failing.consent(unconfirmed, {grant: {add: ['user']}})), {message: /Fabric asked GitHub to revoke the new token, and GitHub did not confirm it\./});
});

test('a grant without a never-request scope is not refused, and a version 1 definition refuses nothing', async t => {
  const h = harness(t, googleV2());
  const {connection} = await h.signIn({appId: 'gmail', level: 'full'});
  assert.equal(h.record(connection.id).status, 'ready');
  const v1 = harness(t, v1Definition('google')), {connection: kept} = await v1.signIn({appId: 'gmail', writeAccess: true}, {grant: {add: [MAILBOX]}});
  assert.ok(v1.record(kept.id).scopes.includes(MAILBOX), 'version 1 never-requests nothing until F10.7');
  assert.deepEqual([h.audits('connection.scope_refused'), v1.audits('connection.scope_refused')], [[], []]);
});

test('Slack admin: refused with one auth.revoke attempt', async t => {
  const h = harness(t, slackV2()), started = h.start({appId: 'slack', level: 'full'});
  await assert.rejects(h.finish(started, h.consent(started, {grant: {add: ['admin']}})), {code: 'never_requested', providerGrant: 'revoked'});
  assert.equal(h.calls(REVOKE.slack).length, 1);
  assert.deepEqual(h.store.list('connections'), []);
});

test('N9, open question 15: a refused Slack token that a live account here holds is left alone and reported shared', async t => {
  const h = harness(t, slackV2());
  const {connection: live} = await h.signIn({appId: 'slack', level: 'full'}), before = h.record(live.id), token = h.vault.get(live.id).accessToken;
  h.sim.reuseUserToken = true;
  const started = h.start({appId: 'slack', level: 'full'});
  await assert.rejects(h.finish(started, h.consent(started, {grant: {add: ['admin']}})), {code: 'never_requested', providerGrant: 'shared'});
  assert.equal(issuedToken(h, 'slack'), token, 'Slack reissued the live account\'s token');
  assert.deepEqual(h.calls(REVOKE.slack), []);
  assert.deepEqual(h.record(live.id), before);
  assert.equal(h.vault.get(live.id).accessToken, token);
  assert.ok(h.sim.access.has(token));
});

test('open question 14: a closed account request whose reissued Slack token a live account holds reports shared and sends no revoke', async t => {
  const h = harness(t, slackV2());
  const {connection: live} = await h.signIn({appId: 'slack', level: 'full'}), token = h.vault.get(live.id).accessToken;
  h.sim.reuseUserToken = true;
  let admissions = 0;
  const started = h.start({appId: 'slack', level: 'full'}, {continuation: {id: randomUUID(), notAfter: new Date(Date.UTC(2026, 9, 11, 13)).toISOString()}});
  await assert.rejects(h.finish(started, h.consent(started), {admitContinuation: () => { if (++admissions > 1) throw closed(); }}), {code: 'continuation_closed', providerGrant: 'shared'});
  assert.deepEqual(h.calls(REVOKE.slack), []);
  assert.equal(h.record(live.id).status, 'ready');
  assert.ok(h.sim.access.has(token));
});

// ---- part j: account requests --------------------------------------------------------------------------------------------
test('an account request refused for a never-request scope records scope_refused and its provider grant, with no account', async t => {
  const f = await signinFixture(t);
  const {id} = await f.ask();
  const started = await f.signIn(id);
  // Correction 7: the version 2 twin of the server's GitHub adapter, bound on the server's own ConnectionManager the way
  // test/sibling-disconnect.test.mjs binds one. The server keeps its version 1 adapter for routes, so the callback runs here
  // with the same trusted admission hook, and its error goes to the account request as the callback route sends it.
  const twin = new OAuth2Provider(githubV2(), {store: f.app.store, vault: f.app.vault, connections: f.app.connections, request: req => f.sim.request(req), clock: () => f.now,
    clientId: SIGNIN_ENV.FABRIC_GITHUB_CLIENT_ID, clientSecret: SIGNIN_ENV.FABRIC_GITHUB_CLIENT_SECRET, redirectUri: `${f.app.origin}/api/oauth/github/callback`});
  f.app.connections.setOAuthProvider(twin);
  const consent = f.sim.consent(started.body.authorizationUrl, {grant: {add: ['user']}});
  let error;
  await twin.callback({state: consent.state, code: consent.code, flowId: started.flowId}, {admitContinuation: flow => f.app.continuations.admitCallback(flow)}).catch(failure => { error = failure; });
  assert.deepEqual([error?.code, error?.providerGrant], ['never_requested', 'revoked']);
  f.app.continuations.completeSignIn(id, sha(started.flowId), {error});
  const view = await f.view(id);
  assert.deepEqual([view.status, view.lastAttempt.outcome], ['awaiting_owner', 'scope_refused']);
  assert.match(describeHandoff(view).notice.text, /^GitHub granted a permission Fabric never holds\. No account was connected\./);
  assert.deepEqual(f.app.store.list('activity').filter(event => event.type === 'continuation.scope_refused').map(event => [event.continuationId, event.providerGrant]), [[id, 'revoked']]);
  assert.deepEqual(f.connections(), []);
  assert.equal(f.sim.calls.filter(req => req.method === 'DELETE' && req.url.endsWith(`/applications/${SIGNIN_ENV.FABRIC_GITHUB_CLIENT_ID}/token`)).length, 1);
});

test('the single-owner server installs the access explainer: a version 2 sign-in without a required scope names the server\'s own row', async t => {
  const f = await signinFixture(t);
  // The same twin, bound on the server's ConnectionManager, reads the explainer server.mjs installed there. The fixture's map
  // documents repo only for creating issues, which the app page shows in its Other changes row: the one permission it names.
  const twin = new OAuth2Provider(githubV2(), {store: f.app.store, vault: f.app.vault, connections: f.app.connections, request: req => f.sim.request(req), clock: () => f.now,
    clientId: SIGNIN_ENV.FABRIC_GITHUB_CLIENT_ID, clientSecret: SIGNIN_ENV.FABRIC_GITHUB_CLIENT_SECRET, redirectUri: `${f.app.origin}/api/oauth/github/callback`, publishing: 'testing'});
  f.app.connections.setOAuthProvider(twin);
  const started = twin.start({appId: 'github'}), consent = f.sim.consent(started.authorizationUrl, {grant: {omit: ['repo']}});
  await assert.rejects(twin.callback({state: consent.state, code: consent.code, flowId: started.flowId}), {code: 'insufficient_scope', message: 'GitHub did not grant permissions that GitHub needs: Other changes. No connection was activated.'});
  assert.deepEqual(f.connections(), []);
});

test('correction 1: an account request whose operation needs an optional scope sends it as a required scope, so declining it activates nothing', async t => {
  const h = harness(t, googleV2(), {maps: ['gmail']});
  const plan = new ContinuationService({store: h.store}).signInPlan({grantEntry: {appId: 'gmail', capabilityId: h.caps['gmail.users.settings.updateVacation']}}, h.provider);
  assert.deepEqual(plan, {scopes: [SETTINGS], grantable: true});
  const started = h.start({appId: 'gmail', writeAccess: true, scopes: plan.scopes});
  assert.deepEqual(h.flowOf(started).required, [MODIFY, SETTINGS]);
  await assert.rejects(h.finish(started, h.consent(started, {grant: {omit: [SETTINGS]}})), {code: 'insufficient_scope'});
  assert.deepEqual(h.store.list('connections'), []);
  // A scope the level requires is already asked for; version 1 plans as before, against its read-and-write set (T6).
  assert.deepEqual(new ContinuationService({store: h.store}).signInPlan({grantEntry: {appId: 'gmail', capabilityId: h.caps['gmail.users.messages.modify']}}, h.provider), {scopes: [], grantable: true});
  const v1 = harness(t, v1Definition('google'), {maps: ['gmail']}), plan1 = capabilityId => new ContinuationService({store: v1.store}).signInPlan({grantEntry: {appId: 'gmail', capabilityId}}, v1.provider);
  assert.deepEqual([plan1(v1.caps['gmail.users.settings.updateVacation']), plan1(v1.caps['gmail.users.messages.get'])], [{scopes: [SETTINGS], grantable: true}, {scopes: [], grantable: true}]);
});

// ---- correction 10: the recovery address reaches every page -------------------------------------------------------------------
test('correction 10: an account request\'s sign-in summary carries the definition\'s settingsUrl, and the continue page words use it', t => {
  const summary = h => new ContinuationService({store: h.store, oauthRoute: () => ({providerId: h.provider.providerId, name: h.provider.name, available: true, reason: null}), signInProvider: () => h.provider})
    .signInSummary({grantEntry: {appId: h.provider.appIds[0], capabilityId: 'none', effect: 'read'}, attempts: 0});
  const github = summary(harness(t, githubV2())), plain = githubV2(); delete plain.revocation.settingsUrl;
  assert.equal(github.settingsUrl, GITHUB_SETTINGS);
  assert.equal(Object.hasOwn(summary(harness(t, plain)), 'settingsUrl'), false);
  assert.equal(Object.hasOwn(summary(harness(t, v1Definition('github'))), 'settingsUrl'), false, 'no checked-in definition sets it before F10.7');
  const view = signIn => ({id: randomUUID(), phase: 'awaiting_owner', expiresAt: '2026-10-11T12:30:00.000Z', client: {name: 'Muse'}, app: {id: 'github', name: 'GitHub'}, operation: {capabilityId: 'github.gists', name: 'List gists', effect: 'read'},
    arguments: {}, accounts: [], signIn, lastAttempt: {outcome: 'scope_refused', at: '2026-10-11T12:00:00.000Z'}, viewDigest: 'view-1', actions: ['select', 'sign_in', 'decline']});
  assert.deepEqual(describeHandoff(view(github)).notice, {kind: 'warn', text: `GitHub granted a permission Fabric never holds. No account was connected. You can remove Fabric at ${GITHUB_SETTINGS}, then sign in again.`});
  assert.equal(describeHandoff(view({...github, settingsUrl: undefined})).notice.text, 'GitHub granted a permission Fabric never holds. No account was connected. You can remove Fabric in your GitHub account settings, then sign in again.');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, readdirSync, readFileSync, statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {ProviderApps} from '../lib/tenant/provider-apps.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';

// F03.8 slice 1 (docs/F03.8-BUILD-MAP.md): a developer registers its own sign-in app per environment. The secret lives
// only in the environment's vault and never comes back; a client id Fabric holds, or one another environment proved,
// is taken; pending registrations never block anyone.
const CANARY = 'canary-secret-7f3a9c1e', SETTINGS = {github: {clientId: 'gh-shared-client', clientSecret: 'gh-shared-secret'}, google: {clientId: 'g-shared-client', clientSecret: 'g-shared-secret'}};
const files = dir => readdirSync(dir).flatMap(name => { const full = path.join(dir, name); return statSync(full).isDirectory() ? files(full) : [full]; });

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-provider-apps-'));
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: SETTINGS, fabricClientIds: [{providerId: 'google', clientId: 'fabric-local-google'}], relay: {base: 'https://connect.example.com', appsReady: false}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'});
  const environment = () => {
    const project = app.registry.createProject({organizationId: org.id, name: 'Agent'}), dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
    return {dev, scope: app.registry.scopeOf(dev), key: app.keys.mint({environmentId: dev.id, preset: 'standard'}).token};
  };
  const call = async (key, method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    const text = await response.text();
    return {status: response.status, text, body: text ? JSON.parse(text) : null, type: response.headers.get('content-type')};
  };
  return {root, app, environment, call};
}
const github = (extra = {}) => ({providerId: 'github', clientId: 'Iv1.abc_DEF-123', clientSecret: CANARY, consentScreenName: 'Acme Agent', ...extra});

test('register, read, change and delete a developer app: the secret goes to the vault only and never comes back', async t => {
  const {root, app, environment, call} = await setup(t);
  const a = environment(), seen = [];
  const created = await call(a.key, 'POST', '/v1/provider-apps', github());
  seen.push(created.text);
  assert.equal(created.status, 201);
  const {providerApp, redirectUri} = created.body;
  assert.match(providerApp.id, /^pa_[a-z2-7]{26}$/);
  assert.deepEqual([providerApp.kind, providerApp.providerId, providerApp.clientId, providerApp.status, providerApp.publishing, providerApp.accountsUsing], ['developer', 'github', 'Iv1.abc_DEF-123', 'unverified', 'testing', 0]);
  assert.equal(redirectUri, `${app.origin}/api/oauth/github/apps/${providerApp.id}/callback`, 'the exact loopback address to register (D2)');
  assert.equal(app.providerApps.secret(a.scope, providerApp.id), CANARY, 'kept in the environment vault');
  const listed = await call(a.key, 'GET', '/v1/provider-apps'); seen.push(listed.text);
  const shared = listed.body.providerApps.filter(item => item.kind === 'shared');
  assert.deepEqual(shared.map(item => item.providerId).sort(), ['github', 'google'], 'shared apps D3 allows here');
  assert.equal(shared.some(item => 'clientId' in item), false, 'shared apps show no client id');
  assert.ok(listed.body.providerApps.some(item => item.id === providerApp.id));
  const patched = await call(a.key, 'PATCH', `/v1/provider-apps/${providerApp.id}`, {clientSecret: `${CANARY}-2`, consentScreenName: 'Acme'}); seen.push(patched.text);
  assert.equal(patched.status, 200); assert.equal(patched.body.consentScreenName, 'Acme');
  assert.equal(app.providerApps.secret(a.scope, providerApp.id), `${CANARY}-2`);
  const bad = await call(a.key, 'PATCH', `/v1/provider-apps/${providerApp.id}`, {clientId: 'other', clientSecret: CANARY}); seen.push(bad.text);
  assert.equal(bad.status, 400, 'the client id never changes: a new client is a new provider app');
  const badSecret = await call(a.key, 'PATCH', `/v1/provider-apps/${providerApp.id}`, {clientSecret: `${CANARY} with spaces`}); seen.push(badSecret.text);
  assert.equal(badSecret.status, 400);
  const removed = await call(a.key, 'DELETE', `/v1/provider-apps/${providerApp.id}`);
  assert.deepEqual([removed.status, removed.text, removed.type], [204, '', null]);
  assert.equal(app.providerApps.secret(a.scope, providerApp.id), null, 'the secret is gone with it');
  assert.equal((await call(a.key, 'GET', '/v1/provider-apps')).body.providerApps.some(item => item.id === providerApp.id), false);
  // The canary is in no answer, no audit row and no file on disk (the vault encrypts it).
  for (const text of seen) assert.equal(text.includes(CANARY), false, text.slice(0, 120));
  const activity = JSON.stringify([app.registry.activity(), app.stores.open(a.scope).repository.list('activity')]);
  assert.equal(activity.includes(CANARY), false); assert.match(activity, /provider_app\.created/);
  for (const file of files(root)) assert.equal(readFileSync(file).includes(CANARY), false, file);
});

test('client ids are checked (L9), Fabric\'s own are reserved, and a pending registration never blocks another environment', async t => {
  const {app, environment, call} = await setup(t);
  const a = environment(), b = environment();
  for (const clientId of ['..', '.', '.hidden', '', 'x'.repeat(257), 'a/b', 'a b', 'a%2Fb', 7]) {
    const refused = await call(a.key, 'POST', '/v1/provider-apps', github({clientId}));
    assert.equal(refused.status, 400, JSON.stringify(clientId)); assert.equal(refused.text.includes('%2F') || refused.text.includes('.hidden'), false, 'never echoed');
  }
  assert.equal((await call(a.key, 'POST', '/v1/provider-apps', github({clientId: 'y'.repeat(256)}))).status, 201);
  for (const [providerId, clientId] of [['github', 'gh-shared-client'], ['google', 'fabric-local-google']]) {
    const taken = await call(a.key, 'POST', '/v1/provider-apps', github({providerId, clientId}));
    assert.deepEqual([taken.status, taken.body.error.code, taken.body.error.message], [409, 'client_already_registered', 'This client id is already registered.']);
  }
  const first = await call(a.key, 'POST', '/v1/provider-apps', github({clientId: 'victim-client'}));
  const second = await call(b.key, 'POST', '/v1/provider-apps', github({clientId: 'victim-client'}));
  assert.deepEqual([first.status, second.status, first.body.providerApp.status, second.body.providerApp.status], [201, 201, 'unverified', 'unverified'], 'pending never blocks');
  assert.equal((await call(a.key, 'POST', '/v1/provider-apps', github({clientId: 'victim-client'}))).body.error.code, 'client_already_registered', 'one environment holds a client id once');
  assert.equal((await call(a.key, 'POST', '/v1/provider-apps', github({providerId: 'nope'}))).body.error.code, 'unknown_provider');
  assert.equal((await call(a.key, 'POST', '/v1/provider-apps', github({scopes: ['repo', 'admin:org']}))).status, 400, 'a developer app can never add a scope');
  assert.equal((await call(a.key, 'POST', '/v1/provider-apps', github({consentDays: 7}))).status, 400, 'consentDays is Google only');
  assert.equal((await call(a.key, 'POST', '/v1/provider-apps', {providerId: 'google', clientId: 'g-dev', clientSecret: CANARY, consentScreenName: 'Acme', consentDays: 7})).body.providerApp.consentDays, 7);
  // A definition that is not reviewed is refused before anything is stored.
  const candidate = new ProviderApps({definitions: () => ({providerId: 'github', reviewStatus: 'candidate'})});
  assert.throws(() => candidate.create({scope: a.scope}, github()), error => error.code === 'provider_not_reviewed');
  void app;
});

test('environments never see each other\'s apps; an app accounts use cannot be deleted; a key without the scope is refused first', async t => {
  const {app, environment, call} = await setup(t);
  const a = environment(), b = environment();
  const mine = (await call(a.key, 'POST', '/v1/provider-apps', github())).body.providerApp;
  assert.equal((await call(b.key, 'GET', '/v1/provider-apps')).body.providerApps.some(item => item.id === mine.id), false);
  const unknown = `pa_${'a'.repeat(26)}`;
  for (const [method, body] of [['PATCH', {consentScreenName: 'x'}], ['DELETE', undefined]]) {
    const theirs = await call(b.key, method, `/v1/provider-apps/${mine.id}`, body), never = await call(b.key, method, `/v1/provider-apps/${unknown}`, body), junk = await call(b.key, method, '/v1/provider-apps/..x', body);
    const plain = answer => ({status: answer.status, code: answer.body.error.code, message: answer.body.error.message});
    assert.deepEqual(plain(theirs), plain(never)); assert.deepEqual(plain(junk), plain(never)); assert.equal(theirs.status, 404);
  }
  // One account on the app: it cannot be deleted (in_use), and accountsUsing counts this environment's only (L5).
  await call(a.key, 'POST', '/v1/connect-sessions', {externalUserId: 'u1'});
  const repo = app.stores.open(a.scope).repository, user = repo.list('endUsers').find(item => item.subjectId === 'u1'), id = randomUUID(), now = app.registry.now();
  repo.put('connections', stampOwner({id, appId: 'github', providerId: 'github', driver: 'http', status: 'ready', authMethod: 'oauth', providerApp: {kind: 'developer', id: mine.id}, identity: {id: 'gh-1'}, createdAt: now, updatedAt: now}, {subjectId: 'u1', userRecordId: user.id}));
  const inUse = await call(a.key, 'DELETE', `/v1/provider-apps/${mine.id}`);
  assert.deepEqual([inUse.status, inUse.body.error.code, inUse.body.error.details], [409, 'in_use', {accountsUsing: 1}]);
  assert.equal((await call(a.key, 'GET', '/v1/provider-apps')).body.providerApps.find(item => item.id === mine.id).accountsUsing, 1);
  repo.put('connections', {...repo.get('connections', id), status: 'revoked'});
  assert.equal((await call(a.key, 'DELETE', `/v1/provider-apps/${mine.id}`)).status, 204);
  const connectOnly = app.keys.mint({environmentId: a.dev.id, preset: 'connect-only'}).token;
  assert.equal((await call(connectOnly, 'GET', '/v1/provider-apps')).body.error.code, 'forbidden_scope');
  assert.equal((await call(connectOnly, 'DELETE', `/v1/provider-apps/${mine.id}`)).body.error.code, 'forbidden_scope');
});

test('developers\' own Slack and Notion apps register at the relay address (D2)', async t => {
  const {environment, call} = await setup(t);
  const a = environment();
  for (const providerId of ['slack', 'notion']) {
    const created = (await call(a.key, 'POST', '/v1/provider-apps', {providerId, clientId: `${providerId}-dev-client`, clientSecret: CANARY, consentScreenName: 'Acme', ...(providerId === 'slack' ? {distribution: 'internal'} : {})})).body;
    assert.equal(created.redirectUri, `https://connect.example.com/oauth/${providerId}/apps/${created.providerApp.id}/callback`);
    // The relay address is known but the live page does not forward apps paths yet (appsReady false): it cannot be turned on.
    const chosen = await call(a.key, 'PUT', `/v1/environment/apps/${providerId}`, {providerApp: created.providerApp.id, enabled: true});
    assert.equal(chosen.body.error.code, 'unavailable', providerId); assert.match(chosen.body.error.message, /relay/);
  }
});

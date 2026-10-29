import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {compileOpenApi} from '../lib/compiler.mjs';
import {EnvironmentStores} from '../lib/tenant/environments.mjs';
import {ProviderApps} from '../lib/tenant/provider-apps.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {createDeveloperApp} from '../developer-server.mjs';

// F03.3a: Fabric's shared sign-in apps per environment (D3), the no-revoke rule on shared Google (D4), and developer
// ceilings that can only lower a permission.
const SETTINGS = {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}, google: {clientId: 'g-client', clientSecret: 'g-secret'}, notion: {clientId: 'n-client', clientSecret: 'n-secret'}, slack: {clientId: 's-client', clientSecret: 's-secret'}};
const DEV = {kind: 'development'}, PROD = {kind: 'production'};

test('shared apps are configured only from explicit operator settings, never from the machine\'s environment variables', t => {
  const previous = process.env.FABRIC_GOOGLE_CLIENT_ID;
  process.env.FABRIC_GOOGLE_CLIENT_ID = 'from-the-environment';
  t.after(() => { if (previous === undefined) delete process.env.FABRIC_GOOGLE_CLIENT_ID; else process.env.FABRIC_GOOGLE_CLIENT_ID = previous; });
  const none = new ProviderApps();
  assert.equal(none.shared('google').configured, false);
  assert.equal(none.credentials('google'), null);
  assert.equal(none.availability('gmail', DEV).state, 'setup_required');
  assert.equal(new ProviderApps({settings: {google: {clientId: ' ', clientSecret: 'x'}}}).shared('google').configured, false, 'blank values are not settings');
  const apps = new ProviderApps({settings: SETTINGS});
  assert.deepEqual(apps.credentials('google'), {clientId: 'g-client', clientSecret: 'g-secret'});
  assert.equal(JSON.stringify(apps.shared('google')).includes('g-secret'), false, 'the public record never carries the secret');
});

test('availability follows D3: GitHub everywhere, Google shared only in development, Notion after its relay, Slack never shared', () => {
  const apps = new ProviderApps({settings: SETTINGS});
  assert.equal(apps.availability('github', DEV).state, 'ready'); assert.equal(apps.availability('github', PROD).state, 'ready');
  const gmailDev = apps.availability('gmail', DEV);
  assert.equal(gmailDev.state, 'ready'); assert.match(gmailDev.notice, /expire every 7 days/);
  assert.equal(apps.availability('google-calendar', PROD).state, 'unavailable');
  assert.equal(apps.availability('notion', DEV).state, 'setup_required');
  // No runtime builds the relay address for Fabric's shared Notion app yet, so it is not ready anywhere (SIGNIN-3).
  assert.equal(new ProviderApps({settings: {...SETTINGS, notion: {...SETTINGS.notion, relayReady: true}}}).availability('notion', DEV).state, 'setup_required');
  assert.equal(apps.availability('notion', PROD).state, 'setup_required');
  assert.equal(apps.availability('slack', DEV).state, 'unavailable'); assert.equal(apps.availability('slack', PROD).state, 'unavailable');
  assert.equal(apps.availability('x', DEV).state, 'unavailable');
});

test('on Fabric\'s shared Google app a disconnect never revokes at Google; a developer\'s own Google app may; token-scoped providers still revoke', () => {
  const apps = new ProviderApps({settings: SETTINGS});
  assert.equal(apps.revocationPolicy(definitionFor('google')), 'local_only');
  assert.equal(apps.revocationPolicy(definitionFor('github')), 'provider');
  assert.equal(apps.revocationPolicy(definitionFor('google'), {kind: 'developer', id: `pa_${'a'.repeat(26)}`}), 'provider', 'F10.4: on the developer\'s own app, behind the sibling confirm (N9)');
  assert.equal(apps.revocationPolicy(definitionFor('github'), {kind: 'developer', id: `pa_${'a'.repeat(26)}`}), 'provider', 'token-scoped providers revoke on a developer app too');
});

test('a developer ceiling caps a row\'s mode in permission decisions and never raises one', t => {
  const doc = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {'/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}},
    '/repos/{owner}/{repo}/issues': {post: {operationId: 'createIssue', parameters: [{name: 'owner', in: 'path', required: true, schema: {type: 'string'}}, {name: 'repo', in: 'path', required: true, schema: {type: 'string'}}],
      requestBody: {content: {'application/json': {schema: {type: 'object', properties: {title: {type: 'string'}}, required: ['title']}}}}, responses: {201: {description: 'Created'}}}}}};
  const caps = compileOpenApi({appId: 'github', document: doc}).capabilities.map(item => ({...item, status: 'active'}));
  const cap = caps.find(item => item.request.method === 'GET'), write = caps.find(item => item.request.method === 'POST');
  const map = {appId: 'github', operations: [{id: 'listRepos', capabilityId: cap.id, method: 'GET', path: '/user/repos'}, {id: 'createIssue', capabilityId: write.id, method: 'POST', path: '/repos/{owner}/{repo}/issues'}]};
  const catalog = {get: (collection, id) => collection === 'capabilities' ? caps.find(item => item.id === id) ?? null : collection === 'applicationMaps' && id === 'github' ? map : null, list: () => []};
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-ceiling-'));
  const stores = new EnvironmentStores({root, catalog});
  t.after(() => { stores.closeAll(); rmSync(root, {recursive: true, force: true}); });
  const env = stores.open({organizationId: 'org_' + 'a'.repeat(26), projectId: 'prj_' + 'a'.repeat(26), environmentId: 'env_' + 'a'.repeat(26)});
  env.repository.put('connections', {id: 'c1', appId: 'github', driver: 'http', status: 'ready', identity: {id: '1'}, authMethod: 'token'});
  const connection = env.repository.get('connections', 'c1');
  let ceiling = null, writeCeiling = null;
  const permissions = new PermissionManager({store: env.repository, ceilingOf: (appId, groupId) => appId !== 'github' ? null : groupId === 'github.repos.read' ? ceiling : groupId === 'github.issues.write' ? writeCeiling : null});
  assert.equal(permissions.decision(connection, write).mode, 'ask', 'the write row defaults to Ask');
  writeCeiling = 'allow';
  assert.equal(permissions.decision(connection, write).mode, 'ask', 'a ceiling above the mode never raises it');
  assert.equal(permissions.decision(connection, cap).mode, 'allow', 'no ceiling: the reviewed default');
  ceiling = 'ask'; assert.equal(permissions.decision(connection, cap).mode, 'ask');
  ceiling = 'deny'; assert.equal(permissions.decision(connection, cap).mode, 'deny');
  ceiling = 'allow'; assert.equal(permissions.decision(connection, cap).mode, 'allow', 'an allow ceiling changes nothing (the API refuses to store one)');
  assert.equal(new PermissionManager({store: env.repository}).decision(connection, cap).mode, 'allow', 'without ceilings, unchanged');
});

test('developers turn apps on or off and lower ceilings per environment; raising, unknown rows and unavailable apps are refused', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-appsettings-'));
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: SETTINGS});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body ? {'Content-Type': 'application/json'} : {})}, ...(body ? {body: JSON.stringify(body)} : {})}); return {status: response.status, body: await response.json()}; };
  const listed = (await call('GET', '/v1/environment/apps')).body.apps;
  const byId = Object.fromEntries(listed.map(item => [item.appId, item]));
  assert.equal(byId.github.enabled, true); assert.equal(byId.slack.enabled, false); assert.equal(byId.slack.availability.state, 'unavailable');
  assert.equal(byId.gmail.availability.state, 'ready');
  assert.equal((await call('PUT', '/v1/environment/apps/slack', {enabled: true})).body.error.code, 'unavailable');
  assert.equal((await call('PUT', '/v1/environment/apps/github', {providerApp: 'pa_' + 'a'.repeat(26)})).body.error.code, 'not_found', 'only this environment\'s own provider apps can be chosen (F03.8)');
  assert.equal((await call('PUT', '/v1/environment/apps/github', {ceilings: {'github.repos.read': 'allow'}})).body.error.code, 'ceiling_raises');
  assert.equal((await call('PUT', '/v1/environment/apps/github', {ceilings: {'gmail.messages.send': 'deny'}})).status, 400);
  assert.equal((await call('PUT', '/v1/environment/apps/github', {secret: true})).status, 400);
  assert.equal((await call('PUT', '/v1/environment/apps/nope', {enabled: false})).status, 404);
  const set = await call('PUT', '/v1/environment/apps/github', {enabled: false, ceilings: {'github.repos.read': 'ask', 'github.issues.write': 'deny'}});
  assert.equal(set.status, 200); assert.equal(set.body.enabled, false); assert.deepEqual(set.body.ceilings, {'github.repos.read': 'ask', 'github.issues.write': 'deny'});
  assert.deepEqual((await call('PUT', '/v1/environment/apps/github', {ceilings: {'github.issues.write': null}})).body.ceilings, {'github.repos.read': 'ask'});
  assert.ok(app.registry.activity().some(event => event.type === 'tenant.app_setting_updated'));
});

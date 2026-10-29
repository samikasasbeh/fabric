import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createDeveloperApp} from '../developer-server.mjs';
import {ROUTES, checkedOrigins} from '../lib/tenant/api.mjs';
import {discoverToPlatform, promoteInPlatform} from '../scripts/tenant-admin.mjs';
import {PlatformCatalog} from '../lib/tenant/platform.mjs';

// F03.1b: the developer server. Server-to-server only, one fixed order of checks, and a key reaches exactly its own
// customer, project and environment.
const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'coverage');

async function setup(t, {withCatalog = false} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-devserver-'));
  if (withCatalog) {
    const spec = JSON.parse(readFileSync(path.join(FIXTURES, 'manifest.json'), 'utf8')).find(entry => entry.appId === 'coverage-google');
    const document = JSON.parse(readFileSync(path.join(FIXTURES, spec.file), 'utf8'));
    await discoverToPlatform({root, appId: spec.appId, apps: [{id: spec.appId, name: spec.appId, discovery: {kind: spec.kind, url: spec.sourceUrl}, apiOrigins: spec.apiOrigins}], request: async () => ({status: 200, headers: {}, data: structuredClone(document)})});
  }
  const app = await createDeveloperApp({dataRoot: root, port: 0});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const customer = name => {
    const org = app.registry.createOrganization({name}), project = app.registry.createProject({organizationId: org.id, name: `${name} agent`, appName: `${name} App`});
    const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
    const prod = app.registry.createEnvironment({projectId: project.id, kind: 'production'}, app.stores);
    app.registry.enableProduction(prod.id);
    return {org, project, dev, prod, devKey: app.keys.mint({environmentId: dev.id, preset: 'full'}).token, prodKey: app.keys.mint({environmentId: prod.id, preset: 'full'}).token,
      connectOnly: app.keys.mint({environmentId: dev.id, preset: 'connect-only'}).token};
  };
  const call = async (method, route, {key, body, headers = {}} = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {...(key ? {Authorization: `Bearer ${key}`} : {}), ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    const type = response.headers.get('content-type') || '';
    return {status: response.status, headers: response.headers, body: type.includes('json') ? await response.json() : await response.text()};
  };
  return {app, root, customer, call};
}

test('the server answers only its own Host, refuses browsers on /v1, and checks the key before revealing any route', async t => {
  const {app, customer, call} = await setup(t);
  const acme = customer('Acme');
  assert.deepEqual((await call('GET', '/health')).body, {ok: true});
  const misdirected = await new Promise(resolve => http.get({host: '127.0.0.1', port: app.port, path: '/health', headers: {Host: `localhost:${app.port}`}}, res => resolve(res.statusCode)));
  assert.equal(misdirected, 421);
  for (const headers of [{Origin: 'https://evil.example'}, {Cookie: 'a=b'}]) {
    const refused = await call('GET', '/v1/project', {key: acme.devKey, headers});
    assert.equal(refused.status, 403); assert.equal(refused.body.error.code, 'browser_not_allowed');
  }
  // Without a valid key, an unknown route and a real one look the same.
  const unknown = await call('GET', '/v1/does-not-exist'), real = await call('GET', '/v1/project'), wrong = await call('GET', '/v1/project', {key: acme.devKey.slice(0, -2) + 'zz'});
  for (const response of [unknown, real, wrong]) { assert.equal(response.status, 401); assert.equal(response.body.error.code, 'unauthorized'); assert.match(response.body.error.requestId, /^req_/); }
  assert.equal((await call('GET', '/v1/does-not-exist', {key: acme.devKey})).status, 404);
  // A missing scope is refused before any lookup.
  const scoped = await call('GET', '/v1/project', {key: acme.connectOnly});
  assert.equal(scoped.status, 403); assert.equal(scoped.body.error.code, 'forbidden_scope');
  assert.equal((await call('GET', '/v1/apps', {key: acme.connectOnly})).status, 200, 'connect-only can read the catalog');
});

test('a key reaches exactly its own environment; another customer\'s key never sees or changes it', async t => {
  const {customer, call} = await setup(t);
  const acme = customer('Acme'), beta = customer('Beta');
  const acmeDev = (await call('GET', '/v1/project', {key: acme.devKey})).body, acmeProd = (await call('GET', '/v1/project', {key: acme.prodKey})).body, betaDev = (await call('GET', '/v1/project', {key: beta.devKey})).body;
  assert.equal(acmeDev.project.id, acme.project.id); assert.equal(acmeDev.environment.id, acme.dev.id); assert.equal(acmeDev.environment.kind, 'development');
  assert.equal(acmeProd.environment.id, acme.prod.id);
  assert.equal(betaDev.project.id, beta.project.id);
  assert.equal(JSON.stringify(betaDev).includes(acme.project.id), false);
  await call('PATCH', '/v1/environment', {key: beta.devKey, body: {redirectOrigins: ['https://beta.example']}});
  assert.deepEqual((await call('GET', '/v1/project', {key: acme.devKey})).body.environment.redirectOrigins, [], 'Beta changed only its own environment');
  await call('PATCH', '/v1/environment', {key: acme.devKey, body: {openerOrigins: ['http://localhost:5173']}});
  assert.deepEqual((await call('GET', '/v1/project', {key: acme.prodKey})).body.environment.openerOrigins, [], 'development never changes production');
});

test('project and environment changes are validated; production names wait for the operator', async t => {
  const {app, customer, call} = await setup(t);
  const acme = customer('Acme');
  const bad = async (key, route, body, pattern) => { const response = await call('PATCH', route, {key, body}); assert.equal(response.status, 400, JSON.stringify(response.body)); assert.match(response.body.error.message, pattern); };
  await bad(acme.devKey, '/v1/project', {id: 'prj_x'}, /Unknown field: id/);
  await bad(acme.devKey, '/v1/project', {dataUse: {text: 'x'.repeat(501)}}, /500 characters/);
  await bad(acme.devKey, '/v1/project', {dataUse: {text: 'ok', learnMoreUrl: 'http://acme.example/privacy'}}, /https link/);
  await bad(acme.devKey, '/v1/project', {supportEmail: 'nope'}, /supportEmail/);
  // Branding is shared by the project's environments, so once production is live even a development key's name change
  // waits for the operator (L10); other fields apply at once.
  const before = (await call('GET', '/v1/project', {key: acme.devKey})).body.project;
  const dev = await call('PATCH', '/v1/project', {key: acme.devKey, body: {appName: 'Acme Assistant', dataUse: {text: 'We use your data to answer your requests.', learnMoreUrl: 'https://acme.example/privacy'}}});
  assert.equal(dev.status, 202); assert.equal(dev.body.project.appName, before.appName, 'unchanged until approved'); assert.equal(dev.body.project.dataUse, undefined, 'the data-use note waits too');
  const prod = await call('PATCH', '/v1/project', {key: acme.prodKey, body: {appName: 'Acme Pro'}});
  assert.equal(prod.status, 202); assert.equal(prod.body.pendingReview, true); assert.equal(prod.body.project.appName, before.appName);
  const {digest} = app.registry.pendingBranding(before.id);
  assert.equal(app.registry.approveBranding(before.id, digest).appName, 'Acme Pro', 'the operator approves the latest pending name');
  assert.equal((await call('GET', '/v1/project', {key: acme.devKey})).body.project.dataUse.text, 'We use your data to answer your requests.');
  assert.equal((await call('GET', '/v1/project', {key: acme.devKey})).body.project.appName, 'Acme Pro');
  assert.equal((await call('GET', '/v1/project', {key: acme.devKey})).body.project.pendingReview, undefined);
  await bad(acme.prodKey, '/v1/environment', {redirectOrigins: ['http://acme.example']}, /https origins only/);
  await bad(acme.devKey, '/v1/environment', {redirectOrigins: ['https://acme.example/callback']}, /exactly scheme, host and port/);
  await bad(acme.devKey, '/v1/environment', {openerOrigins: ['http://127.0.0.1:4320']}, /Fabric's own origins/);
  await bad(acme.devKey, '/v1/environment', {openerOrigins: ['https://connect.runorra.com']}, /Fabric's own origins/);
  await bad(acme.devKey, '/v1/environment', {openerOrigins: Array.from({length: 11}, (_, i) => `https://a${i}.example`)}, /at most 10/);
  assert.equal((await call('PATCH', '/v1/project', {key: acme.devKey, headers: {'Content-Type': 'text/plain'}})).status, 400);
  assert.ok(app.registry.activity().some(event => event.type === 'tenant.project_updated'));
  assert.deepEqual(checkedOrigins(['https://a.example', 'https://a.example'], 'production'), ['https://a.example']);
});

test('the catalog shows only connectable apps, searches, filters, sorts and pages; cards carry no connection state', async t => {
  const {customer, call} = await setup(t);
  const acme = customer('Acme');
  const all = (await call('GET', '/v1/apps', {key: acme.devKey})).body;
  const ids = all.apps.map(app => app.id).sort();
  assert.deepEqual(ids, ['github', 'gmail', 'google-calendar', 'notion', 'slack']);
  assert.equal(all.pageInfo.totalCount, 5);
  for (const card of all.apps) { assert.equal('connectionState' in card, false); assert.deepEqual(card.authKinds, ['oauth']); assert.match(card.iconUrl, /^http:\/\/127\.0\.0\.1:\d+\/assets\/icons\//); }
  assert.deepEqual(all.apps.slice(0, 3).map(app => app.id), ['gmail', 'google-calendar', 'notion'], 'featured first, by rank');
  const byName = (await call('GET', '/v1/apps?sort=name&order=desc', {key: acme.devKey})).body.apps.map(app => app.name);
  assert.deepEqual(byName, [...byName].sort().reverse());
  const two = (await call('GET', '/v1/apps?categoryId=productivity&categoryId=developer', {key: acme.devKey})).body.apps.map(app => app.categoryId);
  assert.ok(two.length > 0 && two.every(id => ['productivity', 'developer'].includes(id)));
  assert.deepEqual((await call('GET', '/v1/apps?q=mail', {key: acme.devKey})).body.apps.map(app => app.id), ['gmail']);
  const first = (await call('GET', '/v1/apps?limit=2', {key: acme.devKey})).body, next = (await call('GET', `/v1/apps?limit=2&after=${first.pageInfo.endCursor}`, {key: acme.devKey})).body;
  assert.equal(first.apps.length, 2); assert.notEqual(next.apps[0].id, first.apps[1].id);
  assert.equal((await call('GET', '/v1/apps?limit=0', {key: acme.devKey})).status, 400);
  const categories = (await call('GET', '/v1/categories', {key: acme.devKey})).body.categories;
  assert.ok(categories.length > 0 && categories.every(category => category.id !== 'device'));
  const detail = (await call('GET', '/v1/apps/gmail', {key: acme.devKey})).body;
  assert.ok(detail.permissionGroups.length > 0); assert.match(detail.providerLinks.termsUrl, /^https:\/\/policies\.google\.com/);
  for (const hidden of ['x', 'workspace', 'local-device', 'spotify', 'nope']) assert.equal((await call('GET', `/v1/apps/${hidden}`, {key: acme.devKey})).status, 404, hidden);
});

test('the consent sheet is Fabric\'s words as plain text; the developer\'s note appears only when set', async t => {
  const {app, customer, call} = await setup(t);
  const acme = customer('Acme');
  const plain = (await call('GET', '/v1/apps/gmail/consent-sheet', {key: acme.devKey})).body;
  assert.deepEqual(plain.points.map(point => point.kind), ['reaches', 'control', 'caution']);
  assert.equal(plain.finePrint.some(item => item.kind === 'developer_data_use'), false);
  assert.deepEqual(plain.finePrint.map(item => item.kind), ['provider', 'custody']);
  assert.equal(plain.action.label, 'Connect Gmail'); assert.match(plain.points[1].title, /Acme App/);
  assert.deepEqual(plain.providerApp.testing, {maxUsers: 100, expiresAfterDays: 7});
  assert.equal(JSON.stringify(plain).includes('<'), false, 'text only');
  assert.equal((await call('GET', '/v1/apps/gmail/consent-sheet', {key: acme.devKey})).body.etag, plain.etag, 'stable etag');
  await call('PATCH', '/v1/project', {key: acme.devKey, body: {dataUse: {text: 'We use your mail to draft replies.'}}});
  assert.equal((await call('GET', '/v1/apps/gmail/consent-sheet', {key: acme.devKey})).body.etag, plain.etag, 'production is live: the note waits for review');
  const projectId = (await call('GET', '/v1/project', {key: acme.devKey})).body.project.id;
  app.registry.approveBranding(projectId, app.registry.pendingBranding(projectId).digest);
  const noted = (await call('GET', '/v1/apps/gmail/consent-sheet', {key: acme.devKey})).body;
  assert.equal(noted.finePrint[0].kind, 'developer_data_use'); assert.equal(noted.finePrint[0].text, 'We use your mail to draft replies.');
  assert.notEqual(noted.etag, plain.etag);
  assert.equal((await call('GET', '/v1/apps/gmail/consent-sheet?level=everything', {key: acme.devKey})).status, 400);
  assert.equal((await call('GET', '/v1/apps/x/consent-sheet', {key: acme.devKey})).status, 404);
});

test('icons are drawn by Fabric with a fixed type and nosniff; capabilities come only from the active platform catalog', async t => {
  const {app, root, customer, call} = await setup(t, {withCatalog: true});
  const acme = customer('Acme');
  const icon = await fetch(`${app.origin}/assets/icons/gmail`);
  assert.equal(icon.status, 200); assert.equal(icon.headers.get('content-type'), 'image/svg+xml'); assert.equal(icon.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(icon.headers.get('content-security-policy'), "default-src 'none'");
  // The bundled brand mark (Simple Icons, CC0) in its official colour on a white tile; nothing but shapes.
  const svg = await icon.text();
  assert.match(svg, /fill="#EA4335"/); assert.match(svg, /<rect width="64" height="64" rx="14" fill="#ffffff"\/>/);
  assert.deepEqual([...new Set(svg.match(/<[a-z]+/g))].sort(), ['<g', '<path', '<rect', '<svg']);
  assert.equal(/script|href|style|on[a-z]+=|<text/i.test(svg), false);
  for (const appId of ['google-calendar', 'github', 'notion']) assert.match(await (await fetch(`${app.origin}/assets/icons/${appId}`)).text(), /<path fill="#[0-9A-F]{6}"/, appId);
  assert.match(await (await fetch(`${app.origin}/assets/icons/slack`)).text(), /<text[^>]*>S<\/text>/, 'Slack is not in Simple Icons: Fabric\'s monogram');
  assert.equal((await fetch(`${app.origin}/assets/icons/x`)).status, 404);
  assert.deepEqual((await call('GET', '/v1/capabilities', {key: acme.devKey})).body.capabilities, [], 'candidates are not listed');
  const reader = new PlatformCatalog({root}), candidates = reader.list('capabilities').map(capability => capability.id);
  reader.close();
  promoteInPlatform({root, appId: 'coverage-google', capabilityIds: [candidates[0]]});
  const listed = (await call('GET', '/v1/capabilities', {key: acme.devKey})).body;
  assert.deepEqual(listed.capabilities.map(capability => capability.id), [candidates[0]]);
  assert.equal(listed.pageInfo.totalCount, 1);
  assert.equal(listed.capabilities[0].certified, false, 'certified only with live evidence');
  assert.equal((await call('GET', `/v1/capabilities/${encodeURIComponent(candidates[0])}`, {key: acme.devKey})).status, 200);
  assert.equal((await call('GET', `/v1/capabilities/${encodeURIComponent(candidates[1])}`, {key: acme.devKey})).status, 404, 'a candidate is not served');
  assert.equal((await call('GET', '/v1/capabilities?appId=coverage-google&limit=101', {key: acme.devKey})).status, 400);
});

// Each route is exercised here or in tenant-provider-apps.test.mjs (environment apps), tenant-connect-sessions.test.mjs
// (sessions), tenant-users-accounts.test.mjs (end users and accounts), tenant-app-pages.test.mjs (one user's app page and
// relay) and tenant-logo.test.mjs (the logo).
test('every developer route is listed, and each is exercised by a test file', () => {
  assert.deepEqual([...ROUTES].sort(), ['GET /v1/users', 'GET /v1/users/([^/]{1,400})', 'DELETE /v1/users/([^/]{1,400})', 'GET /v1/users/([^/]{1,400})/accounts', 'GET /v1/users/([^/]{1,400})/accounts/([^/]{1,100})',
    'POST /v1/users/([^/]{1,400})/accounts/([^/]{1,100})/disconnect', 'POST /v1/users/([^/]{1,400})/accounts/([^/]{1,100})/check', 'PUT /v1/users/([^/]{1,400})/apps/([a-z][a-z0-9-]{0,63})/default-account',
    'GET /v1/accounts', 'GET /v1/accounts/([^/]{1,100})', 'POST /v1/accounts/([^/]{1,100})/disconnect',
    'GET /v1/users/([^/]{1,400})/catalog', 'GET /v1/users/([^/]{1,400})/capabilities', 'GET /v1/users/([^/]{1,400})/apps/([a-z][a-z0-9-]{0,63})', 'POST /v1/users/([^/]{1,400})/accounts/([^/]{1,100})/permissions',
    'POST /v1/users/([^/]{1,400})/accounts/([^/]{1,100})/permissions/reset', 'POST /v1/users/([^/]{1,400})/accounts/([^/]{1,100})/background', 'GET /v1/provider-apps', 'POST /v1/provider-apps', 'PATCH /v1/provider-apps/([^/]{1,100})', 'DELETE /v1/provider-apps/([^/]{1,100})', 'POST /v1/connect-sessions', 'GET /v1/connect-sessions/([a-z0-9_]{1,40})', 'POST /v1/connect-sessions/([a-z0-9_]{1,40})/cancel', 'POST /v1/connect-sessions/([a-z0-9_]{1,40})/link', 'GET /v1/environment/apps', 'PUT /v1/environment/apps/([a-z][a-z0-9-]{0,63})', 'PUT /v1/project/logo', 'POST /v1/executions', 'GET /v1/executions/([^/]{1,100})', 'POST /v1/executions/([^/]{1,100})/cancel', 'POST /v1/proxy/requests', 'POST /v1/options', 'GET /v1/users/([^/]{1,400})/approvals', 'POST /v1/users/([^/]{1,400})/approvals/([^/]{1,100})/decision', 'GET /v1/users/([^/]{1,400})/activity', 'POST /v1/users/([^/]{1,400})/agent-tokens', 'GET /v1/users/([^/]{1,400})/agent-tokens', 'POST /v1/users/([^/]{1,400})/agent-tokens/([^/]{1,100})/revoke', 'GET /v1/apps', 'GET /v1/apps/([a-z][a-z0-9-]{0,63})', 'GET /v1/apps/([a-z][a-z0-9-]{0,63})/consent-sheet', 'GET /v1/capabilities', 'GET /v1/capabilities/([A-Za-z0-9._:-]{1,200})', 'GET /v1/categories', 'GET /v1/project', 'PATCH /v1/environment', 'PATCH /v1/project'].sort());
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {checkedBrand, contrast, BrandError} from '../lib/tenant/brand.mjs';
import {brandingDigest} from '../lib/tenant/registry.mjs';

// F03.10: a project's colours for Fabric's hosted pages (P28): named tokens, #rrggbb, readable contrast, and once
// production is live, the operator's review like every other branding field (L10).
test('brand tokens: #rrggbb only, known tokens only, and text stays readable (4.5:1)', () => {
  assert.deepEqual(checkedBrand({light: {accent: '#5B21B6'}}), {light: {accent: '#5b21b6'}});
  assert.deepEqual(checkedBrand({light: {accent: '#5b21b6'}, dark: {accent: '#c4b5fd', onAccent: '#1e1b4b'}}).dark, {accent: '#c4b5fd', onAccent: '#1e1b4b'});
  assert.ok(contrast('#000000', '#ffffff') > 20); assert.equal(contrast('#777777', '#777777'), 1);
  const refused = [
    [{light: {accent: '#f4f5f2'}}, /accent and the text on it/], // a pale accent under white text
    [{light: {ink: '#e1e6e1'}}, /text and the page/],
    [{dark: {surface: '#eeeeee'}}, /text and the page/],
    [{light: {accent: 'red'}}, /#rrggbb/], [{light: {accent: '#fff'}}, /#rrggbb/], [{light: {accent: '#12345g'}}, /#rrggbb/],
    [{light: {background: '#ffffff'}}, /not a colour token/], [{sepia: {accent: '#000000'}}, /light and dark sets only/], [{}, /light or a dark set/], [{light: {}}, /set of colour tokens/], [[], /light\?, dark\?/],
  ];
  for (const [value, message] of refused) assert.throws(() => checkedBrand(value), error => error instanceof BrandError && message.test(error.message), JSON.stringify(value));
});

test('PATCH /v1/project sets the brand; in production it waits for the operator; the Connect page gets the colours as CSS properties', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-brand-'));
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), key = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  const call = async (method, route, body, token = key) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})}); return {status: response.status, body: await response.json()}; };
  const set = await call('PATCH', '/v1/project', {brand: {light: {accent: '#5B21B6'}, dark: {accent: '#c4b5fd', onAccent: '#1e1b4b'}}});
  assert.equal(set.status, 200); assert.deepEqual(set.body.project.brand.light, {accent: '#5b21b6'});
  assert.equal((await call('PATCH', '/v1/project', {brand: {light: {accent: '#f4f5f2'}}})).status, 400, 'unreadable colours are refused');
  // The Connect page receives the colours as Fabric's CSS custom properties.
  const created = (await call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body, binding = 'browser-brand-binding-01';
  app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
  assert.deepEqual(app.sessions.view(created.id, binding).developer.brand, {light: {'--accent': '#5b21b6'}, dark: {'--accent': '#c4b5fd', '--on-accent': '#1e1b4b'}});
  assert.equal((await call('PATCH', '/v1/project', {brand: null})).body.project.brand, undefined, 'null returns to Fabric\'s colours');
  // Once production is live, a brand change waits for the operator's review, from any environment's key.
  const prod = app.registry.createEnvironment({projectId: project.id, kind: 'production'}, app.stores);
  app.registry.enableProduction(prod.id);
  const waiting = await call('PATCH', '/v1/project', {brand: {light: {accent: '#0f766e'}}});
  assert.equal(waiting.status, 202); assert.deepEqual(waiting.body.project.pendingFields, ['brand']); assert.equal(waiting.body.project.brand, undefined);
  const pending = app.registry.get('projects', project.id).pendingBranding;
  app.registry.approveBranding(project.id, brandingDigest(pending));
  assert.deepEqual((await call('GET', '/v1/project')).body.project.brand, {light: {accent: '#0f766e'}});
});

test('the page applies only Fabric\'s named colour properties, only #rrggbb, through the CSS object model', () => {
  const script = readFileSync(new URL('../public/connect.js', import.meta.url), 'utf8');
  assert.match(script, /const BRAND_PROPERTIES = new Set\(\['--surface', '--surface-raised', '--ink', '--muted', '--line', '--accent', '--on-accent', '--danger', '--attention'\]\)/);
  assert.match(script, /BRAND_PROPERTIES\.has\(name\) && \/\^#\[0-9a-f\]\{6\}\$\/\.test\(value\)\) root\.style\.setProperty\(name, value\)/);
  assert.equal(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|setAttribute\('style'/.test(script), false);
});

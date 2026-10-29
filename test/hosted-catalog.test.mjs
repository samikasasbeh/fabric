import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {fileURLToPath} from 'node:url';
import {createApp} from '../server.mjs';
import {definitionFor, reviewedProviderIds} from '../lib/providers/definitions.mjs';
import {rowAction, connectionNote, iconSource, catalogUrl} from '../public/hosted-catalog.js';

// UI-1: the hosted Connectors catalog and its owner route. Isolated temporary data and loopback ports.
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
async function freePort() { const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const {port} = server.address(); await new Promise(resolve => server.close(resolve)); return port; }

test('row actions link to the app page by id and never to a server-supplied URL', () => {
  assert.deepEqual(rowAction({id: 'gmail', displayName: 'Gmail', primaryAction: 'view'}), {label: 'View', kind: 'link', href: '/connectors/gmail', name: 'View Gmail'});
  assert.equal(rowAction({id: 'a b/c', displayName: 'X', primaryAction: 'connect'}).href, '/connectors/a%20b%2Fc');
  assert.deepEqual(rowAction({id: 'slack', primaryAction: 'setup_required'}), {label: 'Setup needed', kind: 'note', href: null, name: 'Setup needed app'});
  assert.equal(rowAction({id: 'x', primaryAction: 'javascript:alert(1)'}).kind, 'note', 'unknown actions are inert');
  assert.equal(rowAction({id: 'x', primaryAction: 'unavailable', href: 'https://evil.example'}).href, null);
});

test('the account note appears only when the owner must act', () => {
  assert.equal(connectionNote({}), null);
  assert.equal(connectionNote({connectionState: {state: 'available'}}), null);
  assert.equal(connectionNote({connectionState: {state: 'connected', needsAttention: 0}}), null);
  assert.equal(connectionNote({connectionState: {state: 'connected', needsAttention: 1}}), '1 account needs attention');
  assert.equal(connectionNote({connectionState: {state: 'connected', needsAttention: 2}}), '2 accounts need attention');
  assert.equal(connectionNote({connectionState: {state: 'attention', needsAttention: 1}}), 'Reconnect needed');
});

test('only Fabric\'s own icon route is used as an image source, and requests use known keys only', () => {
  assert.equal(iconSource({iconUrl: '/api/icons/gmail'}), '/api/icons/gmail');
  for (const iconUrl of ['https://evil.example/x.png', '//evil.example/x', '/api/icons/../state', 'javascript:alert(1)', '/api/icons/a b', undefined]) assert.equal(iconSource({iconUrl}), null, String(iconUrl));
  assert.equal(catalogUrl(), '/api/ui/catalog');
  assert.equal(catalogUrl({status: 'connected', q: '  mail ', category: 'communication', cursor: 'abc'}), '/api/ui/catalog?status=connected&q=mail&category=communication&cursor=abc');
  assert.equal(catalogUrl({q: 'a&status=x'}), '/api/ui/catalog?q=a%26status%3Dx');
});

test('the page renders text only and loads no inline script or style', async () => {
  const script = await readFile(path.join(ROOT, 'public/hosted-catalog.js'), 'utf8');
  for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function']) assert.ok(!script.includes(sink), `hosted-catalog.js must not use ${sink}`);
  const html = await readFile(path.join(ROOT, 'public/hosted-catalog.html'), 'utf8');
  assert.ok(!/<script(?![^>]*src="\/hosted-catalog\.js")/.test(html)); assert.ok(!/style=/.test(html));
  assert.match(html, /href="\/hosted\.css"/);
});

async function fixture(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-hosted-catalog-')), port = await freePort();
  const app = await createApp({dataDir: dir, port, request: async () => ({status: 200, data: {}})});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); });
  const get = (route, headers = {}) => fetch(`${app.origin}${route}`, {headers});
  return {app, get};
}

test('the owner route serves the catalog view model without leaking account details', async t => {
  const f = await fixture(t);
  f.app.store.put('connections', {id: 'acct-1', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'r', status: 'ready', label: 'GitHub private-label', identity: {id: '9', displayName: 'secret-person', email: 'person@example.test'}, scopes: ['repo:secret'], allowedOrigins: ['https://api.github.com'], createdAt: new Date().toISOString()});
  const response = await f.get('/api/ui/catalog');
  assert.equal(response.status, 200);
  const page = await response.json();
  assert.deepEqual(page.featured.map(card => card.id), ['gmail', 'google-calendar', 'notion']);
  const all = [...page.featured, ...page.categories.flatMap(group => group.preview)];
  const github = all.find(card => card.id === 'github');
  assert.equal(github.primaryAction, 'view'); assert.equal(github.connectionState.accounts, 1);
  assert.ok(page.categories.some(group => group.category.id === 'device'), 'the local owner sees this computer');
  const wire = JSON.stringify(page);
  for (const secret of ['person@example.test', 'secret-person', 'private-label', 'repo:secret', 'acct-1']) assert.ok(!wire.includes(secret), `leaked ${secret}`);
  const connected = await (await f.get('/api/ui/catalog?status=connected')).json();
  assert.deepEqual(connected.categories.flatMap(group => group.preview).map(card => card.id), ['github']);
  const found = await (await f.get('/api/ui/catalog?q=calendar')).json();
  assert.deepEqual(found.results.map(card => card.id), ['google-calendar']);
});

test('access levels come from reviewed definitions and stay honest', async t => {
  const f = await fixture(t);
  const page = await (await f.get('/api/ui/catalog')).json();
  const levels = Object.fromEntries([...page.featured, ...page.categories.flatMap(group => group.preview)].map(card => [card.id, card.accessLevels]));
  // Expected levels are derived from the reviewed definitions themselves (version 2 since F10.7): full access, a read level where the
  // app has one, and Notion's pages.
  for (const providerId of reviewedProviderIds()) for (const entry of definitionFor(providerId).apps) {
    if (!(entry.appId in levels)) continue;
    assert.deepEqual(levels[entry.appId], entry.access.grant === 'pages' ? ['pages'] : ['full', ...(entry.access.levels.read ? ['read'] : [])], entry.appId);
  }
  for (const id of ['workspace', 'local-device', 'instagram', 'spotify']) assert.deepEqual(levels[id], [], `${id} has no sign-in definition`);
  const calendar = (await (await f.get('/api/ui/catalog?q=calendar')).json()).results[0];
  const gmail = (await (await f.get('/api/ui/catalog?q=gmail')).json()).results[0];
  assert.deepEqual(calendar.accessLevels, ['full']);
  assert.deepEqual(gmail.accessLevels, ['full', 'read'], 'Gmail also offers an advanced read-only sign-in');
});

test('the catalog route refuses cross-site reads and bad input, and the page is served under the CSP', async t => {
  const f = await fixture(t);
  assert.equal((await f.get('/api/ui/catalog', {'sec-fetch-site': 'cross-site'})).status, 400);
  assert.equal((await f.get('/api/ui/catalog', {origin: 'https://evil.example'})).status, 400);
  for (const query of ['status=enabled', 'category=nope', 'cursor=bogus']) {
    const response = await f.get(`/api/ui/catalog?${query}`);
    assert.equal(response.status, 400, query); assert.equal((await response.json()).code, 'invalid_request');
  }
  const page = await f.get('/connectors');
  assert.equal(page.status, 200); assert.match(page.headers.get('content-type'), /text\/html/);
  assert.match(page.headers.get('content-security-policy'), /script-src 'self'/);
  assert.match(await page.text(), /src="\/hosted-catalog\.js"/);
  assert.match((await f.get('/hosted-catalog.js')).headers.get('content-type'), /javascript/);
  assert.match((await f.get('/hosted.css')).headers.get('content-type'), /text\/css/);
  const owner = await f.get('/connectors.css');
  assert.match(await owner.text(), /connector/, 'the owner UI keeps its own stylesheet');
});

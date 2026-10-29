import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {Store} from '../lib/store.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {createApp} from '../server.mjs';

// F03 exit check 6, local mode unchanged.
// (1) The single-owner binding and policy hashes equal a committed golden. Any change that moves them would quietly
//     turn every saved Allow or Never stale, so it fails here. The same body gives these exact values at 8ff437c,
//     before F03 began.
// (2) The owner pages load their whole module graph from the single-owner server (F03.10d added /hosted-base.js).
// (3) The catalog icon is never a lazy image (F03.10e).
// (4) Two deliberate F03.5 changes to the owner app page stay: Allow on a read row holding a write needs confirmAllow,
//     and a row holding a candidate operation is marked for review.

const FIXED = '2026-01-01T00:00:00.000Z';
const GOLDEN_ORIGIN = 'https://api.golden.example';

// Fixed records shaped like compiled ones, so the golden pins the hash rules, not the compiler (compiler-golden does that).
const capability = (operationId, method, route) => ({
  specVersion: 'fabric/0.1', version: 1, appId: 'golden', name: operationId, description: `Imported ${method} ${route}.`, driver: 'http',
  effect: method === 'GET' ? 'read' : method === 'DELETE' ? 'delete' : 'write', status: 'active',
  inputSchema: {type: 'object', properties: {}, required: [], additionalProperties: false},
  request: {method, url: `${GOLDEN_ORIGIN}${route}`, headers: {Accept: 'application/json'}, pathParameters: [], queryParameters: []},
  provenance: {kind: 'openapi', fingerprint: '0'.repeat(64), source: 'uploaded', operationId, path: route, method},
  id: `golden.${operationId.toLowerCase()}.fixed`,
});
const OPERATIONS = [
  ['read', 'listItems', 'GET', '/items', ['items.read']],
  ['write', 'createItem', 'POST', '/items', ['items.write']],
  ['sensitive', 'getApiToken', 'GET', '/api-token', []],
  ['savedAllow', 'updateItem', 'PATCH', '/items/{id}', []],
  ['savedNever', 'deleteItem', 'DELETE', '/items/{id}', []],
];
const CONNECTION = {id: 'golden-account', appId: 'golden', driver: 'http', authMethod: 'oauth', authRevision: 'golden-consent-1', status: 'ready', label: 'Golden',
  identity: {id: 'golden-user-1', displayName: 'Golden User'}, allowedOrigins: [GOLDEN_ORIGIN], scopes: ['items.read'], createdAt: FIXED, updatedAt: FIXED};

/** A local store with the fixed records and two saved settings whose revisions are pinned, then every hash it yields. */
function localHashes(t, {clock = Date.parse(FIXED), localAuthority} = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-local-golden-'));
  const store = new Store({dataDir: dir, clock: () => clock, ...(localAuthority ? {localAuthority} : {})});
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  const caps = Object.fromEntries(OPERATIONS.map(([key, operationId, method, route]) => [key, capability(operationId, method, route)]));
  for (const cap of Object.values(caps)) store.put('capabilities', cap);
  store.put('applicationMaps', {id: 'golden', appId: 'golden', operations: OPERATIONS.map(([key, id, method, route, requiredScopes]) => ({id, capabilityId: caps[key].id, method, path: route, requiredScopes}))});
  store.put('connections', CONNECTION);
  const permissions = new PermissionManager({store});
  // The product writes the saved records; only their random revision and their time are pinned afterwards.
  for (const [key, mode, revision] of [['savedAllow', 'allow', 'golden-revision-allow'], ['savedNever', 'deny', 'golden-revision-never']]) {
    permissions.set({connectionId: CONNECTION.id, capabilityId: caps[key].id, mode});
    const id = permissions.policyId(CONNECTION.id, caps[key].id);
    store.put('permissions', {...store.get('permissions', id), revision, updatedAt: FIXED});
  }
  const out = {};
  for (const [key, cap] of Object.entries(caps)) {
    const decision = permissions.decision(CONNECTION, cap);
    assert.equal(decision.bindingHash, permissions.binding(CONNECTION, cap, decision.sensitivity), `${key}: the decision is bound by binding() with its sensitivity`);
    if (store.authorityEnabled) assert.ok(Number.isSafeInteger(decision.connectionGeneration) && Number.isSafeInteger(decision.policyRevision), `${key}: a designated store adds its counters beside the hashes`);
    out[key] = {mode: decision.mode, policySource: decision.policySource, sensitivity: decision.sensitivity, providerAccess: decision.providerAccess, status: decision.status,
      policyId: permissions.policyId(CONNECTION.id, cap.id), binding: permissions.binding(CONNECTION, cap), bindingHash: decision.bindingHash, policyHash: decision.policyHash};
  }
  return out;
}

const GOLDEN = {
  read: {mode: 'allow', policySource: 'default', sensitivity: null, providerAccess: 'granted', status: 'active',
    policyId: '73a819c8a8f336b134fc64f933aceac88360d5ff6697ff1fcfb70c5c3bd0d462',
    binding: 'a10627003fb0be32256a1f784e37ed3541d74db43e044e7b69d37305a19d9d00',
    bindingHash: 'a10627003fb0be32256a1f784e37ed3541d74db43e044e7b69d37305a19d9d00',
    policyHash: '76cb108ab3731494151f3a1f9bbd14bbeb7a142404c04cbdae7c8d3c10bb9701'},
  write: {mode: 'ask', policySource: 'default', sensitivity: null, providerAccess: 'missing', status: 'active',
    policyId: 'af67a8a9039252727ac6aeb1a809d4224a026c12b0e9f9567aaaa348fd8c85ea',
    binding: '5a01f8da57b6b4eb1489ba396d74e44cf887aa62b3d72ef9eea11aca2020a799',
    bindingHash: '5a01f8da57b6b4eb1489ba396d74e44cf887aa62b3d72ef9eea11aca2020a799',
    policyHash: 'eb0afea981c42496b461e28e71fdef5108e37428d4e5d154f8c7a2f82af44389'},
  // A sensitive operation's binding carries its classification; binding() without it is the plain one.
  sensitive: {mode: 'ask', policySource: 'default', sensitivity: 'secrets', providerAccess: 'unknown', status: 'active',
    policyId: 'ff4c6fd68e12a72e7766d772026ad5ec3470a3fb68b32ddde991624571b3b143',
    binding: '19c361069be23d53729a5a7bc0ff45e40b9ca7f8a1b8ef8df6aeed296985027c',
    bindingHash: '8892175577d6d7e34c65985bdd4ed27fe6a57db43ee51ad6996c7d5217003810',
    policyHash: 'd8a6c5c2adbeb5d59621ff7db2dd8ebb429483034a07c391179107b272a8319b'},
  savedAllow: {mode: 'allow', policySource: 'saved', sensitivity: null, providerAccess: 'unknown', status: 'active',
    policyId: '72e32f178d0f4a63616849922a57506eded27effa77d98389e535b76154995fe',
    binding: '0cde73f2723657cc03929aa6e813fcefca1aba2bad6dff519bb7545e6817f8ba',
    bindingHash: '0cde73f2723657cc03929aa6e813fcefca1aba2bad6dff519bb7545e6817f8ba',
    policyHash: 'b8249778e6a1e484677aad50326b1d5b962d0e2b7bf48d0baff3e3ef75a225ec'},
  savedNever: {mode: 'deny', policySource: 'saved', sensitivity: null, providerAccess: 'unknown', status: 'active',
    policyId: 'bbb15cb80dbf97e0611420f6a8409e7500853e06b5a3a1bec991803b9ad1122b',
    binding: '64e2970e368d211d1702ffa3d80240173fd00f602a602b60a3f510928312fe57',
    bindingHash: '64e2970e368d211d1702ffa3d80240173fd00f602a602b60a3f510928312fe57',
    policyHash: '8fd61b64c51cd83bb9a1297d9ff2c50f21bfbbf27b83fa94510929a41a81bdd9'},
};

test('local binding and policy hashes equal the committed golden', t => {
  assert.deepEqual(localHashes(t), GOLDEN);
});

test('the golden does not depend on the store, its clock or its designation', t => {
  assert.deepEqual(localHashes(t, {clock: Date.parse('2031-06-30T12:34:56.000Z')}), GOLDEN, 'another folder and another time');
  assert.deepEqual(localHashes(t, {localAuthority: 'new'}), GOLDEN, 'a designated single-owner store hashes the same');
});

// ---- The single-owner server ------------------------------------------------------------------------------------
// The owner server checks the Host header against the port it was given, so it needs a real port number: one is
// picked by binding port 0 first, as test/hosted-catalog.test.mjs does.
async function freePort() { const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const {port} = server.address(); await new Promise(resolve => server.close(resolve)); return port; }

async function ownerServer(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-local-owner-')), port = await freePort(), network = [];
  // A fixed clock keeps the health check from ever coming due; nothing here may reach a network.
  const app = await createApp({dataDir: dir, port, clock: () => Date.parse('2026-10-11T10:00:00.000Z'), request: async req => { network.push(req.url); throw new Error('No network in this test.'); }});
  await app.start();
  t.after(async () => { await app.close(); rmSync(dir, {recursive: true, force: true}); });
  const first = await fetch(`${app.origin}/api/state`), state = await first.json();
  const session = {cookie: first.headers.get('set-cookie').split(';')[0], csrf: state.csrfToken};
  const call = async (method, route, data) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {'content-type': 'application/json', 'sec-fetch-site': 'same-origin', origin: app.origin, 'x-fabric-csrf': session.csrf, cookie: session.cookie}, ...(data !== undefined ? {body: JSON.stringify(data)} : {})});
    return {status: response.status, body: await response.json()};
  };
  return {app, call, network};
}

test('every owner page loads its whole module graph from the single-owner server', async t => {
  const {app, network} = await ownerServer(t);
  const loaded = new Map();
  const fetchAll = async (url, kind) => {
    const target = new URL(url, app.origin);
    assert.equal(target.origin, app.origin, `${url} must load from the owner server itself`);
    if (loaded.has(target.pathname)) return;
    loaded.set(target.pathname, kind);
    const response = await fetch(target);
    assert.equal(response.status, 200, target.pathname);
    assert.match(response.headers.get('content-type') || '', kind === 'script' ? /^text\/javascript\b/ : /^text\/css\b/, target.pathname);
    if (kind !== 'script') return;
    const source = await response.text();
    // Static imports and re-exports, bare imports and dynamic imports alike.
    for (const match of source.matchAll(/^\s*(?:import|export)\s[^'";]*?\bfrom\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/gm)) {
      const specifier = match[1] ?? match[2] ?? match[3];
      assert.match(specifier, /^(?:\.{1,2})?\//, `${target.pathname} imports ${specifier}, which a browser cannot resolve`);
      await fetchAll(new URL(specifier, target).href, 'script');
    }
  };
  const approval = '0f0e0d0c-0b0a-4908-8706-050403020100';
  for (const page of ['/', '/connectors', '/connectors/gmail', '/activity', `/approve/${approval}`]) {
    const response = await fetch(`${app.origin}${page}`);
    assert.equal(response.status, 200, page); assert.match(response.headers.get('content-type'), /^text\/html\b/, page);
    const html = await response.text();
    const scripts = [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map(match => match[1]), links = [...html.matchAll(/<link\b[^>]*\bhref="([^"]+)"/g)].map(match => match[1]);
    assert.ok(scripts.length > 0 && links.length > 0, `${page} names its script and stylesheet`);
    for (const src of scripts) await fetchAll(src, 'script');
    for (const href of links) await fetchAll(href, 'style');
  }
  for (const file of ['/hosted.css', '/hosted-catalog.js', '/hosted-app.js', '/hosted-activity.js', '/hosted-approve.js', '/hosted-approval.js', '/hosted-base.js', '/hosted-text.js', '/sign-in-target.js', '/app.js', '/connect-client.js', '/styles.css', '/connectors.css'])
    assert.ok(loaded.has(file), `${file} is part of an owner page's graph (loaded: ${[...loaded.keys()].join(', ')})`);
  assert.deepEqual(network, [], 'loading the pages reached no network');
});

test('the catalog builds its icon image without loading: \'lazy\', since a lazy image off the page is never fetched', () => {
  const source = readFileSync(new URL('../public/hosted-catalog.js', import.meta.url), 'utf8');
  const images = [...source.matchAll(/el\(\s*'img'\s*,\s*(\{[^}]*\})/g)].map(match => match[1]);
  assert.equal(images.length, 1, 'one icon image is built');
  assert.match(images[0], /\bsrc\b/);
  assert.doesNotMatch(images[0], /\bloading\b/, 'the icon image sets no loading attribute');
  assert.doesNotMatch(source, /['"]?loading['"]?\s*[:,]\s*['"]lazy['"]/, 'nothing in the catalog script is lazy-loaded');
  assert.doesNotMatch(source, /\.loading\s*=/);
});

// ---- The owner app page (AppDetailService through the owner routes) ----------------------------------------------
function seed(store, appId, server, ops) {
  const paths = {};
  for (const [id, method, route] of ops) paths[route] = {...(paths[route] || {}), [method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method !== 'get' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {q: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: server}], paths}}).capabilities;
  const operations = [];
  for (const [id, method, route, status = 'active', support] of ops) {
    const cap = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `${server}${route}`);
    store.put('capabilities', {...cap, status});
    operations.push({id, capabilityId: cap.id, method: method.toUpperCase(), path: route, ...(support ? {support} : {})});
  }
  store.put('applicationMaps', {id: appId, appId, operations});
}
const plant = (store, fields) => store.put('connections', {driver: 'http', authMethod: 'oauth', authRevision: 'consent-1', status: 'ready', createdAt: FIXED, updatedAt: FIXED, ...fields});
const rowOf = (view, groupId) => view.sections.flatMap(section => section.rows).find(row => row.groupId === groupId);

test('owner page: Allow on a read row that holds a write member needs confirmAllow (F03.5 finding 1, single-owner path)', async t => {
  const {app, call} = await ownerServer(t);
  seed(app.store, 'notion', 'https://api.notion.com', [['notion.pages.get', 'get', '/v1/pages/{page_id}'], ['notion.views.queries.create', 'post', '/v1/views/{view_id}/queries']]);
  plant(app.store, {id: 'notion-account', appId: 'notion', label: 'Notion', identity: {id: 'ws1:user1', displayName: 'User One'}, allowedOrigins: ['https://api.notion.com'], scopes: []});
  const view = await call('GET', '/api/ui/apps/notion');
  assert.equal(view.status, 200);
  const content = rowOf(view.body, 'notion.content.read');
  assert.equal(content.effect, 'read'); assert.equal(content.operations, 2);
  assert.deepEqual([content.mode, content.defaultMode], ['mixed', 'mixed'], 'the read member defaults to Allow, the write member to Ask');
  assert.equal(content.reviewRequired, false);
  const set = extra => call('POST', '/api/ui/apps/notion/accounts/notion-account/permissions', {groupId: 'notion.content.read', mode: 'allow', etag: content.etag, ...extra});
  const refused = await set();
  assert.equal(refused.status, 409); assert.equal(refused.body.code, 'confirm_required', 'a read row is still a decision when a member writes');
  assert.equal(app.store.list('permissions').length, 0, 'the refusal saved nothing');
  const confirmed = await set({confirmAllow: true});
  assert.equal(confirmed.status, 200);
  assert.equal(rowOf(confirmed.body, 'notion.content.read').mode, 'allow'); assert.equal(rowOf(confirmed.body, 'notion.content.read').policySource, 'saved');
});

test('owner page: a row holding a candidate operation is marked for review, even when the map calls it unsupported (F03.5 finding 5)', async t => {
  const {app, call} = await ownerServer(t);
  seed(app.store, 'gmail', 'https://gmail.googleapis.com', [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'],
    ['gmail.users.messages.attachments.get', 'get', '/gmail/v1/users/{userId}/messages/{messageId}/attachments/{id}', 'candidate', 'unsupported']]);
  plant(app.store, {id: 'gmail-account', appId: 'gmail', providerId: 'google', label: 'Gmail', identity: {id: 'g-1', displayName: 'One'}, allowedOrigins: ['https://gmail.googleapis.com'], scopes: ['https://www.googleapis.com/auth/gmail.readonly']});
  const view = await call('GET', '/api/ui/apps/gmail');
  assert.equal(view.status, 200);
  const row = rowOf(view.body, 'gmail.messages.read');
  assert.equal(row.operations, 2);
  assert.equal(row.reviewRequired, true);
  // The owner keeps every mode with a review (tenants offer Never only, F03.10 N6): the local rule is unchanged.
  assert.deepEqual(row.allowedModes, ['allow', 'ask', 'deny']);
  const unreviewed = await call('POST', '/api/ui/apps/gmail/accounts/gmail-account/permissions', {groupId: 'gmail.messages.read', mode: 'ask', etag: row.etag});
  assert.equal(unreviewed.status, 409); assert.equal(unreviewed.body.code, 'review_required');
  assert.equal((await call('POST', '/api/ui/apps/gmail/accounts/gmail-account/permissions', {groupId: 'gmail.messages.read', mode: 'deny', etag: row.etag})).status, 200, 'Never needs no review');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {AppDetailService} from '../lib/app-detail.mjs';

// F03.5b: one end user's app page, catalog and runnable capabilities, and the permission changes a developer's server
// may relay for them (D5). Gmail's reviewed rows decide: "Draft emails" is a write row whose default is Allow.
const OPS = [
  ['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'],
  ['gmail.users.drafts.create', 'post', '/gmail/v1/users/{userId}/drafts'],
  ['gmail.users.labels.create', 'post', '/gmail/v1/users/{userId}/labels'],
  ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send'],
  ['gmail.users.settings.getAutoForwarding', 'get', '/gmail/v1/users/{userId}/settings/autoForwarding'],
];
function seedPlatform(root) {
  const param = name => ({name, in: 'path', required: true, schema: {type: 'string'}});
  const paths = {};
  for (const [id, method, route] of OPS) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => param(match[1])), ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities;
  const store = new PlatformStore({root});
  const operations = [];
  for (const [id, method, route] of OPS) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `https://gmail.googleapis.com${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    // One read returns forwarding settings: discovery classified it as returning secrets, so its row is sensitive.
    operations.push({id, capabilityId: capability.id, method: method.toUpperCase(), path: route, ...(id.endsWith('getAutoForwarding') ? {sensitive: 'secrets'} : {sensitive: null})});
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-pages-'));
  seedPlatform(root);
  const sim = {tokens: new Map(), issued: 0};
  const request = async req => {
    if (req.url === 'https://oauth2.googleapis.com/token') { const token = `ya29.${++sim.issued}`; sim.tokens.set(token, sim.next); return {status: 200, headers: {}, data: {access_token: token, refresh_token: `1//r${sim.issued}`, token_type: 'Bearer', expires_in: 3600, scope: sim.scope}}; }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') { const who = sim.tokens.get(String(req.headers.Authorization).slice(7)); return {status: 200, headers: {}, data: {sub: who.id, email: who.email, name: who.name}}; }
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) return {status: 200, headers: {}, data: {emailAddress: sim.tokens.get(String(req.headers.Authorization).slice(7)).email}};
    throw new Error(`unexpected request ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
  const full = app.keys.mint({environmentId: dev.id, preset: 'full'}).token, standard = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  const catalogOnly = app.keys.mint({environmentId: dev.id, scopes: ['catalog:read']}).token;
  const call = async (key, method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  const connect = async (externalUserId, identity) => {
    const created = (await call(full, 'POST', '/v1/connect-sessions', {externalUserId, appId: 'gmail'})).body, binding = `browser-${created.id}`;
    app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
    const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl);
    sim.next = identity; sim.scope = url.searchParams.get('scope');
    const {finish} = await app.sessions.callback('google', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
    return app.sessions.confirm(created.id, binding, finish).result.accountRef;
  };
  const one = await connect('u1', {id: 'g-1', email: 'one@example.com', name: 'One'}), two = await connect('u2', {id: 'g-2', email: 'two@example.com', name: 'Two'});
  const page = async (key = full, user = 'u1', account) => (await call(key, 'GET', `/v1/users/${user}/apps/gmail${account ? `?account=${account}` : ''}`)).body;
  const row = (view, groupId) => view.sections.flatMap(section => section.rows).find(item => item.groupId === groupId);
  return {app, dev, full, standard, catalogOnly, call, one, two, page, row, scope: app.registry.scopeOf(dev)};
}
const SENSITIVE = 'sensitive.secrets.read';

test('one end user\'s app page: their accounts only, Fabric\'s rows, and never another user\'s account', async t => {
  const {full, call, one, two, page, row} = await setup(t);
  const view = await page();
  assert.equal(view.app.id, 'gmail'); assert.equal('connectionState' in view.app, false, 'the app card carries no connection state');
  assert.equal(view.connectionState, 'connected');
  assert.deepEqual(view.accounts.map(account => account.accountRef), [one]); assert.equal(view.selectedAccountRef, one);
  assert.deepEqual({read: row(view, 'gmail.messages.read').mode, drafts: row(view, 'gmail.drafts.write').mode, send: row(view, 'gmail.messages.send').mode, secrets: row(view, SENSITIVE).mode}, {read: 'allow', drafts: 'allow', send: 'ask', secrets: 'ask'});
  assert.match(view.background.etag, /^[0-9a-f]{32}$/);
  assert.equal(JSON.stringify(view).includes('two@example.com'), false);
  assert.equal((await call(full, 'GET', `/v1/users/u1/apps/gmail?account=${two}`)).body.error.code, 'not_found');
  assert.equal((await call(full, 'GET', '/v1/users/nobody/apps/gmail')).body.error.code, 'not_found');
  assert.equal((await call(full, 'GET', '/v1/users/u1/apps/not-an-app')).body.error.code, 'not_found');
});

test('the relay table (D5): Never, Ask and read Allow need permissions:write; write, delete and sensitive Allow need decisions:write and a confirmation', async t => {
  const {app, scope, full, standard, call, one, two, page, row} = await setup(t);
  const set = async (key, groupId, mode, extra = {}) => { const view = await page(); return call(key, 'POST', `/v1/users/u1/accounts/${one}/permissions`, {groupId, mode, etag: row(view, groupId).etag, ...extra}); };
  // F10.15 listed churn: the write row whose default is Allow is "Manage labels"; "Draft emails" is Never only now (the next test).
  assert.equal((await set(standard, 'gmail.labels.manage', 'deny')).body.mode, 'deny', 'Never on a write row');
  assert.equal((await set(standard, 'gmail.messages.read', 'ask')).body.mode, 'ask', 'Ask on any row');
  assert.equal((await set(standard, 'gmail.messages.read', 'allow')).body.mode, 'allow', 'Allow on a read row that is not sensitive');
  for (const groupId of ['gmail.labels.manage', 'gmail.messages.send', SENSITIVE]) {
    const refused = await set(standard, groupId, 'allow', {confirmAllow: true});
    assert.equal(refused.status, 403, groupId); assert.equal(refused.body.error.code, 'decision_not_permitted', groupId);
  }
  assert.equal(row(await page(), 'gmail.messages.send').mode, 'ask', 'a refused relay changes nothing');
  assert.equal((await set(full, 'gmail.messages.send', 'allow')).body.error.code, 'confirm_required', 'even the decision power needs the person\'s confirmation');
  assert.equal((await set(full, 'gmail.labels.manage', 'allow')).body.error.code, 'confirm_required', 'a write row whose default is Allow still needs it');
  assert.equal((await set(full, 'gmail.messages.send', 'allow', {confirmAllow: true})).body.mode, 'allow');
  // review is refused for everyone, stale etags and other users' accounts get nothing.
  const view = await page();
  assert.equal((await call(full, 'POST', `/v1/users/u1/accounts/${one}/permissions`, {groupId: 'gmail.messages.read', mode: 'allow', etag: row(view, 'gmail.messages.read').etag, review: true})).status, 400);
  assert.equal((await call(full, 'POST', `/v1/users/u1/accounts/${one}/permissions`, {groupId: 'gmail.messages.read', mode: 'deny', etag: 'f'.repeat(32)})).body.error.code, 'etag_mismatch');
  assert.equal((await call(full, 'POST', `/v1/users/u1/accounts/${two}/permissions`, {groupId: 'gmail.messages.read', mode: 'deny', etag: row(view, 'gmail.messages.read').etag})).body.error.code, 'not_found');
  // A developer ceiling refuses any mode above it.
  await call(full, 'PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.messages.read': 'ask'}});
  assert.equal((await set(full, 'gmail.messages.read', 'allow')).body.error.code, 'mode_not_allowed');
  assert.equal((await set(full, 'gmail.messages.read', 'ask')).status, 200);
  // N13: each relayed change names where it was made and the key that made it possible.
  const relayed = app.stores.open(scope).repository.list('activity').filter(event => event.type === 'permission.relayed');
  assert.ok(relayed.length >= 4); assert.ok(relayed.every(event => event.decidedIn === 'developer_app' && typeof event.byKey === 'string'));
  assert.ok(relayed.some(event => event.decision === true && event.groupId === 'gmail.messages.send'));
});

// F10.15 (spec line 123, N6): "Draft emails" has only unsupported members, so a developer's server can set it to Never only; the row reads
// "Not offered" with its members' one shared reason.
const DRAFT_WORDS = 'Fabric\'s plain form of this operation cannot carry a whole message, so it would save an empty draft or blank one. Fabric writes drafts through its reviewed Gmail actions.';
test('"Draft emails" is Never only: the row is not offered and says why; Ask and Allow are refused with the N6 words, whatever the key; Never is relayed', async t => {
  const {standard, full, call, one, page, row} = await setup(t);
  const drafts = row(await page(), 'gmail.drafts.write');
  assert.deepEqual([drafts.allowedModes, drafts.access, drafts.accessReason], [['deny'], 'unavailable', DRAFT_WORDS], 'the row says why it is not offered');
  for (const [key, mode, extra] of [[standard, 'ask', {}], [full, 'ask', {}], [full, 'allow', {confirmAllow: true}]]) {
    const refused = await call(key, 'POST', `/v1/users/u1/accounts/${one}/permissions`, {groupId: 'gmail.drafts.write', mode, etag: drafts.etag, ...extra});
    assert.deepEqual([refused.status, refused.body.error.code, refused.body.error.message], [409, 'mode_not_allowed', 'This permission includes operations that cannot do their job here; it can only be set to Never.'], mode);
  }
  assert.equal((await call(standard, 'POST', `/v1/users/u1/accounts/${one}/permissions`, {groupId: 'gmail.drafts.write', mode: 'deny', etag: drafts.etag})).body.mode, 'deny');
});

test('Reset without decisions:write leaves Gmail\'s "Draft emails" at Ask; with it, the reviewed default Allow returns', async t => {
  const {standard, full, call, one, page, row} = await setup(t);
  const set = async (groupId, mode) => call(full, 'POST', `/v1/users/u1/accounts/${one}/permissions`, {groupId, mode, etag: row(await page(), groupId).etag});
  await set('gmail.drafts.write', 'deny'); await set('gmail.messages.read', 'deny');
  const reset = await call(standard, 'POST', `/v1/users/u1/accounts/${one}/permissions/reset`, {});
  assert.equal(reset.status, 200);
  const after = await page();
  assert.equal(row(after, 'gmail.drafts.write').mode, 'ask', 'a write Allow is never restored without the decision power');
  assert.equal(row(after, 'gmail.messages.read').mode, 'allow', 'read rows return to their default');
  await call(full, 'POST', `/v1/users/u1/accounts/${one}/permissions/reset`, {groupIds: ['gmail.drafts.write']});
  assert.equal(row(await page(), 'gmail.drafts.write').mode, 'allow');
});

test('background reads: off needs permissions:write, back on needs decisions:write; the etag guards both', async t => {
  const {standard, full, call, one, page} = await setup(t);
  const background = async (key, mode, etag) => call(key, 'POST', `/v1/users/u1/accounts/${one}/background`, {mode, etag: etag ?? (await page()).background.etag});
  const off = await background(standard, 'deny');
  assert.equal(off.body.mode, 'deny'); assert.equal((await page()).background.mode, 'deny');
  assert.equal((await background(standard, 'allow')).body.error.code, 'decision_not_permitted');
  assert.equal((await background(full, 'allow', 'f'.repeat(32))).body.error.code, 'etag_mismatch');
  assert.equal((await background(full, 'allow')).body.mode, 'allow');
});

test('an end user\'s catalog shows their own connection states; the developer catalog shows none', async t => {
  const {full, catalogOnly, call} = await setup(t);
  const cards = page => [...page.featured, ...page.categories.flatMap(entry => entry.preview), ...(page.results || [])];
  const mine = (await call(full, 'GET', '/v1/users/u1/catalog?q=gmail')).body;
  const gmail = cards(mine).find(card => card.id === 'gmail');
  assert.equal(gmail.connectionState.state, 'connected'); assert.equal(gmail.primaryAction, 'view');
  assert.match(gmail.iconUrl, /^http:\/\/127\.0\.0\.1:\d+\/assets\/icons\/gmail$/);
  const stranger = cards((await call(full, 'GET', '/v1/users/nobody/catalog?q=gmail')).body).find(card => card.id === 'gmail');
  assert.equal(stranger.connectionState.state, 'available'); assert.equal(stranger.primaryAction, 'connect');
  const slack = cards((await call(full, 'GET', '/v1/users/u1/catalog?q=slack')).body).find(card => card.id === 'slack');
  assert.equal(slack.primaryAction, 'unavailable', 'availability comes from this environment: shared Slack is never offered');
  const developer = (await call(full, 'GET', '/v1/apps?q=gmail')).body.apps;
  assert.equal(developer.some(card => 'connectionState' in card), false, 'the developer party never sees connection state');
  assert.equal((await call(catalogOnly, 'GET', '/v1/users/u1/catalog')).body.error.code, 'forbidden_scope', 'an end user\'s catalog needs accounts:read too');
});

test('an end user\'s runnable capabilities: their ready accounts only, Allow or Ask, Never left out', async t => {
  const {full, call, one, page, row} = await setup(t);
  const listed = (await call(full, 'GET', '/v1/users/u1/capabilities?appId=gmail')).body.capabilities;
  assert.ok(listed.length >= 3); assert.ok(listed.every(item => item.accountRef === one && ['allow', 'ask'].includes(item.mode)));
  await call(full, 'POST', `/v1/users/u1/accounts/${one}/permissions`, {groupId: 'gmail.messages.send', mode: 'deny', etag: row(await page(), 'gmail.messages.send').etag});
  const after = (await call(full, 'GET', '/v1/users/u1/capabilities?appId=gmail')).body.capabilities;
  assert.equal(after.length, listed.length - 1, 'Never is left out');
  assert.deepEqual((await call(full, 'GET', '/v1/users/nobody/capabilities')).body, {capabilities: []});
});

test('F10.4 (T7): an upgrade card is never relayed over /v1, on a row or for the whole account', async t => {
  const {full, call, one, page, row} = await setup(t);
  const rows = AppDetailService.prototype.rows, view = AppDetailService.prototype.view, card = {rows: [{groupId: 'gmail.messages.read', label: 'Read emails', typed: true, proxy: true}], etag: 'e'.repeat(64)};
  // As if the environment's app service could plan sign-ins: every row and the page itself would carry a card.
  AppDetailService.prototype.rows = function (...args) { return rows.apply(this, args).map(item => ({...item, view: {...item.view, upgrade: card}})); };
  AppDetailService.prototype.view = function (...args) { return {...view.apply(this, args), upgrade: {...card, label: 'Upgrade to full access'}}; };
  try {
    const shown = await page();
    const relayed = await call(full, 'POST', `/v1/users/u1/accounts/${one}/permissions`, {groupId: 'gmail.messages.send', mode: 'deny', etag: row(shown, 'gmail.messages.send').etag});
    const reset = await call(full, 'POST', `/v1/users/u1/accounts/${one}/permissions/reset`, {});
    assert.deepEqual([relayed.status, reset.status], [200, 200]);
    for (const body of [shown, relayed.body, reset.body]) assert.ok(!JSON.stringify(body).includes('"upgrade"'), JSON.stringify(body).slice(0, 200));
  } finally { AppDetailService.prototype.rows = rows; AppDetailService.prototype.view = view; }
});

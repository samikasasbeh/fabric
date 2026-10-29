import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {templatesFor, matchRequest} from '../lib/proxy-match.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PermissionManager, permissionEffect, groupDefault} from '../lib/permissions.mjs';
import {compileOpenApi, validateCapability} from '../lib/compiler.mjs';
import {Store} from '../lib/store.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {validateActionFile, actionIds} from '../lib/actions.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {appEntry, ROOT} from '../scripts/defaults-golden.mjs';
import {fixture} from './fixtures/continuation-fixture.mjs';
import {fixtureGroups, fixtureConfigs, fixtureMap, fixtureChoices, fixtureActions} from './fixtures/actions/fixture-app.mjs';
import {TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';
import {actionHarness, certifiedFile} from './fixtures/actions/runtime-fixture.mjs';

// F10.10 (docs/F10.10-BUILD-MAP.md section 3): inside an action, a POST step listed in a read row's reviewedReads is a read only when
// everything it sends is built from reads (lib/action-placement.mjs stepEffect()). This file pins what that step must not move. The proxy
// still reads a reviewed-read POST as a read whatever its body, in the owner's runtime and in a developer environment alike; a typed
// freebusy.query keeps the method rule, so it takes the write lock and ends uncertain; and no signed default, binding, compiled id or
// action id moves. Nothing here talks to a provider: every answer comes from a function in this file.
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const APPS = ['github', 'gmail', 'google-calendar', 'notion', 'slack'];
const F107 = json('./fixtures/access/f10-7-bindings.before.json'), BEFORE = json('./fixtures/access/f10-9-bindings.before.json'), LOADERS = json('./fixtures/access/f10-9-loaders.before.json');
const GOLDEN = json('./fixtures/access/defaults.golden.json');
const CALENDAR = 'https://www.googleapis.com/calendar/v3', G = 'https://www.googleapis.com/auth/';
const CALENDAR_SCOPES = ['calendar.events', 'calendar.calendarlist', 'calendar.calendars', 'calendar.acls', 'calendar.settings.readonly', 'calendar.freebusy'].map(scope => `${G}${scope}`);
/** Typed capabilities for these map operations, compiled from an OpenAPI document as F10.9's churn snapshot compiled them. */
function compiled(appId, operations, server) {
  const paths = {};
  for (const operation of operations) paths[operation.path] = {...paths[operation.path], [operation.method.toLowerCase()]: {operationId: operation.id,
    parameters: [...operation.path.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'ok'}}}};
  return compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: server}], paths}}).capabilities.map(cap => ({...cap, status: 'active'}));
}
/** Calendar's freebusy.query compiled at its synthetic path (F10.7's map), and that map with the capability's id on it. */
function calendarFreebusy() {
  const operations = F107.maps['google-calendar'].operations, free = operations.find(operation => operation.id === 'calendar.freebusy.query');
  const [cap] = compiled('google-calendar', [free], CALENDAR);
  const map = {id: 'google-calendar', appId: 'google-calendar', classifierVersion: SENSITIVITY_VERSION,
    operations: operations.map(operation => ({...operation, sensitive: null, ...(operation.id === free.id ? {capabilityId: cap.id} : {})}))};
  return {cap, map, free};
}

// ---- the proxy, in the owner's runtime ---------------------------------------------------------------------------------------------
test('the proxy is unchanged: a reviewed-read POST is a read whatever its body (a REST request by its member, an RPC request by its row), and Allow by default', async t => {
  const notion = templatesFor(PERMISSION_GROUPS.get('notion'), PROXY_CONFIGS.get('notion'), null), slack = templatesFor(PERMISSION_GROUPS.get('slack'), PROXY_CONFIGS.get('slack'), null);
  const search = matchRequest(notion, {method: 'POST', segments: ['v1', 'search']}, {style: 'rest'});
  assert.deepEqual([search.groupId, search.effect, search.reviewedRead], ['notion.search.read', 'read', true]);
  const canvas = matchRequest(slack, {method: 'POST', segments: ['canvases.getContent']}, {style: 'rpc'});
  assert.deepEqual([canvas.groupId, canvas.effect, canvas.reviewedRead], ['slack.files.read', 'read', false], 'an RPC request reads as its row');
  const f = await fixture(t);
  f.store.put('connections', {id: 'pages', appId: 'notion', driver: 'http', authMethod: 'oauth', authRevision: 'consent-pages', status: 'ready', label: 'pages', identity: {id: 'pages'},
    allowedOrigins: ['https://api.notion.com'], scopes: [], createdAt: '2026-10-11T10:00:00.000Z'});
  const policy = new ProxyPolicy({store: f.store, permissions: f.runtime.permissions});
  // Whatever the body holds, a cursor a write once answered included: the proxy has no provenance, only the member.
  for (const body of [{query: 'plans'}, {query: 'plans', start_cursor: 'c-2', filter: {property: 'object', value: 'page'}}]) {
    const decision = policy.decide('pages', {method: 'POST', path: '/v1/search', body});
    assert.deepEqual([decision.row, decision.effect, decision.mode, decision.requiresApproval, decision.match.reviewedRead], ['group:notion.search.read', 'read', 'allow', false, true], JSON.stringify(body));
  }
  const context = policy.route('pages'), entry = policy.rows(context).find(row => row.row === 'group:notion.search.read');
  const member = policy.memberState(context, entry, 'POST /v1/search');
  assert.deepEqual([member.effect, member.reviewedAsRead, member.mode, member.defaultMode], ['read', true, 'allow', 'allow']);
});

// ---- the proxy and typed calls, in a developer environment --------------------------------------------------------------------------
/** A developer environment with one end user who has a Notion account and a Google Calendar account, and a typed freebusy.query. */
async function developer(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-f10-10-'));
  const {map} = calendarFreebusy(), [cap] = compiled('google-calendar', [F107.maps['google-calendar'].operations.find(operation => operation.id === 'calendar.freebusy.query')], CALENDAR);
  const platform = new PlatformStore({root});
  platform.put('capabilities', cap);
  platform.put('applicationMaps', map);
  platform.close();
  const sim = {calls: []};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    const data = req.url.startsWith('https://api.notion.com/') ? {object: 'list', results: [{object: 'page', id: 'p-1'}], has_more: false} : {kind: 'calendar#freeBusy', calendars: {}};
    return req.responseType === 'buffer' ? {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(data))} : {status: 200, headers: {}, data};
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, notion: {clientId: 'n-client', clientSecret: 'n-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  const call = async (method, route, body, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u1'});
  const user = repo().list('endUsers').find(item => item.subjectId === 'u1' && item.status === 'active');
  const account = (appId, providerId, origin, identity, scopes) => {
    const id = randomUUID(), now = app.registry.now();
    repo().put('connections', stampOwner({id, appId, providerId, driver: 'http', status: 'ready', authMethod: 'oauth', identity, allowedOrigins: [origin], scopes, createdAt: now, updatedAt: now, authRevision: randomUUID()},
      {subjectId: 'u1', userRecordId: user.id}));
    app.stores.open(scope).vault.set(id, {accessToken: `${appId}-secret-token-value`, refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000});
    return id;
  };
  const pages = account('notion', 'notion', 'https://api.notion.com', {id: 'ws-a:notion-user-a', displayName: 'Avery A'}, []);
  const calendar = account('google-calendar', 'google', 'https://www.googleapis.com', {id: 'g-1', displayName: 'g-1@example.com', email: 'g-1@example.com'}, CALENDAR_SCOPES);
  const agent = async (token, method, params) => {
    const response = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id: randomUUID(), method, params})});
    return {status: response.status, body: await response.json()};
  };
  return {app, sim, scope, call, repo, pages, calendar, agent};
}

test('a developer environment reads a reviewed-read POST through the proxy as before: /v1/proxy/requests and an agent\'s proxy.request run at Allow, as a read, with no approval hold', async t => {
  const {sim, call, repo, pages, agent} = await developer(t);
  const search = {method: 'POST', path: '/v1/search', body: {query: 'plans'}};
  const done = await call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'notion', request: search, waitMs: 5000}, {'Idempotency-Key': randomUUID()});
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.deepEqual([done.body.kind, done.body.status, done.body.evidence, done.body.accountRef], ['proxy', 'succeeded', 'observed', pages]);
  const job = repo().get('jobs', done.body.callRef);
  assert.deepEqual([job.effect, job.permissionMode, job.status], ['read', 'allow', 'succeeded']);
  assert.equal(repo().list('jobs').filter(item => item.status === 'awaiting_approval').length, 0, 'no approval hold');
  // The same through an agent token that may use the row, on /fabric/v1.
  const minted = (await call('POST', '/v1/users/u1/agent-tokens', {name: 'Search helper', bindings: [], proxy: [{accountRef: pages, rows: ['group:notion.search.read']}]})).body;
  assert.ok(minted.token, JSON.stringify(minted));
  const alias = (await agent(minted.token, 'capabilities.list', {})).body.result.proxy[0].connectionId;
  const proxied = await agent(minted.token, 'proxy.request', {connectionId: alias, request: search});
  assert.equal(proxied.body.result?.status, 'succeeded', JSON.stringify(proxied.body));
  assert.deepEqual([proxied.body.result.capabilityId, proxied.body.result.approvalRequired, proxied.body.result.evidence, proxied.body.result.request.effect], ['proxy:group:notion.search.read', false, 'observed', 'read']);
  assert.deepEqual([repo().get('jobs', proxied.body.result.id).effect, repo().get('jobs', proxied.body.result.id).permissionMode], ['read', 'allow']);
  assert.equal(sim.calls.filter(line => line === 'POST https://api.notion.com/v1/search').length, 2);
});

test('a developer environment keeps the typed method rule: POST /v1/executions on freebusy.query runs at its default Allow and answers outcome_uncertain', async t => {
  const {call, calendar} = await developer(t);
  const cap = (await call('GET', '/v1/capabilities?appId=google-calendar')).body.capabilities.find(item => item.name === 'calendar.freebusy.query' || item.id.includes('freebusy'));
  assert.ok(cap, 'the typed operation is listed');
  const sent = await call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: cap.id, definitionHash: cap.definitionHash, args: {}, waitMs: 5000},
    {'Idempotency-Key': randomUUID()});
  assert.deepEqual([sent.body.status, sent.body.accountRef, sent.body.error?.code], ['uncertain', calendar, 'outcome_uncertain'], JSON.stringify(sent.body));
});

// ---- typed capabilities, in the owner's runtime ---------------------------------------------------------------------------------------
test('a typed freebusy.query keeps the method rule: a write by effectOf() and permissionEffect(), refused declared read, Allow only through reviewedAsRead, and a 200 holds the write lock and ends uncertain', async t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-f10-10-typed-')), store = new Store({dataDir: dir});
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  const {cap, map} = calendarFreebusy();
  store.put('capabilities', cap);
  store.put('applicationMaps', map);
  store.put('connections', {id: 'cal', appId: 'google-calendar', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: 'g-1'}, allowedOrigins: ['https://www.googleapis.com'], scopes: CALENDAR_SCOPES});
  const runtime = new Runtime({store, connections: {credentials: async () => ({headers: {Authorization: 'Bearer test-only'}, allowedOrigins: ['https://www.googleapis.com']})}});
  assert.deepEqual([cap.request.method, runtime.effectOf(cap), permissionEffect(cap), cap.effect], ['POST', 'write', 'write', 'write']);
  assert.throws(() => validateCapability({...cap, effect: 'read'}), /Declared effect does not match conservative HTTP method classification/);
  const decision = new PermissionManager({store}).decision(store.get('connections', 'cal'), cap), group = PERMISSION_GROUPS.get('google-calendar').groups.find(item => item.id === decision.groupId);
  assert.deepEqual([decision.groupId, decision.effect, decision.defaultMode, decision.mode], ['google-calendar.availability.read', 'write', 'allow', 'allow']);
  assert.deepEqual([groupDefault(group, cap, 'write', {reviewedAsRead: true}), groupDefault(group, cap, 'write', {reviewedAsRead: false})], ['allow', 'ask'], 'only its default follows the reviewed read');
  let locked = null;
  runtime.request = async () => { locked = runtime.writeLocks.has('account:cal'); return {status: 200, data: {kind: 'calendar#freeBusy', calendars: {}}}; };
  const done = await runtime.createJob({connectionId: 'cal', capabilityId: cap.id, args: {}});
  assert.deepEqual([done.effect, done.permissionMode, done.status, locked, runtime.writeLocks.size], ['write', 'allow', 'uncertain', true, 0]);
});

// ---- no churn ------------------------------------------------------------------------------------------------------------------------
/** Every proxy-row binding of one account, over the recorded synthetic maps, as F10.9's snapshot recorded them. */
function proxyRowsOf(connection) {
  const config = PROXY_CONFIGS.get(connection.appId), definition = PERMISSION_GROUPS.get(connection.appId), policy = new ProxyPolicy({store: null});
  const templates = templatesFor(definition, config, F107.maps[connection.appId] ?? null);
  return Object.fromEntries(policy.rows({config, definition}).map(({row}) => [row, policy.binding({connection, config, templates}, row)]));
}

test('no churn: every signed data hash equals the golden, and proxy settings, proxy-row and typed bindings and compiled ids are those F10.9 recorded', t => {
  for (const appId of APPS) assert.equal(appEntry(ROOT, appId).dataHash, GOLDEN.apps[appId].dataHash, `${appId} signed data hash`);
  for (const appId of APPS) assert.equal(PROXY_CONFIGS.get(appId).configHash, LOADERS.proxyConfigs[appId].configHash, `${appId} proxy configHash`);
  for (const appId of APPS) assert.deepEqual(proxyRowsOf(BEFORE.connections[appId]), BEFORE.proxyRows[appId], `${appId} proxy-row bindings`);
  // A typed binding hashes the capability's id and bytes, so equal bindings mean equal compiled ids.
  const SERVERS = {gmail: 'https://gmail.googleapis.com', 'google-calendar': CALENDAR};
  for (const appId of Object.keys(BEFORE.typed)) {
    const dir = mkdtempSync(path.join(tmpdir(), 'fabric-f10-10-churn-')), store = new Store({dataDir: dir}), operations = F107.maps[appId].operations;
    t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
    const caps = compiled(appId, operations, SERVERS[appId]), connection = BEFORE.connections[appId];
    store.put('connections', connection);
    for (const cap of caps) store.put('capabilities', cap);
    store.put('applicationMaps', {id: appId, appId, operations: operations.map(operation => ({...operation, capabilityId: caps.find(cap => cap.name === operation.id).id}))});
    const permissions = new PermissionManager({store}), stored = store.get('connections', connection.id);
    assert.deepEqual(Object.fromEntries(caps.map(cap => [cap.name, permissions.decision(stored, cap).bindingHash]).sort(([a], [b]) => a < b ? -1 : 1)), BEFORE.typed[appId], `${appId} typed bindings`);
  }
});

test('no churn: the fixture actions keep their ids, definition hashes and poll hash (placements and rawAt are never hashed)', () => {
  const groups = fixtureGroups(), deps = {groups, configs: fixtureConfigs(groups), maps: new Map([['fixture', fixtureMap()]]), transforms: TRANSFORMS, pins: PINS, choices: new Map([['fixture', fixtureChoices().sources]])};
  const entries = validateActionFile(fixtureActions(), deps).actions;
  assert.deepEqual(entries.map(entry => [entry.key, entry.id, entry.definitionHash, entry.pollHash]), [
    ['list-items', 'fixture.action.list-items.v1.f4275b116c7968cfc43f563d', '63800a1366904c3a91dce145e4ee81be51029b1fa272deb84134c09c3c2ef627', '6136975e9505f5bb93267d8e1bb59db116bfe0ee9868d557233e699a72348e55'],
    ['update-item', 'fixture.action.update-item.v1.b298bcf427f013ff49d8a0b0', '42ddf80b760eb04f14abd1935bd8c1c4e11f1bcf6a7c5547ce1dbcdfd02aa47b', null],
    ['remove-labels', 'fixture.action.remove-labels.v1.c1d338b2a6149e0d752baeb5', '904e2fabfbd1dc5023e7db463f9feae1eb35cdb6402eebc8445ea96a32de005e', null],
    ['put-file', 'fixture.action.put-file.v1.4f95fad35eb51291b5ddd55d', 'd84d9604caa93f2f037204a039920162d6e40b1c3c51a30e4354be646f45dfa4', null],
    ['reschedule-event', 'fixture.action.reschedule-event.v1.beaa5c53f94a1b74a052f14c', '174e0948b1ca1df97d63747854fec9d40bbf8467ffa7dbda130cf2a6ffd2044d', null],
    ['send-draft', 'fixture.action.send-draft.v1.9a52839d814cc4451f391096', '70e232bfe4d31483a364c43024abdf9cb14abba799867b7b1c112048387ad8ce', null],
    // F10.19 listed churn (docs/F10.19-BUILD-MAP.md part 1): add-row names notion.schema@1 and notion.propertyValues@1, whose fixture stubs gave
    // way to the shipped transforms, so their pins and add-row's id and definition hash moved; nothing else here did.
    ['add-row', 'fixture.action.add-row.v1.9e1887a67b1af2f89d4e20ce', 'b2f29c2431b60b334a0997dc799a34f7ade21da214197166945574844c0c9d7a', null]]);
});

/** The relative modules a file imports statically, resolved against it. F10.11 part p (listed churn, as in test/f10-9-churn.test.mjs): the
 *  action modules now load at start through the one guarded import() in lib/action-gate.mjs, which test/f10-11-churn.test.mjs counts. */
function importsOf(file) {
  const text = readFileSync(file, 'utf8'), found = new Set();
  for (const match of text.matchAll(/(?:\bfrom\s*|\bimport\s+)(['"])(\.{1,2}\/[^'"]+)\1/g)) found.add(path.resolve(path.dirname(file), match[2]));
  return [...found];
}

test('no churn: server.mjs reaches no action module statically; a running Fabric reads actions only through the catalog lib/action-gate.mjs loads', () => {
  const root = fileURLToPath(new URL('..', import.meta.url)), seen = new Set(), queue = [path.join(root, 'server.mjs')];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    for (const next of importsOf(file)) if (/\.m?[jt]s$/.test(next)) queue.push(next);
  }
  assert.ok(seen.size > 20, 'the walk follows the import graph');
  for (const name of ['lib/actions.mjs', 'lib/action-expressions.mjs', 'lib/action-placement.mjs', 'lib/choice-sources.mjs', 'lib/triggers.mjs']) assert.ok(!seen.has(path.join(root, name)), `${name} is not reachable from server.mjs`);
});

// ---- waiting on later steps ---------------------------------------------------------------------------------------------------------
// F10.11 part i: the run-time case, on the fake app's simulator (test/fixtures/provider-simulators/fixture.mjs) and the run harness. A Notion
// Search shaped read (the REST twin's reviewed-read POST /items/search) and a Find free time or canvas shaped read (the RPC twin's reviewed-read
// POST /canvases.read) run under Allow, take no write lock and end succeeded, observed.
test('F10.11: reviewed-read POST actions end succeeded under Allow and take no write lock, on the fake provider (POST /items/search, RPC POST /canvases.read)', async t => {
  const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false}), text = {type: 'string', minLength: 1, maxLength: 64};
  const read = (appId, key, row, step, output) => ({id: `${appId}.action.${key}.v1.${'0'.repeat(24)}`, key, version: 1, name: key, description: `The ${key} read.`, effect: 'read', row,
    hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true}, inputSchema: closed({value: text}), outputSchema: closed({value: {type: 'string', maxLength: 200}}), guards: [], prepare: [],
    perform: [step], output: {value: output}, preview: [{label: 'Value', expr: {input: '/value'}}], definitive: [400], certified: {evidence: `docs/live-evidence/${appId}/actions.json`, definitionHash: '0'.repeat(64)}});
  const search = read('fixture', 'search', 'fixture.items.read', {id: 'find', method: 'POST', path: '/items/search', body: {object: {query: {input: '/value'}}}, expect: {status: [200], require: []}}, {step: 'find', pointer: '/results/0/title'});
  const canvas = read('fixture-rpc', 'canvas', 'fixture-rpc.messages.read', {id: 'canvas', method: 'POST', path: '/canvases.read', body: {object: {canvas_id: {input: '/value'}}},
    expect: {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]}}, {step: 'canvas', pointer: '/title'});
  const h = actionHarness(t, {file: certifiedFile(file => { file.actions.push(search); }), files: [{schemaVersion: 1, appId: 'fixture-rpc', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: [canvas]}]});
  const locks = [], send = h.simulator.request;
  h.runtime.request = async options => { locks.push(h.runtime.writeLocks.size); return send(options); };
  for (const [key, value, shown] of [['search v1', 'plan', 'Plan B'], ['canvas v1', 'F1', 'Roadmap']]) {
    const job = await h.run(key, {value});
    assert.deepEqual([job.status, job.effect, job.result.verification.status, job.result.data], ['succeeded', 'read', 'observed', {value: shown}], key);
  }
  assert.deepEqual(locks, [0, 0], 'no write lock while they ran');
  assert.equal(h.simulator.writes().length, 0);
});

// F10.11 part a recorded Google's own method paths (test/fixtures/access/google-method-paths.json), so the former todo is a test.
test('F10.11 part a: Calendar Find free time places on Google\'s own POST /freeBusy path as a read, and a body fed by a write keeps it a write', () => {
  const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false}), text = max => ({type: 'string', minLength: 1, maxLength: max});
  const freeTime = body => ({schemaVersion: 1, appId: 'google-calendar', specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {}, actions: [{id: `google-calendar.action.find-free-time.v1.${'0'.repeat(24)}`,
    key: 'find-free-time', version: 1, name: 'Find free time', description: 'Finds the busy blocks of a calendar in a window.', effect: 'read', row: 'google-calendar.availability.read',
    hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true}, inputSchema: closed({calendarId: text(200), from: text(64), to: text(64)}), outputSchema: closed({kind: text(64)}),
    guards: [], prepare: [], perform: [{id: 'free', method: 'POST', path: '/freeBusy', body, expect: {status: [200], require: []}}], output: {kind: {step: 'free', pointer: '/kind'}}, preview: [], definitive: [400]}]});
  const deps = {maps: new Map([['google-calendar', googleMap('google-calendar')]]), identities: new Map([['google-calendar', definitionFor('google')]])};
  const file = freeTime({object: {timeMin: {input: '/from'}, timeMax: {input: '/to'}, items: {array: [{object: {id: {input: '/calendarId'}}}]}}});
  file.actions[0].id = actionIds(file, deps).get('find-free-time v1').id;
  const [entry] = validateActionFile(file, deps).actions;
  assert.deepEqual([entry.effect, entry.unplaced], ['read', false]);
  assert.deepEqual(['member', 'groupId', 'template', 'reviewedRead', 'fromReads', 'effect'].map(key => entry.placements[0][key]),
    ['calendar.freebusy.query', 'google-calendar.availability.read', 'POST /freeBusy', true, true, 'read']);
  // A job key is no read source, so the same POST built from one is a write, and the action declared read is refused.
  const keyed = freeTime({object: {timeMin: {input: '/from'}, timeMax: {input: '/to'}, items: {array: [{object: {id: {input: '/calendarId'}}}]}, requestId: {jobKey: 'free'}}});
  assert.throws(() => validateActionFile(keyed, deps), /find-free-time v1: declares effect read, but its steps compute write \(spec line 750\)/);
});

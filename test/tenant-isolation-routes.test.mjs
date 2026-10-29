import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
import {deflateSync, crc32} from 'node:zlib';
import {createDeveloperApp} from '../developer-server.mjs';
import {ROUTES} from '../lib/tenant/api.mjs';
import {newId} from '../lib/tenant/registry.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';

// Exit check 1 (docs/F03-DEVELOPER-LAYER.md section 9, invariant N2): the isolation matrix at the HTTP level, for every
// /v1 route. Environments A and B sit in two projects of one organization, with two end users each; A/u1 and B/u1 share
// the external id u1. Every route is called with A's full key on B's ids (and, where the route names an end user, as
// A/u1 on A/u2's ids) and must answer exactly like a never-existing id of the same shape. B's store, vault and registry
// routes, the platform store and the in-memory maps stay as they were, no revoke reaches Google, and every route still
// works on A's own ids, so a route that refuses everything cannot pass.
const TEST_MAPS = Symbol.for('fabric.test.maps');
const U = '([^/]{1,400})', R = '([^/]{1,100})', APP = '([a-z][a-z0-9-]{0,63})', CS = '([a-z0-9_]{1,40})', CAP = '([A-Za-z0-9._:-]{1,200})';
/** Everything an environment keeps per end user or per developer (section 4.1 N3), digested before and after. */
const COLLECTIONS = ['connections', 'permissions', 'backgroundPolicies', 'jobs', 'endUsers', 'connectSessions', 'continuations', 'approvals', 'clientGrants', 'providerApps', 'usageEvents', 'activity',
  'oauthFlows', 'defaultAccounts', 'idempotencyKeys', 'proxyResponses'];
const REGISTRY = ['projects', 'environments', 'serviceClients', 'serviceKeys', 'sessionRoutes', 'flowRoutes', 'projectLogos', 'clientIds', 'agentTokenRoutes'];
const sha = value => createHash('sha256').update(JSON.stringify(value ?? null)).digest('hex');

// ---- the platform catalog: Gmail typed operations (read, send, list, labels, drafts) and one GitHub read for a hold ----
const GMAIL = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send'],
  ['gmail.users.messages.list', 'get', '/gmail/v1/users/{userId}/messages', ['labelIds']], ['gmail.users.labels.list', 'get', '/gmail/v1/users/{userId}/labels'],
  ['gmail.users.drafts.list', 'get', '/gmail/v1/users/{userId}/drafts']];
function compiled(appId, server, ops) {
  const paths = {};
  for (const [id, method, route, query = []] of ops) paths[route] = {...(paths[route] || {}), [method]: {operationId: id, parameters: [...[...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})), ...query.map(name => ({name, in: 'query', required: false, schema: {type: 'string'}}))],
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const capabilities = compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: server}], paths}}).capabilities;
  return ops.map(([id, method, route]) => ({id, method: method.toUpperCase(), route, capability: capabilities.find(item => item.request.method === method.toUpperCase() && decodeURIComponent(item.request.url) === `${server}${route}`)}));
}
function seed(root) {
  const store = new PlatformStore({root});
  // Gmail is reviewed by operation id: every reviewed operation is in the stored map, the typed ones bound to their capability.
  const operations = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => ({id, method: id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`, sensitive: null}));
  for (const [id, route] of [['gmail.users.threads.get', '/gmail/v1/users/{userId}/threads/{id}'], ['gmail.users.getProfile', '/gmail/v1/users/{userId}/profile']]) { const at = operations.findIndex(op => op.id === id); if (at >= 0) operations[at] = {...operations[at], path: route}; }
  for (const {id, method, route, capability} of compiled('gmail', 'https://gmail.googleapis.com', GMAIL)) {
    store.put('capabilities', {...capability, status: 'active'});
    const at = operations.findIndex(op => op.id === id), entry = {id, capabilityId: capability.id, method, path: route, sensitive: null};
    if (at >= 0) operations[at] = entry; else operations.push(entry);
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  for (const {capability} of compiled('github', 'https://api.github.com', [['repos/list-for-authenticated-user', 'get', '/user/repos']])) store.put('capabilities', {...capability, status: 'active'});
  store.close();
}
const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const pngChunk = (type, data) => { const length = Buffer.alloc(4); length.writeUInt32BE(data.length); const body = Buffer.concat([Buffer.from(type, 'latin1'), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body)); return Buffer.concat([length, body, crc]); };
function png(size) {
  const header = Buffer.alloc(13); header.writeUInt32BE(size, 0); header.writeUInt32BE(size, 4); header[8] = 8; header[9] = 6;
  return Buffer.concat([SIGNATURE, pngChunk('IHDR', header), pngChunk('IDAT', deflateSync(Buffer.alloc((size * 4 + 1) * size))), pngChunk('IEND', Buffer.alloc(0))]);
}

// ---- two cells, A and B -------------------------------------------------------------------------------------------
async function world(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-isolation-routes-'));
  seed(root);
  const now = Date.UTC(2026, 9, 14, 12);
  const sim = {calls: []};
  const header = (req, name) => Object.entries(req.headers || {}).find(([key]) => key.toLowerCase() === name)?.[1];
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    const who = String(header(req, 'authorization') || '').replace(/^Bearer ya29\./, '');
    if (req.url.startsWith('https://oauth2.googleapis.com/revoke')) return {status: 200, headers: {}, data: {}};
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') return {status: 200, headers: {}, data: {sub: who, email: `${who}@example.com`, name: who}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) return {status: 200, headers: {}, data: {emailAddress: `${who}@example.com`}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/labels')) return {status: 200, headers: {}, data: {labels: [{id: 'INBOX', name: 'INBOX'}, {id: 'Label_1', name: 'Receipts'}]}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/messages/send')) return {status: 200, headers: {}, data: {id: 'sent-1', threadId: 't-1'}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/')) return {status: 200, headers: {}, data: {id: 'm-1'}};
    return {status: 404, headers: {}, data: {}};
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, clock: () => now, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const organization = app.registry.createOrganization({name: 'Acme Group'});
  const send = async (token, {method, path: route, body, headers = {}, raw, type}) => {
    const init = {method, headers: {Authorization: `Bearer ${token}`, ...headers}};
    if (raw) { init.headers['Content-Type'] = type; init.body = raw; } else if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    const response = await fetch(`${app.origin}${route}`, init), text = await response.text();
    return {status: response.status, body: text ? JSON.parse(text) : null, text};
  };
  let caps = null;
  const cell = async (tag, appName) => {
    const project = app.registry.createProject({organizationId: organization.id, name: `${tag} Agent`, appName});
    const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
    app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
    const key = app.keys.mint({environmentId: dev.id, preset: 'full'});
    const env = () => app.stores.open(scope), call = spec => send(key.token, spec);
    const c = {tag, project, dev, scope, scopeKey: env().repository.scopeKey, keyId: key.keyId, serviceClientId: app.registry.get('serviceKeys', key.keyId).serviceClientId, env, call, users: {}};
    if (!caps) {
      const listed = [...(await call({method: 'GET', path: '/v1/capabilities?appId=gmail&limit=100'})).body.capabilities, ...(await call({method: 'GET', path: '/v1/capabilities?appId=github'})).body.capabilities];
      const find = part => listed.find(item => item.id.includes(part));
      caps = {read: find('messages-get'), send: find('messages-send'), list: find('messages-list'), hold: listed.find(item => item.appId === 'github')};
      for (const [name, value] of Object.entries(caps)) assert.ok(value, `capability ${name} is seeded`);
    }
    const userOf = externalUserId => env().repository.list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active');
    /** A ready Gmail account for an end user, seeded as a confirmed sign-in would leave it. */
    c.account = async (externalUserId, identity) => {
      if (!userOf(externalUserId)) assert.equal((await call({method: 'POST', path: '/v1/connect-sessions', body: {externalUserId}})).status, 201);
      const user = userOf(externalUserId), id = randomUUID(), stamp = app.registry.now();
      env().repository.put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', allowedOrigins: ['https://gmail.googleapis.com'], scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.compose', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify'],
        driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: identity, displayName: `${identity}@example.com`}, label: `${identity}@example.com`, createdAt: stamp, updatedAt: stamp, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: externalUserId, userRecordId: user.id}));
      env().vault.set(id, {accessToken: `ya29.${identity}`, refreshToken: `1//${identity}`, expiresAt: now + 3600_000});
      return id;
    };
    /** A send on the person's account that waits for their decision (Gmail send defaults to Ask), with its digest. */
    c.ask = async (externalUserId, accountRef) => {
      const made = await call({method: 'POST', path: '/v1/executions', body: {externalUserId, accountRef, capabilityId: caps.send.id, definitionHash: caps.send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}}, headers: {'Idempotency-Key': randomUUID()}});
      assert.equal(made.body.status, 'awaiting_approval', JSON.stringify(made.body));
      const item = (await call({method: 'GET', path: `/v1/users/${externalUserId}/approvals`})).body.approvals.find(entry => entry.callRef === made.body.callRef);
      return {callRef: made.body.callRef, digest: item.digest};
    };
    /** One account's app page as the developer sees it: row etags and the background etag. */
    c.view = async (externalUserId, accountRef) => (await call({method: 'GET', path: `/v1/users/${externalUserId}/apps/gmail?account=${accountRef}`})).body;
    c.rowEtag = async (externalUserId, accountRef, groupId) => (await c.view(externalUserId, accountRef)).sections.flatMap(section => section.rows).find(row => row.groupId === groupId || row.id === groupId).etag;
    c.token = async (externalUserId, accountRef) => {
      const made = await call({method: 'POST', path: `/v1/users/${externalUserId}/agent-tokens`, body: {name: 'Inbox helper', bindings: [{accountRef, capabilityId: caps.read.id}]}});
      assert.equal(made.status, 201, JSON.stringify(made.body));
      return made.body.agentToken.id;
    };
    /** Every kind of record one end user can hold, through the developer API itself. */
    c.person = async externalUserId => {
      const session = await call({method: 'POST', path: '/v1/connect-sessions', body: {externalUserId}});
      assert.equal(session.status, 201);
      const identity = `${tag.toLowerCase()}-${externalUserId}`, ref = await c.account(externalUserId, identity), idem = randomUUID();
      const finishedBody = {externalUserId, capabilityId: caps.read.id, definitionHash: caps.read.definitionHash, args: {userId: 'me', id: 'm-1'}, waitMs: 5000};
      const finished = await call({method: 'POST', path: '/v1/executions', body: finishedBody, headers: {'Idempotency-Key': idem}});
      assert.equal(finished.body.status, 'succeeded', JSON.stringify(finished.body));
      const waiting = await c.ask(externalUserId, ref);
      const saved = await call({method: 'POST', path: `/v1/users/${externalUserId}/accounts/${ref}/permissions`, body: {groupId: 'gmail.drafts.read', mode: 'deny', etag: await c.rowEtag(externalUserId, ref, 'gmail.drafts.read')}});
      assert.equal(saved.status, 200, JSON.stringify(saved.body));
      const background = await call({method: 'POST', path: `/v1/users/${externalUserId}/accounts/${ref}/background`, body: {mode: 'deny', etag: (await c.view(externalUserId, ref)).background.etag}});
      assert.equal(background.status, 200, JSON.stringify(background.body));
      c.users[externalUserId] = {externalUserId, identity, ref, idem, finishedBody, callRef: finished.body.callRef, waiting, token: await c.token(externalUserId, ref), session: session.body.id, userRecordId: userOf(externalUserId).id};
    };
    c.providerApp = async (clientId, consentScreenName) => {
      const made = await call({method: 'POST', path: '/v1/provider-apps', body: {providerId: 'github', clientId, clientSecret: `secret-${clientId}`, consentScreenName}});
      assert.equal(made.status, 201, JSON.stringify(made.body));
      return made.body.providerApp.id;
    };
    return c;
  };
  const A = await cell('A', 'Acme Assistant'), B = await cell('B', 'Beta Marker App');
  for (const user of ['u1', 'u2']) await A.person(user);
  for (const user of ['u1', 'u3']) await B.person(user);
  A.pa = await A.providerApp('alpha-gh-client', 'Alpha Screen');
  B.pa = await B.providerApp('beta-gh-client', 'Beta Screen Marker');
  // B also holds a call waiting for a GitHub account (a continuation and its handoff session), and picks its own GitHub app.
  const held = await B.call({method: 'POST', path: '/v1/executions', body: {externalUserId: 'u1', capabilityId: caps.hold.id, definitionHash: caps.hold.definitionHash, onMissingAccess: 'hold'}, headers: {'Idempotency-Key': randomUUID()}});
  assert.equal(held.status, 202, JSON.stringify(held.body));
  B.hold = {callRef: held.body.callRef, session: held.body.handoff.connectSessionId};
  assert.equal((await B.call({method: 'PUT', path: '/v1/environment/apps/github', body: {providerApp: B.pa}})).status, 200);
  // A's spare person, whose accounts the destructive own-cell controls use up.
  assert.equal((await A.call({method: 'POST', path: '/v1/connect-sessions', body: {externalUserId: 's1'}})).status, 201);
  let spares = 0;
  A.spare = () => A.account('s1', `a-spare-${++spares}`);
  await app.runtimes.drain();
  return {app, sim, A, B, caps};
}

/** Everything of B that A's calls must leave alone: every collection, the vault entries, B's registry records. */
function digestOf(app, cell, organizationId, vaultIds) {
  const env = app.stores.open(cell.scope), repository = env.repository, collections = Object.fromEntries(COLLECTIONS.map(name => [name, repository.list(name)]));
  const ids = new Set([...vaultIds, ...collections.connections.map(item => item.id), ...collections.providerApps.map(item => `providerApp:${item.id}`), ...collections.oauthFlows.map(item => `oauth:${item.id}`), 'optionCursorKey']);
  const vault = Object.fromEntries([...ids].sort().map(id => [id, sha(env.vault.get(id))]));
  const mine = record => [cell.dev.id, cell.project.id, cell.scopeKey].some(id => JSON.stringify(record).includes(id));
  const registry = {organization: app.registry.get('organizations', organizationId), ...Object.fromEntries(REGISTRY.map(name => [name, app.registry.list(name).filter(mine)]))};
  return {collections, vault, registry};
}
const platformOf = (app, cell) => sha(['capabilities', 'applicationMaps'].map(name => app.stores.open(cell.scope).repository.list(name)));
/** The answer without its request id: the only part allowed to differ between a foreign id and a never-existing one. */
const plain = response => JSON.parse(JSON.stringify({status: response.status, body: response.body?.error ? {...response.body, error: {...response.body.error, requestId: undefined}} : response.body}));

// ---- the matrix rows: one per ROUTES entry ---------------------------------------------------------------------------
const get = route => ({method: 'GET', path: route}), del = route => ({method: 'DELETE', path: route});
const post = (route, body, headers) => ({method: 'POST', path: route, body, ...(headers ? {headers} : {})});
const put = (route, body) => ({method: 'PUT', path: route, body}), patch = (route, body) => ({method: 'PATCH', path: route, body});
const idem = () => ({'Idempotency-Key': randomUUID()});
/** A foreign id and a never-existing one of the same shape, called alike: scope 'environment' (B's) or 'user' (A/u2's as A/u1). */
const pair = (label, scope, cross, ghost, expect = 404) => ({label, scope, cross, ghost, expect});
const ghostRef = () => randomUUID(), ghostCs = () => newId('connectSession'), ghostPa = () => newId('providerApp'), GHOST_USER = 'u9';
/** For an account route: B's account under the same external id, B/u3's own account, and A/u2's account as A/u1. */
const accountPairs = (suffix, method, body) => ({A, B}) => [
  pair('B/u1 account as A/u1', 'environment', {method, path: `/v1/users/u1/accounts/${B.users.u1.ref}${suffix}`, body}, {method, path: `/v1/users/u1/accounts/${ghostRef()}${suffix}`, body}),
  pair('B/u3 and its account', 'environment', {method, path: `/v1/users/u3/accounts/${B.users.u3.ref}${suffix}`, body}, {method, path: `/v1/users/${GHOST_USER}/accounts/${ghostRef()}${suffix}`, body}),
  pair('A/u2 account as A/u1', 'user', {method, path: `/v1/users/u1/accounts/${A.users.u2.ref}${suffix}`, body}, {method, path: `/v1/users/u1/accounts/${ghostRef()}${suffix}`, body})];
const userListPairs = suffix => () => [pair('B/u3 by external id', 'environment', get(`/v1/users/u3${suffix}`), get(`/v1/users/${GHOST_USER}${suffix}`), 200)];
const noId = (reason, run, {write = false, check} = {}) => ({kind: 'no-id', reason, write, own: run, ok: [200, 201, 204], check});

const ROWS = {
  'GET /v1/project': noId('The caller\'s own project and environment, from the key.', () => get('/v1/project'), {check: (body, {A}) => assert.equal(body.project.id, A.project.id)}),
  'PATCH /v1/project': noId('Changes the caller\'s own project, from the key.', () => patch('/v1/project', {appName: 'Acme Assistant Two', supportEmail: 'help@acme.example'}), {write: true, check: (body, {A}) => assert.deepEqual([body.project.id, body.project.appName], [A.project.id, 'Acme Assistant Two'])}),
  'PUT /v1/project/logo': noId('Uploads the caller\'s own project logo, from the key.', () => ({method: 'PUT', path: '/v1/project/logo', raw: png(128), type: 'image/png'}), {write: true}),
  'PATCH /v1/environment': noId('Changes the caller\'s own environment, from the key.', () => patch('/v1/environment', {redirectOrigins: ['http://localhost:5173', 'http://localhost:5174'], openerOrigins: ['http://localhost:5173']}), {write: true}),
  'GET /v1/environment/apps': noId('The caller\'s own environment\'s app settings, from the key.', () => get('/v1/environment/apps')),
  [`PUT /v1/environment/apps/${APP}`]: {kind: 'id', cases: ({B}) => [pair('B\'s provider app chosen in A', 'environment', put('/v1/environment/apps/github', {providerApp: B.pa}), put('/v1/environment/apps/github', {providerApp: ghostPa()}))],
    own: ({A}) => put('/v1/environment/apps/github', {providerApp: A.pa}), ok: [200], check: (body, {A}) => assert.deepEqual(body.providerApp, {kind: 'developer', id: A.pa})},
  'GET /v1/provider-apps': noId('The caller\'s own environment\'s provider apps, from the key.', () => get('/v1/provider-apps'), {check: (body, {A}) => assert.ok(body.providerApps.some(item => item.id === A.pa))}),
  // The client id is the provider's value, not a Fabric record: B's own client id is used so the write sits right next to B's.
  'POST /v1/provider-apps': noId('Creates a record in the caller\'s environment; a pending client id never blocks another environment (L9).', () => post('/v1/provider-apps', {providerId: 'github', clientId: 'beta-gh-client', clientSecret: 'a-own-secret', consentScreenName: 'Alpha Second'}), {write: true}),
  [`PATCH /v1/provider-apps/${R}`]: {kind: 'id', cases: ({B}) => [pair('B\'s provider app', 'environment', patch(`/v1/provider-apps/${B.pa}`, {consentScreenName: 'Taken Over'}), patch(`/v1/provider-apps/${ghostPa()}`, {consentScreenName: 'Taken Over'}))],
    own: ({A}) => patch(`/v1/provider-apps/${A.pa}`, {consentScreenName: 'Alpha Screen Two'}), ok: [200], check: (body, {A}) => assert.equal(body.id, A.pa)},
  // B's provider app is chosen by B's GitHub setting, so B's own key would get in_use (409): A must still get not_found.
  [`DELETE /v1/provider-apps/${R}`]: {kind: 'id', cases: ({B}) => [pair('B\'s provider app (in use in B)', 'environment', del(`/v1/provider-apps/${B.pa}`), del(`/v1/provider-apps/${ghostPa()}`))],
    own: async ({A}) => del(`/v1/provider-apps/${await A.providerApp(`alpha-spare-${randomUUID().slice(0, 8)}`, 'Alpha Spare')}`), ok: [204]},
  'POST /v1/connect-sessions': {kind: 'id', cases: ({A, B}) => [
    pair('approve link for B/u1\'s waiting call', 'environment', post('/v1/connect-sessions', {purpose: 'approve', externalUserId: 'u1', callRef: B.users.u1.waiting.callRef}), post('/v1/connect-sessions', {purpose: 'approve', externalUserId: 'u1', callRef: ghostRef()})),
    pair('approve link for B\'s held call', 'environment', post('/v1/connect-sessions', {purpose: 'approve', externalUserId: 'u1', callRef: B.hold.callRef}), post('/v1/connect-sessions', {purpose: 'approve', externalUserId: 'u1', callRef: ghostRef()})),
    pair('manage link for B/u3', 'environment', post('/v1/connect-sessions', {purpose: 'manage', externalUserId: 'u3'}), post('/v1/connect-sessions', {purpose: 'manage', externalUserId: GHOST_USER})),
    pair('approve link for A/u2\'s waiting call as A/u1', 'user', post('/v1/connect-sessions', {purpose: 'approve', externalUserId: 'u1', callRef: A.users.u2.waiting.callRef}), post('/v1/connect-sessions', {purpose: 'approve', externalUserId: 'u1', callRef: ghostRef()}))],
    own: ({A}) => post('/v1/connect-sessions', {purpose: 'approve', externalUserId: 'u1', callRef: A.users.u1.waiting.callRef}), ok: [201]},
  [`GET /v1/connect-sessions/${CS}`]: {kind: 'id', cases: ({B}) => [pair('B/u1\'s link', 'environment', get(`/v1/connect-sessions/${B.users.u1.session}`), get(`/v1/connect-sessions/${ghostCs()}`)),
    pair('B\'s handoff link', 'environment', get(`/v1/connect-sessions/${B.hold.session}`), get(`/v1/connect-sessions/${ghostCs()}`))],
    own: ({A}) => get(`/v1/connect-sessions/${A.users.u1.session}`), ok: [200], check: (body, {A}) => assert.deepEqual([body.id, body.externalUserId], [A.users.u1.session, 'u1'])},
  [`POST /v1/connect-sessions/${CS}/cancel`]: {kind: 'id', cases: ({B}) => [pair('B/u1\'s link', 'environment', post(`/v1/connect-sessions/${B.users.u1.session}/cancel`), post(`/v1/connect-sessions/${ghostCs()}/cancel`)),
    pair('B\'s handoff link', 'environment', post(`/v1/connect-sessions/${B.hold.session}/cancel`), post(`/v1/connect-sessions/${ghostCs()}/cancel`))],
    own: async ({A}) => post(`/v1/connect-sessions/${(await A.call(post('/v1/connect-sessions', {externalUserId: 'u1'}))).body.id}/cancel`), ok: [200], check: body => assert.equal(body.state, 'cancelled')},
  [`POST /v1/connect-sessions/${CS}/link`]: {kind: 'id', cases: ({B}) => [pair('B/u3\'s link', 'environment', post(`/v1/connect-sessions/${B.users.u3.session}/link`), post(`/v1/connect-sessions/${ghostCs()}/link`)),
    pair('B\'s handoff link', 'environment', post(`/v1/connect-sessions/${B.hold.session}/link`), post(`/v1/connect-sessions/${ghostCs()}/link`))],
    own: ({A}) => post(`/v1/connect-sessions/${A.users.u2.session}/link`), ok: [200], check: (body, {A}) => assert.ok(body.connectUrl.includes(A.users.u2.session))},
  'GET /v1/users': {kind: 'id', cases: () => [pair('a search for B/u3', 'environment', get('/v1/users?q=u3'), get(`/v1/users?q=${GHOST_USER}`), 200)],
    own: () => get('/v1/users?q=u'), ok: [200], check: body => assert.deepEqual(body.users.map(user => user.externalUserId).sort(), ['u1', 'u2'])},
  [`GET /v1/users/${U}`]: {kind: 'id', cases: () => [pair('B/u3', 'environment', get('/v1/users/u3'), get(`/v1/users/${GHOST_USER}`))],
    own: () => get('/v1/users/u1'), ok: [200], check: (body, {A}) => assert.deepEqual(body.user.accounts.map(row => row.accountRef), [A.users.u1.ref])},
  // Run last: deleting A/u1 must leave B/u1, who has the same external id, exactly as it was.
  [`DELETE /v1/users/${U}`]: {kind: 'id', last: true, cases: () => [pair('B/u3', 'environment', del('/v1/users/u3'), del(`/v1/users/${GHOST_USER}`))],
    own: () => del('/v1/users/u1'), ok: [200], check: (body, {A}) => assert.deepEqual(body.accounts.map(row => [row.accountRef, row.remoteRevoked]), [[A.users.u1.ref, false]])},
  [`GET /v1/users/${U}/accounts`]: {kind: 'id', cases: userListPairs('/accounts'), own: () => get('/v1/users/u1/accounts'), ok: [200], check: (body, {A}) => assert.deepEqual(body.accounts.map(row => row.accountRef), [A.users.u1.ref])},
  [`GET /v1/users/${U}/accounts/${R}`]: {kind: 'id', cases: accountPairs('', 'GET'), own: ({A}) => get(`/v1/users/u1/accounts/${A.users.u1.ref}`), ok: [200], check: (body, {A}) => assert.equal(body.accountRef, A.users.u1.ref)},
  [`POST /v1/users/${U}/accounts/${R}/disconnect`]: {kind: 'id', cases: accountPairs('/disconnect', 'POST', {}), own: async ({A}) => post(`/v1/users/s1/accounts/${await A.spare()}/disconnect`, {}), ok: [200], check: body => assert.equal(body.remoteRevoked, false)},
  [`POST /v1/users/${U}/accounts/${R}/check`]: {kind: 'id', cases: accountPairs('/check', 'POST'), own: async ({A}) => post(`/v1/users/s1/accounts/${await A.spare()}/check`), ok: [200]},
  [`PUT /v1/users/${U}/apps/${APP}/default-account`]: {kind: 'id', cases: ({A, B}) => [
    pair('B/u1 account as A/u1', 'environment', put('/v1/users/u1/apps/gmail/default-account', {accountRef: B.users.u1.ref}), put('/v1/users/u1/apps/gmail/default-account', {accountRef: ghostRef()})),
    pair('B/u3 and its account', 'environment', put('/v1/users/u3/apps/gmail/default-account', {accountRef: B.users.u3.ref}), put(`/v1/users/${GHOST_USER}/apps/gmail/default-account`, {accountRef: ghostRef()})),
    pair('A/u2 account as A/u1', 'user', put('/v1/users/u1/apps/gmail/default-account', {accountRef: A.users.u2.ref}), put('/v1/users/u1/apps/gmail/default-account', {accountRef: ghostRef()}))],
    own: ({A}) => put('/v1/users/u1/apps/gmail/default-account', {accountRef: A.users.u1.ref}), ok: [200], check: (body, {A}) => assert.deepEqual(body, {appId: 'gmail', accountRef: A.users.u1.ref})},
  [`GET /v1/users/${U}/catalog`]: {kind: 'id', cases: userListPairs('/catalog?status=connected'), own: () => get('/v1/users/u1/catalog?status=connected'), ok: [200],
    check: body => assert.deepEqual([...new Set(JSON.stringify(body).match(/"connectionState":\{[^}]*\}/g))], ['"connectionState":{"state":"connected","accounts":1,"browserSessions":0,"needsAttention":0}'], 'only A/u1\'s one Gmail account counts')},
  [`GET /v1/users/${U}/capabilities`]: {kind: 'id', cases: userListPairs('/capabilities'), own: () => get('/v1/users/u1/capabilities?appId=gmail'), ok: [200],
    check: (body, {A}) => { assert.ok(body.capabilities.length > 0); assert.deepEqual([...new Set(body.capabilities.map(item => item.accountRef))], [A.users.u1.ref]); }},
  [`GET /v1/users/${U}/apps/${APP}`]: {kind: 'id', cases: ({A, B}) => [
    pair('B/u1 account as A/u1', 'environment', get(`/v1/users/u1/apps/gmail?account=${B.users.u1.ref}`), get(`/v1/users/u1/apps/gmail?account=${ghostRef()}`)),
    pair('B/u3', 'environment', get('/v1/users/u3/apps/gmail'), get(`/v1/users/${GHOST_USER}/apps/gmail`)),
    pair('A/u2 account as A/u1', 'user', get(`/v1/users/u1/apps/gmail?account=${A.users.u2.ref}`), get(`/v1/users/u1/apps/gmail?account=${ghostRef()}`))],
    own: ({A}) => get(`/v1/users/u1/apps/gmail?account=${A.users.u1.ref}`), ok: [200], check: (body, {A}) => assert.equal(body.selectedAccountRef, A.users.u1.ref)},
  [`POST /v1/users/${U}/accounts/${R}/permissions`]: {kind: 'id', cases: accountPairs('/permissions', 'POST', {groupId: 'gmail.drafts.read', mode: 'deny', etag: 'e'.repeat(32)}),
    own: async ({A}) => post(`/v1/users/u1/accounts/${A.users.u1.ref}/permissions`, {groupId: 'gmail.drafts.read', mode: 'ask', etag: await A.rowEtag('u1', A.users.u1.ref, 'gmail.drafts.read')}), ok: [200]},
  [`POST /v1/users/${U}/accounts/${R}/permissions/reset`]: {kind: 'id', cases: accountPairs('/permissions/reset', 'POST', {}),
    own: ({A}) => post(`/v1/users/u1/accounts/${A.users.u1.ref}/permissions/reset`, {groupIds: ['gmail.drafts.read']}), ok: [200]},
  [`POST /v1/users/${U}/accounts/${R}/background`]: {kind: 'id', cases: accountPairs('/background', 'POST', {mode: 'deny', etag: 'e'.repeat(32)}),
    own: async ({A}) => post(`/v1/users/u1/accounts/${A.users.u1.ref}/background`, {mode: 'deny', etag: (await A.view('u1', A.users.u1.ref)).background.etag}), ok: [200]},
  'POST /v1/executions': {kind: 'id', cases: ({A, B, caps}) => {
    const body = (externalUserId, accountRef) => ({externalUserId, ...(accountRef ? {accountRef} : {}), capabilityId: caps.read.id, definitionHash: caps.read.definitionHash, args: {userId: 'me', id: 'm-1'}});
    return [pair('B/u1 account as A/u1', 'environment', post('/v1/executions', body('u1', B.users.u1.ref), idem()), post('/v1/executions', body('u1', ghostRef()), idem())),
      pair('B/u3, its default account', 'environment', post('/v1/executions', body('u3'), idem()), post('/v1/executions', body(GHOST_USER), idem())),
      pair('A/u2 account as A/u1', 'user', post('/v1/executions', body('u1', A.users.u2.ref), idem()), post('/v1/executions', body('u1', ghostRef()), idem()))];
  }, own: ({A, caps}) => post('/v1/executions', {externalUserId: 'u1', accountRef: A.users.u1.ref, capabilityId: caps.read.id, definitionHash: caps.read.definitionHash, args: {userId: 'me', id: 'm-1'}, waitMs: 5000}, idem()), ok: [200], check: (body, {A}) => assert.deepEqual([body.status, body.accountRef], ['succeeded', A.users.u1.ref]),
  // B's Idempotency-Key with B's exact request, from A's key: a new call on A/u1's own account, never a replay of B's.
  extra: async ({A, B}) => {
    const theirs = await A.call(post('/v1/executions', B.users.u1.finishedBody, {'Idempotency-Key': B.users.u1.idem})), fresh = await A.call(post('/v1/executions', B.users.u1.finishedBody, idem()));
    const shape = response => ({...plain(response), body: {...response.body, callRef: 'x', createdAt: 'x', updatedAt: 'x'}});
    assert.deepEqual(shape(theirs), shape(fresh)); assert.equal(theirs.status, 200);
    assert.notEqual(theirs.body.callRef, B.users.u1.callRef); assert.equal(theirs.body.accountRef, A.users.u1.ref);
  }},
  [`GET /v1/executions/${R}`]: {kind: 'id', cases: ({B}) => [pair('B/u1\'s finished call', 'environment', get(`/v1/executions/${B.users.u1.callRef}`), get(`/v1/executions/${ghostRef()}`)),
    pair('B/u3\'s waiting call', 'environment', get(`/v1/executions/${B.users.u3.waiting.callRef}?waitMs=10`), get(`/v1/executions/${ghostRef()}?waitMs=10`)),
    pair('B\'s held call', 'environment', get(`/v1/executions/${B.hold.callRef}`), get(`/v1/executions/${ghostRef()}`))],
    own: ({A}) => get(`/v1/executions/${A.users.u1.callRef}`), ok: [200], check: (body, {A}) => assert.equal(body.callRef, A.users.u1.callRef)},
  [`POST /v1/executions/${R}/cancel`]: {kind: 'id', cases: ({B}) => [pair('B/u1\'s waiting call', 'environment', post(`/v1/executions/${B.users.u1.waiting.callRef}/cancel`), post(`/v1/executions/${ghostRef()}/cancel`)),
    pair('B\'s held call', 'environment', post(`/v1/executions/${B.hold.callRef}/cancel`), post(`/v1/executions/${ghostRef()}/cancel`))],
    own: async ({A}) => post(`/v1/executions/${(await A.ask('u1', A.users.u1.ref)).callRef}/cancel`), ok: [200], check: body => assert.equal(body.status, 'cancelled')},
  'POST /v1/options': {kind: 'id', cases: ({A, B, caps}) => {
    const body = (externalUserId, accountRef) => ({externalUserId, ...(accountRef ? {accountRef} : {}), capabilityId: caps.list.id, input: 'labelIds'});
    return [pair('B/u1 account as A/u1', 'environment', post('/v1/options', body('u1', B.users.u1.ref)), post('/v1/options', body('u1', ghostRef()))),
      pair('B/u3, its default account', 'environment', post('/v1/options', body('u3')), post('/v1/options', body(GHOST_USER))),
      pair('A/u2 account as A/u1', 'user', post('/v1/options', body('u1', A.users.u2.ref)), post('/v1/options', body('u1', ghostRef())))];
  }, own: ({A, caps}) => post('/v1/options', {externalUserId: 'u1', accountRef: A.users.u1.ref, capabilityId: caps.list.id, input: 'labelIds'}), ok: [200], check: body => assert.ok(body.options.length > 0)},
  [`GET /v1/users/${U}/approvals`]: {kind: 'id', cases: userListPairs('/approvals'), own: () => get('/v1/users/u1/approvals'), ok: [200],
    check: (body, {A}) => { assert.ok(body.approvals.some(item => item.callRef === A.users.u1.waiting.callRef)); assert.deepEqual([...new Set(body.approvals.map(item => item.accountRef))], [A.users.u1.ref], 'none of A/u2\'s'); }},
  [`POST /v1/users/${U}/approvals/${R}/decision`]: {kind: 'id', cases: ({A, B}) => [
    pair('B/u1\'s waiting call as A/u1', 'environment', post(`/v1/users/u1/approvals/${B.users.u1.waiting.callRef}/decision`, {decision: 'approve', digest: B.users.u1.waiting.digest}), post(`/v1/users/u1/approvals/${ghostRef()}/decision`, {decision: 'approve', digest: B.users.u1.waiting.digest})),
    pair('B/u3 and its waiting call', 'environment', post(`/v1/users/u3/approvals/${B.users.u3.waiting.callRef}/decision`, {decision: 'reject', digest: B.users.u3.waiting.digest}), post(`/v1/users/${GHOST_USER}/approvals/${ghostRef()}/decision`, {decision: 'reject', digest: B.users.u3.waiting.digest})),
    pair('A/u2\'s waiting call as A/u1', 'user', post(`/v1/users/u1/approvals/${A.users.u2.waiting.callRef}/decision`, {decision: 'approve', digest: A.users.u2.waiting.digest}), post(`/v1/users/u1/approvals/${ghostRef()}/decision`, {decision: 'approve', digest: A.users.u2.waiting.digest}))],
    own: async ({A}) => { const waiting = await A.ask('u1', A.users.u1.ref); return post(`/v1/users/u1/approvals/${waiting.callRef}/decision`, {decision: 'reject', digest: waiting.digest}); }, ok: [200], check: body => assert.equal(body.status, 'cancelled')},
  [`POST /v1/users/${U}/agent-tokens`]: {kind: 'id', cases: ({A, B, caps}) => {
    const body = accountRef => ({name: 'Inbox helper', bindings: [{accountRef, capabilityId: caps.read.id}]});
    return [pair('B/u1 account as A/u1', 'environment', post('/v1/users/u1/agent-tokens', body(B.users.u1.ref)), post('/v1/users/u1/agent-tokens', body(ghostRef()))),
      pair('B/u3 and its account', 'environment', post('/v1/users/u3/agent-tokens', body(B.users.u3.ref)), post(`/v1/users/${GHOST_USER}/agent-tokens`, body(ghostRef()))),
      pair('A/u2 account as A/u1', 'user', post('/v1/users/u1/agent-tokens', body(A.users.u2.ref)), post('/v1/users/u1/agent-tokens', body(ghostRef())))];
  }, own: ({A, caps}) => post('/v1/users/u1/agent-tokens', {name: 'Own helper', bindings: [{accountRef: A.users.u1.ref, capabilityId: caps.read.id}]}), ok: [201]},
  [`GET /v1/users/${U}/agent-tokens`]: {kind: 'id', cases: userListPairs('/agent-tokens'), own: () => get('/v1/users/u1/agent-tokens'), ok: [200],
    check: (body, {A}) => { assert.ok(body.agentTokens.some(item => item.id === A.users.u1.token)); assert.equal(body.agentTokens.some(item => item.id === A.users.u2.token), false, 'none of A/u2\'s'); }},
  [`POST /v1/users/${U}/agent-tokens/${R}/revoke`]: {kind: 'id', cases: ({A, B}) => [
    pair('B/u1\'s token as A/u1', 'environment', post(`/v1/users/u1/agent-tokens/${B.users.u1.token}/revoke`), post(`/v1/users/u1/agent-tokens/${ghostRef()}/revoke`)),
    pair('B/u3 and its token', 'environment', post(`/v1/users/u3/agent-tokens/${B.users.u3.token}/revoke`), post(`/v1/users/${GHOST_USER}/agent-tokens/${ghostRef()}/revoke`)),
    pair('A/u2\'s token as A/u1', 'user', post(`/v1/users/u1/agent-tokens/${A.users.u2.token}/revoke`), post(`/v1/users/u1/agent-tokens/${ghostRef()}/revoke`))],
    own: async ({A}) => post(`/v1/users/u1/agent-tokens/${await A.token('u1', A.users.u1.ref)}/revoke`), ok: [200], check: body => assert.equal(body.agentToken.status, 'revoked')},
  [`GET /v1/users/${U}/activity`]: {kind: 'id', cases: ({A, B}) => [pair('B/u3', 'environment', get('/v1/users/u3/activity'), get(`/v1/users/${GHOST_USER}/activity`), 200),
    pair('B/u1\'s account as a filter of A/u1', 'environment', get(`/v1/users/u1/activity?accountRef=${B.users.u1.ref}`), get(`/v1/users/u1/activity?accountRef=${ghostRef()}`), 200),
    pair('A/u2\'s account as a filter of A/u1', 'user', get(`/v1/users/u1/activity?accountRef=${A.users.u2.ref}`), get(`/v1/users/u1/activity?accountRef=${ghostRef()}`), 200)],
    own: () => get('/v1/users/u1/activity'), ok: [200], check: (body, {A}) => {
      const items = body.days.flatMap(day => day.items);
      assert.ok(items.some(item => item.callRef === A.users.u1.callRef));
      assert.deepEqual([...new Set([...items, ...body.approvals].map(item => item.accountRef))], [A.users.u1.ref], 'none of A/u2\'s');
    }},
  'POST /v1/proxy/requests': {kind: 'id', cases: ({A, B}) => {
    const body = (externalUserId, accountRef) => ({externalUserId, ...(accountRef ? {accountRef} : {appId: 'gmail'}), request: {method: 'GET', path: '/gmail/v1/users/me/messages'}});
    return [pair('B/u1 account as A/u1', 'environment', post('/v1/proxy/requests', body('u1', B.users.u1.ref), idem()), post('/v1/proxy/requests', body('u1', ghostRef()), idem())),
      pair('B/u3, its default account', 'environment', post('/v1/proxy/requests', body('u3'), idem()), post('/v1/proxy/requests', body(GHOST_USER), idem())),
      pair('A/u2 account as A/u1', 'user', post('/v1/proxy/requests', body('u1', A.users.u2.ref), idem()), post('/v1/proxy/requests', body('u1', ghostRef()), idem()))];
  }, own: ({A}) => post('/v1/proxy/requests', {externalUserId: 'u1', accountRef: A.users.u1.ref, request: {method: 'GET', path: '/gmail/v1/users/me/messages'}, waitMs: 5000}, idem()), ok: [200, 202], check: (body, {A}) => assert.equal(body.accountRef, A.users.u1.ref)},
  'GET /v1/accounts': {kind: 'id', cases: () => [pair('B/u3 as a filter', 'environment', get('/v1/accounts?externalUserId=u3'), get(`/v1/accounts?externalUserId=${GHOST_USER}`), 200)],
    own: () => get('/v1/accounts?externalUserId=u1'), ok: [200], check: (body, {A}) => assert.deepEqual(body.accounts.map(row => [row.externalUserId, row.accountRef]), [['u1', A.users.u1.ref]])},
  [`GET /v1/accounts/${R}`]: {kind: 'id', cases: ({B}) => [pair('B/u1\'s account', 'environment', get(`/v1/accounts/${B.users.u1.ref}`), get(`/v1/accounts/${ghostRef()}`)), pair('B/u3\'s account', 'environment', get(`/v1/accounts/${B.users.u3.ref}`), get(`/v1/accounts/${ghostRef()}`))],
    own: ({A}) => get(`/v1/accounts/${A.users.u2.ref}`), ok: [200], check: (body, {A}) => assert.deepEqual([body.accountRef, body.externalUserId], [A.users.u2.ref, 'u2'])},
  [`POST /v1/accounts/${R}/disconnect`]: {kind: 'id', cases: ({B}) => [pair('B/u1\'s account', 'environment', post(`/v1/accounts/${B.users.u1.ref}/disconnect`, {}), post(`/v1/accounts/${ghostRef()}/disconnect`, {})),
    pair('B/u3\'s account', 'environment', post(`/v1/accounts/${B.users.u3.ref}/disconnect`, {}), post(`/v1/accounts/${ghostRef()}/disconnect`, {}))],
    own: async ({A}) => post(`/v1/accounts/${await A.spare()}/disconnect`, {}), ok: [200], check: body => assert.equal(body.remoteRevoked, false)},
  'GET /v1/apps': noId('Fabric\'s shared catalog; nothing in it belongs to an environment.', () => get('/v1/apps')),
  [`GET /v1/apps/${APP}`]: noId('An app id of Fabric\'s shared catalog, the same for every environment.', () => get('/v1/apps/gmail')),
  [`GET /v1/apps/${APP}/consent-sheet`]: noId('An app id of Fabric\'s shared catalog; the sheet is built from the caller\'s own project and environment.', () => get('/v1/apps/github/consent-sheet')),
  'GET /v1/categories': noId('Fabric\'s shared catalog categories.', () => get('/v1/categories')),
  'GET /v1/capabilities': noId('Reviewed operations of the platform catalog, read-only to every environment (N6).', () => get('/v1/capabilities?appId=gmail')),
  [`GET /v1/capabilities/${CAP}`]: noId('One reviewed operation of the platform catalog, read-only to every environment (N6).', ({caps}) => get(`/v1/capabilities/${encodeURIComponent(caps.read.id)}`)),
};

test('every /v1 route has a matrix row, and no row names a route that is gone', () => {
  assert.deepEqual(ROUTES.filter(route => !Object.hasOwn(ROWS, route)), [], 'a /v1 route without a row in the isolation matrix');
  assert.deepEqual(Object.keys(ROWS).filter(route => !ROUTES.includes(route)), [], 'a matrix row for a route the router no longer has');
  for (const [route, row] of Object.entries(ROWS)) {
    assert.ok(['id', 'no-id'].includes(row.kind), route);
    assert.equal(typeof row.own, 'function', `${route}: an own-cell control`);
    if (row.kind === 'id') assert.equal(typeof row.cases, 'function', route);
    else assert.ok(typeof row.reason === 'string' && row.reason.length > 10, `${route}: a no-id row says why`);
  }
});

test('every /v1 route answers B\'s ids exactly like ids that never existed, changes nothing of B, and works on A\'s own ids', async t => {
  const {app, sim, A, B, caps} = await world(t), ctx = {A, B, caps};
  const vaultIds = [...Object.values(B.users).map(user => user.ref), `providerApp:${B.pa}`];
  const digest = () => digestOf(app, B, B.project.organizationId, vaultIds), platform = () => platformOf(app, A);
  const before = digest(), platformBefore = platform();
  // The digest is not empty: B really holds every kind of record the matrix aims at.
  for (const name of ['connections', 'permissions', 'backgroundPolicies', 'jobs', 'endUsers', 'connectSessions', 'continuations', 'clientGrants', 'providerApps', 'usageEvents', 'activity', 'idempotencyKeys'])
    assert.ok(before.collections[name].length > 0, `B holds ${name}`);
  assert.ok(before.registry.sessionRoutes.length >= 3 && before.registry.agentTokenRoutes.length === 2 && before.registry.serviceKeys.length === 1, 'B\'s registry routes are there');
  const markers = [B.dev.id, B.project.id, B.pa, B.hold.callRef, B.hold.session, 'Beta Screen Marker', 'Beta Marker App',
    ...Object.values(B.users).flatMap(user => [user.ref, user.callRef, user.waiting.callRef, user.waiting.digest, user.token, user.session, user.userRecordId, `${user.identity}@example.com`])];
  const clean = (response, what) => { const text = JSON.stringify(response.body); for (const marker of markers) assert.equal(text.includes(marker), false, `${what} shows ${marker}`); };
  const bMaps = () => { const text = JSON.stringify([app.executions[TEST_MAPS](), app.runtimes[TEST_MAPS]()]); return [B.dev.id, B.keyId, B.serviceClientId, B.scopeKey].filter(id => text.includes(id)); };
  const order = Object.entries(ROWS).sort(([, a], [, b]) => Number(Boolean(a.last)) - Number(Boolean(b.last)));
  for (const [route, row] of order) {
    await t.test(route, async () => {
      const rowBefore = JSON.stringify(digest());
      if (row.kind === 'id') {
        const cases = row.cases(ctx);
        assert.ok(cases.some(item => item.scope === 'environment'), 'at least one of B\'s ids');
        for (const item of cases) {
          const cross = await A.call(item.cross), ghost = await A.call(item.ghost);
          assert.equal(cross.status, item.expect, `${item.label}: ${cross.text.slice(0, 300)}`);
          assert.deepEqual(plain(cross), plain(ghost), `${item.label}: the same answer as an id that never existed`);
          clean(cross, item.label);
        }
      }
      const response = await A.call(await row.own(ctx));
      assert.ok(row.ok.includes(response.status), `own-cell control: ${response.status} ${response.text.slice(0, 300)}`);
      clean(response, 'own-cell control');
      row.check?.(response.body, ctx);
      await row.extra?.(ctx);
      await app.runtimes.drain();
      assert.equal(JSON.stringify(digest()), rowBefore, row.write ? 'A\'s write changed nothing of B' : 'nothing of B changed');
      assert.deepEqual(bMaps(), [], 'no in-memory map holds anything of B');
    });
  }
  await app.runtimes.drain();
  assert.deepEqual(digest(), before, 'B\'s store, vault and registry routes are as they were before the run');
  assert.equal(platform(), platformBefore, 'the platform store is as it was');
  assert.equal(sim.calls.filter(line => line.includes('oauth2.googleapis.com/revoke')).length, 0, 'no revoke ever reached Google for the shared app');
  assert.deepEqual(sim.calls.filter(line => !/^\w+ https:\/\/(gmail|openidconnect|oauth2)\.googleapis\.com\//.test(line)), [], 'nothing left for any other host');
});

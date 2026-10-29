import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, readdirSync, readFileSync, statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {aliasOf} from '../lib/tenant/agent-tokens.mjs';

// F03.9b (docs/F03.9-BUILD-MAP.md slice A): agent tokens minted per end user, bound to that user's own accounts.
const TYPED = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send']];
const files = dir => readdirSync(dir).flatMap(name => { const full = path.join(dir, name); return statSync(full).isDirectory() ? files(full) : [full]; });
function seed(root) {
  const paths = {};
  for (const [id, method, route] of TYPED) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities;
  const store = new PlatformStore({root});
  const operations = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => ({id, method: id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`, sensitive: null}));
  for (const [id, method, route] of TYPED) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `https://gmail.googleapis.com${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations[operations.findIndex(op => op.id === id)] = {id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null};
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-agent-tokens-'));
  seed(root);
  const app = await createDeveloperApp({dataRoot: root, port: 0, request: async () => ({status: 200, headers: {}, data: {}})});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'});
  const environment = () => {
    const project = app.registry.createProject({organizationId: org.id, name: 'Agent'}), dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
    return {dev, scope: app.registry.scopeOf(dev), minted: app.keys.mint({environmentId: dev.id, preset: 'standard'})};
  };
  const a = environment();
  const call = async (method, route, body, token = a.minted.token) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  const repo = (scope = a.scope) => app.stores.open(scope).repository;
  const account = async (externalUserId, identity) => {
    await call('POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), id = randomUUID(), now = app.registry.now();
    repo().put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: identity, displayName: `${identity}@example.com`}, allowedOrigins: ['https://gmail.googleapis.com'],
      scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: now, updatedAt: now, authRevision: randomUUID()}, {subjectId: externalUserId, userRecordId: user.id}));
    return id;
  };
  const u1 = await account('u1', 'g-1'), u2 = await account('u2', 'g-2');
  const caps = (await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  const read = caps.find(item => item.id.includes('messages-get')), send = caps.find(item => item.id.includes('messages-send'));
  const mint = (body, user = 'u1', token) => call('POST', `/v1/users/${user}/agent-tokens`, {name: 'Inbox helper', ...body}, token);
  return {root, app, a, environment, call, repo, u1, u2, read, send, mint};
}

test('a token is shown once, stored only as a hash, bound to the user\'s own accounts, and records who minted it', async t => {
  const {root, app, a, repo, u1, read, send, mint} = await setup(t);
  const made = await mint({bindings: [{accountRef: u1, capabilityId: read.id}, {accountRef: u1, capabilityId: send.id}], proxy: [{accountRef: u1, rows: ['group:gmail.labels.read']}]});
  assert.equal(made.status, 201);
  assert.deepEqual(Object.keys(made.body).sort(), ['agentToken', 'token']);
  assert.deepEqual(Object.keys(made.body.agentToken).sort(), ['expiresAt', 'id', 'name']);
  assert.match(made.body.token, /^fab_client\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);
  const grant = repo().get('clientGrants', made.body.agentToken.id), secret = made.body.token.split('.')[2];
  assert.deepEqual([grant.mintedByKeyId, grant.delegationId, grant.delegatedBy, grant.ownership.owner.id, typeof grant.userRecordId], [a.minted.keyId, grant.id, {kind: 'product_user', id: 'u1'}, 'u1', 'string']);
  assert.ok(grant.aliasKey); assert.equal(grant.bindings.length, 2); assert.equal(grant.proxy[0].rows[0].row, 'group:gmail.labels.read');
  assert.equal(app.registry.get('agentTokenRoutes', grant.id).mintedByKeyId, a.minted.keyId);
  for (const file of files(root)) assert.equal(readFileSync(file).includes(secret), false, file);
  assert.equal(JSON.stringify([app.registry.activity(), repo().list('activity')]).includes(secret), false);
  assert.ok(repo().list('activity').some(row => row.type === 'agent.token_granted' && row.agentId === grant.id && row.byKey === a.minted.keyId), 'the grant is attributed to its key');
  // Aliases: per grant, never the accountRef.
  const other = (await mint({bindings: [{accountRef: u1, capabilityId: read.id}]})).body.agentToken.id;
  const first = aliasOf(grant, u1), second = aliasOf(repo().get('clientGrants', other), u1);
  assert.notEqual(first, second); assert.notEqual(first, u1); assert.match(first, /^acct_[a-z2-7]{26}$/);
  // A token is no key for the developer API.
  const asToken = await fetch(`${app.origin}/v1/users`, {headers: {Authorization: `Bearer ${made.body.token}`}});
  assert.equal(asToken.status, 401);
});

test('another user\'s or an unknown account is not_found; Never rows, whole apps, unknown requestable operations and bad lifetimes are refused', async t => {
  const {app, call, repo, u1, u2, read, send, mint} = await setup(t);
  const plain = answer => ({status: answer.status, code: answer.body.error?.code, message: answer.body.error?.message});
  const theirs = await mint({bindings: [{accountRef: u2, capabilityId: read.id}]}), unknown = await mint({bindings: [{accountRef: randomUUID(), capabilityId: read.id}]}), junk = await mint({bindings: [{accountRef: 'nope', capabilityId: read.id}]});
  assert.equal(theirs.status, 404); assert.deepEqual(plain(theirs), plain(unknown)); assert.deepEqual(plain(theirs), plain(junk));
  assert.equal((await mint({bindings: [{connectionId: u1, capabilityId: read.id}]})).status, 400, 'store ids are not accepted');
  app.runtimes.bundle(app.registry.scopeOf(app.registry.get('environments', repo().scope.environmentId))).permissions.set({connectionId: u1, capabilityId: read.id, mode: 'deny'});
  assert.equal((await mint({bindings: [{accountRef: u1, capabilityId: read.id}]})).body.error.code, 'permission_denied', 'a Never row cannot be given');
  assert.equal((await mint({bindings: [{accountRef: u1, capabilityId: send.id}]})).status, 201, 'an Ask row can: the agent still has to ask');
  assert.equal((await mint({proxy: [{accountRef: u1, rows: ['group:gmail.permanent.delete']}]})).body.error.code, 'permission_denied', 'a Never proxy row cannot be given');
  const before = repo().list('clientGrants').length;
  assert.equal((await mint({bindings: [{accountRef: u1, capabilityId: send.id}], apps: [{appId: 'gmail'}]})).body.error.code, 'not_available');
  assert.equal((await mint({requestable: [{capabilityId: 'gmail.nope.0'}]})).status, 404, 'an unknown operation cannot be requested');
  for (const expiresInSeconds of [59, 2_592_001, 1.5]) assert.equal((await mint({bindings: [{accountRef: u1, capabilityId: send.id}], expiresInSeconds})).status, 400, String(expiresInSeconds));
  assert.equal(repo().list('clientGrants').length, before, 'nothing stored by a refusal');
  void call;
});

test('list and revoke see only the named user\'s tokens; deleting a user removes theirs; a key revoke can take its tokens along', async t => {
  const {app, a, environment, call, repo, u1, u2, send, mint} = await setup(t);
  const one = (await mint({bindings: [{accountRef: u1, capabilityId: send.id}]})).body.agentToken, two = (await mint({bindings: [{accountRef: u2, capabilityId: send.id}]}, 'u2')).body.agentToken;
  const listed = (await call('GET', '/v1/users/u1/agent-tokens')).body.agentTokens;
  assert.deepEqual(listed.map(item => item.id), [one.id]);
  assert.deepEqual(Object.keys(listed[0]).sort(), ['expiresAt', 'id', 'name', 'status']);
  assert.equal((await call('POST', `/v1/users/u1/agent-tokens/${two.id}/revoke`)).status, 404, 'another user\'s token through this user\'s path');
  const revoked = await call('POST', `/v1/users/u1/agent-tokens/${one.id}/revoke`);
  assert.equal(revoked.body.agentToken.status, 'revoked');
  assert.ok(app.registry.get('agentTokenRoutes', one.id).revokedAt);
  // Another environment's key sees nothing of these users.
  const b = environment();
  assert.deepEqual((await call('GET', '/v1/users/u1/agent-tokens', undefined, b.minted.token)).body, {agentTokens: []});
  assert.equal((await call('POST', `/v1/users/u2/agent-tokens/${two.id}/revoke`, undefined, b.minted.token)).status, 404);
  const connectOnly = app.keys.mint({environmentId: a.dev.id, preset: 'connect-only'}).token;
  assert.equal((await call('GET', '/v1/users/u1/agent-tokens', undefined, connectOnly)).body.error.code, 'forbidden_scope');
  // A key revoke takes along only the tokens it minted, and only when asked to.
  const minter = app.keys.mint({environmentId: a.dev.id, preset: 'standard'});
  const three = (await mint({bindings: [{accountRef: u2, capabilityId: send.id}]}, 'u2', minter.token)).body.agentToken;
  assert.deepEqual(app.keys.revoke(minter.keyId), {agentTokensRevoked: 0});
  assert.equal(app.registry.get('agentTokenRoutes', three.id).revokedAt, null);
  const second = app.keys.mint({environmentId: a.dev.id, preset: 'standard'}), four = (await mint({bindings: [{accountRef: u2, capabilityId: send.id}]}, 'u2', second.token)).body.agentToken;
  assert.deepEqual(app.keys.revoke(second.keyId, {withAgentTokens: true}), {agentTokensRevoked: 1});
  assert.ok(app.registry.get('agentTokenRoutes', four.id).revokedAt); assert.equal(app.registry.get('agentTokenRoutes', two.id).revokedAt, null);
  // Deleting u2 removes u2's grants and routes, and leaves everyone else's.
  const keep = (await mint({bindings: [{accountRef: u1, capabilityId: send.id}]})).body.agentToken;
  assert.equal((await call('DELETE', '/v1/users/u2')).status, 200);
  assert.equal(app.registry.get('agentTokenRoutes', two.id), null); assert.equal(repo().get('clientGrants', two.id), null);
  assert.ok(app.registry.get('agentTokenRoutes', keep.id)); assert.ok(repo().get('clientGrants', keep.id));
});

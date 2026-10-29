import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {Client} from '@modelcontextprotocol/client';
import {InMemoryTransport} from '@modelcontextprotocol/server';
import {createMcpAdapter} from '../lib/mcp-adapter.mts';

// F03.9c (docs/F03.9-BUILD-MAP.md slice B): agents on fabric/0.1 in a developer environment. One person per token,
// aliases only, no links anywhere, no decisions, and every call checked against the token again when it runs.
const TYPED = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send']];
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
  for (const [id, pathname] of [['gmail.users.labels.list', '/gmail/v1/users/{userId}/labels'], ['gmail.users.labels.create', '/gmail/v1/users/{userId}/labels']]) operations[operations.findIndex(op => op.id === id)].path = pathname;
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-agent-protocol-'));
  seed(root);
  const sim = {calls: []};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    const data = req.url.includes('/labels') ? {labels: [{id: 'INBOX'}]} : req.url.includes('/send') ? {id: 'sent-1'} : {id: 'm-1', snippet: 'hello'};
    return req.responseType === 'buffer' ? {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(data))} : {status: 200, headers: {}, data};
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'standard'}), relay = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body, token = key.token, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  const account = async (externalUserId, identity) => {
    await call('POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), id = randomUUID(), now = app.registry.now();
    repo().put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: identity, displayName: `${identity}@example.com`, email: `${identity}@example.com`}, allowedOrigins: ['https://gmail.googleapis.com'],
      scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.labels', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: now, updatedAt: now, authRevision: randomUUID()}, {subjectId: externalUserId, userRecordId: user.id}));
    app.stores.open(scope).vault.set(id, {accessToken: 'ya29.agent-secret-token', refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000});
    return id;
  };
  const u1 = await account('u1', 'one'), u2 = await account('u2', 'two');
  const caps = (await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  const read = caps.find(item => item.id.includes('messages-get')), send = caps.find(item => item.id.includes('messages-send'));
  const mint = async (user = 'u1', accountRef = u1, extra = {}) => (await call('POST', `/v1/users/${user}/agent-tokens`, {name: 'Inbox helper', bindings: [{accountRef, capabilityId: read.id}, {accountRef, capabilityId: send.id}], proxy: [{accountRef, rows: ['group:gmail.labels.read', 'group:gmail.labels.manage']}], ...extra})).body;
  let counter = 0;
  const agent = async (token, method, params, id = `r${++counter}`, headers = {}) => {
    const response = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...headers}, body: JSON.stringify({protocol: 'fabric/0.1', id, method, params})});
    return {status: response.status, body: await response.json()};
  };
  const sent = pattern => sim.calls.filter(line => line.includes(pattern)).length;
  return {app, sim, scope, key, relay, call, repo, u1, u2, read, send, mint, agent, sent};
}
const aliasOfList = list => list.body.result.capabilities[0].connectionId;

test('an agent sees aliases only; another token\'s alias, another person\'s, a raw accountRef or a store id are all not_found', async t => {
  const {agent, mint, u1, u2, read} = await setup(t);
  const a = await mint(), b = await mint(), other = await mint('u2', u2);
  const listA = await agent(a.token, 'capabilities.list', {});
  const aliasA = aliasOfList(listA), aliasB = aliasOfList(await agent(b.token, 'capabilities.list', {})), aliasU2 = aliasOfList(await agent(other.token, 'capabilities.list', {}));
  assert.match(aliasA, /^acct_[a-z2-7]{26}$/); assert.notEqual(aliasA, aliasB, 'two tokens on one account see different aliases');
  assert.equal(JSON.stringify(listA.body).includes(u1), false, 'the accountRef never appears');
  assert.deepEqual(listA.body.result.proxy.map(entry => entry.connectionId), [aliasA]);
  const attempts = [aliasB, aliasU2, u1, 'acct_' + 'a'.repeat(26)].map(connectionId => agent(a.token, 'calls.create', {connectionId, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}}));
  const answers = await Promise.all(attempts);
  for (const answer of answers) { assert.equal(answer.status, 404); assert.deepEqual(answer.body.error, answers[0].body.error); }
  // One token's call is invisible to another token, even of the same person.
  const mine = await agent(a.token, 'calls.create', {connectionId: aliasA, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}});
  const peek = await agent(b.token, 'calls.get', {callId: mine.body.result.id});
  assert.equal(peek.status, 404); assert.equal(peek.body.error.code, 'not_found');
});

test('a call is the person\'s job: the developer sees the accountRef, the agent the alias; nothing anyone sees carries a link', async t => {
  const {app, agent, mint, call, repo, u1, read, sent} = await setup(t);
  const token = await mint(), alias = aliasOfList(await agent(token.token, 'capabilities.list', {}));
  const seen = [await agent(token.token, 'fabric.discover', {}), await agent(token.token, 'capabilities.list', {})];
  const created = await agent(token.token, 'calls.create', {connectionId: alias, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}, task: {title: 'Read the latest'}});
  seen.push(created);
  const job = repo().get('jobs', created.body.result.id);
  assert.deepEqual([created.status, created.body.result.status, created.body.result.connectionId, created.body.result.result], [200, 'succeeded', alias, {data: {id: 'm-1', snippet: 'hello'}}]);
  assert.deepEqual([job.ownership.owner.id, job.connectionId, job.source.kind, job.source.clientId], ['u1', u1, 'client', token.agentToken.id]);
  assert.equal((await call('GET', `/v1/executions/${job.id}`)).body.accountRef, u1, 'the developer sees the real account');
  seen.push(await agent(token.token, 'calls.get', {callId: job.id}));
  seen.push(await agent(token.token, 'proxy.request', {connectionId: alias, request: {method: 'GET', path: '/gmail/v1/users/me/labels'}}));
  assert.equal(seen.at(-1).body.result.status, 'succeeded');
  const text = JSON.stringify(seen.map(answer => answer.body));
  // No Fabric link of any kind (the provider address the agent itself asked for is its own request, not a link).
  assert.equal(text.includes(app.origin) || /\/approve\/|\/continue\/|\/connect\/|#k=|one@example\.com|ya29/.test(text), false, text.slice(0, 200));
  assert.equal(text.includes(u1), false);
  // Attribution: the person, the token and the key that minted it; one usage record per call.
  const created_ = app.registry && repo().list('activity').find(row => row.type === 'job.created' && row.jobId === job.id);
  assert.deepEqual([created_.agentId, typeof created_.userRecordId, created_.keyId], [token.agentToken.id, 'string', job.source.keyId]);
  assert.equal(repo().list('usageEvents').filter(row => row.id === `exec.${job.id}`).length, 1);
  assert.equal(sent('/messages/m-1'), 1);
});

test('the agent never decides: an Ask waits with no link; approve methods do not exist; a relay decides and it runs once', async t => {
  const {agent, mint, call, relay, send, sent} = await setup(t);
  const token = await mint(), alias = aliasOfList(await agent(token.token, 'capabilities.list', {}));
  const asked = await agent(token.token, 'calls.create', {connectionId: alias, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}});
  assert.equal(asked.body.result.status, 'awaiting_approval');
  assert.deepEqual(asked.body.result.approval, {callRef: asked.body.result.id, expiresAt: asked.body.result.approval.expiresAt});
  assert.deepEqual(asked.body.result.card?.actions ?? [], [], 'the card has nothing to press');
  for (const method of ['calls.approve', 'jobs.approve', 'approvals.approve', 'permissions.set']) assert.equal((await agent(token.token, method, {callId: asked.body.result.id})).body.error.code, 'method_not_found', method);
  assert.equal((await call('POST', `/v1/users/u1/approvals/${asked.body.result.id}/decision`, {decision: 'approve', digest: 'f'.repeat(64)}, token.token)).status, 401, 'a token is no developer key');
  const [item] = (await call('GET', '/v1/users/u1/approvals', undefined, relay)).body.approvals;
  await call('POST', `/v1/users/u1/approvals/${item.callRef}/decision`, {decision: 'approve', digest: item.digest}, relay);
  const after = await agent(token.token, 'calls.get', {callId: asked.body.result.id});
  assert.ok(['uncertain', 'succeeded', 'running', 'queued'].includes(after.body.result.status));
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(sent('/messages/send'), 1);
});

test('authority at dispatch: a revoked token, an expired one, a deleted person or a Never row stop the call before anything is sent', async t => {
  const {app, scope, agent, mint, call, relay, send, read, repo, u1, sent} = await setup(t);
  const approveFirst = async () => { const [item] = (await call('GET', '/v1/users/u1/approvals', undefined, relay)).body.approvals; return call('POST', `/v1/users/u1/approvals/${item.callRef}/decision`, {decision: 'approve', digest: item.digest}, relay); };
  const token = await mint(), alias = aliasOfList(await agent(token.token, 'capabilities.list', {}));
  const asked = await agent(token.token, 'calls.create', {connectionId: alias, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}});
  await call('POST', `/v1/users/u1/agent-tokens/${token.agentToken.id}/revoke`);
  await approveFirst();
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(repo().get('jobs', asked.body.result.id).status, 'failed'); assert.equal(sent('/messages/send'), 0);
  // A proxied change waiting for approval, its token then expired: nothing is sent either.
  const second = await mint(), alias2 = aliasOfList(await agent(second.token, 'capabilities.list', {}));
  const proxied = await agent(second.token, 'proxy.request', {connectionId: alias2, request: {method: 'POST', path: '/gmail/v1/users/me/labels', body: {name: 'x'}}});
  assert.equal(proxied.body.result.status, 'awaiting_approval');
  repo().put('clientGrants', {...repo().get('clientGrants', second.agentToken.id), expiresAt: new Date(Date.now() - 1000).toISOString()});
  await approveFirst();
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(repo().get('jobs', proxied.body.result.id).status, 'failed'); assert.equal(sent('POST https://gmail.googleapis.com/gmail/v1/users/me/labels'), 0);
  // A row set to Never after the grant: listed as unavailable, refused, and earlier results withheld.
  const third = await mint(), alias3 = aliasOfList(await agent(third.token, 'capabilities.list', {}));
  const earlier = await agent(third.token, 'calls.create', {connectionId: alias3, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}});
  app.runtimes.bundle(scope).permissions.set({connectionId: u1, capabilityId: read.id, mode: 'deny'});
  const listed = (await agent(third.token, 'capabilities.list', {})).body.result.capabilities.find(item => item.id === read.id);
  assert.deepEqual([listed.status, listed.reason], ['unavailable', 'permission_denied']);
  assert.equal((await agent(third.token, 'calls.create', {connectionId: alias3, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-2'}})).body.error.code, 'permission_denied');
  assert.equal((await agent(third.token, 'calls.get', {callId: earlier.body.result.id})).body.result.resultWithheld, true);
  // The key that minted a token revoked with its tokens while a call waits: nothing is sent when it is approved.
  const minter = app.keys.mint({environmentId: scope.environmentId, preset: 'standard'});
  const fourth = (await call('POST', '/v1/users/u1/agent-tokens', {name: 'Late', bindings: [{accountRef: u1, capabilityId: send.id}]}, minter.token)).body, alias4 = aliasOfList(await agent(fourth.token, 'capabilities.list', {}));
  const waiting = await agent(fourth.token, 'calls.create', {connectionId: alias4, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}});
  app.keys.revoke(minter.keyId, {withAgentTokens: true});
  await approveFirst();
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(repo().get('jobs', waiting.body.result.id).status, 'failed'); assert.equal(sent('/messages/send'), 0);
  // A deleted person: every token of theirs stops.
  await call('DELETE', '/v1/users/u1');
  assert.equal((await agent(third.token, 'capabilities.list', {})).status, 401);
});

test('transport and tokens: browsers, other verbs and oversized bodies are refused; every unusable token gets the same 401', async t => {
  const {app, agent, mint, call, repo, read} = await setup(t);
  const token = await mint();
  assert.equal((await agent(token.token, 'fabric.discover', {}, 'x1', {Origin: 'https://evil.example'})).status, 403);
  assert.equal((await agent(token.token, 'fabric.discover', {}, 'x2', {Cookie: 'a=b'})).status, 403);
  assert.equal((await fetch(`${app.origin}/fabric/v1`, {headers: {Authorization: `Bearer ${token.token}`}})).status, 405);
  const big = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token.token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id: 'b', method: 'fabric.discover', params: {pad: 'x'.repeat(300 * 1024)}})});
  assert.equal(big.status, 413);
  const revoked = await mint(), expired = await mint();
  await call('POST', `/v1/users/u1/agent-tokens/${revoked.agentToken.id}/revoke`);
  app.registry.put('agentTokenRoutes', {...app.registry.get('agentTokenRoutes', expired.agentToken.id), expiresAt: new Date(Date.now() - 1000).toISOString()});
  const [id, secret] = token.token.split('.').slice(1);
  const bad = [`fab_client.${randomUUID()}.${secret}`, `fab_client.${id}.${'A'.repeat(43)}`, revoked.token, expired.token, 'fab_sk_dev.nope', ''];
  const answers = await Promise.all(bad.map(value => agent(value, 'fabric.discover', {}, 'same')));
  for (const answer of answers) { assert.equal(answer.status, 401); assert.deepEqual(answer.body, answers[0].body); }
  // Same request id and parameters: the same call, sent once; different parameters: a conflict.
  const alias = aliasOfList(await agent(token.token, 'capabilities.list', {}));
  const params = {connectionId: alias, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}};
  const first = await agent(token.token, 'calls.create', params, 'req-1'), again = await agent(token.token, 'calls.create', params, 'req-1');
  assert.equal(again.body.result.id, first.body.result.id);
  assert.equal(repo().list('jobs').filter(job => job.source?.requestId === 'req-1').length, 1);
  assert.equal((await agent(token.token, 'calls.create', {...params, args: {userId: 'me', id: 'm-9'}}, 'req-1')).body.error.code, 'idempotency_conflict');
});

// The MCP adapter, unchanged in its local behaviour, works against a developer environment with an agent token.
test('an MCP client uses an agent token: lists by alias, reads, and an Ask comes back as a call reference, never a link', async t => {
  const {app, mint, read, send} = await setup(t);
  const token = await mint();
  const server = createMcpAdapter({env: {FABRIC_ENDPOINT: `${app.origin}/fabric/v1`, FABRIC_CLIENT_TOKEN: token.token}}), client = new Client({name: 'tenant-mcp', version: '1.0.0'});
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); });
  const data = reply => reply.structuredContent;
  const listed = data(await client.callTool({name: 'fabric_list_capabilities', arguments: {}}));
  assert.equal(listed.error, undefined, JSON.stringify(listed).slice(0, 300));
  const readCap = listed.capabilities.find(item => item.id === read.id);
  assert.match(readCap.connectionId, /^acct_/);
  const got = data(await client.callTool({name: 'fabric_invoke', arguments: {requestId: 'mcp-1', connectionId: readCap.connectionId, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}}}));
  assert.deepEqual([got.status, got.result], ['succeeded', {data: {id: 'm-1', snippet: 'hello'}}]);
  const asked = await client.callTool({name: 'fabric_invoke', arguments: {requestId: 'mcp-2', connectionId: readCap.connectionId, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}}});
  assert.equal(data(asked).status, 'awaiting_approval');
  assert.deepEqual(Object.keys(data(asked).approval).sort(), ['callRef', 'expiresAt']);
  assert.equal(JSON.stringify(asked).includes(app.origin), false, 'no Fabric link reaches the model');
  const later = data(await client.callTool({name: 'fabric_get_call', arguments: {callId: data(asked).id}}));
  assert.equal(later.status, 'awaiting_approval');
});

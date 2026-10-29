import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {TenantRegistry} from '../lib/tenant/registry.mjs';
import {ServiceKeys} from '../lib/tenant/keys.mjs';
import {EnvironmentStores} from '../lib/tenant/environments.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {createMcpAdapter} from '../lib/mcp-adapter.mts';
import {Client} from '@modelcontextprotocol/client';
import {InMemoryTransport} from '@modelcontextprotocol/server';

// The security review of the developer layer (docs/F03-SECURITY-REVIEW.md), group a: agents and executions. Each
// confirmed finding has a test here that failed before its fix.
const GMAIL = 'https://gmail.googleapis.com';
const TYPED = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send']];
function seed(root) {
  const paths = {};
  for (const [id, method, route] of TYPED) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: GMAIL}], paths}}).capabilities;
  const store = new PlatformStore({root});
  const operations = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => ({id, method: id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`, sensitive: null}));
  for (const [id, method, route] of TYPED) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `${GMAIL}${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations[operations.findIndex(op => op.id === id)] = {id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null};
  }
  for (const [id, route] of [['gmail.users.labels.list', '/gmail/v1/users/{userId}/labels'], ['gmail.users.labels.create', '/gmail/v1/users/{userId}/labels']]) operations[operations.findIndex(op => op.id === id)].path = route;
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  const [repo] = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {'/repos/{owner}/{repo}': {get: {operationId: 'repos/get', parameters: ['owner', 'repo'].map(name => ({name, in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'OK'}}}}}}}).capabilities;
  store.put('capabilities', {...repo, status: 'active'});
  store.put('applicationMaps', {id: 'github', appId: 'github', classifierVersion: SENSITIVITY_VERSION, operations: [{id: 'repos/get', capabilityId: repo.id, method: 'GET', path: '/repos/{owner}/{repo}', sensitive: null}]});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review-a-'));
  seed(root);
  let now = Date.UTC(2026, 9, 17, 9);
  const sim = {calls: [], identity: 100};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://github.com/login/oauth/access_token') return {status: 200, headers: {}, data: {access_token: `gho_review_${randomUUID()}`, token_type: 'bearer', scope: sim.scope ?? 'read:user,repo'}};
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: {id: sim.identity, login: `octo${sim.identity}`, name: `Octo ${sim.identity}`}};
    if (req.url.startsWith('https://api.github.com/applications/')) return {status: 204, headers: {}, data: null};
    if (req.url.startsWith('https://api.github.com/repos/')) return {status: 200, headers: {}, data: {id: 7, full_name: 'o/r'}};
    const data = req.url.includes('/labels') ? {labels: [{id: 'INBOX'}]} : {id: 'm-1', snippet: 'hello'};
    return req.responseType === 'buffer' ? {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(data))} : {status: 200, headers: {}, data};
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, clock: () => now, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'P0'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev), key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body, token = key, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: response.status === 204 ? null : await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  /** A person with a ready Gmail account (u1 by default). */
  const gmailFor = async externalUserId => {
    await call('POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId), stamp = app.registry.now(), id = randomUUID();
    repo().put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: `g-${externalUserId}`, displayName: `${externalUserId}@example.com`}, allowedOrigins: [GMAIL],
      scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.labels', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: stamp, updatedAt: stamp, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: externalUserId, userRecordId: user.id}));
    app.stores.open(scope).vault.set(id, {accessToken: 'ya29.review', refreshToken: '1//r', expiresAt: Date.parse(stamp) + 3600_000});
    return {id, owner: {subjectId: externalUserId, userRecordId: user.id}};
  };
  const {id: gmail, owner} = await gmailFor('u1');
  const caps = (await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  const read = caps.find(item => item.id.includes('messages-get')), send = caps.find(item => item.id.includes('messages-send'));
  const repoCap = (await call('GET', '/v1/capabilities?appId=github')).body.capabilities[0];
  let counter = 0;
  const agent = async (token, method, params, id = `r${++counter}`) => {
    const response = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id, method, params})});
    return {status: response.status, body: await response.json()};
  };
  const mint = async (extra = {}, minter = key) => (await call('POST', '/v1/users/u1/agent-tokens', {name: 'Helper', bindings: [{accountRef: gmail, capabilityId: read.id}, {accountRef: gmail, capabilityId: send.id}],
    proxy: [{accountRef: gmail, rows: ['group:gmail.labels.read', 'group:gmail.labels.manage']}], requestable: [{capabilityId: repoCap.id}], ...extra}, minter)).body;
  /** A sign-in through the real GitHub path for the session's person, stopped before confirm. */
  const signIn = async session => {
    const binding = `browser-${session.id}-binding`;
    app.sessions.claim(session.id, new URL(session.connectUrl).hash.slice(3), binding);
    const started = app.sessions.start(session.id, binding), url = new URL(started.authorizationUrl);
    const back = await app.sessions.callback('github', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
    return {...back, confirm: () => app.sessions.confirm(session.id, binding, back.finish)};
  };
  const proxy = (request, idem = randomUUID(), token = key) => call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'gmail', request}, token, {'Idempotency-Key': idem});
  const execute = (body, idem = randomUUID(), token = key) => call('POST', '/v1/executions', {externalUserId: 'u1', ...body}, token, {'Idempotency-Key': idem});
  const gmailOff = async () => assert.equal((await call('PUT', '/v1/environment/apps/gmail', {enabled: false})).status, 200);
  const sentTo = pattern => sim.calls.filter(line => line.includes(pattern)).length;
  return {app, sim, dev, scope, key, call, repo, gmail, owner, gmailFor, read, send, repoCap, agent, mint, signIn, proxy, execute, gmailOff, sentTo, advance: ms => { now += ms; }};
}
const aliasOf = async (s, token) => (await s.agent(token, 'capabilities.list', {})).body.result;
const SEND_ARGS = {userId: 'me', body: {raw: 'eA'}};

test('agent-1: an app the developer turned off runs nothing for agents either, typed or proxied', async t => {
  const s = await setup(t);
  const token = (await s.mint()).token, listed = await aliasOf(s, token), alias = listed.capabilities[0].connectionId;
  await s.gmailOff();
  const before = s.sim.calls.length;
  const typed = await s.agent(token, 'calls.create', {connectionId: alias, capabilityId: s.read.id, definitionHash: s.read.definitionHash, args: {userId: 'me', id: 'm-1'}});
  assert.equal(typed.body.error?.code, 'app_disabled'); assert.equal(typed.status, 422);
  const proxied = await s.agent(token, 'proxy.request', {connectionId: alias, request: {method: 'GET', path: '/gmail/v1/users/me/labels'}});
  assert.equal(proxied.body.error?.code, 'app_disabled'); assert.equal(proxied.status, 422);
  assert.equal(s.sim.calls.length, before, 'nothing reached Gmail');
  const after = await aliasOf(s, token);
  assert.ok(after.capabilities.filter(item => item.id.startsWith('gmail.')).every(item => item.status === 'unavailable' && item.reason === 'app_disabled'), JSON.stringify(after.capabilities.map(item => [item.status, item.reason])));
  assert.deepEqual(after.proxy.map(entry => [entry.status, entry.reason]), [['unavailable', 'app_disabled']]);
});

test('GOV-1: a call accepted while the app was on stops at dispatch once it is off, the developer\'s and the agent\'s alike', async t => {
  const s = await setup(t);
  const minted = await s.mint(), grant = s.repo().get('clientGrants', minted.agentToken.id), caller = s.app.keys.verify(s.key);
  const bundle = s.app.runtimes.bundle(s.scope), principal = {kind: 'product_user', ...s.owner}, args = {userId: 'me', id: 'm-1'};
  const developer = await bundle.runtime.prepareJob({connectionId: s.gmail, capabilityId: s.read.id, args, source: {kind: 'service', serviceClientId: caller.serviceClientId, keyId: caller.keyId}}, principal);
  const agentJob = await bundle.runtime.prepareJob({connectionId: s.gmail, capabilityId: s.read.id, args, source: {kind: 'client', clientId: grant.id, requestId: 'queued-1', keyId: grant.mintedByKeyId}}, principal);
  assert.deepEqual([developer.status, agentJob.status], ['queued', 'queued']);
  await s.gmailOff();
  const before = s.sim.calls.length;
  for (const job of [developer, agentJob]) {
    await s.app.runtimes.dispatch(s.scope, job.id);
    assert.deepEqual([s.repo().get('jobs', job.id).status, s.repo().get('jobs', job.id).errorCode], ['failed', 'app_disabled']);
  }
  assert.equal(s.sim.calls.length, before, 'nothing reached Gmail');
});

test('agent-2: an agent\'s proxied requests keep the same limits as the developer\'s: 20 waiting, 60 refusals a minute', async t => {
  const s = await setup(t);
  const token = (await s.mint()).token, alias = (await aliasOf(s, token)).proxy[0].connectionId;
  const codes = [];
  let full = null;
  for (let i = 0; i < 23; i++) { const r = await s.agent(token, 'proxy.request', {connectionId: alias, request: {method: 'POST', path: '/gmail/v1/users/me/labels', body: {name: `l${i}`}}}); codes.push(r.body.result?.status ?? r.body.error?.code); full ??= r.body.error ? r : null; }
  assert.deepEqual([codes.filter(code => code === 'awaiting_approval').length, codes.slice(20)], [20, ['pending_limit', 'pending_limit', 'pending_limit']]);
  assert.equal(full.status, 429);
  const rows = s.repo().list('protocolRequests').length, refused = [];
  for (let i = 0; i < 62; i++) { const r = await s.agent(token, 'proxy.request', {connectionId: alias, request: {method: 'GET', path: '/gmail/v1/users/me/../../x'}}); refused.push(r.body.error?.code); }
  assert.equal(refused.filter(code => code === 'rate_limited').length >= 2, true, JSON.stringify([...new Set(refused)]));
  assert.equal(s.repo().list('protocolRequests').length, rows, 'a refused request leaves no request record');
  const last = await s.agent(token, 'proxy.request', {connectionId: alias, request: {method: 'GET', path: '/gmail/v1/users/me/labels'}});
  assert.equal(last.status, 429, 'over the window even a good request waits');
  s.advance(61_000);
  assert.notEqual((await s.agent(token, 'proxy.request', {connectionId: alias, request: {method: 'GET', path: '/gmail/v1/users/me/labels'}})).body.error?.code, 'rate_limited', 'the window ends');
  // Another token of the same person has its own allowance, and with nothing waiting its own refused requests (each
  // evaluated, none stored) fill its window: the 61st in a minute is rate_limited.
  const other = (await s.mint()).token, otherAlias = (await aliasOf(s, other)).proxy[0].connectionId;
  assert.equal((await s.agent(other, 'proxy.request', {connectionId: otherAlias, request: {method: 'GET', path: '/gmail/v1/users/me/labels'}})).body.result?.status, 'succeeded');
  const stored = s.repo().list('protocolRequests').length, answers = [];
  for (let i = 0; i < 61; i++) answers.push((await s.agent(other, 'proxy.request', {connectionId: otherAlias, request: {method: 'GET', path: '/gmail/v1/users/me/../../x'}})).body.error?.code);
  assert.deepEqual([answers.filter(code => code === 'invalid_path').length, answers.at(-1)], [60, 'rate_limited']);
  assert.equal(s.repo().list('protocolRequests').length, stored, 'no request record for a refusal');
});

test('ROB-4 and ROB-5: typed calls waiting for an approval are capped per requester: 20 per agent token, 20 per key for one person', async t => {
  const s = await setup(t);
  const token = (await s.mint()).token, alias = (await aliasOf(s, token)).capabilities[0].connectionId;
  const ask = () => s.agent(token, 'calls.create', {connectionId: alias, capabilityId: s.send.id, definitionHash: s.send.definitionHash, args: SEND_ARGS});
  for (let i = 0; i < 20; i++) assert.equal((await ask()).body.result?.status, 'awaiting_approval');
  const agentFull = await ask();
  assert.deepEqual([agentFull.status, agentFull.body.error?.code], [429, 'pending_limit']);
  // A read that would not wait still runs.
  assert.equal((await s.agent(token, 'calls.create', {connectionId: alias, capabilityId: s.read.id, definitionHash: s.read.definitionHash, args: {userId: 'me', id: 'm-1'}})).body.result?.status, 'succeeded');
  const body = {capabilityId: s.send.id, definitionHash: s.send.definitionHash, args: SEND_ARGS};
  for (let i = 0; i < 20; i++) assert.equal((await s.execute(body)).body.status, 'awaiting_approval');
  const keyFull = await s.execute(body);
  assert.deepEqual([keyFull.status, keyFull.body.error?.code], [429, 'pending_limit']);
  assert.equal((await s.execute({capabilityId: s.read.id, definitionHash: s.read.definitionHash, args: {userId: 'me', id: 'm-1'}, waitMs: 3000})).body.status, 'succeeded');
  // Another person, and another key, still get theirs.
  await s.gmailFor('u2');
  assert.equal((await s.call('POST', '/v1/executions', {externalUserId: 'u2', ...body}, s.key, {'Idempotency-Key': randomUUID()})).body.status, 'awaiting_approval');
  const second = s.app.keys.mint({environmentId: s.dev.id, preset: 'standard'}).token;
  assert.equal((await s.execute(body, randomUUID(), second)).body.status, 'awaiting_approval');
  // The person's waiting approvals: every one of them, bounded by the caps.
  assert.equal((await s.call('GET', '/v1/users/u1/approvals')).body.approvals.length, 41);
});

test('ROB-5: a person\'s approvals and activity read only that person\'s records, never every job in the environment', async t => {
  const s = await setup(t);
  await s.execute({capabilityId: s.send.id, definitionHash: s.send.definitionHash, args: SEND_ARGS});
  await s.execute({capabilityId: s.read.id, definitionHash: s.read.definitionHash, args: {userId: 'me', id: 'm-1'}, waitMs: 3000});
  const repository = s.repo(), listed = [], list = repository.list;
  repository.list = collection => { listed.push(collection); return list.call(repository, collection); };
  t.after(() => { delete repository.list; });
  const approvals = (await s.call('GET', '/v1/users/u1/approvals')).body.approvals;
  const activity = (await s.call('GET', '/v1/users/u1/activity')).body;
  const nobody = (await s.call('GET', '/v1/users/nobody/activity')).body;
  assert.equal(approvals.length, 1);
  assert.deepEqual([activity.approvals.length, activity.days.flatMap(day => day.items).length], [1, 2]);
  assert.deepEqual([nobody.approvals, nobody.days], [[], []]);
  assert.equal(listed.includes('jobs'), false, `jobs were listed whole: ${listed.join(', ')}`);
  // A held call counts the requester's waiting holds through the index too, never every hold ever made.
  const held = await s.execute({capabilityId: s.repoCap.id, definitionHash: s.repoCap.definitionHash, args: {owner: 'o', repo: 'r'}, onMissingAccess: 'hold'});
  assert.equal(held.body.status, 'connection_required');
  assert.deepEqual(listed.filter(name => ['jobs', 'continuations'].includes(name)), [], `listed whole: ${listed.join(', ')}`);
});

test('agent-3: account requests are limited per token per hour, and a closed one leaves no route behind', async t => {
  const s = await setup(t);
  const token = (await s.mint()).token, params = {appId: 'github', capabilityId: s.repoCap.id, definitionHash: s.repoCap.definitionHash, args: {owner: 'o', repo: 'r'}};
  const routes = () => s.app.registry.list('sessionRoutes').length, baseline = routes();
  const asked = (await s.agent(token, 'calls.create', params)).body.result;
  assert.equal(asked.status, 'awaiting_connection'); assert.equal(routes(), baseline + 1);
  assert.equal((await s.agent(token, 'calls.cancel', {callId: asked.id})).body.result?.status, 'cancelled');
  assert.equal(routes(), baseline, 'the closed request\'s link route is gone');
  let limited = null, answer = null;
  for (let i = 1; i <= 61 && !limited; i++) {
    const r = await s.agent(token, 'calls.create', params);
    if (r.body.error?.code === 'rate_limited') { limited = i; answer = r; } else await s.agent(token, 'calls.cancel', {callId: r.body.result.id});
  }
  assert.equal(limited, 60, 'the 61st request in an hour (60 more after the first) is refused');
  assert.equal(answer.status, 429);
  s.advance(3_600_001);
  assert.equal((await s.agent(token, 'calls.create', params)).body.result?.status, 'awaiting_connection', 'a new hour, a new allowance');
});

test('agent-4: a key revoked with its agent tokens closes their account requests, and the token reads revoked', async t => {
  const s = await setup(t);
  const minter = s.app.keys.mint({environmentId: s.dev.id, preset: 'standard'});
  const {token} = await s.mint({}, minter.token), params = {appId: 'github', capabilityId: s.repoCap.id, definitionHash: s.repoCap.definitionHash, args: {owner: 'o', repo: 'r'}};
  const asked = (await s.agent(token, 'calls.create', params)).body.result;
  s.app.keys.revoke(minter.keyId, {withAgentTokens: true});
  assert.deepEqual((await s.call('GET', '/v1/users/u1/agent-tokens')).body.agentTokens.map(item => item.status), ['revoked']);
  const held = (await s.call('GET', `/v1/executions/${asked.id}`)).body;
  assert.notEqual(held.status, 'connection_required', 'no longer waiting for an account');
  const link = await s.call('POST', `/v1/connect-sessions/${asked.handoff.connectSessionId}/link`);
  assert.equal(link.status, 409, 'no link for a request whose agent is gone');
  // An expired token's request closes the same way, and no link is minted for it even before anyone looked.
  s.advance(1_000);
  const short = (await s.mint({expiresInSeconds: 60})).token;
  const second = (await s.agent(short, 'calls.create', params)).body.result;
  s.advance(61_000);
  assert.equal((await s.call('POST', `/v1/connect-sessions/${second.handoff.connectSessionId}/link`)).status, 409);
  assert.notEqual((await s.call('GET', `/v1/executions/${second.id}`)).body.status, 'connection_required');
  assert.deepEqual((await s.call('GET', '/v1/users/u1/agent-tokens')).body.agentTokens.map(item => item.status), ['revoked', 'expired']);
});

test('authz-3: a revoked key\'s held calls close as key_revoked: no link is minted for them, and one minted earlier runs nothing', async t => {
  const s = await setup(t);
  const asker = s.app.keys.mint({environmentId: s.dev.id, preset: 'standard'});
  const hold = async () => (await s.call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: s.repoCap.id, definitionHash: s.repoCap.definitionHash, args: {owner: 'o', repo: 'r'}, onMissingAccess: 'hold'}, asker.token, {'Idempotency-Key': randomUUID()})).body;
  const first = await hold(), second = await hold();
  assert.deepEqual([first.status, second.status], ['connection_required', 'connection_required']);
  const early = (await s.call('POST', `/v1/connect-sessions/${second.handoff.connectSessionId}/link`)).body;
  s.app.keys.revoke(asker.keyId);
  assert.equal((await s.call('POST', `/v1/connect-sessions/${first.handoff.connectSessionId}/link`)).status, 409, 'no link for a revoked key\'s call');
  assert.deepEqual([(await s.call('GET', `/v1/executions/${first.callRef}`)).body.status], ['cancelled']);
  // The person opens the link minted before the revoke, signs in and confirms: the call does not run.
  const signedIn = await s.signIn({id: second.handoff.connectSessionId, connectUrl: early.connectUrl});
  assert.equal(signedIn.confirm().state, 'connected');
  await s.app.sessions.settled();
  const after = (await s.call('GET', `/v1/executions/${second.callRef}`)).body;
  assert.deepEqual([after.status, after.error?.code], ['failed', 'key_revoked']);
  assert.equal(s.sentTo('/repos/o/r'), 0, 'nothing was sent for the revoked key');
  assert.equal(s.repo().get('jobs', second.callRef), null);
});

test('agent-5: through MCP, the same requestId after the held call resumed answers the call, not an error', async t => {
  const s = await setup(t);
  const {token} = await s.mint();
  const server = createMcpAdapter({env: {FABRIC_ENDPOINT: `${s.app.origin}/fabric/v1`, FABRIC_CLIENT_TOKEN: token}}), client = new Client({name: 'review', version: '1.0.0'});
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); });
  const args = {requestId: 'mcp-ask-1', appId: 'github', capabilityId: s.repoCap.id, definitionHash: s.repoCap.definitionHash, args: {owner: 'o', repo: 'r'}};
  const first = (await client.callTool({name: 'fabric_invoke', arguments: args})).structuredContent;
  assert.equal(first.status, 'awaiting_connection');
  const link = (await s.call('POST', `/v1/connect-sessions/${first.handoff.connectSessionId}/link`)).body;
  const done = await s.signIn({id: first.handoff.connectSessionId, connectUrl: link.connectUrl});
  done.confirm(); await s.app.sessions.settled();
  await s.call('GET', `/v1/executions/${first.id}?waitMs=3000`);
  const replay = (await client.callTool({name: 'fabric_invoke', arguments: args})).structuredContent;
  // A call's projection always carries error (null when none); a tool error would be {error: {code, message}}.
  assert.equal(replay.error, null, JSON.stringify(replay.error)); assert.equal(replay.id, first.id); assert.equal(replay.status, 'succeeded');
});

test('agent-5: the MCP adapter accepts a held call while it resumes (queued, no account yet), and still refuses another app\'s call', async t => {
  const TOKEN = `fab_client.${randomUUID()}.${'a'.repeat(43)}`, id = randomUUID(), at = '2026-10-17T09:00:00.000Z';
  const handoff = {appId: 'github', appName: 'GitHub', connectSessionId: `cs_${'a'.repeat(26)}`, expiresAt: '2026-10-17T09:30:00.000Z', outcome: null, state: 'connected'};
  const hold = {id, status: 'queued', connectionId: null, capabilityId: 'github.repos', appId: 'github', createdAt: at, updatedAt: at, result: null, error: null, errorCode: null, approvalRequired: false, handoff};
  const job = {id, status: 'succeeded', connectionId: `acct_${'b'.repeat(26)}`, capabilityId: 'github.repos', appId: 'github', createdAt: at, updatedAt: at, result: {data: {id: 7}}, error: null, errorCode: null, approvalRequired: false};
  const reply = async value => {
    const server = createMcpAdapter({env: {FABRIC_ENDPOINT: 'http://127.0.0.1:4999/fabric/v1', FABRIC_CLIENT_TOKEN: TOKEN}, fetch: async (_url, input) => new Response(JSON.stringify({protocol: 'fabric/0.1', id: JSON.parse(input.body).id, result: value}), {headers: {'content-type': 'application/json'}})});
    const client = new Client({name: 'review', version: '1.0.0'}), [left, right] = InMemoryTransport.createLinkedPair();
    await server.connect(left); await client.connect(right);
    t.after(async () => { await client.close(); await server.close(); });
    return (await client.callTool({name: 'fabric_invoke', arguments: {requestId: 'r-1', appId: 'github', capabilityId: 'github.repos', definitionHash: 'a'.repeat(64), args: {}}})).structuredContent;
  };
  const resuming = await reply(hold);
  assert.deepEqual([resuming.error, resuming.status, resuming.connectionId], [null, 'queued', null]);
  const resumed = await reply(job);
  assert.deepEqual([resumed.error, resumed.status], [null, 'succeeded']);
  assert.equal((await reply({...job, appId: 'gmail'})).error?.code, 'invalid_response', 'a call of another app is not this request');
  assert.equal((await reply({...hold, status: 'running'})).error?.code, 'invalid_response', 'only a queued hold has no account yet');
});

test('GOV-7: an idempotent replay of an accepted call answers the call, never pending_limit, rate_limited or app_disabled', async t => {
  const s = await setup(t);
  const label = i => ({method: 'POST', path: '/gmail/v1/users/me/labels', body: {name: `l${i}`}});
  let last;
  for (let i = 0; i < 20; i++) { const idem = randomUUID(), answer = await s.proxy(label(i), idem); assert.equal(answer.body.status, 'awaiting_approval'); last = {idem, i, callRef: answer.body.callRef}; }
  for (let i = 0; i < 61; i++) {
    const again = await s.proxy(label(last.i), last.idem);
    assert.deepEqual([again.status, again.body.callRef], [202, last.callRef], `replay ${i}`);
  }
  const fresh = await s.proxy(label(99));
  assert.equal(fresh.body.error?.code, 'pending_limit', 'a fresh request meets the limit; replays were never counted as refusals');
  // Accepted before the app was turned off: the replay is the call; a new request is refused.
  const idem = randomUUID(), body = {capabilityId: s.send.id, definitionHash: s.send.definitionHash, args: SEND_ARGS}, accepted = await s.execute(body, idem);
  assert.equal(accepted.body.status, 'awaiting_approval');
  const token = (await s.mint()).token, alias = (await aliasOf(s, token)).capabilities[0].connectionId, params = {connectionId: alias, capabilityId: s.read.id, definitionHash: s.read.definitionHash, args: {userId: 'me', id: 'm-1'}};
  const asked = (await s.agent(token, 'calls.create', params, 'agent-req-1')).body.result;
  await s.gmailOff();
  const replay = await s.execute(body, idem);
  assert.deepEqual([replay.status, replay.body.callRef, replay.body.status], [202, accepted.body.callRef, 'awaiting_approval']);
  assert.deepEqual([(await s.proxy(label(last.i), last.idem)).body.callRef], [last.callRef]);
  assert.equal((await s.execute(body)).body.error?.code, 'app_disabled');
  const agentReplay = await s.agent(token, 'calls.create', params, 'agent-req-1');
  assert.deepEqual([agentReplay.body.error, agentReplay.body.result?.id], [undefined, asked.id]);
});

test('authz-1: a refused rotation changes nothing: the current key keeps working past the old key\'s grace', t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review-a-keys-'));
  let now = Date.UTC(2026, 9, 17);
  const clock = () => now, registry = new TenantRegistry({root, clock}), stores = new EnvironmentStores({root, clock});
  t.after(() => { registry.close(); stores.closeAll(); rmSync(root, {recursive: true, force: true}); });
  const org = registry.createOrganization({name: 'Acme'}), project = registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = registry.createEnvironment({projectId: project.id, kind: 'development'}, stores), keys = new ServiceKeys(registry);
  const first = keys.mint({environmentId: dev.id, preset: 'standard'}), rotated = keys.rotate(first.serviceClientId);
  now += 24 * 3600 * 1000;
  assert.throws(() => keys.rotate(first.serviceClientId), /already has two active keys/);
  assert.equal(keys.list(dev.id).find(key => key.id === rotated.keyId).expiresAt, null, 'a refused rotate changes nothing');
  keys.revoke(first.keyId);
  now += 8 * 24 * 3600 * 1000;
  assert.equal(keys.verify(rotated.token).keyId, rotated.keyId);
});

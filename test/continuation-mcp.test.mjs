import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import {InMemoryTransport} from '@modelcontextprotocol/server';
import {createMcpAdapter} from '../lib/mcp-adapter.mts';
import {createApp} from '../server.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';

// F02.3b: the agent surface for missing-access handoffs. Part A drives the adapter in memory
// against a fake runtime; part B runs an independent MCP child against an isolated designated app.
const TOKEN = `fab_client.${randomUUID()}.${'a'.repeat(43)}`;
const ENV = {FABRIC_ENDPOINT: 'http://127.0.0.1:4188/fabric/v1', FABRIC_CLIENT_TOKEN: TOKEN};
const HASH = 'a'.repeat(64), ID = '4f6c2c3e-5a1b-4c8d-9e0f-123456789abc';
const at = '2026-10-11T10:00:00.000Z', expires = '2026-10-11T10:30:00.000Z';
const handoffView = (overrides = {}) => ({id: ID, status: 'awaiting_connection', connectionId: null, capabilityId: 'github.listRepos', createdAt: at, updatedAt: at, result: null, error: null, approvalRequired: false,
  handoff: {appId: 'github', appName: 'GitHub', url: `http://127.0.0.1:4188/continue/${ID}`, expiresAt: expires, state: 'awaiting_owner', outcome: null}, resumedCallId: null, ...overrides});
const ask = {requestId: 'ask-1', appId: 'github', capabilityId: 'github.listRepos', definitionHash: HASH, args: {}};

async function memory(t, reply) {
  const calls = [];
  const fetch = async (url, input) => { calls.push(JSON.parse(input.body)); const value = typeof reply === 'function' ? await reply(JSON.parse(input.body), input) : reply; return new Response(JSON.stringify({protocol: 'fabric/0.1', id: JSON.parse(input.body).id, result: value}), {headers: {'content-type': 'application/json'}}); };
  const server = createMcpAdapter({env: ENV, fetch, timeoutMs: 200}), client = new Client({name: 'handoff-test', version: '1.0.0'});
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); });
  return {client, calls, invoke: input => client.callTool({name: 'fabric_invoke', arguments: input}), get: callId => client.callTool({name: 'fabric_get_call', arguments: {callId}})};
}
const code = reply => reply.structuredContent?.error?.code;

test('the adapter keeps six tools and refuses calls that name both or neither account and application', async t => {
  const m = await memory(t, handoffView());
  assert.deepEqual((await m.client.listTools()).tools.map(tool => tool.name).sort(), ['fabric_get_call', 'fabric_invoke', 'fabric_list_capabilities', 'fabric_list_events', 'fabric_proxy_request', 'fabric_watch']);
  const both = await m.invoke({...ask, connectionId: 'acct-a'}), neither = await m.invoke({requestId: 'x', capabilityId: 'c', definitionHash: HASH, args: {}});
  assert.equal(code(both), 'invalid_request'); assert.equal(code(neither), 'invalid_request');
  assert.equal(m.calls.length, 0, 'no upstream request is made for an invalid shape');
});

test('request-only capabilities are listed with no account and never with the client grant inside', async t => {
  const entry = {id: 'github.listRepos', appId: 'github', connectionId: null, definitionHash: HASH, name: 'List repositories', description: '', driver: 'http', inputSchema: {type: 'object'}, effect: 'read', approval: 'after_connection', status: 'connection_required', signIn: 'unavailable'};
  const m = await memory(t, {capabilities: [entry]});
  const listed = (await m.client.callTool({name: 'fabric_list_capabilities', arguments: {}})).structuredContent.capabilities;
  assert.deepEqual(listed, [entry]);
  for (const bad of [{...entry, approval: 'allow'}, {...entry, signIn: 'maybe'}, {...entry, appId: 'Not An App'}, {...entry, inputSchema: {type: 'object', description: TOKEN}}]) {
    const n = await memory(t, {capabilities: [bad]});
    assert.equal(code(await n.client.callTool({name: 'fabric_list_capabilities', arguments: {}})), 'invalid_response');
  }
});

test('an application call returns the owner link in a relayable sentence and the structured handoff', async t => {
  const m = await memory(t, handoffView());
  const reply = await m.invoke(ask);
  assert.equal(reply.isError, false);
  assert.equal(reply.structuredContent.status, 'awaiting_connection'); assert.equal(reply.structuredContent.handoff.url, `http://127.0.0.1:4188/continue/${ID}`);
  assert.match(reply.content[0].text, new RegExp(`open http://127\\.0\\.0\\.1:4188/continue/${ID} before ${expires}`));
  assert.match(reply.content[0].text, new RegExp(`callId "${ID}"\\. Do not resubmit\\.`));
  assert.deepEqual(JSON.parse(reply.content[1].text), reply.structuredContent);
  assert.deepEqual(m.calls[0].params, {appId: 'github', capabilityId: 'github.listRepos', definitionHash: HASH, args: {}});
});

test('a handoff link that is not exactly this endpoint and call is refused', async t => {
  const urls = ['http://127.0.0.1:4189/continue/' + ID, 'https://127.0.0.1:4188/continue/' + ID, `http://127.0.0.1:4188/continue/${ID}?next=evil`, `http://127.0.0.1:4188/continue/${ID}#x`,
    'http://127.0.0.1:4188/continue/00000000-0000-4000-8000-000000000000', 'http://evil.example/continue/' + ID, `http://127.0.0.1:4188/approve/${ID}`];
  for (const url of urls) {
    const m = await memory(t, handoffView({handoff: {...handoffView().handoff, url}}));
    assert.equal(code(await m.invoke(ask)), 'invalid_response', url);
  }
  for (const value of [handoffView({handoff: {...handoffView().handoff, appId: 'gitlab'}}), handoffView({capabilityId: 'github.other'}), handoffView({handoff: {...handoffView().handoff, identity: 'octo'}}), handoffView({connectionId: null, status: 'succeeded'})]) {
    const m = await memory(t, value);
    assert.equal(code(await m.invoke(ask)), 'invalid_response');
  }
});

test('call lookup follows a handoff to completion and marks closed handoffs as errors with fixed text', async t => {
  let view = handoffView();
  const m = await memory(t, () => view);
  assert.equal((await m.get(ID)).structuredContent.status, 'awaiting_connection');
  view = handoffView({status: 'awaiting_approval', approvalRequired: true, connectionId: 'acct-a', handoff: {...handoffView().handoff, url: null, state: 'connected'}, resumedCallId: 'job-1'});
  const pending = await m.get(ID); assert.equal(pending.isError, false); assert.equal(pending.structuredContent.resumedCallId, 'job-1');
  view = handoffView({status: 'succeeded', connectionId: 'acct-a', result: {data: {ok: true}}, handoff: {...handoffView().handoff, url: null, state: 'connected'}, resumedCallId: 'job-1'});
  assert.equal((await m.get(ID)).structuredContent.status, 'succeeded');
  for (const [status, outcome] of [['expired', 'continuation_expired'], ['cancelled', 'owner_declined'], ['failed', 'authority_changed']]) {
    view = handoffView({status, error: `raw provider text ${outcome}`, handoff: {...handoffView().handoff, url: null, state: 'closed', outcome}});
    const closed = await m.get(ID);
    assert.equal(closed.isError, true); assert.equal(closed.structuredContent.handoff.outcome, outcome);
    assert.equal(closed.structuredContent.error.includes('raw provider text'), false);
  }
});

test('a timed-out application call reports interruption and a retry reuses the same request id', async t => {
  let hang = true;
  const m = await memory(t, async () => { if (hang) await new Promise(resolve => setTimeout(resolve, 1000)); return handoffView(); });
  assert.equal(code(await m.invoke(ask)), 'request_interrupted');
  hang = false;
  const retried = await m.invoke(ask);
  assert.equal(retried.structuredContent.id, ID);
  assert.deepEqual(m.calls.map(call => call.id), ['ask-1', 'ask-1'], 'no new request id is minted');
});

async function freePort() { const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const {port} = server.address(); await new Promise(resolve => server.close(resolve)); return port; }

test('an independent MCP child asks for an unconnected app, the owner chooses, and the exact request resumes', async t => {
  const owner = {schemaVersion: 1, id: 'fixture-owner', kind: 'local_owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'fixture-owner'}};
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-continuation-mcp-')), port = await freePort(), calls = [];
  const app = await createApp({dataDir: dir, port, localAuthority: {mode: 'new', ownerPrincipal: owner}, request: async req => { calls.push(req); return {status: 200, data: [{id: 1, full_name: 'octo/fixture'}]}; }});
  await app.start();
  let client, stderr = '';
  t.after(async () => { await client?.close(); await app.close(); await rm(dir, {recursive: true, force: true}); });
  const doc = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {'/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}}}};
  const cap = {...compileOpenApi({appId: 'github', document: doc}).capabilities[0], status: 'active'};
  app.store.put('capabilities', cap);
  app.store.put('connections', {id: 'acct-a', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'consent-a', status: 'ready', label: 'GitHub octo', identity: {id: '101', displayName: 'identity-octo-101', email: 'owner-mail@example.com'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date().toISOString()});
  app.vault.set('acct-a', {accessToken: 'synthetic-only-token'});
  const session = await fetch(`${app.origin}/api/state`), state = await session.json(), cookie = session.headers.get('set-cookie').split(';')[0];
  const owned = (method, route, data) => fetch(`${app.origin}${route}`, {method, headers: {'content-type': 'application/json', cookie, 'x-fabric-csrf': state.csrfToken}, ...(data ? {body: JSON.stringify(data)} : {})}).then(response => response.json());
  const grant = await owned('POST', '/api/clients', {name: 'Independent agent', bindings: [], requestable: [{capabilityId: cap.id}]});
  client = new Client({name: 'independent-handoff-client', version: '1.0.0'}, {versionNegotiation: {mode: {pin: '2026-07-28'}}});
  const transport = new StdioClientTransport({command: process.execPath, args: [fileURLToPath(new URL('../mcp.mts', import.meta.url))], cwd: dir, stderr: 'pipe', env: {FABRIC_ENDPOINT: `${app.origin}/fabric/v1`, FABRIC_CLIENT_TOKEN: grant.token}});
  transport.stderr.on('data', value => { stderr += value; });
  await client.connect(transport);
  const [listed] = (await client.callTool({name: 'fabric_list_capabilities', arguments: {}})).structuredContent.capabilities;
  assert.equal(listed.status, 'connection_required'); assert.equal(listed.connectionId, null);
  const asked = await client.callTool({name: 'fabric_invoke', arguments: {requestId: 'need-github', appId: 'github', capabilityId: cap.id, definitionHash: listed.definitionHash, args: {}}});
  assert.equal(asked.isError, false); assert.equal(asked.structuredContent.status, 'awaiting_connection');
  const link = asked.structuredContent.handoff.url, callId = asked.structuredContent.id;
  assert.equal(link, `${app.origin}/continue/${callId}`); assert.match(asked.content[0].text, /asked to use GitHub: .* Connect GitHub: http:\/\/127\.0\.0\.1:\d+\/continue\//);
  assert.equal(calls.length, 0);
  const view = await owned('GET', `/api/continuations/${callId}`);
  const selected = await owned('POST', `/api/continuations/${callId}/select`, {connectionId: 'acct-a', viewDigest: view.viewDigest});
  assert.equal(selected.status, 'resumed');
  await app.continuations.settled(callId);
  const done = await client.callTool({name: 'fabric_get_call', arguments: {callId}});
  assert.equal(done.isError, false); assert.equal(done.structuredContent.status, 'succeeded');
  assert.equal(done.structuredContent.connectionId, 'acct-a'); assert.ok(done.structuredContent.resumedCallId);
  assert.equal(calls.length, 1);
  const replay = await client.callTool({name: 'fabric_invoke', arguments: {requestId: 'need-github', appId: 'github', capabilityId: cap.id, definitionHash: listed.definitionHash, args: {}}});
  assert.equal(replay.structuredContent.id, callId); assert.equal(calls.length, 1);
  for (const output of [JSON.stringify(asked), JSON.stringify(done), stderr]) { assert.equal(output.includes(grant.token), false); assert.equal(output.includes('synthetic-only-token'), false); }
  for (const output of [JSON.stringify(asked), JSON.stringify(done)]) for (const identity of ['identity-octo-101', 'owner-mail@example.com']) assert.equal(output.includes(identity), false, 'no account identity reaches the agent');
});

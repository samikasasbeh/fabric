import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import {InMemoryTransport} from '@modelcontextprotocol/server';
import {createMcpAdapter} from '../lib/mcp-adapter.mts';
import {FabricClient} from '../lib/fabric-client.mjs';
import {FABRIC_PROTOCOL} from '../lib/fabric-protocol.mjs';
import {finalizeCapability} from '../lib/compiler.mjs';
import {fixture} from './fixtures/signin-fixture.mjs';

// F02.3b/F02.3c agent surface (docs/F02.3-MISSING-ACCESS-SPEC.md sections 4, 5, 13 item 56, 15).
// Part A drives the adapter in memory against a fake runtime (no network); part B runs an independent
// MCP child against the isolated sign-in fixture (GitHub simulator, temporary store, loopback port);
// part C checks FabricClient with an injected fetch. Fixture-only evidence, not live-account evidence.
const ENTRY = fileURLToPath(new URL('../mcp.mts', import.meta.url));
const TOKEN = `fab_client.${randomUUID()}.${'a'.repeat(43)}`;
// In-memory adapters never open this port: every request goes to the injected fetch.
const ORIGIN = 'http://127.0.0.1:47123', ENDPOINT = `${ORIGIN}/fabric/v1`;
const HASH = 'a'.repeat(64), ID = '4f6c2c3e-5a1b-4c8d-9e0f-123456789abc';
const at = '2026-10-11T10:00:00.000Z', expires = '2026-10-11T10:30:00.000Z';
const handoffView = (overrides = {}, handoff = {}) => ({id: ID, status: 'awaiting_connection', connectionId: null, capabilityId: 'github.createIssue', createdAt: at, updatedAt: at, result: null, error: null, approvalRequired: false,
  handoff: {appId: 'github', appName: 'GitHub', url: `${ORIGIN}/continue/${overrides.id ?? ID}`, expiresAt: expires, state: 'awaiting_owner', outcome: null, ...handoff}, resumedCallId: null, ...overrides});
const ask = {requestId: 'ask-1', appId: 'github', capabilityId: 'github.createIssue', definitionHash: HASH, args: {}};
const code = reply => reply.structuredContent?.error?.code;
const envelope = (body, result) => new Response(JSON.stringify({protocol: FABRIC_PROTOCOL, id: body.id, result}), {headers: {'content-type': 'application/json'}});

async function memory(t, reply) {
  const calls = [];
  const fetch = async (_url, input) => { const body = JSON.parse(input.body); calls.push(body); return envelope(body, reply); };
  const server = createMcpAdapter({env: {FABRIC_ENDPOINT: ENDPOINT, FABRIC_CLIENT_TOKEN: TOKEN}, fetch, timeoutMs: 1000}), client = new Client({name: 'handoff-e2e-test', version: '1.0.0'});
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); });
  return {client, calls, invoke: input => client.callTool({name: 'fabric_invoke', arguments: input}), get: callId => client.callTool({name: 'fabric_get_call', arguments: {callId}}), list: () => client.callTool({name: 'fabric_list_capabilities', arguments: {}})};
}
/** A refused handoff answers only the fixed error: no sentence, no link and no call id reach the model. */
function assertNotRelayed(reply, label) {
  assert.equal(code(reply), 'invalid_response', label);
  assert.equal(reply.isError, true, label);
  assert.equal(reply.content.length, 1, `${label}: only the error is returned`);
  assert.equal(JSON.stringify(reply).includes('/continue/'), false, `${label}: no link is relayed`);
  assert.equal(JSON.stringify(reply).includes('Do not resubmit'), false, `${label}: no relay sentence`);
}

// Part A: projection rules in lib/mcp-adapter.mts.

test('a canonical handoff is relayed with its exact link (control for the refusals below)', async t => {
  const m = await memory(t, handoffView());
  const reply = await m.invoke(ask);
  assert.equal(reply.isError, false); assert.equal(reply.content.length, 2);
  assert.equal(reply.structuredContent.handoff.url, `${ORIGIN}/continue/${ID}`);
  assert.equal(reply.structuredContent.handoff.expiresAt, expires);
  assert.match(reply.content[0].text, new RegExp(`open ${ORIGIN.replaceAll('.', '\\.')}/continue/${ID} before ${expires}`));
});

test('a handoff whose call id is not a lowercase UUID is refused as invalid_response by invoke and get_call', async t => {
  for (const id of ['job-1', ID.toUpperCase(), `${ID}0`, ID.replaceAll('-', ''), `{${ID}}`, `${ID.slice(0, 35)}g`]) {
    // The link is otherwise exactly origin + /continue/<id>, so only the call id rule can refuse it.
    const m = await memory(t, handoffView({id}));
    assertNotRelayed(await m.invoke(ask), `invoke ${id}`);
    assertNotRelayed(await m.get(id), `get ${id}`);
    assert.equal(m.calls.length, 2, 'one upstream request per tool call, never retried');
  }
});

test('a handoff whose expiry is not canonical ISO with milliseconds and Z is refused as invalid_response', async t => {
  for (const expiresAt of ['2026-10-11T10:30:00Z', '2026-10-11T10:30:00.000+00:00', '2026-10-11T12:30:00.000+02:00', '2026-10-11T10:30:00.000z', '2026-10-11 10:30:00.000Z',
    '2026-10-11T10:30:00.0Z', '+002026-10-11T10:30:00.000Z', '2026-02-30T10:30:00.000Z', 'not-a-date', Date.parse(expires)]) {
    const m = await memory(t, handoffView({}, {expiresAt}));
    assertNotRelayed(await m.invoke(ask), `invoke ${expiresAt}`);
    assertNotRelayed(await m.get(ID), `get ${expiresAt}`);
  }
});

test('a handoff link with a query, fragment, traversal or any other spelling of the route is refused as invalid_response', async t => {
  const urls = [`${ORIGIN}/continue/${ID}?`, `${ORIGIN}/continue/${ID}?next=/approve`, `${ORIGIN}/continue/${ID}#`, `${ORIGIN}/continue/${ID}#approve`,
    `${ORIGIN}/continue/../continue/${ID}`, `${ORIGIN}/continue/${ID}/../${ID}`, `${ORIGIN}/approve/../continue/${ID}`, `${ORIGIN}/continue/%2e%2e/continue/${ID}`, `${ORIGIN}/continue/./${ID}`,
    `${ORIGIN}//continue/${ID}`, `${ORIGIN}/continue/${ID}/`, `${ORIGIN}/Continue/${ID}`, `HTTP://127.0.0.1:47123/continue/${ID}`, `http://owner@127.0.0.1:47123/continue/${ID}`, `/continue/${ID}`, `${ORIGIN}/continue/${ID} `];
  for (const url of urls) {
    const m = await memory(t, handoffView({}, {url}));
    assertNotRelayed(await m.invoke(ask), `invoke ${url}`);
    assertNotRelayed(await m.get(ID), `get ${url}`);
  }
});

const bound = i => ({id: `workspace.op${i}.v1`, connectionId: 'connection', definitionHash: HASH, status: 'available', name: `Operation ${i}`, description: 'Fixture', appId: 'workspace', driver: 'workspace', inputSchema: {type: 'object'}, effect: 'read', approval: 'allow'});
const requestOnly = i => ({id: `github.op${i}.v1`, appId: 'github', connectionId: null, definitionHash: HASH, name: `Request ${i}`, description: '', driver: 'http', inputSchema: {type: 'object'}, effect: 'write', approval: 'after_connection', status: 'connection_required', signIn: 'available'});
const entries = (bindings, requestable) => [...Array.from({length: bindings}, (_, i) => bound(i)), ...Array.from({length: requestable}, (_, i) => requestOnly(i))];

test('fabric_list_capabilities projects a full grant of 100 bound and 50 request-only entries unchanged', async t => {
  const capabilities = entries(100, 50), m = await memory(t, {capabilities});
  const reply = await m.list();
  assert.equal(reply.isError, false);
  assert.equal(reply.structuredContent.capabilities.length, 150);
  assert.deepEqual(reply.structuredContent.capabilities, capabilities);
});

test('fabric_list_capabilities refuses 151 entries as invalid_response, however they are split', async t => {
  for (const [bindings, requestable] of [[100, 51], [101, 50], [151, 0]]) {
    const m = await memory(t, {capabilities: entries(bindings, requestable)});
    const reply = await m.list();
    assert.equal(code(reply), 'invalid_response', `${bindings}+${requestable}`);
    assert.equal(reply.content.length, 1);
  }
});

// Part B: spec item 56, an independent MCP child through a handoff that needs sign-in.

const readback = {kind: 'http-readback', description: 'Read the created issue back', request: {method: 'GET', url: 'https://api.github.com/repos/{owner}/{repo}/issues/{issue}', pathParameters: ['owner', 'repo', 'issue'], queryParameters: []},
  bindings: {owner: {from: 'input', pointer: '/owner', schema: {type: 'string'}}, repo: {from: 'input', pointer: '/repo', schema: {type: 'string'}}, issue: {from: 'response', pointer: '/id', schema: {type: 'string'}}},
  assertions: [{pointer: '/id', equalsResponse: '/id'}]};

test('spec 56: an MCP child relays the sign-in link, the owner signs in, confirms and approves the write, and the agent reads it across a restart until revoked', async t => {
  const f = await fixture(t);
  // The synthetic write carries a reviewed readback so success is independently verified, not merely returned.
  // Its content-addressed id changes, so the application map lists it with the same required scope.
  const write = {...finalizeCapability({...f.write, verification: readback}), status: 'active'}, map = f.app.store.get('applicationMaps', 'github');
  f.app.store.put('capabilities', write); f.app.store.put('applicationMaps', {...map, operations: [...map.operations, {capabilityId: write.id, requiredScopes: ['repo']}]});
  const grant = (await f.json('POST', '/api/clients', {name: 'Agent', bindings: [], requestable: [{capabilityId: write.id}]})).body;
  const cwd = await mkdtemp(path.join(tmpdir(), 'fabric-mcp-handoff-e2e-'));
  const client = new Client({name: 'independent-handoff-e2e', version: '1.0.0'}, {versionNegotiation: {mode: {pin: '2026-07-28'}}});
  const transport = new StdioClientTransport({command: process.execPath, args: [ENTRY], cwd, stderr: 'pipe', env: {FABRIC_ENDPOINT: `${f.app.origin}/fabric/v1`, FABRIC_CLIENT_TOKEN: grant.token}});
  let stderr = ''; transport.stderr.on('data', chunk => { stderr += chunk; });
  t.after(async () => { await client.close(); await rm(cwd, {recursive: true, force: true}); });
  await client.connect(transport);
  const get = callId => client.callTool({name: 'fabric_get_call', arguments: {callId}});

  const listed = await client.callTool({name: 'fabric_list_capabilities', arguments: {}});
  assert.equal(listed.structuredContent.capabilities.length, 1);
  const [entry] = listed.structuredContent.capabilities;
  assert.equal(entry.status, 'connection_required'); assert.equal(entry.connectionId, null); assert.equal(entry.effect, 'write'); assert.equal(entry.signIn, 'available');
  const input = {requestId: 'need-github-write', appId: 'github', capabilityId: write.id, definitionHash: entry.definitionHash, args: {owner: 'o', repo: 'r', body: {title: 'Synthetic'}}};
  const asked = await client.callTool({name: 'fabric_invoke', arguments: input});
  assert.equal(asked.isError, false); assert.equal(asked.structuredContent.status, 'awaiting_connection');
  const callId = asked.structuredContent.id, link = `${f.app.origin}/continue/${callId}`;
  assert.equal(asked.structuredContent.handoff.url, link);
  assert.equal(asked.content[0].text, `Agent asked to use GitHub: Create issue. Waiting for the account owner to connect GitHub. Nothing has run yet. Connect GitHub: ${link} (expires 2026-10-11 10:30 UTC) Fabric continues this exact request after the owner acts. Check progress with fabric_get_call using callId "${callId}". Do not resubmit.`);
  // Fabric's card for the request: who asked, which app, one link to the exact handoff page.
  const askedCard = asked.structuredContent.card;
  assert.equal(askedCard.kind, 'account_request'); assert.equal(askedCard.requester.name, 'Agent'); assert.equal(askedCard.app.name, 'GitHub');
  assert.deepEqual(askedCard.actions, [{type: 'open_url', role: 'primary', label: 'Connect GitHub', url: link}]);

  // The owner opens exactly the relayed link; its path names the handoff.
  const relayed = /Connect GitHub: (\S+) \(expires/.exec(asked.content[0].text)[1];
  const page = await fetch(relayed);
  assert.equal(page.status, 200); assert.match(page.headers.get('content-type'), /^text\/html/); await page.text();
  const id = new URL(relayed).pathname.split('/')[2];
  assert.equal(id, callId);
  const started = await f.signIn(id);
  assert.equal(started.status, 200);
  assert.ok(new URL(started.body.authorizationUrl).searchParams.get('scope').split(' ').includes('repo'), 'sign-in asks for the write scope');
  assert.equal((await f.callback(started)).location, `/continue/${id}`);
  const signedIn = await get(callId);
  assert.equal(signedIn.structuredContent.status, 'awaiting_connection'); assert.equal(signedIn.structuredContent.handoff.state, 'awaiting_confirmation');
  assert.equal(signedIn.structuredContent.handoff.url, link);
  const pending = await f.view(id);
  assert.equal(pending.pendingConnection.identity.displayName, 'octo-a');
  const connectionId = pending.pendingConnection.connectionId;
  const confirmed = await f.json('POST', `/api/continuations/${id}/confirm`, {confirmDigest: pending.confirmDigest});
  assert.equal(confirmed.status, 200, `confirm answered ${confirmed.body.code}`); assert.equal(confirmed.body.phase, 'awaiting_approval');
  assert.deepEqual(f.api, [], 'the derived write waits for its own approval');
  const jobId = confirmed.body.derived.jobId;
  const waiting = await get(callId);
  assert.equal(waiting.isError, false); assert.equal(waiting.structuredContent.status, 'awaiting_approval'); assert.equal(waiting.structuredContent.approvalRequired, true);
  assert.equal(waiting.structuredContent.handoff.state, 'connected'); assert.equal(waiting.structuredContent.handoff.url, null);
  assert.equal(waiting.structuredContent.resumedCallId, jobId); assert.equal(waiting.structuredContent.connectionId, connectionId);
  // The same card now asks for approval, with a link to the owner's approval page for the derived call.
  const approveLink = `${f.app.origin}/approve/${jobId}`;
  assert.deepEqual(waiting.structuredContent.approval, {url: approveLink, expiresAt: waiting.structuredContent.approval.expiresAt});
  assert.equal(waiting.structuredContent.card.kind, 'approval_request'); assert.equal(waiting.structuredContent.card.id, callId); assert.equal(waiting.structuredContent.card.callId, jobId);
  assert.match(waiting.content[0].text, new RegExp(`Waiting for approval in Fabric\\. Nothing has run yet\\. Approve or decline: ${approveLink} \\(expires `));
  const approvalPage = await fetch(approveLink);
  assert.equal(approvalPage.status, 200); assert.match(approvalPage.headers.get('content-type'), /^text\/html/); await approvalPage.text();

  const approved = await f.json('POST', `/api/jobs/${jobId}/approve`, {approvalDigest: confirmed.body.derived.approval.digest});
  assert.equal(approved.status, 200); assert.equal(approved.body.status, 'succeeded');
  assert.deepEqual(f.api.map(req => `${req.method} ${req.url}`), ['POST https://api.github.com/repos/o/r/issues', 'GET https://api.github.com/repos/o/r/issues/synthetic-result'], 'one write and one readback');
  const done = await get(callId);
  assert.equal(done.isError, false); assert.equal(done.structuredContent.status, 'succeeded');
  assert.equal(done.structuredContent.resumedCallId, jobId); assert.equal(done.structuredContent.connectionId, connectionId);
  assert.equal(done.structuredContent.card.kind, 'status'); assert.equal(done.structuredContent.card.summary, 'Done in GitHub.'); assert.deepEqual(done.structuredContent.card.actions, []);
  assert.equal(done.content.length, 1, 'a finished call relays no sentence'); assert.equal('approval' in done.structuredContent, false);
  assert.deepEqual(done.structuredContent.result.data, {id: 'synthetic-result'});
  assert.equal(done.structuredContent.result.verification.status, 'verified'); assert.equal(done.structuredContent.result.verification.kind, 'http-readback');
  assert.deepEqual(done.structuredContent.result.verification.checks, [{pointer: '/id', passed: true}]);
  assert.deepEqual((await get(jobId)).structuredContent.result, done.structuredContent.result, 'the derived call id reads the same result');

  // The same MCP child keeps reading the same call after Fabric restarts on the same loopback port.
  await f.restart();
  const restarted = await get(callId);
  assert.equal(restarted.isError, false);
  assert.deepEqual(restarted.structuredContent, done.structuredContent);
  assert.equal(f.api.length, 2, 'restart never re-dispatches');

  assert.equal((await f.json('POST', `/api/clients/${grant.client.id}/revoke`, {})).status, 200);
  const revokedRead = await get(callId);
  assert.equal(revokedRead.isError, true); assert.equal(code(revokedRead), 'unauthorized');
  const later = await client.callTool({name: 'fabric_invoke', arguments: {...input, requestId: 'after-revoke'}});
  assert.equal(code(later), 'unauthorized');
  assert.equal(code(await client.callTool({name: 'fabric_list_capabilities', arguments: {}})), 'unauthorized');
  assert.equal(f.api.length, 2); assert.equal(f.app.store.list('continuations').length, 1, 'the refused call recorded no new handoff');

  const accessToken = f.app.vault.get(connectionId).accessToken;
  assert.equal(typeof accessToken, 'string');
  for (const output of [asked, signedIn, waiting, done, restarted, revokedRead, later].map(reply => JSON.stringify(reply))) {
    for (const secret of [grant.token, accessToken, 'octo-a', 'Octo A', pending.confirmDigest, confirmed.body.derived.approval.digest]) assert.equal(output.includes(secret), false, 'no grant, credential, identity or digest reaches the agent');
  }
  assert.equal(stderr.includes(grant.token), false);
});

// Part C: FabricClient (lib/fabric-client.mjs).

test('FabricClient.invoke with both or neither of connectionId and appId returns a rejected promise with invalid_request and sends nothing', async () => {
  const sent = [];
  const client = new FabricClient({endpoint: ENDPOINT, token: TOKEN, fetch: async (_url, input) => { const body = JSON.parse(input.body); sent.push(body); return envelope(body, handoffView()); }});
  for (const input of [{connectionId: 'acct-a', appId: 'github', capabilityId: 'github.createIssue', definitionHash: HASH, args: {}}, {capabilityId: 'github.createIssue', definitionHash: HASH, args: {}}]) {
    let pending;
    assert.doesNotThrow(() => { pending = client.invoke(input); }, 'invoke never throws synchronously');
    assert.ok(pending instanceof Promise);
    await assert.rejects(pending, error => error.code === 'invalid_request' && error.message === 'Send exactly one of connectionId or appId.');
  }
  assert.equal(sent.length, 0);
});

test('FabricClient.invoke with appId sends calls.create with the application shape only', async () => {
  const sent = [];
  const client = new FabricClient({endpoint: ENDPOINT, token: TOKEN, fetch: async (_url, input) => { const body = JSON.parse(input.body); sent.push(body); return envelope(body, handoffView()); }});
  assert.deepEqual(await client.invoke({appId: 'github', capabilityId: 'github.createIssue', definitionHash: HASH, args: {title: 'x'}}, {requestId: 'ask-1'}), handoffView());
  assert.equal(sent.length, 1);
  assert.equal(sent[0].method, 'calls.create'); assert.equal(sent[0].id, 'ask-1');
  assert.deepEqual(sent[0].params, {appId: 'github', capabilityId: 'github.createIssue', definitionHash: HASH, args: {title: 'x'}});
});

test('FabricClient.cancelCall sends calls.cancel with exactly the call id and returns the view', async () => {
  const sent = [], cancelled = handoffView({status: 'cancelled'}, {url: null, state: 'closed', outcome: 'client_cancelled'});
  const client = new FabricClient({endpoint: ENDPOINT, token: TOKEN, fetch: async (url, input) => { const body = JSON.parse(input.body); sent.push({url, input, body}); return envelope(body, cancelled); }});
  assert.deepEqual(await client.cancelCall(ID), cancelled);
  assert.equal(sent.length, 1);
  const [{url, input, body}] = sent;
  assert.equal(url, ENDPOINT); assert.equal(input.method, 'POST'); assert.equal(input.redirect, 'error');
  assert.equal(new Headers(input.headers).get('authorization'), `Bearer ${TOKEN}`);
  assert.deepEqual(Object.keys(body).sort(), ['id', 'method', 'params', 'protocol']);
  assert.equal(body.protocol, FABRIC_PROTOCOL); assert.equal(body.method, 'calls.cancel');
  assert.deepEqual(body.params, {callId: ID});
});

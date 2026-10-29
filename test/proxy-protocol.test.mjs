import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {Client} from '@modelcontextprotocol/client';
import {InMemoryTransport} from '@modelcontextprotocol/server';
import {createMcpAdapter} from '../lib/mcp-adapter.mts';
import {FABRIC_PROTOCOL, protocolManifest} from '../lib/fabric-protocol.mjs';
import {owner, fixture, ORIGIN} from './fixtures/continuation-fixture.mjs';
import {approvalPage, activityPage} from '../lib/ui-contracts.mjs';
import {describePage} from '../public/hosted-approve.js';
import {WARNINGS} from '../public/hosted-approval.js';

// F08.0d (docs/F08.0-GOVERNED-PROXY.md sections 2, 3 and 6): the agent surface of the governed proxy. Fixture store,
// injected provider, synthetic accounts that exist only inside each test; every case counts transport calls.
const json = (status, body) => ({status, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(body))});
async function setup(t, rows = ['group:github.issues.read', 'group:github.issues.write', 'other-reads'], {before, expiresInSeconds} = {}) {
  const f = await fixture(t);
  f.account('acct-a', '101');
  f.hooks.request = async () => json(200, [{id: 1}]);
  if (before) before(f);
  const {client, token} = f.protocol.createClient({name: 'Muse', bindings: [], proxy: [{connectionId: 'acct-a', rows}], ...(expiresInSeconds ? {expiresInSeconds} : {})}, owner);
  const proxy = (request, id = `p-${randomUUID()}`, extra = {}) => f.invoke(token, 'proxy.request', {connectionId: 'acct-a', request, ...extra}, id);
  return {f, client, token, proxy};
}

test('the manifest advertises the proxy, and grants name exact rows on exact accounts', async t => {
  assert.ok(protocolManifest.methods.includes('proxy.request')); assert.equal(protocolManifest.features.governedProxy, 'designated-local-only');
  const {f, client, token} = await setup(t);
  // The agent's own view of its grant says who it is, never what it was granted or how it is bound.
  assert.deepEqual(Object.keys((await f.invoke(token, 'fabric.discover', {})).result.client).sort(), ['expiresAt', 'id', 'name']);
  assert.deepEqual(client.proxy.map(entry => entry.rows.map(row => row.row)), [['group:github.issues.read', 'group:github.issues.write', 'other-reads']], 'the owner sees exactly what was granted');
  const stored = f.store.get('clientGrants', client.id).proxy[0];
  assert.deepEqual(stored.rows.map(row => row.row), ['group:github.issues.read', 'group:github.issues.write', 'other-reads']);
  const grant = proxy => () => f.protocol.createClient({name: 'X', bindings: [], proxy}, owner);
  assert.throws(grant([{connectionId: 'missing', rows: ['other-reads']}]), error => error.code === 'invalid_request');
  assert.throws(grant([{connectionId: 'acct-a', rows: ['group:nope']}]), error => error.code === 'invalid_request');
  assert.throws(grant([{connectionId: 'acct-a', rows: ['group:github.permanent.delete']}]), error => error.code === 'permission_denied', 'a Never row cannot be granted');
  assert.throws(grant([{connectionId: 'acct-a', rows: []}]), error => error.code === 'invalid_request');
  assert.throws(grant([{connectionId: 'acct-a', rows: ['other-reads', 'other-reads']}]), error => error.code === 'invalid_request');
  assert.throws(grant([{connectionId: 'acct-a', rows: ['*']}]), error => error.code === 'invalid_request', 'no wildcards');
});

test('a granted read runs and returns the provider answer, Fabric\'s card and what was asked', async t => {
  const {f, proxy} = await setup(t);
  const {result} = await proxy({method: 'GET', path: '/repos/o/r/issues', query: {state: 'open'}});
  assert.equal(result.status, 'succeeded'); assert.deepEqual(result.result.response.body, [{id: 1}]);
  assert.deepEqual(result.request, {method: 'GET', url: 'https://api.github.com/repos/o/r/issues?state=open', row: 'Access issues and pull requests', effect: 'read'});
  assert.equal(result.card.operation.name, 'Access issues and pull requests (GET)', 'Fabric\'s row label, never the agent\'s path'); assert.equal(result.card.summary, 'Read from GitHub.');
  assert.equal(result.capabilityId, 'proxy:group:github.issues.read'); assert.equal(f.calls.length, 1);
});

test('accounts and rows outside the grant are refused before anything is sent; refusals are only counted', async t => {
  const {f, proxy, token} = await setup(t);
  for (const connectionId of ['acct-other', 'missing']) assert.equal((await f.invoke(token, 'proxy.request', {connectionId, request: {method: 'GET', path: '/user'}}, `x-${connectionId}`)).error.code, 'permission_denied', 'the same answer whether or not the account exists');
  assert.equal((await proxy({method: 'GET', path: '/gists'})).error.code, 'row_not_granted');
  assert.equal((await proxy({method: 'DELETE', path: '/repos/o/r'})).error.code, 'row_not_granted');
  assert.equal((await proxy({method: 'GET', path: '/repos/o/r/../x'})).error.code, 'invalid_path');
  assert.equal((await proxy({method: 'GET', path: '/user/emails', headers: {Authorization: 'x'}})).error.code, 'header_not_allowed');
  assert.equal(f.calls.length, 0); assert.equal(f.store.list('jobs').length, 0, 'refusals create no job');
  assert.ok(f.store.list('activity').filter(event => event.type === 'proxy.rejected').length >= 4);
});

test('a change waits for the owner with an approval link and card, then reports uncertain, never done', async t => {
  const {f, proxy, token} = await setup(t);
  f.hooks.request = async () => json(201, {id: 9});
  const asked = (await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'Bug'}}, 'create-1')).result;
  assert.equal(asked.status, 'awaiting_approval'); assert.equal(f.calls.length, 0);
  assert.equal(asked.approval.url, `${ORIGIN}/approve/${asked.id}`); assert.equal(asked.card.kind, 'approval_request');
  const job = f.store.get('jobs', asked.id);
  await f.runtime.approve(job.id, job.approvalDigest, owner);
  const done = (await f.invoke(token, 'calls.get', {callId: asked.id})).result;
  assert.equal(done.status, 'uncertain'); assert.deepEqual(done.result.response.body, {id: 9}); assert.equal(done.errorCode, 'outcome_uncertain');
  assert.equal(done.card.summary, 'Sent to GitHub; the result could not be confirmed. Check before trying again.');
  assert.equal(JSON.stringify(done).includes(job.approvalDigest), false, 'no approval material reaches the agent');
});

test('replays: the same id returns the same call, a different request conflicts, and ids are shared with calls.create', async t => {
  const {f, proxy, token} = await setup(t);
  const first = (await proxy({method: 'GET', path: '/repos/o/r/issues'}, 'same')).result;
  const again = (await proxy({method: 'GET', path: '/repos/o/r/issues'}, 'same')).result;
  assert.equal(again.id, first.id); assert.equal(f.calls.length, 1, 'never sent twice');
  assert.equal((await proxy({method: 'GET', path: '/repos/o/r/pulls'}, 'same')).error.code, 'idempotency_conflict');
  assert.equal((await f.invoke(token, 'calls.create', {connectionId: 'acct-a', capabilityId: f.read.id, definitionHash: 'a'.repeat(64), args: {}}, 'same')).error.code !== undefined, true);
  // A refused request replays as the same refusal.
  assert.equal((await proxy({method: 'GET', path: '/repos/o/r/../x'}, 'bad')).error.code, 'invalid_path');
  assert.equal((await proxy({method: 'GET', path: '/repos/o/r/../x'}, 'bad')).error.code, 'invalid_path');
});

test('the reservation is linked to the job before anything is sent', async t => {
  const {f, proxy, client} = await setup(t);
  let seen = null;
  f.hooks.request = async () => {seen = f.store.list('protocolRequests').find(entry => entry.requestId === 'linked'); return json(200, []);};
  await proxy({method: 'GET', path: '/repos/o/r/issues'}, 'linked');
  assert.equal(seen?.status, 'recorded'); assert.ok(seen.jobId); assert.equal(seen.clientId, client.id);
});

test('a sent request always reports its status to its agent; only its data is withheld once authority changes', async t => {
  const {f, proxy, token} = await setup(t);
  f.hooks.request = async () => json(201, {id: 3});
  const asked = (await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'x'}})).result;
  const job = f.store.get('jobs', asked.id);
  await f.runtime.approve(job.id, job.approvalDigest, owner);
  f.runtime.proxyPolicy.set({connectionId: 'acct-a', row: 'group:github.issues.write', mode: 'deny'});
  const later = (await f.invoke(token, 'calls.get', {callId: asked.id})).result;
  assert.equal(later.status, 'uncertain'); assert.equal(later.result, null); assert.equal(later.resultWithheld, true);
  assert.match(later.error, /not independently verified/); assert.equal(/prepare a new request/i.test(later.error), false, 'never told to prepare a new request for a change that was sent');
  f.runtime.proxyPolicy.set({connectionId: 'acct-a', row: 'group:github.issues.write', mode: 'ask'});
  const pending = (await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'y'}})).result;
  f.runtime.proxyPolicy.set({connectionId: 'acct-a', row: 'group:github.issues.write', mode: 'deny'});
  assert.equal((await f.invoke(token, 'calls.get', {callId: pending.id})).error.code, 'permission_denied', 'a pending request needs current authority');
});

test('a reauthorized account, a revoked client and the pending limit all stop new requests', async t => {
  const {f, proxy, token, client} = await setup(t);
  for (let i = 0; i < 20; i++) assert.equal((await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: `t${i}`}})).result.status, 'awaiting_approval');
  assert.equal((await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'one more'}})).error.code, 'pending_limit');
  f.store.put('connections', {...f.store.get('connections', 'acct-a'), authRevision: 'consent-new'});
  assert.equal((await proxy({method: 'GET', path: '/repos/o/r/issues'})).error.code, 'grant_changed');
  f.protocol.revokeClient(client.id);
  assert.equal((await f.invoke(token, 'proxy.request', {connectionId: 'acct-a', request: {method: 'GET', path: '/user'}}, 'after')).error.code, 'unauthorized');
  assert.equal(f.calls.length, 0);
});

test('grants are bound separately to the account\'s generation and to each row\'s binding', async t => {
  const scoped = await setup(t);
  scoped.f.store.put('connections', {...scoped.f.store.get('connections', 'acct-a'), scopes: ['repo']});
  assert.equal((await scoped.proxy({method: 'GET', path: '/repos/o/r/issues'})).error.code, 'grant_changed', 'a new generation (here: scopes) needs a new grant');
  const renamed = await setup(t);
  const connection = renamed.f.store.get('connections', 'acct-a');
  renamed.f.store.put('connections', {...connection, identity: {...connection.identity, displayName: 'someone-else'}});
  assert.equal((await renamed.proxy({method: 'GET', path: '/repos/o/r/issues'})).error.code, 'grant_changed', 'a different identity on the same generation needs a new grant');
});

test('a request refused after it was reserved replays as the same refusal', async t => {
  const {f, proxy} = await setup(t);
  f.runtime.proxyPolicy.set({connectionId: 'acct-a', row: 'group:github.issues.read', mode: 'deny'});
  assert.equal((await proxy({method: 'GET', path: '/repos/o/r/issues'}, 'never')).error.code, 'policy_denied');
  assert.equal((await proxy({method: 'GET', path: '/repos/o/r/issues'}, 'never')).error.code, 'policy_denied');
  assert.equal(f.store.list('protocolRequests').find(entry => entry.requestId === 'never').code, 'policy_denied'); assert.equal(f.calls.length, 0);
});

test('clients cannot approve or cancel proxied requests', async t => {
  const {f, proxy, token} = await setup(t);
  const asked = (await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'x'}})).result;
  assert.equal((await f.invoke(token, 'jobs.approve', {callId: asked.id})).error.code, 'method_not_found');
  assert.equal((await f.invoke(token, 'calls.cancel', {callId: asked.id})).error.code, 'unsupported_route');
  assert.equal(f.calls.length, 0);
});

test('capabilities.list shows each granted account and row with its current mode, and nothing else', async t => {
  const {f, token} = await setup(t);
  const listed = (await f.invoke(token, 'capabilities.list', {})).result;
  assert.deepEqual(listed.proxy, [{connectionId: 'acct-a', appId: 'github', status: 'available', rows: [
    {row: 'group:github.issues.read', label: 'Access issues and pull requests', effect: 'read', approval: 'allow'},
    {row: 'group:github.issues.write', label: 'Create and edit issues', effect: 'write', approval: 'ask'},
    {row: 'other-reads', label: 'Other reads', effect: 'read', approval: 'ask'}]}]);
});

test('legacy stores refuse proxy grants and requests', async t => {
  const f = await fixture(t, {authority: null});
  f.account('acct-a', '101');
  assert.throws(() => f.protocol.createClient({name: 'X', bindings: [], proxy: [{connectionId: 'acct-a', rows: ['other-reads']}]}), error => error.code === 'unsupported_route');
});

// ---- MCP ----------------------------------------------------------------------------------
const TOKEN = `fab_client.${randomUUID()}.${'a'.repeat(43)}`, MCP = 'http://127.0.0.1:47123';
async function adapter(t, reply) {
  const calls = [];
  const fetch = async (_url, input) => {const body = JSON.parse(input.body); calls.push(body); return new Response(JSON.stringify({protocol: FABRIC_PROTOCOL, id: body.id, result: typeof reply === 'function' ? reply(body) : reply}), {headers: {'content-type': 'application/json'}});};
  const server = createMcpAdapter({env: {FABRIC_ENDPOINT: `${MCP}/fabric/v1`, FABRIC_CLIENT_TOKEN: TOKEN}, fetch, timeoutMs: 1000}), client = new Client({name: 'proxy-test', version: '1.0.0'});
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => {await client.close(); await server.close();});
  return {calls, call: args => client.callTool({name: 'fabric_proxy_request', arguments: args}), list: () => client.callTool({name: 'fabric_list_capabilities', arguments: {}})};
}
const AT = '2026-10-12T12:00:00.000Z', ID = '9a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d';
const proxyView = (extra = {}) => ({id: ID, status: 'succeeded', connectionId: 'acct-a', capabilityId: 'proxy:group:github.issues.read', createdAt: AT, updatedAt: AT, result: {response: {status: 200, body: [{id: 1}]}},
  error: null, approvalRequired: false, errorCode: null, reason: null, request: {method: 'GET', url: 'https://api.github.com/repos/o/r/issues', row: 'Access issues and pull requests', effect: 'read'}, ...extra});

test('MCP sends proxy.request with exactly the caller\'s request and projects only what it checked', async t => {
  const m = await adapter(t, proxyView());
  const reply = await m.call({requestId: 'r1', connectionId: 'acct-a', request: {method: 'GET', path: '/repos/o/r/issues', query: {state: 'open'}}, task: {title: 'Find bugs'}});
  assert.equal(reply.isError, false); assert.deepEqual(m.calls[0].params, {connectionId: 'acct-a', request: {method: 'GET', path: '/repos/o/r/issues', query: {state: 'open'}}, task: {title: 'Find bugs'}});
  assert.equal(m.calls[0].method, 'proxy.request'); assert.equal(m.calls[0].id, 'r1');
  assert.deepEqual(reply.structuredContent.request, proxyView().request); assert.deepEqual(reply.structuredContent.result, {response: {status: 200, body: [{id: 1}]}});
  for (const bad of [{capabilityId: 'cap-typed'}, {connectionId: 'acct-b'}, {request: {...proxyView().request, url: 'http://evil.example/'}}, {request: {...proxyView().request, extra: 1}}, {errorCode: 'Bad Code'}, {resultWithheld: false}]) {
    const refused = await (await adapter(t, proxyView(bad))).call({requestId: 'r2', connectionId: 'acct-a', request: {method: 'GET', path: '/x'}});
    assert.equal(refused.structuredContent?.error?.code, 'invalid_response', JSON.stringify(bad));
  }
  const invalid = await (await adapter(t, proxyView())).call({requestId: 'r3', connectionId: 'acct-a', request: {method: 'TRACE', path: '/x'}});
  assert.equal(invalid.structuredContent?.error?.code, 'invalid_request', 'the tool schema refuses other methods');
});

test('MCP relays proxy refusals with fixed text and lists the proxy section it checked', async t => {
  const errorReply = code => async (_url, input) => {const body = JSON.parse(input.body); return new Response(JSON.stringify({protocol: FABRIC_PROTOCOL, id: body.id, error: {code, message: 'server text never relayed'}}), {headers: {'content-type': 'application/json'}});};
  for (const code of ['row_not_granted', 'invalid_path', 'policy_denied', 'header_not_allowed']) {
    const server = createMcpAdapter({env: {FABRIC_ENDPOINT: `${MCP}/fabric/v1`, FABRIC_CLIENT_TOKEN: TOKEN}, fetch: errorReply(code), timeoutMs: 1000}), client = new Client({name: 'e', version: '1.0.0'});
    const [left, right] = InMemoryTransport.createLinkedPair(); await server.connect(left); await client.connect(right);
    const reply = await client.callTool({name: 'fabric_proxy_request', arguments: {requestId: 'e1', connectionId: 'acct-a', request: {method: 'GET', path: '/x'}}});
    assert.equal(reply.structuredContent.error.code, code); assert.equal(JSON.stringify(reply).includes('server text'), false);
    await client.close(); await server.close();
  }
  const section = [{connectionId: 'acct-a', appId: 'github', status: 'available', rows: [{row: 'other-reads', label: 'Other reads', effect: 'read', approval: 'ask'}]}];
  const listed = await (await adapter(t, {capabilities: [], proxy: section})).list();
  assert.deepEqual(listed.structuredContent.proxy, section);
  const forged = await (await adapter(t, {capabilities: [], proxy: [{...section[0], rows: [{row: 'x', label: 'y', effect: 'write', approval: 'always'}]}]})).list();
  assert.equal(forged.structuredContent.error.code, 'invalid_response');
});

// ---- F08.0d review fixes ---------------------------------------------------------------
test('an Other-row grant is bound to every reviewed row: moving an endpoint out of one needs a new grant', async t => {
  const {f, proxy} = await setup(t, ['other-reads']);
  assert.equal((await proxy({method: 'GET', path: '/gists'})).error.code, 'row_not_granted');
  const github = f.runtime.proxyPolicy.groups.get('github');
  const narrowed = {...github, groups: github.groups.map(group => group.id === 'github.gists.read' ? {...group, requests: group.requests.filter(request => request !== 'GET /gists')} : group)};
  f.runtime.proxyPolicy.groups = new Map([...f.runtime.proxyPolicy.groups, ['github', narrowed]]);
  assert.equal((await proxy({method: 'GET', path: '/gists'})).error.code, 'grant_changed'); assert.equal(f.calls.length, 0);
});

test('a crash between writing the job and linking its reservation still replays as that job', async t => {
  const {f, proxy} = await setup(t);
  const put = f.store.put.bind(f.store);
  let broken = true;
  f.store.put = (collection, document) => {if (broken && collection === 'protocolRequests' && document.status === 'recorded') throw new Error('crash'); return put(collection, document);};
  await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'Bug'}}, 'file-bug');
  broken = false;
  const replay = (await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'Bug'}}, 'file-bug')).result;
  assert.equal(replay.status, 'awaiting_approval'); assert.equal(f.store.list('jobs').length, 1);
  assert.equal(f.store.list('protocolRequests').find(entry => entry.requestId === 'file-bug').jobId, replay.id);
});

test('refusals are rate limited per client', async t => {
  const {proxy} = await setup(t);
  for (let i = 0; i < 60; i++) assert.equal((await proxy({method: 'GET', path: '/gists'})).error.code, 'row_not_granted');
  assert.equal((await proxy({method: 'GET', path: '/gists'})).error.code, 'rate_limited');
});

test('response bodies live in their own store, expire after 7 days and stop at the holder\'s quota', async t => {
  const {f, proxy, token} = await setup(t, undefined, {expiresInSeconds: 30 * 86400});
  f.hooks.request = async () => json(200, {big: 'x'.repeat(200)});
  const first = (await proxy({method: 'GET', path: '/repos/o/r/issues'})).result;
  assert.deepEqual(first.result.response.body, {big: 'x'.repeat(200)}); assert.equal(first.result.response.payload, 'stored');
  assert.equal(JSON.stringify(f.store.get('jobs', first.id)).includes('xxxxx'), false, 'the job record holds no body');
  f.runtime.proxyResponseQuota = 300;
  const second = (await proxy({method: 'GET', path: '/repos/o/r/issues'})).result;
  assert.equal(second.result.response.payload, 'over_quota'); assert.equal(second.status, 'succeeded');
  f.advance(7 * 24 * 60 * 60 * 1000 + 1);
  const later = (await f.invoke(token, 'calls.get', {callId: first.id})).result;
  assert.equal(later.result.response.payload, 'expired'); assert.equal('body' in later.result.response, false);
});

test('proxy cards and the approval page name Fabric\'s row, never the agent\'s path, and show the warnings', async t => {
  const {f, proxy} = await setup(t, ['group:github.issues.write', 'other-changes', 'other-deletes'], {before: f => f.runtime.proxyPolicy.set({connectionId: 'acct-a', row: 'other-deletes', mode: 'ask'})});
  const path = `/repos/o/r/Read-only-status-check-safe-to-approve/${'x'.repeat(65)}/delete-all-branches`;
  const odd = (await proxy({method: 'POST', path, body: {}})).result;
  assert.equal(odd.card.operation.name, 'Other changes (POST)'); assert.equal(JSON.stringify(odd.card).includes('safe-to-approve'), false);
  const removal = (await proxy({method: 'DELETE', path: '/zz/foo/bar'})).result;
  const page = describePage(approvalPage(f.store.get('jobs', removal.id), {appName: () => 'GitHub', now: f.now}));
  assert.equal(page.heading, 'Other deletes (DELETE) in GitHub');
  assert.ok(page.notes.includes(WARNINGS.delete) && page.notes.includes(WARNINGS.not_reviewed));
  const lines = activityPage({jobs: f.store.list('jobs'), now: f.now}).days.flatMap(day => day.items.map(item => item.title));
  assert.ok(lines.includes('Other deletes (DELETE)') && lines.includes('Other changes (POST)'));
  // An unconfirmed earlier change is called out on the next approval.
  f.hooks.request = async () => json(201, {});
  const first = (await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'a'}})).result, job = f.store.get('jobs', first.id);
  await f.runtime.approve(job.id, job.approvalDigest, owner);
  const second = (await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'b'}})).result;
  assert.ok(describePage(approvalPage(f.store.get('jobs', second.id), {appName: () => 'GitHub', now: f.now})).notes.includes(WARNINGS.duplicate_of_uncertain));
});

test('a call that is already on the wire stays readable after a settings change, without its data', async t => {
  const {f, proxy, token} = await setup(t);
  let midway = null;
  const asked = (await proxy({method: 'POST', path: '/repos/o/r/issues', body: {title: 'x'}})).result;
  f.hooks.request = async () => {
    f.runtime.proxyPolicy.set({connectionId: 'acct-a', row: 'group:github.issues.write', mode: 'deny'});
    midway = await f.invoke(token, 'calls.get', {callId: asked.id});
    return json(201, {});
  };
  const job = f.store.get('jobs', asked.id);
  await f.runtime.approve(job.id, job.approvalDigest, owner);
  assert.equal(midway.result.status, 'running'); assert.equal(midway.result.resultWithheld, true);
});

test('a restart leaves an uncertain proxied call with its error code', async t => {
  const {f, proxy} = await setup(t);
  f.runtime.proxyPolicy.set({connectionId: 'acct-a', row: 'group:github.issues.read', mode: 'allow'});
  f.hooks.request = () => new Promise(() => {});
  proxy({method: 'GET', path: '/repos/o/r/issues'}, 'crash-1');
  await new Promise(resolve => setImmediate(resolve)); await new Promise(resolve => setImmediate(resolve));
  f.reopen();
  const job = f.store.list('jobs')[0];
  assert.deepEqual([job.status, job.errorCode, job.reason], ['uncertain', 'outcome_uncertain', 'restarted']);
});

test('the MCP tool schema refuses non-string query and header values before anything is sent', async t => {
  const m = await adapter(t, {});
  for (const request of [{method: 'GET', path: '/x', query: {per_page: 5}}, {method: 'GET', path: '/x', headers: {'If-None-Match': 5}}]) {
    const reply = await m.call({requestId: 'q1', connectionId: 'acct-a', request});
    assert.equal(reply.structuredContent.error.code, 'invalid_request', JSON.stringify(request));
  }
  assert.equal(m.calls.length, 0);
});

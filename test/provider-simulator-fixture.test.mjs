import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {FixtureSimulator, CANARY, REST_ORIGIN, RPC_BASE} from './fixtures/provider-simulators/fixture.mjs';
import {actionHarness} from './fixtures/actions/runtime-fixture.mjs';

// F10.11 part b (docs/F10.11-BUILD-MAP.md part b and section 3): the fake app's provider simulator. The action runtime's tests send their
// requests to it through the network seam, so it must keep the seam's contract (lib/network.mjs) and its own documented behaviour. It is
// written from its own header comment, never from the fixture's action, permission, proxy or map files, so a runtime bug and a simulator
// bug cannot cancel out.
const TOKEN = 'fixture-token-7c1d', AUTH = {Authorization: `Bearer ${TOKEN}`};
const ORIGINS = [REST_ORIGIN, new URL(RPC_BASE).origin];
const sim = (options = {}) => new FixtureSimulator({token: TOKEN, ...options});
/** One request through the seam, with the account's token unless `headers` says otherwise. */
const send = (simulator, method, path, {body, headers = AUTH, query, rpc = false, ...more} = {}) => {
  const url = new URL(rpc ? `${RPC_BASE}${path}` : `${REST_ORIGIN}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) for (const item of [value].flat()) url.searchParams.append(name, String(item));
  return simulator.request({url: url.href, method, headers: {...headers, ...(body === undefined ? {} : {'Content-Type': 'application/json'})}, ...(body === undefined ? {} : {body: JSON.stringify(body)}), allowedOrigins: ORIGINS, ...more});
};

test('the seam: only the headers the request asked for come back, an answer over maxBytes throws sent true, a body over 1 MiB throws sent false', async () => {
  const simulator = sim();
  const event = await send(simulator, 'GET', '/events/E1');
  assert.deepEqual(Object.keys(event.headers).sort(), ['content-type', 'etag'], 'the default list: content-type, etag, retry-after, x-ratelimit-remaining');
  const linked = await send(simulator, 'GET', '/items', {query: {page: 1}, responseHeaders: ['link']});
  assert.deepEqual(Object.keys(linked.headers), ['link']);
  assert.deepEqual(Object.keys((await send(simulator, 'GET', '/items', {query: {page: 1}})).headers), ['content-type'], 'Link only when asked for');
  await assert.rejects(send(simulator, 'GET', '/items', {maxBytes: 64}), error => error.sent === true && /exceeded the size limit/.test(error.message));
  await assert.rejects(send(simulator, 'POST', '/messages', {body: {to: 'a@fixture.test', text: 'x'.repeat(1024 * 1024)}}), error => error.sent === false && /too large/.test(error.message));
  assert.equal(simulator.writes().length, 0, 'a body refused before sending never reaches the provider');
  // Refused before sending, as lib/network.mjs refuses them.
  for (const [label, request] of [['an origin outside the grant', {url: `${REST_ORIGIN}/items`, method: 'GET', headers: AUTH, allowedOrigins: ['https://other.test']}],
    ['plain http', {url: 'http://api.fixture.test/items', method: 'GET', headers: AUTH, allowedOrigins: ORIGINS}],
    ['an unsafe header', {url: `${REST_ORIGIN}/items`, method: 'GET', headers: {...AUTH, Host: 'x'}, allowedOrigins: ORIGINS}],
    ['a body that is not serialized', {url: `${REST_ORIGIN}/messages`, method: 'POST', headers: AUTH, body: {to: 'x'}, allowedOrigins: ORIGINS}],
    ['an unknown origin', {url: 'https://elsewhere.test/items', method: 'GET', headers: AUTH, allowedOrigins: ['https://elsewhere.test']}]]) {
    await assert.rejects(simulator.request(request), error => error.sent === false, label);
  }
  assert.equal(simulator.calls.length, 4, 'the refused requests were never recorded');
});

test('401 without the token, and the RPC twin answers ok false with HTTP 200; calls are recorded without the Authorization header', async () => {
  const simulator = sim();
  assert.deepEqual(await send(simulator, 'GET', '/items/I1', {headers: {}}).then(answer => [answer.status, answer.data]), [401, {error: 'unauthorized'}]);
  assert.equal((await send(simulator, 'GET', '/items/I1', {headers: {Authorization: 'Bearer wrong'}})).status, 401);
  const rpc = await send(simulator, 'POST', '/messages.post', {rpc: true, headers: {}, body: {channel: 'C1', text: 'hi'}});
  assert.deepEqual([rpc.status, rpc.data], [200, {ok: false, error: 'not_authed'}]);
  assert.deepEqual(await send(simulator, 'POST', '/canvases.read', {rpc: true, body: {canvas_id: 'F404'}}).then(answer => [answer.status, answer.data]), [200, {ok: false, error: 'canvas_not_found'}]);
  const posted = await send(simulator, 'POST', '/messages.post', {rpc: true, body: {channel: 'C1', text: 'hello'}});
  assert.deepEqual([posted.status, posted.data.ok, posted.data.channel], [200, true, 'C1']);
  assert.equal(JSON.stringify(simulator.calls).includes(TOKEN), false, 'the token is never recorded');
  assert.ok(simulator.calls.every(call => !Object.keys(call.headers).some(name => /authorization/i.test(name))));
  assert.equal(simulator.state().rpc.channels.C1.messages.at(-1).text, 'hello');
});

test('paging: GET /items pages by token and by a Link header, newest first, two items a page', async () => {
  const simulator = sim(), ids = [];
  let token;
  do {
    const page = await send(simulator, 'GET', '/items', {query: token ? {pageToken: token} : {}});
    ids.push(...page.data.items.map(item => item.id));
    assert.equal(page.data.hasMore, Boolean(page.data.nextPageToken));
    token = page.data.nextPageToken;
  } while (token);
  assert.deepEqual(ids, ['I5', 'I4', 'I3', 'I2', 'I1']);
  const linked = [];
  for (let page = 1; page; ) {
    const answer = await send(simulator, 'GET', '/items', {query: {page}, responseHeaders: ['link']});
    linked.push(...answer.data.items.map(item => item.id));
    const next = /<([^>]+)>;\s*rel="next"/.exec(answer.headers.link ?? '');
    page = next ? Number(new URL(next[1]).searchParams.get('page')) : 0;
  }
  assert.deepEqual(linked, ids);
  // Filters: kind, labelIds (repeated) and updatedAfter.
  assert.deepEqual((await send(simulator, 'GET', '/items', {query: {kind: 'note'}})).data.items.map(item => item.kind), ['note', 'note']);
  assert.deepEqual((await send(simulator, 'GET', '/items', {query: {labelIds: ['L2']}})).data.items.map(item => item.id), ['I3', 'I1']);
  assert.deepEqual((await send(simulator, 'GET', '/items', {query: {updatedAfter: '2026-10-20T00:00:00.000Z'}})).data.items.map(item => item.id), ['I5', 'I4']);
  assert.equal(simulator.writes().length, 0);
});

test('files: a PUT with a stale sha answers 409 and changes nothing; with the current sha it updates; search changes nothing and export writes', async () => {
  const simulator = sim(), before = await send(simulator, 'GET', '/files/docs/a.md');
  assert.deepEqual([before.status, before.data.path, typeof before.data.sha], [200, 'docs/a.md', 'string']);
  assert.equal((await send(simulator, 'GET', '/files/docs/none.md')).status, 404);
  const stale = await send(simulator, 'PUT', '/files/docs/a.md', {body: {message: 'm', content: Buffer.from('new').toString('base64'), sha: 'f'.repeat(40)}});
  assert.equal(stale.status, 409);
  assert.equal(simulator.state().files['docs/a.md'].sha, before.data.sha, 'nothing changed');
  const updated = await send(simulator, 'PUT', '/files/docs/a.md', {body: {message: 'm', content: Buffer.from('new').toString('base64'), sha: before.data.sha}});
  assert.deepEqual([updated.status, updated.data.content.path], [200, 'docs/a.md']);
  assert.notEqual(updated.data.content.sha, before.data.sha);
  const created = await send(simulator, 'PUT', '/files/docs/b.md', {body: {message: 'm', content: Buffer.from('b').toString('base64')}});
  assert.equal(created.status, 201);
  const state = JSON.stringify(simulator.state());
  const found = await send(simulator, 'POST', '/items/search', {body: {query: 'plan'}});
  assert.deepEqual([found.status, found.data.results.map(result => result.id)], [200, ['I4', 'I2']]);
  assert.equal(JSON.stringify(simulator.state()), state, 'search changes nothing');
  const exported = await send(simulator, 'POST', '/items/export', {body: {kind: 'note'}});
  assert.equal(exported.status, 200);
  assert.equal(simulator.state().exports.length, 1, 'export really writes');
  assert.deepEqual(simulator.writes().map(call => call.route), ['PUT /files/{+path}', 'PUT /files/{+path}', 'PUT /files/{+path}', 'POST /items/export']);
  assert.deepEqual(simulator.reads().map(call => call.route), ['GET /files/{+path}', 'GET /files/{+path}', 'POST /items/search']);
});

test('events: a PATCH with a stale If-Match answers 412 and changes nothing; drafts send once and are gone', async () => {
  const simulator = sim(), event = await send(simulator, 'GET', '/events/E1');
  assert.equal((await send(simulator, 'PATCH', '/events/E1', {headers: {...AUTH, 'If-Match': '"0"'}, body: {start: '2026-10-30T10:00:00Z', end: '2026-10-30T11:00:00Z'}})).status, 412);
  assert.equal(simulator.state().events.E1.start, event.data.start);
  const moved = await send(simulator, 'PATCH', '/events/E1', {headers: {...AUTH, 'If-Match': event.headers.etag}, body: {start: '2026-10-30T10:00:00Z', end: '2026-10-30T11:00:00Z'}});
  assert.deepEqual([moved.status, moved.data.start], [200, '2026-10-30T10:00:00Z']);
  assert.notEqual(moved.headers.etag, event.headers.etag);
  const draft = await send(simulator, 'GET', '/drafts/D1');
  const sent = await send(simulator, 'POST', '/drafts/D1/send', {body: {raw: draft.data.raw, sender: 'acct-1'}});
  assert.equal(sent.status, 200);
  assert.equal((await send(simulator, 'GET', `/items/${sent.data.id}`)).data.kind, 'sent');
  assert.equal((await send(simulator, 'GET', '/drafts/D1')).status, 404);
});

test('the switches: fail answers instead, drop applies then throws sent true, swallow answers without applying, hold waits for release', async () => {
  const simulator = sim();
  simulator.fail('PATCH /items/{item_id}', {status: 429, headers: {'retry-after': '30'}, data: {error: 'slow down'}});
  const limited = await send(simulator, 'PATCH', '/items/I1', {body: {name: 'Renamed'}});
  assert.deepEqual([limited.status, limited.headers['retry-after'], limited.data], [429, '30', {error: 'slow down'}]);
  assert.equal(simulator.state().items.find(item => item.id === 'I1').name, 'Plan A', 'a failed answer changes nothing');
  assert.equal((await send(simulator, 'PATCH', '/items/I1', {body: {name: 'Renamed'}})).status, 200, 'fail is one answer by default');
  simulator.fail('GET /labels', {status: 503, data: {error: 'down'}}, {times: 2});
  assert.deepEqual([(await send(simulator, 'GET', '/labels')).status, (await send(simulator, 'GET', '/labels')).status, (await send(simulator, 'GET', '/labels')).status], [503, 503, 200]);
  simulator.drop('POST /messages');
  await assert.rejects(send(simulator, 'POST', '/messages', {body: {to: 'a@fixture.test', text: 'dropped'}}), error => error.sent === true);
  assert.equal(simulator.state().messages.at(-1).text, 'dropped', 'drop applies the write, then the answer is lost');
  simulator.swallow('PATCH /items/{item_id}');
  const swallowed = await send(simulator, 'PATCH', '/items/I2', {body: {name: 'Never applied'}});
  assert.deepEqual([swallowed.status, swallowed.data.name], [200, 'Never applied']);
  assert.notEqual(simulator.state().items.find(item => item.id === 'I2').name, 'Never applied', 'a readback sees the old value');
  simulator.oversize('GET /labels', 4096);
  await assert.rejects(send(simulator, 'GET', '/labels', {maxBytes: 4000}), error => error.sent === true);
  const gate = simulator.hold('PATCH /items/{item_id}');
  let done = false;
  const held = send(simulator, 'PATCH', '/items/I3', {body: {name: 'Held'}}).then(answer => { done = true; return answer; });
  await gate.reached;
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(done, false, 'held until released');
  assert.notEqual(simulator.state().items.find(item => item.id === 'I3').name, 'Held');
  gate.release();
  assert.equal((await held).status, 200);
  assert.equal(simulator.state().items.find(item => item.id === 'I3').name, 'Held');
  // A redirect or a 304 comes back only through report, as the seam does.
  simulator.fail('GET /items/{item_id}', {status: 302, headers: {location: `${REST_ORIGIN}/items/I2`}});
  await assert.rejects(send(simulator, 'GET', '/items/I1'), error => error.sent === true && /redirects are not followed/.test(error.message));
  simulator.fail('GET /items/{item_id}', {status: 304});
  assert.deepEqual(await send(simulator, 'GET', '/items/I1', {redirect: 'report'}).then(answer => [answer.status, answer.notModified]), [304, true]);
});

test('the canary secret appears only in GET /keys/{key_id}; locked routes answer only so a test can see they were called', async () => {
  const simulator = sim(), seen = [];
  for (const [method, path, body] of [['GET', '/accounts/me/profile'], ['GET', '/items'], ['GET', '/items/I1'], ['GET', '/labels'], ['GET', '/labels/L2'], ['GET', '/drafts/D1'], ['GET', '/events/E1'],
    ['GET', '/files/docs/a.md'], ['POST', '/items/search', {query: 'plan'}], ['GET', '/keys'], ['GET', '/keys/K1'], ['GET', '/items/I1/history']]) {
    const answer = await send(simulator, method, path, body === undefined ? {} : {body});
    assert.equal(answer.status, 200, path);
    if (JSON.stringify(answer).includes(CANARY)) seen.push(path);
  }
  assert.deepEqual(seen, ['/keys/K1']);
  for (const [method, path] of [['PUT', '/items/I1/share'], ['POST', '/hooks'], ['DELETE', '/hooks/H1']]) assert.equal((await send(simulator, method, path, {body: {}})).status, 200, path);
  assert.deepEqual(simulator.calls.filter(call => call.locked).map(call => call.route), ['PUT /items/{item_id}/share', 'POST /hooks', 'DELETE /hooks/{hook_id}']);
  assert.ok(simulator.calls.filter(call => call.locked).every(call => call.write));
});

test('the simulator imports nothing from the fixture action, permission, proxy or map files, nor from the action modules', () => {
  const text = readFileSync(new URL('./fixtures/provider-simulators/fixture.mjs', import.meta.url), 'utf8');
  const imports = [...text.matchAll(/(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(['"])([^'"]+)\1/g)].map(match => match[2]);
  assert.ok(imports.length > 0);
  assert.ok(imports.every(specifier => specifier.startsWith('node:')), `node built-ins only: ${imports.join(', ')}`);
});

test('the harness: the certified fixture actions seeded active on two ready accounts, and the simulator behind the runtime\'s seam', async t => {
  const h = actionHarness(t, {designated: true});
  assert.deepEqual([...h.catalog.entries.values()].map(item => [item.entry.key, item.status]), ['list-items', 'update-item', 'remove-labels', 'put-file', 'reschedule-event', 'send-draft', 'add-row'].map(key => [key, 'active']));
  assert.deepEqual(Object.fromEntries(h.catalog.refused), {});
  for (const item of h.catalog.entries.values()) assert.deepEqual(h.store.get('capabilities', item.entry.id), item.capability);
  assert.deepEqual(h.store.list('connections').map(connection => [connection.id, connection.status]), [['fixture-account', 'ready'], ['fixture-rpc-account', 'ready']]);
  assert.equal(h.runtime.request, h.simulator.request);
  // A proxied read on the fixture account reaches the simulator with the account's token, and is recorded without it.
  const job = await h.runtime.createProxyJob({connectionId: h.account, request: {method: 'GET', path: '/items/I1'}}, h.owner);
  assert.equal(job.status, 'succeeded');
  assert.deepEqual(h.simulator.calls.map(call => [call.route, call.status]), [['GET /items/{item_id}', 200]]);
  // Without the map List items cannot place, and a candidate file seeds candidates.
  const unmapped = actionHarness(t, {map: null});
  assert.equal(unmapped.catalog.entries.get(unmapped.idOf('list-items v1')).status, 'candidate');
  const candidate = actionHarness(t, {file: {...h.file, reviewStatus: 'candidate'}});
  assert.ok([...candidate.catalog.entries.values()].every(item => item.status === 'candidate'));
});

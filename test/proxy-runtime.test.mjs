import test from 'node:test';
import assert from 'node:assert/strict';
import {owner, fixture} from './fixtures/continuation-fixture.mjs';
import {approvalPage, approvalItem} from '../lib/ui-contracts.mjs';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../lib/permission-groups.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {describeApproval} from '../public/hosted-approval.js';

// F08.0c (docs/F08.0-GOVERNED-PROXY.md section 6): proxy jobs through the runtime. Fixture store, an injected
// provider (no network), synthetic accounts that exist only inside each test. Every case counts transport calls.
const TOKEN = 'synthetic-only';
// Response bodies are kept in their own store (7 days, per-holder quota), not on the job.
const kept = (f, job) => f.runtime.proxyResponse(job) || {};
const json = (status, body, headers = {}) => ({status, headers: {'content-type': 'application/json', ...headers}, data: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body))});
async function setup(t, options) {
  const f = await fixture(t, options);
  f.account('acct-a', '101');
  const run = (method, path, extra = {}) => f.runtime.createProxyJob({connectionId: 'acct-a', request: {method, path, ...extra}}, owner);
  const reply = response => { f.hooks.request = async request => (typeof response === 'function' ? response(request) : response); };
  const set = (row, mode, confirmAllow) => f.runtime.proxyPolicy.set({connectionId: 'acct-a', row, mode, confirmAllow});
  return {f, run, reply, set, approve: job => f.runtime.approve(job.id, job.approvalDigest, owner)};
}

test('an allowed read is sent once, exactly as decided, and its JSON comes back observed', async t => {
  const {f, run, reply} = await setup(t);
  reply(json(200, [{id: 1}], {etag: '"e1"', link: '<https://api.github.com/repos/o/r/issues?page=2>; rel="next"'}));
  const job = await run('GET', '/repos/o/r/issues', {query: {per_page: '50', state: 'open'}, headers: {Accept: 'application/vnd.github+json'}});
  assert.equal(job.status, 'succeeded'); assert.equal(f.calls.length, 1);
  const [sent] = f.calls;
  assert.equal(sent.url, 'https://api.github.com/repos/o/r/issues?per_page=50&state=open'); assert.equal(sent.method, 'GET');
  assert.equal(sent.headers.Authorization, `Bearer ${TOKEN}`); assert.equal(sent.headers.Accept, 'application/vnd.github+json', 'the caller\'s reviewed Accept wins');
  assert.equal('body' in sent, false); assert.equal('Content-Type' in sent.headers, false);
  assert.deepEqual([sent.redirect, sent.responseType, sent.maxBytes, sent.allowedOrigins], ['report', 'buffer', 1024 * 1024, ['https://api.github.com']]);
  assert.deepEqual(kept(f, job).body, [{id: 1}]); assert.equal(job.result.response.headers.etag, '"e1"');
  assert.equal(job.result.verification.status, 'observed');
  assert.equal(job.kind, 'proxy'); assert.equal(job.capabilityId, 'proxy:group:github.issues.read');
  const types = f.store.list('activity').map(event => event.type);
  assert.ok(types.includes('proxy.request') && types.includes('proxy.completed'));
});

test('a change asks first, shows exactly what will be sent, and once sent is never reported as done', async t => {
  const {f, run, reply, approve} = await setup(t);
  reply(json(201, {id: 7, title: 'Bug'}));
  const job = await run('POST', '/repos/o/r/issues', {body: {title: 'Bug', labels: ['x']}});
  assert.equal(job.status, 'awaiting_approval'); assert.equal(f.calls.length, 0, 'nothing is sent before approval');
  assert.deepEqual(job.preview.request, {method: 'POST', url: 'https://api.github.com/repos/o/r/issues', headers: {}, body: '{"title":"Bug","labels":["x"]}'});
  assert.deepEqual(job.preview.addedByFabric[0], {name: 'Authorization', value: '(added by Fabric, hidden)'});
  const page = approvalPage(f.store.get('jobs', job.id), {appName: () => 'GitHub', now: f.now});
  assert.deepEqual(page.approval.exact.blocks.map(block => block.label), ['Request', 'Added by Fabric', 'Body']);
  assert.equal(page.approval.exact.blocks.at(-1).text, '{"title":"Bug","labels":["x"]}', 'the body shown is the body sent');
  await assert.rejects(f.runtime.approve(job.id, 'f'.repeat(64), owner), /exact action/);
  const done = await approve(job);
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].body, '{"title":"Bug","labels":["x"]}'); assert.equal(f.calls[0].headers['Content-Type'], 'application/json; charset=utf-8');
  assert.equal(done.status, 'uncertain', 'a 2xx change is sent, not verified'); assert.equal(done.result.verification.status, 'unverified');
  assert.deepEqual(kept(f, done).body, {id: 7, title: 'Bug'}); assert.match(done.error, /not independently verified/);
});

test('Never refuses before a job exists, and a setting changed after acceptance stops the send', async t => {
  const {f, run, set, approve} = await setup(t);
  await assert.rejects(run('DELETE', '/repos/o/r'), error => error.code === 'policy_denied');
  assert.equal(f.store.list('jobs').length, 0); assert.equal(f.calls.length, 0);
  const job = await run('POST', '/repos/o/r/issues', {body: {title: 'x'}});
  set('group:github.issues.write', 'deny');
  await assert.rejects(approve(job), error => ['authority_changed', 'policy_denied'].includes(error.code));
  assert.equal(f.calls.length, 0, 'nothing was sent');
});

test('outcome table: reads fail on errors, changes stay uncertain once sent, redirects are never followed', async t => {
  const cases = [
    ['GET', '/repos/o/r/issues', json(404, {message: 'Not Found'}), 'failed', 'http_status'],
    ['GET', '/repos/o/r/issues', json(429, {message: 'slow down'}, {'retry-after': '30'}), 'failed', 'http_status'],
    ['GET', '/repos/o/r/issues', json(503, {}), 'failed', 'http_status'],
    ['GET', '/repos/o/r/issues', {status: 302, headers: {}, data: null, redirected: true}, 'failed', 'redirect_not_followed'],
    ['POST', '/repos/o/r/issues', json(422, {message: 'Validation Failed'}), 'failed', 'http_status'],
    ['POST', '/repos/o/r/issues', json(409, {}), 'uncertain', 'http_status'],
    ['POST', '/repos/o/r/issues', json(500, {}), 'uncertain', 'http_status'],
    ['POST', '/repos/o/r/issues', {status: 307, headers: {location: 'https://api.github.com/x'}, data: null, redirected: true}, 'uncertain', 'redirect_not_followed'],
  ];
  for (const [method, path, response, status, reason] of cases) {
    const {f, run, reply, approve} = await setup(t);
    reply(response);
    let job = await run(method, path, method === 'GET' ? {} : {body: {title: 'x'}});
    if (job.status === 'awaiting_approval') job = await approve(job);
    assert.deepEqual([job.status, job.reason], [status, reason], `${method} ${response.status}`);
    assert.equal(f.calls.length, 1, 'never retried');
  }
  const {f, run, reply} = await setup(t);
  reply(json(404, {message: 'Not Found'}));
  const missing = await run('GET', '/repos/o/r/issues');
  assert.deepEqual(kept(f, missing).body, {message: 'Not Found'}, 'the provider\'s answer is returned');
});

test('a failure before anything left the machine is failed; one after sending is uncertain for any change, deletes included', async t => {
  const notSent = Object.assign(new Error('Private or reserved network destinations are not allowed.'), {sent: false});
  const timedOut = Object.assign(new Error('Provider request timed out.'), {sent: true});
  const {f, run, reply, set, approve} = await setup(t);
  reply(() => {throw notSent;});
  const blocked = await approve(await run('POST', '/repos/o/r/issues', {body: {title: 'x'}}));
  assert.deepEqual([blocked.status, blocked.errorCode], ['failed', 'fabric_failed']);
  reply(() => {throw timedOut;});
  const lost = await approve(await run('POST', '/repos/o/r/issues', {body: {title: 'y'}}));
  assert.deepEqual([lost.status, lost.reason], ['uncertain', 'timeout']);
  set('group:github.permanent.delete', 'ask');
  // F10.7: deleting a whole repository is never offered (delete_repo is never requested), so a release delete stands in.
  const deletion = await approve(await run('DELETE', '/repos/o/r/releases/1'));
  assert.equal(deletion.effect, 'delete'); assert.deepEqual([deletion.status, deletion.reason], ['uncertain', 'timeout'], 'a timed-out delete is uncertain, never failed');
  const read = await run('GET', '/repos/o/r/issues');
  assert.deepEqual([read.status, read.reason], ['failed', 'timeout']);
  assert.equal(f.calls.length, 4);
});

test('credentials echoed by a provider are redacted in every form, everywhere', async t => {
  const {f, run, reply} = await setup(t);
  reply(json(200, {echo: `Bearer ${TOKEN}`, escaped: JSON.stringify(TOKEN).slice(1, -1), encoded: `x?t=${encodeURIComponent(TOKEN)}`, access_token: 'fresh-token-value', nested: {refresh_token: 'r'}},
    {link: `<https://api.github.com/x?access_token=${TOKEN}>; rel="next"`}));
  const job = await run('GET', '/repos/o/r/issues');
  assert.equal(job.status, 'succeeded'); assert.ok(job.result.response.redactions >= 4);
  assert.equal(kept(f, job).body.access_token, '[redacted]'); assert.equal(kept(f, job).body.nested.refresh_token, '[redacted]');
  reply(() => {throw Object.assign(new Error(`upstream said Bearer ${TOKEN}`), {sent: true});});
  const failed = await run('GET', '/repos/o/r/issues');
  assert.equal(failed.error.includes(TOKEN), false);
  for (const collection of ['jobs', 'activity', 'proxyResponses']) for (const document of f.store.list(collection)) assert.equal(JSON.stringify(document).includes(TOKEN), false, `${collection} holds the token`);
  assert.equal(JSON.stringify([f.store.list('jobs'), f.store.list('proxyResponses')]).includes('fresh-token-value'), false);
});

test('only JSON or text comes back; anything else keeps its size and hash, not its bytes', async t => {
  const {f, run, reply} = await setup(t);
  reply({status: 200, headers: {'content-type': 'image/png'}, data: Buffer.from([0x89, 0x50, 0x4e, 0x47])});
  const image = await run('GET', '/repos/o/r/issues');
  assert.deepEqual([image.status, image.reason], ['failed', 'unsupported_response']);
  assert.equal(image.result.response.bytes, 4); assert.match(image.result.response.sha256, /^[a-f0-9]{64}$/); assert.equal('body' in image.result.response, false); assert.deepEqual(kept(f, image), {});
  reply({status: 200, headers: {'content-type': 'text/plain'}, data: Buffer.from([0xc3, 0x28])});
  assert.equal((await run('GET', '/repos/o/r/issues')).reason, 'unsupported_response', 'invalid UTF-8 is not decoded loosely');
  reply({status: 200, headers: {'content-type': 'text/plain; charset=utf-8'}, data: Buffer.from('plain words')});
  assert.equal(kept(f, await run('GET', '/repos/o/r/issues')).text, 'plain words');
});

test('one change at a time per account, shared with typed writes; an unresolved uncertain change makes the next one ask', async t => {
  const {f, run, reply, set, approve} = await setup(t);
  reply(json(200, {}));
  f.runtime.writeLocks.add('account:acct-a');
  const busy = await approve(await run('POST', '/repos/o/r/issues', {body: {title: 'x'}}));
  assert.deepEqual([busy.status, busy.reason], ['failed', 'write_in_progress']); assert.equal(f.calls.length, 0);
  f.runtime.writeLocks.delete('account:acct-a');
  set('group:github.notifications.manage', 'allow', true);
  const first = await run('PUT', '/notifications', {body: {}});
  assert.equal(first.status, 'uncertain', 'standing Allow sends it; a 2xx change stays uncertain');
  const second = await run('PUT', '/notifications', {body: {}});
  assert.equal(second.status, 'awaiting_approval', 'the next change to that row asks while the first is unresolved');
  assert.ok(second.preview.warnings.includes('duplicate_of_uncertain')); assert.equal(f.calls.length, 1);
  // Approving that request sends it: the Ask recorded at acceptance stands even though the row itself Allows.
  const sentAnyway = await f.runtime.approve(second.id, second.approvalDigest, owner);
  assert.equal(sentAnyway.status, 'uncertain'); assert.equal(f.calls.length, 2);
});

test('a provider header that changes between approval and sending stops the send', async t => {
  const {f, run, reply, approve} = await setup(t);
  reply(json(201, {}));
  let version = '2022-11-28';
  f.runtime.connections = {providers: {providerFor: () => 'github', resolve: () => ({definition: {apiHeaders: {'X-GitHub-Api-Version': '2022-11-28'}}})},
    credentials: async () => ({headers: {'X-GitHub-Api-Version': version, Authorization: `Bearer ${TOKEN}`, Accept: 'application/json'}, allowedOrigins: ['https://api.github.com']})};
  const job = await run('POST', '/repos/o/r/issues', {body: {title: 'x'}});
  assert.ok(job.preview.addedByFabric.some(header => header.name === 'X-GitHub-Api-Version' && header.value === '2022-11-28'));
  version = '2099-01-01';
  const changed = await approve(job);
  assert.deepEqual([changed.status, changed.errorCode], ['failed', 'authority_changed']); assert.equal(f.calls.length, 0);
});

test('authority that changes while a request is in flight withholds the response', async t => {
  const {f, run, reply, set} = await setup(t);
  reply(() => {set('group:github.issues.read', 'deny'); return json(200, {secret: 'data'});});
  const job = await run('GET', '/repos/o/r/issues');
  assert.deepEqual([job.status, job.errorCode, job.result], ['failed', 'authority_changed', null]);
  assert.equal(JSON.stringify(f.store.get('jobs', job.id)).includes('secret'), false);
});

test('the proxy runs only on a designated authority store', async t => {
  const {f, run} = await setup(t, {authority: null});
  assert.equal(f.store.authorityEnabled, false);
  await assert.rejects(run('GET', '/repos/o/r/issues'), error => error.code === 'unsupported_route');
  assert.equal(f.calls.length, 0); assert.equal(f.store.list('jobs').length, 0);
});

test('a token with special characters is redacted in its raw, JSON-escaped and URL-encoded forms', async t => {
  const {f, run, reply} = await setup(t);
  const token = 'tok/en+va"l=ue-123';
  f.runtime.connections = {credentials: async () => ({headers: {Authorization: `Bearer ${token}`}, allowedOrigins: ['https://api.github.com']})};
  reply({status: 200, headers: {'content-type': 'text/plain'}, data: Buffer.from(`raw=${token} json=${JSON.stringify(token).slice(1, -1)} url=${encodeURIComponent(token)}`)});
  const job = await run('GET', '/repos/o/r/issues');
  assert.equal(kept(f, job).text, 'raw=[redacted] json=[redacted] url=[redacted]'); assert.equal(job.result.response.redactions, 3);
});

test('bytes that are not JSON or text are never kept, even when they happen to be valid UTF-8', async t => {
  const {f, run, reply} = await setup(t);
  reply({status: 200, headers: {'content-type': 'application/octet-stream'}, data: Buffer.from('looks like text')});
  const job = await run('GET', '/repos/o/r/issues');
  assert.equal(job.reason, 'unsupported_response'); assert.equal('text' in job.result.response, false); assert.equal('body' in job.result.response, false);
});

test('any settings change after acceptance, even a looser one, needs a new request', async t => {
  const {f, run, set, approve} = await setup(t);
  set('group:github.issues.read', 'ask');
  const job = await run('GET', '/repos/o/r/issues');
  assert.equal(job.status, 'awaiting_approval');
  set('group:github.issues.read', 'allow');
  await assert.rejects(approve(job), error => error.code === 'authority_changed'); assert.equal(f.calls.length, 0);
});

test('a stored job cannot be pushed past its approval', async t => {
  const {f, run} = await setup(t);
  const job = await run('POST', '/repos/o/r/issues', {body: {title: 'x'}});
  f.store.put('jobs', {...f.store.get('jobs', job.id), status: 'queued', approvedAt: new Date(f.now).toISOString(), approvedBy: 'standing-policy'});
  const result = await f.runtime.execute(job.id);
  assert.equal(result.status, 'failed'); assert.equal(result.errorCode, 'approval_required'); assert.equal(f.calls.length, 0);
});

// ---- F08.0c review fixes ----------------------------------------------------------------
test('a stored job cannot be forged past its approval, its lock or its effect', async t => {
  const {f, run} = await setup(t);
  const job = await run('POST', '/repos/o/r/issues', {body: {title: 'x'}});
  f.store.put('jobs', {...f.store.get('jobs', job.id), status: 'queued', approvedAt: new Date(f.now).toISOString(), approvedBy: 'single-action'});
  const unapproved = await f.runtime.execute(job.id);
  assert.equal(unapproved.status, 'failed'); assert.equal(f.calls.length, 0, 'no owner approval exists, so nothing is sent');
  const relabelled = await run('POST', '/repos/o/r/issues', {body: {title: 'y'}});
  f.store.put('jobs', {...f.store.get('jobs', relabelled.id), status: 'queued', effect: 'read', permissionMode: 'allow'});
  f.runtime.writeLocks.add('account:acct-a');
  const result = await f.runtime.execute(relabelled.id);
  assert.deepEqual([result.status, result.errorCode], ['failed', 'authority_changed']); assert.equal(f.calls.length, 0);
});

test('what is sent is the re-decided request: a stored method, header or timeout that differs from the approval is refused', async t => {
  for (const change of [{method: 'PUT'}, {headers: {'If-Match': '"x"'}}, {timeoutMs: 60000}, {added: [{name: 'Authorization', value: '(added by Fabric, hidden)'}]}]) {
    const {f, run, approve} = await setup(t);
    const job = await run('POST', '/repos/o/r/issues', {body: {title: 'x'}});
    const stored = f.store.get('jobs', job.id);
    f.store.put('jobs', {...stored, proxy: {...stored.proxy, ...change}});
    const result = await approve(job).catch(error => ({status: 'refused', errorCode: error.code}));
    assert.ok(['refused', 'failed'].includes(result.status) && result.errorCode === 'authority_changed', JSON.stringify(change));
    assert.equal(f.calls.length, 0, JSON.stringify(change));
  }
});

test('every header Fabric adds is on the approval, and nothing else is sent', async t => {
  const {f, run, approve, reply} = await setup(t);
  reply(json(201, {}));
  const job = await run('POST', '/repos/o/r/issues', {body: {title: 'x'}});
  const added = approvalPage(f.store.get('jobs', job.id), {now: f.now}).approval.exact.blocks.find(block => block.label === 'Added by Fabric').text;
  assert.equal(added, 'Authorization: (added by Fabric, hidden)\nAccept: application/json\nContent-Type: application/json; charset=utf-8');
  await approve(job);
  assert.deepEqual(Object.keys(f.calls[0].headers).sort(), ['Accept', 'Authorization', 'Content-Type']);
});

test('an approval that expires while the request is in flight still records the answer', async t => {
  const {f, run, reply, set, approve} = await setup(t);
  set('group:github.issues.read', 'ask');
  const job = await run('GET', '/repos/o/r/issues');
  f.advance(9 * 60_000 + 50_000);
  reply(() => {f.advance(15_000); return json(200, {ok: 1});});
  const done = await approve(job);
  assert.equal(done.status, 'succeeded'); assert.deepEqual(kept(f, done).body, {ok: 1});
});

test('credentials are found after decoding: JSON escapes, keys, any percent-encoding, and the content type', async t => {
  const {f, run, reply} = await setup(t);
  const token = 'abcd/efgh+ijkl==';
  f.runtime.connections = {credentials: async () => ({headers: {Authorization: `Bearer ${token}`}, allowedOrigins: ['https://api.github.com']})};
  reply({status: 200, headers: {'content-type': 'application/json', link: '<https://api.github.com/x?t=abcd/efgh%2Bijkl%3D%3D>; rel="next"'},
    data: Buffer.from('{"slash":"abcd\\/efgh+ijkl==","unicode":"abcd\\u002fefgh+ijkl==","key":{"abcd\\/efgh+ijkl==":1},"lower":"x?t=abcd%2fefgh%2bijkl%3d%3d","python":"x?t=abcd/efgh%2Bijkl%3D%3D"}')});
  const job = await run('GET', '/repos/o/r/issues');
  assert.equal(job.status, 'succeeded');
  assert.equal(JSON.stringify([f.store.list('jobs'), f.store.list('proxyResponses')]).includes(token), false); assert.equal(JSON.stringify(job.result).includes('efgh+ijkl'), false);
  assert.ok(job.result.response.redactions >= 6);
  reply({status: 200, headers: {'content-type': `Bearer ${token}`}, data: Buffer.from('x')});
  const odd = await run('GET', '/repos/o/r/issues');
  assert.equal(odd.result.response.contentType, null); assert.equal(JSON.stringify([f.store.list('jobs'), f.store.list('proxyResponses')]).includes(token), false);
});

test('a credential too short to keep out of responses is never sent', async t => {
  const {f, run, reply} = await setup(t);
  f.runtime.connections = {credentials: async () => ({headers: {Authorization: 'Bearer k7Q2xZ1'}, allowedOrigins: ['https://api.github.com']})};
  reply(json(200, {echo: 'k7Q2xZ1'}));
  const job = await run('GET', '/repos/o/r/issues');
  assert.deepEqual([job.status, job.errorCode], ['failed', 'fabric_failed']); assert.equal(f.calls.length, 0);
});

test('304 Not Modified answers a conditional read; it is not a redirect', async t => {
  const {run, reply} = await setup(t);
  reply({status: 304, headers: {etag: '"e1"', 'x-ratelimit-remaining': '10'}, data: null, notModified: true});
  const job = await run('GET', '/repos/o/r/issues', {headers: {'If-None-Match': '"e1"'}});
  assert.deepEqual([job.status, job.reason], ['succeeded', 'not_modified']); assert.equal(job.result.response.headers.etag, '"e1"');
});

// F10.3 (T4): a row that reaches other people carries the fixed warning on its approvals. The shipped rows carry the flags; the
// control takes one away. Gmail's two send members are typed-only, so the proxied case is Slack's chat.postMessage (map
// correction 3), and the Gmail send is the typed case.
const withoutAudience = (appId, rowId) => {
  const raw = JSON.parse(JSON.stringify(PERMISSION_GROUPS.get(appId)));
  return new Map([...PERMISSION_GROUPS, [appId, validatePermissionGroups({...raw, groups: raw.groups.map(group => { if (group.id !== rowId) return group; const {audience, ...rest} = group; return rest; })})]]);
};
test('a proxied Slack chat.postMessage on a row that reaches other people waits with reaches_people, shown in Fabric\'s sentence', async t => {
  const {f} = await setup(t);
  f.store.put('connections', {id: 'slack-a', appId: 'slack', driver: 'http', authMethod: 'token', authRevision: 'consent-slack', status: 'ready', label: 'Slack', identity: {id: 'U1'}, allowedOrigins: ['https://slack.com'], createdAt: new Date(f.now).toISOString()});
  const post = () => f.runtime.prepareProxy({connectionId: 'slack-a', request: {method: 'POST', path: '/chat.postMessage', body: {channel: 'C1', text: 'hello'}}}, owner);
  const shipped = f.runtime.proxyPolicy.groups;
  f.runtime.proxyPolicy.groups = withoutAudience('slack', 'slack.messages.send');
  const plain = post();
  assert.deepEqual([plain.status, plain.preview.warnings], ['awaiting_approval', []], 'the control: without the flag');
  f.runtime.proxyPolicy.groups = shipped;
  const job = post();
  assert.deepEqual([job.status, job.proxy.row, job.preview.warnings], ['awaiting_approval', 'group:slack.messages.send', ['reaches_people']]);
  assert.ok(!('routedFrom' in job.proxy));
  const page = approvalPage(f.store.get('jobs', job.id), {appName: () => 'Slack', now: f.now});
  assert.deepEqual(page.approval.warnings, ['reaches_people']);
  assert.deepEqual(describeApproval(page.approval).warnings, ['Reaches other people.']);
  assert.equal(job.approvalDigest, f.runtime.digest(job)); assert.equal(f.calls.length, 0);
});

const GMAIL_SEND = {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths: {'/gmail/v1/users/{userId}/messages/send': {post: {operationId: 'gmail.users.messages.send',
  parameters: [{name: 'userId', in: 'path', required: true, schema: {type: 'string'}}], requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}, responses: {200: {description: 'Sent'}}}}}};
test('a typed Gmail send on a row that reaches other people carries reaches_people in its preview, outside the digest', async t => {
  const {f} = await setup(t);
  const [send] = compileOpenApi({appId: 'gmail', document: GMAIL_SEND}).capabilities.map(cap => ({...cap, status: 'active'}));
  f.store.put('capabilities', send);
  f.store.put('applicationMaps', {id: 'gmail', appId: 'gmail', operations: [{id: 'gmail.users.messages.send', capabilityId: send.id, method: 'POST', path: '/gmail/v1/users/{userId}/messages/send'}]});
  f.store.put('connections', {id: 'gmail-a', appId: 'gmail', driver: 'http', authMethod: 'token', authRevision: 'consent-gmail', status: 'ready', label: 'Gmail', identity: {id: 'g1'}, allowedOrigins: ['https://gmail.googleapis.com'], createdAt: new Date(f.now).toISOString()});
  const ask = () => f.runtime.createJob({connectionId: 'gmail-a', capabilityId: send.id, args: {userId: 'me', body: {raw: 'eA'}}}, owner);
  const shipped = f.runtime.permissions.groups;
  f.runtime.permissions.groups = withoutAudience('gmail', 'gmail.messages.send');
  const plain = await ask();
  assert.equal(plain.status, 'awaiting_approval'); assert.ok(!('warnings' in plain.preview), 'the control: no warnings key on other previews');
  f.runtime.permissions.groups = shipped;
  const job = await ask();
  assert.deepEqual([job.status, job.preview.warnings], ['awaiting_approval', ['reaches_people']]);
  assert.equal(job.approvalDigest, f.runtime.digest({...job, preview: plain.preview}), 'the preview is not in the digest');
  assert.deepEqual(approvalItem(f.store.get('jobs', job.id)).warnings, ['reaches_people']);
  assert.equal(f.calls.length, 0);
});

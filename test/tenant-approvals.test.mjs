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
import {PERMISSION_GROUPS, validatePermissionGroups} from '../lib/permission-groups.mjs';

// F03.9's approval relay, pulled forward (docs/F03-DEVELOPER-LAYER.md section 5.11, D5): the developer's server reads
// one end user's waiting approvals and relays a decision with decisions:write and the exact digest shown.
const OPS = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send']];
function seed(root) {
  const paths = {};
  for (const [id, method, route] of OPS) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities;
  const store = new PlatformStore({root}), operations = [];
  for (const [id, method, route] of OPS) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `https://gmail.googleapis.com${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations.push({id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null});
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-approvals-'));
  seed(root);
  const sim = {calls: []};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/messages/send')) return {status: 200, headers: {}, data: {id: 'sent-1', threadId: 't-1'}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/')) return {status: 200, headers: {}, data: {id: 'm-1'}};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const standard = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token, relayKey = app.keys.mint({environmentId: dev.id, preset: 'full'}), relay = relayKey.token;
  const call = async (key, method, route, body, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  const account = async (externalUserId, identity) => {
    await call(standard, 'POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), id = randomUUID(), now = app.registry.now();
    repo().put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: identity, displayName: `${identity}@example.com`}, allowedOrigins: ['https://gmail.googleapis.com'],
      scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: now, updatedAt: now, authRevision: randomUUID()}, {subjectId: externalUserId, userRecordId: user.id}));
    app.stores.open(scope).vault.set(id, {accessToken: 'ya29.approvals', refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000});
    return id;
  };
  const u1 = await account('u1', 'g-1'), u2 = await account('u2', 'g-2');
  const caps = (await call(standard, 'GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  const send = caps.find(item => item.id.includes('messages-send')), read = caps.find(item => item.id.includes('messages-get'));
  const ask = async (externalUserId = 'u1') => (await call(standard, 'POST', '/v1/executions', {externalUserId, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}}, {'Idempotency-Key': randomUUID()})).body;
  const approvals = (key, externalUserId = 'u1') => call(key, 'GET', `/v1/users/${externalUserId}/approvals`);
  const decide = (key, callRef, body, externalUserId = 'u1') => call(key, 'POST', `/v1/users/${externalUserId}/approvals/${callRef}/decision`, body);
  const sent = () => sim.calls.filter(line => line.includes('/messages/send')).length;
  return {app, sim, scope, standard, relay, relayKey, read, call, repo, u1, u2, send, ask, approvals, decide, sent};
}

test('an end user\'s waiting approvals: the exact request, its digest and expiry; a decision path only for a key that may decide', async t => {
  const {standard, relay, u1, ask, approvals} = await setup(t);
  const waiting = await ask();
  assert.equal(waiting.status, 'awaiting_approval');
  const seen = (await approvals(relay)).body.approvals;
  assert.equal(seen.length, 1);
  const [item] = seen;
  assert.deepEqual([item.callRef, item.accountRef, item.appId, item.effect], [waiting.callRef, u1, 'gmail', 'write']);
  assert.match(item.digest, /^[0-9a-f]{64}$/); assert.ok(Date.parse(item.expiresAt) > Date.now());
  assert.ok(item.exact.complete); assert.match(JSON.stringify(item.exact.blocks), /eA/);
  assert.deepEqual(item.decide, {path: `/v1/users/u1/approvals/${waiting.callRef}/decision`, body: {decision: 'approve or reject', digest: item.digest}});
  assert.equal(/\/api\/|\/approve\/|\/continue\//.test(JSON.stringify(seen)), false, 'no owner paths and no links');
  assert.equal(seen.some(entry => 'approve' in entry || 'cancel' in entry), false);
  const plain = (await approvals(standard)).body.approvals;
  assert.equal(plain.length, 1); assert.equal(plain[0].decide, undefined, 'a key without decisions:write sees no decision path');
  assert.deepEqual((await approvals(relay, 'u2')).body, {approvals: []}, 'another user sees none of it');
  assert.deepEqual((await approvals(relay, 'nobody')).body, {approvals: []});
});

test('approve with the shown digest: the call runs once, detached, and records where it was decided and which key', async t => {
  const {relay, relayKey, call, ask, approvals, decide, sent, repo} = await setup(t);
  const waiting = await ask();
  const [item] = (await approvals(relay)).body.approvals;
  const approved = await decide(relay, waiting.callRef, {decision: 'approve', digest: item.digest});
  assert.ok([200, 202].includes(approved.status));
  const done = await call(relay, 'GET', `/v1/executions/${waiting.callRef}?waitMs=5000`);
  // A write is never reported as done without proof (F03.7b): it ran once, and reads as uncertain.
  assert.equal(done.body.status, 'uncertain'); assert.equal(sent(), 1);
  assert.deepEqual({decision: done.body.decision.decision, decidedIn: done.body.decision.decidedIn}, {decision: 'approved', decidedIn: 'developer_app'});
  const job = repo().get('jobs', waiting.callRef);
  assert.equal(job.decision.keyId, relayKey.keyId, 'the key that made the decision possible is recorded');
  assert.equal(JSON.stringify(done.body).includes(relayKey.keyId), false, 'but never shown in the call');
  const again = await decide(relay, waiting.callRef, {decision: 'approve', digest: item.digest});
  assert.equal(again.status, 409); assert.equal(again.body.error.code, 'not_awaiting_approval');
  assert.equal(sent(), 1, 'never sent twice');
  assert.deepEqual((await approvals(relay)).body.approvals, []);
});

test('reject: nothing runs, the call reads as cancelled with the decision recorded', async t => {
  const {relay, call, ask, approvals, decide, sent} = await setup(t);
  const waiting = await ask();
  const [item] = (await approvals(relay)).body.approvals;
  const rejected = await decide(relay, waiting.callRef, {decision: 'reject', digest: item.digest});
  assert.equal(rejected.status, 200);
  assert.deepEqual([rejected.body.status, rejected.body.decision.decision, rejected.body.decision.decidedIn], ['cancelled', 'rejected', 'developer_app']);
  assert.equal((await call(relay, 'GET', `/v1/executions/${waiting.callRef}`)).body.status, 'cancelled');
  assert.equal(sent(), 0);
});

test('only a key with decisions:write and the exact digest decides; another user\'s call answers exactly like an unknown one', async t => {
  const {standard, relay, ask, approvals, decide, sent} = await setup(t);
  const waiting = await ask(), [item] = (await approvals(relay)).body.approvals;
  const noPower = await decide(standard, waiting.callRef, {decision: 'approve', digest: item.digest});
  assert.equal(noPower.status, 403);
  const wrong = await decide(relay, waiting.callRef, {decision: 'approve', digest: 'f'.repeat(64)});
  assert.equal(wrong.status, 409); assert.equal(wrong.body.error.code, 'digest_mismatch');
  const theirs = await decide(relay, waiting.callRef, {decision: 'approve', digest: item.digest}, 'u2');
  const unknown = await decide(relay, randomUUID(), {decision: 'approve', digest: item.digest}, 'u2');
  const plain = body => ({...body, error: {...body.error, requestId: undefined}});
  assert.equal(theirs.status, 404); assert.deepEqual(plain(theirs.body), plain(unknown.body));
  assert.equal((await decide(relay, waiting.callRef, {decision: 'approve', digest: item.digest, extra: 1})).status, 400);
  assert.equal((await decide(relay, waiting.callRef, {decision: 'maybe', digest: item.digest})).status, 400);
  assert.equal(sent(), 0);
});

test('an expired approval cannot be decided; a rule switched to Never after the Ask stops the approved call', async t => {
  const {app, scope, u1, send, relay, call, ask, approvals, decide, sent, repo} = await setup(t);
  const first = await ask(), [item] = (await approvals(relay)).body.approvals;
  repo().put('jobs', {...repo().get('jobs', first.callRef), approvalExpiresAt: new Date(Date.now() - 1000).toISOString()});
  const late = await decide(relay, first.callRef, {decision: 'approve', digest: item.digest});
  assert.equal(late.status, 410); assert.equal(late.body.error.code, 'approval_expired');
  const second = await ask(), current = (await approvals(relay)).body.approvals.find(entry => entry.callRef === second.callRef);
  app.runtimes.bundle(scope).permissions.set({connectionId: u1, capabilityId: send.id, mode: 'deny'});
  await decide(relay, second.callRef, {decision: 'approve', digest: current.digest});
  const after = await call(relay, 'GET', `/v1/executions/${second.callRef}?waitMs=3000`);
  assert.equal(after.body.status, 'failed');
  assert.equal(sent(), 0, 'nothing was sent');
});

// F03.9: one end user's activity (section 5.11).
test('activity: that user\'s calls by day with the waiting approvals first, in Fabric\'s words, with no links and no identities', async t => {
  const {app, standard, relay, read, call, ask, approvals, decide, repo, u1} = await setup(t);
  const done = (await call(standard, 'POST', '/v1/executions', {externalUserId: 'u1', capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}, waitMs: 3000}, {'Idempotency-Key': randomUUID()})).body;
  const waiting = await ask(), rejected = await ask(), expired = await ask();
  const digest = (await approvals(relay)).body.approvals.find(item => item.callRef === rejected.callRef).digest;
  await decide(relay, rejected.callRef, {decision: 'reject', digest});
  repo().put('jobs', {...repo().get('jobs', expired.callRef), approvalExpiresAt: new Date(Date.now() - 1000).toISOString()});
  const page = (await call(standard, 'GET', '/v1/users/u1/activity')).body;
  assert.deepEqual(page.approvals.map(item => item.callRef), [waiting.callRef], 'only the live approval waits');
  const items = page.days.flatMap(day => day.items), byRef = Object.fromEntries(items.map(item => [item.callRef, item]));
  assert.deepEqual(Object.keys(byRef).sort(), [done.callRef, waiting.callRef, rejected.callRef, expired.callRef].sort());
  assert.deepEqual([byRef[done.callRef].status, byRef[done.callRef].kind, byRef[done.callRef].appId, byRef[done.callRef].accountRef, byRef[done.callRef].summary], ['succeeded', 'action', 'gmail', u1, 'Read from Gmail']);
  assert.deepEqual([byRef[rejected.callRef].status, byRef[rejected.callRef].decidedIn], ['cancelled', 'developer_app']);
  assert.equal(byRef[expired.callRef].status, 'failed', 'an approval nobody gave in time reads as failed');
  assert.equal(byRef[waiting.callRef].status, 'awaiting_approval');
  for (const item of items) assert.deepEqual(Object.keys(item).filter(key => !['callRef', 'kind', 'status', 'title', 'taskTitle', 'summary', 'appId', 'accountRef', 'at', 'decidedIn'].includes(key)), [], 'a closed shape');
  const text = JSON.stringify(page);
  assert.equal(/\/api\/|\/approve\/|\/continue\/|g-1@example\.com|ya29/.test(text), false, 'no owner paths, no links, no account identity, no token');
  for (let i = 1; i < page.days.length; i++) assert.ok(page.days[i - 1].date >= page.days[i].date, 'newest day first');
  void app;
});

test('activity: another user sees nothing of it; filters and paging; the scope is checked first', async t => {
  const {app, scope, standard, call, ask} = await setup(t);
  const one = await ask(), two = await ask();
  assert.deepEqual((await call(standard, 'GET', '/v1/users/u2/activity')).body, {approvals: [], days: []});
  assert.deepEqual((await call(standard, 'GET', '/v1/users/nobody/activity')).body, {approvals: [], days: []});
  assert.equal((await call(standard, 'GET', '/v1/users/u1/activity?appId=github')).body.days.length, 0);
  assert.equal((await call(standard, 'GET', `/v1/users/u1/activity?accountRef=${randomUUID()}`)).body.days.length, 0);
  assert.equal((await call(standard, 'GET', '/v1/users/u1/activity?appId=nope')).status, 400);
  const first = (await call(standard, 'GET', '/v1/users/u1/activity?limit=1')).body;
  assert.equal(first.days.flatMap(day => day.items).length, 1); assert.ok(first.nextCursor);
  const second = (await call(standard, 'GET', `/v1/users/u1/activity?limit=1&cursor=${first.nextCursor}`)).body;
  assert.deepEqual([...first.days, ...second.days].flatMap(day => day.items).map(item => item.callRef).sort(), [one.callRef, two.callRef].sort());
  assert.equal((await call(standard, 'GET', '/v1/users/u1/activity?cursor=%2E%2E')).status, 400);
  const connectOnly = app.keys.mint({environmentId: scope.environmentId, preset: 'connect-only'}).token;
  assert.equal((await call(connectOnly, 'GET', '/v1/users/u1/activity')).body.error.code, 'forbidden_scope');
});

// F10.3 (map correction 1): an approval re-checks a typed call before it is queued. One whose operation Fabric now locks, or
// whose body a route now sends to another row, is refused with its own code and words, ends failed and is never queued,
// audited as approved or sent. The rows are injected: the send joins Gmail's locked row, or its row gains a route.
const gmailRows = change => {
  const raw = JSON.parse(JSON.stringify(PERMISSION_GROUPS.get('gmail')));
  return new Map([...PERMISSION_GROUPS, ['gmail', validatePermissionGroups({...raw, schemaVersion: 2, groups: change(raw.groups)})]]);
};
test('a typed call whose operation Fabric locks while it waits is refused at the relay in Fabric\'s words; it ends failed and nothing is sent', async t => {
  const {app, scope, relay, call, ask, approvals, decide, sent, repo} = await setup(t);
  const waiting = await ask(), [item] = (await approvals(relay)).body.approvals;
  app.runtimes.bundle(scope).permissions.groups = gmailRows(groups => [...groups.filter(group => group.id !== 'gmail.access.grant').map(group => group.id === 'gmail.messages.send' ? {...group, operations: group.operations.filter(id => id !== 'gmail.users.messages.send')} : group),
    {id: 'gmail.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', locked: 'fabric', operations: [...(groups.find(group => group.id === 'gmail.access.grant')?.operations ?? []), 'gmail.users.messages.send']}]);
  const refused = await decide(relay, waiting.callRef, {decision: 'approve', digest: item.digest});
  assert.deepEqual([refused.status, refused.body.error.code], [403, 'permission_denied']);
  assert.match(refused.body.error.message, /^Fabric keeps this off: it gives access to other people or services\./);
  const after = await call(relay, 'GET', `/v1/executions/${waiting.callRef}?waitMs=1000`);
  assert.deepEqual([after.body.status, after.body.error.code], ['failed', 'permission_denied']);
  assert.equal(sent(), 0, 'nothing was sent');
  assert.equal(repo().list('activity').filter(event => event.type === 'job.approved').length, 0, 'never audited as approved');
  assert.deepEqual((await approvals(relay)).body.approvals, []);
  assert.equal((await decide(relay, waiting.callRef, {decision: 'approve', digest: item.digest})).body.error.code, 'not_awaiting_approval');
});

test('a typed call whose body a route now sends to another row is refused at the relay naming that row; it ends failed and nothing is sent', async t => {
  const {app, scope, relay, call, ask, approvals, decide, sent} = await setup(t);
  const waiting = await ask(), [item] = (await approvals(relay)).body.approvals;
  app.runtimes.bundle(scope).permissions.groups = gmailRows(groups => groups.map(group => group.id === 'gmail.messages.send' ? {...group, bodyRoutes: [{member: 'gmail.users.messages.send', pointer: '/raw', present: true, to: 'gmail.messages.trash'}]} : group));
  const refused = await decide(relay, waiting.callRef, {decision: 'approve', digest: item.digest});
  assert.deepEqual([refused.status, refused.body.error.code, refused.body.error.message], [400, 'invalid_request', 'This change belongs to "Move emails to or from trash". Use that operation instead. Nothing was sent.']);
  assert.deepEqual(refused.body.error.details, {routedTo: {groupId: 'gmail.messages.trash', label: 'Move emails to or from trash'}});
  assert.equal((await call(relay, 'GET', `/v1/executions/${waiting.callRef}?waitMs=1000`)).body.status, 'failed');
  assert.equal(sent(), 0, 'nothing was sent');
});

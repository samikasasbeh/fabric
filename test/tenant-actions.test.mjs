import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID, createHash} from 'node:crypto';
import {ROUTES} from '../lib/tenant/api.mjs';
import {capabilityPermissionHash} from '../lib/permissions.mjs';
import {developerHarness, slackFile, slackChoices, channelInfo, githubFile, githubChoices, pickAccount} from './fixtures/actions/developer-fixture.mjs';
import {choiceRequest, choiceNext} from '../lib/actions-runtime.mjs';
import {SLACK_TOKEN} from './fixtures/actions/runtime-fixture.mjs';
import {describePage, outcomeOf, reloadsOn, moved} from '../public/hosted-approve.js';
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {loadActionCatalog, seedActions} from '../lib/action-catalog.mjs';
import {validateActionFile} from '../lib/actions.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {withIds} from './fixtures/actions/fixture-app.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// F10.11 parts m to p (docs/F10.11-BUILD-MAP.md section 3): developer environments: agent tokens, the catalog, executions, held calls, the
// relay, Fabric's approve page and options. A developer environment cannot connect the fake app (it has no reviewed sign-in), so these run
// Slack and Notion actions from a temp action catalog seeded into the platform catalog, with each person's accounts stored as a confirmed
// sign-in stores them, and a scripted provider behind the network seam (test/fixtures/actions/developer-fixture.mjs); the server loads the
// same catalog at start (part p). Parts m, n (the relay and Fabric's approve page), o (/v1/options) and p are tests.

const DM = {email: 'grace@example.com', text: 'Lunch?'};
const hash = capability => capabilityPermissionHash(capability);
/** POST /v1/executions for one action, its definition hash read from the platform record. */
const execute = (d, key, capability, args, {user = 'u1', waitMs = 5000, idem = randomUUID(), ...extra} = {}) =>
  d.call(d.keys.standard, 'POST', '/v1/executions', {externalUserId: user, capabilityId: capability.id, definitionHash: hash(capability), args, waitMs, ...extra}, {'Idempotency-Key': idem});
/** The developer's ceiling on one of an app's rows in this environment. */
function ceiling(d, appId, groupId, mode) {
  const environment = d.app.registry.get('environments', d.scope.environmentId);
  d.app.registry.put('environments', {...environment, apps: {...environment.apps, [appId]: {...environment.apps?.[appId], ceilings: {...environment.apps?.[appId]?.ceilings, [groupId]: mode}}}});
}
const owner = (d, user = 'u1') => { const record = d.repo().list('endUsers').find(item => item.subjectId === user && item.status === 'active'); return {kind: 'product_user', subjectId: user, userRecordId: record.id}; };
/** Decides a waiting call as the relay will (part n), through the runtime's one decision path, and dispatches it. */
async function decide(d, callRef, decision = 'approved', user = 'u1') {
  const runtime = d.bundle().runtime, job = d.repo().get('jobs', callRef);
  runtime.decideWaiting(callRef, job.approvalDigest, owner(d, user), {decision, decidedIn: 'relay', at: d.app.registry.now(), keyId: d.keys.standard.id, serviceClientId: null});
  await d.app.runtimes.dispatch(d.scope, callRef);
  return d.repo().get('jobs', callRef);
}

test('part m: agent tokens accept an active action, record its computed effect and version, and refuse a candidate and a resource-dependent action', async t => {
  const d = await developerHarness(t), find = d.capability('find-person v1'), dm = d.capability('send-dm v1');
  const minted = await d.call(d.keys.standard, 'POST', '/v1/users/u1/agent-tokens', {name: 'Helper', bindings: [{accountRef: d.accounts.u1.slack, capabilityId: find.id}], requestable: [{capabilityId: find.id}, {capabilityId: dm.id}]});
  assert.equal(minted.status, 201, JSON.stringify(minted.body));
  const grant = d.repo().get('clientGrants', minted.body.agentToken.id);
  assert.deepEqual(grant.requestable, [{appId: 'slack', capabilityId: find.id, capabilityVersion: 1, definitionHash: hash(find), effect: 'read', providerId: 'slack'},
    {appId: 'slack', capabilityId: dm.id, capabilityVersion: 1, definitionHash: hash(dm), effect: 'write', providerId: 'slack'}]);
  assert.deepEqual(grant.bindings.map(binding => [binding.capabilityId, binding.definitionHash]), [[find.id, hash(find)]]);
  // A candidate is never given, bound or requested, as if it did not exist.
  const candidate = d.capability('find-channel v1');
  assert.equal(candidate.status, 'candidate');
  for (const body of [{requestable: [{capabilityId: candidate.id}]}, {bindings: [{accountRef: d.accounts.u1.slack, capabilityId: candidate.id}]}]) {
    const refused = await d.call(d.keys.standard, 'POST', '/v1/users/u1/agent-tokens', {name: 'Helper', ...body});
    assert.deepEqual([refused.status, refused.body.error.code], [404, 'not_found'], JSON.stringify(body));
  }
  // An action whose inputs depend on the resource it acts on can only be described once an account exists.
  const described = await d.call(d.keys.standard, 'POST', '/v1/users/u1/agent-tokens', {name: 'Helper', requestable: [{capabilityId: d.capability('post-fields v1').id}]});
  assert.deepEqual([described.status, described.body.error.code, described.body.error.message], [400, 'invalid_request', 'Connect the account first, then describe it.']);
  assert.equal(d.repo().list('clientGrants').length, 1, 'no refused token was stored');
  // With no action catalog (a failed load, part p) no action is given or offered, though its stored record still says active.
  const {permissions, runtime} = d.bundle();
  permissions.actions = null; runtime.actions = null;
  const none = await d.call(d.keys.standard, 'POST', '/v1/users/u1/agent-tokens', {name: 'Helper', requestable: [{capabilityId: find.id}]});
  assert.deepEqual([none.status, none.body.error.code], [404, 'not_found']);
  const offered = (await d.agent(minted.body.token, 'capabilities.list')).body.result.capabilities;
  assert.deepEqual(offered.map(entry => [entry.id, entry.status, entry.reason ?? null]), [[find.id, 'unavailable', 'permission_denied'], [find.id, 'unavailable', 'permission_denied'], [dm.id, 'unavailable', 'permission_denied']]);
});

test('part m: /fabric/v1 lists actions first with the local fields; a two-phase call waits with {callRef, expiresAt}; a token revoked after phase 1 makes phase 2 refuse with authority_changed and send nothing', async t => {
  const d = await developerHarness(t, {typed: true}), find = d.capability('find-person v1'), dm = d.capability('send-dm v1');
  const typed = d.repo().list('capabilities').find(capability => capability.appId === 'slack' && capability.driver === 'http');
  const minted = (await d.call(d.keys.standard, 'POST', '/v1/users/u1/agent-tokens', {name: 'Helper', bindings: [typed, find, dm].map(capability => ({accountRef: d.accounts.u1.slack, capabilityId: capability.id})),
    requestable: [{capabilityId: dm.id}]})).body;
  const listed = (await d.agent(minted.token, 'capabilities.list')).body.result.capabilities;
  assert.deepEqual(listed.map(entry => [entry.id, entry.kind, entry.status]), [[find.id, 'action', 'available'], [dm.id, 'action', 'available'], [dm.id, 'action', 'connection_required'], [typed.id, 'operation', 'available']]);
  const [finding, sending, asking, operation] = listed;
  assert.deepEqual([finding.annotations, operation.annotations], [{readOnly: true, destructive: false, idempotent: true, openWorld: true}, {readOnly: true, destructive: false, idempotent: true, openWorld: true}]);
  assert.deepEqual([sending.rows, sending.outputSchema, sending.choices, sending.approval], [['Send, edit and react to messages', 'Access profiles, user groups and workspace details', 'Mark as read and open direct messages', 'Access messages'], dm.outputSchema, [], 'ask']);
  assert.deepEqual([asking.driver, asking.rows.length, Object.hasOwn(operation, 'rows')], ['action', 4, false]);
  assert.deepEqual([(await d.agent(minted.token, 'fabric.discover')).body.result.features.actions, (await d.agent(minted.token, 'fabric.discover')).body.result.features.twoPhaseApproval], [true, true]);
  // The direct message reads the person, then waits before opening the conversation (its resolving write).
  const created = (await d.agent(minted.token, 'calls.create', {connectionId: sending.connectionId, capabilityId: dm.id, definitionHash: sending.definitionHash, args: DM})).body.result;
  await d.app.runtimes.wait(d.scope, created.id, 5000);
  const waiting = (await d.agent(minted.token, 'calls.get', {callId: created.id})).body.result;
  assert.deepEqual([waiting.status, Object.keys(waiting.approval).sort(), d.repo().get('jobs', created.id).action.phase], ['awaiting_approval', ['callRef', 'expiresAt'], 'reads']);
  assert.match(waiting.card.summary, /^Fabric prepared the exact request\./, 'its read ran, so its card says the request is prepared');
  // Phase 1 approved: the conversation is opened, and the final bytes wait.
  const second = await decide(d, created.id);
  assert.deepEqual([second.status, second.action.phase, d.slack.writes().map(call => call.name)], ['awaiting_approval', 'final', ['conversations.open']]);
  await d.call(d.keys.standard, 'POST', `/v1/users/u1/agent-tokens/${minted.agentToken.id}/revoke`);
  const ended = await decide(d, created.id);
  assert.deepEqual([ended.status, ended.errorCode], ['uncertain', 'authority_changed'], 'the conversation was opened, so uncertain; the token no longer covers the call');
  assert.deepEqual(d.slack.writes().map(call => call.name), ['conversations.open'], 'chat.postMessage was never sent');
  // A binding on an action id a newer version replaced lists as superseded, naming the action that replaced it.
  const fresh = (await d.call(d.keys.standard, 'POST', '/v1/users/u1/agent-tokens', {name: 'Helper', bindings: [{accountRef: d.accounts.u1.slack, capabilityId: find.id}]})).body;
  const old = `slack.action.find-person.v1.${'0123456789abcdef01234567'}`, grant = d.repo().get('clientGrants', fresh.agentToken.id);
  d.catalog.superseded.set(old, {appId: 'slack', replacedBy: find.id, reason: 'change', stopsAfter: '2026-12-31'});
  d.repo().put('clientGrants', {...grant, bindings: [{...grant.bindings[0], capabilityId: old}]});
  const [notice] = (await d.agent(fresh.token, 'capabilities.list')).body.result.capabilities;
  assert.deepEqual(notice, {id: old, connectionId: notice.connectionId, definitionHash: grant.bindings[0].definitionHash, kind: 'action', status: 'unavailable', reason: 'superseded', replacedBy: find.id, stopsAfter: '2026-12-31'});
});

test('part m: an action refused when it is accepted keeps its code and its own words on /v1 and /fabric/v1; one refused while it runs is action_refused in the Execution', async t => {
  const d = await developerHarness(t), fields = d.capability('issue-fields v1'), args = {owner: '..', repo: 'r', values: {}};
  // Read under its row's default Allow, the repository is read when the call runs: its address is refused then, before anything is sent.
  const ran = await execute(d, d.keys.standard, fields, args);
  assert.deepEqual([ran.body.status, ran.body.error.code, ran.body.error.message], ['failed', 'action_refused', 'Fabric refused this action for what it was given or what it read. Nothing was changed.']);
  // With that row at Ask, its read's exact bytes are built when the call is accepted, and the refusal comes there.
  ceiling(d, 'github', 'github.repos.read', 'ask');
  const accepted = await execute(d, d.keys.standard, fields, args);
  assert.deepEqual([accepted.status, accepted.body.error.code, accepted.body.error.message, accepted.body.error.details], [400, 'action_refused', 'The request this action built is not one Fabric sends. Nothing was sent.', {reason: 'request_invalid'}]);
  const minted = (await d.call(d.keys.standard, 'POST', '/v1/users/u1/agent-tokens', {name: 'Helper', bindings: [{accountRef: d.accounts.u1.github, capabilityId: fields.id}]})).body;
  const [entry] = (await d.agent(minted.token, 'capabilities.list')).body.result.capabilities;
  const refused = await d.agent(minted.token, 'calls.create', {connectionId: entry.connectionId, capabilityId: fields.id, definitionHash: entry.definitionHash, args});
  assert.deepEqual([refused.body.error.code, refused.body.error.message], ['action_refused', 'The request this action built is not one Fabric sends. Nothing was sent.']);
  assert.equal(d.calls.length, 0, 'nothing reached GitHub');
});

test('part m: POST /v1/executions: Allow reads and an Ask perform give 202 at phase final; an Ask read row gives phase reads; a Never read row gives 403 with no request, job or usage', async t => {
  const d = await developerHarness(t), create = d.capability('create-page v1'), dm = d.capability('send-dm v1');
  const page = await execute(d, d.keys.standard, create, {parentId: 'shared-page', emoji: 'x'});
  assert.deepEqual([page.status, page.body.status, page.body.approval], [202, 'awaiting_approval', {callRef: page.body.callRef, expiresAt: page.body.approval.expiresAt, phase: 'final'}]);
  // The direct message's read row asks: it stops before any read, at phase reads.
  ceiling(d, 'slack', 'slack.workspace.read', 'ask');
  const asking = await execute(d, d.keys.standard, dm, DM);
  assert.deepEqual([asking.status, asking.body.status, asking.body.approval.phase, d.slack.calls.length], [202, 'awaiting_approval', 'reads', 0]);
  // Never on that row refuses before any call, with no job and no usage.
  ceiling(d, 'slack', 'slack.workspace.read', 'deny');
  const jobs = d.repo().list('jobs').length, usage = d.repo().list('usageEvents').length;
  const refused = await execute(d, d.keys.standard, dm, DM);
  assert.deepEqual([refused.status, refused.body.error.code], [403, 'permission_denied']);
  assert.deepEqual([d.slack.calls.length, d.repo().list('jobs').length, d.repo().list('usageEvents').length], [0, jobs, usage]);
});

test('part m: two concurrent posts with one Idempotency-Key during slow reads both get the same callRef and one usage record', async t => {
  const d = await developerHarness(t), find = d.capability('find-person v1'), idem = randomUUID();
  const gate = d.hold('users.lookupByEmail');
  const first = execute(d, d.keys.standard, find, {email: 'grace@example.com'}, {idem, waitMs: 0});
  await gate.reached;
  const second = await execute(d, d.keys.standard, find, {email: 'grace@example.com'}, {idem, waitMs: 0});
  const answered = await first;
  assert.deepEqual([answered.status, second.status, second.body.callRef], [202, 202, answered.body.callRef], 'the job exists before its read, so a replay never meets idempotency_conflict');
  gate.release();
  await d.app.runtimes.wait(d.scope, answered.body.callRef, 5000);
  assert.equal(d.repo().list('usageEvents').filter(item => item.id === `exec.${answered.body.callRef}`).length, 1);
  assert.equal(d.callsOf('users.lookupByEmail').length, 1, 'read once');
});

test('part m: a failed prepare read is provider_failed with providerStatus, counted once, and nothing is written', async t => {
  const d = await developerHarness(t), dm = d.capability('send-dm v1');
  d.fail('users.lookupByEmail', {status: 503, headers: {}, data: {ok: false, error: 'service_unavailable'}});
  const failed = await execute(d, d.keys.standard, dm, DM);
  assert.deepEqual([failed.status, failed.body.status, failed.body.error.code, failed.body.error.providerStatus], [200, 'failed', 'provider_failed', 503]);
  assert.deepEqual(d.slack.writes(), []);
  assert.equal(d.repo().list('usageEvents').filter(item => item.id === `exec.${failed.body.callRef}`).length, 1);
  const replay = await d.call(d.keys.standard, 'GET', `/v1/executions/${failed.body.callRef}`);
  assert.deepEqual([replay.body.status, replay.body.error.code], ['failed', 'provider_failed']);
});

test('part m: the projection: a read action is observed, a verified readback is verified, a 429 carries retryAfterSeconds, and every decision is listed', async t => {
  const d = await developerHarness(t), find = d.capability('find-person v1'), create = d.capability('create-page v1'), dm = d.capability('send-dm v1');
  const read = await execute(d, d.keys.standard, find, {email: 'grace@example.com'});
  assert.deepEqual([read.body.status, read.body.evidence, read.body.result], ['succeeded', 'observed', {id: 'U2', name: 'Grace Hopper'}]);
  const permissions = d.bundle().permissions;
  permissions.set({connectionId: d.accounts.u1.notion, capabilityId: create.id, mode: 'allow'});
  const made = await execute(d, d.keys.standard, create, {parentId: 'shared-page', emoji: 'x'});
  assert.deepEqual([made.body.status, made.body.evidence, made.body.result], ['succeeded', 'verified', {id: 'page-1'}]);
  d.fail('POST /v1/pages', {status: 429, headers: {'retry-after': '30'}, data: {object: 'error', code: 'rate_limited'}});
  const limited = await execute(d, d.keys.standard, create, {parentId: 'shared-page', emoji: 'y'});
  assert.deepEqual([limited.body.status, limited.body.error.code, limited.body.error.providerStatus, limited.body.error.retryAfterSeconds], ['failed', 'provider_failed', 429, 30]);
  // Both stops of the direct message are decided: the Execution lists each decision, by phase.
  const waiting = await execute(d, d.keys.standard, dm, DM);
  await decide(d, waiting.body.callRef);
  await decide(d, waiting.body.callRef);
  const done = await d.call(d.keys.standard, 'GET', `/v1/executions/${waiting.body.callRef}`);
  assert.deepEqual([done.body.status, done.body.evidence, done.body.decisions.map(item => [item.phase, item.decision])], ['succeeded', 'verified', [['reads', 'approved'], ['final', 'approved']]]);
});

test('part m: two users of one environment editing the same shared page: user A\'s Fabric-made record still asks for user B', async t => {
  const d = await developerHarness(t, {users: ['u1', 'u2']}), create = d.capability('create-page v1'), rename = d.capability('rename-page v1'), permissions = d.bundle().permissions;
  for (const user of ['u1', 'u2']) for (const capability of [create, rename]) permissions.set({connectionId: d.accounts[user].notion, capabilityId: capability.id, mode: 'allow'});
  const made = await execute(d, d.keys.standard, create, {parentId: 'shared-page', emoji: 'a'});
  assert.equal(made.body.status, 'succeeded');
  const pageId = made.body.result.id;
  // User A made it through Fabric, so A's own edit runs under Allow.
  assert.equal((await execute(d, d.keys.standard, rename, {pageId, emoji: 'b'})).body.status, 'succeeded');
  // User B edits the same page in the shared workspace: Fabric did not make it for B, so B is asked.
  const other = await execute(d, d.keys.standard, rename, {pageId, emoji: 'c'}, {user: 'u2'});
  assert.deepEqual([other.body.status, other.body.approval.phase], ['awaiting_approval', 'final']);
});

test('part m: the catalog: actions first, the kind filter, hints with reachesPeople, certified, the detail fields and the superseded detail', async t => {
  const slack = (await import('./fixtures/actions/developer-fixture.mjs')).slackFile();
  slack.superseded = [{id: 'slack.action.find-person.v1.0123456789abcdef01234567', replacedBy: {key: 'find-person', version: 1}, reason: 'change', stopsAfter: '2026-12-31'}];
  const d = await developerHarness(t, {typed: true, slack}), find = d.capability('find-person v1'), dm = d.capability('send-dm v1'), fields = d.capability('post-fields v1');
  const typed = d.repo().list('capabilities').find(capability => capability.appId === 'slack' && capability.driver === 'http');
  const list = async query => (await d.call(d.keys.standard, 'GET', `/v1/capabilities?appId=slack${query}`)).body;
  const all = await list('');
  const actions = [dm, find, fields].map(capability => capability.id).sort();
  assert.ok(typed.id < actions[0], 'by id alone the operation would come first');
  assert.deepEqual(all.capabilities.map(entry => [entry.id, entry.kind]), [...actions.map(id => [id, 'action']), [typed.id, 'operation']], 'actions first, each part by id; the candidate is not listed');
  assert.deepEqual((await list('&kind=action')).capabilities.map(entry => entry.id), actions);
  assert.deepEqual((await list('&kind=operation')).capabilities.map(entry => entry.id), [typed.id]);
  assert.deepEqual((await d.call(d.keys.standard, 'GET', '/v1/capabilities?kind=workflow')).body.error.code, 'invalid_request');
  // Paging keeps the order, with an id as the cursor.
  const first = await list('&limit=2'), rest = await list(`&limit=2&after=${encodeURIComponent(first.pageInfo.endCursor)}`);
  assert.deepEqual([...first.capabilities, ...rest.capabilities].map(entry => entry.id), all.capabilities.map(entry => entry.id));
  const entry = id => all.capabilities.find(item => item.id === id);
  assert.deepEqual(entry(dm.id), {id: dm.id, appId: 'slack', kind: 'action', name: 'Send a direct message', description: dm.description, effect: 'write', version: 1, definitionHash: hash(dm),
    annotations: {readOnly: false, destructive: false, idempotent: false, openWorld: true, reachesPeople: true}, hasOptions: false, certified: true});
  assert.deepEqual([entry(find.id).annotations, entry(find.id).certified], [{readOnly: true, destructive: false, idempotent: true, openWorld: true}, true]);
  assert.deepEqual([entry(typed.id).kind, entry(typed.id).certified], ['operation', false]);
  const detail = (await d.call(d.keys.standard, 'GET', `/v1/capabilities/${encodeURIComponent(dm.id)}`)).body;
  assert.deepEqual([detail.kind, detail.outputSchema, detail.inputSchema, detail.choices, detail.optionInputs], ['action', dm.outputSchema, dm.inputSchema, [], []]);
  assert.deepEqual(detail.rows, [{groupId: 'slack.messages.send', label: 'Send, edit and react to messages'}, {groupId: 'slack.workspace.read', label: 'Access profiles, user groups and workspace details'},
    {groupId: 'slack.conversations.mark', label: 'Mark as read and open direct messages'}, {groupId: 'slack.messages.read', label: 'Access messages'}]);
  const replaced = await d.call(d.keys.standard, 'GET', '/v1/capabilities/slack.action.find-person.v1.0123456789abcdef01234567');
  assert.deepEqual([replaced.status, replaced.body.error.code, replaced.body.error.details], [409, 'capability_changed', {replacedBy: find.id}]);
  assert.equal((await d.call(d.keys.standard, 'GET', `/v1/capabilities/${encodeURIComponent(d.capability('find-channel v1').id)}`)).status, 404, 'a candidate has no detail');
  // With no action catalog, no action is listed or described, though their stored records still say active.
  d.app.runtimes.actions = null;
  assert.deepEqual((await list('')).capabilities.map(item => item.id), [typed.id]);
  assert.equal((await d.call(d.keys.standard, 'GET', `/v1/capabilities/${encodeURIComponent(dm.id)}`)).status, 404);
});

test('part m: /v1/users/:ext/capabilities lists runnable actions first with their T8 mode, and leaves one out under a Never step row or a ceiling on a step row', async t => {
  const d = await developerHarness(t, {typed: true}), find = d.capability('find-person v1'), dm = d.capability('send-dm v1');
  const listed = async () => (await d.call(d.keys.standard, 'GET', '/v1/users/u1/capabilities?appId=slack')).body.capabilities.map(entry => [entry.id, entry.kind, entry.mode]);
  const typed = d.repo().list('capabilities').find(capability => capability.appId === 'slack' && capability.driver === 'http');
  const before = await listed();
  assert.deepEqual(before.slice(0, 3).map(([, kind]) => kind), ['action', 'action', 'action']);
  const sending = (await d.call(d.keys.standard, 'GET', '/v1/users/u1/capabilities?appId=slack')).body.capabilities.find(entry => entry.id === dm.id);
  assert.deepEqual([sending.certified, sending.annotations.reachesPeople], [true, true], 'read from the catalog, as the developer catalog reads it');
  assert.deepEqual([before.find(([id]) => id === find.id)?.[2], before.find(([id]) => id === dm.id)?.[2], before.at(-1)], ['allow', 'ask', [typed.id, 'operation', 'allow']]);
  // A ceiling on Mark as read and open direct messages, a row the direct message's resolving write lands in but not its own: it is left out.
  ceiling(d, 'slack', 'slack.conversations.mark', 'deny');
  assert.equal((await listed()).some(([id]) => id === dm.id), false);
  ceiling(d, 'slack', 'slack.conversations.mark', 'ask');
  assert.equal((await listed()).find(([id]) => id === dm.id)?.[2], 'ask');
  // Never on its readback row (Access messages), through the proxy record: left out too.
  d.bundle().runtime.proxyPolicy.set({connectionId: d.accounts.u1.slack, row: 'group:slack.messages.read', mode: 'deny'});
  assert.equal((await listed()).some(([id]) => id === dm.id), false);
});

test('part m: a held action\'s sign-in requires by name what its steps need; a resource-dependent one is refused and nothing is stored', async t => {
  const d = await developerHarness(t, {users: [], bare: ['u3']}), gists = d.capability('list-gists v1');
  const held = await execute(d, d.keys.standard, gists, {}, {user: 'u3', onMissingAccess: 'hold', waitMs: 0});
  assert.deepEqual([held.status, held.body.status], [202, 'connection_required'], JSON.stringify(held.body));
  const sessionId = held.body.handoff.connectSessionId, link = (await d.call(d.keys.standard, 'POST', `/v1/connect-sessions/${sessionId}/link`)).body, binding = `browser-${sessionId}`;
  d.app.sessions.claim(sessionId, new URL(link.connectUrl).hash.slice(3), binding);
  d.app.sessions.start(sessionId, binding);
  // The sign-in requires gist, the scope its one read needs and the level only offers: declining it connects nothing (T2).
  const [flow] = d.repo().list('oauthFlows');
  assert.deepEqual(flow.required, ['read:user', 'repo', 'gist']);
  // File an issue with fields is described by the repository it files in: no hold, no Connect session, nothing sent.
  const sessions = d.repo().list('connectSessions').length, holds = d.repo().list('continuations').length, fields = d.capability('issue-fields v1');
  const refused = await execute(d, d.keys.standard, fields, {owner: 'o', repo: 'r', values: {}}, {user: 'u3', onMissingAccess: 'hold', waitMs: 0});
  assert.deepEqual([refused.status, refused.body.error.code, refused.body.error.message], [400, 'invalid_request', 'Connect the account first, then describe it.']);
  assert.deepEqual([d.repo().list('connectSessions').length, d.repo().list('continuations').length, d.calls.length], [sessions, holds, 0]);
  // An agent's account request for a resource-dependent action is refused the same way, before its request id is recorded.
  const minted = (await d.call(d.keys.standard, 'POST', '/v1/users/u3/agent-tokens', {name: 'Helper', requestable: [{capabilityId: gists.id}]})).body;
  const grant = d.repo().get('clientGrants', minted.agentToken.id), post = d.capability('post-fields v1');
  d.repo().put('clientGrants', {...grant, requestable: [...grant.requestable, {appId: 'slack', capabilityId: post.id, capabilityVersion: 1, definitionHash: hash(post), effect: 'write', providerId: 'slack'}]});
  const listed = (await d.agent(minted.token, 'capabilities.list')).body.result.capabilities;
  assert.deepEqual(listed.map(entry => [entry.id, entry.status, entry.reason ?? null]), [[gists.id, 'connection_required', null], [post.id, 'unavailable', 'unsupported_route']]);
  const asking = await d.agent(minted.token, 'calls.create', {appId: 'slack', capabilityId: post.id, definitionHash: hash(post), args: {channel: 'C1', values: {}}});
  assert.deepEqual([asking.body.error.code, asking.body.error.message], ['invalid_request', 'Connect the account first, then describe it.']);
  assert.equal(d.repo().list('protocolRequests').length, 0);
});

test('part m: a user delete erases actionPrepared and actionRecords; pending_limit counts a waiting action once, in either phase', async t => {
  const d = await developerHarness(t), dm = d.capability('send-dm v1'), create = d.capability('create-page v1');
  d.bundle().permissions.set({connectionId: d.accounts.u1.notion, capabilityId: create.id, mode: 'allow'});
  assert.equal((await execute(d, d.keys.standard, create, {parentId: 'shared-page', emoji: 'a'})).body.status, 'succeeded');
  const waits = [];
  for (let index = 0; index < 20; index++) waits.push((await execute(d, d.keys.standard, dm, {...DM, text: `Hi ${index}`})).body.callRef);
  // One of them moves to its final stop: still one waiting call.
  assert.equal((await decide(d, waits[0])).action.phase, 'final');
  const full = await execute(d, d.keys.standard, dm, DM);
  assert.deepEqual([full.status, full.body.error.code], [429, 'pending_limit']);
  assert.ok(d.repo().list('actionPrepared').length >= 20 && d.repo().list('actionRecords').length === 1);
  assert.equal((await d.call(d.keys.full, 'DELETE', '/v1/users/u1')).status < 300, true);
  assert.deepEqual([d.repo().list('actionPrepared').length, d.repo().list('actionRecords').length], [0, 0]);
});

/** The labelled blocks of one approval's exact action, as a map. */
const blocksOf = approval => Object.fromEntries(approval.exact.blocks.map(block => [block.label, block.text]));
const relayList = async (d, user = 'u1') => (await d.call(d.keys.full, 'GET', `/v1/users/${user}/approvals`)).body.approvals;

test('part n: relay: the phase reads item, then the phase final item with fields, blocks and a new digest; the old digest is 409; a phase 2 reject cancels with nothing sent', async t => {
  const d = await developerHarness(t), dm = d.capability('send-dm v1');
  const waiting = await execute(d, d.keys.standard, dm, DM), callRef = waiting.body.callRef;
  assert.deepEqual([waiting.status, waiting.body.approval.phase], [202, 'reads']);
  // Phase reads: the read Fabric ran and the conversation it will open, each exactly, and a decision path.
  const [first] = await relayList(d), shown = blocksOf(first);
  assert.deepEqual([first.callRef, first.phase, first.exact.complete], [callRef, 'reads', true]);
  assert.deepEqual([shown['person: Request'], shown['open: Request'], shown['open: Body']],
    ['GET https://slack.com/api/users.lookupByEmail?email=grace%40example.com', 'POST https://slack.com/api/conversations.open', '{"users":"U2"}']);
  assert.deepEqual(first.decide, {path: `/v1/users/u1/approvals/${callRef}/decision`, body: {decision: 'approve or reject', digest: first.digest}});
  const relay = body => d.call(d.keys.full, 'POST', first.decide.path, body);
  // Approving phase reads queues the call: the conversation is opened, and the final bytes wait for their own decision.
  const approved = await relay({decision: 'approve', digest: first.digest});
  assert.deepEqual([approved.status, ['queued', 'running'].includes(approved.body.status)], [202, true], 'a phase reads approve answers 202 while the reads run');
  await d.app.runtimes.wait(d.scope, callRef, 5000);
  assert.deepEqual((await d.call(d.keys.standard, 'GET', `/v1/executions/${callRef}`)).body.approval.phase, 'final', 'the developer reads the next stop from the same callRef');
  const [second] = await relayList(d), final = blocksOf(second);
  assert.deepEqual([second.callRef, second.phase, second.exact.complete], [callRef, 'final', true]);
  assert.notEqual(second.digest, first.digest, 'each stop has its own digest');
  assert.deepEqual([final.Fields, final['post: Request'], JSON.parse(final['post: Body'])], ['To: Grace Hopper\nMessage: Lunch?', 'POST https://slack.com/api/chat.postMessage', {channel: 'DU2', text: 'Lunch?'}]);
  const stale = await relay({decision: 'approve', digest: first.digest});
  assert.deepEqual([stale.status, stale.body.error.code], [409, 'digest_mismatch']);
  const rejected = await relay({decision: 'reject', digest: second.digest});
  assert.deepEqual([rejected.status, rejected.body.status], [200, 'cancelled']);
  assert.deepEqual(d.slack.writes().map(item => item.name), ['conversations.open'], 'chat.postMessage was never sent');
  assert.deepEqual([d.repo().get('actionPrepared', callRef) ?? null, await relayList(d)], [null, []]);
});

test('part n: a missing actionPrepared row and a tampered one each show no Approve on the relay list, the relay page and Fabric\'s page, and Fabric\'s page refuses to approve', async t => {
  const d = await developerHarness(t), dm = d.capability('send-dm v1');
  const callRef = (await execute(d, d.keys.standard, dm, DM)).body.callRef, row = d.repo().get('actionPrepared', callRef);
  const link = await d.open(d.keys.full, {externalUserId: 'u1', purpose: 'approve', callRef});
  /** What each surface offers now: the relay list's decision path, the user's /v1 activity, and Fabric's approve page. */
  const offered = async () => {
    const [item] = await relayList(d), [listed] = (await d.call(d.keys.full, 'GET', '/v1/users/u1/activity')).body.approvals, page = (await link.get('approval')).body;
    return {relay: Boolean(item.decide) && item.exact.complete, activity: Boolean(listed.decide) && listed.exact.complete, page: Boolean(page.approval.approve) && page.approval.exact.complete, cancel: Boolean(page.approval.cancel)};
  };
  assert.deepEqual(await offered(), {relay: true, activity: true, page: true, cancel: true}, 'with its prepared bytes, every surface offers Approve');
  const digest = (await relayList(d))[0].digest;
  const tampered = {...row, content: {...row.content, resolving: {...row.content.resolving, body: '{"users":"U9"}'}}};
  for (const [name, change] of [['missing', () => d.repo().delete('actionPrepared', callRef)], ['tampered', () => d.repo().put('actionPrepared', tampered)]]) {
    change();
    assert.deepEqual(await offered(), {relay: false, activity: false, page: false, cancel: true}, `${name}: no Approve anywhere, Reject still offered`);
    const refused = await link.post(`approvals/${callRef}/decision`, {decision: 'approve', digest});
    assert.deepEqual([refused.status, refused.body.error.code], [409, 'exact_action_incomplete'], name);
    assert.equal(d.repo().get('jobs', callRef).status, 'awaiting_approval', `${name}: nothing was decided`);
  }
  d.repo().put('actionPrepared', row);
  assert.deepEqual(await offered(), {relay: true, activity: true, page: true, cancel: true}, 'the stored bytes back, Approve is back');
  assert.deepEqual(d.slack.writes(), []);
});

test('part n: approve page: one link carries both phases; a reject at either ends it; a concurrent relay decision reloads it; a decoded recipient holding U+202E is shown marked', async t => {
  const d = await developerHarness(t), dm = d.capability('send-dm v1');
  const waitingCall = async (text = 'Lunch?') => (await execute(d, d.keys.standard, dm, {...DM, text})).body.callRef;
  const approveLink = callRef => d.open(d.keys.full, {externalUserId: 'u1', purpose: 'approve', callRef});
  const sessionState = async link => (await d.call(d.keys.full, 'GET', `/v1/connect-sessions/${link.id}`)).body.state;
  // One link, both phases. The call waits 9 minutes first, so the link's own 10 minutes would end before the final stop's window.
  const callRef = await waitingCall();
  d.advance(9 * 60_000);
  const link = await approveLink(callRef), opened = await link.get('approval'), first = opened.body;
  assert.deepEqual([first.state, first.approval.phase, link.created.expiresAt, opened.cookies], ['pending', 'reads', '2026-10-23T09:10:00.000Z', []]);
  const continued = await link.post(`approvals/${callRef}/decision`, first.approval.approve.body);
  assert.deepEqual([continued.status, continued.body], [200, {state: 'continuing', decision: 'approved', phase: 'reads'}], 'a phase reads approve does not finish the page');
  assert.ok(continued.cookies.some(line => line.startsWith('fabric_t_session=') && line.endsWith('Max-Age=60')), 'the cookie follows the continuing link from its decision on');
  assert.equal(await sessionState(link), 'continuing');
  assert.deepEqual(outcomeOf(continued.body), {line: 'Approved. Fabric is preparing the exact request.', redirect: null, continuing: true});
  await d.app.runtimes.wait(d.scope, callRef, 5000);
  d.advance(2 * 60_000);
  assert.equal(await sessionState(link), 'continuing', 'past its first expiry, the developer reads the link by its call\'s final stop');
  // Past the link's first expiry, the same link shows the final stop for as long as that stop's window lasts, and the cookie follows it.
  const second = await link.get('approval');
  assert.deepEqual([second.status, second.body.state, second.body.approval.phase, moved(second.body, first.approval.digest)], [200, 'pending', 'final', true]);
  assert.ok(second.cookies.some(line => line.startsWith('fabric_t_session=') && line.endsWith('Max-Age=480')), 'the page cookie lives as long as the final stop\'s window');
  assert.equal(moved(second.body, second.body.approval.digest), false, 'the same stop is not new');
  const done = await link.post(`approvals/${callRef}/decision`, second.body.approval.approve.body);
  assert.deepEqual([done.status, done.body.state, done.body.decision], [200, 'completed', 'approved']);
  assert.deepEqual([(await link.get('approval')).body.error.code, await sessionState(link)], ['already_finished', 'completed']);
  await d.app.runtimes.wait(d.scope, callRef, 5000);
  assert.deepEqual([d.repo().get('jobs', callRef).status, d.slack.writes().map(item => item.name)], ['succeeded', ['conversations.open', 'chat.postMessage']]);
  // Once the final stop's window ends, the link ends with it.
  const lapsing = await waitingCall('Lapsing');
  d.advance(9 * 60_000);
  const late = await approveLink(lapsing), shownLate = (await late.get('approval')).body;
  await late.post(`approvals/${lapsing}/decision`, shownLate.approval.approve.body);
  await d.app.runtimes.wait(d.scope, lapsing, 5000);
  for (const minutes of [4, 4]) { d.advance(minutes * 60_000); assert.equal((await late.get('approval')).status, 200, 'within the final stop\'s window'); }
  assert.equal(await sessionState(late), 'continuing', 'the developer reads the link as continuing past its first expiry');
  d.advance(3 * 60_000);
  assert.deepEqual((await late.get('approval')).body.error.code, 'expired');
  // A reject at phase reads ends the link; so does a reject at phase final, and nothing is posted.
  for (const at of ['reads', 'final']) {
    const call = await waitingCall(`Reject at ${at}`), rejecting = await approveLink(call);
    let page = (await rejecting.get('approval')).body;
    if (at === 'final') {
      await rejecting.post(`approvals/${call}/decision`, page.approval.approve.body);
      await d.app.runtimes.wait(d.scope, call, 5000);
      page = (await rejecting.get('approval')).body;
    }
    assert.equal(page.approval.phase, at);
    const rejected = await rejecting.post(`approvals/${call}/decision`, page.approval.cancel.body);
    assert.deepEqual([rejected.body.state, rejected.body.decision, d.repo().get('jobs', call).status, await sessionState(rejecting)], ['completed', 'rejected', 'cancelled', 'completed'], at);
  }
  // The relay decides phase reads while the page shows it: the page's approve is refused as moved on, the link stays open, and a reload
  // shows the final stop on the same link.
  const raced = await waitingCall('Raced'), racing = await approveLink(raced), shownRaced = (await racing.get('approval')).body;
  const [item] = (await relayList(d)).filter(entry => entry.callRef === raced);
  assert.equal((await d.call(d.keys.full, 'POST', item.decide.path, {decision: 'approve', digest: item.digest})).status, 202);
  await d.app.runtimes.wait(d.scope, raced, 5000);
  const refused = await racing.post(`approvals/${raced}/decision`, shownRaced.approval.approve.body);
  assert.deepEqual([refused.status, refused.body.error.code, reloadsOn(refused.body.error)], [409, 'digest_mismatch', true]);
  assert.equal(reloadsOn({code: 'not_awaiting_approval'}), true);
  assert.equal(reloadsOn({code: 'exact_action_incomplete'}), false, 'any other refusal is shown, not reloaded');
  const reloaded = (await racing.get('approval')).body;
  assert.deepEqual([reloaded.state, reloaded.approval.phase, await sessionState(racing)], ['pending', 'final', 'opened']);
  assert.equal((await racing.post(`approvals/${raced}/decision`, reloaded.approval.approve.body)).body.state, 'completed');
  await d.app.runtimes.wait(d.scope, raced, 5000);
  // A recipient name read from Slack holding U+202E: the page shows it marked, never as a direction change.
  d.slack.answers['users.lookupByEmail'] = () => ({ok: true, user: {id: 'U2', real_name: 'Grace‮amil.exe'}});
  const marked = await waitingCall('Marked'), marking = await approveLink(marked);
  await marking.post(`approvals/${marked}/decision`, (await marking.get('approval')).body.approval.approve.body);
  await d.app.runtimes.wait(d.scope, marked, 5000);
  const tricky = (await marking.get('approval')).body;
  assert.equal(blocksOf(tricky.approval).Fields, 'To: Grace‮amil.exe\nMessage: Marked', 'the page data carries the name exactly');
  const fields = describePage(tricky, {tenant: true}).exact.find(block => block.label === 'Fields');
  assert.equal(fields.text, 'To: Grace⟦U+202E⟧amil.exe\nMessage: Marked');
  await marking.post(`approvals/${marked}/decision`, tricky.approval.cancel.body);
  assert.equal(d.slack.writes().filter(call => call.name === 'chat.postMessage').length, 2, 'only the two calls approved at both stops posted');
});

test('part n: approve page: a call that runs to its end after its phase reads approval finishes the link on the page\'s next read', async t => {
  const d = await developerHarness(t), dm = d.capability('send-dm v1');
  // The direct message is Allow, and its read row asks: one stop before any read, then it runs to its end.
  d.bundle().permissions.set({connectionId: d.accounts.u1.slack, capabilityId: dm.id, mode: 'allow'});
  ceiling(d, 'slack', 'slack.workspace.read', 'ask');
  const callRef = (await execute(d, d.keys.standard, dm, DM)).body.callRef;
  d.app.registry.put('environments', {...d.app.registry.get('environments', d.scope.environmentId), redirectOrigins: ['http://localhost:5173']});
  const link = await d.open(d.keys.full, {externalUserId: 'u1', purpose: 'approve', callRef, successRedirectUri: 'http://localhost:5173/chat'});
  const shown = (await link.get('approval')).body;
  assert.deepEqual([shown.approval.phase, blocksOf(shown.approval)['person: Request']], ['reads', 'GET https://slack.com/api/users.lookupByEmail?email=grace%40example.com']);
  const gate = d.hold('users.lookupByEmail');
  // The held read is released whatever happens, so a failing check never leaves the call running past the test.
  try {
    assert.equal((await link.post(`approvals/${callRef}/decision`, shown.approval.approve.body)).body.state, 'continuing');
    await gate.reached;
    // While the reads run, the page shows the call running and the link stays open.
    const running = (await link.get('approval')).body;
    assert.deepEqual([running.state, running.status, Object.hasOwn(running, 'finished'), moved(running, shown.approval.digest)], ['settled', 'running', false, false], 'the page keeps waiting');
    assert.equal((await d.call(d.keys.full, 'GET', `/v1/connect-sessions/${link.id}`)).body.state, 'continuing');
  } finally { gate.release(); }
  await d.app.runtimes.wait(d.scope, callRef, 5000);
  const settled = (await link.get('approval')).body;
  assert.deepEqual([settled.state, settled.status, settled.finished.state, moved(settled, shown.approval.digest)], ['settled', 'succeeded', 'completed', true]);
  assert.match(settled.finished.redirect, /^http:\/\/localhost:5173\/chat\?fabric_session=cs_[a-z2-7]{26}&fabric_state=completed$/);
  const session = (await d.call(d.keys.full, 'GET', `/v1/connect-sessions/${link.id}`)).body;
  assert.deepEqual([session.state, session.result], ['completed', {callRef, decision: 'approved'}]);
  assert.equal((await link.get('approval')).body.error.code, 'already_finished');
});

test('part o: /v1/options with actionId lists only under Allow, records nothing, refuses a cursor replayed with another dependsOn value or query, and answers 400 for a configured value that fails the schema; test/tenant-options.test.mjs passes unchanged', async t => {
  const slack = slackFile();
  slack.actions.push(channelInfo());
  const d = await developerHarness(t, {slack, choices: [slackChoices()]}), info = d.capability('channel-info v1');
  // Slack's channel list, two pages and a third the source never reads; C0 is the channel it never offers, and one name holds the token.
  const pages = {'': {ok: true, channels: [{id: 'C0', name: 'archive'}, {id: 'C1', name: 'general'}, {id: 'C2', name: `leak ${SLACK_TOKEN}`}], response_metadata: {next_cursor: 'page-2'}},
    'page-2': {ok: true, channels: [{id: 'C3', name: 'team'}], response_metadata: {next_cursor: 'page-3'}}};
  d.slack.answers['conversations.list'] = ({query}) => pages[query.cursor ?? ''] ?? {ok: false, error: 'invalid_cursor'};
  const options = (body, key = d.keys.standard) => d.call(key, 'POST', '/v1/options', {externalUserId: 'u1', actionId: info.id, definitionHash: hash(info), input: 'channel', ...body});
  const listed = () => d.callsOf('conversations.list').length;
  const stored = () => ['jobs', 'usageEvents', 'actionPrepared', 'actionRecords'].map(name => d.repo().list(name).length);
  const before = stored(), PUBLIC = {kind: 'public_channel'};
  const first = await options({configured: PUBLIC});
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.deepEqual(first.body.options, [{label: 'general', value: 'C1'}, {label: 'leak [redacted]', value: 'C2'}], 'C0 is never offered, and no label carries the credential');
  const sent = new URL(d.callsOf('conversations.list')[0].url);
  assert.deepEqual([sent.pathname, Object.fromEntries(sent.searchParams)], ['/api/conversations.list', {exclude_archived: 'true', types: 'public_channel'}], 'only the source\'s constants and the configured kind');
  const second = await options({configured: PUBLIC, cursor: first.body.nextCursor});
  assert.deepEqual([second.status, second.body.options, Object.hasOwn(second.body, 'nextCursor')], [200, [{label: 'team', value: 'C3'}], false], 'at most two pages');
  assert.equal(new URL(d.callsOf('conversations.list')[1].url).searchParams.get('cursor'), 'page-2');
  // A cursor is bound to the configured values and the query it was read with.
  for (const replay of [{configured: {kind: 'private_channel'}, cursor: first.body.nextCursor}, {configured: PUBLIC, query: 'gen', cursor: first.body.nextCursor}]) {
    const refused = await options(replay);
    assert.deepEqual([refused.status, refused.body.error.code, refused.body.error.message], [400, 'invalid_request', 'This cursor belongs to another list.'], JSON.stringify(replay));
  }
  assert.deepEqual((await options({configured: PUBLIC, query: 'GEN'})).body.options, [{label: 'general', value: 'C1'}], 'searched locally');
  // configured holds only the choice's dependsOn values, each valid for the action's own input schema.
  for (const configured of [{kind: 'bogus'}, {...PUBLIC, channel: 'C1'}, {}, 'public_channel']) {
    const refused = await options({configured});
    assert.deepEqual([refused.status, refused.body.error.code], [400, 'invalid_request'], JSON.stringify(configured));
  }
  assert.equal((await options({configured: {}})).body.error.message, 'Send the value of kind in configured.', 'a value the list needs is asked for by name');
  assert.deepEqual([(await options({input: 'kind', configured: {}})).body.error.code, (await options({configured: PUBLIC, definitionHash: '0'.repeat(64)})).body.error.code], ['no_option_source', 'capability_changed']);
  assert.equal((await options({configured: PUBLIC, capabilityId: info.id})).status, 400, 'an operation or an action, never both');
  assert.equal((await options({configured: PUBLIC, accountRef: d.accounts.u1.notion})).status, 404, 'only an account the action runs on');
  assert.equal((await d.call(d.keys.standard, 'POST', '/v1/options', {externalUserId: 'u1', actionId: d.capability('find-channel v1').id, definitionHash: hash(d.capability('find-channel v1')), input: 'channel'})).status, 404, 'a candidate lists nothing');
  assert.deepEqual(stored(), before, 'never a job, a prepared row, a record or a usage record');
  // Allow only: an Ask or Never on the source's row, from a ceiling or the row's own proxy setting, lists nothing and calls nothing.
  const calls = listed();
  for (const [name, set, undo] of [['ceiling ask', () => ceiling(d, 'slack', 'slack.channels.read', 'ask'), () => ceiling(d, 'slack', 'slack.channels.read', null)],
    ['ceiling never', () => ceiling(d, 'slack', 'slack.channels.read', 'deny'), () => ceiling(d, 'slack', 'slack.channels.read', null)],
    ['row never', () => d.bundle().runtime.proxyPolicy.set({connectionId: d.accounts.u1.slack, row: 'group:slack.channels.read', mode: 'deny'}), () => d.bundle().runtime.proxyPolicy.set({connectionId: d.accounts.u1.slack, row: 'group:slack.channels.read', mode: 'allow'})]]) {
    set();
    const refused = await options({configured: PUBLIC});
    assert.deepEqual([refused.status, refused.body.error.code, listed()], [403, 'permission_denied', calls], name);
    undo();
  }
  assert.equal((await options({configured: PUBLIC})).status, 200, 'Allow again, it lists again');
  // Decided again after the credentials are read, and once more after the answer: a ceiling set meanwhile lists nothing.
  const connections = d.bundle().connections, credentials = connections.credentials.bind(connections);
  connections.credentials = async id => { ceiling(d, 'slack', 'slack.channels.read', 'deny'); return credentials(id); };
  const between = listed(), refusedBetween = await options({configured: PUBLIC});
  assert.deepEqual([refusedBetween.status, listed()], [403, between], 'nothing was sent');
  connections.credentials = credentials;
  ceiling(d, 'slack', 'slack.channels.read', null);
  const gate = d.hold('conversations.list'), during = options({configured: PUBLIC});
  await gate.reached;
  ceiling(d, 'slack', 'slack.channels.read', 'deny');
  gate.release();
  assert.deepEqual([(await during).status, (await during).body.error.code], [403, 'permission_denied'], 'what came back is withheld');
  ceiling(d, 'slack', 'slack.channels.read', null);
  // An account without the scope its row needs lists nothing.
  const account = d.repo().get('connections', d.accounts.u1.slack);
  d.repo().put('connections', {...account, scopes: account.scopes.filter(scope => scope !== 'channels:read')});
  const missing = listed(), unscoped = await options({configured: PUBLIC});
  assert.deepEqual([unscoped.status, listed()], [403, missing]);
  d.repo().put('connections', account);
  // With no action catalog loaded, no action lists anything.
  const {permissions, runtime} = d.bundle();
  permissions.actions = null; runtime.actions = null;
  assert.equal((await options({configured: PUBLIC})).status, 404);
});

test('part o: a configured value never moves a choice list to another row: GET /user/repos, a literal sibling of GET /user/{account_id}, lists nothing', async t => {
  const github = githubFile();
  github.actions.push(pickAccount());
  const d = await developerHarness(t, {github, choices: [githubChoices()]}), pick = d.capability('pick-account v1');
  const options = who => d.call(d.keys.standard, 'POST', '/v1/options', {externalUserId: 'u1', actionId: pick.id, definitionHash: hash(pick), input: 'account', configured: {who}});
  d.fail('GET /user/octocat', {status: 200, headers: {}, data: {items: [{id: 'octocat', name: 'The Octocat'}]}});
  const listed = await options('octocat');
  assert.deepEqual([listed.status, listed.body.options], [200, [{label: 'The Octocat', value: 'octocat'}]]);
  const moved = await options('repos');
  assert.deepEqual([moved.status, moved.body.error.code, d.callsOf('GET /user/repos').length], [403, 'permission_denied', 0]);
});

test('part o: a choice list request: path arguments in the path, the rest in the query or body, the cursor where page.into says, and search text only as its transform\'s output', () => {
  const post = {read: {request: 'POST /v1/spaces/{space}/search'}, page: {next: {pointer: '/next'}, into: {body: '/start_cursor'}, max: 2},
    search: {mode: 'provider', into: {body: '/query'}, transform: 'text.slackEscape@1', argument: 'text', pick: '/text'}};
  assert.deepEqual(choiceRequest(post, {args: {space: 'a b', filter: 'page'}, cursor: 'c2', query: 'x<y'}),
    {input: {method: 'POST', path: '/v1/spaces/a%20b/search', body: {filter: 'page', start_cursor: 'c2', query: 'x&lt;y'}}}, 'the provider sees the transform\'s output, never the raw text');
  const get = {read: {request: 'GET /conversations.list'}, page: {next: {pointer: '/next'}, into: {query: 'cursor'}, max: 2}, search: {mode: 'local'}};
  assert.deepEqual(choiceRequest(get, {args: {limit: 50, exclude_archived: true}, cursor: 'c2', query: 'gen'}), {input: {method: 'GET', path: '/conversations.list', query: {limit: '50', exclude_archived: 'true', cursor: 'c2'}}}, 'local search sends nothing');
  assert.deepEqual(choiceRequest({read: {operation: 'calendar.calendarList.list'}, page: {next: {pointer: '/nextPageToken'}, into: {query: 'pageToken'}, max: 10}, search: null}, {args: {minAccessRole: 'reader'}, cursor: 'p2'}),
    {operation: 'calendar.calendarList.list', args: {minAccessRole: 'reader', pageToken: 'p2'}});
  assert.throws(() => choiceRequest(post, {args: {filter: 'page'}}), error => error.code === 'action_refused' && error.details.reason === 'path_value');
  assert.equal(choiceNext(get, {status: 200, headers: {}, data: {next: 'c2'}}, {pages: 1}), 'c2');
  assert.equal(choiceNext(get, {status: 200, headers: {}, data: {next: 'c3'}}, {pages: 2}), null, 'page.max pages at most');
  assert.equal(choiceNext(get, {status: 200, headers: {}, data: {next: ''}}, {pages: 1}), null, 'the list ended');
});

test('parts m to p: no new route, so the isolation matrix (test/tenant-isolation-routes.test.mjs) is unchanged', () => {
  // The /v1 route table, as recorded at 89b24af before step 11 began: actions ride the routes that were there.
  assert.equal(ROUTES.length, 48);
  assert.equal(createHash('sha256').update(JSON.stringify(ROUTES)).digest('hex'), '574b640310c18de8b1235c1a838bcddb58119bc5b707091251ed77b4a740a309');
});

// ---- the check of parts n to q (docs/F10.11-BUILD-MAP.md section 15) -------------------------------------------------------------------
test('check of part n: an action whose prepared bytes are missing or changed has no decision path on the relay list or the user\'s activity, and no Approve on Fabric\'s page', async t => {
  const d = await developerHarness(t), dm = d.capability('send-dm v1');
  const callRef = (await execute(d, d.keys.standard, dm, DM)).body.callRef, row = d.repo().get('actionPrepared', callRef);
  const link = await d.open(d.keys.full, {externalUserId: 'u1', purpose: 'approve', callRef});
  /** What each surface offers, read apart from whether its blocks are complete: a decision path, or an Approve button. */
  const offered = async () => {
    const [item] = await relayList(d), [listed] = (await d.call(d.keys.full, 'GET', '/v1/users/u1/activity')).body.approvals, page = (await link.get('approval')).body;
    return {relay: Object.hasOwn(item, 'decide'), activity: Object.hasOwn(listed, 'decide'), page: page.approval.approve !== null, reject: page.approval.cancel !== null};
  };
  assert.deepEqual(await offered(), {relay: true, activity: true, page: true, reject: true});
  const tampered = {...row, content: {...row.content, resolving: {...row.content.resolving, body: '{"users":"U9"}'}}};
  for (const [name, change] of [['missing', () => d.repo().delete('actionPrepared', callRef)], ['tampered', () => d.repo().put('actionPrepared', tampered)]]) {
    change();
    assert.deepEqual(await offered(), {relay: false, activity: false, page: false, reject: true}, `${name}: no decision path and no Approve, Reject still offered`);
  }
});

test('check of part n: a continued approve link whose call another party then rejected finishes saying it did not complete, never that it is running', async t => {
  const d = await developerHarness(t), dm = d.capability('send-dm v1');
  const callRef = (await execute(d, d.keys.standard, dm, DM)).body.callRef, link = await d.open(d.keys.full, {externalUserId: 'u1', purpose: 'approve', callRef});
  assert.equal((await link.post(`approvals/${callRef}/decision`, (await link.get('approval')).body.approval.approve.body)).body.state, 'continuing');
  await d.app.runtimes.wait(d.scope, callRef, 5000);
  // The developer's own screen rejects the final stop while the person's link still continues.
  const [final] = await relayList(d);
  assert.equal(final.phase, 'final');
  assert.equal((await d.call(d.keys.full, 'POST', final.decide.path, {decision: 'reject', digest: final.digest})).body.status, 'cancelled');
  const page = (await link.get('approval')).body;
  assert.deepEqual([page.state, page.status, page.finished.state], ['settled', 'cancelled', 'completed']);
  assert.equal(outcomeOf({decision: 'approved', status: page.status, redirect: page.finished.redirect}).line, 'Approved, but it did not complete.');
  assert.deepEqual(d.slack.writes().map(item => item.name), ['conversations.open'], 'the message was never posted');
});

/**
 * A developer environment whose only action is Gmail Read a label, its label picked from Gmail's version 1 labels source (a typed
 * operation, gmail.users.labels.list, active in the platform catalog and bound in Gmail's map), with one Gmail account whose token the
 * labels answer repeats. Returns {options(body), ceiling(mode), calls}.
 */
async function gmailLabelsHarness(t, token) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-action-gmail-')), folder = mkdtempSync(path.join(tmpdir(), 'fabric-action-gmail-catalog-'));
  const typed = {...compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}],
    paths: {'/gmail/v1/users/{userId}/labels': {get: {operationId: 'gmail.users.labels.list', parameters: [{name: 'userId', in: 'path', required: true, schema: {type: 'string'}}], responses: {200: {description: 'OK'}}}}}}}).capabilities[0], status: 'active'};
  const recorded = googleMap('gmail'), map = {...recorded, operations: recorded.operations.map(operation => operation.id === 'gmail.users.labels.list' ? {...operation, capabilityId: typed.id} : operation)};
  const text = max => ({type: 'string', minLength: 1, maxLength: max});
  const file = {schemaVersion: 1, appId: 'gmail', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {userId: 'me'}, actions: [
    {id: `gmail.action.read-label.v1.${'0'.repeat(24)}`, key: 'read-label', version: 1, name: 'Read a label', description: 'Reads one label picked from a list.', effect: 'read', row: 'gmail.labels.read',
      hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true}, inputSchema: {type: 'object', properties: {labelId: text(64)}, required: ['labelId'], additionalProperties: false},
      outputSchema: {type: 'object', properties: {name: {type: 'string', maxLength: 200}}, required: ['name'], additionalProperties: false}, guards: [], prepare: [],
      choices: [{input: 'labelId', source: 'labels'}],
      perform: [{id: 'label', method: 'GET', path: '/gmail/v1/users/{userId}/labels/{id}', params: {id: {input: '/labelId'}}, expect: {status: [200], require: []}}],
      output: {name: {step: 'label', pointer: '/name'}}, preview: [{label: 'Label', expr: {input: '/labelId'}}], definitive: [404], certified: {evidence: 'docs/live-evidence/gmail/actions.json', definitionHash: '0'.repeat(64)}}]};
  const deps = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, identities: new Map([['gmail', definitionFor('google')]]), maps: new Map([['gmail', map]]), choices: new Map()};
  const written = withIds(file, deps), directory = path.join(folder, 'catalog', 'actions'), live = path.join(folder, 'docs', 'live-evidence', 'gmail');
  mkdirSync(directory, {recursive: true});
  mkdirSync(live, {recursive: true});
  writeFileSync(path.join(directory, 'gmail.json'), JSON.stringify(written));
  writeFileSync(path.join(live, 'actions.json'), JSON.stringify(Object.fromEntries(validateActionFile(written, deps).actions.map(entry => [entry.id, {passed: true, transforms: {}, definitionHash: entry.definitionHash}]))));
  const platform = new PlatformStore({root});
  platform.put('capabilities', typed);
  platform.put('applicationMaps', map);
  seedActions(platform, loadActionCatalog({directory, evidenceRoot: folder, deps, maps: new Map([['gmail', map]])}), {audit: () => {}});
  platform.close();
  const calls = [];
  const request = async options => {
    calls.push(`${options.method ?? 'GET'} ${options.url}`);
    if (options.url === 'https://gmail.googleapis.com/gmail/v1/users/me/labels') return {status: 200, headers: {}, data: {labels: [{id: 'INBOX', name: 'INBOX'}, {id: token, name: `Receipts ${token}`}]}};
    throw Object.assign(new Error(`unexpected ${options.url}`), {sent: false});
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, actions: {directory, evidenceRoot: folder}, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); rmSync(folder, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev), key = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  const call = async (method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    return {status: response.status, body: await response.json()};
  };
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u1'});
  const repo = app.stores.open(scope).repository, user = repo.list('endUsers').find(item => item.subjectId === 'u1' && item.status === 'active'), id = randomUUID(), now = app.registry.now();
  const scopes = ['https://www.googleapis.com/auth/gmail.readonly'];
  repo.put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: 'g-1', displayName: 'One'}, allowedOrigins: ['https://gmail.googleapis.com'], scopes,
    createdAt: now, updatedAt: now, authRevision: randomUUID()}, {subjectId: 'u1', userRecordId: user.id}));
  app.stores.open(scope).vault.set(id, {accessToken: token, refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000, scopes});
  const action = repo.get('capabilities', validateActionFile(written, deps).actions[0].id);
  assert.equal(action?.status, 'active', 'Read a label runs in this environment');
  return {calls, options: body => call('POST', '/v1/options', {externalUserId: 'u1', actionId: action.id, definitionHash: hash(action), input: 'labelId', ...body}),
    ceiling(mode) {
      const environment = app.registry.get('environments', scope.environmentId);
      app.registry.put('environments', {...environment, apps: {...environment.apps, gmail: {...environment.apps?.gmail, ceilings: mode === null ? {} : {'gmail.labels.read': mode}}}});
    }};
}

test('check of part o: an action choice from a typed operation source lists only under Allow on its row, and no value or label carries the credential', async t => {
  const token = 'ya29.gmail-check-token-5b1e', g = await gmailLabelsHarness(t, token);
  const listed = await g.options({});
  assert.equal(listed.status, 200, JSON.stringify(listed.body));
  assert.deepEqual(listed.body.options, [{label: 'INBOX', value: 'INBOX'}, {label: 'Receipts [redacted]', value: '[redacted]'}], 'the account\'s own token is scrubbed from labels and values');
  assert.deepEqual(g.calls, ['GET https://gmail.googleapis.com/gmail/v1/users/me/labels']);
  // An Ask or Never on the source's row lists nothing and calls nothing.
  for (const mode of ['ask', 'deny']) {
    g.ceiling(mode);
    const refused = await g.options({});
    assert.deepEqual([refused.status, refused.body.error?.code, g.calls.length], [403, 'permission_denied', 1], mode);
  }
  g.ceiling(null);
  assert.equal((await g.options({})).status, 200, 'Allow again, it lists again');
});

test('check of part o: a request template source scrubs the credential from every value and detail it offers', async t => {
  const slack = slackFile(), choices = slackChoices();
  slack.actions.push(channelInfo());
  choices.sources[0].detail = ['/purpose/value'];
  const d = await developerHarness(t, {slack, choices: [choices]}), info = d.capability('channel-info v1');
  d.slack.answers['conversations.list'] = () => ({ok: true, channels: [{id: 'C1', name: 'general', purpose: {value: 'Company news'}}, {id: `C2${SLACK_TOKEN}`, name: 'secret', purpose: {value: `Holds ${SLACK_TOKEN}`}}]});
  const listed = await d.call(d.keys.standard, 'POST', '/v1/options', {externalUserId: 'u1', actionId: info.id, definitionHash: hash(info), input: 'channel', configured: {kind: 'public_channel'}});
  assert.equal(listed.status, 200, JSON.stringify(listed.body));
  assert.deepEqual(listed.body.options, [{label: 'general', value: 'C1', detail: 'Company news'}, {label: 'secret', value: 'C2[redacted]', detail: 'Holds [redacted]'}]);
  assert.equal(JSON.stringify(listed.body).includes(SLACK_TOKEN), false);
});

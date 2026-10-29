import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {Client} from '@modelcontextprotocol/client';
import {InMemoryTransport} from '@modelcontextprotocol/server';
import {createMcpAdapter} from '../lib/mcp-adapter.mts';
import {FabricProtocol, FABRIC_PROTOCOL, protocolManifest} from '../lib/fabric-protocol.mjs';
import {ContinuationService, operationScopes} from '../lib/continuations.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {PermissionManager, capabilityPermissionHash} from '../lib/permissions.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {workspaceCapabilities} from '../lib/local-driver.mjs';
import {loadActionCatalog} from '../lib/action-catalog.mjs';
import {actionCapability} from '../lib/actions.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {Vault} from '../lib/vault.mjs';
import {validateAuthDefinition} from '../contracts/auth-definition.mts';
import {createApp} from '../server.mjs';
import {freePort} from './fixtures/signin-fixture.mjs';
import {actionHarness, certifiedFile, directMessageFile, OWNER, EVIDENCE} from './fixtures/actions/runtime-fixture.mjs';
import {fixtureActions, fixtureGroups, fixtureConfigs, fixtureSignIn} from './fixtures/actions/fixture-app.mjs';

// F10.11 part l (docs/F10.11-BUILD-MAP.md part l, section 3): the local agent surfaces. capabilities.list and fabric_list_capabilities
// list actions first, every entry with its kind and its four hints (MCP renames them), an action with its output schema, its rows and
// its inputs' choices; only an active action binds, and a moved step or a newly sensitive member makes its grant change; calls.create links
// its reservation before the first request; MCP keeps the new codes and the superseded notice in closed shapes; the tools route lists
// actions first with their own output schema; and a continuation may ask for an active action, with the scopes its steps need.
// Run on the fake app's run harness (test/fixtures/actions/runtime-fixture.mjs) and its simulator.

const ENDPOINT = 'http://127.0.0.1:59998/fabric/v1', ORIGIN = 'http://127.0.0.1:59998';
/** The designated harness with a workspace account beside the fixture accounts, and fabric/0.1 over it: the runtime asks the protocol
 *  about every client job, as server.mjs wires them. */
function protocolHarness(t, options = {}) {
  const h = actionHarness(t, {designated: true, ...options});
  for (const capability of workspaceCapabilities) h.store.put('capabilities', capability);
  h.store.put('connections', {id: 'workspace-account', appId: 'workspace', driver: 'workspace', authMethod: 'workspace', authRevision: 'w1', status: 'ready', identity: {id: 'workspace'}, allowedOrigins: [],
    createdAt: new Date(h.now).toISOString()});
  // Every item open and owned, so Rename or label an item's guard lets it change them (test/actions-runtime.test.mjs seedItems()).
  for (const item of h.simulator.data.items) { item.status = 'open'; item.owner = `owner-of-${item.id}@fixture.test`; }
  const protocol = new FabricProtocol({store: h.store, runtime: h.runtime, clock: () => h.now, origin: ORIGIN});
  h.runtime.authorizeSource = job => protocol.authorizeJob(job);
  return Object.assign(h, {protocol,
    grant: (bindings, extra = {}) => protocol.createClient({name: 'Action agent', bindings: bindings.map(([connectionId, capabilityId]) => ({connectionId, capabilityId})), ...extra}, OWNER),
    call: (token, method, params = {}, id = randomUUID()) => protocol.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id, method, params})});
}
/** An MCP client over the adapter, whose Fabric is `protocol` in memory: nothing listens on a port. */
async function mcpOver(t, token, answer) {
  const fetch = async (url, options) => new Response(JSON.stringify(await answer(options.headers.Authorization, JSON.parse(options.body))), {headers: {'content-type': 'application/json'}});
  const server = createMcpAdapter({env: {FABRIC_ENDPOINT: ENDPOINT, FABRIC_CLIENT_TOKEN: token}, fetch}), client = new Client({name: 'action-exposure', version: '1.0.0'});
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); });
  return client;
}
const listTool = async client => (await client.callTool({name: 'fabric_list_capabilities', arguments: {}})).structuredContent;
const P = name => ({name, in: 'path', required: true, schema: {type: 'string'}});
/** One typed http operation of the fixture app, compiled on a public host and moved to the fixture's API base (as part e's tests make it). */
function typedOne(route, method, operationId) {
  const [cap] = compileOpenApi({appId: 'fixture', document: {openapi: '3.1.0', info: {title: 'Fixture', version: '1'}, servers: [{url: 'https://api.example.com'}],
    paths: {[route]: {[method]: {operationId, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(([, name]) => P(name)), responses: {200: {description: 'Done'}}}}}}}).capabilities;
  return {...cap, status: 'active', request: {...cap.request, url: cap.request.url.replace('https://api.example.com', 'https://api.fixture.test')}};
}
const UPDATE = {itemId: 'I1', change: 'label', labels: ['Work']};
const OK = {status: [200], require: []};
const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
/** Trash an item: PATCH /items/{item_id} with in_trash, which a body route of fixture.items.edit moves to fixture.items.delete (as in
 *  test/actions-permissions.test.mjs), so it touches the row the route moved its step from. */
const trashItem = () => ({id: `fixture.action.trash-item.v1.${'0'.repeat(24)}`, key: 'trash-item', version: 1, name: 'Trash an item', description: 'Moves one item to the trash.',
  effect: 'delete', row: 'fixture.items.delete', hints: {readOnly: false, destructive: true, idempotent: false, openWorld: true}, guards: [], prepare: [], definitive: [400],
  inputSchema: closed({itemId: {type: 'string', minLength: 1, maxLength: 64}}), outputSchema: closed({id: {type: 'string', maxLength: 64}}),
  perform: [{id: 'trash', method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, body: {object: {in_trash: {const: true}}}, expect: OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, expect: OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {input: '/itemId'}}], assert: []},
  output: {id: {step: 'trash', pointer: '/id'}}, preview: [{label: 'Item', expr: {input: '/itemId'}}], certified: {evidence: EVIDENCE, definitionHash: '0'.repeat(64)}});
const ZONE = {either: [{step: 'zone', pointer: '/value'}, {step: 'primary', pointer: '/name'}]};
/** Find with an optional read (R7): GET /keys is optional, GET /labels is its fallback. */
const findWithZone = () => ({id: `fixture.action.find-with-zone.v1.${'0'.repeat(24)}`, key: 'find-with-zone', version: 1, name: 'Find with a zone', description: 'Lists items in a zone.',
  effect: 'read', row: 'fixture.items.read', hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true}, guards: [], definitive: [400],
  inputSchema: closed({kind: {type: 'string', enum: ['all', 'open']}}), outputSchema: closed({zone: {type: 'string', maxLength: 100}}),
  prepare: [{id: 'zone', method: 'GET', path: '/keys', optional: true, expect: OK}, {id: 'primary', method: 'GET', path: '/labels', fallbackFor: 'zone', expect: OK}],
  perform: [{id: 'list', method: 'GET', path: '/items', query: {kind: {input: '/kind'}, zone: ZONE}, expect: OK}], output: {zone: ZONE}, preview: [{label: 'Show', expr: {input: '/kind'}}],
  certified: {evidence: EVIDENCE, definitionHash: '0'.repeat(64)}});

test('part l: capabilities.list and fabric_list_capabilities list actions first; every entry has its kind and four hints; an action its output schema, rows and choices', async t => {
  const h = protocolHarness(t, {file: certifiedFile(file => { file.actions.push(trashItem()); })}), list = h.idOf('list-items v1'), update = h.idOf('update-item v1'), remove = h.idOf('remove-labels v1'), trash = h.idOf('trash-item v1');
  const {token} = h.grant([['workspace-account', 'workspace.list.v1'], [h.account, update], ['workspace-account', 'workspace.write.v1'], [h.account, list], [h.account, remove], [h.account, trash]]);
  const {result} = await h.call(token, 'capabilities.list');
  assert.deepEqual(result.capabilities.map(entry => [entry.id, entry.kind, entry.status]),
    [[update, 'action', 'available'], [list, 'action', 'available'], [remove, 'action', 'available'], [trash, 'action', 'available'], ['workspace.list.v1', 'operation', 'available'], ['workspace.write.v1', 'operation', 'available']],
    'actions first, then operations, each in grant order');
  const [updating, listing, removing, trashing, files, writing] = result.capabilities;
  // Remove labels says it is destructive and idempotent, as its file reviewed it: never read from its effect.
  assert.deepEqual(removing.annotations, {readOnly: false, destructive: true, idempotent: true, openWorld: true});
  // Trash an item touches its own row, and the row its step's member lives in before a body route moves it.
  assert.deepEqual(trashing.rows, ['Delete items', 'Edit items', 'Access items']);
  // An operation's hints follow its effect, as the developer catalog derives them; an action's are its reviewed hints.
  assert.deepEqual([files.annotations, writing.annotations], [{readOnly: true, destructive: false, idempotent: true, openWorld: true}, {readOnly: false, destructive: false, idempotent: false, openWorld: true}]);
  assert.deepEqual([listing.annotations, updating.annotations], [{readOnly: true, destructive: false, idempotent: true, openWorld: true}, {readOnly: false, destructive: false, idempotent: false, openWorld: true}]);
  assert.deepEqual(listing.outputSchema, h.capability('list-items v1').outputSchema);
  // Its rows: its own first, then every other row a step touches.
  assert.deepEqual([listing.rows, updating.rows], [['Access items'], ['Edit items', 'Access items']]);
  assert.deepEqual([listing.choices, updating.choices], [[{input: 'labelId', dependsOn: []}], [{input: 'itemId', dependsOn: []}, {input: 'labels', dependsOn: ['itemId']}]]);
  assert.deepEqual([updating.driver, updating.effect, updating.approval, listing.approval], ['action', 'write', 'ask', 'allow']);
  for (const operation of [files, writing]) for (const field of ['outputSchema', 'rows', 'choices']) assert.equal(Object.hasOwn(operation, field), false, `${operation.id}: ${field} is an action's`);
  assert.deepEqual([protocolManifest.features.actions, protocolManifest.features.twoPhaseApproval, protocolManifest.methods.length], [true, true, 6], 'no method is added');
  // MCP keeps Fabric's order and fields, with its own hint names.
  const mcp = await mcpOver(t, token, (authorization, envelope) => h.protocol.handle(authorization, envelope));
  const listed = (await listTool(mcp)).capabilities;
  assert.deepEqual(listed.map(entry => [entry.id, entry.kind]), [[update, 'action'], [list, 'action'], [remove, 'action'], [trash, 'action'], ['workspace.list.v1', 'operation'], ['workspace.write.v1', 'operation']]);
  assert.deepEqual(listed[1].annotations, {readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true});
  assert.deepEqual(listed[5].annotations, {readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true});
  assert.deepEqual([listed[1].outputSchema, listed[0].rows, listed[0].choices], [listing.outputSchema, updating.rows, updating.choices]);
  assert.equal(Object.hasOwn(listed[4], 'outputSchema'), false);
  const tools = (await mcp.listTools()).tools;
  assert.match(tools.find(tool => tool.name === 'fabric_list_capabilities').description, /Actions come first/);
  assert.match(tools.find(tool => tool.name === 'fabric_invoke').description, /An action may ask the owner twice/);
});

test('part l: createClient refuses a candidate and binds an active action with the file\'s definitionHash; a newly sensitive member or a moved step answers grant_changed', async t => {
  const candidate = protocolHarness(t, {file: certifiedFile(file => { file.reviewStatus = fixtureActions().reviewStatus; })});
  assert.throws(() => candidate.grant([[candidate.account, candidate.idOf('list-items v1')]]), {code: 'permission_denied', message: 'Only currently permitted, reviewed operations may be delegated.'});
  assert.equal(candidate.store.list('clientGrants').length, 0);
  const h = protocolHarness(t), list = h.idOf('list-items v1'), update = h.idOf('update-item v1');
  const {client, token} = h.grant([[h.account, update], [h.account, list]]);
  assert.deepEqual(client.bindings.map(binding => binding.definitionHash), [update, list].map(id => h.catalog.entries.get(id).entry.definitionHash));
  // A typed operation with a sensitive verdict that Rename or label an item's first read reaches: the action is sensitive now.
  h.store.put('capabilities', typedOne('/items/{itemId}', 'get', 'getItemApiKey'));
  const statuses = async (protocol = h.protocol) => (await protocol.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id: randomUUID(), method: 'capabilities.list', params: {}})).result.capabilities.map(entry => [entry.id, entry.status, entry.reason ?? null]);
  assert.deepEqual(await statuses(), [[update, 'unavailable', 'grant_changed'], [list, 'available', null]]);
  const sent = await h.call(token, 'calls.create', {connectionId: h.account, capabilityId: update, definitionHash: client.bindings[0].definitionHash, args: UPDATE});
  assert.equal(sent.error.code, 'grant_changed');
  h.store.delete('capabilities', h.store.list('capabilities').find(capability => capability.name === 'getItemApiKey').id);
  assert.deepEqual(await statuses(), [[update, 'available', null], [list, 'available', null]]);
  // The next start reads the rows again with GET /items/{item_id} moved to another row: the placements are in the grant's binding.
  const moved = fixtureGroups(rows => ({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.read' ? {...group, requests: group.requests.filter(member => member !== 'GET /items/{item_id}')}
    : group.id === 'fixture.keys.read' ? {...group, requests: [...group.requests, 'GET /items/{item_id}']} : group)}));
  const catalog = loadActionCatalog({directory: h.directory, evidenceRoot: h.root, maps: h.maps, deps: {...h.deps, groups: moved, configs: fixtureConfigs(moved)}, codeHashes: h.codeHashes});
  const permissions = new PermissionManager({store: h.store, groups: moved, configs: fixtureConfigs(moved)}), proxyPolicy = new ProxyPolicy({store: h.store, permissions, groups: moved, configs: fixtureConfigs(moved)});
  const runtime = new Runtime({store: h.store, permissions, proxyPolicy, actions: catalog, connections: h.connections, request: h.simulator.request, clock: () => h.now, ownerPrincipal: OWNER});
  const next = new FabricProtocol({store: h.store, runtime, clock: () => h.now});
  runtime.authorizeSource = job => next.authorizeJob(job);
  assert.deepEqual(await statuses(next), [[update, 'unavailable', 'grant_changed'], [list, 'available', null]]);
});

test('part l: client isolation; a client revoked between the phases sends nothing, and one revoked while phase 2 runs gets no result', async t => {
  const h = protocolHarness(t), list = h.idOf('list-items v1'), update = h.idOf('update-item v1');
  const a = h.grant([[h.account, list], [h.account, update]]), b = h.grant([[h.account, list]]);
  const input = (grant, capabilityId, args) => ({connectionId: h.account, capabilityId, definitionHash: grant.client.bindings.find(binding => binding.capabilityId === capabilityId).definitionHash, args});
  const listed = await h.call(a.token, 'calls.create', input(a, list, {kind: 'all'}));
  assert.equal(listed.result.status, 'succeeded');
  assert.equal((await h.call(b.token, 'calls.get', {callId: listed.result.id})).error.code, 'not_found', 'another client never sees the call');
  assert.equal((await h.call(b.token, 'calls.create', input(a, update, UPDATE))).error.code, 'permission_denied', 'nor runs what it was not given');
  // Rename or label an item stops for its final bytes (its own default asks); the client is revoked before the owner approves.
  const waiting = await h.call(a.token, 'calls.create', input(a, update, UPDATE));
  assert.deepEqual([waiting.result.status, h.store.get('jobs', waiting.result.id).action.phase], ['awaiting_approval', 'final']);
  // Its reads ran, so its card says the exact request is prepared; the approval pointer keeps its shape.
  assert.match(waiting.result.card.summary, /^Fabric prepared the exact request\. Waiting for approval in Fabric\./);
  assert.deepEqual(Object.keys(waiting.result.approval).sort(), ['expiresAt', 'url']);
  h.protocol.revokeClient(a.client.id);
  const job = h.store.get('jobs', waiting.result.id);
  await assert.rejects(h.runtime.approve(job.id, job.approvalDigest, OWNER));
  assert.deepEqual(h.simulator.writes(), [], 'phase 2 sends nothing');
  assert.equal((await h.call(a.token, 'calls.get', {callId: job.id})).error.code, 'unauthorized');
  // Revoked while phase 2 runs: the change was sent, the readback answers after the revocation, and the output is withheld.
  const c = h.grant([[h.account, update]]), second = await h.call(c.token, 'calls.create', input(c, update, UPDATE)), stopped = h.store.get('jobs', second.result.id);
  const gate = h.simulator.hold('GET /items/{item_id}'), approving = h.runtime.approve(stopped.id, stopped.approvalDigest, OWNER);
  await Promise.race([gate.reached, approving]);
  h.protocol.revokeClient(c.client.id);
  gate.release();
  const ended = await approving;
  assert.deepEqual([ended.status, ended.result, ended.errorCode], ['uncertain', null, 'authority_changed'], 'sent, so uncertain; its output withheld because authority changed');
  assert.equal(h.simulator.writes().length, 1);
  assert.equal((await h.call(c.token, 'calls.get', {callId: stopped.id})).error.code, 'unauthorized');
});

test('part l: calls.create links its reservation before the first request, so a crash mid-sequence replays the job\'s real status', async t => {
  const h = protocolHarness(t), list = h.idOf('list-items v1'), {client, token} = h.grant([[h.account, list]]), requestId = 'list-once';
  const params = {connectionId: h.account, capabilityId: list, definitionHash: client.bindings[0].definitionHash, args: {kind: 'all'}};
  const gate = h.simulator.hold('GET /items'), first = h.call(token, 'calls.create', params, requestId);
  await gate.reached;
  const reservation = h.store.list('protocolRequests').find(item => item.requestId === requestId), running = h.store.list('jobs').find(job => job.capabilityId === list);
  assert.deepEqual([reservation.status, reservation.jobId, running.status], ['recorded', running.id, 'running'], 'linked before the first request was answered');
  // Fabric restarts while the read is in flight: a new runtime and protocol over the same store.
  const runtime = new Runtime({store: h.store, permissions: h.permissions, proxyPolicy: h.proxyPolicy, actions: h.catalog, connections: h.connections, request: h.simulator.request, clock: () => h.now, ownerPrincipal: OWNER});
  const restarted = new FabricProtocol({store: h.store, runtime, clock: () => h.now});
  runtime.authorizeSource = job => restarted.authorizeJob(job);
  runtime.recover();
  const replay = await restarted.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id: requestId, method: 'calls.create', params});
  assert.deepEqual([replay.result.id, replay.result.status], [running.id, 'failed'], 'the replay answers the job, which ended failed with nothing written');
  gate.release();
  await first;
});

test('part l: fabric/0.1 refuses an action with its own code: action_refused keeps its code through the allowlist', async t => {
  const h = protocolHarness(t), update = h.idOf('update-item v1'), {client, token} = h.grant([[h.account, update]]);
  // With its reads at Ask, the reads' bytes are built when the call is accepted; an item id that is a dot path refuses there.
  h.proxyPolicy.set({connectionId: h.account, row: 'group:fixture.items.read', mode: 'ask'});
  const refused = await h.call(token, 'calls.create', {connectionId: h.account, capabilityId: update, definitionHash: client.bindings[0].definitionHash, args: {...UPDATE, itemId: '..'}});
  assert.equal(refused.error.code, 'action_refused');
  assert.deepEqual([h.store.list('jobs').length, h.simulator.calls.length], [0, 0]);
});

test('part l: the strict MCP projection: hint names, kinds, rows, choices and output schemas in closed shapes; malformed ones refused; extra fields dropped; order kept', async t => {
  const token = `fab_client.${randomUUID()}.${'b'.repeat(43)}`, hash = 'c'.repeat(64);
  const annotations = {readOnly: false, destructive: true, idempotent: false, openWorld: true};
  const action = {id: 'fixture.action.x.v1.abc', connectionId: 'acct', definitionHash: hash, kind: 'action', name: 'Do it', description: 'Does it.', appId: 'fixture', driver: 'action', inputSchema: {type: 'object'},
    effect: 'delete', approval: 'ask', status: 'available', annotations, outputSchema: {type: 'object', properties: {id: {type: 'string'}}}, rows: ['Delete items', 'Access items'], choices: [{input: 'itemId', dependsOn: []}], extra: 'dropped'};
  const operation = {id: 'workspace.list.v1', connectionId: 'ws', definitionHash: hash, kind: 'operation', name: 'List', description: '', appId: 'workspace', driver: 'workspace', inputSchema: {type: 'object'},
    effect: 'read', approval: 'allow', status: 'available', annotations: {readOnly: true, destructive: false, idempotent: true, openWorld: true}};
  const legacy = {...operation, id: 'legacy', kind: undefined, annotations: undefined};
  let served;
  const mcp = await mcpOver(t, token, (authorization, envelope) => ({protocol: 'fabric/0.1', id: envelope.id, result: {capabilities: served}}));
  served = [action, operation, JSON.parse(JSON.stringify(legacy))];
  const listed = (await listTool(mcp)).capabilities;
  assert.deepEqual(listed.map(entry => [entry.id, entry.kind ?? 'operation']), [['fixture.action.x.v1.abc', 'action'], ['workspace.list.v1', 'operation'], ['legacy', 'operation']], 'order kept; no kind is an operation');
  assert.deepEqual(listed[0], {id: action.id, connectionId: 'acct', definitionHash: hash, kind: 'action', status: 'available', name: 'Do it', description: 'Does it.', appId: 'fixture', driver: 'action', inputSchema: {type: 'object'},
    effect: 'delete', approval: 'ask', annotations: {readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true}, outputSchema: action.outputSchema, rows: action.rows, choices: action.choices});
  assert.deepEqual([Object.hasOwn(listed[2], 'kind'), Object.hasOwn(listed[2], 'annotations')], [false, false], 'an older Fabric\'s entry passes unchanged: no kind or hints invented');
  const refused = async entry => { served = [entry]; const reply = await mcp.callTool({name: 'fabric_list_capabilities', arguments: {}}); return reply.isError ? reply.structuredContent.error.code : 'accepted'; };
  for (const [what, entry] of [
    ['an unknown kind', {...operation, kind: 'workflow'}], ['an unknown kind on an unavailable entry', {id: 'x', connectionId: 'ws', definitionHash: hash, kind: 'workflow', status: 'unavailable', reason: 'permission_denied'}], ['an action with no hints', {...action, annotations: undefined}], ['a hint that is not true or false', {...action, annotations: {...annotations, readOnly: 'no'}}],
    ['a hint missing', {...action, annotations: {readOnly: false, destructive: true, idempotent: false}}], ['an action with no output schema', {...action, outputSchema: undefined}],
    ['an output schema that holds the token', {...action, outputSchema: {type: 'object', description: token}}], ['no rows', {...action, rows: []}], ['17 rows', {...action, rows: Array.from({length: 17}, (_, at) => `Row ${at}`)}],
    ['a row of 201 characters', {...action, rows: ['x'.repeat(201)]}], ['a choice with another field', {...action, choices: [{input: 'itemId', dependsOn: [], source: 'items'}]}],
    ['a choice whose dependsOn is not a list', {...action, choices: [{input: 'itemId', dependsOn: 'x'}]}], ['an operation with action fields', {...operation, rows: ['Access items']}],
    ['a request-only entry of another driver', {id: 'x', appId: 'fixture', connectionId: null, definitionHash: hash, kind: 'action', name: 'X', description: '', driver: 'browser', inputSchema: {type: 'object'}, effect: 'read', approval: 'after_connection', status: 'connection_required', signIn: 'available', annotations, outputSchema: {type: 'object'}, rows: ['Access items'], choices: []}],
  ]) assert.equal(await refused(JSON.parse(JSON.stringify(entry))), 'invalid_response', what);
  // A request-only action entry carries driver action.
  served = [{id: 'fixture.action.y.v1.abc', appId: 'fixture', connectionId: null, definitionHash: hash, kind: 'action', name: 'Y', description: '', driver: 'action', inputSchema: {type: 'object'}, effect: 'read', approval: 'after_connection',
    status: 'connection_required', signIn: 'available', annotations, outputSchema: {type: 'object'}, rows: ['Access items'], choices: []}];
  assert.deepEqual((await listTool(mcp)).capabilities[0].driver, 'action');
});

test('part l: MCP keeps input_schema_changed, action_refused and superseded with their words, and an unavailable entry\'s replacedBy', async t => {
  const token = `fab_client.${randomUUID()}.${'d'.repeat(43)}`, hash = 'e'.repeat(64);
  let answer;
  const mcp = await mcpOver(t, token, (authorization, envelope) => ({protocol: 'fabric/0.1', id: envelope.id, ...answer}));
  const invoke = () => mcp.callTool({name: 'fabric_invoke', arguments: {requestId: 'r1', connectionId: 'acct', capabilityId: 'fixture.action.x.v1.abc', definitionHash: hash, args: {}}});
  for (const code of ['input_schema_changed', 'action_refused']) {
    answer = {error: {code, message: 'provider text that never reaches the model'}};
    const reply = await invoke();
    assert.equal(reply.structuredContent.error.code, code);
    assert.doesNotMatch(reply.structuredContent.error.message, /provider text/);
  }
  answer = {error: {code: 'action_refused', message: 'x'}};
  assert.match((await invoke()).structuredContent.error.message, /Nothing was sent/);
  answer = {result: {capabilities: [{id: 'fixture.action.old.v1.abc', connectionId: 'acct', definitionHash: hash, kind: 'action', status: 'unavailable', reason: 'superseded', replacedBy: 'fixture.action.new.v1.abc', stopsAfter: '2026-12-31', extra: 1}]}};
  assert.deepEqual((await listTool(mcp)).capabilities, [{id: 'fixture.action.old.v1.abc', connectionId: 'acct', definitionHash: hash, kind: 'action', status: 'unavailable', reason: 'superseded', replacedBy: 'fixture.action.new.v1.abc', stopsAfter: '2026-12-31'}]);
  for (const bad of [{replacedBy: 7}, {replacedBy: 'fixture.action.new.v1.abc', stopsAfter: 'soon'}, {replacedBy: 'x'.repeat(257)}]) {
    answer = {result: {capabilities: [{id: 'fixture.action.old.v1.abc', connectionId: 'acct', definitionHash: hash, kind: 'action', status: 'unavailable', reason: 'superseded', ...bad}]}};
    const reply = await mcp.callTool({name: 'fabric_list_capabilities', arguments: {}});
    assert.equal(reply.structuredContent.error.code, 'invalid_response', JSON.stringify(bad));
  }
});

test('part l: a bound action whose id a newer version replaced lists as superseded, naming the action that replaced it', async t => {
  const h = protocolHarness(t), list = h.idOf('list-items v1'), [old, {replacedBy, stopsAfter}] = [...h.catalog.superseded][0];
  assert.equal(replacedBy, list);
  // The grant was made while the old id was current: its stored record is the same definition under the old id, which seeding disabled.
  const record = {...h.capability('list-items v1'), id: old, status: 'disabled'};
  h.store.put('capabilities', record);
  const {client, token} = h.grant([[h.account, list]]);
  h.store.put('clientGrants', {...h.store.get('clientGrants', client.id), bindings: [{...client.bindings[0], capabilityId: old, definitionHash: capabilityPermissionHash(record)}]});
  const {result} = await h.call(token, 'capabilities.list');
  assert.deepEqual(result.capabilities, [{id: old, connectionId: h.account, definitionHash: capabilityPermissionHash(record), kind: 'action', status: 'unavailable', reason: 'superseded', replacedBy: list, stopsAfter}]);
});

test('part l: the tools route lists actions first, each with its record\'s output schema', async t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-tools-')), port = await freePort();
  const app = await createApp({dataDir: dir, port, request: async () => { throw new Error('no network in this test'); }});
  await app.start();
  t.after(async () => { await app.close(); rmSync(dir, {recursive: true, force: true}); });
  const file = directMessageFile(), action = {...actionCapability(file, file.actions[0]), status: 'active'};
  const [typed] = compileOpenApi({appId: 'slack', document: {openapi: '3.1.0', info: {title: 'Slack', version: '1'}, servers: [{url: 'https://slack.com/api'}],
    paths: {'/aa.list': {get: {operationId: 'aaList', responses: {200: {description: 'Done'}}}}}}}).capabilities;
  app.store.put('capabilities', {...typed, status: 'active'});
  app.store.put('capabilities', action);
  assert.ok(typed.id < action.id, 'the store lists the typed operation first');
  const boot = await fetch(`${app.origin}/api/state`), cookie = boot.headers.get('set-cookie').split(';')[0];
  const tools = (await (await fetch(`${app.origin}/api/connectors/slack/tools`, {headers: {Cookie: cookie}})).json()).tools;
  // F10.21 listed churn: the owner's Fabric seeds Slack's 13 shipped candidates at start, and they list among the actions too.
  const ours = tools.filter(tool => tool.id === action.id || tool.id === typed.id);
  assert.deepEqual(ours.map(tool => [tool.id, tool.driver]), [[action.id, 'action'], [typed.id, 'http']]);
  assert.equal(tools.findIndex(tool => tool.driver !== 'action'), tools.filter(tool => tool.driver === 'action').length, 'every action before any typed operation');
  assert.deepEqual([ours[0].outputSchema, ours[0].outputSchemaValidated, ours[1].outputSchema], [action.outputSchema, true, null]);
});

/** A sign-in for the continuation cases: reading items is always asked for, editing them only on the Edit items row. */
function scopedSignIn() {
  const definition = structuredClone(fixtureSignIn());
  definition.apps[0].access.levels.full = {required: ['fixture:read'], optional: ['fixture:all', 'fixture:keys'], inContext: [{scope: 'fixture:edit', rows: ['fixture.items.edit']}]};
  return validateAuthDefinition(definition);
}
const SCOPED = rows => ({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.read' ? {...group, scopeSets: [['fixture:read'], ['fixture:all']]}
  : group.id === 'fixture.items.edit' ? {...group, scopeSets: [['fixture:edit']]} : group.id === 'fixture.keys.read' ? {...group, scopeSets: [['fixture:keys']]} : group)});

test('part l: continuations may ask for an active action, with the scopes its steps need; never a candidate, a resource-dependent one, or any with no catalog', async t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-continuations-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const h = protocolHarness(t, {file: certifiedFile(file => { file.actions.push(findWithZone()); }), rows: SCOPED, signIn: scopedSignIn()});
  const provider = new OAuth2Provider(scopedSignIn(), {store: h.store, vault: new Vault(dir), connections: {}, clientId: 'fixture-client', clientSecret: 'fixture-secret', redirectUri: 'http://127.0.0.1:59999/api/oauth/fixture/callback'});
  const service = new ContinuationService({store: h.store, runtime: h.runtime, protocol: h.protocol, clock: () => h.now, origin: 'http://127.0.0.1:59997', signInProvider: () => provider,
    oauthRoute: appId => appId === 'fixture' ? {providerId: 'fixture', name: 'Fixture', configured: true, available: true} : null});
  h.protocol.continuations = service; h.protocol.oauthRoute = service.oauthRoute;
  const update = h.capability('update-item v1');
  assert.deepEqual(service.grantEntryFor(update.id), {appId: 'fixture', capabilityId: update.id, capabilityVersion: 1, definitionHash: capabilityPermissionHash(update), effect: 'write', providerId: 'fixture'});
  assert.throws(() => service.grantEntryFor(h.idOf('add-row v1')), {code: 'invalid_request', message: 'Connect the account first, then describe it.'});
  // A request-only action entry carries its own driver, and a client may ask for it.
  const {client, token} = h.protocol.createClient({name: 'Asker', bindings: [], requestable: [{capabilityId: update.id}]}, OWNER);
  const [entry] = (await h.call(token, 'capabilities.list')).result.capabilities;
  assert.deepEqual([entry.id, entry.kind, entry.driver, entry.status, entry.rows, entry.annotations.readOnly], [update.id, 'action', 'action', 'connection_required', ['Edit items', 'Access items'], false]);
  // A grant that holds a resource-dependent action (written before this check, or by hand) lists it as one no request can carry.
  const row = h.capability('add-row v1'), stored = h.store.get('clientGrants', client.id);
  h.store.put('clientGrants', {...stored, requestable: [...stored.requestable, {appId: 'fixture', capabilityId: row.id, capabilityVersion: 1, definitionHash: capabilityPermissionHash(row), effect: 'write', providerId: 'fixture'}]});
  assert.deepEqual((await h.call(token, 'capabilities.list')).result.capabilities.map(item => [item.id, item.status, item.reason ?? null]), [[update.id, 'connection_required', null], [row.id, 'unavailable', 'unsupported_route']]);
  // The accounts that could run it: its app's http accounts.
  const record = {grantEntry: {appId: 'fixture'}};
  assert.deepEqual(service.eligibleAccounts(record, update).map(account => [account.connectionId, account.eligible]), [[h.account, true]]);
  // Its sign-in asks for what its steps need beyond the level's required scopes: fixture:edit, usable on its rows only.
  const map = h.store.get('applicationMaps', 'fixture');
  assert.deepEqual(operationScopes(provider, 'fixture', map, update.id, 'full', h.permissions.groups, {capability: update, configs: h.permissions.configs, actions: h.catalog}), {scopes: ['fixture:edit'], grantable: true});
  assert.deepEqual(service.signInPlan({grantEntry: {appId: 'fixture', capabilityId: update.id}}, provider), {scopes: ['fixture:edit'], grantable: true});
  // An optional step's scope is never asked for: Find with a zone skips GET /keys without fixture:keys.
  const find = h.capability('find-with-zone v1');
  assert.deepEqual(operationScopes(provider, 'fixture', map, find.id, 'full', h.permissions.groups, {capability: find, configs: h.permissions.configs, actions: h.catalog}), {scopes: [], grantable: true});
  // A step whose member no sign-in can run makes it not grantable; so does a missing catalog, never "no scopes, grantable".
  const gone = fixtureGroups(rows => SCOPED({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.read' ? {...group, unavailable: {'GET /labels': 'no-oauth-scope'}} : group)}));
  assert.deepEqual(operationScopes(provider, 'fixture', map, update.id, 'full', gone, {capability: update, configs: fixtureConfigs(gone), actions: h.catalog}), {scopes: [], grantable: false});
  assert.deepEqual(operationScopes(provider, 'fixture', map, update.id, 'full', h.permissions.groups, {capability: update, configs: h.permissions.configs}), {scopes: [], grantable: false});
  h.permissions.actions = null; h.runtime.actions = null;
  assert.throws(() => service.grantEntryFor(update.id), {code: 'invalid_request', message: 'Only reviewed, active API operations can be requested before an account exists.'});
  assert.deepEqual(service.signInPlan({grantEntry: {appId: 'fixture', capabilityId: update.id}}, provider), {scopes: [], grantable: false});
  assert.deepEqual((await h.call(token, 'capabilities.list')).result.capabilities.map(item => [item.id, item.status, item.reason ?? null]), [[update.id, 'unavailable', 'permission_denied'], [row.id, 'unavailable', 'permission_denied']],
    'with no catalog no action is offered');
  // A candidate is never asked for.
  const candidate = protocolHarness(t, {file: certifiedFile(file => { file.reviewStatus = fixtureActions().reviewStatus; })});
  const asking = new ContinuationService({store: candidate.store, runtime: candidate.runtime, protocol: candidate.protocol, clock: () => candidate.now, origin: 'http://127.0.0.1:59997',
    oauthRoute: () => ({providerId: 'fixture', name: 'Fixture', configured: true, available: true})});
  assert.throws(() => asking.grantEntryFor(candidate.idOf('update-item v1')), {code: 'invalid_request'});
});

test('part l: the manifest still lists six methods', () => {
  assert.deepEqual(protocolManifest.methods, ['fabric.discover', 'capabilities.list', 'calls.create', 'calls.get', 'calls.cancel', 'proxy.request']);
});

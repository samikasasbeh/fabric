import test from 'node:test';
import assert from 'node:assert/strict';
import {owner, fixture} from './fixtures/continuation-fixture.mjs';
import {PERMISSION_GROUPS, validatePermissionGroups, bodyRouteHits} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS, validateProxyConfig} from '../lib/proxy-config.mjs';
import {templatesFor, matchRequest, routeMatch} from '../lib/proxy-match.mjs';
import {normalizeProxyRequest} from '../lib/proxy-request.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {compileOpenApi, finalizeCapability} from '../lib/compiler.mjs';

// F10.3 body routes (docs/F10-FIVE-APPS-DEEP.md section F10.3; docs/F10.3-BUILD-MAP.md parts f and g): a request whose JSON
// body matches a route of its member goes to a row at least as strict. The proxy moves it there, still capped by the row it
// came from; a typed job is never moved, it is refused and names that row. The first cases run on an injected fixture app,
// so they hold whatever the shipped rows say; the cases on the shipped rows follow at the end. Fixture store, synthetic
// accounts, no network: every case counts what was sent.
const P = name => [{name, in: 'path', required: true, schema: {type: 'string'}}], OK = {200: {description: 'ok'}};
const LABELS = {type: 'array', items: {type: 'string'}};
const body = properties => ({content: {'application/json': {schema: {type: 'object', properties}}}});
const ITEMS = {openapi: '3.0.3', info: {title: 'Items', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
  '/items/{id}': {get: {operationId: 'getItem', parameters: P('id'), responses: OK}},
  '/items/{id}/modify': {post: {operationId: 'modifyItem', parameters: P('id'), requestBody: body({addLabelIds: LABELS, removeLabelIds: LABELS, forward: {type: 'string'}}), responses: OK}},
  '/items/batchModify': {post: {operationId: 'batchModify', requestBody: body({ids: LABELS, addLabelIds: LABELS}), responses: OK}},
  '/items/{id}/trash': {post: {operationId: 'trashItem', parameters: P('id'), responses: OK}},
  '/items/{id}/share': {put: {operationId: 'shareItem', parameters: P('id'), requestBody: body({with: {type: 'string'}}), responses: OK}}}};
const TRASH_LABEL = 'Move items to or from trash', GRANT_LABEL = 'Give access to other people or services';
const ROWS = {schemaVersion: 2, appId: 'fixture', groups: [
  {id: 'fixture.items.read', label: 'See items', effect: 'read', defaultMode: 'allow', requests: ['GET /items/{id}']},
  {id: 'fixture.items.mark', label: 'Label items', effect: 'write', defaultMode: 'ask', requests: ['POST /items/{id}/modify', 'POST /items/batchModify'], bodyRoutes: [
    {member: 'POST /items/{id}/modify', pointer: '/addLabelIds', contains: 'TRASH', to: 'fixture.items.trash'},
    {member: 'POST /items/batchModify', pointer: '/addLabelIds', contains: 'SPAM', to: 'fixture.items.trash'},
    {member: 'POST /items/{id}/modify', pointer: '/forward', present: true, to: 'fixture.access.grant'}]},
  {id: 'fixture.items.trash', label: TRASH_LABEL, effect: 'delete', defaultMode: 'ask', requests: ['POST /items/{id}/trash']},
  {id: 'fixture.access.grant', label: GRANT_LABEL, effect: 'write', defaultMode: 'deny', locked: 'fabric', requests: ['PUT /items/{id}/share']}]};
const UNROUTED = {...ROWS, groups: ROWS.groups.map(({bodyRoutes, ...group}) => group)};
const CONFIG = {schemaVersion: 1, appId: 'fixture', apiBase: 'https://api.github.com', style: 'rest', pathPrefixes: ['/'], acceptTypes: ['application/json'], reservedParameters: [], reservedBodyFields: [], arrayParameters: [],
  aliases: [], inheritFamilies: [], documentedRoutes: null, proxyAllowable: [], typedOnly: []};
const MODIFY = '/items/m1/modify';

async function world(t, definition = ROWS) {
  const f = await fixture(t);
  const caps = compileOpenApi({appId: 'fixture', document: ITEMS}).capabilities.map(cap => ({...cap, status: 'active'}));
  for (const cap of caps) f.store.put('capabilities', cap);
  f.store.put('applicationMaps', {id: 'fixture', appId: 'fixture', operations: caps.map(cap => ({id: cap.name, capabilityId: cap.id, method: cap.request.method, path: cap.provenance.path}))});
  f.store.put('connections', {id: 'acct', appId: 'fixture', driver: 'http', authMethod: 'token', authRevision: 'consent-acct', status: 'ready', label: 'Items', identity: {id: 'u1', displayName: 'items-u1'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date(f.now).toISOString()});
  const use = rows => {
    const groups = new Map([...PERMISSION_GROUPS, ['fixture', validatePermissionGroups(rows)]]), configs = new Map([...PROXY_CONFIGS, ['fixture', validateProxyConfig(CONFIG, {groups, allowedOrigins: ['https://api.github.com']})]]);
    Object.assign(f.runtime.permissions, {groups, configs}); Object.assign(f.runtime.proxyPolicy, {groups, configs});
  };
  use(definition);
  const policy = f.runtime.proxyPolicy, cap = name => caps.find(item => item.name === name);
  const decide = (labels, extra = {}, path = MODIFY) => policy.decide('acct', {method: 'POST', path, body: {...(labels ? {addLabelIds: labels} : {}), ...extra}});
  const typed = (name, args) => f.runtime.createJob({connectionId: 'acct', capabilityId: cap(name).id, args}, owner);
  return {f, use, policy, cap, decide, typed, bindings: () => Object.fromEntries(policy.rows(policy.route('acct')).map(({row}) => [row, policy.binding(policy.route('acct'), row)]))};
}
const refusedAs = (groupId, label, words) => error => error.code === 'invalid_request' && error.message === words && JSON.stringify(error.details) === JSON.stringify({routedTo: {groupId, label}});
const TRASH_WORDS = `This change belongs to "${TRASH_LABEL}". Use that operation instead. Nothing was sent.`;
const LOCK_WORDS = 'Fabric keeps this off: it gives access to other people or services. No setting can turn it on.';

// ---- the proxy ---------------------------------------------------------------------------------------------------------
test('routeMatch reads the canonical body: a hit moves the match to the strictest target and says where it came from; a miss is the same match', () => {
  const definition = validatePermissionGroups(ROWS), templates = templatesFor(definition, CONFIG);
  const at = input => {const request = normalizeProxyRequest(input, CONFIG); return {request, found: matchRequest(templates, request)};};
  const {request, found} = at({method: 'POST', path: MODIFY, body: {addLabelIds: ['STARRED', 'TRASH']}}), routed = routeMatch(definition, found, request);
  assert.deepEqual({...routed}, {...found, groupId: 'fixture.items.trash', label: TRASH_LABEL, effect: 'delete', reviewedRead: false, inheritFrom: [], routedFrom: {groupId: 'fixture.items.mark', member: 'POST /items/{id}/modify'}});
  assert.ok(Object.isFrozen(routed) && Object.isFrozen(routed.routedFrom) && Object.isFrozen(routed.inheritFrom));
  const both = at({method: 'POST', path: MODIFY, body: {addLabelIds: ['TRASH'], forward: 'x@example.com'}});
  assert.equal(routeMatch(definition, both.found, both.request).groupId, 'fixture.access.grant', 'the strictest target wins: a locked row');
  for (const input of [{method: 'POST', path: MODIFY, body: {addLabelIds: ['STARRED']}}, {method: 'POST', path: MODIFY}, {method: 'POST', path: '/items/m1/trash', body: {addLabelIds: ['TRASH']}}, {method: 'POST', path: '/nothing/here', body: {addLabelIds: ['TRASH']}}]) {
    const miss = at(input);
    assert.equal(routeMatch(definition, miss.found, miss.request), miss.found, JSON.stringify(input));
  }
  assert.equal(routeMatch(definition, found, request, {style: 'rpc'}), found, 'an RPC app has no body routes');
  assert.equal(routeMatch(validatePermissionGroups(UNROUTED), found, request), found, 'a row without routes');
});

test('proxied: a routed body lands in the stricter row with its effect, its source and the body_routed warning; ASCII folding and a scalar count', async t => {
  const {f, decide} = await world(t);
  const trash = decide(['STARRED', 'TRASH']);
  assert.deepEqual([trash.row, trash.effect, trash.mode, trash.match.member, trash.match.template, trash.routedFrom], ['group:fixture.items.trash', 'delete', 'ask', 'POST /items/{id}/modify', 'POST /items/{id}/modify', {groupId: 'fixture.items.mark', member: 'POST /items/{id}/modify'}]);
  for (const labels of [['trash'], ['Trash'], 'TRASH']) assert.equal(decide(labels).row, 'group:fixture.items.trash', JSON.stringify(labels));
  assert.equal(decide(['SPAM'], {ids: ['a']}, '/items/batchModify').row, 'group:fixture.items.trash');
  for (const [labels, extra] of [[['STARRED']], [['TRAſH']], [null, {removeLabelIds: ['TRASH']}], [['SPAM']]]) {
    const plain = decide(labels, extra);
    assert.deepEqual([plain.row, 'routedFrom' in plain, plain.effect], ['group:fixture.items.mark', false, 'write'], JSON.stringify([labels, extra]));
  }
  const grant = decide(['TRASH'], {forward: 'x@example.com'});
  assert.deepEqual([grant.row, grant.mode, grant.locked, grant.routedFrom.groupId], ['group:fixture.access.grant', 'deny', true, 'fixture.items.mark']);
  assert.equal(grant.reason, LOCK_WORDS);
  const job = f.runtime.prepareProxy({connectionId: 'acct', request: {method: 'POST', path: MODIFY, body: {addLabelIds: ['TRASH']}}}, owner);
  assert.deepEqual([job.status, job.capabilityId, job.effect, job.proxy.row, job.proxy.routedFrom, job.preview.warnings], ['awaiting_approval', 'proxy:group:fixture.items.trash', 'delete', 'group:fixture.items.trash', {groupId: 'fixture.items.mark', member: 'POST /items/{id}/modify'}, ['delete', 'body_routed']]);
  const plain = f.runtime.prepareProxy({connectionId: 'acct', request: {method: 'POST', path: MODIFY, body: {addLabelIds: ['STARRED']}}}, owner);
  assert.deepEqual([plain.proxy.row, 'routedFrom' in plain.proxy, plain.preview.warnings], ['group:fixture.items.mark', false, []]);
  assert.throws(() => f.runtime.prepareProxy({connectionId: 'acct', request: {method: 'POST', path: MODIFY, body: {forward: 'x@example.com'}}}, owner), error => error.code === 'policy_denied' && error.message === LOCK_WORDS);
  assert.equal(f.calls.length, 0);
});

test('proxied: the row a request came from caps it (body_route_source), and that row\'s setting is part of the decision', async t => {
  const {policy, decide} = await world(t);
  const before = decide(['TRASH']);
  policy.set({connectionId: 'acct', row: 'group:fixture.items.mark', mode: 'deny'});
  const capped = decide(['TRASH']);
  assert.deepEqual([capped.row, capped.mode, capped.clamps, capped.executable], ['group:fixture.items.trash', 'deny', ['body_route_source'], false]);
  assert.notEqual(capped.policyHash, before.policyHash);
  policy.set({connectionId: 'acct', row: 'group:fixture.items.mark', mode: 'ask'});
  const back = decide(['TRASH']);
  assert.deepEqual([back.mode, back.clamps], ['ask', []]);
  assert.notEqual(back.policyHash, before.policyHash, 'the source row\'s new revision: an approval made before the Never never comes back');
  policy.set({connectionId: 'acct', row: 'group:fixture.items.trash', mode: 'deny'});
  assert.deepEqual([decide(['TRASH']).mode, decide(['STARRED']).mode], ['deny', 'ask'], 'the target\'s own Never holds, and the source row is untouched by it');
});

test('proxied, developer environments: a saved Never on any typed operation of the row a request came from caps it too (c8)', async t => {
  const {f, cap} = await world(t), {groups, configs} = f.runtime.proxyPolicy;
  const floor = new ProxyPolicy({store: f.store, permissions: f.runtime.permissions, groups, configs, rowFloor: true});
  const spam = () => floor.decide('acct', {method: 'POST', path: '/items/batchModify', body: {ids: ['a'], addLabelIds: ['SPAM']}});
  assert.deepEqual([spam().row, spam().mode, spam().clamps], ['group:fixture.items.trash', 'ask', []]);
  // modifyItem is the other member of the row the request came from, and does not route this endpoint itself (no c4).
  f.runtime.permissions.set({connectionId: 'acct', capabilityId: cap('modifyItem').id, mode: 'deny'});
  assert.deepEqual([spam().row, spam().mode, spam().clamps], ['group:fixture.items.trash', 'deny', ['c8_row_setting']]);
  assert.equal(f.runtime.proxyPolicy.decide('acct', {method: 'POST', path: '/items/batchModify', body: {ids: ['a'], addLabelIds: ['SPAM']}}).mode, 'ask', 'the control: c8 holds in developer environments only');
});

test('proxied: a client granted only the row a request came from gets row_not_granted for a routed one; nothing is sent', async t => {
  const {f} = await world(t);
  const {token} = f.protocol.createClient({name: 'Muse', bindings: [], proxy: [{connectionId: 'acct', rows: ['group:fixture.items.mark']}]}, owner);
  const send = (labels, id) => f.invoke(token, 'proxy.request', {connectionId: 'acct', request: {method: 'POST', path: MODIFY, body: {addLabelIds: labels}}}, id);
  assert.equal((await send(['TRASH'], 'p-1')).error.code, 'row_not_granted');
  assert.equal((await send(['STARRED'], 'p-2')).result.status, 'awaiting_approval');
  assert.equal(f.calls.length, 0);
});

test('proxied: a routed job decided again at run time keeps its row, and sends exactly the approved body', async t => {
  const {f} = await world(t);
  const job = await f.runtime.createProxyJob({connectionId: 'acct', request: {method: 'POST', path: MODIFY, body: {addLabelIds: ['TRASH']}}}, owner);
  assert.equal(job.status, 'awaiting_approval'); assert.equal(f.calls.length, 0);
  const done = await f.runtime.approve(job.id, job.approvalDigest, owner);
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].body, '{"addLabelIds":["TRASH"]}'); assert.equal(f.calls[0].url, 'https://api.github.com/items/m1/modify');
  assert.deepEqual([done.status, done.errorCode, done.proxy.row], ['uncertain', 'outcome_uncertain', 'group:fixture.items.trash'], 'sent, so uncertain: never authority_changed');
});

test('proxied: a new route into a row changes that row\'s binding (Never stays Never, a grant must be made again); the row it comes from keeps its own', async t => {
  const {f, use, policy, decide, bindings} = await world(t, UNROUTED);
  const {client} = f.protocol.createClient({name: 'Muse', bindings: [], proxy: [{connectionId: 'acct', rows: ['group:fixture.items.mark', 'group:fixture.items.trash']}]}, owner);
  policy.set({connectionId: 'acct', row: 'group:fixture.items.trash', mode: 'deny'});
  const was = bindings(), plain = decide(['STARRED']);
  use(ROWS);
  const now = bindings();
  assert.deepEqual(Object.keys(now).filter(row => now[row] !== was[row]).sort(), ['group:fixture.access.grant', 'group:fixture.items.trash'], 'only the targets of the new routes');
  const trash = policy.rows(policy.route('acct')).find(entry => entry.row === 'group:fixture.items.trash');
  assert.deepEqual([policy.base(policy.route('acct'), trash).mode, policy.base(policy.route('acct'), trash).stale], ['deny', true], 'Never stays Never');
  assert.throws(() => f.protocol.assertProxyGrant(client.id, 'acct', 'group:fixture.items.trash'), error => error.code === 'grant_changed');
  assert.doesNotThrow(() => f.protocol.assertProxyGrant(client.id, 'acct', 'group:fixture.items.mark'));
  assert.equal(decide(['STARRED']).policyHash, plain.policyHash, 'an unrouted request keeps its policy hash');
});

// ---- typed jobs --------------------------------------------------------------------------------------------------------
test('typed: a job whose body a route sends elsewhere is refused before anything is stored or sent, and names that row', async t => {
  const {f, typed} = await world(t);
  for (const labels of [['TRASH'], ['STARRED', 'trash']]) await assert.rejects(typed('modifyItem', {id: 'm1', body: {addLabelIds: labels}}), refusedAs('fixture.items.trash', TRASH_LABEL, TRASH_WORDS), JSON.stringify(labels));
  await assert.rejects(typed('batchModify', {body: {ids: ['a'], addLabelIds: ['SPAM']}}), refusedAs('fixture.items.trash', TRASH_LABEL, TRASH_WORDS));
  await assert.rejects(typed('modifyItem', {id: 'm1', body: {addLabelIds: ['TRASH'], forward: 'x@example.com'}}), refusedAs('fixture.access.grant', GRANT_LABEL, LOCK_WORDS), 'a locked target refuses in Fabric\'s lock words');
  assert.deepEqual([f.jobs().length, f.calls.length], [0, 0]);
  for (const args of [{id: 'm1', body: {addLabelIds: ['STARRED'], removeLabelIds: ['TRASH']}}, {id: 'm1'}]) assert.equal((await typed('modifyItem', args)).status, 'awaiting_approval', JSON.stringify(args));
  assert.equal((await typed('batchModify', {body: {ids: ['a'], addLabelIds: ['TRASH']}})).status, 'awaiting_approval', 'only the routes of its own member');
  assert.equal(f.calls.length, 0);
});

test('typed: a capability whose body parameter is not "body" (a model acquisition, placed by its request) is checked too', async t => {
  const {f} = await world(t);
  const model = {...finalizeCapability({specVersion: 'fabric/0.1', version: 1, appId: 'fixture', name: 'Relabel an item', description: 'Changes the labels of one item.', driver: 'http', effect: 'write', status: 'candidate',
    inputSchema: {type: 'object', properties: {id: {type: 'string'}, payload: {type: 'object', properties: {addLabelIds: LABELS}, additionalProperties: false}}, required: ['id'], additionalProperties: false},
    request: {method: 'POST', url: 'https://api.github.com/items/{id}/modify', headers: {}, pathParameters: ['id'], queryParameters: [], bodyParameter: 'payload'},
    provenance: {kind: 'model', fingerprint: 'a'.repeat(64), source: 'user-provided documentation'}, verification: {kind: 'response', description: 'No independent effect verification'}}), status: 'active'};
  f.store.put('capabilities', model);
  const run = labels => f.runtime.createJob({connectionId: 'acct', capabilityId: model.id, args: {id: 'm1', payload: {addLabelIds: labels}}}, owner);
  await assert.rejects(run(['TRASH']), refusedAs('fixture.items.trash', TRASH_LABEL, TRASH_WORDS));
  assert.equal((await run(['STARRED'])).status, 'awaiting_approval');
  assert.equal(f.calls.length, 0);
});

test('typed: a job accepted before its route existed is refused at execute(), before any request is sent', async t => {
  const {f, use, cap} = await world(t, UNROUTED);
  f.runtime.permissions.set({connectionId: 'acct', capabilityId: cap('modifyItem').id, mode: 'allow'});
  const job = await f.runtime.prepareJob({connectionId: 'acct', capabilityId: cap('modifyItem').id, args: {id: 'm1', body: {addLabelIds: ['TRASH']}}}, owner);
  assert.equal(job.status, 'queued');
  use(ROWS);
  const done = await f.runtime.execute(job.id);
  assert.deepEqual([done.status, done.error], ['failed', TRASH_WORDS]);
  assert.equal(f.calls.length, 0);
});

// ---- the shipped rows (part j) -----------------------------------------------------------------------------------------
// Critique test 10 and the routes F10.3 ships: Gmail marking that trashes or spams, filters that forward or trash, GitHub
// repository changes that publish a repository or put its code in another account, and Notion edits that trash or replace a
// page. Gmail is reviewed by operation id, so it gets a stored map with the real paths of the members these cases use.
const GMAIL = 'https://gmail.googleapis.com', MAIL_TRASH = 'Move emails to or from trash', PAGE_TRASH = 'Trash or restore pages, or replace content';
const GMAIL_PATHS = {'gmail.users.messages.modify': ['POST', '/gmail/v1/users/{userId}/messages/{id}/modify'], 'gmail.users.threads.modify': ['POST', '/gmail/v1/users/{userId}/threads/{id}/modify'],
  'gmail.users.messages.batchModify': ['POST', '/gmail/v1/users/{userId}/messages/batchModify'], 'gmail.users.settings.filters.create': ['POST', '/gmail/v1/users/{userId}/settings/filters']};
const OBJECT = {type: 'object'};
const SHIPPED = [['gmail', GMAIL, {'/gmail/v1/users/{userId}/messages/{id}/modify': {post: {operationId: 'gmail.users.messages.modify', parameters: [...P('userId'), ...P('id')], requestBody: body({addLabelIds: LABELS, removeLabelIds: LABELS}), responses: OK}}}],
  ['github', 'https://api.github.com', {'/repos/{owner}/{repo}': {patch: {operationId: 'repos/update', parameters: [...P('owner'), ...P('repo')], requestBody: body({description: {type: 'string'}, visibility: {type: 'string'}, private: {type: 'boolean'}}), responses: OK}}}],
  ['notion', 'https://api.notion.com', {'/v1/pages/{page_id}': {patch: {operationId: 'patch-page', parameters: P('page_id'), requestBody: body({properties: OBJECT, in_trash: {type: 'boolean'}, archived: {type: 'boolean'}}), responses: OK}},
    '/v1/pages/{page_id}/markdown': {patch: {operationId: 'update-page-markdown', parameters: P('page_id'), requestBody: body({type: {type: 'string'}, replace_content: OBJECT, insert_content: OBJECT}), responses: OK}},
    '/v1/blocks/{block_id}': {patch: {operationId: 'update-a-block', parameters: P('block_id'), requestBody: body({paragraph: OBJECT, archived: {type: 'boolean'}}), responses: OK}}}]];

async function shipped(t) {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const caps = SHIPPED.flatMap(([appId, url, paths]) => compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url}], paths}}).capabilities).map(cap => ({...cap, status: 'active'}));
  for (const cap of caps) f.store.put('capabilities', cap);
  const cap = name => caps.find(item => item.name === name);
  f.store.put('applicationMaps', {id: 'gmail', appId: 'gmail', operations: PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => {
    const [method, path] = GMAIL_PATHS[id] ?? [/\.(list|get)$/.test(id) ? 'GET' : 'POST', `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`];
    return {id, method, path, ...(cap(id) ? {capabilityId: cap(id).id} : {})};
  })});
  for (const [id, appId, origin] of [['gmail-a', 'gmail', GMAIL], ['notion-a', 'notion', 'https://api.notion.com']])
    f.store.put('connections', {id, appId, driver: 'http', authMethod: 'token', authRevision: `consent-${id}`, status: 'ready', label: id, identity: {id}, allowedOrigins: [origin], createdAt: new Date(f.now).toISOString()});
  const decide = (connectionId, method, path, input) => f.runtime.proxyPolicy.decide(connectionId, {method, path, ...(input === undefined ? {} : {body: input})});
  const typed = (name, connectionId, args) => f.runtime.prepareJob({connectionId, capabilityId: cap(name).id, args}, owner);
  return {f, decide, typed};
}
const belongs = label => `This change belongs to "${label}". Use that operation instead. Nothing was sent.`;

test('critique test 10: marking that adds or removes TRASH or SPAM lands in the trash row as a delete, held at Ask; a typed job doing it is refused before anything is stored or sent', async t => {
  const {f, decide, typed} = await shipped(t), MESSAGE = '/gmail/v1/users/me/messages/m1/modify', BATCH = '/gmail/v1/users/me/messages/batchModify';
  // Every member, list and label (the twelve routes), then ASCII folding, a scalar, and the label among others.
  const cases = [[MESSAGE, 'gmail.users.messages.modify'], ['/gmail/v1/users/me/threads/t1/modify', 'gmail.users.threads.modify'], [BATCH, 'gmail.users.messages.batchModify']]
    .flatMap(([path, member]) => ['addLabelIds', 'removeLabelIds'].flatMap(list => ['TRASH', 'SPAM'].map(label => [path, {...(path === BATCH ? {ids: ['a']} : {}), [list]: [label]}, member])));
  for (const [path, input, member] of [...cases, [MESSAGE, {addLabelIds: ['STARRED'], removeLabelIds: ['spam']}, 'gmail.users.messages.modify'], [MESSAGE, {addLabelIds: 'Trash'}, 'gmail.users.messages.modify']]) {
    const routed = decide('gmail-a', 'POST', path, input);
    assert.deepEqual([routed.row, routed.effect, routed.mode, routed.audience, routed.routedFrom], ['group:gmail.messages.trash', 'delete', 'ask', undefined, {groupId: 'gmail.messages.mark', member}], `${path} ${JSON.stringify(input)}`);
  }
  for (const input of [{addLabelIds: ['STARRED']}, {removeLabelIds: ['UNREAD', 'INBOX']}, {addLabelIds: ['TRASHED', 'Label_SPAM']}, {}]) {
    const plain = decide('gmail-a', 'POST', MESSAGE, input);
    assert.deepEqual([plain.row, plain.effect, plain.mode, 'routedFrom' in plain], ['group:gmail.messages.mark', 'write', 'ask', false], JSON.stringify(input));
  }
  // c1 holds a routed delete at Ask even where both rows could be set to Allow; the source row's Never caps it.
  class OpenRows extends ProxyPolicy { allowedModes(entry, config, definition) { return ['group:gmail.messages.mark', 'group:gmail.messages.trash'].includes(entry.row) ? ['allow', 'ask', 'deny'] : super.allowedModes(entry, config, definition); } }
  const open = new OpenRows({store: f.store, permissions: f.runtime.permissions});
  for (const row of ['group:gmail.messages.mark', 'group:gmail.messages.trash']) open.set({connectionId: 'gmail-a', row, mode: 'allow', confirmAllow: true});
  const held = open.decide('gmail-a', {method: 'POST', path: BATCH, body: {ids: ['a'], addLabelIds: ['SPAM']}});
  assert.deepEqual([held.row, held.effect, held.mode, held.clamps], ['group:gmail.messages.trash', 'delete', 'ask', ['c1_delete']]);
  open.set({connectionId: 'gmail-a', row: 'group:gmail.messages.mark', mode: 'deny'});
  const capped = decide('gmail-a', 'POST', BATCH, {ids: ['a'], addLabelIds: ['SPAM']});
  assert.deepEqual([capped.row, capped.mode, capped.clamps], ['group:gmail.messages.trash', 'deny', ['body_route_source']]);
  // The typed messages.modify job is refused by prepareJob, naming the row; nothing is stored and nothing is sent.
  for (const labels of [['SPAM'], ['STARRED', 'trash']]) await assert.rejects(async () => typed('gmail.users.messages.modify', 'gmail-a', {userId: 'me', id: 'm1', body: {addLabelIds: labels}}), refusedAs('gmail.messages.trash', MAIL_TRASH, belongs(MAIL_TRASH)), JSON.stringify(labels));
  assert.deepEqual([f.jobs().length, f.calls.length], [0, 0]);
  assert.equal((await typed('gmail.users.messages.modify', 'gmail-a', {userId: 'me', id: 'm1', body: {addLabelIds: ['STARRED']}})).status, 'awaiting_approval');
  assert.equal(f.calls.length, 0);
});

test('a Gmail filter that forwards lands in the locked row, one that trashes or spams in the trash row, any other in the settings row', async t => {
  const {f, decide} = await shipped(t), FILTERS = '/gmail/v1/users/me/settings/filters', from = {groupId: 'gmail.settings.write', member: 'gmail.users.settings.filters.create'};
  for (const action of [{forward: 'someone@example.com'}, {forward: 'someone@example.com', addLabelIds: ['TRASH']}, {forward: null}]) {
    const forward = decide('gmail-a', 'POST', FILTERS, {criteria: {from: 'boss@example.com'}, action});
    assert.deepEqual([forward.row, forward.mode, forward.executable, forward.locked, forward.reason, forward.routedFrom], ['group:gmail.access.grant', 'deny', false, true, LOCK_WORDS, from], JSON.stringify(action));
  }
  for (const labels of [['SPAM'], ['Label_1', 'trash']]) {
    const trashing = decide('gmail-a', 'POST', FILTERS, {criteria: {from: 'x@example.com'}, action: {addLabelIds: labels}});
    assert.deepEqual([trashing.row, trashing.effect, trashing.mode, trashing.routedFrom], ['group:gmail.messages.trash', 'delete', 'ask', from], JSON.stringify(labels));
  }
  for (const action of [{addLabelIds: ['Label_1'], removeLabelIds: ['INBOX']}, {removeLabelIds: ['TRASH']}, {}]) {
    const plain = decide('gmail-a', 'POST', FILTERS, {criteria: {from: 'x@example.com'}, action});
    assert.deepEqual([plain.row, plain.effect, plain.mode, 'routedFrom' in plain], ['group:gmail.settings.write', 'write', 'ask', false], JSON.stringify(action));
  }
  assert.equal(f.calls.length, 0);
});

test('GitHub: publishing a repository, forking into another account or generating into another owner lands in the locked row, in both path forms (correction 5)', async t => {
  const {f, decide, typed} = await shipped(t);
  for (const [method, path, input] of [['PATCH', '/repos/o/r', {visibility: 'public'}], ['PATCH', '/repositories/1', {private: false}], ['PATCH', '/repos/o/r', {description: 'x', private: true}],
    ['POST', '/repos/o/r/forks', {organization: 'elsewhere'}], ['POST', '/repositories/1/forks', {organization: 'elsewhere', name: 'x'}],
    ['POST', '/repos/t/tpl/generate', {owner: 'elsewhere', name: 'x'}], ['POST', '/repositories/1/generate', {owner: 'elsewhere', name: 'x'}]]) {
    const locked = decide('acct-a', method, path, input);
    assert.deepEqual([locked.row, locked.mode, locked.executable, locked.locked, locked.reason, locked.routedFrom?.groupId], ['group:github.access.grant', 'deny', false, true, LOCK_WORDS, 'github.code.write'], `${method} ${path} ${JSON.stringify(input)}`);
  }
  for (const [method, path, input] of [['PATCH', '/repos/o/r', {description: 'x', has_issues: true}], ['PATCH', '/repositories/1', {name: 'renamed'}], ['POST', '/repos/o/r/forks', {}],
    ['POST', '/repositories/1/forks', {name: 'mine', default_branch_only: true}], ['POST', '/repos/t/tpl/generate', {name: 'x'}], ['POST', '/repositories/1/generate', {name: 'x', private: true}]]) {
    const plain = decide('acct-a', method, path, input);
    assert.deepEqual([plain.row, plain.mode, 'routedFrom' in plain, 'locked' in plain], ['group:github.code.write', 'ask', false, false], `${method} ${path} ${JSON.stringify(input)}`);
  }
  await assert.rejects(async () => typed('repos/update', 'acct-a', {owner: 'o', repo: 'r', body: {visibility: 'public'}}), refusedAs('github.access.grant', GRANT_LABEL, LOCK_WORDS));
  assert.equal(f.jobs().length, 0);
  assert.equal((await typed('repos/update', 'acct-a', {owner: 'o', repo: 'r', body: {description: 'x'}})).status, 'awaiting_approval');
  assert.equal(f.calls.length, 0);
});

test('Notion: replacing a page\'s content is a delete in the trash row; a typed edit that trashes, restores or archives is refused naming that row (correction 13)', async t => {
  const {f, decide, typed} = await shipped(t);
  const replaced = decide('notion-a', 'PATCH', '/v1/pages/p1/markdown', {type: 'replace_content', replace_content: {new_str: '# New'}});
  assert.deepEqual([replaced.row, replaced.effect, replaced.mode, replaced.routedFrom], ['group:notion.content.trash', 'delete', 'ask', {groupId: 'notion.content.edit', member: 'PATCH /v1/pages/{page_id}/markdown'}]);
  const inserted = decide('notion-a', 'PATCH', '/v1/pages/p1/markdown', {type: 'insert_content', insert_content: {content: 'x'}});
  assert.deepEqual([inserted.row, inserted.effect, inserted.mode, inserted.audience, 'routedFrom' in inserted], ['group:notion.content.edit', 'write', 'ask', true, false]);
  // Every PATCH member of the edit row routes in_trash and archived to the trash row (correction 13).
  const edit = PERMISSION_GROUPS.get('notion').groups.find(group => group.id === 'notion.content.edit'), patches = edit.requests.filter(request => request.startsWith('PATCH '));
  assert.ok(patches.length >= 4);
  for (const member of patches) for (const field of ['in_trash', 'archived']) assert.deepEqual(bodyRouteHits(edit, member, {[field]: true}).map(route => route.to), ['notion.content.trash'], `${member} ${field}`);
  // The proxy refuses the trash fields themselves; the routes place typed jobs and reviewed action steps.
  for (const [path, input] of [['/v1/pages/p1', {in_trash: true}], ['/v1/blocks/b1', {archived: true}], ['/v1/databases/d1', {in_trash: false}]])
    assert.throws(() => decide('notion-a', 'PATCH', path, input), error => error.code === 'parameter_not_allowed', path);
  for (const [name, args] of [['patch-page', {page_id: 'p1', body: {in_trash: true}}], ['patch-page', {page_id: 'p1', body: {archived: false}}], ['update-a-block', {block_id: 'b1', body: {archived: true}}],
    ['update-page-markdown', {page_id: 'p1', body: {type: 'Replace_Content', replace_content: {}}}]])
    await assert.rejects(async () => typed(name, 'notion-a', args), refusedAs('notion.content.trash', PAGE_TRASH, belongs(PAGE_TRASH)), `${name} ${JSON.stringify(args)}`);
  assert.equal(f.jobs().length, 0);
  for (const [name, args] of [['patch-page', {page_id: 'p1', body: {properties: {}}}], ['update-a-block', {block_id: 'b1', body: {paragraph: {}}}], ['update-page-markdown', {page_id: 'p1', body: {type: 'insert_content', insert_content: {}}}]])
    assert.equal((await typed(name, 'notion-a', args)).status, 'awaiting_approval', name);
  assert.equal(f.calls.length, 0);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../lib/permission-groups.mjs';

// T4 in developer environments (docs/F03-DEVELOPER-LAYER.md section 4.3): operations that give access to other people or
// services are Never, typed or proxied, whatever the person or the developer sets. Since F10.3 the rows Fabric locks
// (catalog/permissions/*.json) hold them in every deployment. The Iteration 8 lock file is retired; its frozen list
// (test/fixtures/access/t4-members.json) is the parity check below.
const GMAIL = 'https://gmail.googleapis.com', CALENDAR = 'https://www.googleapis.com/calendar/v3';
const TYPED = [['gmail.users.watch', 'post', '/gmail/v1/users/{userId}/watch'], ['gmail.users.settings.updateAutoForwarding', 'put', '/gmail/v1/users/{userId}/settings/autoForwarding'],
  ['gmail.users.settings.updateVacation', 'put', '/gmail/v1/users/{userId}/settings/vacation'], ['gmail.users.labels.create', 'post', '/gmail/v1/users/{userId}/labels'],
  ['gmail.users.messages.modify', 'post', '/gmail/v1/users/{userId}/messages/{id}/modify'], ['gmail.users.settings.filters.create', 'post', '/gmail/v1/users/{userId}/settings/filters']];
const REAL = {'gmail.users.settings.forwardingAddresses.create': ['POST', '/gmail/v1/users/{userId}/settings/forwardingAddresses'], 'gmail.users.messages.list': ['GET', '/gmail/v1/users/{userId}/messages'],
  'gmail.users.settings.filters.create': ['POST', '/gmail/v1/users/{userId}/settings/filters']};
const CALENDAR_TYPED = [['calendar.acl.insert', 'post', '/calendars/{calendarId}/acl'], ['calendar.acl.delete', 'delete', '/calendars/{calendarId}/acl/{ruleId}']];
/** Typed capabilities compiled from a small OpenAPI document, and the app's whole map (the proxy needs every reviewed operation),
 *  with real paths where the test uses them and the others synthetic. */
function mapped(store, appId, base, typed, real, scopes, path) {
  const paths = {};
  for (const [id, method, route] of typed) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'delete' ? {} : {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {topicName: {type: 'string'}, enabled: {type: 'boolean'}, name: {type: 'string'}, addLabelIds: {type: 'array', items: {type: 'string'}}, role: {type: 'string'}, criteria: {type: 'object', properties: {from: {type: 'string'}}},
      action: {type: 'object', properties: {addLabelIds: {type: 'array', items: {type: 'string'}}, forward: {type: 'string'}}}}}}}}}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: base}], paths}}).capabilities;
  const operations = PERMISSION_GROUPS.get(appId).groups.flatMap(group => group.operations).map(id => {
    const [method, route] = real[id] ?? [id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path(id)];
    return {id, method, path: route, sensitive: null, ...(scopes[id] ? {requiredScopes: scopes[id]} : {})};
  });
  for (const [id, method, route] of typed) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `${base}${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations[operations.findIndex(op => op.id === id)] = {id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null, ...(scopes[id] ? {requiredScopes: scopes[id]} : {})};
  }
  store.put('applicationMaps', {id: appId, appId, classifierVersion: SENSITIVITY_VERSION, operations});
}
function seed(root, scopes = {}) {
  const store = new PlatformStore({root});
  mapped(store, 'gmail', GMAIL, TYPED, REAL, scopes, id => `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`);
  mapped(store, 'google-calendar', CALENDAR, CALENDAR_TYPED, {}, scopes, id => `/${id.split('.').slice(1).join('/')}`);
  store.close();
}

async function setup(t, {scopes} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-locks-'));
  seed(root, scopes);
  const sim = {calls: []};
  const request = async req => { sim.calls.push(`${req.method || 'GET'} ${req.url}`); return {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from('{"id":"x"}')}; };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const mint = () => app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const callAs = key => async (method, route, body, headers = {}) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})}); return {status: response.status, body: await response.json()}; };
  const call = callAs(mint());
  const repo = () => app.stores.open(scope).repository;
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u1'});
  const user = repo().list('endUsers').find(item => item.subjectId === 'u1'), now = app.registry.now();
  const plant = (appId, fields) => { const id = randomUUID(); repo().put('connections', stampOwner({id, appId, driver: 'http', status: 'ready', authMethod: 'oauth', createdAt: now, updatedAt: now, authRevision: randomUUID(), providerApp: {kind: 'shared'}, ...fields}, {subjectId: 'u1', userRecordId: user.id})); app.stores.open(scope).vault.set(id, {accessToken: `tok-${id}`, refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000}); return id; };
  const gmail = plant('gmail', {providerId: 'google', identity: {id: 'g-1', displayName: 'one@example.com'}, allowedOrigins: [GMAIL], scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/gmail.settings.basic', 'https://www.googleapis.com/auth/gmail.settings.sharing', 'https://www.googleapis.com/auth/gmail.labels']});
  const github = plant('github', {providerId: 'github', identity: {id: '42', displayName: 'octo'}, allowedOrigins: ['https://api.github.com'], scopes: ['read:user', 'repo']});
  const calendar = plant('google-calendar', {providerId: 'google', identity: {id: 'g-1', displayName: 'one@example.com'}, allowedOrigins: ['https://www.googleapis.com'], scopes: ['https://www.googleapis.com/auth/calendar.acls']});
  const caps = [...(await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities, ...(await call('GET', '/v1/capabilities?appId=google-calendar')).body.capabilities], capOf = id => caps.find(item => item.id.includes(id.toLowerCase()));
  return {app, sim, scope, call, callAs, mint, repo, gmail, github, calendar, capOf};
}
const rowOf = (view, groupId) => view.sections.flatMap(section => section.rows).find(row => row.groupId === groupId);

test('typed: a locked operation is Never whatever is set, and a row of only locked operations offers Never only', async t => {
  const {sim, call, gmail, capOf} = await setup(t);
  const view = (await call('GET', `/v1/users/u1/apps/gmail?account=${gmail}`)).body;
  const watch = rowOf(view, 'gmail.access.grant'), settings = rowOf(view, 'gmail.settings.write');
  assert.deepEqual(watch.allowedModes, ['deny'], 'every member locked: Never only');
  assert.ok(settings.allowedModes.includes('allow'), 'a row with some unlocked members keeps its choices');
  const refused = await call('POST', `/v1/users/u1/accounts/${gmail}/permissions`, {groupId: watch.groupId, mode: 'ask', etag: watch.etag});
  assert.equal(refused.status, 409); assert.equal(refused.body.error.code, 'mode_not_allowed'); assert.match(refused.body.error.message, /other people or services/);
  // Allow on the settings row: vacation runs, automatic forwarding stays Never.
  assert.equal((await call('POST', `/v1/users/u1/accounts/${gmail}/permissions`, {groupId: settings.groupId, mode: 'allow', etag: settings.etag, confirmAllow: true})).status, 200);
  const runnable = (await call('GET', '/v1/users/u1/capabilities?appId=gmail')).body.capabilities.map(item => item.id);
  assert.ok(runnable.includes(capOf('updateVacation').id)); assert.equal(runnable.includes(capOf('updateAutoForwarding').id), false); assert.equal(runnable.includes(capOf('gmail-users-watch').id), false);
  const run = id => call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: capOf(id).id, definitionHash: capOf(id).definitionHash, args: {userId: 'me', body: {enabled: true}}}, {'Idempotency-Key': randomUUID()});
  const forwarding = await run('updateAutoForwarding');
  assert.equal(forwarding.status, 403); assert.equal(forwarding.body.error.code, 'permission_denied');
  assert.equal(sim.calls.some(line => line.includes('autoForwarding')), false, 'nothing reached Gmail');
  assert.ok([200, 202].includes((await run('updateVacation')).status), 'an unlocked member of the same row still runs');
});

test('proxied: a request that lands on a locked operation, or fits a locked request, is Never, documented or not', async t => {
  const {sim, call, gmail, github} = await setup(t);
  const proxy = (appId, request) => call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId, accountRef: appId === 'gmail' ? gmail : github, request}, {'Idempotency-Key': randomUUID()});
  const forward = await proxy('gmail', {method: 'POST', path: '/gmail/v1/users/me/settings/forwardingAddresses', body: {forwardingEmail: 'someone@example.com'}});
  assert.equal(forward.status, 403); assert.equal(forward.body.error.code, 'permission_denied');
  for (const request of [{method: 'POST', path: '/repos/o/r/hooks', body: {config: {url: 'https://evil.example/hook'}}}, {method: 'PUT', path: '/repos/o/r/collaborators/stranger', body: {}}, {method: 'POST', path: '/repos/o/r/keys', body: {key: 'ssh-ed25519 AAAA', read_only: false}}, {method: 'POST', path: '/repos/o/r/transfer', body: {new_owner: 'stranger'}}]) {
    const answer = await proxy('github', request);
    assert.equal(answer.status, 403, `${request.method} ${request.path}`); assert.equal(answer.body.error.code, 'permission_denied');
  }
  assert.equal(sim.calls.length, 0, 'nothing reached a provider');
  // A change that gives nothing away still waits for the person, as before.
  assert.equal((await proxy('github', {method: 'POST', path: '/repos/o/r/issues', body: {title: 'x'}})).body.status, 'awaiting_approval');
});

// ---- F10.3: Fabric's own locked rows in a developer environment --------------------------------------------------------------
// These cases swap Gmail's rows in the process-wide catalog for one test and put them back after. labels.create is in no shipped
// locked row, so only the swapped rows hold it (it joins the shipped gmail.access.grant). The settings row
// reaches other people here, and a vacation body that turns the reply on is routed to the trash row.
const LOCK_WORDS = 'Fabric keeps this off: it gives access to other people or services. No setting can turn it on.', ROW_WORDS = 'Fabric keeps this off: it gives access to other people or services.';
const LOCKED = 'Fabric keeps this off: it gives access to other people or services. Nothing was run.', TRASH = 'Move emails to or from trash';
function lockGmail(t) {
  const before = PERMISSION_GROUPS.get('gmail'), raw = JSON.parse(JSON.stringify(before));
  const groups = raw.groups.map(group => group.id === 'gmail.labels.manage' ? {...group, operations: group.operations.filter(id => id !== 'gmail.users.labels.create')}
    : group.id === 'gmail.settings.write' ? {...group, audience: true, bodyRoutes: [{member: 'gmail.users.settings.updateVacation', pointer: '/enabled', equals: true, to: 'gmail.messages.trash'}]} : group);
  const shipped = groups.find(group => group.id === 'gmail.access.grant')?.operations ?? [];
  PERMISSION_GROUPS.set('gmail', validatePermissionGroups({...raw, schemaVersion: 2, groups: [...groups.filter(group => group.id !== 'gmail.access.grant'),
    {id: 'gmail.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', locked: 'fabric', operations: [...shipped, 'gmail.users.labels.create']}]}));
  t.after(() => { PERMISSION_GROUPS.set('gmail', before); });
}

test('F10.3 agents: a token is given no locked binding, request-only entry or proxy row, and one minted before the lock uses none of them', async t => {
  const {app, sim, scope, call, repo, gmail, capOf} = await setup(t), create = capOf('labels-create'), vacation = capOf('updateVacation');
  const mint = body => call('POST', '/v1/users/u1/agent-tokens', {name: 'Labeller', ...body});
  const before = (await mint({bindings: [{accountRef: gmail, capabilityId: create.id}], requestable: [{capabilityId: create.id}, {capabilityId: vacation.id}], proxy: [{accountRef: gmail, rows: ['group:gmail.labels.manage']}]})).body;
  assert.ok(before.token, 'before the lock');
  const agent = async (method, params, id = randomUUID()) => (await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${before.token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id, method, params})})).json();
  const ask = args => agent('calls.create', {appId: 'gmail', capabilityId: vacation.id, definitionHash: vacation.definitionHash, args});
  const waiting = (await ask({userId: 'me', body: {enabled: true}})).result;
  assert.equal(waiting.status, 'awaiting_connection', 'asked before the route');
  lockGmail(t);
  for (const [body, words] of [[{bindings: [{accountRef: gmail, capabilityId: create.id}]}, LOCK_WORDS], [{requestable: [{capabilityId: create.id}]}, 'Fabric never lets agents run this operation: it gives access to other people or services.'],
    [{proxy: [{accountRef: gmail, rows: ['group:gmail.access.grant']}]}, LOCK_WORDS]]) {
    const refused = await mint(body);
    assert.deepEqual([refused.status, refused.body.error.code, refused.body.error.message], [403, 'permission_denied', words], JSON.stringify(body));
  }
  const listed = (await agent('capabilities.list', {})).result.capabilities;
  assert.deepEqual(listed.map(item => [item.id, item.connectionId === null ? 'requestable' : 'bound', item.status, item.reason ?? null]),
    [[create.id, 'bound', 'unavailable', 'permission_denied'], [create.id, 'requestable', 'unavailable', 'permission_denied'], [vacation.id, 'requestable', 'connection_required', null]]);
  const asked = await agent('calls.create', {appId: 'gmail', capabilityId: create.id, definitionHash: create.definitionHash, args: {userId: 'me', body: {name: 'x'}}});
  assert.deepEqual([asked.error.code, asked.error.message], ['permission_denied', 'Fabric never lets agents run this operation: it gives access to other people or services.']);
  const routedAsk = await ask({userId: 'me', body: {enabled: true}}), wrongAsk = await ask({userId: 'me', body: {stranger: true}});
  assert.deepEqual([routedAsk.error.code, routedAsk.error.message], ['invalid_request', `This change belongs to "${TRASH}". Use that operation instead. Nothing was sent.`]);
  assert.equal(wrongAsk.error.code, 'invalid_arguments');
  assert.equal(repo().list('continuations').filter(item => item.kind === 'hold').length, 1, 'no hold but the one asked before the route');
  // That one closes with its own code when the person picks an account, and the agent reads it as refused by permissions.
  await app.executions.resumeHold(scope, repo().get('connectSessions', waiting.handoff.connectSessionId), gmail);
  const refused = (await agent('calls.get', {callId: waiting.id})).result;
  assert.deepEqual([refused.status, refused.errorCode, refused.handoff.outcome], ['failed', 'invalid_request', 'policy_denied']);
  // The developer's own call: the lock in its fixed words, and a routed body naming the row it belongs to.
  const run = (id, args) => call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: capOf(id).id, definitionHash: capOf(id).definitionHash, args}, {'Idempotency-Key': randomUUID()});
  const locked = await run('labels-create', {userId: 'me', body: {name: 'x'}});
  assert.deepEqual([locked.status, locked.body.error.code, locked.body.error.message], [403, 'permission_denied', LOCKED]);
  const routed = await run('updateVacation', {userId: 'me', body: {enabled: true}});
  assert.deepEqual([routed.status, routed.body.error.code, routed.body.error.message, routed.body.error.details], [400, 'invalid_request', `This change belongs to "${TRASH}". Use that operation instead. Nothing was sent.`, {routedTo: {groupId: 'gmail.messages.trash', label: TRASH}}]);
  assert.equal(sim.calls.some(line => /labels|vacation/.test(line)), false, 'nothing reached Gmail');
});

test('F10.3 holds: a call that can never run makes no hold and no Connect session; a waiting hold whose operation becomes locked closes', async t => {
  const {app, scope, call, repo, capOf} = await setup(t);
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u2'});
  const hold = (id, args, key = randomUUID()) => call('POST', '/v1/executions', {externalUserId: 'u2', capabilityId: capOf(id).id, definitionHash: capOf(id).definitionHash, args, onMissingAccess: 'hold'}, {'Idempotency-Key': key});
  const waiting = await hold('labels-create', {userId: 'me', body: {name: 'x'}}), routedBefore = await hold('updateVacation', {userId: 'me', body: {enabled: true}});
  const lockedBefore = await hold('labels-create', {userId: 'me', body: {name: 'y'}});
  assert.deepEqual([waiting.status, routedBefore.status, lockedBefore.status], [202, 202, 202], 'held before the lock and the route');
  lockGmail(t);
  const holds = () => repo().list('continuations').filter(item => item.kind === 'hold').length, handoffs = () => repo().list('connectSessions').filter(item => item.purpose === 'handoff').length, counts = [holds(), handoffs()];
  const routedTo = {routedTo: {groupId: 'gmail.messages.trash', label: TRASH}};
  for (const [id, args, status, code, message, details] of [['labels-create', {userId: 'me', body: {name: 'x'}}, 403, 'permission_denied', LOCKED, undefined],
    ['updateVacation', {userId: 'me', body: {enabled: true}}, 400, 'invalid_request', `This change belongs to "${TRASH}". Use that operation instead. Nothing was sent.`, routedTo],
    ['updateVacation', {userId: 'me', body: {stranger: true}}, 400, 'invalid_arguments', 'The arguments did not match the operation. Nothing was run.', undefined]]) {
    const key = randomUUID(), first = await hold(id, args, key), again = await hold(id, args, key);
    for (const answer of [first, again]) assert.deepEqual([answer.status, answer.body.error.code, answer.body.error.message, answer.body.error.details], [status, code, message, details], `${id} ${JSON.stringify(args)}`);
  }
  assert.deepEqual([holds(), handoffs()], counts, 'no hold and no Connect session for a call that can never run');
  assert.equal((await hold('updateVacation', {userId: 'me', body: {enabled: false}})).status, 202, 'the control: an ordinary body is held');
  // The hold made before the lock closes the first time it is looked at, in the lock's own words, and its Connect session is
  // cancelled with it.
  const closed = (await call('GET', `/v1/executions/${waiting.body.callRef}`)).body;
  assert.deepEqual([closed.status, closed.error.code, closed.error.message, closed.error.attribution], ['failed', 'permission_denied', LOCKED, 'policy']);
  await app.sessions.settled();
  assert.equal(app.sessions.stateOf(scope, waiting.body.handoff.connectSessionId).state, 'cancelled');
  // The routed hold made before the route: when the person picks an account it closes with its own code and fixed words.
  const user = repo().list('endUsers').find(item => item.subjectId === 'u2'), account = randomUUID(), now = app.registry.now();
  repo().put('connections', stampOwner({id: account, appId: 'gmail', driver: 'http', status: 'ready', authMethod: 'oauth', providerId: 'google', createdAt: now, updatedAt: now, authRevision: randomUUID(), providerApp: {kind: 'shared'}, identity: {id: 'g-2', displayName: 'two@example.com'}, allowedOrigins: [GMAIL], scopes: []}, {subjectId: 'u2', userRecordId: user.id}));
  await app.executions.resumeHold(scope, repo().get('connectSessions', routedBefore.body.handoff.connectSessionId), account);
  const refused = (await call('GET', `/v1/executions/${routedBefore.body.callRef}`)).body;
  assert.deepEqual([refused.status, refused.error.code, refused.error.message, refused.error.attribution], ['failed', 'invalid_request', 'This request now belongs to a stricter permission. Nothing was run.', 'policy']);
  // A hold nobody looked at since the lock meets it only when the person picks an account: the same code and words.
  await app.executions.resumeHold(scope, repo().get('connectSessions', lockedBefore.body.handoff.connectSessionId), account);
  const lockedAtResume = (await call('GET', `/v1/executions/${lockedBefore.body.callRef}`)).body;
  assert.deepEqual([lockedAtResume.status, lockedAtResume.error.code, lockedAtResume.error.message, lockedAtResume.error.attribution], ['failed', 'permission_denied', LOCKED, 'policy']);
  assert.deepEqual([repo().get('jobs', routedBefore.body.callRef), repo().get('jobs', lockedBefore.body.callRef)], [null, null]);
});

test('F10.3 developer views: the locked row is Never only wherever it shows, takes no ceiling, and its operations are listed saying why', async t => {
  const {call, gmail, capOf} = await setup(t, {scopes: {'gmail.users.labels.create': ['https://mail.google.com/']}});
  lockGmail(t);
  const groups = (await call('GET', '/v1/apps/gmail')).body.permissionGroups, group = id => groups.find(item => item.id === id);
  assert.deepEqual(group('gmail.access.grant'), {id: 'gmail.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', allowedModes: ['deny'], locked: true, audience: false});
  assert.deepEqual([group('gmail.settings.write').audience, group('gmail.settings.write').locked, group('gmail.settings.write').allowedModes], [true, false, ['allow', 'ask', 'deny']]);
  assert.deepEqual([group('gmail.messages.read').locked, group('gmail.messages.read').audience], [false, false]);
  const listed = (await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities, annotations = id => listed.find(item => item.id === capOf(id).id).annotations;
  assert.deepEqual(annotations('labels-create'), {readOnly: false, destructive: false, idempotent: false, openWorld: true, locked: true});
  assert.deepEqual(annotations('updateVacation'), {readOnly: false, destructive: false, idempotent: false, openWorld: true, reachesPeople: true});
  // An operation says locked because a row Fabric locks holds it: users.watch sits in the shipped gmail.access.grant.
  assert.deepEqual(annotations('gmail-users-watch'), {readOnly: false, destructive: false, idempotent: false, openWorld: true, locked: true});
  assert.deepEqual((await call('GET', `/v1/capabilities/${capOf('labels-create').id}`)).body.annotations, annotations('labels-create'));
  // The person's runnable list leaves the locked operation out, and one that reaches other people says so there too.
  const runnable = (await call('GET', '/v1/users/u1/capabilities?appId=gmail')).body.capabilities, mine = id => runnable.find(item => item.id === capOf(id).id);
  assert.deepEqual([mine('labels-create'), mine('updateVacation')?.annotations], [undefined, annotations('updateVacation')]);
  // The person's app page through the relay: Never only, no Add access even though the account lacks the scope.
  const view = (await call('GET', `/v1/users/u1/apps/gmail?account=${gmail}`)).body, row = rowOf(view, 'gmail.access.grant');
  assert.deepEqual([row.locked, row.allowedModes, row.mode, row.access, 'addBlocked' in row, 'addAccess' in row, row.blockedReason], [true, ['deny'], 'deny', 'missing', false, false, ROW_WORDS]);
  const refused = await call('POST', `/v1/users/u1/accounts/${gmail}/permissions`, {groupId: row.groupId, mode: 'ask', etag: row.etag});
  assert.deepEqual([refused.status, refused.body.error.code, refused.body.error.message], [409, 'mode_not_allowed', ROW_WORDS]);
  // A ceiling has nothing to lower on a row Fabric keeps off; null still clears.
  for (const mode of ['deny', 'ask', 'allow']) {
    const refused = await call('PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.access.grant': mode}});
    assert.deepEqual([refused.status, refused.body.error.code], [409, 'locked_row'], mode);
  }
  assert.equal((await call('PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.access.grant': null}})).status, 200);
});

test('F10.3 ceilings: null clears a ceiling on a row that no longer exists, and only ceilings on rows that exist are shown', async t => {
  const {app, scope, call} = await setup(t), environment = app.registry.get('environments', scope.environmentId);
  app.registry.put('environments', {...environment, apps: {...(environment.apps || {}), gmail: {ceilings: {'gmail.retired.row': 'deny', 'gmail.messages.read': 'ask'}}}});
  assert.deepEqual((await call('GET', '/v1/environment/apps')).body.apps.find(item => item.appId === 'gmail').ceilings, {'gmail.messages.read': 'ask'});
  assert.equal((await call('PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.retired.row': 'deny'}})).status, 400, 'an unknown row still takes no ceiling');
  const cleared = await call('PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.retired.row': null}});
  assert.deepEqual([cleared.status, cleared.body.ceilings], [200, {'gmail.messages.read': 'ask'}]);
  assert.deepEqual(app.registry.get('environments', scope.environmentId).apps.gmail.ceilings, {'gmail.messages.read': 'ask'}, 'gone from the record too');
});

// ---- F10.3 part j: the shipped locked rows in a developer environment (owed by Iteration 8) --------------------------------
// The rows Fabric locks hold every member of the frozen T4 list (test/fixtures/access/t4-members.json), typed and proxied: the lock
// file they replace is retired (part l). Three members are narrowed on purpose to the bodies their routes send to a locked row, so
// the rest of their requests wait for the person in their own row, a deliberate loosening the map lists.
const T4 = JSON.parse(readFileSync(new URL('./fixtures/access/t4-members.json', import.meta.url), 'utf8')).apps;
const NARROWED = {'gmail.users.settings.filters.create': '/action/forward', 'PATCH /repos/{owner}/{repo}': {visibility: 'public'}, 'POST /repos/{owner}/{repo}/forks': {organization: 'elsewhere'}};
const AGENT_WORDS = 'Fabric never lets agents run this operation: it gives access to other people or services.';
const filled = template => template.replace(/\{organization_id\}/g, '9919').replace(/\{[^}]+\}/g, 'p1');

test('F10.3 parity: every operation and request of the frozen T4 list sits in a row Fabric locks and is Never, filled in and in its alias form; three are narrowed to their routed bodies', async t => {
  for (const appId of ['gmail', 'google-calendar']) for (const id of T4[appId].operations) {
    const {groups} = PERMISSION_GROUPS.get(appId), row = groups.find(group => group.operations.includes(id));
    if (!NARROWED[id]) { assert.equal(row?.locked, 'fabric', `${appId}: ${id}`); continue; }
    assert.notEqual(row.locked, 'fabric', `${id} is narrowed to its routed body`);
    assert.ok(row.bodyRoutes.some(route => route.member === id && route.pointer === NARROWED[id] && route.present === true && groups.find(group => group.id === route.to)?.locked === 'fabric'), id);
  }
  const {app, scope, sim, callAs, mint, repo, github} = await setup(t), policy = app.runtimes.bundle(scope).runtime.proxyPolicy;
  // Each key may have 60 refused requests a minute: a fresh one every 40.
  let sent = 0, call = callAs(mint());
  const proxy = async request => { if (++sent % 40 === 0) call = callAs(mint()); return call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'github', accountRef: github, request}, {'Idempotency-Key': randomUUID()}); };
  const prefix = '/repos/{owner}/{repo}';
  for (const entry of T4.github.requests) {
    const [method, template] = entry.split(' '), routed = NARROWED[entry];
    for (const path of [filled(template), ...(template.startsWith(prefix) ? [`/repositories/1${filled(template.slice(prefix.length))}`] : [])]) {
      const request = {method, path, ...(routed ? {body: routed} : method === 'DELETE' ? {} : {body: {}})}, label = `${method} ${path}`;
      const decided = policy.decide(github, request);
      assert.deepEqual([decided.mode, decided.locked, decided.reason], ['deny', true, LOCK_WORDS], label);
      const answer = await proxy(request);
      assert.deepEqual([answer.status, answer.body.error?.code], [403, 'permission_denied'], label);
      if (!routed) continue;
      // Narrowed on purpose: the same request without the routed field is an ordinary change in its own row.
      const unrouted = policy.decide(github, {method, path, body: {name: 'x'}});
      assert.deepEqual([unrouted.row, unrouted.mode, 'locked' in unrouted], ['group:github.code.write', 'ask', false], `${label} without its routed field`);
      const plain = await proxy({method, path, body: {name: 'x'}});
      assert.deepEqual([plain.body.status, repo().get('jobs', plain.body.callRef)?.proxy.row], ['awaiting_approval', 'group:github.code.write'], `${label} without its routed field`);
    }
  }
  assert.equal(sim.calls.length, 0, 'nothing reached GitHub');
});

test('F10.3 body routes through /v1/proxy/requests: a forwarding filter and a published repository are refused; a trashing modify waits in the trash row saying so', async t => {
  const {sim, call, repo, gmail, github} = await setup(t);
  const proxy = (appId, request) => call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId, accountRef: appId === 'gmail' ? gmail : github, request}, {'Idempotency-Key': randomUUID()});
  const waiting = async (appId, request) => { const answer = await proxy(appId, request), job = repo().get('jobs', answer.body.callRef); return [answer.body.status, job?.proxy.row, job?.effect, job?.preview.warnings]; };
  const refused = async (appId, request) => { const answer = await proxy(appId, request); return [answer.status, answer.body.error?.code]; };
  const FILTERS = '/gmail/v1/users/me/settings/filters';
  assert.deepEqual(await refused('gmail', {method: 'POST', path: FILTERS, body: {criteria: {from: 'boss@example.com'}, action: {forward: 'someone@example.com'}}}), [403, 'permission_denied']);
  // The two narrowed members without their routed field wait for the person in their own row.
  assert.deepEqual(await waiting('gmail', {method: 'POST', path: FILTERS, body: {criteria: {from: 'boss@example.com'}, action: {addLabelIds: ['Label_1']}}}), ['awaiting_approval', 'group:gmail.settings.write', 'write', []]);
  assert.deepEqual(await waiting('gmail', {method: 'POST', path: '/gmail/v1/users/me/messages/m1/modify', body: {addLabelIds: ['TRASH']}}), ['awaiting_approval', 'group:gmail.messages.trash', 'delete', ['delete', 'body_routed']]);
  assert.deepEqual(await waiting('gmail', {method: 'POST', path: '/gmail/v1/users/me/messages/m1/modify', body: {addLabelIds: ['STARRED']}}), ['awaiting_approval', 'group:gmail.messages.mark', 'write', []]);
  assert.deepEqual(await waiting('github', {method: 'PATCH', path: '/repos/o/r', body: {description: 'x'}}), ['awaiting_approval', 'group:github.code.write', 'write', []]);
  assert.deepEqual(await refused('github', {method: 'PATCH', path: '/repos/o/r', body: {visibility: 'public'}}), [403, 'permission_denied']);
  assert.equal(sim.calls.length, 0, 'nothing reached a provider');
});

// Correction 4: no silent re-activation when the lock file goes. It held filters.create whole, so the settings row could be set to
// Allow while filters.create had no routes. Its routes are in its typed binding, so that Allow needs fresh consent and reads as Ask.
test('F10.3 part l: an Allow saved on the settings row under the lock file decides Ask for filters.create now that its routes hold it; Never stays Never', async t => {
  const {app, scope, sim, call, repo, gmail, capOf} = await setup(t), permissions = app.runtimes.bundle(scope).permissions;
  const shipped = PERMISSION_GROUPS.get('gmail'), raw = JSON.parse(JSON.stringify(shipped));
  t.after(() => { PERMISSION_GROUPS.set('gmail', shipped); });
  // The settings row as it was under the lock file: the same members, no body routes.
  const unrouted = validatePermissionGroups({...raw, groups: raw.groups.map(group => group.id === 'gmail.settings.write' ? (({bodyRoutes, ...rest}) => rest)(group) : group)});
  const save = async mode => {
    PERMISSION_GROUPS.set('gmail', unrouted);
    const row = rowOf((await call('GET', `/v1/users/u1/apps/gmail?account=${gmail}`)).body, 'gmail.settings.write');
    const answer = await call('POST', `/v1/users/u1/accounts/${gmail}/permissions`, {groupId: row.groupId, mode, etag: row.etag, ...(mode === 'allow' ? {confirmAllow: true} : {})});
    PERMISSION_GROUPS.set('gmail', shipped);
    return answer.status;
  };
  const decided = id => permissions.decision(repo().get('connections', gmail), repo().get('capabilities', capOf(id).id));
  const run = (id, body) => call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: capOf(id).id, definitionHash: capOf(id).definitionHash, args: {userId: 'me', body}}, {'Idempotency-Key': randomUUID()});
  assert.equal(await save('allow'), 200);
  const filter = decided('filters-create'), vacation = decided('updateVacation');
  assert.deepEqual([filter.mode, filter.stale, filter.policySource, 'locked' in filter], ['ask', true, 'stale', false]);
  assert.deepEqual([vacation.mode, vacation.policySource], ['allow', 'saved'], 'a member without routes keeps its Allow');
  const plain = await run('filters-create', {criteria: {from: 'boss@example.com'}, action: {addLabelIds: ['Label_1']}});
  assert.deepEqual([plain.status, plain.body.status], [202, 'awaiting_approval'], 'asks, never runs on the old Allow');
  const forward = await run('filters-create', {criteria: {from: 'boss@example.com'}, action: {forward: 'someone@example.com'}});
  assert.deepEqual([forward.status, forward.body.error.code], [400, 'invalid_request'], 'a forwarding filter belongs to the locked row');
  assert.equal(await save('deny'), 200);
  const never = decided('filters-create');
  assert.deepEqual([never.mode, never.stale, never.executable], ['deny', true, false], 'Never stays Never');
  assert.equal(sim.calls.some(line => line.includes('/settings/filters')), false, 'nothing reached Gmail');
});

test('F10.3 Calendar: sharing a calendar or giving it away is Never typed and proxied; stopping a share asks and reaches other people', async t => {
  const {sim, call, repo, calendar, capOf} = await setup(t);
  const run = (id, args) => call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: capOf(id).id, definitionHash: capOf(id).definitionHash, args}, {'Idempotency-Key': randomUUID()});
  const proxy = request => call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'google-calendar', accountRef: calendar, request}, {'Idempotency-Key': randomUUID()});
  const insert = await run('acl-insert', {calendarId: 'primary', body: {role: 'writer'}});
  assert.deepEqual([insert.status, insert.body.error.code, insert.body.error.message], [403, 'permission_denied', LOCKED]);
  // acl.insert at its real path; the others of the locked row at the test map's synthetic paths.
  for (const path of ['/calendars/primary/acl', '/acl/patch', '/acl/update', '/calendars/transferOwnership', '/acl/watch', '/events/watch', '/channels/stop']) {
    const answer = await proxy({method: 'POST', path, body: {role: 'owner'}});
    assert.deepEqual([answer.status, answer.body.error?.code], [403, 'permission_denied'], path);
  }
  const removed = await run('acl-delete', {calendarId: 'primary', ruleId: 'rule-1'});
  assert.deepEqual([removed.status, removed.body.status], [202, 'awaiting_approval']);
  const stop = await proxy({method: 'DELETE', path: '/calendars/primary/acl/rule-1'}), job = repo().get('jobs', stop.body.callRef);
  assert.deepEqual([stop.body.status, job.proxy.row, job.effect, job.preview.warnings], ['awaiting_approval', 'group:google-calendar.sharing.write', 'delete', ['delete', 'reaches_people']]);
  const groups = (await call('GET', '/v1/apps/google-calendar')).body.permissionGroups, group = id => groups.find(item => item.id === id);
  assert.deepEqual(group('google-calendar.access.grant'), {id: 'google-calendar.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', allowedModes: ['deny'], locked: true, audience: false});
  assert.deepEqual([group('google-calendar.sharing.write').label, group('google-calendar.sharing.write').audience, group('google-calendar.events.write').audience, group('google-calendar.events.delete').audience], ['Stop sharing calendars', true, true, true]);
  assert.equal(group('google-calendar.notifications.watch'), undefined, 'every member of "Get change notifications" is locked, so the row is gone');
  assert.equal(sim.calls.length, 0, 'nothing reached Google');
});

test('F10.3 shipped rows: views, annotations, agent tokens, holds, ceilings and the developer\'s words in a developer environment', async t => {
  const {app, sim, scope, call, repo, gmail, capOf} = await setup(t);
  // Views and annotations follow the shipped flags.
  const groups = (await call('GET', '/v1/apps/gmail')).body.permissionGroups, group = id => groups.find(item => item.id === id);
  assert.deepEqual(group('gmail.access.grant'), {id: 'gmail.access.grant', label: 'Give access to other people or services', effect: 'write', defaultMode: 'deny', allowedModes: ['deny'], locked: true, audience: false});
  assert.deepEqual([group('gmail.messages.send').audience, group('gmail.messages.send').locked, group('gmail.settings.write').label], [true, false, 'Change mail settings, filters and vacation reply']);
  assert.equal(group('gmail.notifications.watch'), undefined);
  const listed = (await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities, annotations = id => listed.find(item => item.id === capOf(id).id).annotations;
  for (const id of ['updateAutoForwarding', 'gmail-users-watch']) assert.equal(annotations(id).locked, true, id);
  assert.equal('locked' in annotations('updateVacation'), false);
  // Agent tokens: no locked binding, request-only entry or proxy row.
  const forwarding = capOf('updateAutoForwarding');
  for (const [body, words] of [[{bindings: [{accountRef: gmail, capabilityId: forwarding.id}]}, LOCK_WORDS], [{requestable: [{capabilityId: forwarding.id}]}, AGENT_WORDS], [{proxy: [{accountRef: gmail, rows: ['group:gmail.access.grant']}]}, LOCK_WORDS]]) {
    const refused = await call('POST', '/v1/users/u1/agent-tokens', {name: 'Mailer', ...body});
    assert.deepEqual([refused.status, refused.body.error.code, refused.body.error.message], [403, 'permission_denied', words], JSON.stringify(body));
  }
  // The developer's own call in the fixed lock words; a hold for a call that can never run is refused and makes nothing.
  const run = (id, args, extra = {}, key = randomUUID()) => call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: capOf(id).id, definitionHash: capOf(id).definitionHash, args, ...extra}, {'Idempotency-Key': key});
  const locked = await run('updateAutoForwarding', {userId: 'me', body: {enabled: true}});
  assert.deepEqual([locked.status, locked.body.error.code, locked.body.error.message], [403, 'permission_denied', LOCKED]);
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u2'});
  const counts = () => [repo().list('continuations').filter(item => item.kind === 'hold').length, repo().list('connectSessions').filter(item => item.purpose === 'handoff').length], before = counts();
  const hold = (id, args, key) => call('POST', '/v1/executions', {externalUserId: 'u2', capabilityId: capOf(id).id, definitionHash: capOf(id).definitionHash, args, onMissingAccess: 'hold'}, {'Idempotency-Key': key});
  for (const [id, args, status, code, message, details] of [['updateAutoForwarding', {userId: 'me', body: {enabled: true}}, 403, 'permission_denied', LOCKED, undefined],
    ['messages-modify', {userId: 'me', id: 'm1', body: {addLabelIds: ['SPAM']}}, 400, 'invalid_request', `This change belongs to "${TRASH}". Use that operation instead. Nothing was sent.`, {routedTo: {groupId: 'gmail.messages.trash', label: TRASH}}]]) {
    const key = randomUUID();
    for (const answer of [await hold(id, args, key), await hold(id, args, key)]) assert.deepEqual([answer.status, answer.body.error.code, answer.body.error.message, answer.body.error.details], [status, code, message, details], `${id} ${JSON.stringify(args)}`);
  }
  assert.deepEqual(counts(), before, 'no hold and no Connect session');
  assert.equal((await hold('messages-modify', {userId: 'me', id: 'm1', body: {addLabelIds: ['STARRED']}}, randomUUID())).status, 202, 'the control: an ordinary body is held');
  // Ceilings: none on the locked row; a stored ceiling on the removed row is hidden and cleared by null.
  for (const mode of ['deny', 'ask', 'allow']) assert.deepEqual(await call('PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.access.grant': mode}}).then(answer => [answer.status, answer.body.error?.code]), [409, 'locked_row'], mode);
  const environment = app.registry.get('environments', scope.environmentId);
  app.registry.put('environments', {...environment, apps: {...(environment.apps || {}), gmail: {ceilings: {'gmail.notifications.watch': 'ask', 'gmail.messages.read': 'ask'}}}});
  assert.deepEqual((await call('GET', '/v1/environment/apps')).body.apps.find(item => item.appId === 'gmail').ceilings, {'gmail.messages.read': 'ask'});
  const cleared = await call('PUT', '/v1/environment/apps/gmail', {ceilings: {'gmail.notifications.watch': null}});
  assert.deepEqual([cleared.status, cleared.body.ceilings], [200, {'gmail.messages.read': 'ask'}]);
  assert.deepEqual(app.registry.get('environments', scope.environmentId).apps.gmail.ceilings, {'gmail.messages.read': 'ask'});
  assert.equal(sim.calls.length, 0, 'nothing reached Gmail');
});

// Part k (open question 3): grant routes GitHub documents that neither the spec's list nor the retired lock file named, with the id forms
// of their /orgs/{org} entries (written out, as GOV-6 chose). Only the locked row holds them.
const GRANT_ROUTES = ['PUT /teams/{team_id}/members/{username}', 'PUT /repos/{owner}/{repo}/agents/secrets/{secret_name}', 'PUT /orgs/{org}/agents/secrets/{secret_name}',
  ...['actions', 'dependabot', 'codespaces', 'agents'].flatMap(kind => [`PUT /orgs/{org}/${kind}/secrets/{secret_name}/repositories`, `PUT /orgs/{org}/${kind}/secrets/{secret_name}/repositories/{repository_id}`]),
  'PUT /user/codespaces/secrets/{secret_name}/repositories', 'PUT /user/codespaces/secrets/{secret_name}/repositories/{repository_id}',
  'PUT /orgs/{org}/organization-roles/teams/{team_slug}/{role_id}', 'PUT /orgs/{org}/organization-roles/users/{username}/{role_id}', 'PUT /orgs/{org}/security-managers/teams/{team_slug}',
  'POST /orgs/{org}/copilot-spaces/{space_number}/collaborators', 'PUT /orgs/{org}/copilot-spaces/{space_number}/collaborators/{actor_type}/{actor_identifier}',
  'POST /users/{username}/copilot-spaces/{space_number}/collaborators', 'PUT /users/{username}/copilot-spaces/{space_number}/collaborators/{actor_type}/{actor_identifier}',
  'PUT /repos/{owner}/{repo}/actions/permissions/access', 'POST /orgs/{org}/private-registries', 'PATCH /orgs/{org}/private-registries/{secret_name}'];

test('F10.3 part k: GitHub grant routes neither list named, and the id forms of their org routes, sit in the locked row and are Never', async t => {
  const routes = [...GRANT_ROUTES, ...GRANT_ROUTES.filter(request => request.includes(' /orgs/{org}/')).map(request => request.replace(' /orgs/{org}/', ' /organizations/{organization_id}/'))];
  assert.deepEqual([GRANT_ROUTES.length, routes.length], [23, 39]);
  const documented = new Set(JSON.parse(readFileSync(new URL('../catalog/proxy/github.routes.json', import.meta.url), 'utf8')).routes);
  const grant = PERMISSION_GROUPS.get('github').groups.find(group => group.id === 'github.access.grant');
  for (const request of GRANT_ROUTES) assert.ok(documented.has(request), `${request} is documented`);
  for (const request of routes) assert.deepEqual([grant.requests.includes(request), T4.github.requests.includes(request)], [true, false], request);
  const {app, scope, sim, callAs, mint, github} = await setup(t), policy = app.runtimes.bundle(scope).runtime.proxyPolicy, prefix = '/repos/{owner}/{repo}';
  let sent = 0, call = callAs(mint());
  for (const request of routes) {
    const [method, template] = request.split(' ');
    for (const path of [filled(template), ...(template.startsWith(prefix) ? [`/repositories/1${filled(template.slice(prefix.length))}`] : [])]) {
      const decided = policy.decide(github, {method, path, body: {}});
      assert.deepEqual([decided.row, decided.mode, decided.locked, decided.reason], ['group:github.access.grant', 'deny', true, LOCK_WORDS], `${method} ${path}`);
      if (++sent % 40 === 0) call = callAs(mint());
      const answer = await call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'github', accountRef: github, request: {method, path, body: {}}}, {'Idempotency-Key': randomUUID()});
      assert.deepEqual([answer.status, answer.body.error?.code], [403, 'permission_denied'], `${method} ${path}`);
    }
  }
  assert.equal(sim.calls.length, 0, 'nothing reached GitHub');
});

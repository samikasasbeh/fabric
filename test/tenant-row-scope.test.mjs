import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {PERMISSION_GROUPS, validatePermissionGroups, UNAVAILABLE_REASONS} from '../lib/permission-groups.mjs';
import {hostedSetup} from './fixtures/hosted-fixture.mjs';
import {rows, definitionOf, stripped} from './fixtures/access/f10-6-fixtures.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {NOT_OFFERED} from '../lib/app-detail.mjs';

// F10.6 in developer environments (docs/F10.6-BUILD-MAP.md part i and corrections 1, 2 and 6): every reviewed row of a person's
// account is on the app page, the one control writes the row's proxy record too, and an operation that can never work through a
// sign-in is refused early everywhere an agent or a developer could ask for it, with fixed words. Rows that carry F10.6 data come
// from test/fixtures/access/f10-6-fixtures.mjs, swapped into the process-wide catalog for one test and put back after. Synthetic
// accounts; every case counts what reached a provider.
const GMAIL = 'https://gmail.googleapis.com', G = 'https://www.googleapis.com/auth/';
const FACTS = JSON.parse(readFileSync(new URL('./fixtures/access/google-method-scopes.json', import.meta.url), 'utf8'));
const TYPED = [['gmail.users.settings.cse.identities.list', 'get', '/gmail/v1/users/{userId}/settings/cse/identities'], ['gmail.users.settings.delegates.list', 'get', '/gmail/v1/users/{userId}/settings/delegates'],
  ['gmail.users.labels.list', 'get', '/gmail/v1/users/{userId}/labels'], ['gmail.users.drafts.create', 'post', '/gmail/v1/users/{userId}/drafts'], ['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}']];
const WORDS_UNAVAILABLE = /never work through|sign-in can never|Fabric never asks/;
const rowOf = (view, groupId) => view.sections.flatMap(section => section.rows).find(row => row.groupId === groupId);

function seed(root, more = () => {}) {
  const store = new PlatformStore({root}), paths = {};
  for (const [id, method, route] of TYPED) paths[route] = {...paths[route], [method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'get' ? {} : {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: GMAIL}], paths}}).capabilities;
  // Gmail is reviewed by operation id: every reviewed operation is in the stored map, with real paths where the cases use them.
  const operations = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => ({id, method: id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`, sensitive: null}));
  for (const [id, method, route] of TYPED) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `${GMAIL}${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations[operations.findIndex(op => op.id === id)] = {id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null, requiredScopes: FACTS.apps.gmail.methods[id]};
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  more(store);
  store.close();
}
/** Swaps one app's reviewed rows in the process-wide catalog for one test. */
function useRows(t, appId, definition) {
  const before = PERMISSION_GROUPS.get(appId);
  PERMISSION_GROUPS.set(appId, validatePermissionGroups(definition));
  t.after(() => { PERMISSION_GROUPS.set(appId, before); });
}

async function setup(t, {more} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-row-scope-'));
  seed(root, more);
  const sim = {calls: []};
  const request = async req => { sim.calls.push(`${req.method || 'GET'} ${req.url}`); return {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from('{"id":"x"}')}; };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body, headers = {}) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})}); return {status: response.status, body: response.status === 204 ? null : await response.json()}; };
  const repo = () => app.stores.open(scope).repository;
  const plant = async (externalUserId, appId, fields) => {
    if (!repo().list('endUsers').some(item => item.subjectId === externalUserId)) await call('POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId), id = randomUUID(), now = app.registry.now();
    repo().put('connections', stampOwner({id, appId, driver: 'http', status: 'ready', authMethod: 'oauth', createdAt: now, updatedAt: now, authRevision: randomUUID(), providerApp: {kind: 'shared'}, ...fields}, {subjectId: externalUserId, userRecordId: user.id}));
    app.stores.open(scope).vault.set(id, {accessToken: `tok-${id}`, refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000});
    return id;
  };
  const github = await plant('u1', 'github', {providerId: 'github', identity: {id: '42', displayName: 'octo'}, allowedOrigins: ['https://api.github.com'], scopes: ['read:user', 'repo']});
  const other = await plant('u2', 'github', {providerId: 'github', identity: {id: '43', displayName: 'cat'}, allowedOrigins: ['https://api.github.com'], scopes: ['read:user', 'repo']});
  const gmail = await plant('u1', 'gmail', {providerId: 'google', identity: {id: 'g-1', displayName: 'one@example.com'}, allowedOrigins: [GMAIL], scopes: [`${G}gmail.readonly`, `${G}gmail.modify`]});
  const caps = (await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities, capOf = id => caps.find(item => item.id.includes(id));
  const view = async (appId, ref, user = 'u1') => (await call('GET', `/v1/users/${user}/apps/${appId}?account=${ref}`)).body;
  const setRow = (ref, body, user = 'u1') => call('POST', `/v1/users/${user}/accounts/${ref}/permissions`, body);
  const proxyRecord = (ref, row) => repo().list('permissions').find(entry => entry.kind === 'proxy-row' && entry.connectionId === ref && entry.row === row) ?? null;
  const proxy = (ref, request, user = 'u1', appId = 'github') => call('POST', '/v1/proxy/requests', {externalUserId: user, appId, accountRef: ref, request}, {'Idempotency-Key': randomUUID()});
  return {app, sim, scope, key, call, repo, plant, github, other, gmail, caps, capOf, view, setRow, proxyRecord, proxy};
}

test('a person\'s GitHub account lists its 13 reviewed rows in sections, and the developer still gets proxyRows', async t => {
  const {view, github} = await setup(t), page = await view('github', github);
  assert.equal(page.sections.flatMap(section => section.rows).length, 13);
  assert.equal(rowOf(page, 'github.access.grant').allowedModes.length, 1);
  assert.ok(Array.isArray(page.proxyRows) && page.proxyRows.length > 0, 'the developer\'s own proxy rows stay');
});

test('the one control: Never on "Push code and manage repositories" writes the proxy record, and a proxied contents PUT is refused with nothing sent', async t => {
  const {sim, view, setRow, proxyRecord, proxy, github} = await setup(t), code = rowOf(await view('github', github), 'github.code.write');
  const set = await setRow(github, {groupId: 'github.code.write', mode: 'deny', etag: code.etag});
  assert.equal(set.status, 200);
  assert.equal(proxyRecord(github, 'group:github.code.write').mode, 'deny');
  const refused = await proxy(github, {method: 'PUT', path: '/repos/o/r/contents/a/b.md', body: {message: 'm', content: 'YQ=='}});
  assert.deepEqual([refused.status, refused.body.error.code], [403, 'permission_denied']);
  assert.equal(sim.calls.length, 0);
});

test('the person\'s hosted page sets the same row through the one control; proxy: true from the page is still refused', async t => {
  const {keys, open, repo, app, scope, account} = await hostedSetup(t);
  // A GitHub account for u1 on the hosted fixture's environment, beside the Gmail account that makes u1 a person there.
  await account('u1', 'g-1');
  const person = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'}), user = repo().list('endUsers').find(item => item.subjectId === 'u1'), id = randomUUID(), now = app.registry.now();
  repo().put('connections', stampOwner({id, appId: 'github', providerId: 'github', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: '42', displayName: 'octo'}, allowedOrigins: ['https://api.github.com'], scopes: ['read:user', 'repo'],
    createdAt: now, updatedAt: now, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: 'u1', userRecordId: user.id}));
  app.stores.open(scope).vault.set(id, {accessToken: 'tok', refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000});
  const page = (await person.person.call('GET', `/connect/${person.id}/v1/apps/github?account=${id}`)).body, code = rowOf(page, 'github.code.write');
  assert.equal((await person.person.call('POST', `/connect/${person.id}/v1/apps/github/accounts/${id}/permissions`, {groupId: 'github.code.write', mode: 'deny', etag: code.etag, proxy: true})).status, 400);
  assert.equal((await person.person.call('POST', `/connect/${person.id}/v1/apps/github/accounts/${id}/permissions`, {groupId: 'github.code.write', mode: 'deny', etag: code.etag})).status, 200);
  assert.equal(repo().list('permissions').find(entry => entry.kind === 'proxy-row' && entry.row === 'group:github.code.write')?.mode, 'deny', 'Q10 holds only for Other and GraphQL rows now');
});

test('proxy: true and the one control share one etag: either change, then the other with the old etag, answers etag_mismatch', async t => {
  // proxy: true keeps its own row and etag (open question 12); the one control's row etag folds the same proxy record in.
  const {view, setRow, github} = await setup(t), shown = async () => {const page = await view('github', github); return {row: rowOf(page, 'github.code.write'), raw: page.proxyRows.find(item => item.groupId === 'github.code.write')};};
  let {row, raw} = await shown();
  assert.equal((await setRow(github, {groupId: 'github.code.write', mode: 'deny', etag: raw.etag, proxy: true})).status, 200);
  assert.equal((await setRow(github, {groupId: 'github.code.write', mode: 'ask', etag: row.etag})).body.error.code, 'etag_mismatch');
  ({row, raw} = await shown());
  assert.equal(row.mode, 'deny', 'the row shows the proxy record proxy: true wrote');
  assert.equal((await setRow(github, {groupId: 'github.code.write', mode: 'ask', etag: row.etag})).status, 200);
  assert.equal((await setRow(github, {groupId: 'github.code.write', mode: 'deny', etag: raw.etag, proxy: true})).body.error.code, 'etag_mismatch');
});

test('a developer ceiling of Ask refuses Allow through the one control, and the proxy row reads Ask', async t => {
  const {call, view, setRow, github} = await setup(t);
  assert.equal((await call('PUT', '/v1/environment/apps/github', {ceilings: {'github.repos.read': 'ask'}})).status, 200);
  const repos = rowOf(await view('github', github), 'github.repos.read');
  assert.equal(repos.mode, 'ask');
  const refused = await setRow(github, {groupId: 'github.repos.read', mode: 'allow', etag: repos.etag, confirmAllow: true});
  assert.deepEqual([refused.status, refused.body.error.code], [409, 'mode_not_allowed']);
});

test('reset on GitHub rows does not crash and returns the proxy record to its default', async t => {
  const {call, view, setRow, proxyRecord, github} = await setup(t);
  await setRow(github, {groupId: 'github.code.write', mode: 'deny', etag: rowOf(await view('github', github), 'github.code.write').etag});
  const saved = proxyRecord(github, 'group:github.code.write');
  assert.equal((await view('github', github)).canReset, true, 'a saved proxy record is something to reset');
  const reset = await call('POST', `/v1/users/u1/accounts/${github}/permissions/reset`, {});
  assert.equal(reset.status, 200);
  const after = proxyRecord(github, 'group:github.code.write');
  assert.deepEqual([after.followsDefault, after.revision !== saved.revision], [true, true]);
  assert.equal(rowOf({sections: [{rows: reset.body.rows}]}, 'github.code.write').mode, 'ask');
});

test('a row whose member is unsupported offers Never only to the person, and the one control refuses anything else', async t => {
  // F10.15's draft markers, which the shipped rows carry since step 15, set again here with a reason of the test's own: both drafts
  // members are unsupported.
  const marked = rows('gmail'), reason = 'It cannot carry a whole message, and an update without one can blank the draft.';
  marked.groups.find(group => group.id === 'gmail.drafts.write').unsupported = {'gmail.users.drafts.create': reason, 'gmail.users.drafts.update': reason};
  useRows(t, 'gmail', marked);
  const {view, setRow, gmail} = await setup(t), drafts = rowOf(await view('gmail', gmail), 'gmail.drafts.write');
  assert.deepEqual(drafts.allowedModes, ['deny']);
  const refused = await setRow(gmail, {groupId: 'gmail.drafts.write', mode: 'ask', etag: drafts.etag});
  assert.deepEqual([refused.status, refused.body.error.code], [409, 'mode_not_allowed']);
  assert.equal((await setRow(gmail, {groupId: 'gmail.drafts.write', mode: 'deny', etag: drafts.etag})).status, 200, 'Never is always allowed');
  assert.ok(rowOf(await view('gmail', gmail), 'gmail.messages.read').allowedModes.includes('allow'), 'the control: a row with no unsupported member keeps its choices');
});

test('add_access: a row whose lacking members are only unavailable answers 422 add_unavailable; locked and held rows keep their answers', async t => {
  useRows(t, 'gmail', rows('gmail'));
  const {call, repo, gmail} = await setup(t), sessions = () => repo().list('connectSessions').length, before = sessions();
  const open = groupId => call('POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'add_access', accountRef: gmail, groupId});
  // Access labels, filters and settings: the labels read works, and the delegate and CSE reads can never be added.
  const unavailable = await open('gmail.labels.read');
  assert.deepEqual([unavailable.status, unavailable.body.error?.code], [422, 'add_unavailable']);
  assert.equal(unavailable.body.error.message, `${UNAVAILABLE_REASONS['service-account-only']} ${UNAVAILABLE_REASONS['workspace-cse-only']}`, 'each reason once, in a fixed order');
  assert.equal((await open('gmail.access.grant')).body.error.code, 'row_locked');
  assert.equal((await open('gmail.messages.read')).body.error.code, 'access_held');
  assert.equal(sessions(), before, 'no link was made');
});

test('a call on an unavailable operation is refused with fixed words, held or not: no hold, no Connect session, and a replay answers the same', async t => {
  useRows(t, 'gmail', rows('gmail'));
  const {call, repo, capOf, sim} = await setup(t), cse = capOf('cse-identities-list'), idem = randomUUID();
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u9'});
  const counts = () => [repo().list('continuations').filter(item => item.kind === 'hold').length, repo().list('connectSessions').filter(session => session.purpose === 'handoff').length];
  const run = () => call('POST', '/v1/executions', {externalUserId: 'u9', capabilityId: cse.id, definitionHash: cse.definitionHash, args: {userId: 'me'}, onMissingAccess: 'hold'}, {'Idempotency-Key': idem});
  const first = await run(), again = await run();
  assert.deepEqual([first.status, first.body.error.code], [403, 'permission_denied']);
  assert.match(first.body.error.message, WORDS_UNAVAILABLE);
  assert.deepEqual([again.status, again.body.error.code, again.body.error.message], [first.status, first.body.error.code, first.body.error.message]);
  assert.deepEqual(counts(), [0, 0]);
  // The control: a member that can work is held.
  const labels = capOf('labels-list'), held = await call('POST', '/v1/executions', {externalUserId: 'u9', capabilityId: labels.id, definitionHash: labels.definitionHash, args: {userId: 'me'}, onMissingAccess: 'hold'}, {'Idempotency-Key': randomUUID()});
  assert.equal(held.status, 202);
  // The developer's own call on an account says the same, never the account's own setting.
  const direct = await call('POST', '/v1/executions', {externalUserId: 'u1', capabilityId: cse.id, definitionHash: cse.definitionHash, args: {userId: 'me'}}, {'Idempotency-Key': randomUUID()});
  assert.deepEqual([direct.status, direct.body.error.code, direct.body.error.message], [403, 'permission_denied', first.body.error.message]);
  assert.equal(sim.calls.length, 0);
});

test('correction 2: a hold made before the marker says why when it is read and when it is resumed', async t => {
  // Before the marker: the shipped rows without their F10.6 keys (part l ships the marker). It lands mid-test; the shipped rows come back after.
  useRows(t, 'gmail', stripped(PERMISSION_GROUPS.get('gmail')));
  const {app, scope, call, repo, plant, capOf, sim} = await setup(t), cse = capOf('cse-identities-list');
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u9'});
  const hold = () => call('POST', '/v1/executions', {externalUserId: 'u9', capabilityId: cse.id, definitionHash: cse.definitionHash, args: {userId: 'me'}, onMissingAccess: 'hold'}, {'Idempotency-Key': randomUUID()});
  const looked = await hold(), resumed = await hold();
  assert.deepEqual([looked.status, looked.body.status, resumed.body.status], [202, 'connection_required', 'connection_required'], 'before the marker each waits for an account');
  PERMISSION_GROUPS.set('gmail', validatePermissionGroups(rows('gmail')));
  // Read: the hold closes the first time anyone looks, in the fixed words, and its Connect session is cancelled with it.
  const read = (await call('GET', `/v1/executions/${looked.body.callRef}`)).body;
  assert.deepEqual([read.status, read.error.code, read.error.attribution], ['failed', 'permission_denied', 'policy']);
  assert.match(read.error.message, WORDS_UNAVAILABLE);
  await app.sessions.settled();
  assert.equal(app.sessions.stateOf(scope, looked.body.handoff.connectSessionId).state, 'cancelled');
  // Resumed: a hold nobody looked at meets the marker when the person picks an account, with the same code and words.
  const account = await plant('u9', 'gmail', {providerId: 'google', identity: {id: 'g-9', displayName: 'nine@example.com'}, allowedOrigins: [GMAIL], scopes: [`${G}gmail.readonly`]});
  await app.executions.resumeHold(scope, repo().get('connectSessions', resumed.body.handoff.connectSessionId), account);
  const after = (await call('GET', `/v1/executions/${resumed.body.callRef}`)).body;
  assert.deepEqual([after.status, after.error.code, after.error.message], ['failed', 'permission_denied', read.error.message]);
  assert.deepEqual([repo().get('jobs', resumed.body.callRef), sim.calls.length], [null, 0]);
});

test('agents: a token cannot get an unavailable requestable entry, and a token given one before the marker lists it unavailable and asks for nothing', async t => {
  useRows(t, 'gmail', stripped(PERMISSION_GROUPS.get('gmail')));
  const {app, call, repo, capOf, gmail} = await setup(t), cse = capOf('cse-identities-list'), labels = capOf('labels-list');
  const before = (await call('POST', '/v1/users/u1/agent-tokens', {name: 'Reader', bindings: [{accountRef: gmail, capabilityId: cse.id}], requestable: [{capabilityId: cse.id}, {capabilityId: labels.id}]})).body;
  assert.ok(before.token, 'before the marker');
  PERMISSION_GROUPS.set('gmail', validatePermissionGroups(rows('gmail')));
  for (const body of [{requestable: [{capabilityId: cse.id}]}, {bindings: [{accountRef: gmail, capabilityId: cse.id}]}]) {
    const refused = await call('POST', '/v1/users/u1/agent-tokens', {name: 'Reader', ...body});
    assert.deepEqual([refused.status, refused.body.error.code], [403, 'permission_denied'], JSON.stringify(body));
  }
  const refused = await call('POST', '/v1/users/u1/agent-tokens', {name: 'Reader', requestable: [{capabilityId: cse.id}]});
  assert.equal(refused.body.error.message, UNAVAILABLE_REASONS['workspace-cse-only'], 'the reason\'s own words');
  const minted = await call('POST', '/v1/users/u1/agent-tokens', {name: 'Reader', bindings: [{accountRef: gmail, capabilityId: labels.id}], requestable: [{capabilityId: labels.id}]});
  assert.equal(minted.status, 201, 'a member that can work is still granted');
  const agent = async (method, params) => (await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${before.token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id: randomUUID(), method, params})})).json();
  const listed = (await agent('capabilities.list', {})).result.capabilities;
  assert.deepEqual(listed.map(item => [item.id, item.connectionId === null ? 'requestable' : 'bound', item.status, item.reason ?? null]),
    [[cse.id, 'bound', 'unavailable', 'permission_denied'], [cse.id, 'requestable', 'unavailable', 'permission_denied'], [labels.id, 'requestable', 'connection_required', null]]);
  const asked = await agent('calls.create', {appId: 'gmail', capabilityId: cse.id, definitionHash: cse.definitionHash, args: {userId: 'me'}});
  assert.deepEqual([asked.error.code, asked.error.message], ['permission_denied', UNAVAILABLE_REASONS['workspace-cse-only']]);
  assert.equal(repo().list('continuations').filter(item => item.kind === 'hold').length, 0, 'no hold');
});

test('correction 6: the capability list marks exactly the unavailable operations, and so does each operation\'s own view', async t => {
  useRows(t, 'gmail', rows('gmail'));
  const {call, capOf} = await setup(t), listed = (await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  const marked = listed.filter(item => item.annotations?.unavailable === true).map(item => item.id);
  assert.deepEqual(marked.sort(), [capOf('cse-identities-list').id, capOf('delegates-list').id].sort());
  assert.equal((await call('GET', `/v1/capabilities/${capOf('delegates-list').id}`)).body.annotations.unavailable, true);
  assert.equal('unavailable' in (await call('GET', `/v1/capabilities/${capOf('labels-list').id}`)).body.annotations, false);
});

test('correction 1: an add_access session on a reconnect_required account lists the proxy row it turns on, and its start needs the confirm', async t => {
  const {app, call, repo, gmail} = await setup(t);
  repo().put('connections', {...repo().get('connections', gmail), status: 'reconnect_required', scopes: []});
  const opened = await call('POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'add_access', accountRef: gmail, groupId: 'gmail.messages.read'});
  assert.equal(opened.status, 201, JSON.stringify(opened.body));
  const binding = `browser-${opened.body.id}`;
  app.sessions.claim(opened.body.id, new URL(opened.body.connectUrl).hash.slice(3), binding);
  const card = app.sessions.view(opened.body.id, binding).upgrade;
  assert.ok(card?.rows.some(row => row.proxy === true), JSON.stringify(card));
  assert.throws(() => app.sessions.start(opened.body.id, binding), {code: 'confirm_required'});
  assert.ok(app.sessions.start(opened.body.id, binding, undefined, undefined, card.etag).authorizationUrl, 'with the card\'s etag it starts');
});

test('a row Add access could offer nothing for says "Not offered", not where Add happens, and its add_access link answers the same', async t => {
  // Version 2 sign-in data, as F10.7 brings it: the environment's GitHub sign-in reads the fixture definition, and "Access gists" asks
  // for a scope outside its full level. "Create and edit gists" is the control: Add could ask for gist there.
  const raw = rows('github');
  useRows(t, 'github', {...raw, groups: raw.groups.map(group => group.id === 'github.gists.read' ? {...group, scopeSets: [['site_admin']]} : group)});
  const {app, scope, call, view, github} = await setup(t), bundle = app.runtimes.bundle(scope);
  bundle.adapters.set('github', new OAuth2Provider(definitionOf('github'), {store: bundle.env.repository, vault: bundle.env.vault, connections: bundle.connections, clientId: 'gh-client', clientSecret: 'gh-secret',
    redirectUri: `${app.origin}/api/oauth/github/callback`, publishing: 'testing'}));
  const page = await view('github', github), gists = rowOf(page, 'github.gists.read'), write = rowOf(page, 'github.gists.write');
  assert.deepEqual([gists.access, gists.addBlocked, 'addAccess' in gists], ['missing', NOT_OFFERED, false]);
  assert.deepEqual([write.access, write.addBlocked, 'addAccess' in write, 'upgrade' in write], ['missing', 'More access is added on Fabric\'s Connect page: create an add_access Connect session for this row.', false, false]);
  const open = groupId => call('POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'add_access', accountRef: github, groupId});
  const refused = await open('github.gists.read');
  assert.deepEqual([refused.status, refused.body.error.code, refused.body.error.message], [422, 'add_unavailable', NOT_OFFERED]);
  assert.equal((await open('github.gists.write')).status, 201);
});

test('correction 3: a held call on a GitHub operation with no map entry asks its sign-in for the scope of the row its request sits in, as on the single-owner runtime', async t => {
  // GitHub is reviewed by request, with no map: the typed "list gists" sits in "Access gists" by its request, whose fixture sets
  // are [[gist]]. Version 2 sign-in data, as F10.7 brings it, where gist is optional at full, so only the hold makes it required.
  const [gists] = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}],
    paths: {'/gists': {get: {operationId: 'listGists', responses: {200: {description: 'OK'}}}}}}}).capabilities;
  useRows(t, 'github', rows('github'));
  const {app, scope, call, repo} = await setup(t, {more: store => store.put('capabilities', {...gists, status: 'active'})}), bundle = app.runtimes.bundle(scope), shared = bundle.adapters.get('github');
  bundle.adapters.set('github', new OAuth2Provider(definitionOf('github'), {store: bundle.env.repository, vault: bundle.env.vault, connections: bundle.connections, clientId: shared.clientId, clientSecret: shared.clientSecret,
    redirectUri: shared.redirectUri, publishing: 'testing'}));
  assert.equal(repo().get('applicationMaps', 'github') ?? null, null, 'no map entry');
  await call('POST', '/v1/connect-sessions', {externalUserId: 'u9'});
  const cap = (await call('GET', '/v1/capabilities?appId=github')).body.capabilities.find(item => item.id === gists.id);
  const held = await call('POST', '/v1/executions', {externalUserId: 'u9', capabilityId: cap.id, definitionHash: cap.definitionHash, args: {}, onMissingAccess: 'hold'}, {'Idempotency-Key': randomUUID()});
  assert.equal(held.status, 202, JSON.stringify(held.body));
  const id = held.body.handoff.connectSessionId, minted = (await call('POST', `/v1/connect-sessions/${id}/link`)).body, binding = `browser-${id}`;
  app.sessions.claim(id, new URL(minted.connectUrl).hash.slice(3), binding);
  const started = app.sessions.start(id, binding), state = new URL(started.authorizationUrl).searchParams.get('state');
  assert.deepEqual(repo().get('oauthFlows', createHash('sha256').update(state).digest('hex')).required, ['read:user', 'repo', 'gist']);
});

test('isolation: one person\'s row change leaves another person\'s proxy and typed records as they were', async t => {
  const {repo, view, setRow, github, other} = await setup(t);
  const theirs = () => JSON.stringify(repo().list('permissions').filter(entry => entry.connectionId === other));
  const before = theirs();
  assert.equal((await setRow(github, {groupId: 'github.code.write', mode: 'deny', etag: rowOf(await view('github', github), 'github.code.write').etag})).status, 200);
  assert.equal(theirs(), before);
  assert.equal(rowOf(await view('github', other, 'u2'), 'github.code.write').mode, 'ask');
});

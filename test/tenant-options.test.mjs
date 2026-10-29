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
import {validateOptionSources} from '../lib/option-sources.mjs';

// F03.7d: options for one input (Calendar calendars, Gmail labels) from the end user's own account, through reviewed
// sources only, under the source's own read row (Allow only), with no job, approval or usage record.
const param = (name, where = 'path') => ({name, in: where, required: where === 'path', schema: {type: 'string'}});
function compile(appId, server, paths) { return compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: server}], paths}}).capabilities; }
function seed(root, {calendarListId = 'calendar.calendarList.list', listBoundTo = null, listSensitive = false, calendarList = null} = {}) {
  const store = new PlatformStore({root}), ids = {};
  const calendar = compile('google-calendar', 'https://www.googleapis.com', {
    '/calendar/v3/users/me/calendarList': {get: {operationId: calendarListId, parameters: [param('pageToken', 'query')], responses: {200: {description: 'OK'}}}},
    '/calendar/v3/calendars/{calendarId}/events': {get: {operationId: 'calendar.events.list', parameters: [param('calendarId')], responses: {200: {description: 'OK'}}}}});
  const gmail = compile('gmail', 'https://gmail.googleapis.com', {
    '/gmail/v1/users/{userId}/labels': {get: {operationId: 'gmail.users.labels.list', parameters: [param('userId')], responses: {200: {description: 'OK'}}}},
    '/gmail/v1/users/{userId}/messages': {get: {operationId: 'gmail.users.messages.list', parameters: [param('userId'), param('labelIds', 'query')], responses: {200: {description: 'OK'}}}}});
  const github = compile('github', 'https://api.github.com', {'/repos/{owner}': {get: {operationId: 'repos/list-for-owner', parameters: [param('owner')], responses: {200: {description: 'OK'}}}}});
  const maps = {'google-calendar': [], gmail: [], github: []};
  for (const [appId, caps] of [['google-calendar', calendar], ['gmail', gmail], ['github', github]]) for (const capability of caps) {
    store.put('capabilities', {...capability, status: 'active'});
    const url = new URL(capability.request.url.replace(/%7B/g, '{').replace(/%7D/g, '}'));
    const id = {'google-calendar': {'/calendar/v3/users/me/calendarList': calendarListId, '/calendar/v3/calendars/{calendarId}/events': 'calendar.events.list'}, gmail: {'/gmail/v1/users/{userId}/labels': 'gmail.users.labels.list', '/gmail/v1/users/{userId}/messages': 'gmail.users.messages.list'}, github: {'/repos/{owner}': 'repos/list-for-owner'}}[appId][decodeURIComponent(url.pathname)];
    maps[appId].push({id, capabilityId: capability.id, method: 'GET', path: decodeURIComponent(url.pathname), sensitive: null});
    ids[id] = capability.id;
  }
  // A map entry whose id says one operation while its capability is another (listBoundTo) must not list.
  if (listBoundTo) maps['google-calendar'].find(op => op.id === calendarListId).capabilityId = ids[listBoundTo];
  if (listSensitive) maps['google-calendar'].find(op => op.id === calendarListId).sensitive = 'secrets';
  // F10.13 part 1: `calendarList` compiles the calendar list as {server, route} and stores it in the map at `path`, as Discovery would.
  if (calendarList) {
    const [list] = compile('google-calendar', calendarList.server, {[calendarList.route]: {get: {operationId: calendarListId, parameters: [param('pageToken', 'query')], responses: {200: {description: 'OK'}}}}});
    store.put('capabilities', {...list, status: 'active'});
    Object.assign(maps['google-calendar'].find(op => op.id === calendarListId), {capabilityId: list.id, path: calendarList.path});
    ids[calendarListId] = list.id;
  }
  for (const [appId, operations] of Object.entries(maps)) store.put('applicationMaps', {id: appId, appId, classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
  return ids;
}

async function setup(t, seedOptions) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-options-'));
  const ids = seed(root, seedOptions);
  const sim = {calls: [], refreshHeld: null, listHeld: null};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url.startsWith('https://www.googleapis.com/calendar/v3/users/me/calendarList') && !req.url.includes('maxResults=1') && sim.listHeld) await sim.listHeld;
    if (req.url.startsWith('https://www.googleapis.com/calendar/v3/users/me/calendarList')) {
      return new URL(req.url).searchParams.get('pageToken') === 'page-2'
        ? {status: 200, headers: {}, data: {items: [{id: 'holidays@group', summary: 'Holidays'}]}}
        : {status: 200, headers: {}, data: {items: [{id: 'primary', summary: 'one@example.com', summaryOverride: 'My calendar'}, {id: 'team@group', summary: 'Team'}, {id: 'ya29.leak', summary: 'ya29.leak'}], nextPageToken: 'page-2'}};
    }
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/labels')) return {status: 200, headers: {}, data: {labels: [{id: 'INBOX', name: 'INBOX'}, {id: 'Label_1', name: 'Receipts'}]}};
    if (req.url === 'https://oauth2.googleapis.com/token') { if (sim.refreshHeld) await sim.refreshHeld; return {status: 200, headers: {}, data: {access_token: 'ya29.fresh-token-value', token_type: 'Bearer', expires_in: 3600, scope: 'https://www.googleapis.com/auth/calendar.readonly'}}; }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') return {status: 200, headers: {}, data: {sub: 'g-1', email: 'one@example.com', name: 'One'}};
    if (req.url.startsWith('https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1')) return {status: 200, headers: {}, data: {kind: 'calendar#calendarList'}};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { sim.refreshHeld = null; sim.listHeld = null; await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  const call = async (method, route, body) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})}); return {status: response.status, body: await response.json()}; };
  const repo = () => app.stores.open(scope).repository;
  const account = async (externalUserId, appId, origin, scopes) => {
    await call('POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), id = randomUUID(), now = app.registry.now();
    repo().put('connections', stampOwner({id, appId, providerId: appId === 'github' ? 'github' : 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: appId === 'github' ? `${externalUserId}-gh` : 'g-1', displayName: 'One'}, allowedOrigins: [origin], scopes,
      createdAt: now, updatedAt: now, authRevision: randomUUID()}, {subjectId: externalUserId, userRecordId: user.id}));
    app.stores.open(scope).vault.set(id, {accessToken: 'ya29.leak', refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000, scopes});
    return id;
  };
  const cal = await account('u1', 'google-calendar', 'https://www.googleapis.com', ['https://www.googleapis.com/auth/calendar.readonly']);
  const mail = await account('u1', 'gmail', 'https://gmail.googleapis.com', ['https://www.googleapis.com/auth/gmail.readonly']);
  const other = await account('u2', 'google-calendar', 'https://www.googleapis.com', ['https://www.googleapis.com/auth/calendar.readonly']);
  const options = body => call('POST', '/v1/options', {externalUserId: 'u1', accountRef: cal, capabilityId: ids['calendar.events.list'], input: 'calendarId', ...body});
  const quiet = () => ({jobs: repo().list('jobs').length, usage: repo().list('usageEvents').length});
  return {app, sim, scope, ids, call, repo, account, cal, mail, other, options, quiet};
}

test('calendars a person can pick, page by page, labelled as they named them; credentials never appear; no job and no usage record', async t => {
  const {options, quiet} = await setup(t);
  const first = await options({});
  assert.equal(first.status, 200);
  assert.deepEqual(first.body.options.slice(0, 2), [{label: 'My calendar', value: 'primary'}, {label: 'Team', value: 'team@group'}]);
  assert.equal(JSON.stringify(first.body).includes('ya29.leak'), false, 'the account\'s own token is scrubbed even from labels and values');
  // The cursor is sealed: no person or account id and no provider page token can be read from it, and a changed one fails.
  const opened = Buffer.from(first.body.nextCursor, 'base64url').toString('latin1');
  for (const hidden of ['usr_', 'page-2', '"u"', '"a"']) assert.equal(opened.includes(hidden), false, hidden);
  const flipped = Buffer.from(first.body.nextCursor, 'base64url'); flipped[flipped.length - 1] ^= 1;
  assert.equal((await options({cursor: flipped.toString('base64url')})).body.error.code, 'invalid_request');
  const second = await options({cursor: first.body.nextCursor});
  assert.deepEqual(second.body, {options: [{label: 'Holidays', value: 'holidays@group'}]});
  assert.deepEqual((await options({query: 'tea'})).body.options.map(item => item.value), ['team@group']);
  assert.deepEqual(quiet(), {jobs: 0, usage: 0});
});

// F10.13 part 1 (docs/F10.13-BUILD-MAP.md part 1): a map Discovery stores holds paths below the app's base (Calendar's /calendar/v3), so the
// capability's URL path is compared with the base joined to the map operation's path, never with the operation's path alone.
test('F10.13 part 1: a Calendar map as Discovery stores it, below /calendar/v3, lists calendars under Allow; a capability outside the base, or whose path only ends with the joined path, answers no_option_source', async t => {
  const discovered = await setup(t, {calendarList: {server: 'https://www.googleapis.com/calendar/v3', route: '/users/me/calendarList', path: '/users/me/calendarList'}});
  const listed = await discovered.options({});
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body.options.slice(0, 2), [{label: 'My calendar', value: 'primary'}, {label: 'Team', value: 'team@group'}]);
  assert.deepEqual(discovered.sim.calls.filter(line => line.includes('/calendarList')), ['GET https://www.googleapis.com/calendar/v3/users/me/calendarList']);
  const labels = await discovered.call('POST', '/v1/options', {externalUserId: 'u1', accountRef: discovered.mail, capabilityId: discovered.ids['gmail.users.messages.list'], input: 'labelIds'});
  assert.deepEqual(labels.body.options, [{label: 'INBOX', value: 'INBOX'}, {label: 'Receipts', value: 'Label_1'}], 'Gmail, whose base has no path, lists as before');
  for (const [label, calendarList] of [['outside the base, at the operation\'s path alone', {server: 'https://www.googleapis.com', route: '/users/me/calendarList', path: '/users/me/calendarList'}],
    ['a path that only ends with the joined path', {server: 'https://www.googleapis.com/extra', route: '/calendar/v3/users/me/calendarList', path: '/users/me/calendarList'}],
    ['a joined path that only ends with the capability\'s', {server: 'https://www.googleapis.com/calendar/v3', route: '/users/me/calendarList', path: '/extra/users/me/calendarList'}]]) {
    const {sim, options} = await setup(t, {calendarList});
    const answer = await options({});
    assert.deepEqual([answer.status, answer.body.error?.code], [422, 'no_option_source'], label);
    assert.equal(sim.calls.length, 0, `${label}: nothing is sent`);
  }
});

test('Gmail labels for a labelIds input; inputs without a reviewed source, and GitHub, answer no_option_source', async t => {
  const {app, scope, ids, call, account, mail, cal} = await setup(t);
  const labels = await call('POST', '/v1/options', {externalUserId: 'u1', accountRef: mail, capabilityId: ids['gmail.users.messages.list'], input: 'labelIds'});
  assert.deepEqual(labels.body.options, [{label: 'INBOX', value: 'INBOX'}, {label: 'Receipts', value: 'Label_1'}]);
  assert.equal((await call('POST', '/v1/options', {externalUserId: 'u1', accountRef: mail, capabilityId: ids['gmail.users.messages.list'], input: 'userId'})).body.error.code, 'no_option_source');
  const hub = await account('u1', 'github', 'https://api.github.com', ['repo']);
  const none = await call('POST', '/v1/options', {externalUserId: 'u1', accountRef: hub, capabilityId: ids['repos/list-for-owner'], input: 'owner'});
  assert.equal(none.status, 422); assert.equal(none.body.error.code, 'no_option_source');
  assert.equal((await call('POST', '/v1/options', {externalUserId: 'u1', accountRef: cal, capabilityId: ids['calendar.events.list'], input: 'nope'})).status, 400);
  // The capabilities say which inputs have options.
  const listed = (await call('GET', '/v1/capabilities?appId=google-calendar')).body.capabilities;
  assert.deepEqual(listed.map(item => item.hasOptions).sort(), [false, true]);
  assert.deepEqual((await call('GET', `/v1/capabilities/${encodeURIComponent(ids['calendar.events.list'])}`)).body.optionInputs, ['calendarId']);
  void app; void scope;
});

test('only an Allow row lists: Ask, Never and a developer ceiling are refused before anything is sent', async t => {
  const {app, sim, scope, ids, cal, options} = await setup(t);
  const permissions = app.runtimes.bundle(scope).permissions;
  for (const mode of ['ask', 'deny']) {
    permissions.set({connectionId: cal, capabilityId: ids['calendar.calendarList.list'], mode});
    const refused = await options({});
    assert.equal(refused.status, 403, mode); assert.equal(refused.body.error.code, 'permission_denied');
  }
  permissions.set({connectionId: cal, capabilityId: ids['calendar.calendarList.list'], mode: 'allow'});
  const environment = app.registry.get('environments', scope.environmentId);
  app.registry.put('environments', {...environment, apps: {'google-calendar': {ceilings: {'google-calendar.calendars.read': 'ask'}}}});
  assert.equal((await options({})).body.error.code, 'permission_denied');
  assert.equal(sim.calls.length, 0);
});

test('a sensitive list row lists nothing even when set to Allow; an app switched off lists nothing', async t => {
  const {app, sim, scope, ids, cal, options} = await setup(t, {listSensitive: true});
  const permissions = app.runtimes.bundle(scope).permissions;
  permissions.set({connectionId: cal, capabilityId: ids['calendar.calendarList.list'], mode: 'allow'});
  assert.equal(permissions.decision(app.stores.open(scope).repository.get('connections', cal), app.stores.open(scope).repository.get('capabilities', ids['calendar.calendarList.list'])).mode, 'allow');
  const sensitive = await options({});
  assert.equal(sensitive.status, 403); assert.equal(sensitive.body.error.code, 'permission_denied');
  const environment = app.registry.get('environments', scope.environmentId);
  app.registry.put('environments', {...environment, apps: {'google-calendar': {enabled: false}}});
  const off = await options({});
  assert.equal(off.status, 422); assert.equal(off.body.error.code, 'app_disabled');
  assert.equal(sim.calls.length, 0);
});

test('if the reviewed rows no longer put the list in its row, nothing lists: never the unreviewed default', async t => {
  const {app, sim, scope, options} = await setup(t);
  const permissions = app.runtimes.bundle(scope).permissions, reviewed = permissions.groups.get('google-calendar');
  const groups = new Map(permissions.groups);
  groups.set('google-calendar', {...reviewed, groups: reviewed.groups.map(group => ({...group, operations: group.operations.filter(id => id !== 'calendar.calendarList.list')}))});
  permissions.groups = groups;
  const answer = await options({});
  assert.equal(answer.status, 422); assert.equal(answer.body.error.code, 'no_option_source');
  assert.equal(sim.calls.length, 0);
});

test('another user\'s account is not_found before any credential is read; a cursor replayed for another user is refused', async t => {
  const {sim, ids, other, call, options} = await setup(t);
  const theirs = await options({accountRef: other});
  assert.equal(theirs.status, 404); assert.equal(sim.calls.length, 0);
  const page = await options({});
  const stolen = await call('POST', '/v1/options', {externalUserId: 'u2', accountRef: other, capabilityId: ids['calendar.events.list'], input: 'calendarId', cursor: page.body.nextCursor});
  assert.equal(stolen.status, 400); assert.match(stolen.body.error.message, /another list/);
});

test('an OpenAPI-built map whose list has another operation id gives no_option_source, never an unreviewed Allow', async t => {
  const {options} = await setup(t, {calendarListId: 'list-calendars'});
  const answer = await options({});
  assert.equal(answer.status, 422); assert.equal(answer.body.error.code, 'no_option_source');
});

test('a map entry bound to another operation\'s capability gives no_option_source, and nothing is sent', async t => {
  const {sim, options} = await setup(t, {listBoundTo: 'calendar.events.list'});
  const answer = await options({});
  assert.equal(answer.status, 422); assert.equal(answer.body.error.code, 'no_option_source');
  assert.equal(sim.calls.length, 0);
});

test('a row switched to Never while the token refreshes lists nothing', async t => {
  const {app, sim, scope, ids, cal, options} = await setup(t);
  const vault = app.stores.open(scope).vault;
  vault.set(cal, {...vault.get(cal), expiresAt: Date.parse(app.registry.now()) + 10_000});
  let release; sim.refreshHeld = new Promise(resolve => { release = resolve; });
  const pending = options({});
  await new Promise(resolve => setTimeout(resolve, 30));
  app.runtimes.bundle(scope).permissions.set({connectionId: cal, capabilityId: ids['calendar.calendarList.list'], mode: 'deny'});
  release();
  const answer = await pending;
  assert.equal(answer.status, 403);
  assert.ok(sim.calls.some(line => line.includes('oauth2.googleapis.com/token')), 'the refresh really ran');
  assert.equal(sim.calls.filter(line => line.includes('/calendarList') && !line.includes('maxResults=1')).length, 0, 'the list itself was never requested');
});

test('option sources are checked when loaded: a source must be an operation of the read row it names', () => {
  const base = {schemaVersion: 1, appId: 'gmail', reviewed: 'x', sources: [{id: 'labels', operation: 'gmail.users.labels.list', row: 'gmail.labels.read', serves: ['labelIds'], args: {}, items: '/labels', value: '/id', label: ['/name'], pageToken: null, maxItems: 10}]};
  assert.equal(validateOptionSources(base).length, 1);
  assert.throws(() => validateOptionSources({...base, sources: [{...base.sources[0], operation: 'gmail.users.messages.send'}]}), /read row/);
  assert.throws(() => validateOptionSources({...base, sources: [{...base.sources[0], row: 'gmail.messages.send'}]}), /read row/);
  assert.throws(() => validateOptionSources({...base, sources: [{...base.sources[0], value: 'id'}]}), /pointers/);
});

test('a row switched to Never while the provider answers withholds the list (review fix)', async t => {
  const {app, sim, scope, ids, cal, options} = await setup(t);
  let release; sim.listHeld = new Promise(resolve => { release = resolve; });
  const pending = options({});
  await new Promise(resolve => setTimeout(resolve, 30));
  app.runtimes.bundle(scope).permissions.set({connectionId: cal, capabilityId: ids['calendar.calendarList.list'], mode: 'deny'});
  release();
  const answer = await pending;
  assert.equal(answer.status, 403); assert.equal(answer.body.options, undefined);
  assert.equal(JSON.stringify(answer.body).includes('My calendar'), false);
});

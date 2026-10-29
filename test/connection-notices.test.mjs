import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, existsSync} from 'node:fs';
import {mkdtemp, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomUUID} from 'node:crypto';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {current, consentDue, shownNotice, NOTICE_WORDS} from '../lib/connection-notices.mjs';
import {describeApp} from '../public/hosted-app.js';
import {HeartbeatScheduler} from '../lib/heartbeat.mjs';
import {createApp} from '../server.mjs';
import {createDeveloperApp} from '../developer-server.mjs';
import {testEnvironment} from '../scripts/test.mjs';
import {owner, freePort} from './fixtures/signin-fixture.mjs';
import {GoogleSimulator} from './fixtures/oauth-simulators.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';

// F10.4 connection notices: activity events of type connection.health that tell the owner an account needs attention
// before it stops working. One per connection, sign-in, kind and subject, however often the condition is seen, so a
// renewal (a new sign-in) can raise its own. They carry no tokens, no provider text and no scope names, show at the top
// of app detail and as the account row's attention line, and never say "disconnect": signing in again keeps settings.
// consent_expiring uses the operator setting FABRIC_<PROVIDER>_CONSENT_DAYS locally; developer environments pass the
// value explicitly (7 on Fabric's shared Google app, the developer app's own consentDays otherwise) and never read it.
const DAY = 24 * 3600 * 1000;
const READ = ['openid', 'email', 'https://www.googleapis.com/auth/calendar.calendarlist.readonly', 'https://www.googleapis.com/auth/calendar.events.readonly'];
const WIDER = [...READ, 'https://www.googleapis.com/auth/calendar.events'];
const PROVIDER_TEXT = 'Synthetic provider complaint 7f3a';
const SECRET = 'notices-client-secret';
const FIELDS = ['appId', 'connectionId', 'count', 'createdAt', 'id', 'kind', 'signInRevision', 'subjectKey', 'type', 'updatedAt'];
const tokenResponse = (extra = {}) => ({status: 200, data: {access_token: `access-${randomUUID()}`, refresh_token: 'notices-refresh', token_type: 'Bearer', expires_in: 3600, scope: READ.join(' '), ...extra}});

/** The single-owner engine on a designated store, with synthetic Google answers. F10.7: on the version 1 Google definition of
 *  test/fixtures/auth-v1 (T6 through the fixtures), whose Calendar read level these scopes are; the shipped catalog is version 2. */
function local(t, {consentDays = null} = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'fabric-notices-'));
  const store = new Store({dataDir: dir, localAuthority: 'new'}), vault = new Vault(dir);
  const state = {now: Date.parse('2026-10-11T00:00:00Z'), tokenHook: null, identity: 200};
  const request = async req => {
    if (req.url.endsWith('/token')) return state.tokenHook ? state.tokenHook(req) : tokenResponse();
    if (req.url.endsWith('/userinfo')) return state.identity === 200 ? {status: 200, data: {sub: 'fixture-account', email: 'fixture@example.test'}} : {status: state.identity, data: {error: 'invalid_token', error_description: PROVIDER_TEXT}};
    if (req.url.includes('/calendar/v3/')) return {status: 200, data: {kind: 'calendar#calendarList'}};
    throw new Error('Unexpected synthetic request');
  };
  const connections = new ConnectionManager({store, vault, request, clock: () => state.now});
  const oauth = new OAuth2Provider(v1Definition('google'), {store, vault, connections, request, clientId: 'notices-client', clientSecret: SECRET, clock: () => state.now, consentDays});
  connections.setOAuthProvider(oauth);
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  const connect = async connectionId => { const flow = oauth.start(connectionId ? {connectionId} : {}); return oauth.callback({state: new URL(flow.authorizationUrl).searchParams.get('state'), code: 'fixture-code', flowId: flow.flowId}); };
  const notices = (id, kind) => store.list('activity').filter(event => event.type === 'connection.health' && event.connectionId === id && (!kind || event.kind === kind));
  const shown = id => current(store, store.get('connections', id)).map(notice => notice.kind);
  return {store, vault, state, connections, oauth, connect, notices, shown, advance: ms => { state.now += ms; }, expire: () => { state.now += 3600 * 1000; }};
}
/** Nothing a notice holds is a credential, a provider's words, a scope name or a message. */
function assertClean(f, notices) {
  assert.ok(notices.length > 0);
  const text = JSON.stringify(notices);
  for (const notice of notices) assert.deepEqual(Object.keys(notice).sort(), FIELDS);
  for (const leak of [SECRET, 'notices-refresh', 'access-', PROVIDER_TEXT, 'invalid_token', 'googleapis.com', 'openid', 'Reconnect', 'rejected']) assert.equal(text.includes(leak), false, leak);
  assert.equal(/token|secret/i.test(Object.keys(Object.assign({}, ...notices)).join(' ')), false);
}

test('exactly one notice per connection, sign-in, kind and subject, however many checks run; a new sign-in gets its own', async t => {
  const f = local(t), {id} = await f.connect(), first = f.store.get('connections', id);
  assert.deepEqual(f.shown(id), []);
  f.state.identity = 401;
  for (let i = 0; i < 3; i++) assert.equal((await f.connections.check(id)).status, 'reconnect_required');
  assert.deepEqual(f.notices(id).map(notice => [notice.kind, notice.signInRevision, notice.subjectKey, notice.count]), [['reconnect_required', first.signInRevision, '', 3]]);
  // Health ticks (a connection heartbeat) see the same condition: they count it, never add a second notice.
  const heartbeats = new HeartbeatScheduler({store: f.store, runtime: null, checkConnection: connectionId => f.connections.check(connectionId), clock: () => f.state.now});
  heartbeats.create({name: 'Health', intervalSeconds: 30, connectionId: id});
  for (let i = 0; i < 3; i++) { f.advance(31 * 1000); await heartbeats.tick(); }
  assert.deepEqual(f.store.list('heartbeats').map(h => [h.runs, h.lastResult.status]), [[3, 'attention']]);
  assert.deepEqual(f.notices(id).map(notice => [notice.kind, notice.signInRevision, notice.count]), [['reconnect_required', first.signInRevision, 6]]);
  assert.deepEqual(f.shown(id), ['reconnect_required']);
  assertClean(f, f.notices(id));
  // A reconnect notice lasts only while the account needs it: a later check that passes on the same sign-in clears it.
  f.state.identity = 200;
  assert.equal((await f.connections.check(id)).status, 'ready'); assert.deepEqual(f.shown(id), []);
  f.state.identity = 401; await f.connections.check(id);
  assert.deepEqual(f.shown(id), ['reconnect_required']); assert.equal(f.notices(id).length, 1, 'the same sign-in: the same notice');
  // Signing in again is a renewal: the old notice is history, not current.
  f.state.identity = 200;
  await f.connect(id);
  assert.equal(f.store.get('connections', id).status, 'ready'); assert.deepEqual(f.shown(id), []);
  f.state.identity = 401;
  await f.connections.check(id); await f.connections.check(id);
  assert.equal(f.notices(id).length, 2, 'one per sign-in');
  assert.deepEqual(f.shown(id), ['reconnect_required']);
});

test('consent_expiring appears one day before the consent days end, once per sign-in, and the next week\'s renewal gets its own', async t => {
  const f = local(t, {consentDays: 7}), {id} = await f.connect();
  assert.equal(f.oauth.consentDays, 7);
  f.advance(5 * DAY); await f.connections.check(id);
  assert.deepEqual(f.notices(id), []);
  f.advance(DAY); await f.connections.check(id); await f.connections.check(id);
  assert.deepEqual(f.notices(id).map(notice => [notice.kind, notice.count]), [['consent_expiring', 2]]);
  assert.deepEqual(f.shown(id), ['consent_expiring']);
  assert.equal(f.store.get('connections', id).status, 'ready', 'a warning, not a failure');
  await f.connect(id);
  await f.connections.check(id);
  assert.deepEqual(f.shown(id), [], 'the renewal starts a new week');
  f.advance(6 * DAY); await f.connections.check(id);
  assert.deepEqual(f.shown(id), ['consent_expiring']);
  const both = f.notices(id, 'consent_expiring');
  assert.equal(both.length, 2); assert.notEqual(both[0].signInRevision, both[1].signInRevision);
  assertClean(f, both);
  // consentDue reads signedInAt, and falls back to createdAt for a record from before sign-in revisions.
  const at = Date.parse('2026-10-01T00:00:00Z'), record = {createdAt: new Date(at).toISOString()};
  assert.deepEqual([consentDue(record, {consentDays: 7, now: at + 6 * DAY - 1}), consentDue(record, {consentDays: 7, now: at + 6 * DAY}), consentDue(record, {consentDays: null, now: at + 60 * DAY})], [false, true, false]);
});

test('without consent days nothing warns, however long the sign-in lasts', async t => {
  const f = local(t), {id} = await f.connect();
  assert.equal(f.oauth.consentDays, null);
  f.advance(60 * DAY); await f.connections.check(id);
  assert.deepEqual(f.notices(id), []);
});

test('a narrower renewal and a narrower refresh each raise one grant_narrowed, keyed by the scopes lost and never naming them', async t => {
  const f = local(t), {id} = await f.connect();
  const renew = scopes => f.connections.establishOAuth({connectionId: id, appId: 'google-calendar', tokens: {accessToken: `access-${randomUUID()}`, refreshToken: 'notices-refresh', expiresAt: f.state.now + 3600 * 1000, scopes}});
  await renew(READ.slice(0, -1));
  const renewal = f.notices(id, 'grant_narrowed');
  assert.equal(renewal.length, 1); assert.match(renewal[0].subjectKey, /^scopes:[0-9a-f]{64}$/);
  assert.equal(renewal[0].signInRevision, f.store.get('connections', id).signInRevision);
  await renew(READ);
  assert.deepEqual(f.shown(id), [], 'the scope came back with a new sign-in');
  f.expire(); f.state.tokenHook = async () => tokenResponse({scope: READ.slice(0, -2).join(' ')});
  await assert.rejects(f.connections.credentials(id), {code: 'connection_changed'});
  await f.connections.check(id).catch(() => {});
  const refresh = f.notices(id, 'grant_narrowed').filter(notice => notice.signInRevision === f.store.get('connections', id).signInRevision);
  assert.equal(refresh.length, 1); assert.notEqual(refresh[0].subjectKey, renewal[0].subjectKey, 'a different set of scopes lost');
  assert.deepEqual(f.shown(id), ['grant_narrowed']);
  assertClean(f, f.notices(id));
});

test('the refresh wall marks the account once: one reconnect notice however often it is met', async t => {
  const f = local(t), {id} = await f.connect();
  f.expire(); f.state.tokenHook = async () => tokenResponse({scope: WIDER.join(' ')});
  await assert.rejects(f.connections.credentials(id), {code: 'reconnect_required'});
  assert.deepEqual(f.notices(id).map(notice => notice.kind), ['reconnect_required'], 'a refresh outside any check raises it too');
  await f.connections.check(id); await f.connections.check(id);
  assert.deepEqual(f.notices(id).map(notice => notice.kind), ['reconnect_required']);
  assertClean(f, f.notices(id));
});

test('a bad consent-days setting names itself before any local state opens; adapters check explicit values; tests never inherit one', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'fabric-consent-days-'));
  t.after(async () => { delete process.env.FABRIC_GOOGLE_CONSENT_DAYS; delete process.env.FABRIC_SLACK_CONSENT_DAYS; await rm(directory, {recursive: true, force: true}); });
  for (const [name, value] of [['FABRIC_GOOGLE_CONSENT_DAYS', '0'], ['FABRIC_GOOGLE_CONSENT_DAYS', '366'], ['FABRIC_GOOGLE_CONSENT_DAYS', 'x'], ['FABRIC_GOOGLE_CONSENT_DAYS', '7.5'], ['FABRIC_SLACK_CONSENT_DAYS', '']]) {
    process.env[name] = value;
    await assert.rejects(createApp({dataDir: join(directory, 'data'), port: 0}), new RegExp(`${name} must be a whole number of days from 1 to 365`));
    assert.equal(existsSync(join(directory, 'data', 'fabric.sqlite')), false);
    delete process.env[name];
  }
  const options = {store: null, vault: null, connections: null, clientId: 'c', clientSecret: 's'};
  for (const consentDays of [0, 366, 2.5, '7']) assert.throws(() => new OAuth2Provider(definitionFor('google'), {...options, consentDays}), /consent days/i);
  assert.equal(new OAuth2Provider(definitionFor('google'), {...options, consentDays: 7}).consentDays, 7);
  process.env.FABRIC_GOOGLE_CONSENT_DAYS = '9';
  assert.equal(new OAuth2Provider(definitionFor('google'), options).consentDays, 9, 'the operator setting, locally');
  assert.equal(new OAuth2Provider(definitionFor('google'), {...options, consentDays: null}).consentDays, null, 'an explicit value wins');
  // A developer's own provider app takes every value explicitly, consent days included (N11).
  const developer = {...options, providerAppId: `pa_${'a'.repeat(26)}`, publishing: 'testing'};
  assert.throws(() => new OAuth2Provider(definitionFor('google'), developer), /consent days/);
  assert.equal(new OAuth2Provider(definitionFor('google'), {...developer, consentDays: null}).consentDays, null);
  assert.deepEqual(testEnvironment({PATH: '/bin', FABRIC_GOOGLE_CONSENT_DAYS: '7'}), {PATH: '/bin'}, 'the test runner drops the operator setting');
});

test('notices show at the top of app detail and as the account row\'s attention line, in words that never say disconnect', async t => {
  const GOOGLE = {FABRIC_GOOGLE_CLIENT_ID: 'notices-google-client', FABRIC_GOOGLE_CLIENT_SECRET: 'notices-google-secret', FABRIC_GOOGLE_CONSENT_DAYS: '7'};
  const previous = Object.fromEntries(Object.keys(GOOGLE).map(key => [key, process.env[key]]));
  Object.assign(process.env, GOOGLE);
  const dir = await mkdtemp(join(tmpdir(), 'fabric-notices-app-'));
  let now = Date.parse('2026-10-11T10:00:00.000Z');
  const sim = new GoogleSimulator({clientId: GOOGLE.FABRIC_GOOGLE_CLIENT_ID, clientSecret: GOOGLE.FABRIC_GOOGLE_CLIENT_SECRET, clock: () => now});
  const request = async req => { if (/^https:\/\/[a-z0-9.]*google(apis)?\.com\//.test(req.url)) return sim.request(req); throw new Error('No network in this fixture'); };
  const app = await createApp({dataDir: dir, port: await freePort(), clock: () => now, request, localAuthority: {mode: 'new', ownerPrincipal: owner}});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  let csrf, session;
  const login = async () => { const first = await fetch(`${app.origin}/api/state`); csrf = (await first.json()).csrfToken; session = first.headers.get('set-cookie').split(';')[0]; };
  await login();
  const call = async (method, route) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {'content-type': 'application/json', 'x-fabric-csrf': csrf, cookie: session}, ...(method === 'POST' ? {body: '{}'} : {})}); return {status: response.status, body: await response.json()}; };
  assert.equal(app.oauth.consentDays, 7);
  const flow = app.oauth.start({appId: 'gmail'}), grant = sim.consent(flow.authorizationUrl, {account: 'a'});
  const {id} = await app.oauth.callback({state: grant.state, code: grant.code, flowId: flow.flowId});
  let page = (await call('GET', '/api/ui/apps/gmail')).body;
  assert.deepEqual(page.notices, []); assert.equal('attention' in page.accounts[0], false);
  now += 6 * DAY;
  await login();
  assert.equal((await call('POST', `/api/connections/${id}/check`)).body.status, 'ready');
  page = (await call('GET', '/api/ui/apps/gmail')).body;
  assert.deepEqual(page.notices.map(notice => [notice.kind, notice.accountRef]), [['consent_expiring', id]]);
  assert.deepEqual(Object.keys(page.notices[0]).sort(), ['accountRef', 'kind', 'message', 'since']);
  assert.equal(page.accounts[0].status, 'ready'); assert.equal(page.accounts[0].attention, page.notices[0].message);
  assert.match(page.notices[0].message, /sign in again/i);
  // A sign-in the provider ended reads the same way: sign in again, never "disconnect".
  sim.revokeAccount('a');
  assert.equal((await call('POST', `/api/connections/${id}/check`)).body.status, 'reconnect_required');
  page = (await call('GET', '/api/ui/apps/gmail')).body;
  assert.deepEqual(page.notices.map(notice => notice.kind).sort(), ['consent_expiring', 'reconnect_required']);
  assert.equal(page.accounts[0].attention, page.notices.find(notice => notice.kind === 'reconnect_required').message, 'the most urgent notice is the attention line');
  for (const text of [...page.notices.map(notice => notice.message), page.accounts[0].attention]) assert.doesNotMatch(text, /disconnect/i);
});

test('developer environments pass consent days explicitly and show notices on the developer\'s and the person\'s views, for that person only', async t => {
  const root = mkdtempSync(join(tmpdir(), 'fabric-notices-tenant-'));
  let now = Date.parse('2026-10-11T10:00:00.000Z');
  const people = new Map(), sim = {next: null};
  const request = async req => {
    if (req.url === 'https://oauth2.googleapis.com/token') { const token = `ya29.${randomUUID()}`; people.set(token, sim.next); return {status: 200, headers: {}, data: {access_token: token, refresh_token: `1//${randomUUID()}`, token_type: 'Bearer', expires_in: 3599, scope: sim.scope}}; }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') { const who = people.get(String(req.headers.Authorization).slice(7)); return {status: 200, headers: {}, data: {sub: who.id, email: who.email, name: who.name}}; }
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) return {status: 200, headers: {}, data: {emailAddress: people.get(String(req.headers.Authorization).slice(7)).email}};
    throw new Error(`unexpected request ${req.url}`);
  };
  const saved = process.env.FABRIC_GOOGLE_CONSENT_DAYS;
  process.env.FABRIC_GOOGLE_CONSENT_DAYS = '30';
  const app = await createDeveloperApp({dataRoot: root, port: 0, clock: () => now, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); if (saved === undefined) delete process.env.FABRIC_GOOGLE_CONSENT_DAYS; else process.env.FABRIC_GOOGLE_CONSENT_DAYS = saved; });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  const connect = async (externalUserId, identity) => {
    const created = (await call('POST', '/v1/connect-sessions', {externalUserId, appId: 'gmail'})).body, binding = `browser-${created.id}`;
    app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
    const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl);
    sim.next = identity; sim.scope = url.searchParams.get('scope');
    const {finish} = await app.sessions.callback('google', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
    return app.sessions.confirm(created.id, binding, finish).result.accountRef;
  };
  const one = await connect('u1', {id: 'g-1', email: 'one@example.com', name: 'One'}), two = await connect('u2', {id: 'g-2', email: 'two@example.com', name: 'Two'});
  assert.equal(app.runtimes.bundle(scope).adapters.get('google').consentDays, 7, 'Fabric\'s shared Google app: Testing mode, never the machine\'s setting');
  const own = (await call('POST', '/v1/provider-apps', {providerId: 'google', clientId: 'dev-google-client', clientSecret: 'dev-google-secret', consentScreenName: 'Acme Agent', consentDays: 3})).body.providerApp.id;
  const plain = (await call('POST', '/v1/provider-apps', {providerId: 'google', clientId: 'dev-google-other', clientSecret: 'dev-google-secret', consentScreenName: 'Acme Agent'})).body.providerApp.id;
  assert.equal(app.runtimes.developerAdapter(scope, own).consentDays, 3);
  assert.equal(app.runtimes.developerAdapter(scope, plain).consentDays, null);
  now += 6 * DAY;
  sim.next = {id: 'g-1', email: 'one@example.com', name: 'One'};
  const checked = await call('POST', `/v1/users/u1/accounts/${one}/check`);
  assert.equal(checked.status, 200); assert.equal(checked.body.status, 'ready'); assert.match(checked.body.attention, /sign in again/i);
  const page = (await call('GET', '/v1/users/u1/apps/gmail')).body;
  assert.deepEqual(page.notices.map(notice => [notice.kind, notice.accountRef]), [['consent_expiring', one]]);
  assert.equal(page.accounts[0].attention, page.notices[0].message);
  assert.equal((await call('GET', '/v1/users/u1/accounts')).body.accounts[0].attention, page.notices[0].message);
  assert.equal((await call('GET', `/v1/accounts/${one}`)).body.attention, page.notices[0].message);
  const other = (await call('GET', '/v1/users/u2/apps/gmail')).body;
  assert.deepEqual(other.notices, []); assert.equal('attention' in other.accounts[0], false); assert.equal(other.accounts[0].accountRef, two);
  const ownerOne = app.accounts.ownerOf(app.accounts.user(app.stores.open(scope), 'u1'));
  const person = app.pages.viewFor({scope, owner: ownerOne}, 'gmail', undefined, {endUser: true});
  assert.deepEqual(person.notices.map(notice => notice.kind), ['consent_expiring']); assert.equal(person.accounts[0].attention, page.notices[0].message);
  const stored = app.stores.open(scope).repository.list('activity').filter(event => event.type === 'connection.health');
  assert.equal(stored.length, 1); assert.equal(stored[0].userRecordId, ownerOne.userRecordId, 'stamped with its owner');
});

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, spec line 1147): an org_restricted notice names its organization, from its subject, and the
// app page lists each organization GitHub refused, one line each. Fabric knows only the organizations GitHub refused (open question 8).
test('shownNotice() gives organization for org_restricted only, from its subject; the app page shows one line per organization', () => {
  const base = {connectionId: 'c1', createdAt: '2026-10-25T00:00:00.000Z'}, ORG_LINE = name => `${name}: this organization limits what Fabric can reach. Ask its admin to approve Fabric.`;
  assert.deepEqual(shownNotice({...base, kind: 'org_restricted', subjectKey: 'org:octo-org'}), {kind: 'org_restricted', accountRef: 'c1', message: NOTICE_WORDS.org_restricted, since: base.createdAt, organization: 'octo-org'});
  for (const [kind, subjectKey] of [['reconnect_required', ''], ['grant_narrowed', `scopes:${'0'.repeat(64)}`], ['consent_expiring', ''], ['grant_narrowed', 'org:octo-org']]) {
    assert.equal(Object.hasOwn(shownNotice({...base, kind, subjectKey}), 'organization'), false, `${kind} ${subjectKey}`);
  }
  assert.equal(Object.hasOwn(shownNotice({...base, kind: 'org_restricted', subjectKey: ''}), 'organization'), false, 'no subject names no organization');
  const notices = [shownNotice({...base, kind: 'org_restricted', subjectKey: 'org:octo-org'}), shownNotice({...base, kind: 'org_restricted', subjectKey: 'org:acme'}), shownNotice({...base, kind: 'consent_expiring', subjectKey: ''})];
  const one = {app: {id: 'github', name: 'GitHub'}, accounts: [{accountRef: 'c1', displayName: 'octo-a'}], selectedAccountRef: 'c1', notices, sections: [], connectionState: 'connected'};
  assert.deepEqual(describeApp(one).notices.map(notice => notice.text), [ORG_LINE('octo-org'), ORG_LINE('acme'), NOTICE_WORDS.consent_expiring]);
  const two = {...one, accounts: [...one.accounts, {accountRef: 'c2', displayName: 'octo-b'}]};
  assert.deepEqual(describeApp(two).notices.map(notice => notice.text), [`octo-a: ${ORG_LINE('octo-org')}`, `octo-a: ${ORG_LINE('acme')}`, `octo-a: ${NOTICE_WORDS.consent_expiring}`], 'with several accounts, each line says which');
});

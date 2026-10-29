import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {appService} from '../lib/tenant/app-pages.mjs';
import {scopesSubject} from '../lib/connection-notices.mjs';

// F10.4 part f (T7 in developer environments, docs/F03-DEVELOPER-LAYER.md section 4.3; replaces the refusal of
// test/tenant-upgrade-refusal.test.mjs). Through Connect sessions in a development environment on Fabric's shared Google
// app: signing in again within what the person approved is a renewal that keeps saved settings, agent grants and the
// account; a wider sign-in is an upgrade that parks at the confirm screen with the upgrade card, turns saved Allow into
// Ask and keeps Never. Reconnect and Add access sessions open, sign in through the account's own sign-in app, and add only
// what an unlocked row needs. Google's grant is never revoked from a shared app (N9).
// F10.7: Gmail signs in with version 2. Its read level is gmail.readonly; `read_write` names the full level for one release (g5), whose
// scope the wider sign-ins and Add access add is gmail.modify.
const G = 'https://www.googleapis.com/auth/', GMAIL = 'https://gmail.googleapis.com', READ = `${G}gmail.readonly`, ADDED = `${G}gmail.modify`;
// The scopes Google documents for each Gmail method. The broadest alternatives are left out: which one Add access picks is
// F10.6's row-aware rule, and here it asks for gmail.modify, the full level's scope.
const DOCUMENTED = JSON.parse(readFileSync(new URL('./fixtures/access/google-method-scopes.json', import.meta.url), 'utf8')).apps.gmail.methods;
const scopesOf = id => (DOCUMENTED[id] ?? []).filter(scope => scope !== 'https://mail.google.com/' && !scope.includes('.addons.'));
const TYPED = [['gmail.users.messages.get', 'GET', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.drafts.create', 'POST', '/gmail/v1/users/{userId}/drafts'],
  ['gmail.users.messages.send', 'POST', '/gmail/v1/users/{userId}/messages/send'], ['gmail.users.settings.updateVacation', 'PUT', '/gmail/v1/users/{userId}/settings/vacation'],
  ['gmail.users.settings.forwardingAddresses.create', 'POST', '/gmail/v1/users/{userId}/settings/forwardingAddresses']];
const secretOf = url => new URL(url).hash.slice(3);
const ME = {id: 'g-7', email: 'seven@example.com', name: 'Seven'}, OTHER = {id: 'g-8', email: 'eight@example.com', name: 'Eight'};

function seed(root) {
  const paths = {};
  for (const [id, method, route] of TYPED) paths[route] = {[method.toLowerCase()]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method !== 'GET' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: GMAIL}], paths}}).capabilities;
  const store = new PlatformStore({root}), typed = new Map(TYPED.map(([id, method, route]) => [id, {method, route}]));
  const operations = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => {
    const known = typed.get(id), capability = known && compiled.find(item => item.request.method === known.method && item.request.url === `${GMAIL}${known.route}`);
    if (capability) store.put('capabilities', {...capability, status: 'active'});
    return {id, ...(capability ? {capabilityId: capability.id} : {}), method: known?.method ?? (/\.(list|get)$/.test(id) ? 'GET' : 'POST'), path: known?.route ?? `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`, requiredScopes: scopesOf(id), sensitive: null};
  });
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-renewal-'));
  seed(root);
  const sim = {tokens: new Map(), issued: 0, calls: [], next: ME, scope: null};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://oauth2.googleapis.com/token') { const token = `ya29.renew-${++sim.issued}`; sim.tokens.set(token, sim.next); return {status: 200, headers: {}, data: {access_token: token, refresh_token: `1//renew-${sim.issued}`, token_type: 'Bearer', expires_in: 3600, scope: sim.scope}}; }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') { const who = sim.tokens.get(String(req.headers.Authorization).slice(7)); return {status: 200, headers: {}, data: {sub: who.id, email: who.email, name: who.name}}; }
    if (req.url.startsWith(`${GMAIL}/gmail/v1/users/me/profile`)) return {status: 200, headers: {}, data: {emailAddress: sim.tokens.get(String(req.headers.Authorization).slice(7)).email}};
    if (req.url.startsWith('https://oauth2.googleapis.com/revoke')) return {status: 200, headers: {}, data: {}};
    if (req.url.startsWith(`${GMAIL}/`)) { const data = {id: 'm-1'}; return req.responseType === 'buffer' ? {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(data))} : {status: 200, headers: {}, data}; }
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const keys = {full: app.keys.mint({environmentId: dev.id, preset: 'full'}).token, connectOnly: app.keys.mint({environmentId: dev.id, preset: 'connect-only'}).token};
  const call = async (method, route, body, key = keys.full) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: response.status === 204 ? null : await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  /** A link claimed by one browser: its view, its start and its sign-in, as Fabric's page drives them. */
  const open = async (body, key) => {
    const created = await call('POST', '/v1/connect-sessions', {externalUserId: 'u1', ...body}, key);
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const id = created.body.id, binding = `browser-${id}-binding`;
    app.sessions.claim(id, secretOf(created.body.connectUrl), binding);
    const link = {id, binding, view: finish => app.sessions.view(id, binding, undefined, finish), start: (level, confirmRows) => app.sessions.start(id, binding, undefined, level, confirmRows)};
    /** The provider grants exactly what was asked, for whoever signs in, less any box the person unticks (`omit`), plus what it
     *  returns unasked (`extra`, an earlier grant of the same client, say). */
    link.signIn = async ({level, confirmRows, identity = ME, omit = [], extra = []} = {}) => {
      const started = link.start(level, confirmRows), url = new URL(started.authorizationUrl);
      sim.next = identity; sim.scope = [...url.searchParams.get('scope').split(' ').filter(scope => !omit.includes(scope)), ...extra].join(' ');
      const back = await app.sessions.callback('google', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId}, started.callbackPath.match(/\/apps\/(pa_[a-z2-7]{26})\//)?.[1] ?? null);
      return {...back, id, url, started, confirm: extra => app.sessions.confirm(id, binding, back.finish, extra), view: () => link.view(back.finish)};
    };
    return link;
  };
  const signIn = async (body = {}, options = {}) => (await open({appId: 'gmail', ...body})).signIn(options);
  const caps = (await call('GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  const cap = name => caps.find(item => item.id.includes(name));
  const decision = (ref, name) => { const bundle = app.runtimes.bundle(scope), connection = repo().get('connections', ref); return bundle.permissions.decision(connection, repo().get('capabilities', cap(name).id)); };
  let counter = 0;
  const agent = async (token, method, params) => {
    const response = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id: `r${++counter}`, method, params})});
    return {status: response.status, body: await response.json()};
  };
  /** An agent token bound to the account's message read, and one call through it: succeeded, or the refusal's code. */
  const agentRead = async ref => {
    const minted = (await call('POST', '/v1/users/u1/agent-tokens', {name: 'Helper', bindings: [{accountRef: ref, capabilityId: cap('messages-get').id}]})).body;
    const alias = (await agent(minted.token, 'capabilities.list', {})).body.result.capabilities[0].connectionId, read = cap('messages-get');
    return async () => { const answer = await agent(minted.token, 'calls.create', {connectionId: alias, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}}); return answer.body.result?.status ?? answer.body.error?.code; };
  };
  const revokes = () => sim.calls.filter(line => line.includes('oauth2.googleapis.com/revoke')).length;
  const activity = type => repo().list('activity').filter(event => event.type === type);
  const rowOf = async (ref, groupId) => (await call('GET', `/v1/users/u1/apps/gmail?account=${ref}`)).body.sections.flatMap(section => section.rows).find(row => row.groupId === groupId);
  return {app, sim, scope, keys, call, repo, open, signIn, cap, decision, agentRead, revokes, activity, rowOf};
}

test('a renewal keeps the saved Allow, the agent grant and the account; the audit says reconsented', async t => {
  const s = await setup(t);
  const first = await s.signIn({}, {level: 'read'});
  const ref = first.confirm().result.accountRef, before = s.repo().get('connections', ref);
  // Send defaults to Ask, so Allow there is a saved setting (one equal to the default only follows it).
  s.app.runtimes.bundle(s.scope).permissions.set({connectionId: ref, capabilityId: s.cap('messages-send').id, mode: 'allow'});
  const read = await s.agentRead(ref);
  assert.equal(await read(), 'succeeded');
  const again = await s.signIn({}, {level: 'read'});
  assert.equal('upgrade' in again.view(), false, 'within what the person approved there is nothing to confirm');
  const done = again.confirm();
  assert.deepEqual([done.result.accountRef, done.result.renewal], [ref, true]);
  const after = s.repo().get('connections', ref);
  assert.equal(after.authRevision, before.authRevision, 'the authorization is kept');
  assert.notEqual(after.signInRevision, before.signInRevision, 'a new sign-in wrote it');
  assert.deepEqual([after.createdAt, after.identity, after.grantCeiling], [before.createdAt, before.identity, before.grantCeiling]);
  assert.deepEqual([s.decision(ref, 'messages-send').mode, s.decision(ref, 'messages-send').policySource], ['allow', 'saved'], 'the saved Allow survives');
  assert.equal(await read(), 'succeeded', 'the agent grant survives');
  assert.equal(s.activity('connection.reconsented').filter(event => event.connectionId === ref).length, 1);
  assert.equal(s.activity('connection.upgraded').length, 0);
  // A reconnect link for an account that needs a sign-in renews the same account in place (never a second row).
  s.repo().put('connections', {...s.repo().get('connections', ref), status: 'reconnect_required', error: 'The provider rejected the credentials.'});
  const link = await s.open({purpose: 'reconnect', accountRef: ref});
  const renewed = await link.signIn();
  assert.equal(renewed.url.searchParams.get('client_id'), 'g-client');
  assert.deepEqual([renewed.confirm().result.accountRef, s.repo().get('connections', ref).status], [ref, 'ready']);
  assert.equal(s.repo().list('connections').filter(item => item.status !== 'revoked').length, 1);
  assert.equal(s.repo().get('connections', ref).authRevision, before.authRevision);
  assert.equal(s.revokes(), 0, 'Fabric\'s shared Google app never revokes the grant (N9)');
});

test('a wider sign-in parks with the upgrade card; confirm needs it, then Allow becomes Ask, Never stays and the agent grant ends', async t => {
  const s = await setup(t);
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef, before = s.repo().get('connections', ref);
  const permissions = s.app.runtimes.bundle(s.scope).permissions;
  permissions.set({connectionId: ref, capabilityId: s.cap('messages-send').id, mode: 'allow'});
  permissions.set({connectionId: ref, capabilityId: s.cap('updatevacation').id, mode: 'deny'});
  const read = await s.agentRead(ref);
  // The same Google account at read and write: Drafts turns on at its default Allow, so it is on the card. Send turns on too,
  // but its saved Allow becomes Ask. In developer environments proxied writes default to Ask, so only the typed side is listed.
  const wider = await s.signIn({}, {level: 'read_write'});
  assert.equal(wider.failed, undefined);
  const card = wider.view().upgrade;
  assert.deepEqual(card.rows.map(row => [row.groupId, row.typed, row.proxy]), [['gmail.drafts.write', true, false]]);
  assert.match(card.etag, /^[0-9a-f]{64}$/);
  assert.deepEqual(Object.keys(card).sort(), ['etag', 'rows']);
  assert.equal((await s.call('GET', `/v1/connect-sessions/${wider.id}`)).body.state, 'awaiting_confirmation');
  for (const body of [undefined, {}, {confirmRows: 'f'.repeat(64)}]) {
    assert.throws(() => wider.confirm(body), error => error.code === 'confirm_required' && error.status === 409 && error.details?.upgrade?.etag === card.etag, JSON.stringify(body));
  }
  const unchanged = s.repo().get('connections', ref);
  assert.deepEqual([unchanged.authRevision, unchanged.signInRevision, unchanged.scopes], [before.authRevision, before.signInRevision, before.scopes], 'nothing changed');
  assert.equal(s.repo().get('connectSessions', wider.id).state, 'awaiting_confirmation', 'the person can still confirm');
  assert.equal(await read(), 'succeeded');
  const done = wider.confirm({confirmRows: card.etag});
  assert.deepEqual([done.result.accountRef, done.result.renewal], [ref, false]);
  const after = s.repo().get('connections', ref);
  assert.notEqual(after.authRevision, before.authRevision, 'an upgrade is a new authorization');
  assert.ok(after.scopes.includes(ADDED));
  assert.deepEqual(after.grantCeiling, [...new Set([...before.grantCeiling, ...after.scopes])].sort(), 'the ceiling grows to include what was granted');
  assert.deepEqual([s.decision(ref, 'messages-send').mode, s.decision(ref, 'messages-send').policySource], ['ask', 'stale'], 'Allow becomes Ask');
  assert.equal(s.decision(ref, 'updatevacation').mode, 'deny', 'Never stays Never');
  assert.equal(await read(), 'authority_changed', 'the agent grant no longer covers the account');
  assert.equal(s.activity('connection.upgraded').filter(event => event.connectionId === ref).length, 1);
  assert.equal(s.repo().list('connections').filter(item => item.status !== 'revoked').length, 1, 'still one account');
  assert.equal(s.revokes(), 0);
});

test('the card reads the environment\'s proxy rows too: proxied reads that turn on at their default Allow are listed', async t => {
  const s = await setup(t);
  // An account that holds no Gmail scope yet (its earlier grant was cut back to the sign-in itself): signing it in again at read
  // turns on every read row, typed and proxied.
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef, held = s.repo().get('connections', ref), identity = held.scopes.filter(scope => !scope.includes('gmail'));
  s.repo().put('connections', {...held, scopes: identity, grantCeiling: identity});
  // F10.7 (g3): such an account reconnects at full unless the link names read.
  const link = await s.open({purpose: 'reconnect', accountRef: ref, level: 'read'}), card = link.view().upgrade;
  const listed = Object.fromEntries(card.rows.map(row => [row.groupId, [row.typed, row.proxy]]));
  assert.deepEqual(listed['gmail.messages.read'], [true, true]);
  assert.deepEqual(listed['gmail.labels.read'], [false, true], 'a row with no typed operation here is listed for the proxy');
  assert.equal('gmail.drafts.write' in listed, false);
  assert.throws(() => link.start(), {code: 'confirm_required'});
  assert.match(new URL(link.start(undefined, card.etag).authorizationUrl).searchParams.get('scope'), /gmail\.readonly/);
});

test('F10.6 correction 1: an account that must reconnect still lists its proxy rows on the card, at the link and at confirm', async t => {
  const s = await setup(t);
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef, held = s.repo().get('connections', ref), identity = held.scopes.filter(scope => !scope.includes('gmail'));
  s.repo().put('connections', {...held, status: 'reconnect_required', scopes: identity, grantCeiling: identity});
  const link = await s.open({purpose: 'reconnect', accountRef: ref}), card = link.view().upgrade;
  const labels = card.rows.find(row => row.groupId === 'gmail.labels.read');
  assert.deepEqual([labels?.typed, labels?.proxy], [false, true], 'a proxied read the sign-in turns on at Allow');
  assert.throws(() => link.start(), {code: 'confirm_required'});
  const signed = await link.signIn({confirmRows: card.etag});
  assert.ok(signed.view().upgrade.rows.some(row => row.groupId === 'gmail.labels.read' && row.proxy === true), 'the confirm card reads it too');
});

test('a narrower renewal keeps the authorization; its rows need more access and it says so once', async t => {
  // F10.7: on version 2 a renewal is narrower when the person unticks an optional box, which the not-granted notice explains, or
  // when a scope it held is not granted again (Google returned gmail.labels unasked at the first sign-in): that one says it narrowed.
  const s = await setup(t), SETTINGS = `${G}gmail.settings.basic`, LABELS = `${G}gmail.labels`;
  const ref = (await s.signIn({}, {level: 'full', extra: [LABELS]})).confirm().result.accountRef, before = s.repo().get('connections', ref);
  assert.ok(before.scopes.includes(LABELS));
  assert.equal((await s.rowOf(ref, 'gmail.settings.write')).access, 'granted');
  const narrow = await s.signIn({}, {level: 'full', omit: [SETTINGS]});
  assert.equal('upgrade' in narrow.view(), false);
  assert.equal(narrow.confirm().result.renewal, true);
  const after = s.repo().get('connections', ref);
  assert.deepEqual([after.authRevision, after.grantCeiling], [before.authRevision, before.grantCeiling]);
  assert.equal(after.scopes.includes(SETTINGS), false);
  const row = await s.rowOf(ref, 'gmail.settings.write');
  assert.equal(row.access, 'missing', 'Needs more access');
  assert.equal('upgrade' in row || 'addAccess' in row, false, 'the card and the Add body are never relayed');
  const page = (await s.call('GET', `/v1/users/u1/apps/gmail?account=${ref}`)).body;
  assert.deepEqual(page.notices.map(notice => notice.kind).sort(), ['grant_narrowed', 'not_granted']);
  assert.deepEqual(s.activity('connection.health').filter(event => event.kind === 'grant_narrowed').map(event => event.subjectKey), [scopesSubject([LABELS])], 'only the lost scope it did not decline');
  // Add access for settings asks for the scope back, within the ceiling: a renewal, with no card to confirm.
  const settings = await (await s.open({purpose: 'add_access', accountRef: ref, groupId: 'gmail.settings.write'})).signIn();
  assert.equal('upgrade' in settings.view(), false);
  assert.equal(settings.confirm().result.renewal, true);
  const back = s.repo().get('connections', ref);
  assert.ok(back.scopes.includes(SETTINGS));
  assert.deepEqual([back.authRevision, back.grantCeiling], [before.authRevision, before.grantCeiling]);
});

test('reconnect and add_access sessions: their powers, their fields, and the same not_found for anything not the person\'s', async t => {
  const s = await setup(t);
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef;
  const create = (body, key) => s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', ...body}, key);
  const reconnect = await create({purpose: 'reconnect', accountRef: ref});
  assert.equal(reconnect.status, 201, JSON.stringify(reconnect.body));
  assert.deepEqual((await s.call('GET', `/v1/connect-sessions/${reconnect.body.id}`)).body.purpose, 'reconnect');
  assert.equal((await create({purpose: 'reconnect', accountRef: ref}, s.keys.connectOnly)).status, 201, 'reconnect is connect:write\'s power');
  assert.equal((await create({purpose: 'add_access', accountRef: ref, groupId: 'gmail.drafts.write'})).status, 201);
  const forbidden = await create({purpose: 'add_access', accountRef: ref, groupId: 'gmail.drafts.write'}, s.keys.connectOnly);
  assert.deepEqual([forbidden.status, forbidden.body.error.code], [403, 'forbidden_scope'], 'adding access is a decision power (connect:manage)');
  const counts = () => ({users: s.repo().list('endUsers').length, sessions: s.repo().list('connectSessions').length, routes: s.app.registry.list('sessionRoutes').length});
  // u2 holds an account too; theirs, an unknown one, a malformed one and an unknown person all read the same.
  const theirs = (await s.signIn({externalUserId: 'u2'}, {level: 'read', identity: OTHER})).confirm().result.accountRef;
  const before = counts(), answers = [];
  for (const body of [{accountRef: theirs}, {accountRef: '00000000-0000-4000-8000-000000000000'}, {accountRef: 'not-an-account'}, {accountRef: 7}, {externalUserId: 'nobody', accountRef: ref}]) {
    for (const purpose of ['reconnect', 'add_access']) {
      const answer = await create({purpose, ...(purpose === 'add_access' ? {groupId: 'gmail.drafts.write'} : {}), ...body});
      assert.equal(answer.status, 404, JSON.stringify(body)); answers.push(answer.body.error);
    }
  }
  for (const answer of answers) assert.deepEqual({...answer, requestId: null}, {...answers[0], requestId: null});
  assert.deepEqual(counts(), before, 'nothing is written, and no person is created');
  const refused = async (body, status, code) => { const answer = await create(body); assert.deepEqual([answer.status, answer.body.error?.code], [status, code], JSON.stringify(body)); };
  await refused({purpose: 'reconnect'}, 400, 'invalid_request');
  await refused({purpose: 'add_access', accountRef: ref}, 400, 'invalid_request');
  await refused({purpose: 'reconnect', accountRef: ref, groupId: 'gmail.drafts.write'}, 400, 'invalid_request');
  await refused({purpose: 'add_access', accountRef: ref, groupId: 'gmail.drafts.write', level: 'read'}, 400, 'invalid_request');
  await refused({appId: 'gmail', accountRef: ref}, 400, 'invalid_request');
  await refused({purpose: 'reconnect', accountRef: ref, appId: 'google-calendar'}, 400, 'invalid_request');
  await refused({purpose: 'reconnect', accountRef: ref, level: 'everything'}, 400, 'invalid_request');
  // Upgrades never skip Fabric's page, where the card is.
  await refused({purpose: 'add_access', accountRef: ref, groupId: 'gmail.drafts.write', presentation: 'direct'}, 409, 'direct_not_allowed');
  // The developer cannot relay the person's confirmation of the card.
  await refused({purpose: 'add_access', accountRef: ref, groupId: 'gmail.drafts.write', confirmRows: 'f'.repeat(64)}, 400, 'invalid_request');
  await refused({appId: 'gmail', confirmRows: 'f'.repeat(64)}, 400, 'invalid_request');
  // Rows: unknown, locked by Fabric (T4), or already held.
  await refused({purpose: 'add_access', accountRef: ref, groupId: 'gmail.nothing'}, 404, 'not_found');
  await refused({purpose: 'add_access', accountRef: ref, groupId: 'gmail.access.grant'}, 409, 'row_locked');
  await refused({purpose: 'add_access', accountRef: ref, groupId: 'gmail.messages.read'}, 409, 'access_held');
});

test('add access asks only for what its unlocked row needs, shows the card first, and the start needs the card', async t => {
  const s = await setup(t);
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef;
  // The settings row adds gmail.settings.basic. Members that need gmail.settings.sharing sit in the row Fabric locks, so no
  // authorization URL ever carries it (T1, T4).
  const settings = await s.open({purpose: 'add_access', accountRef: ref, groupId: 'gmail.settings.write'});
  assert.equal('upgrade' in settings.view(), false, 'the settings row defaults to Ask, so nothing turns on at Allow');
  const started = new URL(settings.start().authorizationUrl).searchParams.get('scope').split(' ');
  assert.ok(started.includes(`${G}gmail.settings.basic`) && started.includes(READ), started.join(' '));
  assert.equal(started.some(scope => scope.includes('settings.sharing')), false);
  // Drafts turns on at its default Allow: the page shows the card before sign-in, and the start needs its etag.
  const drafts = await s.open({purpose: 'add_access', accountRef: ref, groupId: 'gmail.drafts.write'});
  const card = drafts.view().upgrade;
  assert.deepEqual(card.rows.map(row => row.groupId), ['gmail.drafts.write']);
  for (const confirmRows of [undefined, 'f'.repeat(64)]) assert.throws(() => drafts.start(undefined, confirmRows), error => error.code === 'confirm_required' && error.status === 409 && error.details.upgrade.etag === card.etag);
  assert.equal(s.repo().get('connectSessions', drafts.id).state, 'opened', 'nothing started');
  const signed = await drafts.signIn({confirmRows: card.etag});
  assert.deepEqual(signed.url.searchParams.get('scope').split(' ').filter(scope => scope.startsWith(`${G}gmail.`)).sort(), [ADDED, READ]);
  // At confirm the card is computed again from what Google granted; the person confirms that one.
  const final = signed.view().upgrade;
  assert.throws(() => signed.confirm({}), {code: 'confirm_required'});
  assert.deepEqual(signed.confirm({confirmRows: final.etag}).result, {accountRef: ref, appId: 'gmail', renewal: false});
  assert.ok(s.repo().get('connections', ref).scopes.includes(ADDED));
  // Correction 5: the Add body never names a scope only a locked member needs.
  const service = appService(s.app.stores.open(s.scope), s.app.runtimes.bundle(s.scope).runtime, () => s.app.runtimes.bundle(s.scope).adapters.get('google')).forUser({subjectId: 'u1', userRecordId: s.repo().get('connections', ref).userRecordId});
  const app = service.app('gmail'), connection = s.repo().get('connections', ref);
  assert.deepEqual(service.addAccess(app, connection, [{decision: {providerAccess: 'missing', locked: true, scopeSets: [[`${G}gmail.settings.sharing`]]}}]), {});
});

test('a reconnect that signs in another account is dropped as identity_mismatch; one whose account went away merges nowhere', async t => {
  const s = await setup(t);
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef, before = s.repo().get('connections', ref);
  const link = await s.open({purpose: 'reconnect', accountRef: ref});
  const other = await link.signIn({identity: OTHER});
  assert.equal(other.failed, 'identity_mismatch');
  const session = (await s.call('GET', `/v1/connect-sessions/${link.id}`)).body;
  assert.deepEqual([session.state, session.result.errorCode], ['failed', 'identity_mismatch']);
  assert.equal(s.repo().list('connections').some(item => item.identity?.id === OTHER.id), false, 'the other account\'s sign-in is dropped');
  assert.deepEqual(s.repo().get('connections', ref), before, 'the account is untouched');
  assert.equal(s.revokes(), 0, 'dropped here only: Fabric\'s shared Google app never revokes the grant (N9)');
  // The account is disconnected while the person is at Google: the sign-in has nothing to renew.
  const late = await s.open({purpose: 'reconnect', accountRef: ref});
  const started = late.start(), url = new URL(started.authorizationUrl);
  assert.equal((await s.call('POST', `/v1/users/u1/accounts/${ref}/disconnect`, {})).status, 200);
  s.sim.next = ME; s.sim.scope = url.searchParams.get('scope');
  const back = await s.app.sessions.callback('google', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
  assert.equal(back.failed, 'account_changed');
  assert.equal(s.repo().list('connections').filter(item => item.status !== 'revoked').length, 0, 'no account comes back');
  // Grant-wide revokes stay local on Fabric's shared apps.
  const fresh = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef;
  const remote = await s.call('POST', `/v1/users/u1/accounts/${fresh}/disconnect`, {remote: true});
  assert.deepEqual([remote.status, remote.body.error.code], [422, 'remote_unavailable']);
  assert.equal(s.revokes(), 0);
});

test('a reconnect started before the account was disconnected cannot merge at confirm', async t => {
  const s = await setup(t);
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef;
  const link = await s.open({purpose: 'reconnect', accountRef: ref}), waiting = await link.signIn();
  assert.equal(waiting.failed, undefined);
  assert.equal((await s.call('POST', `/v1/users/u1/accounts/${ref}/disconnect`, {})).status, 200);
  assert.throws(() => waiting.confirm(), {code: 'account_changed'});
  assert.equal((await s.call('GET', `/v1/connect-sessions/${link.id}`)).body.result.errorCode, 'account_changed');
  assert.equal(s.repo().list('connections').filter(item => item.status !== 'revoked').length, 0, 'the waiting sign-in is erased, never a new account');
});

test('a reconnect signs in through the account\'s own sign-in app after the environment chose another (D8)', async t => {
  const s = await setup(t);
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef;
  const own = (await s.call('POST', '/v1/provider-apps', {providerId: 'google', clientId: 'dev-google-client', clientSecret: 'dev-google-secret', consentScreenName: 'Acme Agent', consentDays: 7})).body.providerApp.id;
  assert.equal((await s.call('PUT', '/v1/environment/apps/gmail', {providerApp: own, enabled: true})).status, 200);
  // A new account now signs in through the developer's app.
  const fresh = (await s.open({appId: 'gmail'})).start();
  assert.equal(new URL(fresh.authorizationUrl).searchParams.get('client_id'), 'dev-google-client');
  // The existing account stays on Fabric's shared app: its reconnect and its Add access go there.
  for (const body of [{purpose: 'reconnect', accountRef: ref}, {purpose: 'add_access', accountRef: ref, groupId: 'gmail.settings.write'}]) {
    const started = (await s.open(body)).start();
    assert.equal(new URL(started.authorizationUrl).searchParams.get('client_id'), 'g-client', body.purpose);
    assert.equal(started.callbackPath, '/api/oauth/google/callback');
  }
  const link = await s.open({purpose: 'reconnect', accountRef: ref});
  assert.equal(link.view().sheet.providerApp.kind, 'shared', 'the sheet names the sign-in app the person will see');
  assert.equal((await link.signIn()).confirm().result.accountRef, ref);
  assert.deepEqual(s.repo().get('connections', ref).providerApp, {kind: 'shared'});
  // The other way round: an account of the developer's app keeps signing in there after the environment goes back to shared.
  const theirs = (await s.signIn({externalUserId: 'u2'}, {level: 'read', identity: OTHER})).confirm().result.accountRef;
  assert.deepEqual(s.repo().get('connections', theirs).providerApp, {kind: 'developer', id: own});
  // On the developer's own app a reconnect may skip the sheet (H9); Add access never does, so the card is always seen (T7).
  const direct = body => s.call('POST', '/v1/connect-sessions', {externalUserId: 'u2', presentation: 'direct', ...body});
  assert.equal((await direct({purpose: 'reconnect', accountRef: theirs})).status, 201);
  const refused = await direct({purpose: 'add_access', accountRef: theirs, groupId: 'gmail.drafts.write'});
  assert.deepEqual([refused.status, refused.body.error.code], [409, 'direct_not_allowed']);
  assert.equal((await s.call('PUT', '/v1/environment/apps/gmail', {providerApp: 'shared'})).status, 200);
  const again = (await s.open({externalUserId: 'u2', purpose: 'reconnect', accountRef: theirs})).start();
  assert.equal(new URL(again.authorizationUrl).searchParams.get('client_id'), 'dev-google-client');
  assert.equal(again.callbackPath, `/api/oauth/google/apps/${own}/callback`);
});

test('Fabric\'s Connect page: the card before start, and confirmRows through the page routes; details come back on a 409', async t => {
  const s = await setup(t);
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef;
  const created = (await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'add_access', accountRef: ref, groupId: 'gmail.drafts.write'})).body;
  const jar = new Map();
  let csrf = null;
  const page = async (method, route, body) => {
    const cookie = [...jar].filter(([, value]) => value).map(([name, value]) => `${name}=${value}`).join('; ');
    const response = await fetch(`${s.app.origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(cookie ? {Cookie: cookie} : {}), ...(body !== undefined ? {'Content-Type': 'application/json', Origin: s.app.origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    for (const line of response.headers.getSetCookie()) { const [pair] = line.split(';'), at = pair.indexOf('='); jar.set(pair.slice(0, at), pair.slice(at + 1)); }
    const parsed = (response.headers.get('content-type') || '').includes('json') ? await response.json() : await response.text();
    if (typeof parsed?.csrf === 'string') csrf = parsed.csrf;
    return {status: response.status, body: parsed, location: response.headers.get('location')};
  };
  const base = `/connect/${created.id}`;
  assert.equal((await page('POST', `${base}/v1/claim`, {secret: secretOf(created.connectUrl)})).status, 200);
  const view = (await page('GET', `${base}/v1/view`)).body;
  assert.deepEqual(view.upgrade.rows.map(row => row.groupId), ['gmail.drafts.write']);
  assert.ok(view.sheet, 'the sheet and its card');
  const refused = await page('POST', `${base}/v1/start`, {});
  assert.equal(refused.status, 409);
  assert.deepEqual([refused.body.error.code, refused.body.error.details], ['confirm_required', {upgrade: view.upgrade}]);
  assert.match(refused.body.error.message, /without asking/);
  const started = await page('POST', `${base}/v1/start`, {confirmRows: view.upgrade.etag});
  assert.equal(started.status, 200, JSON.stringify(started.body));
  const url = new URL(started.body.authorizationUrl);
  s.sim.next = ME; s.sim.scope = url.searchParams.get('scope');
  const back = await page('GET', `/api/oauth/google/callback?state=${encodeURIComponent(url.searchParams.get('state'))}&code=abc`);
  assert.equal(back.location, `${base}/finish`);
  const waiting = (await page('GET', `${base}/v1/view`)).body;
  assert.equal(waiting.state, 'awaiting_confirmation');
  const unconfirmed = await page('POST', `${base}/v1/confirm`, {});
  assert.deepEqual([unconfirmed.status, unconfirmed.body.error.code, unconfirmed.body.error.details.upgrade.etag], [409, 'confirm_required', waiting.upgrade.etag]);
  const confirmed = await page('POST', `${base}/v1/confirm`, {confirmRows: waiting.upgrade.etag});
  assert.equal(confirmed.status, 200, JSON.stringify(confirmed.body));
  assert.equal(confirmed.body.state, 'connected');
  // The page's own script keeps the details and sends the card's etag.
  const script = readFileSync(new URL('../public/connect.js', import.meta.url), 'utf8');
  assert.match(script, /details: data\?\.error\?\.details/);
  assert.match(script, /confirmRows: upgrade\.etag/);
});

test('an upgrade takes the app\'s current origins, so the next sign-in within the ceiling is a renewal again', async t => {
  const s = await setup(t);
  // An account from an older catalog, whose app has since changed its origins: signing it in again is an upgrade, once.
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef, origins = s.repo().get('connections', ref).allowedOrigins;
  s.repo().put('connections', {...s.repo().get('connections', ref), allowedOrigins: ['https://old.example']});
  const first = await s.signIn({}, {level: 'read'});
  assert.equal(first.confirm({confirmRows: first.view().upgrade.etag}).result.renewal, false);
  const upgraded = s.repo().get('connections', ref);
  assert.deepEqual(upgraded.allowedOrigins, origins, 'the upgrade writes the origins the person just approved');
  const again = await s.signIn({}, {level: 'read'});
  assert.equal('upgrade' in again.view(), false, 'nothing to confirm the next time');
  assert.equal(again.confirm().result.renewal, true);
  assert.equal(s.repo().get('connections', ref).authRevision, upgraded.authRevision);
});

test('a reconnect or Add access sheet offers only the level its link signs in at, so Fabric\'s page can always start it', async t => {
  const s = await setup(t);
  // What Fabric's page sends: the checked level when the sheet offers a choice, else none, and the card it showed.
  const pageStart = link => { const view = link.view(), levels = view.sheet.levels; return link.start(levels.length > 1 ? levels.find(item => item.isDefault).level : undefined, view.upgrade?.etag); };
  const ref = (await s.signIn({}, {level: 'read'})).confirm().result.accountRef;
  for (const [body, level] of [[{purpose: 'reconnect', accountRef: ref}, 'read'], [{purpose: 'reconnect', accountRef: ref, level: 'read_write'}, 'full'], [{purpose: 'add_access', accountRef: ref, groupId: 'gmail.settings.write'}, 'read']]) {
    const link = await s.open(body);
    assert.deepEqual(link.view().sheet.levels.map(item => [item.level, item.isDefault]), [[level, true]], JSON.stringify(body));
    assert.ok(pageStart(link).authorizationUrl, JSON.stringify(body));
  }
  // An account that holds no level the sheet offers (its grant was cut back to the sign-in itself): the sheet names the level
  // the sign-in asks for, full since F10.7 (g3), and the page starts it.
  const held = s.repo().get('connections', ref), identity = held.scopes.filter(scope => !scope.includes('gmail'));
  s.repo().put('connections', {...held, scopes: identity, grantCeiling: identity});
  const custom = await s.open({purpose: 'reconnect', accountRef: ref});
  assert.deepEqual(custom.view().sheet.levels.map(item => item.level), ['full']);
  assert.match(new URL(pageStart(custom).authorizationUrl).searchParams.get('scope'), /gmail\.modify/);
  // A level the link does not sign in at is still refused.
  assert.throws(() => (custom.start('read')), {code: 'invalid_request'});
});

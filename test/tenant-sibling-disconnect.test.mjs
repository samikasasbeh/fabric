import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {raise} from '../lib/connection-notices.mjs';

// F10.4 part g (N9, F03 line 392; build map corrections 3 and 12): in a developer environment Google's revocation removes the
// whole grant of an account on one sign-in client. Fabric's shared Google app never asks Google to revoke. A developer's own
// Google app does, but only on an explicit remote: true, only when no other person here holds the same Google account on
// that client, and only after the developer confirms the same person's other accounts it signs out too. Every automatic
// path (a dropped sign-in, a closed link, a deleted person) and every plain disconnect stays here only, and Fabric's manage
// page never asks for a remote revoke. A simulated Google; nothing leaves the process.
const ME = {id: 'g-7', email: 'seven@example.com', name: 'Seven'}, OTHER = {id: 'g-8', email: 'eight@example.com', name: 'Eight'};
const secretOf = url => new URL(url).hash.slice(3);

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-tenant-siblings-'));
  const sim = {tokens: new Map(), issued: 0, calls: [], next: ME, scope: null};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://oauth2.googleapis.com/token') { const token = `ya29.sib-${++sim.issued}`; sim.tokens.set(token, sim.next); return {status: 200, headers: {}, data: {access_token: token, refresh_token: `1//sib-${sim.issued}`, token_type: 'Bearer', expires_in: 3600, scope: sim.scope}}; }
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') { const who = sim.tokens.get(String(req.headers.Authorization).slice(7)); return {status: 200, headers: {}, data: {sub: who.id, email: who.email, name: who.name}}; }
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) return {status: 200, headers: {}, data: {emailAddress: sim.tokens.get(String(req.headers.Authorization).slice(7)).email}};
    if (req.url.startsWith('https://www.googleapis.com/calendar/v3/users/me/calendarList')) return {status: 200, headers: {}, data: {kind: 'calendar#calendarList'}};
    if (req.url.startsWith('https://oauth2.googleapis.com/revoke')) return {status: 200, headers: {}, data: {}};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const call = async (method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: response.status === 204 ? null : await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  /** A link claimed by one browser, signed in at Google as `identity`, waiting on its confirm screen. */
  const signIn = async (externalUserId, appId, identity = ME, extra = {}) => {
    const created = await call('POST', '/v1/connect-sessions', {externalUserId, appId, ...extra});
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const id = created.body.id, binding = `browser-${id}`;
    app.sessions.claim(id, secretOf(created.body.connectUrl), binding);
    const started = app.sessions.start(id, binding), url = new URL(started.authorizationUrl);
    sim.next = identity; sim.scope = url.searchParams.get('scope');
    const back = await app.sessions.callback('google', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId}, started.callbackPath.match(/\/apps\/(pa_[a-z2-7]{26})\//)?.[1] ?? null);
    return {id, binding, ...back};
  };
  const connect = async (externalUserId, appId, identity = ME) => {
    const {id, binding, finish, failed} = await signIn(externalUserId, appId, identity);
    assert.equal(failed, undefined);
    return app.sessions.confirm(id, binding, finish).result.accountRef;
  };
  /** The developer's own Google app, chosen for Gmail and Calendar. */
  const ownApp = async () => {
    const own = (await call('POST', '/v1/provider-apps', {providerId: 'google', clientId: 'dev-google-client', clientSecret: 'dev-google-secret', consentScreenName: 'Acme Agent', consentDays: 7})).body.providerApp.id;
    for (const appId of ['gmail', 'google-calendar']) assert.equal((await call('PUT', `/v1/environment/apps/${appId}`, {providerApp: own, enabled: true})).status, 200);
    return own;
  };
  const useShared = async appId => assert.equal((await call('PUT', `/v1/environment/apps/${appId}`, {providerApp: 'shared'})).status, 200);
  const revokes = () => sim.calls.filter(line => line.includes('oauth2.googleapis.com/revoke')).length;
  const statusOf = ref => repo().get('connections', ref)?.status ?? null;
  const notices = ref => repo().list('activity').filter(event => event.type === 'connection.health' && event.connectionId === ref);
  return {app, sim, scope, call, repo, signIn, connect, ownApp, useShared, revokes, statusOf, notices};
}

test('on a developer Google app, remote: true names only the same person\'s other accounts on that sign-in app, and nothing changes until confirmed', async t => {
  const s = await setup(t);
  const own = await s.ownApp();
  const mail = await s.connect('u1', 'gmail'), calendar = await s.connect('u1', 'google-calendar');
  // Another person with another Google account on the same app, and the same Google account on Fabric's shared app.
  const theirs = await s.connect('u2', 'google-calendar', OTHER);
  await s.useShared('google-calendar');
  const shared = await s.connect('u1', 'google-calendar');
  assert.deepEqual(s.repo().get('connections', shared).providerApp, {kind: 'shared'});
  assert.deepEqual(s.repo().get('connections', mail).providerApp, {kind: 'developer', id: own});
  const before = s.repo().get('connections', calendar);
  for (const route of [`/v1/users/u1/accounts/${mail}/disconnect`, `/v1/accounts/${mail}/disconnect`]) {
    const asked = await s.call('POST', route, {remote: true});
    assert.equal(asked.status, 409, route);
    assert.equal(asked.body.error.code, 'confirm_required');
    assert.deepEqual(asked.body.error.details, {siblings: [{accountRef: calendar, appId: 'google-calendar', displayName: ME.email}]});
    assert.match(asked.body.error.message, /Google Calendar/); assert.match(asked.body.error.message, /which Fabric cannot see from here/);
  }
  assert.equal(s.revokes(), 0, 'Google is not asked before the confirm');
  assert.deepEqual([mail, calendar, theirs, shared].map(s.statusOf), ['ready', 'ready', 'ready', 'ready'], 'nothing changed');
  const done = await s.call('POST', `/v1/users/u1/accounts/${mail}/disconnect`, {remote: true, confirmSiblings: true});
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.equal(done.body.remoteRevoked, true); assert.equal(done.body.account.status, 'revoked');
  assert.deepEqual(done.body.affected, [{accountRef: calendar, appId: 'google-calendar'}]);
  assert.match(done.body.message, /including any that Fabric cannot see from here/);
  assert.equal(s.revokes(), 1);
  const after = s.repo().get('connections', calendar);
  assert.deepEqual([after.status, after.error], ['reconnect_required', 'Disconnected together with Gmail.']);
  assert.deepEqual([after.authRevision, after.signInRevision], [before.authRevision, before.signInRevision], 'health fields only: a sign-in renews it with its settings');
  assert.deepEqual(s.notices(calendar).map(notice => [notice.kind, notice.count, notice.userRecordId]), [['reconnect_required', 1, before.userRecordId]]);
  assert.deepEqual([theirs, shared].map(s.statusOf), ['ready', 'ready'], 'another person and another sign-in app are untouched');
  const row = (await s.call('GET', `/v1/users/u1/accounts/${calendar}`)).body;
  assert.deepEqual([row.status, row.attention], ['reconnect_required', 'Reconnect this account to use it: sign in again. Your settings stay as they are.']);
  const audit = s.repo().list('activity').find(event => event.type === 'tenant.account_disconnected' && event.accountRef === mail);
  assert.equal(audit.remoteRevoked, true);
});

test('another person holding the same Google account on that sign-in app means no remote revoke', async t => {
  const s = await setup(t);
  await s.ownApp();
  const mine = await s.connect('u1', 'gmail'), theirs = await s.connect('u2', 'gmail');
  for (const body of [{remote: true}, {remote: true, confirmSiblings: true}]) {
    const refused = await s.call('POST', `/v1/users/u1/accounts/${mine}/disconnect`, body);
    assert.deepEqual([refused.status, refused.body.error.code], [422, 'remote_unavailable']);
    assert.match(refused.body.error.message, /another person/i);
    assert.equal(refused.body.error.details, undefined, 'the other person is never named');
  }
  assert.equal(s.revokes(), 0);
  assert.deepEqual([mine, theirs].map(s.statusOf), ['ready', 'ready']);
  const local = await s.call('POST', `/v1/accounts/${mine}/disconnect`, {});
  assert.deepEqual([local.status, local.body.remoteRevoked], [200, false]);
  assert.equal(s.revokes(), 0); assert.equal(s.statusOf(theirs), 'ready');
});

test('another person on another sign-in app, or one already disconnected, does not stop the revoke: Google removes one client\'s grant', async t => {
  const s = await setup(t);
  await s.ownApp();
  const mine = await s.connect('u1', 'gmail'), gone = await s.connect('u3', 'gmail');
  assert.equal((await s.call('POST', `/v1/accounts/${gone}/disconnect`, {})).status, 200);
  await s.useShared('google-calendar');
  const elsewhere = await s.connect('u2', 'google-calendar');
  const done = await s.call('POST', `/v1/users/u1/accounts/${mine}/disconnect`, {remote: true});
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.deepEqual([done.body.remoteRevoked, done.body.affected], [true, undefined]);
  assert.equal(s.revokes(), 1);
  assert.deepEqual([mine, elsewhere].map(s.statusOf), ['revoked', 'ready'], 'the same Google account on Fabric\'s shared app is another grant');
});

test('a plain disconnect on a developer Google app stays here; Fabric\'s shared app refuses remote: true', async t => {
  const s = await setup(t);
  await s.ownApp();
  const mail = await s.connect('u1', 'gmail'), calendar = await s.connect('u1', 'google-calendar'), other = await s.connect('u1', 'gmail', OTHER);
  for (const [ref, body] of [[mail, {}], [other, {remote: false}]]) {
    const local = await s.call('POST', `/v1/users/u1/accounts/${ref}/disconnect`, body);
    assert.equal(local.status, 200, JSON.stringify(local.body));
    assert.equal(local.body.remoteRevoked, false); assert.equal(local.body.affected, undefined);
    assert.match(local.body.message, /^Disconnected here\. Fabric did not ask Google to revoke access/);
  }
  assert.equal(s.revokes(), 0);
  assert.equal(s.statusOf(calendar), 'ready', 'the other account of the same grant keeps working');
  await s.useShared('gmail');
  const shared = await s.connect('u1', 'gmail');
  const refused = await s.call('POST', `/v1/users/u1/accounts/${shared}/disconnect`, {remote: true});
  assert.deepEqual([refused.status, refused.body.error.code], [422, 'remote_unavailable']);
  assert.equal(s.revokes(), 0); assert.equal(s.statusOf(shared), 'ready');
});

test('a dropped sign-in, a closed link, a reconnect as someone else and a deleted person send no grant-wide revoke on a developer Google app', async t => {
  const s = await setup(t);
  await s.ownApp();
  // Each person below has no other account of that Google account here, so nothing would stop a revoke but the rule itself.
  const turnedDown = await s.signIn('u3', 'gmail', OTHER);
  assert.equal((await s.app.sessions.reject(turnedDown.id, turnedDown.binding)).state, 'opened');
  const closed = await s.signIn('u4', 'gmail', OTHER);
  assert.equal((await s.app.sessions.close(closed.id, closed.binding)).state, 'cancelled');
  const mail = await s.connect('u1', 'gmail');
  const mismatch = await s.signIn('u1', undefined, OTHER, {purpose: 'reconnect', accountRef: mail});
  assert.equal(mismatch.failed, 'identity_mismatch');
  assert.equal(s.repo().list('connections').filter(item => item.identity?.id === OTHER.id && item.status !== 'revoked').length, 0, 'every dropped sign-in is erased here');
  assert.equal(s.revokes(), 0);
  // Deleting a person disconnects every account here only, with or without other accounts of the same grant.
  const lone = await s.connect('u5', 'gmail', OTHER);
  const calendar = await s.connect('u1', 'google-calendar'), stays = await s.connect('u2', 'gmail');
  for (const ref of [mail, calendar, stays]) raise(s.repo(), {connection: s.repo().get('connections', ref), kind: 'grant_narrowed'});
  // The other activity that names these accounts (their sign-in audits) is the record of what happened.
  const kept = s.repo().list('activity').filter(event => event.type !== 'connection.health' && [lone, mail, calendar].includes(event.connectionId)).map(event => event.id);
  assert.ok(kept.length >= 3, JSON.stringify(kept));
  for (const user of ['u5', 'u1']) {
    const deleted = await s.call('DELETE', `/v1/users/${user}`);
    assert.equal(deleted.status, 200, JSON.stringify(deleted.body));
    assert.ok(deleted.body.accounts.length >= 1 && deleted.body.accounts.every(account => account.remoteRevoked === false), JSON.stringify(deleted.body));
  }
  assert.equal(s.revokes(), 0);
  assert.equal(s.repo().get('connections', lone), null);
  // A deleted person's connection notices name their accounts, so they go with them; another person's stay.
  assert.deepEqual([mail, calendar].map(ref => s.notices(ref).length), [0, 0]);
  assert.equal(s.notices(stays).length, 1);
  assert.deepEqual(kept.filter(id => !s.repo().get('activity', id)), [], 'the rest of the activity stays');
  assert.ok(s.repo().list('activity').some(event => event.type === 'tenant.user_deleted'));
});

test('Fabric\'s manage page never asks for a remote revoke, on a developer Google app too', async t => {
  const s = await setup(t);
  await s.ownApp();
  const mail = await s.connect('u1', 'gmail'), calendar = await s.connect('u1', 'google-calendar');
  const created = (await s.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'manage'})).body, binding = `browser-${created.id}`;
  s.app.sessions.claim(created.id, secretOf(created.connectUrl), binding);
  for (const body of [{remote: true}, {remote: true, confirmSiblings: true}]) {
    await assert.rejects(s.app.hosted.disconnect(created.id, binding, 'gmail', mail, body), error => error.status === 422 && error.code === 'remote_unavailable' && /never asks Google/.test(error.message));
  }
  assert.equal(s.revokes(), 0); assert.equal(s.statusOf(mail), 'ready');
  const done = await s.app.hosted.disconnect(created.id, binding, 'gmail', mail, {});
  assert.equal(done.remoteRevoked, false); assert.match(done.message, /^Disconnected here/);
  assert.equal(s.revokes(), 0); assert.equal(s.statusOf(calendar), 'ready');
});

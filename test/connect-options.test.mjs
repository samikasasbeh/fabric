import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {IDLE_LIMIT_MS} from '../lib/tenant/connect-sessions.mjs';

// F03.6a: link options and how a link ends. Message links name who they are for (H8); a claimed link idles out after
// 15 minutes; a person who declines at the provider or closes Fabric's page sees it on the page, and the developer's
// return address carries Fabric's result with the developer's own parameters untouched (section 6.6).
async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-options-'));
  const request = async req => req.url === 'https://github.com/login/oauth/access_token' ? {status: 200, headers: {}, data: {access_token: 'gho_x', token_type: 'bearer', scope: 'read:user,repo'}}
    : req.url === 'https://api.github.com/user' ? {status: 200, headers: {}, data: {id: 9, login: 'octo', email: 'octo@example.com'}} : (() => { throw new Error(`unexpected ${req.url}`); })();
  let now = Date.UTC(2026, 9, 13, 12);
  const app = await createDeveloperApp({dataRoot: root, port: 0, clock: () => now, request, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}, google: {clientId: 'g', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant', supportEmail: 'help@acme.example'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
  app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
  const key = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  const link = async body => {
    const response = await fetch(`${app.origin}/v1/connect-sessions`, {method: 'POST', headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify({externalUserId: 'u1', ...body})});
    const created = await response.json();
    return {id: created.id, secret: new URL(created.connectUrl).hash.slice(3)};
  };
  const status = async id => (await (await fetch(`${app.origin}/v1/connect-sessions/${id}`, {headers: {Authorization: `Bearer ${key}`}})).json());
  return {app, link, status, advance: ms => { now += ms; }};
}

test('a message link names who it is for on the sheet, never shows an email, and still ends at the confirm screen', async t => {
  const {app, link} = await setup(t);
  const {id, secret} = await link({appId: 'github', delivery: 'message', userHint: 'Sam at Acme', expiresInSeconds: 4 * 3600});
  app.sessions.claim(id, secret, 'browser-message-binding');
  const view = app.sessions.view(id, 'browser-message-binding');
  assert.equal(view.delivery, 'message'); assert.equal(view.sheet.userHint, 'Sam at Acme'); assert.equal(view.developer.supportEmail, 'help@acme.example');
  assert.match(view.sheet.defaultsLine, /^Without asking: .+\. Asks you first: .+\.$/);
  const started = app.sessions.start(id, 'browser-message-binding'), url = new URL(started.authorizationUrl);
  const {finish} = await app.sessions.callback('github', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
  const confirm = app.sessions.view(id, 'browser-message-binding');
  assert.equal(confirm.state, 'awaiting_confirmation', 'the confirm screen, never an automatic finish');
  assert.equal(JSON.stringify(confirm).includes('octo@example.com'), false);
  assert.equal(app.sessions.confirm(id, 'browser-message-binding', finish).state, 'connected');
});

test('the catalog purpose lists apps without any account details; the shared Google sheet says it is in Testing mode', async t => {
  const {app, link} = await setup(t);
  const any = await link({});
  app.sessions.claim(any.id, any.secret, 'browser-catalog-binding');
  const view = app.sessions.view(any.id, 'browser-catalog-binding');
  assert.ok(view.apps.some(item => item.id === 'github')); assert.equal(view.sheet, undefined);
  for (const item of view.apps) { assert.deepEqual(Object.keys(item).sort(), ['iconUrl', 'id', 'name', 'state']); assert.equal(item.state, 'available'); }
  // Choosing an app shows that app's sheet first: sign-in never starts without Fabric's sheet naming the developer (H9).
  const chosen = app.sessions.view(any.id, 'browser-catalog-binding', 'github');
  assert.equal(chosen.sheet.app.id, 'github'); assert.equal(chosen.sheet.action.label, 'Connect GitHub');
  assert.throws(() => app.sessions.view(any.id, 'browser-catalog-binding', 'slack'), {code: 'not_found'}, 'an app this environment does not offer');
  assert.throws(() => app.sessions.view(any.id, 'browser-catalog-binding', 'nope'), {code: 'not_found'});
  const gmail = await link({appId: 'gmail'});
  app.sessions.claim(gmail.id, gmail.secret, 'browser-gmail-binding');
  assert.match(app.sessions.view(gmail.id, 'browser-gmail-binding').sheet.notices[0], /access lasts 7 days/);
});

test('a claimed link idles out after 15 minutes without page activity; activity keeps it open', async t => {
  const {app, link, advance} = await setup(t);
  const {id, secret} = await link({appId: 'github', expiresInSeconds: 3600});
  app.sessions.claim(id, secret, 'browser-idle-binding');
  advance(IDLE_LIMIT_MS - 1000);
  assert.equal(app.sessions.view(id, 'browser-idle-binding').state, 'opened', 'still open; this view counts as activity');
  advance(IDLE_LIMIT_MS - 1000);
  assert.equal(app.sessions.view(id, 'browser-idle-binding').state, 'opened');
  advance(IDLE_LIMIT_MS + 1000);
  assert.equal(app.sessions.view(id, 'browser-idle-binding').state, 'expired');
  assert.throws(() => app.sessions.start(id, 'browser-idle-binding'), {code: 'expired'});
});

test('declining at the provider lands on Fabric\'s page as a failure, and the error address carries Fabric\'s fixed words', async t => {
  const {app, link, status} = await setup(t);
  const {id, secret} = await link({appId: 'github', errorRedirectUri: 'http://localhost:5173/connected?app=github&ok=0'});
  app.sessions.claim(id, secret, 'browser-decline-binding');
  const started = app.sessions.start(id, 'browser-decline-binding'), state = new URL(started.authorizationUrl).searchParams.get('state');
  // A wrong browser's attempt changes nothing.
  await assert.rejects(app.sessions.callback('github', {state, error: 'access_denied', flowId: 'not-the-flow'}), {code: 'invalid_state'});
  assert.equal(app.sessions.view(id, 'browser-decline-binding').state, 'signing_in');
  const page = await fetch(`${app.origin}/api/oauth/github/callback?state=${encodeURIComponent(state)}&error=access_denied`, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${started.flowId}`}});
  assert.equal(page.status, 303); assert.equal(page.headers.get('location'), `/connect/${id}/finish`);
  assert.equal(page.headers.getSetCookie().some(line => line.startsWith('fabric_t_finish=')), false, 'nothing to confirm');
  const view = app.sessions.view(id, 'browser-decline-binding');
  assert.equal(view.state, 'failed'); assert.equal(view.errorCode, 'consent_denied');
  const back = new URL(view.redirect);
  assert.deepEqual(Object.fromEntries(back.searchParams), {app: 'github', ok: '0', fabric_session: id, fabric_state: 'failed', error: 'consent_denied', error_description: 'The person declined access at the provider.'});
  assert.deepEqual((await status(id)).result, {errorCode: 'consent_denied'});
});

test('closing Fabric\'s page cancels the link, once, and the developer hears it', async t => {
  const {app, link, status} = await setup(t);
  const {id, secret} = await link({appId: 'github', errorRedirectUri: 'http://localhost:5173/connected'});
  app.sessions.claim(id, secret, 'browser-close-binding');
  await assert.rejects(app.sessions.close(id, 'another-browser-binding'), {code: 'not_found'});
  const closed = await app.sessions.close(id, 'browser-close-binding');
  assert.equal(closed.state, 'cancelled'); assert.equal(closed.redirect, `http://localhost:5173/connected?fabric_session=${id}&fabric_state=failed&error=cancelled&error_description=The+Connect+link+was+cancelled.`);
  await assert.rejects(app.sessions.close(id, 'browser-close-binding'), {code: 'already_finished'});
  assert.equal((await status(id)).state, 'cancelled');
});

test('the person may choose an offered level; "Not this account" drops the account and lets them sign in again; Done names the account without an email', async t => {
  const {app, link, status} = await setup(t);
  const gmail = await link({appId: 'gmail'});
  app.sessions.claim(gmail.id, gmail.secret, 'browser-level-binding');
  const offered = app.sessions.view(gmail.id, 'browser-level-binding').sheet.levels.map(item => item.level);
  assert.ok(offered.includes('read') && offered.length === 2, `Gmail offers read-only beside its default (${offered})`);
  const read = new URL(app.sessions.start(gmail.id, 'browser-level-binding', undefined, 'read').authorizationUrl).searchParams.get('scope');
  assert.match(read, /gmail\.readonly/); assert.doesNotMatch(read, /gmail\.(modify|compose|send)/, 'read-only asks for reading only');
  assert.throws(() => app.sessions.start(gmail.id, 'browser-level-binding', undefined, 'pages'), {code: 'invalid_request'});
  // GitHub: sign in, turn the account down, sign in again, confirm.
  const {id, secret} = await link({appId: 'github', successRedirectUri: 'http://localhost:5173/done'});
  app.sessions.claim(id, secret, 'browser-reject-binding');
  const run = async () => { const started = app.sessions.start(id, 'browser-reject-binding'), url = new URL(started.authorizationUrl); return app.sessions.callback('github', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId}); };
  const first = await run();
  assert.equal(app.sessions.view(id, 'browser-reject-binding', undefined, first.finish).pendingAccount.displayName, 'octo');
  await assert.rejects(app.sessions.reject(id, 'another-browser-binding'), {code: 'not_found'});
  assert.deepEqual(await app.sessions.reject(id, 'browser-reject-binding'), {state: 'opened'});
  const scope = app.registry.scopeOf(app.registry.list('environments')[0]);
  assert.equal(app.stores.open(scope).repository.list('connections').length, 0, 'the turned-down account is erased');
  assert.throws(() => app.sessions.confirm(id, 'browser-reject-binding', first.finish), {code: 'already_finished'}, 'its finish value is spent');
  const second = await run();
  assert.equal(app.sessions.confirm(id, 'browser-reject-binding', second.finish).state, 'connected');
  const done = app.sessions.view(id, 'browser-reject-binding');
  assert.deepEqual(done.account, {displayName: 'octo', accessLabel: done.account.accessLabel}); assert.match(done.account.accessLabel, /access|Read|Custom|write/i);
  assert.equal(JSON.stringify(done).includes('octo@example.com'), false);
  assert.match(done.redirect, /^http:\/\/localhost:5173\/done\?fabric_session=/);
  assert.equal((await status(id)).state, 'connected');
});

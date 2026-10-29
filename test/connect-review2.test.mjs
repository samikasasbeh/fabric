import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {CONFIRM_LIMIT_MS, IDLE_LIMIT_MS} from '../lib/tenant/connect-sessions.mjs';

// The independent review of F03.6a and F03.6b (Connect-link findings), each shown by a failing test before its fix:
// an account left on a confirm screen that ended is erased under N9; hints must name someone; the page cookie lives
// as long as the link; a developer's cancel reads as a cancel; starting and coming back count as activity.
async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-review2-'));
  const sim = {calls: [], tokens: new Map(), issued: 0};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://github.com/login/oauth/access_token') { const token = `gho_${++sim.issued}`; sim.tokens.set(token, {id: 5, login: 'octo'}); return {status: 200, headers: {}, data: {access_token: token, token_type: 'bearer', scope: 'read:user,repo'}}; }
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: sim.tokens.get(String(req.headers.Authorization).slice(7))};
    if (req.url === 'https://api.github.com/applications/gh-client/token') return {status: 204, headers: {}, data: null};
    throw new Error(`unexpected ${req.url}`);
  };
  let now = Date.UTC(2026, 9, 13, 12);
  const app = await createDeveloperApp({dataRoot: root, port: 0, clock: () => now, request, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
  const key = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  const v1 = async (method, route, body) => { const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})}); return {status: response.status, body: await response.json()}; };
  /** A link claimed by one browser and signed in up to its confirm screen. */
  const toConfirm = async (extra = {}) => {
    const created = (await v1('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github', ...extra})).body, binding = `browser-${created.id}`;
    app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
    const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl);
    const back = await app.sessions.callback('github', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
    return {id: created.id, binding, finish: back.finish};
  };
  const env = () => app.stores.open(scope);
  const left = () => env().repository.list('connections').filter(item => item.status === 'pending_confirmation');
  const revokes = () => sim.calls.filter(line => line.includes('/applications/gh-client/token')).length;
  return {app, sim, v1, toConfirm, env, left, revokes, advance: ms => { now += ms; }};
}

test('closing the page on the confirm screen erases the waiting account and revokes its token (N9)', async t => {
  const {app, toConfirm, env, left, revokes} = await setup(t);
  const {id, binding} = await toConfirm();
  const ref = left()[0].id;
  assert.ok(env().vault.get(ref));
  await app.sessions.close(id, binding);
  assert.deepEqual(left(), []); assert.equal(env().vault.get(ref), null); assert.equal(revokes(), 1);
  assert.equal(app.registry.get('sessionRoutes', id).pendingSince, undefined);
});

test('a developer cancel on the confirm screen erases it too, and reads as a cancel, not as the person closing the page', async t => {
  const {v1, toConfirm, left, revokes} = await setup(t);
  const {id} = await toConfirm({errorRedirectUri: 'http://localhost:5173/back'});
  const cancelled = await v1('POST', `/v1/connect-sessions/${id}/cancel`);
  assert.equal(cancelled.body.state, 'cancelled'); assert.deepEqual(cancelled.body.result, {errorCode: 'cancelled'});
  assert.deepEqual(left(), []); assert.equal(revokes(), 1);
});

test('an account left waiting past the 10-minute confirm limit, or behind an idle page, is erased by the sweep', async t => {
  const {app, toConfirm, left, revokes, advance} = await setup(t);
  const first = await toConfirm();
  advance(CONFIRM_LIMIT_MS - 60_000);
  assert.equal(app.sessions.view(first.id, first.binding, undefined, first.finish).state, 'awaiting_confirmation', 'still in time');
  assert.equal(await app.sessions.sweep(), 0, 'nothing due yet');
  advance(2 * 60_000);
  assert.throws(() => app.sessions.confirm(first.id, first.binding, first.finish), {code: 'expired'});
  assert.equal(await app.sessions.sweep(), 1);
  assert.deepEqual(left(), []); assert.equal(revokes(), 1);
  assert.equal(app.sessions.view(first.id, first.binding).state, 'expired');
  assert.equal(await app.sessions.sweep(), 0, 'once only');
  // Without waiting for the sweep: a look at an idle link that ended with an account waiting starts its erasure.
  const second = await toConfirm();
  advance(IDLE_LIMIT_MS + 60_000);
  assert.equal(app.sessions.view(second.id, second.binding).state, 'expired');
  await app.sessions.settled();
  assert.deepEqual(left(), []); assert.equal(revokes(), 2);
});

test('reading the sheet, then starting and coming back from the provider, all count as activity', async t => {
  const {app, v1, advance} = await setup(t);
  const created = (await v1('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github'})).body, binding = 'browser-activity-binding';
  app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
  advance(IDLE_LIMIT_MS - 60_000);
  const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl);
  // Two minutes at the provider: 16 minutes after the claim, alive only because starting counted as activity.
  advance(2 * 60_000);
  const back = await app.sessions.callback('github', {state: url.searchParams.get('state'), code: 'abc', flowId: started.flowId});
  assert.equal(back.failed, undefined);
  advance(CONFIRM_LIMIT_MS - 60_000);
  assert.equal(app.sessions.confirm(created.id, binding, back.finish).state, 'connected');
});

test('a hint must name someone: blank, invisible, format and control characters are refused; edges are trimmed', async t => {
  const {app, v1} = await setup(t);
  for (const hint of [' ', '\u3000', '\u200b', 'Sam\u202e', 'Sam\u2028Lee', '--', '<b>Sam</b>']) {
    const response = await v1('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github', delivery: 'message', userHint: hint});
    assert.equal(response.status, 400, JSON.stringify(hint));
  }
  const created = (await v1('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github', delivery: 'message', userHint: '  Sam at Acme  '})).body;
  app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), 'browser-hint-binding');
  assert.equal(app.sessions.view(created.id, 'browser-hint-binding').sheet.userHint, 'Sam at Acme');
});

test('the page cookie lives exactly as long as the link: four hours for a message link, two minutes for a short one', async t => {
  const {app, v1} = await setup(t);
  for (const [body, seconds] of [[{delivery: 'message', userHint: 'Sam', expiresInSeconds: 4 * 3600}, 4 * 3600], [{expiresInSeconds: 120}, 120]]) {
    const created = (await v1('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github', ...body})).body;
    const response = await fetch(`${app.origin}/connect/${created.id}/v1/claim`, {method: 'POST', headers: {'Content-Type': 'application/json', Origin: app.origin, 'Sec-Fetch-Site': 'same-origin'}, body: JSON.stringify({secret: new URL(created.connectUrl).hash.slice(3)})});
    assert.match(response.headers.getSetCookie()[0], new RegExp(`Max-Age=${seconds}$`));
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';

// F03.4a: Connect sessions. One link for one end user, a secret only in the fragment, one claim for one browser, and a
// fixed order of checks so a wrong secret never reveals anything else.
const SETTINGS = {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}};

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-sessions-'));
  let now = Date.UTC(2026, 9, 13, 12);
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: SETTINGS, clock: () => now});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const customer = name => {
    const org = app.registry.createOrganization({name}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
    const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
    app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
    return {dev, key: app.keys.mint({environmentId: dev.id, preset: 'full'}).token};
  };
  const call = async (key, method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  return {app, root, customer, call, advance: ms => { now += ms; }};
}
const secretOf = url => new URL(url).hash.slice(3);
const files = dir => { const out = []; const walk = folder => { for (const entry of readdirSync(folder, {withFileTypes: true})) { const full = path.join(folder, entry.name); if (entry.isDirectory()) walk(full); else out.push(full); } }; walk(dir); return out; };

test('a developer gets a short-lived link for one end user; the end user is created once; the secret is never stored', async t => {
  const {app, root, customer, call} = await setup(t);
  const acme = customer('Acme');
  const created = await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'aura-user-1', appId: 'github', successRedirectUri: 'http://localhost:5173/connected?app=x&ok=1'});
  assert.equal(created.status, 201);
  assert.match(created.body.id, /^cs_[a-z2-7]{26}$/);
  assert.match(created.body.connectUrl, new RegExp(`^${app.origin}/connect/${created.body.id}#k=[A-Za-z0-9_-]{43}$`));
  assert.equal(created.body.reach, 'this_machine');
  const secret = secretOf(created.body.connectUrl);
  for (const file of files(root)) assert.equal(readFileSync(file).includes(secret), false, file);
  const again = await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'aura-user-1'});
  const env = app.stores.open(app.registry.scopeOf(acme.dev));
  assert.equal(env.repository.list('endUsers').length, 1, 'the same external id is one end user');
  const viewed = await call(acme.key, 'GET', `/v1/connect-sessions/${created.body.id}`);
  assert.deepEqual({user: viewed.body.externalUserId, state: viewed.body.state, appId: viewed.body.appId}, {user: 'aura-user-1', state: 'created', appId: 'github'});
  assert.equal(JSON.stringify(viewed.body).includes(secret), false);
  assert.equal((await call(acme.key, 'GET', `/v1/connect-sessions/${again.body.id}`)).body.state, 'created');
});

test('requests are validated: user id, app, availability, return addresses, purposes and lifetime', async t => {
  const {customer, call} = await setup(t);
  const acme = customer('Acme');
  const refused = async (body, status, code) => { const response = await call(acme.key, 'POST', '/v1/connect-sessions', body); assert.equal(response.status, status, JSON.stringify(response.body)); assert.equal(response.body.error.code, code); };
  await refused({externalUserId: ''}, 400, 'invalid_external_user_id');
  await refused({externalUserId: 'a b'}, 400, 'invalid_external_user_id');
  await refused({externalUserId: 'u', appId: 'nope'}, 404, 'not_found');
  await refused({externalUserId: 'u', appId: 'slack'}, 422, 'unavailable');
  await refused({externalUserId: 'u', appId: 'notion'}, 422, 'setup_required');
  await refused({externalUserId: 'u', successRedirectUri: 'http://localhost:5174/x'}, 400, 'redirect_not_allowed');
  await refused({externalUserId: 'u', successRedirectUri: 'http://localhost:51730/x'}, 400, 'redirect_not_allowed');
  await refused({externalUserId: 'u', successRedirectUri: 'http://localhost:5173@evil.example/x'}, 400, 'redirect_not_allowed');
  await refused({externalUserId: 'u', successRedirectUri: 'http://localhost:5173/x?fabric_session=1'}, 400, 'redirect_not_allowed');
  await refused({externalUserId: 'u', errorRedirectUri: 'http://localhost:5173/x?error=forged'}, 400, 'redirect_not_allowed');
  // F10.4: reconnect and add_access name the person's account (and add_access its row), and never create a person.
  await refused({externalUserId: 'u', purpose: 'reconnect'}, 400, 'invalid_request');
  await refused({externalUserId: 'u', purpose: 'add_access', accountRef: '00000000-0000-4000-8000-000000000000'}, 400, 'invalid_request');
  await refused({externalUserId: 'u', purpose: 'reconnect', accountRef: '00000000-0000-4000-8000-000000000000'}, 404, 'not_found');
  await refused({externalUserId: 'u', purpose: 'add_access', accountRef: '00000000-0000-4000-8000-000000000000', groupId: 'github.repos.read'}, 404, 'not_found');
  await refused({externalUserId: 'u', purpose: 'manage'}, 404, 'not_found'); // F03.10: a manage link never creates a user
  await refused({externalUserId: 'u', purpose: 'handoff'}, 422, 'not_available');
  await refused({externalUserId: 'u', purpose: 'sideways'}, 400, 'invalid_request');
  await refused({externalUserId: 'u', delivery: 'message'}, 400, 'invalid_request');
  await refused({externalUserId: 'u', delivery: 'message', userHint: '<b>x</b>'}, 400, 'invalid_request');
  await refused({externalUserId: 'u', delivery: 'message', userHint: 'Sam', expiresInSeconds: 4 * 3600 + 1}, 400, 'invalid_request');
  await refused({externalUserId: 'u', expiresInSeconds: 3601}, 400, 'invalid_request');
  await refused({externalUserId: 'u', appId: 'github', presentation: 'direct'}, 409, 'direct_not_allowed');
  await refused({externalUserId: 'u', appId: 'github', consentEtag: 'x'}, 400, 'invalid_request');
  assert.equal((await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'u', appId: 'github', delivery: 'message', userHint: 'Sam at Acme', expiresInSeconds: 4 * 3600})).status, 201, 'a message link may last 4 hours');
  await refused({externalUserId: 'u', expiresInSeconds: 59}, 400, 'invalid_request');
  await refused({externalUserId: 'u', presentation: 'direct'}, 400, 'invalid_request');
  await call(acme.key, 'PUT', '/v1/environment/apps/github', {enabled: false});
  await refused({externalUserId: 'u', appId: 'github'}, 422, 'app_disabled');
});

test('claiming the link: a wrong secret is not_found before anything else; one browser only; expired links never open', async t => {
  const {app, customer, call, advance} = await setup(t);
  const acme = customer('Acme');
  const created = (await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'aura-user-1', appId: 'github', expiresInSeconds: 120})).body;
  const secret = secretOf(created.connectUrl);
  assert.throws(() => app.sessions.claim(created.id, 'x'.repeat(43), 'browser-one-binding'), {code: 'not_found'});
  assert.throws(() => app.sessions.claim('cs_' + 'a'.repeat(26), secret, 'browser-one-binding'), {code: 'not_found'});
  const first = app.sessions.claim(created.id, secret, 'browser-one-binding');
  assert.equal(first.session.state, 'opened'); assert.equal(first.owner.subjectId, 'aura-user-1');
  assert.equal(app.sessions.claim(created.id, secret, 'browser-one-binding').session.claimedAt, first.session.claimedAt, 'the same browser may reopen it');
  assert.throws(() => app.sessions.claim(created.id, secret, 'browser-two-binding'), {code: 'session_in_use'});
  assert.equal((await call(acme.key, 'POST', `/v1/connect-sessions/${created.id}/link`)).body.error.code, 'session_in_use', 'a claimed link cannot be re-issued');
  // An unclaimed session: a new link voids the old secret; expiry is checked after the secret.
  const second = (await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'aura-user-2', expiresInSeconds: 60})).body;
  const relinked = (await call(acme.key, 'POST', `/v1/connect-sessions/${second.id}/link`)).body;
  assert.throws(() => app.sessions.claim(second.id, secretOf(second.connectUrl), 'browser-one-binding'), {code: 'not_found'}, 'the old secret is void');
  advance(61_000);
  assert.throws(() => app.sessions.claim(second.id, 'x'.repeat(43), 'browser-one-binding'), {code: 'not_found'}, 'wrong secret: not_found even when expired');
  assert.throws(() => app.sessions.claim(second.id, secretOf(relinked.connectUrl), 'browser-one-binding'), {code: 'expired'});
  assert.equal((await call(acme.key, 'GET', `/v1/connect-sessions/${second.id}`)).body.state, 'expired');
});

test('cancel finishes a session once; another developer\'s key never sees, cancels or relinks it', async t => {
  const {customer, call} = await setup(t);
  const acme = customer('Acme'), beta = customer('Beta');
  const created = (await call(acme.key, 'POST', '/v1/connect-sessions', {externalUserId: 'aura-user-1'})).body;
  for (const [method, route] of [['GET', `/v1/connect-sessions/${created.id}`], ['POST', `/v1/connect-sessions/${created.id}/cancel`], ['POST', `/v1/connect-sessions/${created.id}/link`]]) {
    const response = await call(beta.key, method, route);
    assert.equal(response.status, 404, route); assert.equal(response.body.error.code, 'not_found');
  }
  assert.equal((await call(acme.key, 'POST', `/v1/connect-sessions/${created.id}/cancel`)).body.state, 'cancelled');
  assert.equal((await call(acme.key, 'POST', `/v1/connect-sessions/${created.id}/cancel`)).body.error.code, 'already_finished');
  assert.equal((await call(acme.key, 'GET', '/v1/connect-sessions/not-an-id')).status, 404);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { createApp } from '../server.mjs';
import { GitHubSimulator } from './fixtures/oauth-simulators.mjs';

// HTTP-level proof of the provider-neutral OAuth routes against a simulated GitHub.
// Isolated temporary store and loopback port; no private state, network or .env.
const ENV = { FABRIC_GITHUB_CLIENT_ID: 'route-fixture-client', FABRIC_GITHUB_CLIENT_SECRET: 'route-fixture-secret', FABRIC_SLACK_CLIENT_ID: 'route-slack-client', FABRIC_SLACK_CLIENT_SECRET: 'route-slack-secret' };
async function freePort() { const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const { port } = server.address(); await new Promise(resolve => server.close(resolve)); return port; }

async function fixture(t) {
  const previous = Object.fromEntries(Object.keys(ENV).map(key => [key, process.env[key]]));
  Object.assign(process.env, ENV);
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-oauth-routes-')), port = await freePort();
  const sim = new GitHubSimulator({ clientId: ENV.FABRIC_GITHUB_CLIENT_ID, clientSecret: ENV.FABRIC_GITHUB_CLIENT_SECRET, clock: Date.now });
  const request = async req => {
    if (/^https:\/\/(github\.com|api\.github\.com)\//.test(req.url)) return sim.request(req);
    throw new Error('No network in this fixture');
  };
  const app = await createApp({ dataDir: dir, port, request });
  await app.start();
  t.after(async () => {
    await app.close(); await rm(dir, { recursive: true, force: true });
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  });
  const first = await fetch(`${app.origin}/api/state`), state = await first.json(), session = first.headers.get('set-cookie').split(';')[0];
  const call = (method, route, data, cookie = '') => fetch(`${app.origin}${route}`, { method, redirect: 'manual', headers: { 'content-type': 'application/json', 'x-fabric-csrf': state.csrfToken, cookie: [session, cookie].filter(Boolean).join('; ') }, ...(data ? { body: JSON.stringify(data) } : {}) });
  return { app, sim, state, call };
}
const flowCookie = response => /fabric_oauth=([^;]+); HttpOnly; SameSite=Lax; Path=(\/api\/oauth\/[a-z-]+\/callback); Max-Age=600/.exec(response.headers.get('set-cookie'));

test('settings and catalog describe every reviewed provider truthfully without exposing secrets', async t => {
  const { state } = await fixture(t);
  assert.deepEqual(Object.keys(state.settings.oauthProviders).sort(), ['github', 'google', 'notion', 'slack']);
  assert.equal(state.settings.oauthProviders.github.configured, true);
  assert.equal(state.settings.oauthProviders.github.redirectUri.endsWith('/api/oauth/github/callback'), true);
  assert.equal(state.settings.oauthProviders.github.available, true);
  assert.equal(state.settings.oauthProviders.github.authorizationOrigin, 'https://github.com');
  assert.equal(state.settings.oauthProviders.slack.configured, true); assert.equal(state.settings.oauthProviders.slack.available, false);
  assert.match(state.settings.oauthProviders.slack.reason, /HTTPS callback/);
  assert.equal(state.settings.oauthProviders.notion.configured, Boolean(process.env.FABRIC_NOTION_CLIENT_ID && process.env.FABRIC_NOTION_CLIENT_SECRET));
  const slack = state.catalog.find(app => app.id === 'slack').connectionOptions.find(option => option.method === 'oauth');
  assert.equal(slack.enabled, false); assert.equal(slack.availability, 'unavailable'); assert.match(slack.setupReason, /HTTPS callback/);
  const github = state.catalog.find(app => app.id === 'github').connectionOptions.find(option => option.method === 'oauth');
  assert.equal(github.label, 'Sign in with GitHub'); assert.equal(github.enabled, true); assert.equal(github.recommended, true);
  assert.deepEqual(github.action, { method: 'POST', path: '/api/oauth/github/start', body: { appId: 'github' } });
  for (const secret of [ENV.FABRIC_GITHUB_CLIENT_SECRET, ENV.FABRIC_SLACK_CLIENT_SECRET]) assert.equal(JSON.stringify(state).includes(secret), false);
});

test('generic start and callback routes connect a GitHub account with a provider-scoped browser cookie', async t => {
  const { sim, call } = await fixture(t);
  const started = await call('POST', '/api/oauth/github/start', { appId: 'github' }), body = await started.json(), cookie = flowCookie(started);
  assert.equal(started.status, 200); assert.ok(cookie); assert.equal(cookie[2], '/api/oauth/github/callback');
  assert.equal(new URL(body.authorizationUrl).origin, 'https://github.com');
  const consent = sim.consent(body.authorizationUrl);
  const callback = await call('GET', `/api/oauth/github/callback?state=${encodeURIComponent(consent.state)}&code=${encodeURIComponent(consent.code)}`, null, `fabric_oauth=${cookie[1]}`);
  assert.equal(callback.status, 303); assert.equal(callback.headers.get('location'), '/?oauth=connected');
  assert.match(callback.headers.get('set-cookie'), /Path=\/api\/oauth\/github\/callback; Max-Age=0/);
  const connections = (await (await call('GET', '/api/state')).json()).connections.filter(item => item.appId === 'github');
  assert.equal(connections.length, 1); assert.equal(connections[0].status, 'ready'); assert.equal(connections[0].authMethod, 'oauth');
  assert.equal(connections[0].identity.id, '101');
  const revoked = await call('POST', `/api/connections/${connections[0].id}/revoke`, {});
  const result = await revoked.json();
  assert.equal(result.remoteRevoked, true); assert.equal(result.connection.status, 'revoked');
  assert.ok(sim.calls.some(req => req.method === 'DELETE' && req.url === 'https://api.github.com/applications/route-fixture-client/token'));
});

test('a flow can only complete on its own provider route and unknown providers are refused', async t => {
  const { sim, call } = await fixture(t);
  const started = await call('POST', '/api/oauth/github/start', { appId: 'github' }), body = await started.json(), cookie = flowCookie(started);
  const consent = sim.consent(body.authorizationUrl), query = `state=${encodeURIComponent(consent.state)}&code=${encodeURIComponent(consent.code)}`;
  const wrongRoute = await call('GET', `/api/oauth/google/callback?${query}`, null, `fabric_oauth=${cookie[1]}`);
  assert.equal(wrongRoute.status, 303); assert.notEqual(wrongRoute.headers.get('location'), '/?oauth=connected');
  const right = await call('GET', `/api/oauth/github/callback?${query}`, null, `fabric_oauth=${cookie[1]}`);
  assert.equal(right.headers.get('location'), '/?oauth=connected', 'the wrong route did not consume the flow');
  const unknown = await call('POST', '/api/oauth/not-a-provider/start', { appId: 'github' });
  assert.equal(unknown.status, 400); assert.match((await unknown.json()).error, /Unknown sign-in provider/);
  const traversal = await call('POST', '/api/oauth/..%2Fgoogle/start', { appId: 'gmail' });
  assert.equal(traversal.status, 404, 'an encoded traversal never matches the provider pattern and reaches no handler');
  const slack = await call('POST', '/api/oauth/slack/start', { appId: 'slack' });
  assert.equal(slack.status, 400); assert.equal((await slack.json()).code, 'redirect_unsupported');
  assert.equal(flowCookie(slack), null, 'no flow cookie is issued when sign-in cannot start');
  const mismatched = await call('POST', '/api/oauth/github/start', { appId: 'gmail' });
  assert.equal(mismatched.status, 400); assert.match((await mismatched.json()).error, /Unsupported GitHub application/);
});

test('connect/start chooses the reviewed sign-in route for the selected application', async t => {
  const { call } = await fixture(t);
  const response = await call('POST', '/api/connect/start', { appId: 'github', method: 'oauth' }), body = await response.json();
  assert.equal(response.status, 200); assert.equal(body.kind, 'oauth');
  assert.equal(new URL(body.authorizationUrl).origin, 'https://github.com');
  assert.equal(flowCookie(response)[2], '/api/oauth/github/callback');
});

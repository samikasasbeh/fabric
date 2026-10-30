import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {createApp} from '../../server.mjs';
import {compileOpenApi} from '../../lib/compiler.mjs';
import {FABRIC_PROTOCOL} from '../../lib/fabric-protocol.mjs';
import {GitHubSimulator} from './oauth-simulators.mjs';

// F02.3c: signing in to a new account from a handoff. The connection is quarantined until the
// owner confirms its verified identity. Isolated designated app, loopback port, GitHub simulator.
export const owner = {schemaVersion: 1, id: 'fixture-owner', kind: 'local_owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'fixture-owner'}};
export const ENV = {FABRIC_GITHUB_CLIENT_ID: 'signin-fixture-client', FABRIC_GITHUB_CLIENT_SECRET: 'signin-fixture-secret'};
export const doc = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
  '/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}},
  '/repos/{owner}/{repo}/issues': {post: {operationId: 'createIssue', parameters: [{name: 'owner', in: 'path', required: true, schema: {type: 'string'}}, {name: 'repo', in: 'path', required: true, schema: {type: 'string'}}],
    requestBody: {content: {'application/json': {schema: {type: 'object', properties: {title: {type: 'string'}}, required: ['title']}}}}, responses: {201: {description: 'Created'}}}}}};
export async function freePort() { const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const {port} = server.address(); await new Promise(resolve => server.close(resolve)); return port; }

/**
 * An action folder with no files, for a test of synthetic GitHub operations: since step 18 certified GitHub's shipped actions, they place
 * with no map and would join the test's rows (F10.18 listed churn).
 */
export async function noShippedActions(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'fabric-no-actions-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  return {directory};
}

/** `actions` (F10.11 part p) is the owner's server's action catalog seam, as createApp() takes it. */
export async function fixture(t, {actions} = {}) {
  const previous = Object.fromEntries(Object.keys(ENV).map(key => [key, process.env[key]]));
  Object.assign(process.env, ENV);
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-continuation-signin-')), port = await freePort();
  let now = Date.parse('2026-10-11T10:00:00.000Z'), app;
  const clock = () => now, api = [], hooks = {token: null};
  const sim = new GitHubSimulator({clientId: ENV.FABRIC_GITHUB_CLIENT_ID, clientSecret: ENV.FABRIC_GITHUB_CLIENT_SECRET, clock});
  const request = async req => {
    if (req.url === 'https://github.com/login/oauth/access_token' && hooks.token) await hooks.token();
    if (req.url === 'https://api.github.com/user' || req.url.startsWith('https://github.com/') || req.url.includes('/applications/')) return sim.request(req);
    api.push(req); return {status: req.method === 'GET' ? 200 : 201, data: {id: 'synthetic-result'}};
  };
  const open = async mode => { app = await createApp({dataDir: dir, port, clock, request, localAuthority: {mode, ownerPrincipal: owner}, ...(actions ? {actions} : {})}); await app.start(); };
  await open('new');
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  const caps = compileOpenApi({appId: 'github', document: doc}).capabilities;
  const read = {...caps.find(cap => cap.request.method === 'GET'), status: 'active'}, write = {...caps.find(cap => cap.request.method === 'POST'), status: 'active'};
  app.store.put('capabilities', read); app.store.put('capabilities', write);
  app.store.put('applicationMaps', {id: 'github', operations: [{capabilityId: read.id, requiredScopes: []}, {capabilityId: write.id, requiredScopes: ['repo']}]});
  let session;
  const login = async () => { const first = await fetch(`${app.origin}/api/state`), state = await first.json(); session = {cookie: first.headers.get('set-cookie').split(';')[0], csrf: state.csrfToken}; };
  await login();
  const owned = (method, route, data, extraCookie = '') => fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'content-type': 'application/json', 'x-fabric-csrf': session.csrf, cookie: [session.cookie, extraCookie].filter(Boolean).join('; ')}, ...(data !== undefined ? {body: JSON.stringify(data)} : {})});
  const json = async (method, route, data) => { const response = await owned(method, route, data); return {status: response.status, body: await response.json()}; };
  const protocol = (token, method, params, id = `req-${Math.random().toString(36).slice(2, 9)}`) => fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {'content-type': 'application/json', authorization: `Bearer ${token}`}, body: JSON.stringify({protocol: FABRIC_PROTOCOL, id, method, params})}).then(response => response.json());
  const f = {
    sim, api, hooks, read, write, json, owned, protocol,
    get app() { return app; }, get now() { return now; }, advance: ms => { now += ms; },
    async restart() { await app.close(); await open('require'); await login(); },
    async ask(cap = read, args = {}) {
      const grant = (await json('POST', '/api/clients', {name: 'Agent', bindings: [], requestable: [{capabilityId: cap.id}]})).body;
      const view = (await protocol(grant.token, 'calls.create', {appId: 'github', capabilityId: cap.id, definitionHash: grant.client.requestable[0].definitionHash, args})).result;
      return {token: grant.token, id: view.id};
    },
    view: async id => (await json('GET', `/api/continuations/${id}`)).body,
    async signIn(id) {
      const response = await owned('POST', `/api/continuations/${id}/sign-in`, {viewDigest: (await f.view(id)).viewDigest});
      const cookie = /fabric_oauth=([^;]+); HttpOnly; SameSite=Lax; Path=\/api\/oauth\/github\/callback; Max-Age=(\d+)/.exec(response.headers.get('set-cookie') || '');
      return {status: response.status, body: await response.json(), flowId: cookie?.[1], maxAge: Number(cookie?.[2])};
    },
    async callback(started, {account = 'a', grant = 'all', deny = false, cookie = started.flowId} = {}) {
      const consent = sim.consent(started.body.authorizationUrl, {account, grant, deny});
      const query = new URLSearchParams({state: consent.state, ...(consent.code ? {code: consent.code} : {error: consent.error})});
      const response = await owned('GET', `/api/oauth/github/callback?${query}`, undefined, cookie ? `fabric_oauth=${cookie}` : '');
      return {status: response.status, location: response.headers.get('location'), consent, query};
    },
    tokenCalls: () => sim.calls.filter(req => req.url === 'https://github.com/login/oauth/access_token').length,
    connections: () => app.store.list('connections'),
  };
  return f;
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readdirSync, readFileSync, rmSync, statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {inspect} from 'node:util';
import {randomBytes, randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {Vault} from '../lib/vault.mjs';
import {ROUTES} from '../lib/tenant/api.mjs';
import {PAGE_ACTIONS, PAGE_API, CALLBACK_ROUTES, AGENT_ROUTE, pageActionOf} from '../lib/tenant/page-routes.mjs';
import {tenantAgentManifest} from '../lib/tenant/agent-protocol.mjs';

// F03.11, exit checks 3 and 4 (docs/F03-DEVELOPER-LAYER.md section 9, invariants N14 to N16 in section 4.2). One developer
// environment is walked end to end through the real routes against simulated GitHub and Google: keys (one rotated), a
// developer's own Google app with a canary secret, a Connect link minted twice, a browser claim, sign-in and confirm, an
// execution and a proxied request, an agent token and its held call, a manage link, an approve link, a sign-in through the
// developer's own app, a refresh, and disconnects. Afterwards no credential is found in any byte under the data root (also
// as base64 and base64url), in any answer beyond that answer's own one-time delivery, in any audit row or in any log line;
// the browser-facing and agent surfaces are pinned with no raw-credential route; and no agent answer holds a link.

const RAW_CREDENTIAL = /token|secret|credential|password/i;

test('the browser-facing and agent surfaces are pinned, and none of them hands out a raw credential', () => {
  assert.deepEqual(PAGE_ACTIONS.map(({method, action}) => `${method} ${action}`), [
    'POST claim', 'GET view', 'POST start', 'POST confirm', 'POST close', 'POST reject', 'POST select', 'POST decline',
    'GET catalog', 'GET activity', 'GET approval', 'GET apps/:appId',
    'POST apps/:appId/accounts/:accountRef/permissions', 'POST apps/:appId/accounts/:accountRef/reset',
    'POST apps/:appId/accounts/:accountRef/background', 'POST apps/:appId/accounts/:accountRef/disconnect',
    'POST approvals/:callRef/decision',
  ]);
  assert.deepEqual(tenantAgentManifest.methods, ['fabric.discover', 'capabilities.list', 'calls.create', 'calls.get', 'calls.cancel', 'proxy.request']);
  assert.deepEqual(CALLBACK_ROUTES, ['GET /api/oauth/:providerId/callback', 'GET /api/oauth/:providerId/apps/:providerAppId/callback']);
  assert.equal(AGENT_ROUTE, 'POST /fabric/v1');
  assert.equal(tenantAgentManifest.features.links, false, 'the manifest promises no links');
  for (const {action} of PAGE_ACTIONS) assert.equal(RAW_CREDENTIAL.test(action), false, action);
  for (const method of tenantAgentManifest.methods) assert.equal(RAW_CREDENTIAL.test(method), false, method);
  for (const route of CALLBACK_ROUTES) assert.equal(RAW_CREDENTIAL.test(route), false, route);
  // The only /v1 routes that name a token are the agent-token routes, which return a new token once and never a stored one.
  assert.deepEqual(ROUTES.filter(route => /token|secret|credential|password|authorization/i.test(route)), [
    'POST /v1/users/([^/]{1,400})/agent-tokens', 'GET /v1/users/([^/]{1,400})/agent-tokens', 'POST /v1/users/([^/]{1,400})/agent-tokens/([^/]{1,100})/revoke',
  ]);
  // An action the list does not name never reaches the page API.
  for (const action of ['token', 'tokens', 'credentials', 'secret', 'password', 'apps/gmail/accounts/00000000-0000-0000-0000-000000000000/token']) {
    assert.equal(pageActionOf(action), null, action);
    assert.equal(PAGE_API.test(`/connect/cs_${'a'.repeat(26)}/v1/${action}`), false, action);
  }
});

// ---- the simulated world -------------------------------------------------------------------------------------

function seed(root) {
  const store = new PlatformStore({root});
  const typed = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send']];
  const paths = {};
  for (const [id, method, route] of typed) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const gmail = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities;
  // Gmail is reviewed by operation id: every reviewed operation sits in the map, so the proxy can review a request.
  const operations = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => ({id, method: id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`, sensitive: null}));
  for (const [id, method, route] of typed) {
    const capability = gmail.find(item => item.request.method === method.toUpperCase() && item.request.url === `https://gmail.googleapis.com${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations[operations.findIndex(op => op.id === id)] = {id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null};
  }
  for (const [id, pathname] of [['gmail.users.messages.list', '/gmail/v1/users/{userId}/messages'], ['gmail.users.labels.list', '/gmail/v1/users/{userId}/labels'], ['gmail.users.getProfile', '/gmail/v1/users/{userId}/profile']]) {
    const at = operations.findIndex(op => op.id === id);
    if (at >= 0) operations[at] = {...operations[at], path: pathname};
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  const [repos] = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}],
    paths: {'/repos/{owner}/{repo}': {get: {operationId: 'repos/get', parameters: ['owner', 'repo'].map(name => ({name, in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'OK'}}}}}}}).capabilities;
  store.put('capabilities', {...repos, status: 'active'});
  store.put('applicationMaps', {id: 'github', appId: 'github', classifierVersion: SENSITIVITY_VERSION, operations: [{id: 'repos/get', capabilityId: repos.id, method: 'GET', path: '/repos/{owner}/{repo}', sensitive: null}]});
  store.close();
}

/** GitHub and Google as Fabric sees them; every token they issue is remembered so the scans can look for it. */
function simulator() {
  const sim = {calls: [], issued: [], googleScope: ''};
  const issue = prefix => { const value = `${prefix}${randomBytes(24).toString('base64url')}`; sim.issued.push(value); return value; };
  sim.request = async req => {
    sim.calls.push({url: req.url, method: req.method || 'GET', headers: req.headers || {}, body: typeof req.body === 'string' ? req.body : ''});
    const reply = data => req.responseType === 'buffer' ? {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(data))} : {status: 200, headers: {}, data};
    if (req.url === 'https://github.com/login/oauth/access_token') return {status: 200, headers: {}, data: {access_token: issue('gho_'), token_type: 'bearer', scope: 'read:user,repo'}};
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: {id: 4242, login: 'octo', name: 'Octo Cat'}};
    if (req.url.startsWith('https://api.github.com/repos/')) return reply({id: 7, full_name: 'o/r'});
    if (req.url.startsWith('https://api.github.com/applications/')) return {status: 204, headers: {}, data: null};
    if (req.url === 'https://oauth2.googleapis.com/token') return {status: 200, headers: {}, data: {access_token: issue('ya29.'), refresh_token: issue('1//'), token_type: 'Bearer', expires_in: 3600, scope: sim.googleScope}};
    if (req.url === 'https://oauth2.googleapis.com/revoke') return {status: 200, headers: {}, data: {}};
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') return {status: 200, headers: {}, data: {sub: 'g-sub-1', email: 'one@example.com', name: 'One'}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/profile')) return reply({emailAddress: 'one@example.com'});
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/messages/send')) return reply({id: 'sent-1', threadId: 't-1'});
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/labels')) return reply({labels: [{id: 'INBOX'}]});
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/')) return reply({id: 'm-1', snippet: 'hello', messages: [{id: 'm-1'}]});
    throw new Error(`unexpected ${req.url}`);
  };
  return sim;
}

// ---- what the scans look for -----------------------------------------------------------------------------------

/**
 * Every form a secret can take in stored or sent bytes: itself, and the stretch of its base64 and base64url encodings
 * that does not depend on its neighbours, for each of the three alignments it can sit at.
 */
function forms(secret) {
  const out = new Set([secret]);
  for (const offset of [0, 1, 2]) {
    const bytes = Buffer.concat([Buffer.alloc(offset), Buffer.from(secret, 'utf8')]);
    for (const encoding of ['base64', 'base64url']) out.add(bytes.toString(encoding).slice(offset ? 4 : 0, Math.floor(bytes.length / 3) * 4));
  }
  return [...out].filter(form => form.length >= 16);
}
const filesUnder = dir => readdirSync(dir).flatMap(name => { const full = path.join(dir, name); return statSync(full).isDirectory() ? filesUnder(full) : [full]; });

/**
 * console.*, process.stdout and stderr, every answer the walk's fetch receives, and every vault write (the vault is
 * encrypted, so a byte scan cannot see into it), recorded until stop().
 */
function recorder() {
  const lines = [], exchanges = [], vaultWrites = [], undo = [];
  for (const name of ['log', 'info', 'warn', 'error', 'debug', 'trace']) {
    const original = console[name];
    console[name] = (...args) => { lines.push(args.map(arg => typeof arg === 'string' ? arg : inspect(arg, {depth: 8})).join(' ')); };
    undo.push(() => { console[name] = original; });
  }
  for (const stream of [process.stdout, process.stderr]) {
    const original = stream.write;
    // The test runner reports through stdout, so writes pass through after being recorded.
    stream.write = function write(chunk, ...rest) { lines.push(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)); return original.call(this, chunk, ...rest); };
    undo.push(() => { stream.write = original; });
  }
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const response = await realFetch(input, init), url = new URL(typeof input === 'object' && input !== null && 'url' in input ? input.url : String(input));
    exchanges.push({method: init.method ?? 'GET', path: url.pathname, status: response.status, headers: [...response.headers].filter(([name]) => name !== 'set-cookie'), setCookies: response.headers.getSetCookie(), text: await response.clone().text()});
    return response;
  };
  undo.push(() => { globalThis.fetch = realFetch; });
  const vaultSet = Vault.prototype.set;
  Vault.prototype.set = function set(id, value) { vaultWrites.push(JSON.stringify([id, value])); return vaultSet.call(this, id, value); };
  undo.push(() => { Vault.prototype.set = vaultSet; });
  let stopped = false;
  return {lines, exchanges, vaultWrites, stop() { if (stopped) return; stopped = true; for (const step of undo.reverse()) step(); }};
}

/**
 * The only places an answer may carry a secret: that answer's own one-time delivery. Everything else in the answer
 * (headers, other cookies, the rest of the body) is returned as `rest` for the scan.
 */
const DELIVERIES = Object.freeze([
  {route: 'POST /v1/connect-sessions (201)', kind: 'link', where: 'connectUrl after #k='},
  {route: 'POST /v1/connect-sessions/:id/link', kind: 'link', where: 'connectUrl after #k='},
  {route: 'POST /v1/users/:externalUserId/agent-tokens (201)', kind: 'agent', where: 'body token'},
  {route: 'POST /connect/:id/v1/claim', kind: 'binding', where: 'Set-Cookie fabric_t_session'},
  {route: 'POST /connect/:id/v1/claim', kind: 'csrf', where: 'body csrf'},
  {route: 'GET /connect/:id/v1/view', kind: 'csrf', where: 'body csrf'},
  {route: 'POST /connect/:id/v1/start', kind: 'flow', where: 'Set-Cookie fabric_t_oauth'},
  {route: 'POST /connect/:id/v1/start', kind: 'state', where: 'authorizationUrl state parameter'},
  {route: 'GET /api/oauth/:providerId/callback and /apps/:providerAppId/callback (303)', kind: 'finish', where: 'Set-Cookie fabric_t_finish'},
]);
function split(exchange) {
  const {method, path: route, status} = exchange, delivered = [];
  let body;
  try { body = JSON.parse(exchange.text); } catch { body = exchange.text; }
  let setCookies = [...exchange.setCookies];
  const cookie = (name, kind) => {
    setCookies = setCookies.map(line => {
      const value = new RegExp(`^${name}=([^;]*)`).exec(line)?.[1];
      if (!value) return line;
      delivered.push({kind, value});
      return line.replace(value, '<delivered>');
    });
  };
  const take = (kind, field) => { if (body && typeof body[field] === 'string') { delivered.push({kind, value: body[field]}); body = {...body, [field]: '<delivered>'}; } };
  const SESSION = 'cs_[a-z2-7]{26}';
  if (method === 'POST' && status < 300 && (route === '/v1/connect-sessions' || new RegExp(`^/v1/connect-sessions/${SESSION}/link$`).test(route)) && typeof body?.connectUrl === 'string') {
    const at = body.connectUrl.indexOf('#k=');
    if (at >= 0) { delivered.push({kind: 'link', value: body.connectUrl.slice(at + 3)}); body = {...body, connectUrl: body.connectUrl.slice(0, at)}; }
  }
  if (method === 'POST' && status === 201 && /^\/v1\/users\/[^/]+\/agent-tokens$/.test(route)) take('agent', 'token');
  if (method === 'POST' && status === 200 && new RegExp(`^/connect/${SESSION}/v1/claim$`).test(route)) { cookie('fabric_t_session', 'binding'); take('csrf', 'csrf'); }
  if (method === 'GET' && status === 200 && new RegExp(`^/connect/${SESSION}/v1/view$`).test(route)) take('csrf', 'csrf');
  if (method === 'POST' && status === 200 && new RegExp(`^/connect/${SESSION}/v1/start$`).test(route)) {
    cookie('fabric_t_oauth', 'flow');
    if (typeof body?.authorizationUrl === 'string') {
      const url = new URL(body.authorizationUrl), state = url.searchParams.get('state');
      if (state) { delivered.push({kind: 'state', value: state}); url.searchParams.delete('state'); body = {...body, authorizationUrl: url.href}; }
    }
  }
  if (method === 'GET' && status === 303 && /^\/api\/oauth\/[a-z][a-z0-9-]{1,39}(?:\/apps\/pa_[a-z2-7]{26})?\/callback$/.test(route)) cookie('fabric_t_finish', 'finish');
  return {delivered, rest: JSON.stringify({headers: exchange.headers, setCookies, body})};
}

// ---- the walk ----------------------------------------------------------------------------------------------------

async function walk(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-credentials-scan-'));
  seed(root);
  const sim = simulator();
  const SHARED_GITHUB_SECRET = `gh-shared-${randomBytes(18).toString('base64url')}`, SHARED_GOOGLE_SECRET = `g-shared-${randomBytes(18).toString('base64url')}`;
  const CANARY = `canary-${randomBytes(24).toString('base64url')}`;
  const app = await createDeveloperApp({dataRoot: root, port: 0, request: sim.request, providerSettings: {github: {clientId: 'gh-client', clientSecret: SHARED_GITHUB_SECRET}, google: {clientId: 'g-client', clientSecret: SHARED_GOOGLE_SECRET}}});
  t.after(async () => { await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });

  /** Every secret the walk sees, by value: its kind, a name for messages (never the value) and the forms to scan for. */
  const secrets = new Map();
  const keep = (kind, name, value) => {
    assert.equal(typeof value, 'string', `${name} was captured`);
    assert.ok(value.length >= 16, `${name} is long enough to scan for`);
    if (!secrets.has(value)) secrets.set(value, {kind, name, forms: forms(value)});
    return value;
  };
  keep('clientSecret', 'Fabric\'s shared GitHub client secret', SHARED_GITHUB_SECRET);
  keep('clientSecret', 'Fabric\'s shared Google client secret', SHARED_GOOGLE_SECRET);
  keep('clientSecret', 'the developer\'s client secret canary', CANARY);
  /** Byte scans at checkpoints, so a secret written and later erased is caught too. */
  const atRest = [];
  const scan = label => {
    const files = filesUnder(root);
    for (const file of files) {
      const bytes = readFileSync(file);
      for (const {name, forms: shapes} of secrets.values()) if (shapes.some(form => bytes.includes(form))) atRest.push(`${label}: ${name} in ${path.relative(root, file)}`);
    }
    return files;
  };

  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
  const repo = () => app.stores.open(scope).repository;
  // Keys: one of them rotated; the old key keeps working through its grace period.
  const full = app.keys.mint({environmentId: dev.id, preset: 'full'}), rotated = app.keys.rotate(full.serviceClientId);
  const manageKey = app.keys.mint({environmentId: dev.id, scopes: ['connect:manage']}), approveKey = app.keys.mint({environmentId: dev.id, scopes: ['connect:approve']});
  for (const [name, minted] of [['full key', full], ['rotated full key', rotated], ['manage key', manageKey], ['approve key', approveKey]]) keep('key', name, minted.token.split('.')[2]);
  assert.notEqual(rotated.token, full.token);

  const call = async (key, method, route, body, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key.token ?? key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    const text = await response.text();
    return {status: response.status, body: text ? JSON.parse(text) : null};
  };
  let requestCounter = 0;
  const agent = async (token, method, params) => {
    const response = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id: `r${++requestCounter}`, method, params})});
    return {status: response.status, body: await response.json()};
  };
  /** A browser on Fabric's page: its own cookie jar, Sec-Fetch-Site on every request, Origin, JSON and the CSRF value on writes. */
  const browser = () => {
    const jar = new Map();
    let csrf = null;
    return {jar, get csrf() { return csrf; }, async call(method, route, body, headers = {}) {
      const cookie = [...jar].filter(([, value]) => value).map(([name, value]) => `${name}=${value}`).join('; ');
      const response = await fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(cookie ? {Cookie: cookie} : {}), ...(body !== undefined ? {'Content-Type': 'application/json', Origin: app.origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      for (const line of response.headers.getSetCookie()) { const [pair] = line.split(';'), at = pair.indexOf('='); jar.set(pair.slice(0, at), pair.slice(at + 1)); }
      const type = response.headers.get('content-type') || '', parsed = type.includes('json') ? await response.json() : await response.text();
      if (typeof parsed?.csrf === 'string') csrf = parsed.csrf;
      return {status: response.status, headers: response.headers, body: parsed};
    }};
  };
  const linkSecret = (name, connectUrl) => keep('link', name, new URL(connectUrl).hash.slice(3));
  /** Claims a link in a fresh browser and keeps the browser binding and the CSRF value. */
  const claim = async (label, id, secret) => {
    const person = browser(), page = (method, action, body, query = '') => person.call(method, `/connect/${id}/v1/${action}${query}`, body);
    const claimed = await page('POST', 'claim', {secret});
    assert.equal(claimed.status, 200, `${label} claim`);
    keep('binding', `${label} browser binding`, person.jar.get('fabric_t_session'));
    keep('csrf', `${label} CSRF value`, claimed.body.csrf);
    const view = await page('GET', 'view');
    assert.equal(view.status, 200, `${label} view`);
    return {person, page, view: view.body};
  };
  /** Start on Fabric's page, consent at the simulated provider, come back; keeps the flow id, the state and the finish value. */
  const signIn = async (label, opened) => {
    const started = await opened.page('POST', 'start', {});
    assert.equal(started.status, 200, `${label} start`);
    const url = new URL(started.body.authorizationUrl), state = keep('state', `${label} OAuth state`, url.searchParams.get('state'));
    keep('flow', `${label} OAuth flow id`, opened.person.jar.get('fabric_t_oauth'));
    if (url.hostname === 'accounts.google.com') {
      const definition = definitionFor('google');
      sim.googleScope = (url.searchParams.get('scope') || '').split(definition.authorization.scopeSeparator).filter(Boolean).join(definition.token.scopeSeparator);
    }
    scan(`${label} at the provider`);
    const back = await opened.person.call('GET', `${new URL(url.searchParams.get('redirect_uri')).pathname}?state=${encodeURIComponent(state)}&code=${randomUUID()}`);
    assert.equal(back.status, 303, `${label} callback`);
    keep('finish', `${label} finish value`, opened.person.jar.get('fabric_t_finish'));
    const waiting = await opened.page('GET', 'view');
    assert.equal(waiting.body.state, 'awaiting_confirmation', `${label} waits for its confirm`);
    scan(`${label} awaiting confirmation`);
    const confirmed = await opened.page('POST', 'confirm', {});
    assert.equal(confirmed.status, 200, `${label} confirm`);
    assert.equal(confirmed.body.state, 'connected', `${label} connected`);
    return confirmed.body.result.accountRef;
  };
  scan('after keys');

  // A developer's own Google app with the canary secret: created, read, renamed, and refused once.
  const created = await call(full, 'POST', '/v1/provider-apps', {providerId: 'google', clientId: 'dev-google.apps.example', clientSecret: CANARY, consentScreenName: 'Acme Agent'});
  assert.equal(created.status, 201);
  const providerAppId = created.body.providerApp.id;
  assert.equal((await call(rotated, 'GET', '/v1/provider-apps')).status, 200);
  assert.equal((await call(rotated, 'PATCH', `/v1/provider-apps/${providerAppId}`, {consentScreenName: 'Acme Agent Two'})).status, 200);
  assert.equal((await call(rotated, 'PATCH', `/v1/provider-apps/${providerAppId}`, {clientSecret: ''})).status, 400);
  scan('after the provider app');

  // GitHub on Fabric's shared app: a link, minted again (the first secret is void), claimed, signed in and confirmed.
  const ghCaps = (await call(rotated, 'GET', '/v1/capabilities?appId=github')).body.capabilities, repos = ghCaps[0];
  const link = await call(full, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'github', successRedirectUri: 'http://localhost:5173/done', errorRedirectUri: 'http://localhost:5173/failed'});
  assert.equal(link.status, 201);
  const first = linkSecret('first GitHub link secret', link.body.connectUrl);
  const again = await call(rotated, 'POST', `/v1/connect-sessions/${link.body.id}/link`);
  assert.equal(again.status, 200);
  const second = linkSecret('re-minted GitHub link secret', again.body.connectUrl);
  assert.equal((await browser().call('GET', `/connect/${link.body.id}`)).status, 200);
  assert.equal((await browser().call('POST', `/connect/${link.body.id}/v1/claim`, {secret: first})).status, 404, 'the first secret is void after /link');
  const github = await claim('GitHub', link.body.id, second);
  scan('after the GitHub claim');
  const ghRef = await signIn('GitHub', github);
  assert.equal((await call(rotated, 'GET', `/v1/connect-sessions/${link.body.id}`)).body.state, 'connected');
  assert.equal((await call(rotated, 'GET', '/v1/users/u1/accounts')).status, 200);
  assert.equal((await call(rotated, 'GET', `/v1/users/u1/accounts/${ghRef}`)).status, 200);

  // An execution on the GitHub account.
  const run = await call(rotated, 'POST', '/v1/executions', {externalUserId: 'u1', capabilityId: repos.id, definitionHash: repos.definitionHash, args: {owner: 'o', repo: 'r'}}, {'Idempotency-Key': randomUUID()});
  assert.ok([200, 202].includes(run.status), `execution ${run.status}`);
  assert.equal((await call(rotated, 'GET', `/v1/executions/${run.body.callRef}?waitMs=3000`)).body.status, 'succeeded');

  // Gmail through the developer's own Google app: its secret is used at the token exchange and at refresh, nowhere else.
  assert.equal((await call(rotated, 'PUT', '/v1/environment/apps/gmail', {providerApp: providerAppId, enabled: true})).status, 200);
  const gmailLink = await call(rotated, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', appId: 'gmail'});
  assert.equal(gmailLink.status, 201);
  const gmail = await claim('Gmail', gmailLink.body.id, linkSecret('Gmail link secret', gmailLink.body.connectUrl));
  const exchangesBefore = sim.calls.length;
  const gmailRef = await signIn('Gmail', gmail);
  const exchange = sim.calls.slice(exchangesBefore).find(item => item.url === 'https://oauth2.googleapis.com/token');
  assert.ok(exchange?.body.includes(`client_secret=${encodeURIComponent(CANARY)}`), 'the developer\'s client secret was used at the token exchange');
  assert.deepEqual(repo().get('connections', gmailRef).providerApp, {kind: 'developer', id: providerAppId});
  const vault = app.stores.open(scope).vault;
  vault.set(gmailRef, {...vault.get(gmailRef), expiresAt: Date.now() - 1000});
  const refreshesBefore = sim.calls.length;
  assert.equal((await call(rotated, 'POST', `/v1/users/u1/accounts/${gmailRef}/check`)).status, 200);
  const refresh = sim.calls.slice(refreshesBefore).find(item => item.url === 'https://oauth2.googleapis.com/token');
  assert.ok(refresh?.body.includes('grant_type=refresh_token') && refresh.body.includes(`client_secret=${encodeURIComponent(CANARY)}`), 'the refresh used the developer\'s client secret');

  // Executions and a proxied request on the Gmail account; a send waits for the person.
  const gmailCaps = (await call(rotated, 'GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  const read = gmailCaps.find(item => item.id.includes('messages-get')), send = gmailCaps.find(item => item.id.includes('messages-send'));
  const readRun = await call(rotated, 'POST', '/v1/executions', {externalUserId: 'u1', capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}, waitMs: 3000}, {'Idempotency-Key': randomUUID()});
  assert.equal(readRun.body.status, 'succeeded');
  const proxied = await call(rotated, 'POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'gmail', request: {method: 'GET', path: '/gmail/v1/users/me/messages', query: {maxResults: '5'}}, waitMs: 5000}, {'Idempotency-Key': randomUUID()});
  assert.equal(proxied.body.status, 'succeeded');
  const waiting = await call(rotated, 'POST', '/v1/executions', {externalUserId: 'u1', capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}}, {'Idempotency-Key': randomUUID()});
  assert.equal(waiting.body.status, 'awaiting_approval');

  // An agent token for u1: used on /fabric/v1 for reads, a proxied request, an Ask, a held call and methods that do not exist.
  const minted = await call(rotated, 'POST', '/v1/users/u1/agent-tokens', {name: 'Inbox helper', bindings: [{accountRef: gmailRef, capabilityId: read.id}, {accountRef: gmailRef, capabilityId: send.id}], proxy: [{accountRef: gmailRef, rows: ['group:gmail.labels.read']}], requestable: [{capabilityId: repos.id}]});
  assert.equal(minted.status, 201);
  const agentToken = keep('agent', 'agent token', minted.body.token);
  keep('agent', 'agent token secret part', agentToken.split('.')[2]);
  scan('after the agent token');
  const agentAnswers = [];
  const ask = async (method, params) => { const answer = await agent(agentToken, method, params); agentAnswers.push({method, ...answer}); return answer; };
  assert.equal((await ask('fabric.discover', {})).status, 200);
  const listed = (await ask('capabilities.list', {})).body.result.capabilities;
  const alias = listed.find(item => item.id === read.id).connectionId, requestable = listed.find(item => item.id === repos.id);
  const agentRead = await ask('calls.create', {connectionId: alias, capabilityId: read.id, definitionHash: read.definitionHash, args: {userId: 'me', id: 'm-1'}});
  assert.equal(agentRead.body.result.status, 'succeeded');
  assert.equal((await ask('calls.get', {callId: agentRead.body.result.id})).status, 200);
  assert.equal((await ask('proxy.request', {connectionId: alias, request: {method: 'GET', path: '/gmail/v1/users/me/labels'}})).body.result.status, 'succeeded');
  assert.equal((await ask('calls.create', {connectionId: alias, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eQ'}}})).body.result.status, 'awaiting_approval');
  const probes = [];
  for (const method of ['credentials.get', 'tokens.get', 'accounts.token', 'connections.credentials', 'proxy.credentials', 'secrets.list']) probes.push({method, code: (await ask(method, {})).body.error?.code});
  // The held call: Fabric makes a handoff session; the developer mints its link; the person picks the account and confirms.
  const held = await ask('calls.create', {appId: 'github', capabilityId: repos.id, definitionHash: requestable.definitionHash, args: {owner: 'o', repo: 'r'}});
  assert.equal(held.body.result.status, 'awaiting_connection');
  const handoffId = held.body.result.handoff.connectSessionId;
  const handoffLink = await call(rotated, 'POST', `/v1/connect-sessions/${handoffId}/link`);
  assert.equal(handoffLink.status, 200);
  const handoff = await claim('handoff', handoffId, linkSecret('handoff link secret', handoffLink.body.connectUrl));
  const [choice] = handoff.view.handoff.accounts;
  assert.equal((await handoff.page('POST', 'select', {choice: choice.choice})).status, 200);
  assert.equal((await handoff.page('POST', 'confirm', {})).body.state, 'connected');
  await app.sessions.settled();
  assert.equal((await call(rotated, 'GET', `/v1/executions/${held.body.result.id}?waitMs=3000`)).body.status, 'succeeded');
  assert.equal((await ask('calls.get', {callId: held.body.result.id})).body.result.status, 'succeeded');

  // An approve link for the waiting send: the person approves on Fabric's page.
  const approveLink = await call(approveKey, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'approve', callRef: waiting.body.callRef, successRedirectUri: 'http://localhost:5173/approved'});
  assert.equal(approveLink.status, 201);
  const approving = await claim('approve', approveLink.body.id, linkSecret('approve link secret', approveLink.body.connectUrl));
  scan('after the approve claim');
  const shown = (await approving.page('GET', 'approval')).body.approval;
  const decided = await approving.page('POST', `approvals/${waiting.body.callRef}/decision`, shown.approve.body);
  assert.deepEqual([decided.status, decided.body.decision], [200, 'approved']);
  assert.equal((await call(rotated, 'GET', `/v1/executions/${waiting.body.callRef}?waitMs=3000`)).status, 200);

  // A manage link: the hosted data routes, a permission change, background, reset, a disconnect and Done.
  const manageLink = await call(manageKey, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'manage', successRedirectUri: 'http://localhost:5173/settings'});
  assert.equal(manageLink.status, 201);
  const managing = await claim('manage', manageLink.body.id, linkSecret('manage link secret', manageLink.body.connectUrl));
  scan('after the manage claim');
  assert.equal((await managing.page('GET', 'catalog')).status, 200);
  const appView = (await managing.page('GET', 'apps/gmail', undefined, `?account=${gmailRef}`)).body;
  const row = appView.sections.flatMap(section => section.rows).find(item => item.groupId === 'gmail.messages.read');
  assert.equal((await managing.page('POST', `apps/gmail/accounts/${gmailRef}/permissions`, {groupId: row.groupId, mode: 'ask', etag: row.etag})).status, 200);
  assert.equal((await managing.page('POST', `apps/gmail/accounts/${gmailRef}/background`, {mode: 'deny', etag: appView.background.etag})).status, 200);
  assert.equal((await managing.page('POST', `apps/gmail/accounts/${gmailRef}/reset`, {})).status, 200);
  assert.equal((await managing.page('GET', 'activity')).status, 200);
  assert.equal((await managing.page('GET', 'apps/github', undefined, `?account=${ghRef}`)).status, 200);
  // No raw-credential action on the claimed page, and no token route beside the callbacks.
  for (const action of ['token', 'credentials', 'secret', `apps/github/accounts/${ghRef}/token`]) {
    probes.push({action: `GET ${action}`, status: (await managing.page('GET', action)).status});
    probes.push({action: `POST ${action}`, status: (await managing.page('POST', action, {})).status});
  }
  for (const route of ['/api/oauth/github/token', '/api/oauth/google/token', `/api/oauth/google/apps/${providerAppId}/token`]) probes.push({action: `GET ${route}`, status: (await browser().call('GET', route)).status});
  const revokesBefore = sim.calls.length;
  assert.equal((await managing.page('POST', `apps/github/accounts/${ghRef}/disconnect`, {})).status, 200);
  assert.ok(sim.calls.slice(revokesBefore).some(item => item.url.startsWith('https://api.github.com/applications/')), 'GitHub heard the disconnect');
  assert.equal((await managing.page('POST', 'close', {})).body.state, 'completed');

  // The developer disconnects the Gmail account and revokes the agent token.
  assert.equal((await call(rotated, 'POST', `/v1/accounts/${gmailRef}/disconnect`, {})).status, 200);
  assert.equal((await call(rotated, 'POST', `/v1/users/u1/agent-tokens/${minted.body.agentToken.id}/revoke`)).status, 200);
  assert.equal((await ask('fabric.discover', {})).status, 401, 'the revoked token stops');
  await app.sessions.settled();

  assert.ok(sim.issued.length >= 4, 'the providers issued tokens');
  sim.issued.forEach((value, index) => keep('provider', `provider token ${index + 1} (${value.startsWith('gho_') ? 'GitHub access' : value.startsWith('ya29.') ? 'Google access' : 'Google refresh'})`, value));
  return {app, repo, secrets, scan, atRest, agentAnswers, probes};
}

test('a full developer walk leaves no credential at rest, in an answer, an audit row or a log line, and no agent answer holds a link', async t => {
  const recorded = recorder();
  t.after(() => recorded.stop());
  let world;
  try { world = await walk(t); } finally { recorded.stop(); }
  const {app, repo, secrets, scan, atRest, agentAnswers, probes} = world;
  const all = [...secrets.values()];
  const kinds = new Set(all.map(item => item.kind));
  assert.deepEqual([...kinds].sort(), ['agent', 'binding', 'clientSecret', 'csrf', 'finish', 'flow', 'key', 'link', 'provider', 'state']);
  const found = haystack => all.filter(({forms: shapes}) => shapes.some(form => haystack.includes(form))).map(({name}) => name);
  // Read before the stores close.
  const audit = JSON.stringify([app.registry.activity(), repo().list('activity')]);
  const maps = JSON.stringify([app.executions[Symbol.for('fabric.test.maps')](), app.runtimes[Symbol.for('fabric.test.maps')]()]);
  const live = scan('end of the walk, server open');
  await app.close();
  const closed = scan('end of the walk, server closed');

  await t.test('a. no byte under the data root holds a plaintext key, link secret, binding, CSRF value, flow id, state, finish value, agent token, client secret or provider token', () => {
    for (const files of [live, closed]) {
      assert.ok(files.some(file => file.endsWith('.enc')), 'the vault was scanned');
      assert.ok(files.some(file => file.endsWith('fabric.sqlite')), 'the stores were scanned');
    }
    assert.ok(all.filter(item => item.kind === 'link').length >= 6 && all.filter(item => item.kind === 'binding').length >= 5, 'every link and browser was captured');
    assert.deepEqual(atRest, []);
    // Hashed, not sealed: the vault holds provider tokens, PKCE verifiers and the developer's client secret, never a key,
    // link secret, binding, CSRF value, flow id, state, finish value or agent token.
    const hashedOnly = all.filter(item => !['provider', 'clientSecret'].includes(item.kind));
    assert.ok(recorded.vaultWrites.length >= 6, `the vault writes were recorded (${recorded.vaultWrites.length})`);
    assert.deepEqual(recorded.vaultWrites.flatMap(text => hashedOnly.filter(({forms: shapes}) => shapes.some(form => text.includes(form))).map(({name}) => `vault write holds ${name}`)), []);
  });

  await t.test('b. no answer or header carries a secret beyond its own one-time delivery', () => {
    const {exchanges} = recorded;
    assert.ok(exchanges.length > 60, `the walk's answers were recorded (${exchanges.length})`);
    const deliveredCount = new Map(), leaks = [];
    for (const exchange of exchanges) {
      const {delivered, rest} = split(exchange);
      for (const name of found(rest)) leaks.push(`${exchange.method} ${exchange.path} ${exchange.status}: ${name}`);
      for (const {kind, value} of delivered) {
        const known = secrets.get(value);
        assert.ok(known, `${exchange.method} ${exchange.path} delivered a ${kind} the walk never captured`);
        assert.equal(known.kind, kind, `${exchange.method} ${exchange.path} delivered ${known.name} as a ${kind}`);
        deliveredCount.set(value, (deliveredCount.get(value) ?? 0) + 1);
      }
    }
    assert.deepEqual(leaks, []);
    assert.deepEqual(DELIVERIES.map(item => item.kind), ['link', 'link', 'agent', 'binding', 'csrf', 'csrf', 'flow', 'state', 'finish'], 'the allowed deliveries, listed');
    // Each one-time secret came over HTTP exactly once, in its own answer; keys and client secrets never came at all.
    for (const [value, {kind, name}] of secrets) {
      const times = deliveredCount.get(value) ?? 0;
      if (['link', 'binding', 'flow', 'state', 'finish'].includes(kind) || name === 'agent token') assert.equal(times, 1, `${name} delivered once`);
      if (['key', 'clientSecret', 'provider'].includes(kind)) assert.equal(times, 0, `${name} never delivered`);
      if (kind === 'csrf') assert.ok(times >= 1, `${name} came from claim or view`);
    }
  });

  await t.test('c. no audit row and no in-memory map holds a secret', () => {
    assert.ok(audit.includes('connect.account_confirmed') && audit.includes('agent.token_granted'), 'the walk was audited');
    assert.deepEqual(found(audit), []);
    assert.deepEqual(found(maps), []);
  });

  await t.test('d. no console line and no stdout or stderr write during the walk holds a secret', () => {
    assert.deepEqual(found(recorded.lines.join('\n')), []);
  });

  await t.test('e. no raw-credential method, page action or token route answers', () => {
    for (const probe of probes) {
      if (probe.method) assert.equal(probe.code, 'method_not_found', probe.method);
      else assert.equal(probe.status, 404, probe.action);
    }
    assert.ok(probes.length >= 17);
  });

  await t.test('f. no agent answer holds a link to Fabric\'s server, a Connect page or the developer\'s own app', () => {
    const fabricAnswers = recorded.exchanges.filter(item => item.path === '/fabric/v1');
    assert.equal(fabricAnswers.length, agentAnswers.length);
    assert.ok(agentAnswers.length >= 14, `the agent was answered (${agentAnswers.length})`);
    assert.ok(agentAnswers.some(answer => answer.body.result?.handoff?.connectSessionId), 'a handoff answer was among them');
    for (const answer of fabricAnswers) {
      const text = answer.text + JSON.stringify(answer.headers);
      assert.equal(text.includes(app.origin), false, 'no address of Fabric\'s server');
      assert.equal(/https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])/.test(text), false, 'no local address');
      assert.equal(/\/connect\/|\/approve|\/continue\/|#k=|fabric_t_|connectUrl/.test(text), false, 'no Connect, approve or continue link');
    }
  });
});

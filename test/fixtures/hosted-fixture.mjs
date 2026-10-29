// F03.10: one setup for the hosted manage and approval pages. A developer server with a clock the test moves, Gmail
// read and send compiled from a small description, people with one Gmail account each, and keys with and without the
// link powers. A browser keeps its own cookies and sends what Fabric's page sends (Sec-Fetch-Site, Origin, the CSRF
// value from claim or view).
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../../developer-server.mjs';
import {PlatformStore} from '../../lib/tenant/platform.mjs';
import {compileOpenApi} from '../../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../../lib/sensitivity.mjs';
import {stampOwner} from '../../lib/tenant/deployment.mjs';

// F10.15: "Manage labels" labels.create is the write at Allow that stays in the account; Gmail's typed drafts.create is unsupported (its plain
// form carries no message), so "Draft emails" is Never only in a developer environment.
const GMAIL = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send'], ['gmail.users.drafts.create', 'post', '/gmail/v1/users/{userId}/drafts'],
  ['gmail.users.labels.create', 'post', '/gmail/v1/users/{userId}/labels']];
// Notion's search row is a read row with a write member (a view query is a POST): Allow on it is still confirmed.
const NOTION = [['notion.pages.get', 'get', '/v1/pages/{page_id}'], ['notion.views.queries.create', 'post', '/v1/views/{view_id}/queries'], ['notion.search', 'post', '/v1/search']];
function seed(root, appId, server, ops) {
  const paths = {};
  for (const [id, method, route] of ops) paths[route] = {...(paths[route] || {}), [method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method !== 'get' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}, name: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId, document: {openapi: '3.0.3', info: {title: appId, version: '1'}, servers: [{url: server}], paths}}).capabilities;
  const store = new PlatformStore({root}), operations = [];
  for (const [id, method, route] of ops) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `${server}${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations.push({id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null});
  }
  store.put('applicationMaps', {id: appId, appId, classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

export async function hostedSetup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-hosted-'));
  seed(root, 'gmail', 'https://gmail.googleapis.com', GMAIL);
  seed(root, 'notion', 'https://api.notion.com', NOTION);
  let now = Date.UTC(2026, 9, 14, 12);
  const sim = {calls: []};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/me/messages/send')) return {status: 200, headers: {}, data: {id: 'sent-1', threadId: 't-1'}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/')) return {status: 200, headers: {}, data: {id: 'm-1'}};
    if (req.url.startsWith('https://oauth2.googleapis.com/revoke')) return {status: 200, headers: {}, data: {}};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, clock: () => now, request, providerSettings: {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}, notion: {clientId: 'n-client', clientSecret: 'n-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
  const mint = options => app.keys.mint({environmentId: dev.id, ...options});
  const keys = {standard: mint({preset: 'standard'}), full: mint({preset: 'full'}), manage: mint({scopes: ['connect:manage']}), approve: mint({scopes: ['connect:approve']}), connectOnly: mint({preset: 'connect-only'})};
  const call = async (key, method, route, body, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key.token ?? key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: response.status === 204 ? null : await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  const userOf = externalUserId => repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active');
  /** A person with one ready account: Gmail (read, compose and send, and since F10.7 gmail.modify, the scope Gmail's rows name
   *  where the map is silent) unless another app is named. */
  const account = async (externalUserId, identity, {appId = 'gmail', displayName = `${identity}@example.com`} = {}) => {
    if (!userOf(externalUserId)) await call(keys.standard, 'POST', '/v1/connect-sessions', {externalUserId});
    const user = userOf(externalUserId), id = randomUUID(), stamp = app.registry.now();
    const shape = appId === 'notion' ? {providerId: 'notion', allowedOrigins: ['https://api.notion.com'], scopes: []}
      : {providerId: 'google', allowedOrigins: ['https://gmail.googleapis.com'], scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.compose', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify']};
    repo().put('connections', stampOwner({id, appId, ...shape, driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: identity, displayName}, label: displayName,
      createdAt: stamp, updatedAt: stamp, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: externalUserId, userRecordId: user.id}));
    app.stores.open(scope).vault.set(id, {accessToken: 'ya29.hosted', refreshToken: '1//r', expiresAt: Date.parse(stamp) + 3600_000});
    return id;
  };
  const caps = async () => (await call(keys.standard, 'GET', '/v1/capabilities?appId=gmail')).body.capabilities;
  /** A send that waits for the person's decision (Gmail send defaults to Ask). */
  const ask = async (externalUserId = 'u1', raw = 'eA') => {
    const send = (await caps()).find(item => item.id.includes('messages-send'));
    return (await call(keys.standard, 'POST', '/v1/executions', {externalUserId, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw}}}, {'Idempotency-Key': randomUUID()})).body;
  };
  const browser = () => {
    const jar = new Map();
    let csrf = null;
    return {jar, get binding() { return jar.get('fabric_t_session'); }, async call(method, route, body, headers = {}) {
      const cookie = [...jar].filter(([, value]) => value).map(([name, value]) => `${name}=${value}`).join('; ');
      const response = await fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(cookie ? {Cookie: cookie} : {}), ...(body !== undefined ? {'Content-Type': 'application/json', Origin: app.origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      for (const line of response.headers.getSetCookie()) { const [pair] = line.split(';'), at = pair.indexOf('='); jar.set(pair.slice(0, at), pair.slice(at + 1)); }
      const type = response.headers.get('content-type') || '', parsed = type.includes('json') ? await response.json() : await response.text();
      if (typeof parsed?.csrf === 'string') csrf = parsed.csrf;
      return {status: response.status, headers: response.headers, body: parsed};
    }};
  };
  /** Mints a manage or approve link and opens it in a fresh browser. */
  const open = async (key, body) => {
    const created = await call(key, 'POST', '/v1/connect-sessions', body);
    if (created.status !== 201) throw new Error(`link refused: ${JSON.stringify(created.body)}`);
    const person = browser(), id = created.body.id;
    const claimed = await person.call('POST', `/connect/${id}/v1/claim`, {secret: new URL(created.body.connectUrl).hash.slice(3)});
    if (claimed.status !== 200) throw new Error(`claim refused: ${JSON.stringify(claimed.body)}`);
    return {id, person, created: created.body};
  };
  return {app, sim, scope, dev, keys, call, repo, userOf, account, caps, ask, browser, open, advance: ms => { now += ms; }, now: () => now};
}

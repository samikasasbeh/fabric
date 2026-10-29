// Exit check 1 (docs/F03-DEVELOPER-LAYER.md section 9, the isolation matrix), for the routes a browser or an agent
// reaches: every Connect page action, every fabric/0.1 method and both OAuth callbacks answer another environment's or
// another person's ids exactly like ids that never existed, and change nothing anywhere. Also the matrix's concurrency
// cells (one claim wins, one callback per state, two environments signing in at once each keep their own flow) and its
// in-memory maps (one environment's traffic leaves no key of another environment in them).
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash, randomBytes, randomUUID} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner, ownershipOf, tenantDeployment} from '../lib/tenant/deployment.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {PAGE_ACTIONS, PAGE_API, pageActionOf, CALLBACK_ROUTES, AGENT_ROUTE} from '../lib/tenant/page-routes.mjs';
import {tenantAgentManifest} from '../lib/tenant/agent-protocol.mjs';

const TEST_MAPS = Symbol.for('fabric.test.maps');
const SETTINGS = {google: {clientId: 'g-client', clientSecret: 'g-secret'}, github: {clientId: 'gh-client', clientSecret: 'gh-secret'}};
const GMAIL_SCOPES = ['readonly', 'compose', 'send', 'labels', 'modify'].map(name => `https://www.googleapis.com/auth/gmail.${name}`);
const PURPOSES = ['connect', 'manage', 'approve'];
const sha = value => createHash('sha256').update(value).digest('hex');
const base32 = length => [...randomBytes(length)].map(byte => 'abcdefghijklmnopqrstuvwxyz234567'[byte & 31]).join('');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
/** An answer without its request id, so answers to different requests can be compared byte for byte. */
const strip = body => {
  if (!body || typeof body !== 'object') return body;
  const {requestId, ...rest} = body;
  if (rest.error && typeof rest.error === 'object') { const {requestId: inner, ...error} = rest.error; rest.error = error; }
  return rest;
};

// Gmail read and send as typed operations, and every reviewed Gmail operation in the map (the proxy rows need them).
const TYPED = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send']];
function seed(root) {
  const paths = {};
  for (const [id, method, route] of TYPED) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities;
  const store = new PlatformStore({root});
  const operations = PERMISSION_GROUPS.get('gmail').groups.flatMap(group => group.operations).map(id => ({id, method: id.endsWith('.list') || id.endsWith('.get') ? 'GET' : 'POST', path: `/gmail/v1/users/{userId}/${id.split('.').slice(2).join('/')}`, sensitive: null}));
  for (const [id, method, route] of TYPED) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `https://gmail.googleapis.com${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations[operations.findIndex(op => op.id === id)] = {id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null};
  }
  for (const [id, pathname] of [['gmail.users.labels.list', '/gmail/v1/users/{userId}/labels'], ['gmail.users.labels.create', '/gmail/v1/users/{userId}/labels']]) operations[operations.findIndex(op => op.id === id)].path = pathname;
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

/**
 * Two environments of one organization, A and B, in two projects. A has people u1 and u2, B has u1 under the same
 * external id. Each person has a Gmail account, a send waiting for approval, an agent token with a call of its own
 * waiting too, and one claimed Connect session of each purpose (connect, manage, approve), each in its own browser.
 */
async function world(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-isolation-page-'));
  seed(root);
  const now = Date.UTC(2026, 9, 14, 12);
  // Simulated Google, GitHub and Gmail. A gate holds one kind of request until the test lets it through.
  const sim = {calls: [], scope: {}, tokens: 0, gates: {}, identity: {google: {sub: 'google-sub-shared', email: 'shared@example.com', name: 'Shared Person'}, github: {id: 4242, login: 'octo', name: 'Octo'}}};
  const held = async name => { if (sim.gates[name]) await sim.gates[name].promise; };
  const request = async req => {
    const url = String(req.url);
    sim.calls.push(`${req.method || 'GET'} ${url}`);
    if (url === 'https://oauth2.googleapis.com/token') { await held('googleToken'); return {status: 200, headers: {}, data: {access_token: `ya29.sim-${++sim.tokens}`, refresh_token: `1//sim-${sim.tokens}`, token_type: 'Bearer', expires_in: 3600, scope: sim.scope.google}}; }
    if (url === 'https://openidconnect.googleapis.com/v1/userinfo') return {status: 200, headers: {}, data: sim.identity.google};
    if (url === 'https://github.com/login/oauth/access_token') { await held('githubToken'); return {status: 200, headers: {}, data: {access_token: `gho_sim${++sim.tokens}`, token_type: 'bearer', scope: sim.scope.github}}; }
    if (url === 'https://api.github.com/user') return {status: 200, headers: {}, data: sim.identity.github};
    if (url === 'https://oauth2.googleapis.com/revoke' || url.startsWith('https://api.github.com/applications/')) return {status: 200, headers: {}, data: {}};
    if (url.startsWith('https://gmail.googleapis.com/')) {
      if (/\/messages\/(?!send)[^/?]+(\?|$)/.test(url)) await held('gmailRead');
      const data = url.includes('/labels') ? {labels: [{id: 'INBOX'}]} : url.includes('/profile') ? {emailAddress: sim.identity.google.email} : url.includes('/send') ? {id: 'sent-1'} : {id: 'm-1'};
      return req.responseType === 'buffer' ? {status: 200, headers: {'content-type': 'application/json'}, data: Buffer.from(JSON.stringify(data))} : {status: 200, headers: {}, data};
    }
    throw new Error(`unexpected request ${url}`);
  };
  const gate = name => {
    let open;
    const promise = new Promise(resolve => { open = resolve; });
    sim.gates[name] = {promise, release: () => { delete sim.gates[name]; open(); }};
    return sim.gates[name].release;
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, clock: () => now, request, providerSettings: SETTINGS});
  t.after(async () => { for (const entry of Object.values(sim.gates)) entry.release(); await app.close(); rmSync(root, {recursive: true, force: true}); });

  /** A browser with its own cookies, sending what Fabric's page sends (Sec-Fetch-Site, Origin, the CSRF value). */
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
  const agent = async (token, method, params, id = `r-${randomUUID()}`) => {
    const response = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id, method, params})});
    return {status: response.status, body: await response.json()};
  };

  const org = app.registry.createOrganization({name: 'Acme'});
  const environment = name => {
    const project = app.registry.createProject({organizationId: org.id, name, appName: `${name} Assistant`});
    const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
    const key = app.keys.mint({environmentId: dev.id, preset: 'full'});
    const call = async (method, route, body, headers = {}, token = key.token) => {
      const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      const text = await response.text();
      return {status: response.status, body: text ? JSON.parse(text) : null};
    };
    return {name, project, dev, scope, key, keys: [key], call, scopeKey: app.stores.open(scope).scopeKey, repo: () => app.stores.open(scope).repository, vault: () => app.stores.open(scope).vault};
  };
  const A = environment('Alpha'), B = environment('Beta');

  /** One claimed Connect session of a purpose, opened in a fresh browser. */
  const claimed = async (env, externalUserId, body) => {
    const created = await env.call('POST', '/v1/connect-sessions', {externalUserId, ...body});
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const secret = new URL(created.body.connectUrl).hash.slice(3), person = browser();
    const opened = await person.call('POST', `/connect/${created.body.id}/v1/claim`, {secret});
    assert.equal(opened.status, 200, JSON.stringify(opened.body));
    return {id: created.body.id, secret, person};
  };
  const cell = async (env, externalUserId, label) => {
    await env.call('POST', '/v1/connect-sessions', {externalUserId});
    const user = env.repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), accountRef = randomUUID(), stamp = app.registry.now();
    env.repo().put('connections', stampOwner({id: accountRef, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: `seed-${label}`, displayName: `${label}@example.com`}, label: `${label}@example.com`,
      allowedOrigins: ['https://gmail.googleapis.com'], scopes: GMAIL_SCOPES, createdAt: stamp, updatedAt: stamp, authRevision: randomUUID(), providerApp: {kind: 'shared'}}, {subjectId: externalUserId, userRecordId: user.id}));
    env.vault().set(accountRef, {accessToken: `ya29.${label}`, refreshToken: '1//r', expiresAt: now + 3600_000});
    const caps = (await env.call('GET', '/v1/capabilities?appId=gmail')).body.capabilities;
    const read = caps.find(item => item.id.includes('messages-get')), send = caps.find(item => item.id.includes('messages-send'));
    const asked = await env.call('POST', '/v1/executions', {externalUserId, accountRef, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}}, {'Idempotency-Key': randomUUID()});
    assert.equal(asked.body.status, 'awaiting_approval', JSON.stringify(asked.body));
    const digest = (await env.call('GET', `/v1/users/${externalUserId}/approvals`)).body.approvals.find(item => item.callRef === asked.body.callRef).digest;
    const minted = await env.call('POST', `/v1/users/${externalUserId}/agent-tokens`, {name: `${label} helper`, bindings: [{accountRef, capabilityId: read.id}, {accountRef, capabilityId: send.id}], proxy: [{accountRef, rows: ['group:gmail.labels.read']}]});
    assert.equal(minted.status, 201, JSON.stringify(minted.body));
    const alias = (await agent(minted.body.token, 'capabilities.list', {})).body.result.capabilities[0].connectionId;
    const agentCall = await agent(minted.body.token, 'calls.create', {connectionId: alias, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw: 'eA'}}});
    assert.equal(agentCall.body.result.status, 'awaiting_approval', JSON.stringify(agentCall.body));
    const sessions = {};
    for (const [purpose, body] of [['connect', {appId: 'gmail'}], ['manage', {purpose: 'manage'}], ['approve', {purpose: 'approve', callRef: asked.body.callRef}]]) sessions[purpose] = await claimed(env, externalUserId, body);
    return {env, externalUserId, label, user, accountRef, read, send, waiting: {callRef: asked.body.callRef, digest}, token: minted.body.token, tokenId: minted.body.agentToken.id, alias, agentCallRef: agentCall.body.result.id, sessions};
  };
  const A1 = await cell(A, 'u1', 'alpha-u1'), A2 = await cell(A, 'u2', 'alpha-u2'), B1 = await cell(B, 'u1', 'beta-u1');
  assert.equal(A1.externalUserId, B1.externalUserId, 'the same external id in both environments');
  // Ids of every kind that never existed anywhere.
  const ghost = {label: 'ghost', accountRef: randomUUID(), alias: `acct_${base32(26)}`, agentCallRef: randomUUID(), tokenId: randomUUID(), waiting: {callRef: randomUUID(), digest: randomBytes(32).toString('hex')},
    sessions: Object.fromEntries(PURPOSES.map(purpose => [purpose, {id: `cs_${base32(26)}`}]))};

  /**
   * Every document of the registry and of both environments, by hash, plus a hash of each vault record that a document
   * names (accounts and sign-in flows). Read through a separate read-only connection, so looking changes nothing.
   */
  const dump = ({except = () => false} = {}) => {
    const out = {};
    for (const [label, file, env] of [['registry', path.join(root, 'registry', 'fabric.sqlite'), null], ['A', path.join(app.stores.folder(A.scope), 'fabric.sqlite'), A], ['B', path.join(app.stores.folder(B.scope), 'fabric.sqlite'), B]]) {
      const db = new DatabaseSync(file, {readOnly: true});
      let rows;
      try { rows = db.prepare('SELECT collection, id, document FROM documents ORDER BY collection, id').all(); } finally { db.close(); }
      for (const row of rows) if (!except(label, row.collection, row.id)) out[`${label}/${row.collection}/${row.id}`] = sha(row.document);
      if (env) for (const row of rows.filter(item => ['connections', 'oauthFlows'].includes(item.collection))) {
        const id = row.collection === 'connections' ? row.id : `oauth:${row.id}`, secret = env.vault().get(id);
        out[`${label}/vault/${id}`] = secret === null ? null : sha(JSON.stringify(secret));
      }
    }
    return out;
  };
  /** Starts a provider sign-in from Fabric's page, as the person's click does; the simulated provider then grants what was asked. */
  const start = async (person, sessionId, body = {}) => {
    const started = await person.call('POST', `/connect/${sessionId}/v1/start`, body);
    assert.equal(started.status, 200, JSON.stringify(started.body));
    const url = new URL(started.body.authorizationUrl), providerId = url.hostname === 'github.com' ? 'github' : 'google', definition = definitionFor(providerId);
    sim.scope[providerId] = (url.searchParams.get('scope') || '').split(definition.authorization.scopeSeparator).filter(Boolean).join(definition.token.scopeSeparator);
    const cookie = started.headers.getSetCookie().find(line => line.startsWith('fabric_t_oauth='));
    return {state: url.searchParams.get('state'), flowId: person.jar.get('fabric_t_oauth'), callbackPath: /Path=([^;]+)/.exec(cookie)[1], providerId};
  };
  /** The provider's redirect back, from a browser holding only the given flow cookie. */
  const callback = async (callbackPath, state, flowId) => {
    const response = await fetch(`${app.origin}${callbackPath}?${new URLSearchParams({state, code: `code-${randomUUID()}`})}`, {redirect: 'manual', headers: flowId ? {Cookie: `fabric_t_oauth=${flowId}`} : {}});
    return {status: response.status, location: response.headers.get('location'), body: response.status === 303 ? null : await response.json()};
  };
  const tokenCalls = providerId => sim.calls.filter(line => line === `POST ${providerId === 'github' ? 'https://github.com/login/oauth/access_token' : 'https://oauth2.googleapis.com/token'}`).length;
  const googleRevokes = () => sim.calls.filter(line => line.includes('oauth2.googleapis.com/revoke')).length;
  const until = async (check, what) => { for (let tries = 0; tries < 400; tries++) { if (await check()) return; await pause(5); } assert.fail(`timed out waiting for ${what}`); };
  return {app, root, sim, gate, browser, agent, A, B, A1, A2, B1, ghost, dump, claimed, start, callback, tokenCalls, googleRevokes, until};
}

/**
 * One row per Connect page action: how its path, query and body name the target's records. The target is another
 * environment's person, another person of the actor's environment, or a set of ids that never existed.
 */
const choiceFor = (sessionId, accountRef) => sha(`${sessionId}:${accountRef}`).slice(0, 24);
const PAGE_ROWS = [
  {method: 'POST', action: 'claim', path: () => 'claim', body: (target, actor) => ({secret: actor.secret})},
  {method: 'GET', action: 'view', path: () => 'view', query: () => '?appId=gmail'},
  {method: 'POST', action: 'start', path: () => 'start', body: () => ({appId: 'gmail'})},
  {method: 'POST', action: 'confirm', path: () => 'confirm', body: () => ({})},
  {method: 'POST', action: 'close', path: () => 'close', body: () => ({})},
  {method: 'POST', action: 'reject', path: () => 'reject', body: () => ({})},
  {method: 'POST', action: 'select', path: () => 'select', body: (target, actor, sessionId) => ({choice: choiceFor(sessionId, target.accountRef)})},
  {method: 'POST', action: 'decline', path: () => 'decline', body: () => ({})},
  {method: 'GET', action: 'catalog', path: () => 'catalog', query: () => '?q=gmail'},
  {method: 'GET', action: 'activity', path: () => 'activity', query: target => `?appId=gmail&accountRef=${target.accountRef}`, record: 'manage'},
  {method: 'GET', action: 'approval', path: () => 'approval'},
  {method: 'GET', action: 'apps/:appId', path: () => 'apps/gmail', query: target => `?account=${target.accountRef}`, record: 'manage'},
  {method: 'POST', action: 'apps/:appId/accounts/:accountRef/permissions', path: target => `apps/gmail/accounts/${target.accountRef}/permissions`, body: () => ({groupId: 'gmail.messages.read', mode: 'deny', etag: 'x'}), record: 'manage'},
  {method: 'POST', action: 'apps/:appId/accounts/:accountRef/reset', path: target => `apps/gmail/accounts/${target.accountRef}/reset`, body: () => ({}), record: 'manage'},
  {method: 'POST', action: 'apps/:appId/accounts/:accountRef/background', path: target => `apps/gmail/accounts/${target.accountRef}/background`, body: () => ({mode: 'deny', etag: 'x'}), record: 'manage'},
  {method: 'POST', action: 'apps/:appId/accounts/:accountRef/disconnect', path: target => `apps/gmail/accounts/${target.accountRef}/disconnect`, body: () => ({}), record: 'manage'},
  {method: 'POST', action: 'approvals/:callRef/decision', path: target => `approvals/${target.waiting.callRef}/decision`, body: target => ({decision: 'approve', digest: target.waiting.digest}), record: 'approve'},
];

test('every Connect page action has a row, and each answers another environment\'s and another person\'s session like one that never existed, changing nothing', async t => {
  const {A1, A2, B1, ghost, dump} = await world(t);
  // The generated-list check: a new page action without a row here fails.
  assert.deepEqual(PAGE_ROWS.map(row => `${row.method} ${row.action}`).sort(), PAGE_ACTIONS.map(entry => `${entry.method} ${entry.action}`).sort());
  const exercised = new Set();
  for (const row of PAGE_ROWS) for (const purpose of PURPOSES) {
    // A/u1's browser, holding its own session cookie and CSRF value for a session of this purpose.
    const actor = A1.sessions[purpose], answers = [], before = dump();
    for (const target of [B1, A2, ghost]) {
      const sessionId = target.sessions[purpose].id, route = `/connect/${sessionId}/v1/${row.path(target)}`;
      const routed = PAGE_API.exec(route);
      assert.deepEqual(routed && {...pageActionOf(routed[2])}, {method: row.method, action: row.action}, `${route} reaches its own action`);
      const response = await actor.person.call(row.method, `${route}${row.query?.(target) ?? ''}`, row.method === 'POST' ? row.body(target, actor, sessionId) : undefined);
      answers.push({status: response.status, body: strip(response.body)});
    }
    const label = `${row.method} ${row.action} with A/u1's ${purpose} cookie`;
    assert.deepEqual(answers[0], answers[2], `${label}: B's session answers like one that never existed`);
    assert.deepEqual(answers[1], answers[2], `${label}: A/u2's session answers like one that never existed`);
    assert.deepEqual([answers[2].status, answers[2].body?.error?.code], [404, 'not_found'], `${label}: the uniform not_found`);
    assert.deepEqual(dump(), before, `${label}: no session, store, vault or route changed`);
    exercised.add(`${row.method} ${row.action}`);
  }
  assert.equal(exercised.size, PAGE_ACTIONS.length, 'every row ran');
  // Controls: the actor's cookie and CSRF value are good on its own sessions, so the refusals above were about the target.
  for (const purpose of PURPOSES) {
    const view = await A1.sessions[purpose].person.call('GET', `/connect/${A1.sessions[purpose].id}/v1/view`);
    assert.deepEqual([view.status, view.body.state], [200, 'opened'], purpose);
  }
  const manage = A1.sessions.manage, mine = await manage.person.call('GET', `/connect/${manage.id}/v1/apps/gmail?account=${A1.accountRef}`);
  assert.equal(mine.status, 200); assert.equal(mine.body.selectedAccountRef, A1.accountRef);
  const approve = A1.sessions.approve, approval = await approve.person.call('GET', `/connect/${approve.id}/v1/approval`);
  assert.equal(approval.status, 200); assert.equal(approval.body.approval.digest, A1.waiting.digest);
  const reset = await manage.person.call('POST', `/connect/${manage.id}/v1/apps/gmail/accounts/${A1.accountRef}/reset`, {});
  assert.equal(reset.status, 200, JSON.stringify(reset.body));
});

test('on its own session, a page action naming another environment\'s or another person\'s account or call answers like one that never existed', async t => {
  const {A, A1, A2, B1, ghost, dump} = await world(t);
  const rows = PAGE_ROWS.filter(row => row.record);
  assert.deepEqual(rows.map(row => row.action).sort(), PAGE_ACTIONS.filter(entry => /:accountRef|:callRef|^activity$|^apps\/:appId$/.test(entry.action)).map(entry => entry.action).sort());
  for (const row of rows) {
    const actor = A1.sessions[row.record], answers = [];
    // Each request is page activity on the actor's own link, so only that link's own row may change.
    const before = dump({except: (label, collection, id) => label === 'A' && collection === 'connectSessions' && id === actor.id});
    for (const target of [B1, A2, ghost]) {
      const response = await actor.person.call(row.method, `/connect/${actor.id}/v1/${row.path(target)}${row.query?.(target) ?? ''}`, row.method === 'POST' ? row.body(target, actor, actor.id) : undefined);
      answers.push({status: response.status, body: strip(response.body)});
    }
    assert.deepEqual(answers[0], answers[2], `${row.action}: B's ${row.record === 'approve' ? 'call' : 'account'} answers like one that never existed`);
    assert.deepEqual(answers[1], answers[2], `${row.action}: A/u2's answers like one that never existed`);
    if (row.action === 'activity') assert.deepEqual([answers[2].status, answers[2].body.days, answers[2].body.approvals], [200, [], []], 'an account filter that is not the person\'s own shows nothing');
    else assert.deepEqual([answers[2].status, answers[2].body?.error?.code], [404, 'not_found'], row.action);
    assert.deepEqual(dump({except: (label, collection, id) => label === 'A' && collection === 'connectSessions' && id === actor.id}), before, `${row.action}: nothing changed`);
    const text = JSON.stringify(answers);
    for (const other of [B1, A2]) for (const value of [other.accountRef, other.waiting.callRef, other.label]) assert.equal(text.includes(value), false, `${row.action} shows nothing of ${other.label}`);
  }
  assert.equal(A.repo().get('connectSessions', A1.sessions.manage.id).state, 'opened');
});

/** One row per fabric/0.1 method: each kind of id the method takes, and how the request names it. */
const AGENT_ROWS = [
  // Methods that take no ids: an id sent anyway is refused the same way whoever it belongs to.
  {method: 'fabric.discover', kinds: {alias: cell => cell.alias, tokenId: cell => cell.tokenId}, params: value => ({connectionId: value})},
  {method: 'capabilities.list', kinds: {alias: cell => cell.alias, tokenId: cell => cell.tokenId}, params: value => ({connectionId: value})},
  {method: 'calls.create', kinds: {alias: cell => cell.alias, accountRef: cell => cell.accountRef}, params: (value, actor) => ({connectionId: value, capabilityId: actor.read.id, definitionHash: actor.read.definitionHash, args: {userId: 'me', id: 'm-1'}})},
  {method: 'calls.get', kinds: {agentCallRef: cell => cell.agentCallRef, callRef: cell => cell.waiting.callRef, connectSessionId: cell => cell.sessions.connect.id}, params: value => ({callId: value})},
  {method: 'calls.cancel', kinds: {agentCallRef: cell => cell.agentCallRef, callRef: cell => cell.waiting.callRef, connectSessionId: cell => cell.sessions.connect.id}, params: value => ({callId: value})},
  {method: 'proxy.request', kinds: {alias: cell => cell.alias, accountRef: cell => cell.accountRef}, params: value => ({connectionId: value, request: {method: 'GET', path: '/gmail/v1/users/me/labels'}})},
];

test('every fabric/0.1 method has a row, and A/u1\'s agent token gets the same answer for B\'s and A/u2\'s ids as for ids that never existed', async t => {
  const {app, agent, A1, A2, B1, ghost, dump} = await world(t);
  assert.equal(AGENT_ROUTE, 'POST /fabric/v1');
  assert.deepEqual(AGENT_ROWS.map(row => row.method).sort(), [...tenantAgentManifest.methods].sort());
  for (const row of AGENT_ROWS) for (const [kind, valueOf] of Object.entries(row.kinds)) {
    const before = dump(), answers = [], id = `isolation-${row.method}-${kind}`;
    for (const target of [B1, A2, ghost]) {
      const response = await agent(A1.token, row.method, row.params(valueOf(target), A1), id);
      answers.push({status: response.status, body: response.body});
    }
    const label = `${row.method} with another cell's ${kind}`;
    assert.deepEqual(answers[0], answers[2], `${label}: B's answers like one that never existed`);
    assert.deepEqual(answers[1], answers[2], `${label}: A/u2's answers like one that never existed`);
    const expected = Object.keys(row.kinds).includes('tokenId') ? [400, 'invalid_request'] : [404, 'not_found'];
    assert.deepEqual([answers[2].status, answers[2].body.error?.code], expected, label);
    assert.deepEqual(dump(), before, `${label}: nothing changed in either environment`);
  }
  // Controls: the token reaches its own person's things, and what it is shown names nobody else.
  const seen = [await agent(A1.token, 'fabric.discover', {}), await agent(A1.token, 'capabilities.list', {}), await agent(A1.token, 'calls.get', {callId: A1.agentCallRef})];
  assert.deepEqual(seen.map(answer => answer.status), [200, 200, 200]);
  assert.equal(seen[0].body.result.client.id, A1.tokenId);
  assert.deepEqual([...new Set(seen[1].body.result.capabilities.map(item => item.connectionId))], [A1.alias]);
  assert.equal(seen[2].body.result.id, A1.agentCallRef);
  const own = await agent(A1.token, 'calls.create', {connectionId: A1.alias, capabilityId: A1.read.id, definitionHash: A1.read.definitionHash, args: {userId: 'me', id: 'm-1'}});
  assert.deepEqual([own.status, own.body.result.status], [200, 'succeeded']);
  const text = JSON.stringify(seen.map(answer => answer.body));
  for (const other of [B1, A2]) for (const value of [other.alias, other.accountRef, other.tokenId, other.agentCallRef, other.waiting.callRef, other.label]) assert.equal(text.includes(value), false, `nothing of ${other.label}`);
  await app.runtimes.drain();
});

test('both callbacks: B\'s OAuth state from a browser holding A\'s flow cookie is refused exactly like an unknown state, and B\'s flow is untouched', async t => {
  const {A, B, A1, B1, claimed, start, callback, dump, googleRevokes} = await world(t);
  // A developer's own GitHub app in each environment (F03.8), so both callback addresses carry a live flow.
  const register = async (env, clientId) => {
    const created = await env.call('POST', '/v1/provider-apps', {providerId: 'github', clientId, clientSecret: `${clientId}-secret`, consentScreenName: `${env.name} Agent`});
    assert.equal(created.status, 201, JSON.stringify(created.body));
    assert.equal((await env.call('PUT', '/v1/environment/apps/github', {providerApp: created.body.providerApp.id, enabled: true})).status, 200);
    return created.body.providerApp.id;
  };
  await register(A, 'dev-alpha'); await register(B, 'dev-beta');
  const githubA = await claimed(A, 'u1', {appId: 'github'}), githubB = await claimed(B, 'u1', {appId: 'github'});
  const flows = {
    'GET /api/oauth/:providerId/callback': {a: await start(A1.sessions.connect.person, A1.sessions.connect.id), b: await start(B1.sessions.connect.person, B1.sessions.connect.id), people: {b: B1.sessions.connect}},
    'GET /api/oauth/:providerId/apps/:providerAppId/callback': {a: await start(githubA.person, githubA.id), b: await start(githubB.person, githubB.id), people: {b: githubB}},
  };
  // The generated-list check: both callback routes have a row.
  assert.deepEqual(Object.keys(flows).sort(), [...CALLBACK_ROUTES].sort());
  assert.match(flows['GET /api/oauth/:providerId/apps/:providerAppId/callback'].b.callbackPath, /^\/api\/oauth\/github\/apps\/pa_[a-z2-7]{26}\/callback$/);
  const results = [];
  for (const [route, {a, b, people}] of Object.entries(flows)) {
    const before = dump(), unknown = randomBytes(32).toString('base64url');
    const answers = {
      bStateACookie: await callback(b.callbackPath, b.state, a.flowId),
      bStateNoCookie: await callback(b.callbackPath, b.state, null),
      bStateOnAsAddress: await callback(a.callbackPath, b.state, a.flowId),
      unknownStateBsAddress: await callback(b.callbackPath, unknown, a.flowId),
      unknownStateAsAddress: await callback(a.callbackPath, unknown, a.flowId),
    };
    for (const [name, answer] of Object.entries(answers)) assert.deepEqual([answer.status, answer.body?.error?.code], [400, 'invalid_state'], `${route} ${name}`);
    assert.deepEqual(dump(), before, `${route}: no flow, route, session, account or vault record changed`);
    // B's own browser still finishes its sign-in, and A's too: neither flow was used up.
    const finished = await people.b.person.call('GET', `${b.callbackPath}?${new URLSearchParams({state: b.state, code: 'c-b'})}`);
    assert.deepEqual([finished.status, finished.headers.get('location')], [303, `/connect/${people.b.id}/finish`], `${route}: B's flow still completes`);
    assert.equal(B.repo().get('connectSessions', people.b.id).state, 'awaiting_confirmation');
    assert.equal((await callback(a.callbackPath, a.state, a.flowId)).status, 303, `${route}: A's flow still completes`);
    results.push({route, answers});
  }
  assert.equal(googleRevokes(), 0, 'no revoke at Google for the shared client');
  // One refusal for every case, on both routes: a live state of another environment must not read differently from a
  // state that never existed (no existence oracle).
  const expected = results.map(({route, answers}) => ({route, ...Object.fromEntries(Object.keys(answers).map(name => [name, answers.unknownStateBsAddress]))}));
  assert.deepEqual(results.map(({route, answers}) => ({route, ...answers})), expected, 'every refusal is the unknown state\'s refusal');
});

test('concurrency: two claims of one link leave exactly one winner, for connect, manage and approve links', async t => {
  const {app, A, A1, browser} = await world(t);
  for (const [purpose, body] of [['connect', {appId: 'gmail'}], ['manage', {purpose: 'manage'}], ['approve', {purpose: 'approve', callRef: A1.waiting.callRef}]]) {
    const created = (await A.call('POST', '/v1/connect-sessions', {externalUserId: 'u1', ...body})).body, secret = new URL(created.connectUrl).hash.slice(3);
    const people = [browser(), browser()];
    const answers = await Promise.all(people.map(person => person.call('POST', `/connect/${created.id}/v1/claim`, {secret})));
    assert.deepEqual(answers.map(answer => answer.status).sort(), [200, 409], purpose);
    const winner = answers[0].status === 200 ? 0 : 1, loser = 1 - winner;
    assert.equal(answers[loser].body.error.code, 'session_in_use', purpose);
    assert.equal(people[loser].binding, undefined, `${purpose}: the loser holds no session cookie`);
    assert.equal(A.repo().get('connectSessions', created.id).browserBindingHash, sha(people[winner].binding), `${purpose}: the link is bound to the winner`);
    assert.equal((await people[winner].call('GET', `/connect/${created.id}/v1/view`)).status, 200);
    assert.equal((await people[loser].call('GET', `/connect/${created.id}/v1/view`)).status, 404);
  }
  void app;
});

test('concurrency: two callbacks on one OAuth state at once create at most one account, on both callback addresses', async t => {
  const {A, A2, claimed, gate, start, callback, tokenCalls, until, googleRevokes} = await world(t);
  const created = await A.call('POST', '/v1/provider-apps', {providerId: 'github', clientId: 'dev-alpha', clientSecret: 'dev-alpha-secret', consentScreenName: 'Alpha Agent'});
  assert.equal((await A.call('PUT', '/v1/environment/apps/github', {providerApp: created.body.providerApp.id, enabled: true})).status, 200);
  const cases = [['google', A2.sessions.connect], ['github', await claimed(A, 'u2', {appId: 'github'})]];
  for (const [providerId, session] of cases) {
    const flow = await start(session.person, session.id), exchanges = tokenCalls(providerId);
    // Hold the token exchange so the second callback arrives while the first is still in flight.
    const release = gate(`${providerId}Token`);
    let answered = 0;
    const both = Promise.all([0, 1].map(() => callback(flow.callbackPath, flow.state, flow.flowId).then(answer => { answered++; return answer; })));
    // Released once one callback has answered while the other waits at the provider, or once both reached the provider.
    await until(() => (answered >= 1 && tokenCalls(providerId) > exchanges) || tokenCalls(providerId) - exchanges >= 2, `the ${providerId} callbacks`);
    release();
    const answers = await both;
    assert.deepEqual(answers.map(answer => answer.status).sort(), [303, 400], providerId);
    assert.equal(answers.find(answer => answer.status === 400).body.error.code, 'invalid_state', providerId);
    assert.equal(tokenCalls(providerId) - exchanges, 1, `${providerId}: the code is exchanged once`);
    const made = A.repo().list('connections').filter(item => item.origin?.sessionId === session.id);
    assert.equal(made.length, 1, `${providerId}: one account`);
    assert.equal(A.repo().get('connectSessions', session.id).state, 'awaiting_confirmation');
  }
  assert.equal(googleRevokes(), 0);
});

test('concurrency: two environments starting shared-Google sign-ins at the same moment each get their own flow and their own account', async t => {
  const {app, A, B, A1, B1, gate, start, tokenCalls, until, dump, googleRevokes} = await world(t);
  const people = {A: A1.sessions.connect, B: B1.sessions.connect};
  const [flowA, flowB] = await Promise.all([start(people.A.person, people.A.id), start(people.B.person, people.B.id)]);
  assert.notEqual(flowA.state, flowB.state); assert.notEqual(flowA.flowId, flowB.flowId);
  for (const [env, other, flow, session] of [[A, B, flowA, people.A], [B, A, flowB, people.B]]) {
    const id = sha(flow.state);
    assert.equal(app.registry.get('flowRoutes', id).environmentId, env.dev.id, `${env.name}'s state routes to ${env.name}`);
    assert.equal(env.repo().get('oauthFlows', id).tenant.sessionId, session.id);
    assert.equal(other.repo().get('oauthFlows', id), null, `${other.name} holds nothing of ${env.name}'s flow`);
  }
  // Both callbacks in flight together, each from the browser that started it, with the same simulated Google identity.
  const exchanges = tokenCalls('google'), release = gate('googleToken');
  const back = (session, flow) => session.person.call('GET', `${flow.callbackPath}?${new URLSearchParams({state: flow.state, code: `code-${randomUUID()}`})}`);
  const both = Promise.all([back(people.A, flowA), back(people.B, flowB)]);
  await until(() => tokenCalls('google') - exchanges === 2, 'both token exchanges');
  release();
  const [backA, backB] = await both;
  assert.deepEqual([backA.status, backA.headers.get('location'), backB.status, backB.headers.get('location')], [303, `/connect/${people.A.id}/finish`, 303, `/connect/${people.B.id}/finish`]);
  for (const [env, cellOf, session] of [[A, A1, people.A], [B, B1, people.B]]) {
    const pending = env.repo().list('connections').filter(item => item.identity?.id === 'google-sub-shared');
    assert.equal(pending.length, 1, `${env.name}: one new account`);
    assert.equal(pending[0].origin.sessionId, session.id);
    assert.deepEqual(ownershipOf(pending[0], tenantDeployment(env.repo().scope)), {subjectId: 'u1', userRecordId: cellOf.user.id}, `${env.name}'s own u1`);
  }
  assert.notEqual(A1.user.id, B1.user.id, 'the same external id is two people');
  // Each person confirms in the browser that came back from Google.
  for (const [env, session] of [[A, people.A], [B, people.B]]) {
    const confirmed = await session.person.call('POST', `/connect/${session.id}/v1/confirm`, {});
    assert.deepEqual([confirmed.status, confirmed.body.state], [200, 'connected'], `${env.name}: ${JSON.stringify(confirmed.body)}`);
    const ready = env.repo().list('connections').filter(item => item.identity?.id === 'google-sub-shared' && item.status === 'ready');
    assert.deepEqual(ready.map(item => item.id), [confirmed.body.result.accountRef]);
  }
  const rows = dump(), textOf = label => Object.keys(rows).filter(key => key.startsWith(`${label}/`)).join('\n');
  assert.equal(textOf('A').includes(people.B.id) || textOf('A').includes(sha(flowB.state)), false, 'A holds nothing of B\'s sign-in');
  assert.equal(textOf('B').includes(people.A.id) || textOf('B').includes(sha(flowA.state)), false, 'B holds nothing of A\'s sign-in');
  assert.equal(googleRevokes(), 0, 'no revoke at Google for the shared client');
});

test('in-memory maps: after A\'s traffic (waiting reads, refusals, running calls) no key belongs to B, and A\'s waiters never slow B', async t => {
  const {app, gate, agent, A, B, A1, B1, until} = await world(t);
  const maps = () => ({...app.executions[TEST_MAPS](), ...app.runtimes[TEST_MAPS]()});
  assert.deepEqual(maps(), {waiting: [], refusals: [], inflight: []}, 'nothing in flight before the traffic');
  const release = gate('gmailRead');
  const read = (env, cell) => env.call('POST', '/v1/executions', {externalUserId: cell.externalUserId, accountRef: cell.accountRef, capabilityId: cell.read.id, definitionHash: cell.read.definitionHash, args: {userId: 'me', id: 'm-1'}}, {'Idempotency-Key': randomUUID()});
  // A: a running call from the developer's key and one from A/u1's agent, held at the provider.
  const running = await read(A, A1);
  assert.equal(running.status, 202, JSON.stringify(running.body));
  const agentCall = agent(A1.token, 'calls.create', {connectionId: A1.alias, capabilityId: A1.read.id, definitionHash: A1.read.definitionHash, args: {userId: 'me', id: 'm-1'}});
  await until(() => maps().inflight.length === 2, 'two running calls');
  // A: 16 reads waiting with one key, the most a key may have; the next is told to come back.
  const waiters = Array.from({length: 16}, () => A.call('GET', `/v1/executions/${running.body.callRef}?waitMs=20000`));
  await until(async () => (await A.call('GET', `/v1/executions/${running.body.callRef}?waitMs=1`)).status === 429, 'A\'s key at its waiting limit');
  // A: a refused proxied request, counted against A's service client.
  const refused = await A.call('POST', '/v1/proxy/requests', {externalUserId: 'u1', appId: 'gmail', request: {method: 'GET', path: '/gmail/v1/users/me/../../x'}}, {'Idempotency-Key': randomUUID()});
  assert.equal(refused.status, 400, JSON.stringify(refused.body));
  const seen = maps(), aJobs = new Set(A.repo().list('jobs').map(job => job.id));
  assert.deepEqual(seen.waiting, [A.key.keyId], 'one waiting count, A\'s key');
  assert.deepEqual(seen.refusals, [`${A.dev.id}:${A.key.serviceClientId}`], 'one refusal window, A\'s client');
  assert.equal(seen.inflight.length, 2);
  for (const key of seen.inflight) { assert.ok(key.startsWith(`${A.scopeKey}:`), key); assert.ok(aJobs.has(key.slice(A.scopeKey.length + 1)), key); }
  const bJobs = B.repo().list('jobs').map(job => job.id), bIds = [B.dev.id, B.project.id, B.scopeKey, ...B.keys.flatMap(key => [key.keyId, key.serviceClientId]), ...bJobs, B1.tokenId];
  for (const key of [...seen.waiting, ...seen.refusals, ...seen.inflight]) for (const id of bIds) assert.equal(key.includes(id), false, `${key} holds ${id} of B`);
  // B's own key is not slowed by A's: B's running call can still be waited on, never 429.
  const bRunning = await read(B, B1);
  assert.equal(bRunning.status, 202);
  const bWaited = await B.call('GET', `/v1/executions/${bRunning.body.callRef}?waitMs=50`);
  assert.equal(bWaited.status, 202, JSON.stringify(bWaited.body));
  release();
  const settled = await Promise.all(waiters);
  assert.ok(settled.every(answer => answer.status === 200), JSON.stringify(settled.map(answer => answer.status)));
  assert.equal((await agentCall).body.result.status, 'succeeded');
  await app.runtimes.drain();
  await until(() => maps().waiting.length === 0 && maps().inflight.length === 0, 'the maps to empty');
  assert.deepEqual(maps().refusals, [`${A.dev.id}:${A.key.serviceClientId}`], 'only A\'s refusal window remains');
});

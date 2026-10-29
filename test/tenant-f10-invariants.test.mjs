import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {relayAppRedirect} from '../lib/oauth-relay.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';

// F03.11 exit check 5 (docs/F03-DEVELOPER-LAYER.md section 9, section 4.3): F10's invariants hold inside a developer
// environment, for the parts that were proven only in local mode before. T2: a sign-in that gets less than it asked for
// ends failed, with nothing stored and nothing waiting. T5: an approval binds the exact bytes the provider receives, and
// a call changed after its digest was shown is refused, on the developer relay and on Fabric's approve page. T6: a
// developer's own Slack and Notion sign-in addresses match a fixed golden. T1: no session and no page start can name a
// scope. And the tenant row's etag is checked before the developer's ceiling.
const BASE = 'https://connect.example.com';
const GMAIL = [['gmail.users.messages.get', 'get', '/gmail/v1/users/{userId}/messages/{id}'], ['gmail.users.messages.send', 'post', '/gmail/v1/users/{userId}/messages/send']];
const SEND_URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send';

function seed(root) {
  const paths = {};
  for (const [id, method, route] of GMAIL) paths[route] = {[method]: {operationId: id, parameters: [...route.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})),
    ...(method === 'post' ? {requestBody: {content: {'application/json': {schema: {type: 'object', properties: {raw: {type: 'string'}}}}}}} : {}), responses: {200: {description: 'OK'}}}};
  const compiled = compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'Gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}}).capabilities;
  const store = new PlatformStore({root}), operations = [];
  for (const [id, method, route] of GMAIL) {
    const capability = compiled.find(item => item.request.method === method.toUpperCase() && item.request.url === `https://gmail.googleapis.com${route}`);
    store.put('capabilities', {...capability, status: 'active'});
    operations.push({id, capabilityId: capability.id, method: method.toUpperCase(), path: route, sensitive: null});
  }
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', classifierVersion: SENSITIVITY_VERSION, operations});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-f10-'));
  seed(root);
  // The simulated providers record every request exactly as Fabric hands it over: method, URL and body bytes.
  const sim = {calls: [], grant: {github: '', google: ''}};
  const request = async req => {
    sim.calls.push({method: req.method || 'GET', url: req.url, body: req.body});
    if (req.url === 'https://github.com/login/oauth/access_token') return {status: 200, headers: {}, data: {access_token: `gho_${randomUUID()}`, token_type: 'bearer', scope: sim.grant.github}};
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: {id: 42, login: 'octo', name: 'Octo'}};
    if (req.url === 'https://oauth2.googleapis.com/token') return {status: 200, headers: {}, data: {access_token: `ya29.${randomUUID()}`, refresh_token: '1//refresh', token_type: 'Bearer', expires_in: 3600, scope: sim.grant.google}};
    if (req.url === 'https://openidconnect.googleapis.com/v1/userinfo') return {status: 200, headers: {}, data: {sub: 'g-sub-1', email: 'one@example.com', name: 'One'}};
    if (req.url === 'https://oauth2.googleapis.com/revoke') return {status: 200, headers: {}, data: {}};
    if (req.url.startsWith(SEND_URL)) return {status: 200, headers: {}, data: {id: 'sent-1', threadId: 't-1'}};
    if (req.url.startsWith('https://gmail.googleapis.com/gmail/v1/users/')) return {status: 200, headers: {}, data: {id: 'm-1', emailAddress: 'one@example.com'}};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, relay: {base: BASE, appsReady: true},
    providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}, google: {clientId: 'g-client', clientSecret: 'g-secret'}}});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
  const keys = {full: app.keys.mint({environmentId: dev.id, preset: 'full'}), standard: app.keys.mint({environmentId: dev.id, preset: 'standard'}), approve: app.keys.mint({environmentId: dev.id, scopes: ['connect:approve']})};
  const call = async (key, method, route, body, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key.token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    const text = await response.text();
    return {status: response.status, body: text ? JSON.parse(text) : null};
  };
  const repo = () => app.stores.open(scope).repository;
  /** A person with one ready Gmail account on Fabric's shared Google app. */
  const account = async externalUserId => {
    await call(keys.standard, 'POST', '/v1/connect-sessions', {externalUserId});
    const user = repo().list('endUsers').find(item => item.subjectId === externalUserId && item.status === 'active'), id = randomUUID(), now = app.registry.now();
    repo().put('connections', stampOwner({id, appId: 'gmail', providerId: 'google', driver: 'http', status: 'ready', authMethod: 'oauth', identity: {id: `g-${externalUserId}`, displayName: `${externalUserId}@example.com`}, label: `${externalUserId}@example.com`,
      allowedOrigins: ['https://gmail.googleapis.com'], scopes: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify'], createdAt: now, updatedAt: now, authRevision: randomUUID(), providerApp: {kind: 'shared'}},
    {subjectId: externalUserId, userRecordId: user.id}));
    app.stores.open(scope).vault.set(id, {accessToken: 'ya29.f10', refreshToken: '1//r', expiresAt: Date.parse(now) + 3600_000});
    return id;
  };
  /** A Gmail send that waits for the person's decision (send defaults to Ask). */
  const ask = async (externalUserId, raw) => {
    const send = (await call(keys.standard, 'GET', '/v1/capabilities?appId=gmail')).body.capabilities.find(item => item.id.includes('messages-send'));
    const created = await call(keys.standard, 'POST', '/v1/executions', {externalUserId, capabilityId: send.id, definitionHash: send.definitionHash, args: {userId: 'me', body: {raw}}}, {'Idempotency-Key': randomUUID()});
    assert.equal(created.body.status, 'awaiting_approval', JSON.stringify(created.body));
    return created.body;
  };
  /** A browser on Fabric's page: its own cookies, Sec-Fetch-Site, the exact Origin, and the CSRF value from claim or view. */
  const browser = () => {
    const jar = new Map();
    let csrf = null;
    return {jar, async call(method, route, body) {
      const cookie = [...jar].filter(([, value]) => value).map(([name, value]) => `${name}=${value}`).join('; ');
      const response = await fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(cookie ? {Cookie: cookie} : {}), ...(body !== undefined ? {'Content-Type': 'application/json', Origin: app.origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      for (const line of response.headers.getSetCookie()) { const [pair] = line.split(';'), at = pair.indexOf('='); jar.set(pair.slice(0, at), pair.slice(at + 1)); }
      const parsed = (response.headers.get('content-type') || '').includes('json') ? await response.json() : await response.text();
      if (typeof parsed?.csrf === 'string') csrf = parsed.csrf;
      return {status: response.status, headers: response.headers, body: parsed};
    }};
  };
  /** Mints a link with this key and opens it in a fresh browser: the page's own calls for that link. */
  const open = async (key, body) => {
    const created = await call(key, 'POST', '/v1/connect-sessions', body);
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const person = browser(), id = created.body.id;
    const claimed = await person.call('POST', `/connect/${id}/v1/claim`, {secret: new URL(created.body.connectUrl).hash.slice(3)});
    assert.equal(claimed.status, 200, JSON.stringify(claimed.body));
    return {id, person, get: (action, query = '') => person.call('GET', `/connect/${id}/v1/${action}${query}`), post: (action, body = {}) => person.call('POST', `/connect/${id}/v1/${action}`, body)};
  };
  const sends = () => sim.calls.filter(item => item.url.startsWith(SEND_URL));
  return {app, sim, scope, keys, call, repo, account, ask, open, sends};
}

const sha256 = value => createHash('sha256').update(value).digest('hex');
const blockOf = (exact, label) => exact.blocks.find(block => block.label === label)?.text;
/** The address with only its state and PKCE challenge values replaced; every other byte stays as built. */
const golden = address => address.replace(/([?&]state=)[^&]*/, '$1<state>').replace(/([?&]code_challenge=)[^&]*/, '$1<challenge>');
/** Every query parameter but state and the PKCE challenge, in order. */
const paramsOf = address => [...new URL(address).searchParams].filter(([name]) => !['state', 'code_challenge'].includes(name));

for (const [providerId, appId, level, grant] of [
  ['github', 'github', undefined, 'read:user'],
  ['google', 'gmail', undefined, 'openid email https://www.googleapis.com/auth/gmail.readonly'],
]) {
  test(`T2 required or nothing: a ${appId} sign-in granted less than it asked for fails with insufficient_scope; nothing is stored and nothing waits`, async t => {
    const {app, sim, keys, call, repo, open} = await setup(t);
    const page = await open(keys.full, {externalUserId: 'u-t2', appId, errorRedirectUri: 'http://localhost:5173/back'});
    assert.ok((await page.get('view')).body.sheet, 'the person sees the consent sheet first');
    const started = await page.post('start', level ? {level} : {});
    assert.equal(started.status, 200, JSON.stringify(started.body));
    const address = new URL(started.body.authorizationUrl), definition = definitionFor(providerId);
    const asked = address.searchParams.get('scope').split(definition.authorization.scopeSeparator);
    const granted = grant.split(' ');
    assert.ok(asked.some(scope => !granted.includes(scope)), `the grant must fall short of what was asked: ${asked}`);
    sim.grant[providerId] = granted.join(definition.token.scopeSeparator);
    const exchanges = sim.calls.length;
    const back = await fetch(`${app.origin}/api/oauth/${providerId}/callback?state=${encodeURIComponent(address.searchParams.get('state'))}&code=c`, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${page.person.jar.get('fabric_t_oauth')}`}});
    assert.equal(back.status, 303);
    assert.equal(back.headers.get('location'), `/connect/${page.id}/finish`);
    assert.equal(back.headers.getSetCookie().some(line => line.startsWith('fabric_t_finish=') && !line.startsWith('fabric_t_finish=;')), false, 'no finish value: there is nothing to confirm');
    assert.ok(sim.calls.slice(exchanges).some(item => item.url === definition.token.url), 'the code was exchanged, so the short grant really came back');
    // The developer and the person both read how it ended.
    const session = (await call(keys.full, 'GET', `/v1/connect-sessions/${page.id}`)).body;
    assert.equal(session.state, 'failed');
    assert.deepEqual(session.result, {errorCode: 'insufficient_scope'});
    const view = (await page.get('view')).body;
    assert.deepEqual([view.state, view.errorCode], ['failed', 'insufficient_scope']);
    assert.match(view.redirect, /[?&]error=insufficient_scope(&|$)/);
    // Nothing stored and nothing waiting: no account (not even one waiting for confirmation), no flow, no route.
    assert.deepEqual(repo().list('connections'), []);
    assert.deepEqual(repo().list('oauthFlows'), []);
    assert.equal(app.registry.get('flowRoutes', sha256(address.searchParams.get('state'))), null);
    const confirm = await page.post('confirm');
    assert.deepEqual([confirm.status, confirm.body.error.code], [409, 'already_finished']);
    const again = await page.post('start', {});
    assert.equal(again.status, 409, 'the failed link cannot start another sign-in');
    assert.deepEqual(repo().list('connections'), []);
  });
}

test('T5 approval binds bytes: a call approved with the digest shown runs once, and the provider receives exactly the request shown', async t => {
  const {keys, call, repo, account, ask, open, sends} = await setup(t);
  await account('u1');
  // A body with quotes, a line break, an accent and a direction override: shown and sent byte for byte, never cleaned.
  const RAW = 'Subject: "hi"\nBody: café ‮evil';
  // The developer relay: the shown approval, decided with its own digest.
  const waiting = await ask('u1', RAW);
  const item = (await call(keys.full, 'GET', '/v1/users/u1/approvals')).body.approvals.find(entry => entry.callRef === waiting.callRef);
  assert.equal(item.exact.complete, true);
  const decided = await call(keys.full, 'POST', `/v1/users/u1/approvals/${waiting.callRef}/decision`, {decision: 'approve', digest: item.digest});
  assert.ok([200, 202].includes(decided.status), JSON.stringify(decided.body));
  const ran = (await call(keys.full, 'GET', `/v1/executions/${waiting.callRef}?waitMs=5000`)).body;
  assert.equal(ran.status, 'uncertain', 'a write ran, and is never reported done without proof');
  assert.equal(sends().length, 1, 'sent once');
  const [sent] = sends();
  assert.equal(`${sent.method} ${sent.url}`, blockOf(item.exact, 'Request'));
  assert.equal(typeof sent.body, 'string');
  assert.equal(sent.body, blockOf(item.exact, 'Body'), 'the provider received exactly the body that was approved');
  assert.equal(JSON.parse(sent.body).raw, RAW);
  // Fabric's approve page: the same binding, through the person's own decision.
  const second = await ask('u1', `${RAW} 2`);
  const page = await open(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: second.callRef});
  const shown = (await page.get('approval')).body.approval;
  assert.equal(shown.exact.complete, true);
  const approved = await page.post(`approvals/${second.callRef}/decision`, shown.approve.body);
  assert.equal(approved.status, 200, JSON.stringify(approved.body));
  assert.equal((await call(keys.full, 'GET', `/v1/executions/${second.callRef}?waitMs=5000`)).body.status, 'uncertain');
  assert.equal(sends().length, 2);
  const last = sends()[1];
  assert.equal(`${last.method} ${last.url}`, blockOf(shown.exact, 'Request'));
  assert.equal(last.body, blockOf(shown.exact, 'Body'));
  assert.equal(JSON.parse(last.body).raw, `${RAW} 2`);
  assert.equal(repo().get('jobs', second.callRef).decision.decidedIn, 'fabric_page');
});

test('T5 approval binds bytes: a call whose arguments change after its digest was shown is refused on the relay and on Fabric\'s approve page; nothing reaches the provider', async t => {
  const {app, keys, call, repo, account, ask, open, sends} = await setup(t);
  await account('u1');
  const tamper = callRef => { const job = repo().get('jobs', callRef); repo().put('jobs', {...job, args: {...job.args, body: {raw: 'eB, not what was shown'}}}); };
  const refusedCodes = ['digest_mismatch', 'authority_changed'];
  // The developer relay.
  const relayed = await ask('u1', 'eA');
  const item = (await call(keys.full, 'GET', '/v1/users/u1/approvals')).body.approvals.find(entry => entry.callRef === relayed.callRef);
  tamper(relayed.callRef);
  const refused = await call(keys.full, 'POST', `/v1/users/u1/approvals/${relayed.callRef}/decision`, {decision: 'approve', digest: item.digest});
  assert.equal(refused.status, 409, JSON.stringify(refused.body));
  assert.ok(refusedCodes.includes(refused.body.error.code), refused.body.error.code);
  // Fabric's approve page: the person was shown the call, then it changed underneath.
  const paged = await ask('u1', 'eA');
  const page = await open(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: paged.callRef});
  const shown = (await page.get('approval')).body.approval;
  assert.ok(shown.approve, 'the call could be approved as shown');
  tamper(paged.callRef);
  const pageRefused = await page.post(`approvals/${paged.callRef}/decision`, shown.approve.body);
  assert.equal(pageRefused.status, 409, JSON.stringify(pageRefused.body));
  assert.ok(refusedCodes.includes(pageRefused.body.error.code), pageRefused.body.error.code);
  assert.notEqual((await call(keys.full, 'GET', `/v1/connect-sessions/${page.id}`)).body.state, 'completed', 'a refused decision does not finish the link');
  await app.runtimes.drain();
  await new Promise(resolve => setTimeout(resolve, 50));
  for (const callRef of [relayed.callRef, paged.callRef]) {
    const job = repo().get('jobs', callRef);
    assert.equal(job.status, 'awaiting_approval', `${callRef} was not decided`);
    assert.equal(job.approvedAt ?? null, null);
  }
  assert.equal(sends().length, 0, 'nothing reached the provider');
});

// F10.7 (critique 5): the catalog is version 2, so this compares the developer runtime with the single-owner runtime under version 2.
// Version 1 URL stability (T6) stays proven at adapter level through test/fixtures/auth-v1 (test/auth-v2.test.mjs).
test('under version 2 a developer\'s own Slack and Notion apps build the single-owner runtime\'s address, apart from state', async t => {
  const {keys, call, open} = await setup(t);
  const local = mkdtempSync(path.join(tmpdir(), 'fabric-f10-t6-'));
  const store = new Store({dataDir: local}), vault = new Vault(local);
  t.after(() => { store.close(); rmSync(local, {recursive: true, force: true}); });
  const register = async providerId => {
    const created = await call(keys.full, 'POST', '/v1/provider-apps', {providerId, clientId: `dev-${providerId}-client`, clientSecret: `dev-${providerId}-secret`, consentScreenName: 'Acme Agent'});
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const id = created.body.providerApp.id;
    assert.match(id, /^pa_[a-z2-7]{26}$/);
    assert.equal(created.body.redirectUri, `${BASE}/oauth/${providerId}/apps/${id}/callback`);
    assert.equal((await call(keys.full, 'PUT', `/v1/environment/apps/${providerId}`, {providerApp: id, enabled: true})).body.enabled, true);
    return id;
  };
  const slack = await register('slack'), notion = await register('notion');
  // Slack's full level asks for its required and optional user scopes (testing consent), never the in-context ones; it has no read level.
  const {full} = definitionFor('slack').apps[0].access.levels, SLACK_FULL = encodeURIComponent([...full.required, ...full.optional].join(','));
  const slackAt = userScope => `https://slack.com/oauth/v2/authorize?client_id=dev-slack-client&redirect_uri=https%3A%2F%2Fconnect.example.com%2Foauth%2Fslack%2Fapps%2F${slack}%2Fcallback&response_type=code&user_scope=${userScope}&state=<state>`;
  const cases = [
    ['slack', slack, undefined, slackAt(SLACK_FULL)],
    ['slack', slack, 'read_write', slackAt(SLACK_FULL)],
    ['notion', notion, undefined, `https://api.notion.com/v1/oauth/authorize?client_id=dev-notion-client&redirect_uri=https%3A%2F%2Fconnect.example.com%2Foauth%2Fnotion%2Fapps%2F${notion}%2Fcallback&response_type=code&owner=user&state=<state>`],
  ];
  for (const [providerId, providerAppId, level, expected] of cases) {
    const page = await open(keys.full, {externalUserId: 'u-t6', appId: providerId});
    const started = await page.post('start', level ? {level} : {});
    assert.equal(started.status, 200, JSON.stringify(started.body));
    const address = started.body.authorizationUrl, url = new URL(address);
    assert.equal(golden(address), expected, `${providerId} ${level ?? 'default'}`);
    assert.equal(`${url.origin}${url.pathname}`, expected.split('?')[0]);
    assert.deepEqual(paramsOf(address), paramsOf(expected.replace('<state>', 'x')), 'every other parameter, in order');
    assert.equal(url.searchParams.getAll('state').length, 1); assert.match(url.searchParams.get('state'), /^[A-Za-z0-9_-]{43}$/);
    assert.equal(url.searchParams.has('code_challenge'), false, 'neither provider uses PKCE');
    // The single-owner adapter for the same client and the same relay address builds the same bytes (F10's T6).
    const single = new OAuth2Provider(definitionFor(providerId), {store, vault, connections: new ConnectionManager({store, vault}), clientId: `dev-${providerId}-client`, clientSecret: `dev-${providerId}-secret`,
      redirectUri: relayAppRedirect(BASE, providerId, providerAppId), allowHostedRedirect: true, publishing: 'testing'});
    assert.equal(golden(single.start({appId: providerId, level: level === 'read' ? 'read' : 'full'}).authorizationUrl), expected, `single-owner ${providerId} ${level ?? 'default'}`);
  }
});

test('T1 never request: a Connect session cannot name a scope, and a page start asks only for the reviewed scopes whatever its body carries', async t => {
  const {keys, call, repo, open} = await setup(t);
  for (const extra of [{scopes: ['delete_repo']}, {scope: 'admin:org'}, {userScopes: ['admin:org']}, {scopes: []}]) {
    const refused = await call(keys.full, 'POST', '/v1/connect-sessions', {externalUserId: 'u-t1', appId: 'github', ...extra});
    assert.deepEqual([refused.status, refused.body.error.code], [400, 'invalid_request'], JSON.stringify(extra));
    assert.match(refused.body.error.message, new RegExp(`field: ${Object.keys(extra)[0]}`));
  }
  assert.equal(repo().list('endUsers').some(user => user.subjectId === 'u-t1'), false, 'a refused request creates no one');
  assert.deepEqual(repo().list('connectSessions').filter(session => session.ownership?.owner?.id === 'u-t1'), []);
  // F10.7: GitHub's version 2 full level, asked for whole under the testing consent policy; it has no read level, so read is refused.
  const {full} = definitionFor('github').apps.find(entry => entry.appId === 'github').access.levels, reviewed = [...full.required, ...full.optional], separator = definitionFor('github').authorization.scopeSeparator;
  assert.equal((await (await open(keys.full, {externalUserId: 'u-t1b', appId: 'github'})).post('start', {level: 'read'})).status, 400, 'GitHub has no read level');
  const EXTRA = {scopes: ['admin:org', 'delete_repo'], scope: 'admin:org delete_repo', user_scope: 'admin:org', userScopes: ['admin:org'], requestedScopes: ['delete_repo']};
  for (const [level, expected] of [[undefined, reviewed], ['full', reviewed]]) {
    const plain = await open(keys.full, {externalUserId: 'u-t1b', appId: 'github'}), loaded = await open(keys.full, {externalUserId: 'u-t1b', appId: 'github'});
    const base = (await plain.post('start', level ? {level} : {})).body.authorizationUrl;
    const extra = await loaded.post('start', {...(level ? {level} : {}), appId: 'github', ...EXTRA});
    assert.equal(new URL(base).searchParams.get('scope'), expected.join(separator), 'the reviewed level');
    if (extra.status === 200) {
      const address = extra.body.authorizationUrl;
      assert.equal(new URL(address).searchParams.get('scope'), expected.join(separator), `level ${level ?? 'default'}: only the reviewed scopes`);
      assert.deepEqual(paramsOf(address), paramsOf(base), 'no parameter added or changed');
      assert.equal(/admin(%3A|:)org|delete_repo/.test(address), false);
    } else {
      assert.equal(extra.status, 400, JSON.stringify(extra.body));
      assert.equal((await call(keys.full, 'GET', `/v1/connect-sessions/${loaded.id}`)).body.state, 'opened', 'a refused start starts nothing');
    }
  }
});

test('the tenant row etag is checked before the ceiling: a stale etag asking above an Ask ceiling answers etag_mismatch', async t => {
  const {keys, call, account, open} = await setup(t);
  const ref = await account('u1');
  const ROW = 'gmail.messages.read';
  assert.equal((await call(keys.full, 'PUT', '/v1/environment/apps/gmail', {ceilings: {[ROW]: 'ask'}})).status, 200);
  const rowOf = async () => (await call(keys.full, 'GET', `/v1/users/u1/apps/gmail?account=${ref}`)).body.sections.flatMap(section => section.rows).find(row => row.groupId === ROW);
  const set = body => call(keys.full, 'POST', `/v1/users/u1/accounts/${ref}/permissions`, {groupId: ROW, ...body});
  const shown = await rowOf();
  assert.deepEqual(shown.allowedModes, ['ask', 'deny'], 'the Ask ceiling holds');
  assert.equal((await set({mode: 'deny', etag: shown.etag})).status, 200);
  const current = await rowOf();
  assert.notEqual(current.etag, shown.etag, 'the etag moved on');
  // Stale etag and a mode above the ceiling: the etag answers first.
  const stale = await set({mode: 'allow', etag: shown.etag});
  assert.deepEqual([stale.status, stale.body.error.code], [409, 'etag_mismatch'], JSON.stringify(stale.body));
  const staleConfirmed = await set({mode: 'allow', etag: shown.etag, confirmAllow: true});
  assert.deepEqual([staleConfirmed.status, staleConfirmed.body.error.code], [409, 'etag_mismatch']);
  // Controls: the ceiling still refuses a fresh etag, and a stale etag is refused for an allowed mode too.
  const above = await set({mode: 'allow', etag: current.etag});
  assert.deepEqual([above.status, above.body.error.code], [409, 'mode_not_allowed']);
  const staleAllowed = await set({mode: 'ask', etag: shown.etag});
  assert.deepEqual([staleAllowed.status, staleAllowed.body.error.code], [409, 'etag_mismatch']);
  assert.deepEqual([(await rowOf()).mode, (await rowOf()).etag], ['deny', current.etag], 'nothing changed');
  // Fabric's manage page goes through the same check, in the same order.
  const page = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'});
  const onPage = await page.post(`apps/gmail/accounts/${ref}/permissions`, {groupId: ROW, mode: 'allow', etag: shown.etag});
  assert.deepEqual([onPage.status, onPage.body.error.code], [409, 'etag_mismatch'], JSON.stringify(onPage.body));
  assert.equal((await rowOf()).mode, 'deny');
});

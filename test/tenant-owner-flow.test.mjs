import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash, randomBytes, randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {hostedSetup} from './fixtures/hosted-fixture.mjs';
import {PAGE_ACTIONS, CALLBACK_ROUTES} from '../lib/tenant/page-routes.mjs';

// F03.11 exit check 2 (docs/F03-DEVELOPER-LAYER.md section 9, N4 and N10): the owner comes from the flow, for every
// purpose. Opening a connect, manage or approve link checks the secret first, then expiry, then the browser; two
// browsers opening one link at once leave one winner; the hosted manage and approval data routes answer only the
// browser that opened their own link; a session cookie that rides along with a provider callback never decides whose
// account it is; and one browser holding two links keeps them apart, each cookie on its own path.
const sha256 = value => createHash('sha256').update(value).digest('hex');
const csrfOf = binding => sha256(`csrf:${binding}`);
const secretOf = url => new URL(url).hash.slice(3);
const NOT_FOUND = {error: {code: 'not_found', message: 'Nothing with that id exists here.'}};
const MALFORMED = {error: {code: 'invalid_request', message: 'Malformed cookies.'}};
const UNKNOWN_SESSION = `cs_${'a'.repeat(26)}`;

/** One request the way a page in a browser sends it, with exactly the cookie and CSRF value given. */
async function pageRequest(origin, method, route, {cookie, csrf, body} = {}) {
  const post = method !== 'GET';
  const response = await fetch(`${origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(cookie !== undefined ? {Cookie: cookie} : {}),
    ...(post ? {'Content-Type': 'application/json', Origin: origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {})}, ...(post ? {body: JSON.stringify(body ?? {})} : {})});
  const text = await response.text();
  return {status: response.status, text, body: text ? JSON.parse(text) : null, headers: response.headers};
}

/**
 * A browser that keeps cookies the way a browser does (RFC 6265 5.1.4 and 5.3): by name and Path, replaced on the same
 * name and path, dropped on Max-Age=0, and sent only to requests under their own path. The page's CSRF value is held per
 * session, as each page keeps its own. Every Cookie header sent is recorded.
 */
function pathBrowser(origin) {
  const jar = [], sent = [], csrf = new Map();
  const under = (cookiePath, requestPath) => requestPath === cookiePath || (requestPath.startsWith(cookiePath) && (cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/'));
  const defaultPath = requestPath => { const at = requestPath.lastIndexOf('/'); return at <= 0 ? '/' : requestPath.slice(0, at); };
  const sessionOf = requestPath => /^\/connect\/(cs_[a-z2-7]{26})(?:\/|$)/.exec(requestPath)?.[1] ?? null;
  const remember = (line, requestPath) => {
    const [pair, ...parts] = line.split(';'), at = pair.indexOf('='), name = pair.slice(0, at).trim(), value = pair.slice(at + 1).trim();
    const attributes = new Map(parts.map(part => { const eq = part.indexOf('='); return eq < 0 ? [part.trim().toLowerCase(), ''] : [part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim()]; }));
    const cookiePath = attributes.get('path')?.startsWith('/') ? attributes.get('path') : defaultPath(requestPath);
    const existing = jar.findIndex(cookie => cookie.name === name && cookie.path === cookiePath);
    if (existing >= 0) jar.splice(existing, 1);
    if (attributes.has('max-age') && Number(attributes.get('max-age')) <= 0) return;
    jar.push({name, value, path: cookiePath});
  };
  return {
    jar, sent,
    value(name, cookiePath) { return jar.find(cookie => cookie.name === name && cookie.path === cookiePath)?.value; },
    csrfFor(sessionId) { return csrf.get(sessionId); },
    async call(method, route, body, headers = {}) {
      const requestPath = new URL(route, origin).pathname, session = sessionOf(requestPath), token = session && csrf.get(session);
      const cookie = jar.filter(item => under(item.path, requestPath)).sort((a, b) => b.path.length - a.path.length).map(item => `${item.name}=${item.value}`).join('; ');
      const all = {'Sec-Fetch-Site': 'same-origin', ...(cookie ? {Cookie: cookie} : {}), ...(body !== undefined ? {'Content-Type': 'application/json', Origin: origin, ...(token ? {'X-Fabric-CSRF': token} : {})} : {}), ...headers};
      sent.push({path: requestPath, session, cookie: all.Cookie ?? null, crafted: headers.Cookie !== undefined});
      const response = await fetch(`${origin}${route}`, {method, redirect: 'manual', headers: all, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      for (const line of response.headers.getSetCookie()) remember(line, requestPath);
      const type = response.headers.get('content-type') || '', parsed = type.includes('json') ? await response.json() : await response.text();
      if (session && typeof parsed?.csrf === 'string') csrf.set(session, parsed.csrf);
      return {status: response.status, headers: response.headers, body: parsed};
    },
  };
}

/** A developer environment that signs people in to GitHub against a simulated provider (each sign-in a new identity). */
async function signinWorld(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-owner-flow-'));
  const sim = {calls: [], grant: '', people: 0};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://github.com/login/oauth/access_token') return {status: 200, headers: {}, data: {access_token: `gho_${randomUUID()}`, token_type: 'bearer', scope: sim.grant}};
    if (req.url === 'https://api.github.com/user') { sim.people += 1; return {status: 200, headers: {}, data: {id: 5000 + sim.people, login: `octo-${sim.people}`, name: 'Octo'}}; }
    if (req.url.startsWith('https://api.github.com/applications/')) return {status: 204, headers: {}, data: null};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: {github: {clientId: 'gh-shared', clientSecret: 'gh-shared-secret'}}, request});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const api = async (method, route, body) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    const text = await response.text();
    return {status: response.status, body: text ? JSON.parse(text) : null};
  };
  const link = async (externalUserId, extra = {appId: 'github'}) => {
    const created = await api('POST', '/v1/connect-sessions', {externalUserId, ...extra});
    assert.equal(created.status, 201, JSON.stringify(created.body));
    return {id: created.body.id, secret: secretOf(created.body.connectUrl)};
  };
  const repo = () => app.stores.open(scope).repository;
  const userOf = subjectId => repo().list('endUsers').find(item => item.subjectId === subjectId && item.status === 'active');
  /** Connect on Fabric's page: the provider address, with the simulator set to grant exactly what was asked. */
  const startSignIn = async (person, id) => {
    const started = await person.call('POST', `/connect/${id}/v1/start`, {});
    assert.equal(started.status, 200, JSON.stringify(started.body));
    const url = new URL(started.body.authorizationUrl);
    sim.grant = (url.searchParams.get('scope') || '').split(' ').filter(Boolean).join(',');
    return {state: url.searchParams.get('state'), callbackPath: new URL(url.searchParams.get('redirect_uri')).pathname};
  };
  return {app, sim, api, link, repo, userOf, startSignIn, scope};
}

test('claim order on manage and approve links (and connect): a wrong secret is not_found even when expired or claimed; then expired; then session_in_use', async t => {
  const {keys, call, repo, account, ask, browser, advance, app} = await hostedSetup(t);
  await account('u1', 'g-1');
  const waiting = await ask('u1');
  const kinds = {manage: [keys.manage, {purpose: 'manage'}], approve: [keys.approve, {purpose: 'approve', callRef: waiting.callRef}], connect: [keys.full, {appId: 'github'}]};
  const links = {};
  for (const [purpose, [key, body]] of Object.entries(kinds)) {
    const mint = async () => { const created = await call(key, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', expiresInSeconds: 120, ...body}); assert.equal(created.status, 201, JSON.stringify(created.body)); return {id: created.body.id, secret: secretOf(created.body.connectUrl)}; };
    links[purpose] = {claimed: await mint(), unclaimed: await mint(), owner: browser(), other: browser()};
  }
  const claim = (person, id, secret) => person.call('POST', `/connect/${id}/v1/claim`, {secret});
  const unknown = await claim(browser(), UNKNOWN_SESSION, links.manage.claimed.secret);
  assert.equal(unknown.status, 404); assert.deepEqual(unknown.body, NOT_FOUND);
  for (const [purpose, {claimed, owner, other}] of Object.entries(links)) {
    // Live and unclaimed: a wrong secret opens nothing and binds nothing.
    const wrongLive = await claim(other, claimed.id, 'x'.repeat(43));
    assert.equal(wrongLive.status, 404, purpose); assert.deepEqual(wrongLive.body, NOT_FOUND);
    assert.equal(repo().get('connectSessions', claimed.id).browserBindingHash, null, `${purpose}: nothing bound`);
    assert.equal(other.binding, undefined);
    assert.equal((await claim(owner, claimed.id, claimed.secret)).status, 200, purpose);
    const bound = repo().get('connectSessions', claimed.id);
    assert.equal(bound.browserBindingHash, sha256(owner.binding));
    // Claimed: a wrong secret is still not_found, from another browser and from the owner's own; the right one is in use.
    for (const person of [other, owner]) { const wrong = await claim(person, claimed.id, randomBytes(32).toString('base64url')); assert.equal(wrong.status, 404, purpose); assert.deepEqual(wrong.body, NOT_FOUND); }
    const inUse = await claim(other, claimed.id, claimed.secret);
    assert.equal(inUse.status, 409, purpose); assert.equal(inUse.body.error.code, 'session_in_use');
    assert.equal(other.binding, undefined, `${purpose}: the loser gets no cookie`);
    const again = await claim(owner, claimed.id, claimed.secret);
    assert.equal(again.status, 200, `${purpose}: the same browser may come back`);
    assert.deepEqual(repo().get('connectSessions', claimed.id), bound, `${purpose}: refusals and the return wrote nothing`);
  }
  advance(121_000);
  for (const [purpose, {claimed, unclaimed, owner, other}] of Object.entries(links)) {
    const before = JSON.stringify([repo().get('connectSessions', claimed.id), repo().get('connectSessions', unclaimed.id)]);
    // Expired and claimed: wrong secret first, then expiry before "in use".
    for (const person of [other, owner]) { const wrong = await claim(person, claimed.id, 'x'.repeat(43)); assert.equal(wrong.status, 404, purpose); assert.deepEqual(wrong.body, NOT_FOUND); }
    for (const person of [other, owner]) { const late = await claim(person, claimed.id, claimed.secret); assert.equal(late.status, 410, purpose); assert.equal(late.body.error.code, 'expired'); }
    // Expired and never claimed.
    const wrong = await claim(browser(), unclaimed.id, 'x'.repeat(43));
    assert.equal(wrong.status, 404, purpose); assert.deepEqual(wrong.body, NOT_FOUND);
    const late = await claim(browser(), unclaimed.id, unclaimed.secret);
    assert.equal(late.status, 410, purpose); assert.equal(late.body.error.code, 'expired');
    assert.equal(JSON.stringify([repo().get('connectSessions', claimed.id), repo().get('connectSessions', unclaimed.id)]), before, `${purpose}: nothing written`);
    // The same order holds at the claim itself, below the page.
    assert.throws(() => app.sessions.claim(claimed.id, 'x'.repeat(43), 'browser-z-binding-0001'), {code: 'not_found'});
    assert.throws(() => app.sessions.claim(claimed.id, claimed.secret, 'browser-z-binding-0001'), {status: 410, code: 'expired'});
  }
});

test('two browsers claiming one link in the same tick leave exactly one winner, for connect, manage and approve links', async t => {
  const {app, keys, call, repo, account, ask, browser} = await hostedSetup(t);
  await account('u1', 'g-1');
  const waiting = await ask('u1');
  const kinds = {connect: [keys.full, {appId: 'github'}], manage: [keys.manage, {purpose: 'manage'}], approve: [keys.approve, {purpose: 'approve', callRef: waiting.callRef}]};
  const mint = async (key, body) => { const created = await call(key, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', ...body}); assert.equal(created.status, 201, JSON.stringify(created.body)); return {id: created.body.id, secret: secretOf(created.body.connectUrl)}; };
  for (const [purpose, [key, body]] of Object.entries(kinds)) {
    // Inside the server: both claims start before either returns.
    const direct = await mint(key, body), A = 'browser-a-binding-0001', B = 'browser-b-binding-0001';
    const settled = await Promise.allSettled([A, B].map(binding => (async () => app.sessions.claim(direct.id, direct.secret, binding))()));
    assert.deepEqual(settled.map(result => result.status).sort(), ['fulfilled', 'rejected'], purpose);
    assert.equal(settled.find(result => result.status === 'rejected').reason.code, 'session_in_use', purpose);
    const winner = settled[0].status === 'fulfilled' ? A : B, loser = winner === A ? B : A;
    assert.equal(repo().get('connectSessions', direct.id).browserBindingHash, sha256(winner), `${purpose}: the binding is the winner's`);
    assert.equal(app.sessions.view(direct.id, winner).state, 'opened');
    assert.throws(() => app.sessions.view(direct.id, loser), {code: 'not_found'});
    assert.throws(() => app.sessions.claim(direct.id, direct.secret, loser), {code: 'session_in_use'});
    // Over HTTP: two fresh browsers post the claim together.
    const shared = await mint(key, body), people = [browser(), browser()];
    const answers = await Promise.all(people.map(person => person.call('POST', `/connect/${shared.id}/v1/claim`, {secret: shared.secret})));
    assert.deepEqual(answers.map(answer => answer.status).sort(), [200, 409], purpose);
    const won = answers.findIndex(answer => answer.status === 200), lost = 1 - won;
    assert.equal(answers[lost].body.error.code, 'session_in_use');
    assert.equal(answers.filter(answer => answer.headers.getSetCookie().some(line => line.startsWith('fabric_t_session='))).length, 1, `${purpose}: one cookie is issued`);
    assert.equal(people[lost].binding, undefined);
    assert.equal(repo().get('connectSessions', shared.id).browserBindingHash, sha256(people[won].binding), `${purpose}: the binding is the winner's`);
    assert.equal((await people[won].call('GET', `/connect/${shared.id}/v1/view`)).body.state, 'opened');
    const refused = await people[lost].call('GET', `/connect/${shared.id}/v1/view`);
    assert.equal(refused.status, 404); assert.deepEqual(refused.body, NOT_FOUND);
    assert.equal((await people[lost].call('POST', `/connect/${shared.id}/v1/claim`, {secret: shared.secret})).body.error.code, 'session_in_use', `${purpose}: the loser stays out`);
  }
});

test('the hosted manage and approval data routes refuse a stranger, a planted cookie, another session\'s real cookie and a duplicated cookie, and nothing changes', async t => {
  const {app, keys, repo, account, ask, open, advance, sim} = await hostedSetup(t);
  const u1 = await account('u1', 'g-1'); await account('u2', 'g-2');
  const waiting1 = await ask('u1'), waiting2 = await ask('u2');
  const manage = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'}), approve = await open(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: waiting1.callRef});
  const theirManage = await open(keys.full, {externalUserId: 'u2', purpose: 'manage'}), theirApprove = await open(keys.approve, {externalUserId: 'u2', purpose: 'approve', callRef: waiting2.callRef});
  // Every hosted data route of section 5.13, taken from the route list so a new one cannot be missed.
  const FLOW = new Set(['claim', 'view', 'start', 'confirm', 'close', 'reject', 'select', 'decline']);
  const routes = PAGE_ACTIONS.filter(entry => !FLOW.has(entry.action));
  assert.deepEqual(routes.map(entry => `${entry.method} ${entry.action}`), ['GET catalog', 'GET activity', 'GET approval', 'GET apps/:appId', 'POST apps/:appId/accounts/:accountRef/permissions',
    'POST apps/:appId/accounts/:accountRef/reset', 'POST apps/:appId/accounts/:accountRef/background', 'POST apps/:appId/accounts/:accountRef/disconnect', 'POST approvals/:callRef/decision']);
  // Real etags and the real digest, read by the right browsers, so each refusal can only be the cookie.
  const view = (await manage.person.call('GET', `/connect/${manage.id}/v1/apps/gmail?account=${u1}`)).body;
  const row = view.sections.flatMap(section => section.rows).find(item => item.groupId === 'gmail.messages.read');
  const digest = (await approve.person.call('GET', `/connect/${approve.id}/v1/approval`)).body.approval.digest;
  assert.match(row.etag, /\S/); assert.match(view.background.etag, /\S/); assert.match(digest, /^[0-9a-f]{64}$/);
  const BODIES = {permissions: {groupId: 'gmail.messages.read', mode: 'deny', etag: row.etag}, reset: {}, background: {mode: 'allow', etag: view.background.etag}, disconnect: {}, decision: {decision: 'approve', digest}};
  const requests = routes.map(entry => {
    const own = ['approval', 'approvals/:callRef/decision'].includes(entry.action) ? approve : manage;
    const action = entry.action.replace(':appId', 'gmail').replace(':accountRef', u1).replace(':callRef', waiting1.callRef);
    return {entry, own, route: `/connect/${own.id}/v1/${action}${entry.action === 'apps/:appId' ? `?account=${u1}` : ''}`, body: entry.method === 'POST' ? BODIES[entry.action.split('/').at(-1)] : undefined};
  });
  // The answer for a session that never existed is the yardstick: every refusal below has the same bytes.
  const yardstick = await pageRequest(app.origin, 'GET', `/connect/${UNKNOWN_SESSION}/v1/catalog`);
  assert.equal(yardstick.status, 404); assert.deepEqual(yardstick.body, NOT_FOUND);
  const SURFACES = ['connections', 'permissions', 'backgroundPolicies', 'jobs', 'endUsers', 'connectSessions', 'activity'];
  const snapshot = () => JSON.stringify([SURFACES.map(name => repo().list(name)), app.registry.list('sessionRoutes'), sim.calls.length]);
  advance(1000); // a refused request that still counted as page activity would move lastSeenAt
  const before = snapshot();
  const planted = randomBytes(32).toString('base64url');
  for (const {entry, own, route, body} of requests) {
    const label = `${entry.method} ${entry.action}`;
    const others = [theirManage, theirApprove, own === manage ? approve : manage];
    const refusedWith = [
      ['a stranger with no cookie', {}],
      ['a planted value', {cookie: `fabric_t_session=${planted}`, csrf: csrfOf(planted)}],
      ['a short planted value', {cookie: `fabric_t_session=${'p'.repeat(43)}`, csrf: csrfOf('p'.repeat(43))}],
      ...others.map(other => [`the real cookie of ${other.id}`, {cookie: `fabric_t_session=${other.person.binding}`, csrf: csrfOf(other.person.binding)}]),
    ];
    for (const [who, credentials] of refusedWith) {
      const response = await pageRequest(app.origin, entry.method, route, {...credentials, body});
      assert.equal(response.status, 404, `${label}: ${who}`);
      assert.equal(response.text, yardstick.text, `${label}: ${who} reads exactly like a session that never existed`);
    }
    // Two session cookies in one header are refused before any session is looked at, whatever their order.
    const real = own.person.binding;
    for (const cookie of [`fabric_t_session=${planted}; fabric_t_session=${real}`, `fabric_t_session=${real}; fabric_t_session=${theirManage.person.binding}`, `fabric_t_session=${real}; fabric_t_session=${real}`]) {
      const response = await pageRequest(app.origin, entry.method, route, {cookie, csrf: csrfOf(real), body});
      assert.equal(response.status, 400, `${label}: ${cookie.slice(0, 40)}`); assert.deepEqual(response.body, MALFORMED);
    }
  }
  assert.equal(snapshot(), before, 'no record, route, audit row or provider call changed, and no session counted the refusals as activity');
  for (const link of [manage, approve, theirManage, theirApprove]) assert.equal(app.sessions.view(link.id, link.person.binding).state, 'opened');
  assert.equal(repo().get('jobs', waiting1.callRef).status, 'awaiting_approval');
  // The same requests from the browsers that opened the links do work: the refusals were the cookie, nothing else.
  for (const {entry, own, route, body} of requests.filter(item => !['disconnect', 'reset', 'background'].includes(item.entry.action.split('/').at(-1)))) {
    const response = await own.person.call(entry.method, route, body);
    assert.equal(response.status, 200, `${entry.method} ${entry.action}: ${JSON.stringify(response.body)}`);
  }
  assert.equal(repo().get('jobs', waiting1.callRef).decision.sessionId, approve.id);
});

test('a provider callback for U1\'s flow in a browser that carries U2\'s session cookie creates U1\'s account only, on both callback routes', async t => {
  const {app, api, link, repo, userOf, startSignIn} = await signinWorld(t);
  const callbackShapes = CALLBACK_ROUTES.map(route => new RegExp(`^${route.slice('GET '.length).replace(':providerId', '[a-z][a-z0-9-]{1,39}').replace(':providerAppId', 'pa_[a-z2-7]{26}')}$`));
  const covered = new Set();
  let round = 0;
  for (const providerApp of ['shared', 'developer']) {
    if (providerApp === 'developer') {
      const registered = await api('POST', '/v1/provider-apps', {providerId: 'github', clientId: 'dev-owner-flow', clientSecret: 'dev-owner-flow-secret', consentScreenName: 'Acme Agent'});
      assert.equal(registered.status, 201, JSON.stringify(registered.body));
      assert.equal((await api('PUT', '/v1/environment/apps/github', {providerApp: registered.body.providerApp.id, enabled: true})).status, 200);
    }
    // U2's cookie from a connect link, then from a manage link: neither purpose's session cookie names the owner.
    for (const foreignPurpose of ['connect', 'manage']) {
      round += 1;
      const one = await link('aura-user-1'), two = await link('aura-user-2', foreignPurpose === 'manage' ? {purpose: 'manage'} : {appId: 'github'});
      const first = pathBrowser(app.origin), second = pathBrowser(app.origin);
      assert.equal((await first.call('POST', `/connect/${one.id}/v1/claim`, {secret: one.secret})).status, 200);
      assert.equal((await second.call('POST', `/connect/${two.id}/v1/claim`, {secret: two.secret})).status, 200);
      const flow = await startSignIn(first, one.id), flowId = first.value('fabric_t_oauth', flow.callbackPath);
      assert.match(flowId, /\S/);
      covered.add(callbackShapes.findIndex(shape => shape.test(flow.callbackPath)));
      const foreign = second.value('fabric_t_session', `/connect/${two.id}`), twoBefore = JSON.stringify(repo().get('connectSessions', two.id));
      const accountsBefore = repo().list('connections').map(item => item.id);
      const callback = cookie => pageRequest(app.origin, 'GET', `${flow.callbackPath}?state=${encodeURIComponent(flow.state)}&code=c-${round}`, {cookie});
      // U2's session cookie alone, without U1's flow cookie, is no way back.
      const alone = await callback(`fabric_t_session=${foreign}`);
      assert.equal(alone.status, 400, `${providerApp}/${foreignPurpose}`); assert.equal(alone.body.error.code, 'invalid_state');
      assert.deepEqual(repo().list('connections').map(item => item.id), accountsBefore, 'no account from the foreign cookie');
      // U2's session cookie beside U1's flow cookie: U1's sign-in finishes, for U1.
      const back = await callback(`fabric_t_session=${foreign}; fabric_t_oauth=${flowId}`);
      assert.equal(back.status, 303, `${providerApp}/${foreignPurpose}: ${back.text}`);
      assert.equal(back.headers.get('location'), `/connect/${one.id}/finish`);
      const finishLine = back.headers.getSetCookie().find(line => line.startsWith('fabric_t_finish='));
      assert.ok(finishLine.includes(`Path=/connect/${one.id};`), 'the finish value belongs to U1\'s link only');
      assert.equal(back.headers.getSetCookie().some(line => line.includes(`/connect/${two.id}`)), false, 'nothing is set for U2\'s link');
      const finish = finishLine.split(';')[0].slice('fabric_t_finish='.length);
      const added = repo().list('connections').filter(item => !accountsBefore.includes(item.id));
      assert.equal(added.length, 1);
      const [pending] = added;
      assert.deepEqual([pending.ownership.owner.id, pending.userRecordId, pending.origin?.sessionId, pending.status], ['aura-user-1', userOf('aura-user-1').id, one.id, 'pending_confirmation'], `${providerApp}/${foreignPurpose}`);
      assert.equal(pending.providerApp?.kind ?? 'shared', providerApp === 'developer' ? 'developer' : 'shared');
      assert.equal(JSON.stringify(repo().get('connectSessions', two.id)), twoBefore, 'U2\'s session is unchanged');
      assert.equal((await api('GET', `/v1/connect-sessions/${one.id}`)).body.state, 'awaiting_confirmation');
      assert.equal((await api('GET', `/v1/connect-sessions/${two.id}`)).body.state, 'opened');
      // U2's browser cannot confirm it, even holding the finish value; U1's browser with it can.
      const stolen = await second.call('POST', `/connect/${two.id}/v1/confirm`, {}, {Cookie: `fabric_t_session=${foreign}; fabric_t_finish=${finish}`});
      assert.equal(stolen.status, 409); assert.equal(stolen.body.error.code, 'already_finished');
      const onTheirPath = await second.call('POST', `/connect/${one.id}/v1/confirm`, {}, {Cookie: `fabric_t_session=${foreign}; fabric_t_finish=${finish}`, 'X-Fabric-CSRF': csrfOf(foreign)});
      assert.equal(onTheirPath.status, 404); assert.deepEqual(onTheirPath.body, NOT_FOUND);
      assert.equal(JSON.stringify(repo().get('connectSessions', two.id)), twoBefore, 'U2\'s session is still unchanged');
      const confirmed = await first.call('POST', `/connect/${one.id}/v1/confirm`, {}, {Cookie: `fabric_t_session=${first.value('fabric_t_session', `/connect/${one.id}`)}; fabric_t_finish=${finish}`});
      assert.equal(confirmed.status, 200, JSON.stringify(confirmed.body));
      assert.equal(confirmed.body.result.accountRef, pending.id);
      const ready = repo().get('connections', pending.id);
      assert.deepEqual([ready.status, ready.ownership.owner.id, ready.userRecordId], ['ready', 'aura-user-1', userOf('aura-user-1').id]);
    }
  }
  assert.deepEqual([...covered].sort(), CALLBACK_ROUTES.map((_, index) => index), 'both callback routes walked');
  assert.equal(repo().list('connections').filter(item => item.ownership.owner.id === 'aura-user-2' || item.userRecordId === userOf('aura-user-2').id).length, 0, 'U2 never owns an account');
  assert.equal(repo().list('connections').length, round);
});

test('two connect sessions in one cookie jar: each request carries only its own cookie, and each session acts on its own records', async t => {
  const {app, api, link, repo, userOf, startSignIn} = await signinWorld(t);
  const s1 = await link('aura-user-1'), s2 = await link('aura-user-2');
  const person = pathBrowser(app.origin), at1 = `/connect/${s1.id}`, at2 = `/connect/${s2.id}`;
  for (const session of [s1, s2]) assert.equal((await person.call('POST', `/connect/${session.id}/v1/claim`, {secret: session.secret})).status, 200);
  assert.deepEqual(person.jar.filter(cookie => cookie.name === 'fabric_t_session').map(cookie => cookie.path).sort(), [at1, at2].sort(), 'one cookie per link, each on its own path');
  const one = person.value('fabric_t_session', at1), two = person.value('fabric_t_session', at2);
  assert.notEqual(one, two);
  assert.equal(repo().get('connectSessions', s1.id).browserBindingHash, sha256(one));
  assert.equal(repo().get('connectSessions', s2.id).browserBindingHash, sha256(two));
  const view1 = await person.call('GET', `${at1}/v1/view`), view2 = await person.call('GET', `${at2}/v1/view`);
  assert.deepEqual([view1.status, view1.body.state, view2.status, view2.body.state], [200, 'opened', 200, 'opened']);
  assert.notEqual(person.csrfFor(s1.id), person.csrfFor(s2.id));
  // Session A's path with session B's value, and the reverse, are refused and change nothing.
  const sessionsBefore = JSON.stringify([repo().get('connectSessions', s1.id), repo().get('connectSessions', s2.id)]);
  for (const [at, value] of [[at2, one], [at1, two]]) {
    const read = await person.call('GET', `${at}/v1/view`, undefined, {Cookie: `fabric_t_session=${value}`});
    assert.equal(read.status, 404); assert.deepEqual(read.body, NOT_FOUND);
    for (const action of ['start', 'close', 'confirm']) {
      const write = await person.call('POST', `${at}/v1/${action}`, {}, {Cookie: `fabric_t_session=${value}`, 'X-Fabric-CSRF': csrfOf(value)});
      assert.equal(write.status, 404, `${action} on ${at}`); assert.deepEqual(write.body, NOT_FOUND);
    }
  }
  assert.equal(JSON.stringify([repo().get('connectSessions', s1.id), repo().get('connectSessions', s2.id)]), sessionsBefore);
  // Sign in on session one only; the callback path carries the flow cookie and no session cookie at all.
  const flow = await startSignIn(person, s1.id);
  assert.match(person.value('fabric_t_oauth', flow.callbackPath), /\S/);
  const back = await person.call('GET', `${flow.callbackPath}?state=${encodeURIComponent(flow.state)}&code=jar`);
  assert.equal(back.status, 303); assert.equal(back.headers.get('location'), `${at1}/finish`);
  assert.equal(person.sent.at(-1).cookie.includes('fabric_t_session'), false, 'no session cookie reaches the callback');
  assert.equal(person.value('fabric_t_oauth', flow.callbackPath), undefined, 'the flow cookie is spent');
  assert.match(person.value('fabric_t_finish', at1), /\S/); assert.equal(person.value('fabric_t_finish', at2), undefined);
  const accounts = repo().list('connections');
  assert.equal(accounts.length, 1);
  assert.deepEqual([accounts[0].ownership.owner.id, accounts[0].userRecordId, accounts[0].origin?.sessionId, accounts[0].status], ['aura-user-1', userOf('aura-user-1').id, s1.id, 'pending_confirmation']);
  assert.equal((await api('GET', `/v1/connect-sessions/${s1.id}`)).body.state, 'awaiting_confirmation');
  assert.equal((await api('GET', `/v1/connect-sessions/${s2.id}`)).body.state, 'opened');
  const finishing = (await person.call('GET', `${at1}/v1/view`)).body, other = (await person.call('GET', `${at2}/v1/view`)).body;
  assert.equal(finishing.state, 'awaiting_confirmation'); assert.ok(finishing.pendingAccount, 'session one shows its own account to confirm');
  assert.equal(other.state, 'opened'); assert.equal(other.pendingAccount, undefined); assert.equal(other.finishElsewhere, undefined);
  const wrong = await person.call('POST', `${at2}/v1/confirm`, {});
  assert.equal(wrong.status, 409); assert.equal(wrong.body.error.code, 'already_finished');
  const right = await person.call('POST', `${at1}/v1/confirm`, {});
  assert.equal(right.status, 200, JSON.stringify(right.body)); assert.equal(right.body.state, 'connected'); assert.equal(right.body.result.accountRef, accounts[0].id);
  assert.equal(repo().list('connections').filter(item => item.userRecordId === userOf('aura-user-2').id || item.ownership.owner.id === 'aura-user-2').length, 0);
  assert.equal((await person.call('POST', `${at2}/v1/close`, {})).body.state, 'cancelled');
  assert.equal((await person.call('GET', `${at1}/v1/view`)).body.state, 'connected');
  // Every request sent at most one session cookie, and only the one for its own link.
  assertOwnCookies(person, {[s1.id]: one, [s2.id]: two});
});

/** Every page request the jar itself built carried exactly its own link's session cookie (the claim aside). */
function assertOwnCookies(person, valueOf) {
  const pageRequests = person.sent.filter(item => item.session && !item.crafted);
  assert.ok(pageRequests.length > 0);
  for (const {path: sentPath, session, cookie} of pageRequests) {
    const values = (cookie ?? '').split('; ').filter(part => part.startsWith('fabric_t_session=')).map(part => part.slice('fabric_t_session='.length));
    if (sentPath.endsWith('/v1/claim') && values.length === 0) continue;
    assert.deepEqual(values, [valueOf[session]], `${sentPath} sent ${cookie}`);
  }
}

test('two hosted sessions in one cookie jar: a manage and an approve link for U1 and a manage link for U2 each see only their own records', async t => {
  const {app, keys, call, repo, account, ask, sim} = await hostedSetup(t);
  const u1 = await account('u1', 'g-1'), u2 = await account('u2', 'g-2');
  const waiting1 = await ask('u1');
  const mint = async (key, body) => { const created = await call(key, 'POST', '/v1/connect-sessions', body); assert.equal(created.status, 201, JSON.stringify(created.body)); return {id: created.body.id, secret: secretOf(created.body.connectUrl)}; };
  const m1 = await mint(keys.manage, {externalUserId: 'u1', purpose: 'manage'}), m2 = await mint(keys.manage, {externalUserId: 'u2', purpose: 'manage'});
  const a1 = await mint(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: waiting1.callRef});
  const person = pathBrowser(app.origin), links = [m1, m2, a1];
  for (const link of links) assert.equal((await person.call('POST', `/connect/${link.id}/v1/claim`, {secret: link.secret})).status, 200);
  const value = link => person.value('fabric_t_session', `/connect/${link.id}`);
  assert.equal(new Set(links.map(value)).size, 3, 'three cookies, three paths');
  // Each page reads its own person only.
  const mine = (await person.call('GET', `/connect/${m1.id}/v1/apps/gmail`)).body, theirs = (await person.call('GET', `/connect/${m2.id}/v1/apps/gmail`)).body;
  assert.deepEqual(mine.accounts.map(row => row.accountRef), [u1]); assert.deepEqual(theirs.accounts.map(row => row.accountRef), [u2]);
  const catalog1 = JSON.stringify((await person.call('GET', `/connect/${m1.id}/v1/catalog`)).body), catalog2 = JSON.stringify((await person.call('GET', `/connect/${m2.id}/v1/catalog`)).body);
  assert.equal(catalog1.includes(u2) || catalog1.includes('g-2'), false); assert.equal(catalog2.includes(u1) || catalog2.includes('g-1'), false);
  const activity2 = (await person.call('GET', `/connect/${m2.id}/v1/activity`)).body;
  assert.ok([...activity2.days.flatMap(day => day.items), ...activity2.approvals].every(item => item.accountRef === u2), 'U2\'s activity only');
  const approval = (await person.call('GET', `/connect/${a1.id}/v1/approval`)).body;
  assert.deepEqual([approval.state, approval.approval.accountRef], ['pending', u1]);
  // Another link's value on this link's path, and another page's CSRF value with this page's cookie, are refused.
  const before = JSON.stringify([['connections', 'permissions', 'backgroundPolicies', 'jobs', 'connectSessions', 'activity'].map(name => repo().list(name)), sim.calls.length]);
  const crossings = [[m1, m2, 'GET', 'catalog'], [m2, m1, 'GET', `apps/gmail?account=${u1}`], [a1, m1, 'GET', 'approval'], [m1, a1, 'POST', `apps/gmail/accounts/${u1}/reset`],
    [a1, m2, 'POST', `approvals/${waiting1.callRef}/decision`, approval.approval.approve.body], [m2, a1, 'POST', `apps/gmail/accounts/${u2}/disconnect`]];
  for (const [target, holder, method, action, body] of crossings) {
    const response = await person.call(method, `/connect/${target.id}/v1/${action}`, method === 'POST' ? (body ?? {}) : undefined, {Cookie: `fabric_t_session=${value(holder)}`, ...(method === 'POST' ? {'X-Fabric-CSRF': csrfOf(value(holder))} : {})});
    assert.equal(response.status, 404, `${action} on ${target.id} with ${holder.id}'s cookie`); assert.deepEqual(response.body, NOT_FOUND);
  }
  const mixed = await person.call('POST', `/connect/${m2.id}/v1/apps/gmail/accounts/${u2}/reset`, {}, {'X-Fabric-CSRF': person.csrfFor(m1.id)});
  assert.equal(mixed.status, 403); assert.equal(mixed.body.error.code, 'csrf_mismatch');
  assert.equal(JSON.stringify([['connections', 'permissions', 'backgroundPolicies', 'jobs', 'connectSessions', 'activity'].map(name => repo().list(name)), sim.calls.length]), before, 'nothing changed');
  // Each link still works with its own cookie, from the same jar.
  assert.equal((await person.call('POST', `/connect/${m1.id}/v1/apps/gmail/accounts/${u1}/reset`, {})).status, 200);
  const decided = await person.call('POST', `/connect/${a1.id}/v1/approvals/${waiting1.callRef}/decision`, approval.approval.approve.body);
  assert.equal(decided.status, 200, JSON.stringify(decided.body)); assert.equal(decided.body.decision, 'approved');
  assert.equal(repo().get('jobs', waiting1.callRef).decision.sessionId, a1.id);
  assertOwnCookies(person, Object.fromEntries(links.map(link => [link.id, value(link)])));
});

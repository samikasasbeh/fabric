import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createDeveloperApp} from '../developer-server.mjs';
import {PlatformStore} from '../lib/tenant/platform.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {Client} from '@modelcontextprotocol/client';
import {InMemoryTransport} from '@modelcontextprotocol/server';
import {createMcpAdapter} from '../lib/mcp-adapter.mts';

// F03.9d (docs/F03.9-BUILD-MAP.md slice C): a held execution. With onMissingAccess hold, a person without an account
// gets a handoff session; the developer mints its link; the person connects (or picks) an account on Fabric's page and
// confirms; the same callRef runs, once. Nothing is sent or counted before that, and every other ending sends nothing.
function seed(root) {
  const paths = {'/repos/{owner}/{repo}': {get: {operationId: 'repos/get', parameters: ['owner', 'repo'].map(name => ({name, in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'OK'}}}}};
  const [capability] = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths}}).capabilities;
  const store = new PlatformStore({root});
  store.put('capabilities', {...capability, status: 'active'});
  store.put('applicationMaps', {id: 'github', appId: 'github', classifierVersion: SENSITIVITY_VERSION, operations: [{id: 'repos/get', capabilityId: capability.id, method: 'GET', path: '/repos/{owner}/{repo}', sensitive: null}]});
  store.close();
}

async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-holds-'));
  seed(root);
  const sim = {calls: [], identity: 100};
  const request = async req => {
    sim.calls.push(`${req.method || 'GET'} ${req.url}`);
    if (req.url === 'https://github.com/login/oauth/access_token') return {status: 200, headers: {}, data: {access_token: `gho_${randomUUID()}`, token_type: 'bearer', scope: 'read:user,repo'}};
    if (req.url === 'https://api.github.com/user') return {status: 200, headers: {}, data: {id: sim.identity, login: `octo${sim.identity}`, name: `Octo ${sim.identity}`}};
    if (req.url.startsWith('https://api.github.com/repos/')) return {status: 200, headers: {}, data: {id: 7, full_name: 'o/r'}};
    if (req.url.startsWith('https://api.github.com/applications/')) return {status: 204, headers: {}, data: null};
    throw new Error(`unexpected ${req.url}`);
  };
  const app = await createDeveloperApp({dataRoot: root, port: 0, request, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}});
  t.after(async () => { await app.sessions.settled(); await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'standard'}), linker = app.keys.mint({environmentId: dev.id, preset: 'standard'});
  const call = async (method, route, body, token = key.token, headers = {}) => {
    const response = await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
    return {status: response.status, body: await response.json()};
  };
  const repo = () => app.stores.open(scope).repository;
  const cap = (await call('GET', '/v1/capabilities?appId=github')).body.capabilities[0];
  // People exist once a link was made for them (and left unused).
  for (const user of ['u1', 'u2']) { const made = (await call('POST', '/v1/connect-sessions', {externalUserId: user})).body; await call('POST', `/v1/connect-sessions/${made.id}/cancel`); }
  const hold = (user = 'u1', idem = randomUUID(), extra = {}) => call('POST', '/v1/executions', {externalUserId: user, capabilityId: cap.id, definitionHash: cap.definitionHash, args: {owner: 'o', repo: 'r'}, onMissingAccess: 'hold', ...extra}, key.token, {'Idempotency-Key': idem});
  /** The developer mints the handoff link with the second key, the person opens it in one browser. */
  const open = async sessionId => {
    const link = (await call('POST', `/v1/connect-sessions/${sessionId}/link`, undefined, linker.token)).body, binding = `browser-${sessionId}`;
    app.sessions.claim(sessionId, new URL(link.connectUrl).hash.slice(3), binding);
    return {link, binding};
  };
  /** Sign in on the simulated GitHub from the page, come back, and return the finish value. */
  const signIn = async (sessionId, binding) => {
    const started = app.sessions.start(sessionId, binding), url = new URL(started.authorizationUrl);
    const back = await fetch(`${app.origin}${started.callbackPath}?state=${encodeURIComponent(url.searchParams.get('state'))}&code=c`, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${started.flowId}`}});
    return back.headers.getSetCookie().find(line => line.startsWith('fabric_t_finish=')).split(';')[0].slice('fabric_t_finish='.length);
  };
  /** A normal Connect link for the person, used to completion. */
  const connect = async user => {
    const made = (await call('POST', '/v1/connect-sessions', {externalUserId: user, appId: 'github'})).body, binding = `b-${made.id}`;
    app.sessions.claim(made.id, new URL(made.connectUrl).hash.slice(3), binding);
    return app.sessions.confirm(made.id, binding, await signIn(made.id, binding)).result.accountRef;
  };
  const sentRepo = () => sim.calls.filter(line => line.includes('/repos/o/r')).length;
  return {app, sim, scope, key, linker, call, repo, cap, hold, open, signIn, connect, sentRepo};
}

test('a held call waits with a handoff session and no link; the person signs in on Fabric\'s page; the same callRef runs once', async t => {
  const {app, call, repo, hold, open, signIn, sentRepo, key, linker} = await setup(t);
  const idem = randomUUID(), held = await hold('u1', idem);
  assert.equal(held.status, 202);
  assert.deepEqual([held.body.status, held.body.accountRef, held.body.evidence], ['connection_required', null, 'none']);
  assert.match(held.body.handoff.connectSessionId, /^cs_[a-z2-7]{26}$/); assert.equal(JSON.stringify(held.body).includes('http'), false, 'no link for the developer to follow');
  const callRef = held.body.callRef, sessionId = held.body.handoff.connectSessionId;
  assert.equal(repo().get('jobs', callRef), null); assert.equal(repo().list('usageEvents').filter(row => row.id === `exec.${callRef}`).length, 0); assert.equal(sentRepo(), 0);
  // The same Idempotency-Key replays the same hold, with no second session.
  const again = await hold('u1', idem);
  assert.deepEqual([again.body.callRef, again.body.handoff.connectSessionId], [callRef, sessionId]);
  assert.equal(repo().list('connectSessions').filter(item => item.purpose === 'handoff').length, 1);
  const session = (await call('GET', `/v1/connect-sessions/${sessionId}`)).body;
  assert.deepEqual([session.purpose, session.callRef], ['handoff', callRef]);
  assert.equal((await call('POST', '/v1/connect-sessions', {externalUserId: 'u1', purpose: 'handoff'})).status, 422, 'only Fabric makes handoff sessions');
  // Before /link, nothing can claim it; a second /link voids the first.
  assert.throws(() => app.sessions.claim(sessionId, 'no-such-session', 'browser-zzzzzzzzzzzzzzzz'), {code: 'not_found'});
  const first = (await call('POST', `/v1/connect-sessions/${sessionId}/link`, undefined, key.token)).body;
  const {binding} = await open(sessionId);
  assert.throws(() => app.sessions.claim(sessionId, new URL(first.connectUrl).hash.slice(3), 'browser-other-browser1'), error => ['not_found', 'session_in_use'].includes(error.code));
  const view = app.sessions.view(sessionId, binding);
  assert.deepEqual(view.handoff.accounts, []); assert.ok(view.sheet); assert.equal(view.handoff.canDecline, true);
  const finish = await signIn(sessionId, binding);
  assert.equal(app.sessions.confirm(sessionId, binding, finish).state, 'connected');
  await app.sessions.settled();
  const done = await call('GET', `/v1/executions/${callRef}?waitMs=3000`);
  assert.deepEqual([done.body.callRef, done.body.status, done.body.result], [callRef, 'succeeded', {id: 7, full_name: 'o/r'}]);
  assert.equal(sentRepo(), 1); assert.equal(repo().list('jobs').length, 1);
  assert.equal(repo().list('usageEvents').filter(row => row.id === `exec.${callRef}`).length, 1);
  // Who decided where: Fabric's page, through the link the second key minted; the job keeps the key that asked.
  const resumed = repo().list('activity').find(row => row.type === 'execution.resumed');
  assert.deepEqual([resumed.callRef, resumed.decidedIn, resumed.linkKeyId], [callRef, 'fabric_page', linker.keyId]);
  assert.equal(repo().get('jobs', callRef).source.keyId, key.keyId);
});

test('a hold offers only the person\'s own accounts; one connected elsewhere never binds by itself; choosing and confirming resumes', async t => {
  const {app, call, repo, hold, open, connect, sentRepo, sim} = await setup(t);
  sim.identity = 200; const theirs = await connect('u2');
  const held = (await hold('u1')).body, sessionId = held.handoff.connectSessionId;
  sim.identity = 300; const mine = await connect('u1');
  await app.sessions.settled();
  assert.equal((await call('GET', `/v1/executions/${held.callRef}`)).body.status, 'connection_required', 'an account connected through another link does not bind the hold');
  const {binding} = await open(sessionId);
  const view = app.sessions.view(sessionId, binding);
  assert.deepEqual(view.handoff.accounts.map(item => item.displayName), ['octo300']);
  assert.equal(JSON.stringify(view).includes(theirs) || JSON.stringify(view).includes('octo200') || JSON.stringify(view).includes(mine), false, 'never another person\'s account, never an accountRef');
  assert.throws(() => app.sessions.select(sessionId, binding, 'not-a-choice'), {code: 'not_found'});
  assert.deepEqual(app.sessions.select(sessionId, binding, view.handoff.accounts[0].choice).selectedAccount, {displayName: 'octo300'});
  // "Not this account" after choosing keeps the account; choosing again and confirming resumes on it.
  assert.equal((await app.sessions.reject(sessionId, binding)).state, 'opened');
  assert.equal(repo().get('connections', mine).status, 'ready');
  app.sessions.select(sessionId, binding, view.handoff.accounts[0].choice);
  assert.equal(app.sessions.confirm(sessionId, binding).state, 'connected');
  await app.sessions.settled();
  const done = await call('GET', `/v1/executions/${held.callRef}?waitMs=3000`);
  assert.deepEqual([done.body.status, done.body.accountRef], ['succeeded', mine]);
  assert.equal(sentRepo(), 1);
});

test('every other ending sends nothing: decline, the developer\'s cancel, expiry, an app turned off, a deleted person; a confirm racing a cancel runs once', async t => {
  const {app, call, repo, hold, open, signIn, connect, sentRepo, scope, sim} = await setup(t);
  // Decline.
  const declined = (await hold('u1')).body, d = await open(declined.handoff.connectSessionId);
  await app.sessions.decline(declined.handoff.connectSessionId, d.binding);
  assert.equal((await call('GET', `/v1/executions/${declined.callRef}`)).body.status, 'cancelled');
  // The developer cancels; a later confirm is refused.
  const cancelled = (await hold('u1')).body, c = await open(cancelled.handoff.connectSessionId);
  const out = await call('POST', `/v1/executions/${cancelled.callRef}/cancel`);
  assert.equal(out.body.status, 'cancelled');
  assert.throws(() => app.sessions.confirm(cancelled.handoff.connectSessionId, c.binding), error => ['already_finished', 'not_found', 'expired'].includes(error.code));
  assert.equal((await call('POST', `/v1/executions/${cancelled.callRef}/cancel`)).status, 409);
  // Expiry.
  const expired = (await hold('u1')).body;
  repo().put('connectSessions', {...repo().get('connectSessions', expired.handoff.connectSessionId), expiresAt: new Date(Date.now() - 1000).toISOString()});
  const lapsed = (await call('GET', `/v1/executions/${expired.callRef}`)).body;
  assert.deepEqual([lapsed.status, lapsed.error.code], ['failed', 'handoff_expired']);
  // The app turned off while the person signs in: the account connects, the call does not run.
  const off = (await hold('u1')).body, o = await open(off.handoff.connectSessionId);
  sim.identity = 400; const finish = await signIn(off.handoff.connectSessionId, o.binding);
  const environment = app.registry.get('environments', scope.environmentId);
  app.registry.put('environments', {...environment, apps: {github: {enabled: false}}});
  app.sessions.confirm(off.handoff.connectSessionId, o.binding, finish);
  await app.sessions.settled();
  const refused = (await call('GET', `/v1/executions/${off.callRef}`)).body;
  assert.deepEqual([refused.status, refused.error.code], ['failed', 'app_disabled']);
  app.registry.put('environments', {...environment, apps: {}});
  // The operation changed while the call was held: the account connects, the call does not run.
  const changed = (await hold('u1', randomUUID(), {waitMs: 3000})).body;
  assert.equal(changed.status, 'succeeded', 'u1 has an account by now, so this one simply runs');
  const made4 = (await call('POST', '/v1/connect-sessions', {externalUserId: 'u4'})).body; await call('POST', `/v1/connect-sessions/${made4.id}/cancel`);
  const stale = (await hold('u4')).body, st = await open(stale.handoff.connectSessionId);
  repo().put('continuations', {...repo().get('continuations', stale.callRef), definitionHash: 'f'.repeat(64)});
  sim.identity = 450; const staleFinish = await signIn(stale.handoff.connectSessionId, st.binding);
  app.sessions.confirm(stale.handoff.connectSessionId, st.binding, staleFinish);
  await app.sessions.settled();
  assert.equal((await call('GET', `/v1/executions/${stale.callRef}`)).body.error.code, 'capability_changed');
  // A confirm racing a cancel in the same tick: exactly one side wins. A cancel that wins means nothing is ever sent;
  // a cancel that loses is refused and the call runs once. Never cancelled and run.
  const raced = (await hold('u2')).body, r = await open(raced.handoff.connectSessionId);
  sim.identity = 500; const raceFinish = await signIn(raced.handoff.connectSessionId, r.binding);
  const before = sentRepo();
  app.sessions.confirm(raced.handoff.connectSessionId, r.binding, raceFinish);
  const racing = await app.executions.cancel({scope, keyId: 'key_racing', serviceClientId: 'svc_racing'}, raced.callRef).then(view => ({won: true, view}), error => ({won: false, code: error.code}));
  await app.sessions.settled();
  await call('GET', `/v1/executions/${raced.callRef}?waitMs=3000`);
  const jobs = repo().list('jobs').filter(job => job.id === raced.callRef);
  assert.ok(jobs.length <= 1);
  if (racing.won) { assert.equal(sentRepo(), before, 'cancelled, so never sent'); assert.ok(!jobs.length || jobs[0].status === 'cancelled'); }
  else { assert.equal(racing.code, 'not_cancellable'); assert.equal(sentRepo(), before + 1, 'refused cancel, so it ran once'); }
  const ranRaced = sentRepo() - before;
  // A person deleted during a hold: the callRef is not_found and the hold and its route are gone.
  const made = (await call('POST', '/v1/connect-sessions', {externalUserId: 'u3'})).body; await call('POST', `/v1/connect-sessions/${made.id}/cancel`);
  const gone = (await hold('u3')).body;
  await call('DELETE', '/v1/users/u3');
  assert.equal((await call('GET', `/v1/executions/${gone.callRef}`)).status, 404);
  assert.equal(repo().get('continuations', gone.callRef), null); assert.equal(app.registry.get('sessionRoutes', gone.handoff.connectSessionId), null);
  assert.equal(sentRepo(), 1 + ranRaced, 'only the call with an account and (if it won) the raced one ran');
  void connect;
});

test('on Fabric\'s page, through the real routes: choose an account and confirm, or decline', async t => {
  const {app, call, hold, connect, sentRepo, linker} = await setup(t);
  const browser = () => {
    const jar = new Map();
    let csrf = null;
    return {jar, async call(method, route, body) {
      const cookie = [...jar].filter(([, value]) => value).map(([name, value]) => `${name}=${value}`).join('; ');
      const response = await fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(cookie ? {Cookie: cookie} : {}), ...(body !== undefined ? {'Content-Type': 'application/json', Origin: app.origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      for (const line of response.headers.getSetCookie()) { const [pair] = line.split(';'), at = pair.indexOf('='); jar.set(pair.slice(0, at), pair.slice(at + 1)); }
      const parsed = await response.json();
      if (typeof parsed?.csrf === 'string') csrf = parsed.csrf;
      return {status: response.status, body: parsed};
    }};
  };
  await connect('u1');
  const held = (await hold('u2')).body;
  await connect('u2');
  const link = (await call('POST', `/v1/connect-sessions/${held.handoff.connectSessionId}/link`, undefined, linker.token)).body, id = held.handoff.connectSessionId;
  const person = browser();
  assert.equal((await person.call('POST', `/connect/${id}/v1/claim`, {secret: new URL(link.connectUrl).hash.slice(3)})).status, 200);
  const view = (await person.call('GET', `/connect/${id}/v1/view`)).body;
  assert.equal(view.handoff.accounts.length, 1, 'only u2\'s own account');
  assert.equal((await person.call('POST', `/connect/${id}/v1/select`, {choice: view.handoff.accounts[0].choice})).status, 200);
  assert.ok((await person.call('GET', `/connect/${id}/v1/view`)).body.handoff.selectedAccount);
  assert.equal((await person.call('POST', `/connect/${id}/v1/confirm`, {})).body.state, 'connected');
  await app.sessions.settled();
  assert.equal((await call('GET', `/v1/executions/${held.callRef}?waitMs=3000`)).body.status, 'succeeded');
  // Decline through the page: the call ends cancelled, and nothing more is sent.
  const sentBefore = sentRepo();
  await hold('u1', randomUUID(), {waitMs: 3000});
  const made = (await call('POST', '/v1/connect-sessions', {externalUserId: 'u5'})).body; await call('POST', `/v1/connect-sessions/${made.id}/cancel`);
  const another = (await hold('u5')).body, link2 = (await call('POST', `/v1/connect-sessions/${another.handoff.connectSessionId}/link`, undefined, linker.token)).body, other = browser();
  await other.call('POST', `/connect/${another.handoff.connectSessionId}/v1/claim`, {secret: new URL(link2.connectUrl).hash.slice(3)});
  assert.equal((await other.call('POST', `/connect/${another.handoff.connectSessionId}/v1/decline`, {})).body.state, 'cancelled');
  assert.equal((await other.call('GET', `/connect/${another.handoff.connectSessionId}/v1/view`)).body.errorCode, 'declined');
  assert.equal((await call('GET', `/v1/executions/${another.callRef}`)).body.status, 'cancelled');
  assert.equal(sentRepo(), sentBefore + 1, 'only u1\'s call (which had an account) ran');
});

// F03.9e: an agent asks for an operation the person has no account for; the same hold answers it.
test('an agent\'s account request: a hold with no link; the developer relays it; the person connects; the same id runs under the request\'s own authority', async t => {
  const {app, call, repo, cap, open, signIn, sentRepo, sim} = await setup(t);
  let counter = 0;
  const agent = async (token, method, params, id = `a${++counter}`) => (await (await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'}, body: JSON.stringify({protocol: 'fabric/0.1', id, method, params})})).json());
  const mint = async user => (await call('POST', `/v1/users/${user}/agent-tokens`, {name: 'Asker', requestable: [{capabilityId: cap.id}]})).body;
  const token = await mint('u1');
  const listed = (await agent(token.token, 'capabilities.list', {})).result.capabilities[0];
  assert.deepEqual([listed.connectionId, listed.status, listed.approval, listed.signIn], [null, 'connection_required', 'after_connection', 'available']);
  const params = {appId: 'github', capabilityId: cap.id, definitionHash: cap.definitionHash, args: {owner: 'o', repo: 'r'}};
  const asked = await agent(token.token, 'calls.create', params, 'ask-1');
  assert.deepEqual([asked.result.status, asked.result.connectionId, asked.result.handoff.state], ['awaiting_connection', null, 'awaiting_owner']);
  assert.equal(/http|#k=|\/connect\//.test(JSON.stringify(asked)), false, 'no link for the agent');
  assert.equal((await agent(token.token, 'calls.create', params, 'ask-1')).result.id, asked.result.id, 'the same request id is the same request');
  // The developer sees the hold, mints the link from the relayed session, and the person signs in and confirms.
  const developer = (await call('GET', `/v1/executions/${asked.result.id}`)).body;
  assert.deepEqual([developer.status, developer.handoff.connectSessionId], ['connection_required', asked.result.handoff.connectSessionId]);
  const {binding} = await open(asked.result.handoff.connectSessionId);
  sim.identity = 600; const finish = await signIn(asked.result.handoff.connectSessionId, binding);
  app.sessions.confirm(asked.result.handoff.connectSessionId, binding, finish);
  await app.sessions.settled();
  await call('GET', `/v1/executions/${asked.result.id}?waitMs=3000`);
  const ran = (await agent(token.token, 'calls.get', {callId: asked.result.id})).result;
  assert.deepEqual([ran.id, ran.status], [asked.result.id, 'succeeded'], 'the grant has no bindings: the hold alone authorised it');
  assert.match(ran.connectionId, /^acct_[a-z2-7]{26}$/); assert.equal(sentRepo(), 1);
  assert.equal(repo().list('activity').find(row => row.type === 'execution.held' && row.callRef === asked.result.id)?.agentId, token.agentToken.id);
  // Withdraw: once; a second time is an invalid transition; another token's call is not_found.
  const second = (await agent(token.token, 'calls.create', {...params, args: {owner: 'o', repo: 'x'}}, 'ask-2')).result;
  const other = await mint('u1');
  assert.equal((await agent(other.token, 'calls.cancel', {callId: second.id})).error.code, 'not_found');
  assert.equal((await agent(token.token, 'calls.cancel', {callId: second.id})).result.status, 'cancelled');
  assert.equal((await agent(token.token, 'calls.cancel', {callId: second.id})).error.code, 'invalid_transition');
  assert.equal((await agent(token.token, 'calls.cancel', {callId: asked.result.id})).error.code, 'unsupported_route', 'a submitted call is the person\'s to cancel');
  // Revoking the token while a request waits closes it: a later confirm resumes nothing.
  const third = (await agent(other.token, 'calls.create', {...params, args: {owner: 'o', repo: 'y'}}, 'ask-3')).result;
  const t3 = await open(third.handoff.connectSessionId);
  await call('POST', `/v1/users/u1/agent-tokens/${other.agentToken.id}/revoke`);
  assert.equal((await call('GET', `/v1/executions/${third.id}`)).body.status, 'cancelled');
  const accounts = app.sessions.view(third.handoff.connectSessionId, t3.binding);
  assert.equal(accounts.state, 'cancelled');
  await app.sessions.settled();
  assert.equal(repo().get('jobs', third.id), null); assert.equal(sentRepo(), 1);
});

test('through MCP, an agent\'s account request names its Connect session for the app, never a link', async t => {
  const {app, call, cap} = await setup(t);
  const token = (await call('POST', '/v1/users/u1/agent-tokens', {name: 'Asker', requestable: [{capabilityId: cap.id}]})).body;
  const server = createMcpAdapter({env: {FABRIC_ENDPOINT: `${app.origin}/fabric/v1`, FABRIC_CLIENT_TOKEN: token.token}}), client = new Client({name: 'tenant-mcp-handoff', version: '1.0.0'});
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); });
  const listed = (await client.callTool({name: 'fabric_list_capabilities', arguments: {}})).structuredContent.capabilities[0];
  assert.deepEqual([listed.status, listed.connectionId, listed.signIn], ['connection_required', null, 'available']);
  const reply = await client.callTool({name: 'fabric_invoke', arguments: {requestId: 'mcp-ask-1', appId: 'github', capabilityId: cap.id, definitionHash: cap.definitionHash, args: {owner: 'o', repo: 'r'}}});
  const value = reply.structuredContent;
  assert.deepEqual([value.status, value.handoff.url, value.handoff.state], ['awaiting_connection', null, 'awaiting_owner']);
  assert.match(value.handoff.connectSessionId, /^cs_[a-z2-7]{26}$/);
  assert.match(reply.content[0].text, new RegExp(`Connect link for session ${value.handoff.connectSessionId}`));
  assert.equal(JSON.stringify(reply).includes(app.origin), false);
});

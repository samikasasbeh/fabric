import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash, randomBytes} from 'node:crypto';
import {existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createApp, lockDataDir} from '../server.mjs';
import {CERTIFICATION_PORT, certificationFolderRefusal, checkCertification} from '../lib/certification.mjs';
import {createGuard, newRunId, refuseRequest, GUARD_WORDS} from '../lib/live-guard.mjs';
import {MARKER} from '../lib/local-authority.mts';
import {resolveTenantRoot} from '../lib/tenant/environments.mjs';
import {PermissionManager, ACTION_WORDS} from '../lib/permissions.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {FabricProtocol} from '../lib/fabric-protocol.mjs';
import {shippedFolder, accounts} from './fixtures/actions/owner-fixture.mjs';
import {actionHarness, SlackScript, OWNER} from './fixtures/actions/runtime-fixture.mjs';
import {freePort} from './fixtures/signin-fixture.mjs';

// F10.12 part 1 (docs/F10.12-BUILD-MAP.md section 3, test/live-certification.test.mjs): the certification runtime. createApp() with the
// `certification` option, built on port 4320 without ever listening there (only start() listens), with scripted answers behind the
// network seam. Pages are read through a throwaway listener on a free port that sends the Host header the app expects.

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DESIGNATED = {mode: 'new', ownerPrincipal: OWNER};

function temp(t, prefix = 'fabric-certification-') {
  const folder = mkdtempSync(path.join(tmpdir(), prefix));
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  return folder;
}
/** Every file under a folder with its size, time and content hash, so a refusal that opened or wrote anything shows. */
function snapshot(folder) {
  if (!existsSync(folder)) return null;
  const files = {};
  const walk = dir => {
    for (const entry of readdirSync(dir, {withFileTypes: true})) {
      const file = path.join(dir, entry.name), stats = lstatSync(file);
      if (entry.isDirectory()) { files[path.relative(folder, file) + '/'] = stats.mtimeMs; walk(file); }
      else files[path.relative(folder, file)] = [stats.size, stats.mtimeMs, createHash('sha256').update(readFileSync(file)).digest('hex')];
    }
  };
  walk(folder);
  return files;
}
/** A guard that passes everything to the inner requester and records what reached it. */
function passGuard(seen = [], signIns = []) {
  return {seen, signIns, wrap: inner => async options => { seen.push(`${options.method ?? 'GET'} ${options.url}`); return inner(options); }, signIn: (providerId, scopes) => { signIns.push([providerId, [...scopes]]); }};
}
/** A certification Fabric over a fresh folder, never listening on 4320. */
async function certApp(t, {dataDir = path.join(temp(t), 'harness'), guard = passGuard(), request, actions, localAuthority = DESIGNATED} = {}) {
  const app = await createApp({dataDir, port: CERTIFICATION_PORT, localAuthority, certification: {guard}, ...(request ? {request} : {}), ...(actions ? {actions} : {})});
  let closed = false;
  t.after(async () => { if (!closed) { closed = true; await app.close(); } });
  return {app, dataDir, close: async () => { if (!closed) { closed = true; await app.close(); } }};
}
/** Listens on a free port (never 4188 or 4320) and calls the app as the browser does, with the Host header of 127.0.0.1:4320. */
async function listen(t, app) {
  await new Promise((resolve, reject) => { app.server.once('error', reject); app.server.listen(0, '127.0.0.1', resolve); });
  const port = app.server.address().port;
  assert.ok(![4188, CERTIFICATION_PORT].includes(port));
  const send = (method, route, {data, cookie, csrf} = {}) => new Promise((resolve, reject) => {
    const body = data === undefined ? null : JSON.stringify(data);
    const request = http.request({host: '127.0.0.1', port, method, path: route, headers: {host: `127.0.0.1:${CERTIFICATION_PORT}`, ...(body ? {'content-type': 'application/json', 'content-length': Buffer.byteLength(body)} : {}),
      ...(cookie ? {cookie} : {}), ...(csrf ? {'x-fabric-csrf': csrf} : {})}}, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch {} resolve({status: response.statusCode, headers: response.headers, text, json}); });
    });
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
  const state = await send('GET', '/api/state');
  const session = {cookie: String(state.headers['set-cookie']).split(';')[0], csrf: state.json.csrfToken};
  return {send, owned: (method, route, data) => send(method, route, {data, ...session}), state};
}
/** A certification Runtime beside the harness's own, over the same store, catalog and simulator. */
function certRuntime(h, {request = h.simulator.request} = {}) {
  const permissions = new PermissionManager({store: h.store, groups: h.groups, configs: h.configs});
  const proxyPolicy = new ProxyPolicy({store: h.store, permissions, groups: h.groups, configs: h.configs});
  const runtime = new Runtime({store: h.store, permissions, proxyPolicy, connections: h.connections, request, clock: () => h.now, actions: h.catalog, ownerPrincipal: OWNER, certification: true});
  return {runtime, permissions, proxyPolicy};
}
const approveAll = async (runtime, job) => { for (let turns = 0; job.status === 'awaiting_approval' && turns < 4; turns++) job = await runtime.approve(job.id, job.approvalDigest, OWNER); return job; };

test('cert 1: the harness refuses the main data folder, a link to it, a folder inside it, the repository and a folder in it, a tenant root and a folder an ordinary Fabric wrote, before any file opens', async t => {
  // The folder rule over a temporary repository root.
  const root = temp(t, 'fabric-certification-root-'), main = path.join(root, '.fabric'), outside = temp(t);
  mkdirSync(main);
  mkdirSync(path.join(root, 'docs'));
  const link = path.join(outside, 'link-to-main');
  symlinkSync(main, link);
  assert.match(certificationFolderRefusal(main, {root}), /main data folder/);
  assert.match(certificationFolderRefusal(link, {root}), /main data folder/, 'a symbolic link to it');
  assert.match(certificationFolderRefusal(path.join(link, 'not-yet'), {root}), /main data folder/, 'a new folder through the link');
  assert.match(certificationFolderRefusal(path.join(main, 'inside'), {root}), /main data folder/, 'a folder inside it');
  assert.match(certificationFolderRefusal(root, {root}), /main data folder/, 'a folder that holds it');
  assert.match(certificationFolderRefusal(path.join(root, 'docs'), {root}), /repository/);
  assert.match(certificationFolderRefusal(path.join(root, 'docs', 'new'), {root}), /repository/);
  assert.match(certificationFolderRefusal('relative/harness', {root}), /absolute/);
  const tenant = resolveTenantRoot(path.join(temp(t), 'tenants'));
  assert.match(certificationFolderRefusal(tenant, {root}), /developer layer/);
  assert.match(certificationFolderRefusal(path.join(tenant, 'env'), {root}), /developer layer/);
  // A folder an ordinary Fabric wrote: its store has no designated marker.
  const ordinary = temp(t);
  await (await createApp({dataDir: ordinary, port: await freePort(), request: async () => { throw new Error('no network'); }})).close();
  assert.match(certificationFolderRefusal(ordinary, {root}), /without the live-test harness/);
  const busy = temp(t);
  writeFileSync(path.join(busy, 'notes.txt'), 'mine');
  assert.match(certificationFolderRefusal(busy, {root}), /holds other files/);
  // Accepted: a new folder, an empty one, one holding only the lock and the guard's files, and a store the harness made.
  assert.equal(certificationFolderRefusal(path.join(temp(t), 'new', 'harness'), {root}), null);
  const empty = temp(t);
  assert.equal(certificationFolderRefusal(empty, {root}), null);
  mkdirSync(path.join(empty, 'live-certify'));
  writeFileSync(path.join(empty, 'runtime.lock'), '1');
  assert.equal(certificationFolderRefusal(empty, {root}), null);
  const made = await certApp(t);
  await made.close();
  assert.equal(readFileSync(path.join(made.dataDir, 'fabric.sqlite')).readUInt32BE(68), MARKER);
  assert.equal(certificationFolderRefusal(made.dataDir, {root}), null);
  // Through createApp(), with the real repository: every refusal comes before a file opens.
  const insideRepo = path.join(ROOT, 'test', `not-a-harness-${randomBytes(4).toString('hex')}`), mainHere = existsSync(path.join(ROOT, '.fabric'));
  const before = snapshot(ordinary), busyBefore = snapshot(busy), tenantBefore = snapshot(tenant);
  for (const [dataDir, words] of [[path.join(ROOT, '.fabric'), /main data folder/], [ROOT, /main data folder|repository/], [path.join(ROOT, 'docs'), /repository/], [insideRepo, /repository/],
    [tenant, /developer layer/], [ordinary, /without the live-test harness/], [busy, /holds other files/], ['relative/harness', /absolute/]]) {
    await assert.rejects(createApp({dataDir, port: CERTIFICATION_PORT, localAuthority: DESIGNATED, certification: {guard: passGuard()}}), {message: words}, dataDir);
  }
  assert.deepEqual([snapshot(ordinary), snapshot(busy), snapshot(tenant), existsSync(insideRepo), existsSync(path.join(ROOT, '.fabric'))], [before, busyBefore, tenantBefore, false, mainHere]);
});

test('cert 2: certification is refused without a designated store, on another port, as true, or with a guard that lacks wrap or signIn', async t => {
  const guard = passGuard(), dataDir = path.join(temp(t), 'harness');
  for (const [options, words] of [[{localAuthority: undefined, certification: {guard}}, /designated/], [{port: 4321, certification: {guard}}, /4320/], [{port: 4188, certification: {guard}}, /4320/],
    [{certification: true}, /guard/], [{certification: {guard: {wrap: guard.wrap}}}, /guard/], [{certification: {guard: {signIn: guard.signIn}}}, /guard/],
    [{certification: {guard: {wrap: 'wrap', signIn: guard.signIn}}}, /guard/], [{certification: {guard, extra: true}}, /guard/], [{certification: {}}, /guard/], [{certification: null}, /guard/]]) {
    await assert.rejects(createApp({dataDir, port: CERTIFICATION_PORT, localAuthority: DESIGNATED, ...options}), {message: words}, JSON.stringify(Object.keys(options)));
  }
  assert.equal(existsSync(dataDir), false, 'nothing opened');
  assert.throws(() => checkCertification(true), /guard/);
  assert.throws(() => checkCertification({guard: {wrap() {}, signIn: 1}}), /guard/);
  assert.deepEqual(Object.keys(checkCertification({guard})), ['guard']);
  const {app} = await certApp(t, {dataDir, guard});
  assert.equal(app.origin, 'http://127.0.0.1:4320');
  assert.equal(app.runtime.permissions.certification, true);
});

test('cert 3: without the option nothing changes: a placed candidate is not executable, validateJob() refuses it and no grant binds it', async t => {
  const where = shippedFolder(t);
  where.pass(false);
  const app = await createApp({dataDir: temp(t), port: await freePort(), localAuthority: DESIGNATED, actions: where.options, request: async () => { throw new Error('no network'); }});
  t.after(() => app.close());
  accounts(app);
  const gists = app.store.get('capabilities', where.idOf('list-gists v1')), connection = app.store.get('connections', 'github-account');
  const decision = app.runtime.permissions.decision(connection, gists);
  assert.deepEqual([gists.status, decision.status, decision.executable, decision.certifying, app.runtime.permissions.certification], ['candidate', 'candidate', false, undefined, false]);
  assert.notEqual(decision.reason, ACTION_WORDS.certifying);
  assert.throws(() => app.runtime.validateJob({connectionId: 'github-account', capabilityId: gists.id, args: {}}), /reviewed, active capability/);
  assert.equal(app.runtime.permissions.certifying(gists), false);
  assert.throws(() => app.protocol.createClient({name: 'Agent', bindings: [{connectionId: 'github-account', capabilityId: gists.id}], expiresInSeconds: 3600}, OWNER), /reviewed operations/);
});

test('cert 4: candidates run at Ask only: a placed, pinned candidate on Allow rows asks, binds and runs after one approval; never at Allow; Never still refuses; unplaced, repinned and superseded never run; an active action asks too', async t => {
  const h = actionHarness(t, {designated: true, evidence: () => ({})});
  const {runtime, permissions, proxyPolicy} = certRuntime(h), connection = h.store.get('connections', h.account), list = h.capability('list-items v1');
  assert.equal(list.status, 'candidate');
  const plain = h.permissions.decision(connection, list), certifying = permissions.decision(connection, list);
  assert.deepEqual([plain.executable, plain.mode], [false, 'allow']);
  assert.deepEqual([certifying.status, certifying.executable, certifying.certifying, certifying.mode, certifying.prepareMode, certifying.performMode, certifying.requiresApproval, certifying.reason],
    ['candidate', true, true, 'ask', 'allow', 'ask', true, ACTION_WORDS.certifying]);
  assert.match(ACTION_WORDS.certifying, /^Certification run: this action runs at Ask only, for its live tests\. Only a reviewed file with live evidence makes it active \(I8\)\.$/);
  // It binds into a client grant only in the certification runtime, and an agent's calls.create on that grant waits for the owner's one approval.
  const protocol = new FabricProtocol({store: h.store, runtime, clock: () => h.now, origin: 'http://127.0.0.1:4320'});
  runtime.authorizeSource = job => protocol.authorizeJob(job);
  const grant = protocol.createClient({name: 'C0', bindings: [{connectionId: h.account, capabilityId: list.id}], expiresInSeconds: 3600}, OWNER);
  assert.equal(grant.client.bindings.length, 1);
  const called = await protocol.handle(`Bearer ${grant.token}`, {protocol: 'fabric/0.1', id: 'RUNID234.C0.1', method: 'calls.create',
    params: {connectionId: h.account, capabilityId: list.id, definitionHash: grant.client.bindings[0].definitionHash, args: {kind: 'all'}}});
  assert.equal(called.result.status, 'awaiting_approval', JSON.stringify(called.error ?? null));
  const waiting = h.store.get('jobs', called.result.id);
  assert.equal(waiting.source.requestId, 'RUNID234.C0.1');
  await runtime.approve(waiting.id, waiting.approvalDigest, OWNER);
  const got = await protocol.handle(`Bearer ${grant.token}`, {protocol: 'fabric/0.1', id: 'RUNID234.C0.2', method: 'calls.get', params: {callId: waiting.id}});
  assert.equal(got.result.status, 'succeeded');
  assert.throws(() => new FabricProtocol({store: h.store, runtime: h.runtime, clock: () => h.now, origin: 'http://127.0.0.1:4188'}).createClient({name: 'C0', bindings: [{connectionId: h.account, capabilityId: list.id}]}, OWNER), /reviewed operations/);
  // It runs after one approval, and never at Allow, even with its own record at Allow.
  permissions.set({connectionId: h.account, capabilityId: list.id, mode: 'allow'});
  assert.equal(permissions.decision(connection, list).mode, 'ask');
  const job = await runtime.createJob({connectionId: h.account, capabilityId: list.id, args: {kind: 'all'}}, OWNER);
  assert.equal(job.status, 'awaiting_approval');
  const done = await runtime.approve(job.id, job.approvalDigest, OWNER);
  assert.equal(done.status, 'succeeded');
  assert.equal(h.store.get('capabilities', list.id).status, 'candidate', 'a run promotes nothing (I8)');
  await assert.rejects(h.runtime.createJob({connectionId: h.account, capabilityId: list.id, args: {kind: 'all'}}, OWNER), /reviewed, active capability/, 'the ordinary runtime still refuses it');
  // A Never row still refuses.
  proxyPolicy.set({connectionId: h.account, row: 'group:fixture.items.read', mode: 'deny'});
  assert.deepEqual([permissions.decision(connection, list).mode, permissions.decision(connection, list).executable], ['deny', false]);
  await assert.rejects(runtime.createJob({connectionId: h.account, capabilityId: list.id, args: {kind: 'all'}}, OWNER));
  // Unplaced, repinned and superseded candidates never qualify.
  const unplaced = actionHarness(t, {designated: true, evidence: () => ({}), map: null}), unplacedRun = certRuntime(unplaced);
  assert.equal(unplacedRun.permissions.certifying(unplaced.capability('list-items v1')), false);
  assert.equal(unplacedRun.permissions.decision(unplaced.store.get('connections', unplaced.account), unplaced.capability('list-items v1')).executable, false);
  await assert.rejects(unplacedRun.runtime.createJob({connectionId: unplaced.account, capabilityId: unplaced.idOf('list-items v1'), args: {kind: 'all'}}, OWNER));
  const repinned = actionHarness(t, {designated: true, evidence: () => ({}), codeHashes: ids => Object.fromEntries(ids.map(id => [id, 'f'.repeat(64)]))}), repinnedRun = certRuntime(repinned);
  const remove = repinned.capability('remove-labels v1');
  assert.equal(repinned.catalog.pinned(repinned.catalog.entries.get(remove.id)), false);
  assert.equal(repinnedRun.permissions.certifying(remove), false);
  await assert.rejects(repinnedRun.runtime.createJob({connectionId: repinned.account, capabilityId: remove.id, args: {itemId: 'I1', names: ['a']}}, OWNER));
  const old = {...list, id: [...h.catalog.superseded.keys()][0]};
  h.store.put('capabilities', old);
  assert.equal(permissions.certifying(old), false);
  assert.equal(permissions.decision(connection, old).executable, false);
  // The stored record must say candidate too.
  assert.equal(permissions.certifying({...h.capability('send-draft v1'), status: 'active'}), false);
  // An active action asks too.
  const active = actionHarness(t, {designated: true}), activeRun = certRuntime(active), activeList = active.capability('list-items v1');
  assert.equal(activeList.status, 'active');
  const activeDecision = activeRun.permissions.decision(active.store.get('connections', active.account), activeList);
  assert.deepEqual([activeDecision.mode, activeDecision.executable, activeDecision.certifying, active.permissions.decision(active.store.get('connections', active.account), activeList).mode], ['ask', true, undefined, 'allow']);
});

test('cert 5: every request of every module passes the guard: a sign-in check, a discovery, a read and a write reach the inner requester exactly as the guard saw them', async t => {
  const where = shippedFolder(t);
  where.pass(false);
  const slack = new SlackScript(), reached = [];
  const request = async options => {
    reached.push(`${options.method ?? 'GET'} ${options.url}`);
    const url = new URL(options.url);
    if (url.origin === 'https://slack.com') return slack.request(options);
    if (url.href === 'https://api.github.com/user') return {status: 200, headers: {}, data: {id: 101, login: 'octo', name: 'Octo'}};
    if (url.pathname === '/gists') return {status: 200, headers: {}, data: []};
    return {status: 200, headers: {}, data: {kind: 'discovery#restDescription'}};
  };
  const guard = passGuard(), {app} = await certApp(t, {guard, request, actions: where.options});
  accounts(app);
  const gists = await approveAll(app.runtime, await app.runtime.createJob({connectionId: 'github-account', capabilityId: where.idOf('list-gists v1'), args: {}}, OWNER));
  const dm = await approveAll(app.runtime, await app.runtime.createJob({connectionId: 'slack-account', capabilityId: where.idOf('send-dm v1'), args: {email: 'grace@example.com', text: 'Lunch?'}}, OWNER));
  await app.discovery.discover({appId: 'google-calendar'}).catch(() => {});
  // The identity check last: its scripted account differs from the stored one, so it leaves the account needing a sign-in.
  await app.connections.check('github-account').catch(() => {});
  assert.ok(['succeeded', 'failed'].includes(gists.status) && dm.status === 'succeeded', `${gists.status} ${dm.status} ${dm.error}`);
  assert.deepEqual(guard.seen, reached);
  for (const expected of ['GET https://api.github.com/user', 'GET https://www.googleapis.com/discovery/v1/apis/calendar/v3/rest', 'GET https://api.github.com/gists', 'POST https://slack.com/api/chat.postMessage']) {
    assert.ok(reached.some(line => line.startsWith(expected)), expected);
  }
  assert.equal(slack.writes().length, 2);
});

test('cert 6: a perform step the guard refuses ends the job failed with action_refused, writesSent empty and nothing sent', async t => {
  const h = actionHarness(t, {designated: true, evidence: () => ({})});
  const rules = {fixture: {base: 'https://api.fixture.test', route: request => request.method === 'GET' ? {write: false} : refuseRequest('not_allowlisted')}};
  const guard = createGuard({appId: 'fixture', runId: newRunId(), folder: temp(t), key: randomBytes(32), rules});
  const {runtime} = certRuntime(h, {request: guard.wrap(h.simulator.request)});
  guard.begin('T1');
  const job = await runtime.createJob({connectionId: h.account, capabilityId: h.idOf('send-draft v1'), args: {draftId: 'D1'}}, OWNER);
  assert.equal(job.status, 'awaiting_approval');
  const ended = await approveAll(runtime, job);
  assert.deepEqual([ended.status, ended.errorCode, ended.details, ended.action.writesSent, ended.error], ['failed', 'action_refused', {reason: 'live_guard', rule: 'not_allowlisted'}, [], GUARD_WORDS.not_allowlisted]);
  assert.deepEqual(h.simulator.calls.filter(call => call.method !== 'GET'), [], 'nothing was sent');
  assert.equal(guard.trace('T1').length, h.simulator.calls.length, 'only the reads were sent');
});

test('cert 7 (critique test 2): a disconnect in the certification folder makes zero revocation calls, disconnects there only and leaves the main folder untouched', async t => {
  const tokens = {accessToken: 'ya29.cert-access-token', refreshToken: '1//cert-refresh-token', expiresAt: Date.now() + 3_600_000, scopes: ['openid', 'email', 'https://www.googleapis.com/auth/calendar.events']};
  const account = id => ({id, appId: 'google-calendar', providerId: 'google', driver: 'http', authMethod: 'oauth', authRevision: 'r1', status: 'ready', label: 'Calendar', identity: {id: 'google-sub-1', displayName: 'owner@fabric-owner.test'},
    scopes: tokens.scopes, allowedOrigins: ['https://www.googleapis.com'], createdAt: new Date().toISOString()});
  // The main folder: an ordinary Fabric with a Google connection for the same account.
  const main = temp(t), ordinary = await createApp({dataDir: main, port: await freePort(), request: async () => { throw new Error('no network'); }});
  ordinary.store.put('connections', account('main-google'));
  ordinary.vault.set('main-google', tokens);
  await ordinary.close();
  const before = snapshot(main);
  // The certification folder, with the real guard behind a recorder: no revocation request may even reach the guard.
  const folder = path.join(temp(t), 'harness'), real = createGuard({appId: 'google-calendar', runId: newRunId(), folder: temp(t), key: randomBytes(32)}), atGuard = [], reached = [];
  const guard = {wrap: inner => { const wrapped = real.wrap(inner); return async options => { atGuard.push(options.url); return wrapped(options); }; }, signIn: real.signIn};
  const {app, close} = await certApp(t, {dataDir: folder, guard, request: async options => { reached.push(options.url); return {status: 200, headers: {}, data: {}}; }});
  app.store.put('connections', account('cert-google'));
  app.vault.set('cert-google', tokens);
  app.oauth.clientId = 'cert-client'; app.oauth.clientSecret = 'cert-secret';
  const result = await app.oauth.revoke('cert-google', undefined, {remote: true, confirmSiblings: true});
  assert.deepEqual([result.remoteRevoked, app.store.get('connections', 'cert-google').status, atGuard, reached], [false, 'revoked', [], []]);
  assert.match(result.message, /^Disconnected here\./);
  await close();
  assert.deepEqual(snapshot(main), before);
});

test('cert 8: a sixth GitHub sign-in within an hour, or one that would make 10 in total, is refused before the browser opens; the start route passes the requested scopes', async t => {
  const previous = {id: process.env.FABRIC_GITHUB_CLIENT_ID, secret: process.env.FABRIC_GITHUB_CLIENT_SECRET};
  Object.assign(process.env, {FABRIC_GITHUB_CLIENT_ID: 'cert-github-client', FABRIC_GITHUB_CLIENT_SECRET: 'cert-github-secret'});
  t.after(() => { for (const [key, value] of [['FABRIC_GITHUB_CLIENT_ID', previous.id], ['FABRIC_GITHUB_CLIENT_SECRET', previous.secret]]) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  const real = createGuard({appId: 'github', runId: newRunId(), folder: temp(t), key: randomBytes(32)}), asked = [];
  const guard = {wrap: real.wrap, signIn: (providerId, scopes) => { asked.push([providerId, [...scopes]]); return real.signIn(providerId, scopes); }};
  const {app} = await certApp(t, {guard, request: async () => { throw new Error('no network'); }});
  const web = await listen(t, app), start = () => web.owned('POST', '/api/oauth/github/start', {appId: 'github', writeAccess: true});
  const flows = () => app.store.list('oauthFlows').length;
  // No count from elsewhere yet: refused, with no URL and no flow.
  const first = await start();
  assert.deepEqual([first.status, first.json.code, first.json.error, first.json.authorizationUrl, flows()], [429, 'rate_limited', GUARD_WORDS.github_elsewhere, undefined, 0]);
  const [[providerId, scopes]] = asked;
  assert.equal(providerId, 'github');
  real.setElsewhere('github', scopes, 0);
  for (let index = 0; index < 5; index++) {
    const started = await start();
    assert.equal(started.status, 200);
    assert.deepEqual(new URL(started.json.authorizationUrl).searchParams.get('scope').split(' ').sort(), [...scopes].sort(), 'the guard saw the scope set the URL asks for');
  }
  assert.equal(flows(), 5);
  const sixth = await start();
  assert.deepEqual([sixth.status, sixth.json.code, sixth.json.error, sixth.json.authorizationUrl, flows()], [429, 'rate_limited', GUARD_WORDS.github_hourly, undefined, 5]);
  // The lifetime count on a provider start: 8 live elsewhere, so the second sign-in here would make 10.
  const lifetime = createGuard({appId: 'github', runId: newRunId(), folder: temp(t), key: randomBytes(32)});
  const other = await certApp(t, {guard: lifetime, request: async () => { throw new Error('no network'); }});
  const provider = other.app.connections.providers.resolve({providerId: 'github', appId: 'github'});
  lifetime.setElsewhere('github', scopes, 8);
  assert.ok(provider.start({appId: 'github', writeAccess: true}).authorizationUrl);
  assert.throws(() => provider.start({appId: 'github', writeAccess: true}), error => error.code === 'rate_limited' && error.message === GUARD_WORDS.github_tokens);
  assert.equal(other.app.store.list('oauthFlows').length, 1);
});

test('cert 9: lockDataDir() refuses a second lock while the first holds, and its release lets the next one take it', async t => {
  const folder = path.join(temp(t), 'harness'), release = await lockDataDir(folder);
  assert.equal(statSync(folder).mode & 0o777, 0o700);
  assert.equal(readFileSync(path.join(folder, 'runtime.lock'), 'utf8'), String(process.pid));
  await assert.rejects(lockDataDir(folder), /already running/);
  await release();
  assert.equal(existsSync(path.join(folder, 'runtime.lock')), false);
  const again = await lockDataDir(folder);
  await again();
});

test('cert 10: the connectors page and an app page still load in certification mode, and nothing they read reaches a provider', async t => {
  const reached = [], guard = createGuard({appId: 'google-calendar', runId: newRunId(), folder: temp(t), key: randomBytes(32)});
  const {app} = await certApp(t, {guard, request: async options => { reached.push(options.url); throw new Error('no network'); }});
  const web = await listen(t, app);
  assert.equal(web.state.status, 200);
  for (const route of ['/connectors', '/connectors/google-calendar', '/api/ui/catalog', '/api/ui/apps/google-calendar', '/api/ui/apps/github']) {
    const page = await web.owned('GET', route);
    assert.equal(page.status, 200, `${route}: ${page.text.slice(0, 200)}`);
  }
  assert.deepEqual(reached, []);
});

// F10.12 check: build map section 10, item 2, says a linked store counts as not made by the harness; a hand-made fault that dropped the
// link check was caught by no test.
test('cert 11 (F10.12 check): a fabric.sqlite that is a symbolic link counts as not made by the harness, even when it reaches a store the harness made, and nothing opens', async t => {
  const root = temp(t, 'fabric-certification-root-');
  mkdirSync(path.join(root, '.fabric'));
  const made = await certApp(t);
  await made.close();
  assert.equal(certificationFolderRefusal(made.dataDir, {root}), null, 'the store itself is the harness\'s own');
  const linked = temp(t);
  symlinkSync(path.join(made.dataDir, 'fabric.sqlite'), path.join(linked, 'fabric.sqlite'));
  const before = [snapshot(made.dataDir), snapshot(linked)];
  assert.match(certificationFolderRefusal(linked, {root}), /without the live-test harness/);
  await assert.rejects(createApp({dataDir: linked, port: CERTIFICATION_PORT, localAuthority: {...DESIGNATED, mode: 'require'}, certification: {guard: passGuard()}}), {message: /without the live-test harness/});
  assert.deepEqual([snapshot(made.dataDir), snapshot(linked)], before);
});

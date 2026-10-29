import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {mkdtemp, readdir, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createApp} from '../server.mjs';
import {RELAY_PORTS, RELAY_APPS_PORT, relayed, relayOrigin, relayAppRedirect} from '../lib/oauth-relay.mjs';
import {definitionFor, reviewedProviderIds} from '../lib/providers/definitions.mjs';
import {freePort} from './fixtures/signin-fixture.mjs';
import {NotionSimulator} from './fixtures/oauth-simulators.mjs';

// Callback relay (docs/AUTH-ENGINE.md): providers that refuse loopback callbacks (Slack, Notion) are given
// <base>/oauth/<provider>/<port>/callback; the static page in relay/index.html sends the browser back to the
// loopback callback, where the flow cookie and state are checked. Temporary data, loopback ports, simulated providers.
const ENV = {FABRIC_NOTION_CLIENT_ID: 'relay-notion-client', FABRIC_NOTION_CLIENT_SECRET: 'relay-notion-secret', FABRIC_SLACK_CLIENT_ID: 'relay-slack-client', FABRIC_SLACK_CLIENT_SECRET: 'relay-slack-secret', FABRIC_PUBLIC_CALLBACK_BASE: undefined};
const BASE = 'https://connect.example.com';
const RELAY = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'relay');
const PAGE = await readFile(path.join(RELAY, 'index.html'), 'utf8');
const SCRIPT = /<script>([\s\S]*?)<\/script>/.exec(PAGE)[1];
const RELAYED = reviewedProviderIds().filter(id => relayed(definitionFor(id)));

function environment(t, values) {
  const previous = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  for (const [key, value] of Object.entries(values)) {if (value === undefined) delete process.env[key]; else process.env[key] = value;}
  t.after(() => {for (const [key, value] of Object.entries(previous)) {if (value === undefined) delete process.env[key]; else process.env[key] = value;}});
}
async function open(t, options = {}, env = {}) {
  environment(t, {...ENV, ...env});
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-relay-')), port = await freePort();
  t.after(() => rm(dir, {recursive: true, force: true}));
  const app = await createApp({dataDir: dir, port, request: async () => ({status: 200, data: {}}), ...(typeof options === 'function' ? options(port) : options)});
  await app.start();
  t.after(() => app.close());
  const first = await fetch(`${app.origin}/api/state`), state = await first.json();
  return {app, port, state, session: {cookie: first.headers.get('set-cookie').split(';')[0], csrf: state.csrfToken}};
}
// Runs the hosted page's script against one address, as a browser would, and reports what it did.
function visit(address, script = SCRIPT) {
  const url = new URL(address), seen = {navigated: null, replaced: null, message: null};
  const context = {URLSearchParams, location: {pathname: url.pathname, search: url.search, replace: target => {seen.navigated = target;}},
    history: {replaceState: (_state, _title, target) => {seen.replaced = target;}}, document: {getElementById: () => ({set textContent(value) {seen.message = value;}})}};
  vm.runInNewContext(script, context);
  return seen;
}
const pageList = name => JSON.parse(new RegExp(`${name} = (\\[[^\\]]*\\])`).exec(SCRIPT)[1].replaceAll("'", '"'));

test('the relayed providers are exactly the reviewed definitions that require HTTPS, and the page forwards the same providers and ports', () => {
  assert.deepEqual(RELAYED.sort(), ['notion', 'slack']);
  for (const id of reviewedProviderIds()) assert.equal(relayed(definitionFor(id)), definitionFor(id).authorization.loopbackRedirect === 'https-required', id);
  // A provider whose loopback support is unverified is not relayed: the page would not forward it.
  for (const loopbackRedirect of ['allowed', 'unverified', undefined]) assert.equal(relayed({authorization: {loopbackRedirect}}), false, String(loopbackRedirect));
  assert.deepEqual(pageList('providers').sort(), RELAYED);
  assert.deepEqual(pageList('ports'), RELAY_PORTS.map(String));
});

test('the page allows only its own script, by hash, and says what to do if it never runs', () => {
  // Browsers hash the script text after normalizing line endings to LF; .gitattributes keeps the file LF.
  const hash = createHash('sha256').update(SCRIPT.replace(/\r\n?/g, '\n'), 'utf8').digest('base64');
  const policy = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(PAGE)[1];
  assert.equal(policy, `default-src 'none'; script-src 'sha256-${hash}'; base-uri 'none'; form-action 'none'`);
  assert.match(PAGE, /<meta name="referrer" content="no-referrer">/);
  assert.equal((PAGE.match(/<script/g) || []).length, 1);
  assert.match(PAGE, /<p id="message">Returning to Fabric on this computer\. If nothing happens, start the sign-in again from Fabric\.<\/p>/);
});

test('the relay folder deploys as it is: every /oauth/ path serves the page, with the same policy as response headers', async () => {
  // Netlify reads _redirects and _headers from the published folder; other static hosts need the same two rules.
  assert.equal(await readFile(path.join(RELAY, '_redirects'), 'utf8'), '/oauth/*  /index.html  200\n');
  const headers = (await readFile(path.join(RELAY, '_headers'), 'utf8')).split('\n');
  const policy = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(PAGE)[1];
  assert.equal(headers[0], '/*');
  assert.deepEqual(headers.slice(1).filter(Boolean).map(line => line.trim()), [`Content-Security-Policy: ${policy}; frame-ancestors 'none'`, 'Referrer-Policy: no-referrer', 'Cache-Control: no-store', 'X-Content-Type-Options: nosniff', 'Strict-Transport-Security: max-age=31536000']);
});

test('the page forwards only code, state, error and error_description, first value each, to the matching loopback callback', () => {
  for (const provider of RELAYED) for (const port of RELAY_PORTS) {
    const seen = visit(`${BASE}/oauth/${provider}/${port}/callback?code=C1&state=S1&code=C2&scope=x&redirect=https%3A%2F%2Fevil.example&error_description=nope`);
    assert.equal(seen.navigated, `http://127.0.0.1:${port}/api/oauth/${provider}/callback?code=C1&state=S1&error_description=nope`);
    assert.equal(seen.replaced, null);
  }
  assert.equal(visit(`${BASE}/oauth/notion/4188/callback?error=access_denied&state=S1`).navigated, 'http://127.0.0.1:4188/api/oauth/notion/callback?error=access_denied&state=S1');
});

test('any other address navigates nowhere and takes the code and state out of the address bar', () => {
  for (const address of [
    `${BASE}/oauth/github/4188/callback?code=C&state=S`, `${BASE}/oauth/google/4188/callback?code=C&state=S`,
    `${BASE}/oauth/notion/4189/callback?code=C&state=S`, `${BASE}/oauth/notion/80/callback?code=C&state=S`,
    `${BASE}/oauth/notion/4188/callback/?code=C&state=S`, `${BASE}/oauth/notion/4188/callback/extra?code=C&state=S`,
    `${BASE}/oauth/notion/4188%2F@evil.example/callback?code=C&state=S`, `${BASE}//oauth/notion/4188/callback?code=C&state=S`,
    `${BASE}/oauth/notion/4188?code=C&state=S`, `${BASE}/x/oauth/notion/4188/callback?code=C&state=S`, `${BASE}/?code=C&state=S`,
    `${BASE}/oauth/Notion/4188/callback?code=C&state=S`, `${BASE}/oauth/notion/04188/callback?code=C&state=S`,
  ]) {
    const seen = visit(address);
    assert.equal(seen.navigated, null, address);
    assert.equal(seen.replaced, '/', address);
    assert.match(seen.message, /not a Fabric sign-in address/, address);
  }
});

test('with a relay base on a forwarded port, Notion and Slack get the public callback; Google and GitHub keep their loopback callbacks', async t => {
  const {app, port, state} = await open(t, port => ({publicCallbackBase: BASE, relayPorts: [port]}));
  const providers = state.settings.oauthProviders;
  assert.equal(providers.notion.redirectUri, `${BASE}/oauth/notion/${port}/callback`); assert.equal(providers.notion.available, true);
  assert.equal(providers.slack.redirectUri, `${BASE}/oauth/slack/${port}/callback`); assert.equal(providers.slack.available, true);
  assert.equal(providers.github.redirectUri, `${app.origin}/api/oauth/github/callback`);
  assert.equal(state.settings.googleOAuth.redirectUri, `${app.origin}/api/oauth/google/callback`);
});

test('on a port the page does not forward, Notion and Slack say so and refuse to start instead of dead-ending at the relay', async t => {
  const {app, port, state, session} = await open(t, {publicCallbackBase: BASE});
  assert.equal(RELAY_PORTS.includes(port), false);
  for (const id of ['notion', 'slack']) {
    const provider = state.settings.oauthProviders[id];
    assert.equal(provider.available, false, id);
    assert.equal(provider.reason, `${id === 'notion' ? 'Notion' : 'Slack'} only accepts HTTPS callbacks. The callback relay forwards only Fabric ports 4188 and 4320, and this Fabric runs on port ${port}. Set FABRIC_PORT to one of them.`);
    assert.equal(provider.redirectUri, `${app.origin}/api/oauth/${id}/callback`, `${id} keeps no relay address it cannot use`);
    const started = await fetch(`${app.origin}/api/oauth/${id}/start`, {method: 'POST', headers: {'content-type': 'application/json', 'x-fabric-csrf': session.csrf, cookie: session.cookie}, body: JSON.stringify({appId: id})});
    assert.equal(started.status, 400, id);
  }
  assert.equal(state.settings.oauthProviders.github.redirectUri, `${app.origin}/api/oauth/github/callback`);
});

test('without a relay, Notion and Slack say plainly that they need the relay setting; an empty setting means no relay', async t => {
  const {state} = await open(t, {}, {FABRIC_PUBLIC_CALLBACK_BASE: ''});
  assert.equal(process.env.FABRIC_PUBLIC_CALLBACK_BASE, '');
  for (const id of ['notion', 'slack']) {
    assert.equal(state.settings.oauthProviders[id].available, false, id);
    assert.match(state.settings.oauthProviders[id].reason, /only accepts HTTPS callbacks\. Sign-in becomes available once FABRIC_PUBLIC_CALLBACK_BASE names the hosted callback relay\./, id);
  }
});

test('the relay base must be a public HTTPS origin without a path, and is refused before any local data opens', async t => {
  const refused = ['http://connect.example.com', 'https://connect.example.com/relay', 'https://user@connect.example.com', 'https://127.0.0.1', 'https://127.0.0.2', 'https://10.0.0.1',
    'https://[::1]', 'https://[::ffff:127.0.0.1]', 'https://2130706433', 'https://0x7f.1', 'https://localhost', 'http://localhost', 'https://localhost.', 'https://fabric.localhost', 'https://connect.example.com.',
    'https://connect.example.com?x=1', 'https://connect.example.com?', 'https://connect.example.com#x', 'https://connect.example.com:0', ' https://connect.example.com', '   ', 'not a url'];
  for (const publicCallbackBase of refused) {
    assert.throws(() => relayOrigin(publicCallbackBase), /^Error: FABRIC_PUBLIC_CALLBACK_BASE must be /, JSON.stringify(publicCallbackBase));
    const dir = await mkdtemp(path.join(tmpdir(), 'fabric-relay-bad-'));
    t.after(() => rm(dir, {recursive: true, force: true}));
    await assert.rejects(createApp({dataDir: dir, port: await freePort(), publicCallbackBase}), /FABRIC_PUBLIC_CALLBACK_BASE must be /, JSON.stringify(publicCallbackBase));
    assert.deepEqual(await readdir(dir), [], 'nothing was opened or created');
  }
  assert.equal(relayOrigin('https://Connect.Example.com'), 'https://connect.example.com');
  assert.equal(relayOrigin('https://connect.example.com:8443'), 'https://connect.example.com:8443');
  assert.equal(relayOrigin('https://connect.example.com/'), 'https://connect.example.com');
  for (const unset of [undefined, null, '']) assert.equal(relayOrigin(unset), null);
});

test('a Notion sign-in completes through the page: the provider sees the public callback, Fabric checks the flow locally, the owner sees who connected', async t => {
  let now = Date.parse('2026-10-12T12:00:00.000Z');
  const sim = new NotionSimulator({clientId: ENV.FABRIC_NOTION_CLIENT_ID, clientSecret: ENV.FABRIC_NOTION_CLIENT_SECRET, clock: () => now});
  const {app, port, session} = await open(t, port => ({publicCallbackBase: BASE, relayPorts: [port], clock: () => now, request: async req => sim.request(req)}));
  const started = await fetch(`${app.origin}/api/oauth/notion/start`, {method: 'POST', headers: {'content-type': 'application/json', 'x-fabric-csrf': session.csrf, cookie: session.cookie}, body: JSON.stringify({appId: 'notion'})});
  assert.equal(started.status, 200);
  const {authorizationUrl} = await started.json(), flow = /fabric_oauth=([^;]+)/.exec(started.headers.get('set-cookie'))[1];
  assert.equal(new URL(authorizationUrl).searchParams.get('redirect_uri'), `${BASE}/oauth/notion/${port}/callback`);
  const consent = sim.consent(authorizationUrl);
  assert.ok(consent.code, 'the simulator accepted the authorization request');
  // The hosted page, with this test's port in its list, is what sends the browser back.
  const page = SCRIPT.replace("ports = ['4188', '4320']", `ports = ['${port}']`);
  assert.notEqual(page, SCRIPT);
  const seen = visit(`${BASE}/oauth/notion/${port}/callback?${new URLSearchParams({code: consent.code, state: consent.state})}`, page);
  assert.equal(new URL(seen.navigated).origin, app.origin);
  const relayed = await fetch(seen.navigated, {redirect: 'manual', headers: {cookie: `fabric_oauth=${flow}`}});
  assert.equal(relayed.status, 303);
  const connections = app.store.list('connections').filter(connection => connection.appId === 'notion');
  assert.equal(connections.length, 1); assert.equal(connections[0].status, 'ready', 'the token exchange used the same public callback the provider saw');
  assert.deepEqual(connections[0].identity, {id: 'ws-a:notion-user-a', displayName: 'Avery A', email: 'avery@a.example', workspaceName: 'Workspace A'}, 'the owner sees the person and workspace, not the integration name');
  // Without the flow cookie set on this machine, a relayed callback connects nothing.
  const replay = sim.consent(authorizationUrl);
  await fetch(visit(`${BASE}/oauth/notion/${port}/callback?${new URLSearchParams({code: replay.code, state: replay.state})}`, page).navigated, {redirect: 'manual'});
  assert.equal(app.store.list('connections').filter(connection => connection.appId === 'notion').length, 1);
});

test('without the email capability, a Notion connection still names the owner, and never the integration', async t => {
  let now = Date.parse('2026-10-12T12:00:00.000Z');
  const sim = new NotionSimulator({clientId: ENV.FABRIC_NOTION_CLIENT_ID, clientSecret: ENV.FABRIC_NOTION_CLIENT_SECRET, clock: () => now});
  sim.shareEmail = false;
  const {app, session} = await open(t, port => ({publicCallbackBase: BASE, relayPorts: [port], clock: () => now, request: async req => sim.request(req)}));
  const started = await fetch(`${app.origin}/api/oauth/notion/start`, {method: 'POST', headers: {'content-type': 'application/json', 'x-fabric-csrf': session.csrf, cookie: session.cookie}, body: JSON.stringify({appId: 'notion'})});
  const {authorizationUrl} = await started.json(), flow = /fabric_oauth=([^;]+)/.exec(started.headers.get('set-cookie'))[1];
  const consent = sim.consent(authorizationUrl);
  await fetch(`${app.origin}/api/oauth/notion/callback?${new URLSearchParams({code: consent.code, state: consent.state})}`, {redirect: 'manual', headers: {cookie: `fabric_oauth=${flow}`}});
  const [connection] = app.store.list('connections').filter(item => item.appId === 'notion');
  assert.deepEqual(connection.identity, {id: 'ws-a:notion-user-a', displayName: 'Avery A', workspaceName: 'Workspace A'});
});

test('before the operator configures the client, starting says which callback to register: the relay address, not a loopback one', async t => {
  const {port, app, session, state} = await open(t, port => ({publicCallbackBase: BASE, relayPorts: [port]}), {FABRIC_NOTION_CLIENT_ID: undefined, FABRIC_NOTION_CLIENT_SECRET: undefined});
  assert.equal(state.settings.oauthProviders.notion.available, false);
  const started = await fetch(`${app.origin}/api/oauth/notion/start`, {method: 'POST', headers: {'content-type': 'application/json', 'x-fabric-csrf': session.csrf, cookie: session.cookie}, body: JSON.stringify({appId: 'notion'})});
  const body = await started.json();
  assert.equal(started.status, 400); assert.equal(body.code, 'not_configured');
  assert.equal(body.error, `Notion OAuth is not configured. Set FABRIC_NOTION_CLIENT_ID and FABRIC_NOTION_CLIENT_SECRET and register this callback in your Notion project: ${BASE}/oauth/notion/${port}/callback`);
});

test('relay ports are an embedding seam of one to eight port numbers, refused before any local data opens', async t => {
  for (const relayPorts of [[], Array.from({length: 9}, (_, i) => 5000 + i), ['4188'], [0], [65536], 'not a list']) {
    const dir = await mkdtemp(path.join(tmpdir(), 'fabric-relay-ports-'));
    t.after(() => rm(dir, {recursive: true, force: true}));
    await assert.rejects(createApp({dataDir: dir, port: await freePort(), publicCallbackBase: BASE, relayPorts}), /^Error: Relay ports must be one to eight TCP port numbers\.$/, JSON.stringify(relayPorts));
    assert.deepEqual(await readdir(dir), []);
  }
});

test('an unconfigured Notion or Slack without a usable relay names the relay setting, never a loopback callback the provider refuses', async t => {
  const unset = {FABRIC_NOTION_CLIENT_ID: undefined, FABRIC_NOTION_CLIENT_SECRET: undefined, FABRIC_SLACK_CLIENT_ID: undefined, FABRIC_SLACK_CLIENT_SECRET: undefined};
  for (const [options, help] of [
    [{publicCallbackBase: null}, () => 'Sign-in becomes available once FABRIC_PUBLIC_CALLBACK_BASE names the hosted callback relay.'],
    [{publicCallbackBase: BASE}, port => `The callback relay forwards only Fabric ports 4188 and 4320, and this Fabric runs on port ${port}. Set FABRIC_PORT to one of them.`],
  ]) {
    const {app, port, session} = await open(t, options, unset);
    for (const [id, name] of [['notion', 'Notion'], ['slack', 'Slack']]) {
      const started = await fetch(`${app.origin}/api/oauth/${id}/start`, {method: 'POST', headers: {'content-type': 'application/json', 'x-fabric-csrf': session.csrf, cookie: session.cookie}, body: JSON.stringify({appId: id})});
      const body = await started.json();
      assert.equal(started.status, 400); assert.equal(body.code, 'redirect_unsupported');
      assert.equal(body.error, `${name} only accepts HTTPS callbacks. ${help(port)} No sign-in was started.`);
      assert.doesNotMatch(body.error, /127\.0\.0\.1/);
    }
  }
});

// F03.8, D2: a developer's own Slack or Notion app comes back through /oauth/<provider>/apps/<pa_id>/callback, which the
// page sends to the developer runtime's port only, with the same kept parameters; anything else that looks close is refused.
test('the page forwards a developer app\'s callback to the developer runtime only, and refuses near misses', () => {
  assert.equal(/appsPort = '(\d+)'/.exec(SCRIPT)[1], String(RELAY_APPS_PORT));
  const pa = `pa_${'abcdefghijklmnopqrstuvwxyz'}`;
  for (const provider of RELAYED) {
    const seen = visit(`${relayAppRedirect(BASE, provider, pa)}?code=C1&state=S1&code=C2&scope=x&error_description=nope`);
    assert.equal(seen.navigated, `http://127.0.0.1:${RELAY_APPS_PORT}/api/oauth/${provider}/apps/${pa}/callback?code=C1&state=S1&error_description=nope`, provider);
  }
  const refused = [`/oauth/github/apps/${pa}/callback`, `/oauth/google/apps/${pa}/callback`, `/oauth/slack/apps/${pa.toUpperCase()}/callback`, `/oauth/slack/apps/pa_${'a'.repeat(25)}/callback`,
    `/oauth/slack/apps/pa_${'a'.repeat(27)}/callback`, ...['0', '1', '8', '9'].map(digit => `/oauth/slack/apps/pa_${'a'.repeat(25)}${digit}/callback`), `/oauth/slack/apps/xx_${'a'.repeat(26)}/callback`,
    `/oauth/slack/${pa}/callback`, `/oauth/slack/app/${pa}/callback`, `/oauth/slack/apps/${pa}/callback/`, `/oauth/slack/apps/${pa}/callback/extra`, `/oauth/slack/apps/pa_${'a'.repeat(12)}%2F${'a'.repeat(12)}/callback`,
    `/oauth/slack/4188/apps/${pa}/callback`, `/oauth/slack/apps/4340/callback`];
  for (const pathname of refused) {
    const seen = visit(`${BASE}${pathname}?code=C&state=S`);
    assert.deepEqual([seen.navigated, seen.replaced], [null, '/'], pathname);
    assert.match(seen.message, /not a Fabric sign-in address/, pathname);
  }
});

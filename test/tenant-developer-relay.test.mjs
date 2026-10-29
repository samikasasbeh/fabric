import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {mkdtempSync, rmSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createDeveloperApp} from '../developer-server.mjs';
import {relayAppRedirect} from '../lib/oauth-relay.mjs';
import {SlackSimulator, NotionSimulator} from './fixtures/oauth-simulators.mjs';

// F03.8 slice 4 (D2): a developer's own Slack or Notion app signs in through the relay page. The provider sees the
// public relay address registered for that app; the page sends the browser to the developer runtime; Fabric checks the
// flow there; and every relayed sign-in ends at the confirm screen, activating only on confirm (M11).
const BASE = 'https://connect.example.com';
const PAGE = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'relay', 'index.html'), 'utf8'), SCRIPT = /<script>([\s\S]*?)<\/script>/.exec(PAGE)[1];
function visit(address, script) {
  const url = new URL(address), seen = {navigated: null};
  vm.runInNewContext(script, {URLSearchParams, location: {pathname: url.pathname, search: url.search, replace: target => { seen.navigated = target; }}, history: {replaceState: () => {}}, document: {getElementById: () => ({set textContent(_value) {}})}});
  return seen;
}

for (const [providerId, Simulator] of [['slack', SlackSimulator], ['notion', NotionSimulator]]) {
  test(`a developer's own ${providerId} app signs in through the relay page and waits for the person to confirm`, async t => {
    const root = mkdtempSync(path.join(tmpdir(), `fabric-dev-relay-${providerId}-`));
    const sim = new Simulator({clientId: `dev-${providerId}-client`, clientSecret: `dev-${providerId}-secret`, clock: Date.now});
    const app = await createDeveloperApp({dataRoot: root, port: 0, relay: {base: BASE, appsReady: true}, request: async req => sim.request(req)});
    t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
    const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
    const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
    const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
    const call = async (method, route, body) => (await fetch(`${app.origin}${route}`, {method, headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify(body)})).json();
    const {providerApp, redirectUri} = await call('POST', '/v1/provider-apps', {providerId, clientId: `dev-${providerId}-client`, clientSecret: `dev-${providerId}-secret`, consentScreenName: 'Acme Agent'});
    assert.equal(redirectUri, relayAppRedirect(BASE, providerId, providerApp.id));
    const appId = providerId === 'slack' ? 'slack' : 'notion';
    assert.equal((await call('PUT', `/v1/environment/apps/${appId}`, {providerApp: providerApp.id, enabled: true})).enabled, true);
    const created = await call('POST', '/v1/connect-sessions', {externalUserId: 'u1', appId}), binding = `browser-${created.id}`;
    app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
    const sheet = app.sessions.view(created.id, binding).sheet;
    assert.deepEqual(sheet.providerApp, {kind: 'developer', consentScreenName: 'Acme Agent'}, 'the sheet names the developer\'s own app');
    const started = app.sessions.start(created.id, binding), url = new URL(started.authorizationUrl);
    assert.equal(url.searchParams.get('client_id'), `dev-${providerId}-client`);
    assert.equal(url.searchParams.get('redirect_uri'), redirectUri, 'the provider sees the public relay address for this app');
    const consent = sim.consent(started.authorizationUrl);
    assert.ok(consent.code, consent.error);
    const page = SCRIPT.replace("appsPort = '4340'", `appsPort = '${new URL(app.origin).port}'`);
    const seen = visit(`${redirectUri}?${new URLSearchParams({code: consent.code, state: consent.state})}`, page);
    assert.equal(seen.navigated.startsWith(`${app.origin}${started.callbackPath}?`), true, seen.navigated);
    const back = await fetch(seen.navigated, {redirect: 'manual', headers: {Cookie: `fabric_t_oauth=${started.flowId}`}});
    assert.equal(back.status, 303);
    assert.equal((await call('GET', `/v1/connect-sessions/${created.id}`)).state, 'awaiting_confirmation', 'a relayed sign-in waits at the confirm screen');
    const finish = back.headers.getSetCookie().find(line => line.startsWith('fabric_t_finish=')).split(';')[0].slice('fabric_t_finish='.length);
    const confirmed = app.sessions.confirm(created.id, binding, finish);
    assert.equal(confirmed.state, 'connected');
    const account = app.stores.open(scope).repository.get('connections', confirmed.result.accountRef);
    assert.deepEqual([account.status, account.providerApp], ['ready', {kind: 'developer', id: providerApp.id}]);
    assert.equal((await call('GET', '/v1/provider-apps')).providerApps.find(item => item.id === providerApp.id).status, 'verified', 'the first full sign-in proved the client');
  });
}

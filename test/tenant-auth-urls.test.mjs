import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {definitionFor, reviewedProviderIds} from '../lib/providers/definitions.mjs';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {offeredLevels} from '../lib/access-levels.mjs';
import {signInOf} from '../lib/tenant/views.mjs';

// F03.3b, T6: a sign-in address built inside a developer environment on Fabric's shared app is the single-owner
// runtime's address for the same app and level, apart from the per-sign-in values (state, PKCE challenge) and the
// callback, which is the developer server's own. Nothing about tenancy changes what the provider is asked for.
const SETTINGS = {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}, google: {clientId: 'g-client', clientSecret: 'g-secret'}, notion: {clientId: 'n-client', clientSecret: 'n-secret'}, slack: {clientId: 's-client', clientSecret: 's-secret'}};
const PER_SIGN_IN = ['state', 'code_challenge', 'redirect_uri'];

test('tenant sign-in addresses equal the single-owner ones for every app and level, apart from state, challenge and callback', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-t6-')), local = mkdtempSync(path.join(tmpdir(), 'fabric-t6-local-'));
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: SETTINGS});
  const store = new Store({dataDir: local}), vault = new Vault(local);
  t.after(async () => { await app.close(); store.close(); rmSync(root, {recursive: true, force: true}); rmSync(local, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores), scope = app.registry.scopeOf(dev);
  const key = app.keys.mint({environmentId: dev.id, preset: 'standard'}).token;
  // The real tenant path: a Connect session for one end user, claimed by one browser, started at one level.
  const viaSession = async (appId, level) => {
    const created = await (await fetch(`${app.origin}/v1/connect-sessions`, {method: 'POST', headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify({externalUserId: 't6-user', appId})})).json();
    const binding = `browser-${created.id}`;
    app.sessions.claim(created.id, new URL(created.connectUrl).hash.slice(3), binding);
    return new URL(app.sessions.start(created.id, binding, undefined, level).authorizationUrl);
  };
  const compared = [];
  for (const providerId of reviewedProviderIds()) {
    const definition = definitionFor(providerId), credentials = SETTINGS[providerId];
    const connections = new ConnectionManager({store, vault});
    const single = new OAuth2Provider(definition, {store, vault, connections, clientId: credentials.clientId, clientSecret: credentials.clientSecret, allowHostedRedirect: true,
      redirectUri: providerId === 'slack' || providerId === 'notion' ? 'https://connect.runorra.com/api/oauth/callback' : `http://127.0.0.1:4188/api/oauth/${providerId}/callback`, publishing: 'testing'});
    const tenant = app.sessions.adapterFor(scope, providerId).adapter;
    // Providers that accept only HTTPS callbacks (Notion, Slack) cannot start on the developer server's loopback
    // callback: they wait for the relay (D3), and say so rather than sending anything.
    if (definition.authorization.loopbackRedirect === 'https-required') {
      for (const entry of definition.apps) assert.throws(() => tenant.start({appId: entry.appId, level: 'full'}), {code: 'redirect_unsupported'}, entry.appId);
      continue;
    }
    for (const entry of definition.apps) {
      for (const level of offeredLevels(signInOf(entry.appId).access)) {
        const a = new URL(single.start({appId: entry.appId, level: level === 'read' ? 'read' : 'full'}).authorizationUrl);
        const b = await viaSession(entry.appId, level);
        assert.equal(`${b.origin}${b.pathname}`, `${a.origin}${a.pathname}`, `${entry.appId} ${level}`);
        const strip = url => Object.fromEntries([...url.searchParams].filter(([name]) => !PER_SIGN_IN.includes(name)).sort());
        assert.deepEqual(strip(b), strip(a), `${entry.appId} ${level}`);
        assert.equal(b.searchParams.get('redirect_uri'), `${app.origin}/api/oauth/${providerId}/callback`);
        compared.push(`${entry.appId} ${level}`);
      }
    }
  }
  // Every level of every app whose provider accepts a loopback callback (F10.7: version 2 levels, so GitHub has no read level).
  assert.deepEqual(compared, ['github full', 'google-calendar full', 'gmail full', 'gmail read']);
});

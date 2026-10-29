import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {mkdtemp, rm, access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../lib/store.mjs';
import {PersistentBrowser} from '../lib/persistent-browser.mjs';
import {canonicalHash} from '../lib/compiler.mjs';

const owner = {schemaVersion: 1, kind: 'local_owner', id: 'owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'owner'}};

// This exercises the driver seam, not Runtime policy or a real SaaS account.
// Every browser request is intercepted, and every stored login value is synthetic.
test('authority-mode Chromium profiles retain two synthetic sessions across page and runtime closure', {timeout: 90000}, async t => {
  let chromium;
  try { ({chromium} = await import('playwright')); await access(chromium.executablePath()); }
  catch (error) {
    if (process.env.FABRIC_REQUIRE_BROWSER_TEST === '1') throw error;
    t.skip('The installed Chromium fixture browser is required.'); return;
  }
  const dataDir = await mkdtemp(path.join(tmpdir(), 'fabric-authority-browser-live-'));
  let store = new Store({dataDir, localAuthority: 'new'});
  const apps = ['notes-fixture', 'mail-fixture'].map(id => ({id, name: id, webOrigins: [`https://${id}.fabric.test`]}));
  const launches = [];
  const html = '<!doctype html><title>Authority fixture</title><main id="identity"></main><input type="password" value="never-export-this"><script>document.querySelector("main").textContent=localStorage.getItem("fixture-identity")||"Sign in required";</script>';
  const launch = async (profile, options) => {
    const context = await chromium.launchPersistentContext(profile, {...options, headless: true, serviceWorkers: 'block'});
    await context.route('**/*', route => {
      if (apps.some(app => app.webOrigins.includes(new URL(route.request().url()).origin))) {
        return route.fulfill({status: 200, contentType: 'text/html', body: html});
      }
      return route.abort();
    });
    launches.push({profile, context});
    return context;
  };
  const makeManager = () => new PersistentBrowser({store, catalog: () => apps, dataDir, launch, ownerPrincipal: owner});
  let manager = makeManager();
  t.after(async () => { await manager.shutdown(); store.close(); await rm(dataDir, {recursive: true, force: true}); });
  const read = connection => {
    const cap = store.get('capabilities', `${connection.appId}.session.read.v1`);
    const args = {selector: '#identity'}, id = randomUUID();
    const request = {
      schemaVersion: 1, id, scope: owner.scope, principal: owner,
      access: {kind: 'connection', id: connection.id, generation: store.connectionGeneration(connection.id)},
      capability: {appId: cap.appId, id: cap.id, version: cap.version, definitionHash: canonicalHash(cap), effect: 'read'},
      args, policyRevision: 1, idempotencyKey: id,
      createdAt: new Date().toISOString(), deadline: new Date(Date.now() + 600000).toISOString(),
    };
    return manager.execute(connection.id, cap.action, args, () => ({request, cap}));
  };
  const connections = [], generations = [], profiles = [];
  for (const [index, app] of apps.entries()) {
    const connection = await manager.connect({appId: app.id, consent: true}, owner);
    connections.push(connection); generations.push(store.connectionGeneration(connection.id));
    const {context, profile} = launches.at(-1); profiles.push(profile);
    const page = context.pages().find(candidate => candidate.url().startsWith(app.webOrigins[0]));
    assert.ok(page);
    await context.addCookies([{name: 'fixture-session', value: `synthetic-${index}`, url: app.webOrigins[0], httpOnly: true, secure: true, expires: Math.floor(Date.now() / 1000) + 3600}]);
    await page.evaluate(identity => localStorage.setItem('fixture-identity', identity), `Fixture account ${index}`);
    await page.close();
    const result = await read(connection);
    assert.match(JSON.stringify(result.data), new RegExp(`Fixture account ${index}`));
    assert.doesNotMatch(JSON.stringify(result.data), new RegExp(`Fixture account ${1 - index}`));
    assert.equal(result.verification.accountVerified, false);
    assert.equal(manager.evidence(connection).account.verified, false);
    assert.equal(store.connectionGeneration(connection.id), generations[index]);
  }
  assert.equal(new Set(profiles).size, apps.length);
  await manager.shutdown(); store.close();
  store = new Store({dataDir, localAuthority: 'require'}); manager = makeManager();
  assert.equal(launches.length, apps.length, 'Restart does not launch browsers or read pages.');
  for (const [index, connection] of connections.entries()) {
    assert.equal(manager.evidence(connection).session.state, 'dormant');
    manager.check(connection.id);
    assert.equal(store.connectionGeneration(connection.id), generations[index]);
    const result = await read(connection);
    assert.match(JSON.stringify(result.data), new RegExp(`Fixture account ${index}`));
    assert.doesNotMatch(JSON.stringify(result.data), /synthetic-|never-export-this/);
    const {context, profile} = launches.at(-1);
    assert.equal(profile, profiles[index]);
    assert.equal((await context.cookies()).find(cookie => cookie.name === 'fixture-session')?.value, `synthetic-${index}`);
    assert.equal(store.connectionGeneration(connection.id), generations[index]);
  }
  for (const [index, connection] of connections.entries()) {
    const revoked = await manager.revoke(connection.id, owner);
    assert.equal(store.get('connections', connection.id).status, 'revoked');
    assert.equal(revoked.profileCleanup.status, 'retained');
    assert.equal(revoked.profileCleanup.cleanupRequired, true);
    assert.equal(manager.evidence(connection).session.state, 'revoked');
    await assert.rejects(async () => manager.open(connection.id, owner));
    await assert.rejects(async () => read(connection));
    await access(profiles[index]); // New-mode revoke retains bytes pending reviewed physical cleanup.
    assert.equal(manager.evidence(connection).account.verified, false);
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {Store} from '../lib/store.mjs';
import {Vault} from '../lib/vault.mjs';
import {ConnectionManager} from '../lib/connections.mjs';
import {GoogleOAuthManager} from '../lib/oauth.mjs';
import {GoogleSimulator} from './fixtures/oauth-simulators.mjs';

// F10.4 (T7): a renewal keeps the authorization and the connection generation, so neither can tell a stale result from
// a current one. Every check that compares authRevision also compares signInRevision: a check, refresh, callback or
// sign-in that began before a renewal can neither certify, disable nor replace the renewed account. Each case runs on a
// designated store (where the generation guard is blind to a renewal) and on a plain one (developer environments).
const TOKEN = 'https://oauth2.googleapis.com/token', USERINFO = 'https://openidconnect.googleapis.com/v1/userinfo';
const changed = {code: 'connection_changed'};
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; }

function fixture(t, designated) {
  const dir = mkdtempSync(join(tmpdir(), 'fabric-renewal-races-'));
  const store = new Store({dataDir: dir, ...(designated ? {localAuthority: 'new'} : {})}), vault = new Vault(dir);
  let now = Date.parse('2026-10-11T10:00:00.000Z');
  const clock = () => now, calls = [], held = {};
  // Simulator tokens never expire at Google here, so an old credential still answers; Fabric's own expiry still applies.
  const sim = new GoogleSimulator({clientId: 'races-client', clientSecret: 'races-secret', clock}); sim.expiring = false;
  const request = async req => {
    calls.push(req);
    const kind = req.url === USERINFO ? 'identity' : req.url === TOKEN ? 'token' : null;
    if (kind && held[kind]) { const hook = held[kind]; delete held[kind]; return hook(req); }
    return sim.request(req);
  };
  const connections = new ConnectionManager({store, vault, request, clock});
  const oauth = new GoogleOAuthManager({store, vault, connections, request, clientId: 'races-client', clientSecret: 'races-secret', clock});
  connections.setOAuthManager(oauth);
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  return {
    store, vault, connections, oauth, sim,
    advance(ms) { now += ms; },
    get now() { return now; },
    refreshes: () => calls.filter(req => req.url === TOKEN && new URLSearchParams(req.body).get('grant_type') === 'refresh_token').length,
    /** Holds the next identity or token request until released, with a given response or the simulator's own. */
    hold(kind) {
      const gate = deferred(), entered = deferred();
      held[kind] = async req => { entered.resolve(); const response = await gate.promise; return response ?? sim.request(req); };
      return {entered: entered.promise, release: response => gate.resolve(response)};
    },
    start: (options = {}) => oauth.start({appId: 'gmail', ...options}),
    finish(flow, account = 'a') { const grant = sim.consent(flow.authorizationUrl, {account}); return oauth.callback({state: grant.state, code: grant.code, flowId: flow.flowId}); },
    async signIn(options = {}) { return this.finish(this.start(options)); },
  };
}

for (const designated of [true, false]) {
  const store = designated ? 'designated store' : 'plain store';

  test(`${store}: a check whose identity call fails after a renewal does not mark the renewed account`, async t => {
    const f = fixture(t, designated), {id} = await f.signIn(), hold = f.hold('identity');
    const pending = f.connections.check(id); await hold.entered;
    await f.signIn({connectionId: id});
    const renewed = f.store.get('connections', id);
    f.advance(60 * 1000);
    hold.release({status: 401, data: {error: 'invalid_token'}});
    assert.equal((await pending).status, 'ready');
    assert.deepEqual(f.store.get('connections', id), renewed);
  });

  test(`${store}: a check whose identity call succeeds after a renewal does not certify the renewed account`, async t => {
    const f = fixture(t, designated), {id} = await f.signIn(), hold = f.hold('identity');
    const pending = f.connections.check(id); await hold.entered;
    await f.signIn({connectionId: id});
    const renewed = f.store.get('connections', id);
    f.advance(60 * 1000);
    hold.release();
    assert.equal((await pending).status, 'ready');
    assert.deepEqual(f.store.get('connections', id), renewed, 'no write from the check that began before the renewal');
  });

  test(`${store}: a refresh that fails after a renewal does not mark the renewed account`, async t => {
    const f = fixture(t, designated), {id} = await f.signIn();
    f.advance(3600 * 1000);
    const hold = f.hold('token'), pending = f.oauth.refresh(id); await hold.entered;
    await f.signIn({connectionId: id});
    const renewed = f.store.get('connections', id), tokens = f.vault.get(id);
    hold.release({status: 400, data: {error: 'invalid_grant'}});
    await assert.rejects(pending, {code: 'reconnect_required'});
    assert.deepEqual(f.store.get('connections', id), renewed); assert.deepEqual(f.vault.get(id), tokens);
  });

  test(`${store}: a refresh that succeeds after a renewal holding the same credential strings is refused`, async t => {
    const f = fixture(t, designated), {id} = await f.signIn(), before = f.vault.get(id);
    f.advance(3600 * 1000);
    const hold = f.hold('token'), pending = f.oauth.refresh(id); await hold.entered;
    // The renewal stores the very same token strings: only the sign-in revision tells the two apart.
    await f.connections.establishOAuth({connectionId: id, appId: 'gmail', tokens: {...before, expiresAt: f.now + 3599 * 1000}});
    const renewed = f.store.get('connections', id), tokens = f.vault.get(id);
    assert.deepEqual([tokens.accessToken, tokens.refreshToken], [before.accessToken, before.refreshToken]);
    hold.release();
    await assert.rejects(pending, changed);
    assert.deepEqual(f.store.get('connections', id), renewed); assert.deepEqual(f.vault.get(id), tokens);
  });

  test(`${store}: of two sign-ins started from the same state, the second callback after the first renewal answers connection_changed`, async t => {
    const f = fixture(t, designated), {id} = await f.signIn();
    const first = f.start({connectionId: id}), second = f.start({connectionId: id});
    await f.finish(first);
    const renewed = f.store.get('connections', id), tokens = f.vault.get(id);
    await assert.rejects(f.finish(second), changed);
    assert.deepEqual(f.store.get('connections', id), renewed); assert.deepEqual(f.vault.get(id), tokens);
  });

  test(`${store}: a sign-in whose identity call outlives a renewal answers connection_changed`, async t => {
    const f = fixture(t, designated), {id} = await f.signIn();
    const issued = f.sim.issue('a', ['openid', 'email', 'https://www.googleapis.com/auth/gmail.readonly'], {refreshable: true});
    const hold = f.hold('identity');
    const pending = f.connections.establishOAuth({connectionId: id, appId: 'gmail', tokens: {...issued, expiresAt: f.now + 3599 * 1000, scopes: ['openid', 'email', 'https://www.googleapis.com/auth/gmail.readonly']}});
    await hold.entered;
    await f.signIn({connectionId: id});
    const renewed = f.store.get('connections', id), tokens = f.vault.get(id);
    hold.release();
    await assert.rejects(pending, changed);
    assert.deepEqual(f.store.get('connections', id), renewed); assert.deepEqual(f.vault.get(id), tokens);
  });

  test(`${store}: a refresh after a renewal never joins one that began before it`, async t => {
    const f = fixture(t, designated), {id} = await f.signIn();
    f.advance(3600 * 1000);
    const hold = f.hold('token'), stale = f.oauth.refresh(id); await hold.entered;
    await f.signIn({connectionId: id});
    f.advance(3600 * 1000);
    assert.equal(f.refreshes(), 1);
    const current = f.oauth.refresh(id);
    assert.equal(f.refreshes(), 2, 'a refresh of its own, with the renewed credential');
    hold.release();
    await assert.rejects(stale, changed);
    const tokens = await current;
    assert.equal(tokens.accessToken, f.vault.get(id).accessToken);
    assert.equal(f.store.get('connections', id).status, 'ready');
  });
}

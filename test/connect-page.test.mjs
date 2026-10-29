import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createDeveloperApp} from '../developer-server.mjs';

// F03.4c: the hosted Connect page, walked like a browser (one cookie jar per browser) against a simulated GitHub.
async function setup(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-connect-page-'));
  const request = async req => req.url.startsWith('https://github.com/login/oauth/access_token') ? {status: 200, headers: {}, data: {access_token: 'gho_page', token_type: 'bearer', scope: 'read:user,repo'}}
    : {status: 200, headers: {}, data: {id: 77, login: 'octo', name: 'Octo Cat', email: 'octo@example.com'}};
  const app = await createDeveloperApp({dataRoot: root, port: 0, providerSettings: {github: {clientId: 'gh-client', clientSecret: 'gh-secret'}}, request});
  t.after(async () => { await app.close(); rmSync(root, {recursive: true, force: true}); });
  const org = app.registry.createOrganization({name: 'Acme'}), project = app.registry.createProject({organizationId: org.id, name: 'Agent', appName: 'Acme Assistant'});
  const dev = app.registry.createEnvironment({projectId: project.id, kind: 'development'}, app.stores);
  app.registry.put('environments', {...app.registry.get('environments', dev.id), redirectOrigins: ['http://localhost:5173']});
  const key = app.keys.mint({environmentId: dev.id, preset: 'full'}).token;
  const created = await (await fetch(`${app.origin}/v1/connect-sessions`, {method: 'POST', headers: {Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'}, body: JSON.stringify({externalUserId: 'aura-user-1', appId: 'github', successRedirectUri: 'http://localhost:5173/done'})})).json();
  const browser = () => {
    const jar = new Map();
    const remember = response => { for (const line of response.headers.getSetCookie()) { const [pair] = line.split(';'); const at = pair.indexOf('='); jar.set(pair.slice(0, at), pair.slice(at + 1)); } };
    const cookie = () => [...jar].filter(([, value]) => value).map(([name, value]) => `${name}=${value}`).join('; ');
    // Like a real browser on Fabric's page: Sec-Fetch-Site on every request, and the CSRF value from claim or view on every action.
    let csrf = null;
    return {jar, async call(method, route, body, headers = {}) {
      const response = await fetch(`${app.origin}${route}`, {method, redirect: 'manual', headers: {'Sec-Fetch-Site': 'same-origin', ...(jar.size ? {Cookie: cookie()} : {}), ...(body !== undefined ? {'Content-Type': 'application/json', Origin: app.origin, ...(csrf ? {'X-Fabric-CSRF': csrf} : {})} : {}), ...headers}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      remember(response);
      const type = response.headers.get('content-type') || '', parsed = type.includes('json') ? await response.json() : await response.text();
      if (typeof parsed?.csrf === 'string') csrf = parsed.csrf;
      return {status: response.status, headers: response.headers, body: parsed};
    }};
  };
  return {app, created, id: created.id, secret: new URL(created.connectUrl).hash.slice(3), browser, key};
}

test('a person walks the page: claim, consent sheet, Connect, provider sign-in, confirm, back to the developer\'s app', async t => {
  const {app, id, secret, browser, key} = await setup(t);
  const person = browser();
  const page = await person.call('GET', `/connect/${id}`);
  assert.equal(page.status, 200); assert.match(page.body, /connect\.js/);
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(page.headers.get('x-frame-options'), 'DENY'); assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
  const claimed = await person.call('POST', `/connect/${id}/v1/claim`, {secret});
  assert.equal(claimed.status, 200);
  assert.match(person.jar.get('fabric_t_session'), /^[A-Za-z0-9_-]{43}$/);
  const sessionCookie = claimed.headers.getSetCookie().find(line => line.startsWith('fabric_t_session='));
  for (const attribute of ['HttpOnly', 'SameSite=Strict', `Path=/connect/${id};`]) assert.ok(sessionCookie.includes(attribute), `${attribute} in ${sessionCookie}`);
  const view = (await person.call('GET', `/connect/${id}/v1/view`)).body;
  assert.equal(view.state, 'opened'); assert.equal(view.sheet.developer.appName, 'Acme Assistant'); assert.equal(view.sheet.action.label, 'Connect GitHub');
  const started = (await person.call('POST', `/connect/${id}/v1/start`, {})).body;
  assert.match(started.authorizationUrl, /^https:\/\/github\.com\/login\/oauth\/authorize\?/);
  assert.ok(person.jar.get('fabric_t_oauth'), 'the flow cookie is set for the callback path');
  const state = new URL(started.authorizationUrl).searchParams.get('state');
  const back = await person.call('GET', `/api/oauth/github/callback?state=${encodeURIComponent(state)}&code=abc`);
  assert.equal(back.status, 303); assert.equal(back.headers.get('location'), `/connect/${id}/finish`);
  const finish = (await person.call('GET', `/connect/${id}/v1/view`)).body;
  assert.equal(finish.state, 'awaiting_confirmation'); assert.equal(finish.pendingAccount.displayName, 'octo', 'GitHub names an account by its login');
  assert.equal(JSON.stringify(finish).includes('octo@example.com'), false, 'never an email');
  assert.deepEqual(Object.keys(app.sessions.view(id, person.jar.get('fabric_t_session'), undefined, person.jar.get('fabric_t_finish')).pendingAccount), ['displayName'], 'the account to confirm carries its name only');
  assert.deepEqual(Object.keys(app.sessions.view(id, person.jar.get('fabric_t_session'))).includes('pendingAccount'), false, 'without the finish value, no account at all');
  const done = (await person.call('POST', `/connect/${id}/v1/confirm`, {})).body;
  assert.equal(done.state, 'connected'); assert.equal(done.redirect, `http://localhost:5173/done?fabric_session=${id}&fabric_state=connected&fabric_app=github&fabric_account=${done.result.accountRef}`);
  const result = await (await fetch(`${app.origin}/v1/connect-sessions/${id}`, {headers: {Authorization: `Bearer ${key}`}})).json();
  assert.equal(result.state, 'connected'); assert.equal(result.result.appId, 'github');
});

test('the page refuses other origins, other browsers and missing cookies; it never shows anything without the claiming browser', async t => {
  const {id, secret, browser} = await setup(t);
  const person = browser(), stranger = browser();
  assert.equal((await person.call('POST', `/connect/${id}/v1/claim`, {secret}, {Origin: 'https://evil.example'})).status, 403);
  assert.equal((await person.call('POST', `/connect/${id}/v1/claim`, {secret})).status, 200);
  assert.equal((await stranger.call('POST', `/connect/${id}/v1/claim`, {secret})).body.error.code, 'session_in_use');
  assert.equal((await stranger.call('GET', `/connect/${id}/v1/view`)).body.error.code, 'not_found');
  assert.equal((await stranger.call('POST', `/connect/${id}/v1/start`, {})).body.error.code, 'not_found');
  assert.equal((await browser().call('POST', `/connect/${id}/v1/claim`, {secret: 'x'.repeat(43)})).body.error.code, 'not_found');
  // A request carrying a duplicated session cookie is refused outright.
  assert.equal((await person.call('GET', `/connect/${id}/v1/view`, undefined, {Cookie: `fabric_t_session=planted; fabric_t_session=${person.jar.get('fabric_t_session')}`})).status, 400);
  // The page's own script never puts server text into HTML.
  const script = readFileSync(new URL('../public/connect.js', import.meta.url), 'utf8');
  assert.equal(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(script), false);
  assert.match(script, /history\.replaceState/, 'the secret leaves the address bar');
  assert.equal(/postMessage\([^)]*['"]\*['"]/.test(script), false, 'never postMessage to *');
});

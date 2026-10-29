import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {fileURLToPath} from 'node:url';
import {createApp} from '../server.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {FABRIC_PROTOCOL} from '../lib/fabric-protocol.mjs';
import {describeHandoff, shouldPoll, signInTarget, decide, visible} from '../public/continue.js';

// F02.4: the owner page a handoff link opens. The page's decisions live in pure helpers, so
// they are tested here against synthetic views and against real owner views over HTTP.
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ID = '11111111-1111-4111-8111-111111111111';
const base = {id: ID, revision: 1, expiresAt: '2026-10-11T10:30:00.000Z', client: {name: 'Muse'}, app: {id: 'github', name: 'GitHub'},
  operation: {capabilityId: 'github.createIssue', name: 'Create issue', effect: 'write'}, arguments: {owner: 'o', repo: 'r', body: {title: '<img src=x onerror=alert(1)>'}},
  accounts: [], signIn: null, pendingConnection: null, lastAttempt: null, outcome: null, derived: null, viewDigest: null, confirmDigest: null, actions: []};
const choose = {...base, phase: 'awaiting_owner', viewDigest: 'view-1', actions: ['select', 'sign_in', 'decline'],
  accounts: [{connectionId: 'acct-a', label: 'GitHub a', identity: {displayName: 'octo-a', email: 'a@example.test'}, eligible: true, afterSelection: 'asks_approval'},
    {connectionId: 'acct-b', label: 'GitHub b', identity: {displayName: 'octo-b'}, eligible: false, reason: 'not_permitted', afterSelection: 'blocked'}],
  signIn: {providerId: 'github', providerName: 'GitHub', available: true, reason: null, afterSignIn: 'asks_approval'}};

test('the choose stage binds every button to the exact view the owner saw', () => {
  const model = describeHandoff(choose);
  assert.equal(model.stage, 'choose');
  assert.equal(model.title, 'Muse wants to create issue in GitHub');
  assert.equal(model.effect, 'Changes data');
  assert.deepEqual(model.accounts[0].request, {path: `/api/continuations/${ID}/select`, body: {connectionId: 'acct-a', viewDigest: 'view-1'}});
  assert.equal(model.accounts[0].hint, 'You will approve the exact action next.');
  assert.equal(model.accounts[1].request, null, 'an ineligible account has no request to send');
  assert.equal(model.accounts[1].eligible, false);
  assert.equal(model.accounts[1].hint, 'Not permitted for this operation.');
  const why = reason => describeHandoff({...choose, accounts: [{...choose.accounts[1], reason}]}).accounts[0].hint;
  assert.equal(why('reconnect_required'), 'Reconnect this account before it can be used.');
  assert.equal(why('Execution is denied by your setting for this account and operation.'), 'Execution is denied by your setting for this account and operation.');
  assert.deepEqual(model.signIn.request, {path: `/api/continuations/${ID}/sign-in`, body: {viewDigest: 'view-1'}});
  assert.deepEqual(model.decline, {path: `/api/continuations/${ID}/decline`, body: {}});
  assert.equal(JSON.parse(model.args).body.title, '<img src=x onerror=alert(1)>', 'arguments are kept as inert text, never markup');
  assert.equal(shouldPoll(model), false);
});

test('operation names read as a sentence without mangling product names', () => {
  const title = name => describeHandoff({...base, operation: {...base.operation, name}}).title;
  assert.equal(title('createIssue'), 'Muse wants to create issue in GitHub');
  assert.equal(title('list_repos'), 'Muse wants to list repos in GitHub');
  assert.equal(title('Send Slack message'), 'Muse wants to send Slack message in GitHub');
  assert.equal(title('GitHub sync'), 'Muse wants to GitHub sync in GitHub');
  assert.equal(describeHandoff({...base, operation: {capabilityId: 'github.fooBar', effect: 'read'}}).title, 'Muse wants to foo bar in GitHub');
});

test('eligibility must be exactly true and an unavailable sign-in shows its reason without a request', () => {
  const model = describeHandoff({...choose, accounts: [{...choose.accounts[0], eligible: 'yes'}],
    signIn: {...choose.signIn, available: false, reason: 'Sign-in is not set up for GitHub here.'}});
  assert.equal(model.accounts[0].request, null);
  assert.equal(model.signIn.request, null);
  assert.equal(model.signIn.hint, 'Sign-in is not set up for GitHub here.');
  assert.match(describeHandoff({...choose, phase: 'signing_in'}).signIn.hint, /^A sign-in is open\./);
  assert.equal(describeHandoff({...choose, actions: ['select']}).decline, null, 'decline appears only when the server offers it');
});

test('a failed sign-in attempt is explained in owner language', () => {
  for (const [outcome, expected] of [['declined_at_provider', /You declined on GitHub/], ['insufficient_scope', /did not grant every permission/],
    ['sign_in_failed', /did not complete/], ['sign_in_interrupted', /restarted while you were signing in/], ['wrong_account', /disconnected/]]) {
    const model = describeHandoff({...choose, lastAttempt: {outcome, at: '2026-10-11T10:01:00.000Z'}});
    assert.equal(model.notice.kind, 'warn'); assert.match(model.notice.text, expected);
  }
});

test('confirm stage carries the confirm digest and a plain reject', () => {
  const model = describeHandoff({...base, phase: 'awaiting_confirmation', confirmDigest: 'confirm-1', actions: ['confirm', 'reject_account', 'decline'],
    pendingConnection: {connectionId: 'q-1', identity: {displayName: 'octo-new', email: 'new@example.test'}, duplicateOf: 'acct-a', afterConfirm: 'runs_now'}});
  assert.equal(model.stage, 'confirm');
  assert.equal(model.pending.name, 'octo-new'); assert.equal(model.pending.duplicate, true); assert.equal(model.pending.hint, 'Runs right away.');
  assert.deepEqual(model.pending.confirm, {path: `/api/continuations/${ID}/confirm`, body: {confirmDigest: 'confirm-1'}});
  assert.deepEqual(model.pending.reject, {path: `/api/continuations/${ID}/reject-account`, body: {}});
});

test('approve stage sends only the displayed approval digest for the derived job', () => {
  const jobId = '22222222-2222-4222-8222-222222222222';
  const preview = {account: {displayName: 'octo-a'}, operation: 'Create issue', request: {method: 'POST', url: 'https://api.github.com/repos/o/r/issues', body: {title: 'x'}}};
  const model = describeHandoff({...base, phase: 'awaiting_approval', derived: {jobId, status: 'awaiting_approval', approval: {digest: 'approve-1', expiresAt: base.expiresAt, preview}}}, Date.parse('2026-10-11T10:05:00.000Z'));
  assert.equal(model.stage, 'approve');
  assert.deepEqual(model.approval.approve, {path: `/api/jobs/${jobId}/approve`, body: {approvalDigest: 'approve-1'}});
  assert.deepEqual(model.approval.cancel, {path: `/api/jobs/${jobId}/cancel`, body: {}});
  assert.equal(model.approval.preview.request.url, preview.request.url);
  assert.equal(model.decline, null);
});

test('continuing and running stages keep refreshing; finished ones stop', () => {
  assert.equal(shouldPoll(describeHandoff({...base, phase: 'continuing'})), true);
  for (const status of ['queued', 'running']) assert.equal(shouldPoll(describeHandoff({...base, phase: 'connected', derived: {jobId: 'j', status}})), true);
  for (const status of ['succeeded', 'failed', 'uncertain', 'cancelled']) {
    const model = describeHandoff({...base, phase: 'connected', derived: {jobId: 'j', status, error: status === 'failed' ? 'Provider said no.' : null}});
    assert.equal(model.stage, 'done'); assert.equal(shouldPoll(model), false); assert.notEqual(model.result.text, '');
    assert.equal(model.result.detail, status === 'failed' ? 'Provider said no.' : '');
  }
});

test('every outcome and attempt code the service can write has owner wording', async () => {
  const source = await readFile(path.join(ROOT, 'lib/continuations.mjs'), 'utf8');
  const outcomes = new Set([...source.matchAll(/close\([^,]+,'[a-z_]+','([a-z_]+)'/g)].map(match => match[1]));
  for (const match of source.matchAll(/outcome:\{code:'([a-z_]+)'/g)) outcomes.add(match[1]);
  for (const code of ['policy_denied', 'authority_changed', 'capability_retired']) outcomes.add(code); // derive() forwards these
  assert.ok(outcomes.size >= 8, `found ${[...outcomes]}`);
  for (const code of outcomes) {
    const model = describeHandoff({...base, phase: 'closed', outcome: {code, at: base.expiresAt}});
    assert.equal(model.stage, 'closed'); assert.notEqual(model.notice.text, 'This request is closed.', `no wording for ${code}`);
  }
  const attempts = new Set([...source.matchAll(/'(declined_at_provider|insufficient_scope|scope_refused|sign_in_failed)'/g)].map(match => match[1]));
  for (const match of source.matchAll(/lastAttempt:\{outcome:'([a-z_]+)'/g)) attempts.add(match[1]);
  for (const outcome of attempts) assert.ok(describeHandoff({...choose, lastAttempt: {outcome}}).notice, `no wording for ${outcome}`);
});

test('the sign-in redirect is followed only to the declared HTTPS provider origin', () => {
  assert.equal(signInTarget('https://github.com/login/oauth/authorize?state=s', 'https://github.com'), 'https://github.com/login/oauth/authorize?state=s');
  for (const [url, expected] of [['https://evil.example/login', 'https://github.com'], ['http://github.com/login', 'http://github.com'], ['javascript:alert(1)', 'https://github.com'],
    ['https://github.com.evil.example/', 'https://github.com'], ['not a url', 'https://github.com'], ['https://github.com/login', undefined], ['https://github.com/login', '']]) {
    assert.throws(() => signInTarget(url, expected), /Unexpected sign-in destination/);
  }
});

test('the page renders text only and never builds markup from data', async () => {
  const script = await readFile(path.join(ROOT, 'public/continue.js'), 'utf8');
  for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'setAttribute(\'on', 'href=']) assert.ok(!script.includes(sink), `continue.js must not use ${sink}`);
  const html = await readFile(path.join(ROOT, 'public/continue.html'), 'utf8');
  assert.ok(!/<script(?![^>]*src="\/continue\.js")/.test(html), 'only the page module is loaded; no inline script');
  assert.ok(!/style=/.test(html), 'no inline styles, so the existing CSP holds');
});

// ---- over HTTP -----------------------------------------------------------------------------
const owner = {schemaVersion: 1, id: 'fixture-owner', kind: 'local_owner', scope: {schemaVersion: 1, kind: 'local', localOwnerId: 'fixture-owner'}};
const doc = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
  '/repos/{owner}/{repo}/issues': {post: {operationId: 'createIssue', parameters: [{name: 'owner', in: 'path', required: true, schema: {type: 'string'}}, {name: 'repo', in: 'path', required: true, schema: {type: 'string'}}],
    requestBody: {content: {'application/json': {schema: {type: 'object', properties: {title: {type: 'string'}}, required: ['title']}}}}, responses: {201: {description: 'Created'}}}}}};
async function freePort() { const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const {port} = server.address(); await new Promise(resolve => server.close(resolve)); return port; }

async function fixture(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-continue-page-')), port = await freePort();
  const calls = [];
  const app = await createApp({dataDir: dir, port, clock: () => Date.parse('2026-10-11T10:00:00.000Z'), request: async req => { calls.push(req); return {status: 201, data: {id: 7, title: 'x'}}; },
    localAuthority: {mode: 'new', ownerPrincipal: owner}});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); });
  const cap = {...compileOpenApi({appId: 'github', document: doc}).capabilities[0], status: 'active'};
  app.store.put('capabilities', cap);
  app.store.put('connections', {id: 'acct-a', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'consent-a', status: 'ready', label: 'GitHub octo', identity: {id: '101', displayName: 'octo'}, allowedOrigins: ['https://api.github.com'], createdAt: '2026-10-11T10:00:00.000Z'});
  app.vault.set('acct-a', {accessToken: 'synthetic-only-token'});
  const first = await fetch(`${app.origin}/api/state`), state = await first.json(), cookie = first.headers.get('set-cookie').split(';')[0];
  const send = (request, method = 'POST') => fetch(`${app.origin}${request.path}`, {method, headers: {'content-type': 'application/json', 'x-fabric-csrf': state.csrfToken, cookie}, ...(method === 'POST' ? {body: JSON.stringify(request.body)} : {})});
  const view = async id => (await send({path: `/api/continuations/${id}`}, 'GET')).json();
  const created = await (await send({path: '/api/clients', body: {name: 'Muse', bindings: [], requestable: [{capabilityId: cap.id}]}})).json();
  const asked = await fetch(`${app.origin}/fabric/v1`, {method: 'POST', headers: {'content-type': 'application/json', authorization: `Bearer ${created.token}`},
    body: JSON.stringify({protocol: FABRIC_PROTOCOL, id: 'req-page', method: 'calls.create', params: {appId: 'github', capabilityId: cap.id, definitionHash: created.client.requestable[0].definitionHash, args: {owner: 'o', repo: 'r', body: {title: 'x'}}}})}).then(response => response.json());
  return {app, cap, calls, send, view, handoff: asked.result};
}

test('the handoff link serves the owner page and its assets under the existing CSP', async t => {
  const f = await fixture(t);
  const page = await fetch(f.handoff.handoff.url);
  assert.equal(page.status, 200); assert.match(page.headers.get('content-type'), /text\/html/);
  assert.match(page.headers.get('content-security-policy'), /script-src 'self'/); assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
  const html = await page.text();
  assert.match(html, /id="handoff"/); assert.match(html, /src="\/continue\.js"/);
  assert.ok(!html.includes(f.handoff.id), 'the page itself carries no handoff data');
  const script = await fetch(`${f.app.origin}/continue.js`), styles = await fetch(`${f.app.origin}/hosted.css`);
  assert.match(script.headers.get('content-type'), /text\/javascript/); assert.match(styles.headers.get('content-type'), /text\/css/);
  assert.equal((await fetch(`${f.app.origin}/continue/${f.handoff.id}/extra`)).status, 404);
});

test('the requests the page builds are exactly what the owner routes accept, end to end', async t => {
  const f = await fixture(t);
  const now = Date.parse('2026-10-11T10:00:00.000Z'); // the fixture's clock
  let model = describeHandoff(await f.view(f.handoff.id), now);
  assert.equal(model.stage, 'choose'); assert.equal(model.title, 'Muse wants to create issue in GitHub');
  const use = model.buttons.find(button => button.key === 'use:acct-a');
  assert.ok(use, 'the existing account is offered');
  const selected = await f.send(use.request);
  assert.equal(selected.status, 200, await selected.clone().text());
  await f.app.continuations.settled(f.handoff.id);
  model = describeHandoff(await f.view(f.handoff.id), now);
  // A write asks for its own exact approval: this step is required, never skipped.
  assert.equal(model.stage, 'approve');
  assert.equal(model.approval.preview.request.method, 'POST');
  assert.equal(f.calls.length, 0, 'nothing runs before the exact action is approved');
  const approved = await f.send(model.buttons.find(button => button.key === 'approve').request);
  assert.equal(approved.status, 200, await approved.clone().text());
  await f.app.continuations.settled(f.handoff.id);
  model = describeHandoff(await f.view(f.handoff.id), now);
  assert.equal(model.stage, 'done');
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].url, 'https://api.github.com/repos/o/r/issues');
  // The synthetic provider cannot verify a write, so the page must say so, never claim success.
  assert.equal(model.result.status, 'uncertain'); assert.match(model.result.text, /could not confirm/);
  assert.equal(shouldPoll(model), false);
});

test('a stale view is refused and the page receives the fresh view to show', async t => {
  const f = await fixture(t);
  const model = describeHandoff(await f.view(f.handoff.id));
  const stale = {...model.accounts[0].request, body: {...model.accounts[0].request.body, viewDigest: 'stale'}};
  const response = await f.send(stale);
  assert.equal(response.status, 409);
  const body = await response.json();
  assert.equal(body.code, 'view_changed');
  assert.equal(describeHandoff(body.view).accounts[0].request.body.viewDigest, model.accounts[0].request.body.viewDigest);
  const declined = await f.send(model.decline);
  assert.equal(declined.status, 200);
  const closed = describeHandoff(await f.view(f.handoff.id));
  assert.equal(closed.stage, 'closed'); assert.match(closed.notice.text, /You declined this request/);
  assert.equal(closed.decline, null); assert.equal(f.calls.length, 0);
});

// ---- review fixes (second independent review) ------------------------------------------
const NOW = Date.parse('2026-10-11T10:05:00.000Z');
const approval = (expiresAt, extra = {}) => ({...base, phase: 'awaiting_approval', derived: {jobId: '22222222-2222-4222-8222-222222222222', status: 'awaiting_approval', approval: {digest: 'approve-1', expiresAt, preview: {}}}, ...extra});

test('each stage shows its own deadline: the request on choose and confirm, the approval on approve, none after', () => {
  assert.equal(describeHandoff(choose, NOW).deadline, base.expiresAt);
  const approve = describeHandoff(approval('2026-10-11T10:15:00.000Z'), NOW);
  assert.equal(approve.stage, 'approve'); assert.equal(approve.deadline, '2026-10-11T10:15:00.000Z', 'the 10-minute approval deadline, not the 30-minute request');
  for (const phase of ['continuing', 'connected', 'closed']) assert.equal(describeHandoff({...base, phase, derived: {status: 'succeeded'}, outcome: {code: 'owner_declined'}}, NOW).deadline, null, phase);
});

test('an approval past its own deadline offers only cancelling', () => {
  const model = describeHandoff(approval('2026-10-11T10:04:59.000Z'), NOW);
  assert.equal(model.stage, 'approval_expired'); assert.match(model.notice.text, /time to approve this action has passed/);
  assert.deepEqual(model.buttons.map(button => button.key), ['cancel']);
  assert.equal(shouldPoll(model), false);
});

test('a failed earlier sign-in is mentioned only while the owner is choosing again', () => {
  const lastAttempt = {outcome: 'wrong_account', at: base.expiresAt};
  assert.ok(describeHandoff({...choose, lastAttempt}, NOW).notice);
  const confirm = describeHandoff({...base, phase: 'awaiting_confirmation', lastAttempt, confirmDigest: 'c', pendingConnection: {identity: {displayName: 'x'}, afterConfirm: 'runs_now'}}, NOW);
  assert.equal(confirm.notice, null);
  assert.equal(describeHandoff(approval('2026-10-11T10:15:00.000Z', {lastAttempt}), NOW).notice, null);
});

test('every button is data: exact keys, labels and requests per stage', () => {
  const chooseModel = describeHandoff(choose, NOW);
  assert.deepEqual(chooseModel.buttons.map(({key, label, variant}) => [key, label, variant]), [['use:acct-a', 'Use this account', 'primary'], ['sign-in', 'Sign in', 'secondary'], ['decline', 'Decline request', 'danger']]);
  assert.equal(chooseModel.buttons[0].request, chooseModel.accounts[0].request);
  assert.deepEqual(chooseModel.buttons[1].signIn, {providerId: 'github'});
  const confirm = describeHandoff({...base, phase: 'awaiting_confirmation', confirmDigest: 'confirm-1', actions: ['confirm', 'reject_account', 'decline'],
    pendingConnection: {identity: {displayName: 'Fabric bot', workspaceName: 'Acme Corp'}, afterConfirm: 'runs_now'}}, NOW);
  assert.deepEqual(confirm.buttons.map(button => [button.key, button.label, button.request.path, JSON.stringify(button.request.body)]), [
    ['confirm', 'Continue as Acme Corp', `/api/continuations/${ID}/confirm`, '{"confirmDigest":"confirm-1"}'],
    ['reject', 'Not this account', `/api/continuations/${ID}/reject-account`, '{}'],
    ['decline', 'Decline request', `/api/continuations/${ID}/decline`, '{}']]);
  const approve = describeHandoff(approval('2026-10-11T10:15:00.000Z'), NOW);
  assert.deepEqual(approve.buttons.map(button => [button.key, button.request.path, JSON.stringify(button.request.body)]), [
    ['approve', '/api/jobs/22222222-2222-4222-8222-222222222222/approve', '{"approvalDigest":"approve-1"}'],
    ['cancel', '/api/jobs/22222222-2222-4222-8222-222222222222/cancel', '{}']]);
  assert.deepEqual(describeHandoff({...base, phase: 'connected', derived: {status: 'succeeded'}}, NOW).buttons, []);
});

test('decide sends exactly the button request and follows sign-in only to the declared origin', async () => {
  const sent = [], assigned = [];
  const deps = {send: async request => { sent.push(request); return {authorizationUrl: 'https://github.com/login/oauth/authorize?state=s'}; }, assign: url => assigned.push(url), oauthProviders: {github: {authorizationOrigin: 'https://github.com'}}};
  const model = describeHandoff(choose, NOW);
  await decide(model.buttons[0], deps);
  assert.deepEqual(sent, [model.accounts[0].request]); assert.deepEqual(assigned, [], 'a plain decision never navigates');
  await decide(model.buttons[1], deps);
  assert.deepEqual(assigned, ['https://github.com/login/oauth/authorize?state=s']);
  const evil = {...deps, send: async () => ({authorizationUrl: 'https://evil.example/login'})};
  await assert.rejects(decide(model.buttons[1], evil), /Unexpected sign-in destination/);
  await assert.rejects(decide(model.buttons[1], {...deps, oauthProviders: {}}), /Unexpected sign-in destination/, 'no declared origin, no navigation');
  assert.equal(assigned.length, 1);
});

test('workspaces are shown so two workspaces of one integration never look the same', () => {
  const a = describeHandoff({...base, phase: 'awaiting_confirmation', confirmDigest: 'c', pendingConnection: {identity: {displayName: 'Fabric bot', workspaceName: 'Acme Corp'}, afterConfirm: 'runs_now'}}, NOW);
  const b = describeHandoff({...base, phase: 'awaiting_confirmation', confirmDigest: 'c', pendingConnection: {identity: {displayName: 'Fabric bot', workspaceName: 'Personal'}, afterConfirm: 'runs_now'}}, NOW);
  assert.notEqual(a.pending.name, b.pending.name); assert.equal(a.pending.detail, 'Fabric bot');
  const account = describeHandoff({...choose, accounts: [{...choose.accounts[0], identity: {displayName: 'octo', workspaceName: 'Acme', email: 'o@example.test'}}]}, NOW).accounts[0];
  assert.equal(account.label, 'Acme'); assert.equal(account.detail, 'octo · o@example.test');
});

test('the sign-in option says how much access it asks for', () => {
  // F10.7: a version 2 app asks for full access (Notion: the pages the person picks); a version 1 app keeps its read and write words.
  const hint = signIn => describeHandoff({...choose, signIn: {...choose.signIn, writeAccess: true, ...signIn}}, NOW).signIn.hint;
  assert.match(hint({access: 'full', scopes: []}), /Asks GitHub for full access\./);
  assert.match(hint({access: 'full', scopes: ['read:org']}), /Asks GitHub for full access plus what this request needs\./);
  assert.match(hint({access: 'pages', scopes: []}), /GitHub asks you to pick the pages Fabric may use\./);
  assert.doesNotMatch(hint({access: 'full', scopes: []}), /read and write/);
  const plain = hint({access: 'read_write', scopes: []});
  assert.match(plain, /Asks GitHub for read and write access\./);
  const extra = hint({scopes: ['admin:org']});
  assert.match(extra, /read and write access plus what this request needs/);
});

test('invisible and direction-changing characters in agent text are made visible', () => {
  assert.equal(visible('pay\u202eevil'), 'pay⟦U+202E⟧evil');
  assert.equal(visible('a\u200bb\u2066c\u0007'), 'a⟦U+200B⟧b⟦U+2066⟧c⟦U+0007⟧');
  assert.equal(visible('line\nnext\ttab'), 'line\nnext\ttab', 'ordinary whitespace is kept');
  const model = describeHandoff({...choose, arguments: {to: 'boss\u202egnp.exe'}}, NOW);
  assert.ok(model.args.includes('⟦U+202E⟧') && !model.args.includes('\u202e'));
});

test('the exact request is open while the owner decides', () => {
  assert.equal(describeHandoff(choose, NOW).argsOpen, true);
  assert.equal(describeHandoff(approval('2026-10-11T10:15:00.000Z'), NOW).argsOpen, true);
  assert.equal(describeHandoff({...base, phase: 'connected', derived: {status: 'succeeded'}}, NOW).argsOpen, false);
});

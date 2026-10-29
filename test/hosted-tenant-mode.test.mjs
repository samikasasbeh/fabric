import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import {hostedSetup} from './fixtures/hosted-fixture.mjs';
import {baseFor, errorOf} from '../public/hosted-base.js';
import {rowAction, iconSource, catalogUrl} from '../public/hosted-catalog.js';
import {needsConfirm, rowRequest, describeApp} from '../public/hosted-app.js';
import {describePage, buttonsFor, outcomeOf} from '../public/hosted-approve.js';
import {describeApproval} from '../public/hosted-approval.js';

// F03.10: the four hosted pages (catalog, app, activity, approval) in a developer's environment. The same files serve
// the owner's local Fabric; under /connect/<session>/ they read and change through that link's own API.
const CS = `cs_${'a'.repeat(26)}`, TENANT = baseFor(`/connect/${CS}/apps/gmail`), OWNER = baseFor('/connectors/gmail');
const REF = '0f0e0d0c-0b0a-4908-8706-050403020100';

test('a page picks its base from its own address; anything malformed is the owner\'s and fails closed there', () => {
  assert.equal(OWNER.tenant, false); assert.equal(TENANT.tenant, true); assert.equal(TENANT.sessionId, CS);
  for (const path of [`/connect/${CS}/apps`, `/connect/${CS}/activity`, `/connect/${CS}/approve`]) assert.equal(baseFor(path).tenant, true, path);
  for (const path of ['/connect/cs_short/apps', `/connect/${CS.toUpperCase()}/apps`, `/x/connect/${CS}/apps`, '/activity', null]) assert.equal(baseFor(path).tenant, false, String(path));
  // Both error shapes read the same way.
  assert.deepEqual([errorOf({error: {code: 'expired', message: 'Gone.'}}, 410).message, errorOf({error: {code: 'expired'}}, 410).code], ['Gone.', 'expired']);
  assert.deepEqual([errorOf({error: 'Owner words.', code: 'not_found'}, 404).message, errorOf({error: 'x', code: 'not_found'}, 404).code], ['Owner words.', 'not_found']);
});

test('catalog helpers on a manage link: its own API, its own app pages, and Fabric\'s icon path only', () => {
  assert.equal(catalogUrl({status: 'connected', q: ' mail ', category: 'email'}, TENANT), `/connect/${CS}/v1/catalog?q=mail&category=email`, 'no status: the server shows connected apps only');
  assert.equal(catalogUrl({status: 'connected'}), '/api/ui/catalog?status=connected', 'the owner is unchanged');
  assert.equal(rowAction({id: 'gmail', name: 'Gmail', primaryAction: 'view'}, TENANT).href, `/connect/${CS}/apps/gmail`);
  assert.equal(rowAction({id: 'gmail', name: 'Gmail', primaryAction: 'view'}).href, '/connectors/gmail');
  assert.equal(iconSource({iconUrl: '/assets/icons/gmail'}, TENANT), '/assets/icons/gmail');
  for (const iconUrl of ['https://evil.example/x.svg', '/assets/icons/../x', 'javascript:alert(1)', '/api/icons/gmail', '//evil.example/assets/icons/gmail', '/assets/icons/Gmail']) assert.equal(iconSource({iconUrl}, TENANT), null, iconUrl);
  assert.equal(iconSource({iconUrl: '/assets/icons/gmail'}), null, 'the owner page keeps its own icon route');
});

test('app helpers on a manage link: every change under the link\'s API, background bound to its etag, no Add account', () => {
  const detail = {app: {id: 'gmail', name: 'Gmail'}, connectionState: 'connected', selectedAccountRef: REF,
    accounts: [{accountRef: REF, displayName: 'one@example.com', initial: 'O', status: 'ready', isDefault: true}],
    sections: [{label: 'Read', rows: [{groupId: 'gmail.messages.read', label: 'Access emails', effect: 'read', mode: 'allow', defaultMode: 'allow', allowedModes: ['allow', 'ask', 'deny'], etag: 'e1', reviewRequired: false, allowNeedsConfirm: false}]}],
    background: {mode: 'allow', etag: 'b1', allowedEffects: ['read'], runsWhile: 'runtime_running'}, canReset: true};
  const model = describeApp(detail, TENANT), prefix = `/connect/${CS}/v1/apps/gmail/accounts/${REF}/`;
  for (const request of [model.disconnect.request, model.reset, model.background.request('deny'), rowRequest(detail, detail.sections[0].rows[0], 'ask', {}, TENANT)]) assert.ok(request.path.startsWith(prefix), request.path);
  assert.deepEqual(model.background.request('deny').body, {mode: 'deny', etag: 'b1'});
  assert.equal(model.addAccount, null);
  // The owner's background request is unchanged: its route refuses extra keys.
  assert.deepEqual(describeApp({...detail, background: {mode: 'allow', allowedEffects: ['read'], runsWhile: 'runtime_running'}}).background.request('deny').body, {mode: 'deny'});
  // Allow on a write keeps the standing-consent review, page half.
  assert.equal(needsConfirm({effect: 'read', allowNeedsConfirm: true}, 'allow'), 'allow', 'a read row with a write member');
  assert.equal(needsConfirm({effect: 'write', defaultMode: 'allow', allowNeedsConfirm: true}, 'allow'), 'allow', 'even when Allow is the default');
  assert.equal(needsConfirm({effect: 'read', allowNeedsConfirm: false}, 'allow'), null);
  assert.equal(needsConfirm({effect: 'write', allowNeedsConfirm: true, reviewRequired: false}, 'ask'), null);
  assert.equal(needsConfirm({effect: 'write', defaultMode: 'allow'}, 'allow'), null, 'the owner\'s own rule is unchanged');
  const row = detail.sections[0].rows[0];
  assert.deepEqual(rowRequest(detail, row, 'allow', {}, TENANT).body, {groupId: row.groupId, mode: 'allow', etag: 'e1'});
  assert.deepEqual(rowRequest(detail, row, 'allow', {confirmAllow: true}, TENANT).body, {groupId: row.groupId, mode: 'allow', etag: 'e1', confirmAllow: true});
});

test('the approval page shows the exact bytes; an incomplete one offers Reject only, in words without the workspace; an expired one nothing', () => {
  const path = `/connect/${CS}/v1/approvals/${REF}/decision`;
  const pending = {state: 'pending', approval: {callRef: REF, operation: 'Send email', appName: 'Gmail', warnings: [], expiresAt: '2026-10-14T12:10:00.000Z', digest: 'd'.repeat(64),
    exact: {complete: true, blocks: [{label: 'Body', text: 'a‮b​c'}]}, approve: {path, body: {decision: 'approve', digest: 'd'.repeat(64)}}, cancel: {path, body: {decision: 'reject', digest: 'd'.repeat(64)}}}};
  const model = describePage(pending, {tenant: true});
  assert.equal(model.exact[0].text, 'a⟦U+202E⟧b⟦U+200B⟧c');
  assert.deepEqual(buttonsFor(model, {tenant: true}).map(button => button.label), ['Approve', 'Reject']);
  const incomplete = describePage({...pending, approval: {...pending.approval, approve: null, exact: {complete: false, blocks: [{label: 'Body', text: 'x'}]}}}, {tenant: true});
  assert.deepEqual(buttonsFor(incomplete, {tenant: true}).map(button => button.label), ['Reject']);
  const words = incomplete.notes.join(' ');
  assert.match(words, /reject it/); assert.doesNotMatch(words, /workspace/i);
  assert.match(describeApproval({...pending.approval, exact: {complete: false, blocks: []}}).incomplete, /Fabric workspace/, 'the owner\'s words are unchanged');
  const expired = describePage({state: 'expired', operation: 'Send email', appName: 'Gmail', summary: 'This approval expired. Nothing ran.'}, {tenant: true});
  assert.deepEqual(buttonsFor(expired, {tenant: true}), []);
  assert.deepEqual(outcomeOf({decision: 'approved', status: 'queued', redirect: 'http://localhost:5173/x'}), {line: 'Approved. It is running.', redirect: 'http://localhost:5173/x'});
  assert.deepEqual(outcomeOf({decision: 'rejected'}), {line: 'Rejected. Nothing ran.', redirect: null});
});

test('markup in data stays text: a task title, an approval body and an account name come back as plain strings', () => {
  const evil = '<img src=x onerror=alert(1)>';
  const approval = describeApproval({operation: 'Send email', appName: 'Gmail', taskTitle: evil, exact: {complete: true, blocks: [{label: 'Body', text: evil}]}, warnings: []}, {tenant: true});
  assert.equal(approval.agentSays, `Agent says: “${evil}”`); assert.equal(approval.blocks[0].text, evil);
  const model = describeApp({app: {id: 'gmail', name: 'Gmail'}, connectionState: 'connected', selectedAccountRef: REF, accounts: [{accountRef: REF, displayName: evil, initial: '<', status: 'ready'}], sections: []}, TENANT);
  assert.equal(model.accounts[0].name, evil);
  // Every hosted script, the Connect page and the shared base put text in as text: no HTML sinks anywhere.
  const scripts = ['connect.js', ...readdirSync(new URL('../public/', import.meta.url)).filter(name => /^hosted-.*\.js$/.test(name))];
  assert.ok(scripts.includes('hosted-base.js') && scripts.length >= 8, scripts.join(','));
  for (const name of scripts) {
    const source = readFileSync(new URL(`../public/${name}`, import.meta.url), 'utf8');
    for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'DOMParser', 'eval(', 'new Function', 'srcdoc']) assert.equal(source.includes(sink), false, `${name} uses ${sink}`);
  }
});

test('a manage link serves the four pages with Fabric\'s page headers, and every file they load', async t => {
  const {app, keys, account, ask, open} = await hostedSetup(t);
  await account('u1', 'g-1');
  const {id, person} = await open(keys.full, {externalUserId: 'u1', purpose: 'manage'});
  const loaded = new Set();
  const fetchAll = async (url, kind) => {
    if (loaded.has(url)) return; loaded.add(url);
    const response = await fetch(`${app.origin}${url}`);
    assert.equal(response.status, 200, url);
    assert.match(response.headers.get('content-type'), kind === 'script' ? /javascript/ : /text\/css/, url);
    if (kind === 'script') for (const match of (await response.text()).matchAll(/^import\s[^'"]*['"](\.\/[^'"]+)['"]/gm)) await fetchAll(new URL(match[1], `${app.origin}${url}`).pathname, 'script');
  };
  const waiting = await ask('u1');
  const approve = await open(keys.full, {externalUserId: 'u1', purpose: 'approve', callRef: waiting.callRef});
  for (const path of [`/connect/${id}/apps`, `/connect/${id}/apps/gmail`, `/connect/${id}/activity`, `/connect/${approve.id}/approve`]) {
    const page = await person.call('GET', path);
    assert.equal(page.status, 200, path); assert.match(page.headers.get('content-type'), /text\/html/);
    assert.match(page.headers.get('content-security-policy'), /default-src 'none'; script-src 'self'/); assert.equal(page.headers.get('x-frame-options'), 'DENY');
    for (const match of page.body.matchAll(/<script[^>]*src="([^"]+)"/g)) await fetchAll(match[1], 'script');
    for (const match of page.body.matchAll(/<link[^>]*href="([^"]+)"/g)) await fetchAll(match[1], 'style');
  }
  assert.ok(loaded.has('/hosted-base.js') && loaded.has('/sign-in-target.js') && loaded.has('/hosted-approval.js') && loaded.has('/hosted-text.js'), [...loaded].join(','));
  assert.equal((await fetch(`${app.origin}/hosted-nope.js`)).status, 404);
  assert.equal((await fetch(`${app.origin}/connect/${id}/apps/Gmail`)).status, 404);
});

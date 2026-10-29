import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {baseFor, errorOf, cardText} from '../public/hosted-base.js';
import {describeApp, confirmedRequest, siblingChoices} from '../public/hosted-app.js';

// F10.4 part h: the front ends show what a confirm is about and send exactly the confirm the server asked for. The upgrade
// card (T7) goes with Add access and full upgrades as confirmRows; a Google disconnect that would sign out other accounts of
// the same grant offers "Disconnect everywhere" (confirmSiblings) or "Disconnect here only" (remote: false); connection
// notices show under the summary. Fabric's manage page in a developer environment disconnects here only (build map
// correction 3), so it never offers the sibling choice.
const CS = `cs_${'a'.repeat(26)}`, TENANT = baseFor(`/connect/${CS}/apps/gmail`), OWNER = baseFor('/connectors/gmail');
const CARD = {rows: [{groupId: 'gmail.send', label: 'Send email', typed: true, proxy: false}, {groupId: 'gmail.drafts.write', label: 'Write drafts', typed: true, proxy: true}], etag: 'e'.repeat(64)};
const SIBLINGS = [{connectionId: 'cal-1', appId: 'google-calendar', displayName: 'a@example.com', waiting: false}, {connectionId: 'cal-2', appId: 'google-calendar', displayName: 'a@example.com', waiting: true}];
const source = name => readFileSync(new URL(`../public/${name}`, import.meta.url), 'utf8');
/** Objects made inside a vm context have that context's prototypes; compared by value. */
const plain = value => JSON.parse(JSON.stringify(value));

/** Just enough of the DOM for the page functions under test: text, children, attributes, replace and click. */
class Node {
  constructor(tag, attrs = {}, ...children) { this.tag = tag; this.attrs = attrs; this.hidden = attrs.hidden === true; this.children = children.flat(Infinity).filter(value => value !== null && value !== undefined && value !== false); this.parent = null; for (const child of this.children) if (child instanceof Node) child.parent = this; }
  get textContent() { return this.hidden ? '' : this.children.map(child => child instanceof Node ? child.textContent : String(child)).join(' '); }
  set textContent(value) { this.children = [String(value)]; }
  append(...children) { for (const child of children.flat(Infinity).filter(value => value !== null && value !== undefined && value !== false)) { if (child instanceof Node) child.parent = this; this.children.push(child); } }
  replaceChildren(...children) { this.children = []; this.append(...children); }
  replaceWith(next) { const siblings = this.parent.children; siblings[siblings.indexOf(this)] = next; if (next instanceof Node) next.parent = this.parent; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
  all() { return [this, ...this.children.filter(child => child instanceof Node).flatMap(child => child.all())]; }
  button(label) { return this.all().find(node => node.tag === 'button' && node.textContent.trim() === label); }
  querySelector(selector) { return selector === 'input[name="level"]:checked' ? this.all().find(node => node.tag === 'input' && node.attrs.name === 'level' && node.attrs.checked) ?? null : null; }
}
const el = (tag, attrs, ...children) => new Node(tag, attrs, ...children);

test('errorOf keeps the card, the siblings and the affected accounts from both Fabrics, and nothing malformed', () => {
  const linked = errorOf({error: {code: 'confirm_required', message: 'Confirm.', details: {upgrade: CARD}}}, 409);
  assert.deepEqual([linked.code, linked.message, linked.upgrade, linked.siblings], ['confirm_required', 'Confirm.', CARD, undefined]);
  const owner = errorOf({error: 'Disconnecting Gmail at Google also signs...', code: 'confirm_required', siblings: SIBLINGS}, 409);
  assert.deepEqual([owner.code, owner.siblings, owner.upgrade], ['confirm_required', SIBLINGS, undefined]);
  assert.deepEqual(errorOf({error: 'x', code: 'confirm_required', upgrade: CARD, affected: [{connectionId: 'c', appId: 'gmail'}]}, 409).affected, [{connectionId: 'c', appId: 'gmail'}]);
  for (const upgrade of [{rows: CARD.rows}, {rows: 'x', etag: 'e'}, 'card']) assert.equal(errorOf({error: 'x', code: 'confirm_required', upgrade}, 409).upgrade, undefined);
  assert.equal(errorOf({error: {code: 'confirm_required', message: 'm', details: {siblings: 'x'}}}, 409).siblings, undefined);
  // The view a refused row change carries is unchanged.
  assert.deepEqual(errorOf({error: 'Changed.', code: 'view_changed', view: {app: {}}}, 409).view, {app: {}});
});

test('the app page model: Add carries its card, a full upgrade its own, and notices name their account', () => {
  const row = {groupId: 'gmail.send', label: 'Send email', effect: 'write', mode: 'ask', defaultMode: 'allow', allowedModes: ['allow', 'ask', 'deny'], access: 'missing', policySource: 'default', reviewRequired: false, etag: 'r1',
    addAccess: {providerId: 'google', body: {connectionId: 'a-1', scopes: ['https://www.googleapis.com/auth/gmail.send']}}, upgrade: CARD};
  const detail = {app: {id: 'gmail', name: 'Gmail'}, connectionState: 'connected', selectedAccountRef: 'a-1',
    accounts: [{accountRef: 'a-1', displayName: 'a@example.com', email: 'a@example.com', initial: 'A', status: 'ready'}, {accountRef: 'a-2', displayName: 'b@example.com', email: 'b@example.com', initial: 'B', status: 'reconnect_required'}],
    notices: [{kind: 'reconnect_required', accountRef: 'a-2', message: 'Reconnect this account to use it: sign in again. Your settings stay as they are.', since: '2026-10-17T00:00:00.000Z'}],
    upgrade: {label: 'Upgrade to full access', providerId: 'google', body: {connectionId: 'a-1', level: 'full'}, rows: CARD.rows, etag: CARD.etag},
    sections: [{label: 'Write and delete permissions', rows: [row]}]};
  const model = describeApp(detail), add = model.sections[0].rows[0].add;
  assert.deepEqual(add, {request: {path: '/api/oauth/google/start', body: row.addAccess.body}, signIn: {providerId: 'google'}, card: CARD});
  assert.deepEqual(confirmedRequest(add, CARD.etag), {request: {path: '/api/oauth/google/start', body: {...row.addAccess.body, confirmRows: CARD.etag}}, signIn: {providerId: 'google'}, card: CARD});
  assert.deepEqual(add.request.body, row.addAccess.body, 'the action shown is never changed by confirming it');
  assert.deepEqual(model.upgrade, {label: 'Upgrade to full access', request: {path: '/api/oauth/google/start', body: {connectionId: 'a-1', level: 'full'}}, signIn: {providerId: 'google'}, card: CARD});
  assert.equal(describeApp({...detail, upgrade: {...detail.upgrade, rows: [], etag: null}}).upgrade.card, undefined, 'within what was approved there is nothing to confirm');
  assert.deepEqual(model.notices, [{accountRef: 'a-2', text: 'b@example.com: Reconnect this account to use it: sign in again. Your settings stay as they are.'}]);
  assert.deepEqual(describeApp({...detail, accounts: detail.accounts.slice(1)}).notices.map(notice => notice.text), ['Reconnect this account to use it: sign in again. Your settings stay as they are.'], 'one account needs no name');
  assert.deepEqual(describeApp({...detail, notices: undefined}).notices, []);
  assert.equal(cardText(CARD), 'After this sign-in the agent can do these without asking you first: Send email, Write drafts. Anything you set to Allow before asks you again, and anything set to Never stays off.');
});

test('a disconnect that would sign out other accounts offers everywhere or here only on the owner\'s page, and never on a manage link', () => {
  const detail = {app: {id: 'gmail', name: 'Gmail'}, connectionState: 'connected', selectedAccountRef: 'a-1', accounts: [{accountRef: 'a-1', displayName: 'a@example.com', initial: 'A', status: 'ready'}], sections: []};
  const owner = describeApp(detail).disconnect, error = errorOf({error: 'Disconnecting Gmail at Google also signs a@example.com out of Google Calendar here.', code: 'confirm_required', siblings: SIBLINGS}, 409);
  assert.deepEqual(owner.request, {path: '/api/ui/apps/gmail/accounts/a-1/disconnect', body: {}});
  const choices = siblingChoices(owner, error, OWNER);
  assert.equal(choices.text, error.message, 'the server\'s words name the other accounts and what Google does');
  assert.deepEqual(choices.everywhere.request, {path: '/api/ui/apps/gmail/accounts/a-1/disconnect', body: {confirmSiblings: true}});
  assert.deepEqual(choices.hereOnly.request, {path: '/api/ui/apps/gmail/accounts/a-1/disconnect', body: {remote: false}});
  assert.equal(choices.everywhere.disconnects && choices.hereOnly.disconnects, true);
  assert.equal(siblingChoices(owner, errorOf({error: 'x', code: 'not_found'}, 404), OWNER), null);
  assert.equal(siblingChoices(owner, errorOf({error: 'Confirm.', code: 'confirm_required', upgrade: CARD}, 409), OWNER), null);
  assert.equal(siblingChoices(describeApp(detail, TENANT).disconnect, error, TENANT), null, 'the manage page disconnects here only');
  assert.deepEqual(describeApp(detail, TENANT).disconnect.request.body, {}, 'and never sends remote');
});

test('the owner workspace: Add access sends the server\'s body to its provider, shows the card from a 409 and continues with its etag', async () => {
  // F10.7 (open question 19): the per-operation Add sends the body the server computed for that operation, unchanged, to that
  // provider's start route, and opens only that provider's authorization origin. The browser never picks a scope.
  const flow = source('app.js'), code = flow.slice(flow.indexOf('function googleConsentDialog'), flow.indexOf('async function openLocal'));
  assert.doesNotMatch(flow, /minimalGoogleScope/, 'no scope ranking in the browser');
  const card = {rows: [{groupId: 'gmail.labels.manage', label: 'Manage labels', typed: true, proxy: false}], etag: 'f'.repeat(64)};
  const oauthProviders = {google: {name: 'Google', available: true, authorizationOrigin: 'https://accounts.google.com', consentMode: 'full'}, github: {name: 'GitHub', available: true, authorizationOrigin: 'https://github.com', consentMode: 'full'}};
  const run = async ({app, connection, add, url, carded = true}) => {
    let form, work, opened;
    const calls = [], assigned = [];
    const context = {el, cardText, state: {settings: {googleOAuthConfigured: true, oauthProviders}},
      note: (text, tone) => el('p', {tone}, text), actions: (...nodes) => el('div', {class: 'dialog-actions'}, nodes), cancel: () => el('button', {}, 'Cancel'), button: (label, action, kind, attrs) => Object.assign(el('button', attrs, label), {action}),
      submitForm: (node, run) => { form = node; work = run; }, openDialog: (title, description, content) => { opened = title; form = content; }, URL, location: {assign: href => assigned.push(href)},
      api: async (path, body) => { calls.push({path, body}); if (carded && !body.confirmRows) throw Object.assign(new Error('After this sign-in, agents could do these without asking: Manage labels. Confirm to continue.'), {code: 'confirm_required', details: {upgrade: card}}); return {authorizationUrl: url}; }};
    runInNewContext(`${code}; signInDialog`, context)(app, {connection, add});
    return {get form() { return form; }, work: () => work(), calls, assigned, get opened() { return opened; }};
  };
  const gmail = {providerId: 'google', body: {connectionId: 'a-1', level: 'full', scopes: ['https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/gmail.settings.basic']}};
  const page = await run({app: {id: 'gmail', name: 'Gmail'}, connection: {id: 'a-1', identity: {email: 'a@example.com'}}, add: gmail, url: 'https://accounts.google.com/o/oauth2/v2/auth?x=1'});
  assert.equal(page.opened, 'Add account access');
  assert.match(page.form.textContent, /gmail\.modify[\s\S]*gmail\.settings\.basic/, 'the box names every scope the sign-in asks for');
  assert.doesNotMatch(page.form.textContent, /without asking you first/, 'no card before the server names one');
  await page.work();
  assert.deepEqual(plain(page.calls[0]), {path: '/api/oauth/google/start', body: gmail.body}, 'the server\'s body, unchanged');
  assert.match(page.form.textContent, /After this sign-in the agent can do these without asking you first: Manage labels\./);
  assert.ok(page.form.button('Confirm and continue'), 'the submit now confirms the card');
  assert.deepEqual(page.assigned, [], 'nothing opened yet');
  await page.work();
  assert.deepEqual(plain(page.calls[1].body), {...gmail.body, confirmRows: card.etag});
  assert.deepEqual(page.assigned, ['https://accounts.google.com/o/oauth2/v2/auth?x=1']);
  // Another provider's Add goes to its own route, and only its own authorization origin is opened.
  const github = {providerId: 'github', body: {connectionId: 'g-1', level: 'full', scopes: ['gist']}};
  const hub = await run({app: {id: 'github', name: 'GitHub'}, connection: {id: 'g-1', label: 'octo'}, add: github, url: 'https://github.com/login/oauth/authorize?x=1', carded: false});
  // Under a full consent policy an Add at the full level asks for the whole level besides the scope it names, and the box says so.
  assert.match(hub.form.textContent, /gist[\s\S]*Sign-in also asks GitHub for the rest of full access to this app\./);
  for (const [providerId, add, mode] of [['google', {...gmail, body: {...gmail.body, level: 'read', scopes: ['https://www.googleapis.com/auth/gmail.modify']}}, 'full'], ['google', gmail, 'required']]) {
    const before = oauthProviders[providerId].consentMode;
    oauthProviders[providerId].consentMode = mode;
    const box = await run({app: {id: 'gmail', name: 'Gmail'}, connection: {id: 'a-1', identity: {email: 'a@example.com'}}, add, url: 'https://accounts.google.com/o/oauth2/v2/auth?x=1'});
    oauthProviders[providerId].consentMode = before;
    assert.doesNotMatch(box.form.textContent, /rest of full access/, `${add.body.level} under ${mode}: only the named scopes and what the account holds`);
  }
  await hub.work();
  assert.deepEqual([plain(hub.calls), hub.assigned], [[{path: '/api/oauth/github/start', body: github.body}], ['https://github.com/login/oauth/authorize?x=1']]);
  const elsewhere = await run({app: {id: 'github', name: 'GitHub'}, connection: {id: 'g-1', label: 'octo'}, add: github, url: 'https://accounts.google.com/o/oauth2/v2/auth?x=1', carded: false});
  await assert.rejects(elsewhere.work(), /Unexpected authorization destination/);
  assert.deepEqual(elsewhere.assigned, []);
});

test('the owner workspace: a Google revoke that names other accounts offers everywhere or here only, and says what it affected', async () => {
  const flow = source('app.js'), code = flow.slice(flow.indexOf('function revokeDialog'), flow.indexOf('function appSelect'));
  for (const [label, body] of [['Disconnect everywhere', {confirmSiblings: true}], ['Disconnect here only', {remote: false}]]) {
    let form, work;
    const calls = [], notices = [], dialog = {open: true, close() { this.open = false; }};
    const context = {el, dialog, isPersistentBrowser: () => false, isDurableBrowser: () => false, appName: id => ({gmail: 'Gmail', 'google-calendar': 'Google Calendar'})[id] ?? id,
      note: (text, tone) => el('p', {tone}, text), actions: (...nodes) => el('div', {}, nodes), cancel: () => el('button', {}, 'Cancel'), button: (text, action, kind, attrs) => Object.assign(el('button', attrs, text), {action}),
      submitForm: (node, run) => { form = node; work = run; }, openDialog: () => {}, refresh: async () => {}, notify: (message, error) => notices.push([message, Boolean(error)]),
      api: async (path, sent) => {
        calls.push({path, body: sent});
        if (!sent.confirmSiblings && sent.remote !== false) throw Object.assign(new Error('Disconnecting Gmail at Google also signs a@example.com out of Google Calendar here.'), {code: 'confirm_required', details: {error: 'x', code: 'confirm_required', siblings: SIBLINGS.slice(0, 1)}});
        return sent.confirmSiblings ? {remoteRevoked: true, message: 'Disconnected locally and Google revocation confirmed.', affected: [{connectionId: 'cal-1', appId: 'google-calendar'}]} : {remoteRevoked: false, message: 'Disconnected here. Fabric did not ask Google to revoke access.'};
      }};
    runInNewContext(`${code}; revokeDialog`, context)({id: 'mail-1', appId: 'gmail', label: 'Gmail'});
    await work();
    assert.deepEqual(plain(calls), [{path: '/api/connections/mail-1/revoke', body: {}}]);
    assert.match(form.textContent, /also signs a@example\.com out of Google Calendar/);
    assert.match(form.textContent, /Google Calendar \(a@example\.com\)/);
    assert.equal(dialog.open, true, 'nothing changed, so the dialog stays');
    await form.button(label).action();
    assert.deepEqual(plain(calls[1]), {path: '/api/connections/mail-1/revoke', body});
    assert.equal(dialog.open, false);
    assert.deepEqual(notices, [[body.confirmSiblings ? 'Disconnected locally and Google revocation confirmed. Google Calendar needs a sign-in again.' : 'Disconnected here. Fabric did not ask Google to revoke access.', false]]);
  }
});

test('Fabric\'s Connect page: the confirm screen shows the card and confirms with its etag, and a stale card is replaced', async () => {
  const script = source('connect.js');
  const code = script.slice(script.indexOf('function confirmCard'), script.indexOf('/** A call is waiting'));
  const card = {rows: [{groupId: 'gmail.send', label: 'Send email', typed: true, proxy: false}], etag: 'a'.repeat(64)}, fresh = {rows: [...card.rows, {groupId: 'gmail.drafts.write', label: 'Write drafts', typed: true, proxy: false}], etag: 'b'.repeat(64)};
  const calls = [], rendered = [];
  const context = {
    el: (tag, {attrs, textContent, ...props} = {}, ...children) => Object.assign(el(tag, {...attrs, ...props}, textContent ?? [], ...children), props),
    add: (parent, ...children) => { parent.append(...children); return parent; }, topBar: () => null, appNameOf: () => 'Acme Assistant',
    button: (label, onClick) => Object.assign(el('button', {}, label), {action: onClick}), busy: (control, label, run) => run(), render: view => rendered.push(view),
    api: async (path, body) => { calls.push({path, body}); if (path === 'view') return {state: 'connected'}; if ('confirmRows' in body && body.confirmRows !== fresh.etag) throw Object.assign(new Error('Confirm.'), {code: 'confirm_required', details: {upgrade: fresh}}); return {state: 'connected'}; },
  };
  const confirmScreen = runInNewContext(`${code}; confirmScreen`, context);
  const screen = confirmScreen({state: 'awaiting_confirmation', appName: 'Gmail', providerName: 'Google', pendingAccount: {displayName: 'a@example.com'}, upgrade: card});
  assert.match(screen.textContent, /can do these without asking you first/); assert.match(screen.textContent, /Send email/);
  await assert.rejects(screen.button('Connect and allow').action(), {code: 'confirm_required'});
  assert.deepEqual(plain(calls[0]), {path: 'confirm', body: {confirmRows: card.etag}});
  assert.match(screen.textContent, /Write drafts/, 'the card the server holds now');
  await screen.button('Connect and allow').action();
  assert.deepEqual(plain(calls[1]), {path: 'confirm', body: {confirmRows: fresh.etag}});
  assert.deepEqual(plain(rendered), [{state: 'connected'}]);
  // An upgrade that turns nothing on at Allow still confirms with its etag, and says saved Allows ask again.
  const quiet = confirmScreen({state: 'awaiting_confirmation', appName: 'Gmail', pendingAccount: {displayName: 'a@example.com'}, upgrade: {rows: [], etag: fresh.etag}});
  assert.match(quiet.textContent, /asks you again/);
  await quiet.button('Connect').action();
  assert.deepEqual(plain(calls.at(-2)), {path: 'confirm', body: {confirmRows: fresh.etag}});
  // A sign-in that is not an upgrade confirms with nothing.
  await confirmScreen({state: 'awaiting_confirmation', appName: 'Gmail', pendingAccount: {displayName: 'a@example.com'}}).button('Connect').action();
  assert.deepEqual(plain(calls.at(-2)), {path: 'confirm', body: {}});
});

test('Fabric\'s Connect page: a reconnect or Add access sheet shows the card, starts with its etag, and a stale card is replaced', async () => {
  const script = source('connect.js');
  const code = script.slice(script.indexOf('function upgradeCard'), script.indexOf('function appsScreen'));
  const card = {rows: [{groupId: 'gmail.send', label: 'Send email', typed: true, proxy: false}], etag: 'c'.repeat(64)}, fresh = {rows: [...card.rows, {groupId: 'gmail.drafts.write', label: 'Write drafts', typed: true, proxy: false}], etag: 'd'.repeat(64)};
  const calls = [], assigned = [];
  const context = {
    el: (tag, {attrs, textContent, ...props} = {}, ...children) => Object.assign(el(tag, {...attrs, ...props}, textContent ?? [], ...children), props),
    add: (parent, ...children) => { parent.append(...children); return parent; }, topBar: () => null, appNameOf: () => 'Acme Assistant', location: {assign: url => assigned.push(url)},
    button: (label, onClick) => Object.assign(el('button', {}, label), {action: onClick}), busy: (control, label, run) => run(),
    api: async (path, body) => { calls.push({path, body}); if (body.confirmRows !== undefined && body.confirmRows !== fresh.etag) throw Object.assign(new Error('Confirm.'), {code: 'confirm_required', details: {upgrade: fresh}}); return {authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth?x=2'}; },
  };
  const sheetScreen = runInNewContext(`${code}; sheetScreen`, context);
  // The sheet of a reconnect or Add access link offers one level, the one its link signs in at, so start sends none.
  const sheet = {levels: [{level: 'full', label: 'Read and write', isDefault: true}], action: {label: 'Continue with Google'}, app: {id: 'gmail', name: 'Gmail', iconUrl: '/icons/gmail.svg'}, developer: {appName: 'Acme Assistant'},
    accessLine: 'Read and write', points: [], defaultsLine: 'Agents ask first.', notices: [], providerApp: {consentScreenName: 'Fabric'}, finePrint: []};
  const screen = sheetScreen({state: 'opened', appName: 'Gmail', providerName: 'Google', sheet, upgrade: card});
  assert.match(screen.textContent, /can do these without asking you first/); assert.match(screen.textContent, /Send email/);
  await assert.rejects(screen.button('Continue with Google').action(), {code: 'confirm_required'});
  assert.deepEqual(plain(calls[0]), {path: 'start', body: {confirmRows: card.etag}}, 'starting confirms the card shown');
  assert.match(screen.textContent, /Write drafts/, 'the card the server holds now');
  assert.deepEqual(assigned, [], 'nothing opened yet');
  await screen.button('Continue with Google').action();
  assert.deepEqual(plain(calls[1]), {path: 'start', body: {confirmRows: fresh.etag}});
  assert.deepEqual(assigned, ['https://accounts.google.com/o/oauth2/v2/auth?x=2']);
  // A link whose sign-in widens nothing shows no card and starts with nothing to confirm.
  const plainSheet = sheetScreen({state: 'opened', appName: 'Gmail', providerName: 'Google', sheet});
  assert.doesNotMatch(plainSheet.textContent, /without asking you first/);
  await plainSheet.button('Continue with Google').action();
  assert.deepEqual(plain(calls.at(-1)), {path: 'start', body: {}});
});

// Live session 1: after a GitHub sign-in the banner said "Google authorization returned". The words name no provider; a failure's own
// words already do ("Google consent was declined...", "GitHub did not grant...").
test('the sign-in return banner names no provider: "Sign-in returned..." on success, "Sign-in did not complete: <the reason>" on failure', () => {
  const flow = source('app.js'), code = flow.slice(flow.indexOf("const oauthResult = new URLSearchParams(location.search).get('oauth');"));
  assert.ok(code.includes("'Sign-in returned. Choose the connected app to review your account access.'"));
  assert.ok(code.includes('`Sign-in did not complete: ${oauthResult.slice(0, 500)}`'));
  assert.equal(/Google authorization/.test(flow), false);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { requestBrowserBridge, inputValue, directoryCandidates, connectionKind, buildSummary } from '../public/connect-client.js';
import * as connectionClient from '../public/connect-client.js';

function targetMock() {
  const listeners = new Set();
  const target = {
    crypto: { randomUUID: () => 'request-1' }, location: { origin: 'http://127.0.0.1:4188' },
    addEventListener(type, fn) { assert.equal(type, 'message'); listeners.add(fn); },
    removeEventListener(type, fn) { listeners.delete(fn); },
    postMessage(message, origin) { this.message = message; this.destination = origin; },
    respond(overrides = {}) { for (const fn of [...listeners]) fn({ source: target, origin: target.location.origin, data: { source: 'fabric-extension', type: 'fabric:bridge:result', requestId: 'request-1', ok: true, version: '0.2' }, ...overrides }); },
    listenerCount() { return listeners.size; }
  };
  return target;
}

test('browser handoff is same-origin and only accepts the matching window result', async () => {
  const target = targetMock();
  const result = requestBrowserBridge('ping', {}, { target, timeoutMs: 100 });
  assert.equal(target.destination, target.location.origin);
  assert.equal(target.message.type, 'fabric:bridge:ping');
  target.respond({ origin: 'https://attacker.example' });
  target.respond({ source: {} });
  target.respond({ data: { source: 'fabric-extension', type: 'fabric:bridge:result', requestId: 'unrelated', ok: true } });
  assert.equal(target.listenerCount(), 1);
  target.respond();
  assert.equal((await result).version, '0.2');
  assert.equal(target.listenerCount(), 0);
});

test('missing browser helper times out and removes its listener', async () => {
  const target = targetMock();
  await assert.rejects(requestBrowserBridge('ping', {}, { target, timeoutMs: 5 }), /not available in this browser/);
  assert.equal(target.listenerCount(), 0);
});

test('browser handoff error is actionable and never treated as a connected account', async () => {
  const target = targetMock();
  const request = requestBrowserBridge('connect', { pairing: { pairingId: 'pair-1', code: 'local-code' } }, { target, timeoutMs: 100 });
  target.respond({ data: { source: 'fabric-extension', type: 'fabric:bridge:result', requestId: 'request-1', ok: false, error: 'Permission not granted.' } });
  await assert.rejects(request, /Permission not granted/);
  assert.equal(target.listenerCount(), 0);
});

test('typed action forms preserve declared input types', () => {
  assert.equal(inputValue({ type: 'integer' }, '3'), 3);
  assert.equal(inputValue({ type: 'boolean' }, false), false);
  assert.deepEqual(inputValue({ type: 'array' }, '[1]'), [1]);
  assert.deepEqual(inputValue({ type: 'object' }, '{"limit":2}'), { limit: 2 });
  assert.throws(() => inputValue({ type: 'integer' }, '2.4'), /valid number/);
  assert.throws(() => inputValue({ type: 'object' }, 'null'), /JSON object/);
  assert.throws(() => inputValue({ type: 'array' }, '{}'), /JSON array/);
});

test('element builder serializes ARIA booleans without changing HTML boolean attributes', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const builder = source.slice(source.indexOf('function el('), source.indexOf('const text ='));
  const create = runInNewContext(`${builder}; el`, {
    document: { createElement: () => ({ attributes: {}, setAttribute(key, value) { this.attributes[key] = value; } }) }
  });
  assert.equal(create('button', { 'aria-pressed': true }).attributes['aria-pressed'], 'true');
  assert.equal(create('button', { 'aria-pressed': false }).attributes['aria-pressed'], 'false');
  assert.equal(create('input', { required: true }).attributes.required, '');
  assert.equal(create('input', { required: false }).attributes.required, undefined);
  assert.equal(create('button', { disabled: true }).disabled, true);
  assert.equal(create('button', { disabled: false }).attributes.disabled, undefined);
});

test('connector and permission search contrast overrides the legacy light theme', async () => {
  const css = await readFile(new URL('../public/connectors.css', import.meta.url), 'utf8');
  assert.match(css, /\.simple-view \.connector-toolbar \.search input,\.simple-view \.permission-search input \{ background:#303034; color:var\(--ink\); \}/);
});

test('directory fixtures remain listings, reject malformed identities, and preserve provenance', () => {
  const fixture = { id: 'fixture:calendar', name: 'Fixture Calendar', source: { name: 'Fixture directory', kind: 'community-directory' }, website: 'https://fixture.example', accountConnected: false };
  assert.deepEqual(directoryCandidates({ candidates: [fixture, null, { name: 'No identifier' }, { id: 'empty' }] }), [fixture]);
  assert.equal(directoryCandidates({ candidates: [fixture] })[0].accountConnected, false);
  assert.deepEqual(directoryCandidates({ candidates: {} }), []);
  assert.deepEqual(directoryCandidates({ status: 'resolved', app: { id: 'fixture' } }), []);
});

test('action factory descriptions never imply a real account connection', () => {
  assert.equal(connectionKind({ driver: 'device' }), 'This computer');
  assert.equal(connectionKind({ driver: 'browser' }), 'Browser session');
  assert.equal(connectionKind({ driver: 'workspace' }), 'Local folder');
  assert.equal(connectionKind({ driver: 'http', authMethod: 'oauth' }), 'Provider account');
  assert.match(buildSummary({ status: 'built', capabilityIds: ['fixture.read'] }), /1 action definition prepared.*still require a supported connection/);
  assert.match(buildSummary({ status: 'built', capabilityIds: ['fixture.read'], unsupported: [{ operationId: 'fixture.write' }] }), /1 other operation is not executable yet/);
  assert.match(buildSummary({ status: 'blocked', capabilityIds: [] }), /No executable actions were established/);
  assert.match(buildSummary({ status: 'failed' }), /No new access was granted/);
});

test('directory lookup is explicit, selection is required, and factory detail is secondary', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const lookup = source.slice(source.indexOf('async function resolveApplication'), source.indexOf('function websiteDialog'));
  assert.match(lookup, /api\('\/api\/catalog\/lookup', \{ query: value \}\)/);
  assert.match(lookup, /api\('\/api\/catalog\/select', \{ candidateId: candidate.id \}\)/);
  assert.match(lookup, /These are directory listings, not connected accounts/);
  assert.match(lookup, /src: `\/api\/catalog\/icons\/\$\{encodeURIComponent\(candidate.id\)\}`/);
  assert.doesNotMatch(lookup, /src: candidate\.(iconUrl|website)/);
  assert.match(source, /api\('\/api\/factory\/build', \{ appId \}\)/);
  assert.match(source, /'More details'/);
  const catalog = source.slice(source.indexOf('function renderCatalog'), source.indexOf('function appCategory'));
  assert.doesNotMatch(catalog.match(/searchInput.addEventListener\('input'[^\n]+/)?.[0] || '', /api\(|resolveApplication/);
});

test('native dialog has labels, escape dismissal, and focus restoration', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /<dialog[^>]+aria-labelledby="dialog-title"[^>]+aria-describedby="dialog-description"/);
  assert.match(source, /if \(!dialog.open\) dialogReturnFocus = returnFocus \|\| document.activeElement/);
  assert.match(source, /returnFocus: event.submitter \|\| searchInput/);
  assert.match(source, /dialog.addEventListener\('cancel', event => \{ event.preventDefault\(\); dialog.close\(\); \}\)/);
  assert.match(source, /restore\?\.isConnected && !restore.disabled/);
});

test('unsupported connection outcome displays a limitation without Retry or Connected', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const flow = source.slice(source.indexOf('async function startConnection'), source.indexOf('function connectionSuccess'));
  const buttons = [], notices = [];
  const result = { kind: 'unsupported', connectionEstablished: false, message: 'This installation has no supported account connection yet.', plan: { routes: [], recommended: null } };
  const start = runInNewContext(`${flow}; startConnection`, {
    rows: () => [],
    api: async () => result,
    el: () => ({ isConnected: true, replaceChildren() {} }),
    appIcon: () => ({}), connectionProgress: () => ({}),
    openDialog() {}, dialog: { open: true, close() {} },
    note: message => { notices.push(message); return {}; },
    actions: (...items) => items,
    button: label => { buttons.push(label); return {}; },
    refresh: () => { throw new Error('Unsupported outcome must not mark an account connected.'); },
    connectionSuccess: () => { throw new Error('Unsupported outcome must not render success.'); },
    browserConnectionDialog: () => { throw new Error('Unsupported outcome must not start a fallback pairing.'); }
  });
  await start({ id: 'fixture', name: 'Fixture app' });
  assert.deepEqual(buttons, ['Close']);
  assert.deepEqual(notices, [result.message]);
});

test('a paired browser is not a connected account and heartbeat evidence is not login evidence', () => {
  assert.equal(typeof connectionClient.isConnectedService, 'function');
  assert.equal(typeof connectionClient.browserConnectionState, 'function');
  const connection = { driver: 'browser', status: 'session_ready', browserEvidence: { bridge: { status: 'alive', lastHeartbeatAt: new Date().toISOString() }, account: { verified: false, status: 'unverified' }, page: { status: 'not_observed' } } };
  assert.equal(connectionClient.isConnectedService(connection), false);
  assert.equal(connectionClient.isConnectedService({ driver: 'http', status: 'ready' }), true);
  assert.equal(connectionClient.isConnectedService({ driver: 'device', status: 'ready' }), true);
  assert.equal(connectionClient.isConnectedService({ driver: 'http', status: 'unavailable' }), false);
  const state = connectionClient.browserConnectionState(connection);
  assert.equal(state.accountVerified, false);
  assert.equal(state.canTest, true);
  assert.equal(state.pageObserved, false);
});

test('legacy pairing and stale helper evidence never display a usable or verified browser account', () => {
  const now = Date.now();
  const legacy = connectionClient.browserConnectionState({ driver: 'browser', status: 'session_ready', lastCheckedAt: new Date(now).toISOString() }, now);
  assert.equal(legacy.status, 'waiting');
  assert.equal(legacy.canTest, false);
  const connection = { driver: 'browser', status: 'session_ready', browserEvidence: { bridge: { status: 'alive', lastHeartbeatAt: new Date(now - 91000).toISOString() }, account: { verified: true }, page: { status: 'observed' }, observedPage: { observedAt: new Date(now - 1000).toISOString() } } };
  const stale = connectionClient.browserConnectionState(connection, now);
  assert.equal(stale.status, 'stale');
  assert.equal(stale.canTest, false);
  assert.equal(stale.pageObserved, false);
  assert.equal(stale.accountVerified, false);
  connection.browserEvidence.bridge.lastHeartbeatAt = new Date(now).toISOString();
  const observed = connectionClient.browserConnectionState(connection, now);
  assert.equal(observed.pageObserved, true);
  assert.equal(observed.accountVerified, false);
  connection.browserEvidence.page.status = 'stale';
  assert.equal(connectionClient.browserConnectionState(connection, now).pageObserved, false);
  connection.status = 'revoked';
  assert.equal(connectionClient.browserConnectionState(connection, now).canTest, false);
});

test('existing central browser sessions do not start a new local helper installation', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const flow = source.slice(source.indexOf('async function startConnection'), source.indexOf('function connectionSuccess'));
  const existing = { id: 'existing-tab', appId: 'notion', driver: 'browser', status: 'session_ready' };
  let managed = 0, requests = 0;
  const start = runInNewContext(`${flow}; startConnection`, {
    rows: kind => kind === 'connections' ? [existing] : [],
    existingBrowserDialog: (app, connections) => { managed++; assert.equal(connections[0].id, existing.id); },
    api: async () => { requests++; throw new Error('Must not create a new pairing.'); },
    el: () => ({ isConnected: true, replaceChildren() {} }), appIcon() {}, connectionProgress() {}, openDialog() {},
    dialog: { open: true, close() {} }, note() {}, actions() {}, button() {}
  });
  await start({ id: 'notion', name: 'Notion' });
  assert.equal(managed, 1);
  assert.equal(requests, 0);
});

test('an explicit OAuth choice is preserved when a paired browser route already exists', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const flow = source.slice(source.indexOf('async function startConnection'), source.indexOf('function connectionSuccess'));
  let managed = 0, requested;
  const start = runInNewContext(`${flow}; startConnection`, {
    rows: () => [{ id: 'browser', appId: 'gmail', driver: 'browser', status: 'session_ready' }],
    existingBrowserDialog: () => { managed++; },
    api: async (path, body) => { requested = { path, ...body }; return { kind: 'oauth', authorizationUrl: 'https://accounts.google.com/authorize' }; },
    el: () => ({ isConnected: true, replaceChildren() {} }), appIcon() {}, connectionProgress() {}, openDialog() {},
    dialog: { open: true, close() {} }, note() {}, actions() {}, button() {}, cancel() {}, URL
  });
  await start({ id: 'gmail', name: 'Gmail' }, 'oauth');
  assert.equal(managed, 0);
  assert.deepEqual(requested, { path: '/api/connect/start', appId: 'gmail', method: 'oauth' });
});

test('consumer flow uses real resolve, connect, exact pairing status, and observed target routes', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const browserFlow = source.slice(source.indexOf('async function browserConnectionDialog'), source.indexOf('function connectDialog'));
  assert.match(source, /api\('\/api\/resolve'/);
  assert.match(source, /api\('\/api\/connect\/start'/);
  assert.match(browserFlow, /requestBrowserBridge\('connect', \{ pairing \}/);
  assert.match(browserFlow, /pairing\.pairingId/);
  assert.doesNotMatch(browserFlow, /Get connection code|Copy connection code|Paste an access token|href: origin/);
  assert.match(source, /snapshotId, targetId: target\.targetId/);
  assert.match(source, /\/api\/icons\//);
});

async function setupHarness(overrides = {}) {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const flow = source.slice(source.indexOf('async function browserHelperSetup'), source.indexOf('function waitForBrowserPair'));
  class Element {
    constructor(tag, attrs = {}, ...children) { this.tag = tag; this.attrs = attrs; this.children = children.flat(Infinity).filter(value => value != null); this.isConnected = true; this.disabled = !!attrs.disabled; this.events = {}; }
    get textContent() { return this.children.map(item => typeof item === 'object' ? item.textContent : String(item)).join(' '); }
    set textContent(value) { this.children = [value]; }
    replaceChildren(...items) { this.children = items.flat(Infinity); }
    addEventListener(type, listener) { this.events[type] = listener; }
    click() { return this.action?.({ currentTarget: this }); }
  }
  const el = (tag, attrs, ...children) => new Element(tag, attrs, ...children);
  const makeButton = (label, action, type, attrs) => { const control = el('button', attrs, label); control.action = action; return control; };
  const content = el('div', {}), calls = [], starts = [], timers = new Map(), saved = new Map();
  let timerId = 0, reloads = 0;
  const settings = { platform: 'darwin', supported: true, extensionAvailable: true, directory: '/fixture/Fabric/extension', browsers: [{ id: 'chrome', name: 'Chrome', installed: true }, { id: 'edge', name: 'Edge', installed: false }] };
  const context = {
    isPersistentBrowser: connectionClient.isPersistentBrowser, isDurableBrowser: connectionClient.isDurableBrowser, browserCapabilityMatches: connectionClient.browserCapabilityMatches, browserOperationPresentation: connectionClient.browserOperationPresentation,
    el, button: makeButton, copyButton: label => makeButton(label),
    actions: (...controls) => el('div', {}, ...controls),
    field: (label, control) => el('label', {}, label, control),
    note: (message, tone) => el('div', { tone }, message),
    select: (items, placeholder, selected) => { const node = el('select', {}, ...items.map(([id, label]) => el('option', { value: id }, label))); node.value = selected; return node; },
    connectionProgress: (label, description) => el('div', {}, label, description),
    stopDialogWork: null, dialog: { open: true, close() { this.open = false; context.stopDialogWork?.(); } },
    api: async (path, body) => { calls.push({ path, body }); return body ? { opened: true } : settings; },
    requestBrowserBridge: async () => { throw new Error('No helper'); },
    startConnection: async (app, method) => { starts.push({ appId: app.id, method }); },
    navigator: { userAgent: 'Codex' },
    location: { origin: 'http://127.0.0.1:4188', pathname: '/', search: '', reload() { reloads++; } },
    history: { replaceState(_state, _title, url) { this.url = url; } },
    sessionStorage: { setItem(key, value) { saved.set(key, value); }, getItem: key => saved.get(key), removeItem: key => saved.delete(key) },
    selectedAppId: 'notion', appById: id => id === 'notion' ? { id, name: 'Notion' } : null,
    setTimeout: callback => { const id = ++timerId; timers.set(id, callback); return id; }, clearTimeout: id => timers.delete(id),
    ...overrides
  };
  const functions = runInNewContext(`${flow}; ({ setup: browserHelperSetup, resume: resumeBrowserSetup })`, context);
  const descendants = node => [node, ...node.children.filter(child => child instanceof Element).flatMap(descendants)];
  return { ...functions, content, context, calls, starts, settings, timers, saved, reloads: () => reloads, nodes: () => descendants(content), find: label => descendants(content).find(node => node.tag === 'button' && node.textContent === label) };
}

test('helper setup offers explicit installed-browser actions and Mac folder guidance, without native auto-open', async () => {
  const harness = await setupHarness();
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content);
  assert.equal(harness.calls.length, 1);
  assert.equal(harness.calls[0].path, '/api/browser-setup');
  assert.equal(harness.calls[0].body, undefined);
  assert.ok(harness.find('Open Fabric in Chrome'));
  assert.ok(harness.find('Open extension settings'));
  assert.ok(harness.find('Show helper folder'));
  assert.ok(harness.find('Reload and continue'));
  assert.equal(harness.find('Open Fabric in Edge'), undefined);
  assert.match(harness.content.textContent, /Command–Shift–G/);
  assert.match(harness.content.textContent, /No account is connected yet/);
  assert.ok(harness.nodes().some(node => node.attrs.role === 'status'));
  assert.equal(harness.starts.length, 0);
  harness.context.stopDialogWork();
  assert.equal(harness.timers.size, 0);
});

test('native setup dispatch is click-only, disables duplicate actions, and never confirms installation', async () => {
  const harness = await setupHarness();
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content);
  let finish;
  const requests = [];
  harness.context.api = (path, body) => { requests.push({ path, ...body }); return new Promise(resolve => { finish = resolve; }); };
  const open = harness.find('Open Fabric in Chrome');
  const first = open.click();
  assert.equal(open.disabled, true);
  assert.equal(harness.find('Show helper folder').disabled, true);
  await open.click();
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0], { path: '/api/browser-setup', action: 'open-fabric', browser: 'chrome', appId: 'notion' });
  finish({ opened: true }); await first;
  assert.equal(open.disabled, false);
  assert.match(harness.content.textContent, /Requested Fabric in Chrome.*cannot detect a helper installed in another browser/);
  assert.equal(harness.starts.length, 0);
  harness.context.stopDialogWork();
});

test('closing setup cancels polling and ignores an in-flight helper response', async () => {
  let resolvePing;
  const harness = await setupHarness({ requestBrowserBridge: () => new Promise(resolve => { resolvePing = resolve; }) });
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content);
  harness.context.dialog.close();
  resolvePing({ version: '0.2' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(harness.starts.length, 0);
  assert.equal(harness.timers.size, 0);
});

test('detected helper starts a fresh approval flow instead of claiming an account connection', async () => {
  const harness = await setupHarness({ requestBrowserBridge: async () => ({ version: '0.2' }) });
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(harness.starts, [{ appId: 'notion', method: 'browser' }]);
  assert.match(harness.content.textContent, /Preparing a new approval request.*No account is connected yet/);
  assert.equal(harness.timers.size, 0);
});

test('reload continuation stores only short-lived app identity and resumes only that known connector', async () => {
  const harness = await setupHarness();
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content);
  harness.find('Reload and continue').click();
  assert.equal(harness.reloads(), 1);
  assert.equal(harness.context.history.url, '/#connectors/notion');
  const pending = JSON.parse(harness.saved.get('fabric.browser-setup-resume'));
  assert.deepEqual(Object.keys(pending).sort(), ['appId', 'createdAt']);
  await harness.resume();
  assert.deepEqual(harness.starts, [{ appId: 'notion', method: 'browser' }]);
  assert.equal(harness.saved.size, 0);
  for (const invalid of [{ appId: 'notion', createdAt: Date.now() - 300001 }, { appId: 'unknown-app', createdAt: Date.now() }, { appId: 'notion', createdAt: Date.now() + 300000 }]) {
    harness.saved.set('fabric.browser-setup-resume', JSON.stringify(invalid));
    await harness.resume();
  }
  assert.equal(harness.starts.length, 1);
  assert.equal(harness.saved.size, 0);
});

test('native setup errors stay visible and re-enable controls without connecting', async () => {
  const harness = await setupHarness();
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content);
  harness.context.api = async () => { throw new Error('Chrome could not be opened.'); };
  const control = harness.find('Open extension settings');
  await control.click();
  assert.equal(control.disabled, false);
  assert.ok(harness.nodes().some(node => node.attrs.role === 'alert' && node.textContent === 'Chrome could not be opened.'));
  assert.equal(harness.starts.length, 0);
  harness.context.stopDialogWork();
});

test('browser selection routes each setup action only to the explicitly selected installed browser', async () => {
  const harness = await setupHarness();
  harness.settings.browsers.push({ id: 'edge', name: 'Edge', installed: true });
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content);
  const chooser = harness.nodes().find(node => node.tag === 'select');
  chooser.value = 'edge'; chooser.events.change();
  assert.ok(harness.find('Open Fabric in Edge'));
  await harness.find('Open extension settings').click();
  await harness.find('Show helper folder').click();
  const requests = harness.calls.filter(call => call.body).map(call => ({ ...call.body }));
  assert.deepEqual(requests, [
    { action: 'open-extensions', browser: 'edge', appId: 'notion' },
    { action: 'reveal-extension', browser: 'edge', appId: 'notion' }
  ]);
  assert.equal(harness.starts.length, 0);
  harness.context.stopDialogWork();
});

test('unsupported setup reports the runtime reason without native buttons or polling', async () => {
  const harness = await setupHarness();
  Object.assign(harness.settings, { supported: false, reason: 'This helper requires port 4188.' });
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content);
  assert.match(harness.content.textContent, /This helper requires port 4188/);
  assert.equal(harness.find('Open Fabric in Chrome'), undefined);
  assert.equal(harness.timers.size, 0);
  assert.equal(harness.calls.filter(call => call.body).length, 0);
});

test('an unconfirmed native dispatch result is an error, not a successful opening', async () => {
  const harness = await setupHarness();
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content);
  harness.context.api = async () => ({ opened: false });
  await harness.find('Show helper folder').click();
  assert.ok(harness.nodes().some(node => node.attrs.role === 'alert' && /could not confirm/.test(node.textContent)));
  assert.equal(harness.starts.length, 0);
  harness.context.stopDialogWork();
});

test('Test page access requires an explicit form submit and uses the existing read job engine', async () => {
  const harness = await setupHarness();
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const flow = source.slice(source.indexOf('function operationDialog'), source.indexOf('async function inspectForAction'));
  const connection = { id: 'paired-tab', appId: 'notion', driver: 'browser', browserEvidence: { bridge: { status: 'alive', lastHeartbeatAt: new Date().toISOString() } } };
  const capability = { id: 'notion.browser.observe.v1', appId: 'notion', driver: 'browser', action: { op: 'observe' }, effect: 'read', status: 'active', inputSchema: { type: 'object', properties: {} } };
  let submit, form, shownJob, notices = 0;
  const requests = [];
  const functions = runInNewContext(`${flow}; ({ test: testPageAccess })`, {
    ...harness.context, browserConnectionState: connectionClient.browserConnectionState,
    rows: () => [capability], appName: () => 'Notion', cancel: () => harness.context.button('Cancel'),
    submitForm: (value, work) => { form = value; submit = work; }, openDialog() {},
    api: async (path, body) => { requests.push({ path, ...JSON.parse(JSON.stringify(body)) }); return { id: 'read-job', status: 'awaiting_approval' }; },
    refresh: async () => {}, jobDialog: job => { shownJob = job; }, notify: () => { notices++; }
  });
  functions.test(connection);
  assert.equal(requests.length, 0);
  assert.match(form.textContent, /reads visible page text and controls/);
  assert.match(form.textContent, /does not verify which account is signed in/);
  await submit();
  assert.deepEqual(requests, [{ path: '/api/jobs', connectionId: 'paired-tab', capabilityId: capability.id, args: {} }]);
  assert.equal(shownJob.status, 'awaiting_approval');
  functions.test({ ...connection, browserEvidence: { bridge: { status: 'stale' } } });
  assert.equal(notices, 1);
  assert.equal(requests.length, 1);
});

test('browser lifecycle describes provider-controlled expiry and actual health scheduling', async () => {
  const harness = await setupHarness();
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const flow = source.slice(source.indexOf('function connectionLifetime'), source.indexOf('function existingBrowserDialog'));
  const render = runInNewContext(`${flow}; connectionLifetime`, { ...harness.context, date: value => value || 'Not yet' });
  assert.equal(render({ driver: 'browser' }), null);
  const view = render({ driver: 'browser', lifecycle: { kind: 'browser-tab', expiresAt: null, requirements: 'Keep the paired tab open.', renewal: 'Sign in on the provider website when required.', health: { enabled: true, nextRunAt: '2026-10-10T12:00:00Z', lastRunAt: '2026-10-10T11:59:00Z' } } });
  assert.match(view.textContent, /No fixed account expiry is known/);
  assert.match(view.textContent, /2026-10-10T12:00:00Z/);
  assert.match(view.textContent, /do not read page content or verify a browser account/);
  assert.match(source, /const lifetime = connectionLifetime\(selectedAccount\); if \(lifetime\) accountSection.append\(lifetime\)/);
});

test('browser catalog, pairing completion, and page results cannot imply a verified provider account', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const catalog = source.slice(source.indexOf('function renderCatalog'), source.indexOf('function appCategory'));
  assert.match(catalog, /isConnectedService\(connection\)/);
  assert.match(catalog, /'Browser sessions'/);
  assert.match(source, /browserPairingComplete\(app, progress.connectionId\)/);
  assert.doesNotMatch(source, /label = 'Browser connected'/);
  const results = source.slice(source.indexOf('function jobDialog'), source.indexOf('function renderActivity'));
  assert.match(results, /job.result.verification.kind === \(isPersistentBrowser\(connection\) \? 'persistent-browser-dom' : 'paired-browser-dom'\)/);
  assert.match(results, /This does not verify which account is signed in/);
});

async function browserDialogHarness(initialStatus) {
  const harness = await setupHarness();
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const flow = source.slice(source.indexOf('function connectionLifetime'), source.indexOf('function googleConsentDialog'));
  let connections = [];
  const requested = [], tested = [];
  const setStatus = status => { connections = [{ id: 'paired-tab', appId: 'notion', label: 'Notion app tab', driver: 'browser', status: 'session_ready', browserEvidence: { bridge: { status, lastHeartbeatAt: new Date().toISOString() }, page: { status: 'not_observed' } } }]; };
  setStatus(initialStatus);
  const context = { ...harness.context,
    dialog: { open: true, close() { this.open = false; context.stopDialogWork?.(); } },
    rows: kind => kind === 'connections' ? connections : [],
    browserConnectionState: connectionClient.browserConnectionState,
    browserEvidenceSummary: connection => harness.context.el('div', {}, connectionClient.browserConnectionState(connection).label),
    openDialog(_title, _description, content) { context.stopDialogWork?.(); context.stopDialogWork = null; harness.content.replaceChildren(content); },
    api: async (path, body) => { requested.push({ path, body }); return { connections: connections.map(({ label, ...status }) => status) }; },
    testPageAccess: connection => { tested.push(connection); }, notify() {}, queueMicrotask,
    date: value => value || 'Not yet', refresh: async () => {}, openConnector: async () => {}, renderConnector() {}
  };
  const functions = runInNewContext(`${flow}; ({ existing: existingBrowserDialog, paired: browserPairingComplete })`, context);
  const tick = async () => { const callbacks = [...harness.timers.values()]; harness.timers.clear(); for (const callback of callbacks) await callback(); await new Promise(resolve => setImmediate(resolve)); };
  return { ...harness, context, ...functions, setStatus, requested, tested, tick, connections: () => connections };
}

test('idle durable access stays testable without an app tab and becomes unavailable when its browser is stale', async () => {
  const harness = await browserDialogHarness('alive');
  const connection = harness.connections()[0];
  Object.assign(connection, { bridgeVersion: '0.3', sessionScope: 'browser-profile' });
  Object.assign(connection.browserEvidence.bridge, { scope: 'browser-profile', executionState: 'idle' });
  harness.existing({ id: 'notion', name: 'Notion' }, harness.connections());
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(harness.find('Test page access').disabled, false);
  assert.match(harness.content.textContent, /Saved app access/);
  assert.match(harness.content.textContent, /Ready on demand/);
  assert.equal(harness.find('Upgrade to on-demand access'), undefined);
  assert.equal(harness.tested.length, 0);
  connection.browserEvidence.bridge.status = 'stale';
  await harness.tick();
  assert.equal(harness.find('Test page access').disabled, true);
  assert.match(harness.content.textContent, /Browser needs attention/);
  harness.context.stopDialogWork();
});

test('legacy upgrade starts a new explicit pairing only after the upgrade click', async () => {
  const harness = await browserDialogHarness('alive');
  const starts = [];
  harness.context.startConnection = (...args) => starts.push(args);
  harness.existing({ id: 'notion', name: 'Notion' }, harness.connections());
  await new Promise(resolve => setImmediate(resolve));
  assert.match(harness.content.textContent, /Tab-only access stays unchanged/);
  assert.equal(starts.length, 0);
  await harness.find('Upgrade to on-demand access').click();
  assert.deepEqual(JSON.parse(JSON.stringify(starts)), [[{ id: 'notion', name: 'Notion' }, 'browser', { forceNew: true, helperOnly: true }]]);
  assert.equal(harness.connections()[0].sessionScope, undefined);
  harness.context.stopDialogWork();
});

test('durable helper update waits for version 0.3 before starting a fresh approval', async () => {
  const harness = await setupHarness({ requestBrowserBridge: async () => ({ version: '0.2' }) });
  await harness.setup({ id: 'notion', name: 'Notion' }, harness.content, { requiredVersion: '0.3', updateRequired: true });
  await new Promise(resolve => setImmediate(resolve));
  assert.match(harness.content.textContent, /Update the browser helper/);
  assert.match(harness.content.textContent, /Existing tab-only permissions remain unchanged/);
  assert.equal(harness.starts.length, 0);
  harness.context.requestBrowserBridge = async () => ({ version: '0.3' });
  for (const callback of [...harness.timers.values()]) await callback();
  assert.deepEqual(harness.starts, [{ appId: 'notion', method: 'browser' }]);
  harness.context.stopDialogWork?.();
});

for (const mode of ['existing', 'paired']) {
  test(`${mode} browser dialog updates waiting to alive without closing or rebuilding its action control`, async () => {
    const harness = await browserDialogHarness('waiting');
    if (mode === 'existing') harness.existing({ id: 'notion', name: 'Notion' }, harness.connections());
    else harness.content.replaceChildren(harness.paired({ id: 'notion', name: 'Notion' }, 'paired-tab'));
    await new Promise(resolve => setImmediate(resolve));
    const button = harness.find('Test page access');
    assert.equal(button.disabled, true);
    harness.setStatus('alive'); await harness.tick();
    assert.equal(harness.find('Test page access'), button);
    assert.equal(button.disabled, false);
    assert.match(harness.content.textContent, /Browser helper available/);
    assert.match(harness.content.textContent, /Notion app tab/);
    assert.equal(harness.tested.length, 0);
    harness.context.stopDialogWork?.();
  });

  test(`${mode} browser dialog updates alive to stale and disables its action without closing`, async () => {
    const harness = await browserDialogHarness('alive');
    if (mode === 'existing') harness.existing({ id: 'notion', name: 'Notion' }, harness.connections());
    else harness.content.replaceChildren(harness.paired({ id: 'notion', name: 'Notion' }, 'paired-tab'));
    await new Promise(resolve => setImmediate(resolve));
    const button = harness.find('Test page access');
    assert.equal(button.disabled, false);
    harness.setStatus('stale'); await harness.tick();
    assert.equal(harness.find('Test page access'), button);
    assert.equal(button.disabled, true);
    assert.match(harness.content.textContent, /Paired tab needs attention/);
    assert.equal(harness.tested.length, 0);
    harness.context.stopDialogWork?.();
  });
}

test('browser dialog rechecks the current connection ID on click before opening a read form', async () => {
  const harness = await browserDialogHarness('alive');
  harness.existing({ id: 'notion', name: 'Notion' }, harness.connections());
  await new Promise(resolve => setImmediate(resolve));
  harness.setStatus('stale');
  await harness.find('Test page access').click();
  assert.equal(harness.tested.length, 0);
  assert.equal(harness.find('Test page access').disabled, true);
  assert.match(harness.content.textContent, /Paired tab needs attention/);
  harness.setStatus('alive'); await harness.tick();
  const current = harness.connections()[0];
  await harness.find('Test page access').click();
  assert.equal(harness.tested[0].id, current.id);
  assert.equal(harness.tested[0].browserEvidence, current.browserEvidence);
  assert.equal(harness.tested[0].label, 'Notion app tab');
  assert.ok(harness.requested.every(request => request.path === '/api/status' && request.body === undefined));
  harness.context.stopDialogWork();
});

test('failed browser-dialog status refresh cannot re-enable a previously live action', async () => {
  const harness = await browserDialogHarness('alive');
  harness.existing({ id: 'notion', name: 'Notion' }, harness.connections());
  await new Promise(resolve => setImmediate(resolve));
  harness.context.api = async () => { throw new Error('Runtime unavailable'); };
  await harness.find('Test page access').click();
  assert.equal(harness.find('Test page access').disabled, true);
  assert.match(harness.content.textContent, /could not be refreshed/);
  assert.equal(harness.tested.length, 0);
  harness.context.stopDialogWork();
});

test('browser-dialog close cancels timers and ignores an in-flight result', async () => {
  const harness = await browserDialogHarness('waiting');
  let complete;
  harness.context.api = () => new Promise(resolve => { complete = resolve; });
  harness.existing({ id: 'notion', name: 'Notion' }, harness.connections());
  const original = harness.content.textContent;
  harness.context.dialog.close();
  harness.setStatus('alive'); complete({ connections: harness.connections() });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(harness.content.textContent, original);
  assert.equal(harness.timers.size, 0);
  assert.equal(harness.tested.length, 0);
});

test('replacing a browser dialog stops its watcher without touching unrelated form contents', async () => {
  const harness = await browserDialogHarness('waiting');
  harness.existing({ id: 'notion', name: 'Notion' }, harness.connections());
  await new Promise(resolve => setImmediate(resolve));
  const unrelated = harness.context.el('form', {}, harness.context.el('input', { value: 'Keep this draft' }));
  harness.context.openDialog('Other form', '', unrelated);
  harness.setStatus('alive'); await harness.tick();
  assert.equal(harness.content.children[0], unrelated);
  assert.equal(unrelated.children[0].attrs.value, 'Keep this draft');
  assert.equal(harness.timers.size, 0);
  assert.equal(harness.tested.length, 0);
});

test('F10.7: the developer settings dialog shows the Google tab only for Google\'s apps, asks for full access, and never posts another app to Google', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const flow = source.slice(source.indexOf('function connectDialog'), source.indexOf('function simpleApplicationDialog'));
  const methods = source.slice(source.indexOf('function methodsFor'), source.indexOf('\n}\n', source.indexOf('function methodsFor')) + 3);
  const open = async app => {
    class Node { constructor(tag, attrs = {}, ...children) { this.tag = tag; this.attrs = attrs; this.children = children.flat(Infinity).filter(value => value !== null && value !== undefined && value !== false); }
      get textContent() { return this.children.map(child => child instanceof Node ? child.textContent : String(child)).join(' '); }
      append(...children) { this.children.push(...children.flat(Infinity).filter(value => value !== null && value !== undefined && value !== false)); }
      replaceChildren(...children) { this.children = []; this.append(...children); }
      querySelectorAll() { return []; } }
    const el = (tag, attrs, ...children) => new Node(tag, attrs, ...children), calls = [], assigned = [], forms = [];
    let content;
    const context = {el, URL, calls, note: text => el('p', {}, text), actions: (...nodes) => el('div', {}, nodes), cancel: () => el('button', {}, 'Cancel'), field: (label, control) => el('label', {}, label, control),
      button: (label, action, kind, attrs = {}) => Object.assign(el('button', attrs, label), {action}), submitForm: (form, work) => forms.push({form, work}), openDialog: (title, description, node) => { content = node; },
      state: {settings: {googleOAuthConfigured: true}}, location: {origin: 'http://127.0.0.1:4188', assign: href => assigned.push(href)}, importDialog: () => {},
      api: async (path, body) => { calls.push({path, body}); return {authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth?x=1'}; }};
    runInNewContext(`${methods}\n${flow}; connectDialog`, context)(app);
    const tabs = content.children.find(node => node.attrs?.class === 'method-tabs').children.map(button => button.textContent);
    return {tabs, forms, calls, assigned, content};
  };
  const github = await open({id: 'github', name: 'GitHub', authMethods: ['token', 'oauth', 'browser']});
  assert.deepEqual([...github.tabs], ['Access token', 'Browser session'], 'GitHub\'s sign-in is under Connect, never a Google tab');
  assert.equal(github.calls.some(call => call.path === '/api/oauth/google/start'), false);
  const gmail = await open({id: 'gmail', name: 'Gmail', authMethods: ['oauth', 'browser']});
  assert.deepEqual([...gmail.tabs], ['Provider consent', 'Browser session']);
  const [{form, work}] = gmail.forms;
  assert.doesNotMatch(form.textContent, /Read-only access is the default|Also request write access/);
  assert.match(form.textContent, /full access/);
  await work();
  // Objects made inside a vm context have that context's prototypes; compared by value.
  assert.deepEqual(JSON.parse(JSON.stringify([gmail.calls, gmail.assigned])), [[{path: '/api/oauth/google/start', body: {appId: 'gmail', level: 'full'}}], ['https://accounts.google.com/o/oauth2/v2/auth?x=1']]);
});

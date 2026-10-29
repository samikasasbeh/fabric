import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { browserCapabilityMatches, browserConnectionState, connectionKind, isConnectedService, isPersistentBrowser, isDurableBrowser, browserOperationPresentation } from '../public/connect-client.js';

const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
const app = { id: 'notion', name: 'Notion', webOrigins: ['https://www.notion.so'] };
const session = (state = 'available') => ({ id: 'saved-session', appId: app.id, driver: 'browser', transport: 'persistent', persistentSession: true, status: 'session_ready', lifecycle: { kind: 'persistent-browser', sessionState: state, retention: 'until-disconnected' }, browserEvidence: { bridge: { status: state === 'available' ? 'alive' : state === 'revoked' || state === 'unavailable' ? state : 'waiting', lastHeartbeatAt: null }, account: { verified: false }, page: { status: 'not_observed' } } });
const durable = (status = 'alive', executionState = 'idle') => ({ id: 'saved-app', appId: app.id, driver: 'browser', transport: 'helper', bridgeVersion: '0.3', sessionScope: 'browser-profile', status: 'session_ready', browserEvidence: { bridge: { status, scope: 'browser-profile', executionState, origin: app.webOrigins[0], lastHeartbeatAt: new Date().toISOString() }, account: { verified: false }, page: { status: 'not_observed' } } });

function harness() {
  class Element {
    constructor(tag, attrs = {}, ...children) { this.tag = tag; this.attrs = attrs; this.children = children.flat(Infinity).filter(value => value != null && value !== false); this.isConnected = true; this.disabled = !!attrs.disabled; }
    get textContent() { return this.children.map(value => typeof value === 'object' ? value.textContent : String(value)).join(' '); }
    set textContent(value) { this.children = [value]; }
    // Native replaceChildren converts non-Nodes (including null) to text.
    replaceChildren(...children) { this.children = children.map(value => value instanceof Element ? value : String(value)); }
    append(...children) { this.children.push(...children.flat(Infinity).filter(value => value != null && value !== false)); }
    click() { return this.action?.({ currentTarget: this }); }
  }
  const el = (tag, attrs, ...children) => new Element(tag, attrs, ...children);
  const button = (label, action, _style, attrs) => { const node = el('button', attrs, label); node.action = action; return node; };
  const root = el('div'), calls = [], starts = [], completed = [], notices = [];
  const context = { el, button, isPersistentBrowser, isDurableBrowser, browserCapabilityMatches, browserConnectionState, browserOperationPresentation,
    actions: (...nodes) => el('div', {}, nodes), cancel: () => button('Cancel', () => context.dialog.close()),
    note: (message, tone) => el('p', { tone }, message), appIcon: () => el('i'), connectionProgress: (title, description) => el('p', {}, title, description),
    dialog: { open: true, close() { this.open = false; } },
    openDialog: (_title, _description, content) => root.replaceChildren(content),
    api: async (path, body) => { calls.push({ path, body }); return body ? { connection: session() } : { available: true }; },
    refresh: async () => {}, loadConnector: async () => {}, notify: message => notices.push(message),
    browserPairingComplete: (_app, id, connection) => { completed.push(connection); return el('p', {}, 'Saved browser session', id); },
    startConnection: (...args) => starts.push(args)
  };
  const flow = source.slice(source.indexOf('async function savedBrowserConsentDialog'), source.indexOf('async function startConnection'));
  const functions = runInNewContext(`${flow}; ({ consent: savedBrowserConsentDialog, reopen: openSavedBrowser })`, context);
  const descendants = node => [node, ...node.children.filter(child => child instanceof Element).flatMap(descendants)];
  return { ...functions, context, root, calls, starts, completed, notices, find: label => descendants(root).find(node => node.tag === 'button' && node.textContent === label) };
}

test('saved browser labels never claim a connected or verified account', () => {
  assert.equal(connectionKind(session()), 'Saved browser session');
  assert.equal(isConnectedService(session()), false);
  assert.equal(browserConnectionState(session()).accountVerified, false);
  assert.equal(browserConnectionState(session()).canTest, true);
  for (const state of ['dormant', 'needs_sign_in']) assert.equal(browserConnectionState(session(state)).canTest, true);
  for (const state of ['opening', 'revoked', 'unavailable']) assert.equal(browserConnectionState(session(state)).canTest, false);
  assert.match(browserConnectionState(session('dormant')).label, /reopens when needed/);
  assert.equal(isPersistentBrowser({ driver: 'browser', lifecycle: { kind: 'persistent-browser' } }), true);
  assert.equal(isPersistentBrowser({ driver: 'browser' }), false);
});

test('durable helper access is ready on demand while idle without claiming an account or live page', () => {
  const connection = durable();
  connection.browserEvidence.page.status = 'observed';
  connection.browserEvidence.observedPage = { observedAt: new Date().toISOString() };
  assert.equal(connectionKind(connection), 'Saved app access');
  const state = browserConnectionState(connection);
  assert.equal(state.label, 'Ready on demand');
  assert.equal(state.canTest, true);
  assert.equal(state.accountVerified, false);
  assert.equal(state.pageObserved, false);
  assert.equal(isConnectedService(connection), false);
  connection.browserEvidence.bridge.executionState = 'open';
  assert.equal(browserConnectionState(connection).pageObserved, true);
});

test('durable helper still needs a fresh browser heartbeat and never upgrades legacy authority implicitly', () => {
  const connection = durable();
  connection.browserEvidence.bridge.lastHeartbeatAt = new Date(Date.now() - 91000).toISOString();
  assert.equal(browserConnectionState(connection).label, 'Browser needs attention');
  assert.equal(browserConnectionState(connection).canTest, false);
  assert.equal(browserConnectionState(durable('waiting')).label, 'Waiting for browser helper');
  assert.equal(browserConnectionState(durable('revoked')).label, 'Saved app access removed');
  const legacy = { ...durable(), sessionScope: undefined, browserEvidence: { bridge: { status: 'alive', lastHeartbeatAt: new Date().toISOString() } } };
  assert.equal(connectionKind(legacy), 'Browser session');
  assert.equal(browserConnectionState(legacy).label, 'Browser helper available');
  legacy.browserEvidence.bridge.status = 'stale';
  assert.equal(browserConnectionState(legacy).label, 'Paired tab needs attention');
});

test('durable read labels are contextual without changing stored tool definitions or permissions', () => {
  const capability = Object.freeze({ id: 'notion.browser.observe.v1', appId: 'notion', driver: 'browser', effect: 'read', name: 'Inspect paired page', description: 'Read-only access to the explicitly paired tab.', action: { op: 'observe' } });
  const policy = Object.freeze({ capabilityId: capability.id, name: capability.name, mode: 'ask' });
  const flow = source.slice(source.indexOf('function connectorOperations'), source.indexOf('function permissionGroup'));
  const operations = runInNewContext(`${flow}; connectorOperations`, { rows: () => [capability], selectedAppId: 'notion', browserCapabilityMatches, isDurableBrowser, browserOperationPresentation });
  const data = { connections: [durable()], permissionsByConnection: { 'saved-app': [policy] } };
  const shown = operations(data, 'saved-app')[0];
  assert.equal(shown.name, 'Inspect app page');
  assert.match(shown.description, /approved read.*temporary tab/);
  assert.equal(shown.capabilityId, capability.id);
  assert.equal(shown.mode, 'ask');
  assert.equal(capability.name, 'Inspect paired page');
  assert.equal(policy.name, 'Inspect paired page');
  const legacy = { id: 'old-tab', appId: 'notion', driver: 'browser', bridgeVersion: '0.2' };
  assert.equal(operations({ connections: [legacy] }, legacy.id)[0].name, 'Inspect paired page');
});

test('durable consent describes retained access and sends no connection grant before Continue', async () => {
  const h = harness(), bridgeCalls = [], waited = [];
  const flow = source.slice(source.indexOf('async function browserConnectionDialog'), source.indexOf('async function browserHelperSetup'));
  const connect = runInNewContext(`${flow}; browserConnectionDialog`, { ...h.context,
    requestBrowserBridge: async (type, payload) => { bridgeCalls.push({ type, payload }); return type === 'ping' ? { version: '0.3' } : { confirmationOpened: true, pairingId: 'pair' }; },
    browserHelperSetup: () => { throw new Error('Current helper must not require reinstall'); },
    waitForBrowserPair: (_app, pairing) => waited.push(pairing.pairingId)
  });
  const pairing = { pairingId: 'pair', bridgeVersion: '0.3', sessionScope: 'browser-profile' };
  await connect(app, { pairing, origin: app.webOrigins[0] }, h.root);
  assert.deepEqual(bridgeCalls.map(call => call.type), ['ping']);
  assert.match(h.root.textContent, /until Disconnect/);
  assert.match(h.root.textContent, /No app tab needs to stay open/);
  assert.match(h.root.textContent, /Each approved read can open a temporary tab/);
  assert.match(h.root.textContent, /Sign in separately/);
  assert.match(h.root.textContent, /does not export passwords or sign-in tokens/);
  assert.doesNotMatch(h.root.textContent, /\bnull\b/);
  assert.equal(h.calls.length, 0);
  await h.find('Continue in browser').click();
  assert.deepEqual(bridgeCalls.map(call => call.type), ['ping', 'connect']);
  assert.equal(bridgeCalls[1].payload.pairing, pairing);
  assert.deepEqual(waited, ['pair']);
});

test('new durable approval requires helper 0.3 while a newer helper preserves old tab-only consent', async () => {
  const flow = source.slice(source.indexOf('async function browserConnectionDialog'), source.indexOf('async function browserHelperSetup'));
  for (const [helperVersion, pairingVersion] of [['0.2', '0.3'], ['0.3', '0.2']]) {
    const h = harness(), setup = [];
    const connect = runInNewContext(`${flow}; browserConnectionDialog`, { ...h.context,
      requestBrowserBridge: async type => { assert.equal(type, 'ping'); return { version: helperVersion }; },
      browserHelperSetup: (_app, _content, options) => setup.push(options)
    });
    await connect(app, { pairing: { bridgeVersion: pairingVersion, ...(pairingVersion === '0.3' ? { sessionScope: 'browser-profile' } : {}) } }, h.root);
    if (pairingVersion === '0.3') {
      assert.deepEqual(JSON.parse(JSON.stringify(setup)), [{ requiredVersion: '0.3', updateRequired: true }]);
      assert.equal(h.find('Continue in browser'), undefined);
    } else {
      assert.equal(setup.length, 0);
      assert.match(h.root.textContent, /inspect this tab/);
      assert.doesNotMatch(h.root.textContent, /until Disconnect|temporary tab|\bnull\b/);
    }
  }
});

test('durable lifecycle explains shared profile sign-in and no required app tab without changing legacy guidance', () => {
  const h = harness();
  const flow = source.slice(source.indexOf('function browserEvidenceSummary'), source.indexOf('function browserDialogEntry'));
  const render = runInNewContext(`${flow}; ({ summary: browserEvidenceSummary, lifetime: connectionLifetime })`, { ...h.context, date: value => value, humanize: value => value });
  const ready = render.summary(durable());
  assert.match(ready.textContent, /Ready on demand/);
  assert.match(ready.textContent, /No app tab needs to stay open/);
  assert.match(ready.textContent, /Account identity: not verified/);
  assert.match(render.summary(durable('stale')).textContent, /Open Chrome or Edge/);
  const life = render.lifetime({ ...durable(), lifecycle: { requirements: 'old tab-only text', health: { enabled: false } } });
  assert.match(life.textContent, /until Disconnect/);
  assert.match(life.textContent, /not your website sign-in/);
  assert.doesNotMatch(life.textContent, /old tab-only text|Keep the paired tab/);
  assert.match(render.summary({ driver: 'browser' }).textContent, /Keep the paired app tab open/);
  const askOnly = source.match(/const askOnly = ([^;]+);/)[1];
  assert.equal(runInNewContext(askOnly, { browserWrite: false, isPersistentBrowser, isDurableBrowser, connection: durable() }), true);
  assert.equal(runInNewContext(askOnly, { browserWrite: false, isPersistentBrowser, isDurableBrowser, connection: { driver: 'browser' } }), false);
});

test('saved sessions use owned-browser availability, not an extension heartbeat', () => {
  const available = session();
  assert.equal(browserConnectionState(available).status, 'alive');
  assert.equal(browserConnectionState(available).canTest, true);
  assert.equal(browserConnectionState(available).lastHeartbeatAt, null);
  const dormant = session('dormant');
  dormant.browserEvidence.observedPage = { observedAt: new Date().toISOString() };
  dormant.browserEvidence.page.status = 'observed';
  assert.equal(browserConnectionState(dormant).canTest, true);
  assert.equal(browserConnectionState(dormant).pageObserved, false);
  assert.equal(browserConnectionState({ ...available, transport: undefined, persistentSession: false, lifecycle: undefined }).canTest, false);
});

test('saved-session operations exclude helper writes and other connection transports', () => {
  const capability = { id: 'notion.session.observe.v1', appId: 'notion', driver: 'browser', transport: 'persistent', effect: 'read', action: { op: 'observe', transport: 'persistent' } };
  assert.equal(browserCapabilityMatches(capability, session()), true);
  assert.equal(browserCapabilityMatches({ ...capability, effect: 'write' }, session()), false);
  assert.equal(browserCapabilityMatches({ ...capability, appId: 'slack' }, session()), false);
  assert.equal(browserCapabilityMatches(capability, { driver: 'browser', appId: 'notion' }), false);
  assert.equal(browserCapabilityMatches({ ...capability, transport: undefined, id: 'notion.browser.observe.v1', action: { op: 'observe' } }, session()), false);
});

test('browser capability route matching uses explicit transport, not ID or action hints', () => {
  const cap = { id: 'notion.session.observe.v1', appId: 'notion', driver: 'browser', effect: 'read', action: { op: 'observe', transport: 'persistent' } };
  const helper = { ...session(), transport: undefined, persistentSession: false, lifecycle: undefined };
  assert.equal(browserCapabilityMatches(cap, session()), false);
  assert.equal(browserCapabilityMatches(cap, helper), true);
  assert.equal(browserCapabilityMatches({ ...cap, transport: 'helper' }, session()), false);
  assert.equal(browserCapabilityMatches({ ...cap, id: 'arbitrary-name', action: { op: 'observe' }, transport: 'persistent' }, session()), true);
  assert.equal(browserCapabilityMatches({ ...cap, transport: 'unsupported' }, { ...session(), transport: 'unsupported' }), false);
  assert.equal(browserCapabilityMatches({ ...cap, transport: 'persistent' }, { ...session(), transport: undefined }), false);
});

test('opening saved-session consent only checks availability; grant requires the Connect click', async () => {
  const h = harness(); await h.consent(app);
  assert.deepEqual(h.calls, [{ path: '/api/session-browser', body: undefined }]);
  assert.match(h.root.textContent, /until you Disconnect/);
  assert.match(h.root.textContent, /read-only/);
  assert.match(h.root.textContent, /Ask for each request/);
  assert.match(h.root.textContent, /No extension or developer account/);
  assert.doesNotMatch(h.root.textContent, /\bnull\b/);
  assert.equal(h.completed.length, 0);
  await h.find('Connect with Fabric browser').click();
  assert.deepEqual(JSON.parse(JSON.stringify(h.calls[1])), { path: '/api/session-browser/connect', body: { appId: 'notion', consent: true } });
  assert.equal(h.completed.length, 1);
  assert.equal(h.calls.some(call => call.path === '/api/jobs'), false);
});

test('saved-session Connect disables duplicate requests and exposes failures', async () => {
  const h = harness(); await h.consent(app);
  let fail, posted = 0;
  h.context.api = () => { posted++; return new Promise((_resolve, reject) => { fail = reject; }); };
  const button = h.find('Connect with Fabric browser');
  const pending = button.click();
  assert.equal(button.disabled, true); await button.click(); assert.equal(posted, 1);
  fail(new Error('Browser launch failed')); await pending;
  assert.equal(button.disabled, false);
  assert.match(h.root.textContent, /Browser launch failed/);
  assert.equal(h.completed.length, 0);
});

test('unavailable Fabric browser has no Connect action and never silently installs a helper', async () => {
  const h = harness(); h.context.api = async () => ({ available: false, error: 'Browser executable missing' });
  await h.consent(app);
  assert.equal(h.find('Connect with Fabric browser'), undefined);
  assert.match(h.root.textContent, /Browser executable missing.*No session has been created/);
  assert.equal(h.starts.length, 0);
  await h.find('Use the existing browser helper').click();
  assert.deepEqual(JSON.parse(JSON.stringify(h.starts[0])), [app, 'browser', { forceNew: true, helperOnly: true }]);
});

test('saved-session grant rejects a mismatched result rather than rendering success', async () => {
  const h = harness(); await h.consent(app);
  h.context.api = async () => ({ connection: { ...session(), appId: 'slack' } });
  await h.find('Connect with Fabric browser').click();
  assert.match(h.root.textContent, /did not confirm/);
  assert.equal(h.completed.length, 0);
});

test('reopen dispatches only for the chosen saved session and does not read a page', async () => {
  const h = harness(); const control = h.context.button('Open sign-in window');
  await h.reopen(session('dormant'), control);
  assert.deepEqual(JSON.parse(JSON.stringify(h.calls)), [{ path: '/api/session-browser/saved-session/open', body: {} }]);
  assert.equal(control.disabled, false);
  assert.match(h.notices[0], /No page content has been read/);
  await h.reopen({ ...session(), status: 'revoked' }, control);
  assert.equal(h.calls.length, 1);
});

test('web apps default to the normal-browser helper; separate read-only browser and OAuth remain explicit', async () => {
  const h = harness(); const routes = [];
  const flow = source.slice(source.indexOf('async function startConnection'), source.indexOf('function connectionSuccess'));
  const start = runInNewContext(`${flow}; startConnection`, { ...h.context, rows: () => [],
    savedBrowserConsentDialog: () => routes.push('saved-consent'),
    api: async (_path, body) => { routes.push(body.method); return { kind: 'unsupported', message: 'Fixture limitation' }; }
  });
  await start(app); assert.deepEqual(routes, ['browser']);
  await start(app, 'browser', { helperOnly: true });
  await start(app, 'browser', { forceNew: true, savedBrowser: true });
  await start(app, 'oauth');
  assert.deepEqual(routes, ['browser', 'browser', 'saved-consent', 'oauth']);
});

test('default normal-browser route never diverts Google or other web apps to saved profiles or OAuth', async () => {
  for (const appId of ['gmail', 'google-calendar', 'notion', 'slack']) {
    const h = harness(), calls = [];
    const target = { ...app, id: appId };
    const saved = { ...session(), appId };
    const helper = { ...saved, id: 'helper', transport: 'helper', persistentSession: false, lifecycle: undefined };
    let existing = [saved];
    const flow = source.slice(source.indexOf('async function startConnection'), source.indexOf('function connectionSuccess'));
    const start = runInNewContext(`${flow}; startConnection`, { ...h.context, rows: () => existing,
      existingBrowserDialog: (_app, connections) => calls.push(connections.map(connection => connection.id)),
      savedBrowserConsentDialog: () => assert.fail('Default must not launch a separate automated browser'),
      api: async (path, body) => { calls.push([path, body.method]); return { kind: 'unsupported', message: 'Fixture limitation' }; }
    });
    await start(target);
    assert.deepEqual(JSON.parse(JSON.stringify(calls)), [['/api/connect/start', 'browser']]);
    existing = [saved, helper]; calls.length = 0;
    await start(target);
    assert.deepEqual(JSON.parse(JSON.stringify(calls)), [['helper']]);
    assert.equal(saved.status, 'session_ready');
  }
});

test('persistent Test page access chooses its own read capability and prepares an approval job only on submit', async () => {
  const h = harness(); const calls = [];
  const capabilities = ['browser', 'session'].map(transport => ({ id: `notion.${transport}.observe.v1`, appId: 'notion', driver: 'browser', ...(transport === 'session' ? { transport: 'persistent' } : {}), effect: 'read', status: 'active', action: { op: 'observe', ...(transport === 'session' ? { transport: 'persistent' } : {}) }, inputSchema: { properties: {} } }));
  let submit, form;
  const flow = source.slice(source.indexOf('function operationDialog'), source.indexOf('async function inspectForAction'));
  const run = runInNewContext(`${flow}; testPageAccess`, { ...h.context, rows: () => capabilities, appName: () => 'Notion',
    submitForm: (node, work) => { form = node; submit = work; },
    api: async (path, body) => { calls.push({ path, body }); return { status: 'awaiting_approval' }; },
    jobDialog: job => assert.equal(job.status, 'awaiting_approval')
  });
  run(session()); assert.equal(calls.length, 0);
  assert.match(form.textContent, /saved browser session/);
  assert.match(form.textContent, /Approval is required for this request/);
  await submit();
  assert.equal(calls[0].body.capabilityId, 'notion.session.observe.v1');
  assert.equal(calls[0].path, '/api/jobs');
});

test('saved-session disconnect explains local deletion and submits only on confirmation', async () => {
  const h = harness(); let submit;
  const flow = source.slice(source.indexOf('function revokeDialog'), source.indexOf('function appSelect'));
  const revoke = runInNewContext(`${flow}; revokeDialog`, { ...h.context, appName: () => 'Notion', submitForm: (_form, work) => { submit = work; } });
  revoke(session());
  assert.match(h.root.textContent, /removes its locally saved sign-in data/);
  assert.match(h.root.textContent, /does not guarantee provider logout/);
  assert.equal(h.calls.length, 0);
  await submit();
  assert.equal(h.calls[0].path, '/api/connections/saved-session/revoke');
});

test('saved-session page results cannot expose legacy helper write controls', () => {
  const h = harness();
  const flow = source.slice(source.indexOf('function observedControls'), source.indexOf('function permissionReview'));
  const functions = runInNewContext(`${flow}; ({ observedControls, browserTargetDialog })`, { ...h.context, rows: () => [session()] });
  assert.equal(functions.observedControls({ connectionId: session().id, status: 'succeeded', result: { data: { snapshotId: 'snapshot', controls: [{ targetId: 'target', canClick: true }] } } }), null);
  functions.browserTargetDialog(session(), 'snapshot', { targetId: 'target' }, 'click');
  assert.match(h.notices[0], /read-only/);
  assert.equal(h.calls.length, 0);
});

test('job dialog recognizes saved-session page evidence without claiming account verification', () => {
  const h = harness(); const titles = [];
  const flow = source.slice(source.indexOf('function jobDialog'), source.indexOf('function renderActivity'));
  const show = runInNewContext(`${flow}; jobDialog`, { ...h.context, rows: () => [session()],
    statusBadge: value => h.context.el('span', {}, value), verificationBadge: () => null,
    nameOf: (_kind, id) => id, date: value => value, jsonBlock: value => h.context.el('pre', {}, JSON.stringify(value)),
    observedControls: () => null, openDialog: (title, _description, content) => { titles.push(title); h.root.replaceChildren(content); }
  });
  const job = { id: 'read', connectionId: session().id, capabilityId: 'notion.session.observe.v1', status: 'succeeded', effect: 'read', createdAt: new Date().toISOString(), result: { verification: { status: 'observed', kind: 'persistent-browser-dom' } } };
  show(job);
  assert.equal(titles[0], 'Page access observed');
  assert.match(h.root.textContent, /Saved browser session/);
  assert.match(h.root.textContent, /does not verify which account is signed in/);
  show({ ...job, result: { verification: { status: 'observed', kind: 'paired-browser-dom' } } });
  assert.equal(titles[1], 'Action details');
  assert.doesNotMatch(h.root.textContent, /Page access observed/);
});

test('client browser proposal displays the trusted target and waits for the exact approval', async () => {
  const h = harness(); let submit;
  const connection = { ...session(), transport: 'helper', persistentSession: false, lifecycle: undefined };
  const flow = source.slice(source.indexOf('function jobDialog'), source.indexOf('function renderActivity'));
  const show = runInNewContext(`${flow}; jobDialog`, { ...h.context, rows: () => [connection],
    statusBadge: value => h.context.el('span', {}, value), verificationBadge: () => null,
    nameOf: (_kind, id) => id, date: value => value, text: value => String(value ?? ''), jsonBlock: () => h.context.el('pre'),
    observedControls: () => null, submitForm: (_form, work) => { submit = work; }
  });
  const proposal = { id: 'proposal', source: { kind: 'client', clientId: 'client' }, connectionId: connection.id, capabilityId: 'notion.browser.fill.v2', effect: 'write', status: 'awaiting_approval', approvalDigest: 'exact-digest', args: { snapshotId: 'snapshot', targetId: 'control', value: 'Review notes' }, preview: { browserTarget: { origin: 'https://www.notion.so', url: 'https://www.notion.so/fixture', title: 'My page', label: 'Search notes', role: 'textbox', operation: 'fill', snapshotExpiresAt: '2026-10-10T12:00:00.000Z' } } };
  show(proposal);
  assert.match(h.root.textContent, /AI client/);
  assert.match(h.root.textContent, /has not run/);
  assert.match(h.root.textContent, /https:\/\/www.notion.so\/fixture/);
  assert.match(h.root.textContent, /Search notes/);
  assert.match(h.root.textContent, /Review notes/);
  assert.equal(h.calls.length, 0);
  h.context.api = async (path, body) => { h.calls.push({ path, body }); return { ...proposal, status: 'cancelled' }; };
  await submit();
  assert.deepEqual(JSON.parse(JSON.stringify(h.calls)), [{ path: '/api/jobs/proposal/approve', body: { approvalDigest: 'exact-digest' } }]);
});

test('browser write approvals collapse technical request details without changing other approvals', () => {
  for (const [driver, effect] of [['browser', 'write'], ['browser', 'read'], ['http', 'write']]) {
    const h = harness();
    const connection = { id: 'connection', appId: 'notion', driver, transport: 'helper' };
    const flow = source.slice(source.indexOf('function jobDialog'), source.indexOf('function renderActivity'));
    const show = runInNewContext(`${flow}; jobDialog`, { ...h.context, rows: () => [connection],
      statusBadge: value => h.context.el('span', {}, value), verificationBadge: () => null,
      nameOf: (_kind, id) => id, date: value => value, text: value => String(value ?? ''),
      jsonBlock: () => h.context.el('pre', {}, 'technical request marker'),
      observedControls: () => null, submitForm: () => {}
    });
    show({ id: 'proposal', connectionId: connection.id, effect, status: 'awaiting_approval',
      args: { value: 'Review notes' }, preview: { browserTarget: { origin: 'https://www.notion.so', label: 'Search notes', operation: 'fill' } }
    });
    const descendants = node => [node, ...(node.children || []).filter(child => typeof child === 'object').flatMap(descendants)];
    const nodes = descendants(h.root);
    const disclosure = nodes.find(node => node.tag === 'details' && node.children.some(child => child.tag === 'summary' && child.textContent === 'Request details'));
    if (driver === 'browser' && effect === 'write') {
      assert.ok(disclosure, 'browser-write technical request must be a disclosure');
      assert.equal(disclosure.attrs.open, undefined, 'technical request starts collapsed');
      assert.match(disclosure.textContent, /technical request marker/);
      assert.ok(nodes.some(node => node.tag === 'section' && node.attrs.class === 'browser-target-review'));
      assert.equal(nodes.some(node => node.tag === 'h3' && node.textContent === 'Exact request'), false);
    } else {
      assert.equal(disclosure, undefined);
      assert.ok(nodes.some(node => node.tag === 'h3' && node.textContent === 'Exact request'));
    }
    assert.equal(h.calls.length, 0);
  }
});

test('reported or uncertain browser writes offer a new inspection only after an explicit click', async () => {
  for (const status of ['succeeded', 'uncertain']) {
    const h = harness(), reads = [];
    const connection = { ...session(), transport: 'helper', persistentSession: false, lifecycle: undefined };
    const flow = source.slice(source.indexOf('function jobDialog'), source.indexOf('function renderActivity'));
    const show = runInNewContext(`${flow}; jobDialog`, { ...h.context, rows: () => [connection],
      statusBadge: value => h.context.el('span', {}, value), verificationBadge: () => null,
      nameOf: (_kind, id) => id, date: value => value, jsonBlock: () => h.context.el('pre'),
      observedControls: () => null, testPageAccess: item => reads.push(item.id)
    });
    show({ id: 'write', connectionId: connection.id, effect: 'write', status, args: {} });
    assert.equal(reads.length, 0);
    await h.find('Inspect page again').click();
    assert.deepEqual(reads, [connection.id]);
    assert.equal(h.calls.length, 0);
  }
});

test('an observed write is not labeled as an observed read', () => {
  const start = source.indexOf('const verificationBadge =');
  const end = source.indexOf('\nconst note =', start);
  const label = runInNewContext(`${source.slice(start, end)}; verificationBadge`, { badge: value => value });
  assert.equal(label({ effect: 'write', result: { verification: { status: 'observed' } } }), 'Action observed');
  assert.equal(label({ effect: 'read', result: { verification: { status: 'observed' } } }), 'Observed read');
  const activity = runInNewContext(`${source.slice(start, end)}; activityStatusLabel`, { badge: value => value, humanize: value => value });
  assert.equal(activity({ status: 'succeeded', effect: 'write', result: { verification: { status: 'observed' } } }), 'Action reported');
  assert.equal(activity({ status: 'succeeded', effect: 'read', result: { verification: { status: 'observed' } } }), 'Read observed');
  assert.equal(activity({ status: 'awaiting_approval', effect: 'write' }), 'Needs approval');
});

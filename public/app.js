import { requestBrowserBridge, inputValue, directoryCandidates, connectionKind, buildSummary, isConnectedService, browserConnectionState, isPersistentBrowser, isDurableBrowser, browserCapabilityMatches, browserOperationPresentation } from './connect-client.js';
import { cardText } from './hosted-base.js';
import { describeApproval } from './hosted-approval.js';

const main = document.querySelector('#main');
const dialog = document.querySelector('#dialog');
const views = { connectors: ['Connectors', '▦'], activity: ['Activity', '◷'], advanced: ['Advanced', '⚙'], connections: ['Connection settings', '↗'], capabilities: ['Capabilities', '⌘'], heartbeats: ['Heartbeats', '◷'] };
let state = null;
const initialRoute = location.hash.slice(1).split('/');
let activeView = initialRoute[0] in views ? initialRoute[0] : 'connectors';
let selectedAppId = null;
try { selectedAppId = activeView === 'connectors' && initialRoute[1] ? decodeURIComponent(initialRoute[1]) : null; } catch { /* An invalid route returns to the connector list. */ }
let selectedAccountId = null;
let permissionSearch = '';
const connectorDetails = new Map();
const connectorRequests = new Map();
const discoveryState = new Map();
const factoryState = new Map();
let search = '';
let catalogFilter = 'available';
let refreshing = false;
let lastSignature = '';
let navSignature = '';
let stopDialogWork = null;
let dialogReturnFocus = null;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined) continue;
    if (key.startsWith('aria-') && typeof value === 'boolean') {
      node.setAttribute(key, String(value));
      continue;
    }
    if (value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'value') node.value = value;
    else if (key === 'checked') node.checked = value;
    else if (key === 'disabled') node.disabled = value;
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) if (child !== null && child !== undefined && child !== false) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
}
const text = value => value === null || value === undefined ? '—' : typeof value === 'object' ? JSON.stringify(value) : String(value);
const pretty = value => JSON.stringify(value ?? {}, null, 2);
const rows = name => Array.isArray(state?.[name]) ? state[name] : [];
const date = value => value ? new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' }) : 'Not yet';
const appById = id => rows('catalog').find(item => item.id === id || item.appId === id);
const appName = id => appById(id)?.name || id || 'Application';
const nameOf = (kind, id) => rows(kind).find(item => item.id === id)?.name || rows(kind).find(item => item.id === id)?.label || id;
const button = (label, action, type = 'secondary', attrs = {}) => el('button', { type: 'button', class: `button ${type}`, onclick: action, ...attrs }, label);
const badge = (label, tone = '') => el('span', { class: `tag ${tone}` }, label);
const statusBadge = status => badge(String(status || 'unknown').replaceAll('_', ' '), ['active', 'ready', 'session_ready', 'connected', 'healthy', 'succeeded', 'verified'].includes(status) ? 'good' : ['failed', 'revoked', 'error', 'expired'].includes(status) ? 'bad' : ['candidate', 'uncertain', 'awaiting_approval', 'needs_authority', 'pending', 'attention'].includes(status) ? 'warn' : 'neutral');
const verificationBadge = job => job.result?.verification?.status === 'verified' ? badge('Verified effect', 'good') : job.result?.verification?.status === 'observed' ? badge(job.effect === 'read' ? 'Observed read' : 'Action observed', 'neutral') : job.status === 'uncertain' ? badge('Effect not verified', 'warn') : null;
const activityStatusLabel = job => job.status === 'awaiting_approval' ? 'Needs approval' : job.status === 'succeeded' ? (job.result?.verification?.status === 'verified' ? 'Verified' : job.effect === 'read' ? 'Read observed' : 'Action reported') : humanize(job.status);
const note = (message, tone = '') => el('div', { class: `inline-note ${tone}` }, message);
const jsonBlock = value => el('pre', {}, pretty(value));
function notify(message, error = false) {
  const area = document.querySelector('#notification');
  area.className = `notification${error ? ' error' : ''}`;
  area.replaceChildren(el('span', {}, message), el('button', { type: 'button', 'aria-label': 'Dismiss notification', onclick: () => { area.hidden = true; } }, '×'));
  area.hidden = false;
}
async function api(path, body) {
  const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-Fabric-CSRF': state?.csrfToken || '' }, body: body === undefined ? undefined : JSON.stringify(body) });
  let data;
  try { data = await response.json(); } catch { throw new Error(`Runtime returned an unreadable response (${response.status}).`); }
  if (!response.ok) {
    const error = new Error(text(data.error?.message || data.error || data.message || `Request failed (${response.status})`));
    error.code = data.error?.code || data.code; error.details = data; throw error;
  }
  return data;
}
async function refresh({ announce = false } = {}) {
  if (refreshing) return;
  refreshing = true;
  try {
    const next = await api('/api/state');
    const signature = JSON.stringify(activeView === 'connectors' ? [next.catalog, next.connections, next.applicationMaps, next.capabilities] : next);
    state = next;
    document.querySelector('#server-status').textContent = 'Local runtime connected';
    document.querySelector('#server-dot').className = 'status-dot';
    document.querySelector('#model-status').textContent = state.settings?.modelConfigured ? `Model: ${state.settings.modelName || 'configured'}` : 'Model not configured · deterministic tools available';
    renderNav();
    if (signature !== lastSignature || !main.children.length) render();
    if (activeView === 'connectors' && selectedAppId && !dialog.open) await loadConnector(selectedAppId, { quiet: true });
    lastSignature = signature;
    if (announce) notify('Workspace updated from the runtime.');
  } catch (error) {
    document.querySelector('#server-status').textContent = 'Runtime unreachable';
    document.querySelector('#server-dot').className = 'status-dot error';
    if (!state) main.replaceChildren(empty('Cannot reach the local runtime', `${error.message} Start Fabric with npm start, then try again.`, button('Retry connection', () => refresh(), '')));
    if (announce || !state) notify(error.message, true);
  } finally { refreshing = false; }
}
function navigate(view) { activeView = view === 'catalog' ? 'connectors' : view; selectedAppId = null; selectedAccountId = null; location.hash = activeView; renderNav(); render(); }
function renderNav() {
  const nextSignature = JSON.stringify([activeView, ...Object.keys(views).map(id => rows(id).length)]);
  if (nextSignature === navSignature) return;
  navSignature = nextSignature;
  const navButton = id => el('button', { type: 'button', class: 'nav-button', 'aria-current': activeView === id ? 'page' : null, onclick: () => navigate(id) }, el('span', { class: 'nav-icon', 'aria-hidden': 'true' }, views[id][1]), views[id][0]);
  const advanced = el('details', { class: 'advanced-navigation', open: !['connectors', 'activity'].includes(activeView) }, el('summary', {}, el('span', { class: 'nav-icon', 'aria-hidden': 'true' }, '⚙'), 'Advanced'), el('div', { class: 'advanced-items' }, ['advanced', 'connections', 'capabilities', 'heartbeats'].map(navButton)));
  document.querySelector('#navigation').replaceChildren(navButton('connectors'), navButton('activity'), advanced);
  document.querySelector('#breadcrumb-title').textContent = views[activeView][0];
  document.querySelector('#model-status').hidden = ['connectors', 'activity'].includes(activeView);
}
function head(title, description, actions = []) { return el('div', { class: 'page-head' }, el('div', {}, el('div', { class: 'eyebrow' }, 'Fabric / ' + views[activeView][0]), el('h1', {}, title), el('p', {}, description)), el('div', { class: 'head-actions' }, actions)); }
function empty(title, description, action) { return el('div', { class: 'empty' }, el('div', { class: 'empty-mark', 'aria-hidden': 'true' }, '◇'), el('h2', {}, title), el('p', {}, description), action); }
function render() { if (!state) return; main.classList.toggle('simple-view', ['connectors', 'activity'].includes(activeView)); ({ connectors: () => selectedAppId ? renderConnector() : renderCatalog(), advanced: renderAdvanced, connections: renderConnections, capabilities: renderCapabilities, activity: renderActivity, heartbeats: renderHeartbeats })[activeView](); }

function renderCatalog() {
  const searchInput = el('input', { type: 'search', placeholder: 'Search an app, device, or website', 'aria-label': 'Search connectors', value: search, autocomplete: 'off' });
  const count = el('span', { class: 'count' });
  const list = el('div', { class: 'connector-lists' });
  const segments = el('div', { class: 'catalog-segments', role: 'group', 'aria-label': 'Connection status' });
  const update = () => {
    const catalog = rows('catalog').filter(app => `${app.name} ${app.id} ${app.description || ''} ${app.category || ''}`.toLowerCase().includes(search.toLowerCase()));
    const connected = app => rows('connections').some(connection => connection.appId === app.id && isConnectedService(connection));
    const paired = app => rows('connections').some(connection => connection.appId === app.id && connection.driver === 'browser' && connection.status !== 'revoked');
    const visible = catalog.filter(app => catalogFilter === 'connected' ? connected(app) : catalogFilter === 'browsers' ? paired(app) : !connected(app) && !paired(app));
    count.textContent = `${visible.length} connector${visible.length === 1 ? '' : 's'}`;
    segments.replaceChildren(...['available', 'connected', 'browsers'].map(filter => button(filter === 'browsers' ? 'Browser sessions' : humanize(filter), () => { catalogFilter = filter; update(); }, 'segment', { 'aria-pressed': filter === catalogFilter })));
    const groups = ['Your device', 'Productivity', 'Social', 'Business', 'Other applications'];
    list.replaceChildren(...groups.map(title => [title, visible.filter(app => appCategory(app) === title)]).filter(([, apps]) => apps.length).map(([title, apps]) => el('section', { class: 'connector-section' }, el('h2', { class: 'group-heading' }, title), el('div', { class: 'connector-list settings-group' }, apps.map(app => appCard(app, rows('catalog').indexOf(app)))))));
    if (catalogFilter === 'browsers') list.prepend(el('p', { class: 'small-copy muted' }, 'Saved app access and browser sessions are separate from verified accounts. Open their details to request page access.'));
    if (!visible.length) list.append(catalogFilter !== 'available' ? empty(catalogFilter === 'browsers' ? 'No browser sessions here' : 'No connected accounts or devices here', catalogFilter === 'browsers' ? 'Choose an app to save a Fabric browser session or use an existing browser helper.' : 'Connected accounts and local devices appear here. Browser sessions have their own section.', button('Browse available apps', () => { catalogFilter = 'available'; update(); }, '')) : empty(`Find “${search.trim() || 'your app'}”`, 'Search the application directory, or enter the app’s exact website. Finding an app does not connect an account.', button('Search directory', () => resolveApplication(search), '')));
  };
  searchInput.addEventListener('input', event => { search = event.target.value; update(); });
  const searchForm = el('form', { class: 'toolbar connector-toolbar connector-search-form' }, el('div', { class: 'search' }, el('span', { class: 'search-mark', 'aria-hidden': 'true' }, '⌕'), searchInput), button('Find app', null, '', { type: 'submit' }));
  submitForm(searchForm, event => resolveApplication(search, { returnFocus: event.submitter || searchInput }));
  main.replaceChildren(head('Connectors', 'Your apps and devices, with access you control.'), searchForm, segments, el('div', { class: 'catalog-caption' }, el('span', {}, 'Apps & devices'), count), list, button('Connect another website', () => websiteDialog(), 'ghost'), el('p', { class: 'footer-note' }, 'Your account stays yours. Access is limited to the connection and permissions you approve.'));
  update();
}
function appCategory(app) {
  if (['workspace', 'local-device'].includes(app.id) || ['device', 'workspace'].includes(app.driver)) return 'Your device';
  if (['x', 'facebook', 'instagram', 'threads', 'youtube', 'linkedin'].includes(app.id)) return 'Social';
  if (['gmail', 'google-calendar', 'google-drive', 'google-docs', 'notion', 'slack', 'outlook', 'todoist', 'spotify'].includes(app.id)) return 'Productivity';
  if (['github', 'stripe', 'shopify', 'salesforce', 'hubspot'].includes(app.id)) return 'Business';
  return 'Other applications';
}
function methodsFor(app) {
  const supplied = app.authMethods || app.methods || app.connectionMethods;
  if (Array.isArray(supplied)) return supplied.map(method => typeof method === 'string' ? method : method.id || method.type);
  const methods = [];
  if (app.id === 'local' || app.id === 'workspace' || app.driver === 'workspace') return ['local'];
  if (app.oauth || /google/i.test(app.id)) methods.push('googleOAuth');
  if (app.tokenSupported !== false && (app.auth || app.apiBaseUrl || app.baseUrl || app.apiOrigin || app.api)) methods.push('token');
  if (app.browser || app.browserCapable || app.browserSupported || app.origins || app.browserOrigins) methods.push('browser');
  return methods;
}
function appCard(app, index) {
  const id = app.id || app.appId;
  const connections = rows('connections').filter(connection => connection.appId === id && connection.status !== 'revoked');
  const accounts = connections.filter(isConnectedService);
  const browsers = connections.filter(connection => connection.driver === 'browser');
  const row = el('div', { class: 'connector-row app-catalog-row' }, el('button', { type: 'button', class: 'connector-open', onclick: () => openConnector(id), 'aria-label': `View ${app.name || id} connection and permissions` }, appIcon(app, index), el('span', { class: 'connector-row-copy' }, el('strong', {}, app.name || id), el('span', {}, connectorDescription(app)))));
  if (connections.length) row.append(button(accounts.length ? `${accounts.length} connected` : browsers.some(isPersistentBrowser) ? 'Saved browser session' : browsers.some(isDurableBrowser) ? (browsers.some(connection => isDurableBrowser(connection) && browserConnectionState(connection).canTest) ? 'Ready on demand' : 'Browser needs attention') : browsers.length ? (browsers.some(connection => browserConnectionState(connection).canTest) ? 'Browser tab paired' : 'Browser needs attention') : 'Needs attention', () => openConnector(id), 'ghost small', { 'aria-label': `Manage ${app.name || id}` }));
  else row.append(button('Connect', () => addAccount(app), 'secondary small', { 'data-connect-app': id }));
  return row;
}
function appIcon(app) {
  const holder = el('span', { class: 'app-icon genuine-icon', 'aria-hidden': 'true' });
  const fallback = el('span', { class: 'generic-app-mark' }, app.driver === 'device' ? '▣' : '◇');
  const image = el('img', { src: `/api/icons/${encodeURIComponent(app.id)}`, alt: '', loading: 'lazy', decoding: 'async', referrerpolicy: 'no-referrer' });
  image.addEventListener('error', () => image.replaceWith(fallback), { once: true });
  holder.append(image); return holder;
}
function connectorDescription(app) {
  const descriptions = { gmail: 'Messages, drafts, and labels', 'google-calendar': 'Calendars, events, and invitations', github: 'Repositories, issues, and your profile', notion: 'Pages and databases you share', slack: 'Messages and workspace information', x: 'Your selected browser session', facebook: 'Your selected browser session', workspace: 'Files in your Fabric folder' };
  return descriptions[app.id] || app.description || 'See available data and actions';
}
function renderAdvanced() {
  main.replaceChildren(head('Advanced', 'Application setup, technical tools, and scheduled checks. Your main account controls are in Connectors.'), el('div', { class: 'settings-group' }, advancedRow('Connection settings', 'Check access, inspect connection records, and pair a browser.', () => navigate('connections')), advancedRow('Capabilities', 'Import, review, and run application operations.', () => navigate('capabilities')), advancedRow('Heartbeats', 'Schedule read-only operations or connection checks.', () => navigate('heartbeats')), advancedRow('Add an application', 'Extend the catalog with an application manifest.', applicationDialog), advancedRow('Import an interface', 'Acquire operations from an OpenAPI document.', importDialog), advancedRow('Local workspace', 'Connect the dedicated Fabric folder for local testing.', openLocal)), el('p', { class: 'footer-note' }, state.settings?.modelConfigured ? `Optional model: ${state.settings.modelName || 'configured'}.` : 'An optional model is not configured. Document-based discovery and local tools remain available.'));
}
function advancedRow(title, description, action) { return el('button', { type: 'button', class: 'connector-row', onclick: action }, el('span', { class: 'connector-row-copy' }, el('strong', {}, title), el('span', {}, description)), el('span', { class: 'chevron', 'aria-hidden': 'true' }, '›')); }
async function loadConnector(appId, { quiet = false } = {}) {
  if (connectorRequests.has(appId)) return connectorRequests.get(appId);
  const request = (async () => {
    try {
      const details = await api(`/api/connectors/${encodeURIComponent(appId)}`);
      const previous = connectorDetails.get(appId);
      connectorDetails.set(appId, details);
      if (selectedAppId === appId && activeView === 'connectors' && (!quiet || JSON.stringify(previous) !== JSON.stringify(details))) renderConnector();
      return details;
    } catch (error) {
      if (!quiet || !connectorDetails.has(appId)) {
        const previous = discoveryState.get(appId) || {};
        discoveryState.set(appId, { ...previous, error: error.message });
        if (selectedAppId === appId && activeView === 'connectors') renderConnector();
      }
      return null;
    } finally { connectorRequests.delete(appId); }
  })();
  connectorRequests.set(appId, request);
  return request;
}
async function openConnector(appId, { discover = true } = {}) {
  selectedAppId = appId; selectedAccountId = null; permissionSearch = ''; activeView = 'connectors';
  location.hash = `connectors/${encodeURIComponent(appId)}`; renderNav(); renderConnector();
  const details = await loadConnector(appId);
  await loadFactoryBuilds(appId);
  if (discover && details && !details.map && details.app?.discovery && !discoveryState.get(appId)?.attempted) await discoverConnector(appId);
}
async function loadFactoryBuilds(appId) {
  if (factoryState.get(appId)?.loading) return;
  try {
    const response = await api(`/api/factory/builds?appId=${encodeURIComponent(appId)}`);
    const builds = Array.isArray(response) ? response : response.builds || [];
    const previous = factoryState.get(appId) || {};
    factoryState.set(appId, { ...previous, reports: builds, loaded: true });
    if (selectedAppId === appId && activeView === 'connectors') renderConnector();
  } catch (error) {
    factoryState.set(appId, { ...(factoryState.get(appId) || {}), historyError: error.message });
  }
}
async function buildConnector(appId) {
  if (factoryState.get(appId)?.loading) return;
  factoryState.set(appId, { ...(factoryState.get(appId) || {}), loading: true, error: null });
  if (selectedAppId === appId) renderConnector();
  try {
    const response = await api('/api/factory/build', { appId });
    const report = response.build || response.report || response;
    factoryState.set(appId, { loading: false, loaded: true, reports: [report], report });
    await refresh();
    await loadConnector(appId);
    await loadFactoryBuilds(appId);
  } catch (error) {
    factoryState.set(appId, { ...(factoryState.get(appId) || {}), loading: false, error: error.message });
  }
  if (selectedAppId === appId && activeView === 'connectors') renderConnector();
}
async function discoverConnector(appId) {
  if (discoveryState.get(appId)?.loading) return;
  discoveryState.set(appId, { loading: true, attempted: true });
  if (selectedAppId === appId) renderConnector();
  try {
    const map = await api('/api/discover', { appId });
    const previous = connectorDetails.get(appId) || {};
    connectorDetails.set(appId, { ...previous, map: map.map || map.applicationMap || map });
    discoveryState.set(appId, { loading: false, attempted: true });
    await loadConnector(appId);
    await refresh();
  } catch (error) {
    discoveryState.set(appId, { loading: false, attempted: true, error: error.message });
  }
  if (selectedAppId === appId && activeView === 'connectors') renderConnector();
}
function currentConnector() { return connectorDetails.get(selectedAppId) || { app: appById(selectedAppId), connections: rows('connections').filter(connection => connection.appId === selectedAppId), map: rows('applicationMaps').find(map => map.appId === selectedAppId) }; }
function renderConnector() {
  const data = currentConnector();
  const app = data.app || appById(selectedAppId);
  if (!app) { main.replaceChildren(empty('App not found', 'Return to Connectors to choose an available application.', button('Back to Connectors', () => navigate('connectors'), ''))); return; }
  const discovery = discoveryState.get(selectedAppId) || {};
  const factory = factoryState.get(selectedAppId) || {};
  const latestBuild = factory.report || factory.reports?.[0];
  const map = data.map || data.applicationMap;
  const connections = (data.connections || []).filter(connection => connection.status !== 'revoked');
  const accounts = connections.filter(connection => connection.driver !== 'browser');
  const browserConnections = connections.filter(connection => connection.driver === 'browser');
  if (!connections.some(connection => connection.id === selectedAccountId)) selectedAccountId = accounts[0]?.id || browserConnections[0]?.id || null;
  const selectedAccount = connections.find(connection => connection.id === selectedAccountId);
  const operations = connectorOperations(data, selectedAccountId);
  const back = button('‹ Connectors', () => navigate('connectors'), 'ghost');
  const header = el('div', { class: 'connector-detail-header' }, appIcon(app, rows('catalog').findIndex(item => item.id === app.id)), el('div', {}, el('h1', {}, app.name), el('p', {}, connectorDescription(app))));
  const accountSection = el('section', { class: 'connector-section' }, el('div', { class: 'section-head' }, el('h2', {}, 'Connection'), button(connections.length ? 'Add another connection' : `Connect ${app.name}`, () => startConnection(app, undefined, { forceNew: !!connections.length }), 'small', { 'data-connect-app': app.id })));
  const accountList = el('div', { class: 'settings-group' });
  if (!connections.length) accountList.append(el('div', { class: 'settings-row account-empty' }, el('div', {}, el('strong', {}, 'Not connected yet'), el('p', {}, 'Choose a supported way to connect. Fabric will explain what it can access before you continue.'))));
  accounts.forEach(connection => accountList.append(el('button', { type: 'button', class: `settings-row account-row${connection.id === selectedAccountId ? ' selected' : ''}`, 'aria-pressed': connection.id === selectedAccountId, onclick: () => { selectedAccountId = connection.id; renderConnector(); } }, el('span', { class: 'account-avatar', 'aria-hidden': 'true' }, (connection.identity?.displayName || connection.label || 'A').slice(0, 1).toUpperCase()), el('span', { class: 'connector-row-copy' }, el('strong', {}, connection.identity?.email || connection.identity?.displayName || connection.label), el('span', {}, `${connectionKind(connection)} · ${connection.status === 'ready' ? 'Connected' : connection.status.replaceAll('_', ' ')}`)), el('span', { class: 'account-check', 'aria-hidden': 'true' }, connection.id === selectedAccountId ? '✓' : ''))));
  if (accounts.length || !connections.length) accountSection.append(accountList);
  if (browserConnections.length) accountSection.append(el('h3', { class: 'browser-session-label' }, 'Browser sessions'), el('p', { class: 'small-copy muted' }, 'Manage saved app access and browser sessions from this preview. Browser access does not verify which account is signed in.'), el('div', { class: 'settings-group' }, browserConnections.map(connection => el('button', { type: 'button', class: `settings-row account-row${connection.id === selectedAccountId ? ' selected' : ''}`, 'aria-pressed': connection.id === selectedAccountId, onclick: () => { selectedAccountId = connection.id; renderConnector(); } }, el('span', { class: 'account-avatar', 'aria-hidden': 'true' }, '↗'), el('span', { class: 'connector-row-copy' }, el('strong', {}, isPersistentBrowser(connection) ? 'Saved browser session' : isDurableBrowser(connection) ? 'Saved app access' : connection.label || 'Paired application tab'), el('span', {}, browserConnectionState(connection).label)), el('span', { class: 'account-check', 'aria-hidden': 'true' }, connection.id === selectedAccountId ? '✓' : '')))));
  if (selectedAccount?.driver === 'browser') accountSection.append(browserEvidenceSummary(selectedAccount));
  if (selectedAccount?.driver === 'browser' && !isPersistentBrowser(selectedAccount) && !isDurableBrowser(selectedAccount)) accountSection.append(
    el('p', { class: 'small-copy muted' }, 'This older connection is tab-only. Saving on-demand access requires a new approval; existing permissions are not upgraded.'),
    button('Upgrade to on-demand access', () => startConnection(app, 'browser', { forceNew: true, helperOnly: true }), 'secondary small')
  );
  if (selectedAccount) {
    accountSection.append(el('div', { class: 'account-tools' }, isPersistentBrowser(selectedAccount) ? button('Open sign-in window', event => openSavedBrowser(selectedAccount, event.currentTarget), 'secondary small') : null, selectedAccount.driver === 'browser' ? button('Test page access', () => testPageAccess(selectedAccount), 'secondary small', { disabled: !browserConnectionState(selectedAccount).canTest }) : null, button(isPersistentBrowser(selectedAccount) ? 'Check browser' : selectedAccount.driver === 'browser' ? 'Check helper' : 'Check connection', () => checkAccount(selectedAccount), 'ghost small'), button('Disconnect', () => disconnectAccount(selectedAccount), 'ghost small')));
    const lifetime = connectionLifetime(selectedAccount); if (lifetime) accountSection.append(lifetime);
  }
  const permissionContainer = el('section', { class: 'connector-section' }, el('div', { class: 'section-head' }, el('div', {}, el('h2', {}, isPersistentBrowser(selectedAccount) ? 'Access for this saved session' : isDurableBrowser(selectedAccount) ? 'Access for this app' : selectedAccount?.driver === 'browser' ? 'Access for this browser tab' : selectedAccount ? 'Access for this connection' : 'Published data and actions'), el('p', { class: 'small-copy muted' }, isPersistentBrowser(selectedAccount) ? 'Read-only for now. Each page request asks for approval; account identity remains unverified.' : isDurableBrowser(selectedAccount) ? 'Each read and change asks for approval. Closing the app tab does not remove this access; your browser must be running.' : selectedAccount?.driver === 'browser' ? 'Page reads are requested explicitly. Browser changes require approval; account identity remains unverified.' : selectedAccount ? 'Allow without asking, ask each time, or keep an operation off.' : 'This describes the app’s interface. No account data has been read.'))));
  if (discovery.loading) permissionContainer.append(note('Checking the application’s published interface… This reads public metadata, not your account data.'));
  if (discovery.error) permissionContainer.append(note(`Could not finish checking this app: ${discovery.error}`, 'error'));
  if (factory.loading) permissionContainer.append(connectionProgress('Finding available actions…', 'Checking supported interfaces and preparing action descriptions. No account task is being run.'));
  if (factory.error) permissionContainer.append(note(`Could not finish finding actions: ${factory.error}`, 'error'));
  if (latestBuild && !factory.loading) permissionContainer.append(el('p', { class: 'factory-summary small-copy muted', role: 'status' }, buildSummary(latestBuild)));
  if (!map && !operations.length && !discovery.loading && !factory.loading) permissionContainer.append(empty('Find what Fabric can do here', 'Fabric can inspect supported published interfaces. Finding action descriptions does not grant account access.', button(latestBuild || factory.error ? 'Check again' : 'Find available actions', () => buildConnector(app.id), '')));
  if (map || operations.length) {
    if (['partial', 'unsupported', 'failed'].includes(map?.status)) permissionContainer.append(note(map?.status === 'partial' ? 'Some operations could not be made executable. They remain visible below with their limitations.' : 'This interface is not fully executable. Review the availability shown for each operation.', 'warn'));
    const searchInput = el('input', { type: 'search', placeholder: 'Search data and actions', 'aria-label': 'Search data and actions', value: permissionSearch });
    const groups = el('div', { class: 'permission-groups' });
    const update = () => {
      const matching = operations.filter(operation => `${operation.name} ${operation.description} ${operation.resource || ''}`.toLowerCase().includes(permissionSearch.toLowerCase()));
      groups.replaceChildren(...['read', 'write'].map(group => permissionGroup(group, matching.filter(operation => group === 'read' ? operation.effect === 'read' : operation.effect !== 'read'), selectedAccount, app)));
      if (!matching.length) groups.replaceChildren(el('p', { class: 'small-copy muted' }, 'No matching data or actions.'));
    };
    searchInput.addEventListener('input', () => { permissionSearch = searchInput.value; update(); });
    permissionContainer.append(el('div', { class: 'search permission-search' }, el('span', { class: 'search-mark', 'aria-hidden': 'true' }, '⌕'), searchInput), groups); update();
  }
  const advanced = el('details', { class: 'connector-advanced' }, el('summary', {}, 'More details'), el('div', { class: 'connector-advanced-body' }, map ? el('p', { class: 'small-copy muted' }, `Interface checked ${date(map.discoveredAt)}. Source: ${map.sourceUrl || 'local/imported interface'}`) : null, el('div', { class: 'head-actions' }, button('Check available actions', () => buildConnector(app.id), 'secondary small', { disabled: factory.loading }), app.discovery ? button('Refresh published interface', () => discoverConnector(app.id), 'secondary small', { disabled: discovery.loading }) : null), factory.historyError ? note(`Action check history is unavailable: ${factory.historyError}`, 'warn') : null, latestBuild ? el('details', { class: 'factory-report' }, el('summary', {}, 'How these actions were established'), el('p', { class: 'small-copy muted' }, `Latest check: ${humanize(latestBuild.status || 'unknown')}. A generated description does not prove a connected account or a successful execution.`), jsonBlock(latestBuild)) : null, browserConnections.length ? note(`${browserConnections.length} browser connection${browserConnections.length === 1 ? '' : 's'} saved. Browser access is not a verified provider account; browser reads remain interactive.`, 'warn') : null, map?.gaps?.length ? el('details', {}, el('summary', {}, 'Coverage limitations'), jsonBlock(map.gaps)) : null, map?.changes ? el('details', {}, el('summary', {}, 'Interface changes'), jsonBlock(map.changes)) : null));
  if ((app.webOrigins || app.browserOrigins || []).length) advanced.querySelector('.head-actions').append(button('Separate read-only browser', () => startConnection(app, 'browser', { forceNew: true, savedBrowser: true }), 'secondary small'));
  const toolsUrl = `/api/connectors/${encodeURIComponent(app.id)}/tools${selectedAccountId ? `?connectionId=${encodeURIComponent(selectedAccountId)}` : ''}`;
  const developer = el('details', { class: 'connector-advanced developer-details' }, el('summary', {}, 'For developers'), el('div', { class: 'connector-advanced-body' }, el('p', { class: 'small-copy muted' }, 'The machine-readable tool description uses this same application map and connection permissions. Discovered operations are not automatically executable.'), el('p', { class: 'small-copy' }, selectedAccount ? `Selected ${isDurableBrowser(selectedAccount) ? 'saved app access' : isPersistentBrowser(selectedAccount) ? 'saved browser session' : selectedAccount.driver === 'browser' ? 'browser tab' : 'connection'}: ${selectedAccount.identity?.email || selectedAccount.label}` : 'No connection selected.'), el('a', { href: toolsUrl, target: '_blank', rel: 'noopener', class: 'button secondary small' }, 'View machine-readable tools')));
  developer.querySelector('.connector-advanced-body').append(el('div', { class: 'head-actions' }, button('Developer connection settings', () => connectDialog(app), 'secondary small'), button('Import interface', () => importDialog(app.id), 'secondary small')));
  main.replaceChildren(back, header, accountSection, permissionContainer, advanced, developer);
}
function connectorOperations(data, connectionId) {
  const map = data.map || data.applicationMap;
  const mapped = Array.isArray(map?.operations) ? map.operations : [];
  const policies = data.permissionsByConnection?.[connectionId] || [];
  const connection = data.connections?.find(item => item.id === connectionId);
  const source = mapped.length && connection?.driver !== 'browser' ? mapped : rows('capabilities').filter(capability => capability.appId === selectedAppId && (!connection || (connection.driver === 'browser' ? browserCapabilityMatches(capability, connection) : capability.driver === connection.driver))).map(capability => ({ ...capability, capabilityId: capability.id, support: capability.status, method: capability.request?.method, path: capability.request?.url }));
  return source.map(operation => {
    const capability = rows('capabilities').find(item => item.id === operation.capabilityId);
    return { ...operation, destination: capability?.request?.url || null, ...(policies.find(policy => policy.capabilityId === operation.capabilityId) || {}), ...browserOperationPresentation(capability, connection) };
  });
}
function permissionGroup(group, operations, connection, app) {
  if (!operations.length) return el('div');
  const title = group === 'read' ? 'Read permissions' : 'Write and delete permissions';
  const description = group === 'read' ? 'View and retrieve information.' : 'Create, change, send, or remove information.';
  const grouped = new Map();
  operations.forEach(operation => { const resource = operation.resource || 'Operations'; if (!grouped.has(resource)) grouped.set(resource, []); grouped.get(resource).push(operation); });
  const container = el('section', { class: `permission-group ${group}` }, el('div', { class: 'permission-group-label' }, el('h3', {}, title), el('span', {}, `${operations.length} operation${operations.length === 1 ? '' : 's'}`)), el('p', { class: 'small-copy muted' }, description));
  if (operations.length <= 12) container.append(el('div', { class: 'settings-group' }, operations.map(operation => permissionRow(operation, connection, app))));
  else grouped.forEach((items, resource) => container.append(el('details', { class: 'resource-group' }, el('summary', {}, el('strong', {}, humanize(resource)), el('span', {}, `${items.length}`)), el('div', { class: 'settings-group nested-settings' }, items.map(operation => permissionRow(operation, connection, app))))));
  return container;
}
function humanize(value) { return String(value).replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[._-]/g, ' ').replace(/^./, char => char.toUpperCase()); }
function operationLabel(operation) {
  if (!operation.name?.includes('.') || operation.name !== operation.id) return operation.name || humanize(operation.id);
  const verb = operation.id.split('.').at(-1);
  const resource = humanize((operation.resource || '').split('.').at(-1) || 'information').toLowerCase();
  const action = ({ get: 'Read', list: 'List', insert: 'Create', create: 'Create', update: 'Update', patch: 'Update', delete: 'Delete', send: 'Send' })[verb];
  return action ? `${action} ${resource}` : humanize(verb);
}
function operationAvailability(operation, connection) {
  if (operation.support === 'unsupported' || ['unsupported', 'removed'].includes(operation.status) || !operation.capabilityId) return ['Not executable', 'neutral'];
  if (!connection) return ['Needs account', 'neutral'];
  if (connection.driver === 'browser' && !browserConnectionState(connection).canTest) return [browserConnectionState(connection).label, 'warn'];
  if (operation.locked) return ['Fabric keeps this off', 'neutral'];
  // F10.6: no sign-in can ever give it access, whatever its mode; its reason, under "What this allows", says why.
  if (operation.providerAccess === 'unavailable') return ['Not offered', 'neutral'];
  if (operation.providerAccess === 'missing') return ['Needs access', 'warn'];
  if (operation.mode === 'deny') return ['Off', 'neutral'];
  if (operation.status === 'candidate') return ['Needs review', 'neutral'];
  if (operation.executable) return [operation.mode === 'ask' ? 'Ask each time' : operation.providerAccess === 'unknown' ? 'Provider enforced' : 'Available', operation.providerAccess === 'unknown' ? 'neutral' : 'good'];
  if (connection.status !== 'ready') return ['Connection needs attention', 'warn'];
  return ['Not executable', 'neutral'];
}
function permissionRow(operation, connection, app) {
  const label = operationLabel(operation);
  const availability = operationAvailability(operation, connection);
  // A member Fabric locks (F10.3) stays Off: no choice to make and no access to add.
  const canSet = !!connection && (connection.driver === 'browser' ? browserConnectionState(connection).canTest : connection.status === 'ready') && !!operation.capabilityId && operation.support !== 'unsupported' && !['unsupported', 'removed'].includes(operation.status) && !operation.locked;
  const browserWrite = connection?.driver === 'browser' && operation.effect !== 'read';
  const askOnly = browserWrite || isPersistentBrowser(connection) || isDurableBrowser(connection);
  const mode = askOnly && operation.mode !== 'deny' ? 'ask' : operation.mode || (operation.effect === 'read' ? 'allow' : 'ask');
  const control = canSet ? select(askOnly ? [['deny', 'Off'], ['ask', 'Ask']] : [['deny', 'Off'], ['ask', 'Ask'], ['allow', 'Allow']], null, mode) : null;
  if (control) { control.setAttribute('aria-label', `Access for ${label}`); control.className = 'permission-select'; control.addEventListener('change', () => { const requested = control.value; control.value = mode; permissionReview(operation, connection, requested, app); }); }
  const details = el('details', { class: 'operation-details' }, el('summary', {}, 'What this allows'), el('p', { class: 'small-copy muted' }, operation.reason || operation.description || 'Review this operation against the application’s published interface.'), el('dl', { class: 'key-value' }, el('dt', {}, 'Operation'), el('dd', { class: 'mono' }, `${operation.method || ''} ${operation.path || operation.id || operation.name}`), el('dt', {}, connection?.driver === 'browser' ? 'Browser access' : 'Account access'), el('dd', {}, !connection ? 'No connection selected' : connection.driver === 'browser' ? (isDurableBrowser(connection) ? 'Saved access for this app’s origin in your browser profile; account identity is not verified.' : isPersistentBrowser(connection) ? 'Separate read-only browser session; account identity is not verified.' : 'Paired tab only; provider account identity is not verified.') : operation.providerAccess === 'unknown' ? 'Provider-enforced; scopes could not be fully observed.' : operation.providerAccess === 'unavailable' ? 'Not offered through sign-in; the reason is above.' : operation.providerAccess || 'Not yet checked'), operation.requiredScopes?.length ? [el('dt', {}, 'Provider permissions'), el('dd', {}, operation.requiredScopes.join('\n'))] : null));
  if (operation.responseSchema) details.append(el('details', {}, el('summary', {}, 'Documented data fields'), el('p', { class: 'small-copy muted' }, 'These are declared response fields, not account contents. Fabric has not validated a live response against this schema.'), jsonBlock(operation.responseSchema)));
  if (operation.scopeSets?.length) details.append(el('p', { class: 'small-copy muted' }, `Provider access requires one of these alternatives: ${operation.scopeSets.map(group => group.join(' AND ')).join(' OR ')}.`));
  if (operation.gaps?.length) details.append(el('details', {}, el('summary', {}, `${operation.gaps.length} interface limitation${operation.gaps.length === 1 ? '' : 's'}`), jsonBlock(operation.gaps)));
  const capability = rows('capabilities').find(item => item.id === operation.capabilityId);
  return el('div', { class: 'permission-row' }, el('div', { class: 'permission-copy' }, el('strong', {}, label), el('p', {}, operation.description || operation.reason || (operation.effect === 'read' ? 'Read information from this application.' : 'Change information in this application.')), el('div', { class: 'permission-status' }, el('span', { class: `availability ${availability[1]}` }, availability[0]), operation.effect === 'delete' ? el('span', { class: 'availability warn' }, 'Deletes data') : null, operation.stale ? el('span', { class: 'availability warn' }, 'Access needs review') : null), details), el('div', { class: 'permission-controls' }, control, canSet && capability?.status === 'active' && mode !== 'deny' ? button(browserWrite ? 'Choose control' : 'Try action', () => browserWrite ? inspectForAction(connection) : operationDialog(capability, connection), 'ghost small') : null, canSet && (operation.status === 'candidate' || operation.stale) ? button('Review access', () => permissionReview(operation, connection, mode, app), 'secondary small') : null, connection && operation.providerAccess === 'missing' && !operation.locked ? button('Add access', () => addAccount(app, { connection, add: operation.addAccess, blocked: operation.addBlocked }), 'secondary small') : null));
}

function operationDialog(capability, connection, { pageTest = false } = {}) {
  const schema = capability.inputSchema || {};
  const controls = new Map();
  const fields = Object.entries(schema.properties || {}).map(([name, spec]) => {
    const required = schema.required?.includes(name);
    const attrs = { required, 'data-argument': name, autocomplete: 'off' };
    const input = spec.enum ? select(spec.enum.map(value => [String(value), String(value)]), required ? 'Choose a value' : 'Not specified') : spec.type === 'boolean' ? select([['true', 'Yes'], ['false', 'No']], required ? 'Choose a value' : 'Not specified') : ['object', 'array'].includes(spec.type) ? el('textarea', { ...attrs, rows: '4', class: 'code-input', placeholder: spec.type === 'array' ? '[]' : '{}' }) : el('input', { ...attrs, type: ['number', 'integer'].includes(spec.type) ? 'number' : 'text', ...(spec.minimum !== undefined ? { min: spec.minimum } : {}), ...(spec.maximum !== undefined ? { max: spec.maximum } : {}), ...(spec.type === 'integer' ? { step: '1' } : {}), ...(spec.maxLength ? { maxlength: spec.maxLength } : {}) });
    input.required = !!required;
    if (spec.default !== undefined) input.value = typeof spec.default === 'object' ? JSON.stringify(spec.default) : String(spec.default);
    controls.set(name, { input, spec });
    return field(humanize(name), input, spec.description || (!required ? 'Optional' : undefined));
  });
  const form = el('form', {}, note(pageTest ? `This reads visible page text and controls from your ${isPersistentBrowser(connection) ? 'saved browser session' : isDurableBrowser(connection) ? 'saved app access' : 'paired browser tab'}, which may include private information. It does not verify which account is signed in. ${isDurableBrowser(connection) ? 'After approval, Fabric opens an on-demand temporary tab if needed. Your browser profile provides the site session; sign in on the real website if required.' : isPersistentBrowser(connection) ? 'Approval is required for this request.' : 'Your saved permission still applies.'}` : capability.effect === 'read' ? 'This requests real information through your connection. Your saved permission determines whether approval is required.' : 'This can change the application. Review the target and inputs carefully; your saved permission determines whether another approval is required.', capability.effect === 'read' ? '' : 'warn'), ...fields, !fields.length && !pageTest ? el('p', { class: 'small-copy muted' }, 'This action does not need any additional information.') : null, actions(cancel(), button(pageTest ? 'Test page access' : 'Continue', null, '', { type: 'submit' })));
  submitForm(form, async () => {
    const args = {};
    for (const [name, { input, spec }] of controls) if (input.value !== '') args[name] = inputValue(spec, spec.type === 'boolean' ? input.value === 'true' : input.value);
    const job = await api('/api/jobs', { connectionId: connection.id, capabilityId: capability.id, args }); await refresh(); jobDialog(job);
  });
  openDialog(pageTest ? 'Test page access' : browserOperationPresentation(capability, connection).name || capability.name, connection.label || appName(connection.appId), form);
}

function testPageAccess(connection) {
  if (connection.driver !== 'browser' || !browserConnectionState(connection).canTest) { notify(isPersistentBrowser(connection) ? 'Open the saved sign-in window and keep Fabric running, then check the browser again. No page has been read.' : isDurableBrowser(connection) ? 'Keep Chrome or Edge, the Fabric helper, and this local runtime running, then check the helper again. No app tab needs to stay open. No page has been read.' : 'Open the paired tab in Chrome or Edge and keep Fabric running, then check the helper again. No page has been read.', true); return; }
  const capability = rows('capabilities').find(item => browserCapabilityMatches(item, connection) && item.action?.op === 'observe' && item.effect === 'read' && item.status === 'active');
  if (!capability) { notify('This browser session has no supported page inspection action. No page has been read.', true); return; }
  operationDialog(capability, connection, { pageTest: true });
}

async function inspectForAction(connection) {
  const capability = rows('capabilities').find(item => browserCapabilityMatches(item, connection) && item.action?.op === 'observe' && item.status === 'active');
  if (!capability) { notify('This connection has no supported page inspection action.', true); return; }
  operationDialog(capability, connection);
}

function observedControls(job) {
  const data = job.result?.data;
  if (job.status !== 'succeeded' || !data?.snapshotId || !Array.isArray(data.controls)) return null;
  const connection = rows('connections').find(item => item.id === job.connectionId);
  if (!connection || connection.driver !== 'browser' || isPersistentBrowser(connection)) return null;
  const controls = data.controls.filter(item => item.targetId && (item.canClick || item.canFill));
  return el('section', { class: 'observed-controls' }, el('h3', {}, 'Controls found on this page'), el('p', { class: 'small-copy muted' }, 'Choose a control from this inspection. Every change asks for approval. If the page changes, closes, or this inspection expires, inspect it again.'), el('div', { class: 'settings-group' }, controls.slice(0, 60).map(target => el('div', { class: 'settings-row' }, el('div', { class: 'connector-row-copy' }, el('strong', {}, target.label || target.role || target.kind || 'Page control'), el('span', {}, target.role || target.kind || 'Control')), el('div', { class: 'head-actions' }, target.canClick ? button('Click', () => browserTargetDialog(connection, data.snapshotId, target, 'click'), 'secondary small') : null, target.canFill ? button('Enter text', () => browserTargetDialog(connection, data.snapshotId, target, 'fill'), 'secondary small') : null)))), !controls.length ? el('p', { class: 'small-copy muted' }, 'No supported clickable or text controls were found.') : null);
}

function browserTargetDialog(connection, snapshotId, target, op) {
  if (isPersistentBrowser(connection)) { notify('Saved browser sessions are read-only in this version. No change has been requested.', true); return; }
  const capability = rows('capabilities').find(item => browserCapabilityMatches(item, connection) && item.action?.op === op && item.status === 'active');
  if (!capability) { notify('Reconnect this app with the latest browser helper to enable this action.', true); return; }
  const value = el('textarea', { required: true, rows: '3', maxlength: '10000', autocomplete: 'off', placeholder: 'Text to enter in this control' });
  const form = el('form', {}, note('This acts on the exact control from your recent inspection. You will approve the exact request before it is sent. If that page has closed, inspect it again first.', 'warn'), el('p', { class: 'small-copy' }, el('strong', {}, 'Control: '), target.label || target.role || target.kind || target.targetId), op === 'fill' ? field('Text', value, 'Do not enter passwords, payment details, or other secrets.') : null, actions(cancel(), button('Review action', null, '', { type: 'submit' })));
  submitForm(form, async () => { const job = await api('/api/jobs', { connectionId: connection.id, capabilityId: capability.id, args: { snapshotId, targetId: target.targetId, ...(op === 'fill' ? { value: value.value } : {}) } }); await refresh(); jobDialog(job); });
  openDialog(op === 'click' ? 'Click this control?' : 'Enter text in this control', appName(connection.appId), form);
}
function permissionReview(operation, connection, mode, app) {
  const checkbox = el('input', { type: 'checkbox', required: true });
  const consequence = mode === 'deny' ? 'Fabric will block this operation for the selected connection.' : mode === 'ask' ? 'Fabric will ask you to approve each execution of this operation.' : operation.effect === 'read' ? (connection.driver === 'browser' ? 'Fabric may fulfill an explicit page-read request without another approval. Browser reads do not run unattended or verify a signed-in account.' : 'Fabric may run this read operation for this connection without asking each time.') : 'Fabric may run future executions of this operation on this connection without another approval prompt. This includes different arguments and may change, send, or delete data.';
  // F09.1: Allow on an operation that returns keys or secrets, or a read that may change something, says so.
  const risk = mode === 'allow' && operation.sensitivity === 'secrets' ? 'This operation can return keys or secrets. Allow lets the agent receive them without asking.' : mode === 'allow' && operation.sensitivity === 'suspected-write' ? 'This read may change something. Allow lets the agent run it without asking.' : null;
  const form = el('form', {}, el('div', { class: 'permission-review-account' }, appIcon(app), el('div', {}, el('strong', {}, operation.name), el('p', { class: 'small-copy muted' }, connection.identity?.email || connection.identity?.displayName || connection.label))), el('p', { class: 'small-copy' }, operation.description), risk ? note(risk, 'warn') : null, note(consequence, mode === 'allow' && operation.effect !== 'read' ? 'warn' : ''), operation.providerAccess === 'missing' ? note('The provider has not granted the required account access. Saving this preference does not grant that access or make the operation executable.', 'warn') : null, operation.providerAccess === 'unknown' ? note('The provider still checks its own permissions when this operation runs. Fabric cannot claim that all required scopes are present.') : null, el('details', {}, el('summary', {}, 'Review operation and destination'), jsonBlock({ name: operation.name, method: operation.method, path: operation.path, effect: operation.effect, requiredScopes: operation.requiredScopes, capabilityId: operation.capabilityId, source: currentConnector().map?.sourceUrl })), el('label', { class: 'check-field' }, checkbox, 'I have reviewed this operation and the access described above.'), actions(cancel(), button(mode === 'deny' ? 'Turn off' : `Save ${mode === 'ask' ? 'Ask' : 'Allow'}`, null, mode === 'allow' && operation.effect === 'delete' ? 'danger' : '', { type: 'submit' })));
  if (operation.destination) {
    const destination = el('p', { class: 'small-copy permission-destination' }, el('strong', {}, 'Destination: '), el('code', {}, `${operation.method || ''} ${operation.destination}`));
    form.insertBefore(destination, form.querySelector('.inline-note'));
  }
  submitForm(form, async () => { await api(`/api/connections/${encodeURIComponent(connection.id)}/permissions`, { capabilityId: operation.capabilityId, mode, review: true }); dialog.close(); await loadConnector(app.id); await refresh(); notify(`${operationLabel(operation)}: ${mode === 'deny' ? 'Off' : mode === 'ask' ? 'Ask each time' : 'Allowed for this connection'}.`); });
  openDialog(mode === 'allow' && (operation.effect !== 'read' || risk) ? 'Allow without asking each time?' : connection.driver === 'browser' ? 'Review browser access' : 'Review account access', 'This setting applies to this operation and this connection only.', form);
}
async function checkAccount(connection) { await connectionAction(connection.id, 'check'); await loadConnector(connection.appId); }
function disconnectAccount(connection) { revokeDialog(connection); }
// F10.7 (open question 19): Add access sends the body the server computed for that operation (its provider, account, level and the
// exact scopes) to that provider's start route. The browser never picks a scope.
function addAccount(app, { connection, add, blocked } = {}) {
  if (!connection) { startConnection(app); return; }
  if (!add?.providerId || !add.body) { notify(blocked || 'This permission is not available through sign-in for this app.', true); return; }
  signInDialog(app, { connection, add });
}

async function resolveApplication(query = '', { returnFocus } = {}) {
  const value = query.trim();
  if (!value) { websiteDialog(); return; }
  const content = el('div', { class: 'directory-flow' }, connectionProgress('Searching application directories…', 'This checks public app listings. No account is being connected.'));
  openDialog(`Find ${value}`, 'Choose the application you mean, then review its connection and permissions.', content, { returnFocus });
  try {
    const result = await api('/api/catalog/lookup', { query: value });
    if (!dialog.open || !content.isConnected) return;
    if (result.status === 'resolved' && result.app) { await showResolvedApplication(result, { build: !!result.created }); return; }
    const candidates = directoryCandidates(result);
    const sources = Array.isArray(result.index?.sources) ? result.index.sources : [];
    const notices = sources.filter(source => source.error).map(source => `${source.name || source.id}: ${source.error}`);
    content.replaceChildren(...[
      el('p', { class: 'small-copy directory-status', role: 'status', 'aria-live': 'polite' }, candidates.length ? `${candidates.length} matching application${candidates.length === 1 ? '' : 's'}. These are directory listings, not connected accounts.` : result.message || 'No matching application was found in the available directories.'),
      result.index?.stale ? note('Showing cached directory information. Review the website and source before choosing.', 'warn') : null,
      notices.length ? note('One or more directories could not be refreshed. Results may be incomplete.', 'warn') : null,
      el('div', { class: 'settings-group directory-results' }, candidates.map(candidate => directoryCandidate(candidate, content))),
      candidates.length ? el('p', { class: 'small-copy muted' }, 'Selecting a listing inspects its published interface. It does not sign in or grant account access.') : null,
      sources.length ? el('details', { class: 'directory-sources' }, el('summary', {}, 'Sources checked'), el('div', { class: 'small-copy muted' }, sources.map(source => el('p', {}, `${source.name || source.id} · ${source.status || 'Status unavailable'}${source.fetchedAt ? ` · ${date(source.fetchedAt)}` : ''}`))), notices.length ? el('p', { class: 'small-copy muted' }, notices.join('\n')) : null) : null,
      actions(button('Cancel', () => dialog.close()), button('Use a website instead', () => websiteDialog(value), 'secondary'))
    ].filter(Boolean));
  } catch (error) {
    if (dialog.open && content.isConnected) content.replaceChildren(note(error.message, 'error'), el('p', { class: 'small-copy muted' }, 'No account has been connected. You can retry the directory or use the app’s exact website.'), actions(button('Use a website', () => websiteDialog(value)), button('Try again', () => resolveApplication(value), '')));
  }
}

function directoryCandidate(candidate, content) {
  const source = candidate.source || {};
  const description = el('span', { class: 'connector-row-copy' }, el('strong', {}, candidate.name), candidate.description ? el('span', {}, candidate.description) : null, candidate.website ? el('span', { class: 'directory-website' }, candidate.website) : null, el('span', { class: 'directory-provenance' }, `${source.name || 'Directory listing'} · ${source.kind === 'official-directory' ? 'Provider-published listing' : 'Community directory listing'}`));
  const identity = el('span', { class: 'app-icon genuine-icon directory-icon', 'aria-hidden': 'true' });
  const icon = el('img', { src: `/api/catalog/icons/${encodeURIComponent(candidate.id)}`, alt: '', loading: 'lazy', decoding: 'async', referrerpolicy: 'no-referrer' });
  icon.addEventListener('error', () => icon.replaceWith(el('span', { class: 'generic-app-mark' }, '◇')), { once: true });
  identity.append(icon);
  const choose = button('Choose', async event => {
    const control = event.currentTarget;
    const controls = [...content.querySelectorAll('[data-directory-candidate]')];
    controls.forEach(item => { item.disabled = true; }); control.textContent = 'Checking…';
    const progress = connectionProgress(`Checking ${candidate.name}…`, 'Reading its public identity and connection options. No account access is granted.');
    content.querySelector('.form-error')?.remove(); content.prepend(progress);
    try {
      const result = await api('/api/catalog/select', { candidateId: candidate.id });
      if (!dialog.open || !content.isConnected) return;
      if (!result.app) throw new Error(result.message || 'This listing could not be established as an application.');
      await showResolvedApplication(result, { build: true });
    } catch (error) {
      if (!dialog.open || !content.isConnected) return;
      content.prepend(el('div', { class: 'form-error', role: 'alert' }, error.message));
    } finally { progress.remove(); controls.forEach(item => { item.disabled = false; }); control.textContent = 'Choose'; }
  }, 'secondary small', { 'data-directory-candidate': candidate.id, 'aria-label': `Choose ${candidate.name}` });
  return el('div', { class: 'settings-row directory-candidate' }, identity, description, choose);
}

async function showResolvedApplication(result, { build = false } = {}) {
  dialog.close(); search = ''; await refresh(); await openConnector(result.app.id, { discover: !build });
  if (build) await buildConnector(result.app.id);
  else if (result.created) notify(`${result.app.name} found. Choose Connect to approve access.`);
}

function connectionProgress(title, description) {
  return el('div', { class: 'connection-progress', role: 'status', 'aria-live': 'polite', 'aria-busy': 'true' }, el('span', { class: 'progress-indicator', 'aria-hidden': 'true' }), el('div', {}, el('strong', {}, title), description ? el('p', { class: 'small-copy muted' }, description) : null));
}

function websiteDialog(query = '') {
  const website = el('input', { type: 'text', required: true, placeholder: 'app.example.com', autocomplete: 'url', inputmode: 'url', 'aria-label': 'Application website', value: /^[\w-]+\.[\w.-]+/.test(query) || query.startsWith('https://') ? query : '' });
  const form = el('form', {}, field('Website', website, 'Use the website you normally sign into. We use this exact address, not a guessed company name.'), el('p', { class: 'small-copy muted' }, 'Fabric checks the public website for its name and icon, then shows the available connection. Your account is not accessed until you approve.'), actions(cancel(), button('Find connection', null, '', { type: 'submit' })));
  submitForm(form, async () => {
    const result = await api('/api/resolve', { query: website.value.trim() });
    if (!result.app) throw new Error(result.message || 'Enter the application’s website.');
    await showResolvedApplication(result, { build: !!result.created });
  });
  openDialog(query && !website.value ? `Find ${query}` : 'Connect a website', 'An exact website lets Fabric find the real application.', form);
}

async function savedBrowserConsentDialog(app) {
  const content = el('div', { class: 'connect-flow' }, connectionProgress('Checking Fabric browser…', 'No session has been created.'));
  openDialog(`Connect ${app.name}`, 'Use a dedicated browser session on this computer.', content);
  let availability;
  try { availability = await api('/api/session-browser'); }
  catch (error) { availability = { available: false, error: error.message }; }
  if (!dialog.open || !content.isConnected) return;
  const feedback = el('div', { role: 'status', 'aria-live': 'polite' });
  const otherWays = el('details', { class: 'connector-advanced' }, el('summary', {}, 'Other ways to connect'), el('div', { class: 'connector-advanced-body' }, button('Use the existing browser helper', () => startConnection(app, 'browser', { forceNew: true, helperOnly: true }), 'secondary small'), ['gmail', 'google-calendar'].includes(app.id) ? button('Use Google account authorization', () => startConnection(app, 'oauth', { forceNew: true }), 'secondary small') : null));
  let busy = false;
  const connect = button('Connect with Fabric browser', async () => {
    if (busy || !dialog.open || !content.isConnected) return;
    busy = true; connect.disabled = true; connect.textContent = 'Opening sign-in window…';
    feedback.replaceChildren();
    try {
      const result = await api('/api/session-browser/connect', { appId: app.id, consent: true });
      if (!result.connection?.id || result.connection.appId !== app.id || !isPersistentBrowser(result.connection)) throw new Error('The runtime did not confirm a saved browser session.');
      await refresh();
      if (!dialog.open || !content.isConnected) { notify('Browser session saved. Open the app’s connection settings to continue sign-in.'); return; }
      content.replaceChildren(browserPairingComplete(app, result.connection.id, result.connection));
    } catch (error) {
      if (dialog.open && content.isConnected) feedback.replaceChildren(el('div', { class: 'form-error', role: 'alert' }, error.message));
    } finally {
      busy = false; connect.disabled = false; connect.textContent = 'Connect with Fabric browser';
    }
  }, '', { disabled: !availability.available });
  content.replaceChildren(el('div', { class: 'connection-identity' }, appIcon(app), el('strong', {}, app.name)),
    el('p', { class: 'small-copy' }, `Sign in on ${app.name}’s real website in a dedicated Fabric browser window. No extension or developer account is needed for this route.`),
    el('ul', { class: 'small-copy' }, el('li', {}, 'The dedicated local session, including saved sign-in data, stays on this computer until you Disconnect.'), el('li', {}, 'This first version is read-only. Page access defaults to Ask for each request; no account content is read automatically in the background.'), el('li', {}, 'Your computer and local Fabric runtime must be running. The app may ask you to sign in again.')),
    el('p', { class: 'small-copy muted' }, 'Connecting saves a browser session; it does not verify your account identity or grant access to everything in the account.'),
    ...(!availability.available ? [note(`Fabric browser is unavailable: ${availability.error || 'A supported local browser could not be found.'} No session has been created.`, 'warn')] : []),
    feedback, actions(cancel(), ...(availability.available ? [connect] : [])), otherWays);
}

async function openSavedBrowser(connection, control) {
  if (!isPersistentBrowser(connection) || connection.status === 'revoked' || control?.disabled) return;
  const label = control?.textContent;
  if (control) { control.disabled = true; control.textContent = 'Opening…'; }
  try {
    const result = await api(`/api/session-browser/${encodeURIComponent(connection.id)}/open`, {});
    if (result.connection?.id !== connection.id || !isPersistentBrowser(result.connection)) throw new Error('The runtime did not confirm this saved browser session.');
    await refresh(); await loadConnector(connection.appId);
    notify('Sign in on the application’s website if needed. No page content has been read.');
  } catch (error) { notify(error.message, true); }
  finally { if (control) { control.disabled = false; control.textContent = label; } }
}

async function startConnection(app, method, { forceNew = false, helperOnly = false, savedBrowser = false } = {}) {
  const webApp = (app.webOrigins || app.browserOrigins || []).length > 0;
  if (savedBrowser && !helperOnly && (!method || method === 'browser') && webApp) { await savedBrowserConsentDialog(app); return; }
  const existing = rows('connections').filter(connection => connection.appId === app.id && connection.driver === 'browser' && (connection.transport || 'helper') === 'helper' && connection.status !== 'revoked');
  if (!forceNew && existing.length && (!method || method === 'browser')) { existingBrowserDialog(app, existing); return; }
  if (!method && webApp) method = 'browser';
  const content = el('div', { class: 'connect-flow' }, el('div', { class: 'connection-identity' }, appIcon(app), el('strong', {}, app.name)), connectionProgress('Checking how to connect…', 'Finding a supported path. No task is being run.'));
  openDialog(`Connect ${app.name}`, 'You approve access before Fabric can use this connection.', content);
  try {
    const result = await api('/api/connect/start', { appId: app.id, ...(method ? { method } : {}) });
    if (!dialog.open || !content.isConnected) return;
    if (result.kind === 'connected') {
      content.replaceChildren(result.connection?.driver === 'browser' ? browserPairingComplete(app, result.connection.id) : connectionSuccess(app, result.connection?.id, result.connection?.driver === 'device' ? 'Device connected' : 'Connected'));
      await refresh(); return;
    }
    if (result.kind === 'oauth') {
      const url = new URL(result.authorizationUrl);
      if (url.protocol !== 'https:' || url.username || url.password) throw new Error('The authorization address is not valid.');
      content.replaceChildren(el('div', { class: 'connection-identity' }, appIcon(app), el('strong', {}, app.name)), el('p', { class: 'small-copy' }, `Continue securely on ${url.hostname}. Review the permissions there, then return to Fabric.`), actions(cancel(), button('Continue to sign in', () => location.assign(url.href), '')));
      return;
    }
    if (result.kind === 'browser' && result.pairing) { await browserConnectionDialog(app, result, content); return; }
    content.replaceChildren(note(result.message || result.reason || 'No supported connection is available yet for this application.', 'warn'), el('p', { class: 'small-copy muted' }, 'No account has been connected. Fabric cannot grant access on behalf of the application.'), actions(button('Close', () => dialog.close())));
  } catch (error) {
    if (dialog.open && content.isConnected) content.replaceChildren(note(error.message, 'error'), actions(button('Close', () => dialog.close()), button('Try again', () => startConnection(app, method, { forceNew, helperOnly, savedBrowser }), '')));
  }
}

function connectionSuccess(app, connectionId, label = 'Connected') {
  return el('div', { class: 'connection-success', role: 'status', 'aria-live': 'polite' }, el('span', { class: 'connection-success-mark', 'aria-hidden': 'true' }, '✓'), el('h3', {}, label), el('p', { class: 'small-copy muted' }, 'Review the supported actions and decide which permissions to allow. No task has been run through this connection yet.'), actions(button('Review permissions', async () => { dialog.close(); await refresh(); await openConnector(app.id); if (connectionId) selectedAccountId = connectionId; renderConnector(); }, '', { 'data-pair-complete': '' })));
}

function browserEvidenceSummary(connection) {
  const evidence = browserConnectionState(connection);
  const attempt = connection.browserEvidence?.page?.lastAttempt;
  const persistent = isPersistentBrowser(connection);
  const durable = isDurableBrowser(connection);
  return el('div', { class: 'small-copy' },
    el('p', {}, el('strong', {}, evidence.label), evidence.lastHeartbeatAt ? ` · Last ${persistent ? 'browser check' : 'helper response'} ${date(evidence.lastHeartbeatAt)}` : persistent ? '' : '. No helper response has been observed yet.'),
    persistent ? el('p', { class: 'muted' }, evidence.canTest ? 'Test page access to request a read. After your approval, Fabric reopens the saved session if needed. Keep this computer and Fabric running; the app may ask you to sign in again.' : 'Check the browser status before requesting a read. Your session is retained locally until Disconnect. No page is being read in the background.') : durable ? el('p', { class: 'muted' }, evidence.canTest ? 'No app tab needs to stay open. An approved read opens a temporary tab when needed. Keep Chrome or Edge, the helper, and Fabric running. No page is being read in the background.' : 'Your saved app access remains until Disconnect. Open Chrome or Edge with the helper enabled and keep Fabric running, then choose Check helper. An app tab does not need to stay open.') : !evidence.canTest ? note('Keep the paired app tab open in Chrome or Edge, with the Fabric helper enabled and this local runtime running. Then choose Check helper. No page is being read in the background.', 'warn') : el('p', { class: 'muted' }, 'The local runtime can reach the paired helper. You can request a page read from this preview; no helper installation is needed here.'),
    durable ? el('p', { class: 'small-copy muted' }, 'Sign in on the app’s normal website using this browser profile if needed. The site controls sign-in expiry. Fabric does not export your passwords or sign-in tokens.') : null,
    el('p', {}, el('strong', {}, evidence.pageLabel), evidence.observedAt ? ` · ${date(evidence.observedAt)}` : ''),
    attempt && ['failed', 'timed_out', 'cancelled'].includes(attempt.status) ? el('p', { class: 'small-copy muted' }, `Last page-read attempt ${humanize(attempt.status).toLowerCase()} ${date(attempt.at)}. No new page access was confirmed.`) : null,
    el('p', { class: 'small-copy muted' }, 'Account identity: not verified. Saving or pairing a browser session does not prove a signed-in account; a page read only observes that page.')
  );
}

function connectionLifetime(connection) {
  const lifecycle = connection.lifecycle;
  if (!lifecycle) return null;
  const browser = connection.driver === 'browser';
  return el('details', { class: 'connector-advanced' }, el('summary', {}, 'Connection lifetime and health'), el('div', { class: 'connector-advanced-body small-copy' },
    isPersistentBrowser(connection) ? el('p', {}, 'Saved browser session: kept on this computer until Disconnect. Disconnect removes its local saved sign-in data; it does not guarantee logout from the provider on other devices.') : null,
    isDurableBrowser(connection) ? el('p', {}, 'Saved app access lasts until Disconnect and uses the site session in your normal browser profile. Closing an app tab does not remove it. Disconnect removes Fabric’s access, not your website sign-in.') : null,
    el('p', {}, isDurableBrowser(connection) ? 'Keep the browser, helper, and local Fabric runtime running. An approved read can open a temporary app tab on demand.' : lifecycle.requirements || (isPersistentBrowser(connection) ? 'Keep this computer and Fabric running. An approved request reopens the saved browser when needed.' : browser ? 'Keep the paired tab, browser, and local Fabric runtime open.' : 'Provider permissions and connection health still apply.')),
    el('p', {}, browser ? 'No fixed account expiry is known. The application controls how long you stay signed in.' : lifecycle.expiresAt ? `Access expires ${date(lifecycle.expiresAt)}.` : 'No fixed expiry was reported.'),
    lifecycle.renewal ? el('p', {}, lifecycle.renewal) : null,
    el('p', {}, lifecycle.health?.enabled ? `Next runtime health check: ${date(lifecycle.health.nextRunAt)}. These checks do not read page content or verify a browser account.` : 'Automatic health checks are not enabled for this connection.'),
    lifecycle.health?.lastRunAt ? el('p', {}, `Last health check: ${date(lifecycle.health.lastRunAt)}.`) : null
  ));
}

function browserDialogEntry(app, connectionId) {
  const entry = { id: connectionId, current: null, run: null };
  entry.title = el('h3', {}, 'Paired app tab');
  entry.evidence = el('div');
  entry.button = button('Test page access', () => entry.run?.(), '', { disabled: true });
  entry.open = button('Open sign-in window', event => openSavedBrowser(entry.current, event.currentTarget), 'secondary', { hidden: true });
  entry.node = el('section', { class: 'connection-choice' }, entry.title, entry.evidence, actions(entry.open, button('Review connection', async () => { dialog.close(); await refresh(); await openConnector(app.id); selectedAccountId = connectionId; renderConnector(); }), entry.button));
  return entry;
}

function watchBrowserDialog(app, content, entries) {
  if (!dialog.open || !content.isConnected) return;
  stopDialogWork?.();
  let stopped = false, timer, checking = false, sequence = 0, evidenceFresh = true;
  const active = () => !stopped && dialog.open && content.isConnected;
  const stop = () => { stopped = true; sequence++; clearTimeout(timer); };
  stopDialogWork = stop;
  const update = connections => {
    evidenceFresh = true;
    for (const entry of entries) {
      const connection = connections.find(item => item.id === entry.id && item.appId === app.id && item.driver === 'browser') || { id: entry.id, appId: app.id, driver: 'browser', status: 'revoked' };
      // The status projection intentionally omits identity data; retain only the
      // tab label already shown, never previous readiness or page evidence.
      entry.current = { ...connection, label: connection.label || entry.current?.label };
      entry.title.textContent = isPersistentBrowser(entry.current) ? 'Saved browser session' : isDurableBrowser(entry.current) ? 'Saved app access' : entry.current.label || 'Paired app tab';
      entry.open.hidden = !isPersistentBrowser(entry.current);
      entry.evidence.replaceChildren(browserEvidenceSummary(connection));
      entry.button.disabled = checking || !browserConnectionState(connection).canTest;
    }
  };
  const unavailable = error => {
    evidenceFresh = false;
    for (const entry of entries) {
      entry.button.disabled = true;
      entry.evidence.replaceChildren(note(`Browser status could not be refreshed: ${error.message}. No page has been read.`, 'warn'));
    }
  };
  const readEvidence = async () => {
    const request = ++sequence;
    let response;
    try { response = await api('/api/status'); }
    catch (error) { if (!active() || request !== sequence) return false; throw error; }
    if (!active() || request !== sequence) return false;
    if (!Array.isArray(response.connections)) throw new Error('The runtime returned no connection status');
    update(response.connections);
    return true;
  };
  for (const entry of entries) entry.run = async () => {
    if (!active() || checking) return;
    checking = true; entries.forEach(item => { item.button.disabled = true; });
    entry.button.textContent = 'Checking browser…';
    try {
      if (!await readEvidence()) return;
      if (!browserConnectionState(entry.current).canTest) return;
      // Fetch only connection metadata here. Page contents still require the read form.
      testPageAccess(entry.current);
    } catch (error) { if (active()) unavailable(error); }
    finally {
      checking = false; entry.button.textContent = 'Test page access';
      if (active()) entries.forEach(item => { item.button.disabled = !evidenceFresh || !browserConnectionState(item.current).canTest; });
    }
  };
  update(rows('connections'));
  const poll = async () => {
    if (!active()) return;
    if (!checking) {
      try { await readEvidence(); }
      catch (error) { if (active()) unavailable(error); }
    }
    if (active()) timer = setTimeout(poll, 2200);
  };
  poll();
}

function existingBrowserDialog(app, connections) {
  const entries = connections.map(connection => browserDialogEntry(app, connection.id));
  const legacy = connections.some(connection => !isPersistentBrowser(connection) && !isDurableBrowser(connection));
  const content = el('div', { class: 'connect-flow' }, el('p', { class: 'small-copy' }, connections.some(isDurableBrowser) ? 'Fabric has saved access for this app in your browser profile. No app tab needs to stay open. Request a read here; each request asks for approval.' : connections.some(isPersistentBrowser) ? 'Fabric already has a saved browser session for this app. Request a page read from here; it reopens after approval if needed. Open the sign-in window if the app needs you to sign in again.' : 'Fabric already has a paired browser tab for this app. You can use it from this preview; you do not need to install the helper here.'), entries.map(entry => entry.node), legacy ? el('p', { class: 'small-copy muted' }, 'Tab-only access stays unchanged. Upgrade requires a new approval for on-demand access.') : null, actions(button('Close', () => dialog.close()), button(legacy ? 'Upgrade to on-demand access' : 'Add another browser session', () => startConnection(app, 'browser', { forceNew: true, helperOnly: true }), 'secondary')));
  openDialog(`${app.name}: browser sessions`, 'A browser session is not a verified provider account.', content);
  watchBrowserDialog(app, content, entries);
}

function browserPairingComplete(app, connectionId, connection) {
  connection ||= rows('connections').find(item => item.id === connectionId);
  const entry = browserDialogEntry(app, connectionId);
  const content = el('div', { class: 'connect-flow' }, el('h3', {}, isPersistentBrowser(connection) ? 'Saved browser session' : isDurableBrowser(connection) ? 'Saved app access' : 'Browser tab paired'), isDurableBrowser(connection) ? el('p', { class: 'small-copy' }, 'Access is saved for this app until Disconnect. If sign-in is needed, use the app’s normal website in this browser profile. Saving access has not read any page or verified an account.') : isPersistentBrowser(connection) ? el('p', { class: 'small-copy' }, 'Continue sign-in in the browser window. Saving the session does not verify your account; no account content has been read.') : null, entry.node);
  queueMicrotask(() => watchBrowserDialog(app, content, [entry]));
  return content;
}
const providerName = option => typeof option.label === 'string' ? option.label.replace(/^Sign in with /, '') : 'the provider';
// Sign-in for providers on the reviewed auth engine. The server names the start route and the
// only authorization origin the browser may be sent to; anything else is refused.
function providerConsentDialog(app, option) {
  const provider = providerName(option), providerId = option.id.replace(/-oauth$/, '');
  const form = el('form', {}, el('p', { class: 'small-copy' }, `Choose your account securely with ${provider}. Fabric never asks for your ${provider} password.`));
  form.append(actions(cancel(), button(`Continue with ${provider}`, null, '', { type: 'submit' })));
  submitForm(form, async () => {
    const result = await api(option.action.path, option.action.body);
    const url = new URL(result.authorizationUrl), expected = state.settings?.oauthProviders?.[providerId]?.authorizationOrigin;
    if (url.protocol !== 'https:' || !expected || url.origin !== expected) throw new Error('Unexpected authorization destination.');
    location.assign(url.href);
  });
  openDialog(`Add ${app.name} account`, 'You stay in control of the permissions you grant.', form);
}
function googleConsentDialog(app) { signInDialog(app, { add: { providerId: 'google', body: { appId: app.id } } }); }
// A new account, or Add access on one (F10.7): what the sign-in asks for, then that provider's own page. Only the provider's
// authorization origin the server names is ever opened.
function signInDialog(app, { connection, add }) {
  const providerId = add.providerId, provider = state.settings?.oauthProviders?.[providerId], name = provider?.name || 'the provider';
  const scopes = Array.isArray(add.body.scopes) ? add.body.scopes.filter(scope => typeof scope === 'string') : [];
  const asks = scopes.length ? el('details', {}, el('summary', {}, 'Requested provider permission'), el('pre', {}, scopes.join('\n')))
    : note(`${provider?.consentMode === 'required' ? `Sign-in asks ${name} for what this app needs to work.` : `Sign-in asks ${name} for full access to this app.`} You control each operation here.`);
  // Under a full consent policy an Add at the full level asks for the whole level besides the scopes it names (lib/providers/oauth2.mjs signInScopes()).
  const whole = scopes.length && add.body.level === 'full' && provider?.consentMode === 'full' ? note(`Sign-in also asks ${name} for the rest of full access to this app.`) : null;
  const form = el('form', {}, el('p', { class: 'small-copy' }, connection ? `Add the required ${app.name} access to ${connection.identity?.email || connection.label}. ${name} will show the permissions before you decide.` : `Choose your account securely with ${name}. Fabric never asks for your ${name} password.`), asks, whole);
  const ready = providerId === 'google' ? state.settings?.googleOAuthConfigured === true : provider?.available === true;
  if (!ready) form.append(note(`${name} sign-in is not ready on this Fabric installation. This is setup for the Fabric owner, not a credential you need to find. No account has been connected.`, 'warn'));
  // T7 (F10.4): access that would turn permissions on at Allow is shown first, and continuing again confirms that list (its etag).
  let upgrade = null, buttons = actions(cancel(), button(connection ? 'Continue to add access' : `Continue with ${name}`, null, '', { type: 'submit', disabled: !ready }));
  const card = el('div', { class: 'inline-note warn', role: 'status', hidden: true });
  form.append(card, buttons);
  submitForm(form, async () => {
    let result;
    try { result = await api(`/api/oauth/${encodeURIComponent(providerId)}/start`, { ...add.body, ...(upgrade ? { confirmRows: upgrade.etag } : {}) }); }
    catch (error) {
      if (error.code !== 'confirm_required' || !Array.isArray(error.details?.upgrade?.rows)) throw error;
      upgrade = error.details.upgrade; card.replaceChildren(cardText(upgrade)); card.hidden = false;
      const next = actions(cancel(), button('Confirm and continue', null, '', { type: 'submit' })); buttons.replaceWith(next); buttons = next;
      return;
    }
    const url = new URL(result.authorizationUrl), expected = provider?.authorizationOrigin;
    if (url.protocol !== 'https:' || !expected || url.origin !== expected) throw new Error('Unexpected authorization destination.');
    location.assign(url.href);
  });
  openDialog(connection ? 'Add account access' : `Add ${app.name} account`, 'You stay in control of the permissions you grant.', form);
}
async function openLocal(keepConnector = false) {
  try { await api('/api/connections/local', {}); await refresh(); if (keepConnector === true) await openConnector('workspace'); else navigate('connections'); notify('Local workspace connected. File access is restricted to the dedicated Fabric workspace.'); }
  catch (error) { notify(error.message, true); }
}

function openDialog(title, description, content, { returnFocus } = {}) {
  stopDialogWork?.(); stopDialogWork = null;
  if (!dialog.open) dialogReturnFocus = returnFocus || document.activeElement;
  dialog.classList.toggle('connection-sheet', !!content.classList?.contains('connect-flow'));
  document.querySelector('#dialog-content').replaceChildren(el('div', { class: 'dialog-header' }, el('div', {}, el('h2', { id: 'dialog-title', tabindex: '-1' }, title), el('p', { id: 'dialog-description' }, description)), el('button', { class: 'close-button', type: 'button', 'aria-label': 'Close dialog', onclick: () => dialog.close() }, '×')), el('div', { class: 'dialog-body' }, content));
  if (!dialog.open) dialog.showModal();
  requestAnimationFrame(() => {
    if (dialog.open && content.isConnected) (content.querySelector('input:not([type=hidden]):not([disabled]),textarea:not([disabled]),select:not([disabled])') || dialog.querySelector('#dialog-title'))?.focus({ preventScroll: true });
  });
}
function field(label, control, help) { return el('label', { class: 'field' }, label, control, help ? el('span', { class: 'field-help' }, help) : null); }
function select(items, placeholder, selected) { const node = el('select', {}, placeholder ? el('option', { value: '' }, placeholder) : null, items.map(([value, label]) => el('option', { value }, label))); if (selected !== undefined) node.value = selected; return node; }
function parseJson(value, label = 'JSON') { try { return JSON.parse(value); } catch { throw new Error(`${label} must be valid JSON. Check quotes, commas, and brackets.`); } }
function actions(...buttons) { return el('div', { class: 'dialog-actions' }, buttons); }
function cancel() { return button('Cancel', () => dialog.close()); }
function submitForm(form, work) {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    form.querySelector('.form-error')?.remove();
    const submit = form.querySelector('button[type="submit"]');
    const label = submit?.textContent;
    if (submit) { submit.disabled = true; submit.textContent = 'Working…'; }
    try { await work(event); }
    catch (error) { const alert = el('div', { class: 'form-error', role: 'alert' }, error.message); form.prepend(alert); alert.scrollIntoView({ block: 'nearest' }); }
    finally { if (submit) { submit.disabled = false; submit.textContent = label; } }
  });
}
function connectionChoices(app) {
  const options = (app.connectionOptions || []).filter(option => option.kind === 'consumer');
  const content = el('div', { class: 'connect-choices' });
  const descriptions = {
    oauth: 'Choose your account on Google’s own sign-in page, then review the access you want to allow.',
    browser: 'Use the app in Chrome or Edge. The Fabric helper supports page inspection and individually approved clicks or text entry.',
    workspace: 'Use Fabric’s dedicated local folder. Other files on your computer remain outside this connection.'
  };
  for (const option of [...options].sort((a, b) => Number(b.recommended) - Number(a.recommended))) {
    const card = el('section', { class: 'connection-choice', 'data-connection-method': option.method }, el('h3', {}, option.label), el('p', { class: 'small-copy muted' }, option.method === 'oauth' && option.id !== 'google-oauth' ? option.description : descriptions[option.method] || 'This connection method is not ready yet.'));
    const google = option.id === 'google-oauth', provider = providerName(option);
    if (option.enabled) {
      const action = option.method === 'oauth' ? () => google ? googleConsentDialog(app) : providerConsentDialog(app, option) : option.method === 'browser' ? () => browserConnectionDialog(app) : option.method === 'workspace' ? async () => { await openLocal(true); dialog.close(); } : null;
      if (action) card.append(button(option.method === 'oauth' ? `Continue with ${provider}` : option.method === 'browser' ? 'Set up browser connection' : 'Connect folder', action, '', { 'data-choose-method': option.method }));
    } else card.append(note(option.method === 'oauth' && option.availability === 'unavailable' && option.setupReason ? option.setupReason : option.method === 'oauth' ? 'Sign-in is not ready on this Fabric installation. The Fabric owner needs to enable it; you do not need to find a secret or create a developer account.' : 'This connection method is not available in this version.', 'warn'));
    content.append(card);
  }
  if (!options.length) content.append(note('Easy connection is not available for this app yet.', 'warn'), el('p', { class: 'small-copy' }, 'Fabric needs a supported sign-in, browser, or desktop connection method first. You do not need to find a secret key. Registering an app does not connect its account.'));
  content.append(el('p', { class: 'small-copy muted' }, 'Browser access and direct account access are different. Fabric will show only the actions supported by the connection you choose.'), actions(cancel()));
  openDialog(`Connect ${app.name}`, 'Sign in with the app, or use it in your browser. No developer credentials needed for these options.', content);
}

function copyButton(label, value) {
  const control = button(label, async () => {
    try { await navigator.clipboard.writeText(value); control.textContent = 'Copied'; }
    catch { notify('Copy was unavailable. Select the displayed text and copy it manually.', true); }
  }, 'secondary small');
  return control;
}

async function browserConnectionDialog(app, result, host) {
  if (!result?.pairing) { await startConnection(app, 'browser'); return; }
  const content = host;
  const pairing = result.pairing;
  const durable = pairing.bridgeVersion === '0.3' && pairing.sessionScope === 'browser-profile';
  const requiredVersion = pairing.bridgeVersion === '0.3' ? '0.3' : '0.2';
  let helper;
  try {
    helper = await requestBrowserBridge('ping');
    if (!dialog.open || !content.isConnected) return;
    if (!['0.2', '0.3'].includes(helper.version) || (requiredVersion === '0.3' && helper.version !== '0.3')) throw new Error('Update the Fabric browser helper, then reload this page.');
  } catch (error) {
    if (!dialog.open || !content.isConnected) return;
    await browserHelperSetup(app, content, { requiredVersion, updateRequired: !!helper?.version });
    return;
  }
  const origin = result.origin || pairing.origin || app.webOrigins?.[0] || app.browserOrigins?.[0];
  content.replaceChildren(el('div', { class: 'connection-identity' }, appIcon(app), el('strong', {}, app.name)), el('p', { class: 'small-copy' }, durable ? `Save access for ${origin || app.name} in your normal browser profile until Disconnect. No app tab needs to stay open. Each approved read can open a temporary tab; Chrome or Edge and Fabric must be running.` : `The helper will open ${app.name} in your normal browser after you approve. Your Chrome or Edge profile keeps its sign-in session. Sign in there normally if needed; Fabric does not receive your password.`), ...(durable ? [el('p', { class: 'small-copy muted' }, 'Sign in separately on the app’s normal website if needed. The site session stays in your browser profile; Fabric does not export passwords or sign-in tokens. Saving access does not verify your account.')] : []), note(durable ? 'Each read and individual browser change asks for approval. A change uses a recent page inspection; if that page closes, inspect again. Nothing reads your account in the background.' : 'Fabric can inspect this tab and propose individual clicks or text entry. You approve each browser change before it runs. It cannot control the desktop app or bypass the app’s own permissions.'), actions(cancel(), button('Continue in browser', async event => {
    const control = event.currentTarget; control.disabled = true; control.textContent = 'Opening approval…';
    try {
      const handoff = await requestBrowserBridge('connect', { pairing }, { timeoutMs: 8000 });
      if (!dialog.open || !content.isConnected) return;
      if (!handoff.confirmationOpened || handoff.pairingId !== pairing.pairingId) throw new Error('The browser did not confirm the expected connection request.');
      waitForBrowserPair(app, pairing, content);
    } catch (error) {
      if (!dialog.open || !content.isConnected) return;
      content.querySelector('.form-error')?.remove(); content.prepend(el('div', { class: 'form-error', role: 'alert' }, error.message));
      control.disabled = false; control.textContent = 'Continue in browser';
    }
  }, '', { 'data-start-pair': app.id })));
}

async function browserHelperSetup(app, content, { requiredVersion = '0.2', updateRequired = false } = {}) {
  stopDialogWork?.();
  let stopped = false, timer, busy = false;
  const stop = () => { stopped = true; clearTimeout(timer); };
  stopDialogWork = stop;
  const active = () => !stopped && dialog.open && content.isConnected;
  content.replaceChildren(connectionProgress('Preparing browser setup…', 'Nothing is connected yet.'));
  let setup;
  try { setup = await api('/api/browser-setup'); }
  catch (error) {
    if (active()) content.replaceChildren(el('div', { class: 'form-error', role: 'alert' }, error.message), actions(button('Close', () => dialog.close()), button('Try setup again', () => browserHelperSetup(app, content, { requiredVersion, updateRequired }), '')));
    return;
  }
  if (!active()) return;
  const browsers = (Array.isArray(setup.browsers) ? setup.browsers : []).filter(browser => ['chrome', 'edge'].includes(browser.id) && browser.installed === true);
  const address = `${location.origin}/#connectors/${encodeURIComponent(app.id)}`;
  if (!setup.supported || !setup.extensionAvailable || !browsers.length) {
    const reason = !setup.supported ? (setup.reason || 'Automatic browser setup is unavailable on this Fabric installation.') : !setup.extensionAvailable ? 'The Fabric helper folder is missing. Restore it before continuing.' : 'Install Chrome or Edge on this computer, then return here.';
    content.replaceChildren(el('h3', {}, 'A browser helper is needed'), note(reason, 'warn'), el('p', { class: 'small-copy' }, 'This prototype uses a one-time Chrome or Edge extension installation. Nothing is connected yet.'), el('div', { class: 'copyable-address' }, el('code', {}, address), copyButton('Copy Fabric link', address)), actions(button('Close', () => dialog.close()), button('Check setup again', () => browserHelperSetup(app, content, { requiredVersion, updateRequired }), '')));
    return;
  }
  const userAgent = navigator.userAgent || '';
  const currentBrowser = /Edg\//.test(userAgent) ? 'edge' : /Chrome\//.test(userAgent) && !/Electron|Codex/i.test(userAgent) ? 'chrome' : null;
  const chooser = select(browsers.map(browser => [browser.id, browser.name]), null, browsers.some(browser => browser.id === currentBrowser) ? currentBrowser : browsers[0].id);
  const selectedBrowser = () => browsers.find(browser => browser.id === chooser.value) || browsers[0];
  const status = el('p', { class: 'small-copy muted', role: 'status', 'aria-live': 'polite' }, 'Checking this browser only. A newly installed helper needs a page reload.');
  const feedback = el('div', { class: 'small-copy', role: 'status', 'aria-live': 'polite' });
  const controls = [];
  const runSetup = async (action, control) => {
    if (busy || !active()) return;
    busy = true;
    const browser = selectedBrowser();
    const label = control.textContent;
    controls.forEach(item => { item.disabled = true; }); chooser.disabled = true;
    control.textContent = 'Opening…'; feedback.replaceChildren();
    try {
      const result = await api('/api/browser-setup', { action, browser: browser.id, appId: app.id });
      if (!active()) return;
      if (result?.opened !== true) throw new Error('Fabric could not confirm that the setup window was requested. Nothing was installed or connected.');
      feedback.textContent = action === 'open-fabric' ? `Requested Fabric in ${browser.name}. Continue in that window and select Connect. This preview cannot detect a helper installed in another browser.` : action === 'open-extensions' ? `Requested ${browser.name} extension settings. Enable Developer mode, then choose Load unpacked.` : 'Requested the helper folder in your file manager. Use that folder in Load unpacked.';
    } catch (error) {
      if (active()) feedback.replaceChildren(el('div', { class: 'form-error', role: 'alert' }, error.message));
    } finally {
      busy = false; control.textContent = label;
      controls.forEach(item => { item.disabled = false; }); chooser.disabled = false;
    }
  };
  const openFabric = button(`Open Fabric in ${selectedBrowser().name}`, event => runSetup('open-fabric', event.currentTarget), '');
  const openExtensions = button('Open extension settings', event => runSetup('open-extensions', event.currentTarget));
  const showFolder = button('Show helper folder', event => runSetup('reveal-extension', event.currentTarget));
  const reload = button('Reload and continue', () => {
    if (busy || !active()) return;
    try {
      sessionStorage.setItem('fabric.browser-setup-resume', JSON.stringify({ appId: app.id, createdAt: Date.now() }));
      history.replaceState(null, '', `${location.pathname}${location.search}#connectors/${encodeURIComponent(app.id)}`);
      reload.disabled = true; stop(); location.reload();
    } catch {
      feedback.replaceChildren(el('div', { class: 'form-error', role: 'alert' }, 'This browser could not save setup progress. Reload Fabric manually, then select Connect again.'));
    }
  });
  controls.push(openFabric, openExtensions, showFolder, reload);
  chooser.addEventListener('change', () => { openFabric.textContent = `Open Fabric in ${selectedBrowser().name}`; });
  const directory = typeof setup.directory === 'string' ? setup.directory : '';
  const folderHelp = el('details', { class: 'browser-install' }, el('summary', {}, setup.platform === 'darwin' ? 'Can’t find the folder? Press ⌘⇧G' : 'Can’t find the folder? Copy its path'), el('p', { class: 'small-copy' }, setup.platform === 'darwin' ? 'In the folder picker, press ⌘⇧G (Command–Shift–G), paste the copied folder path, press Return, then Select.' : 'In the folder picker, paste the copied folder path into the location field, then select that folder.'), directory ? el('div', { class: 'extension-path' }, el('code', {}, directory), copyButton('Copy folder path', directory)) : note('The runtime did not return the helper folder path.', 'warn'));
  content.replaceChildren(
    el('div', { class: 'helper-install-heading' }, el('h3', {}, updateRequired ? 'Update the browser helper' : 'Set up the browser helper once')),
    el('p', { class: 'small-copy' }, updateRequired ? 'On-demand access needs helper 0.3. Reload the updated Fabric helper in extension settings, then reload this page. Existing tab-only permissions remain unchanged; new access still needs your approval.' : 'A one-time prototype installation in Chrome or Edge. Safari, this in-app preview, and desktop apps cannot use the helper. No account is connected yet.'),
    browsers.length > 1 ? field('Use this browser', chooser) : el('p', { class: 'small-copy' }, `Available on this computer: ${selectedBrowser().name}.`),
    openFabric,
    el('ol', { class: 'small-copy setup-steps' }, el('li', {}, 'Open extension settings and enable Developer mode.'), el('li', {}, updateRequired ? 'Choose Reload on Fabric’s extension card. If it is missing, use Load unpacked and select the Fabric helper folder.' : 'Choose Load unpacked, then select the Fabric helper folder.')),
    el('div', { class: 'head-actions' }, openExtensions, showFolder), folderHelp, feedback,
    el('p', { class: 'small-copy muted' }, 'Installed here? Reload below. Opened another browser? Continue there. You will review access before approving; opening a window grants no access.'),
    status, actions(button('Close', () => dialog.close()), reload)
  );
  const poll = async () => {
    if (!active()) return;
    try {
      const helper = await requestBrowserBridge('ping', {}, { timeoutMs: 1200 });
      if (!active()) return;
      if (helper.version === '0.3' || (requiredVersion === '0.2' && helper.version === '0.2')) {
        stop();
        content.replaceChildren(connectionProgress('Helper detected', 'Preparing a new approval request. No account is connected yet.'));
        await startConnection(app, 'browser', { forceNew: true, helperOnly: true });
        return;
      }
      status.textContent = 'Update the Fabric helper to the current version, then reload this browser tab.';
    } catch { /* Missing helper is expected until installation finishes in this browser. */ }
    if (active()) timer = setTimeout(poll, 2200);
  };
  poll();
}

async function resumeBrowserSetup() {
  let pending;
  try {
    const saved = sessionStorage.getItem('fabric.browser-setup-resume');
    sessionStorage.removeItem('fabric.browser-setup-resume');
    pending = saved ? JSON.parse(saved) : null;
  } catch { return; }
  if (!pending || pending.appId !== selectedAppId || !Number.isFinite(pending.createdAt) || Date.now() - pending.createdAt < 0 || Date.now() - pending.createdAt > 300000) return;
  const app = appById(pending.appId);
  if (app) await startConnection(app, 'browser', { forceNew: true, helperOnly: true });
}

function waitForBrowserPair(app, pairing, content) {
  const status = el('p', { class: 'small-copy', role: 'status', 'aria-live': 'polite' }, 'Approve the connection in the helper page that just opened. Nothing is connected yet.');
  content.replaceChildren(el('div', { class: 'connection-identity' }, appIcon(app), el('strong', {}, app.name)), el('ol', { class: 'connect-progress-steps' }, el('li', { class: 'complete' }, 'Application found'), el('li', { class: 'current' }, 'Approve in your browser'), el('li', {}, 'Review your permissions')), status, actions(button('Close', () => dialog.close())));
  let stopped = false, timer;
  stopDialogWork = () => { stopped = true; clearTimeout(timer); };
  const poll = async () => {
    if (stopped || !dialog.open || !content.isConnected) return;
    try {
      const progress = await api(`/api/pair/${encodeURIComponent(pairing.pairingId)}/status`);
      if (stopped || !content.isConnected) return;
      if (progress.status === 'paired') { stopped = true; await refresh(); if (dialog.open && content.isConnected) content.replaceChildren(browserPairingComplete(app, progress.connectionId)); return; }
      if (['expired', 'revoked'].includes(progress.status)) {
        stopped = true; content.replaceChildren(note(progress.status === 'expired' ? 'The connection request expired before approval. Start again when you are ready.' : 'The connection was disconnected.', 'warn'), actions(button('Close', () => dialog.close()), button('Try again', () => startConnection(app, 'browser'), ''))); return;
      }
      status.textContent = 'Approve the connection in the helper page that just opened. Nothing is connected yet.';
    } catch { if (!stopped && content.isConnected) status.textContent = 'The runtime is not responding. Checking the connection again…'; }
    if (!stopped) timer = setTimeout(poll, 1600);
  };
  poll();
}

function connectDialog(app) {
  const id = app.id || app.appId;
  const supplied = methodsFor(app);
  // F10.7: 'oauth' is the Google tab only for Google's own apps; another provider's sign-in is under Connect, never posted to Google.
  const google = ['gmail', 'google-calendar'].includes(id);
  const methods = supplied.map(method => /google|oauth/i.test(method) ? (google ? 'googleOAuth' : null) : /token|key|bearer/i.test(method) ? 'token' : /local|workspace/i.test(method) ? 'local' : method).filter((method, index, array) => ['googleOAuth', 'token', 'browser', 'local'].includes(method) && array.indexOf(method) === index);
  const content = el('div');
  const tabs = el('div', { class: 'method-tabs', role: 'group', 'aria-label': 'Connection method' });
  const body = el('div');
  const showMethod = method => {
    tabs.querySelectorAll('button').forEach(tab => tab.setAttribute('aria-pressed', String(tab.dataset.method === method)));
    if (method === 'local') { body.replaceChildren(note('This gives Fabric access only to its dedicated workspace directory. It does not scan your computer.'), el('pre', {}, state.workspaceRoot || 'Workspace path will be returned by the runtime.'), button('Connect local workspace', async () => { await openLocal(); dialog.close(); }, '')); return; }
    if (method === 'googleOAuth') {
      const form = el('form', {}, note('You will authorize access directly with Google. Fabric does not ask for your Google password. Sign-in asks for full access to this app; your saved per-operation permissions still apply.'));
      if (!state.settings?.googleOAuthConfigured) form.append(note('Google OAuth is not configured in this runtime.', 'warn'), el('p', { class: 'small-copy muted' }, `Create a Google OAuth web client with the ${id === 'gmail' ? 'Gmail' : 'Calendar'} API enabled. Set FABRIC_GOOGLE_CLIENT_ID and FABRIC_GOOGLE_CLIENT_SECRET in the product .env file, set the redirect URI shown below in Google Cloud, then restart Fabric.`), el('pre', {}, state.settings?.googleRedirectUri || `${location.origin}/api/oauth/google/callback`));
      form.append(actions(cancel(), button('Continue with Google ↗', null, '', { type: 'submit', disabled: !state.settings?.googleOAuthConfigured })));
      submitForm(form, async () => { const result = await api('/api/oauth/google/start', { appId: id, level: 'full' }); const url = new URL(result.authorizationUrl); if (url.protocol !== 'https:' || url.hostname !== 'accounts.google.com') throw new Error('The runtime returned an unexpected authorization destination.'); location.assign(url.href); });
      body.replaceChildren(form); return;
    }
    if (method === 'browser') {
      const form = el('form', {}, note('Pair the Fabric browser extension with an application tab you choose. Your sign-in remains in your browser; Fabric does not import cookies or passwords.'), el('p', { class: 'small-copy muted' }, 'Load the extension from the extension folder in this product using your browser’s unpacked-extension developer option. Open the application, sign in there if necessary, then pair that tab.'), actions(cancel(), button('Create pairing code', null, '', { type: 'submit' })));
      submitForm(form, async () => { const result = await api('/api/pair', { appId: id }); body.replaceChildren(note('Waiting for you to pair the application tab. A pairing code is not a connected account.'), el('div', { class: 'pair-code' }, result.code), el('p', { class: 'small-copy' }, result.instructions || 'Open the Fabric extension on the selected application tab, enter this code, and approve the connection.'), el('p', { class: 'small-copy muted' }, `Expires ${date(result.expiresAt)}. The Connections page will show the actual paired state.`), actions(button('View connections', () => { dialog.close(); navigate('connections'); }, ''))); });
      body.replaceChildren(form); return;
    }
    const labelInput = el('input', { name: 'label', type: 'text', placeholder: 'e.g. Personal account', maxlength: '120', autocomplete: 'off' });
    const token = el('input', { name: 'token', type: 'password', required: true, placeholder: 'Paste an access token', autocomplete: 'new-password', spellcheck: 'false' });
    const form = el('form', {}, note('Use a provider-issued token with only the permissions you need. The token is sent to the local runtime and is not stored in browser storage.'), app.tokenHelp ? el('p', { class: 'small-copy muted' }, app.tokenHelp) : null, field('Connection label', labelInput), field('Access token', token, 'Never enter your account password here. Account identity is checked; operation scopes remain provider-controlled.'), actions(cancel(), button('Check and connect', null, '', { type: 'submit' })));
    submitForm(form, async () => { try { const connection = await api('/api/connections', { appId: id, label: labelInput.value, token: token.value }); token.value = ''; await refresh(); dialog.close(); await openConnector(id); notify(`Connection recorded: ${text(connection.status || 'see current state')}.`); } finally { token.value = ''; } });
    body.replaceChildren(form);
  };
  methods.forEach(method => tabs.append(button(({ googleOAuth: 'Provider consent', token: 'Access token', browser: 'Browser session', local: 'Local workspace' })[method], () => showMethod(method), '', { 'data-method': method, 'aria-pressed': 'false' })));
  content.append(tabs, body);
  if (!methods.length) body.append(note('No supported account authorization path is configured for this application yet.', 'warn'), el('p', { class: 'small-copy muted' }, 'You can import its OpenAPI document for review, but importing an interface does not grant account access.'), button('Import a capability source', () => importDialog(id), ''));
  else showMethod(methods[0]);
  if (Array.isArray(app.limitations) && app.limitations.length) content.append(el('details', {}, el('summary', {}, 'Application access limitations'), el('ul', { class: 'small-copy muted' }, app.limitations.map(limitation => el('li', {}, limitation)))));
  openDialog(`${app.name || id}: developer settings`, 'For developers who already manage app credentials. Normal connection options are under Connect.', content);
}

function simpleApplicationDialog(initialName = '') {
  const name = el('input', { type: 'text', required: true, maxlength: '100', value: initialName, placeholder: 'Application name', autocomplete: 'off' });
  const website = el('input', { type: 'url', required: true, placeholder: 'https://app.example.com', autocomplete: 'url' });
  const apiOrigin = el('input', { type: 'url', placeholder: 'https://api.example.com' });
  const source = el('input', { type: 'url', placeholder: 'https://api.example.com/openapi.json' });
  const identity = el('input', { type: 'text', placeholder: '/v1/me' });
  const identityPointer = el('input', { type: 'text', placeholder: '/id', value: '/id' });
  const checkedOrigin = (value, label) => { const url = new URL(value); if (url.protocol !== 'https:' || url.username || url.password) throw new Error(`${label} must be a public HTTPS address without embedded credentials.`); return url.origin; };
  const form = el('form', {}, field('Name', name), field('Application website', website, 'Use the website where you normally open this app.'), note('This adds the application to your catalog. It does not sign you in or grant Fabric access to your account.'), el('details', {}, el('summary', {}, 'Advanced: published API information (optional)'), field('API address', apiOrigin), field('OpenAPI JSON document URL', source, 'A supported published interface lets Fabric discover the declared operations.'), field('Identity check path', identity, 'Required for a bearer-token account connection. Must be a documented GET endpoint.'), field('Identity field', identityPointer, 'JSON pointer to a stable account ID in that response.')), actions(cancel(), button('Add application', null, '', { type: 'submit' })));
  submitForm(form, async () => {
    const webOrigin = checkedOrigin(website.value, 'Application website');
    const apiOrigins = apiOrigin.value.trim() ? [checkedOrigin(apiOrigin.value, 'API address')] : [];
    if (identity.value.trim() && !apiOrigins.length) throw new Error('An API address is needed for an identity check.');
    if (source.value.trim()) checkedOrigin(source.value, 'OpenAPI document');
    const base = name.value.trim().toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50);
    let id = /^[a-z]/.test(base) ? base : `app-${base || 'custom'}`;
    if (id.length < 2) id = `app-${id}`;
    if (appById(id)) id = `${id}-${crypto.randomUUID().slice(0, 6)}`;
    const result = await api('/api/applications', { id, name: name.value.trim(), description: `Application at ${new URL(webOrigin).hostname}`, webOrigins: [webOrigin], apiOrigins, ...(source.value.trim() ? { discovery: { kind: 'openapi', url: source.value.trim() } } : {}), ...(identity.value.trim() ? { identityProbe: { path: identity.value.trim(), idPointer: identityPointer.value.trim() } } : {}) });
    dialog.close(); search = ''; await refresh(); await openConnector(result.id); notify('Application added. Account access has not been granted.');
  });
  openDialog('Add application', 'Start with the app’s name and website.', form);
}
function applicationDialog() {
  const manifest = el('textarea', { class: 'code-input', required: true, spellcheck: 'false', value: pretty({ id: 'my-application', name: 'My application', description: 'Describe the application and intended access.', apiOrigins: ['https://api.example.com'], webOrigins: ['https://app.example.com'], identityProbe: { path: '/v1/me', idPointer: '/id', displayNamePointer: '/name' } }) });
  const approved = el('input', { type: 'checkbox', required: true });
  const form = el('form', {}, note('Extend the catalog with an application manifest. A manifest declares allowed origins and an identity check; it does not grant account access or create executable tools.'), field('Application manifest (JSON)', manifest, 'Use HTTPS origins only. identityProbe is optional, but a bearer-token connection needs a supported GET identity probe that returns a stable account ID. Browser pairing requires webOrigins.'), el('label', { class: 'check-field' }, approved, 'I have checked these application origins and approve adding this manifest to my local catalog.'), actions(cancel(), button('Add to catalog', null, '', { type: 'submit' })));
  submitForm(form, async () => { await api('/api/applications', parseJson(manifest.value, 'Application manifest')); dialog.close(); search = ''; await refresh(); navigate('catalog'); notify('Application manifest added. Choose it to authorize a supported connection.'); });
  openDialog('Add an application', 'The catalog is extensible. Declare the application’s real access surfaces before acquiring its capabilities.', form);
}

function renderConnections() {
  const connections = rows('connections');
  main.replaceChildren(head('Your connections.', 'Authority is explicit. Inspect the real connection state, check access, or revoke a connection at any time.', [button('Connect application', () => navigate('catalog'), '')]), connections.length ? el('div', { class: 'row-list' }, connections.map(connection => el('article', { class: 'record' }, el('span', { class: 'app-icon', 'aria-hidden': 'true' }, appName(connection.appId).slice(0, 2).toUpperCase()), el('div', { class: 'record-content' }, el('h3', {}, connection.label || appName(connection.appId)), el('div', { class: 'record-meta' }, appName(connection.appId), statusBadge(connection.status), badge(connection.authMethod || connection.method || connection.driver || connection.type || 'Authorized connection')), el('p', {}, connection.account?.email || connection.account?.name || connection.identity?.email || connection.identity?.displayName || connection.identity?.name || connection.accountLabel || 'Identity details appear after provider verification.'), el('p', {}, `Last checked ${date(connection.lastCheckedAt || connection.checkedAt || connection.updatedAt)}`), connection.error ? note(text(connection.error), 'error') : null, el('details', {}, el('summary', {}, 'Connection details'), jsonBlock(connection))), el('div', { class: 'record-actions' }, button('Check health', () => connectionAction(connection.id, 'check'), 'secondary small', { disabled: connection.status === 'revoked' }), button('Acquire tools', () => acquireDialog(connection.appId), 'secondary small', { disabled: connection.status === 'revoked' }), button('Revoke', () => revokeDialog(connection), 'danger small', { disabled: connection.status === 'revoked' }))))) : empty('No applications connected yet', 'Choose an application or try the restricted local workspace. A catalog entry alone does not grant account access.', button('Browse catalog', () => navigate('catalog'), '')), el('p', { class: 'footer-note' }, 'A healthy connection is not a promise that every operation is permitted. Provider scopes, expiry, and application behavior still apply.'));
}
async function connectionAction(id, action) { try { await api(`/api/connections/${encodeURIComponent(id)}/${action}`, {}); await refresh(); notify(action === 'check' ? 'Health check completed. See the observed state below.' : 'Connection revoked.'); } catch (error) { notify(error.message, true); } }
function revokeDialog(connection) {
  const persistent = isPersistentBrowser(connection), durable = isDurableBrowser(connection);
  const form = el('form', {}, note(persistent ? 'Disconnect closes this dedicated browser and removes its locally saved sign-in data. You will need to sign in again if you reconnect. This does not guarantee provider logout on other devices.' : durable ? 'Disconnect removes Fabric’s saved access for this app. Your normal browser profile and website sign-in are not deleted or logged out. Reconnecting requires a new approval.' : 'This removes Fabric’s local authority for this connection. Revoke any provider-issued token or consent at the provider too if you want to invalidate it everywhere.', 'warn'), actions(cancel(), button(persistent ? 'Disconnect and remove saved session' : durable ? 'Disconnect saved app access' : 'Revoke connection', null, 'danger', { type: 'submit' })));
  const path = `/api/connections/${encodeURIComponent(connection.id)}/revoke`;
  const done = async result => { dialog.close(); await refresh(); notify(persistent ? 'Disconnected. The local saved browser session was removed.' : durable ? 'Disconnected. Fabric’s saved app access was removed.' : revokedWords(result)); };
  submitForm(form, async () => {
    let result;
    try { result = await api(path, {}); }
    catch (error) {
      // F10.4: Google's revoke removes the whole grant, so the other accounts of it here are named first and nothing has changed.
      if (error.code !== 'confirm_required' || !Array.isArray(error.details?.siblings)) throw error;
      form.replaceChildren(siblingChoice(error, async body => done(await api(path, body))));
      return;
    }
    await done(result);
  });
  openDialog(persistent ? 'Disconnect saved browser session?' : durable ? 'Disconnect saved app access?' : 'Revoke this connection?', connection.label || appName(connection.appId), form);
}
/** What a revoke did, in the server's words, and which other accounts now need a sign-in. */
function revokedWords(result) {
  const affected = (Array.isArray(result?.affected) ? result.affected : []).map(item => appName(item.appId));
  return [result?.message || 'Fabric connection revoked.', affected.length ? `${affected.join(', ')} ${affected.length > 1 ? 'need' : 'needs'} a sign-in again.` : ''].filter(Boolean).join(' ');
}
/** The two answers to a Google revoke that would sign out other accounts here: everywhere (confirmSiblings) or here only (remote: false). */
function siblingChoice(error, send) {
  const failed = el('div', { role: 'alert' });
  const choose = body => async () => { failed.replaceChildren(); try { await send(body); } catch (problem) { failed.replaceChildren(note(problem.message, 'error')); } };
  return el('div', {}, note(error.message, 'warn'),
    el('ul', {}, error.details.siblings.map(item => el('li', {}, `${appName(item.appId)} (${item.displayName || 'this account'})${item.waiting ? ', waiting for your confirmation' : ''}`))), failed,
    actions(cancel(), button('Disconnect here only', choose({ remote: false })), button('Disconnect everywhere', choose({ confirmSiblings: true }), 'danger')));
}

function appSelect(selected) { return select(rows('catalog').map(app => [app.id || app.appId, app.name || app.id]), 'Choose an application', selected); }
function importDialog(selected) {
  const app = appSelect(selected); app.required = true;
  const base = el('input', { type: 'url', required: true, placeholder: 'https://api.example.com', autocomplete: 'off' });
  const source = el('input', { type: 'url', placeholder: 'https://example.com/openapi.json (optional)' });
  const document = el('textarea', { class: 'code-input', required: true, spellcheck: 'false', placeholder: '{ "openapi": "3.1.0", "info": { … }, "paths": { … } }', 'aria-label': 'OpenAPI JSON document' });
  const file = el('input', { type: 'file', accept: '.json,application/json' });
  file.addEventListener('change', async () => { if (file.files?.[0]) { if (file.files[0].size > 2_000_000) { notify('Choose a JSON document smaller than 2 MB.', true); file.value = ''; return; } document.value = await file.files[0].text(); } });
  const approved = el('input', { type: 'checkbox', required: true });
  const loadExample = async id => { try { const example = await api(`/examples/${id}.openapi.json`); document.value = pretty(example); app.value = id; base.value = example.servers?.[0]?.url || ''; source.value = ''; approved.checked = false; } catch (error) { notify(error.message, true); } };
  const samples = el('div', { class: 'method-tabs', role: 'group', 'aria-label': 'Load example interface' }, button('Load GitHub interface', () => loadExample('github')), button('Load Google Calendar interface', () => loadExample('google-calendar')));
  const form = el('form', {}, note('OpenAPI is compiled into declarative candidates, not executable JavaScript. Review each operation before promoting it.'), el('p', { class: 'small-copy muted' }, 'Start with a bundled, hand-authored subset of documented provider endpoints, or supply your own schema. These examples are not official provider specifications or connected accounts.'), samples, field('Application', app), field('Approved API base URL', base, 'Explicitly choose the HTTPS origin. The runtime will also enforce its application allowlist.'), field('Source URL', source, 'Provenance only. Paste or upload the actual JSON document below.'), field('Upload JSON', file), field('OpenAPI document', document), el('label', { class: 'check-field' }, approved, 'I approve this API base URL for capability review. This does not authorize any account action.'), actions(cancel(), button('Compile candidates', null, '', { type: 'submit' })));
  submitForm(form, async () => { const result = await api('/api/import', { appId: app.value, document: parseJson(document.value, 'OpenAPI document'), baseUrl: base.value.trim() || undefined, sourceUrl: source.value.trim() || undefined }); await refresh(); dialog.close(); navigate('capabilities'); notify(`Import completed. ${result.capabilities?.length ?? result.candidates?.length ?? 'New'} candidate operations are ready for review.${result.warnings?.length ? ` ${result.warnings.length} compiler warning(s); inspect the import record.` : ''}`); if (result.warnings?.length) showResult('Compiler warnings', result.warnings); });
  openDialog('Import an application interface', 'Acquire operations from an OpenAPI JSON document. An authorized account is still required to execute them.', form);
}
function acquireDialog(selected) {
  const app = appSelect(selected); app.required = true;
  const goal = el('textarea', { required: true, placeholder: 'Describe the operation you need, its target, and the desired result.', rows: '3' });
  const document = el('textarea', { class: 'code-input', placeholder: 'Optional: paste an OpenAPI JSON document', spellcheck: 'false' });
  const documentation = el('textarea', { placeholder: 'Optional: paste relevant official API documentation, parameters, response shapes, and constraints.', rows: '5' });
  const form = el('form', {}, note(state.settings?.modelConfigured ? `Model-assisted acquisition sends your goal and reference documentation to the configured model provider (${state.settings.modelName || 'configured'}). Generated operations remain candidates until reviewed. Import OpenAPI compiles locally without sending material to a model.` : 'No model is configured. Deterministic acquisition can compile a supplied OpenAPI document; the runtime will not pretend to discover or invent an application interface.', state.settings?.modelConfigured ? 'warn' : 'warn'), !state.settings?.modelConfigured ? el('p', { class: 'small-copy muted' }, 'For model-assisted synthesis, configure FABRIC_MODEL_URL, FABRIC_MODEL_API_KEY, and FABRIC_MODEL_NAME in the product .env file, then restart Fabric.') : null, field('Application', app), field('What should the capability do?', goal), field('Interface document (optional)', document), field('Reference documentation (optional)', documentation, 'Model synthesis requires a configured provider. Do not paste credentials or private account data into reference material.'), actions(cancel(), button('Acquire capabilities', null, '', { type: 'submit' })));
  submitForm(form, async () => { const result = await api('/api/acquire', { appId: app.value, goal: goal.value, document: document.value.trim() ? parseJson(document.value, 'Interface document') : undefined, documentation: documentation.value.trim() || undefined }); await refresh(); dialog.close(); navigate('capabilities'); showResult('Acquisition result', result); });
  openDialog('Acquire a capability', 'Describe the task. Available interfaces and authority determine what can actually be built.', form);
}
function renderCapabilities() {
  const capabilities = rows('capabilities');
  const candidateCount = capabilities.filter(capability => capability.status === 'candidate').length;
  main.replaceChildren(head('Capabilities you can inspect.', 'Review the operation, destination, and expected effects. A generated candidate cannot run until it is promoted.', [button('Import OpenAPI', () => importDialog()), button('Acquire capability', () => acquireDialog(), '')]), ...(candidateCount ? [note(`${candidateCount} candidate${candidateCount === 1 ? '' : 's'} waiting for review. Promotion makes an operation available; it does not approve a future write.`)] : []), capabilities.length ? el('div', { class: 'row-list' }, capabilities.map(capability => el('article', { class: 'record' }, el('div', { class: 'record-content' }, el('h3', {}, capability.name || capability.id), el('div', { class: 'record-meta' }, appName(capability.appId), statusBadge(capability.status), badge(capability.effect === 'read' ? 'Read operation' : 'Changes data', capability.effect === 'read' ? 'neutral' : 'warn'), badge(capability.driver || 'http')), el('p', {}, capability.description || capability.request?.url || text(capability.action) || 'Inspect the full capability contract before execution.'), el('p', { class: 'mono' }, capability.id)), el('div', { class: 'record-actions' }, button(capability.status === 'candidate' ? 'Review candidate' : 'Inspect', () => reviewCapability(capability), 'secondary small'), capability.status === 'active' ? button('Run', () => runDialog(capability), 'small') : null, el('a', { class: 'button secondary small', href: `/api/capabilities/${encodeURIComponent(capability.id)}/export`, download: `${capability.id}.json` }, 'Export JSON'))))) : empty('No acquired capabilities yet', 'Connect the local workspace for built-in file operations, or import an application’s interface to create reviewable candidates.', button('Import OpenAPI', () => importDialog(), '')));
}
function reviewCapability(capability) {
  const approved = el('input', { type: 'checkbox', required: true });
  const form = el('form', {}, el('div', { class: 'tag-row' }, statusBadge(capability.status), badge(capability.effect || 'Unknown effect', capability.effect === 'read' ? 'neutral' : 'warn')), note(capability.verification?.description || 'Read the verification contract. Provider response success does not automatically establish an independent effect check.'), jsonBlock(capability));
  if (capability.status === 'candidate') form.append(el('label', { class: 'check-field' }, approved, 'I have reviewed this operation, its destination, inputs, and declared effects.'), actions(cancel(), button('Promote capability', null, '', { type: 'submit' })));
  else form.append(actions(button('Close', () => dialog.close()), button('Run capability', () => runDialog(capability), '')));
  submitForm(form, async () => { await api(`/api/capabilities/${encodeURIComponent(capability.id)}/promote`, {}); dialog.close(); await refresh(); notify('Capability promoted. Saved account permissions determine whether execution requires approval.'); });
  openDialog(capability.name || 'Capability review', capability.description || 'Inspect the complete, versioned capability contract.', form);
}
function sampleArgs(schema = {}) {
  const args = {};
  for (const [key, spec] of Object.entries(schema.properties || {})) {
    if (spec.default !== undefined) args[key] = spec.default;
    else if (spec.example !== undefined) args[key] = spec.example;
    else if (schema.required?.includes(key)) args[key] = spec.type === 'number' || spec.type === 'integer' ? 0 : spec.type === 'boolean' ? false : spec.type === 'array' ? [] : spec.type === 'object' ? {} : '';
  }
  return args;
}
function connectionSelect(appId, selected) { return select(rows('connections').filter(connection => connection.status !== 'revoked' && (!appId || connection.appId === appId)).map(connection => [connection.id, `${connection.label || appName(connection.appId)} · ${connection.status || 'unknown'}`]), 'Choose an authorized connection', selected); }
function runDialog(capability) {
  const connection = connectionSelect(capability.appId); connection.required = true;
  const args = el('textarea', { class: 'code-input', required: true, value: pretty(sampleArgs(capability.inputSchema)), spellcheck: 'false' });
  const form = el('form', {}, note(capability.effect === 'read' ? 'Results may contain private account data. Your saved account permission determines whether this runs immediately, asks for approval, or is blocked.' : 'This operation can change data. If its saved account permission is Allow, submitting runs it without another prompt. Ask prepares an exact approval; Off blocks it.', capability.effect === 'read' ? '' : 'warn'), field('Connection', connection), field('Arguments (JSON object)', args), el('details', {}, el('summary', {}, 'Input schema'), jsonBlock(capability.inputSchema)), actions(cancel(), button('Run operation', null, '', { type: 'submit' })));
  submitForm(form, async () => { const job = await api('/api/jobs', { connectionId: connection.value, capabilityId: capability.id, args: parseJson(args.value, 'Arguments') }); await refresh(); navigate('activity'); jobDialog(job); });
  openDialog(capability.name || 'Run capability', 'Execution is tied to this capability version, connection, and set of arguments.', form);
}
function showResult(title, result) { openDialog(title, 'Observed response from the local runtime.', el('div', {}, jsonBlock(result), actions(button('Close', () => dialog.close(), '')))); }
/**
 * F10.11 part j: a reviewed action waits with its exact prepared requests. The dialog shows the exact blocks Fabric's approval page gives
 * (lib/ui-contracts.mjs exactAction()), never the stored prepared data, and offers Approve only when that page does: with its prepared
 * bytes missing or changed there is nothing to approve here.
 */
async function actionApprovalDialog(job) {
  let page;
  try { page = await api(`/api/ui/approvals/${encodeURIComponent(job.id)}`); } catch (error) { notify(error.message, true); return; }
  const model = page.approval ? describeApproval(page.approval) : null;
  const cancel = button('Cancel job', async () => { try { await api(`/api/jobs/${encodeURIComponent(job.id)}/cancel`, {}); dialog.close(); await refresh(); } catch (error) { notify(error.message, true); } });
  const body = el('div', {}, el('div', { class: 'tag-row' }, statusBadge(job.status)), note('Review the exact requests. Approval applies only to these bytes, not future actions.', 'warn'),
    el('dl', { class: 'key-value' }, el('dt', {}, 'Action'), el('dd', {}, model ? model.heading : nameOf('capabilities', job.capabilityId)), el('dt', {}, 'Connection'), el('dd', {}, nameOf('connections', job.connectionId)),
      el('dt', {}, 'Started'), el('dd', {}, date(job.createdAt))),
    ...(model ? model.warnings.map(words => note(words, 'warn')) : []), ...(model ? model.blocks.map(block => el('div', {}, el('h3', {}, block.label), el('pre', {}, block.text))) : []));
  if (!model?.approve) body.append(note('This action\'s prepared request cannot be shown in full here, so it cannot be approved here. You can cancel it.', 'error'), actions(cancel, button('Close', () => dialog.close(), '')));
  else {
    const form = el('form'), checked = el('input', { type: 'checkbox', required: true });
    form.append(el('label', { class: 'check-field' }, checked, 'I authorize exactly these requests on this connection.'), actions(cancel, button('Approve', null, '', { type: 'submit' })));
    submitForm(form, async () => { const result = await api(model.approve.path, model.approve.body); await refresh(); jobDialog(result); });
    body.append(form);
  }
  openDialog('Approve this action?', 'Fabric prepared these exact requests.', body);
}
function jobDialog(job) {
  if (job.kind === 'action' && job.status === 'awaiting_approval') return actionApprovalDialog(job);
  const needsApproval = job.status === 'awaiting_approval';
  const connection = rows('connections').find(item => item.id === job.connectionId);
  const browser = connection?.driver === 'browser';
  const actionName = browserOperationPresentation(rows('capabilities').find(item => item.id === job.capabilityId), connection).name || nameOf('capabilities', job.capabilityId);
  const expandedRequest = needsApproval && !(browser && job.effect !== 'read');
  const observedPage = browser && job.effect === 'read' && job.status === 'succeeded' && job.result?.verification?.status === 'observed' && job.result.verification.kind === (isPersistentBrowser(connection) ? 'persistent-browser-dom' : 'paired-browser-dom');
  const body = el('div', {}, el('div', { class: 'tag-row' }, statusBadge(job.status), verificationBadge(job)), observedPage ? note('Page access observed. The browser returned page content for this request. This does not verify which account is signed in or grant access to the rest of the app.') : null, needsApproval ? note('Review the exact target and inputs. Approval applies only to this request, not future actions.', 'warn') : job.status === 'uncertain' ? note('The outcome could not be verified. Do not retry blindly: the action may already have taken effect.', 'warn') : null, el('dl', { class: 'key-value' }, el('dt', {}, 'Action'), el('dd', {}, actionName), el('dt', {}, isPersistentBrowser(connection) ? 'Saved browser session' : isDurableBrowser(connection) ? 'Saved app access' : browser ? 'Paired tab' : 'Connection'), el('dd', {}, nameOf('connections', job.connectionId)), el('dt', {}, 'Started'), el('dd', {}, date(job.createdAt))), expandedRequest ? el('div', {}, el('h3', {}, 'Exact request'), jsonBlock(job.preview || { args: job.args })) : el('details', {}, el('summary', {}, 'Request details'), jsonBlock(job.preview || { args: job.args })), job.result != null ? el('details', {}, el('summary', {}, 'Result and evidence'), jsonBlock(job.result)) : null, job.error ? note(text(job.error), 'error') : null, el('details', {}, el('summary', {}, 'Technical reference'), el('pre', {}, job.id)));
  if (job.status === 'awaiting_approval') {
    if (browser && job.effect !== 'read') {
      body.append(note(`${job.source?.kind === 'client' && job.source?.clientId ? 'An AI client proposed this browser change.' : 'This is a proposed browser change.'} It has not run. Review the exact page, control, and text before approving. Approval applies to this one request only.`, 'warn'));
      const target = job.preview?.browserTarget;
      if (target) body.append(el('section', { class: 'browser-target-review' }, el('h3', {}, 'Browser change to approve'), el('dl', { class: 'key-value' },
        el('dt', {}, 'Website'), el('dd', {}, text(target.origin)),
        el('dt', {}, 'Page'), el('dd', {}, text(target.title)),
        el('dt', {}, 'Page address'), el('dd', {}, text(target.url)),
        el('dt', {}, 'Control'), el('dd', {}, text(target.label || target.role)),
        el('dt', {}, 'Operation'), el('dd', {}, text(target.operation)),
        ...(typeof job.args?.value === 'string' ? [el('dt', {}, 'Text to enter'), el('dd', {}, job.args.value)] : []),
        el('dt', {}, 'Inspection expires'), el('dd', {}, date(target.snapshotExpiresAt))
      ), el('p', { class: 'small-copy muted' }, 'This target comes from the recorded page inspection. If the page changes or the inspection expires, inspect it again. It does not verify account identity.')));
    }
    const form = el('form');
    const checked = el('input', { type: 'checkbox', required: true });
    form.append(el('details', {}, el('summary', {}, 'Approval digest'), el('pre', {}, job.approvalDigest)), el('label', { class: 'check-field' }, checked, 'I authorize this exact operation on this connection with these arguments.'), actions(button('Cancel job', async () => { try { await api(`/api/jobs/${encodeURIComponent(job.id)}/cancel`, {}); dialog.close(); await refresh(); } catch (error) { notify(error.message, true); } }), button('Approve and execute', null, '', { type: 'submit' })));
    submitForm(form, async () => { const result = await api(`/api/jobs/${encodeURIComponent(job.id)}/approve`, { approvalDigest: job.approvalDigest }); await refresh(); jobDialog(result); }); body.append(form);
  } else {
    const controls = observedControls(job); if (controls) body.append(controls);
    const canInspectOutcome = browser && !isPersistentBrowser(connection) && job.effect !== 'read' && ['succeeded', 'uncertain'].includes(job.status);
    if (canInspectOutcome && job.status === 'succeeded' && job.result?.verification?.status !== 'verified') body.append(note('The browser reported an action result. This is not independent proof of a saved application change. Inspect the page again to check the outcome.'));
    body.append(actions(canInspectOutcome ? button('Inspect page again', () => testPageAccess(connection), 'secondary') : null, button('Close', () => dialog.close(), '')));
  }
  openDialog(needsApproval ? 'Approve this action?' : observedPage ? 'Page access observed' : 'Action details', 'The recorded result of this request.', body);
}
function renderActivity() {
  const jobs = [...rows('jobs')].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const activity = [...rows('activity')].sort((a, b) => String(b.createdAt || b.at || b.timestamp).localeCompare(String(a.createdAt || a.at || a.timestamp)));
  const pending = jobs.filter(job => job.status === 'awaiting_approval');
  const completed = jobs.filter(job => job.status !== 'awaiting_approval');
  const jobRow = job => el('button', { type: 'button', class: 'connector-row activity-row', onclick: () => jobDialog(job) }, el('span', { class: `activity-mark ${job.status === 'failed' || job.status === 'uncertain' ? 'warn' : ''}`, 'aria-hidden': 'true' }, job.status === 'awaiting_approval' ? '?' : job.status === 'succeeded' ? '✓' : '·'), el('span', { class: 'connector-row-copy' }, el('strong', {}, nameOf('capabilities', job.capabilityId) || 'Operation'), el('span', {}, `${nameOf('connections', job.connectionId) || 'Account'} · ${date(job.createdAt)}`), job.error ? el('span', { class: 'activity-error' }, text(job.error)) : null), el('span', { class: 'activity-state' }, activityStatusLabel(job)), el('span', { class: 'chevron', 'aria-hidden': 'true' }, '›'));
  const audit = el('details', { class: 'connector-advanced' }, el('summary', {}, 'Technical activity log'), el('div', { class: 'connector-advanced-body' }, activity.length ? el('div', { class: 'event-list' }, activity.slice(0, 100).map(event => el('div', { class: 'event' }, el('div', { class: 'event-main' }, el('div', { class: 'event-title' }, humanize(event.type || event.action || event.event || 'Runtime event')), el('details', {}, el('summary', {}, 'Inspect event'), jsonBlock(event))), el('time', { class: 'event-time' }, date(event.createdAt || event.at || event.timestamp))))) : el('p', { class: 'small-copy muted' }, 'No activity recorded.')));
  main.replaceChildren(head('Activity', 'See what Fabric has done and what needs your attention.'), pending.length ? el('section', { class: 'connector-section' }, el('h2', { class: 'group-heading' }, 'Needs your approval'), el('div', { class: 'settings-group' }, pending.map(jobRow))) : null, completed.length ? el('section', { class: 'connector-section' }, el('h2', { class: 'group-heading' }, 'Recent activity'), el('div', { class: 'settings-group' }, completed.slice(0, 100).map(jobRow))) : !pending.length ? empty('No actions yet', 'Actions performed through your connections will appear here, with their results.') : null, audit);
}
function metric(value, label) { return el('div', { class: 'metric' }, el('strong', {}, value), el('span', {}, label)); }
function renderHeartbeats() {
  const heartbeats = rows('heartbeats');
  main.replaceChildren(head('Work that wakes up.', 'Schedule connection checks or reviewed read operations. Every observed tick, result, and error is recorded—not simulated.', [button('Create heartbeat', () => heartbeatDialog(), '')]), note('Heartbeats run while this local runtime is running. Minimum interval: 30 seconds. Unattended writes are not permitted; a heartbeat never approves a change for you.'), el('div', { class: 'metrics' }, metric(heartbeats.filter(heartbeat => heartbeat.enabled).length, 'Enabled heartbeats'), metric(heartbeats.reduce((sum, heartbeat) => sum + (Array.isArray(heartbeat.runs) ? heartbeat.runs.length : Number(heartbeat.runs) || 0), 0), 'Recorded runs'), metric(heartbeats.filter(heartbeat => !heartbeat.enabled).length, 'Paused heartbeats')), heartbeats.length ? el('div', { class: 'row-list heartbeat-grid' }, heartbeats.map(heartbeat => el('article', { class: 'record' }, el('div', { class: 'record-content' }, el('h3', {}, heartbeat.name || 'Heartbeat'), el('div', { class: 'record-meta' }, badge(heartbeat.enabled ? 'Enabled' : 'Paused', heartbeat.enabled ? 'good' : 'neutral'), `Every ${heartbeat.intervalSeconds} seconds`, badge(heartbeat.capabilityId ? 'Read capability' : 'Health check')), el('p', {}, heartbeat.capabilityId ? nameOf('capabilities', heartbeat.capabilityId) : heartbeat.connectionId ? `Connection: ${nameOf('connections', heartbeat.connectionId)}` : 'Connection health checks'), el('p', {}, `Last run: ${date(heartbeat.lastRunAt)} · Next: ${heartbeat.enabled ? date(heartbeat.nextRunAt) : 'Paused'}`)), el('div', { class: 'record-actions' }, button(heartbeat.enabled ? 'Pause' : 'Resume', () => toggleHeartbeat(heartbeat), 'secondary small'), button('Inspect runs', () => heartbeatDetails(heartbeat), 'secondary small')), heartbeat.lastResult ? el('div', { class: 'heartbeat-result' }, el('div', { class: 'record-meta' }, 'Latest result', statusBadge(heartbeat.lastResult.status || (heartbeat.lastResult.error ? 'failed' : 'observed'))), el('details', {}, el('summary', {}, 'Evidence'), jsonBlock(heartbeat.lastResult))) : null))) : empty('Start with an observable heartbeat', 'Check a connection on a schedule, or run a reviewed read-only capability. You can pause it at any time.', button('Create heartbeat', () => heartbeatDialog(), '')), el('p', { class: 'footer-note' }, 'The page refreshes observed runtime state every five seconds while visible. It does not animate or invent work between server updates.'));
}
function heartbeatDialog() {
  const name = el('input', { type: 'text', required: true, placeholder: 'e.g. Workspace check', maxlength: '120' });
  const interval = el('input', { type: 'number', min: '30', max: '86400', step: '1', required: true, value: '30' });
  const caps = rows('capabilities').filter(capability => capability.status === 'active' && capability.effect === 'read' && capability.driver !== 'browser');
  const capability = select(caps.map(item => [item.id, `${appName(item.appId)} / ${item.name || item.id}`]), 'Connection health check (no capability)');
  const connection = connectionSelect();
  const args = el('textarea', { class: 'code-input', value: '{}', spellcheck: 'false' });
  const argsField = field('Arguments (JSON object)', args); argsField.hidden = true;
  const connectionField = field('Connection', connection, 'Without a capability, leave blank to check all available connections.');
  capability.addEventListener('change', () => {
    const selected = caps.find(item => item.id === capability.value);
    const available = rows('connections').filter(item => item.status !== 'revoked' && (!selected || item.appId === selected.appId));
    connection.replaceChildren(el('option', { value: '' }, selected ? 'Choose a connection' : 'All connections'), ...available.map(item => el('option', { value: item.id }, item.label || appName(item.appId))));
    connection.required = !!selected; argsField.hidden = !selected; args.value = pretty(sampleArgs(selected?.inputSchema));
  });
  const form = el('form', {}, note('Only connection health checks and promoted API/local read capabilities can run unattended. Browser reads require an interactive request until independent account binding is available. The local runtime must remain running.'), field('Heartbeat name', name), field('Interval in seconds', interval, 'Minimum 30 seconds. Provider rate limits still apply.'), field('Operation', capability), connectionField, argsField, actions(cancel(), button('Start heartbeat', null, '', { type: 'submit' })));
  submitForm(form, async () => { await api('/api/heartbeats', { name: name.value.trim(), intervalSeconds: Number(interval.value), connectionId: connection.value || undefined, capabilityId: capability.value || undefined, args: capability.value ? parseJson(args.value, 'Arguments') : {} }); dialog.close(); await refresh(); navigate('heartbeats'); notify('Heartbeat created. Its observed execution time and results will appear in this view.'); });
  openDialog('Create a heartbeat', 'A durable schedule with explicit scope and visible results.', form);
}
async function toggleHeartbeat(heartbeat) { try { await api(`/api/heartbeats/${encodeURIComponent(heartbeat.id)}/${heartbeat.enabled ? 'pause' : 'resume'}`, {}); await refresh(); notify(heartbeat.enabled ? 'Heartbeat paused.' : 'Heartbeat resumed.'); } catch (error) { notify(error.message, true); } }
function heartbeatDetails(heartbeat) {
  const jobs = rows('jobs').filter(job => job.source?.heartbeatId === heartbeat.id).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  openDialog(heartbeat.name || 'Heartbeat details', 'Observed schedule state and execution records from the runtime.', el('div', {}, jsonBlock(heartbeat), jobs.length ? el('div', {}, el('h3', {}, 'Recorded executions'), el('div', { class: 'row-list' }, jobs.slice(0, 10).map(job => el('div', { class: 'record' }, el('div', { class: 'record-content' }, el('div', { class: 'record-meta' }, statusBadge(job.status), verificationBadge(job)), el('p', {}, date(job.createdAt))), button('View evidence', () => jobDialog(job), 'secondary small'))))) : null, actions(button('Close', () => dialog.close(), ''))));
}

document.querySelector('#refresh').addEventListener('click', () => refresh({ announce: true }));
window.addEventListener('hashchange', () => {
  const [route, app] = location.hash.slice(1).split('/');
  if (route === 'main') return;
  const view = route === 'catalog' ? 'connectors' : route in views ? route : 'connectors';
  let appId = null;
  try { appId = view === 'connectors' && app ? decodeURIComponent(app) : null; } catch { appId = null; }
  if (view === activeView && appId === selectedAppId) return;
  if (dialog.open) dialog.close();
  activeView = view; selectedAppId = appId; selectedAccountId = null; permissionSearch = '';
  renderNav(); render();
  if (selectedAppId && state) { loadConnector(selectedAppId); loadFactoryBuilds(selectedAppId); }
});
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
dialog.addEventListener('cancel', event => { event.preventDefault(); dialog.close(); });
dialog.addEventListener('close', () => {
  stopDialogWork?.(); stopDialogWork = null;
  dialog.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
  const restore = dialogReturnFocus; dialogReturnFocus = null;
  queueMicrotask(() => { if (!dialog.open) (restore?.isConnected && !restore.disabled ? restore : main)?.focus({ preventScroll: true }); });
});
setInterval(() => { if (!document.hidden && !dialog.open && !document.activeElement?.matches('input,textarea,select,[contenteditable="true"]')) refresh(); }, 5000);
renderNav();
const oauthResult = new URLSearchParams(location.search).get('oauth');
refresh().then(() => {
  if (selectedAppId) loadFactoryBuilds(selectedAppId);
  if (!oauthResult) { resumeBrowserSetup(); return; }
  history.replaceState(null, '', `${location.pathname}#connectors`);
  navigate('connectors');
  notify(oauthResult === 'connected' ? 'Sign-in returned. Choose the connected app to review your account access.' : `Sign-in did not complete: ${oauthResult.slice(0, 500)}`, oauthResult !== 'connected');
});

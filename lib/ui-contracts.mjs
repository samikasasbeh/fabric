import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {canonicalHash} from './compiler.mjs';
import {levelLabel} from './access-levels.mjs';
import {NOTICE_WORDS} from './connection-notices.mjs';
import {UNAVAILABLE_REASONS} from './permission-groups.mjs';

// UI-0 screen contracts (docs/UI-0-SCREEN-CONTRACTS.md). Pure projections from runtime state to
// the view model each screen renders, one view per party. The local owner routes use them now;
// the tenant API (F03.0) serves the same shapes. No store access, no I/O beyond the static
// category list, so every field a party can see is decided here and tested here.
export const PARTIES = Object.freeze(['owner', 'end_user', 'developer']);
export const CATEGORIES = Object.freeze(JSON.parse(readFileSync(new URL('../catalog/categories.json', import.meta.url), 'utf8')).map(category => Object.freeze(category)));
const CATEGORY = new Map(CATEGORIES.map(category => [category.id, category]));
const STATUSES = new Set(['all', 'available', 'connected']);
const PREVIEW = 5, PAGE = 50, MAX_PAGE = 100;
const BROWSER_READY = new Set(['ready', 'paired', 'session_ready']);
const AUTH_KIND = {oauth: 'oauth', token: 'api_key', browser: 'browser', workspace: 'local', device: 'local'};

function fail(code, message) {const error = new Error(message); error.code = code; throw error;}
const text = (value, limit) => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, limit) : '';
const sees = party => {if (!PARTIES.includes(party)) fail('invalid_request', 'Unknown audience.'); return {connections: party !== 'developer', device: party === 'owner'};};

/** Present accounts are neither revoked nor quarantined; a present account is healthy when it can run now. */
export function connectionState(appId, connections) {
  const present = connections.filter(connection => connection?.appId === appId && !['revoked', 'pending_confirmation'].includes(connection.status));
  const healthy = connection => connection.driver === 'browser' ? BROWSER_READY.has(connection.status) : connection.status === 'ready';
  const accounts = present.filter(connection => connection.driver !== 'browser').length, browserSessions = present.length - accounts;
  const needsAttention = present.filter(connection => !healthy(connection)).length;
  return {state: present.some(healthy) ? 'connected' : present.length ? 'attention' : 'available', accounts, browserSessions, needsAttention};
}

/** The one action a catalog row offers, from real connection state and the runtime's connection options. */
export function primaryAction(app, state) {
  if (state && state.state !== 'available') return 'view';
  const options = Array.isArray(app.connectionOptions) ? app.connectionOptions : [];
  if (options.some(option => option.enabled && option.availability === 'available')) return 'connect';
  if (options.some(option => option.availability === 'setup_required')) return 'setup_required';
  return 'unavailable';
}

function driverOf(app) {
  const methods = Array.isArray(app.authMethods) ? app.authMethods : [];
  if (methods.some(method => method === 'workspace' || method === 'device')) return 'local';
  if (methods.length && methods.every(method => method === 'browser')) return 'browser';
  return 'api';
}
const categoryOf = app => CATEGORY.has(app.categoryId) ? app.categoryId : 'other';

/** AppCard for one audience. The developer and agent never receive connection state. */
export function appCard(app, {party = 'owner', connections = [], accessLevels = () => []} = {}) {
  const view = sees(party);
  const authKinds = [...new Set((Array.isArray(app.authMethods) ? app.authMethods : []).map(method => AUTH_KIND[method]).filter(Boolean))];
  const card = {id: app.id, name: text(app.name, 80) || app.id, displayName: text(app.displayName, 80) || text(app.name, 80) || app.id,
    ...(app.provider ? {provider: text(app.provider, 80)} : {}),
    tagline: text(app.tagline, 80) || text(app.description, 80), iconUrl: `/api/icons/${encodeURIComponent(app.id)}`,
    categoryId: categoryOf(app), featured: app.featured === true, ...(app.featured === true && Number.isSafeInteger(app.featuredRank) ? {featuredRank: app.featuredRank} : {}),
    driver: driverOf(app), authKinds, accessLevels: [...accessLevels(app.id)]};
  const state = view.connections ? connectionState(app.id, connections) : null;
  card.primaryAction = primaryAction(app, state);
  if (state) card.connectionState = state;
  return card;
}

function encodeCursor(offset) {return Buffer.from(`o:${offset}`).toString('base64url');}
function decodeCursor(cursor) {
  if (cursor === undefined || cursor === null || cursor === '') return 0;
  const match = typeof cursor === 'string' && /^o:(\d{1,6})$/.exec(Buffer.from(cursor, 'base64url').toString());
  if (!match) fail('invalid_request', 'The cursor is not valid.');
  return Number(match[1]);
}
const order = (a, b) => (a.featured && b.featured ? a.featuredRank - b.featuredRank : a.featured ? -1 : b.featured ? 1 : 0) || a.name.localeCompare(b.name);

/** CatalogPage: Featured, categories with five-row previews and See all, or a flat page for search and See all. */
export function catalogPage({apps, connections = [], party = 'owner', status = 'all', q = '', categoryId, cursor, limit = PAGE, accessLevels} = {}) {
  const view = sees(party);
  if (!STATUSES.has(status)) fail('invalid_request', 'Status must be all, available or connected.');
  if (status !== 'all' && !view.connections) fail('invalid_request', 'Connection status filters are available to the account owner only.');
  if (categoryId !== undefined && categoryId !== '' && (!CATEGORY.has(categoryId) || (CATEGORY.get(categoryId).ownerOnly && !view.device))) fail('invalid_request', 'Unknown category.');
  const size = Math.min(Math.max(Number.isSafeInteger(Number(limit)) ? Number(limit) : PAGE, 1), MAX_PAGE);
  const query = text(q, 120).toLowerCase(), start = decodeCursor(cursor);
  let cards = (Array.isArray(apps) ? apps : []).filter(app => app && typeof app.id === 'string').map(app => appCard(app, {party, connections, accessLevels}))
    .filter(card => view.device || !CATEGORY.get(card.categoryId)?.ownerOnly);
  if (status === 'connected') cards = cards.filter(card => card.connectionState.state !== 'available');
  if (status === 'available') cards = cards.filter(card => card.connectionState.state === 'available');
  if (query) cards = cards.filter(card => [card.name, card.displayName, card.id, card.tagline, card.provider, CATEGORY.get(card.categoryId)?.label].filter(Boolean).join(' ').toLowerCase().includes(query));
  cards.sort(order);
  const counts = new Map();
  for (const card of cards) counts.set(card.categoryId, (counts.get(card.categoryId) || 0) + 1);
  const categories = CATEGORIES.filter(category => counts.has(category.id)).map(({id, label, order: rank}) => ({id, label, order: rank, count: counts.get(id)}));
  const page = {status, ...(query ? {q: query} : {}), categories: [], featured: []};
  if (query || categoryId) {
    const scoped = categoryId ? cards.filter(card => card.categoryId === categoryId) : cards;
    page.categoryId = categoryId || null;
    page.results = scoped.slice(start, start + size);
    if (start + size < scoped.length) page.nextCursor = encodeCursor(start + size);
    page.categories = categories.map(category => ({category, preview: [], more: false}));
    return page;
  }
  page.featured = cards.filter(card => card.featured);
  page.categories = categories.map(category => {
    const members = cards.filter(card => card.categoryId === category.id);
    return {category, preview: members.slice(0, PREVIEW), more: members.length > PREVIEW};
  });
  return page;
}

// ---- App detail (UI-2) ------------------------------------------------------------------
const ACCOUNT_STATUS = new Set(['ready', 'reconnect_required', 'expired', 'pending_confirmation', 'revoked']);
const MODE_ORDER = ['allow', 'ask', 'deny'];
const LOCKED_ROW = 'Fabric keeps this off: it gives access to other people or services.';

/** AccountRow: a fixed field list. Never scopes, tokens, hashes, generations or origins. A connection notice of the current sign-in
 *  (F10.4) is the attention line, even on a ready account. */
export function accountRow(connection, {accessLevel = () => 'custom', notice = null} = {}) {
  const identity = connection.identity || {};
  const displayName = text(identity.displayName, 120) || text(connection.label, 120) || 'Account';
  const healthy = connection.driver === 'browser' ? BROWSER_READY.has(connection.status) : connection.status === 'ready';
  const status = healthy ? 'ready' : ACCOUNT_STATUS.has(connection.status) ? connection.status : 'reconnect_required';
  return {accountRef: connection.id, displayName, ...(identity.email ? {email: text(identity.email, 200)} : {}), ...(identity.workspaceName ? {workspaceName: text(identity.workspaceName, 120)} : {}),
    initial: (text(identity.workspaceName, 1) || displayName.charAt(0) || '?').toUpperCase(), status,
    ...(NOTICE_WORDS[notice?.kind] ? {attention: NOTICE_WORDS[notice.kind]} : status === 'ready' ? {} : {attention: status === 'expired' ? 'Sign-in expired. Reconnect to keep using it.' : 'Reconnect this account to use it.'}),
    ...held(accessLevel(connection)), connectedAt: connection.createdAt || null};
}
const held = value => ({accessLevel: value && typeof value === 'object' ? String(value.level) : String(value || 'custom'), accessLabel: levelLabel(value)});

/** F10.6: the members of a row that cannot work through a sign-in, when their reasons differ. */
const CANNOT_WORK = 'None of these can work through a sign-in.';

/** One permission row for the selected account, from the engine's per-operation decisions of its members. A row Fabric
 *  locks offers Never only and never Add access; `locked` and `audience` appear only when true, so other rows keep their shape.
 *  `upgrade` (F10.4, T7) is the card Add access must confirm, carried only next to the Add access it belongs to.
 *  F10.6: `proxy` is the row's own proxy setting ({mode, defaultMode, allowedModes, source, revision, bindingHash}). A row with no typed
 *  member shows it as its mode; every row folds its revision and binding into the etag and never shows them. Access is read over the
 *  members that can work through a sign-in; `notes`, `working` and `total` and the confirm flag appear only when given or needed.
 *  F10.11 part k: a row that actions joined takes its mode from its typed and action members (so Allow on a row its proxy record held
 *  alone has a record to live in), while its access, `working` and `total` stay its provider members': an action is made of them. */
export function permissionRow({id, label, effect, decisions, addAccess = null, addBlocked = null, upgrade = null, sensitive = null, locked = false, audience = false, proxy = null, allowNeedsConfirm = null}) {
  const typed = decisions.filter(decision => decision.capabilityId), own = proxy && !typed.length ? proxy : null, shown = typed.length ? typed : decisions;
  const modes = own ? [own.mode] : [...new Set(shown.map(decision => decision.mode))], defaults = own ? [own.defaultMode] : [...new Set(shown.map(decision => decision.defaultMode))];
  const sources = own ? new Set([own.source]) : new Set(shown.map(decision => decision.policySource));
  // T3: a member marked unavailable or unsupported only says why; the others decide the access, and a row with none is never granted.
  // Read over the provider members; a row of actions alone (a sensitive row) reads its actions.
  const providers = decisions.filter(decision => decision.kind !== 'action'), counted = providers.length ? providers : decisions;
  const working = counted.filter(decision => decision.providerAccess !== 'unavailable' && decision.status !== 'unsupported'), cannot = counted.filter(decision => !working.includes(decision));
  const access = !working.length ? (counted.length ? 'unavailable' : 'unknown') : working.some(decision => decision.providerAccess === 'missing') ? 'missing' : working.every(decision => decision.providerAccess === 'granted') ? 'granted'
    : working.every(decision => decision.providerAccess === 'local') ? 'local' : 'unknown';
  const why = [...new Set(cannot.map(decision => decision.providerAccess === 'unavailable' ? UNAVAILABLE_REASONS[decision.unavailable] : decision.reason).filter(Boolean))];
  const notes = [...(!own && proxy?.mode === 'ask' && shown.some(decision => decision.mode === 'allow') ? ['raw_requests_ask'] : []), ...[...new Set(counted.map(decision => decision.unavailable).filter(Boolean))].sort(),
    ...[...new Set(decisions.flatMap(decision => Array.isArray(decision.conditions) ? decision.conditions : []))].sort()];
  const allowBlocked = decisions.some(decision => decision.allowBlocked);
  return {groupId: id, label, effect, ...(sensitive ? {sensitive} : {}), ...(locked ? {locked: true} : {}), ...(audience ? {audience: true} : {}), mode: modes.length === 1 ? modes[0] : 'mixed', defaultMode: defaults.length === 1 ? defaults[0] : 'mixed',
    allowedModes: locked ? ['deny'] : (own ? own.allowedModes : MODE_ORDER).filter(mode => mode !== 'allow' || !allowBlocked), ...(locked ? {blockedReason: LOCKED_ROW} : allowBlocked ? {blockedReason: 'Actions on a browser page always ask, so Allow is not offered.'} : {}),
    access, ...(access === 'unavailable' ? {accessReason: why.length === 1 ? why[0] : CANNOT_WORK} : {}), ...(access === 'missing' && !locked ? addAccess ? {addAccess, ...(upgrade ? {upgrade} : {})} : {addBlocked: addBlocked || 'This permission cannot be added from here.'} : {}),
    ...(notes.length ? {notes} : {}), ...(working.length && cannot.length ? {working: working.length, total: counted.length} : {}),
    policySource: sources.has('stale') ? 'stale' : sources.has('saved') ? 'saved' : 'default', reviewRequired: decisions.some(decision => decision.status === 'candidate' || decision.candidate === true),
    ...(typeof allowNeedsConfirm === 'boolean' ? {allowNeedsConfirm} : {}),
    // An opaque token over exactly what was shown, so a change between view and decision is refused. A proxy member has no
    // capability, so it is named by its member; the row's proxy record joins only when there is one.
    operations: decisions.length, etag: createHash('sha256').update([...decisions.map(decision => `${decision.capabilityId ?? `member:${decision.member}`}:${decision.policyHash}`).sort(), ...(proxy ? [`proxy:${proxy.revision}:${proxy.bindingHash}`] : [])].join('|')).digest('hex').slice(0, 32)};
}

// ---- Activity and approvals (UI-4) -------------------------------------------------------
/** "createIssue" or "users.drafts: list" read as words, for a timeline line. */
export function operationLabel(name) {
  const raw = text(name, 120) || 'an operation';
  const words = /\s/.test(raw) ? raw.replace(/:\s*/g, ' ') : raw.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_.-]+/g, ' ').toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}
const RESULT_LINE = {
  succeeded: (effect, app) => effect === 'read' ? `Read from ${app}` : `Done in ${app}`,
  uncertain: (effect, app) => `Sent to ${app}; the result could not be confirmed`,
  failed: () => 'Did not complete',
  cancelled: () => 'Cancelled before it ran',
  awaiting_approval: () => 'Waiting for your approval',
  queued: () => 'Running', running: () => 'Running',
};
const HANDOFF_LINE = {awaiting_owner: 'Waiting for you to choose an account', signing_in: 'Waiting for you to finish signing in', awaiting_confirmation: 'Waiting for you to confirm the account',
  binding: 'Connecting the account', declined: 'You declined the account request', cancelled: 'The account request was withdrawn', expired: 'The account request expired', failed: 'The account request closed'};
const dayKey = iso => String(iso).slice(0, 10);

/** The most text an approval shows in one block. Anything longer is not approvable from a hosted page. */
export const EXACT_LIMIT = 100_000;
const asText = value => typeof value === 'string' ? value : JSON.stringify(value ?? null, null, 2);
/**
 * The exact action an approval covers, for every driver: the HTTP request and body exactly as sent; or the
 * inputs, the inspected browser target and the file a workspace write replaces. Never cut: a block longer
 * than EXACT_LIMIT makes the whole action incomplete, and an incomplete action cannot be approved here.
 * F10.11 part j: a reviewed action shows its prepared bytes, read through `prepared` (job id to its actionPrepared row), and nothing else.
 */
export function exactAction(job, {prepared} = {}) {
  if (job?.kind === 'action') return actionBlocks(job, prepared);
  const preview = job.preview || {}, blocks = [];
  if (preview.request) {
    blocks.push({label: 'Request', text: `${preview.request.method} ${preview.request.url}`});
    // A proxied request also shows the caller's headers and the headers Fabric adds (credentials by name only).
    const headers = preview.request.headers && typeof preview.request.headers === 'object' ? Object.entries(preview.request.headers) : [];
    if (headers.length) blocks.push({label: 'Headers', text: headers.map(([name, value]) => `${name}: ${value}`).join('\n')});
    if (Array.isArray(preview.addedByFabric) && preview.addedByFabric.length) blocks.push({label: 'Added by Fabric', text: preview.addedByFabric.map(header => `${header.name}: ${header.value}`).join('\n')});
    if (preview.request.body !== undefined && preview.request.body !== null) blocks.push({label: 'Body', text: asText(preview.request.body)});
  } else {
    if (preview.browserTarget) blocks.push({label: 'Page and target', text: asText(preview.browserTarget)});
    blocks.push({label: 'Inputs', text: asText(preview.arguments ?? job.args ?? {})});
    if (preview.existingFile) blocks.push({label: 'File it replaces', text: asText(preview.existingFile)});
  }
  const complete = blocks.every(block => block.text.length <= EXACT_LIMIT);
  return {complete, blocks: complete ? blocks : blocks.map(block => ({label: block.label, text: block.text.slice(0, EXACT_LIMIT)}))};
}

/**
 * F10.11 part j: an action's exact blocks, failing closed. With no reader, no prepared row, a row whose content does not hash to the job's
 * preparedHash, or a row of another phase, it is incomplete and offers no Approve; it never falls back to the inputs. Phase reads shows
 * each read whose bytes are known exactly (a read filled from an earlier answer as its reviewed template), then the resolving write it
 * gates; phase final shows the decoded fields, the choices with their labels, the fields a resource had when read, then each perform
 * request. A body longer than EXACT_LIMIT is shown whole as consecutive blocks with its sha256, so nothing is cut.
 */
function actionBlocks(job, prepared) {
  const none = {complete: false, blocks: []};
  let row = null;
  try { row = typeof prepared === 'function' ? prepared(job.id) : null; } catch { return none; }
  const content = row?.content;
  if (!content || typeof content !== 'object' || typeof job.action?.preparedHash !== 'string' || content.phase !== job.action.phase) return none;
  try { if (canonicalHash(content) !== job.action.preparedHash) return none; } catch { return none; }
  const blocks = [], lines = items => items.join('\n');
  const request = item => {
    const at = item.index ? `${item.stepId} (${item.index + 1})` : item.stepId;
    if (item.template !== undefined) { blocks.push({label: `${at}: Request`, text: `${item.method} ${item.url} (filled from the read above)`}); return; }
    blocks.push({label: `${at}: Request`, text: `${item.method} ${item.url}`});
    const headers = Object.entries(item.headers ?? {});
    if (headers.length) blocks.push({label: `${at}: Headers`, text: lines(headers.map(([name, value]) => `${name}: ${value}`))});
    if (Array.isArray(item.added) && item.added.length) blocks.push({label: `${at}: Added by Fabric`, text: lines(item.added.map(header => `${header.name}: ${header.value}`))});
    if (typeof item.body !== 'string') return;
    if (item.body.length <= EXACT_LIMIT) { blocks.push({label: `${at}: Body`, text: item.body}); return; }
    const count = Math.ceil(item.body.length / EXACT_LIMIT);
    for (let part = 0; part < count; part++) blocks.push({label: `${at}: Body (${part + 1} of ${count})`, text: item.body.slice(part * EXACT_LIMIT, (part + 1) * EXACT_LIMIT)});
    blocks.push({label: `${at}: Body sha256`, text: createHash('sha256').update(item.body).digest('hex')});
  };
  if (content.phase === 'final') {
    const fields = Array.isArray(content.fields) ? content.fields : [], choices = Array.isArray(content.choices) ? content.choices : [];
    if (fields.length) blocks.push({label: 'Fields', text: lines(fields.map(field => `${field.label}: ${field.value}`))});
    if (choices.length) blocks.push({label: 'Choices', text: lines(choices.map(choice => `${choice.input}: ${choice.label} (${choice.id})`))});
    const schemas = Object.entries(content.schemas && typeof content.schemas === 'object' ? content.schemas : {});
    if (schemas.length) blocks.push({label: 'Resource fields', text: lines(schemas.map(([input, read]) => `${input}: Fields as read at ${read.readAt} (schema ${String(read.hash).slice(0, 12)})`))});
    for (const item of Array.isArray(content.perform) ? content.perform : []) request(item);
  } else {
    for (const item of Array.isArray(content.reads) ? content.reads : []) request(item);
    if (content.resolving) request(content.resolving);
  }
  return {complete: blocks.every(block => block.text.length <= EXACT_LIMIT), blocks};
}

/** One approval waiting for the owner, with the exact action that would run. Approve only when all of it can be shown. `prepared` reads an
 *  action job's prepared row (F10.11 part j); without it an action is never approvable here. */
export function approvalItem(job, {appName = id => id, capabilityName = () => null, accountName = () => null, clientName = () => null, prepared} = {}) {
  const exact = exactAction(job, {prepared});
  // A proxied request is named by its row and method; its warnings come from Fabric's own decision, as fixed codes.
  const operation = job.kind === 'proxy' && job.proxy ? `${job.proxy.rowLabel} (${job.proxy.method})` : operationLabel(job.preview?.operation || capabilityName(job.capabilityId));
  const warnings = (Array.isArray(job.preview?.warnings) ? job.preview.warnings : []).filter(code => ['not_reviewed', 'delete', 'duplicate_of_uncertain', 'reaches_people', 'body_routed', 'prepares_first', 'not_made_by_fabric'].includes(code));
  return {callRef: job.id, appId: job.preview?.application || null, appName: appName(job.preview?.application), operation, effect: job.effect || null, warnings,
    // F10.11 part n: an action waits at phase reads (the reads and any resolving write) or phase final (the exact final request).
    ...(job.kind === 'action' ? {phase: job.action?.phase === 'final' ? 'final' : 'reads'} : {}),
    account: accountName(job.connectionId), agent: clientName(job.source?.clientId), taskTitle: text(job.task?.title, 120) || null, expiresAt: job.approvalExpiresAt, exact,
    approve: exact.complete ? {path: `/api/jobs/${encodeURIComponent(job.id)}/approve`, body: {approvalDigest: job.approvalDigest}} : null, cancel: {path: `/api/jobs/${encodeURIComponent(job.id)}/cancel`, body: {}}};
}

/**
 * The approval page a card links to (/approve/<call>): the exact action while it can still be approved,
 * otherwise only what happened. Nothing here approves; the page posts the shown digest itself.
 */
export function approvalPage(job, {appName = id => id, capabilityName = () => null, accountName = () => null, clientName = () => null, prepared, now = Date.now()} = {}) {
  const names = {appName, capabilityName, accountName, clientName, prepared};
  const app = appName(job.preview?.application) || 'the app';
  const base = {callRef: job.id, operation: job.kind === 'proxy' && job.proxy ? `${job.proxy.rowLabel} (${job.proxy.method})` : operationLabel(job.preview?.operation || capabilityName(job.capabilityId)), appName: app, taskTitle: text(job.task?.title, 120) || null, agent: clientName(job.source?.clientId)};
  if (job.status === 'awaiting_approval' && Date.parse(job.approvalExpiresAt) > now) return {...base, state: 'pending', approval: approvalItem(job, names)};
  if (job.status === 'awaiting_approval') return {...base, state: 'expired', summary: 'This approval expired. Nothing ran.', cancel: {path: `/api/jobs/${encodeURIComponent(job.id)}/cancel`, body: {}}};
  const status = RESULT_LINE[job.status] ? job.status : 'failed';
  return {...base, state: 'settled', status, summary: RESULT_LINE[status](job.effect, app)};
}

/** The owner's activity: approvals waiting first, then every agent call and account request grouped by day.
 *  Lines are written by Fabric from recorded state only; an uncertain write is never shown as done. */
export function activityPage({jobs = [], continuations = [], appName = id => id, capabilityName = () => null, accountName = () => null, clientName = () => null, prepared, now = Date.now(), cursor, limit = PAGE} = {}) {
  const size = Math.min(Math.max(Number.isSafeInteger(Number(limit)) ? Number(limit) : PAGE, 1), MAX_PAGE), start = decodeCursor(cursor);
  const bound = new Set(continuations.map(record => record?.binding?.jobId).filter(Boolean));
  const approvals = jobs.filter(job => job?.status === 'awaiting_approval' && Date.parse(job.approvalExpiresAt) > now).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).map(job => approvalItem(job, {appName, capabilityName, accountName, clientName, prepared}));
  const items = [
    ...jobs.filter(job => job && job.id).map(job => {
      const app = appName(job.preview?.application) || 'the app', status = RESULT_LINE[job.status] ? job.status : 'failed';
      return {callRef: job.id, kind: 'action', status, taskTitle: text(job.task?.title, 120) || null, title: job.kind === 'proxy' && job.proxy ? `${job.proxy.rowLabel} (${job.proxy.method})` : operationLabel(job.preview?.operation || capabilityName(job.capabilityId)),
        summary: RESULT_LINE[status](job.effect, app), appId: job.preview?.application || null, appName: app, account: accountName(job.connectionId), agent: clientName(job.source?.clientId),
        ...(bound.has(job.id) ? {viaRequest: true} : {}), at: job.updatedAt || job.createdAt};
    }),
    // A resumed request appears once, as its action; open or closed requests appear on their own.
    ...continuations.filter(record => record && record.status !== 'resumed').map(record => ({callRef: record.id, kind: 'account_request', status: record.status,
      taskTitle: text(record.taskTitle, 120) || null, title: `${operationLabel(capabilityName(record.grantEntry?.capabilityId))} needs a ${appName(record.grantEntry?.appId)} account`,
      summary: HANDOFF_LINE[record.status] || 'The account request closed', appId: record.grantEntry?.appId || null, appName: appName(record.grantEntry?.appId), agent: clientName(record.clientId),
      ...(['awaiting_owner', 'signing_in', 'awaiting_confirmation'].includes(record.status) ? {openUrl: `/continue/${encodeURIComponent(record.id)}`} : {}), at: record.updatedAt || record.createdAt})),
  ].sort((a, b) => String(b.at).localeCompare(String(a.at)));
  const page = items.slice(start, start + size), days = [];
  for (const item of page) {
    const key = dayKey(item.at);
    if (!days.length || days.at(-1).date !== key) days.push({date: key, items: []});
    days.at(-1).items.push(item);
  }
  return {approvals, days, ...(start + size < items.length ? {nextCursor: encodeCursor(start + size)} : {})};
}

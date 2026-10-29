// F03.1b: what a developer's server sees of the catalog. Pure projections: tenant app cards (no connection state, no
// browser-only or local apps), the app detail with its permission rows, categories, and the consent sheet that the
// Connect page shows an end user. Fabric writes every sentence; only the developer's own data-use note is theirs.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {CATEGORIES, accountRow} from '../ui-contracts.mjs';
import {PERMISSION_GROUPS, groupFor, memberData} from '../permission-groups.mjs';
import {PROXY_CONFIGS} from '../proxy-config.mjs';
import {lockedRowOf, rowMemberOf} from '../row-locks.mjs';
import {definitionFor, reviewedProviderIds} from '../providers/definitions.mjs';
import {normalizeAuthApp} from '../../contracts/auth-definition.mts';
import {offeredLevels, heldLevel, requestedLevel} from '../access-levels.mjs';
import {withPages} from '../connection-notes.mjs';
import {accessSummary} from '../app-detail.mjs';
import {capabilityPermissionHash, annotationsOf, actionChoices, actionRowGroups, actionStepScopes} from '../permissions.mjs';
import {sourceFor} from '../option-sources.mjs';

const PROVIDERS = JSON.parse(readFileSync(new URL('../../catalog/providers.json', import.meta.url), 'utf8')).providers;
const APPS = (() => { const data = JSON.parse(readFileSync(new URL('../../catalog/apps.json', import.meta.url), 'utf8')); return Array.isArray(data) ? data : data.apps; })();
const LEVEL_LABEL = {full: 'Full access', read: 'Read-only', read_write: 'Read and write', pages: 'Pages you choose'};
const text = (value, limit) => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, limit) : '';

/** The reviewed provider that signs users in to an app, and the app's normalized sign-in rules. */
export function signInOf(appId) {
  for (const providerId of reviewedProviderIds()) {
    const definition = definitionFor(providerId), entry = definition.apps.find(app => app.appId === appId);
    if (entry) return {providerId, definition, access: normalizeAuthApp(definition, entry)};
  }
  return null;
}
/** Apps a developer's end users can connect: a reviewed sign-in, never browser-only or local apps. */
export function tenantApps() { return APPS.filter(app => signInOf(app.id)); }

/** The developer party's app card: no connection state, OAuth only, absolute icon address. */
export function tenantAppCard(app, {origin}) {
  const category = CATEGORIES.find(item => item.id === app.categoryId);
  return {id: app.id, name: text(app.name, 80), tagline: text(app.tagline, 80) || text(app.description, 80), categoryId: category ? category.id : null,
    featured: app.featured === true, ...(app.featured === true && Number.isSafeInteger(app.featuredRank) ? {featuredRank: app.featuredRank} : {}),
    iconUrl: `${origin}/assets/icons/${encodeURIComponent(app.id)}`, authKinds: ['oauth'], driver: 'api', accessLevels: offeredLevels(signInOf(app.id).access)};
}

/** Search and paging over the tenant catalog. categoryIds may repeat; sort is name or featured; totalCount counts only connectable apps. */
export function tenantCatalog({origin, q = '', categoryIds = [], sort = 'featured', order = 'asc', after, limit = 50}) {
  if (!['name', 'featured'].includes(sort) || !['asc', 'desc'].includes(order)) throw Object.assign(new Error('sort must be name or featured; order asc or desc.'), {code: 'invalid_request'});
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw Object.assign(new Error('limit must be 1 to 100.'), {code: 'invalid_request'});
  const needle = text(q, 100).toLowerCase();
  let apps = tenantApps().filter(app => (!categoryIds.length || categoryIds.includes(app.categoryId)) && (!needle || `${app.id} ${app.name} ${app.tagline || ''} ${app.description || ''}`.toLowerCase().includes(needle)));
  const rank = app => sort === 'featured' ? [app.featured ? 0 : 1, app.featuredRank ?? 999, app.name.toLowerCase()] : [app.name.toLowerCase()];
  apps.sort((a, b) => { const x = rank(a), y = rank(b); for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1; return 0; });
  if (order === 'desc') apps.reverse();
  const totalCount = apps.length, start = after ? apps.findIndex(app => app.id === after) + 1 : 0;
  if (after && start === 0) throw Object.assign(new Error('Unknown cursor.'), {code: 'invalid_request'});
  const page = apps.slice(start, start + limit);
  return {apps: page.map(app => tenantAppCard(app, {origin})), pageInfo: {count: page.length, totalCount, ...(start + limit < totalCount ? {endCursor: page.at(-1).id} : {})}};
}

/** Categories that hold at least one connectable app; the device category never appears. */
export function tenantCategories() {
  const used = new Set(tenantApps().map(app => app.categoryId));
  return CATEGORIES.filter(category => used.has(category.id) && category.id !== 'device').map(({id, label, order}) => ({id, label, order}));
}

/** The reviewed rows as the developer sees them. A row Fabric locks (T4, F10.3) is Never for everyone, so it offers Never only. */
const groupsOf = appId => (PERMISSION_GROUPS.get(appId)?.groups || []).map(group => ({id: group.id, label: group.label, effect: group.effect, defaultMode: group.defaultMode,
  allowedModes: group.locked === 'fabric' ? ['deny'] : group.effect === 'delete' ? ['ask', 'deny'] : ['allow', 'ask', 'deny'], locked: group.locked === 'fabric', audience: group.audience === true}));

/** One app for the developer: card, description, permission rows and the provider's links. */
export function tenantAppDetail(appId, {origin}) {
  const app = tenantApps().find(item => item.id === appId);
  if (!app) return null;
  const {providerId} = signInOf(appId), provider = PROVIDERS[providerId];
  return {app: {...tenantAppCard(app, {origin}), description: text(app.description, 500), limitations: (app.limitations || []).slice(0, 10).map(item => text(item, 300)), ...(app.docsUrl ? {docsUrl: app.docsUrl} : {})},
    permissionGroups: groupsOf(appId), providerLinks: provider ? {termsUrl: provider.termsUrl, privacyUrl: provider.privacyUrl} : null};
}

/** One plain line on what runs without asking and what asks first, from the reviewed defaults. */
function defaultsLine(groups) {
  const list = items => items.length > 3 ? `${items.slice(0, 3).join(', ')} and more` : items.join(', ');
  const allow = groups.filter(group => group.defaultMode === 'allow').map(group => group.label.toLowerCase());
  const ask = groups.filter(group => group.defaultMode === 'ask').map(group => group.label.toLowerCase());
  return [allow.length ? `Without asking: ${list(allow)}.` : '', ask.length ? `Asks you first: ${list(ask)}.` : ''].filter(Boolean).join(' ') || 'Everything asks you first.';
}

/**
 * The consent sheet the Connect page shows (section 6.5). Every sentence is Fabric's; `project.dataUse` is the only
 * developer text and appears only when set. Plain text throughout.
 */
/** `providerApp` is the environment's chosen app for this one: Fabric's shared app by default, or {kind: 'developer', consentScreenName}.
 *  `fixed`: the link signs in at one level (F10.4 reconnect and Add access), so the sheet offers only that one. `consentMode` (F10.7):
 *  what that sign-in app asks for under its consent policy, 'full' or 'required', so the access line promises only what it grants. */
export function consentSheet(appId, {origin, project, level, userHint, fixed = false, providerApp = null, consentMode = 'full'}) {
  const app = tenantApps().find(item => item.id === appId);
  if (!app) return null;
  const {providerId, access} = signInOf(appId), provider = PROVIDERS[providerId] || {name: providerId}, appName = text(project.appName, 80), name = text(app.name, 80);
  const levels = offeredLevels(access);
  // F10.7 (g5): for one release a developer's read_write names full access on a version 2 app.
  if (level !== undefined) level = requestedLevel(level, levels);
  if (level !== undefined && !levels.includes(level)) throw Object.assign(new Error('That access level is not offered for this app.'), {code: 'invalid_request'});
  const chosen = level ?? (levels.includes('full') ? 'full' : levels.includes('read_write') ? 'read_write' : levels[0]);
  const groups = groupsOf(appId), reads = groups.filter(group => group.effect === 'read').map(group => group.label.toLowerCase());
  const sheet = {
    app: {id: app.id, name, iconUrl: `${origin}/assets/icons/${encodeURIComponent(app.id)}`},
    developer: {appName, ...(project.logoUrl ? {logoUrl: project.logoUrl} : {})},
    // Notion grants pages the person picks rather than levels, so its line says that (UI-0's access line, section 6.4).
    accessLine: accessSummary({oauth: true, levels: levels.length ? levels : providerId === 'notion' ? ['pages'] : levels, consentMode, providerName: provider.name}),
    levels: levels.filter(item => !fixed || item === chosen).map(item => ({level: item, label: LEVEL_LABEL[item] || item, isDefault: item === chosen})),
    points: [
      {kind: 'reaches', title: `What ${appName} can reach`, text: `${appName} can use your ${name} account${reads.length ? `: ${reads.slice(0, 4).join(', ')}${reads.length > 4 ? ' and more' : ''}` : ''}.`},
      {kind: 'control', title: `You choose what ${appName} can do`, text: `Each permission is set to Allow, Ask or Never. ${appName} asks you before anything set to Ask. You can change these, or disconnect, at any time.`},
      {kind: 'caution', title: 'Keep an eye on it', text: 'AI agents can make mistakes. Check its activity, and set anything you are unsure about to Ask.'},
    ],
    defaults: groups.map(group => ({groupId: group.id, label: group.label, mode: group.defaultMode})),
    defaultsLine: defaultsLine(groups),
    notices: providerId === 'google' && providerApp?.kind !== 'developer' ? ['Only Google accounts Fabric has added as testers can connect, and access lasts 7 days.'] : [],
    ...(userHint ? {userHint: text(userHint, 80)} : {}),
    finePrint: [
      ...(project.dataUse?.text ? [{kind: 'developer_data_use', text: text(project.dataUse.text, 500), ...(project.dataUse.learnMoreUrl ? {learnMoreUrl: project.dataUse.learnMoreUrl} : {})}] : []),
      {kind: 'provider', text: `${appName} connects to ${provider.name} through Fabric. ${provider.name}'s terms and privacy policy apply.`, termsUrl: provider.termsUrl, privacyUrl: provider.privacyUrl},
      {kind: 'custody', text: `Fabric keeps your ${provider.name} sign-in encrypted and never gives it to ${appName} or its agent.`},
    ],
    providerApp: providerApp?.kind === 'developer' ? {kind: 'developer', consentScreenName: text(providerApp.consentScreenName, 80)} : {kind: 'shared', consentScreenName: 'Fabric', ...(providerId === 'google' ? {testing: {maxUsers: 100, expiresAfterDays: 7}} : {})},
    action: {label: `Connect ${name}`},
  };
  return {...sheet, etag: createHash('sha256').update(JSON.stringify(sheet)).digest('hex').slice(0, 32)};
}

/** The fields of a DeveloperAccountRow, and no others (D7): never scopes, tokens, identity ids, origins or the client id. */
export const DEVELOPER_ACCOUNT_FIELDS = Object.freeze(['accountRef', 'appId', 'displayName', 'email', 'status', 'healthy', 'attention', 'accessLevel', 'accessLabel', 'providerApp', 'isDefault', 'connectedAt', 'lastUsedAt', 'lastCheckedAt', 'nextCheckAt']);

/** One account as the developer's server sees it (section 5.7), built field by field from the stored connection. `pages` is the
 *  account's note (F10.19, lib/connection-notes.mjs pagesNote()), so a page grant reads "Pages you shared (N)". */
export function developerAccountRow(connection, {isDefault = false, notice = null, pages = null} = {}) {
  const row = accountRow(connection, {accessLevel: record => record.authMethod === 'oauth' ? withPages(heldLevel(signInOf(record.appId)?.access ?? null, record.scopes), pages) : 'custom', notice});
  const attention = connection.status === 'unavailable' && !notice ? `The last check could not reach the provider. Check again later.` : row.attention;
  const time = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
  const providerApp = connection.providerApp?.kind === 'developer' && typeof connection.providerApp.id === 'string' ? {kind: 'developer', id: connection.providerApp.id} : {kind: 'shared'};
  return {accountRef: row.accountRef, appId: connection.appId, displayName: row.displayName, ...(row.email ? {email: row.email} : {}), status: row.status, healthy: row.status === 'ready',
    ...(attention ? {attention} : {}), accessLevel: row.accessLevel, accessLabel: row.accessLabel, providerApp, isDefault: isDefault === true, connectedAt: time(connection.createdAt),
    ...(time(connection.lastUsedAt) ? {lastUsedAt: time(connection.lastUsedAt)} : {}), ...(time(connection.lastCheckedAt) ? {lastCheckedAt: time(connection.lastCheckedAt)} : {})};
}

/**
 * One account as the person sees it on Fabric's hosted pages (F03.10, UI-0 section 3.5): the account row's own fields,
 * plus whether it is the default and when it was last used. Never the app id, the provider app or check times.
 */
export function endUserAccountRow(connection, {isDefault = false, notice = null, pages = null} = {}) {
  const time = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
  return {...accountRow(connection, {accessLevel: record => record.authMethod === 'oauth' ? withPages(heldLevel(signInOf(record.appId)?.access ?? null, record.scopes), pages) : 'custom', notice}), isDefault: isDefault === true,
    ...(time(connection.lastUsedAt) ? {lastUsedAt: time(connection.lastUsedAt)} : {})};
}

/** The inputs of an operation that a reviewed option source can fill (F03.7d). */
export function optionInputs(capability) { return Object.keys(capability.inputSchema?.properties || {}).filter(name => sourceFor(capability.appId, name)).sort(); }

/** Where a capability sits for the developer's catalog, as {row, member}: the row Fabric locks, by its map operation or its request, else
 *  its reviewed row; and its member's own row data, placed as its decision places it (F10.6 correction 6), or null. F10.11 part m: an
 *  action answers from the action catalog `actions`: the row Fabric locks that a step meets, else its own row, and `action`: its status in
 *  the catalog, the rows it touches ({groupId, label}, its own first), whether one reaches people, and whether a step it cannot skip can
 *  never work through a sign-in. With no catalog entry, `action` is null. */
export function capabilityRow(capability, map, actions = null) {
  if (capability?.driver === 'action') {
    const item = actions?.entryOf?.(capability) ?? null, definition = PERMISSION_GROUPS.get(capability.appId), locked = item ? lockedRowOf(PERMISSION_GROUPS, PROXY_CONFIGS, capability, null, map, actions) : null;
    if (!item) return {row: null, member: null, action: null};
    const rows = actionRowGroups(definition, item.entry), steps = actionStepScopes(PERMISSION_GROUPS, actions, capability, map) ?? [];
    return {row: locked ?? definition?.groups.find(group => group.id === item.entry.row) ?? null, member: null,
      action: {status: item.status, rows: rows.map(group => ({groupId: group.id, label: group.label})), reachesPeople: rows.some(group => group.audience === true), unavailable: steps.some(step => !step.optional && Boolean(step.unavailable))}};
  }
  const operation = Array.isArray(map?.operations) ? map.operations.find(entry => entry && entry.capabilityId === capability.id) ?? null : null;
  const placed = rowMemberOf(PERMISSION_GROUPS, PROXY_CONFIGS, capability, operation, map);
  return {row: lockedRowOf(PERMISSION_GROUPS, PROXY_CONFIGS, capability, operation, map) ?? groupFor(PERMISSION_GROUPS, capability.appId, operation), member: placed ? memberData(placed.group, placed.member) : null};
}
/** One capability as the developer sees it (section 5.8): Fabric's own effect flags, never certified without live evidence. With
 *  its row, a locked operation says so and one that reaches other people says that too (F10.3), so a refused binding is explained;
 *  with its member, one no sign-in can ever run says that (F10.6). */
export function capabilityView(capability, {row = null, member = null, action = null} = {}) {
  // F10.11 part m: an action's hints are its reviewed ones, with what its rows say; it is certified only while the catalog runs it.
  if (capability.driver === 'action') {
    return {id: capability.id, appId: capability.appId, kind: 'action', name: capability.name, description: String(capability.description || '').slice(0, 500), effect: capability.effect, version: capability.version ?? 1,
      definitionHash: capabilityPermissionHash(capability), annotations: {...annotationsOf(capability), ...(row?.locked === 'fabric' ? {locked: true} : {}), ...(action?.reachesPeople ? {reachesPeople: true} : {}),
        ...(action?.unavailable ? {unavailable: true} : {})}, hasOptions: actionChoices(capability).length > 0, certified: capability.status === 'active' && action?.status === 'active'};
  }
  const effect = capability.effect ?? (capability.request?.method === 'GET' ? 'read' : 'write');
  return {id: capability.id, appId: capability.appId, kind: 'operation', name: capability.name, description: String(capability.description || '').slice(0, 500), effect, version: capability.version ?? 1,
    definitionHash: capabilityPermissionHash(capability), annotations: {readOnly: effect === 'read', destructive: effect === 'delete', idempotent: effect === 'read', openWorld: true, ...(row?.locked === 'fabric' ? {locked: true} : {}), ...(row?.audience === true ? {reachesPeople: true} : {}),
      ...(member?.unavailable ? {unavailable: true} : {})},
    hasOptions: optionInputs(capability).length > 0, certified: false};
}

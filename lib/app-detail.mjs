import {appCard, accountRow, permissionRow} from './ui-contracts.mjs';
import {groupFor, reviewedRead, memberKey, memberData, UNAVAILABLE_REASONS} from './permission-groups.mjs';
import {permissionEffect, leastPrivilegedExtra, mapIndex, scopeAlternatives, scopeSetsOf, sameRoute, ACTION_WORDS} from './permissions.mjs';
import {rowMemberOf} from './row-locks.mjs';
import {validateCapability, canonicalHash} from './compiler.mjs';
import {MAX_REQUESTED_SCOPES, usableScopes} from './providers/oauth2.mjs';
import {heldLevel} from './access-levels.mjs';
import {effectiveScopes} from '../contracts/auth-definition.mts';
import {LOCAL_DEPLOYMENT, endUser, ownedBy} from './tenant/deployment.mjs';
import {current, shownNotice} from './connection-notices.mjs';
import {limitationsFor} from './slack-limits.mjs';

// App detail screen (UI-2, docs/UI-0-SCREEN-CONTRACTS.md section 3.6): one account at a time, its
// operations as plain-language rows with Allow, Ask or Never, what still needs more provider access,
// background reads, reset and disconnect. The engine keeps deciding per operation; a row sets its
// members together, bound to what the owner saw (etag), with the same review rules as before.
const SECTIONS = [{id: 'read', label: 'Read permissions', effects: ['read']}, {id: 'write', label: 'Write and delete permissions', effects: ['write', 'delete']}];
const OTHER = {read: 'Other reads', write: 'Other changes', delete: 'Other deletions'};
// Operations that return credentials, or GETs named like a change, sit in their own rows whatever their group, so a
// row-level Allow never covers them, and Allow on these rows always needs confirming (F09.1, I9).
const SENSITIVE = {secrets: {read: 'Reads that return keys or secrets', write: 'Changes that return keys or secrets', delete: 'Deletions that return keys or secrets'},
  'suspected-write': {read: 'Reads that may change something', write: 'Reads that may change something', delete: 'Reads that may change something'}};
const BACKGROUND = 'backgroundPolicies';
/** F10.6: why a row that lacks access has no Add access, when no member that lacks it can be offered a scope sign-in asks for. */
export const NOT_OFFERED = `Not offered: ${UNAVAILABLE_REASONS['not-requested']}`;

/** One rule for every route: Allow on an operation is a decision (standing consent that needs confirming, and in a
 *  developer environment the decision power) when it is sensitive, or when it writes or deletes and is not one of its
 *  row's reviewed reads. Judged per operation, so a write sitting in a read row is still a decision. */
export function allowIsDecision(member) {
  return Boolean(member.decision.sensitivity) || (member.decision.effect !== 'read' && member.reviewedAsRead !== true);
}

function fail(code, message, extra) {const error = new Error(message); error.code = code; if (extra) Object.assign(error, extra); throw error;}
/** Rows in the order the app's reviewed definition lists them; anything else after, by id. */
const ranked = (groups, appId) => {const definition = groups?.get(appId); return id => {const index = definition?.groups.findIndex(group => group.id === id) ?? -1; return index < 0 ? 1e6 : index;};};
/** True when one named alternative is wholly within `scopes`, as decisions read provider access. */
const named = (scopeSets, scopes) => scopeSets.some(set => set.length > 0 && set.every(scope => scopes.has(scope)));
/** F10.6 (part h, A4): where a row's proxy record lands when the owner picks `mode`: that mode when the proxy row can take it, else the
 *  row's proxy default ("Raw requests still ask"). `same` when that is the record already in force, so nothing is written and no pending
 *  proxied approval in the row is refused (correction 10). */
const proxyPlan = (store, {entry, state}, mode) => {
  const target = entry.allowedModes.includes(mode) ? mode : entry.defaultMode, record = store.get('permissions', state.id);
  return {entry, target, same: target === entry.defaultMode ? !record || record.followsDefault === true : Boolean(record) && record.followsDefault !== true && !state.stale && record.mode === target};
};
/** F10.11 part k: whether an action runs on `scopes`, read from its steps (PermissionManager.actionScopes()): every step it cannot skip can
 *  work through a sign-in and holds one of its named alternatives, or needs none named. An optional step that lacks access is skipped
 *  (F10.9 R7), so it never counts. False when the catalog has no current entry for it. */
const actionHeld = (steps, scopes) => Array.isArray(steps) && steps.every(step => step.optional || !step.unavailable && (!step.scopeSets.length || step.scopeSets.some(set => !set.length) || named(step.scopeSets, scopes)));
/** Open question 13: Allow is confirmed whenever it turns a record on above its own default. Typed members: a change, a sensitive read
 *  or a decision member, over a typed default that is not Allow. The proxy record: Allow on a change, as F08.0 confirms it. */
const typedConfirm = row => {const typed = row.members.filter(member => member.capability); return typed.length > 0 && (row.effect !== 'read' || Boolean(row.sensitive) || typed.some(allowIsDecision)) && typed.some(member => member.decision.defaultMode !== 'allow');};
const proxyConfirm = plan => Boolean(plan) && plan.target === 'allow' && !plan.same && plan.entry.effect !== 'read';

/** The access promise on an app's page: made only when sign-in here can actually grant it. Full access is promised only
 *  when sign-in asks for the whole full level; under a 'required' consent policy it asks for the essentials. */
export function accessSummary({oauth, levels, consentMode, providerName, connectable}) {
  if (oauth && levels.includes('full')) return consentMode === 'full' ? 'Full access at sign-in. You control each permission below.'
    : 'Sign-in asks for what this app needs to work. Add the rest from the permission that needs it, below.';
  if (oauth && levels.includes('pages')) return `${providerName} shares only the pages you pick. You control each permission below.`;
  if (oauth && levels.includes('read_write')) return 'You can give read-only or read and write access';
  if (oauth && levels.includes('read')) return 'You can give read-only access';
  return connectable ? 'Access is set by the token or session you connect' : null;
}

export class AppDetailService {
  constructor({store, runtime, catalog, accessLevels, accessLevelOf, oauthProviderFor, revoke, deployment = LOCAL_DEPLOYMENT}) {
    Object.assign(this, {store, runtime, catalog, accessLevels, accessLevelOf, oauthProviderFor, revoke, deployment, owner: null});
  }
  /** F03.2: the same service seen by one end user of a developer environment; every account lookup is theirs only. */
  forUser(owner) { return Object.assign(Object.create(this), {owner: endUser(owner)}); }
  app(appId) {
    const app = this.catalog().find(item => item.id === appId);
    if (!app) fail('not_found', 'Application not found.');
    return app;
  }
  present(appId) {return this.store.list('connections').filter(connection => connection.appId === appId && !['revoked', 'pending_confirmation'].includes(connection.status) && ownedBy(connection, this.owner, this.deployment));}
  account(appId, accountRef) {
    const accounts = this.present(appId);
    if (accountRef === undefined || accountRef === null || accountRef === '') return accounts.find(connection => connection.status === 'ready') || accounts[0] || null;
    const account = accounts.find(connection => connection.id === accountRef);
    if (!account) fail('not_found', 'Account not found for this application.');
    return account;
  }
  /** Rows for one account: reviewed groups first, then one "Other" row per effect for anything ungrouped, then the sensitive
   *  rows, and last the row Fabric locks (F10.3, T4), which holds its members whatever their sensitivity. A typed operation with no
   *  map entry sits in the row its request does (F10.6 correction 3), and is left out when it fits no reviewed row, as before. F10.11 part
   *  k: an active action joins its declared row, or its sensitive row, beside the provider members its steps send. */
  rows(app, connection, {cards = false} = {}) {
    const permissions = this.runtime.permissions, map = this.store.get('applicationMaps', app.id), operations = Array.isArray(map?.operations) ? map.operations : [], index = mapIndex(map);
    // One memo for this listing: every action decision reads the account's proxy rows and typed templates once (part e).
    const mapped = new Set(operations.map(operation => operation.capabilityId).filter(Boolean)), rows = new Map(), memo = new Map();
    const typed = [...operations.map(operation => [operation.capabilityId ? this.store.get('capabilities', operation.capabilityId) : null, operation, null]),
      ...this.store.list('capabilities').filter(capability => capability.appId === app.id && sameRoute(connection, capability) && !mapped.has(capability.id)).map(capability => [capability, null, rowMemberOf(permissions.groups, permissions.configs, capability, null, map, permissions.actions)])];
    for (const [capability, operation, placed] of typed) {
      if (!capability || capability.appId !== app.id || !sameRoute(connection, capability) || (!operation && !placed && !permissions.lockedRowOf(capability, null, map))) continue;
      let decision;
      try {decision = this.runtime.permissions.decision(connection, capability, index, {memo});} catch {continue;}
      // Only an active action is on a row: a candidate, or one this Fabric cannot run now, is on none (I8). It sits in the row it declares
      // (its last perform step lands there), never the row a body route moved that step's member from.
      const action = capability.driver === 'action';
      if (action && decision.status !== 'active') continue;
      const effect = permissionEffect(capability), locked = this.runtime.permissions.lockedRowOf(capability, operation, map), sensitive = locked ? null : decision.sensitivity || null;
      const group = locked || (sensitive ? null : action ? permissions.groups.get(app.id)?.groups.find(item => item.id === decision.groupId) ?? null : placed ? placed.group : groupFor(this.runtime.permissions.groups, app.id, operation));
      const key = locked ? locked.id : sensitive ? `sensitive.${sensitive}.${effect}` : group ? group.id : `other.${effect}`;
      if (!rows.has(key)) rows.set(key, {id: key, label: sensitive ? SENSITIVE[sensitive][effect] : group?.label || OTHER[effect], effect: group?.effect || effect, order: locked ? 3 : sensitive ? 2 : group ? 0 : 1, sensitive, ...(locked ? {locked: true} : {}), members: []});
      const allowBlocked = capability.driver === 'browser' && effect !== 'read' || (connection.transport === 'persistent' || connection.sessionScope === 'browser-profile') && connection.identity?.verified !== true;
      rows.get(key).members.push({capability, reviewedAsRead: Boolean(group && reviewedRead(group, operation)), decision: {...decision, allowBlocked, candidate: capability.status === 'candidate'}});
    }
    // F10.6 (part g): every reviewed row with no typed member of this account is listed from the proxy's view of the account, even one
    // that must reconnect (display()), its members read as the proxy reads them (correction 8). Every row with a proxy setting carries it.
    const policy = this.runtime.proxyPolicy, definition = permissions.groups?.get(app.id), context = policy && definition ? policy.display(connection, definition) : null;
    for (const entry of context ? policy.rows(context).filter(item => item.group) : []) {
      const id = entry.group.id, held = rows.get(id);
      // F10.11 part k: a row that only actions joined still lists its provider members, read from the proxy; a typed member's row does not.
      if (!held || held.members.every(member => member.capability?.driver === 'action')) {
        const members = [...new Set([...entry.group.operations, ...entry.group.requests].map(memberKey))].map(member => policy.memberState(context, entry, member)).filter(Boolean)
          .map(decision => ({capability: null, member: decision.member, reviewedAsRead: decision.reviewedAsRead, decision}));
        if (held) held.members.push(...members);
        else rows.set(id, {id, label: entry.label, effect: entry.effect, order: entry.locked ? 3 : 0, sensitive: null, ...(entry.locked ? {locked: true} : {}), members});
      }
      rows.get(id).proxy = {entry, state: policy.base(context, entry)};
    }
    const rank = ranked(this.runtime.permissions.groups, app.id), sorted = [...rows.values()].sort((a, b) => a.order - b.order || rank(a.id) - rank(b.id) || a.label.localeCompare(b.label));
    // The app page's Add access carries its upgrade card (T7), built here once from the rows already decided. Each card reads the
    // same proxy rows, so they are read once too.
    const provider = cards ? this.oauthProviderFor(app.id) : null;
    let proxy;
    const cardFor = body => {try {const card = this.upgradeFor(provider, body, sorted, proxy ??= this.proxyDefaults(connection)); return card?.rows.length ? {upgrade: {rows: card.rows, etag: card.etag}} : {};} catch {return {};}};
    // A locked row is Never whatever access the account has, so it offers no Add access.
    return sorted.map(row => {
      const added = row.locked ? {} : this.addAccess(app, connection, row.members), state = row.proxy?.state;
      return {...row, view: permissionRow({id: row.id, label: row.label, effect: row.effect, sensitive: row.sensitive, locked: row.locked === true, audience: row.members.some(member => member.decision.audience === true),
        decisions: row.members.map(member => member.decision), ...added, ...(provider && added.addAccess ? cardFor(added.addAccess.body) : {}),
        ...(state ? {proxy: {mode: state.mode, defaultMode: row.proxy.entry.defaultMode, allowedModes: row.proxy.entry.allowedModes, source: state.source, revision: state.revision, bindingHash: state.bindingHash}} : {}),
        allowNeedsConfirm: typedConfirm(row) || proxyConfirm(row.proxy && proxyPlan(this.store, row.proxy, 'allow'))})};
    });
  }
  /** The account's proxy rows of reviewed groups, each with its setting and the scope alternatives of its members, read as decide()
   *  reads them: Discovery's from the map by id, else the row's own sets, and none for a member that can never work through a sign-in
   *  (F10.6). Read from the proxy's view of the account (display()), so an account that must reconnect still lists them on its cards
   *  (correction 1). None when the account has no proxy. */
  proxyRows(connection) {
    const policy = this.runtime.proxyPolicy, context = policy?.display(connection, this.runtime.permissions.groups?.get(connection.appId));
    if (!context) return [];
    const operations = new Map();
    for (const operation of Array.isArray(context.map?.operations) ? context.map.operations : []) if (operation && typeof operation === 'object' && typeof operation.id === 'string' && !operations.has(operation.id)) operations.set(operation.id, operation);
    return policy.rows(context).filter(entry => entry.group).map(entry => ({entry, state: policy.base(context, entry),
      sets: context.templates.filter(template => !template.unreviewed && template.groupId === entry.group.id).flatMap(template => {
        const data = memberData(entry.group, template.member), read = scopeSetsOf(operations.get(template.member) ?? null, data);
        return data.unavailable || read.invalid ? [] : [read.scopeSets];
      })}));
  }
  /** The account's proxy rows that run at a default Allow now, each with the scope alternatives of its members. */
  proxyDefaults(connection) {
    return this.proxyRows(connection).flatMap(({entry, state, sets}) => {
      if (state.source !== 'default' || state.mode !== 'allow') return [];
      return [{groupId: entry.group.id, label: entry.label, revision: state.revision, bindingHash: state.bindingHash, sets}];
    });
  }
  /**
   * T7, the upgrade card: every row, typed or proxy, that would run at Allow after the account holds `scopesAfter`. A member is
   * listed when it lacks provider access now, gains it afterwards, and its mode afterwards is Allow. The upgrade writes a new
   * authorization, so a saved or stale setting becomes Ask (Never stays Never), and only a default, which already carries
   * ceilings and Fabric's locks, can be Allow. The etag binds the authorization, the sign-in, the ceiling, the set asked for
   * and every listed row's policy, so a change between showing the card and starting refuses the start. A scope a granted parent
   * grants is held, now and after (F10.5), so a row that a returned parent turns on is listed too.
   */
  upgradeCard(connection, rows, scopesAfter, proxy = this.proxyDefaults(connection)) {
    const permissions = this.runtime.permissions, asked = [...new Set(scopesAfter)].sort(), card = new Map();
    const held = new Set(permissions.grantedScopes(connection)), after = new Set(permissions.grantedScopes({...connection, scopes: asked}));
    const gains = scopeSets => !named(scopeSets, held) && !scopeSets.some(set => !set.length) && named(scopeSets, after);
    // A typed row is one with a typed or action member: a row listed from the proxy alone (F10.6) is carded below, as a proxy row. An action
    // (F10.11 part k) is newly on when every step it runs holds what it needs afterwards.
    for (const row of rows) if (row.members.some(({capability, decision}) => capability && decision.providerAccess === 'missing' && decision.policySource === 'default' && decision.mode === 'allow' && this.heldWith(capability, decision, after)))
      card.set(row.id, {groupId: row.id, label: row.label, members: row.members.filter(member => member.capability).map(({decision}) => `${decision.capabilityId}:${decision.policyHash}`).sort(), proxy: null});
    for (const entry of proxy) if (entry.sets.some(gains)) card.set(entry.groupId, {groupId: entry.groupId, label: card.get(entry.groupId)?.label ?? entry.label, members: card.get(entry.groupId)?.members ?? null, proxy: [entry.revision, entry.bindingHash]});
    const rank = ranked(this.runtime.permissions.groups, connection.appId), listed = [...card.values()].sort((a, b) => rank(a.groupId) - rank(b.groupId) || a.groupId.localeCompare(b.groupId));
    const etag = canonicalHash({connectionId: connection.id, authRevision: connection.authRevision ?? null, signInRevision: connection.signInRevision ?? null, grantCeiling: [...new Set(connection.grantCeiling ?? connection.scopes ?? [])].sort(),
      scopesAfter: asked, rows: listed.map(entry => ({row: entry.groupId, members: entry.members ?? [], proxy: entry.proxy}))});
    return {rows: listed.map(entry => ({groupId: entry.groupId, label: entry.label, typed: entry.members !== null, proxy: entry.proxy !== null})), etag};
  }
  /** Whether a typed or action member holds what it needs with `scopes`: a typed one by its named alternatives, an action by every step it
   *  cannot skip (F10.11 part k). */
  heldWith(capability, decision, scopes) {
    return capability?.driver === 'action' ? actionHeld(this.runtime.permissions.actionScopes(capability), scopes) : named(decision.scopeSets, scopes);
  }
  /** What starting `input` on an existing account must confirm (T7): the card and the app scopes the sign-in plans, or null when
   *  the plan stays within what the owner approved (a renewal), or names no account or a disconnected one (a first sign-in).
   *  Identity scopes never count. `trusted` is the plan's own: a Connect session that names its account (F10.4). `input` is the
   *  start's own body, a full upgrade's flag included (F10.7), so the card reads exactly the set the sign-in asks for. */
  upgradeFor(provider, input, rows, proxy, trusted) {
    const planned = provider.plan(input, trusted), connection = planned.existing;
    if (!connection || connection.status === 'revoked') return null;
    const identity = provider.definition.authorization.identityScopes, scopes = [...new Set([...planned.scopes, ...planned.userScopes])].filter(scope => !identity.includes(scope)).sort();
    const ceiling = connection.grantCeiling ?? connection.scopes ?? [];
    if (scopes.every(scope => ceiling.includes(scope))) return null;
    return {...this.upgradeCard(connection, rows ?? this.rows(this.app(connection.appId), connection), scopes, proxy), scopes};
  }
  /**
   * The callback wall (T7), run right after an upgrade is stored: a member the upgrade newly granted at a default Allow that the
   * confirmed card did not cover (the provider granted more than was asked, or no card was confirmed at all) is saved at Ask
   * before anything can run on it. A proxy row counts as confirmed only when the card listed it (F10.6 correction 1). A first
   * sign-in (no `previous`, F10.7) has no card, and the scopes it asked for stand in for one.
   */
  pinUnconfirmed(previous, next, confirmedScopes) {
    // A scope a granted parent grants counts, before and in what was confirmed (F10.5).
    const permissions = this.runtime.permissions, before = new Set(previous ? permissions.grantedScopes(previous) : []);
    const confirmed = Array.isArray(confirmedScopes) ? new Set(permissions.grantedScopes({...next, scopes: confirmedScopes})) : before;
    let index = null;
    try {index = mapIndex(this.store.get('applicationMaps', next.appId));} catch {}
    // Every typed operation of the app, one with no map entry too: its decision reads the row data of the row its request sits in (F10.6).
    for (const capability of index ? this.store.list('capabilities') : []) {
      if (!capability || capability.appId !== next.appId || !sameRoute(next, capability)) continue;
      let decision;
      try {decision = this.runtime.permissions.decision(next, capability, index);} catch {continue;}
      if (decision.providerAccess !== 'granted' || decision.policySource !== 'default' || decision.mode !== 'allow') continue;
      // F10.11 part k: an action is newly on when the steps it runs did not all hold before, and the confirmed scopes would not have held them.
      if (capability.driver === 'action' ? this.heldWith(capability, decision, before) || this.heldWith(capability, decision, confirmed)
        : decision.scopeSets.some(set => !set.length) || named(decision.scopeSets, before) || named(decision.scopeSets, confirmed)) continue;
      this.runtime.permissions.set({connectionId: next.id, capabilityId: capability.id, mode: 'ask'});
    }
    // Raw requests: a proxy row the upgrade turns on at a default Allow runs only when the confirmed card listed it, read as the card read
    // it from the account before this sign-in; scopes that were only planned confirm nothing. When the proxy cannot route the account,
    // nothing is written: it cannot run then either.
    const gains = (held, after) => sets => !named(sets, held) && !sets.some(set => !set.length) && named(sets, after), now = new Set(permissions.grantedScopes(next));
    const carded = new Set(previous && Array.isArray(confirmedScopes) ? this.proxyDefaults(previous).filter(entry => entry.sets.some(gains(before, confirmed))).map(entry => entry.groupId) : []);
    // F10.7 (decision 9, correction 1): a first sign-in has no account before it, so what it asked for is its card for raw rows too,
    // read from the account it made. A plain first sign-in pins nothing; only what the provider granted beyond the plan starts at Ask.
    if (!previous && Array.isArray(confirmedScopes)) for (const entry of this.proxyDefaults(next)) if (entry.sets.some(gains(before, confirmed))) carded.add(entry.groupId);
    for (const entry of this.proxyDefaults(next)) {
      if (carded.has(entry.groupId) || !entry.sets.some(gains(before, now))) continue;
      try {this.runtime.proxyPolicy.set({connectionId: next.id, row: `group:${entry.groupId}`, mode: 'ask'});} catch {}
    }
  }
  /** The exact incremental-consent request for a row that needs more provider access: the least-privileged
   *  documented scopes for every member that lacks access, through the existing sign-in route. A member Fabric locks is
   *  Never whatever access the account has, so it never asks for a scope (T1, T4). A version 2 app asks only for scopes usable on
   *  the member's own reviewed row (F10.6), and a member none can cover is not offered without holding back the rest of its row. F10.11
   *  part k: an action asks for each step it cannot skip that lacks access, with the scopes usable on that step's own row. */
  addAccess(app, connection, members) {
    const missing = members.filter(member => member.decision.providerAccess === 'missing' && member.decision.locked !== true);
    if (!missing.length) return {};
    // The account's own sign-in where a deployment tells sign-ins apart (F10.6: a developer environment's rows ask whether Add could offer anything).
    const provider = connection.authMethod === 'oauth' ? this.oauthProviderFor(app.id, connection) : null;
    if (!provider || !provider.availability().available) return {addBlocked: provider ? provider.availability().reason || 'Sign-in is not available here.' : 'This account was not connected through sign-in, so more access cannot be added here.'};
    const definition = provider.app(app.id), reading = provider.access(definition), documented = new Set((this.store.get('applicationMaps', app.id)?.operations || []).flatMap(operation => operation.requiredScopes || []));
    // What the account holds, with every scope a granted parent grants (F10.5): Add access never asks for one again.
    const held = effectiveScopes(reading, Array.isArray(connection.scopes) ? connection.scopes : []), scopes = new Set();
    let skipped = 0;
    for (const {capability, decision} of missing) {
      const steps = capability?.driver === 'action' ? this.runtime.permissions.actionScopes(capability) : null;
      if (capability?.driver === 'action' && !steps) {skipped++; continue;}
      const needs = steps ? steps.filter(step => !step.optional && !actionHeld([step], new Set(held))) : [decision];
      for (const need of needs) {
        const usable = usableScopes(reading, need.groupId);
        const extra = leastPrivilegedExtra(need.scopeSets, held, usable ?? (scope => provider.belongsToApp(definition, scope) && documented.has(scope)));
        if (extra === null) {if (usable) {skipped++; continue;} return {addBlocked: 'This permission is not available through sign-in for this app.'};}
        for (const scope of extra) scopes.add(scope);
      }
    }
    if (skipped && !scopes.size) return {addBlocked: NOT_OFFERED};
    if (scopes.size > MAX_REQUESTED_SCOPES) return {addBlocked: 'This permission needs too many provider scopes to add at once.'};
    // A version 2 account adds to the level it holds, so Add access never narrows it to read; version 1 is unchanged (T6).
    const level = reading.schemaVersion === 2 ? {level: heldLevel(reading, connection.scopes) === 'read' ? 'read' : 'full'} : {};
    return {addAccess: {providerId: provider.providerId, body: {connectionId: connection.id, ...level, scopes: [...scopes].sort()}}};
  }
  /** T2 (F10.5): the permissions a sign-in without `scopes` leaves without access, as [{groupId, label}] in row order: the rows
   *  of members none of whose named alternatives avoids a missing scope. A typed operation counts when it is active or still a candidate,
   *  as the page lists both (live session 1: a fresh discovery is all candidates, and the refusal named none); a disabled one does not.
   *  A row Fabric locks is Never anyway, so never listed.
   *  F10.11 part k: an active action counts in the row it sits in when a step it cannot skip has no alternative that avoids one. */
  rowsNeeding(appId, scopes) {
    const app = this.app(appId), missing = new Set(scopes), map = this.store.get('applicationMaps', appId), permissions = this.runtime.permissions, rows = new Map();
    const add = (capability, sensitive, group) => {
      const effect = permissionEffect(capability), key = sensitive ? `sensitive.${sensitive}.${effect}` : group ? group.id : `other.${effect}`;
      if (!rows.has(key)) rows.set(key, {groupId: key, label: sensitive ? SENSITIVE[sensitive][effect] : group?.label || OTHER[effect], order: sensitive ? 2 : group ? 0 : 1});
    };
    for (const operation of Array.isArray(map?.operations) ? map.operations : []) {
      const capability = operation?.capabilityId ? this.store.get('capabilities', operation.capabilityId) : null;
      if (!capability || capability.appId !== app.id || capability.driver !== 'http' || !['active', 'candidate'].includes(capability.status) || permissions.lockedRowOf(capability, operation, map)) continue;
      const {scopeSets, invalid} = scopeAlternatives(operation);
      if (invalid || !scopeSets.length || !scopeSets.every(set => set.some(scope => missing.has(scope)))) continue;
      const sensitive = permissions.sensitivityOf(capability, operation, map) || null;
      add(capability, sensitive, sensitive ? null : groupFor(permissions.groups, app.id, operation));
    }
    for (const capability of this.store.list('capabilities')) {
      const item = capability?.driver === 'action' && capability.appId === app.id ? permissions.actions?.entryOf?.(capability) : null;
      if (!item || item.status !== 'active' || capability.status !== 'active' || permissions.lockedRowOf(capability, null, map)) continue;
      if (!(permissions.actionScopes(capability, map) ?? []).some(step => !step.optional && step.scopeSets.length && step.scopeSets.every(set => set.some(scope => missing.has(scope))))) continue;
      const sensitive = permissions.sensitivityOf(capability, null, map) || null;
      add(capability, sensitive, sensitive ? null : permissions.groups.get(app.id)?.groups.find(group => group.id === item.entry.row) ?? null);
    }
    const rank = ranked(permissions.groups, app.id);
    return [...rows.values()].sort((a, b) => a.order - b.order || rank(a.groupId) - rank(b.groupId) || a.label.localeCompare(b.label)).map(({groupId, label}) => ({groupId, label}));
  }
  view(appId, accountRef) {
    const app = this.app(appId), connection = this.account(appId, accountRef), levels = this.accessLevels(appId);
    const rows = connection ? this.rows(app, connection, {cards: true}) : [];
    const provider = this.oauthProviderFor(appId), oauth = provider?.availability().available === true;
    // Only what can actually happen here: a connect route the runtime reports as available, or the reason it is not.
    const options = Array.isArray(app.connectionOptions) ? app.connectionOptions : [];
    const usable = options.filter(option => option.enabled && option.availability === 'available');
    const blocked = options.find(option => option.availability === 'setup_required') || options[0] || null;
    const accounts = this.present(appId), notices = new Map(accounts.map(account => [account.id, current(this.store, account)]));
    // F10.5: the selected account's not-granted notice names its permissions that need what the sign-in did not get.
    if (connection && notices.has(connection.id)) notices.set(connection.id, notices.get(connection.id).map(notice => notice.kind === 'not_granted' ? this.notGranted(connection, notice, rows) : notice));
    const policy = connection ? this.store.get(BACKGROUND, connection.id) : null;
    const map = this.store.get('applicationMaps', appId);
    return {
      app: {...appCard(app, {party: 'owner', connections: this.store.list('connections'), accessLevels: () => levels}), description: String(app.description || '').slice(0, 500),
        // F10.21: under FABRIC_SLACK_DISTRIBUTION=distributed, Slack's page says how Slack limits the app (lib/slack-limits.mjs).
        limitations: [...(Array.isArray(app.limitations) ? app.limitations.slice(0, 10) : []), ...limitationsFor(app.id, this.runtime?.slackDistribution)], ...(app.docsUrl ? {docsUrl: app.docsUrl} : {})},
      // F10.4: what needs attention on each account's current sign-in, at the top of the page.
      notices: accounts.flatMap(account => notices.get(account.id).map(shownNotice)),
      connectionState: accounts.length ? 'connected' : 'not_connected',
      // A promise about access is made only when sign-in can actually grant it here.
      accessSummary: accessSummary({oauth, levels, consentMode: provider?.consentMode, providerName: provider?.name, connectable: usable.length > 0}),
      accounts: accounts.map(account => accountRow(account, {accessLevel: this.accessLevelOf, notice: notices.get(account.id)[0] ?? null})),
      selectedAccountRef: connection?.id ?? null,
      // The full level: a version 1 app's read-and-write set, unchanged (T6), or a version 2 app's full access.
      addAccount: oauth ? {kind: 'oauth', providerId: provider.providerId, body: {appId, level: 'full'}} : usable.length ? {kind: 'owner_ui', href: `/#connectors/${encodeURIComponent(appId)}`} : null,
      ...(oauth && levels.includes('full') && levels.includes('read') ? {addReadOnlyAccount: {kind: 'oauth', providerId: provider.providerId, label: 'Advanced: read-only access', body: {appId, level: 'read'}}} : {}),
      ...(oauth && connection?.authMethod === 'oauth' ? this.fullUpgrade(provider, connection, rows) : {}),
      // An account that must sign in again (the provider revoked it, or its sign-in lapsed) offers exactly that: a renewal on the same
      // account, which keeps every saved setting (lib/connections.mjs, T7). Its notice says so; "Add account" would make a new account
      // with none of them (live check of 2026-10-29, after Google access was removed from the test account).
      ...(oauth && connection?.authMethod === 'oauth' && ['reconnect_required', 'expired'].includes(connection.status)
        ? {renew: {label: 'Sign in again', providerId: provider.providerId, body: {appId, connectionId: connection.id}}} : {}),
      ...(oauth || usable.length ? {} : {connectBlocked: provider ? `${app.name} can't be connected here yet: ${provider.name} sign-in has not been set up by whoever runs this Fabric.`
        : String(blocked?.setupReason || 'Connecting this app is not available here yet.').slice(0, 300)}),
      sections: SECTIONS.map(section => ({id: section.id, label: section.label, rows: rows.filter(row => section.effects.includes(row.effect)).map(row => row.view)})).filter(section => section.rows.length),
      background: connection ? {mode: policy?.mode === 'deny' ? 'deny' : 'allow', allowedEffects: ['read'], runsWhile: 'runtime_running'} : null,
      // A saved proxy record is something to reset too (F10.6).
      canReset: rows.some(row => row.view.policySource !== 'default' || (row.proxy && row.proxy.state.source !== 'default')),
      // F10.18: certified actions that place with no map (GitHub's) are typed operations too, so their app says nothing about raw requests only.
      discovery: map || rows.some(row => row.members.some(member => member.capability?.driver === 'action')) ? {state: 'ready'}
        : {state: 'missing', message: rows.length ? 'These permissions apply to raw requests now. Discovering the app adds typed operations.' : 'This app\'s operations have not been discovered yet. Open it in the workspace to discover them.'},
    };
  }
  /** F10.5: the selected account's not-granted notice, with its own words and the permissions that need what the sign-in did not
   *  get: the typed rows with a member that lacks provider access and that those scopes would grant, then the proxy rows the same
   *  way, in row order. A row Fabric locks is Never anyway, so it is never named. Plain count words when they cannot be read. */
  notGranted(connection, notice, rows) {
    try {
      const permissions = this.runtime.permissions, held = new Set(permissions.grantedScopes(connection)), missing = Array.isArray(connection.grant?.missing) ? connection.grant.missing : [];
      const after = new Set(permissions.grantedScopes({...connection, scopes: [...held, ...missing]})), gains = scopeSets => !named(scopeSets, held) && named(scopeSets, after), listed = new Map();
      for (const row of rows) if (!row.locked && row.members.some(({capability, decision}) => decision.providerAccess === 'missing' && this.heldWith(capability, decision, after))) listed.set(row.id, row.label);
      const rank = ranked(permissions.groups, connection.appId), proxy = this.proxyRows(connection).filter(({entry, sets}) => !entry.locked && !listed.has(entry.group.id) && sets.some(gains));
      for (const {entry} of proxy.sort((a, b) => rank(a.entry.group.id) - rank(b.entry.group.id) || a.entry.group.id.localeCompare(b.entry.group.id))) listed.set(entry.group.id, entry.label);
      const shown = [...listed].map(([groupId, label]) => ({groupId, label})), one = notice.count === 1;
      return {...notice, rows: shown, message: `${notice.count} permission${one ? ' was' : 's were'} not granted at sign-in${shown.length ? `: ${shown.map(row => row.label).join('; ')}. Add ${one ? 'it' : 'them'} from ${shown.length === 1 ? 'that permission' : 'those permissions'} below.` : '.'}`};
    } catch {return notice;}
  }
  /** T7: a version 2 account that holds less than full access offers the upgrade, with the rows it would turn on at Allow. Within
   *  what the owner approved before, it is a renewal: no rows, and nothing to confirm. Dormant for version 1 apps (F10.7). */
  fullUpgrade(provider, connection, rows) {
    try {
      const reading = provider.access(provider.app(connection.appId)), held = heldLevel(reading, connection.scopes);
      // F10.19 (spec lines 1176-1177): a page grant (Notion) has no fuller level. "Share more pages" signs in again on the same account, where
      // the provider's own page picker adds pages: a renewal with no scopes, so there are no rows to confirm and every setting is kept.
      if (reading.schemaVersion === 2 && reading.grant === 'pages') return {upgrade: {label: 'Share more pages', providerId: provider.providerId, body: {connectionId: connection.id}, rows: [], etag: null}};
      if (reading.schemaVersion !== 2 || !['partial', 'read', 'custom'].includes(held?.level ?? held)) return {};
      // F10.7 (g6, correction 2): an explicit full upgrade, so the card and the sign-in ask for the whole full level under any policy.
      const body = {connectionId: connection.id, level: 'full', fullUpgrade: true}, card = this.upgradeFor(provider, body, rows);
      return {upgrade: {label: 'Upgrade to full access', providerId: provider.providerId, body, rows: card?.rows ?? [], etag: card?.rows.length ? card.etag : null}};
    } catch {return {};}
  }
  ready(appId, accountRef) {
    const connection = this.account(appId, accountRef);
    if (!connection || connection.status !== 'ready' && connection.status !== 'session_ready') fail('invalid_request', 'Choose a ready account before changing its permissions.');
    return connection;
  }
  /** Sets every member of one row, bound to the row the owner saw. Allow on a write asks for an explicit
   *  confirmation (standing consent); generated operations need the review the workspace already asks for. F10.6 (A4): the same
   *  control writes the row's proxy record, through the proxy's own rows: the mode when the proxy row can take it, else its default. */
  setRow(appId, accountRef, body) {
    if (!body || typeof body !== 'object' || Object.keys(body).some(key => !['groupId', 'mode', 'etag', 'review', 'confirmAllow'].includes(key))) fail('invalid_request', 'Send the row, the mode and the row token only.');
    const connection = this.ready(appId, accountRef), app = this.app(appId);
    const row = this.rows(app, connection).find(item => item.id === body.groupId);
    if (!row) fail('not_found', 'Permission row not found.');
    if (body.etag !== row.view.etag) fail('view_changed', 'This permission changed. Review it again.', {view: this.view(appId, connection.id)});
    if (!row.view.allowedModes.includes(body.mode)) fail('invalid_request', row.view.blockedReason || 'Choose Allow, Ask or Never.');
    if (row.view.reviewRequired && body.mode !== 'deny' && body.review !== true) fail('review_required', 'These operations were generated from the provider\'s documentation. Review them before turning them on.');
    // When the proxy cannot route the account, or has no such row, only typed records are written (correction 9).
    const policy = this.runtime.proxyPolicy, members = row.members.filter(member => member.capability);
    let plan = null;
    if (row.proxy) try {const context = policy.route(connection.id), entry = policy.rows(context).find(item => item.row === `group:${row.id}`); if (entry) plan = proxyPlan(this.store, {entry, state: policy.base(context, entry)}, body.mode);} catch {}
    if (!members.length && !plan) fail('invalid_request', 'This permission covers raw requests, and this account cannot send them now. Nothing was changed.');
    if (body.mode === 'allow' && body.confirmAllow !== true && (typedConfirm(row) || proxyConfirm(plan))) fail('confirm_required', row.sensitive === 'secrets' ? 'These operations can return keys or secrets. Allow lets the agent run them without asking. Confirm to continue.'
      : row.sensitive ? 'These reads may change something. Allow lets the agent run them without asking. Confirm to continue.' : 'Allow lets the agent do this without asking, with any details. Confirm to continue.');
    // All or nothing: every member is checked before any is saved. F10.11 part k: an action takes a record only while the catalog holds its
    // reviewed definition, placed, whatever the mode, so one that changed since the page was read refuses the whole row before anything is
    // written (its record would be refused half way).
    const changed = members.find(({capability}) => capability.driver === 'action' && this.runtime.permissions.actions?.entryOf?.(capability)?.entry.unplaced !== false);
    if (changed) fail('capability_changed', `${changed.capability.name}: ${ACTION_WORDS.changed} Nothing was changed.`);
    // Never needs no other check, since restricting is always safe; Allow and Ask refuse the whole row when a member was made by older
    // compiler rules (F09.1) and must be discovered again, so a row never ends up half changed.
    if (body.mode !== 'deny') {
      const stale = members.filter(({capability}) => {if (capability.driver !== 'http') return false; try {validateCapability(capability); return false;} catch {return true;}});
      if (stale.length) fail('rediscover_required', `Discover ${app.name || appId} again before changing this row: ${stale.length === 1 ? 'one operation was' : `${stale.length} operations were`} made by older rules (${stale.slice(0, 3).map(({capability}) => capability.name).join(', ')}${stale.length > 3 ? ', ...' : ''}). Nothing was changed.`);
    }
    // The proxy record first: the row's etag covers its revision, so a change in between was refused above.
    if (plan && !plan.same) policy.set({connectionId: connection.id, row: plan.entry.row, mode: plan.target, confirmAllow: body.confirmAllow === true});
    for (const {capability} of members) {
      this.runtime.permissions.set({connectionId: connection.id, capabilityId: capability.id, mode: body.mode});
      // F10.11 (part d): a row's Allow or Ask never promotes an action; only its reviewed file and live evidence make it active.
      if (capability.status === 'candidate' && body.mode !== 'deny' && capability.driver !== 'action') {
        const promoted = {...capability, status: 'active'};
        this.store.put('capabilities', promoted); this.store.audit({type: 'capability.promoted', capabilityId: capability.id, definitionHash: canonicalHash(promoted)});
      }
    }
    return this.view(appId, connection.id);
  }
  reset(appId, accountRef, body = {}) {
    if (!body || typeof body !== 'object' || Object.keys(body).some(key => key !== 'groupIds') || (body.groupIds !== undefined && (!Array.isArray(body.groupIds) || body.groupIds.some(id => typeof id !== 'string')))) fail('invalid_request', 'Send the rows to reset, or nothing for all of them.');
    const connection = this.ready(appId, accountRef), rows = this.rows(this.app(appId), connection);
    const chosen = body.groupIds ? rows.filter(row => body.groupIds.includes(row.id)) : rows;
    this.runtime.permissions.reset({connectionId: connection.id, capabilityIds: chosen.flatMap(row => row.members.filter(member => member.capability).map(member => member.capability.id))});
    // F10.6: the same rows' proxy records go back to their defaults too, each with a fresh revision; none when the proxy cannot route.
    const proxied = chosen.filter(row => row.proxy).map(row => `group:${row.id}`);
    if (proxied.length) try {this.runtime.proxyPolicy.reset({connectionId: connection.id, rows: proxied});} catch {}
    return this.view(appId, connection.id);
  }
  /** Background actions: unattended reads for this account. Turning it off can only restrict. */
  setBackground(appId, accountRef, body) {
    if (!body || typeof body !== 'object' || Object.keys(body).some(key => key !== 'mode') || !['allow', 'deny'].includes(body.mode)) fail('invalid_request', 'Background actions are Allow or Never.');
    const connection = this.ready(appId, accountRef);
    this.store.put(BACKGROUND, {id: connection.id, connectionId: connection.id, mode: body.mode, updatedAt: new Date().toISOString()});
    this.store.audit({type: 'background.updated', connectionId: connection.id, mode: body.mode});
    return this.view(appId, connection.id);
  }
  /** Disconnect one account, the same way on every route: {account, remoteRevoked, message}, and `affected` after a confirmed
   *  revoke also signed out other apps of the same account (F10.4). `remote: false` disconnects here only; a revoke that would
   *  sign other apps out answers confirm_required naming them until `confirmSiblings: true`. */
  async disconnect(appId, accountRef, body = {}) {
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !['remote', 'confirmSiblings'].includes(key))
      || ['remote', 'confirmSiblings'].some(key => body[key] !== undefined && typeof body[key] !== 'boolean')) fail('invalid_request', 'Send remote and confirmSiblings only, each true or false.');
    const connection = this.account(appId, accountRef);
    if (!connection) fail('not_found', 'Account not found for this application.');
    // A confirm_required from the sign-in adapter carries its siblings and its words as they are.
    const result = await this.revoke(connection.id, {remote: body.remote, confirmSiblings: body.confirmSiblings});
    const stored = this.store.get('connections', connection.id) || {...connection, status: 'revoked'};
    return {account: accountRow(stored, {accessLevel: this.accessLevelOf}), remoteRevoked: result?.remoteRevoked === true,
      message: typeof result?.message === 'string' ? result.message : 'Disconnected. Fabric no longer holds this account\'s access.',
      ...(Array.isArray(result?.affected) && result.affected.length ? {affected: result.affected.map(item => ({connectionId: item.connectionId, appId: item.appId}))} : {})};
  }
}

/** Unattended reads respect each account's background setting. */
export function backgroundAllowed(store, connectionId) {return store.get(BACKGROUND, connectionId)?.mode !== 'deny';}

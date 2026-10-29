// F03.5b (docs/F03-DEVELOPER-LAYER.md sections 5.8 and 5.9): one end user's catalog, app page, runnable capabilities,
// and the permission changes a developer's server may relay for them. The relay table (D5) is enforced here, after the
// route's own scope: Never and Ask need permissions:write; Allow on a write, delete or sensitive row, a Reset that would
// bring such an Allow back, and background reads turned back on need decisions:write too. Promotion (`review`) is
// refused for everyone (N6), a developer ceiling refuses any mode above it (N7), and every relayed change is recorded
// with where it was made and which key made it possible (N13).
import {createHash} from 'node:crypto';
import {TenantError, notFound, invalid} from './errors.mjs';
import {tenantDeployment} from './deployment.mjs';
import {tenantApps, tenantAppDetail, signInOf, capabilityView, capabilityRow, endUserAccountRow} from './views.mjs';
import {developerParty, partyFields} from './party.mjs';
import {AppDetailService, allowIsDecision, NOT_OFFERED} from '../app-detail.mjs';
import {catalogPage} from '../ui-contracts.mjs';
import {offeredLevels, heldLevel} from '../access-levels.mjs';
import {pagesLevel} from '../connection-notes.mjs';

const BACKGROUND = 'backgroundPolicies';
const MORE_ACCESS = 'More access is added on Fabric\'s Connect page: create an add_access Connect session for this row.';
/** The same fact in the person's own words on Fabric's hosted page (F03.10). */
const MORE_ACCESS_PAGE = 'Ask the app for a link to add this access.';
const LOCKED_ROW = 'Fabric keeps this off: it gives access to other people or services.';

function only(body, fields) {
  if (body === undefined) body = {};
  if (body === null || typeof body !== 'object' || Array.isArray(body)) throw invalid('The body must be a JSON object.');
  if ('review' in body) throw invalid('review is not available to developers: generated operations are reviewed by Fabric\'s operator.');
  const unknown = Object.keys(body).find(key => !fields.includes(key));
  if (unknown) throw invalid(`Unknown field: ${unknown.slice(0, 40)}.`);
  return body;
}
/** The app service's own error codes, as the developer API's. */
function translated(error) {
  if (error instanceof TenantError) return error;
  const code = error?.code;
  if (code === 'not_found') return notFound();
  if (code === 'view_changed') return new TenantError(409, 'etag_mismatch', 'This permission changed. Read it again before changing it.');
  if (code === 'confirm_required') return new TenantError(409, 'confirm_required', String(error.message));
  if (code === 'review_required' || code === 'rediscover_required' || code === 'mode_not_allowed') return new TenantError(409, 'mode_not_allowed', String(error.message));
  if (code === 'invalid_request') return invalid(String(error.message));
  return error;
}
/** One row as shown: Add access and its upgrade card are never relayed (T7), so a row that needs more access says where it
 *  happens, or that no scope a sign-in asks for could add it (F10.6). A row Fabric locks is Never whatever access the account has,
 *  so it says nothing about adding any (F10.3). */
const rowView = (row, words = MORE_ACCESS) => {
  const {addAccess, addBlocked, upgrade, ...rest} = row;
  return rest.access === 'missing' && !rest.locked ? {...rest, addBlocked: addBlocked === NOT_OFFERED ? NOT_OFFERED : words} : rest;
};
/** N6: a member that is not active (a candidate), or that cannot do its job (the map or its row marks it unsupported, F10.6), can
 *  only be Never. A member read from the proxy alone has no capability. */
const inactive = member => Boolean(member.capability && member.capability.status !== 'active') || member.decision.status === 'unsupported';
/** T4: a row Fabric locks stays Never (F10.3). */
const allLocked = row => row.view.locked === true;
/** D5 and UI-0 decision 4: Allow on this row lets the agent write, delete or reach sensitive data without asking, so it is confirmed. */
const allowNeedsConfirm = row => row.effect !== 'read' || Boolean(row.sensitive) || row.members.some(allowIsDecision);
/** One environment's app service over its own runtime, so an upgrade card lists proxy rows too (F10.4). Fabric's Connect page
 *  passes the sign-in adapter it signs in with. The developer's routes pass each account's own, which only Add access reads, so a row
 *  can say when nothing could be offered (F10.6); they never relay Add access bodies or cards (T7). */
export function appService(env, runtime, oauthProviderFor = () => null) {
  return new AppDetailService({store: env.repository, runtime, catalog: () => tenantApps(), deployment: tenantDeployment(env.scope), oauthProviderFor,
    accessLevels: appId => offeredLevels(signInOf(appId)?.access ?? null),
    accessLevelOf: connection => connection.authMethod === 'oauth' ? pagesLevel(env.repository, connection, heldLevel(signInOf(connection.appId)?.access ?? null, connection.scopes)) : 'custom'});
}

export class TenantAppPages {
  /** @param {{stores: any, registry: any, providerApps: any, accounts: import('./accounts.mjs').TenantAccounts, origin: string, appSetting: Function}} deps */
  constructor(deps) { Object.assign(this, deps); }

  /** The environment's app service and permission engine, with the developer's ceilings applied. */
  #bundle(scope) {
    const env = this.stores.open(scope), environment = this.registry.get('environments', scope.environmentId);
    // The environment's own permission engine: its ceilings are read live from the registry (N7).
    const {permissions, runtime} = this.runtimes.bundle(scope), ceilingOf = permissions.ceilingOf;
    return {env, environment, permissions, service: appService(env, runtime, (appId, connection) => connection ? this.#signIn(scope, connection) : null), ceilingOf, scope};
  }
  /** The sign-in an account signs in again with (its own provider app's, else Fabric's shared one), or null. Only Add access reads
   *  it, so a row can say when no scope could be offered (F10.6); nothing it builds is relayed (T7). */
  #signIn(scope, connection) {
    const providerId = signInOf(connection.appId)?.providerId, own = connection.providerApp?.kind === 'developer' ? connection.providerApp.id : null;
    try { const adapter = own ? this.runtimes.developerAdapter(scope, own) : this.runtimes.bundle(scope).adapters.get(providerId); return adapter?.providerId === providerId ? adapter : null; } catch { return null; }
  }
  #owner(env, externalUserId) {
    const user = this.accounts.user(env, externalUserId);
    if (!user) throw notFound();
    return this.accounts.ownerOf(user);
  }
  /**
   * F03.10: who acts, for whom. A developer's route names the end user; Fabric's hosted page brings the owner from its
   * session. Either way the cores below see only {scope, owner, party}.
   */
  #actor(caller, externalUserId) { return {scope: caller.scope, owner: this.#owner(this.stores.open(caller.scope), externalUserId), party: developerParty(caller)}; }
  /** A row as shown to either party: the modes it can really take here, and whether Allow is confirmed. */
  #shown(bundle, appId, row, words) {
    const ceiling = bundle.ceilingOf(appId, row.id), idle = row.members.some(inactive), locked = allLocked(row);
    // N6: an operation that is not active can only be Never; N7: a ceiling only lowers; T4: a row of locked operations is
    // Never. Review is refused in tenants.
    const allowedModes = row.view.allowedModes.filter(mode => idle || locked || ceiling === 'deny' ? mode === 'deny' : ceiling === 'ask' ? mode !== 'allow' : true);
    return {...rowView(row.view, words), allowedModes, reviewRequired: false, allowNeedsConfirm: allowNeedsConfirm(row)};
  }
  /** One present account of the named user, as the app service sees it. */
  #account(bundle, owner, accountRef) {
    const row = this.accounts.rows(bundle.env, owner).find(item => item.accountRef === accountRef);
    if (!row) throw notFound();
    const connection = bundle.env.repository.get('connections', accountRef);
    if (connection.status !== 'ready') throw new TenantError(409, 'connection_required', 'This account needs to be reconnected before its permissions change.');
    return connection;
  }
  #backgroundEtag(env, connectionId) {
    const policy = env.repository.get(BACKGROUND, connectionId);
    return createHash('sha256').update(`${connectionId}:${policy?.mode ?? 'allow'}:${policy?.updatedAt ?? ''}`).digest('hex').slice(0, 32);
  }

  /** GET /v1/users/:ext/apps/:appId?account= : the end user's view of one app. It never defaults to another user's account. */
  view(caller, externalUserId, appId, accountRef) {
    if (!tenantApps().some(app => app.id === appId)) throw notFound();
    return this.viewFor(this.#actor(caller, externalUserId), appId, accountRef);
  }
  /**
   * One app for one owner. The developer's view carries its account rows and proxy rows; the person's own view on
   * Fabric's page carries only the account fields a person sees (UI-0 section 3.5) and no proxy rows (Q10).
   */
  viewFor({scope, owner}, appId, accountRef, {endUser = false} = {}) {
    if (!tenantApps().some(app => app.id === appId)) throw notFound();
    const bundle = this.#bundle(scope), service = bundle.service.forUser(owner);
    let page;
    try { page = service.view(appId, accountRef || undefined); } catch (error) { throw translated(error); }
    const connection = page.selectedAccountRef ? bundle.env.repository.get('connections', page.selectedAccountRef) : null;
    const rows = new Map((connection ? service.rows(service.app(appId), connection) : []).map(row => [row.id, row])), words = endUser ? MORE_ACCESS_PAGE : MORE_ACCESS;
    const sections = page.sections.map(section => ({...section, rows: section.rows.map(item => rows.has(item.groupId) ? this.#shown(bundle, appId, rows.get(item.groupId), words) : rowView(item, words))}));
    return {app: tenantAppDetail(appId, {origin: this.origin}).app, notices: page.notices, connectionState: page.connectionState, accounts: this.accounts.rows(bundle.env, owner, appId, endUser ? endUserAccountRow : undefined), selectedAccountRef: page.selectedAccountRef,
      sections, background: page.background ? {...page.background, etag: this.#backgroundEtag(bundle.env, page.selectedAccountRef)} : null, canReset: page.canReset,
      ...(endUser ? {} : {proxyRows: page.selectedAccountRef ? this.#proxyRows(scope, page.selectedAccountRef) : []})};
  }

  /** The account's proxy rows (F08.0 section 5): one setting per row for requests the developer sends through the proxy. */
  #proxyRows(scope, connectionId) {
    const policy = this.runtimes.bundle(scope).runtime.proxyPolicy;
    let rows;
    try { rows = policy.view(connectionId); } catch { return []; }
    return rows.map(row => ({groupId: row.row.startsWith('group:') ? row.row.slice('group:'.length) : row.row, label: row.label, effect: row.effect, mode: row.mode, defaultMode: row.defaultMode, allowedModes: row.allowedModes, source: row.source, etag: this.#proxyEtag(scope, connectionId, row.row)}));
  }
  #proxyEtag(scope, connectionId, row) {
    const policy = this.runtimes.bundle(scope).runtime.proxyPolicy, record = this.stores.open(scope).repository.get('permissions', policy.policyId(connectionId, row));
    return createHash('sha256').update(`${connectionId}:${row}:${record?.revision ?? 'default'}:${record?.mode ?? ''}`).digest('hex').slice(0, 32);
  }

  /** POST /v1/users/:ext/accounts/:ref/permissions {groupId, mode, etag, confirmAllow?} */
  setRow(caller, externalUserId, accountRef, body) { return this.setRowFor(this.#actor(caller, externalUserId), accountRef, body); }
  /** One row's mode for one owner's account, by either party. The person's page never sends proxy rows (Q10). */
  setRowFor({scope, owner, party}, accountRef, body, {proxyAllowed = true} = {}) {
    const changes = only(body, proxyAllowed ? ['groupId', 'mode', 'etag', 'proxy', 'confirmAllow'] : ['groupId', 'mode', 'etag', 'confirmAllow']);
    if (!['allow', 'ask', 'deny'].includes(changes.mode)) throw invalid('mode is allow, ask or deny.');
    if (typeof changes.groupId !== 'string' || typeof changes.etag !== 'string') throw invalid('Send the row id and the etag you were shown.');
    if (changes.proxy !== undefined && typeof changes.proxy !== 'boolean') throw invalid('proxy is true or false.');
    const bundle = this.#bundle(scope), connection = this.#account(bundle, owner, accountRef), service = bundle.service.forUser(owner);
    if (changes.proxy === true) return this.#setProxyRow(party, bundle, owner, connection, changes);
    let rows;
    try { rows = service.rows(service.app(connection.appId), connection); } catch (error) { throw translated(error); }
    const row = rows.find(item => item.id === changes.groupId);
    if (!row) throw notFound();
    if (changes.etag !== row.view.etag) throw new TenantError(409, 'etag_mismatch', 'This permission changed. Read it again before changing it.');
    // N7: a mode above the developer's own ceiling, or one the row cannot take, is refused rather than silently lowered.
    const ceiling = bundle.ceilingOf(connection.appId, row.id);
    if (!row.view.allowedModes.includes(changes.mode) || (ceiling === 'deny' && changes.mode !== 'deny') || (ceiling === 'ask' && changes.mode === 'allow')) throw new TenantError(409, 'mode_not_allowed', ceiling ? `This environment caps this permission at ${ceiling === 'deny' ? 'Never' : 'Ask'}.` : String(row.view.blockedReason || 'This mode is not available for this permission.'));
    // N6: an operation that is not active (a candidate, or one the map or its row marks unsupported) can only be set to Never.
    const idle = changes.mode !== 'deny' ? row.members.find(inactive) : null;
    if (idle) throw new TenantError(409, 'mode_not_allowed', idle.decision.status === 'unsupported' ? 'This permission includes operations that cannot do their job here; it can only be set to Never.' : 'This permission includes operations Fabric has not reviewed yet; it can only be set to Never.');
    if (changes.mode !== 'deny' && allLocked(row)) throw new TenantError(409, 'mode_not_allowed', LOCKED_ROW);
    // D5: Allow on a write, delete or sensitive row, or on any write member of a read row, is a decision, and needs the
    // decision power and an explicit confirmation.
    const decision = changes.mode === 'allow' && allowNeedsConfirm(row);
    if (decision && !party.canDecide) throw new TenantError(403, 'decision_not_permitted', 'Allow on this permission is a decision; it needs a key with decisions:write, or the person can choose it on Fabric\'s page.');
    if (decision && changes.confirmAllow !== true) throw new TenantError(409, 'confirm_required', 'Allow lets the agent do this without asking. Send confirmAllow: true to relay the person\'s confirmation.');
    try { service.setRow(connection.appId, connection.id, {groupId: row.id, mode: changes.mode, etag: changes.etag, ...(decision ? {confirmAllow: true} : {})}); } catch (error) { throw translated(error); }
    bundle.env.repository.audit({type: 'permission.relayed', ...partyFields(party), userRecordId: owner.userRecordId, accountRef: connection.id, groupId: row.id, mode: changes.mode, decision});
    const updated = service.rows(service.app(connection.appId), connection).find(item => item.id === row.id);
    return this.#shown(bundle, connection.appId, updated, party.decidedIn === 'fabric_page' ? MORE_ACCESS_PAGE : MORE_ACCESS);
  }

  /**
   * {groupId, mode, etag, proxy: true}: the row's setting for proxied requests, including rows Fabric has no typed
   * operation for yet. The same relay rules: a ceiling or a mode the row cannot take is refused; Allow on a change, or
   * on unreviewed Other reads, is a decision.
   */
  #setProxyRow(party, bundle, owner, connection, changes) {
    const policy = this.runtimes.bundle(bundle.scope).runtime.proxyPolicy;
    let rows;
    try { rows = policy.view(connection.id); } catch { throw new TenantError(422, 'proxy_unavailable', 'This account cannot use the proxy.'); }
    const row = rows.find(item => item.row === `group:${changes.groupId}` || (!item.row.startsWith('group:') && item.row === changes.groupId));
    if (!row) throw notFound();
    if (changes.etag !== this.#proxyEtag(bundle.scope, connection.id, row.row)) throw new TenantError(409, 'etag_mismatch', 'This permission changed. Read it again before changing it.');
    const ceiling = row.row.startsWith('group:') ? bundle.ceilingOf(connection.appId, changes.groupId) : null;
    if (!row.allowedModes.includes(changes.mode) || (ceiling === 'deny' && changes.mode !== 'deny') || (ceiling === 'ask' && changes.mode === 'allow')) throw new TenantError(409, 'mode_not_allowed', ceiling ? `This environment caps this permission at ${ceiling === 'deny' ? 'Never' : 'Ask'}.` : `This permission can be ${row.allowedModes.join(' or ')} for the proxy.`);
    const decision = changes.mode === 'allow' && row.mode !== 'allow' && (row.effect !== 'read' || !row.row.startsWith('group:'));
    if (decision && !party.canDecide) throw new TenantError(403, 'decision_not_permitted', 'Allow on this permission is a decision; it needs a key with decisions:write, or the person can choose it on Fabric\'s page.');
    if (decision && changes.confirmAllow !== true) throw new TenantError(409, 'confirm_required', 'Allow lets the agent send these requests without asking. Send confirmAllow: true to relay the person\'s confirmation.');
    try { policy.set({connectionId: connection.id, row: row.row, mode: changes.mode, confirmAllow: changes.mode === 'allow'}); } catch (error) { throw translated(error); }
    bundle.env.repository.audit({type: 'permission.relayed', ...partyFields(party), userRecordId: owner.userRecordId, accountRef: connection.id, groupId: changes.groupId, proxy: true, mode: changes.mode, decision});
    return this.#proxyRows(bundle.scope, connection.id).find(item => item.groupId === changes.groupId);
  }

  /** POST /v1/users/:ext/accounts/:ref/permissions/reset {groupIds?}: without the decision power, a write Allow comes back as Ask. */
  reset(caller, externalUserId, accountRef, body) { return this.resetFor(this.#actor(caller, externalUserId), accountRef, body); }
  /**
   * Back to the defaults, by either party. A write Allow comes back only through a relay with the decision power: on
   * Fabric's page it comes back as Ask, and the person turns Allow on row by row, with its confirmation (Q6).
   */
  resetFor({scope, owner, party}, accountRef, body) {
    const changes = only(body, ['groupIds']);
    if (changes.groupIds !== undefined && (!Array.isArray(changes.groupIds) || changes.groupIds.length > 100 || changes.groupIds.some(id => typeof id !== 'string'))) throw invalid('groupIds is a list of row ids.');
    const bundle = this.#bundle(scope), connection = this.#account(bundle, owner, accountRef), service = bundle.service.forUser(owner);
    const app = service.app(connection.appId), chosen = service.rows(app, connection).filter(row => !changes.groupIds || changes.groupIds.includes(row.id));
    const capabilityIds = chosen.flatMap(row => row.members.filter(member => member.capability).map(member => member.capability.id));
    bundle.permissions.reset({connectionId: connection.id, capabilityIds});
    const keepAllow = party.decidedIn === 'developer_app' && party.canDecide;
    let clamped = 0;
    if (!keepAllow) {
      // Synchronous from reset to clamp: no request runs between them, so no write Allow is ever in force. Judged on the
      // default before the developer's ceiling too: a ceiling can be lifted later, and an Allow that follows the default
      // would come back with it.
      for (const member of service.rows(app, connection).filter(row => !changes.groupIds || changes.groupIds.includes(row.id)).flatMap(row => row.members).filter(member => member.capability)) {
        if (allowIsDecision(member) && (member.decision.mode === 'allow' || (member.decision.defaultMode === 'allow' && member.decision.locked !== true))) { bundle.permissions.set({connectionId: connection.id, capabilityId: member.capability.id, mode: 'ask'}); clamped++; }
      }
    }
    // The proxy rows of the same rows go back to their defaults too. No proxy row defaults to Allow on a change.
    try { this.runtimes.bundle(scope).runtime.proxyPolicy.reset({connectionId: connection.id, ...(changes.groupIds ? {rows: changes.groupIds.map(id => id.startsWith('other-') || id === 'graphql' ? id : `group:${id}`)} : {})}); } catch { /* no proxy for this account */ }
    bundle.env.repository.audit({type: 'permission.relayed_reset', ...partyFields(party), userRecordId: owner.userRecordId, accountRef: connection.id, rows: chosen.length, clampedToAsk: clamped});
    const words = party.decidedIn === 'fabric_page' ? MORE_ACCESS_PAGE : MORE_ACCESS;
    return {rows: service.rows(app, connection).map(row => this.#shown(bundle, connection.appId, row, words)), clampedToAsk: clamped};
  }

  /** POST /v1/users/:ext/accounts/:ref/background {mode, etag}: turning background reads off needs no decision power; on does. */
  setBackground(caller, externalUserId, accountRef, body) { return this.setBackgroundFor(this.#actor(caller, externalUserId), accountRef, body); }
  setBackgroundFor({scope, owner, party}, accountRef, body) {
    const changes = only(body, ['mode', 'etag']);
    if (!['allow', 'deny'].includes(changes.mode)) throw invalid('Background actions are allow or deny.');
    const bundle = this.#bundle(scope), connection = this.#account(bundle, owner, accountRef);
    if (changes.etag !== this.#backgroundEtag(bundle.env, connection.id)) throw new TenantError(409, 'etag_mismatch', 'The background setting changed. Read it again before changing it.');
    if (changes.mode === 'allow' && !party.canDecide) throw new TenantError(403, 'decision_not_permitted', 'Turning background reads back on is a decision; it needs a key with decisions:write.');
    try { bundle.service.forUser(owner).setBackground(connection.appId, connection.id, {mode: changes.mode}); } catch (error) { throw translated(error); }
    bundle.env.repository.audit({type: 'background.relayed', ...partyFields(party), userRecordId: owner.userRecordId, accountRef: connection.id, mode: changes.mode});
    return {mode: changes.mode, allowedEffects: ['read'], runsWhile: 'runtime_running', etag: this.#backgroundEtag(bundle.env, connection.id)};
  }

  /** GET /v1/users/:ext/catalog : the end user's catalog with their connection states; never another user's. */
  catalog(caller, externalUserId, query = {}) {
    const user = this.accounts.user(this.stores.open(caller.scope), externalUserId);
    return this.catalogFor({scope: caller.scope, owner: user ? this.accounts.ownerOf(user) : null}, query);
  }
  /** One owner's catalog (no owner: nobody's accounts, every card available). */
  catalogFor({scope, owner}, {status, q, categoryId, cursor, limit} = {}) {
    const env = this.stores.open(scope), environment = this.registry.get('environments', scope.environmentId);
    const connections = owner ? this.accounts.accountsOf(env, owner) : [];
    // Each card's action comes from this environment's availability, not from any process-wide setting.
    const apps = tenantApps().map(app => {
      const setting = this.appSetting(app.id, environment, this.providerApps), ready = setting.enabled && setting.availability.state === 'ready';
      return {...app, authMethods: ['oauth'], connectionOptions: [{enabled: setting.enabled, availability: ready ? 'available' : setting.availability.state === 'setup_required' ? 'setup_required' : 'unavailable'}]};
    });
    let page;
    try { page = catalogPage({apps, connections, party: 'end_user', status: status || 'all', q: q || '', categoryId: categoryId || undefined, cursor: cursor || undefined, limit: limit || undefined, accessLevels: appId => offeredLevels(signInOf(appId)?.access ?? null)}); }
    catch (error) { throw invalid(String(error.message)); }
    const icon = card => ({...card, iconUrl: `${this.origin}/assets/icons/${encodeURIComponent(card.id)}`});
    return {...page, featured: page.featured.map(icon), categories: page.categories.map(entry => ({...entry, preview: entry.preview.map(icon)})), ...(page.results ? {results: page.results.map(icon)} : {})};
  }

  /** GET /v1/users/:ext/capabilities?appId= : what this user's ready accounts can run, Allow or Ask; Never and missing access left out (P17).
   *  Each is annotated from its row as in the catalog, so one that reaches other people says so here too (F10.3). F10.11 part m: runnable
   *  actions first, each with its T8 mode (every row its steps touch decides it). */
  capabilities(caller, externalUserId, {appId} = {}) {
    const bundle = this.#bundle(caller.scope), user = this.accounts.user(bundle.env, externalUserId);
    if (!user) return {capabilities: []};
    const out = [];
    for (const connection of this.accounts.accountsOf(bundle.env, this.accounts.ownerOf(user))) {
      if (connection.status !== 'ready' || (appId && connection.appId !== appId)) continue;
      const map = bundle.env.repository.get('applicationMaps', connection.appId);
      for (const decision of bundle.permissions.list(connection.id)) {
        if (!decision.executable || !['allow', 'ask'].includes(decision.mode)) continue;
        const capability = bundle.env.repository.get('capabilities', decision.capabilityId);
        if (capability?.status === 'active') out.push({...capabilityView(capability, capabilityRow(capability, map, bundle.permissions.actions)), accountRef: connection.id, mode: decision.mode});
      }
    }
    return {capabilities: [...out.filter(entry => entry.kind === 'action'), ...out.filter(entry => entry.kind !== 'action')]};
  }
}

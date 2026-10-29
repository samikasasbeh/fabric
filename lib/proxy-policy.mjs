import {randomUUID} from 'node:crypto';
import {canonicalHash} from './compiler.mjs';
import {PERMISSION_GROUPS, parseTemplate, groupFor, memberKey, memberData, UNAVAILABLE_REASONS} from './permission-groups.mjs';
import {templatesFor, matchRequest, routeMatch, fitsTemplate, aliasVariants} from './proxy-match.mjs';
import {normalizeProxyRequest, proxyBase, ProxyRequestError} from './proxy-request.mjs';
import {PROXY_CONFIGS} from './proxy-config.mjs';
import {scopeSetsOf, providerAccessOf, bindingIdentity} from './permissions.mjs';
import {typedRequest, LOCK_WORDS} from './row-locks.mjs';

// F08.0b: the owner's Allow/Ask/Never for proxied requests (docs/F08.0-GOVERNED-PROXY.md section 5).
// Each row has its own proxy setting, stored as its own record and never derived from the typed-operation
// settings. A request's mode is that setting, then the clamps, strictest wins:
//   c1 deletes at most Ask; c2 "Other changes" at most Ask; c3 "Other reads" at most the strictest read row
//   or typed read on the account; c4 at most the typed operation for the same endpoint; c5 Never passes down
//   to unreviewed sub-paths; c6 a change runs unattended only with the proxy's own Allow on a reviewed row;
//   c7 (an unresolved uncertain write to the same row) is applied by the caller at acceptance; c8 (developer
//   environments only) a saved Ask or Never on the row's typed operations caps the row.
// F10.3 (T4): a row Fabric locks is Never, and so is any request that fits one of its templates; a body route moves a request
// to a stricter row, still capped by the row it came from (body_route_source).
const MODES = ['allow', 'ask', 'deny'], STRICT = {allow: 0, ask: 1, deny: 2}, RANK = {read: 0, write: 1, delete: 2};
const strictest = (...modes) => modes.reduce((a, b) => STRICT[b] > STRICT[a] ? b : a, 'allow');
const OTHER = {'other-reads': {label: 'Other reads', effect: 'read'}, 'other-changes': {label: 'Other changes', effect: 'write'}, 'other-deletes': {label: 'Other deletes', effect: 'delete'}, graphql: {label: 'GraphQL requests', effect: 'write'}};
const fail = (code, message) => {throw new ProxyRequestError(code, message);};
const ready = connection => connection && connection.status === 'ready';

/** The row a match lands in: "group:<id>" for a reviewed row, otherwise the Other row's name. */
export const rowId = match => match.kind === 'group' ? `group:${match.groupId}` : match.kind;
/** T4 (F10.3): true when a canonical request fits any template of a row Fabric locks, whatever row it best matches. The proxy and an
 *  action's built requests (lib/actions-runtime.mjs checkConcrete(), F10.11 part g) read this one test. */
export function fitsLocked(templates, request, {style = 'rest'} = {}) {
  return templates.some(template => template.locked && fitsTemplate(template, request, {style}));
}

export class ProxyPolicy {
  /** `rowFloor` (developer environments): the person's own saved setting for a row is the floor for proxied requests in it (c8). */
  constructor({store, permissions, groups = PERMISSION_GROUPS, configs = PROXY_CONFIGS, rowFloor = false}) {Object.assign(this, {store, permissions, groups, configs, rowFloor});}

  policyId(connectionId, row) {return canonicalHash({kind: 'proxy-row', connectionId, row});}

  /** The account, its app's reviewed settings and templates, or proxy_unavailable. */
  route(connectionId) {
    const connection = this.store.get('connections', connectionId);
    if (!ready(connection) || connection.driver !== 'http') fail('proxy_unavailable', 'The proxy needs a ready API account.');
    const config = this.configs.get(connection.appId), definition = this.groups.get(connection.appId);
    if (!config || !definition) fail('proxy_unavailable', 'This app has no reviewed proxy settings.');
    if (!Array.isArray(connection.allowedOrigins) || !connection.allowedOrigins.includes(proxyBase(config.apiBase).origin)) fail('proxy_unavailable', 'This account was not connected for the app\'s reviewed API address.');
    const map = this.store.get('applicationMaps', connection.appId);
    const templates = templatesFor(definition, config, map);
    if (!templates) fail('proxy_unavailable', 'This app\'s operations are not mapped yet, so its Never rows could not be enforced.');
    return {connection, config, definition, templates, map};
  }
  /** F10.6: route()'s context for showing an account's rows, without the ready check, so an account that must reconnect still lists
   *  them; null where route() refuses for any other reason. Only the app page reads it: changes and decisions keep route(). */
  display(connection, definition = this.groups.get(connection?.appId)) {
    const config = connection?.driver === 'http' ? this.configs.get(connection.appId) : null;
    if (!config || !definition) return null;
    try {
      if (!Array.isArray(connection.allowedOrigins) || !connection.allowedOrigins.includes(proxyBase(config.apiBase).origin)) return null;
      const map = this.store.get('applicationMaps', connection.appId), templates = templatesFor(definition, config, map);
      return templates ? {connection, config, definition, templates, map} : null;
    } catch {return null;}
  }

  /** Every row an account's proxy requests can land in, with its effect and the modes the owner may choose. */
  rows({config, definition}) {
    const other = config.style === 'rpc' ? ['other-changes'] : ['other-reads', 'other-changes', 'other-deletes', 'graphql'];
    return [...definition.groups.map(group => ({row: `group:${group.id}`, label: group.label, effect: group.effect, group, locked: group.locked === 'fabric', audience: group.audience === true})),
      ...other.map(row => ({row, ...OTHER[row], group: null, locked: false, audience: false}))]
      .map(entry => ({...entry, defaultMode: this.rowDefault(entry), allowedModes: this.allowedModes(entry, config, definition)}));
  }
  rowDefault({row, group}) {
    if (group?.locked === 'fabric') return 'deny';
    if (group) return group.defaultMode === 'deny' ? 'deny' : group.effect === 'read' && group.defaultMode === 'allow' ? 'allow' : 'ask';
    return ['other-deletes', 'graphql'].includes(row) ? 'deny' : 'ask';
  }
  allowedModes({row, group, effect}, config, definition = null) {
    // T4 (F10.3): no owner control opens a row Fabric locks.
    if (group?.locked === 'fabric') return ['deny'];
    // T4 (F10.3), every deployment: a GraphQL body can carry any grant, so an app with a locked row keeps its GraphQL row Never.
    if (row === 'graphql' && definition?.groups.some(entry => entry.locked === 'fabric')) return ['deny'];
    if (!group) return row === 'other-reads' ? MODES : ['ask', 'deny'];
    if (effect === 'read') return MODES;
    return effect === 'write' && config.proxyAllowable.includes(group.id) ? MODES : ['ask', 'deny'];
  }
  /**
   * What a row's setting (and a client's grant of it) is bound to: the account's authorization and the row's reviewed
   * definition with its resolved paths. An Other or GraphQL row is the complement of every reviewed row, so it is
   * bound to all of them: moving an endpoint out of any reviewed row changes it, and never widens it silently. A row that body
   * routes send requests into is bound to those routes too (F10.3); the row they come from only loses requests and keeps its hash.
   */
  binding({connection, config, templates, definition = this.groups.get(connection.appId)}, row) {
    const reviewed = templates.filter(template => !template.unreviewed && (!row.startsWith('group:') || `group:${template.groupId}` === row));
    const inbound = (definition?.groups ?? []).flatMap(group => (group.bodyRoutes ?? []).filter(route => `group:${route.to}` === row).map(route => {
      const kind = ['contains', 'equals', 'present'].find(key => Object.hasOwn(route, key));
      return `${group.id}|${route.member}|${route.pointer}|${kind}|${JSON.stringify(route[kind])}`;
    })).sort();
    return canonicalHash({kind: 'proxy-row', connectionId: connection.id, appId: connection.appId, authRevision: connection.authRevision ?? null, identity: bindingIdentity(connection.identity), createdAt: connection.createdAt ?? null,
      configHash: config.configHash, row, templates: reviewed.map(template => `${template.groupId}|${template.request}|${template.member}`).sort(), ...(inbound.length ? {inbound} : {})});
  }
  /** The row's own setting before clamps: saved, following the default, or (after drift) Never stays Never, anything else Asks. */
  base(context, entry) {
    const record = this.store.get('permissions', this.policyId(context.connection.id, entry.row));
    const bindingHash = this.binding(context, entry.row), stale = Boolean(record && record.bindingHash !== bindingHash);
    const follows = record?.followsDefault === true, saved = Boolean(record && !follows && !stale && MODES.includes(record.mode));
    let mode = follows ? entry.defaultMode : saved ? record.mode : stale ? (record.mode === 'deny' ? 'deny' : 'ask') : entry.defaultMode;
    if (!entry.allowedModes.includes(mode)) mode = entry.allowedModes.includes('ask') ? 'ask' : 'deny';
    // N7: a developer's ceiling on a reviewed row caps its proxy mode too; it never raises one.
    const ceiling = entry.group && this.permissions?.ceilingOf ? this.permissions.ceilingOf(context.connection.appId, entry.group.id) : null;
    if (ceiling === 'deny') mode = 'deny'; else if (ceiling === 'ask' && mode === 'allow') mode = 'ask';
    // Any existing record contributes its own revision, stale or not: 'default' means only that no record exists, so a
    // binding that drifts and returns can never make an old hash valid again.
    return {mode, stale, source: follows ? 'default' : saved ? 'saved' : stale ? 'stale' : 'default', revision: record ? `${record.revision}` : 'default', bindingHash, id: this.policyId(context.connection.id, entry.row)};
  }
  /**
   * Every typed HTTP operation of the account's app as a template relative to the proxy's base, with the alias
   * routes that reach it. Built from the capabilities themselves, so it holds whether or not a map is stored.
   * A path segment the grammar cannot read becomes a one-segment parameter: broader, so c4 only ever tightens.
   */
  typedTemplates({connection, config}) {
    const out = [];
    for (const capability of this.store.list('capabilities')) {
      if (!capability || capability.appId !== connection.appId || capability.driver !== 'http') continue;
      // One reading of a typed request for the proxy and the typed side (lib/row-locks.mjs).
      const typed = typedRequest(capability, config);
      if (!typed) continue;
      for (const request of aliasVariants(typed, config.aliases)) {
        try {out.push({capability, template: parseTemplate(request)});} catch {}
      }
    }
    return out;
  }
  /** The typed operations the stored map puts in one reviewed row of the account's app, for c8. */
  members({connection, map}, groupId) {
    const operations = Array.isArray(map?.operations) ? map.operations : [], out = [];
    for (const operation of operations) {
      if (!operation || typeof operation !== 'object' || !operation.capabilityId || groupFor(this.groups, connection.appId, operation)?.id !== groupId) continue;
      const capability = this.store.get('capabilities', operation.capabilityId);
      if (capability && capability.appId === connection.appId && capability.driver === 'http') out.push(capability);
    }
    return out;
  }
  /** F10.6: one reviewed member's provider access, read the way typed decisions read it (lib/permissions.mjs): a member its row marks
   *  unavailable never works; else Discovery's scopes where the stored map has the member by id, else the row's own sets. Malformed
   *  Discovery data says nothing, as before, and the row's sets never stand in for it. */
  memberAccess(connection, map, group, member) {
    const data = memberData(group, member);
    if (data.unavailable) return {providerAccess: 'unavailable', scopeSets: [], data};
    const operation = Array.isArray(map?.operations) ? map.operations.find(op => op && typeof op === 'object' && op.id === member) ?? null : null, {scopeSets, invalid} = scopeSetsOf(operation, data);
    return {providerAccess: invalid ? 'unknown' : providerAccessOf(connection, scopeSets, () => this.permissions.grantedScopes(connection)), scopeSets, data};
  }
  /**
   * F10.6 (correction 8): what one reviewed member of a row reads on the app page, as a decision. Its mode is the row's own setting,
   * then the clamps that hold for every request to it: Never when it runs only typed, sits in a row Fabric locks or can never work
   * through a sign-in, at most Ask for a delete or for a change outside proxyAllowable. Its effect is the proxy's (a reviewed read is a
   * read); it has no sensitivity, since the proxy has no input for one. Its hash covers what it shows and its row's record, and the
   * row's etag folds it in. Null for a member the row does not have; {+x} and {x} name one member.
   */
  memberState(context, entry, request) {
    const {connection, config, templates, map} = context, member = typeof request === 'string' ? memberKey(request) : null, template = entry.group ? templates.find(item => !item.unreviewed && item.groupId === entry.group.id && item.member === member) : null;
    if (!template) return null;
    const own = template.method === 'GET' ? 'read' : template.method === 'DELETE' ? 'delete' : 'write', reviewedAsRead = config.style !== 'rpc' && template.reviewedRead === true;
    const effect = config.style === 'rpc' ? entry.effect : reviewedAsRead ? 'read' : RANK[own] >= RANK[entry.effect] ? own : entry.effect;
    const state = this.base(context, entry), {providerAccess, scopeSets, data} = this.memberAccess(connection, map, entry.group, member), clamps = [];
    let mode = state.mode;
    const clamp = (name, limit) => {const next = strictest(mode, limit); if (next !== mode) {clamps.push(name); mode = next;}};
    if (config.typedOnly.includes(member)) clamp('typed_only', 'deny');
    if (entry.locked) clamp('t4_locked', 'deny');
    if (effect === 'delete') clamp('c1_delete', 'ask');
    if (effect !== 'read' && !config.proxyAllowable.includes(entry.group.id)) clamp('c6_change_needs_reviewed_allow', 'ask');
    if (providerAccess === 'unavailable') clamp('unavailable', 'deny');
    const policyHash = canonicalHash({kind: 'proxy-member', bindingHash: state.bindingHash, row: entry.row, member, rowRevision: state.revision, mode, clamps, providerAccess, scopeSets, configHash: config.configHash});
    return {member, groupId: entry.group.id, effect, mode, defaultMode: entry.defaultMode, clamps, providerAccess, ...(data.unavailable ? {unavailable: data.unavailable} : {}), ...(data.conditions ? {conditions: [...data.conditions]} : {}),
      scopeSets, sensitivity: null, reviewedAsRead, status: 'active', executable: ready(connection) && mode !== 'deny' && providerAccess !== 'missing' && providerAccess !== 'unavailable', requiresApproval: mode === 'ask',
      policySource: state.source, stale: state.stale, policyHash, ...(entry.locked ? {locked: true} : {}), ...(entry.audience ? {audience: true} : {})};
  }
  /** The typed decision and its record's revision, for c3 and c4. */
  typed(connection, capability) {
    try {
      const decision = this.permissions.decision(connection, capability);
      const record = this.store.get('permissions', this.permissions.policyId(connection.id, capability.id));
      return {mode: decision.mode, effect: decision.effect, revision: `${capability.id}:${record?.revision ?? 'default'}`};
    } catch {return {mode: 'deny', effect: 'write', revision: `${capability.id}:unavailable`};}
  }

  /**
   * The decision for one agent request on one account. Throws ProxyRequestError for anything the normalizer refuses
   * or when the proxy is unavailable. `unresolvedUncertain` applies c7, evaluated once by the caller at acceptance.
   */
  decide(connectionId, input, {timeoutMs, unresolvedUncertain = false} = {}) {
    const context = this.route(connectionId), {connection, config, definition, templates, map} = context;
    const request = normalizeProxyRequest(input, config, {timeoutMs});
    const found = matchRequest(templates, request, {style: config.style, inheritFamilies: config.inheritFamilies});
    // F10.3: a body that a route of its member matches moves the request to that stricter row, read from the canonical body.
    const match = routeMatch(definition, found, request, {style: config.style});
    const rows = this.rows(context), byRow = new Map(rows.map(entry => [entry.row, entry]));
    const entry = byRow.get(rowId(match));
    if (!entry) fail('invalid_request', 'This request does not fit any row of this app.');
    const base = this.base(context, entry), related = [], clamps = [];
    let mode = base.mode;
    const clamp = (name, limit) => {const next = strictest(mode, limit); if (next !== mode) {clamps.push(name); mode = next;}};
    if (match.kind === 'group' && config.typedOnly.includes(match.member)) clamp('typed_only', 'deny');
    // T4 (F10.3), every deployment: a row Fabric locks is Never, and so is a request that fits any of its templates, whatever row
    // it best matches. An app with a locked row keeps every GraphQL request Never: a GraphQL body can carry any grant.
    const anyLocked = fitsLocked(templates, request, {style: config.style});
    const graphqlLocked = match.kind === 'graphql' && definition.groups.some(group => group.locked === 'fabric');
    const fabricLocked = entry.locked || anyLocked || graphqlLocked;
    if (fabricLocked) clamp('t4_locked', 'deny');
    // A routed request is never looser than the row it came from.
    if (match.routedFrom) {const source = byRow.get(`group:${match.routedFrom.groupId}`), state = this.base(context, source); related.push(`${source.row}:${state.revision}`); clamp('body_route_source', state.mode);}
    // c4 for every row, Other rows included: any typed operation that routes this exact request caps it.
    const capped = new Set();
    for (const {capability, template} of this.typedTemplates(context)) {
      if (capped.has(capability.id) || !fitsTemplate(template, request, {style: config.style})) continue;
      capped.add(capability.id);
      const state = this.typed(connection, capability); related.push(state.revision); clamp('c4_typed_operation', state.mode);
    }
    // c8, developer environments: the end user sets a row once, on its typed operations. A saved Ask or Never on any of
    // the row's members caps every proxied request in the row; an Allow leaves the row's own proxy setting in force.
    if (this.rowFloor && match.kind === 'group') {
      for (const capability of [match.groupId, match.routedFrom?.groupId].filter(Boolean).flatMap(groupId => this.members(context, groupId))) {
        const record = this.store.get('permissions', this.permissions.policyId(connection.id, capability.id));
        if (!record || record.followsDefault === true) continue;
        const state = this.typed(connection, capability); related.push(state.revision); clamp('c8_row_setting', state.mode);
      }
    }
    if (match.effect === 'delete') clamp('c1_delete', 'ask');
    if (match.kind === 'other-changes') clamp('c2_other_changes', 'ask');
    if (match.kind === 'other-reads') {
      for (const read of rows.filter(row => row.group && row.effect === 'read')) {const state = this.base(context, read); related.push(`${read.row}:${state.revision}`); clamp('c3_read_rows', state.mode);}
      for (const capability of this.store.list('capabilities').filter(cap => cap.appId === connection.appId && cap.driver === 'http')) {
        const state = this.typed(connection, capability);
        if (state.effect === 'read') {related.push(state.revision); clamp('c3_typed_reads', state.mode);}
      }
    }
    for (const groupId of match.inheritFrom) {
      const inherited = byRow.get(`group:${groupId}`);
      if (!inherited) continue;
      const state = this.base(context, inherited);
      related.push(`${inherited.row}:${state.revision}`);
      if (state.mode === 'deny') clamp('c5_inherited_never', 'deny');
    }
    if (match.effect !== 'read' && !(match.kind === 'group' && config.proxyAllowable.includes(match.groupId))) clamp('c6_change_needs_reviewed_allow', 'ask');
    // Provider scopes: a local Allow cannot stand in for a missing scope (F10.6: the member's row data where the map is silent). A
    // routed request keeps its source member, so its data is read from the row it came from. A member that can never work through
    // a sign-in is Never, in the hash, so every Never check refuses it.
    const source = match.kind === 'group' ? definition.groups.find(group => group.id === (match.routedFrom?.groupId ?? match.groupId)) : null;
    const {providerAccess, data} = source ? this.memberAccess(connection, map, source, match.member) : {providerAccess: 'unknown', data: null}, unavailable = data?.unavailable ?? null;
    if (unavailable) clamp('unavailable', 'deny');
    // c7 is evaluated once, at acceptance, and stays out of the policy hash.
    const hashed = {mode, clamps: [...clamps]};
    if (unresolvedUncertain && match.effect !== 'read') clamp('c7_unresolved_uncertain', 'ask');
    const reason = fabricLocked ? LOCK_WORDS : unavailable ? UNAVAILABLE_REASONS[unavailable] : providerAccess === 'missing' ? 'The account does not have the provider scope this endpoint needs. Reconnect with that access.'
      : clamps.includes('typed_only') ? 'This operation runs only through a reviewed action, so the exact message can be shown. Use the Send email action.'
      : mode === 'deny' ? (clamps.includes('c5_inherited_never') ? `Never: it sits under "${byRow.get(`group:${match.inheritFrom[0]}`)?.label}", which is set to Never.` : `Never: "${entry.label}" is set to Never.`)
      : mode === 'ask' ? 'Each exact request must be approved before it runs.' : match.effect === 'read' ? 'Allowed by your setting for this row.' : 'Allowed by your proxy setting for this reviewed row. Requests are never replayed automatically.';
    const policyHash = canonicalHash({bindingHash: base.bindingHash, row: entry.row, mode: hashed.mode, rowRevision: base.revision, related: related.sort(), clamps: hashed.clamps, providerAccess, configHash: config.configHash,
      ...(match.routedFrom ? {routedFrom: match.routedFrom} : {})});
    const authority = this.store.authorityEnabled ? {connectionGeneration: this.store.connectionGeneration(connection.id), policyRevision: this.store.policyRevision(base.id)} : {};
    return {connectionId: connection.id, appId: connection.appId, row: entry.row, rowLabel: entry.label, groupId: match.groupId, effect: match.effect, mode, defaultMode: entry.defaultMode,
      allowedModes: entry.allowedModes, clamps, match, request, providerAccess, ...(unavailable ? {unavailable} : {}), executable: mode !== 'deny' && providerAccess !== 'missing' && providerAccess !== 'unavailable', requiresApproval: mode === 'ask', reason,
      policySource: base.source, stale: base.stale, bindingHash: base.bindingHash, policyHash, ...authority,
      ...(fabricLocked ? {locked: true} : {}), ...(entry.audience ? {audience: true} : {}), ...(match.routedFrom ? {routedFrom: match.routedFrom} : {})};
  }

  /** The owner's proxy rows for one account, for the app page. */
  view(connectionId) {
    const context = this.route(connectionId);
    return this.rows(context).map(entry => {const state = this.base(context, entry); return {row: entry.row, label: entry.label, effect: entry.effect, mode: state.mode, defaultMode: entry.defaultMode, allowedModes: entry.allowedModes, source: state.source,
      ...(entry.locked ? {locked: true} : {}), ...(entry.audience ? {audience: true} : {})};});
  }

  /** Sets one row's proxy mode. Allow on a change needs its own confirmation; modes outside the row's allowed list are refused. */
  set({connectionId, row, mode, confirmAllow = false}) {
    const context = this.route(connectionId), entry = this.rows(context).find(candidate => candidate.row === row);
    if (!entry) fail('invalid_request', 'That row is not part of this app.');
    if (entry.locked && mode !== 'deny') fail('invalid_request', LOCK_WORDS);
    if (!entry.allowedModes.includes(mode)) fail('invalid_request', `"${entry.label}" can be ${entry.allowedModes.join(' or ')} for the proxy.`);
    if (mode === 'allow' && entry.effect !== 'read' && confirmAllow !== true) fail('confirm_required', `Allowing "${entry.label}" lets agents make these changes without asking, with any details. Confirm to continue.`);
    const follows = mode === entry.defaultMode;
    // Choosing the default is still a new record with a fresh revision: never a deletion, so no ABA.
    this.store.put('permissions', {id: this.policyId(connectionId, row), kind: 'proxy-row', connectionId, row, mode, ...(follows ? {followsDefault: true} : {}), bindingHash: this.binding(context, row), revision: randomUUID(), updatedAt: new Date().toISOString()});
    this.store.audit({type: 'proxy.policy.updated', connectionId, row, mode, ...(follows ? {source: 'default'} : {})});
    return this.view(connectionId).find(candidate => candidate.row === row);
  }

  /** Reset to defaults for some or all rows: fresh revisions that follow the default. */
  reset({connectionId, rows}) {
    this.route(connectionId);
    const only = rows ? new Set(rows) : null;
    const changed = this.store.list('permissions').filter(record => record.kind === 'proxy-row' && record.connectionId === connectionId && record.followsDefault !== true && (!only || only.has(record.row)));
    for (const record of changed) this.store.put('permissions', {...record, followsDefault: true, revision: randomUUID(), updatedAt: new Date().toISOString()});
    this.store.audit({type: 'proxy.policy.reset', connectionId, count: changed.length});
    return changed.length;
  }
}

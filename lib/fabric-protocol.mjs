import {randomBytes, randomUUID, createHash, timingSafeEqual} from 'node:crypto';
import {canonicalHash} from './compiler.mjs';
import {capabilityPermissionHash, permissionEffect, annotationsOf, actionChoices, resourceDependent} from './permissions.mjs';
import {validatePrincipal} from '../contracts/identity.mts';
import {taskTitle} from './runtime.mjs';
import {callCard} from './cards.mjs';
import {LOCK_WORDS} from './row-locks.mjs';
// A grant name is shown to people on cards and pages: no invisible or direction-changing characters.
import {hasHidden} from '../public/hosted-text.js';

export const FABRIC_PROTOCOL = 'fabric/0.1';
export const protocolManifest = Object.freeze({
  protocol: FABRIC_PROTOCOL,
  product: 'Fabric',
  transport: {method: 'POST', path: '/fabric/v1', authentication: 'Bearer scoped-client-grant'},
  methods: ['fabric.discover', 'capabilities.list', 'calls.create', 'calls.get', 'calls.cancel', 'proxy.request', 'triggers.list', 'triggers.subscribe', 'events.list', 'triggers.unsubscribe'],
  states: ['awaiting_connection', 'awaiting_approval', 'queued', 'running', 'succeeded', 'failed', 'uncertain', 'cancelled', 'expired'],
  features: {typedCapabilities: true, scopedClients: true, revocation: true, idempotentCallRequests: true, outcomeEvidence: true, clientSelfApproval: false, mcpCompatible: false, missingAccessHandoff: 'designated-local-only', governedProxy: 'designated-local-only',
    actions: true, twoPhaseApproval: true, triggers: 'polling'},
  notice: 'Experimental Fabric contract, not an MCP endpoint. An account grant and runtime permission are both required.',
});

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const REQUESTABLE_KEYS = 'appId,capabilityId,capabilityVersion,definitionHash,effect,providerId';
const requestableEntry = entry => record(entry) && Object.keys(entry).sort().join() === REQUESTABLE_KEYS && cleanText(entry.appId, 64) && cleanText(entry.capabilityId, 256) &&
  Number.isSafeInteger(entry.capabilityVersion) && entry.capabilityVersion >= 1 && /^[a-f0-9]{64}$/.test(entry.definitionHash) && ['read', 'write', 'delete'].includes(entry.effect) && cleanText(entry.providerId, 64);
const hash = value => createHash('sha256').update(value).digest('hex');
const cleanText = (value, max) => typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function fail(code, message) {const error = new Error(message); error.code = code; throw error;}
function fields(value, allowed) {
  if (!record(value) || Object.keys(value).some(key => !allowed.includes(key))) fail('invalid_request', 'Unexpected request fields.');
}
function projection(client) {
  const {tokenHash, ...publicFields} = client;
  return publicFields;
}
const TERMINAL = new Set(['succeeded', 'failed', 'uncertain', 'cancelled', 'expired']);
/** F10.11 part l: what a listed entry is, by its stored capability: an action, or (anything else, or nothing stored) an operation. */
export const kindOf = capability => capability?.driver === 'action' ? 'action' : 'operation';
/** F10.11 parts l and m: actions first, then operations, each in the order given. fabric/0.1 lists them so in both deployments. */
export const actionsFirst = entries => [...entries.filter(entry => entry.kind === 'action'), ...entries.filter(entry => entry.kind !== 'action')];
/** F10.11 parts l and m: what fabric/0.1 lists of a capability beside its own fields, in both deployments: its kind, its four hints and,
 *  for an action, the schema of its checked output, the rows it touches (its own first, at most 16) and the inputs a choice list can fill. */
export function listedFields(permissions, cap) {
  return {kind: kindOf(cap), annotations: annotationsOf(cap), ...(cap.driver === 'action' ? {outputSchema: cap.outputSchema, rows: permissions.actionRows(cap), choices: actionChoices(cap)} : {})};
}
/** F10.11 parts l and m: an entry on an action id a newer version of its file replaced is unavailable, naming the action that replaced it
 *  and the date its file gives; null for any other id. */
export function supersededEntry(permissions, id, entry) {
  const replaced = permissions.actions?.superseded?.get?.(id);
  return replaced ? {...entry, kind: 'action', status: 'unavailable', reason: 'superseded', replacedBy: replaced.replacedBy, stopsAfter: replaced.stopsAfter} : null;
}
/** F10.11 parts l and m: the view a call's card is built from: an action whose reads ran waits on its exact final request, and its card
 *  says so; the approval pointer on the wire keeps its shape. */
export function cardView(view, job) {
  return job?.kind === 'action' && job.action?.readsDone === true && view.approval ? {...view, approval: {...view.approval, prepared: true}} : view;
}
const PROXY_REFUSALS = new Set(['invalid_path', 'parameter_not_allowed', 'header_not_allowed', 'method_not_allowed', 'unsupported_body', 'request_too_large', 'row_not_granted', 'policy_denied', 'provider_access_missing', 'proxy_unavailable', 'invalid_request']);
/** A proxy call as its client sees it: the job projection plus what was asked, the error code and, when authority
 *  has since changed, the result withheld while the status stays readable. */
function proxyJobResult(job, origin, {withheld = false, body = null} = {}) {
  const base = jobResult(job, origin);
  // The body comes from the response store while it is kept; the record says whether it was kept, dropped or expired.
  const result = withheld || !base.result ? null : {...base.result, response: {...base.result.response, ...(body || {}), payload: body ? 'stored' : base.result.response?.payload === 'stored' ? 'expired' : base.result.response?.payload ?? 'none'}};
  const errorCode = job.errorCode ?? (job.status === 'uncertain' ? 'outcome_uncertain' : null);
  return {...base, result, errorCode, reason: job.reason ?? null,
    request: {method: job.proxy.method, url: job.proxy.url, row: job.proxy.rowLabel, effect: job.effect}, ...(withheld ? {resultWithheld: true} : {})};
}
function jobResult(job, origin = null) {
  // Approval digests, provider identities, headers and owner-only previews are not
  // part of the client protocol. Approval happens in the owner's Fabric UI; the client
  // gets only the address of that page and when it lapses, to relay to a person.
  const approval = job.status === 'awaiting_approval' && origin && UUID.test(job.id) && !Number.isNaN(Date.parse(job.approvalExpiresAt))
    ? {approval: {url: `${new URL(origin).origin}/approve/${job.id}`, expiresAt: new Date(job.approvalExpiresAt).toISOString()}} : {};
  return {id: job.id, status: job.status, connectionId: job.connectionId, capabilityId: job.capabilityId, createdAt: job.createdAt, updatedAt: job.updatedAt, result: job.result, error: job.error, approvalRequired: job.status === 'awaiting_approval', ...approval};
}

export class FabricProtocol {
  constructor({store, runtime, clock = Date.now, origin = null, appName = id => id}) {Object.assign(this, {store, runtime, clock, origin, appName}); this.inflight = new Map(); this.refusals = new Map(); this.continuations = null; this.subscriptions = null; this.oauthRoute = () => null;}

  get authorityEnabled() {return this.store.authorityEnabled === true;}

  ownerPrincipal() {
    try {
      const owner = validatePrincipal(this.runtime.ownerPrincipal);
      if (owner.kind !== 'local_owner') throw new Error();
      return owner;
    } catch {fail('unauthorized', 'An explicitly configured local owner is required.');}
  }

  assertOwner(principal) {
    const owner = this.ownerPrincipal();
    try {
      if (canonicalHash(validatePrincipal(principal)) !== canonicalHash(owner)) throw new Error();
    } catch {fail('unauthorized', 'Only the configured local owner may grant client access.');}
    return owner;
  }

  // This derives identity from a server-owned grant. Token authentication at the
  // protocol boundary, or the runtime's accepted request, establishes the caller.
  principalForClient(client) {
    try {
      const owner = this.ownerPrincipal();
      if (canonicalHash(validatePrincipal(client.ownerPrincipal)) !== canonicalHash(owner)) throw new Error();
      return validatePrincipal({schemaVersion: 1, kind: 'local_client', id: client.id, scope: owner.scope, delegatedBy: {kind: 'local_owner', id: owner.id}});
    } catch {fail('unauthorized', 'Client ownership is missing or changed. Ask the owner for a new grant.');}
  }

  listClients() {return this.store.list('clientGrants').map(projection);}

  createClient(data, principal) {
    const owner = this.authorityEnabled ? this.assertOwner(principal) : null;
    if (this.authorityEnabled) canonicalHash(data);
    // A legacy store refuses request-only grants before looking at anything else in the body.
    if (data && typeof data === 'object' && Object.hasOwn(data, 'requestable') && (!this.authorityEnabled || !this.continuations)) fail('unsupported_route', 'Account requests require designated authority mode.');
    if (data && typeof data === 'object' && Object.hasOwn(data, 'proxy') && !this.authorityEnabled) fail('unsupported_route', 'The governed proxy requires designated authority mode.');
    fields(data, ['name', 'bindings', 'expiresInSeconds', 'requestable', 'proxy']);
    const {name, bindings, expiresInSeconds = 86400, requestable, proxy} = data;
    if (!cleanText(name, 80) || !name.trim() || hasHidden(name)) fail('invalid_request', 'Give the client a name of up to 80 visible characters.');
    if (!Number.isSafeInteger(expiresInSeconds) || expiresInSeconds < 60 || expiresInSeconds > 30 * 86400) fail('invalid_request', 'Client access must expire between one minute and 30 days.');
    // Request-only authority: the client may ask for these exact operations on an app it has no
    // account for. It never executes, lists accounts or adds bindings by itself.
    if (requestable !== undefined && (!this.authorityEnabled || !this.continuations)) fail('unsupported_route', 'Account requests require designated authority mode.');
    if (requestable !== undefined && (!Array.isArray(requestable) || requestable.length > 50)) fail('invalid_request', 'Select at most 50 operations the client may request access for.');
    const requestedIds = new Set();
    const requested = (requestable || []).map(item => {
      fields(item, ['capabilityId']);
      if (!cleanText(item.capabilityId, 256)) fail('invalid_request', 'Choose an operation.');
      if (requestedIds.has(item.capabilityId)) fail('invalid_request', 'Duplicate requestable operation.');
      requestedIds.add(item.capabilityId);
      return this.continuations.grantEntryFor(item.capabilityId);
    });
    const proxied = this.proxyGrantEntries(proxy);
    if (!Array.isArray(bindings) || bindings.length > 100 || bindings.length + requested.length + proxied.length < 1) fail('invalid_request', 'Select between 1 and 100 account-operation pairs.');
    const seen = new Set();
    const bound = bindings.map(binding => {
      fields(binding, ['connectionId', 'capabilityId']);
      if (!cleanText(binding.connectionId, 256) || !cleanText(binding.capabilityId, 256)) fail('invalid_request', 'Choose an account and capability.');
      const connection = this.store.get('connections', binding.connectionId), cap = this.store.get('capabilities', binding.capabilityId);
      if (!connection || !cap) fail('invalid_request', 'Choose an existing account and capability.');
      const decision = this.runtime.permissions.decision(connection, cap);
      // T4 (F10.3): an operation Fabric locks is never delegated, and the owner is told why.
      if (decision.locked) fail('permission_denied', LOCK_WORDS);
      if (!decision.executable) fail('permission_denied', 'Only currently permitted, reviewed operations may be delegated.');
      if (this.authorityEnabled && cap.driver === 'browser') fail('unsupported_route', 'Browser authority requires a reviewed provenance bridge before it can be delegated.');
      // Delegation permits a proposal, never approval or unattended UI actions.
      if (cap.driver === 'browser' && permissionEffect(cap) !== 'read' &&
          (connection.transport === 'persistent' || !(connection.bridgeVersion === '0.2' || (connection.bridgeVersion === '0.3' && connection.sessionScope === 'browser-profile')) ||
           !['click', 'fill'].includes(cap.action?.op) || !decision.requiresApproval)) {
        fail('unsupported_route', 'Browser action proposals require an inspected-control helper and exact owner approval.');
      }
      const key = canonicalHash(binding);
      if (seen.has(key)) fail('invalid_request', 'Duplicate account-operation pair.');
      seen.add(key);
      const authority = this.authorityEnabled ? {connectionGeneration: this.store.connectionGeneration(connection.id)} : {};
      return {...binding, definitionHash: capabilityPermissionHash(cap), bindingHash: decision.bindingHash, ...authority};
    });
    const id = randomUUID(), token = `fab_client.${id}.${randomBytes(32).toString('base64url')}`;
    const client = {id, name: name.trim(), bindings: bound, ...(requested.length ? {requestable: requested} : {}), ...(proxied.length ? {proxy: proxied} : {}), status: 'active', createdAt: new Date(this.clock()).toISOString(), expiresAt: new Date(this.clock() + expiresInSeconds * 1000).toISOString(), tokenHash: hash(token), ...(owner ? {ownerPrincipal: owner} : {})};
    this.store.put('clientGrants', client);
    this.store.audit({type: 'client.granted', clientId: id, operationCount: bound.length, requestableCount: requested.length, proxyCount: proxied.length});
    return {client: projection(client), token, notice: 'Shown once. This grants only the selected operations; it cannot approve actions or change permissions.'};
  }

  /**
   * Proxy grants (F08.0d): per account, an explicit list of rows the client may send proxied requests into
   * (reviewed rows by id, or other-reads, other-changes, other-deletes, graphql). No wildcards. Each row is bound to
   * the account's authorization and the row's reviewed definition, so a catalog or account change never widens it.
   * A row set to Never cannot be granted; for a row Fabric locks, the refusal says why (F10.3).
   */
  proxyGrantEntries(proxy) {
    if (proxy === undefined) return [];
    if (!Array.isArray(proxy) || proxy.length > 20) fail('invalid_request', 'Grant the proxy for at most 20 accounts.');
    const seen = new Set();
    return proxy.map(entry => {
      fields(entry, ['connectionId', 'rows']);
      if (!cleanText(entry.connectionId, 256) || seen.has(entry.connectionId)) fail('invalid_request', 'Choose each account once.');
      seen.add(entry.connectionId);
      if (!Array.isArray(entry.rows) || !entry.rows.length || entry.rows.length > 45 || new Set(entry.rows).size !== entry.rows.length || entry.rows.some(row => !cleanText(row, 200))) fail('invalid_request', 'Choose between 1 and 45 distinct rows.');
      let context;
      try {context = this.runtime.proxyPolicy.route(entry.connectionId);} catch {fail('invalid_request', 'Choose a ready account of an app with reviewed proxy settings.');}
      const rows = this.runtime.proxyPolicy.rows(context);
      return {connectionId: entry.connectionId, appId: context.connection.appId, configHash: context.config.configHash, connectionGeneration: this.store.connectionGeneration(entry.connectionId),
        rows: entry.rows.map(row => {
          const known = rows.find(candidate => candidate.row === row);
          if (!known) fail('invalid_request', `${row} is not a row of this app.`);
          if (known.locked) fail('permission_denied', LOCK_WORDS);
          if (this.runtime.proxyPolicy.base(context, known).mode === 'deny') fail('permission_denied', `"${known.label}" is set to Never, so it cannot be granted.`);
          return {row, bindingHash: this.runtime.proxyPolicy.binding(context, row)};
        })};
    });
  }

  /** The client's proxy grant for one account and row, current against the account, the reviewed settings and the row. */
  assertProxyGrant(clientId, connectionId, row) {
    const client = this.activeClient(clientId);
    const entry = (client.proxy || []).find(item => item.connectionId === connectionId);
    if (!entry) fail('permission_denied', 'This account was not granted to this client for proxied requests.');
    let generation, context;
    try {generation = this.store.connectionGeneration(connectionId); context = this.runtime.proxyPolicy.route(connectionId);} catch {fail('grant_changed', 'The account changed; the owner must review a new client grant.');}
    if (generation !== entry.connectionGeneration || context.config.configHash !== entry.configHash) fail('grant_changed', 'The account or the app\'s reviewed proxy settings changed; the owner must review a new client grant.');
    const granted = entry.rows.find(item => item.row === row);
    if (!granted) fail('row_not_granted', 'This client may not send requests that land in this row.');
    if (this.runtime.proxyPolicy.binding(context, row) !== granted.bindingHash) fail('grant_changed', 'The account or this row changed; the owner must review a new client grant.');
    return {client, entry};
  }

  /** The proxy section of capabilities.list: each granted account and row with its current mode. Nothing about other accounts. */
  proxyCapabilities(client) {
    return (client.proxy || []).map(entry => {
      let view;
      try {view = this.runtime.proxyPolicy.view(entry.connectionId);} catch {return {connectionId: entry.connectionId, appId: entry.appId, status: 'unavailable', reason: 'grant_changed', rows: []};}
      return {connectionId: entry.connectionId, appId: entry.appId, status: 'available', rows: entry.rows.map(({row}) => {
        const current = view.find(item => item.row === row);
        let reason = null;
        try {this.assertProxyGrant(client.id, entry.connectionId, row);} catch (error) {reason = error.code || 'grant_changed';}
        return {row, label: current?.label ?? row, effect: current?.effect ?? 'write', approval: reason ? 'unavailable' : current?.mode === 'allow' ? 'allow' : current?.mode === 'deny' ? 'deny' : 'ask', ...(reason ? {reason} : {})};
      })};
    });
  }

  revokeClient(id) {
    const client = this.store.get('clientGrants', id);
    if (!client) fail('not_found', 'Client not found.');
    client.status = 'revoked'; client.revokedAt = new Date(this.clock()).toISOString();
    this.store.put('clientGrants', client); this.store.audit({type: 'client.revoked', clientId: id});
    this.continuations?.cancelForClient(id);
    this.subscriptions?.cancelForClient(id);
    return projection(client);
  }

  activeClient(id) {
    const client = this.store.get('clientGrants', id);
    if (!client || client.status !== 'active' || Date.parse(client.expiresAt) <= this.clock()) fail('unauthorized', 'Client access is missing, expired or revoked.');
    if (this.authorityEnabled) {
      if (client.id !== id || typeof client.tokenHash !== 'string' || !/^[a-f0-9]{64}$/.test(client.tokenHash) || typeof client.expiresAt !== 'string' || !Number.isFinite(Date.parse(client.expiresAt)) || !Array.isArray(client.bindings) || client.bindings.length > 100 || (client.requestable !== undefined && (!Array.isArray(client.requestable) || client.requestable.length > 50 || !client.requestable.every(requestableEntry))) || (client.proxy !== undefined && (!Array.isArray(client.proxy) || client.proxy.length > 20 || client.proxy.some(entry => !record(entry) || !cleanText(entry.connectionId, 256) || !Number.isSafeInteger(entry.connectionGeneration) || !Array.isArray(entry.rows)))) ||
          client.bindings.length + (client.requestable?.length || 0) + (client.proxy?.length || 0) < 1 ||
          client.bindings.some(binding => !record(binding) || !cleanText(binding.connectionId, 256) || !cleanText(binding.capabilityId, 256) || !Number.isSafeInteger(binding.connectionGeneration) || binding.connectionGeneration < 1)) {
        fail('unauthorized', 'Client authority is incomplete or expired. Ask the owner for a new grant.');
      }
      this.principalForClient(client);
    }
    return client;
  }

  authenticate(authorization) {
    if (typeof authorization !== 'string' || authorization.length > 256) fail('unauthorized', 'A scoped Fabric client grant is required.');
    const match = authorization.match(/^Bearer (fab_client\.([a-f0-9-]{36})\.[A-Za-z0-9_-]{43})$/);
    if (!match) fail('unauthorized', 'A scoped Fabric client grant is required.');
    const client = this.activeClient(match[2]), supplied = Buffer.from(hash(match[1]), 'hex'), expected = Buffer.from(client.tokenHash, 'hex');
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) fail('unauthorized', 'A scoped Fabric client grant is required.');
    return client;
  }

  assertBinding(clientId, connectionId, capabilityId) {
    const client = this.activeClient(clientId);
    const binding = client.bindings.find(item => item.connectionId === connectionId && item.capabilityId === capabilityId);
    if (!binding) fail('permission_denied', 'This account-operation pair was not granted to this client.');
    const connection = this.store.get('connections', connectionId), cap = this.store.get('capabilities', capabilityId);
    if (!connection || !cap || capabilityPermissionHash(cap) !== binding.definitionHash) fail('grant_changed', 'The capability changed; the owner must review a new client grant.');
    const decision = this.runtime.permissions.decision(connection, cap);
    if (decision.bindingHash !== binding.bindingHash) fail('grant_changed', 'The connection authority changed; the owner must review a new client grant.');
    if (this.authorityEnabled) {
      let generation;
      try {generation = this.store.connectionGeneration(connectionId);} catch {fail('grant_changed', 'The connection authority changed; the owner must review a new client grant.');}
      if (generation !== binding.connectionGeneration) fail('grant_changed', 'The connection authority changed; the owner must review a new client grant.');
    }
    if (!decision.executable) fail('permission_denied', 'The operation is not currently permitted.');
    return {binding, cap, connection, decision, client};
  }

  authorizeJob(job) {
    if (job.source?.kind !== 'client') {
      if (this.authorityEnabled && job.executionRequest?.principal?.kind === 'local_client') fail('permission_denied', 'The accepted client request no longer matches its source.');
      return;
    }
    if (!cleanText(job.source.clientId, 256)) fail('unauthorized', 'A client identity is required.');
    if (job.kind === 'proxy') {
      const {client} = this.assertProxyGrant(job.source.clientId, job.connectionId, job.proxy?.row);
      try {if (canonicalHash(validatePrincipal(job.executionRequest.principal)) !== canonicalHash(this.principalForClient(client))) throw new Error();}
      catch {fail('permission_denied', 'The accepted client identity no longer matches this request.');}
      return;
    }
    // A request derived from a missing-access handoff draws authority only from that handoff,
    // for exactly one job, and never falls back to grant bindings.
    if (Object.hasOwn(job.source, 'continuationId')) {
      if (!this.authorityEnabled || !this.continuations) fail('permission_denied', 'Continued requests require designated authority mode.');
      try {this.continuations.assertJobAuthority(job);}
      catch (error) {fail(error.code === 'unauthorized' ? 'unauthorized' : 'permission_denied', 'The continued request is no longer authorized.');}
      return;
    }
    const {client} = this.assertBinding(job.source.clientId, job.connectionId, job.capabilityId);
    if (this.authorityEnabled && job.executionRequest) {
      try {
        if (canonicalHash(validatePrincipal(job.executionRequest.principal)) !== canonicalHash(this.principalForClient(client))) throw new Error();
      } catch {fail('permission_denied', 'The accepted client identity no longer matches this request.');}
    }
  }

  resultForClient(clientId, job) {
    if (job?.kind === 'proxy') {
      if (job.source?.kind !== 'client' || job.source.clientId !== clientId) fail('not_found', 'Call not found.');
      let current = true;
      try {
        this.assertProxyGrant(clientId, job.connectionId, job.proxy.row);
        if (this.runtime.proxyPolicy.decide(job.connectionId, job.args.request, {timeoutMs: job.args.timeoutMs}).mode === 'deny') current = false;
      } catch (error) {if (error.code === 'unauthorized') throw error; current = false;}
      // A call that has ended always reports its status, so a sent change is never re-sent as "new"; its data is
      // returned only while the grant and the setting still allow it. A pending call needs current authority.
      // A call that was not sent yet needs current authority; one that is running or has ended stays readable.
      if (!current && ['awaiting_approval', 'queued'].includes(job.status)) fail('permission_denied', 'This client no longer has authority for this pending request.');
      return proxyJobResult(job, this.origin, {withheld: !current, body: current ? this.runtime.proxyResponse(job) : null});
    }
    if (this.authorityEnabled) {
      if (!job || job.source?.kind !== 'client' || job.source.clientId !== clientId) fail('not_found', 'Call not found.');
      this.authorizeJob(job);
      try {this.runtime.assertAcceptedAuthority(job);} catch {fail('permission_denied', 'Accepted request authority is missing, expired or changed. Prepare a new request.');}
    }
    return jobResult(job, this.origin);
  }

  /** Adds Fabric's card for this call: built here from stored state and reviewed names, never from the agent. */
  withCard(client, view) {
    let card;
    try {
      const proxied = typeof view.capabilityId === 'string' && view.capabilityId.startsWith('proxy:') ? this.store.get('jobs', view.id) : null;
      const capability = proxied ? null : this.store.get('capabilities', view.capabilityId);
      const appId = view.handoff?.appId ?? proxied?.proxy?.appId ?? capability?.appId ?? null;
      // A proxied call is described by its own method and reviewed template (or path), and its real effect.
      // A proxied call is named by Fabric's own row label and the method, never by the agent's path.
      const operationName = proxied?.proxy ? `${proxied.proxy.rowLabel} (${proxied.proxy.method})` : capability?.name ?? view.capabilityId;
      const effect = proxied ? proxied.effect : capability ? permissionEffect(capability) : 'write';
      const shown = cardView(view, capability?.driver === 'action' ? this.store.get('jobs', view.resumedCallId ?? view.id) : null);
      card = callCard(shown, {requesterName: client.name, appId, appName: view.handoff?.appName ?? this.appName(appId), operationName, effect, origin: this.origin, now: this.clock()});
    } catch {return view;}
    return {...view, card};
  }

  /** F10.11 part l: actions first (bound, then request-only), then operations, each in its grant's order. */
  capabilities(client) {
    return actionsFirst([...this.boundCapabilities(client), ...this.requestableCapabilities(client)]);
  }

  // Request-only entries never disclose which accounts exist for the application.
  requestableCapabilities(client) {
    return (client.requestable || []).map(entry => {
      const cap = this.store.get('capabilities', entry.capabilityId), base = {id: entry.capabilityId, appId: entry.appId, connectionId: null, definitionHash: entry.definitionHash, kind: kindOf(cap)};
      const replaced = supersededEntry(this.runtime.permissions, entry.capabilityId, base);
      if (replaced) return replaced;
      const reference = cap && cap.status === 'active' ? this.runtime.capabilityReference(cap) : null;
      if (!reference || reference.definitionHash !== entry.definitionHash || reference.version !== entry.capabilityVersion) return {...base, status: 'unavailable', reason: 'grant_changed'};
      // T4 (F10.3): an entry granted before Fabric locked its operation can never run, so it is not offered; nor is one no sign-in can
      // run (F10.6), nor (F10.11 part l) an action this Fabric does not run now.
      if (this.runtime.permissions.lockOf(cap)) return {...base, status: 'unavailable', reason: 'permission_denied'};
      if (this.runtime.permissions.unavailableOf(cap)) return {...base, status: 'unavailable', reason: 'permission_denied'};
      if (cap.driver === 'action' && this.runtime.permissions.actions?.entryOf?.(cap)?.status !== 'active') return {...base, status: 'unavailable', reason: 'permission_denied'};
      // An action described by the resource it acts on cannot be asked for before an account exists to describe it.
      if (resourceDependent(cap)) return {...base, status: 'unavailable', reason: 'unsupported_route'};
      return {id: cap.id, appId: entry.appId, connectionId: null, definitionHash: entry.definitionHash, name: cap.name, description: cap.description || '', driver: cap.driver, inputSchema: cap.inputSchema,
        effect: entry.effect, ...listedFields(this.runtime.permissions, cap), approval: 'after_connection', status: 'connection_required', signIn: this.oauthRoute(entry.appId)?.available ? 'available' : 'unavailable'};
    });
  }

  boundCapabilities(client) {
    return client.bindings.map(binding => {
      const base = {id: binding.capabilityId, connectionId: binding.connectionId, definitionHash: binding.definitionHash, kind: kindOf(this.store.get('capabilities', binding.capabilityId))};
      const replaced = supersededEntry(this.runtime.permissions, binding.capabilityId, base);
      if (replaced) return replaced;
      try {
        const {cap, decision} = this.assertBinding(client.id, binding.connectionId, binding.capabilityId);
        return {...base, id: cap.id, name: cap.name, description: cap.description || '', appId: cap.appId, driver: cap.driver, inputSchema: cap.inputSchema, effect: permissionEffect(cap),
          ...listedFields(this.runtime.permissions, cap), approval: decision.requiresApproval ? 'ask' : 'allow', status: 'available'};
      } catch (error) {
        return {...base, status: 'unavailable', reason: error.code || 'permission_denied'};
      }
    });
  }

  async handle(authorization, envelope) {
    let id = null;
    try {
      const client = this.authenticate(authorization);
      const principal = this.authorityEnabled ? this.principalForClient(client) : undefined;
      fields(envelope, ['protocol', 'id', 'method', 'params']);
      if (envelope.protocol !== FABRIC_PROTOCOL) fail('unsupported_version', `Use protocol ${FABRIC_PROTOCOL}.`);
      const requestIdPattern = this.authorityEnabled ? /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/ : /^[A-Za-z0-9_.:-]+$/;
      if (!cleanText(envelope.id, 128) || !requestIdPattern.test(envelope.id)) fail('invalid_request', 'A bounded request id is required.');
      id = envelope.id;
      const params = envelope.params ?? {};
      // Reject non-JSON/unsafe fields before hashing or persisting an envelope.
      canonicalHash(params);
      let result;
      if (envelope.method === 'fabric.discover') {fields(params, []); result = {...protocolManifest, client: {id: client.id, name: client.name, expiresAt: client.expiresAt}};}
      else if (envelope.method === 'capabilities.list') {fields(params, []); result = {capabilities: this.capabilities(client), ...(client.proxy?.length ? {proxy: this.proxyCapabilities(client)} : {})};}
      else if (envelope.method === 'calls.get') {
        fields(params, ['callId']);
        if (!cleanText(params.callId, 256)) fail('invalid_request', 'A call id is required.');
        const job = this.store.get('jobs', params.callId);
        if (job) {
          if (job.source?.kind !== 'client' || job.source.clientId !== client.id) fail('not_found', 'Call not found.');
          if (job.kind !== 'proxy' && !Object.hasOwn(job.source, 'continuationId')) this.assertBinding(client.id, job.connectionId, job.capabilityId);
          result = this.resultForClient(client.id, job);
        } else if (this.authorityEnabled && this.continuations) result = this.continuations.clientView(client.id, params.callId);
        else fail('not_found', 'Call not found.');
      } else if (envelope.method === 'calls.create') {
        if (record(params) && Object.hasOwn(params, 'appId')) {
          if (Object.hasOwn(params, 'connectionId')) fail('invalid_request', 'Send either an account or an application, not both.');
          result = this.createHandoff(client, id, params, principal);
        } else {
          if (this.authorityEnabled && !(record(params) && Object.hasOwn(params, 'connectionId'))) fail('invalid_request', 'Send either an account or an application.');
          result = await this.createCall(client, id, params, principal);
          // Revocation cannot undo a dispatched effect, but can withhold its data
          // from a client whose authority expired while awaiting the response.
          this.assertBinding(client.id, params.connectionId, params.capabilityId);
          if (this.authorityEnabled) result = this.resultForClient(client.id, this.store.get('jobs', result.id));
        }
      } else if (envelope.method === 'calls.cancel') {
        fields(params, ['callId']);
        if (!cleanText(params.callId, 256)) fail('invalid_request', 'A call id is required.');
        if (!this.authorityEnabled || !this.continuations) fail('unsupported_route', 'Withdrawing account requests requires designated authority mode.');
        const job = this.store.get('jobs', params.callId);
        if (job) fail(job.source?.kind === 'client' && job.source.clientId === client.id ? 'unsupported_route' : 'not_found', job.source?.clientId === client.id ? 'Submitted requests cannot be cancelled by a client.' : 'Call not found.');
        result = this.continuations.clientCancel(client.id, params.callId);
      }
      else if (envelope.method === 'proxy.request') {
        if (!this.authorityEnabled) fail('unsupported_route', 'The governed proxy requires designated authority mode.');
        result = await this.proxyRequest(client, id, params, principal);
      }
      else if (envelope.method === 'triggers.list' && this.subscriptions) {fields(params, []); result = this.subscriptions.list(client);}
      else if (envelope.method === 'triggers.subscribe' && this.subscriptions) result = this.subscriptions.subscribe(client, id, params);
      else if (envelope.method === 'triggers.unsubscribe' && this.subscriptions) result = this.subscriptions.unsubscribe(client, params);
      else if (envelope.method === 'events.list' && this.subscriptions) result = await this.subscriptions.events(client, params);
      else fail('method_not_found', 'This Fabric method is not supported. Clients cannot approve actions or change permissions.');
      if (envelope.method.startsWith('calls.') || envelope.method === 'proxy.request') result = this.withCard(client, result);
      return {protocol: FABRIC_PROTOCOL, id, result};
    } catch (error) {
      const allowed = new Set(['unauthorized', 'invalid_request', 'unsupported_version', 'permission_denied', 'unsupported_route', 'grant_changed', 'not_found', 'method_not_found', 'idempotency_conflict', 'outcome_unknown', 'request_failed', 'pending_limit', 'invalid_transition',
        'rate_limited', 'invalid_path', 'parameter_not_allowed', 'header_not_allowed', 'method_not_allowed', 'unsupported_body', 'request_too_large', 'row_not_granted', 'policy_denied', 'provider_access_missing', 'proxy_unavailable', 'authority_changed',
        // Iteration 9: a watch's own limits.
        'subscription_limit', 'wait_limit',
        // F10.11 part l: an action's own refusals keep their code, as on /api and /v1.
        'input_schema_changed', 'action_refused']);
      return {protocol: FABRIC_PROTOCOL, id, error: {code: allowed.has(error.code) ? error.code : 'invalid_request', message: allowed.has(error.code) ? error.message : 'Request rejected. Check the capability inputs and current permissions.'}};
    }
  }

  /** Missing-access shape of calls.create. Synchronous, so concurrent duplicates serialize. */
  createHandoff(client, requestId, params, principal) {
    if (!this.authorityEnabled || !this.continuations) fail('unsupported_route', 'Account requests require designated authority mode.');
    if (!cleanText(requestId, 128) || !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(requestId)) fail('invalid_request', 'A bounded request id is required.');
    fields(params, ['appId', 'capabilityId', 'definitionHash', 'args', 'task']);
    taskTitle(params.task);
    if (!cleanText(params.appId, 64) || !cleanText(params.capabilityId, 256) || typeof params.definitionHash !== 'string' || (params.args !== undefined && !record(params.args))) fail('invalid_request', 'Choose an application operation and its arguments.');
    try {
      if (canonicalHash(validatePrincipal(principal)) !== canonicalHash(this.principalForClient(this.activeClient(client.id)))) throw new Error();
    } catch {fail('unauthorized', 'An authenticated client identity is required.');}
    const key = canonicalHash({clientId: client.id, requestId}), requestHash = canonicalHash(params);
    const previous = this.store.get('protocolRequests', key);
    if (previous) {
      if (previous.id !== key || previous.clientId !== client.id || previous.requestId !== requestId) fail('outcome_unknown', 'The earlier request record is inconsistent. It cannot be replayed safely.');
      if (previous.requestHash !== requestHash) fail('idempotency_conflict', 'This request id was already used with different arguments.');
      let continuationId = previous.continuationId;
      if (!continuationId && previous.status === 'reserved' && !previous.jobId) {
        // Crash window: the handoff was written but the reservation was not yet linked.
        const linked = this.continuations.byProtocolKey(key);
        if (linked && linked.clientId === client.id && linked.requestId === requestId) {this.store.put('protocolRequests', {...previous, continuationId: linked.id, status: 'recorded'}); continuationId = linked.id;}
      }
      if (!continuationId) fail(previous.status === 'failed' ? 'request_failed' : 'outcome_unknown', 'The earlier request cannot be replayed safely. Review its activity before issuing a new request.');
      const linked = this.store.get('continuations', continuationId);
      if (!linked || linked.clientId !== client.id || linked.requestId !== requestId || linked.protocolRequestKey !== key) fail('outcome_unknown', 'The earlier request record is inconsistent. It cannot be replayed safely.');
      return this.continuations.clientView(client.id, continuationId);
    }
    const prepared = this.continuations.prepare(client, structuredClone(params));
    const entry = {id: key, clientId: client.id, requestId, requestHash, status: 'reserved', createdAt: new Date(this.clock()).toISOString()};
    this.store.put('protocolRequests', entry);
    const handoff = this.continuations.create(client, principal, requestId, structuredClone(params), {protocolRequestKey: key, wireRequestHash: requestHash}, prepared);
    this.store.put('protocolRequests', {...entry, continuationId: handoff.id, status: 'recorded'});
    return this.continuations.clientView(client.id, handoff.id);
  }

  /**
   * proxy.request (F08.0d): one request on one granted account. Order: the account grant (the same answer whether or
   * not the account exists), replay of the same request id, the decision and its row grant, then acceptance. The
   * reservation is linked to the job before anything is sent, so a crash mid-send replays as the job's real status.
   * Refusals are counted in the audit log as metadata only; they create no job.
   */
  async proxyRequest(client, requestId, params, principal) {
    if (!cleanText(requestId, 128) || !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(requestId)) fail('invalid_request', 'A bounded request id is required.');
    fields(params, ['connectionId', 'request', 'timeoutMs', 'task']);
    const task = taskTitle(params.task);
    if (!cleanText(params.connectionId, 256)) fail('invalid_request', 'Choose a granted account.');
    try {if (canonicalHash(validatePrincipal(principal)) !== canonicalHash(this.principalForClient(this.activeClient(client.id)))) throw new Error();}
    catch {fail('unauthorized', 'An authenticated client identity is required.');}
    if (!(client.proxy || []).some(entry => entry.connectionId === params.connectionId)) fail('permission_denied', 'This account was not granted to this client for proxied requests.');
    // Refusals are rate limited per client: at most 60 a minute, then nothing more is evaluated or logged.
    const now = this.clock(), window = (this.refusals.get(client.id) || []).filter(at => now - at < 60_000);
    this.refusals.set(client.id, window);
    if (window.length >= 60) fail('rate_limited', 'Too many refused proxied requests. Wait a minute before trying again.');
    const key = canonicalHash({clientId: client.id, requestId}), requestHash = canonicalHash({method: 'proxy.request', params});
    const previous = this.store.get('protocolRequests', key);
    if (previous) {
      if (previous.id !== key || previous.clientId !== client.id || previous.requestId !== requestId) fail('outcome_unknown', 'The earlier request record is inconsistent. It cannot be replayed safely.');
      if (previous.requestHash !== requestHash) fail('idempotency_conflict', 'This request id was already used with different arguments.');
      if (this.inflight.has(key)) return this.inflight.get(key);
      let job = previous.jobId && this.store.get('jobs', previous.jobId);
      if (!job && previous.status === 'reserved') {
        // Crash window: the job was written but the reservation was not yet linked. Find it by its own request identity.
        job = this.store.list('jobs').find(item => item?.kind === 'proxy' && item.source?.kind === 'client' && item.source.clientId === client.id && item.source.requestId === requestId) || null;
        if (job) this.store.put('protocolRequests', {...previous, jobId: job.id, status: 'recorded'});
      }
      if (job && job.kind === 'proxy' && job.source?.requestId === requestId) return this.resultForClient(client.id, job);
      if (previous.status === 'failed' && PROXY_REFUSALS.has(previous.code)) fail(previous.code, 'This request was refused before. Nothing was sent.');
      fail(previous.status === 'failed' ? 'request_failed' : 'outcome_unknown', 'The earlier request cannot be replayed safely. Review its activity before issuing a new request.');
    }
    const refused = error => {window.push(this.clock()); this.store.audit({type: 'proxy.rejected', clientId: client.id, connectionId: params.connectionId, code: typeof error?.code === 'string' ? error.code : 'invalid_request'}); return error;};
    try {
      const decision = this.runtime.proxyPolicy.decide(params.connectionId, params.request, {timeoutMs: params.timeoutMs});
      this.assertProxyGrant(client.id, params.connectionId, decision.row);
    } catch (error) {throw refused(error);}
    if (this.store.list('jobs').filter(job => job?.kind === 'proxy' && job.source?.clientId === client.id && job.status === 'awaiting_approval').length >= 20) throw refused(Object.assign(new Error('Too many proxied requests are waiting for the owner.'), {code: 'pending_limit'}));
    const entry = {id: key, clientId: client.id, requestId, requestHash, status: 'reserved', createdAt: new Date(this.clock()).toISOString()};
    this.store.put('protocolRequests', entry);
    const pending = Promise.resolve().then(async () => {
      let job;
      try {
        job = this.runtime.prepareProxy({connectionId: params.connectionId, request: params.request, ...(params.timeoutMs !== undefined ? {timeoutMs: params.timeoutMs} : {}), source: {kind: 'client', clientId: client.id, requestId}}, principal, task ? {task: {title: task}} : {});
        this.store.put('protocolRequests', {...entry, jobId: job.id, status: 'recorded'});
        if (job.status === 'queued') job = await this.runtime.execute(job.id);
        return this.resultForClient(client.id, this.store.get('jobs', job.id));
      } catch (error) {
        if (!job) {this.store.put('protocolRequests', {...entry, status: 'failed', ...(PROXY_REFUSALS.has(error?.code) ? {code: error.code} : {})}); refused(error);}
        throw error;
      } finally {this.inflight.delete(key);}
    });
    this.inflight.set(key, pending); return pending;
  }

  async createCall(client, requestId, params, principal) {
    if (this.authorityEnabled) {
      if (!cleanText(requestId, 128) || !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(requestId)) fail('invalid_request', 'A bounded request id is required.');
      canonicalHash(params);
      params = structuredClone(params);
      try {
        if (canonicalHash(validatePrincipal(principal)) !== canonicalHash(this.principalForClient(this.activeClient(client.id)))) throw new Error();
      } catch {fail('unauthorized', 'An authenticated client identity is required.');}
    }
    fields(params, ['connectionId', 'capabilityId', 'definitionHash', 'args', 'task']);
    const task = taskTitle(params.task);
    const {binding} = this.assertBinding(client.id, params.connectionId, params.capabilityId);
    if (params.definitionHash !== binding.definitionHash) fail('grant_changed', 'Use the exact definition hash returned by capabilities.list.');
    const key = canonicalHash({clientId: client.id, requestId}), requestHash = canonicalHash(params);
    const previous = this.store.get('protocolRequests', key);
    if (previous) {
      if (this.authorityEnabled && (previous.id !== key || previous.clientId !== client.id || previous.requestId !== requestId)) fail('outcome_unknown', 'The earlier request record is inconsistent. It cannot be replayed safely.');
      if (previous.requestHash !== requestHash) fail('idempotency_conflict', 'This request id was already used with different arguments.');
      if (this.inflight.has(key)) return this.inflight.get(key);
      const job = previous.jobId && this.store.get('jobs', previous.jobId);
      if (job) {
        const result = this.resultForClient(client.id, job);
        if (this.authorityEnabled && (previous.status !== 'recorded' || job.source?.requestId !== requestId || job.executionRequest?.idempotencyKey !== requestId || job.connectionId !== params.connectionId || job.capabilityId !== params.capabilityId || canonicalHash(job.args) !== canonicalHash(params.args ?? {}) || job.executionRequest?.capability?.definitionHash !== params.definitionHash)) fail('outcome_unknown', 'The earlier request record does not match its accepted call. It cannot be replayed safely.');
        return result;
      }
      fail(previous.status === 'failed' ? 'request_failed' : 'outcome_unknown', 'The earlier request cannot be replayed safely. Review its activity before issuing a new request.');
    }
    const entry = {id: key, clientId: client.id, requestId, requestHash, status: 'reserved', createdAt: new Date(this.clock()).toISOString()};
    this.store.put('protocolRequests', entry);
    // Defer until the promise is registered, deduplicating concurrent requests. F10.11 part l: the reservation is linked to the job before
    // it runs, as proxy.request links it, so a crash in the middle of an action's requests replays the job's real status.
    const pending = Promise.resolve().then(async () => {
      let job;
      try {
        this.assertBinding(client.id, params.connectionId, params.capabilityId);
        job = await this.runtime.createJob({connectionId: params.connectionId, capabilityId: params.capabilityId, args: params.args ?? {}, source: {kind: 'client', clientId: client.id, requestId}}, principal,
          {...(task ? {task: {title: task}} : {}), accepted: stored => { job = stored; this.store.put('protocolRequests', {...entry, jobId: stored.id, status: 'recorded'}); }});
        return this.resultForClient(client.id, job);
      } catch (error) {if (!job) this.store.put('protocolRequests', {...entry, status: 'failed'}); throw error;}
      finally {this.inflight.delete(key);}
    });
    this.inflight.set(key, pending); return pending;
  }
}

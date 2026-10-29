// F03.9c (docs/F03-DEVELOPER-LAYER.md section 5.12, docs/F03.9-BUILD-MAP.md slice B): fabric/0.1 for agent tokens in a
// developer environment. An agent acts for exactly one end user, sees only account aliases, never receives a link,
// and never decides: approvals go to the developer's relay or Fabric's page. Every call it creates is the end user's
// job, attributed to the token and the key that minted it, and is checked against the token again when it runs.
import {createHash, randomUUID, timingSafeEqual} from 'node:crypto';
import {canonicalHash, validateInput} from '../compiler.mjs';
import {capabilityPermissionHash, permissionEffect, resourceDependent, ACTION_WORDS} from '../permissions.mjs';
import {kindOf, actionsFirst, listedFields, supersededEntry, cardView} from '../fabric-protocol.mjs';
import {taskTitle} from '../runtime.mjs';
import {callCard} from '../cards.mjs';
import {AGENT_LOCK_WORDS, routedWords} from '../row-locks.mjs';
import {UNAVAILABLE_REASONS} from '../permission-groups.mjs';
import {ownedBy, ownershipOf, stampOwner, tenantDeployment} from './deployment.mjs';
import {aliasOf, resolveAlias, TOKEN} from './agent-tokens.mjs';

export const AGENT_PROTOCOL = 'fabric/0.1';
export const tenantAgentManifest = Object.freeze({
  protocol: AGENT_PROTOCOL, product: 'Fabric',
  transport: {method: 'POST', path: '/fabric/v1', authentication: 'Bearer agent token'},
  methods: ['fabric.discover', 'capabilities.list', 'calls.create', 'calls.get', 'calls.cancel', 'proxy.request'],
  states: ['awaiting_connection', 'awaiting_approval', 'queued', 'running', 'succeeded', 'failed', 'uncertain', 'cancelled'],
  features: {typedCapabilities: true, accountAliases: true, links: false, clientSelfApproval: false, idempotentCallRequests: true, outcomeEvidence: true, governedProxy: true, missingAccessHandoff: true,
    actions: true, twoPhaseApproval: true},
  notice: 'An agent acts for one person, through the accounts and operations its token names. It cannot approve anything or change permissions.',
});
const sha256 = value => createHash('sha256').update(value).digest('hex');
const DUMMY = sha256('fab_client.no-such-token');
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/, CALL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const coded = (code, message) => Object.assign(new Error(message), {code});
const fail = (code, message) => { throw coded(code, message); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function fields(value, allowed) { if (!record(value) || Object.keys(value).some(key => !allowed.includes(key))) fail('invalid_request', 'Unexpected request fields.'); }
const ERRORS = new Set(['unauthorized', 'invalid_request', 'unsupported_version', 'permission_denied', 'unsupported_route', 'grant_changed', 'not_found', 'method_not_found', 'idempotency_conflict', 'outcome_unknown',
  'request_failed', 'rate_limited', 'invalid_path', 'parameter_not_allowed', 'header_not_allowed', 'method_not_allowed', 'unsupported_body', 'request_too_large', 'row_not_granted', 'policy_denied', 'provider_access_missing',
  'proxy_unavailable', 'authority_changed', 'invalid_arguments', 'capability_changed', 'connection_required', 'app_disabled', 'invalid_transition', 'pending_limit', 'setup_required', 'unavailable',
  // F10.11 part m: an action's own refusals keep their code, as on the owner's fabric/0.1, /api and /v1.
  'input_schema_changed', 'action_refused']);
/** HTTP status for a protocol answer (decision 4 of the F03.9 map). */
export function agentStatus(answer) {
  const code = answer?.error?.code;
  return !code ? 200 : {unauthorized: 401, permission_denied: 403, policy_denied: 403, not_found: 404, not_available: 422, app_disabled: 422, rate_limited: 429, pending_limit: 429}[code] ?? 400;
}
const APP_OFF = 'This app is turned off in this environment. Nothing was run.';

export class TenantAgentProtocol {
  /** @param {{env: any, scope: any, runtime: any, permissions: any, registry: any, runtimes: any, executions: any, usage: any}} deps */
  constructor(deps) { Object.assign(this, deps); this.inflight = new Map(); }
  #now() { return Date.parse(this.registry.now()); }

  /**
   * The token's grant, active now, or unauthorized. One hash compare happens whatever is missing, so an unknown id
   * costs the same as a wrong secret. The end user must still be active and the token's route not revoked.
   */
  authenticate(token) {
    const match = typeof token === 'string' ? TOKEN.exec(token) : null, grant = match ? this.env.repository.get('clientGrants', match[1]) : null;
    const expected = grant?.kind === 'agent_token' && /^[0-9a-f]{64}$/.test(grant.tokenHash ?? '') ? grant.tokenHash : DUMMY;
    const same = timingSafeEqual(Buffer.from(sha256(typeof token === 'string' ? token : ''), 'hex'), Buffer.from(expected, 'hex'));
    if (!match || !grant || !same) fail('unauthorized', 'This agent token is not valid.');
    return this.activeGrant(grant.id);
  }
  /** Fails closed unless the grant is active, unexpired, fully attributed, its route live and its end user active. */
  activeGrant(id) {
    const grant = typeof id === 'string' ? this.env.repository.get('clientGrants', id) : null, route = grant ? this.registry.get('agentTokenRoutes', grant.id) : null;
    let owner = null;
    try { owner = grant ? ownershipOf(grant, tenantDeployment(this.env.scope)) : null; } catch { owner = null; }
    const user = owner ? this.env.repository.get('endUsers', owner.userRecordId) : null;
    if (!grant || grant.kind !== 'agent_token' || grant.status !== 'active' || !(Date.parse(grant.expiresAt) > this.#now()) || !owner || !grant.aliasKey || !grant.mintedByKeyId || grant.delegationId !== grant.id
      || !route || route.revokedAt || route.environmentId !== this.scope.environmentId || !user || user.status !== 'active' || user.subjectId !== owner.subjectId) fail('unauthorized', 'This agent token is not valid.');
    return {grant, owner};
  }
  #principal(owner) { return {kind: 'product_user', subjectId: owner.subjectId, userRecordId: owner.userRecordId}; }
  /** The developer turned this app off here (F03.7): nothing of it runs, for agents either. */
  #appOff(appId) { return this.registry.get('environments', this.scope.environmentId)?.apps?.[appId]?.enabled === false; }
  #binding(grant, accountRef, capabilityId) { return (grant.bindings || []).find(binding => binding.connectionId === accountRef && binding.capabilityId === capabilityId) ?? null; }

  async handle(token, envelope) {
    let id = null;
    try {
      const {grant, owner} = this.authenticate(token);
      fields(envelope, ['protocol', 'id', 'method', 'params']);
      if (envelope.protocol !== AGENT_PROTOCOL) fail('unsupported_version', `Use protocol ${AGENT_PROTOCOL}.`);
      if (typeof envelope.id !== 'string' || !REQUEST_ID.test(envelope.id)) fail('invalid_request', 'A bounded request id is required.');
      id = envelope.id;
      const params = envelope.params ?? {};
      try { canonicalHash(params); } catch { fail('invalid_request', 'The request holds a name Fabric never accepts.'); }
      let result;
      if (envelope.method === 'fabric.discover') { fields(params, []); result = {...tenantAgentManifest, client: {id: grant.id, name: grant.name, expiresAt: grant.expiresAt}}; }
      else if (envelope.method === 'capabilities.list') { fields(params, []); result = this.capabilities(grant); }
      else if (envelope.method === 'calls.get') {
        fields(params, ['callId']);
        const own = this.#ownCall(grant, owner, params.callId);
        result = own.job ? this.withCard(grant, this.view(grant, own.job)) : this.holdView(grant, own.hold);
      } else if (envelope.method === 'calls.create') result = record(params) && Object.hasOwn(params, 'appId') ? await this.#request(grant, owner, id, params) : this.withCard(grant, await this.#create(grant, owner, id, params));
      else if (envelope.method === 'proxy.request') result = this.withCard(grant, await this.#proxy(grant, owner, id, params));
      else if (envelope.method === 'calls.cancel') { fields(params, ['callId']); result = await this.#withdraw(grant, owner, params.callId); }
      else fail('method_not_found', 'This Fabric method is not supported. Agents cannot approve actions or change permissions.');
      return {protocol: AGENT_PROTOCOL, id, result};
    } catch (error) {
      const known = ERRORS.has(error?.code);
      return {protocol: AGENT_PROTOCOL, id, error: {code: known ? error.code : 'invalid_request', message: known ? String(error.message).slice(0, 300) : 'Request rejected. Check the inputs and current permissions.'}};
    }
  }

  /** What the agent may use: its operations by alias, each with its current state, and its proxy rows by alias. F10.11 part m: the same
   *  fields and order as the owner's fabric/0.1 (lib/fabric-protocol.mjs): actions first, each entry with its kind and hints. */
  capabilities(grant) {
    const capabilities = (grant.bindings || []).map(binding => {
      const alias = aliasOf(grant, binding.connectionId), cap = this.env.repository.get('capabilities', binding.capabilityId), connection = this.env.repository.get('connections', binding.connectionId);
      const base = {id: binding.capabilityId, connectionId: alias, definitionHash: binding.definitionHash, kind: kindOf(cap)};
      const replaced = supersededEntry(this.permissions, binding.capabilityId, base);
      if (replaced) return replaced;
      let decision = null;
      try { decision = cap && connection && connection.status === 'ready' ? this.permissions.decision(connection, cap) : null; } catch { decision = null; }
      if (!cap || cap.status !== 'active' || capabilityPermissionHash(cap) !== binding.definitionHash) return {...base, status: 'unavailable', reason: 'grant_changed'};
      if (this.#appOff(cap.appId)) return {...base, status: 'unavailable', reason: 'app_disabled'};
      if (!decision?.executable) return {...base, status: 'unavailable', reason: connection?.status === 'ready' ? 'permission_denied' : 'connection_required'};
      return {id: cap.id, connectionId: alias, definitionHash: binding.definitionHash, name: cap.name, description: String(cap.description || '').slice(0, 500), appId: cap.appId, driver: cap.driver, inputSchema: cap.inputSchema,
        effect: permissionEffect(cap), ...listedFields(this.permissions, cap), approval: decision.requiresApproval ? 'ask' : 'allow', status: 'available'};
    });
    // Request-only entries never say which accounts the person has.
    const environment = this.registry.get('environments', this.scope.environmentId);
    const requestable = (grant.requestable || []).map(entry => {
      const cap = this.env.repository.get('capabilities', entry.capabilityId), base = {id: entry.capabilityId, appId: entry.appId, connectionId: null, definitionHash: entry.definitionHash, kind: kindOf(cap)};
      const replaced = supersededEntry(this.permissions, entry.capabilityId, base);
      if (replaced) return replaced;
      if (!cap || cap.status !== 'active' || capabilityPermissionHash(cap) !== entry.definitionHash) return {...base, status: 'unavailable', reason: 'grant_changed'};
      if (this.#appOff(entry.appId)) return {...base, status: 'unavailable', reason: 'app_disabled'};
      // T4 (F10.3): an entry given before its operation was locked can never run, so it is not offered; nor is one no sign-in can run (F10.6),
      // nor (F10.11 part m) an action this environment does not run now.
      if (this.permissions.lockOf(cap)) return {...base, status: 'unavailable', reason: 'permission_denied'};
      if (this.permissions.unavailableOf(cap)) return {...base, status: 'unavailable', reason: 'permission_denied'};
      if (cap.driver === 'action' && this.permissions.actions?.entryOf?.(cap)?.status !== 'active') return {...base, status: 'unavailable', reason: 'permission_denied'};
      // An action described by the resource it acts on cannot be asked for before an account exists to describe it.
      if (resourceDependent(cap)) return {...base, status: 'unavailable', reason: 'unsupported_route'};
      let signIn = 'unavailable';
      try { const setting = this.executions.sessions.appSetting(entry.appId, environment, this.executions.sessions.providerApps); signIn = setting.enabled && setting.availability.state === 'ready' ? 'available' : 'unavailable'; } catch { signIn = 'unavailable'; }
      return {id: cap.id, appId: entry.appId, connectionId: null, definitionHash: entry.definitionHash, name: cap.name, description: String(cap.description || '').slice(0, 500), driver: cap.driver, inputSchema: cap.inputSchema, effect: entry.effect,
        ...listedFields(this.permissions, cap), approval: 'after_connection', status: 'connection_required', signIn};
    });
    // Each granted proxy account with its granted rows and their current mode, as fabric/0.1 lists them.
    const proxy = (grant.proxy || []).map(entry => {
      let rows = null;
      try { rows = this.runtime.proxyPolicy.view(entry.connectionId); } catch { rows = null; }
      const granted = entry.rows.map(item => { const row = rows?.find(candidate => candidate.row === item.row); return row ? {row: row.row, label: row.label, effect: row.effect, approval: row.mode} : {row: item.row, label: item.row, effect: 'read', approval: 'unavailable', reason: 'proxy_unavailable'}; });
      const reason = this.#appOff(entry.appId) ? 'app_disabled' : rows ? null : 'proxy_unavailable';
      return {connectionId: aliasOf(grant, entry.connectionId), appId: entry.appId, status: reason ? 'unavailable' : 'available', ...(reason ? {reason} : {}), rows: granted};
    });
    return {capabilities: actionsFirst([...capabilities, ...requestable]), ...(proxy.length ? {proxy} : {})};
  }
  /** A call of this token's own, or not_found exactly like a missing one. */
  #ownCall(grant, owner, callId) {
    if (typeof callId !== 'string' || !CALL_ID.test(callId)) fail('not_found', 'Call not found.');
    const job = this.env.repository.get('jobs', callId), held = job ? null : this.env.repository.get('continuations', callId), item = job ?? (held?.kind === 'hold' ? held : null);
    if (!item || item.source?.kind !== 'client' || item.source.clientId !== grant.id || !ownedBy(item, owner, tenantDeployment(this.env.scope))) fail('not_found', 'Call not found.');
    return job ? {job} : {hold: item};
  }
  /** An account request as the agent sees it: the handoff session to relay to the app (never a link), and how it is going. */
  holdView(grant, hold) {
    const view = this.executions.holdView(this.scope, this.env, hold), session = this.executions.sessions.stateOf(this.scope, hold.connectSessionId);
    const state = view.status === 'connection_required' ? ({created: 'awaiting_owner', opened: 'awaiting_owner', signing_in: 'signing_in', awaiting_confirmation: 'awaiting_confirmation'}[session.state] ?? 'awaiting_owner') : view.status === 'queued' ? 'connected' : 'closed';
    const closed = this.env.repository.get('continuations', hold.id) ?? hold, code = closed.outcome?.code ?? null;
    const outcome = code === null ? null : {declined: 'owner_declined', withdrawn: 'client_cancelled', cancelled: 'client_cancelled', agent_revoked: 'client_revoked', key_revoked: 'client_revoked', handoff_expired: 'continuation_expired', capability_changed: 'authority_changed',
      app_disabled: 'authority_changed', permission_denied: 'policy_denied', connection_required: 'policy_denied', invalid_request: 'policy_denied'}[code] ?? 'fabric_failed';
    const appName = this.executions.sessions.tenantApps().find(app => app.id === hold.appId)?.name ?? hold.appId;
    return {id: hold.id, status: view.status === 'connection_required' ? 'awaiting_connection' : view.status, connectionId: null, capabilityId: hold.capabilityId, appId: hold.appId, createdAt: hold.createdAt, updatedAt: view.updatedAt,
      result: null, error: view.error?.message ?? null, errorCode: view.error?.code ?? null, approvalRequired: false,
      handoff: {appId: hold.appId, appName, connectSessionId: hold.connectSessionId, expiresAt: hold.expiresAt, outcome, state}};
  }
  /** calls.create {appId, ...}: the agent asks for an operation it may request; a hold the person answers on Fabric's page. */
  async #request(grant, owner, requestId, params) {
    fields(params, ['appId', 'capabilityId', 'definitionHash', 'args', 'task']);
    const entry = (grant.requestable || []).find(item => item.appId === params.appId && item.capabilityId === params.capabilityId);
    if (!entry) fail('not_found', 'No such operation for this agent to request.');
    const cap = this.env.repository.get('capabilities', entry.capabilityId);
    if (params.definitionHash !== entry.definitionHash || !cap || cap.status !== 'active' || capabilityPermissionHash(cap) !== entry.definitionHash) fail('grant_changed', 'Use the exact definition hash capabilities.list returned.');
    // A call that can never run makes no hold: its operation locked (T4) or unavailable through any sign-in (F10.6), its arguments
    // wrong, or its body routed to another row.
    if (this.permissions.lockOf(cap)) fail('permission_denied', AGENT_LOCK_WORDS);
    const unavailable = this.permissions.unavailableOf(cap);
    if (unavailable) fail('permission_denied', UNAVAILABLE_REASONS[unavailable]);
    // F10.11 part m: an action described by the resource it acts on waits for no account: it is described once one exists.
    if (resourceDependent(cap)) fail('invalid_request', ACTION_WORDS.describe);
    if (params.args !== undefined && !record(params.args)) fail('invalid_request', 'args is an object.');
    try { validateInput(cap.inputSchema, params.args ?? {}); } catch { fail('invalid_arguments', 'The arguments do not match this operation.'); }
    const routed = this.permissions.routedBody(cap, params.args ?? {});
    if (routed) fail('invalid_request', routedWords(routed));
    const title = taskTitle(params.task);
    const key = canonicalHash({clientId: grant.id, requestId}), requestHash = canonicalHash(params), previous = this.env.repository.get('protocolRequests', key);
    if (previous) {
      if (previous.clientId !== grant.id || previous.requestHash !== requestHash) fail('idempotency_conflict', 'This request id was already used with different parameters.');
      const job = previous.jobId && this.env.repository.get('jobs', previous.jobId), hold = previous.jobId && this.env.repository.get('continuations', previous.jobId);
      if (job) return this.withCard(grant, this.view(grant, job));
      if (hold?.kind === 'hold') return this.holdView(grant, hold);
      fail('outcome_unknown', 'The earlier request did not finish being accepted. Send a new request id.');
    }
    // At most 60 account requests an hour per token, withdrawn or not: asking and withdrawing in a loop stops there.
    const mine = source => source?.kind === 'client' && source.clientId === grant.id;
    if (this.executions.asksFull(this.env, owner, mine)) fail('rate_limited', 'Too many account requests in the last hour. Wait before asking again.');
    this.executions.holdAllowed(this.scope, this.env, entry.appId, mine);
    const callRef = randomUUID(), source = {kind: 'client', clientId: grant.id, requestId, keyId: grant.mintedByKeyId, holdId: callRef};
    this.env.repository.put('protocolRequests', stampOwner({id: key, clientId: grant.id, requestId, requestHash, status: 'recorded', jobId: callRef, createdAt: this.registry.now()}, owner));
    const hold = this.executions.makeHold(this.scope, this.env, {owner, cap, callRef, args: params.args, title, source, createdBy: {serviceClientId: grant.mintedByServiceClientId ?? null, keyId: grant.mintedByKeyId, agentId: grant.id}});
    return this.holdView(grant, hold);
  }
  /** calls.cancel: the agent withdraws its own account request while it waits; submitted calls are the person's to cancel. */
  async #withdraw(grant, owner, callId) {
    const own = this.#ownCall(grant, owner, callId);
    if (own.job) fail('unsupported_route', 'A submitted call cannot be cancelled by an agent.');
    const closed = await this.executions.closeHold(this.scope, this.env, own.hold, 'withdrawn', {withdrawnByAgent: grant.id});
    if (!closed) fail('invalid_transition', 'This request is no longer waiting.');
    return this.holdView(grant, this.env.repository.get('continuations', own.hold.id));
  }
  /** The agent's view of a call: the developer's Execution with the account as its alias; no link, no identity, no digest. */
  view(grant, job) {
    const execution = this.executions.project({scope: this.scope}, this.env, job), proxied = job.kind === 'proxy';
    // fabric/0.1's call shape: result is an object or null, error a fixed sentence or null (its code beside it).
    const result = execution.result === undefined ? null : proxied ? execution.result : {data: execution.result};
    return {id: job.id, status: execution.status, connectionId: aliasOf(grant, job.connectionId), capabilityId: job.capabilityId, appId: execution.appId, createdAt: execution.createdAt, updatedAt: execution.updatedAt,
      result, error: execution.error?.message ?? null, errorCode: execution.error?.code ?? null, evidence: execution.evidence, approvalRequired: execution.status === 'awaiting_approval',
      ...(execution.resultWithheld ? {resultWithheld: true} : {}), ...(execution.approval ? {approval: {callRef: job.id, expiresAt: execution.approval.expiresAt}} : {}),
      ...(proxied ? {request: {method: job.proxy?.method, url: job.proxy?.url, row: job.proxy?.rowLabel, effect: job.effect}, reason: null} : {})};
  }
  /** Fabric's card for the call, from stored state and reviewed names: without a link, so it has no actions. */
  withCard(grant, view) {
    try {
      const job = this.env.repository.get('jobs', view.id), capability = job?.kind === 'proxy' ? null : this.env.repository.get('capabilities', job?.capabilityId);
      const operationName = job?.kind === 'proxy' && job.proxy ? `${job.proxy.rowLabel} (${job.proxy.method})` : capability?.name ?? 'an operation';
      const effect = job?.kind === 'proxy' ? job.effect : capability ? permissionEffect(capability) : 'write';
      const appName = this.executions.sessions.tenantApps().find(app => app.id === view.appId)?.name ?? view.appId;
      return {...view, card: callCard(cardView(view, job), {requesterName: grant.name, appId: view.appId, appName, operationName, effect, now: this.#now()})};
    } catch { return view; }
  }
  /**
   * Same request id, same parameters: the same call; different parameters: idempotency_conflict. Never sent twice. A
   * new request is first admitted (the app switch, the limits): a refusal there stores nothing, and a replay never
   * meets it.
   */
  async #once(grant, owner, requestId, params, create, admit) {
    const key = canonicalHash({clientId: grant.id, requestId}), requestHash = canonicalHash(params), previous = this.env.repository.get('protocolRequests', key);
    if (previous) {
      if (previous.clientId !== grant.id || previous.requestHash !== requestHash) fail('idempotency_conflict', 'This request id was already used with different parameters.');
      if (this.inflight.has(key)) return this.inflight.get(key);
      const job = previous.jobId && this.env.repository.get('jobs', previous.jobId);
      if (job) return this.view(grant, job);
      fail(previous.status === 'failed' ? 'request_failed' : 'outcome_unknown', 'The earlier request did not finish being accepted. Send a new request id.');
    }
    admit();
    const entry = stampOwner({id: key, clientId: grant.id, requestId, requestHash, status: 'reserved', createdAt: this.registry.now()}, owner);
    this.env.repository.put('protocolRequests', entry);
    const pending = Promise.resolve().then(async () => {
      let job;
      try { job = await create(); }
      catch (error) { this.env.repository.put('protocolRequests', {...entry, status: 'failed'}); throw error; }
      this.env.repository.put('protocolRequests', {...entry, jobId: job.id, status: 'recorded'});
      this.usage.append(this.env, {id: `${job.kind === 'proxy' ? 'proxy' : 'exec'}.${job.id}`, kind: job.kind === 'proxy' ? 'proxy' : 'execution', userRecordId: owner.userRecordId, serviceClientId: grant.mintedByServiceClientId ?? null, keyId: grant.mintedByKeyId,
        appId: job.kind === 'proxy' ? job.proxy?.appId ?? null : this.env.repository.get('capabilities', job.capabilityId)?.appId ?? null, capabilityId: job.kind === 'proxy' ? null : job.capabilityId});
      if (job.status === 'queued') {
        this.runtimes.dispatch(this.scope, job.id);
        await this.runtimes.wait(this.scope, job.id, 25_000);
      }
      return this.view(grant, this.env.repository.get('jobs', job.id) ?? job);
    }).finally(() => this.inflight.delete(key));
    this.inflight.set(key, pending);
    return pending;
  }
  async #create(grant, owner, requestId, params) {
    fields(params, ['connectionId', 'capabilityId', 'definitionHash', 'args', 'task']);
    // An alias this token does not hold, a raw accountRef or any store id all answer the same not_found.
    const accountRef = resolveAlias(grant, params.connectionId), binding = accountRef ? this.#binding(grant, accountRef, params.capabilityId) : null;
    if (!binding) fail('not_found', 'No such account and operation for this agent.');
    if (params.definitionHash !== binding.definitionHash) fail('grant_changed', 'Use the exact definition hash capabilities.list returned.');
    if (params.args !== undefined && !record(params.args)) fail('invalid_request', 'args is an object.');
    const task = taskTitle(params.task);
    const admit = () => {
      const cap = this.env.repository.get('capabilities', binding.capabilityId), connection = this.env.repository.get('connections', accountRef);
      if (cap && this.#appOff(cap.appId)) fail('app_disabled', APP_OFF);
      // The executions limit: at most 20 of this token's calls waiting for the person's approval; a call that would not wait still runs.
      let waits = false;
      try { waits = Boolean(cap && connection && this.permissions.decision(connection, cap).requiresApproval); } catch { waits = false; }
      if (waits && this.executions.pendingFull(this.env, {proxy: false, owner, from: source => source?.kind === 'client' && source.clientId === grant.id}))
        fail('pending_limit', 'Too many of this agent\'s calls are waiting for approval. Wait for some to be decided.');
    };
    return this.#once(grant, owner, requestId, params, async () => {
      try {
        return await this.runtime.prepareJob({connectionId: accountRef, capabilityId: binding.capabilityId, args: params.args ?? {}, source: {kind: 'client', clientId: grant.id, requestId, keyId: grant.mintedByKeyId}},
          this.#principal(owner), task ? {task: {title: task}} : {});
      } catch (error) { throw this.#coded(error); }
    }, admit);
  }
  async #proxy(grant, owner, requestId, params) {
    fields(params, ['connectionId', 'request', 'timeoutMs', 'task']);
    const accountRef = resolveAlias(grant, params.connectionId), entry = accountRef ? (grant.proxy || []).find(item => item.connectionId === accountRef) : null;
    if (!entry) fail('not_found', 'No such proxy account for this agent.');
    const task = taskTitle(params.task), options = params.timeoutMs !== undefined ? {timeoutMs: params.timeoutMs} : {};
    // The developer's proxy limits, per token: 60 refusals a minute (then rate_limited before anything is evaluated) and
    // 20 requests waiting for approval. A refusal here stores nothing.
    const {limited, refused} = this.executions.refusalWindow(this.scope, grant.id);
    const admit = () => {
      if (this.#appOff(entry.appId)) fail('app_disabled', APP_OFF);
      if (limited) fail('rate_limited', 'Too many refused proxied requests. Wait a minute before trying again.');
      if (this.executions.pendingFull(this.env, {proxy: true, owner, from: source => source?.kind === 'client' && source.clientId === grant.id}))
        throw refused(coded('pending_limit', 'Too many proxied requests are waiting for approval. Wait for some to be decided.'));
      let decision;
      try { decision = this.runtime.proxyPolicy.decide(accountRef, params.request, options); } catch (error) { throw refused(this.#coded(error)); }
      if (!entry.rows.some(item => item.row === decision.row)) throw refused(coded('row_not_granted', 'This request lands in a row this agent was not given.'));
    };
    return this.#once(grant, owner, requestId, params, async () => {
      try {
        return this.runtime.prepareProxy({connectionId: accountRef, request: params.request, ...options, source: {kind: 'client', clientId: grant.id, requestId, keyId: grant.mintedByKeyId}},
          this.#principal(owner), task ? {task: {title: task}} : {});
      } catch (error) { throw refused(this.#coded(error)); }
    }, admit);
  }
  #coded(error) { return ERRORS.has(error?.code) ? error : Object.assign(new Error('Request rejected. Check the inputs and current permissions.'), {code: 'invalid_request'}); }

  /**
   * The runtime's check for every job of this environment, at creation and again when it runs. First the app switch, for
   * every job (the developer's own too): an app turned off runs nothing, even a call accepted before. Then, for an
   * agent's job: the token is still active and the person's, and the call is still inside what it was given (the
   * binding and its hashes, or the proxy row).
   */
  authorizeJob(job) {
    const appId = job?.kind === 'proxy' ? job.proxy?.appId : typeof job?.capabilityId === 'string' ? this.env.repository.get('capabilities', job.capabilityId)?.appId : null;
    if (typeof appId === 'string' && this.#appOff(appId)) fail('app_disabled', APP_OFF);
    if (job?.source?.kind !== 'client') return;
    let grant, owner;
    try { ({grant, owner} = this.activeGrant(job.source.clientId)); } catch { fail('authority_changed', 'The agent\'s token is no longer valid. Nothing was run.'); }
    let stored;
    try { stored = ownershipOf(job, tenantDeployment(this.env.scope)); } catch { stored = null; }
    if (!stored || stored.userRecordId !== owner.userRecordId || stored.subjectId !== owner.subjectId || job.source.keyId !== grant.mintedByKeyId) fail('authority_changed', 'This call is not the agent\'s person\'s. Nothing was run.');
    // A call resumed from the agent's account request takes its authority from that hold only, never from bindings.
    if (job.source.holdId !== undefined) {
      const hold = this.env.repository.get('continuations', job.source.holdId), cap = this.env.repository.get('capabilities', job.capabilityId);
      const entry = (grant.requestable || []).find(item => item.capabilityId === job.capabilityId);
      let holder = null;
      try { holder = hold ? ownershipOf(hold, tenantDeployment(this.env.scope)) : null; } catch { holder = null; }
      if (!hold || hold.kind !== 'hold' || hold.id !== job.id || hold.source?.clientId !== grant.id || !holder || holder.userRecordId !== owner.userRecordId || !entry || !cap
        || capabilityPermissionHash(cap) !== entry.definitionHash || hold.definitionHash !== entry.definitionHash) fail('authority_changed', 'The agent\'s request no longer covers this call. Nothing was run.');
      return;
    }
    if (job.kind === 'proxy') {
      const entry = (grant.proxy || []).find(item => item.connectionId === job.connectionId);
      let context = null;
      try { context = this.runtime.proxyPolicy.route(job.connectionId); } catch { context = null; }
      const row = entry?.rows.find(item => item.row === job.proxy?.row);
      if (!entry || !context || context.config.configHash !== entry.configHash || !row || this.runtime.proxyPolicy.binding(context, row.row) !== row.bindingHash) fail('authority_changed', 'The agent\'s proxy grant no longer covers this request. Nothing was run.');
      return;
    }
    const binding = this.#binding(grant, job.connectionId, job.capabilityId), cap = this.env.repository.get('capabilities', job.capabilityId), connection = this.env.repository.get('connections', job.connectionId);
    let decision = null;
    try { decision = binding && cap && connection ? this.permissions.decision(connection, cap) : null; } catch { decision = null; }
    if (!binding || !cap || capabilityPermissionHash(cap) !== binding.definitionHash || !decision?.executable || decision.bindingHash !== binding.bindingHash) fail('authority_changed', 'The agent\'s grant no longer covers this call. Nothing was run.');
  }
}

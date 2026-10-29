// F03.7b (docs/F03-DEVELOPER-LAYER.md section 5.10, docs/F03.7-BUILD-MAP.md slice 2): a developer's server runs a
// reviewed operation on one end user's account, under that account's Allow, Ask and Never, and may wait for the result.
// Order of checks (section 5.1): the key and scope (the router), the end user, the account, the Idempotency-Key, the
// operation's definition, then the permission decision. The source is always the calling key, never the body. The
// response is built from stored state through a closed projection: no links, no account identity, no provider text.
import {randomUUID} from 'node:crypto';
import {TenantError, notFound, invalid} from './errors.mjs';
import {IdempotencyKeys, IDEMPOTENCY} from './idempotency.mjs';
import {capabilityPermissionHash, resourceDependent, ACTION_WORDS} from '../permissions.mjs';
import {ownershipOf, tenantDeployment, stampOwner, ownedBy} from './deployment.mjs';
import {taskTitle} from '../runtime.mjs';
import {ERROR_DEFINITIONS} from '../../contracts/execution.mts';
import {PROXY_CONFIGS} from '../proxy-config.mjs';
import {proxyBase, ProxyRequestError} from '../proxy-request.mjs';
import {proxyResponseBody} from '../proxy-runtime.mjs';
import {validateInput} from '../compiler.mjs';
import {routedWords} from '../row-locks.mjs';

export const MAX_WAIT_MS = 25_000, MAX_WAITERS = 16;
const ROUTE = 'POST /v1/executions', PROXY_ROUTE = 'POST /v1/proxy/requests';
const TERMINAL = new Set(['succeeded', 'failed', 'uncertain', 'cancelled']);
/** Fixed words per code (N14): provider text never reaches the developer. */
const WORDS = {
  outcome_uncertain: 'The change was sent, but its effect was not independently verified. Check before trying again; it was not retried.',
  provider_failed: 'The provider did not complete this request.', fabric_failed: 'Fabric could not send this request. Nothing was sent.',
  authority_changed: 'The account, its permissions or the operation changed while this ran. The result was withheld.',
  approval_expired: 'Nobody approved this in time. Nothing was run.', not_found: 'The account for this request no longer exists here.',
  permission_denied: 'This account\'s permissions do not allow this now. Nothing was run.', connection_required: 'The account needs to be reconnected. Nothing was run.',
  handoff_expired: 'Nobody connected an account in time. Nothing was run.', handoff_failed: 'The account could not be connected. Nothing was run.', app_disabled: 'This app was turned off. Nothing was run.',
  capability_changed: 'This operation changed. Nothing was run.', invalid_arguments: 'The arguments did not match the operation. Nothing was run.',
  policy_denied: 'This account\'s permissions do not allow this request now. Nothing was sent.', write_in_progress: 'Another change was in progress for this account. Nothing was sent.',
  proxy_unavailable: 'This account cannot use the proxy now. Nothing was sent.', provider_access_missing: 'The account lacks the provider access this request needs. Nothing was sent.',
  key_revoked: 'The key that made this call was revoked. Nothing was run.', agent_revoked: 'The agent\'s token was revoked or expired. Nothing was run.',
  locked: 'Fabric keeps this off: it gives access to other people or services. Nothing was run.', invalid_request: 'This request now belongs to a stricter permission. Nothing was run.',
  unavailable: 'This operation can never work through a sign-in. Nothing was run.',
  // F10.11 part m: an action's own outcomes.
  input_schema_changed: 'The fields of this resource changed after they were read. Nothing was sent: read them again and ask again.',
  action_refused: 'Fabric refused this action for what it was given or what it read. Nothing was changed.',
};
/** A relayed decision as the developer sees it: what was decided, where, and when; never the key's id. F10.11 part m: an action's every
 *  decision too, one per stop, by phase. */
const decisionOf = job => ({...(job.decision && ['approved', 'rejected'].includes(job.decision.decision) ? {decision: {decision: job.decision.decision, decidedIn: job.decision.decidedIn, at: job.decision.at}} : {}),
  ...(job.kind === 'action' && Array.isArray(job.action?.decisions) && job.action.decisions.length ? {decisions: job.action.decisions.map(({phase, decision, at}) => ({phase: phase === 'final' ? 'final' : 'reads', decision, at}))} : {})});
/** The governed proxy's refusals as the developer API's (docs/F03.7-BUILD-MAP.md slice 3). */
function proxyRefusal(error) {
  if (error instanceof TenantError) return error;
  if (error?.code === 'not_found') return notFound();
  if (!(error instanceof ProxyRequestError)) return translated(error);
  if (error.code === 'policy_denied') return new TenantError(403, 'permission_denied', 'This account\'s permissions do not allow this request.');
  if (error.code === 'provider_access_missing' || error.code === 'proxy_unavailable') return new TenantError(422, error.code, String(error.message).slice(0, 300));
  return new TenantError(400, 'invalid_request', String(error.message).slice(0, 300), {code: error.code});
}
/**
 * A full url becomes the path and query the reviewed normaliser checks: it must sit exactly on the app's reviewed
 * base. Never new URL().pathname, which would resolve '..' and '%2e%2e' and could move a request to another API.
 */
export function proxyInput(appId, request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw invalid('request is {method, path or url, query?, headers?, body?}.');
  if (request.url === undefined) return request;
  if (request.path !== undefined) throw invalid('Send path or url, not both.');
  const config = PROXY_CONFIGS.get(appId);
  if (!config) throw new TenantError(422, 'proxy_unavailable', 'This app has no reviewed proxy settings.');
  const base = proxyBase(config.apiBase), prefix = `${base.origin}${base.basePath}`, url = request.url;
  if (typeof url !== 'string' || url.length > 4096 || !url.startsWith(`${prefix}/`) || url.includes('#')) throw new TenantError(422, 'origin_not_reviewed', `The url must start with ${prefix}/ and carry no fragment.`);
  const rest = url.slice(prefix.length), at = rest.indexOf('?'), path = at < 0 ? rest : rest.slice(0, at), search = at < 0 ? '' : rest.slice(at + 1);
  const {url: _url, ...others} = request;
  if (!search) return {...others, path};
  if (request.query !== undefined) throw invalid('Send the query in the url or in query, not both.');
  const query = {};
  for (const pair of search.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('='), raw = eq < 0 ? [pair, ''] : [pair.slice(0, eq), pair.slice(eq + 1)];
    let name, value;
    try { [name, value] = raw.map(part => decodeURIComponent(part.replace(/\+/g, ' '))); } catch { throw invalid('The url query is not valid percent-encoding.'); }
    query[name] = Object.hasOwn(query, name) ? [...[query[name]].flat(), value] : value;
  }
  return {...others, path, query};
}
const ATTRIBUTION = {caller: 'input', fabric: 'fabric', provider: 'provider', credential: 'credential', policy: 'policy', delivery: 'fabric'};
const attributionOf = code => ATTRIBUTION[ERROR_DEFINITIONS[code]?.source] ?? ({not_found: 'credential', permission_denied: 'policy', connection_required: 'credential', capability_changed: 'policy', invalid_arguments: 'input', handoff_expired: 'credential', handoff_failed: 'credential', app_disabled: 'policy', key_revoked: 'credential', agent_revoked: 'credential', invalid_request: 'policy'}[code] ?? 'fabric');
/** The runtime's coded refusals as the developer API's. */
const STATUS = {permission_denied: 403, connection_required: 409, invalid_arguments: 400, capability_changed: 409, not_found: 404, not_cancellable: 409};
function translated(error) {
  if (error instanceof TenantError) return error;
  const code = error?.code;
  // T4 (F10.3): a lock says so in Fabric's fixed words, never as the account's own setting.
  if (code === 'permission_denied' && error.locked === true) return new TenantError(403, code, WORDS.locked);
  // F10.6 (T3): an operation that can never work through a sign-in says so in Fabric's fixed words too.
  if (code === 'permission_denied' && error.unavailable === true) return new TenantError(403, code, WORDS.unavailable);
  if (code && STATUS[code]) return new TenantError(STATUS[code], code, code === 'not_found' ? 'Nothing with that id exists here.' : WORDS[code] || String(error.message).slice(0, 300));
  // F10.11 part m: an action refused when it was accepted keeps its code and its own fixed words, as on /api, with the reason it names.
  if (code === 'action_refused') return new TenantError(400, code, String(error.message).slice(0, 300), typeof error.details?.reason === 'string' ? {reason: error.details.reason} : undefined);
  return error;
}

export const MAX_PENDING_PROXY = 20, MAX_PROXY_REFUSALS = 60, MAX_WAITING_HOLDS = 20, HOLD_SECONDS = 1800, MAX_PENDING_CALLS = 20, MAX_HOLDS_AN_HOUR = 60;
export class TenantExecutions {
  #waiting = new Map();
  /** Refused proxied requests per environment and requester (a service client or an agent token) in the last minute (build map slice 3, Limits). */
  #refusals = new Map();
  /** @param {{stores: any, registry: any, accounts: import('./accounts.mjs').TenantAccounts, runtimes: import('./runtime-bundle.mjs').EnvironmentRuntimes, usage: import('./usage.mjs').UsageRecords}} deps */
  constructor(deps) { Object.assign(this, deps); this.keys = new IdempotencyKeys({registry: deps.registry}); }

  /**
   * At most 16 waiting requests per key at once. A read-back past that is told to come back (429); a request already
   * accepted is never refused after the fact: it simply answers at once (202), with its callRef.
   */
  async #waited(caller, work, {accepted = false} = {}) {
    const count = this.#waiting.get(caller.keyId) || 0;
    if (count >= MAX_WAITERS && accepted) return;
    if (count >= MAX_WAITERS) throw new TenantError(429, 'rate_limited', 'Too many requests are waiting with this key; try again shortly.', undefined, {'Retry-After': '1'});
    this.#waiting.set(caller.keyId, count + 1);
    try { return await work(); } finally { const left = (this.#waiting.get(caller.keyId) || 1) - 1; if (left) this.#waiting.set(caller.keyId, left); else this.#waiting.delete(caller.keyId); }
  }
  /** The developer turned this app off here: nothing runs on it. Only an explicit off counts; a shared sign-in app that
   *  is full or not set up stops new connections, never the accounts already connected. */
  #turnedOff(caller, appId) {
    if (this.registry.get('environments', caller.scope.environmentId)?.apps?.[appId]?.enabled === false) throw new TenantError(422, 'app_disabled', 'This app is turned off in this environment.');
  }
  /** Tests only (exit check 1): which keys and clients have calls waiting or refusals counted now. Changes nothing. */
  [Symbol.for('fabric.test.maps')]() { return {waiting: [...this.#waiting.keys()], refusals: [...this.#refusals.keys()]}; }
  /**
   * One requester's refusals here (a developer's service client, or an agent token): past 60 in a minute it is
   * rate_limited before anything else is evaluated. Shared by /v1/proxy/requests and agents' proxy.request.
   */
  refusalWindow(scope, requester) {
    const key = `${scope.environmentId}:${requester}`, now = Date.parse(this.registry.now());
    const window = (this.#refusals.get(key) || []).filter(at => now - at < 60_000);
    if (window.length) this.#refusals.set(key, window); else this.#refusals.delete(key);
    return {limited: window.length >= MAX_PROXY_REFUSALS, refused: error => { window.push(now); this.#refusals.set(key, window); return error; }};
  }
  /** Whether one requester already made 60 account requests (holds) for this person in the last hour, withdrawn or not. */
  asksFull(env, owner, from) {
    const since = Date.parse(this.registry.now()) - 3_600_000;
    return env.repository.listWhere('continuations', 'userRecordId', owner.userRecordId).filter(item => item?.kind === 'hold' && Date.parse(item.createdAt) > since && from(item.source)).length >= MAX_HOLDS_AN_HOUR;
  }
  /**
   * Whether one requester already has its most calls of this kind waiting for an approval: 20 proxied requests in the
   * environment, or 20 typed calls for one person. Read through an index (the person's records, or the waiting ones),
   * never by parsing every job.
   */
  pendingFull(env, {proxy, owner = null, from}) {
    const now = Date.parse(this.registry.now()), deployment = tenantDeployment(env.scope);
    const jobs = owner ? env.repository.listWhere('jobs', 'userRecordId', owner.userRecordId).filter(job => ownedBy(job, owner, deployment)) : env.repository.listWhere('jobs', 'status', 'awaiting_approval');
    const waiting = jobs.filter(job => job?.status === 'awaiting_approval' && (job.kind === 'proxy') === proxy && Date.parse(job.approvalExpiresAt) > now && from(job.source)).length;
    return waiting >= (proxy ? MAX_PENDING_PROXY : MAX_PENDING_CALLS);
  }
  /** A refusal that holds only for now (the app is off, a limit is full): the key's reservation goes, so the same key can try again later. */
  #released(env, record, error) { env.repository.delete(IDEMPOTENCY, record.id); return error; }
  #waitMs(value) {
    if (value === undefined || value === null || value === '') return 0;
    const ms = Number(value);
    if (!Number.isSafeInteger(ms) || ms < 0 || ms > MAX_WAIT_MS) throw invalid(`waitMs is 0 to ${MAX_WAIT_MS}.`);
    return ms;
  }

  /** POST /v1/executions */
  async create(caller, body, idempotencyKey) {
    const fields = ['externalUserId', 'accountRef', 'appId', 'capabilityId', 'definitionHash', 'args', 'task', 'waitMs', 'onMissingAccess'];
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw invalid('The body must be a JSON object.');
    const unknown = Object.keys(body).find(key => !fields.includes(key));
    if (unknown) throw invalid(`Unknown field: ${unknown.slice(0, 40)}.`);
    const key = IdempotencyKeys.checked(idempotencyKey), waitMs = this.#waitMs(body.waitMs);
    if (body.onMissingAccess !== undefined && !['refuse', 'hold'].includes(body.onMissingAccess)) throw invalid('onMissingAccess is refuse or hold.');
    if (typeof body.capabilityId !== 'string' || typeof body.definitionHash !== 'string') throw invalid('Send capabilityId and definitionHash.');
    if (body.args !== undefined && (body.args === null || typeof body.args !== 'object' || Array.isArray(body.args))) throw invalid('args is an object.');
    const bundle = this.runtimes.bundle(caller.scope), env = bundle.env;
    // The end user, then the account: another user's or an unknown account is not_found, before anything else is said.
    const user = this.accounts.user(env, body.externalUserId);
    if (!user) throw notFound();
    const owner = this.accounts.ownerOf(user), cap = env.repository.get('capabilities', body.capabilityId);
    if (!cap || cap.status !== 'active') throw notFound();
    if (body.appId !== undefined && body.appId !== cap.appId) throw invalid('appId does not match the operation.');
    let account;
    try { account = body.accountRef !== undefined ? this.accounts.ownedAccount(env, owner, body.accountRef) : this.accounts.chosenAccount(env, owner, cap.appId); }
    catch (error) {
      // F03.9d: no account yet and the developer asked to hold: the call waits for the person to connect one.
      if (body.onMissingAccess === 'hold' && body.accountRef === undefined && error?.code === 'connection_required') return this.#hold(caller, env, owner, cap, body, key);
      throw error;
    }
    if (account.appId !== cap.appId) throw notFound();
    // Then the Idempotency-Key (after scope and ownership), keyed by environment, service client, route and key. A
    // replay of an accepted call answers that call: the app switch and the limits apply to new requests only.
    const {waitMs: _ignored, ...request} = body, callRef = randomUUID();
    const {record, replay} = this.keys.begin(env, caller, {route: ROUTE, key, body: request, owner, callRef});
    if (replay) return this.#replay(caller, env, record, waitMs);
    try { this.#turnedOff(caller, cap.appId); } catch (error) { throw this.#released(env, record, error); }
    // At most 20 calls from this service client waiting for this person's approval; a call that would not wait still runs.
    let waits = false;
    try { waits = bundle.permissions.decision(account, cap).requiresApproval === true; } catch { waits = false; }
    if (waits && this.pendingFull(env, {proxy: false, owner, from: source => source?.kind === 'service' && source.serviceClientId === caller.serviceClientId}))
      throw this.#released(env, record, new TenantError(429, 'pending_limit', 'Too many calls are waiting for this person\'s approval. Wait for some to be decided.'));
    let job;
    try {
      if (capabilityPermissionHash(cap) !== body.definitionHash) throw new TenantError(409, 'capability_changed', 'This operation changed since you read it; read it again and send its current definitionHash.');
      // The source is the calling key, set here; the body can never name one.
      job = await bundle.runtime.prepareJob({connectionId: account.id, capabilityId: cap.id, args: body.args ?? {}, source: {kind: 'service', serviceClientId: caller.serviceClientId, keyId: caller.keyId}},
        {kind: 'product_user', ...owner}, {jobId: callRef, ...(body.task !== undefined ? {task: body.task} : {})});
    } catch (error) {
      // A body routed to another row names that row (F10.3), so the developer can send it there instead.
      const known = error?.code === 'invalid_request' ? new TenantError(400, 'invalid_request', String(error.message), error.details?.routedTo ? {routedTo: error.details.routedTo} : undefined) : translated(error);
      if (known instanceof TenantError) this.keys.refused(env, record, known);
      throw known;
    }
    this.keys.recorded(env, record);
    this.usage.append(env, {id: `exec.${job.id}`, kind: 'execution', userRecordId: owner.userRecordId, serviceClientId: caller.serviceClientId, keyId: caller.keyId, appId: cap.appId, capabilityId: cap.id});
    if (job.status === 'queued') this.runtimes.dispatch(caller.scope, job.id);
    return this.#answer(caller, env, job.id, waitMs, {accepted: true});
  }
  /** POST /v1/proxy/requests: one governed request on one end user's account, under the account's proxy rows and every clamp (c1 to c7). */
  async createProxy(caller, body, idempotencyKey) {
    const fields = ['externalUserId', 'accountRef', 'appId', 'request', 'timeoutMs', 'task', 'waitMs'];
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw invalid('The body must be a JSON object.');
    const unknown = Object.keys(body).find(key => !fields.includes(key));
    if (unknown) throw invalid(`Unknown field: ${unknown.slice(0, 40)}.`);
    const key = IdempotencyKeys.checked(idempotencyKey), waitMs = this.#waitMs(body.waitMs);
    if (body.accountRef === undefined && typeof body.appId !== 'string') throw invalid('Without an accountRef, name the appId.');
    const bundle = this.runtimes.bundle(caller.scope), env = bundle.env;
    const user = this.accounts.user(env, body.externalUserId);
    if (!user) throw notFound();
    const owner = this.accounts.ownerOf(user);
    const account = body.accountRef !== undefined ? this.accounts.ownedAccount(env, owner, body.accountRef) : this.accounts.chosenAccount(env, owner, body.appId);
    if (body.appId !== undefined && account.appId !== body.appId) throw notFound();
    // A replay of an accepted request answers that request, never a limit or the app switch, and is never counted.
    const {waitMs: _ignored, ...request} = body;
    const {record, replay} = this.keys.begin(env, caller, {route: PROXY_ROUTE, key, body: request, owner, callRef: null});
    if (replay) return this.#replay(caller, env, record, waitMs);
    try { this.#turnedOff(caller, account.appId); } catch (error) { throw this.#released(env, record, error); }
    // Limits per environment and service client: 60 refused requests a minute, then nothing more is evaluated; at most
    // 20 proxied requests waiting for an approval at once.
    const {limited, refused} = this.refusalWindow(caller.scope, caller.serviceClientId);
    if (limited) throw this.#released(env, record, new TenantError(429, 'rate_limited', 'Too many refused proxied requests. Wait a minute before trying again.', undefined, {'Retry-After': '60'}));
    if (this.pendingFull(env, {proxy: true, from: source => source?.kind === 'service' && source.serviceClientId === caller.serviceClientId}))
      throw this.#released(env, record, refused(new TenantError(429, 'pending_limit', 'Too many proxied requests are waiting for approval. Wait for some to be decided.')));
    let job;
    try {
      const input = proxyInput(account.appId, body.request);
      // Synchronous from here to the stored job: no other request can interleave between the reservation and the job.
      job = bundle.runtime.prepareProxy({connectionId: account.id, request: input, ...(body.timeoutMs !== undefined ? {timeoutMs: body.timeoutMs} : {}), source: {kind: 'service', serviceClientId: caller.serviceClientId, keyId: caller.keyId}},
        {kind: 'product_user', ...owner}, {...(body.task !== undefined ? {task: body.task} : {})});
    } catch (error) {
      const known = error?.code === 'invalid_request' && !(error instanceof ProxyRequestError) ? invalid(String(error.message)) : proxyRefusal(error);
      if (known instanceof TenantError) { this.keys.refused(env, record, known); refused(known); }
      throw known;
    }
    this.keys.recorded(env, {...record, callRef: job.id});
    this.usage.append(env, {id: `proxy.${job.id}`, kind: 'proxy', userRecordId: owner.userRecordId, serviceClientId: caller.serviceClientId, keyId: caller.keyId, appId: account.appId});
    if (job.status === 'queued') this.runtimes.dispatch(caller.scope, job.id);
    return this.#answer(caller, env, job.id, waitMs, {accepted: true});
  }
  /**
   * A held execution (F03.9d): no job yet, and a handoff Connect session for this person and app. The developer mints its
   * link with /link; when the person connects (or picks) an account and confirms, the same callRef runs. Nothing is sent
   * and nothing is counted until then.
   */
  /**
   * Whether a hold may be made now (shared by developer keys and agent tokens): the app is on and can connect accounts,
   * and the same requester has fewer than 20 calls waiting.
   */
  holdAllowed(scope, env, appId, requester) {
    if (this.registry.get('environments', scope.environmentId)?.apps?.[appId]?.enabled === false) throw new TenantError(422, 'app_disabled', 'This app is turned off in this environment.');
    const environment = this.registry.get('environments', scope.environmentId), setting = this.sessions.appSetting(appId, environment, this.sessions.providerApps);
    if (setting.availability.state !== 'ready') throw new TenantError(422, setting.availability.state, setting.availability.reason);
    if (!setting.enabled) throw new TenantError(422, 'app_disabled', 'This app is turned off in this environment.');
    const now = Date.parse(this.registry.now());
    const waiting = env.repository.listWhere('continuations', 'status', 'waiting').filter(item => item?.kind === 'hold' && Date.parse(item.expiresAt) > now && requester(item.source)).length;
    if (waiting >= MAX_WAITING_HOLDS) throw new TenantError(429, 'pending_limit', 'Too many calls are waiting for an account. Let some finish first.');
  }
  /** Stores a hold and its handoff session (no link yet). Shared by developer keys and agent tokens. */
  makeHold(scope, env, {owner, cap, callRef, args, title, source, createdBy}) {
    const now = Date.parse(this.registry.now()), expiresAt = new Date(now + HOLD_SECONDS * 1000).toISOString();
    const session = this.sessions.createHandoff(scope, {owner, appId: cap.appId, callRef, createdBy, expiresAt});
    const hold = stampOwner({id: callRef, kind: 'hold', capabilityId: cap.id, definitionHash: capabilityPermissionHash(cap), appId: cap.appId, args: args ?? {}, ...(title ? {task: {title}} : {}), source, connectSessionId: session.id,
      status: 'waiting', createdAt: this.registry.now(), updatedAt: this.registry.now(), expiresAt}, owner);
    env.repository.put('continuations', hold);
    env.repository.audit({type: 'execution.held', callRef, userRecordId: owner.userRecordId, appId: cap.appId, ...(source.kind === 'client' ? {agentId: source.clientId, keyId: source.keyId} : {byKey: source.keyId})});
    return hold;
  }
  /** A hold of this environment, its view settled (lazily closed when its link ended). */
  holdView(scope, env, hold) { return this.#holdView(this.#settleHold(scope, env, hold)); }
  /** Closes a waiting hold from Fabric's side (an agent withdrew it, its token was revoked, its person deleted). */
  async closeHold(scope, env, hold, code, by = {}) {
    // Fabric's own close records its own code (a token revoked here reads agent_revoked with who revoked it).
    const settled = this.#settleHold(scope, env, hold, {requester: false});
    if (settled.status !== 'waiting') return false;
    env.repository.put('continuations', {...settled, status: 'closed', outcome: {status: 'cancelled', code}, ...by, updatedAt: this.registry.now()});
    await this.#endHandoff(scope, env, settled.connectSessionId);
    return true;
  }
  /** Cancels a closed hold's handoff (releasing any account waiting there); a link nobody opened also loses its route. */
  async #endHandoff(scope, env, sessionId) {
    await this.sessions.cancelHandoff(scope, sessionId);
    if (!env.repository.get('connectSessions', sessionId)?.claimedAt) this.registry.removeRoute('sessionRoutes', sessionId);
  }
  /**
   * Why a waiting hold's requester can no longer ask, or null: an agent token revoked (alone or with its key) or
   * expired, or a developer key revoked or expired. Checked whenever the hold is looked at, linked or resumed.
   */
  #requesterGone(scope, hold) {
    const source = hold.source;
    if (source?.kind === 'client') {
      try { this.runtimes.bundle(scope).agents.activeGrant(source.clientId); return null; } catch { return 'agent_revoked'; }
    }
    const key = typeof source?.keyId === 'string' ? this.registry.get('serviceKeys', source.keyId) : null, client = key && this.registry.get('serviceClients', key.serviceClientId);
    const active = key && !key.revokedAt && (!key.expiresAt || Date.parse(key.expiresAt) > Date.parse(this.registry.now())) && key.environmentId === scope.environmentId;
    return active && client?.status === 'active' && client.id === source.serviceClientId ? null : 'key_revoked';
  }
  /** Whether the hold behind a handoff session still waits (closing it first if its requester is gone): no link otherwise. */
  handoffWaiting(scope, session) {
    const env = this.runtimes.bundle(scope).env, hold = env.repository.get('continuations', session.callRef);
    return Boolean(hold && hold.kind === 'hold' && hold.connectSessionId === session.id && this.#settleHold(scope, env, hold).status === 'waiting');
  }
  #hold(caller, env, owner, cap, body, key) {
    const {waitMs: _ignored, ...request} = body, callRef = randomUUID();
    const {record, replay} = this.keys.begin(env, caller, {route: ROUTE, key, body: request, owner, callRef});
    if (replay) return this.#replay(caller, env, record, 0);
    try {
      this.#turnedOff(caller, cap.appId);
      this.holdAllowed(caller.scope, env, cap.appId, source => source?.serviceClientId === caller.serviceClientId);
    } catch (error) { throw this.#released(env, record, error); }
    let title = null;
    try {
      if (capabilityPermissionHash(cap) !== body.definitionHash) throw new TenantError(409, 'capability_changed', 'This operation changed since you read it; read it again and send its current definitionHash.');
      try { title = taskTitle(body.task); } catch (error) { throw invalid(String(error.message)); }
      // A call that can never run makes no hold and no Connect session: its operation locked (T4) or unavailable through any sign-in
      // (F10.6), its arguments wrong, or its body routed to another row (F10.3). Each refusal is kept with the key, so a replay answers the same.
      const permissions = this.runtimes.bundle(caller.scope).permissions, args = body.args ?? {};
      if (permissions.lockOf(cap)) throw new TenantError(403, 'permission_denied', WORDS.locked);
      if (permissions.unavailableOf(cap)) throw new TenantError(403, 'permission_denied', WORDS.unavailable);
      // F10.11 part m: an action described by the resource it acts on waits for no account: it is described once one exists.
      if (resourceDependent(cap)) throw invalid(ACTION_WORDS.describe);
      try { validateInput(cap.inputSchema, args); } catch { throw new TenantError(400, 'invalid_arguments', WORDS.invalid_arguments); }
      const routed = permissions.routedBody(cap, args);
      if (routed) throw new TenantError(400, 'invalid_request', routedWords(routed), {routedTo: {groupId: routed.groupId, label: routed.label}});
    } catch (error) { this.keys.refused(env, record, error); throw error; }
    const source = {kind: 'service', serviceClientId: caller.serviceClientId, keyId: caller.keyId};
    const hold = this.makeHold(caller.scope, env, {owner, cap, callRef, args: body.args, title, source, createdBy: {serviceClientId: caller.serviceClientId, keyId: caller.keyId}});
    this.keys.recorded(env, record);
    return {status: 202, body: this.#holdView(hold)};
  }
  /**
   * A hold whose link ended (expired, failed, cancelled or declined) is closed the first time anyone looks; so is one
   * whose requester is gone (a revoked or expired token or key), or whose operation is now locked (T4, F10.3) or can never
   * work through a sign-in (F10.6), and its link is cancelled with it. The outcome says which.
   */
  #settleHold(scope, env, hold, {requester = true} = {}) {
    if (hold.status !== 'waiting') return hold;
    const {state, errorCode} = this.sessions.stateOf(scope, hold.connectSessionId);
    const gone = !requester || ['expired', 'failed', 'cancelled'].includes(state) ? null : this.#requesterGone(scope, hold);
    const locked = !requester || gone || ['expired', 'failed', 'cancelled'].includes(state) ? false : this.#lockedNow(scope, env, hold);
    if (gone || locked) {
      const outcome = gone ? {status: 'cancelled', code: gone} : {status: 'failed', code: 'permission_denied', ...(locked === 'unavailable' ? {unavailable: true} : {locked: true})};
      const closed = {...hold, status: 'closed', outcome, updatedAt: this.registry.now()};
      env.repository.put('continuations', closed);
      env.repository.audit({type: 'execution.hold_closed', callRef: hold.id, code: outcome.code});
      // Detached and tracked like the link's other endings, so shutdown and tests can wait for it.
      const done = this.#endHandoff(scope, env, hold.connectSessionId).catch(() => {});
      this.sessions.revocations?.add(done); done.finally(() => this.sessions.revocations?.delete(done));
      return closed;
    }
    if (!['expired', 'failed', 'cancelled'].includes(state)) return hold;
    const outcome = state === 'expired' ? {status: 'failed', code: 'handoff_expired'} : state === 'failed' ? {status: 'failed', code: 'handoff_failed'} : {status: 'cancelled', code: errorCode === 'declined' ? 'declined' : 'cancelled'};
    const closed = {...hold, status: 'closed', outcome, updatedAt: this.registry.now()};
    env.repository.put('continuations', closed);
    return closed;
  }
  /** Why no account could ever run the held operation now: 'locked' when Fabric keeps it off, 'unavailable' when no sign-in can
   *  (F10.6), else null. */
  #lockedNow(scope, env, hold) {
    const cap = env.repository.get('capabilities', hold.capabilityId), permissions = this.runtimes.bundle(scope).permissions;
    return !cap ? null : permissions.lockOf(cap) ? 'locked' : permissions.unavailableOf(cap) ? 'unavailable' : null;
  }
  /** What the developer sees of a hold: never a link; the handoff session to mint one for. One closed by a lock (T4), or because no
   *  sign-in can run its operation (F10.6), says so in Fabric's fixed words, never as the account's own setting. */
  #holdView(hold) {
    const base = {callRef: hold.id, capabilityId: hold.capabilityId, appId: hold.appId, createdAt: hold.createdAt, updatedAt: hold.updatedAt, evidence: 'none'};
    if (hold.status === 'waiting') return {...base, status: 'connection_required', accountRef: null, handoff: {connectSessionId: hold.connectSessionId, expiresAt: hold.expiresAt}};
    if (hold.status === 'resuming' || hold.status === 'resumed') return {...base, status: 'queued', accountRef: hold.binding?.accountRef ?? null};
    const code = hold.outcome?.code ?? 'fabric_failed';
    return {...base, status: hold.outcome?.status ?? 'failed', accountRef: hold.binding?.accountRef ?? null,
      ...(hold.outcome?.status === 'failed' ? {error: {code, message: hold.outcome.locked === true ? WORDS.locked : hold.outcome.unavailable === true ? WORDS.unavailable : WORDS[code] || 'This request did not complete.', attribution: attributionOf(code), retryable: false}} : {})};
  }
  /**
   * The person confirmed an account on Fabric's page: the held call runs on it as the same callRef. The hold is taken
   * synchronously (a racing cancel finds it gone), then checked again: the account is theirs, ready and for the app; the
   * app is still on; the operation unchanged. Any refusal closes the hold with that code, and nothing is sent.
   */
  async resumeHold(scope, session, accountRef) {
    const bundle = this.runtimes.bundle(scope), env = bundle.env, hold = env.repository.get('continuations', session.callRef);
    if (!hold || hold.kind !== 'hold' || hold.status !== 'waiting' || hold.connectSessionId !== session.id) return;
    let owner;
    try { owner = ownershipOf(hold, tenantDeployment(env.scope)); } catch { return; }
    const binding = {accountRef, decidedIn: 'fabric_page', linkKeyId: env.repository.get('connectSessions', session.id)?.linkedBy?.keyId ?? null};
    env.repository.put('continuations', {...hold, status: 'resuming', binding, updatedAt: this.registry.now()});
    const close = (code, mark = {}) => { env.repository.put('continuations', {...hold, status: 'closed', binding, outcome: {status: 'failed', code, ...mark}, updatedAt: this.registry.now()}); env.repository.audit({type: 'execution.hold_refused', callRef: hold.id, code}); };
    try {
      // The requester must still be able to ask: a revoked or expired key or token runs nothing, link or no link.
      const gone = this.#requesterGone(scope, hold);
      if (gone) return close(gone);
      const connection = env.repository.get('connections', accountRef);
      if (!connection || connection.status !== 'ready' || connection.appId !== hold.appId || !ownedBy(connection, owner, tenantDeployment(env.scope))) return close('connection_required');
      if (this.registry.get('environments', scope.environmentId)?.apps?.[hold.appId]?.enabled === false) return close('app_disabled');
      const cap = env.repository.get('capabilities', hold.capabilityId);
      if (!cap || cap.status !== 'active' || capabilityPermissionHash(cap) !== hold.definitionHash) return close('capability_changed');
      const job = await bundle.runtime.prepareJob({connectionId: accountRef, capabilityId: cap.id, args: hold.args, source: hold.source}, {kind: 'product_user', ...owner}, {jobId: hold.id, ...(hold.task ? {task: hold.task} : {})});
      this.usage.append(env, {id: `exec.${job.id}`, kind: 'execution', userRecordId: owner.userRecordId, serviceClientId: hold.source.serviceClientId ?? null, keyId: hold.source.keyId, appId: cap.appId, capabilityId: cap.id});
      env.repository.put('continuations', {...hold, status: 'resumed', binding, updatedAt: this.registry.now()});
      env.repository.audit({type: 'execution.resumed', callRef: hold.id, userRecordId: owner.userRecordId, accountRef, decidedIn: 'fabric_page', linkKeyId: binding.linkKeyId});
      if (job.status === 'queued') this.runtimes.dispatch(scope, job.id);
    } catch (error) {
      // A lock or an operation no sign-in can run is read by its mark (F10.3, F10.6), so the view says why in fixed words.
      const code = translated(error)?.code, mark = code !== 'permission_denied' ? {} : error?.locked === true ? {locked: true} : error?.unavailable === true ? {unavailable: true} : {};
      close(typeof code === 'string' && WORDS[code] ? code : 'fabric_failed', mark);
    }
  }
  async #replay(caller, env, record, waitMs) {
    if (record.status === 'refused') throw new TenantError(record.refusal.status, record.refusal.code, record.refusal.message, record.refusal.details);
    // A held call replays as itself: the same callRef and the same handoff session.
    if (record.callRef && !env.repository.get('jobs', record.callRef) && env.repository.get('continuations', record.callRef)?.kind === 'hold') return this.#answer(caller, env, record.callRef, 0, {accepted: true});
    if (!record.callRef || !env.repository.get('jobs', record.callRef)) throw new TenantError(409, 'idempotency_conflict', 'A request with this Idempotency-Key did not finish being accepted; send it again with a new key.');
    return this.#answer(caller, env, record.callRef, waitMs, {accepted: true});
  }
  async #answer(caller, env, callRef, waitMs, {accepted = false} = {}) {
    const pending = () => ['queued', 'running'].includes(env.repository.get('jobs', callRef)?.status);
    if (waitMs > 0 && pending()) await this.#waited(caller, () => this.runtimes.wait(caller.scope, callRef, waitMs), {accepted});
    // Read again after the wait: an end user deleted meanwhile answers exactly like a missing call.
    const {job, hold} = this.#job(env, callRef);
    if (!job) { const view = this.#holdView(this.#settleHold(caller.scope, env, hold)); return {status: TERMINAL.has(view.status) ? 200 : 202, body: view}; }
    const execution = this.project(caller, env, job);
    return {status: TERMINAL.has(execution.status) ? 200 : 202, body: execution};
  }

  /** The stored job of this environment, its end user still active; anything else is not_found (environment-wide, N2). */
  #job(env, callRef) {
    if (typeof callRef !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(callRef)) throw notFound();
    const job = env.repository.get('jobs', callRef), held = job ? null : env.repository.get('continuations', callRef);
    const hold = held?.kind === 'hold' ? held : null;
    if (!job && !hold) throw notFound();
    let owner;
    try { owner = ownershipOf(job ?? hold, tenantDeployment(env.scope)); } catch { throw notFound(); }
    const user = env.repository.get('endUsers', owner.userRecordId);
    if (!user || user.status !== 'active' || user.subjectId !== owner.subjectId) throw notFound();
    return job ? {job, owner} : {hold, owner};
  }
  /** GET /v1/executions/:callRef?waitMs= */
  async get(caller, callRef, waitMs) {
    const env = this.runtimes.bundle(caller.scope).env;
    this.#job(env, callRef);
    return this.#answer(caller, env, callRef, this.#waitMs(waitMs));
  }
  /** POST /v1/executions/:callRef/cancel */
  async cancel(caller, callRef) {
    const bundle = this.runtimes.bundle(caller.scope), found = this.#job(bundle.env, callRef), {owner} = found;
    if (found.hold) {
      // A waiting hold ends here: its link closes (releasing any account waiting there), and nothing is ever sent.
      const hold = this.#settleHold(caller.scope, bundle.env, found.hold);
      if (hold.status !== 'waiting') throw new TenantError(409, 'not_cancellable', 'This call is no longer waiting for an account.');
      const closed = {...hold, status: 'closed', outcome: {status: 'cancelled', code: 'cancelled'}, cancelledByKey: caller.keyId, updatedAt: this.registry.now()};
      bundle.env.repository.put('continuations', closed);
      bundle.env.repository.audit({type: 'execution.hold_cancelled', callRef, userRecordId: owner.userRecordId, byKey: caller.keyId});
      await this.sessions.cancelHandoff(caller.scope, hold.connectSessionId);
      return this.#holdView(closed);
    }
    let job;
    try { job = bundle.runtime.cancel(callRef, {kind: 'product_user', ...owner}, {keyId: caller.keyId, serviceClientId: caller.serviceClientId}); } catch (error) { throw translated(error); }
    return this.project(caller, bundle.env, job);
  }

  /** The Execution the developer sees, from stored state only; the result is withheld if authority changed since. */
  project(caller, env, job) {
    const bundle = this.runtimes.bundle(caller.scope), now = Date.parse(this.registry.now());
    let status = job.status, errorCode = job.errorCode ?? null;
    // An approval nobody gave in time reads as failed (decision of October 13, 2026).
    if (status === 'awaiting_approval' && Date.parse(job.approvalExpiresAt) <= now) { status = 'failed'; errorCode = 'approval_expired'; }
    if ((status === 'failed' || status === 'uncertain') && !errorCode) errorCode = status === 'uncertain' ? 'outcome_uncertain' : 'fabric_failed';
    // A sign-in the provider revoked (a refresh answered invalid_grant) is the developer's documented connection_required.
    if (errorCode === 'reconnect_required') errorCode = 'connection_required';
    const proxy = job.kind === 'proxy', cap = proxy ? null : env.repository.get('capabilities', job.capabilityId), connection = env.repository.get('connections', job.connectionId);
    // A result is shown only while the account and its permission still allow it (F08.0 section 6).
    let withheld = false;
    if (job.result) {
      try {
        const decision = !connection || connection.status === 'revoked' ? null : proxy ? bundle.runtime.proxyPolicy.decide(job.connectionId, job.args.request, {timeoutMs: job.args.timeoutMs}) : cap ? bundle.permissions.decision(connection, cap) : null;
        withheld = !decision || decision.mode === 'deny';
      } catch { withheld = true; }
    }
    if (proxy) {
      // The provider's response as stored: status, allowlisted headers, and the body while it is kept (7 days).
      const response = job.result?.response, kept = response && !withheld ? proxyResponseBody(bundle.runtime, job) : null;
      const verification = job.result?.verification, evidence = status === 'succeeded' && verification?.status === 'observed' ? 'observed' : 'none';
      return {callRef: job.id, kind: 'proxy', status, appId: job.proxy?.appId ?? null, accountRef: job.connectionId, createdAt: job.createdAt, updatedAt: job.updatedAt,
        ...(response && !withheld ? {result: {status: response.status, headers: response.headers, ...(kept ? kept : {})}} : {}), ...(withheld ? {resultWithheld: true} : {}), evidence,
        ...(errorCode && (status === 'failed' || status === 'uncertain') ? {error: {code: errorCode, message: WORDS[errorCode] || 'This request did not complete.', attribution: attributionOf(errorCode), ...(response?.status && status !== 'succeeded' ? {providerStatus: response.status} : {}), retryable: false}} : {}),
        ...(status === 'awaiting_approval' ? {approval: {callRef: job.id, expiresAt: job.approvalExpiresAt}} : {}), ...decisionOf(job)};
    }
    const verification = job.result?.verification;
    // F10.11 part m: an action's readback verifies as a typed one's does; its approval says which phase waits, reads or final.
    const evidence = ['http-readback', 'action-readback'].includes(verification?.kind) && verification.status === 'verified' ? 'verified' : status === 'succeeded' && verification?.status === 'observed' ? 'observed' : 'none';
    return {callRef: job.id, status, capabilityId: job.capabilityId, appId: cap?.appId ?? null, accountRef: job.connectionId, createdAt: job.createdAt, updatedAt: job.updatedAt,
      ...(job.result && !withheld && job.result.data !== undefined ? {result: job.result.data} : {}), ...(withheld ? {resultWithheld: true} : {}), evidence,
      ...(errorCode && (status === 'failed' || status === 'uncertain') ? {error: {code: errorCode, message: WORDS[errorCode] || 'This request did not complete.', attribution: attributionOf(errorCode), ...(job.providerStatus ? {providerStatus: job.providerStatus} : {}),
        ...(Number.isSafeInteger(job.retryAfterSeconds) ? {retryAfterSeconds: job.retryAfterSeconds} : {}), retryable: false}} : {}),
      ...(status === 'awaiting_approval' ? {approval: {callRef: job.id, expiresAt: job.approvalExpiresAt, ...(job.kind === 'action' ? {phase: job.action?.phase === 'final' ? 'final' : 'reads'} : {})}} : {}), ...decisionOf(job)};
  }
}

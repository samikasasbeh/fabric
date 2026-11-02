import {randomUUID, createHash} from 'node:crypto';
import {canonicalHash} from './compiler.mjs';
import {credentialValues, secretContext, scrubString, scrubValue} from './redaction.mjs';
import {proxyBase, ProxyRequestError} from './proxy-request.mjs';
import {validateExecutionRequest, hashExecutionRequest, assertDispatchable} from '../contracts/execution.mts';
import {ownedBy, ownershipOf} from './tenant/deployment.mjs';
import {apiRuleOf, apiVerdict, narrowOnMissingScope, providerDetails} from './api-success.mjs';
import {RETENTION, RESPONSE_TTL, bodyTtl, retentionOf, where} from './retention.mjs';
import {paceCheck} from './slack-limits.mjs';
import {noteWrite, spaceWrite} from './write-spacing.mjs';
import {grantHeaderOf, observeGrant, providerOf, takeGrantHeader} from './grant-drift.mjs';

// F08.0c: proxy jobs through the runtime's own acceptance, approval and authority path
// (docs/F08.0-GOVERNED-PROXY.md section 6). A proxy job is an ordinary job with kind "proxy". Its args are the
// agent's request as given. Every check re-decides that request from current settings, and what is sent is the
// final re-decision itself, never a stored copy: the method, URL, headers, body and timeout the owner approved.
// Nothing is retried and nothing is replayed. Designated authority stores only.
export const RESPONSE_LIMIT = 1024 * 1024;
// Response bodies live in their own collection (never inside jobs, which every listing loads), for 7 days, with a
// per-client byte quota. Over the quota the call still records its status and headers; only the body is dropped. F10.21: an app with a
// shorter retention (lib/retention.mjs; Slack, 24 hours) keeps its bodies only that long, and they carry `retention` so a sweep finds them.
export {RESPONSE_TTL};
export const RESPONSE_QUOTA = 50 * 1024 * 1024;
// Bodies are found by key, never by listing the collection, so one holder's kept bodies cannot slow another's calls
// (N1): each holder has one small index document beside its bodies (id, bytes and expiry of each), carrying the same
// owner fields, so a user delete erases it with them. At most RESPONSE_KEPT bodies per holder keep that index small.
export const RESPONSE_KEPT = 10_000;
const INDEX = 'holder:', INDEXED = 'holders-indexed';
// In a developer environment each end user has their own response quota, never a shared one (F03.2, F03.7).
const holder = job => job.userRecordId ? `user:${job.userRecordId}` : job.source?.kind === 'client' ? `client:${job.source.clientId}` : 'owner';
const tenantOf = runtime => runtime.deployment?.kind === 'tenant';

/** Once per store: indexes the bodies kept before holders had an index, so they still count and still expire. */
function indexOnce(store) {
  if (store.get('proxyResponses', INDEXED)) return;
  const indexes = new Map();
  for (const entry of store.list('proxyResponses')) {
    if (typeof entry.holder !== 'string' || entry.id.startsWith(INDEX)) continue;
    const index = indexes.get(entry.holder) ?? {id: `${INDEX}${entry.holder}`, holder: entry.holder, ...(entry.userRecordId ? {ownership: entry.ownership, userRecordId: entry.userRecordId} : {}), entries: []};
    index.entries.push({id: entry.id, bytes: entry.bytes, expiresAt: entry.expiresAt});
    indexes.set(entry.holder, index);
  }
  for (const index of indexes.values()) store.put('proxyResponses', index);
  store.put('proxyResponses', {id: INDEXED});
}
/** Stores one response body under the job, after dropping the holder's expired bodies, unless the holder's quota is full. */
function storeBody(runtime, job, payload) {
  const {store} = runtime, now = runtime.clock(), key = holder(job), id = `${INDEX}${key}`;
  indexOnce(store);
  const index = store.get('proxyResponses', id) ?? {id, holder: key, ...(job.userRecordId ? {ownership: job.ownership, userRecordId: job.userRecordId} : {}), entries: []};
  const before = index.entries.length;
  index.entries = index.entries.filter(entry => { const live = Date.parse(entry.expiresAt) > now; if (!live) store.delete('proxyResponses', entry.id); return live; });
  const bytes = Buffer.byteLength(JSON.stringify(payload));
  const used = index.entries.reduce((sum, entry) => sum + entry.bytes, 0);
  if (used + bytes > (runtime.proxyResponseQuota ?? RESPONSE_QUOTA) || index.entries.length >= (runtime.proxyResponseKept ?? RESPONSE_KEPT)) {
    if (index.entries.length !== before) store.put('proxyResponses', index);
    return 'over_quota';
  }
  const appId = job.proxy?.appId, expiresAt = new Date(now + bodyTtl(appId)).toISOString();
  store.put('proxyResponses', {id: job.id, holder: key, connectionId: job.connectionId, ...(job.userRecordId ? {ownership: job.ownership, userRecordId: job.userRecordId} : {}), ...payload, bytes, createdAt: new Date(now).toISOString(), expiresAt,
    ...(retentionOf(appId) === null ? {} : {retention: appId})});
  index.entries.push({id: job.id, bytes, expiresAt});
  store.put('proxyResponses', index);
  return 'stored';
}
/** F10.21: deletes every body of an app with a shorter retention once it expired, and its entry in its holder's index, so the quota stays
 *  right. The bodies are found by their retention field, never by reading every body (N1). */
export function sweepBodies(store, now) {
  for (const appId of Object.keys(RETENTION)) {
    const gone = new Map();
    for (const entry of where(store, 'proxyResponses', 'retention', appId)) {
      if (Date.parse(entry.expiresAt) > now) continue;
      store.delete('proxyResponses', entry.id);
      gone.set(entry.holder, [...(gone.get(entry.holder) ?? []), entry.id]);
    }
    for (const [key, ids] of gone) {
      const index = store.get('proxyResponses', `${INDEX}${key}`);
      if (index) store.put('proxyResponses', {...index, entries: index.entries.filter(item => !ids.includes(item.id))});
    }
  }
}
/** A proxy job's response body while it is kept: {body} or {text}, or null once expired, dropped or never stored. */
export function proxyResponseBody(runtime, job) {
  if (job?.result?.response?.payload !== 'stored') return null;
  const entry = runtime.store.get('proxyResponses', job.id);
  if (!entry || Date.parse(entry.expiresAt) <= runtime.clock()) return null;
  return Object.hasOwn(entry, 'body') ? {body: entry.body} : {text: entry.text};
}
const MIN_SECRET = 8;
export const RESPONSE_HEADERS = ['content-type', 'etag', 'last-modified', 'link', 'retry-after', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'location'];
const CLIENT_ERRORS = new Set([400, 401, 403, 404, 405, 406, 410, 411, 412, 413, 414, 415, 416, 417, 422, 428, 431]);
const UNCERTAIN_WINDOW = 24 * 60 * 60 * 1000;
const STRICT = {allow: 0, ask: 1, deny: 2};
const MEDIA_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;
const STRICT_UTF8 = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});
const sha256 = value => createHash('sha256').update(value).digest('hex');
const coded = (code, message, extra = {}) => Object.assign(new ProxyRequestError(code, message), extra);
const stricter = (a, b) => STRICT[a] >= STRICT[b] ? a : b;

function designated(runtime) {
  // A developer environment runs the proxy too (F03.7): there, ownership comes from the stored records instead.
  if (!runtime.store.authorityEnabled && !tenantOf(runtime)) throw coded('unsupported_route', 'The governed proxy runs only on a designated authority store.');
}

/** The reviewed provider headers Fabric adds for an app (from its sign-in definition), without the credential. Exported for actions
 *  (F10.11 part g), so a card and a dispatch read the same headers. */
export function providerHeaders(runtime, appId) {
  try {const providers = runtime.connections?.providers, providerId = providers?.providerFor(appId); return providerId ? {...(providers.resolve({providerId, appId}).definition.apiHeaders || {})} : {};}
  catch {return {};}
}
/** F10.21: the sign-in definition the runtime's provider list holds for an app, or null. apiRuleOf() reads the reviewed one first, so this
 *  can only add a rule for an app that has none. */
function providerDefinition(runtime, appId) {
  try {const providers = runtime.connections?.providers, providerId = providers?.providerFor(appId); return providerId ? providers.resolve({providerId, appId}).definition ?? null : null;}
  catch {return null;}
}
/**
 * Every header Fabric adds when sending, as shown for approval: the credential by name only, the reviewed provider
 * headers, Accept when the caller sent none, and Content-Type when there is a body. One function, used both to
 * build the approval and to check the send, by the proxy and by actions alike (F10.11 part g).
 */
export function addedHeaders(request, provider) {
  return [{name: 'Authorization', value: '(added by Fabric, hidden)'}, ...Object.entries(provider).map(([name, value]) => ({name, value: String(value)})),
    ...(request.headers.Accept ? [] : [{name: 'Accept', value: 'application/json'}]), ...(request.body !== null ? [{name: 'Content-Type', value: 'application/json; charset=utf-8'}] : [])];
}

/**
 * c7: the rows of one account with an unresolved uncertain change in the last 24 hours: a proxy job's row, and every write row an action
 * job records (job.action.writeRows, its resolving write included; F10.11 part f), so each counts the other. Typed jobs stay out. Read
 * once per acceptance, so an action with several write rows lists the jobs once.
 */
export function uncertainRows(store, connectionId, now) {
  const rows = new Set();
  for (const job of store.list('jobs')) {
    if (job?.connectionId !== connectionId || job.effect === 'read' || job.status !== 'uncertain' || !(now - Date.parse(job.updatedAt) < UNCERTAIN_WINDOW)) continue;
    if (job.kind === 'proxy' && typeof job.proxy?.row === 'string') rows.add(job.proxy.row);
    if (job.kind === 'action' && Array.isArray(job.action?.writeRows)) for (const row of job.action.writeRows) if (typeof row === 'string') rows.add(row);
  }
  return rows;
}
/** c7 for one row: an unresolved uncertain change to it on the same account in the last 24 hours. Evaluated once, at acceptance. */
export function unresolvedUncertain(store, connectionId, row, now) {
  return uncertainRows(store, connectionId, now).has(row);
}

/** What the synthetic capability reference of a proxy job is bound to: the reviewed settings, the row, the exact request and every added header. */
function reference(decision, config, added) {
  const {request, match} = decision;
  return {appId: decision.appId, id: `proxy:${decision.row}`, version: 1, effect: decision.effect,
    definitionHash: canonicalHash({kind: 'proxy', configHash: config.configHash, row: decision.row, template: match.template, member: match.member ?? null, method: request.method, url: request.url,
      headers: request.headers, added, bodyHash: request.bodyHash, timeoutMs: request.timeoutMs, ...(decision.routedFrom ? {routedFrom: decision.routedFrom} : {})})};
}

/** Accepts one proxy request as a job: decided, previewed, digested and bound to an immutable accepted request. */
export function prepareProxyJob(runtime, data, principal, {title = null, owner = null} = {}) {
  const {store} = runtime, tenant = tenantOf(runtime);
  designated(runtime);
  canonicalHash(data);
  if (!data || typeof data !== 'object' || Object.keys(data).some(key => !['connectionId', 'request', 'timeoutMs', 'source'].includes(key))) throw coded('invalid_request', 'A proxy job is {connectionId, request, timeoutMs?, source?}.');
  const {connectionId, request: input, timeoutMs, source = {kind: 'user'}} = structuredClone(data);
  // In a developer environment a request comes from a developer's key for one end user, and nothing else.
  // In a developer environment: a developer's key, or an agent token (F03.9c), for one end user; nothing else.
  const tenantSource = (source?.kind === 'service' && typeof source.serviceClientId === 'string' && typeof source.keyId === 'string') || (source?.kind === 'client' && typeof source.clientId === 'string' && typeof source.keyId === 'string');
  if (tenant ? !(tenantSource && owner) : !['user', 'client'].includes(source?.kind)) throw coded('invalid_request', 'Proxy requests come from the owner or a granted client only.');
  const first = runtime.proxyPolicy.decide(connectionId, input, {timeoutMs});
  const c7 = unresolvedUncertain(store, connectionId, first.row, runtime.clock());
  const decision = c7 ? runtime.proxyPolicy.decide(connectionId, input, {timeoutMs, unresolvedUncertain: true}) : first;
  // T4: a member Fabric locks is refused as Never whatever access the account has (F10.7: locked rows carry scope data now), as a
  // typed call is (lib/runtime.mjs).
  if (decision.providerAccess === 'missing' && !decision.locked) throw coded('provider_access_missing', decision.reason);
  if (decision.mode === 'deny') throw coded('policy_denied', decision.reason);
  const connection = store.get('connections', connectionId), config = runtime.proxyPolicy.configs.get(connection.appId);
  const added = addedHeaders(decision.request, providerHeaders(runtime, connection.appId)), ref = reference(decision, config, added), id = randomUUID(), now = runtime.now();
  const job = {id, kind: 'proxy', connectionId, capabilityId: ref.id, args: {request: structuredClone(input), timeoutMs: decision.request.timeoutMs}, source, effect: decision.effect,
    capabilityHash: canonicalHash(ref), identityHash: canonicalHash(connection.identity || {}), connectionBindingHash: decision.bindingHash, permissionHash: decision.policyHash, permissionMode: decision.mode,
    status: decision.requiresApproval ? 'awaiting_approval' : 'queued', createdAt: now, updatedAt: now, result: null, error: null,
    proxy: {appId: connection.appId, row: decision.row, rowLabel: decision.rowLabel, template: decision.match.template, member: decision.match.member ?? null, method: decision.request.method,
      url: decision.request.url, headers: decision.request.headers, added, body: decision.request.body, bodyHash: decision.request.bodyHash, bodyBytes: decision.request.bodyBytes,
      timeoutMs: decision.request.timeoutMs, clamps: decision.clamps, duplicateOfUncertain: c7, ...(decision.routedFrom ? {routedFrom: decision.routedFrom} : {})}};
  if (tenant) Object.assign(job, {ownership: {owner: {kind: 'product_user', id: owner.subjectId}}, userRecordId: owner.userRecordId});
  else {
    const actor = runtime.acceptedPrincipal(principal, source);
    job.executionRequest = validateExecutionRequest({schemaVersion: 1, id, scope: actor.scope, principal: actor, access: {kind: 'connection', id: connectionId, generation: decision.connectionGeneration},
      capability: ref, args: job.args, policyRevision: decision.policyRevision, idempotencyKey: source.requestId || id, createdAt: now, deadline: new Date(Date.parse(now) + 10 * 60_000).toISOString()});
    job.executionRequestHash = hashExecutionRequest(job.executionRequest);
  }
  if (title) job.task = {title};
  const warnings = [...(decision.match.kind === 'group' ? [] : ['not_reviewed']), ...(decision.effect === 'delete' ? ['delete'] : []), ...(c7 ? ['duplicate_of_uncertain'] : []),
    ...(decision.audience ? ['reaches_people'] : []), ...(decision.routedFrom ? ['body_routed'] : [])];
  // The owner approves exactly this: Fabric's row label, the full URL, the caller's headers, every header Fabric
  // adds (the credential by name only) and the body bytes as they will be sent.
  job.preview = {application: connection.appId, account: connection.identity || {displayName: connection.label}, operation: decision.rowLabel,
    effect: decision.effect, permissionMode: decision.mode, providerAccess: decision.providerAccess,
    request: {method: decision.request.method, url: decision.request.url, headers: decision.request.headers, ...(decision.request.body !== null ? {body: decision.request.body} : {})},
    addedByFabric: added, match: {kind: decision.match.kind, groupId: decision.match.groupId, template: decision.match.template}, warnings};
  if (decision.effect !== 'read' || decision.requiresApproval) {
    job.approvalExpiresAt = job.executionRequest?.deadline ?? new Date(Date.parse(now) + 10 * 60_000).toISOString();
    job.approvalDigest = runtime.digest(job);
    if (decision.mode === 'allow') {job.approvedAt = now; job.approvedBy = 'standing-policy';}
  }
  proxyAuthority(runtime, job);
  store.put('jobs', job);
  const url = new URL(decision.request.url);
  store.audit({type: 'proxy.request', jobId: id, clientId: source.clientId ?? null, ...(runtime.attribution ? runtime.attribution(job) : {}), connectionId, appId: connection.appId, method: decision.request.method, origin: url.origin, template: decision.match.template,
    pathHash: sha256(url.pathname), queryKeys: [...url.searchParams.keys()], row: decision.row, effect: decision.effect, mode: decision.mode, decision: job.status, bodyHash: decision.request.bodyHash, bodyBytes: decision.request.bodyBytes, duplicateOfUncertain: c7});
  return job;
}

/**
 * Re-decides a proxy job from current settings and requires everything it was accepted under to be unchanged: the
 * row, the effect, every field that will be sent (method, URL, caller headers, added headers, body, timeout), the
 * reference, the account's identity and binding, the policy hash, the accepted request and the dispatch authority.
 * Returns the decision and the mode to enforce (the stricter of the decision and the mode recorded at acceptance).
 * At dispatch the approval is required, never waived.
 */
export function proxyAuthority(runtime, job, {dispatch = false, at} = {}) {
  designated(runtime);
  const tenant = tenantOf(runtime);
  // N3: in a developer environment the stored job's own owner must own the account, before anything is decided.
  if (tenant) {
    let stored;
    try {stored = ownershipOf(job, runtime.deployment);} catch {throw runtime.notFound();}
    if (!ownedBy(runtime.store.get('connections', job.connectionId), stored, runtime.deployment)) throw runtime.notFound();
  }
  const decision = runtime.proxyPolicy.decide(job.connectionId, job.args.request, {timeoutMs: job.args.timeoutMs});
  const connection = runtime.store.get('connections', job.connectionId), config = runtime.proxyPolicy.configs.get(connection.appId);
  const added = addedHeaders(decision.request, providerHeaders(runtime, connection.appId)), ref = reference(decision, config, added), proxy = job.proxy || {};
  const sameSend = decision.request.method === proxy.method && decision.request.url === proxy.url && decision.request.body === proxy.body && decision.request.timeoutMs === proxy.timeoutMs
    && canonicalHash(decision.request.headers) === canonicalHash(proxy.headers ?? null) && canonicalHash(added) === canonicalHash(proxy.added ?? null);
  if (decision.row !== proxy.row || decision.effect !== job.effect || !sameSend || canonicalHash(ref) !== job.capabilityHash) throw coded('authority_changed', 'The request, what would be sent, or the row it lands in changed. Nothing was run; send a new request.');
  if (canonicalHash(connection.identity || {}) !== job.identityHash || decision.bindingHash !== job.connectionBindingHash || decision.policyHash !== job.permissionHash) throw coded('authority_changed', 'The account or its proxy settings changed. Nothing was run; send a new request.');
  if (decision.providerAccess === 'missing' && !decision.locked) throw coded('provider_access_missing', decision.reason);
  if (decision.mode === 'deny') throw coded('policy_denied', decision.reason);
  const mode = stricter(job.permissionMode in STRICT ? job.permissionMode : 'deny', decision.mode);
  if (mode === 'deny') throw coded('policy_denied', 'This request is not permitted.');
  // A developer environment has no accepted-request record or numeric authority; everything above is its check.
  // An agent's call is checked against its token here too (F03.9c), before anything is sent.
  if (tenant) { runtime.authorizeSource(job); return {decision, mode}; }
  const request = validateExecutionRequest(job.executionRequest);
  if (hashExecutionRequest(request) !== job.executionRequestHash || request.id !== job.id || request.access.kind !== 'connection' || request.access.id !== job.connectionId || request.capability.id !== job.capabilityId || canonicalHash(request.args) !== canonicalHash(job.args)) throw coded('authority_changed', 'The immutable accepted request no longer matches this job.');
  runtime.acceptedPrincipal(request.principal, job.source || {});
  if (request.principal.kind === 'local_client' && job.source.requestId !== request.idempotencyKey) throw coded('authority_changed', 'The accepted client request identity changed.');
  runtime.authorizeSource(job);
  const current = {scope: runtime.ownerPrincipal.scope, principal: request.principal, ownerPrincipal: runtime.ownerPrincipal,
    connection: {id: connection.id, generation: decision.connectionGeneration, appId: connection.appId, status: 'active', ownership: {schemaVersion: 1, scope: runtime.ownerPrincipal.scope, owner: {kind: 'local_owner', id: runtime.ownerPrincipal.id}}},
    capability: {reference: ref, status: 'active'}, policy: {revision: decision.policyRevision, decision: mode}};
  // `at` evaluates the request's deadline as of a past moment (when it was sent); settings are always current.
  try {assertDispatchable({request, now: at ?? runtime.now(), current, ...(dispatch && job.executionApproval ? {approval: job.executionApproval} : {})});}
  catch (error) {if (dispatch || error.code !== 'approval_required') throw error;}
  return {decision, mode, request, current};
}

/** proxyAuthority at dispatch, plus the approval it needs: an exact single-action approval for Ask, a standing one for an Allow. */
export function assertProxyAuthorization(runtime, job) {
  const result = proxyAuthority(runtime, job, {dispatch: true});
  if (result.decision.effect !== 'read' || result.mode === 'ask') {
    if (!job.approvedAt || job.approvalDigest !== runtime.digest(job) || Date.parse(job.approvalExpiresAt) <= runtime.clock()) throw coded('approval_expired', 'The exact request has no current approval.');
    if (result.mode === 'ask' && job.approvedBy !== 'single-action') throw coded('approval_required', 'This request needs an exact single-action approval.');
    if (result.mode !== 'ask' && job.approvedBy !== 'standing-policy') throw coded('approval_required', 'The standing setting was not bound to this exact request.');
  }
  return result;
}

/** The outcome of a response that came back, per the outcome table: the job status, the error code and why. F10.21: a 2xx of an app with
 *  apiSuccessRequire is held to it (`verdict`): a refusal changed nothing, read or write, and an answer that says nothing fails a read and
 *  leaves a write uncertain, as any unverified 2xx write. */
function classify(response, effect, verdict = null) {
  const write = effect !== 'read';
  if (verdict?.state === 'refused' || (verdict?.state === 'unknown' && !write)) return {status: 'failed', errorCode: 'provider_failed', reason: 'api_error'};
  if (response.notModified) return write ? {status: 'uncertain', errorCode: 'outcome_uncertain', reason: 'not_modified'} : {status: 'succeeded', errorCode: null, reason: 'not_modified'};
  if (response.redirected) return write ? {status: 'uncertain', errorCode: 'outcome_uncertain', reason: 'redirect_not_followed'} : {status: 'failed', errorCode: 'provider_failed', reason: 'redirect_not_followed'};
  if (response.status >= 200 && response.status < 300) return write ? {status: 'uncertain', errorCode: 'outcome_uncertain', reason: 'not_verified'} : {status: 'succeeded', errorCode: null, reason: null};
  if (CLIENT_ERRORS.has(response.status)) return {status: 'failed', errorCode: 'provider_failed', reason: 'http_status'};
  return write ? {status: 'uncertain', errorCode: 'outcome_uncertain', reason: 'http_status'} : {status: 'failed', errorCode: 'provider_failed', reason: 'http_status'};
}

/** The response as the agent and the owner may see it: allowlisted headers, JSON or text only, credentials removed. */
function readResponse(response, ctx) {
  const headers = {};
  for (const [name, value] of Object.entries(response.headers || {})) headers[name] = scrubString(value, ctx);
  const declared = String(headers['content-type'] || '').split(';')[0].trim().toLowerCase(), contentType = MEDIA_TYPE.test(declared) ? declared : null;
  const base = {status: response.status, headers, contentType};
  if (!Buffer.isBuffer(response.data) || !response.data.length) return {response: {...base, bytes: 0}, readable: true};
  const bytes = response.data.length, json = contentType === 'application/json' || /^application\/[a-z0-9.+-]+\+json$/.test(contentType || ''), text = (contentType || '').startsWith('text/');
  if (!json && !text) return {response: {...base, bytes, sha256: sha256(response.data)}, readable: false};
  let decoded;
  try {decoded = STRICT_UTF8.decode(response.data);} catch {return {response: {...base, bytes, sha256: sha256(response.data)}, readable: false};}
  if (json) {
    // Parse first, then scrub: JSON escapes such as "\/" or "/" are decoded before credentials are looked for.
    try {return {response: {...base, bytes, body: scrubValue(JSON.parse(decoded), ctx)}, readable: true};} catch {}
  }
  return {response: {...base, bytes, text: scrubString(decoded, ctx)}, readable: true};
}

/** Sends one queued proxy job and records what happened. A change that was sent is never reported as done. */
export async function executeProxy(runtime, job) {
  const {store} = runtime, id = job.id, started = runtime.clock();
  runtime.running.add(id);
  const ctx = {values: [], forms: [], count: 0};
  let sent = false, lockKey, httpStatus = null, responseBytes = 0, responseHash = null, effect = job.effect, verdict = null;
  try {
    ({decision: {effect}} = assertProxyAuthorization(runtime, job));
    if (effect !== 'read') {
      lockKey = `account:${job.connectionId}`;
      if (runtime.writeLocks.has(lockKey)) {lockKey = null; throw coded('write_in_progress', 'Another change is in progress for this account. Nothing was sent.', {reason: 'write_in_progress'});}
      runtime.writeLocks.add(lockKey);
    }
    job.status = 'running'; job.updatedAt = runtime.now(); store.put('jobs', job);
    // F10.17: a change waits out its app's gap since the account's last write (lib/write-spacing.mjs) before it is decided again and sent.
    const spacing = {appId: job.proxy.appId, connectionId: job.connectionId};
    if (effect !== 'read') await spaceWrite(runtime, spacing);
    const authority = await runtime.connections.credentials(job.connectionId);
    ({values: ctx.values, forms: ctx.forms} = secretContext(credentialValues(authority.headers)));
    if (!ctx.values.length || ctx.values.some(value => value.length < MIN_SECRET)) throw coded('fabric_failed', 'The account credential is too short to keep out of responses safely. Nothing was sent.');
    const config = runtime.proxyPolicy.configs.get(job.proxy.appId), base = proxyBase(config.apiBase);
    if (!Array.isArray(authority.allowedOrigins) || !authority.allowedOrigins.includes(base.origin)) throw coded('proxy_unavailable', 'This account is not granted the app\'s reviewed API address. Nothing was sent.');
    const current = store.get('connections', job.connectionId);
    if (!current || current.status === 'revoked' || canonicalHash(current.identity || {}) !== job.identityHash) throw coded('authority_changed', 'The account changed before sending. Nothing was sent.');
    // A credential refresh can change the account or its scopes: decide again right before sending, and send that decision.
    const {decision} = assertProxyAuthorization(runtime, job), request = decision.request;
    const {Authorization: credential, Accept: _accept, ...provider} = authority.headers;
    if (canonicalHash(addedHeaders(request, provider)) !== canonicalHash(job.proxy.added)) throw coded('authority_changed', 'The headers Fabric would add differ from the ones approved. Nothing was sent.');
    const headers = {...request.headers, ...provider, ...(credential ? {Authorization: credential} : {}), Accept: request.headers.Accept || 'application/json', ...(request.body !== null ? {'Content-Type': 'application/json; charset=utf-8'} : {})};
    // F10.21: Slack's limit for a distributed app, held before anything is sent (lib/slack-limits.mjs).
    const paced = paceCheck(runtime, current, request);
    if (paced) throw coded(paced.code, paced.words, {reason: paced.reason, ...(paced.retryAfterSeconds === undefined ? {} : {retryAfterSeconds: paced.retryAfterSeconds})});
    // F10.17: a provider whose sign-in names a grant header lists what the token holds in it (lib/grant-drift.mjs); it is asked for here
    // and taken off the answer before anything stores or shows it.
    const providerId = providerOf(runtime, current), grantHeader = grantHeaderOf(providerId);
    let response;
    const sentAt = runtime.now();
    if (effect !== 'read') noteWrite(runtime, spacing);
    try {
      response = await runtime.request({url: request.url, method: request.method, headers, ...(request.body !== null ? {body: request.body} : {}), allowedOrigins: [base.origin],
        timeoutMs: request.timeoutMs, maxBytes: RESPONSE_LIMIT, responseType: 'buffer', redirect: 'report', responseHeaders: grantHeader ? [...RESPONSE_HEADERS, grantHeader] : RESPONSE_HEADERS});
    } catch (error) {
      sent = error?.sent !== false;
      throw coded(sent ? 'outcome_uncertain' : 'fabric_failed', String(error?.message || 'The provider could not be reached.'), {reason: /timed out/i.test(error?.message) ? 'timeout' : /size limit/i.test(error?.message) ? 'response_too_large' : 'connection_failed'});
    }
    sent = true; httpStatus = response.status;
    // F10.17: the grant header is taken off the answer before anything stores or shows it (lib/grant-drift.mjs).
    const taken = takeGrantHeader(response.headers, providerId);
    response = {...response, headers: taken.headers};
    // F10.21: the body is read first, so a 2xx is held to the app's success rule before it counts.
    const read = readResponse(response, ctx), rule = apiRuleOf(job.proxy.appId, providerDefinition(runtime, job.proxy.appId));
    verdict = rule && response.status >= 200 && response.status < 300 && !response.notModified && !response.redirected ? apiVerdict(rule, read.response.body) : null;
    const outcome = classify(response, effect, verdict);
    responseBytes = read.response.bytes; responseHash = Buffer.isBuffer(response.data) ? sha256(response.data) : null;
    // Authority that changed away while the request was in flight withholds the data; the approval's own expiry only
    // had to hold when it was sent.
    const seen = {providerId, value: taken.value, status: response.status, data: read.response.body};
    let inflight = true;
    try {proxyAuthority(runtime, job, {at: sentAt});} catch {inflight = false;}
    // F10.17: after the in-flight check, so the job that saw a narrowing keeps its answer and the next request is decided on the narrowed grant.
    observeGrant(runtime, current, seen);
    if (!inflight) {
      job.result = null; job.status = effect === 'read' ? 'failed' : 'uncertain'; job.errorCode = 'authority_changed'; job.reason = 'authority_changed';
      job.error = effect === 'read' ? 'Authority changed while the request was in flight. The response was withheld.' : 'The change was sent, but authority changed while it was in flight. Its outcome is uncertain and the response was withheld. Do not repeat it blindly.';
      return job;
    }
    let {status, errorCode, reason} = outcome;
    if (!read.readable && status === 'succeeded') {status = 'failed'; errorCode = 'provider_failed'; reason = 'unsupported_response';}
    const {body: parsed, text: plain, ...meta} = read.response;
    const payload = parsed !== undefined ? {body: parsed} : plain !== undefined ? {text: plain} : null;
    job.result = {response: {...meta, redactions: ctx.count, payload: payload ? storeBody(runtime, job, payload) : 'none'}, verification: {kind: 'provider-response', status: status === 'succeeded' ? 'observed' : status === 'uncertain' ? 'unverified' : 'rejected', httpStatus: response.status}};
    job.status = status; job.errorCode = errorCode; job.reason = reason;
    job.error = status === 'succeeded' ? null : status === 'uncertain' ? 'The change was sent, but its effect was not independently verified. Check before trying again; it was not retried.' : `The provider did not complete this request (${reason === 'unsupported_response' ? 'the response was not JSON or text' : `HTTP ${response.status}`}).`;
    if (reason === 'api_error') { job.error = `The provider refused this request (${verdict.error}). Nothing was changed.`; job.details = providerDetails(verdict); }
  } catch (error) {
    job.status = sent && effect !== 'read' ? 'uncertain' : 'failed';
    job.errorCode = error?.code === 'outcome_uncertain' && job.status === 'failed' ? 'provider_failed' : error?.code || (job.status === 'uncertain' ? 'outcome_uncertain' : 'fabric_failed');
    job.reason = error?.reason || null;
    if (error?.retryAfterSeconds !== undefined) job.retryAfterSeconds = error.retryAfterSeconds;
    job.error = scrubString(String(error?.message || 'The request could not be completed.'), ctx).slice(0, 600);
  } finally {
    // A job whose end user was deleted while it ran is not written back: the delete stands (F03.5).
    const gone = tenantOf(runtime) && !store.get('jobs', id);
    if (!gone) {job.updatedAt = runtime.now(); store.put('jobs', job);}
    runtime.running.delete(id);
    if (lockKey) runtime.writeLocks.delete(lockKey);
    if (!gone) store.audit({type: 'proxy.completed', jobId: id, clientId: job.source?.clientId ?? null, ...(runtime.attribution ? runtime.attribution(job) : {}), connectionId: job.connectionId, status: job.status, httpStatus, reason: job.reason ?? null,
      approvedBy: job.approvedBy ?? null, durationMs: runtime.clock() - started, responseBytes, responseHash, redactions: ctx.count});
    // F10.21 part b: only once the job's own record is written, Slack's missing_scope narrows the account.
    if (!gone && job.reason === 'api_error' && verdict?.error === 'missing_scope') narrowOnMissingScope(runtime, job.connectionId, verdict);
  }
  return job;
}

// F03.9's approval relay, pulled forward (decision 3 of October 13, 2026; docs/F03-DEVELOPER-LAYER.md section 5.11 and
// D5): the developer's server reads one end user's waiting approvals and relays a decision made in its own screens.
// Order: the end user, then the call (another user's or an unknown call is not_found, whatever its state), then its
// state, its expiry and the exact digest shown. Deciding needs decisions:write (the route) and is recorded with where
// it was made and which key made it possible. An approved call runs detached, like any execution; a rejected one never
// runs. Agents never decide and never see these routes. F10.11 part n: an action decides one stop at a time (phase reads, then
// phase final); each item says its phase, shows that stop's prepared bytes, and is decided with that stop's own digest.
import {TenantError, notFound, invalid} from './errors.mjs';
import {approvalItem, approvalPage, exactAction} from '../ui-contracts.mjs';
import {ownedBy, ownershipOf, tenantDeployment} from './deployment.mjs';
import {endUserAccountRow, tenantApps} from './views.mjs';
import {developerParty} from './party.mjs';

const CALL_REF = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, DIGEST = /^[0-9a-f]{64}$/;
// F10.3: an approved typed call that can no longer run is refused with its own code; the call then reads as failed.
const REFUSED = {permission_denied: 403, invalid_request: 400, capability_changed: 409, connection_required: 409};

export class TenantApprovals {
  /** @param {{runtimes: any, accounts: any, registry: any, executions: any}} deps */
  constructor(deps) { Object.assign(this, deps); }

  /** True when this stored job belongs to this end user, matched on both owner ids. */
  #owns(env, job, owner) {
    let stored;
    try { stored = ownershipOf(job, tenantDeployment(env.scope)); } catch { return false; }
    return stored.userRecordId === owner.userRecordId && stored.subjectId === owner.subjectId;
  }
  #names(env) {
    const capability = id => env.repository.get('capabilities', id), names = new Map(tenantApps().map(app => [app.id, app.name]));
    return {appName: id => (id && names.get(id)) || id || null, capabilityName: id => capability(id)?.name ?? null, accountName: () => null, clientName: () => null, prepared: preparedReader(env)};
  }
  /** One waiting approval: the exact request, its digest and expiry; a decision path only where this party may decide here. */
  #item(env, job, decidePath) {
    const {approve, cancel: _cancel, account: _account, agent: _agent, ...shown} = approvalItem(job, this.#names(env));
    const path = approve && decidePath ? decidePath(job) : null;
    return {...shown, accountRef: job.connectionId, digest: job.approvalDigest, ...(path ? {decide: {path, body: {decision: 'approve or reject', digest: job.approvalDigest}}} : {})};
  }

  /** GET /v1/users/:ext/approvals: that user's calls waiting for a decision, oldest first. An unknown user has none. */
  list(caller, externalUserId) {
    const env = this.runtimes.bundle(caller.scope).env, user = this.accounts.user(env, externalUserId);
    if (!user) return {approvals: []};
    return this.listFor(env, this.accounts.ownerOf(user), {decidePath: this.relayPath(caller, externalUserId)});
  }
  /** The /v1 decision path, only for a key with the decision power (N12: never a link, and never for agents). */
  relayPath(caller, externalUserId) { return developerParty(caller).canDecide ? job => `/v1/users/${encodeURIComponent(externalUserId)}/approvals/${job.id}/decision` : null; }
  /**
   * One owner's waiting approvals, oldest first. Only that person's records are read (by their index), never every job
   * in the environment; a caller that already read them passes them as jobs.
   */
  listFor(env, owner, {decidePath = null, jobs = null} = {}) {
    const now = Date.parse(this.registry.now());
    const waiting = (jobs ?? env.repository.listWhere('jobs', 'userRecordId', owner.userRecordId)).filter(job => job.status === 'awaiting_approval' && Date.parse(job.approvalExpiresAt) > now && this.#owns(env, job, owner))
      .sort((a, b) => a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : a.id < b.id ? -1 : 1);
    return {approvals: waiting.map(job => this.#item(env, job, decidePath))};
  }
  /**
   * F03.10: one call's approval page for its owner, in one read. While it waits: the exact action, Approve only when all
   * of it can be shown, and Reject always. Expired: what happened, and nothing to press. Settled: the outcome. Another
   * person's call, an unknown one and a malformed one are the same not_found.
   */
  pageFor(env, owner, callRef, {decidePath}) {
    const job = typeof callRef === 'string' && CALL_REF.test(callRef) ? env.repository.get('jobs', callRef) : null;
    if (!job || !this.#owns(env, job, owner)) throw notFound();
    // The person sees which of their own accounts the call acts on, by that account's display name only.
    const accountName = id => { const connection = id ? env.repository.get('connections', id) : null; return connection && ownedBy(connection, owner, tenantDeployment(env.scope)) ? endUserAccountRow(connection).displayName : null; };
    const page = approvalPage(job, {...this.#names(env), accountName, now: Date.parse(this.registry.now())});
    if (page.state === 'expired') { const {cancel: _cancel, ...rest} = page; return rest; }
    if (page.state !== 'pending') return page;
    const {approve, cancel: _cancel, agent: _agent, ...shown} = page.approval, path = decidePath(job);
    return {...page, approval: {...shown, accountRef: job.connectionId, digest: job.approvalDigest,
      approve: approve ? {path, body: {decision: 'approve', digest: job.approvalDigest}} : null, cancel: {path, body: {decision: 'reject', digest: job.approvalDigest}}}};
  }

  /** POST /v1/users/:ext/approvals/:callRef/decision {decision: 'approve' or 'reject', digest} */
  async decide(caller, externalUserId, callRef, body) {
    checkedDecision(body);
    if (!developerParty(caller).canDecide) throw new TenantError(403, 'decision_not_permitted', 'Deciding for an end user needs a key with decisions:write.');
    const env = this.runtimes.bundle(caller.scope).env, user = this.accounts.user(env, externalUserId);
    if (!user) throw notFound();
    const job = this.decideFor(caller.scope, this.accounts.ownerOf(user), callRef, body, developerParty(caller));
    const execution = this.executions.project(caller, env, job);
    return {status: ['succeeded', 'failed', 'uncertain', 'cancelled'].includes(execution.status) ? 200 : 202, body: execution};
  }
  /**
   * One owner's waiting call decided by a party: ownership first, then the stored state, its expiry and the exact
   * digest (T5). Fabric's page approves only an action it could show in full (requireComplete, Q9); Reject always works.
   * Returns the stored job after the decision.
   */
  decideFor(scope, owner, callRef, body, party, {requireComplete = false} = {}) {
    checkedDecision(body);
    if (!party.canDecide) throw new TenantError(403, 'decision_not_permitted', 'Deciding for an end user needs a key with decisions:write.');
    const bundle = this.runtimes.bundle(scope), env = bundle.env;
    const job = typeof callRef === 'string' && CALL_REF.test(callRef) ? env.repository.get('jobs', callRef) : null;
    if (!job || !this.#owns(env, job, owner)) throw notFound();
    if (requireComplete && body.decision === 'approve' && job.status === 'awaiting_approval' && !exactAction(job, {prepared: preparedReader(env)}).complete) throw new TenantError(409, 'exact_action_incomplete', 'This request is too long to show in full here, so it cannot be approved here. You can reject it.');
    const decision = {decision: body.decision === 'approve' ? 'approved' : 'rejected', decidedIn: party.decidedIn, serviceClientId: party.serviceClientId, keyId: party.keyId, ...(party.sessionId ? {sessionId: party.sessionId} : {}), at: this.registry.now()};
    const principal = {kind: 'product_user', ...owner};
    // An app the developer turned off runs nothing, approved or not.
    if (body.decision === 'approve' && this.registry.get('environments', scope.environmentId)?.apps?.[env.repository.get('connections', job.connectionId)?.appId]?.enabled === false) throw new TenantError(422, 'app_disabled', 'This app is turned off in this environment.');
    try {
      const decided = bundle.runtime.decideWaiting(job.id, body.digest, principal, decision);
      if (decided.status === 'queued') this.runtimes.dispatch(scope, decided.id);
    } catch (error) {
      if (error instanceof TenantError) throw error;
      if (error?.code === 'not_found') throw notFound();
      // An approval nobody gave in time is gone (410); the rest are conflicts with what is stored now.
      if (error?.code === 'approval_expired') throw new TenantError(410, error.code, String(error.message).slice(0, 300));
      if (['not_awaiting_approval', 'digest_mismatch', 'authority_changed'].includes(error?.code)) throw new TenantError(409, error.code, String(error.message).slice(0, 300));
      if (Object.hasOwn(REFUSED, error?.code)) throw new TenantError(REFUSED[error.code], error.code, String(error.message).slice(0, 300), error.details);
      throw error;
    }
    return env.repository.get('jobs', job.id);
  }
}

/** F10.11 part n: an action job's prepared bytes, read from its own environment by job id. Every surface that shows an action's card reads
 *  them through this, so an action whose bytes are missing or changed shows no Approve anywhere (lib/ui-contracts.mjs exactAction()). */
export const preparedReader = env => id => env.repository.get('actionPrepared', id);

/** A decision body: approve or reject, with the digest that was shown. */
function checkedDecision(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw invalid('The body must be a JSON object.');
  const unknown = Object.keys(body).find(key => !['decision', 'digest'].includes(key));
  if (unknown) throw invalid(`Unknown field: ${unknown.slice(0, 40)}.`);
  if (!['approve', 'reject'].includes(body.decision)) throw invalid('decision is approve or reject.');
  if (typeof body.digest !== 'string' || !DIGEST.test(body.digest)) throw invalid('Send the digest shown with the approval.');
}

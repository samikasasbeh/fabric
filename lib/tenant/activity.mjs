// F03.9 (docs/F03-DEVELOPER-LAYER.md section 5.11): one end user's activity for the developer's server. Built from that
// user's own records only (matched on both owner ids), with the waiting approvals first and every call grouped by day,
// newest first. Lines are Fabric's own words from recorded state: an uncertain write is never shown as done, and no
// line carries a link, an account identity or provider text. Filters serve a per-app timeline (MUSE-CONNECTORS-UX.md).
import {activityPage} from '../ui-contracts.mjs';
import {ownershipOf, tenantDeployment} from './deployment.mjs';
import {tenantApps} from './views.mjs';
import {invalid} from './errors.mjs';

const ACCOUNT_REF = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class TenantActivity {
  /** @param {{runtimes: any, accounts: any, registry: any, approvals: import('./approvals.mjs').TenantApprovals}} deps */
  constructor(deps) { Object.assign(this, deps); }

  /** GET /v1/users/:ext/activity?appId=&accountRef=&cursor=&limit= */
  list(caller, externalUserId, query = {}) {
    checkedQuery(query);
    const env = this.runtimes.bundle(caller.scope).env, user = this.accounts.user(env, externalUserId);
    if (!user) return {approvals: [], days: []};
    return this.listFor(env, this.accounts.ownerOf(user), query, {decidePath: this.approvals.relayPath(caller, externalUserId)});
  }
  /** One owner's activity (F03.10: also Fabric's hosted page, whose approvals carry no decision path). */
  listFor(env, owner, query = {}, {decidePath = null} = {}) {
    checkedQuery(query);
    const {appId, accountRef, cursor, limit} = query, deployment = tenantDeployment(env.scope), now = Date.parse(this.registry.now());
    const mine = job => { try { const stored = ownershipOf(job, deployment); return stored.userRecordId === owner.userRecordId && stored.subjectId === owner.subjectId; } catch { return false; } };
    const capability = id => env.repository.get('capabilities', id);
    const appOf = job => job.kind === 'proxy' ? job.proxy?.appId ?? null : job.preview?.application ?? capability(job.capabilityId)?.appId ?? null;
    // Only this person's records are read (by their index), never every job in the environment.
    const theirs = env.repository.listWhere('jobs', 'userRecordId', owner.userRecordId).filter(job => job?.id && mine(job));
    const jobs = theirs.filter(job => (appId === undefined || appOf(job) === appId) && (accountRef === undefined || job.connectionId === accountRef))
      // An approval nobody gave in time reads as failed, as in the Execution (decision of October 13, 2026).
      .map(job => job.status === 'awaiting_approval' && Date.parse(job.approvalExpiresAt) <= now ? {...job, status: 'failed'} : job);
    const names = new Map(tenantApps().map(app => [app.id, app.name]));
    let page;
    try { page = activityPage({jobs, appName: id => names.get(id) ?? null, capabilityName: id => capability(id)?.name ?? null, now, cursor, ...(limit !== undefined ? {limit} : {})}); }
    catch { throw invalid('cursor is not one Fabric gave.'); }
    const byId = new Map(jobs.map(job => [job.id, job]));
    const days = page.days.map(day => ({date: day.date, items: day.items.map(item => {
      const job = byId.get(item.callRef);
      return {callRef: item.callRef, kind: job?.kind === 'proxy' ? 'proxy' : 'action', status: item.status, title: item.title, ...(item.taskTitle ? {taskTitle: item.taskTitle} : {}), summary: item.summary,
        appId: job ? appOf(job) : item.appId, accountRef: job?.connectionId ?? null, at: item.at, ...(job?.decision?.decidedIn ? {decidedIn: job.decision.decidedIn} : {})};
    })}));
    // The waiting approvals as the approvals route shows them (a decision path only for a key that may decide), filtered alike.
    const approvals = this.approvals.listFor(env, owner, {decidePath, jobs: theirs}).approvals.filter(item => (appId === undefined || item.appId === appId) && (accountRef === undefined || item.accountRef === accountRef));
    return {approvals, days, ...(page.nextCursor ? {nextCursor: page.nextCursor} : {})};
  }
}

function checkedQuery({appId, accountRef, cursor} = {}) {
  if (appId !== undefined && !tenantApps().some(app => app.id === appId)) throw invalid('appId is not an app Fabric offers.');
  if (accountRef !== undefined && !ACCOUNT_REF.test(accountRef)) throw invalid('accountRef is not an account reference.');
  if (cursor !== undefined && (typeof cursor !== 'string' || !/^[A-Za-z0-9_-]{1,40}$/.test(cursor))) throw invalid('cursor is not one Fabric gave.');
}

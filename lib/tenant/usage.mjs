// F03.7 (D11): append-only usage records per developer environment. Each accepted execution or proxy request, and each
// account connected, is one record whose id comes from what it counts, so a replay can never count twice. Refusals are
// never recorded. Records carry the end user's usr_ id only (never the external id), so they survive a user delete and
// keep the month's history. No prices: what to charge is decided later from these counts (I04).
import {TenantRepositoryError} from '../repositories/tenant.mts';

export const USAGE = 'usageEvents';

export class UsageRecords {
  constructor({registry}) { this.registry = registry; }
  /** Appends one record; an id already recorded (a replay) is left as it is. Returns true when it was new. */
  append(env, {id, kind, userRecordId, serviceClientId = null, keyId = null, appId = null, capabilityId = null}) {
    const at = this.registry.now();
    try {
      env.repository.put(USAGE, {id, kind, at, month: at.slice(0, 7), userRecordId, serviceClientId, keyId, appId, capabilityId});
      return true;
    } catch (error) {
      if (error instanceof TenantRepositoryError && error.code === 'append_only') return false;
      throw error;
    }
  }
  /** One month's counts for the environment: accepted executions, accepted proxy requests, accounts connected, active end users. */
  month(env, month) {
    const rows = env.repository.list(USAGE).filter(row => row.month === month);
    const count = kind => rows.filter(row => row.kind === kind).length;
    return {month, executions: count('execution'), proxyRequests: count('proxy'), accountsConnected: count('account_connected'), activeEndUsers: new Set(rows.map(row => row.userRecordId)).size};
  }
}

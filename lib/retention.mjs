// F10.21 part 1 c (docs/F10.21-BUILD-MAP.md part 1 c; spec line 1220): what Fabric keeps of the data a provider returned, and for how long.
// Owner decision 11 (docs/F10-FIVE-APPS-DEEP.md section 6): until the owner reviews Slack's API Terms, which require minimal retention,
// Slack action results and proxied Slack response bodies are kept 24 hours; after that only the job's status, codes, hashes and audit rows
// remain. Every other app keeps the proxy's 7 days and its action results, as before. Proxied bodies are swept by lib/proxy-runtime.mjs
// (sweepBodies(), beside the holder index it keeps), action results here; lib/runtime.mjs runs both at start, on every job acceptance and
// every minute while a Fabric runs. What a sweep looks for carries a `retention` field naming its app, so it is found through the store's
// index on that field, never by reading every body or every job.
import {canonicalHash} from './compiler.mjs';

/** Decision 11: Slack's 24 hours, until the owner's review of Slack's API Terms. A constant, not a provider field: the rule is Slack's and
 *  temporary (open question 6 of the build map). */
export const RETENTION = Object.freeze({slack: 24 * 60 * 60 * 1000});
/** The proxy's own lifetime of a kept response body (lib/proxy-runtime.mjs re-exports it), for every app without a shorter one. */
export const RESPONSE_TTL = 7 * 24 * 60 * 60 * 1000;
/** An app's shorter retention in milliseconds, or null when it keeps the defaults. */
export const retentionOf = appId => typeof appId === 'string' && Object.hasOwn(RETENTION, appId) ? RETENTION[appId] : null;
/** How long a proxied response body of an app is kept. */
export const bodyTtl = appId => retentionOf(appId) ?? RESPONSE_TTL;
/** The documents of a collection whose top-level field equals value: through the store's index when it has one, else filtered. */
export const where = (store, collection, field, value) => typeof store.listWhere === 'function' ? store.listWhere(collection, field, value)
  : store.list(collection).filter(document => document?.[field] === value);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * Replaces each action result of an app with a shorter retention whose keepUntil has passed by {verification, dataHash, kept: false}: the
 * data goes, its hash stays. The job's status, reason, codes and hashes are untouched, and its `retention` field goes with the data, so a
 * later sweep never reads it again.
 */
export function sweepResults(store, now) {
  for (const appId of Object.keys(RETENTION)) for (const job of where(store, 'jobs', 'retention', appId)) {
    const until = Date.parse(job.result?.keepUntil ?? '');
    if (Number.isFinite(until) && until > now) continue;
    const {retention: _app, ...rest} = job;
    const result = record(job.result) && job.result.data !== undefined ? {verification: job.result.verification ?? null, dataHash: canonicalHash(job.result.data), kept: false} : job.result;
    store.put('jobs', {...rest, result});
  }
}

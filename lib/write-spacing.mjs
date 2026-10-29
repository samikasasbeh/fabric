// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, spec line 1143): writes spaced apart on one account, for the apps whose provider asks it.
// GitHub's REST guidance asks a client that changes things to wait at least one second between those requests, and enforces secondary
// rate limits on writes; the limit is the token's, so the gap holds whatever path sends the write, an action or a raw proxied request
// (open question 10). The account's write lock (lib/actions-runtime.mjs lock(), lib/proxy-runtime.mjs) already sends its writes one at a
// time, so the gap is read and recorded without a race.
//
// - WRITE_SPACING_MS is the reviewed table: an app it does not name is never delayed, and reads are never delayed (callers pass writes only).
// - spaceWrite() runs before the write's last authority checks, so they are decided after the wait; noteWrite() runs as the write leaves,
//   so the next gap is measured from the send itself and two sends are never closer than the gap, however long the checks took.
// - The wait goes through runtime.wait(ms) (a timer by default; tests pass one that moves their fake clock), and the times live in memory
//   per runtime and account: a restart starts the gap again, and takes longer than any gap.

/** The reviewed gap between two writes on one account, in milliseconds, per app. */
export const WRITE_SPACING_MS = Object.freeze({github: 1000});

const LAST = new WeakMap();
const gapOf = appId => typeof appId === 'string' && Object.hasOwn(WRITE_SPACING_MS, appId) ? WRITE_SPACING_MS[appId] : 0;
const timesOf = runtime => { let times = LAST.get(runtime); if (!times) { times = new Map(); LAST.set(runtime, times); } return times; };

/** Records that a write of the account leaves now, for an app the table names. */
export function noteWrite(runtime, {appId, connectionId}) {
  if (gapOf(appId)) timesOf(runtime).set(connectionId, runtime.clock());
}

/**
 * Waits what is left of the app's gap since the account's last write, through runtime.wait(ms), then records this write's time. Returns
 * the milliseconds it waited: 0 for an app the table does not name, a first write, or a gap already passed.
 */
export async function spaceWrite(runtime, {appId, connectionId}) {
  const gap = gapOf(appId);
  if (!gap) return 0;
  const last = timesOf(runtime).get(connectionId), left = last === undefined ? 0 : last + gap - runtime.clock();
  if (left > 0) await runtime.wait(left);
  noteWrite(runtime, {appId, connectionId});
  return Math.max(0, left);
}

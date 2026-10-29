import {createHash} from 'node:crypto';
import {stampOwner} from './tenant/deployment.mjs';

// F10.4: connection notices, activity events of type connection.health that say an account needs attention before it
// stops working. There is one per connection, sign-in, kind and subject (an organization, or the set of scopes a grant
// lost), so seeing the same condition again only counts it, and a renewal (a new sign-in) can raise its own. A notice
// holds no tokens, no provider text and no scope names. It is written by its own id, never through audit(), whose ids
// are random and whose arrays are cut. org_restricted (F10.17) names the organization that refused, in its subject org:<name>.
export const NOTICE_KINDS = Object.freeze(['reconnect_required', 'grant_narrowed', 'org_restricted', 'consent_expiring']);
// F10.5: notices derived from the account itself and never stored, so raise() refuses them. not_granted is what the current
// sign-in asked for and did not get, while the account still lacks it: per sign-in by construction, with nothing to erase.
export const DERIVED_KINDS = Object.freeze(['not_granted']);
const TYPE = 'connection.health', DAY = 24 * 3600 * 1000;
const SUBJECT = /^(|org:[A-Za-z0-9._:-]{1,200}|scopes:[0-9a-f]{64})$/;
const ORGANIZATION = /^org:([A-Za-z0-9._:-]{1,200})$/;
// The words never say "disconnect": signing in again is a renewal, which keeps every setting.
export const NOTICE_WORDS = Object.freeze({
  reconnect_required: 'Reconnect this account to use it: sign in again. Your settings stay as they are.',
  grant_narrowed: 'The provider now gives this account less access, so some permissions need more access. Sign in again to restore it.',
  org_restricted: 'An organization limits what this account can reach. Ask its admin to approve this app.',
  consent_expiring: 'This sign-in ends soon. Sign in again before then to keep using this account. Your settings stay as they are.',
  not_granted: 'Some permissions were not granted at sign-in. The permissions that need them can add them.',
});
const sha = value => createHash('sha256').update(value).digest('hex');
/** A notice belongs to one sign-in: the record's sign-in revision, or its authorization when it has none (a pasted token). */
const noticeId = (connection, kind, subjectKey) => sha(JSON.stringify([TYPE, connection.id, connection.signInRevision ?? connection.authRevision ?? null, kind, subjectKey]));
/** The subject of a grant_narrowed notice: which scopes were lost, as a digest, never by name. */
export const scopesSubject = scopes => `scopes:${sha(JSON.stringify([...new Set(scopes)].sort()))}`;
/** The scopes `before` held that `after` lacks, when `after` is a strict subset of `before`; otherwise none. */
export function narrowedBy(before, after) {
  if (!Array.isArray(before) || !Array.isArray(after) || after.some(scope => !before.includes(scope))) return [];
  return [...new Set(before.filter(scope => !after.includes(scope)))];
}

/** Raises one notice, or counts it again. Synchronous from read to write, so two callers never make two. */
export function raise(store, {connection, kind, subjectKey = '', now = Date.now()}) {
  if (!connection?.id || !NOTICE_KINDS.includes(kind) || typeof subjectKey !== 'string' || !SUBJECT.test(subjectKey)) throw new Error('Unknown connection notice.');
  const id = noticeId(connection, kind, subjectKey), at = new Date(now).toISOString(), existing = store.get('activity', id);
  const notice = {id, type: TYPE, kind, connectionId: connection.id, appId: connection.appId, signInRevision: connection.signInRevision ?? null, subjectKey, count: (existing?.count ?? 0) + 1, createdAt: existing?.createdAt ?? at, updatedAt: at};
  // In a developer environment the notice belongs to the account's own end user.
  const owner = connection.ownership?.owner?.kind === 'product_user' ? {subjectId: connection.ownership.owner.id, userRecordId: connection.userRecordId} : null;
  return store.put('activity', owner ? stampOwner(notice, owner) : notice);
}

/** The notices of the account's current sign-in, most urgent first. A reconnect notice lasts only while the account needs it. The
 *  not-granted notice comes last: an account that works without some optional access is the least urgent (F10.5). */
export function current(store, connection) {
  if (!connection?.id || ['revoked', 'pending_confirmation'].includes(connection.status)) return [];
  const events = typeof store.listWhere === 'function' ? store.listWhere('activity', 'connectionId', connection.id) : store.list('activity');
  const stored = events.filter(event => event?.type === TYPE && event.connectionId === connection.id && NOTICE_KINDS.includes(event.kind) && event.id === noticeId(connection, event.kind, event.subjectKey ?? '')
    && (event.kind !== 'reconnect_required' || connection.status === 'reconnect_required')).sort((a, b) => NOTICE_KINDS.indexOf(a.kind) - NOTICE_KINDS.indexOf(b.kind));
  const held = Array.isArray(connection.scopes) ? connection.scopes : [], missing = Array.isArray(connection.grant?.missing) ? connection.grant.missing : [];
  const still = [...new Set(missing.filter(scope => typeof scope === 'string' && !held.includes(scope)))].sort();
  return still.length ? [...stored, {id: noticeId(connection, 'not_granted', scopesSubject(still)), type: TYPE, kind: 'not_granted', connectionId: connection.id, appId: connection.appId,
    signInRevision: connection.signInRevision ?? null, count: still.length, createdAt: connection.signedInAt ?? connection.createdAt ?? null}] : stored;
}

/** A notice as people see it: its kind, the account, fixed words and since when. A derived notice also says how many, and on the
 *  selected account carries its own words and a copy of the rows that need it (F10.5). An org_restricted notice names its organization,
 *  from its subject, so the app page lists each organization that refused (F10.17). */
export const shownNotice = notice => ({kind: notice.kind, accountRef: notice.connectionId, message: NOTICE_WORDS[notice.kind], since: notice.createdAt,
  ...(notice.kind === 'org_restricted' && ORGANIZATION.test(notice.subjectKey ?? '') ? {organization: ORGANIZATION.exec(notice.subjectKey)[1]} : {}),
  ...(DERIVED_KINDS.includes(notice.kind) ? {count: notice.count, ...(typeof notice.message === 'string' ? {message: notice.message} : {}),
    ...(Array.isArray(notice.rows) ? {rows: notice.rows.map(row => ({groupId: row.groupId, label: row.label}))} : {})} : {})});

/** True from one day before a sign-in's consent ends (Google's Testing mode). Records from before sign-in revisions use createdAt. */
export function consentDue(record, {consentDays, now = Date.now()} = {}) {
  if (!Number.isSafeInteger(consentDays) || consentDays < 1) return false;
  const since = Date.parse(record?.signedInAt ?? record?.createdAt);
  return Number.isFinite(since) && since + (consentDays - 1) * DAY <= now;
}

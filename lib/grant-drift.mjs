// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, spec lines 1144-1147, B7): grant drift. A provider whose reviewed sign-in names a grant
// header (contracts/auth-definition.mts grantHeader: GitHub's x-oauth-scopes) lists in it, on every answer, what the token holds now. A
// person can take a scope back on GitHub after consent, and Fabric would otherwise go on deciding on the scopes it recorded at sign-in.
//
// - grantHeaderOf() names the header only for such a provider; the action runtime and the proxy ask the network seam for it beside their own
//   response headers, and takeGrantHeader() takes it off the answer before anything stores, scrubs or shows it, so no job, step answer,
//   card, output, audit row or evidence ever holds it.
// - observeGrant() reads it only for the sign-in that sent the request. Read with the definition's implications (effectiveScopes(), so a
//   listed admin:org covers a recorded read:org), a recorded scope the header no longer covers is lost: the record's scopes lose it, as a
//   narrowing refresh writes them (lib/providers/oauth2.mjs), and raise() gives one grant_narrowed keyed by the scopes lost, never naming
//   them. The same set seen again finds nothing more to lose and changes nothing. The header never adds a scope (T7), and a header that is
//   absent or is not a scope list changes nothing. The callers observe after the answer's own authority check, so the job that saw a
//   narrowing keeps its answer, and the next request is decided on the narrowed grant (open question 16).
// - For GitHub only, a 403 whose message is GitHub's documented refusal for an organization's OAuth App access restriction raises
//   org_restricted with subject org:<name>, the name checked as a GitHub owner name. Any other 403 changes nothing. A restriction narrows
//   nothing: it is shown, never worked around.
// A grant header suits an OAuth app, whose tokens carry scopes. A provider app whose tokens carry none (a GitHub App's user tokens send an
// empty header) must not name one: its sign-in would read as holding nothing.
import {definitionFor} from './providers/definitions.mjs';
import {effectiveScopes, normalizeAuthApp} from '../contracts/auth-definition.mts';
import {raise, scopesSubject} from './connection-notices.mjs';

const SCOPE = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$/;
const OWNER_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
/** Each provider's documented words when an organization restricts OAuth App access, the organization's name in the first group. */
const RESTRICTIONS = Object.freeze({
  github: /^Although you appear to have the correct authorization credentials, the `([^`\n]{1,100})` organization has enabled OAuth App access restrictions, meaning that data access to third-parties is limited\./,
});

/** The grant header a provider's reviewed sign-in names, in lower case as the network seam names response headers; null for any other. */
export function grantHeaderOf(providerId) {
  if (typeof providerId !== 'string') return null;
  try { return definitionFor(providerId).grantHeader ?? null; } catch { return null; }
}

/** The provider of an account: its record's own, else the one the trusted registry holds for its app. */
export function providerOf(runtime, connection) {
  if (typeof connection?.providerId === 'string') return connection.providerId;
  try { return runtime?.connections?.providers?.providerFor?.(connection?.appId) ?? null; } catch { return null; }
}

/** An answer's headers without the provider's grant header, and the header's value (null when it has none). Nothing else changes. */
export function takeGrantHeader(headers, providerId) {
  const name = grantHeaderOf(providerId), rest = {...(headers ?? {})};
  if (!name || !Object.hasOwn(rest, name)) return {value: null, headers: rest};
  const value = rest[name];
  delete rest[name];
  return {value: typeof value === 'string' ? value : null, headers: rest};
}

/** Narrows the record to what the header covers; {lost} when it lost a scope, else null. */
function narrow(runtime, record, app, value) {
  const listed = value.trim() === '' ? [] : value.split(',').map(item => item.trim());
  if (listed.some(scope => !SCOPE.test(scope)) || !Array.isArray(record.scopes) || record.scopes.some(scope => typeof scope !== 'string')) return null;
  const covered = new Set(effectiveScopes(app, listed));
  const kept = record.scopes.filter(scope => covered.has(scope)), lost = [...new Set(record.scopes.filter(scope => !covered.has(scope)))];
  if (!lost.length) return null;
  const now = runtime.clock(), next = {...record, scopes: kept, updatedAt: new Date(now).toISOString()};
  runtime.store.put('connections', next);
  raise(runtime.store, {connection: next, kind: 'grant_narrowed', subjectKey: scopesSubject(lost), now});
  return {lost};
}

/** Raises org_restricted for the provider's documented organization refusal; {organization} when it did, else null. */
function restriction(runtime, record, providerId, data) {
  const rule = Object.hasOwn(RESTRICTIONS, providerId) ? RESTRICTIONS[providerId] : null;
  const message = data !== null && typeof data === 'object' && !Array.isArray(data) && typeof data.message === 'string' ? data.message : null;
  const match = rule && message !== null ? rule.exec(message) : null;
  if (!match || !OWNER_NAME.test(match[1])) return null;
  raise(runtime.store, {connection: record, kind: 'org_restricted', subjectKey: `org:${match[1]}`, now: runtime.clock()});
  return {organization: match[1]};
}

/**
 * What one answer says about the account's grant. `connection` is the record the request was sent under; the header counts only while
 * the account is still that sign-in. `value` is the grant header's value (null when absent), `status` and `data` the answer's. Returns
 * {lost?, organization?} for what changed, or null when nothing did.
 */
export function observeGrant(runtime, connection, {providerId, value = null, status = null, data = null} = {}) {
  if (!grantHeaderOf(providerId) || typeof connection?.id !== 'string') return null;
  const record = runtime.store.get('connections', connection.id);
  if (!record || record.status === 'revoked' || record.appId !== connection.appId || record.authRevision !== connection.authRevision
    || (record.signInRevision ?? null) !== (connection.signInRevision ?? null)) return null;
  const definition = definitionFor(providerId), entry = definition.apps.find(app => app.appId === record.appId);
  if (!entry) return null;
  const narrowed = typeof value === 'string' ? narrow(runtime, record, normalizeAuthApp(definition, entry), value) : null;
  const restricted = status === 403 ? restriction(runtime, runtime.store.get('connections', record.id), providerId, data) : null;
  return narrowed || restricted ? {...narrowed, ...restricted} : null;
}

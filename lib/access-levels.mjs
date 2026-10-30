// Access levels a sign-in offers and the level an account holds (F10.2), from one normalized auth app entry
// (contracts/auth-definition.mts normalizeAuthApp). Version 1 entries keep their read and read_write vocabulary, so no
// screen claims "Full access" before an app's definition really asks for it; version 2 entries say full, partial, read
// or pages. A page grant (Notion) is never called full access, whatever it holds.
import {fullLevelScopes, effectiveScopes} from '../contracts/auth-definition.mts';

const key = scopes => [...new Set(scopes)].sort().join(' ');

/** The levels a sign-in can offer for this app. */
export function offeredLevels(access) {
  if (!access) return [];
  if (access.schemaVersion === 2) return access.grant === 'pages' ? ['pages'] : ['full', ...(access.levels.read ? ['read'] : [])];
  const read = key(access.levels.read?.required || []), full = key(access.levels.full.required);
  return [...(read ? ['read'] : []), ...(full && full !== read ? ['read_write'] : [])];
}

/** F10.7 (g5): for one release, a developer's `read_write` names full access on an app whose sign-in offers full (version 2). Every
 *  other level, and every level of a version 1 app, is read as given, so `read` is still refused where no read level exists. */
export function requestedLevel(level, offered) {
  return level === 'read_write' && offered.includes('full') ? 'full' : level;
}

/** The address a provider may answer an OpenID Connect sign-in scope under. */
const IDENTITY_ALIASES = Object.freeze({email: 'https://www.googleapis.com/auth/userinfo.email', profile: 'https://www.googleapis.com/auth/userinfo.profile'});

/** The level an account holds, from its granted scopes: a string, or {level: 'partial', notGranted} for version 2. A scope a
 *  granted parent grants is held (F10.5), so GitHub's admin:org holds read:org. */
export function heldLevel(access, grantedScopes) {
  if (!access) return 'custom';
  const raw = Array.isArray(grantedScopes) ? grantedScopes : [], granted = new Set(effectiveScopes(access, raw)), all = scopes => scopes.length > 0 && scopes.every(scope => granted.has(scope));
  if (access.schemaVersion === 2) {
    if (access.grant === 'pages') return 'pages';
    if (!fullLevelScopes(access).length) return 'custom';
    const {required, optional} = access.levels.full;
    if (required.every(scope => granted.has(scope)) && (required.length || optional.some(scope => granted.has(scope)))) {
      const notGranted = optional.filter(scope => !granted.has(scope)).length;
      return notGranted ? {level: 'partial', notGranted} : 'full';
    }
    // Read-only only when that is all the account was granted: any other app scope makes it custom, never "Read-only".
    const readScopes = access.levels.read ? [...access.levels.read.required, ...access.levels.read.optional] : [];
    // A provider may answer a sign-in scope under another name: Google grants `email` as its userinfo.email address.
    const identity = (access.identityScopes || []).flatMap(scope => [scope, IDENTITY_ALIASES[scope]]);
    const onlyRead = raw.every(scope => readScopes.includes(scope) || identity.includes(scope));
    return access.levels.read && all(access.levels.read.required) && onlyRead ? 'read' : 'custom';
  }
  return offeredLevels(access).includes('read_write') && all(access.levels.full.required) ? 'read_write' : all(access.levels.read?.required || []) ? 'read' : 'custom';
}

const LABELS = {full: 'Full access', read_write: 'Read and write', read: 'Read-only', pages: 'Pages you shared', custom: 'Custom'};

/** The account row's words for a held level. F10.19: a page grant with its account note (lib/connection-notes.mjs) says how many pages
 *  an agent's last full Search saw, "Pages you shared (12)", or "(100+)" when Notion had more. */
export function levelLabel(held) {
  if (held && typeof held === 'object' && held.level === 'partial') return `Partial access (${held.notGranted} permission${held.notGranted === 1 ? '' : 's'} not granted)`;
  if (held && typeof held === 'object' && held.level === 'pages') {
    return Number.isSafeInteger(held.pages) && held.pages >= 0 && typeof held.more === 'boolean' ? `${LABELS.pages} (${held.pages}${held.more ? '+' : ''})` : LABELS.pages;
  }
  return LABELS[held] || LABELS.custom;
}

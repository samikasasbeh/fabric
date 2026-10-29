// F03.4a (docs/F03-DEVELOPER-LAYER.md section 5.6): Connect sessions. A developer's server asks for a short-lived
// link for one end user. Fabric creates the end user on first sight, stores the session in the environment (owned by
// that user), and a route in the registry so the link finds its environment without opening any other. The link's
// secret travels only in the URL fragment; Fabric keeps its SHA-256. Opening the link claims the session once, for one
// browser, with a fixed order of checks: a wrong secret is always not_found, before expiry or "in use".
import {createHash, randomBytes, randomUUID, timingSafeEqual} from 'node:crypto';
import {newId} from './registry.mjs';
import {stampOwner, endUser, ownershipOf, tenantDeployment, ownedBy} from './deployment.mjs';
import {signInOf, consentSheet} from './views.mjs';
import {offeredLevels, heldLevel, levelLabel, requestedLevel} from '../access-levels.mjs';
import {SHARED_GOOGLE_IDENTITY_BUDGET} from './provider-apps.mjs';
import {appService} from './app-pages.mjs';
import {LOCK_WORDS} from '../row-locks.mjs';
import {UNAVAILABLE_REASONS} from '../permission-groups.mjs';
import {raise, narrowedBy, scopesSubject} from '../connection-notices.mjs';
import {operationScopes} from '../continuations.mjs';
import {logoUrl} from './logos.mjs';
import {brandCss} from './brand.mjs';

const SUBJECT = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const FABRIC_PARAMS = ['fabric_session', 'fabric_state', 'fabric_app', 'fabric_account', 'error', 'error_description'];
const FINISHED = new Set(['connected', 'failed', 'expired', 'cancelled', 'completed']);
/** H8: a claimed link with no page activity for this long ends. */
export const IDLE_LIMIT_MS = 15 * 60 * 1000;
/** F03.10: manage and approve links last at most 10 minutes, so they end after 5 idle minutes. */
export const PAGE_IDLE_LIMIT_MS = 5 * 60 * 1000;
/** Links to Fabric's hosted manage and approval pages (F03.10): never a sign-in, never a new user. */
const PAGE_PURPOSES = new Set(['manage', 'approve']);
/** The scope that may mint, or mint again, a session of each purpose (section 5.6). */
const SCOPE_OF = Object.freeze({connect: 'connect:write', handoff: 'connect:write', reconnect: 'connect:write', add_access: 'connect:manage', manage: 'connect:manage', approve: 'connect:approve'});
/** F10.4: links that sign in again an account the person already holds. They never create a person or a second account. */
const ACCOUNT_PURPOSES = new Set(['reconnect', 'add_access']);
const CALL_REF = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Section 6.2 step 8: an account not confirmed within this long after the callback is erased (N9 decides any revoke). */
export const CONFIRM_LIMIT_MS = 10 * 60 * 1000;
/** One link starts at most this many sign-ins; each new one ends the one before it. */
export const START_LIMIT = 20;
/** A link's or sign-in's registry route stays this long past its end, so an open page can still say how it ended. */
export const ROUTE_GRACE_MS = 60 * 60 * 1000;
// A hint names a person: visible text only, without controls, format characters, line separators or markup.
const HINT = /^[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}<>]{1,80}$/u;
/** Fixed words for the developer's error redirect (section 6.6); never provider text. */
const FAILURE_WORDS = {consent_denied: 'The person declined access at the provider.', cancelled: 'The Connect link was cancelled.', expired: 'The Connect link expired.',
  user_cap_reached: 'This environment has reached its limit of Google accounts on Fabric\'s shared sign-in.', insufficient_scope: 'The provider did not grant the access that was asked for.',
  never_requested: 'The provider granted a permission Fabric never holds, so nothing was connected.',
  provider_app_disabled: 'This sign-in app\'s client id is registered in another environment, so nothing was connected.',
  setup_required: 'This sign-in app is not set up in this environment, so nothing was connected.',
  identity_mismatch: 'The person signed in with a different account than the one this link is for, so nothing changed.',
  account_changed: 'The account this link is for was disconnected or changed while the person was signing in, so nothing changed.'};
const failureWords = code => FAILURE_WORDS[code] ?? 'The connection could not be completed.';
/** T7: what confirming the upgrade card means, in the words the owner's start route uses. */
const cardWords = rows => rows.length ? `After this sign-in, agents could do these without asking: ${rows.map(row => row.label).join(', ').slice(0, 300)}. Confirm to continue.`
  : 'This sign-in adds access to the account. Permissions you set to Allow will ask again; Never stays Never. Confirm to continue.';
/**
 * F10.4, F10.7 (g3, correction 12): the level a reconnect link signs an account in again at, from the level it holds or the link names.
 * Read stays read. A custom account signs in at read on a version 1 app that has a read level, as before (T6), and at full on a
 * version 2 app, with the upgrade card; an account that holds only read-level scopes already reads as read there.
 */
export function reconnectLevel(access, level) {
  return level === 'read' || (level === 'custom' && access?.schemaVersion !== 2 && access?.levels?.read) ? 'read' : 'full';
}
/** The developer's return address with Fabric's result appended; the developer's own parameters stay untouched. */
function withResult(uri, params) {
  // Appended to the stored address as it is: re-serialising the query would re-encode the developer's own parameters
  // (a%20b would become a+b) and break anything signed over them. checkedRedirect() refuses fragments and Fabric's names.
  const joiner = uri.includes('?') ? (/[?&]$/.test(uri) ? '' : '&') : '?';
  return `${uri}${joiner}${new URLSearchParams(params)}`;
}
const sha256 = value => createHash('sha256').update(value).digest('hex');
const DUMMY = sha256('no-such-session');

export class SessionError extends Error {
  constructor(status, code, message, details) { super(message); this.status = status; this.code = code; if (details) this.details = details; }
}
const notFound = () => new SessionError(404, 'not_found', 'Nothing with that id exists here.');

/** The environment's end user for an external id, created on first sight. */
export function endUserFor(repository, subjectId, now) {
  if (typeof subjectId !== 'string' || !SUBJECT.test(subjectId)) throw new SessionError(400, 'invalid_external_user_id', 'externalUserId must be 1 to 128 characters: letters, digits and . _ : @ -');
  const existing = repository.list('endUsers').find(user => user.subjectId === subjectId && user.status === 'active');
  if (existing) return existing;
  const user = {id: newId('user'), subjectId, status: 'active', createdAt: now};
  repository.put('endUsers', user);
  repository.audit({type: 'tenant.user_created', userRecordId: user.id});
  return user;
}

/** An exact allowed origin for a return address; refuses redirects already carrying Fabric's parameter names. */
export function checkedRedirect(value, environment) {
  let url;
  try { url = new URL(value); } catch { throw new SessionError(400, 'redirect_not_allowed', 'Redirects must be absolute URLs.'); }
  if (url.username || url.password || url.hash || !environment.redirectOrigins.includes(url.origin)) throw new SessionError(400, 'redirect_not_allowed', 'That redirect is not one of this environment\'s redirect origins.');
  if (FABRIC_PARAMS.some(name => url.searchParams.has(name))) throw new SessionError(400, 'redirect_not_allowed', 'A redirect cannot already carry Fabric\'s parameter names.');
  return url.href;
}

/** An exact origin from the environment's opener origins, for the popup message (section 6.6), or 400. */
function checkedOpener(value, environment) {
  let url;
  try { url = new URL(value); } catch { url = null; }
  if (typeof value !== 'string' || !url || url.origin !== value || !(environment.openerOrigins || []).includes(value)) throw new SessionError(400, 'opener_not_allowed', 'That opener is not one of this environment\'s opener origins.');
  return value;
}

/** The provider app that issued an account: the developer's own, or Fabric's shared one. */
const appOf = record => record?.providerApp?.kind === 'developer' && typeof record.providerApp.id === 'string' ? {kind: 'developer', id: record.providerApp.id} : {kind: 'shared'};
const sameApp = (a, b) => a.kind === b.kind && (a.kind === 'shared' || a.id === b.id);
/** An account the person holds, whatever its health (reconnect_required included): not revoked, not still waiting. */
const present = record => !['revoked', 'pending_confirmation'].includes(record?.status);

export class ConnectSessions {
  /** @param {{registry: any, stores: any, providerApps: any, origin: string, appSetting: Function, tenantApps: Function}} deps */
  constructor(deps) { Object.assign(this, deps); this.revocations = new Set(); this.settling = new Set(); }
  /** Revocations still in flight (tests and shutdown wait for them). */
  settled() { return Promise.allSettled([...this.revocations]); }
  #now() { return Date.parse(this.registry.now()); }
  #iso(ms) { return new Date(ms).toISOString(); }
  #secret() { return randomBytes(32).toString('base64url'); }
  #url(id, secret) { return `${this.origin}/connect/${id}#k=${secret}`; }

  /**
   * POST /v1/connect-sessions: purpose connect or reconnect (needs connect:write), add_access, a decision, or manage
   * (connect:manage), or approve (connect:approve). Handoff sessions are made only by Fabric (F03.9d).
   */
  create(caller, body) {
    const allowed = ['externalUserId', 'purpose', 'appId', 'accountRef', 'groupId', 'level', 'callRef', 'delivery', 'userHint', 'presentation', 'consentEtag', 'successRedirectUri', 'errorRedirectUri', 'openerOrigin', 'expiresInSeconds'];
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new SessionError(400, 'invalid_request', 'The body must be a JSON object.');
    const unknown = Object.keys(body).find(key => !allowed.includes(key));
    if (unknown) throw new SessionError(400, 'invalid_request', `Unknown or not yet available field: ${unknown.slice(0, 40)}.`);
    const purpose = body.purpose ?? 'connect', account = ACCOUNT_PURPOSES.has(purpose);
    if (purpose === 'handoff') throw new SessionError(422, 'not_available', 'Fabric makes handoff sessions itself when a call needs an account.');
    if (!['connect', 'reconnect', 'add_access', 'manage', 'approve'].includes(purpose)) throw new SessionError(400, 'invalid_request', 'purpose is connect, reconnect, add_access, manage or approve.');
    // Each purpose is its own power: a key that can connect accounts cannot open the manage or approval pages (H5), nor add access.
    if (!caller.scopes.includes(SCOPE_OF[purpose])) throw new SessionError(403, 'forbidden_scope', `This key lacks the ${SCOPE_OF[purpose]} scope.`);
    // F10.4: a reconnect names the person's account, an Add access its account and permission row; only a reconnect picks a level.
    for (const [field, fits] of [['accountRef', account], ['groupId', purpose === 'add_access'], ['level', purpose === 'reconnect']]) if (body[field] !== undefined && !fits) throw new SessionError(400, 'invalid_request', `${field} does not go with ${purpose} sessions.`);
    if (account && (body.accountRef === undefined || (purpose === 'add_access' && body.groupId === undefined))) throw new SessionError(400, 'invalid_request', purpose === 'add_access' ? 'An add_access session names the account (accountRef) and the permission row (groupId).' : 'A reconnect session names the account: accountRef.');
    if (PAGE_PURPOSES.has(purpose)) return this.#createPage(caller, body, purpose);
    if (body.callRef !== undefined) throw new SessionError(400, 'invalid_request', 'callRef goes with approve sessions only.');
    const delivery = body.delivery ?? 'redirect';
    if (!['redirect', 'message'].includes(delivery)) throw new SessionError(400, 'invalid_request', 'delivery is redirect or message.');
    // H8: a link sent by message names who it is for, shows that on the sheet, and always ends at the confirm screen.
    const userHint = typeof body.userHint === 'string' ? body.userHint.trim() : body.userHint;
    if (userHint !== undefined && (typeof userHint !== 'string' || !HINT.test(userHint) || !/[\p{L}\p{N}]/u.test(userHint))) throw new SessionError(400, 'invalid_request', 'userHint is 1 to 80 characters of plain text that names someone.');
    if (delivery === 'message' && userHint === undefined) throw new SessionError(400, 'invalid_request', 'A link sent by message needs a userHint naming who it is for.');
    const presentation = body.presentation ?? 'sheet';
    if (!['sheet', 'direct'].includes(presentation)) throw new SessionError(400, 'invalid_request', 'presentation is sheet or direct.');
    if (body.consentEtag !== undefined && presentation !== 'direct') throw new SessionError(400, 'invalid_request', 'consentEtag goes with direct presentation only.');
    const seconds = body.expiresInSeconds ?? 1800, longest = delivery === 'message' ? 4 * 3600 : 3600;
    if (!Number.isSafeInteger(seconds) || seconds < 60 || seconds > longest) throw new SessionError(400, 'invalid_request', `expiresInSeconds must be 60 to ${longest}.`);
    const environment = this.registry.get('environments', caller.scope.environmentId), handle = this.stores.open(caller.scope);
    let held = null, known = null, level = body.level;
    if (account) {
      // The person and the account exist already. Another person's account, an unknown one and a malformed one are the same
      // not_found, and nothing is written before every check has passed (N2).
      if (typeof body.externalUserId !== 'string' || !SUBJECT.test(body.externalUserId)) throw new SessionError(400, 'invalid_external_user_id', 'externalUserId must be 1 to 128 characters: letters, digits and . _ : @ -');
      known = handle.repository.list('endUsers').find(user => user.subjectId === body.externalUserId && user.status === 'active');
      if (!known) throw notFound();
      held = this.#accountOf(handle, {subjectId: known.subjectId, userRecordId: known.id}, body.accountRef);
      if (body.appId !== undefined && body.appId !== held.appId) throw new SessionError(400, 'invalid_request', 'This account belongs to another app.');
      // F10.7 (g5): for one release a developer's read_write names full access on a version 2 app.
      const offered = offeredLevels(signInOf(held.appId).access);
      level = body.level === undefined ? undefined : requestedLevel(body.level, offered);
      if (level !== undefined && !offered.includes(level)) throw new SessionError(400, 'invalid_request', 'That access level is not offered for this app.');
      // An upgrade never skips Fabric's page, which shows the rows it turns on (T7); a reconnect keeps H9.
      if (presentation === 'direct' && (purpose === 'add_access' || appOf(held).kind === 'shared')) throw new SessionError(409, 'direct_not_allowed', purpose === 'add_access' ? 'Adding access always shows Fabric\'s page, with the permissions it turns on.' : 'direct presentation needs your own provider app (F03.8); on Fabric\'s shared apps the person always sees Fabric\'s sheet.');
      const {adapter} = this.#accountSignIn(caller.scope, environment, held);
      if (purpose === 'add_access') this.#addAccessFor(appService(handle, this.runtimes.bundle(caller.scope).runtime, () => adapter).forUser({subjectId: known.subjectId, userRecordId: known.id}), held, body.groupId);
    } else if (body.appId !== undefined) {
      if (typeof body.appId !== 'string' || !this.tenantApps().some(app => app.id === body.appId)) throw notFound();
      const setting = this.appSetting(body.appId, environment, this.providerApps);
      if (setting.availability.state !== 'ready') throw new SessionError(422, setting.availability.state, setting.availability.reason);
      if (!setting.enabled) throw new SessionError(422, 'app_disabled', 'This app is turned off in this environment.');
      // H9: skipping Fabric's sheet removes the only screen that names the developer, so never on a shared app.
      if (presentation === 'direct' && setting.providerApp.kind === 'shared') throw new SessionError(409, 'direct_not_allowed', 'direct presentation needs your own provider app (F03.8); on Fabric\'s shared apps the person always sees Fabric\'s sheet.');
    } else if (presentation === 'direct') throw new SessionError(400, 'invalid_request', 'direct presentation needs an appId.');
    const success = body.successRedirectUri === undefined ? null : checkedRedirect(body.successRedirectUri, environment);
    const error = body.errorRedirectUri === undefined ? null : checkedRedirect(body.errorRedirectUri, environment);
    const opener = body.openerOrigin === undefined ? null : checkedOpener(body.openerOrigin, environment);
    const now = this.#now(), user = known ?? endUserFor(handle.repository, body.externalUserId, this.#iso(now)), appId = held?.appId ?? body.appId;
    const id = newId('connectSession'), secret = this.#secret(), expiresAt = this.#iso(now + seconds * 1000);
    const session = stampOwner({id, purpose, ...(appId ? {appId} : {}), ...(held ? {accountRef: held.id, ...(purpose === 'add_access' ? {groupId: body.groupId} : {}), ...(level !== undefined ? {level} : {})} : {}), delivery, presentation, ...(userHint ? {userHint} : {}), state: 'created', secretHash: sha256(secret), browserBindingHash: null,
      successRedirectUri: success, errorRedirectUri: error, ...(opener ? {openerOrigin: opener} : {}), createdBy: {serviceClientId: caller.serviceClientId, keyId: caller.keyId}, createdAt: this.#iso(now), expiresAt, claimedAt: null, result: null}, {subjectId: user.subjectId, userRecordId: user.id});
    handle.repository.put('connectSessions', session);
    // The route lets the link find its environment without opening any other.
    this.registry.put('sessionRoutes', {id, organizationId: caller.scope.organizationId, projectId: caller.scope.projectId, environmentId: caller.scope.environmentId, expiresAt});
    handle.repository.audit({type: 'connect.session_created', sessionId: id, userRecordId: user.id, appId: appId ?? null, ...(held ? {purpose, accountRef: held.id} : {}), byKey: caller.keyId});
    return {status: 201, body: {id, connectUrl: this.#url(id, secret), expiresAt, reach: 'this_machine'}};
  }
  /**
   * F03.10: a link to Fabric's manage pages (one person's apps, permissions and activity) or to one waiting approval.
   * Redirect delivery only, 10 minutes at most, for a person Fabric already knows: these links never create a user. An
   * approve link names one call of that person's that is waiting now; another person's call, an unknown one and a
   * malformed one all answer the same not_found, and nothing is written before every check has passed (N2).
   */
  #createPage(caller, body, purpose) {
    if ((body.delivery ?? 'redirect') !== 'redirect') throw new SessionError(400, 'invalid_request', 'Manage and approve links use redirect delivery only.');
    for (const field of ['userHint', 'consentEtag']) if (body[field] !== undefined) throw new SessionError(400, 'invalid_request', `${field} goes with connect links only.`);
    if (body.presentation !== undefined && body.presentation !== 'sheet') throw new SessionError(400, 'invalid_request', 'Manage and approve links always show Fabric\'s page.');
    const seconds = body.expiresInSeconds ?? 600;
    if (!Number.isSafeInteger(seconds) || seconds < 60 || seconds > 600) throw new SessionError(400, 'invalid_request', 'expiresInSeconds must be 60 to 600 for manage and approve links.');
    if (purpose === 'approve') {
      if (body.appId !== undefined) throw new SessionError(400, 'invalid_request', 'An approve link is for one call; it takes a callRef, not an appId.');
      if (body.callRef === undefined) throw new SessionError(400, 'invalid_request', 'An approve link needs the callRef of the waiting call.');
    } else if (body.callRef !== undefined) throw new SessionError(400, 'invalid_request', 'callRef goes with approve sessions only.');
    const environment = this.registry.get('environments', caller.scope.environmentId), repository = this.stores.open(caller.scope).repository;
    // Q4: an app that is turned off or not ready can still be managed (Never and Disconnect keep working).
    if (body.appId !== undefined && (typeof body.appId !== 'string' || !this.tenantApps().some(app => app.id === body.appId))) throw notFound();
    const success = body.successRedirectUri === undefined ? null : checkedRedirect(body.successRedirectUri, environment);
    const error = body.errorRedirectUri === undefined ? null : checkedRedirect(body.errorRedirectUri, environment);
    const opener = body.openerOrigin === undefined ? null : checkedOpener(body.openerOrigin, environment);
    if (typeof body.externalUserId !== 'string' || !SUBJECT.test(body.externalUserId)) throw new SessionError(400, 'invalid_external_user_id', 'externalUserId must be 1 to 128 characters: letters, digits and . _ : @ -');
    const user = repository.list('endUsers').find(item => item.subjectId === body.externalUserId && item.status === 'active');
    if (!user) throw notFound();
    const owner = {subjectId: user.subjectId, userRecordId: user.id}, now = this.#now();
    let expiresMs = now + seconds * 1000;
    if (purpose === 'approve') {
      // Ownership before state: another person's call reads exactly like one that does not exist.
      const job = typeof body.callRef === 'string' && CALL_REF.test(body.callRef) ? repository.get('jobs', body.callRef) : null;
      if (!job || !ownedBy(job, owner, tenantDeployment(repository.scope))) throw notFound();
      if (job.status !== 'awaiting_approval') throw new SessionError(409, 'not_awaiting_approval', 'This call is not waiting for a decision.');
      const until = Date.parse(job.approvalExpiresAt);
      if (!(until > now)) throw new SessionError(410, 'approval_expired', 'Nobody decided this call in time; it will not run.');
      expiresMs = Math.min(expiresMs, until);
    }
    const id = newId('connectSession'), secret = this.#secret(), expiresAt = this.#iso(expiresMs);
    const session = stampOwner({id, purpose, ...(body.appId ? {appId: body.appId} : {}), ...(purpose === 'approve' ? {callRef: body.callRef} : {}), delivery: 'redirect', presentation: 'sheet', state: 'created', secretHash: sha256(secret), browserBindingHash: null,
      successRedirectUri: success, errorRedirectUri: error, ...(opener ? {openerOrigin: opener} : {}), createdBy: {serviceClientId: caller.serviceClientId, keyId: caller.keyId}, createdAt: this.#iso(now), expiresAt, claimedAt: null, result: null}, owner);
    repository.put('connectSessions', session);
    this.registry.put('sessionRoutes', {id, organizationId: caller.scope.organizationId, projectId: caller.scope.projectId, environmentId: caller.scope.environmentId, expiresAt});
    repository.audit({type: 'connect.session_created', sessionId: id, purpose, userRecordId: user.id, appId: body.appId ?? null, ...(purpose === 'approve' ? {callRef: body.callRef} : {}), byKey: caller.keyId});
    return {status: 201, body: {id, connectUrl: this.#url(id, secret), expiresAt, reach: 'this_machine'}};
  }

  #load(caller, id) {
    if (typeof id !== 'string' || !/^cs_[a-z2-7]{26}$/.test(id)) throw notFound();
    const session = this.stores.open(caller.scope).repository.get('connectSessions', id);
    if (!session) throw notFound();
    return session;
  }
  #state(session, scope = null) {
    if (FINISHED.has(session.state)) return session.state;
    const limit = PAGE_PURPOSES.has(session.purpose) ? PAGE_IDLE_LIMIT_MS : IDLE_LIMIT_MS;
    const now = this.#now(), idle = session.claimedAt && now - Date.parse(session.lastSeenAt ?? session.claimedAt) > limit;
    const unconfirmed = session.state === 'awaiting_confirmation' && session.awaitingSince && now - Date.parse(session.awaitingSince) > CONFIRM_LIMIT_MS;
    return this.#until(scope, session) <= now || idle || unconfirmed ? 'expired' : session.state;
  }
  /**
   * When a session ends. F10.11 part n: an approve link whose call's first stop was approved on Fabric's page (state continuing) lives as
   * long as its call's current approval window, which never passes the call's deadline (lib/actions-runtime.mjs); its 600 seconds applied
   * only when it was made. Read without its environment, it keeps the end last stored on it.
   */
  #until(scope, session) {
    if (session.purpose !== 'approve' || session.state !== 'continuing' || !scope) return Date.parse(session.expiresAt);
    const until = Date.parse(this.stores.open(scope).repository.get('jobs', session.callRef)?.approvalExpiresAt ?? '');
    return Number.isFinite(until) ? until : 0;
  }
  /**
   * A session that leaves the confirm screen any way but confirm (close, cancel, idle, expiry, the 10-minute limit)
   * drops the account waiting there: erased here, and the revocation policy (N9) decides whether the provider hears.
   */
  async #release(scope, session) {
    if (!session.pendingAccountRef) return session;
    // Pinned across any provider revoke, so the session is still written to an open store after it.
    return this.stores.hold(scope, async env => {
      const pending = env.repository.get('connections', session.pendingAccountRef);
      if (pending?.status === 'pending_confirmation') {
        let adapter = null;
        try { ({adapter} = this.adapterFor(scope, pending.providerId ?? signInOf(pending.appId)?.providerId, appOf(pending))); } catch { /* no sign-in app: erased locally below */ }
        if (adapter) await this.#drop(adapter, env, pending); else { env.vault.delete(pending.id); env.repository.delete('connections', pending.id); }
      }
      const fresh = env.repository.get('connectSessions', session.id) ?? session, released = {...fresh, pendingAccountRef: null, finishHash: null};
      env.repository.put('connectSessions', released);
      this.#pendingRoute(session.id, false);
      return released;
    });
  }
  /** Any look at a link that ended with an account still waiting starts its erasure at once (the sweep is the backstop). */
  #settleLater(scope, session) {
    if (!session?.pendingAccountRef || this.#state(session) === 'awaiting_confirmation' || this.settling.has(session.id)) return;
    this.settling.add(session.id);
    const done = this.#release(scope, session).catch(() => {}).finally(() => this.settling.delete(session.id));
    this.revocations.add(done); done.finally(() => this.revocations.delete(done));
  }
  /** Marks a link's registry route while an account waits on its confirm screen, so the sweep opens only those environments (N1). */
  #pendingRoute(id, pending) {
    const route = this.registry.get('sessionRoutes', id);
    if (!route) return;
    const {pendingSince, ...rest} = route;
    this.registry.put('sessionRoutes', pending ? {...rest, pendingSince: this.registry.now()} : rest);
  }
  /**
   * Erases accounts left waiting on a confirm screen that ended (idle, expiry, the 10-minute limit). Runs every minute.
   * Routes past their link's or sign-in's end (and the grace) leave the registry here, without opening any environment.
   */
  async sweep() {
    let swept = 0;
    const routes = this.registry.list('sessionRoutes'), ended = route => Date.parse(route.expiresAt) + ROUTE_GRACE_MS <= this.#now();
    for (const route of routes) if (!route.pendingSince && ended(route)) this.registry.removeRoute('sessionRoutes', route.id);
    for (const route of this.registry.list('flowRoutes')) if (ended(route)) this.registry.removeRoute('flowRoutes', route.id);
    for (const route of routes.filter(item => item.pendingSince)) {
      const scope = this.#byRoute(route);
      let session;
      try { session = this.stores.open(scope).repository.get('connectSessions', route.id); } catch { continue; }
      if (!session?.pendingAccountRef) { this.#pendingRoute(route.id, false); continue; }
      const state = this.#state(session);
      if (state === 'awaiting_confirmation') continue;
      const released = await this.#release(scope, session);
      if (!FINISHED.has(released.state)) this.stores.open(scope).repository.put('connectSessions', {...released, state: 'expired', completedAt: this.registry.now(), result: {errorCode: 'expired'}});
      swept++;
    }
    return swept;
  }
  /** Page activity keeps a claimed link alive (H8). */
  #seen(scope, session) { const touched = {...session, lastSeenAt: this.registry.now()}; this.stores.open(scope).repository.put('connectSessions', touched); return touched; }
  #view(caller, session) {
    const user = this.stores.open(caller.scope).repository.get('endUsers', ownershipOf(session, {kind: 'tenant'}).userRecordId);
    return {id: session.id, externalUserId: user?.subjectId ?? null, purpose: session.purpose, ...(session.appId ? {appId: session.appId} : {}), ...(session.accountRef ? {accountRef: session.accountRef} : {}), ...(session.groupId ? {groupId: session.groupId} : {}), ...(['handoff', 'approve'].includes(session.purpose) ? {callRef: session.callRef} : {}), state: this.#state(session, caller.scope), expiresAt: session.expiresAt, createdByKeyId: session.createdBy?.keyId ?? null, ...(session.result ? {result: session.result} : {})};
  }
  /** GET /v1/connect-sessions/:id */
  get(caller, id) { const session = this.#load(caller, id); this.#settleLater(caller.scope, session); return this.#view(caller, session); }
  /** POST /v1/connect-sessions/:id/cancel */
  async cancel(caller, id) {
    const session = this.#load(caller, id);
    if (FINISHED.has(this.#state(session, caller.scope))) throw new SessionError(409, 'already_finished', 'This session has already finished.');
    const released = await this.#release(caller.scope, session);
    const cancelled = {...released, state: 'cancelled', completedAt: this.registry.now(), result: {errorCode: 'cancelled'}};
    this.stores.open(caller.scope).repository.put('connectSessions', cancelled);
    this.#unrouteUnclaimed(cancelled);
    return this.#view(caller, cancelled);
  }
  /** A link that ended before any browser opened it has no page to serve: its registry route goes now. */
  #unrouteUnclaimed(session) { if (!session.claimedAt) this.registry.removeRoute('sessionRoutes', session.id); }
  /** POST /v1/connect-sessions/:id/link: a fresh secret, voiding any unclaimed one. The key that minted it is recorded (N13). */
  link(caller, id) {
    const session = this.#load(caller, id), needed = SCOPE_OF[session.purpose] ?? 'connect:write';
    // Minting a link is the purpose's power, whichever key made the session (section 5.6). A key that may not read
    // sessions (no connect:write) gets the answer an unknown id gets, so it never learns which ids exist (N2).
    if (!caller.scopes.includes(needed)) {
      if (!caller.scopes.includes('connect:write')) throw notFound();
      throw new SessionError(403, 'forbidden_scope', `This key lacks the ${needed} scope.`);
    }
    if (FINISHED.has(this.#state(session, caller.scope))) throw new SessionError(409, 'already_finished', 'This session has already finished.');
    // A held call whose requester is gone (a revoked or expired key or agent token) closes here and gets no link.
    if (session.purpose === 'handoff' && this.runtimes.executions && !this.runtimes.executions.handoffWaiting(caller.scope, session)) throw new SessionError(409, 'already_finished', 'This session has already finished.');
    if (session.claimedAt) throw new SessionError(409, 'session_in_use', 'This link has already been opened.');
    const secret = this.#secret(), repository = this.stores.open(caller.scope).repository;
    repository.put('connectSessions', {...session, secretHash: sha256(secret), linkedBy: {keyId: caller.keyId, serviceClientId: caller.serviceClientId, at: this.registry.now()}});
    repository.audit({type: 'connect.link_minted', sessionId: id, byKey: caller.keyId});
    return {connectUrl: this.#url(id, secret), expiresAt: session.expiresAt};
  }
  /**
   * F03.9d: the Connect session behind a held execution (purpose handoff). Only Fabric makes one, never POST
   * /v1/connect-sessions; it has no usable link until the developer mints one with /link, which records its key.
   */
  createHandoff(scope, {owner, appId, callRef, createdBy, expiresAt}) {
    const id = newId('connectSession'), repository = this.stores.open(scope).repository;
    const session = stampOwner({id, purpose: 'handoff', appId, callRef, delivery: 'redirect', presentation: 'sheet', state: 'created', secretHash: sha256(this.#secret()), browserBindingHash: null,
      successRedirectUri: null, errorRedirectUri: null, createdBy, createdAt: this.registry.now(), expiresAt, claimedAt: null, result: null}, owner);
    repository.put('connectSessions', session);
    this.registry.put('sessionRoutes', {id, organizationId: scope.organizationId, projectId: scope.projectId, environmentId: scope.environmentId, expiresAt});
    repository.audit({type: 'connect.handoff_created', sessionId: id, callRef, userRecordId: owner.userRecordId, byKey: createdBy.keyId});
    return session;
  }
  /** The state of a session as its hold sees it ('expired' once past its time). */
  stateOf(scope, sessionId) {
    const session = this.stores.open(scope).repository.get('connectSessions', sessionId);
    return session ? {state: this.#state(session), errorCode: session.result?.errorCode ?? null} : {state: 'expired', errorCode: null};
  }
  /** Cancels a handoff from Fabric's side (the developer cancelled the held call): any waiting account is released. */
  async cancelHandoff(scope, sessionId) {
    const repository = this.stores.open(scope).repository, session = repository.get('connectSessions', sessionId);
    if (!session || FINISHED.has(this.#state(session))) return;
    const released = await this.#release(scope, session);
    repository.put('connectSessions', {...released, state: 'cancelled', completedAt: this.registry.now(), result: {errorCode: 'cancelled'}});
    this.#unrouteUnclaimed(released);
  }
  /** The person's own present, ready accounts that can run the held call; each by an opaque choice, shown by name only. */
  #eligible(scope, session) {
    const env = this.stores.open(scope), repository = env.repository, owner = ownershipOf(session, {kind: 'tenant'}), deployment = tenantDeployment(repository.scope);
    const hold = repository.get('continuations', session.callRef), cap = hold && repository.get('capabilities', hold.capabilityId), permissions = this.runtimes.bundle(scope).permissions;
    if (!cap) return [];
    return repository.list('connections').filter(item => item.appId === session.appId && item.status === 'ready' && ownedBy(item, owner, deployment)).filter(item => {
      try { return permissions.decision(item, cap).executable; } catch { return false; }
    }).map(item => ({choice: sha256(`${session.id}:${item.id}`).slice(0, 24), accountRef: item.id, displayName: String(item.identity?.displayName || item.label || 'Account').slice(0, 80)}));
  }
  /** Use an account the person already has for the held call: remembered, then confirmed on the next screen. */
  select(id, browserBinding, choice) {
    const {session, scope} = this.#claimed(id, browserBinding);
    if (session.purpose !== 'handoff' || this.#state(session) !== 'opened') throw new SessionError(409, 'already_finished', 'There is nothing to choose now.');
    const picked = this.#eligible(scope, session).find(item => item.choice === choice);
    if (!picked) throw notFound();
    this.stores.open(scope).repository.put('connectSessions', {...session, selectedAccountRef: picked.accountRef, lastSeenAt: this.registry.now()});
    return {state: 'opened', selectedAccount: {displayName: picked.displayName}};
  }
  /** The person declines the request: the held call ends, nothing is sent, and any waiting account is released. */
  async decline(id, browserBinding) {
    const {session, scope} = this.#claimed(id, browserBinding);
    if (session.purpose !== 'handoff') throw notFound();
    if (FINISHED.has(this.#state(session))) throw new SessionError(409, 'already_finished', 'This session has already finished.');
    const released = await this.#release(scope, session), repository = this.stores.open(scope).repository;
    repository.put('connectSessions', {...released, state: 'cancelled', selectedAccountRef: null, completedAt: this.registry.now(), result: {errorCode: 'declined'}});
    repository.audit({type: 'connect.handoff_declined', sessionId: id, callRef: session.callRef});
    return {state: 'cancelled'};
  }

  /**
   * The sign-in engine for one provider inside one environment (N11): Fabric's shared app, or one of the environment's
   * own provider apps (F03.8), which serves only its own sign-ins and the accounts it issued.
   */
  adapterFor(scope, providerId, providerApp = {kind: 'shared'}) {
    const bundle = this.runtimes.bundle(scope);
    if (providerApp?.kind === 'developer') {
      const adapter = this.runtimes.developerAdapter(scope, providerApp.id);
      if (!adapter || adapter.providerId !== providerId) throw new SessionError(422, 'setup_required', 'This sign-in app is not set up in this environment.');
      return {adapter, connections: bundle.connections, env: bundle.env};
    }
    const adapter = bundle.adapters.get(providerId);
    if (!adapter) throw new SessionError(422, 'setup_required', 'Fabric\'s operator has not set up this sign-in app yet.');
    return {adapter, connections: bundle.connections, env: bundle.env};
  }
  /** The person's own account a reconnect or Add access link is for, while they hold it; anything else is the same not_found (N2). */
  #accountOf(env, owner, accountRef) {
    const account = typeof accountRef === 'string' ? env.repository.get('connections', accountRef) : null;
    if (!account || !present(account) || account.authMethod !== 'oauth' || !this.tenantApps().some(app => app.id === account.appId) || !ownedBy(account, owner, tenantDeployment(env.scope))) throw notFound();
    return account;
  }
  /**
   * D8: an account signs in again through the sign-in app that issued it, whatever this environment chooses for new accounts
   * now. That app must be ready here, and the app not turned off.
   */
  #accountSignIn(scope, environment, account) {
    const setting = environment.apps?.[account.appId] ?? {}, providerApp = appOf(account), {providerId} = signInOf(account.appId);
    if (setting.enabled === false) throw new SessionError(422, 'app_disabled', 'This app is turned off in this environment.');
    const availability = this.providerApps.availability(account.appId, {...environment, apps: {...(environment.apps ?? {}), [account.appId]: {...setting, providerApp: providerApp.kind === 'developer' ? providerApp.id : 'shared'}}});
    if (availability.state !== 'ready') throw new SessionError(422, availability.state, availability.reason);
    return {providerId, providerApp, ...this.adapterFor(scope, providerId, providerApp)};
  }
  /**
   * F10.4: what an Add access link asks for, computed by Fabric from one permission row: the least-privileged scopes its missing
   * members need, never more. A row Fabric locks, or one whose only missing members are locked, asks for nothing (T1, T4).
   */
  #addAccessFor(service, account, groupId) {
    const app = service.app(account.appId), row = typeof groupId === 'string' ? service.rows(app, account).find(item => item.id === groupId) : null;
    if (!row) throw notFound();
    const missing = row.members.filter(member => member.decision.providerAccess === 'missing');
    if (row.locked || (missing.length && missing.every(member => member.decision.locked === true))) throw new SessionError(409, 'row_locked', LOCK_WORDS);
    // F10.6 (T3): a row whose only members that lack access can never work through a sign-in has nothing to add, and says why.
    const reasons = [...new Set(row.members.map(member => member.decision.unavailable).filter(Boolean))].sort();
    if (!missing.length && reasons.length) throw new SessionError(422, 'add_unavailable', reasons.map(reason => UNAVAILABLE_REASONS[reason]).join(' '));
    const added = service.addAccess(app, account, row.members);
    if (added.addBlocked) throw new SessionError(422, 'add_unavailable', added.addBlocked);
    if (!added.addAccess) throw new SessionError(409, 'access_held', 'This account already has the access this permission needs.');
    return added.addAccess.body;
  }
  /**
   * What a reconnect or Add access link signs in: the person's account, its own sign-in app, the input for start() (a reconnect
   * at the account's level unless the link names one, an Add access with the row's scopes), the level its sheet shows, and the
   * upgrade card when the sign-in would widen what the person approved and turn rows on at Allow (T7).
   */
  #accountPlan(scope, session) {
    const env = this.stores.open(scope), environment = this.registry.get('environments', scope.environmentId), owner = ownershipOf(session, tenantDeployment(env.scope));
    const account = this.#accountOf(env, owner, session.accountRef), signIn = this.#accountSignIn(scope, environment, account), access = signInOf(account.appId).access;
    const service = appService(env, this.runtimes.bundle(scope).runtime, () => signIn.adapter).forUser(owner), held = heldLevel(access, account.scopes), level = session.level ?? held?.level ?? held;
    const added = session.purpose === 'add_access' ? this.#addAccessFor(service, account, session.groupId) : null;
    const input = added ? {appId: account.appId, ...(added.level ? {level: added.level} : {}), scopes: added.scopes} : {appId: account.appId, level: reconnectLevel(access, level)};
    const trusted = {tenantFlow: {accountRef: account.id}}, card = service.upgradeFor(signIn.adapter, input, undefined, undefined, trusted);
    // The sheet offers one level, the one this link signs in at: the level held, or else the one the sign-in asks for. So
    // Fabric's page never offers a level start() refuses.
    const offered = offeredLevels(access), asked = signIn.adapter.plan(input, trusted).level === 'read' ? ['read'] : ['full', 'read_write'];
    return {...signIn, account, input, sheetLevel: offered.includes(level) ? level : asked.find(item => offered.includes(item)), upgrade: card?.rows.length ? {rows: card.rows, etag: card.etag} : null};
  }
  /** T1 (F10.5 correction 10): where a person removes the app at the provider, from the definition this environment signs the
   *  app's provider in with, so the page's words for a refused permission give the way back. Nothing when it names none. */
  #settingsUrl(scope, appId) {
    const signIn = signInOf(appId), settingsUrl = signIn && (this.runtimes.bundle(scope).adapters.get(signIn.providerId)?.definition ?? signIn.definition).revocation?.settingsUrl;
    return settingsUrl ? {settingsUrl} : {};
  }
  /** F10.7 (g4): what the account's own sign-in app asks for under the definition's consent policy (D8: it signs in through that one). */
  #consentModeOf(scope, account) {
    const own = appOf(account), record = own.kind === 'developer' ? this.providerApps.developer(scope, own.id) : null;
    return this.providerApps.consentMode(signInOf(account.appId).providerId, record);
  }
  /** The sign-in app an account's sheet names: the developer's consent screen, or Fabric's shared app (null). */
  #sheetAppOf(scope, account) {
    const own = appOf(account), record = own.kind === 'developer' ? this.providerApps.developer(scope, own.id) : null;
    return record ? {kind: 'developer', consentScreenName: record.consentScreenName} : null;
  }
  /**
   * The person's own present account this sign-in is merged into (same app, same sign-in app, same identity, whatever its
   * health: a reconnect is the usual reason to sign in again), and how (T7): a renewal grants nothing outside what the person
   * last approved (grantCeiling, or the scopes of an account from before ceilings) on the same origins; anything more is an upgrade.
   */
  #classify(env, owner, pending) {
    const deployment = tenantDeployment(env.scope);
    const same = env.repository.list('connections').find(other => other.id !== pending.id && other.appId === pending.appId && present(other) && other.identity?.id === pending.identity?.id && sameApp(appOf(other), appOf(pending)) && ownedBy(other, owner, deployment));
    if (!same) return {same: null, kind: 'connected'};
    const ceiling = same.grantCeiling ?? same.scopes ?? [];
    const renewal = Array.isArray(same.scopes) && Array.isArray(pending.scopes) && pending.scopes.every(scope => ceiling.includes(scope)) && JSON.stringify(same.allowedOrigins) === JSON.stringify(pending.allowedOrigins);
    return {same, kind: renewal ? 'reconsented' : 'upgraded'};
  }
  /** The upgrade card at confirm (T7): every row that runs at Allow once the account holds what this sign-in granted. */
  #confirmCard(scope, owner, same, pending) {
    const service = appService(this.stores.open(scope), this.runtimes.bundle(scope).runtime).forUser(owner), identity = signInOf(same.appId)?.definition.authorization.identityScopes ?? [];
    const card = service.upgradeCard(same, service.rows(service.app(same.appId), same), [...new Set(pending.scopes ?? [])].filter(item => !identity.includes(item)).sort());
    return {rows: card.rows, etag: card.etag};
  }
  #byRoute(route) { return route && {organizationId: route.organizationId, projectId: route.projectId, environmentId: route.environmentId}; }
  /** A suspended organization or environment (or production before the operator enables it) serves no page and no sign-in. */
  #live(scope) {
    const environment = scope && this.registry.get('environments', scope.environmentId), organization = environment && this.registry.get('organizations', environment.organizationId);
    return Boolean(environment && environment.status === 'active' && organization && organization.status === 'active' && (environment.kind !== 'production' || environment.productionEnabled));
  }
  /** The claimed session for this browser, or not_found: the page acts only on the session its own browser opened. */
  #claimed(id, browserBinding) {
    const route = typeof id === 'string' && /^cs_[a-z2-7]{26}$/.test(id) ? this.registry.get('sessionRoutes', id) : null;
    const scope = this.#byRoute(route), session = scope && this.#live(scope) ? this.stores.open(scope).repository.get('connectSessions', id) : null;
    if (!session || !session.browserBindingHash || typeof browserBinding !== 'string' || !timingSafeEqual(Buffer.from(sha256(browserBinding), 'hex'), Buffer.from(session.browserBindingHash, 'hex'))) throw notFound();
    return {session, scope};
  }
  /**
   * F03.10: the caller behind one request from a hosted manage or approval page. Checks, in order: this browser's
   * claimed session, its purpose, that it is still open, that its person is still the same live end user (both ids:
   * a user deleted and created again under the same external id is someone else, N3), and that the key that minted the
   * link is still active and still holds the purpose's scope (Q8). The owner comes only from the session, never from
   * anything the page sends. Each request counts as page activity.
   */
  pageCaller(id, browserBinding, purposes) {
    const {session, scope} = this.#claimed(id, browserBinding);
    if (!purposes.includes(session.purpose)) throw notFound();
    const state = this.#state(session, scope);
    if (state === 'expired') throw new SessionError(410, 'expired', 'This link has expired. Ask the app for a new one.');
    if (FINISHED.has(state)) throw new SessionError(409, 'already_finished', 'This session has already finished.');
    const repository = this.stores.open(scope).repository, owner = ownershipOf(session, {kind: 'tenant'}), user = repository.get('endUsers', owner.userRecordId);
    if (!user || user.status !== 'active' || user.subjectId !== owner.subjectId) throw notFound();
    const minted = session.linkedBy ?? session.createdBy;
    if (!this.#minterHolds(minted, SCOPE_OF[session.purpose], scope)) throw new SessionError(410, 'expired', 'This link has expired. Ask the app for a new one.');
    // F10.11 part n: a continuing approve link follows its call to its next stop's window. Its route needs no change: the route's hour of
    // grace outlasts any such link (at most three stops of ten minutes each).
    const until = this.#until(scope, session), current = session.state === 'continuing' && until > Date.parse(session.expiresAt) ? {...session, expiresAt: this.#iso(until)} : session;
    return {session: this.#seen(scope, current), scope, owner: endUser(owner),
      party: Object.freeze({decidedIn: 'fabric_page', keyId: minted?.keyId ?? null, serviceClientId: minted?.serviceClientId ?? null, sessionId: session.id, canDecide: true})};
  }
  /** Whether the key that minted a link is still active, in this environment, and its client still holds the scope. */
  #minterHolds(minted, needed, scope) {
    const key = minted?.keyId && this.registry.get('serviceKeys', minted.keyId), client = key && this.registry.get('serviceClients', key.serviceClientId);
    const active = key && !key.revokedAt && (!key.expiresAt || Date.parse(key.expiresAt) > this.#now()) && key.environmentId === scope.environmentId;
    return Boolean(active && client && client.status === 'active' && client.id === minted.serviceClientId && client.scopes.includes(needed));
  }
  /**
   * F10.11 part n: an approve link whose call's phase reads stop was approved on it stays open for the call's next stop (one link for both
   * phases). Only Fabric's page decision does this; the developer reads the state as continuing.
   */
  continuePage(scope, session) {
    const continuing = {...session, state: 'continuing', continuedAt: this.registry.now()};
    this.stores.open(scope).repository.put('connectSessions', continuing);
    return continuing;
  }
  /** F10.11 part n: the seconds a continuing approve link has left, for this browser's page cookie, which lives exactly as long as its link;
   *  null for any other link or browser. */
  continuingSeconds(id, browserBinding) {
    let session;
    try { ({session} = this.#claimed(id, browserBinding)); } catch { return null; }
    if (session.purpose !== 'approve' || session.state !== 'continuing') return null;
    return Math.max(1, Math.min(4 * 3600, Math.floor((Date.parse(session.expiresAt) - this.#now()) / 1000)));
  }
  /** Ends a manage or approve session as done; the developer reads the result and gets the person back (Q1). */
  finishPage(scope, session, result) {
    const done = {...session, state: 'completed', completedAt: this.registry.now(), result};
    this.stores.open(scope).repository.put('connectSessions', done);
    return {state: 'completed', ...(done.successRedirectUri ? {redirect: this.#successRedirect(done)} : {}), ...this.#opener(done, 'completed')};
  }
  /** What the page shows this browser: the sheet for the session's app, the apps to choose from, the account to confirm, or how it ended. Never an email. */
  view(id, browserBinding, chosenAppId, finish) {
    let {session, scope} = this.#claimed(id, browserBinding);
    const state = this.#state(session, scope);
    this.#settleLater(scope, session);
    if (!FINISHED.has(state) && state !== 'expired') session = this.#seen(scope, session);
    const project = this.registry.get('projects', scope.projectId), environment = this.registry.get('environments', scope.environmentId), repository = this.stores.open(scope).repository;
    const logo = logoUrl(project, this.origin), appOf = appId => this.tenantApps().find(item => item.id === appId);
    const base = {state, ...(PAGE_PURPOSES.has(session.purpose) ? {purpose: session.purpose} : {}), delivery: session.delivery ?? 'redirect', ...(session.userHint ? {userHint: session.userHint} : {}), developer: {appName: project.appName, ...(logo ? {logoUrl: logo} : {}), ...(project.supportEmail ? {supportEmail: project.supportEmail} : {}), ...(project.brand ? {brand: brandCss(project.brand)} : {})},
      ...(session.appId ? {appName: appOf(session.appId)?.name ?? session.appId, providerName: signInOf(session.appId)?.definition.displayName ?? null, ...this.#settingsUrl(scope, session.appId)} : {})};
    if (state === 'connected') {
      // The person's own account, by name and access only: never an email (H8).
      const account = session.result?.accountRef && repository.get('connections', session.result.accountRef);
      return {...base, ...(account ? {account: {displayName: String(account.identity?.displayName || account.label || 'Account').slice(0, 80), accessLabel: levelLabel(heldLevel(signInOf(account.appId)?.access ?? null, account.scopes))}} : {}),
        ...(session.successRedirectUri ? {redirect: this.#successRedirect(session)} : {}), ...this.#opener(session, 'connected', {appId: session.result?.appId, accountRef: session.result?.accountRef})};
    }
    if (state === 'completed') return {...base, ...(session.successRedirectUri ? {redirect: this.#successRedirect(session)} : {}), ...this.#opener(session, 'completed')};
    if (FINISHED.has(state)) {
      const errorCode = session.result?.errorCode ?? state;
      return {...base, errorCode, ...(session.errorRedirectUri ? {redirect: this.#errorRedirect(session, errorCode)} : {}), ...this.#opener(session, state === 'cancelled' || state === 'expired' ? state : 'failed', {errorCode})};
    }
    if (state === 'awaiting_confirmation') {
      // Which account signed in (for Google, its address) is shown only to the browser that came back from the provider:
      // a browser that merely opened the link learns nothing about someone else's sign-in (N4).
      if (!this.#finishedHere(session, finish)) return {...base, finishElsewhere: true};
      const pending = repository.get('connections', session.pendingAccountRef), holder = ownershipOf(session, tenantDeployment(repository.scope));
      // T7: a sign-in that widens an account the person holds shows the upgrade card here, and confirm needs it.
      const {same, kind} = pending ? this.#classify(this.stores.open(scope), holder, pending) : {};
      return {...base, pendingAccount: {displayName: String(pending?.identity?.displayName || pending?.label || 'this account').slice(0, 80)}, ...(kind === 'upgraded' ? {upgrade: this.#confirmCard(scope, holder, same, pending)} : {})};
    }
    // F03.10: the hosted pages load their own data; the view says only which page this link opens.
    if (session.purpose === 'manage') return {...base, manage: {appId: session.appId ?? null}};
    if (session.purpose === 'approve') return base;
    // A held call (F03.9d): the person's own accounts that can run it, by name only, or a new sign-in, or decline.
    if (session.purpose === 'handoff') {
      const accounts = this.#eligible(scope, session), selected = session.selectedAccountRef ? accounts.find(item => item.accountRef === session.selectedAccountRef) : null;
      const hold = repository.get('continuations', session.callRef), cap = hold && repository.get('capabilities', hold.capabilityId);
      return {...base, handoff: {operation: cap?.name ?? null, accounts: accounts.map(({choice, displayName}) => ({choice, displayName})), ...(selected ? {selectedAccount: {displayName: selected.displayName}} : {}), canDecline: true},
        sheet: consentSheet(session.appId, {origin: this.origin, project: {...project, logoUrl: logo}, providerApp: this.providerApps.sheetApp(scope, environment, session.appId), consentMode: this.providerApps.sheetConsentMode(scope, environment, session.appId)})};
    }
    // F10.4: a reconnect or Add access link shows its sheet at the one level it signs in at and the account's sign-in app, and
    // the upgrade card before sign-in when the sign-in would turn rows on at Allow. A plan that cannot be made shows the sheet;
    // the start says why.
    if (ACCOUNT_PURPOSES.has(session.purpose)) {
      let plan = null;
      try { plan = this.#accountPlan(scope, session); } catch { /* start() answers with the reason */ }
      // F10.7 (g4): the access line follows the sign-in app the sheet names, the account's own when the plan is made.
      return {...base, sheet: consentSheet(session.appId, {origin: this.origin, project: {...project, logoUrl: logo}, userHint: session.userHint, level: plan?.sheetLevel, fixed: Boolean(plan), providerApp: plan ? this.#sheetAppOf(scope, plan.account) : null,
        consentMode: plan ? this.#consentModeOf(scope, plan.account) : this.providerApps.sheetConsentMode(scope, null, session.appId)}), ...(plan?.upgrade ? {upgrade: plan.upgrade} : {})};
    }
    if (session.appId) return {...base, sheet: consentSheet(session.appId, {origin: this.origin, project: {...project, logoUrl: logo}, userHint: session.userHint, providerApp: this.providerApps.sheetApp(scope, environment, session.appId), consentMode: this.providerApps.sheetConsentMode(scope, environment, session.appId)})};
    // A link for no one app: the apps this environment offers, with this person's connection state (never account details).
    const owner = ownershipOf(session, {kind: 'tenant'}), deployment = tenantDeployment(repository.scope);
    const connected = new Set(repository.list('connections').filter(item => !['revoked', 'pending_confirmation'].includes(item.status) && ownedBy(item, owner, deployment)).map(item => item.appId));
    const apps = this.tenantApps().filter(app => { const setting = this.appSetting(app.id, environment, this.providerApps); return setting.enabled && setting.availability.state === 'ready'; });
    const chosen = typeof chosenAppId === 'string' && apps.some(app => app.id === chosenAppId) ? chosenAppId : null;
    if (chosenAppId !== undefined && chosenAppId !== null && !chosen) throw notFound();
    return {...base, apps: apps.map(app => ({id: app.id, name: app.name, iconUrl: `${this.origin}/assets/icons/${encodeURIComponent(app.id)}`, state: connected.has(app.id) ? 'connected' : 'available'})),
      ...(chosen ? {sheet: consentSheet(chosen, {origin: this.origin, project: {...project, logoUrl: logo}, userHint: session.userHint, providerApp: this.providerApps.sheetApp(scope, environment, chosen), consentMode: this.providerApps.sheetConsentMode(scope, environment, chosen)})} : {})};
  }
  #finishedHere(session, finish) { return typeof finish === 'string' && Boolean(session.finishHash) && timingSafeEqual(Buffer.from(sha256(finish), 'hex'), Buffer.from(session.finishHash, 'hex')); }
  /**
   * Section 6.6: how a finished session tells a developer's popup opener. Only to the session's own opener origin, and
   * only the session id, its state, and the app and account refs or the error code: never a name or an email.
   */
  #opener(session, state, {appId, accountRef, errorCode} = {}) {
    if (!session.openerOrigin) return {};
    return {opener: {origin: session.openerOrigin, message: {type: 'fabric.connect', sessionId: session.id, state, ...(appId ? {appId} : {}), ...(accountRef ? {accountRef} : {}), ...(errorCode ? {errorCode} : {})}}};
  }
  #successRedirect(session) {
    if (PAGE_PURPOSES.has(session.purpose)) return withResult(session.successRedirectUri, {fabric_session: session.id, fabric_state: 'completed'});
    return withResult(session.successRedirectUri, {fabric_session: session.id, fabric_state: 'connected', fabric_app: session.result.appId, fabric_account: session.result.accountRef});
  }
  #errorRedirect(session, errorCode) { return withResult(session.errorRedirectUri, {fabric_session: session.id, fabric_state: 'failed', error: errorCode, error_description: failureWords(errorCode)}); }
  /** The person closes Fabric's page: the link ends, and the developer hears it as cancelled. */
  async close(id, browserBinding) {
    const {session, scope} = this.#claimed(id, browserBinding);
    if (FINISHED.has(this.#state(session, scope))) throw new SessionError(409, 'already_finished', 'This session has already finished.');
    // Done on the manage pages: the person finished there, so the developer hears completed (an approval closed without a decision is cancelled).
    if (session.purpose === 'manage') return this.finishPage(scope, session, {});
    const released = await this.#release(scope, session);
    const closed = {...released, state: 'cancelled', completedAt: this.registry.now(), result: {errorCode: 'cancelled'}};
    this.stores.open(scope).repository.put('connectSessions', closed);
    return {state: 'cancelled', ...(session.errorRedirectUri ? {redirect: this.#errorRedirect(closed, 'cancelled')} : {}), ...this.#opener(closed, 'cancelled', {errorCode: 'cancelled'})};
  }
  /**
   * Starts the provider sign-in from Fabric's page (a click there, never automatically). Returns the provider URL and the flow
   * cookie value. A reconnect or Add access sign-in that would turn rows on at Allow starts only with the card's etag (T7).
   */
  start(id, browserBinding, appId, level, confirmRows) {
    const {session, scope} = this.#claimed(id, browserBinding);
    // Signing in is the power of the links that connect accounts: a manage or approve link never starts one.
    if (!['connect', 'handoff', 'reconnect', 'add_access'].includes(session.purpose)) throw notFound();
    if (this.#state(session) === 'expired') throw new SessionError(410, 'expired', 'This link has expired. Ask the app for a new one.');
    if (!['opened', 'signing_in'].includes(session.state)) throw new SessionError(409, 'already_finished', 'This session cannot start a sign-in now.');
    const chosen = session.appId ?? appId;
    if (session.appId && appId !== undefined && appId !== session.appId) throw new SessionError(400, 'invalid_request', 'This link is for another app.');
    const environment = this.registry.get('environments', scope.environmentId);
    if (typeof chosen !== 'string' || !this.tenantApps().some(app => app.id === chosen)) throw notFound();
    // The levels sign-in offers for this app; for one release a read_write sent for a version 2 app names full access (F10.7 g5).
    const offered = offeredLevels(signInOf(chosen).access);
    if (level !== undefined) level = requestedLevel(level, offered);
    const plan = ACCOUNT_PURPOSES.has(session.purpose) ? this.#accountPlan(scope, session) : null;
    if (plan && level !== undefined && level !== plan.sheetLevel) throw new SessionError(400, 'invalid_request', 'This link signs the account in again at its own access level.');
    if (plan?.upgrade && confirmRows !== plan.upgrade.etag) throw new SessionError(409, 'confirm_required', cardWords(plan.upgrade.rows), {upgrade: plan.upgrade});
    const setting = plan ? null : this.appSetting(chosen, environment, this.providerApps);
    if (setting && (setting.availability.state !== 'ready' || !setting.enabled)) throw new SessionError(422, setting.enabled ? setting.availability.state : 'app_disabled', setting.availability.reason || 'This app is turned off.');
    // The person may pick one of the levels the sheet offers (Gmail read-only as an advanced choice); full by default.
    if (level !== undefined && !offered.includes(level)) throw new SessionError(400, 'invalid_request', 'That access level is not offered for this app.');
    // The environment's chosen provider app for this app: Fabric's shared one or the developer's own (F03.8). A reconnect or Add
    // access keeps the account's own (D8).
    const {providerId} = signInOf(chosen), providerApp = plan ? plan.providerApp : setting.providerApp?.kind === 'developer' ? setting.providerApp : {kind: 'shared'}, {adapter, env} = plan ?? this.adapterFor(scope, providerId, providerApp);
    // A link starts a bounded number of sign-ins, and only its newest one can finish: the one before it, its secret
    // and its registry route go first, so one page cannot pile up flows and routes (SIGNIN-4).
    const starts = Number.isSafeInteger(session.starts) ? session.starts : 0;
    if (starts >= START_LIMIT) throw new SessionError(429, 'rate_limited', 'This link has started too many sign-ins. Ask the app for a new one.');
    if (typeof session.flowRouteId === 'string') { env.repository.delete('oauthFlows', session.flowRouteId); env.vault.delete(`oauth:${session.flowRouteId}`); this.registry.removeRoute('flowRoutes', session.flowRouteId); }
    const owner = ownershipOf(session, {kind: 'tenant'}), providerAppId = providerApp.kind === 'developer' ? providerApp.id : undefined, chosenLevel = level === 'read' ? 'read' : 'full';
    // F10.5 correction 1: a held call's sign-in asks by name for the least-privileged scope its operation needs, so declining it
    // connects nothing. Version 2 only: a version 1 sign-in asks for what it always asked for (T6). An operation with no map entry
    // plans from the row its request sits in, as its decision reads it (F10.6 correction 3).
    const hold = session.purpose === 'handoff' ? env.repository.get('continuations', session.callRef) : null, {permissions} = this.runtimes.bundle(scope);
    const needed = hold?.capabilityId && adapter.access(adapter.app(chosen)).schemaVersion === 2 ? operationScopes(adapter, chosen, env.repository.get('applicationMaps', chosen), hold.capabilityId, chosenLevel,
      permissions.groups, {capability: env.repository.get('capabilities', hold.capabilityId), configs: permissions.configs, actions: permissions.actions}).scopes : [];
    const flow = adapter.start(plan ? plan.input : {appId: chosen, level: chosenLevel, ...(needed.length ? {scopes: needed} : {})}, {tenantFlow: {sessionId: id, subjectId: owner.subjectId, userRecordId: owner.userRecordId, notAfter: session.expiresAt, ...(plan ? {accountRef: plan.account.id} : {}), ...(providerAppId ? {providerAppId} : {})}});
    const state = new URL(flow.authorizationUrl).searchParams.get('state'), flowRouteId = sha256(state);
    this.registry.put('flowRoutes', {id: flowRouteId, ...scope, providerId, ...(providerAppId ? {providerAppId} : {}), expiresAt: flow.expiresAt});
    env.repository.put('connectSessions', {...session, state: 'signing_in', appId: chosen, lastSeenAt: this.registry.now(), starts: starts + 1, flowRouteId});
    return {authorizationUrl: flow.authorizationUrl, flowId: flow.flowId, providerId, callbackPath: providerAppId ? `/api/oauth/${providerId}/apps/${providerAppId}/callback` : `/api/oauth/${providerId}/callback`};
  }
  /** The provider's redirect back: finds the environment by the state's route, completes the flow, and parks the account for confirmation. */
  async callback(providerId, {state, code, error, flowId}, providerAppId = null) {
    const routeId = typeof state === 'string' && state.length <= 256 ? sha256(state) : null, route = routeId ? this.registry.get('flowRoutes', routeId) : null;
    // A sign-in comes back on its own provider app's address only: a shared app's state on a developer app's address
    // (or the reverse, or another developer app) is refused before anything is used up.
    if (!route || route.providerId !== providerId || (route.providerAppId ?? null) !== providerAppId || !this.#live(this.#byRoute(route))) throw new SessionError(400, 'invalid_state', 'This sign-in has expired or was already used. Start again from the app.');
    // Pinned until the account is parked: no other environment's traffic can close this store and vault under the token
    // exchange, so a token the provider issues is always kept or dropped, never orphaned.
    return this.stores.hold(this.#byRoute(route), () => this.#signedIn(route, routeId, providerId, {state, code, error, flowId}));
  }
  async #signedIn(route, routeId, providerId, {state, code, error, flowId}) {
    const routeApp = route.providerAppId ? {kind: 'developer', id: route.providerAppId} : {kind: 'shared'};
    const scope = this.#byRoute(route);
    let adapter, env;
    try { ({adapter, env} = this.adapterFor(scope, providerId, routeApp)); }
    catch (failure) {
      // The developer's app was disabled (another environment proved its client) or lost its secret while the person was
      // at the provider: nothing is exchanged; the flow and route go, and the person's page says how it ended.
      if (routeApp.kind !== 'developer') throw failure;
      const repository = this.stores.open(scope).repository, vault = this.stores.open(scope).vault, flow = repository.get('oauthFlows', routeId), session = flow?.tenant?.sessionId && repository.get('connectSessions', flow.tenant.sessionId);
      if (flow) { repository.delete('oauthFlows', routeId); vault.delete(`oauth:${routeId}`); }
      this.registry.removeRoute('flowRoutes', routeId);
      if (!session || this.#state(session) !== 'signing_in') throw failure;
      const record = this.providerApps.developer(scope, routeApp.id), errorCode = record && this.providerApps.status(record, this.stores.open(scope)) === 'disabled' ? 'provider_app_disabled' : 'setup_required';
      repository.put('connectSessions', {...session, state: 'failed', completedAt: this.registry.now(), result: {errorCode}});
      return {sessionId: session.id, failed: errorCode};
    }
    const flowSession = env.repository.get('oauthFlows', routeId)?.tenant?.sessionId;
    let connection;
    // The route goes once the flow is gone (used or failed after consumption), never on a mere wrong-browser attempt.
    try { connection = await adapter.callback({state, code, error, flowId}); }
    catch (failure) {
      // Past the flow's own checks (the right browser, a spent flow), the failure belongs to the session: the person
      // sees it on Fabric's page and the developer reads it. A wrong-browser attempt (invalid_state) changes nothing.
      const spent = !env.repository.get('oauthFlows', routeId), session = flowSession && env.repository.get('connectSessions', flowSession);
      if (spent && failure?.code !== 'invalid_state' && session && this.#state(session) === 'signing_in') {
        const errorCode = ['consent_denied', 'insufficient_scope', 'never_requested'].includes(failure.code) ? failure.code : 'provider_error';
        env.repository.put('connectSessions', {...session, state: 'failed', completedAt: this.registry.now(), result: {errorCode}});
        return {sessionId: session.id, failed: errorCode};
      }
      throw failure;
    }
    finally { if (!env.repository.get('oauthFlows', routeId)) this.registry.removeRoute('flowRoutes', routeId); }
    const stored = env.repository.get('connections', connection.id), sessionId = stored?.origin?.sessionId, session = sessionId && env.repository.get('connectSessions', sessionId);
    // The link was cancelled, expired or its end user deleted while the person was at the provider: the new account is
    // dropped, and the revocation policy (N9) decides whether the provider hears about it.
    if (!session || this.#state(session) !== 'signing_in') {
      await this.#drop(adapter, env, stored);
      throw new SessionError(400, 'invalid_state', 'This Connect link was cancelled or has expired. Start again from the app.');
    }
    // N8: the first full sign-in through a developer's own app proves the client id for this environment. Synchronous
    // from the check to the record, so two environments racing can never both win; the loser's new account is dropped
    // (N9 decides any revoke) and its app reads as disabled from now on.
    if (routeApp.kind === 'developer') {
      const record = this.providerApps.developer(scope, routeApp.id);
      const claim = record ? this.registry.claimClientId(record.clientIdHash, env.repository.scopeKey, {providerAppId: record.id}) : 'taken';
      if (claim === 'taken') {
        await this.#drop(adapter, env, stored);
        env.repository.put('connectSessions', {...session, state: 'failed', completedAt: this.registry.now(), result: {errorCode: 'provider_app_disabled'}});
        env.repository.audit({type: 'provider_app.proof_refused', providerAppId: routeApp.id, sessionId: session.id});
        return {sessionId: session.id, failed: 'provider_app_disabled'};
      }
      if (record.status !== 'verified') {
        env.repository.put('providerApps', {...record, status: 'verified', verifiedAt: this.registry.now()});
        env.repository.audit({type: 'provider_app.verified', providerAppId: record.id, providerId: record.providerId});
      }
    }
    // F10.4: a reconnect or Add access link signs in again the account it is for. Another account, or none left to sign in
    // again (disconnected meanwhile), is dropped (N9 decides any revoke) and nothing changes.
    if (ACCOUNT_PURPOSES.has(session.purpose)) {
      const account = env.repository.get('connections', session.accountRef), errorCode = !account || !present(account) ? 'account_changed' : account.identity?.id !== stored?.identity?.id || !sameApp(appOf(account), appOf(stored)) ? 'identity_mismatch' : null;
      if (errorCode) {
        await this.#drop(adapter, env, stored);
        env.repository.put('connectSessions', {...session, state: 'failed', completedAt: this.registry.now(), result: {errorCode}});
        env.repository.audit({type: 'connect.signin_refused', sessionId: session.id, appId: stored?.appId ?? null, errorCode});
        return {sessionId: session.id, failed: errorCode};
      }
    }
    // M10: Fabric's shared Testing-mode Google client serves at most this many Google accounts per environment.
    if (providerId === 'google' && routeApp.kind === 'shared' && this.#googleBudgetReached(env, stored)) {
      await this.#drop(adapter, env, stored);
      env.repository.put('connectSessions', {...session, state: 'failed', completedAt: this.registry.now(), result: {errorCode: 'user_cap_reached'}});
      return {sessionId: session.id, failed: 'user_cap_reached'};
    }
    // The browser that finished at the provider gets a one-time value; only that browser can confirm (N4).
    const finish = this.#secret();
    env.repository.put('connectSessions', {...session, state: 'awaiting_confirmation', pendingAccountRef: connection.id, finishHash: sha256(finish), lastSeenAt: this.registry.now(), awaitingSince: this.registry.now()});
    this.#pendingRoute(sessionId, true);
    return {sessionId, finish};
  }
  /**
   * Whether one more Google identity would pass the environment's budget (M10). Counted: active Google accounts and, at
   * sign-in, accounts still waiting for a live confirm screen, so several sign-ins held unconfirmed cannot slip past it.
   */
  #googleBudgetReached(env, pending, {withPending = true} = {}) {
    const live = other => {
      if (!['revoked', 'pending_confirmation'].includes(other.status)) return true;
      if (!withPending || other.status !== 'pending_confirmation') return false;
      const session = other.origin?.sessionId && env.repository.get('connectSessions', other.origin.sessionId);
      return Boolean(session && this.#state(session) === 'awaiting_confirmation' && session.pendingAccountRef === other.id);
    };
    // Only accounts on Fabric's shared Google client count; a developer's own Google app has its own limits.
    const held = new Set(env.repository.list('connections').filter(other => other.id !== pending?.id && (other.providerId ?? signInOf(other.appId)?.providerId) === 'google' && appOf(other).kind === 'shared' && other.identity?.id && live(other)).map(other => other.identity.id));
    return !held.has(pending?.identity?.id) && held.size >= SHARED_GOOGLE_IDENTITY_BUDGET;
  }
  async #drop(adapter, env, stored) {
    if (!stored) return;
    let owner = null;
    try { owner = ownershipOf(stored, tenantDeployment(env.scope)); } catch { /* an unowned record is erased without asking anyone */ }
    // Pinned across the provider's revoke, so the vault and store it erases from are still open after it. N9: a token
    // another account here still holds (Slack and Notion can hand one person the same token again) is erased here only,
    // never revoked at the provider. So is a sign-in whose revocation would remove the whole grant (Google, T1): dropping it
    // never signs the person out of anything else.
    await this.stores.hold(env.scope, async () => {
      if (owner) { try { await adapter.revoke(stored.id, owner, adapter.revocationCovers() === 'grant' || this.providerApps.tokenHeldElsewhere(env, stored) ? {remote: false} : {}); } catch { /* erased below either way */ } }
      env.vault.delete(stored.id); env.repository.delete('connections', stored.id);
    });
  }
  /** "Not this account" on the confirm screen: the signed-in account is dropped (N9 decides any revoke) and the person can sign in again. */
  async reject(id, browserBinding) {
    const {session, scope} = this.#claimed(id, browserBinding);
    // "Not this account" after choosing an existing one only clears the choice: that account is never dropped.
    if (session.purpose === 'handoff' && session.selectedAccountRef && !session.pendingAccountRef) {
      this.stores.open(scope).repository.put('connectSessions', {...session, selectedAccountRef: null, lastSeenAt: this.registry.now()});
      return {state: 'opened'};
    }
    if (session.state !== 'awaiting_confirmation' || !session.pendingAccountRef) throw new SessionError(409, 'already_finished', 'There is nothing to turn down.');
    const env = this.stores.open(scope), pending = env.repository.get('connections', session.pendingAccountRef);
    if (pending) {
      const providerId = pending.providerId ?? signInOf(pending.appId)?.providerId;
      let adapter = null;
      try { ({adapter} = this.adapterFor(scope, providerId, appOf(pending))); } catch { /* no sign-in app: erased locally below */ }
      if (adapter) await this.#drop(adapter, env, pending); else { env.vault.delete(pending.id); env.repository.delete('connections', pending.id); }
    }
    env.repository.audit({type: 'connect.account_turned_down', sessionId: id, appId: pending?.appId ?? null});
    // A cancel, close or expiry that landed while the account was dropped stands: a finished link never opens again.
    const fresh = env.repository.get('connectSessions', id);
    if (!fresh || fresh.state !== 'awaiting_confirmation' || fresh.pendingAccountRef !== session.pendingAccountRef) return {state: fresh ? this.#state(fresh) : 'expired'};
    const next = {...fresh, state: this.#state(fresh) === 'expired' ? 'expired' : 'opened', pendingAccountRef: null, finishHash: null, lastSeenAt: this.registry.now()};
    env.repository.put('connectSessions', next);
    this.#pendingRoute(id, false);
    return {state: next.state};
  }
  /**
   * The person confirms on Fabric's page: the account activates, or the same account is signed in again, and the developer can
   * read the result. Signing in again within what the person approved is a renewal; a wider sign-in is an upgrade, confirmed with
   * the card's etag (`confirmRows`) as the page showed it (T7).
   */
  confirm(id, browserBinding, finish, body = {}) {
    const {session, scope} = this.#claimed(id, browserBinding);
    if (this.#state(session) === 'expired') throw new SessionError(410, 'expired', 'This link has expired. Ask the app for a new one.');
    // F03.9d: the person chose an account they already have for the held call; no sign-in happened, so no finish value.
    if (session.purpose === 'handoff' && session.selectedAccountRef && !session.pendingAccountRef) {
      if (this.#state(session) !== 'opened') throw new SessionError(409, 'already_finished', 'There is nothing to confirm.');
      const picked = this.#eligible(scope, session).find(item => item.accountRef === session.selectedAccountRef);
      if (!picked) throw notFound();
      const repository = this.stores.open(scope).repository, result = {accountRef: picked.accountRef, appId: session.appId, renewal: false};
      repository.put('connectSessions', {...session, state: 'connected', completedAt: this.registry.now(), result, selectedAccountRef: null});
      repository.audit({type: 'connect.account_chosen', sessionId: id, accountRef: picked.accountRef, callRef: session.callRef});
      this.#resumeLater(scope, session, picked.accountRef);
      return {state: 'connected', result};
    }
    if (session.state !== 'awaiting_confirmation' || !session.pendingAccountRef) throw new SessionError(409, 'already_finished', 'There is nothing to confirm.');
    // The claiming browser must also be the one that came back from the provider.
    if (!this.#finishedHere(session, finish)) throw new SessionError(403, 'finish_mismatch', 'Finish signing in from the browser that went to the provider.');
    const env = this.stores.open(scope), deployment = tenantDeployment(env.scope), owner = ownershipOf(session, deployment);
    const pending = env.repository.get('connections', session.pendingAccountRef);
    if (!pending || !ownedBy(pending, owner, deployment) || pending.status !== 'pending_confirmation') throw notFound();
    // M10 again at the moment of activation: only active Google accounts count, and confirming is synchronous, so the
    // environment never holds more than the budget. Shared Google never revokes remotely (N9), so the drop is local.
    if ((pending.providerId ?? signInOf(pending.appId)?.providerId) === 'google' && appOf(pending).kind === 'shared' && this.#googleBudgetReached(env, pending, {withPending: false})) {
      env.vault.delete(pending.id); env.repository.delete('connections', pending.id);
      env.repository.put('connectSessions', {...session, state: 'failed', completedAt: this.registry.now(), result: {errorCode: 'user_cap_reached'}, pendingAccountRef: null, finishHash: null});
      this.#pendingRoute(id, false);
      throw new SessionError(422, 'user_cap_reached', `This environment already uses ${SHARED_GOOGLE_IDENTITY_BUDGET} Google accounts on Fabric's shared Testing-mode sign-in.`);
    }
    // The same person signing in the same account again keeps one account: the new credential replaces the old.
    // Only on the same provider app: the same account through another app is a second account, never merged (D8).
    const {same, kind} = this.#classify(env, owner, pending);
    // F10.4: a reconnect or Add access link merges only into the account it is for. When that account went away meanwhile, the
    // sign-in is erased here (N9 decides whether the provider hears; confirm stays synchronous) and nothing changes.
    if (ACCOUNT_PURPOSES.has(session.purpose) && same?.id !== session.accountRef) {
      const dropped = env.vault.get(pending.id);
      env.vault.delete(pending.id); env.repository.delete('connections', pending.id);
      this.#revokeReplaced(scope, pending, dropped, 'connection.dropped_token_revoked');
      env.repository.put('connectSessions', {...session, state: 'failed', completedAt: this.registry.now(), result: {errorCode: 'account_changed'}, pendingAccountRef: null, finishHash: null});
      this.#pendingRoute(id, false);
      throw new SessionError(409, 'account_changed', FAILURE_WORDS.account_changed);
    }
    // T7: an upgrade needs the card computed now from what the provider granted. Without its etag nothing changes, and the
    // person can still confirm.
    if (kind === 'upgraded') {
      const card = this.#confirmCard(scope, owner, same, pending);
      if (body?.confirmRows !== card.etag) throw new SessionError(409, 'confirm_required', cardWords(card.rows), {upgrade: card});
    }
    let accountRef;
    if (same) {
      const previous = env.vault.get(same.id), replacement = env.vault.get(pending.id);
      env.vault.set(same.id, replacement); env.vault.delete(pending.id); env.repository.delete('connections', pending.id);
      // N9: a token-scoped provider's old token is revoked once Fabric stops holding it (shared Google never is).
      if (previous?.accessToken && previous.accessToken !== replacement?.accessToken) this.#revokeReplaced(scope, same, previous);
      // The credential's facts come from the new sign-in, and its sign-in revision voids any check started under the old one. A
      // renewal keeps the authorization, so saved settings and agent grants survive; an upgrade is a new authorization whose
      // ceiling grows to include what it granted, on the app's origins now, so saved Allow settings become Ask and Never stays
      // Never, and the next sign-in within that ceiling is a renewal again.
      const now = this.registry.now(), signIn = {signInRevision: pending.signInRevision ?? randomUUID(), signedInAt: pending.signedInAt ?? now};
      const merged = {...same, scopes: pending.scopes ?? same.scopes, expiresAt: pending.expiresAt ?? null, refreshAvailable: pending.refreshAvailable === true, ...signIn,
        ...(kind === 'upgraded' ? {authRevision: randomUUID(), ...(Array.isArray(pending.scopes) ? {grantCeiling: [...new Set([...(same.grantCeiling ?? same.scopes ?? []), ...pending.scopes])].sort()} : {}), allowedOrigins: pending.allowedOrigins} : {}), status: 'ready', error: null, updatedAt: now};
      // F10.5: what this sign-in asked for and did not get is its own; an old sign-in's never survives.
      if (pending.grant) merged.grant = pending.grant; else delete merged.grant;
      env.repository.put('connections', merged);
      env.repository.audit({type: kind === 'upgraded' ? 'connection.upgraded' : 'connection.reconsented', connectionId: same.id, appId: same.appId});
      // A renewal that grants less is still a renewal; it says so once, so the rows that need more access are explained. A scope
      // the person declined at the provider is explained by the not-granted notice instead.
      const lost = kind === 'reconsented' ? narrowedBy(same.scopes, merged.scopes).filter(scope => !pending.grant?.missing.includes(scope)) : [];
      if (lost.length) raise(env.repository, {connection: merged, kind: 'grant_narrowed', subjectKey: scopesSubject(lost), now: this.#now()});
      accountRef = same.id;
    } else {
      const {origin, planned, ...rest} = pending;
      env.repository.put('connections', {...rest, status: 'ready', providerApp: appOf(pending), updatedAt: this.registry.now()});
      accountRef = pending.id;
      // F10.7 (decision 9): a first sign-in has no card, so what it asked for stands in for one; whatever else the provider granted
      // starts at Ask, typed and raw, before the account can run anything.
      if (Array.isArray(planned)) appService(env, this.runtimes.bundle(scope).runtime).forUser(owner).pinUnconfirmed(null, env.repository.get('connections', accountRef), planned);
      // D11: a newly connected account is one usage record (a re-sign-in of the same account is not).
      this.usage?.append(env, {id: `account.${accountRef}`, kind: 'account_connected', userRecordId: owner.userRecordId, keyId: session.createdBy?.keyId ?? null, serviceClientId: session.createdBy?.serviceClientId ?? null, appId: pending.appId});
    }
    const user = env.repository.get('endUsers', owner.userRecordId);
    if (user?.status === 'active') env.repository.put('endUsers', {...user, lastConnectedAt: this.registry.now()});
    const result = {accountRef, appId: pending.appId, renewal: kind === 'reconsented'};
    env.repository.put('connectSessions', {...session, state: 'connected', completedAt: this.registry.now(), result, pendingAccountRef: null, finishHash: null});
    this.#pendingRoute(id, false);
    env.repository.audit({type: 'connect.account_confirmed', sessionId: id, accountRef, appId: pending.appId});
    if (session.purpose === 'handoff') this.#resumeLater(scope, session, accountRef);
    return {state: 'connected', result, ...(session.successRedirectUri ? {redirect: this.#successRedirect({...session, result})} : {}), ...this.#opener(session, 'connected', {appId: result.appId, accountRef: result.accountRef})};
  }

  /**
   * The held call resumes on the confirmed account (F03.9d). The hook marks the hold synchronously, so a cancel racing the
   * confirm finds it already taken; the rest runs after, tracked so shutdown and tests can wait for it.
   */
  #resumeLater(scope, session, accountRef) {
    if (typeof this.resumeHold !== 'function') return;
    const done = Promise.resolve(this.resumeHold(scope, session, accountRef)).catch(() => {});
    this.revocations.add(done); done.finally(() => this.revocations.delete(done));
  }
  /**
   * Best effort, after the swap (or a dropped sign-in): the outcome is recorded either way, and a failure never undoes
   * the confirm. A token another account here still holds is never sent (N9).
   */
  #revokeReplaced(scope, account, tokens, type = 'connection.replaced_token_revoked') {
    const signIn = signInOf(account.appId);
    if (!tokens || !signIn || signIn.definition.revocation?.covers !== 'token' || this.providerApps.revocationPolicy(signIn.definition, appOf(account)) !== 'provider') return;
    let adapter, env;
    try { ({adapter, env} = this.adapterFor(scope, signIn.providerId, appOf(account))); } catch { return; }
    if (this.providerApps.tokenHeldElsewhere(env, account, tokens)) return;
    const done = adapter.revokeTokens(tokens).catch(() => false).then(remoteRevoked => {
      try { env.repository.audit({type, connectionId: account.id, appId: account.appId, remoteRevoked}); } catch { /* the environment may have closed */ }
    });
    this.revocations.add(done); done.finally(() => this.revocations.delete(done));
  }

  /**
   * Opening the link: synchronous from read to write, so two claims leave exactly one winner. Order: the route, the
   * secret (a wrong one is not_found whatever else is true), expiry, then one browser only.
   */
  claim(id, secret, browserBinding, presentedBinding) {
    const route = typeof id === 'string' && /^cs_[a-z2-7]{26}$/.test(id) ? this.registry.get('sessionRoutes', id) : null;
    const session = route && this.#live(this.#byRoute(route)) ? this.stores.open(this.#byRoute(route)).repository.get('connectSessions', id) : null;
    const usable = typeof session?.secretHash === 'string' && /^[0-9a-f]{64}$/.test(session.secretHash);
    const presented = Buffer.from(sha256(typeof secret === 'string' ? secret : ''), 'hex'), stored = Buffer.from(usable ? session.secretHash : DUMMY, 'hex');
    if (!timingSafeEqual(presented, stored) || !session || !usable) throw notFound();
    if (this.#state(session, this.#byRoute(route)) === 'expired') throw new SessionError(410, 'expired', 'This link has expired. Ask the app for a new one.');
    if (FINISHED.has(session.state)) throw new SessionError(409, 'already_finished', 'This session has already finished.');
    if (typeof browserBinding !== 'string' || browserBinding.length < 16) throw new SessionError(400, 'invalid_request', 'A browser binding is required.');
    // The first claim always binds the fresh value Fabric made; a value the browser already carried only recognises
    // the same browser coming back, so a planted cookie can never become a session's binding.
    const kept = session.claimedAt ? (presentedBinding ?? browserBinding) : browserBinding;
    if (session.claimedAt && (typeof kept !== 'string' || !timingSafeEqual(Buffer.from(sha256(kept), 'hex'), Buffer.from(session.browserBindingHash, 'hex')))) throw new SessionError(409, 'session_in_use', 'This link is already open in another browser.');
    const repository = this.stores.open(this.#byRoute(route)).repository;
    const claimed = session.claimedAt ? session : {...session, claimedAt: this.registry.now(), lastSeenAt: this.registry.now(), browserBindingHash: sha256(browserBinding), state: 'opened'};
    if (!session.claimedAt) repository.put('connectSessions', claimed);
    return {binding: kept, session: claimed, scope: {organizationId: route.organizationId, projectId: route.projectId, environmentId: route.environmentId}, owner: endUser({subjectId: ownershipOf(claimed, {kind: 'tenant'}).subjectId, userRecordId: claimed.userRecordId})};
  }
}

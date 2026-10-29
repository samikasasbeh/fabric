import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { safeRequest } from '../network.mjs';
import { ConnectionError } from './errors.mjs';
import { heldLevel } from '../access-levels.mjs';
import { captureConnectionAuthority, assertConnectionAuthority, sameSignIn } from '../authority-guard.mjs';
import { raise, narrowedBy, scopesSubject } from '../connection-notices.mjs';
import { ownedBy } from '../tenant/deployment.mjs';
import { validateAuthDefinition, definitionOrigins, revocationUrl, normalizeAuthApp, fullLevelScopes, levelScopes, effectiveScopes, refusedScopes } from '../../contracts/auth-definition.mts';

const clean = (value, limit = 200) => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g,'').slice(0,limit) : '';
const hash = value => createHash('sha256').update(value).digest('hex');
const equal = (a,b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a),Buffer.from(b));
const validCredential = value => typeof value === 'string' && value.length > 0 && value.length <= 16000 && !/\s/.test(value);
const LOOPBACK = ['127.0.0.1','localhost','[::1]'];
const PUBLISHING = ['testing','production'];
const REVOCATION_POLICIES = ['provider','local_only'];
const consentDaysOf = value => value === null || (Number.isSafeInteger(value) && value >= 1 && value <= 365);
// Add access and account-request sign-ins may ask for at most this many extra scopes at once (F10.2, with the contract cap).
export const MAX_REQUESTED_SCOPES = 64;
/** F10.19 (B6): the one reviewed token introspection address of each provider that has one, on its token origin. Only introspect() calls it
 *  (the live-test harness, once in N0); it is never a route, and the proxy refuses it (a Never row whose member is unavailable). */
export const INTROSPECTION = Object.freeze({notion: 'https://api.notion.com/v1/oauth/introspect'});
function pointerValue(value, pointer) {
  for (const part of pointer.slice(1).split('/')) {
    if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.hasOwn(value,part)) return undefined;
    value = value[part];
  }
  return value;
}
// RFC 6749 section 2.3.1 form-encodes each value before HTTP Basic encoding; several
// providers document plain base64(id:secret) instead, so the definition chooses.
/** F10.6: what Add access and an account-request sign-in may ask for on one row of a version 2 app, as a predicate: a scope of the
 *  full level's required or optional lists, or an in-context scope that names the row, and never a never-request scope. A read-level
 *  scope is not usable, since plan() refuses one by name. Null for version 1, which keeps its map-documented rule. */
export function usableScopes(reading, groupId) {
  if (reading?.schemaVersion !== 2) return null;
  const full = reading.levels.full, level = new Set([...full.required, ...full.optional]);
  return scope => typeof scope === 'string' && !reading.neverRequest.includes(scope) && (level.has(scope) || full.inContext.some(entry => entry.scope === scope && entry.rows.includes(groupId)));
}
const basic = (id, secret, encoding) => `Basic ${Buffer.from(encoding === 'raw' ? `${id}:${secret}` : `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;
const present = value => value !== undefined && value !== null && value !== '';
const satisfies = (data, rules) => rules.every(rule => Object.hasOwn(rule,'present') ? present(pointerValue(data,rule.pointer)) : pointerValue(data,rule.pointer) === rule.equals);
const splitScopes = (value, separator) => typeof value === 'string' ? (separator === ',' ? value.split(',').map(s => s.trim()) : value.split(/\s+/)).filter(Boolean) : undefined;

/**
 * Provider-neutral OAuth 2.0 authorization-code lifecycle driven by a reviewed
 * auth definition. Authority and replay guarantees are identical for every
 * provider; only endpoints, scopes, encodings and named parsers differ.
 * @implements {import('../../contracts/provider.mts').ProviderAdapter}
 */
export class OAuth2Provider {
  #definition; #origins;
  /**
   * @param {unknown} definition
   * @param {import('../../contracts/provider.mts').GoogleProviderOptions & {allowHostedRedirect?: boolean, callbackHelp?: string, publishing?: 'testing' | 'production', consentDays?: number | null}} options
   * `callbackHelp` is the embedding's own sentence on how to make an HTTPS-only provider available here. `publishing`
   * (default: the operator setting FABRIC_<PROVIDER>_PUBLISHING, else testing) picks the version 2 consent policy.
   * `consentDays` (default: the operator setting FABRIC_<PROVIDER>_CONSENT_DAYS, else null) is how long one consent lasts,
   * such as 7 in Google's Testing mode; a check warns a day before it ends (F10.4).
   * `revocationPolicy` (N9, trusted embedding only): 'local_only' means this adapter never asks the provider to revoke
   * anything, on any path; a developer environment sets it on Fabric's shared app wherever revocation covers the grant.
   * `signInGuard(providerId, scopes)` (F10.12, trusted embedding only): the live-test harness's sign-in count, asked before any sign-in starts;
   * a throw refuses it with its words and code rate_limited, before a flow is stored or an authorization URL is made.
   */
  constructor(definition,{store,vault,connections,request = safeRequest,clientId,clientSecret,redirectUri,clock = Date.now,allowHostedRedirect = false,callbackHelp,publishing,consentDays,revocationPolicy = 'provider',providerAppId,signInGuard}) {
    // F03.8, trusted embedding only: the developer's own provider app this adapter signs in through. Such an adapter
    // takes every client value explicitly (never a machine environment variable) and serves only its own flows.
    if (providerAppId !== undefined && (typeof providerAppId !== 'string' || !/^pa_[a-z2-7]{26}$/.test(providerAppId) || typeof clientId !== 'string' || typeof clientSecret !== 'string' || !['testing','production'].includes(publishing) || consentDays === undefined)) throw new Error('A developer provider app adapter needs its id, client id, client secret, publishing and consent days.');
    this.providerAppId = providerAppId ?? null;
    const checked = validateAuthDefinition(definition);
    if (checked.reviewStatus !== 'reviewed') throw new ConnectionError(`${checked.displayName} sign-in is a candidate definition and has not been reviewed for use.`, 'invalid_input');
    this.#definition = checked; this.#origins = definitionOrigins(checked);
    this.store = store; this.vault = vault; this.connections = connections; this.request = request;
    this.clientId = clientId === undefined ? process.env[checked.credentialEnvironment.clientId] : clientId;
    this.clientSecret = clientSecret === undefined ? process.env[checked.credentialEnvironment.clientSecret] : clientSecret;
    this.redirectUri = redirectUri ?? `http://127.0.0.1:4188/api/oauth/${checked.providerId}/callback`;
    this.clock = clock; this.refreshing = new Map();
    if (!REVOCATION_POLICIES.includes(revocationPolicy)) throw new Error('The revocation policy must be provider or local_only.');
    this.revocationPolicy = revocationPolicy;
    if (signInGuard !== undefined && typeof signInGuard !== 'function') throw new Error('A sign-in guard is a function.');
    this.signInGuard = signInGuard ?? null;
    if (callbackHelp !== undefined && (typeof callbackHelp !== 'string' || !callbackHelp || callbackHelp.length > 300 || /[\u0000-\u001f\u007f]/.test(callbackHelp))) throw new Error('OAuth callback help must be one short sentence.');
    this.callbackHelp = callbackHelp ?? 'Sign-in becomes available once FABRIC_PUBLIC_CALLBACK_BASE names the hosted callback relay.';
    const publishingVariable = `FABRIC_${checked.providerId.toUpperCase().replace(/-/g,'_')}_PUBLISHING`;
    this.publishing = publishing ?? (process.env[publishingVariable] || 'testing');
    if (!PUBLISHING.includes(this.publishing)) throw new Error(`${publishingVariable} must be testing or production.`);
    const consentVariable = `FABRIC_${checked.providerId.toUpperCase().replace(/-/g,'_')}_CONSENT_DAYS`, operatorDays = process.env[consentVariable];
    if (consentDays === undefined && operatorDays) {
      if (!/^\d{1,3}$/.test(operatorDays) || !consentDaysOf(Number(operatorDays))) throw new Error(`${consentVariable} must be a whole number of days from 1 to 365.`);
      consentDays = Number(operatorDays);
    }
    if (consentDays !== undefined && !consentDaysOf(consentDays)) throw new Error('Consent days must be a whole number from 1 to 365, or null.');
    this.consentDays = consentDays ?? null;
    this.normalized = new Map(checked.apps.map(app => [app.appId,normalizeAuthApp(checked,app)]));
    const redirect = new URL(this.redirectUri);
    const loopback = redirect.protocol === 'http:' && LOOPBACK.includes(redirect.hostname);
    // A hosted HTTPS callback is a trusted embedding decision, never a request input.
    const hosted = allowHostedRedirect === true && redirect.protocol === 'https:' && !LOOPBACK.includes(redirect.hostname);
    if ((!loopback && !hosted) || redirect.username || redirect.password || redirect.search || redirect.hash) throw new Error('OAuth redirect must be an explicit local loopback callback.');
  }
  /** @returns {string} */
  get providerId() { return this.#definition.providerId; }
  /** @returns {readonly string[]} */
  get appIds() { return Object.freeze(this.#definition.apps.map(app => app.appId)); }
  /** @returns {import('../../contracts/auth-definition.mts').AuthDefinition} */
  get definition() { return this.#definition; }
  get name() { return this.#definition.displayName; }
  get configured() { return Boolean(this.clientId && this.clientSecret); }
  /** False when the provider refuses this installation's callback (for example Slack on plain HTTP). */
  get redirectSupported() { return !(this.#definition.authorization.loopbackRedirect === 'https-required' && new URL(this.redirectUri).protocol !== 'https:'); }
  /** Truthful readiness for UI and agents: configured credentials and a callback the provider accepts. */
  availability() {
    if (!this.redirectSupported) return {configured:this.configured,available:false,reason:`${this.name} only accepts HTTPS callbacks. ${this.callbackHelp}`};
    return {configured:this.configured,available:this.configured,reason:this.configured ? null : `The product operator must configure the ${this.name} sign-in client.`};
  }
  /** @returns {import('../../contracts/provider.mts').ProviderConfiguration} A version 2 sign-in asks for full access by default (F10.7). */
  configuration() { const env = this.#definition.credentialEnvironment; return {configured:this.configured,redirectUri:this.redirectUri,requiredEnvironment:[env.clientId,env.clientSecret],defaultAccess:this.#definition.schemaVersion === 2 ? 'full' : 'read-only'}; }
  app(appId) {
    const app = typeof appId === 'string' ? this.#definition.apps.find(item => item.appId === appId) : undefined;
    if (!app) throw new ConnectionError(`Unsupported ${this.name} application.`, 'invalid_input');
    return app;
  }
  /** @returns {import('../../contracts/auth-definition.mts').NormalizedAuthApp} One reading of a version 1 or 2 app entry. */
  access(app) { return this.normalized.get(app.appId); }
  /** What sign-in asks for under this installation's publishing state: version 1 definitions always ask for the whole level. */
  get consentMode() { return this.#definition.consentPolicy?.[this.publishing] ?? 'full'; }
  /** Version 1: the reviewed upgrade prefixes and exact scopes. Version 2: any scope of the app's levels (never a never-request scope).
   *  For a version 2 app, Add access and account-request sign-ins ask through usableFor() instead (F10.6). */
  belongsToApp(app, scope) {
    if (typeof scope !== 'string') return false;
    const access = this.access(app);
    if (access.upgradeScopes) return access.upgradeScopes.prefixes.some(prefix => scope.startsWith(prefix)) || access.upgradeScopes.exact.includes(scope);
    return !access.neverRequest.includes(scope) && (fullLevelScopes(access).includes(scope) || (access.levels.read !== null && [...access.levels.read.required,...access.levels.read.optional].includes(scope)));
  }
  /** F10.6: the scopes Add access and an account-request sign-in may ask for on one row of `app` (usableScopes()), or null for a
   *  version 1 app. start() checks level membership only, since it does not know the row. */
  usableFor(app, groupId) { return usableScopes(this.access(app),groupId); }
  /** What a grant of `scopes` holds for this app (F10.5): the scopes, and every scope a granted parent grants. */
  effectiveScopes(appId,scopes) { return effectiveScopes(this.access(this.app(appId)),Array.isArray(scopes) ? scopes : []); }
  /** The granted scopes Fabric never holds (T1): on the never list of any app of this provider, directly or through what they
   *  grant, so no app can carry another's refused permission. Every app reads the same implications. */
  refused(scopes) {
    const apps = [...this.normalized.values()];
    return refusedScopes(apps.flatMap(app => app.neverRequest),apps[0].implies,Array.isArray(scopes) ? scopes.filter(scope => typeof scope === 'string') : []);
  }
  /** Apps whose grant is a user credential (Slack user_scope) carry every scope as a user scope. */
  usesUserScopes(app) { return this.access(app).grant === 'user_scope'; }
  /** The app scopes a sign-in at one level asks for: required, plus optional under the 'full' consent policy. An explicit full upgrade
   *  (F10.7 g6) asks for the optional ones under any policy, since the owner asked for the whole level. */
  signInScopes(app, level, {fullUpgrade = false} = {}) {
    const access = this.access(app), chosen = level === 'read' ? access.levels.read : access.levels.full;
    if (!chosen) throw new ConnectionError(`${this.name} offers only full access for this application.`, 'invalid_input');
    return [...chosen.required,...(this.consentMode === 'full' || fullUpgrade ? chosen.optional : [])];
  }
  /**
   * @param {import('../../contracts/provider.mts').ProviderStartInput} [input]
   * @param {{continuation?: {id: string, notAfter: string}, upgrade?: {etag: string, scopes: string[]}}} [trusted] In-process only: binds the flow to one
   * missing-access handoff and clamps it to that handoff's deadline, or (F10.4) carries the upgrade card the owner confirmed for
   * a reconnect, so the callback wall knows what was approved. No HTTP or protocol path can supply it.
   * @returns {import('../../contracts/provider.mts').ProviderStartResult}
   */
  start({connectionId,label,writeAccess = false,level,appId:requestedApp,scopes:requestedScopes,fullUpgrade} = {},trusted = {}) {
    const definition = this.#definition, name = this.name, continuation = trusted?.continuation;
    // F03.4b, trusted in-process only: the Connect session, end user and environment this sign-in belongs to.
    const tenantFlow = trusted?.tenantFlow;
    if (tenantFlow !== undefined && (!tenantFlow || !/^cs_[a-z2-7]{26}$/.test(tenantFlow.sessionId ?? '') || !/^usr_[a-z2-7]{26}$/.test(tenantFlow.userRecordId ?? '') || typeof tenantFlow.subjectId !== 'string' || connectionId !== undefined || continuation !== undefined
      || (tenantFlow.notAfter !== undefined && !Number.isFinite(Date.parse(tenantFlow.notAfter))) || (tenantFlow.accountRef !== undefined && !/^[0-9a-f-]{36}$/.test(tenantFlow.accountRef)))) throw new ConnectionError('Invalid Connect session sign-in.', 'invalid_input');
    // A sign-in names the provider app it goes through, and only that app's adapter starts it (F03.8).
    if ((tenantFlow?.providerAppId ?? null) !== this.providerAppId || (this.providerAppId && !tenantFlow)) throw new ConnectionError('Invalid Connect session sign-in.', 'invalid_input');
    if (level !== undefined && level !== 'full' && level !== 'read') throw new ConnectionError('The access level must be full or read.', 'invalid_input');
    if (typeof writeAccess !== 'boolean') throw new ConnectionError('Write access must be true or false.', 'invalid_input');
    if (level !== undefined && writeAccess === true && level !== 'full') throw new ConnectionError('Write access needs the full access level.', 'invalid_input');
    if (continuation !== undefined && (!continuation || typeof continuation.id !== 'string' || !/^[0-9a-f-]{36}$/.test(continuation.id) || !Number.isFinite(Date.parse(continuation.notAfter)) || connectionId !== undefined)) throw new ConnectionError('Invalid account request sign-in.', 'invalid_input');
    const upgrade = trusted?.upgrade;
    if (upgrade !== undefined && (!upgrade || typeof upgrade.etag !== 'string' || !/^[0-9a-f]{64}$/.test(upgrade.etag) || !Array.isArray(upgrade.scopes) || upgrade.scopes.length > 1000 || upgrade.scopes.some(s => typeof s !== 'string') || !connectionId || tenantFlow !== undefined || continuation !== undefined)) throw new ConnectionError('Invalid upgrade sign-in.', 'invalid_input');
    // The callback comes first: a not-configured message names it, so it must be one the provider accepts.
    if (!this.redirectSupported) throw new ConnectionError(`${name} only accepts HTTPS callbacks. ${this.callbackHelp} No sign-in was started.`, 'redirect_unsupported');
    if (!this.configured) throw new ConnectionError(`${name} OAuth is not configured. Set ${definition.credentialEnvironment.clientId} and ${definition.credentialEnvironment.clientSecret} and register this callback in your ${name} project: ${this.redirectUri}`, 'not_configured');
    const {appId,level:chosenLevel,scopes,userScopes,existing} = this.plan({connectionId,writeAccess,level,appId:requestedApp,scopes:requestedScopes,fullUpgrade},{tenantFlow});
    // F10.12: the live-test harness counts sign-ins with the exact scope set this one asks for, before anything is stored or a URL made.
    try { this.signInGuard?.(this.providerId,[...scopes,...userScopes]); } catch (error) { throw Object.assign(new ConnectionError(String(error?.message || 'This sign-in was refused.').slice(0,600), 'rate_limited'),{httpStatus:429}); }
    const connectionAuthority = connectionId ? captureConnectionAuthority(this.store,existing.id) : null;
    for (const flow of this.store.list('oauthFlows')) if (flow.expiresAt <= this.clock()) { this.store.delete('oauthFlows',flow.id); this.vault.delete(`oauth:${flow.id}`); }
    const state = randomBytes(32).toString('base64url'), flowId = randomBytes(32).toString('base64url'), verifier = randomBytes(48).toString('base64url');
    // A sign-in never outlives the account request or Connect link it belongs to.
    const id = hash(state), expiresAt = Math.min(this.clock() + 10 * 60 * 1000,continuation ? Date.parse(continuation.notAfter) : Infinity,tenantFlow?.notAfter ? Date.parse(tenantFlow.notAfter) : Infinity);
    if (expiresAt <= this.clock()) throw new ConnectionError('This account request has expired. No sign-in was started.', 'invalid_input');
    // A never-request scope an older connection still holds is not carried into the reconnect (T1); the owner sees why.
    const reading = this.access(this.app(appId)), neverRequest = reading.neverRequest, dropped = (existing?.scopes || []).filter(s => neverRequest.includes(s));
    if (dropped.length) this.store.audit({type:'connection.scope_dropped',connectionId:existing.id,appId,scopes:[...new Set(dropped)].sort()});
    // F10.5 (T2): a version 2 flow keeps its level and what it requires: that level's required scopes and every scope asked for by
    // name (Add access, an account request's extras), so only a declined optional or carried scope narrows. A page grant lists none.
    const required = reading.schemaVersion === 2 ? [...new Set([...(chosenLevel === 'read' ? reading.levels.read : reading.levels.full).required,...(requestedScopes || [])])] : null;
    // A reconnect binds the authorization and the sign-in it started from: a renewal keeps the first and changes the second.
    this.store.put('oauthFlows',{id,providerId:definition.providerId,appId,flowIdHash:hash(flowId),expiresAt,...(continuation?{continuationId:continuation.id}:{}),...(tenantFlow?{tenant:tenantFlow}:{}),connectionId:connectionId || null,connectionVersion:existing?.authRevision || null,connectionSignIn:existing?.signInRevision ?? null,...(this.store.authorityEnabled?{connectionAuthority}:{}),label:typeof label === 'string' ? label.slice(0,200) : null,scopes,...(userScopes.length?{userScopes}:{}),...(required?{level:chosenLevel,required}:{}),...(upgrade?{upgrade:{etag:upgrade.etag,scopes:[...upgrade.scopes]}}:{})});
    this.vault.set(`oauth:${id}`,{verifier});
    const url = new URL(definition.authorization.url), separator = definition.authorization.scopeSeparator;
    const parameters = {client_id:this.clientId,redirect_uri:this.redirectUri,response_type:'code',...(scopes.length?{scope:scopes.join(separator)}:{}),...(userScopes.length?{user_scope:userScopes.join(separator)}:{}),...definition.authorization.extraParameters,state,
      ...(definition.authorization.pkce === 'S256' ? {code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'} : {})};
    for (const [key,value] of Object.entries(parameters)) url.searchParams.set(key,value);
    return {authorizationUrl:url.href,expiresAt:new Date(expiresAt).toISOString(),flowId};
  }
  /**
   * What a sign-in asks for, without starting one: the app, the level, the scopes and user scopes its authorization URL
   * names, and the account it reconnects. Writes nothing. start() uses it, and so can a gate that must see the plan first.
   * @param {import('../../contracts/provider.mts').ProviderStartInput} [input]
   * @param {{tenantFlow?: Record<string, unknown>}} [trusted] start()'s own, already checked: a Connect session sign-in.
   */
  plan({connectionId,writeAccess = false,level,appId,scopes:requestedScopes,fullUpgrade = false} = {},trusted = {}) {
    // F10.7 (g6, correction 2): an explicit full upgrade names the account, the full level and no scopes. It asks for the whole
    // full level under any consent policy, so the upgrade card and the sign-in it starts read the same set.
    if (fullUpgrade !== false && (fullUpgrade !== true || !connectionId || level !== 'full' || requestedScopes !== undefined)) throw new ConnectionError('A full upgrade names the account and the full access level, and no scopes.', 'invalid_input');
    // A Connect session sign-in (tenantFlow) plans like a new account: its flow never names a connection. A reconnect or Add access
    // session (F10.4) names the account it signs in again, already checked as the person's own, so that account's scopes carry forward.
    const definition = this.#definition, name = this.name, tenantFlow = trusted?.tenantFlow, accountRef = tenantFlow?.accountRef;
    const existing = connectionId ? this.store.get('connections',connectionId) : accountRef ? this.store.get('connections',accountRef) : null;
    appId = appId || existing?.appId || definition.apps[0].appId;
    const app = this.app(appId), reading = this.access(app);
    // Version 1 keeps its read default (T6). A version 2 sign-in that names no level stays at the level the account
    // holds (read only when it holds read), and a new one starts at the app's default, full: Add access never narrows.
    const chosenLevel = level ?? (writeAccess ? 'full' : reading.schemaVersion === 1 ? 'read' : existing && heldLevel(reading,existing.scopes) === 'read' ? 'read' : 'full');
    if (connectionId && (!existing || existing.appId !== appId || existing.authMethod !== 'oauth' || existing.status === 'pending_confirmation')) throw new ConnectionError(`${name} connection not found for this application.`, 'invalid_input');
    // The account signs in again through the sign-in app that issued it (D8), and only while it is held.
    if (accountRef && (!existing || existing.appId !== appId || existing.authMethod !== 'oauth' || ['pending_confirmation','revoked'].includes(existing.status) || (existing.providerApp?.kind === 'developer' ? existing.providerApp.id : null) !== this.providerAppId)) throw new ConnectionError(`${name} connection not found for this application.`, 'invalid_input');
    // New access must be described by this app's reviewed access. A UI request cannot add arbitrary provider
    // scopes, reuse another application's authority, or ask for a scope the definition never requests (T1).
    const access = this.access(app), belongs = scope => this.belongsToApp(app,scope);
    if (requestedScopes !== undefined && (!Array.isArray(requestedScopes) || requestedScopes.length > MAX_REQUESTED_SCOPES || requestedScopes.some(s => typeof s !== 'string'))) throw new ConnectionError('Additional scopes must come from this application’s discovered permissions.', 'invalid_scope');
    if (requestedScopes?.some(s => access.neverRequest.includes(s))) throw new ConnectionError(`Fabric never asks ${name} for that permission for this application. No sign-in was started.`, 'never_requested');
    if (access.upgradeScopes) {
      // Version 1: the scope must also be documented by this app's discovered interface.
      const documented = new Set((this.store.get('applicationMaps',appId)?.operations || []).flatMap(op => op.requiredScopes || []));
      if (requestedScopes?.some(s => !belongs(s) || !documented.has(s))) throw new ConnectionError('Additional scopes must come from this application’s discovered permissions.', 'invalid_scope');
    } else if (requestedScopes?.some(s => !fullLevelScopes(access).includes(s))) throw new ConnectionError('Additional scopes must come from this application’s full access level.', 'invalid_scope');
    // Preserved and upgraded scopes travel with the credential Fabric keeps: user scopes for a
    // user-credential app, ordinary scopes otherwise. A user-credential app never requests a bot grant.
    const userGrant = this.usesUserScopes(app), asked = this.signInScopes(app,chosenLevel,{fullUpgrade});
    // Version 1 carries every granted scope of the app; version 2 only scopes of the level being requested, so a
    // full-level reconnect never carries a read-level scope such as gmail.readonly.
    const keep = access.upgradeScopes ? belongs : (scope => levelScopes(access,chosenLevel).includes(scope) && !access.neverRequest.includes(scope));
    const carried = [...(existing?.scopes || []).filter(keep),...(requestedScopes || [])];
    const scopes = [...new Set([...definition.authorization.identityScopes,...(userGrant ? [] : [...asked,...carried])])];
    const userScopes = userGrant ? [...new Set([...asked,...carried])] : [];
    return {appId,level:chosenLevel,scopes,userScopes,existing};
  }
  /** @param {{appId: string, accessToken: string, authorize?: () => unknown}} input @returns {Promise<import('../../contracts/provider.mts').ProviderIdentity>} */
  async observeIdentity({appId,accessToken,authorize}) {
    const app = this.app(appId), identity = this.#definition.identity, name = this.name;
    if (!validCredential(accessToken) || !accessToken.trim()) throw new ConnectionError('Enter a valid provider token without spaces.', 'invalid_input');
    const headers = {...this.#definition.apiHeaders,...identity.request.headers,Authorization:`Bearer ${accessToken}`,Accept:'application/json'};
    const request = async (url,allowedOrigins,post = false) => {
      authorize?.();
      let response;
      // Preserve the connection manager's injected requester for identity checks,
      // independently of OAuth token-service request overrides.
      try { response = await this.connections.request({url,headers:post ? {...headers,'Content-Type':'application/x-www-form-urlencoded'} : headers,allowedOrigins,...(post ? {method:'POST',body:''} : {})}); }
      catch { throw new ConnectionError('Provider connection failed. No credentials or provider error body were logged.'); }
      finally { authorize?.(); }
      if (response.status === 401 || response.status === 403) throw new ConnectionError('The provider rejected the credentials or required permission. Reconnect the account.', 'reconnect_required');
      if (response.status < 200 || response.status >= 300 || !response.data || typeof response.data !== 'object') throw new ConnectionError('The provider could not verify this connection. Try again later.');
      return response.data;
    };
    // The definition decides whether an unidentifiable response means the credential is dead.
    const unidentified = () => identity.requireFailure === 'reconnect_required'
      ? new ConnectionError(`${name} rejected the token or returned no account identity. Reconnect the account.`, 'reconnect_required')
      : new ConnectionError(`${name} returned no verifiable account identity.`);
    const data = await request(identity.request.url,this.#origins.identity,identity.request.method === 'POST');
    if (!satisfies(data,identity.require)) throw unidentified();
    // Account IDs must survive exactly; cleaning/truncating malformed subjects
    // could collapse different provider identities into the same local binding.
    const part = value => {
      const text = typeof value === 'string' ? value : identity.id.allowNumbers && Number.isSafeInteger(value) && value > 0 ? String(value) : null;
      if (text === null || !text.trim() || text !== clean(text)) throw unidentified();
      return text;
    };
    // The alternate key applies only when a primary pointer is absent (for example an internal
    // integration has no human owner); a present but malformed primary value still fails.
    const primary = identity.id.pointers.map(pointer => pointerValue(data,pointer));
    const key = identity.alternateId && primary.some(value => value === undefined) ? identity.alternateId : identity.id;
    const accountId = key.pointers.map(pointer => part(pointerValue(data,pointer))).join(key.separator);
    // Observe bounded application access without persisting the provider contents.
    if (app.accessProbe) await request(app.accessProbe.url,[new URL(app.accessProbe.url).origin]);
    const display = identity.displayName.pointers.map(pointer => clean(pointerValue(data,pointer))).find(Boolean) || identity.displayName.fallback;
    const email = identity.email ? clean(pointerValue(data,identity.email)) : '';
    const attributes = Object.fromEntries(Object.entries(identity.attributes).map(([key,pointer]) => [key,clean(pointerValue(data,pointer))]).filter(([,value]) => value));
    return {id:accountId,displayName:display,...(email ? {email} : {}),...attributes};
  }
  clientHeaders(authentication) {
    return authentication === 'basic' ? {Authorization:basic(this.clientId,this.clientSecret,this.#definition.token.quirks.basicEncoding)} : {};
  }
  async tokenRequest(parameters) {
    const token = this.#definition.token, name = this.name;
    // Never a token request with empty client values (a missing secret would otherwise be sent as the text "null").
    if (!this.configured) throw new ConnectionError(`${name} sign-in is not set up here.`, 'not_configured');
    const fields = token.clientAuthentication === 'body' ? {...parameters,client_id:this.clientId,client_secret:this.clientSecret} : {...parameters};
    const headers = {...this.#definition.apiHeaders,'Content-Type':token.encoding === 'json' ? 'application/json' : 'application/x-www-form-urlencoded',Accept:'application/json',...this.clientHeaders(token.clientAuthentication)};
    let response;
    try { response = await this.request({url:token.url,method:'POST',headers,body:token.encoding === 'json' ? JSON.stringify(fields) : new URLSearchParams(fields).toString(),allowedOrigins:this.#origins.token}); }
    catch { throw new ConnectionError(`${name} token service is unreachable. Try again later.`); }
    return this.parseTokens(response);
  }
  /** Named, reviewed response parsers; documented quirks apply only where a definition opts in. */
  parseTokens(response) {
    const token = this.#definition.token, quirks = token.quirks, name = this.name;
    const unavailable = () => new ConnectionError(`${name} token service is temporarily unavailable. Try again later.`);
    const rejected = code => {
      if (code === 'ratelimited') throw unavailable();
      if (token.reconnectErrors.includes(code)) throw new ConnectionError(`${name} authorization expired or was revoked. Reconnect the original account.`, 'reconnect_required');
      throw new ConnectionError(`${name} rejected the authorization request. Check client configuration and consent permissions.`, 'oauth_rejected');
    };
    const errorCode = body => typeof body?.error === 'string' ? body.error : quirks.errorCodeField === 'error-or-code' && typeof body?.code === 'string' ? body.code : undefined;
    // Rate limits and provider outages are transient, not a configuration or consent problem.
    if (response.status === 429 || response.status >= 500) throw unavailable();
    if (response.status >= 400) rejected(errorCode(response.data));
    let data = response.data;
    if (quirks.errorInSuccessBody && data && typeof data === 'object' && data.access_token === undefined && typeof data.error === 'string') rejected(data.error);
    if (token.responseFormat === 'slack-v2') {
      // Slack reports failures as ok:false in a 2xx body; its documented refresh example omits ok.
      if (!data || typeof data !== 'object' || data.ok === false || (data.ok !== true && data.access_token === undefined)) rejected(data?.error);
      // A user-scoped grant arrives under authed_user; Fabric acts as the user when one is present.
      if (data.authed_user && typeof data.authed_user === 'object' && data.authed_user.access_token !== undefined) data = {...data.authed_user};
    }
    if (!data || !validCredential(data.access_token) || !token.acceptedTokenTypes.includes(String(data.token_type).toLowerCase())) throw new ConnectionError(`${name} returned an invalid token response.`);
    const lifetime = data.expires_in === undefined || data.expires_in === null ? null : Number(data.expires_in);
    if ((token.requireExpiry || lifetime !== null) && (!Number.isFinite(lifetime) || lifetime <= 0 || lifetime > token.maxLifetimeSeconds)) throw new ConnectionError(`${name} returned an invalid token response.`);
    const refreshToken = data.refresh_token === null && quirks.nullRefreshMeansNone ? undefined : data.refresh_token;
    if (refreshToken !== undefined && !validCredential(refreshToken)) throw new ConnectionError(`${name} returned an invalid refresh credential.`);
    return {accessToken:data.access_token,refreshToken,expiresAt:lifetime === null ? null : this.clock() + lifetime*1000,scopes:splitScopes(data.scope,token.scopeSeparator)};
  }
  /** Removes an unfinished flow (a superseded or closed account-request sign-in). */
  discardFlow(flowIdHash) {
    if (typeof flowIdHash !== 'string') return;
    for (const flow of this.store.list('oauthFlows')) if (flow.flowIdHash === flowIdHash) { this.store.delete('oauthFlows',flow.id); this.vault.delete(`oauth:${flow.id}`); }
  }
  /**
   * @param {import('../../contracts/provider.mts').ProviderCallbackInput} input
   * @param {{admitContinuation?: (flow: Record<string, unknown>) => void}} [trusted] In-process only. A flow started
   * for a missing-access handoff completes only when this synchronous check admits it, before the token
   * exchange and again before credentials are persisted.
   * @returns {Promise<import('../../contracts/provider.mts').ProviderConnection>}
   */
  async callback({state,code,error,flowId},trusted = {}) {
    const definition = this.#definition, name = this.name;
    if (typeof state !== 'string' || state.length > 256 || typeof flowId !== 'string' || flowId.length > 256) throw new ConnectionError('Invalid OAuth state or browser session. Start the connection again.', 'invalid_state');
    const id = hash(state), flow = this.store.get('oauthFlows',id);
    // Flows recorded before provider routing existed were Google-only and expire within ten minutes.
    const owner = flow && (Object.hasOwn(flow,'providerId') ? flow.providerId : 'google');
    if (!flow || owner !== definition.providerId || (flow.tenant?.providerAppId ?? null) !== this.providerAppId || flow.expiresAt <= this.clock() || !equal(flow.flowIdHash,hash(flowId))) throw new ConnectionError('OAuth state expired, was already used, or does not match this browser.', 'invalid_state');
    const privateFlow = this.vault.get(`oauth:${id}`);
    // Consume before network I/O: a callback cannot be replayed, including after token exchange failure.
    this.store.delete('oauthFlows',id); this.vault.delete(`oauth:${id}`);
    if (error) throw new ConnectionError(`${name} consent was declined or could not be completed.`, 'consent_denied');
    const appId = flow.appId || definition.apps[0].appId;
    this.app(appId);
    if (!privateFlow?.verifier || typeof code !== 'string' || !code || code.length > 8192) throw new ConnectionError('Missing authorization code. Start the connection again.', 'invalid_code');
    // Missing historical provenance is not current consent. A new-account flow
    // explicitly records null; reconnect flows bind the exact existing generation.
    let authority = null;
    if (this.store.authorityEnabled) {
      if (!Object.hasOwn(flow,'connectionAuthority') || (flow.connectionId ? flow.connectionAuthority?.id !== flow.connectionId : flow.connectionAuthority !== null)) throw new ConnectionError(`Connection authority changed while ${name} consent was open. Start reconnect again.`, 'connection_changed');
      authority = flow.connectionAuthority;
      if (authority) assertConnectionAuthority(this.store,authority);
    }
    const continuationId = Object.hasOwn(flow,'continuationId') ? flow.continuationId : null;
    if (continuationId !== null) {
      if (typeof trusted?.admitContinuation !== 'function') throw new ConnectionError('This sign-in belongs to an account request and can only complete through it.', 'invalid_state');
      trusted.admitContinuation(flow);
    }
    let tokens;
    try { tokens = await this.tokenRequest({grant_type:'authorization_code',code,redirect_uri:this.redirectUri,...(definition.authorization.pkce === 'S256' ? {code_verifier:privateFlow.verifier} : {})}); }
    finally { if (authority) assertConnectionAuthority(this.store,authority); }
    // T1, before anything is verified or stored: a grant carrying a scope Fabric never holds (on any app's never list, or
    // granting one) activates nothing, and the flow is already spent. A provider whose revocation removes the whole grant
    // (Google) is never asked, whatever this adapter's policy; a token a live account here holds is left alone (N9).
    const refused = this.refused(tokens.scopes);
    if (refused.length) {
      const providerGrant = this.revocationCovers() === 'grant' ? 'may_remain' : this.#tokenHeldHere(tokens) ? 'shared' : await this.revokeTokens(tokens) ? 'revoked' : 'may_remain';
      this.store.audit({type:'connection.scope_refused',providerId:definition.providerId,appId,connectionId:flow.connectionId ?? flow.tenant?.accountRef ?? null,providerGrant,scopes:refused});
      throw Object.assign(new ConnectionError(this.#refusedWords(appId,providerGrant),'never_requested'),{providerGrant});
    }
    // T2: a version 2 flow requires its level's required scopes and every scope asked for by name; a version 1 flow, and one
    // stored before F10.5, every app scope it asked for, ordinary or user. A scope a granted parent grants is held.
    const reading = this.access(this.app(appId)), effective = new Set(effectiveScopes(reading,tokens.scopes ?? []));
    const asked = [...flow.scopes.filter(s => !definition.authorization.identityScopes.includes(s)),...(flow.userScopes || [])], leveled = Array.isArray(flow.required);
    const required = leveled ? flow.required : asked;
    if (required.length && (!tokens.scopes || required.some(s => !effective.has(s)))) throw new ConnectionError(this.#notGrantedWords(appId,leveled ? required.filter(s => !tokens.scopes || !effective.has(s)) : null), 'insufficient_scope');
    // What the sign-in asked for and did not get narrows the account; the grant says which (a page grant names no scopes).
    const grant = leveled && reading.grant !== 'pages' ? {level:flow.level,missing:[...new Set(asked.filter(s => !effective.has(s)))].sort()} : null;
    // A renewal keeps the authorization but not the sign-in: of two reconnects started from the same state, only the first lands.
    const reconnected = flow.connectionId ? this.store.get('connections',flow.connectionId) : null;
    if (flow.connectionId && (reconnected?.authRevision !== flow.connectionVersion || !sameSignIn(reconnected,{signInRevision:flow.connectionSignIn}))) throw new ConnectionError(`Connection changed while ${name} consent was open. Start reconnect again.`, 'connection_changed');
    // An account-request sign-in creates a quarantined connection that only the owner's confirmation activates. What the sign-in asked
    // for (`planned`, F10.7 decision 9) is a first sign-in's card: anything else it granted starts at Ask.
    const planned = [...new Set(asked)].sort();
    try {
      // A Connect session sign-in: the owner comes from the flow alone, never from whichever browser finishes it.
      if (flow.tenant) return await this.connections.establishOAuth({tokens,label:flow.label,appId,initialStatus:'pending_confirmation',
        origin:{kind:'connect_session',sessionId:flow.tenant.sessionId},user:{subjectId:flow.tenant.subjectId,userRecordId:flow.tenant.userRecordId},planned,
        providerApp:this.providerAppId ? {kind:'developer',id:this.providerAppId} : {kind:'shared'},...(grant ? {grant} : {})});
      return await this.connections.establishOAuth({tokens,label:flow.label,connectionId:flow.connectionId,appId,...(flow.upgrade ? {upgrade:flow.upgrade} : {}),...(grant ? {grant} : {}),planned,
        ...(continuationId !== null ? {initialStatus:'pending_confirmation',origin:{kind:'continuation',continuationId},beforePersist:() => trusted.admitContinuation(flow)} : {})});
    } catch (error) {
      // The account request closed while the provider was issuing tokens: they are dropped here. A provider whose revocation
      // removes the whole grant (Google) is never asked (T1): that would sign the same account out of every app on this sign-in
      // client. The owner learns whether a live account here, in any app, holds that grant. Other providers revoke the token,
      // unless a live account here holds that same token (N9): Slack can issue a person's token again.
      if (continuationId !== null && error?.code === 'continuation_closed') {
        const grant = this.revocationCovers() === 'grant', shared = grant ? typeof error.identityId === 'string' &&
          this.store.list('connections').some(other => this.connections.providerOf(other) === definition.providerId && !['revoked','pending_confirmation'].includes(other.status) && other.identity?.id === error.identityId) : this.#tokenHeldHere(tokens);
        error.providerGrant = shared ? 'shared' : grant ? 'may_remain' : await this.revokeTokens(tokens) ? 'revoked' : 'may_remain';
      }
      throw error;
    }
  }
  /** @param {string} id @returns {Promise<import('../../contracts/provider.mts').ProviderTokens>} */
  async refresh(id) {
    const authority = captureConnectionAuthority(this.store,id), stored = this.store.get('connections',id);
    // One refresh per authority and sign-in: a renewal keeps the generation and the authorization, so a caller after one
    // never joins a refresh that began before it.
    const key = JSON.stringify([id,authority?.generation ?? null,stored?.authRevision ?? null,stored?.signInRevision ?? null]);
    let operation = this.refreshing.get(key);
    if (!operation) { operation = this.refreshOnce(id); this.refreshing.set(key,operation); }
    try {
      const tokens = await operation;
      if (authority) assertConnectionAuthority(this.store,authority);
      return tokens;
    } catch (error) {
      if (authority) assertConnectionAuthority(this.store,authority);
      throw error;
    } finally { if (this.refreshing.get(key) === operation) this.refreshing.delete(key); }
  }
  /** Confirms the stored credential still belongs to the bound account; throws otherwise. */
  async verifyIdentity(record,accessToken,authority) {
    const identity = await this.connections.observe(record.appId,accessToken,undefined,authority?()=>assertConnectionAuthority(this.store,authority):undefined);
    if (authority) assertConnectionAuthority(this.store,authority);
    if (identity.id !== record.identity.id) throw new ConnectionError(`${this.name} account identity changed during refresh. Reconnect the original account.`, 'reconnect_required');
  }
  async refreshOnce(id) {
    const definition = this.#definition, name = this.name;
    const record = this.store.get('connections',id);
    if (!record || record.authMethod !== 'oauth' || record.status === 'revoked') throw new ConnectionError(`${name} connection is not active.`, 'reconnect_required');
    this.app(record.appId);
    const authority = captureConnectionAuthority(this.store,id);
    let old = this.vault.get(id);
    if (!old?.accessToken) throw new ConnectionError('Credentials are missing. Reconnect the original account.', 'reconnect_required');
    const disconnected = () => new ConnectionError(`${name} connection was disconnected.`, 'reconnect_required');
    const unchanged = (current,currentTokens,expected) => current.authRevision === record.authRevision && sameSignIn(current,record) && currentTokens.accessToken === expected.accessToken && currentTokens.refreshToken === expected.refreshToken;
    // T7 in every store: a renewal never widens what the owner approved (grantCeiling, or the scopes held by a record from
    // before ceilings). Such credentials are never delivered, and the account needs a sign-in, which shows the upgrade.
    const beyond = (scopes,current) => { const ceiling = current.grantCeiling ?? current.scopes ?? []; return (scopes || []).some(scope => !ceiling.includes(scope)); };
    const wider = () => new ConnectionError(`${name} granted more access during renewal than the owner approved. Reconnect the original account to review it.`, 'reconnect_required');
    // T1 (F10.7, decision 1): a record from before step 7 can hold a scope Fabric now never requests (Gmail's full mailbox, say). Its
    // credential is never delivered, at use or at renewal, and the provider is never asked to revoke: the account needs a sign-in,
    // whose reconnect drops the scope with its audit. Checked before an unexpired credential is handed back and before a pending pair.
    const holdsRefused = (...lists) => lists.some(scopes => this.refused(scopes).length > 0);
    const noLongerHeld = () => new ConnectionError(`${name} access on this account includes a permission Fabric no longer holds. Reconnect the account to drop it. Fabric did not ask ${name} to revoke anything.`, 'reconnect_required');
    try {
      if (holdsRefused(record.scopes,old.scopes)) throw noLongerHeld();
      if (old.identityPending) {
        // A rotated pair saved before its identity check is not delivered until that check passes.
        await this.verifyIdentity(record,old.accessToken,authority);
        const current = this.store.get('connections',id), currentTokens = this.vault.get(id);
        if (!current || current.status === 'revoked' || !currentTokens) throw disconnected();
        if (!unchanged(current,currentTokens,old)) throw new ConnectionError('Credentials changed during renewal. Retry the operation.', 'connection_changed');
        if (beyond(old.scopes,current)) throw wider();
        const {identityPending,...verified} = old;
        this.vault.set(id,verified); old = verified;
      }
      // Providers that issue non-expiring access tokens record a null expiry.
      if (old.expiresAt === null || old.expiresAt > this.clock() + 60000) return old;
      if (!this.configured || !definition.refresh.supported || !old.refreshToken) throw new ConnectionError(`${name} access expired and cannot be renewed. Reconnect the original account.`, 'reconnect_required');
      const fresh = await this.tokenRequest({grant_type:'refresh_token',refresh_token:old.refreshToken});
      if (authority) assertConnectionAuthority(this.store,authority);
      // A rotated refresh credential replaces the old one; an omitted one is kept only when the provider documents reuse.
      const tokens = {...fresh,refreshToken:fresh.refreshToken || (definition.refresh.keepPreviousWhenOmitted ? old.refreshToken : undefined),scopes:fresh.scopes || old.scopes};
      // A renewal that brings such a scope back, even within the ceiling, is not delivered or recorded either.
      if (holdsRefused(tokens.scopes)) throw noLongerHeld();
      let expected = old;
      if (fresh.refreshToken && fresh.refreshToken !== old.refreshToken) {
        // The provider has just invalidated the old single-use refresh credential. Save the new
        // pair before any further I/O so a transient failure cannot strand the account, but keep
        // it undeliverable until the identity check below passes.
        const current = this.store.get('connections',id), currentTokens = this.vault.get(id);
        if (!current || current.status === 'revoked' || !currentTokens) throw disconnected();
        if (!unchanged(current,currentTokens,old)) throw new ConnectionError('Credentials changed during renewal. Retry the operation.', 'connection_changed');
        expected = {...tokens,identityPending:true};
        this.vault.set(id,expected);
      }
      await this.verifyIdentity(record,fresh.accessToken,authority);
      const current = this.store.get('connections',id);
      // A disconnect occurring during I/O must win over token refresh.
      const currentTokens = this.vault.get(id);
      if (!current || current.status === 'revoked' || !currentTokens) throw disconnected();
      if (!unchanged(current,currentTokens,expected)) throw new ConnectionError('Credentials changed during renewal. Retry the operation.', 'connection_changed');
      const scopeSet = value => JSON.stringify([...new Set(value || [])].sort());
      if (scopeSet(tokens.scopes) !== scopeSet(current.scopes)) {
        if (beyond(tokens.scopes,current)) throw wider();
        // A grant that lost scopes says so once per sign-in and set of scopes lost (F10.4).
        const lost = narrowedBy(current.scopes,tokens.scopes);
        if (lost.length) raise(this.store,{connection:current,kind:'grant_narrowed',subjectKey:scopesSubject(lost),now:this.clock()});
        // Narrower (or back within the ceiling) is a renewal. Where the generation guards authority, persist the change but
        // do not deliver credentials from the superseded request; the next request renews under the new authority.
        if (authority) {
          this.store.put('connections',{...current,...(tokens.scopes ? {scopes:tokens.scopes} : {}),updatedAt:new Date(this.clock()).toISOString()});
          throw new ConnectionError(`${name} permissions changed during renewal. Retry the operation.`, 'connection_changed');
        }
      }
      this.vault.set(id,tokens);
      // Providers without OAuth scopes (Notion) report none; never persist an undefined field.
      this.store.put('connections',{...current,expiresAt:tokens.expiresAt,...(tokens.scopes ? {scopes:tokens.scopes} : {}),refreshAvailable:Boolean(tokens.refreshToken),updatedAt:new Date(this.clock()).toISOString()});
      this.store.audit({type:'connection.renewed',connectionId:id,appId:record.appId});
      if (authority) assertConnectionAuthority(this.store,authority);
      return tokens;
    } catch (error) {
      if (authority) assertConnectionAuthority(this.store,authority);
      const current = this.store.get('connections',id);
      if (current && current.authRevision === record.authRevision && sameSignIn(current,record) && current.status !== 'revoked' && error.code === 'reconnect_required') {
        const marked = {...current,status:'reconnect_required',error:error.message,updatedAt:new Date(this.clock()).toISOString()};
        this.store.put('connections',marked);
        raise(this.store,{connection:marked,kind:'reconnect_required',now:this.clock()});
      }
      throw error;
    }
  }
  /** @param {string} id @returns {Promise<import('../../contracts/provider.mts').ProviderRevokeResult>} */
  /** Asks the provider to revoke issued tokens. Best effort: true only when the provider confirms. */
  async revokeTokens(tokens) {
    const revocation = this.#definition.revocation;
    // N9: the one choke point for every remote revoke (disconnect, a closed account request, a rejected account).
    if (this.revocationPolicy === 'local_only') return false;
    if (!revocation || ((revocation.clientAuthentication !== 'none' || revocation.url.includes('{client_id}')) && !this.configured)) return false;
    const credential = revocation.preferredToken === 'refresh' ? tokens?.refreshToken || tokens?.accessToken : tokens?.accessToken || tokens?.refreshToken;
    if (!credential) return false;
    const fields = {[revocation.tokenParameter]:credential,...(revocation.clientAuthentication === 'body' ? {client_id:this.clientId,client_secret:this.clientSecret} : {})};
    const headers = {...this.#definition.apiHeaders,'Content-Type':revocation.encoding === 'json' ? 'application/json' : 'application/x-www-form-urlencoded',...(revocation.encoding === 'json' ? {Accept:'application/json'} : {}),...this.clientHeaders(revocation.clientAuthentication)};
    try {
      const response = await this.request({url:revocationUrl(this.#definition,this.clientId),method:revocation.method,headers,body:revocation.encoding === 'json' ? JSON.stringify(fields) : new URLSearchParams(fields).toString(),allowedOrigins:this.#origins.revocation});
      // A 2xx alone is not confirmation for providers that report failure in the body (Slack ok:false).
      return revocation.successStatuses.includes(response.status) && satisfies(response.data,revocation.successRequire);
    } catch { return false; /* never expose provider errors */ }
  }
  /**
   * F10.19 (B6, spec line 1174): asks the provider whether one account's access token is active and which scope it lists. Notion only
   * (INTROSPECTION); any other provider refuses with nothing sent. Client-authenticated like revokeTokens(): HTTP Basic with the
   * integration's client id and secret, the token alone in a JSON body, the definition's API headers, and only the token origin allowed.
   * Returns exactly {active, scope}, scope a string or null: never the token, its issue time or the provider's request id. It stores and
   * audits nothing. Never a route: the live-test harness calls it once, before N0 (step 20).
   * @param {string} id @returns {Promise<{active: boolean, scope: string | null}>}
   */
  async introspect(id) {
    const name = this.name, url = Object.hasOwn(INTROSPECTION,this.providerId) ? INTROSPECTION[this.providerId] : null;
    if (!url) throw new ConnectionError(`${name} has no reviewed token introspection.`, 'invalid_input');
    if (!this.configured) throw new ConnectionError(`${name} sign-in is not set up here.`, 'not_configured');
    const record = this.store.get('connections',id);
    if (!record || record.authMethod !== 'oauth' || record.status === 'revoked' || this.connections.providerOf(record) !== this.providerId) throw new ConnectionError(`${name} connection not found.`, 'invalid_input');
    const token = this.vault.get(id)?.accessToken;
    if (!validCredential(token)) throw new ConnectionError('Credentials are missing. Reconnect the original account.', 'reconnect_required');
    const headers = {...this.#definition.apiHeaders,'Content-Type':'application/json',Accept:'application/json',...this.clientHeaders('basic')};
    let response;
    try { response = await this.request({url,method:'POST',headers,body:JSON.stringify({token}),allowedOrigins:this.#origins.token}); }
    catch { throw new ConnectionError(`${name} token introspection is unreachable. Try again later.`); }
    const data = response?.data;
    if (response?.status !== 200 || !data || typeof data !== 'object' || typeof data.active !== 'boolean') throw new ConnectionError(`${name} did not answer the token introspection.`);
    return {active:data.active,scope:typeof data.scope === 'string' ? clean(data.scope,2000) : null};
  }
  /** The access a new connection gets by default: the full level as sign-in asks for it under the consent policy. */
  defaultScopes(app) {return this.signInScopes(app,'full');}
  /** What a provider revocation removes: the whole grant for this client, or only the presented token. */
  revocationCovers() {return this.#definition.revocation?.covers ?? null;}
  /**
   * Disconnects one account. `owner` is the end user in a developer environment (ignored in the single-owner runtime);
   * `remote: false` disconnects here only. Under a local_only policy the provider is never asked, with one fixed message.
   * F10.4 (B1): where a revocation removes the whole grant (Google), it also signs out the siblings: the same account on the
   * same sign-in client in any other app here. Until `confirmSiblings: true` they are named and nothing changes. After a
   * confirmed revoke they need a sign-in (health fields only, so a renewal keeps their settings) and come back as `affected`.
   */
  async revoke(id,owner,{remote,confirmSiblings} = {}) {
    const revocation = this.#definition.revocation, name = this.name;
    const record = this.connections.get(id,owner);
    if (!record || record.authMethod !== 'oauth') throw new ConnectionError(`${name} connection not found.`, 'invalid_input');
    this.app(record.appId);
    const tokens = this.vault.get(id);
    // Listed before anything here changes, and only for a revoke that will reach the provider.
    const asks = this.revocationPolicy !== 'local_only' && remote !== false && revocation?.covers === 'grant' && Boolean(tokens?.accessToken || tokens?.refreshToken)
      && !((revocation.clientAuthentication !== 'none' || revocation.url.includes('{client_id}')) && !this.configured);
    const siblings = asks ? this.siblings(this.store.get('connections',id),owner) : [];
    if (siblings.length && confirmSiblings !== true) throw Object.assign(new ConnectionError(this.#siblingWords(record,siblings), 'confirm_required'),
      {siblings:siblings.map(item => ({connectionId:item.id,appId:item.appId,displayName:clean(item.identity?.displayName || item.label,120),waiting:item.status === 'pending_confirmation'}))});
    // Local disconnection happens immediately, even if provider revocation subsequently fails.
    const connection = this.connections.revoke(id,owner);
    if (this.revocationPolicy === 'local_only') return {connection,remoteRevoked:false,message:this.providerAppId ? `Disconnected here. Revoking at ${name} would sign this account out of everything that uses this app's grant, so Fabric did not ask; remove it in ${name} account settings if needed.` : `Disconnected here. Removing Fabric in your ${name} account would also sign this ${name} account out of every other app that uses Fabric's shared ${name} sign-in.`};
    if (remote === false) return {connection,remoteRevoked:false,message:`Disconnected here. Fabric did not ask ${name} to revoke access; remove it in ${name} account settings if needed.`};
    const remaining = `remove the grant in ${name} account settings if needed.`;
    if (!revocation) return {connection,remoteRevoked:false,message:`Disconnected locally. ${name} does not offer remote revocation here; ${remaining}`};
    // Never send a token with empty client credentials or an unfilled client path.
    if ((revocation.clientAuthentication !== 'none' || revocation.url.includes('{client_id}')) && !this.configured) return {connection,remoteRevoked:false,message:`Disconnected locally. ${name} revocation was not attempted because ${name} sign-in is not configured; ${remaining}`};
    const remoteRevoked = await this.revokeTokens(tokens);
    if (!remoteRevoked) return {connection,remoteRevoked,message:`Disconnected locally. ${name} revocation was not confirmed; ${remaining}`};
    const affected = this.#signedOut(siblings,record,owner);
    // Say exactly what the provider removed: the whole grant, or only the presented token. A whole grant always signs the
    // account out of every app on this sign-in client, siblings here or not, and the words say so (F10.4).
    const everywhere = `${name} also signed ${clean(record.identity?.displayName,120) || 'this account'} out of every other app that uses this ${name} sign-in client, ${this.connections.deployment?.kind === 'tenant' ? 'including any that Fabric cannot see from here' : 'including other Fabric folders and the 4188 prototype'}.`;
    return {connection,remoteRevoked,revokedScope:revocation.covers,message:revocation.covers === 'grant' ? `Disconnected locally and ${name} revocation confirmed. ${everywhere}` : `Disconnected locally and ${name} revoked this connection's token. ${name} may still list the app authorization; remove it in ${name} account settings to revoke it completely.`,
      ...(affected.length ? {affected} : {})};
  }
  /** The accounts a grant-wide revoke of `record` signs out too: not disconnected, on this provider and the same provider app, the
   *  same provider account, and the same end user. */
  siblings(record,owner) {
    const appKey = item => item?.providerApp?.kind === 'developer' ? `developer:${item.providerApp.id}` : 'shared';
    return this.store.list('connections').filter(other => other.id !== record.id && other.status !== 'revoked' && this.connections.providerOf(other) === this.providerId
      && other.identity?.id === record.identity?.id && appKey(other) === appKey(record) && ownedBy(other,owner,this.connections.deployment));
  }
  #appName(appId) { try { return this.connections.app(appId)?.name || appId; } catch { return appId; } }
  /** N9: whether a live account here, on this provider and this sign-in app (pending accounts included), holds one of these
   *  tokens. Slack can hand one person the same token again, so revoking it would sign that account out too. In constant time. */
  #tokenHeldHere(tokens) {
    const digest = value => createHash('sha256').update(value).digest(), values = item => [item?.accessToken, item?.refreshToken].filter(value => typeof value === 'string' && value.length > 0).map(digest);
    const mine = values(tokens), appKey = item => item?.providerApp?.kind === 'developer' ? `developer:${item.providerApp.id}` : 'shared', ours = this.providerAppId ? `developer:${this.providerAppId}` : 'shared';
    if (!mine.length) return false;
    return this.store.list('connections').some(other => other.status !== 'revoked' && this.connections.providerOf(other) === this.providerId && appKey(other) === ours
      && values(this.vault.get(other.id)).some(theirs => mine.some(value => timingSafeEqual(value, theirs))));
  }
  /** T1 (B3): why a refused sign-in connected nothing, what became of the provider's grant, and the way back. Never names a
   *  scope or quotes the provider; the address comes from the reviewed definition. */
  #refusedWords(appId,providerGrant) {
    const name = this.name, settingsUrl = this.#definition.revocation?.settingsUrl, remove = settingsUrl ? `at ${settingsUrl}` : `in your ${name} account settings`;
    const refused = `${name} granted a permission Fabric never holds for ${this.#appName(appId)}, so nothing was connected.`;
    if (this.revocationCovers() === 'grant') return `${refused} Fabric did not ask ${name} to revoke it, because that would sign this account out of every app that uses this sign-in client. To remove it, remove Fabric ${remove}.`;
    const token = providerGrant === 'revoked' ? `Fabric revoked the new ${name} token.` : providerGrant === 'shared' ? `Fabric left the new ${name} token alone, because an account here still uses it.`
      : this.revocationPolicy === 'local_only' || !this.#definition.revocation ? `Fabric did not ask ${name} to revoke the new token.` : `Fabric asked ${name} to revoke the new token, and ${name} did not confirm it.`;
    return `${refused} ${token} ${name} keeps that permission on Fabric's authorization. Remove Fabric ${remove}, then connect again.`;
  }
  /** T2: a version 2 sign-in names the permissions its missing required scopes leave without access, through the embedding's
   *  explainer (at most five, and how many more); version 1 and anything the explainer cannot say keep the plain words. */
  #notGrantedWords(appId,missing) {
    const name = this.name, plain = `${name} did not grant all the requested application permissions. No connection was activated.`;
    const {labels,more} = missing?.length && this.connections.explainMissing ? this.connections.explainMissing(appId,missing) : {labels:[],more:0};
    return labels.length ? `${name} did not grant permissions that ${this.#appName(appId)} needs: ${labels.join('; ')}${more ? ` and ${more} more` : ''}. No connection was activated.` : plain;
  }
  #siblingWords(record,siblings) {
    const name = this.name, names = siblings.map(item => `${this.#appName(item.appId)}${item.status === 'pending_confirmation' ? ' (not yet confirmed)' : ''}`);
    const listed = names.length > 1 ? `${names.slice(0,-1).join(', ')} and ${names.at(-1)}` : names[0];
    const unseen = this.connections.deployment?.kind === 'tenant' ? 'which Fabric cannot see from here' : 'including other Fabric folders and the 4188 prototype, which this Fabric cannot see';
    return `Disconnecting ${this.#appName(record.appId)} at ${name} also signs ${clean(record.identity?.displayName,120) || 'this account'} out of ${listed} here, and out of every other app that uses this ${name} sign-in client, ${unseen}. Confirm to disconnect everywhere, or disconnect here only.`;
  }
  /** After a confirmed grant-wide revoke: a waiting sibling is erased here and any other needs a sign-in, unless it changed meanwhile. */
  #signedOut(siblings,record,owner) {
    const affected = [], reason = `Disconnected together with ${this.#appName(record.appId)}.`;
    for (const sibling of siblings) {
      const current = this.store.get('connections',sibling.id);
      if (!current || current.status === 'revoked' || current.authRevision !== sibling.authRevision || !sameSignIn(current,sibling)) continue;
      if (current.status === 'pending_confirmation') this.connections.revoke(current.id,owner);
      else {
        const marked = {...current,status:'reconnect_required',error:reason,updatedAt:new Date(this.clock()).toISOString()};
        this.store.put('connections',marked);
        raise(this.store,{connection:marked,kind:'reconnect_required',now:this.clock()});
      }
      affected.push({connectionId:current.id,appId:current.appId});
    }
    return affected;
  }
}

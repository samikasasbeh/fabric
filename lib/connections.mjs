import { readFileSync } from 'node:fs';
import { LOCAL_DEPLOYMENT, endUser, ownedBy, stampOwner } from './tenant/deployment.mjs';
import { randomUUID } from 'node:crypto';
import { safeRequest } from './network.mjs';
import { GoogleProvider } from './providers/google.mjs';
import { OAuth2Provider } from './providers/oauth2.mjs';
import { definitionFor, reviewedProviderIds } from './providers/definitions.mjs';
import { TrustedProviderRegistry } from './providers/registry.mts';
import { ConnectionError } from './providers/errors.mjs';
import { captureConnectionAuthority, assertConnectionAuthority, sameSignIn } from './authority-guard.mjs';
import { raise, consentDue, narrowedBy, scopesSubject } from './connection-notices.mjs';
import { forgetPages } from './connection-notes.mjs';

/** F10.19: whether an app's reviewed sign-in grants pages, not scopes (Notion). */
const pageGrant = (provider, appId) => { try { return provider.access(provider.app(appId))?.grant === 'pages'; } catch { return false; } };
export { ConnectionError } from './providers/errors.mjs';

export const catalog = Object.freeze(JSON.parse(readFileSync(new URL('../catalog/apps.json', import.meta.url), 'utf8')).map(app => Object.freeze(app)));
const byId = new Map(catalog.map(app => [app.id, app]));
export function catalogFor(store) {
  return [...catalog.map(app => ({...app,apiOrigins:app.allowedOrigins,webOrigins:app.browserOrigins || []})), ...store.list('applications').filter(app => !byId.has(app.id)).map(app => ({...app,allowedOrigins:app.apiOrigins || [],browserOrigins:app.webOrigins || [],browserCapable:Boolean(app.webOrigins?.length),authMethods:[...(app.identityProbe ? ['token'] : []),...(app.webOrigins?.length ? ['browser'] : [])]}))];
}
function pointer(value, path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.length > 500) return undefined;
  for (const part of path.slice(1).split('/').map(p => p.replace(/~1/g,'/').replace(/~0/g,'~'))) {
    if (!value || typeof value !== 'object' || !Object.hasOwn(value,part) || ['__proto__','prototype','constructor'].includes(part)) return undefined;
    value = value[part];
  }
  return value;
}
const clean = (value, limit = 200) => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g,'').slice(0,limit) : '';
function publicConnection(value) {
  if (!value) return null;
  const allowed = ['id','appId','label','driver','status','identity','allowedOrigins','createdAt','updatedAt','lastCheckedAt','error','scopes','authMethod','expiresAt','refreshAvailable','transport','persistentSession','grantExpiresAt','bridgeVersion','sessionScope'];
  return Object.fromEntries(allowed.filter(k => value[k] !== undefined).map(k => [k, structuredClone(value[k])]));
}
/** F10.5, trusted from the provider callback only: what a sign-in asked for and did not get, as the level it asked for and the
 *  app scopes missing, sorted and once each, bounded like the scopes the authority projection reads. */
const validGrant = grant => Boolean(grant) && typeof grant === 'object' && !Array.isArray(grant) && Object.keys(grant).sort().join() === 'level,missing' && ['full','read'].includes(grant.level)
  && Array.isArray(grant.missing) && grant.missing.length <= 1000 && grant.missing.every((scope,index) => typeof scope === 'string' && scope.length > 0 && scope.length <= 2000 && (index === 0 || grant.missing[index - 1] < scope));
function assertToken(token) { if (typeof token !== 'string' || !token.trim() || token.length > 16000 || /\s/.test(token)) throw new ConnectionError('Enter a valid provider token without spaces.', 'invalid_input'); }
function assertResponse(response) {
  if (response.status === 401 || response.status === 403) throw new ConnectionError('The provider rejected the credentials or required permission. Reconnect the account.', 'reconnect_required');
  if (response.status < 200 || response.status >= 300 || !response.data || typeof response.data !== 'object') throw new ConnectionError('The provider could not verify this connection. Try again later.');
}
export class ConnectionManager {
  /** deployment: LOCAL_DEPLOYMENT (one owner, nothing stored) or a tenant deployment, where every connection is owned by one end user (F03.2). */
  constructor({store,vault,request = safeRequest,clock = Date.now,deployment = LOCAL_DEPLOYMENT}) {
    if (typeof clock !== 'function') throw new Error('A connection clock function is required.');
    this.store = store; this.vault = vault; this.request = request; this.clock = clock; this.oauth = null; this.oauthBound = new Set(); this.deployment = deployment;
    // Identity probes work before OAuth is configured. The explicit setOAuthManager /
    // setOAuthProvider facades replace these unconfigured trusted adapters.
    const unconfigured = {store,vault,connections:this,request,clock,clientId:'',clientSecret:'',consentDays:null};
    this.providers = new TrustedProviderRegistry(new GoogleProvider(unconfigured),...reviewedProviderIds().filter(id => id !== 'google').map(id => new OAuth2Provider(definitionFor(id),unconfigured)));
  }
  setOAuthManager(oauth) { this.providers.bindGoogleOAuth(oauth); this.oauth = oauth; this.oauthBound.add('google'); }
  /** Binds the operator-configured adapter for one reviewed non-Google provider. */
  setOAuthProvider(provider) { this.providers.bind(provider); this.oauthBound.add(provider.providerId); }
  /** Legacy OAuth records predate provider routing and were always Google. */
  providerOf(record) { return record?.providerId ?? this.providers.providerFor(record?.appId) ?? 'google'; }
  /** F03.8, trusted in-process only: resolves a developer's own provider app to its adapter, or null when it is not usable here. */
  setDeveloperAdapters(resolve) { this.developerAdapters = resolve; }
  /** F10.4, trusted in-process only: the callback wall (T7), called as (previous, stored, confirmedScopes) right after an upgrade is stored. */
  setUpgradeGuard(guard) { this.upgradeGuard = guard; }
  /** F10.5, trusted in-process only: names the permissions a sign-in leaves without access, as (appId, scopes) => [{groupId, label}]. */
  setAccessExplainer(explain) { this.accessExplainer = explain; }
  /** At most five of those permissions' labels and how many more; none when nothing is installed or it fails. Never throws. */
  explainMissing(appId, scopes) {
    try {
      const rows = this.accessExplainer?.(appId,[...scopes]), labels = [...new Set((Array.isArray(rows) ? rows : []).map(row => clean(row?.label,120).trim()).filter(Boolean))];
      return {labels:labels.slice(0,5),more:Math.max(0,labels.length - 5)};
    } catch { return {labels:[],more:0}; }
  }
  /** F10.5: what an OAuth account's grant holds, read through its provider's reviewed definition: its scopes and every scope a
   *  granted parent grants. Any other record, or any failure, reads the scopes as stored, the narrower reading. */
  effectiveScopes(record) {
    if (record?.authMethod !== 'oauth' || !Array.isArray(record.scopes)) return record?.scopes;
    try { return this.providers.resolve({providerId:this.providerOf(record),appId:record.appId}).effectiveScopes(record.appId,record.scopes); } catch { return record.scopes; }
  }
  oauthProvider(record) {
    const providerId = this.providerOf(record);
    // An account stays on the provider app that issued it (D8): refresh and revoke use that client, never the
    // environment's current default, and never a shared app in its place.
    if (record?.providerApp?.kind === 'developer') {
      const adapter = this.developerAdapters?.(record.providerApp.id) ?? null;
      if (!adapter || adapter.providerId !== providerId) throw new ConnectionError('This account\'s sign-in app is not set up here.', 'setup_required');
      return adapter;
    }
    let provider;
    try { provider = this.providers.resolve({providerId,appId:record.appId}); }
    catch { throw new ConnectionError('This OAuth connection belongs to an unsupported provider. Reconnect the account.', 'reconnect_required'); }
    if (!this.oauthBound.has(providerId)) throw new ConnectionError(`${provider.name} OAuth is not configured.`, 'reconnect_required');
    return provider;
  }
  app(id) { return catalogFor(this.store).find(app => app.id === id); }
  /** In a developer environment, only the given end user's connections; another user's look like nothing. */
  list(owner) { return this.store.list('connections').filter(record => ownedBy(record,owner,this.deployment)).map(publicConnection); }
  get(id, owner) { const record = this.store.get('connections',id); return record && ownedBy(record,owner,this.deployment) ? publicConnection(record) : publicConnection(null); }
  /** The trusted owner a write needs in a developer environment; none in the single-owner runtime. */
  #owner(owner) {
    if (this.deployment.kind === 'local') return null;
    if (!owner) throw new ConnectionError('A connection in a developer environment needs its end user.', 'invalid_input');
    return endUser(owner);
  }
  #reconnectable(old, owner) { return !old || ownedBy(old,owner,this.deployment); }
  headers(appId, accessToken) {
    // Provider API headers (versions, user agent) come from the reviewed auth definition.
    const providerId = this.providers.providerFor(appId);
    const apiHeaders = providerId ? this.providers.resolve({providerId,appId}).definition.apiHeaders : {};
    return { ...apiHeaders, Authorization: `Bearer ${accessToken}`, Accept: 'application/json' };
  }
  async observe(appId, accessToken, binding, authorize) {
    assertToken(accessToken);
    let app = this.app(appId);
    if (!app) throw new ConnectionError('Unknown application.', 'invalid_input');
    if (binding && !byId.has(appId)) app = {...app,allowedOrigins:binding.allowedOrigins,identityProbe:binding.identityProbe};
    const headers = this.headers(appId,accessToken);
    const request = async options => {
      authorize?.();
      let response;
      try { response = await this.request({...options, headers:{...headers,...options.headers}, allowedOrigins:options.allowedOrigins || app.allowedOrigins}); }
      catch { throw new ConnectionError('Provider connection failed. No credentials or provider error body were logged.'); }
      finally { authorize?.(); }
      assertResponse(response);return response.data;
    };
    // Built-in applications verify identity through their reviewed auth definition,
    // for OAuth and pasted developer tokens alike.
    if (this.providers.supportsApp(appId)) return this.providers.resolve({providerId:this.providers.providerFor(appId),appId}).observeIdentity({appId,accessToken,...(authorize?{authorize}:{})});
    if (!byId.has(appId) && app.identityProbe) {
      const {path,idPointer,displayNamePointer} = app.identityProbe;
      if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.includes('\\') || path.includes('#') || !app.allowedOrigins.length) throw new ConnectionError('Custom API requires a safe relative identity endpoint.', 'invalid_input');
      let endpoint;
      try { endpoint = new URL(path,app.allowedOrigins[0]); } catch { throw new ConnectionError('Invalid custom identity endpoint.', 'invalid_input'); }
      if (endpoint.origin !== app.allowedOrigins[0]) throw new ConnectionError('Identity endpoint is outside the selected application.', 'invalid_input');
      const data = await request({url:endpoint.href});
      const idValue = pointer(data,idPointer), nameValue = pointer(data,displayNamePointer);
      if (!['string','number'].includes(typeof idValue) || !String(idValue) || String(idValue).length > 200 || String(idValue).includes(accessToken) || (typeof nameValue === 'string' && nameValue.includes(accessToken))) throw new ConnectionError('Custom API returned no safe stable account identity.');
      return {id:clean(String(idValue)),displayName:clean(nameValue) || clean(String(idValue))};
    }
    throw new ConnectionError('This application requires another connection route.', 'invalid_input');
  }
  async connect({appId,token,label,connectionId,user}) {
    const ownerOf = this.#owner(user);
    const app = this.app(appId);
    if (!app?.authMethods.includes('token')) throw new ConnectionError('Direct token connection is not supported for this application.', 'invalid_input');
    assertToken(token);
    const old = connectionId ? this.store.get('connections',connectionId) : null;
    if (connectionId && (!old || old.appId !== appId || old.authMethod !== 'token' || !this.#reconnectable(old,ownerOf))) throw new ConnectionError('Connection does not match this application.', 'invalid_input');
    const authority = old ? captureConnectionAuthority(this.store,old.id) : null;
    let identity;
    try { identity = await this.observe(appId,token,undefined,authority?()=>assertConnectionAuthority(this.store,authority):undefined); }
    finally { if (authority) assertConnectionAuthority(this.store,authority); }
    if (old && old.identity.id !== identity.id) throw new ConnectionError('Account mismatch: reconnect using the original account or create a separate connection.', 'account_mismatch');
    if (old && this.store.get('connections',old.id)?.authRevision !== old.authRevision) throw new ConnectionError('Connection changed during verification. Start reconnect again.', 'connection_changed');
    const id = old?.id || randomUUID(), now = new Date(this.clock()).toISOString();
    this.vault.set(id,{accessToken:token});
    const record = {id,appId,label:clean(label) || old?.label || app.name,driver:'http',status:'ready',identity,allowedOrigins:[...app.allowedOrigins],...(app.identityProbe ? {identityProbe:structuredClone(app.identityProbe)} : {}),authMethod:'token',createdAt:old?.createdAt || now,updatedAt:now,lastCheckedAt:now};
    this.store.put('connections',{...(ownerOf ? stampOwner(record,ownerOf) : record),authRevision:randomUUID()});
    this.store.audit({type:'connection.connected',connectionId:id,appId});
    return publicConnection(record);
  }
  // initialStatus, origin, beforePersist, upgrade (what the owner confirmed on the upgrade card), grant (what a version 2 sign-in
  // asked for and did not get, F10.5) and planned (the app scopes the sign-in asked for, F10.7) are trusted in-process options from
  // the provider callback only.
  async establishOAuth({tokens,label,connectionId,appId = 'google-calendar',providerId,initialStatus,origin,beforePersist,user,providerApp,upgrade,grant,planned}) {
    const ownerOf = this.#owner(user);
    if (upgrade !== undefined && (!connectionId || !upgrade || typeof upgrade.etag !== 'string' || !Array.isArray(upgrade.scopes) || upgrade.scopes.some(scope => typeof scope !== 'string'))) throw new ConnectionError('Invalid upgrade sign-in.', 'invalid_input');
    if (grant !== undefined && !validGrant(grant)) throw new ConnectionError('Invalid sign-in grant.', 'invalid_input');
    if (planned !== undefined && (!Array.isArray(planned) || planned.length > 1000 || planned.some(scope => typeof scope !== 'string' || !scope || scope.length > 2000))) throw new ConnectionError('Invalid sign-in plan.', 'invalid_input');
    // A quarantined account comes from an account request (continuation) or, in a developer environment, a Connect session.
    const quarantineOrigin = origin?.kind === 'continuation' || (origin?.kind === 'connect_session' && this.deployment.kind === 'tenant' && /^cs_[a-z2-7]{26}$/.test(origin.sessionId ?? ''));
    if (initialStatus !== undefined && (initialStatus !== 'pending_confirmation' || !quarantineOrigin || connectionId)) throw new ConnectionError('Invalid quarantined connection request.', 'invalid_input');
    // Which provider app issued the account: trusted, from a developer environment's Connect session sign-in only.
    if (providerApp !== undefined && (origin?.kind !== 'connect_session' || this.deployment.kind !== 'tenant' || !(providerApp?.kind === 'shared' || (providerApp?.kind === 'developer' && /^pa_[a-z2-7]{26}$/.test(providerApp.id ?? ''))))) throw new ConnectionError('Invalid provider app.', 'invalid_input');
    const owner = providerId ?? this.providers.providerFor(appId);
    let provider;
    try { provider = this.providers.resolve({providerId:owner,appId}); } catch { throw new ConnectionError('Unsupported OAuth application.', 'invalid_input'); }
    const app = byId.get(appId), name = provider.name;
    if (!app) throw new ConnectionError('Unsupported OAuth application.', 'invalid_input');
    const old = connectionId ? this.store.get('connections',connectionId) : null;
    if (connectionId && (!old || old.appId !== appId || old.authMethod !== 'oauth' || old.status === 'pending_confirmation' || this.providerOf(old) !== owner || !this.#reconnectable(old,ownerOf))) throw new ConnectionError(`${name} connection not found.`, 'invalid_input');
    const authority = old ? captureConnectionAuthority(this.store,old.id) : null;
    let identity;
    try { identity = await this.observe(appId,tokens.accessToken,undefined,authority?()=>assertConnectionAuthority(this.store,authority):undefined); }
    finally { if (authority) assertConnectionAuthority(this.store,authority); }
    if (old && old.identity.id !== identity.id) throw new ConnectionError(`Account mismatch: choose the original ${name} account or create a separate connection.`, 'account_mismatch');
    const current = old ? this.store.get('connections',old.id) : null;
    if (old && (current?.authRevision !== old.authRevision || !sameSignIn(current,old))) throw new ConnectionError('Connection changed during verification. Start reconnect again.', 'connection_changed');
    const id = old?.id || randomUUID(), now = new Date(this.clock()).toISOString();
    // A provider can omit refresh_token on subsequent consent; retain it only for the verified SAME
    // account, only where the provider documents reuse, and only while the new access still expires.
    const previous = old ? this.vault.get(id) : null;
    const keep = provider.definition.refresh.keepPreviousWhenOmitted && tokens.expiresAt !== null;
    const stored = {...tokens,refreshToken:tokens.refreshToken || (keep ? previous?.refreshToken : undefined)};
    // A closed account request must leave no credential and no connection behind.
    try { beforePersist?.(); } catch (error) { if (error && typeof error === 'object') error.identityId = identity.id; throw error; }
    // T7: a renewal is the same account signing in again within the widest set the owner approved (grantCeiling, or the
    // scopes a record from before ceilings holds), on the same origins. It keeps the authorization and every field that is
    // not health, so saved settings, client grants and the generation survive. Anything else is an upgrade, a new
    // authorization whose ceiling grows to include what it granted. A sign-in after a disconnect starts again from nothing. The
    // ceiling is read raw, without implications (F10.5): a parent in it does not cover its child, so that sign-in is an upgrade.
    const granted = tokens.scopes, ceiling = current?.grantCeiling ?? current?.scopes ?? [];
    // F10.19 (spec "Share more pages", F10.4 question 10): a page grant (Notion) names no scopes. Signing in again on the same account and
    // origins, with no scope held or granted, is a renewal: the owner widens the page set in the provider's own picker.
    const pages = Boolean(current) && pageGrant(provider,appId) && !(current.scopes ?? []).length && !(granted ?? []).length;
    const kind = !current || current.status === 'revoked' ? 'connected' : (pages || current.scopes && granted && granted.every(scope => ceiling.includes(scope))) && JSON.stringify(current.allowedOrigins) === JSON.stringify(app.allowedOrigins) ? 'reconsented' : 'upgraded';
    // F10.5: a record holds only its current sign-in's grant; a sign-in that carries none leaves none.
    const signIn = {signInRevision:randomUUID(),signedInAt:now}, declined = grant ? {level:grant.level,missing:[...grant.missing]} : null;
    this.vault.set(id,stored);
    if (kind === 'reconsented') {
      const renewed = {...current,label:clean(label) || current.label || app.name,status:'ready',error:null,identity,scopes:granted,expiresAt:tokens.expiresAt,refreshAvailable:Boolean(stored.refreshToken),updatedAt:now,lastCheckedAt:now,...signIn};
      if (declined) renewed.grant = declined; else delete renewed.grant;
      // F10.19: a page grant reports no scopes, so its renewal stores none (a stored undefined is not plain JSON).
      if (!granted) delete renewed.scopes;
      this.store.put('connections',renewed);
      this.store.audit({type:'connection.reconsented',connectionId:id,appId});
      // A renewal that grants less is still a renewal; it says so once, so the rows that need more access are explained. A scope
      // the person declined at the provider is explained by the not-granted notice instead (F10.5).
      const lost = narrowedBy(current.scopes,granted).filter(scope => !declined?.missing.includes(scope));
      if (lost.length) raise(this.store,{connection:renewed,kind:'grant_narrowed',subjectKey:scopesSubject(lost),now:this.clock()});
      return publicConnection(renewed);
    }
    const record = {id,appId,providerId:owner,...(providerApp ? {providerApp:providerApp.kind === 'developer' ? {kind:'developer',id:providerApp.id} : {kind:'shared'}} : {}),label:clean(label) || old?.label || app.name,driver:'http',status:initialStatus ?? 'ready',...(origin ? {origin:origin.kind === 'connect_session' ? {kind:'connect_session',sessionId:origin.sessionId} : {kind:'continuation',continuationId:origin.continuationId}} : {}),...(origin?.kind === 'connect_session' && planned ? {planned:[...planned]} : {}),identity,allowedOrigins:[...app.allowedOrigins],authMethod:'oauth',...(tokens.scopes ? {scopes:tokens.scopes,grantCeiling:[...new Set([...(kind === 'upgraded' ? ceiling : []),...tokens.scopes])].sort()} : {}),expiresAt:tokens.expiresAt,refreshAvailable:Boolean(stored.refreshToken),createdAt:old?.createdAt || now,updatedAt:now,lastCheckedAt:now,...(declined ? {grant:declined} : {}),...signIn};
    this.store.put('connections',{...(ownerOf ? stampOwner(record,ownerOf) : record),authRevision:randomUUID()});
    // The callback wall, before any await: nothing an upgrade granted beyond the card the owner confirmed runs at Allow, whatever the provider granted.
    if (kind === 'upgraded') this.upgradeGuard?.(current,this.store.get('connections',id),upgrade?.scopes);
    // F10.7 (decision 9): a first sign-in has no card, so what it asked for stands in for one, and whatever else it granted starts at
    // Ask. An account that waits for a confirm keeps what it asked for (a Connect session), and is pinned when it is activated.
    if (kind === 'connected' && planned && !initialStatus) this.upgradeGuard?.(null,this.store.get('connections',id),planned);
    this.store.audit({type:kind === 'upgraded' ? 'connection.upgraded' : 'connection.connected',connectionId:id,appId});
    return publicConnection(record);
  }
  async check(id, owner) {
    const record = this.store.get('connections',id);
    if (!record || record.status === 'revoked' || !ownedBy(record,owner,this.deployment)) throw new ConnectionError('Connection is not active.', 'invalid_input');
    // Health checks never touch a quarantined account; only the owner's confirmation activates it.
    if (record.status === 'pending_confirmation') throw new ConnectionError('This account is waiting for the owner to confirm it.', 'invalid_input');
    if (record.driver !== 'http') throw new ConnectionError('Use the route-specific connection check.', 'invalid_input');
    const authority = captureConnectionAuthority(this.store,id);
    // A response started under an older authorization, or before a renewal (which keeps the authorization), can neither
    // certify nor disable the account.
    const superseded = fresh => !fresh || fresh.authRevision !== record.authRevision || !sameSignIn(fresh,record);
    try {
      let tokens = this.vault.get(id), provider = null;
      if (record.authMethod === 'oauth') {
        provider = this.oauthProvider(record);
        tokens = await provider.refresh(id);
        if (authority) assertConnectionAuthority(this.store,authority);
      }
      if (!tokens?.accessToken) throw new ConnectionError('Credentials are missing. Reconnect the account.', 'reconnect_required');
      const identity = await this.observe(record.appId,tokens.accessToken,record,authority?()=>assertConnectionAuthority(this.store,authority):undefined);
      if (authority) assertConnectionAuthority(this.store,authority);
      if (identity.id !== record.identity.id) throw new ConnectionError('Provider account identity changed. Reconnect the original account.', 'reconnect_required');
      const fresh = this.store.get('connections',id);
      if (superseded(fresh)) return this.get(id,owner);
      if (fresh.status === 'revoked') throw new ConnectionError('Connection was revoked.', 'reconnect_required');
      const now = new Date(this.clock()).toISOString(), checked = {...fresh,status:'ready',identity,updatedAt:now,lastCheckedAt:now,error:null};
      this.store.put('connections',checked);
      // A consent that ends after a set number of days (Google's Testing mode) is announced a day before, once per sign-in.
      if (consentDue(checked,{consentDays:provider?.consentDays,now:this.clock()})) raise(this.store,{connection:checked,kind:'consent_expiring',now:this.clock()});
    } catch (error) {
      if (authority) assertConnectionAuthority(this.store,authority);
      const fresh = this.store.get('connections',id);
      if (superseded(fresh)) return this.get(id,owner);
      if (error?.code === 'setup_required') throw error;
      if (fresh.status !== 'revoked') {
        const marked = {...fresh,status:error.code === 'reconnect_required' ? 'reconnect_required' : 'unavailable',error:error instanceof ConnectionError ? error.message : 'Connection could not be verified.',updatedAt:new Date(this.clock()).toISOString()};
        this.store.put('connections',marked);
        if (marked.status === 'reconnect_required') raise(this.store,{connection:marked,kind:'reconnect_required',now:this.clock()});
      }
    }
    this.store.audit({type:'connection.checked',connectionId:id,status:this.get(id,owner).status});
    return this.get(id,owner);
  }
  revoke(id, owner) {
    const record = this.store.get('connections',id);
    if (!record || !ownedBy(record,owner,this.deployment)) throw new ConnectionError('Connection not found.', 'invalid_input');
    // Validate committed authority before removing the separately stored secret.
    captureConnectionAuthority(this.store,id);
    this.vault.delete(id);
    this.store.put('connections',{...record,status:'revoked',authRevision:randomUUID(),refreshAvailable:false,error:null,updatedAt:new Date(this.clock()).toISOString()});
    // F10.19: the account's page count goes with it (lib/connection-notes.mjs).
    forgetPages(this.store,id);
    this.store.audit({type:'connection.disconnected',connectionId:id,appId:record.appId});
    return this.get(id,owner);
  }
  async credentials(id) {
    const record = this.store.get('connections',id);
    if (!record || record.driver !== 'http' || record.status !== 'ready') throw new ConnectionError('A verified active API connection is required.', 'reconnect_required');
    const authority = captureConnectionAuthority(this.store,id);
    let tokens = this.vault.get(id);
    if (record.authMethod === 'oauth') {
      try { tokens = await this.oauthProvider(record).refresh(id); }
      finally { if (authority) assertConnectionAuthority(this.store,authority); }
    }
    if (!tokens?.accessToken || this.store.get('connections',id)?.status !== 'ready') throw new ConnectionError('Credentials unavailable. Reconnect the account.', 'reconnect_required');
    if (authority) assertConnectionAuthority(this.store,authority);
    // Never let editing a custom catalogue record silently expand an existing account grant.
    return {headers:this.headers(record.appId,tokens.accessToken),allowedOrigins:[...record.allowedOrigins]};
  }
}

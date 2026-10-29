// F03.3 (docs/F03-DEVELOPER-LAYER.md D3, D4, N9, N11): Fabric's shared sign-in apps, per environment. The operator
// gives every shared app's settings explicitly (never read silently from the machine's environment variables). Which
// shared apps an environment may use follows D3; on Fabric's shared Google app a disconnect never revokes at Google,
// because one person's grant there spans every developer that uses it (D4).
import {createHash, randomUUID, timingSafeEqual} from 'node:crypto';
import {signInOf} from './views.mjs';
import {TenantError, notFound, invalid} from './errors.mjs';
import {newId} from './registry.mjs';
import {validClientId, validName, TenantRecordError} from '../../contracts/tenant.mts';
import {definitionFor} from '../providers/definitions.mjs';
import {relayed, relayAppRedirect} from '../oauth-relay.mjs';

/** D3: what each provider's shared app may serve, by environment kind. */
export const SHARED_RULES = Object.freeze({
  github: Object.freeze({development: 'shared', production: 'shared'}),
  notion: Object.freeze({development: 'shared_after_relay', production: 'shared'}),
  google: Object.freeze({development: 'shared_testing', production: 'developer_only'}),
  slack: Object.freeze({development: 'developer_only', production: 'developer_only'}),
});
const NAMES = {github: 'GitHub', notion: 'Notion', google: 'Google', slack: 'Slack'};
/** At most this many distinct Google identities per environment on the shared Testing-mode client (M10). */
export const SHARED_GOOGLE_IDENTITY_BUDGET = 10;

const explicit = value => typeof value === 'string' && value.trim().length > 0;
const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
/** A stable pa_ id for Fabric's shared app of a provider: listed, but never accepted where a developer app is chosen (L6). */
export const sharedAppId = providerId => `pa_${[...createHash('sha256').update(`fabric-shared:${providerId}`).digest()].slice(0, 26).map(byte => BASE32[byte & 31]).join('')}`;
/** The registry key of one provider client: never the client id itself. */
export const clientIdHash = (providerId, clientId) => createHash('sha256').update(JSON.stringify([providerId, clientId])).digest('hex');
const SECRET = /^[\x21-\x7e]{1,1024}$/;
const vaultId = id => `providerApp:${id}`;
const DISTRIBUTIONS = ['internal', 'distributed', 'marketplace'];

export class ProviderApps {
  #settings;
  /**
   * @param {{settings?: Record<string, {clientId?: string, clientSecret?: string, consentScreenName?: string, relayReady?: boolean}>}} options
   * Operator settings per provider. A shared app counts as configured only when both client values are explicit.
   */
  constructor({settings = {}, registry = null, stores = null, origin = null, relay = null, fabricClientIds = [], definitions = definitionFor} = {}) {
    this.#settings = Object.freeze(Object.fromEntries(Object.entries(settings).map(([providerId, value]) => [providerId, Object.freeze({...value})])));
    Object.assign(this, {registry, stores, origin, relay, fabricClientIds, definitions});
  }

  // ---- F03.8: developers' own sign-in apps (docs/F03-DEVELOPER-LAYER.md section 5.4, D2, D8, N8, N11, N14, L5, L9) ----
  /**
   * H10: Fabric's own client ids (the shared apps and any local ones named here) are held by Fabric in the registry, so
   * no developer can ever register or prove them. Explicit inputs only; never the machine's environment variables.
   */
  seedFabricClientIds() {
    if (!this.registry) return;
    const ids = [...Object.entries(this.#settings).filter(([, value]) => explicit(value.clientId)).map(([providerId, value]) => ({providerId, clientId: value.clientId})), ...this.fabricClientIds];
    for (const {providerId, clientId} of ids) this.registry.claimClientId(clientIdHash(providerId, clientId), 'fabric');
  }
  #env(scope) { return this.stores.open(scope); }
  #definition(providerId) {
    let definition;
    try { definition = this.definitions(providerId); } catch { throw new TenantError(422, 'unknown_provider', 'Fabric has no sign-in for that provider.'); }
    if (definition.reviewStatus !== 'reviewed' || !SHARED_RULES[providerId]) throw new TenantError(422, 'provider_not_reviewed', 'Fabric has not reviewed this provider for developers\' own apps yet.');
    return definition;
  }
  /** D2: the exact callback a developer registers at the provider. Slack and Notion go through the relay page. */
  redirectUri(providerId, id) {
    const definition = this.definitions(providerId);
    if (relayed(definition)) return this.relay?.base ? relayAppRedirect(this.relay.base, providerId, id) : null;
    return `${this.origin}/api/oauth/${providerId}/apps/${id}/callback`;
  }
  /** unverified until its first successful sign-in, then verified; disabled once another environment proved the same client. */
  status(record, env) {
    if (record.status === 'verified') return 'verified';
    const owner = this.registry.clientIdOwner(record.clientIdHash);
    return owner && owner !== env.repository.scopeKey ? 'disabled' : 'unverified';
  }
  /** L5: accounts of this environment that use the app, waiting ones included (they still need its client to be dropped). */
  accountsUsing(env, id) {
    return env.repository.list('connections').filter(record => record?.providerApp?.kind === 'developer' && record.providerApp.id === id && record.status !== 'revoked').length;
  }
  #view(env, record) {
    return {id: record.id, kind: 'developer', providerId: record.providerId, clientId: record.clientId, consentScreenName: record.consentScreenName, redirectUri: this.redirectUri(record.providerId, record.id),
      publishing: record.publishing, ...(record.consentDays !== undefined ? {consentDays: record.consentDays} : {}), ...(record.distribution !== undefined ? {distribution: record.distribution} : {}),
      status: this.status(record, env), accountsUsing: this.accountsUsing(env, record.id), createdAt: record.createdAt, ...(record.verifiedAt ? {verifiedAt: record.verifiedAt} : {})};
  }
  /** What the consent sheet says about the sign-in app chosen for an app here: the developer's consent screen name, or null (shared). */
  sheetApp(scope, environment, appId) {
    const chosen = environment?.apps?.[appId]?.providerApp;
    const record = typeof chosen === 'string' && chosen.startsWith('pa_') && this.stores ? this.developer(scope, chosen) : null;
    return record ? {kind: 'developer', consentScreenName: record.consentScreenName} : null;
  }
  /**
   * F10.7 (g4, correction 3): what a sign-in through one provider app asks for, by the definition's consent policy: a developer's own
   * app under its record's publishing state, Fabric's shared app under Testing, as its adapter signs in. 'full' where the definition
   * has no policy (version 1 always asks for the whole level).
   */
  consentMode(providerId, record = null) {
    return this.definitions(providerId).consentPolicy?.[record?.kind === 'developer' ? record.publishing : 'testing'] ?? 'full';
  }
  /** The consent mode of the sign-in app the consent sheet names for `appId` here (sheetApp()): the environment's choice for new accounts. */
  sheetConsentMode(scope, environment, appId) {
    const signIn = signInOf(appId), chosen = environment?.apps?.[appId]?.providerApp;
    if (!signIn) return 'full';
    return this.consentMode(signIn.providerId, typeof chosen === 'string' && chosen.startsWith('pa_') && this.stores ? this.developer(scope, chosen) : null);
  }
  /** One of this environment's developer apps, or null: another environment's id reads exactly like an unknown one. */
  developer(scope, id) {
    if (typeof id !== 'string' || !/^pa_[a-z2-7]{26}$/.test(id)) return null;
    const record = this.#env(scope).repository.get('providerApps', id);
    return record?.kind === 'developer' ? record : null;
  }
  /** The client secret of one of this environment's developer apps, or null when missing. */
  secret(scope, id) {
    const value = this.#env(scope).vault.get(vaultId(id));
    return value && typeof value.clientSecret === 'string' && SECRET.test(value.clientSecret) ? value.clientSecret : null;
  }
  #fields(body, allowed) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw invalid('The body must be a JSON object.');
    const unknown = Object.keys(body).find(key => !allowed.includes(key));
    if (unknown) throw invalid(`Unknown field: ${unknown.slice(0, 40)}.`);
    return body;
  }
  #checked(providerId, body, record = {}) {
    const out = {};
    if ('consentScreenName' in body) out.consentScreenName = validName(body.consentScreenName, 'consentScreenName');
    if ('publishing' in body) { if (!['testing', 'production'].includes(body.publishing)) throw invalid('publishing is testing or production.'); out.publishing = body.publishing; }
    if ('consentDays' in body) {
      if (providerId !== 'google') throw invalid('consentDays applies to Google apps only.');
      if (!Number.isSafeInteger(body.consentDays) || body.consentDays < 1 || body.consentDays > 365) throw invalid('consentDays is a whole number of days from 1 to 365.');
      out.consentDays = body.consentDays;
    }
    if ('distribution' in body) {
      if (providerId !== 'slack') throw invalid('distribution applies to Slack apps only.');
      if (!DISTRIBUTIONS.includes(body.distribution)) throw invalid(`distribution is ${DISTRIBUTIONS.join(', ')}.`);
      out.distribution = body.distribution;
    }
    if ('clientSecret' in body && (typeof body.clientSecret !== 'string' || !SECRET.test(body.clientSecret))) throw invalid('clientSecret must be 1 to 1024 printable characters without spaces.');
    void record;
    return out;
  }
  #audit(env, caller, type, record, fields) {
    env.repository.audit({type, providerAppId: record.id, providerId: record.providerId, ...(fields ? {fields} : {}), byKey: caller.keyId, serviceClientId: caller.serviceClientId});
  }
  /** Shared apps D3 allows here (no client id) and this environment's own apps (section 5.4). */
  list(caller, environment) {
    const env = this.#env(caller.scope);
    const shared = Object.keys(SHARED_RULES).filter(providerId => SHARED_RULES[providerId][environment.kind] !== 'developer_only' && this.shared(providerId).configured).map(providerId => {
      const record = this.shared(providerId);
      return {id: sharedAppId(providerId), kind: 'shared', providerId, consentScreenName: record.consentScreenName, redirectUri: null, publishing: record.publishing ?? 'production', status: 'verified',
        accountsUsing: env.repository.list('connections').filter(item => item?.providerId === providerId && (item.providerApp?.kind ?? 'shared') === 'shared' && item.status !== 'revoked').length};
    });
    const own = env.repository.list('providerApps').filter(record => record?.kind === 'developer').sort((a, b) => a.createdAt < b.createdAt ? -1 : 1).map(record => this.#view(env, record));
    return {providerApps: [...shared, ...own]};
  }
  /** POST /v1/provider-apps: the secret goes to the environment's vault only; the answer is the exact address to register. */
  create(caller, body) {
    this.#fields(body, ['providerId', 'clientId', 'clientSecret', 'consentScreenName', 'publishing', 'consentDays', 'distribution']);
    if (typeof body.providerId !== 'string') throw invalid('Send the providerId.');
    this.#definition(body.providerId);
    let clientId;
    try { clientId = validClientId(body.clientId); } catch (error) { throw invalid(error instanceof TenantRecordError ? error.message : 'clientId is not valid.'); }
    if (body.clientSecret === undefined) throw invalid('Send the clientSecret.');
    if (body.consentScreenName === undefined) throw invalid('Send the consentScreenName people see at the provider.');
    const checked = this.#checked(body.providerId, body), env = this.#env(caller.scope), hash = clientIdHash(body.providerId, clientId);
    // N8: a client id Fabric holds, or one another environment proved, is taken; the answer never says where.
    const owner = this.registry.clientIdOwner(hash);
    if (owner && owner !== env.repository.scopeKey) throw new TenantError(409, 'client_already_registered', 'This client id is already registered.');
    if (env.repository.list('providerApps').some(record => record?.clientIdHash === hash)) throw new TenantError(409, 'client_already_registered', 'This client id is already registered.');
    const record = {id: newId('providerApp'), kind: 'developer', providerId: body.providerId, clientId, clientIdHash: hash, publishing: 'testing', ...checked, revision: randomUUID(), status: 'unverified', createdAt: this.registry.now()};
    env.vault.set(vaultId(record.id), {clientSecret: body.clientSecret});
    env.repository.put('providerApps', record);
    this.#audit(env, caller, 'provider_app.created', record);
    const providerApp = this.#view(env, record);
    return {status: 201, body: {providerApp, redirectUri: providerApp.redirectUri}};
  }
  /** PATCH /v1/provider-apps/:id: the client id never changes; a new client is a new provider app. */
  update(caller, id, body) {
    this.#fields(body, ['clientSecret', 'consentScreenName', 'publishing', 'consentDays']);
    const record = this.developer(caller.scope, id);
    if (!record) throw notFound();
    const checked = this.#checked(record.providerId, body), env = this.#env(caller.scope);
    if (body.clientSecret !== undefined) env.vault.set(vaultId(record.id), {clientSecret: body.clientSecret});
    const next = {...record, ...checked, revision: randomUUID()};
    env.repository.put('providerApps', next);
    this.#audit(env, caller, 'provider_app.updated', next, Object.keys(body).sort());
    return this.#view(env, next);
  }
  /** DELETE /v1/provider-apps/:id: refused while accounts use it or an app setting selects it. */
  remove(caller, id, environment) {
    const record = this.developer(caller.scope, id);
    if (!record) throw notFound();
    const env = this.#env(caller.scope), accountsUsing = this.accountsUsing(env, record.id);
    if (accountsUsing) throw new TenantError(409, 'in_use', 'Accounts still use this provider app; they stay on the app that connected them.', {accountsUsing});
    const selectedBy = Object.entries(environment.apps || {}).filter(([, setting]) => setting?.providerApp === record.id).map(([appId]) => appId).sort();
    if (selectedBy.length) throw new TenantError(409, 'in_use', 'An app in this environment signs in through this provider app; choose another first.', {accountsUsing: 0, selectedBy});
    env.vault.delete(vaultId(record.id));
    env.repository.delete('providerApps', record.id);
    this.registry.releaseClientId(record.clientIdHash, env.repository.scopeKey);
    this.#audit(env, caller, 'provider_app.deleted', record);
    return {status: 204};
  }
  /** The shared app's public record; never its secret. */
  shared(providerId) {
    const value = this.#settings[providerId] || {};
    return Object.freeze({kind: 'shared', providerId, configured: explicit(value.clientId) && explicit(value.clientSecret), consentScreenName: explicit(value.consentScreenName) ? value.consentScreenName : 'Fabric',
      ...(providerId === 'google' ? {publishing: 'testing', testing: {maxUsers: 100, expiresAfterDays: 7}} : {})});
  }
  /** The client values for building a sign-in adapter, or null; never a fallback to process environment variables. */
  credentials(providerId) {
    const value = this.#settings[providerId] || {};
    return explicit(value.clientId) && explicit(value.clientSecret) ? {clientId: value.clientId, clientSecret: value.clientSecret} : null;
  }
  /** Whether an app can be connected in this environment through Fabric's shared app, and why not. */
  availability(appId, environment) {
    const signIn = signInOf(appId);
    if (!signIn) return {state: 'unavailable', reason: 'This app has no reviewed sign-in.'};
    const providerId = signIn.providerId, rule = SHARED_RULES[providerId]?.[environment.kind], name = NAMES[providerId] || providerId;
    const chosen = environment.apps?.[appId]?.providerApp;
    if (typeof chosen === 'string' && chosen.startsWith('pa_')) return this.#developerAvailability(environment, providerId, chosen, name);
    if (!rule || rule === 'developer_only') return {state: 'unavailable', reason: `Fabric's shared ${name} app is not available in ${environment.kind}; register your own ${name} app and choose it for this app.`};
    if (!this.shared(providerId).configured) return {state: 'setup_required', reason: `Fabric's operator has not set up the shared ${name} app yet.`};
    // A provider that refuses loopback callbacks (Notion) signs in only through the HTTPS relay, and no runtime builds
    // that address for Fabric's shared app yet: until one does, the app is not ready, whatever relayReady says.
    if (relayed(this.definitions(providerId))) return {state: 'setup_required', reason: `Fabric's shared ${name} app needs its HTTPS callback relay, which this runtime does not have yet.`};
    if (rule === 'shared_after_relay' && this.#settings[providerId]?.relayReady !== true) return {state: 'setup_required', reason: `The shared ${name} app needs its callback relay for this environment first.`};
    if (rule === 'shared_testing') return {state: 'ready', notice: `Testing mode: each person's Google address must be added as a test user (at most 100 across all developers), sign-ins expire every 7 days, and at most ${SHARED_GOOGLE_IDENTITY_BUDGET} Google accounts per environment.`};
    return {state: 'ready'};
  }
  /** A developer's own app is ready only when it is this environment's, not disabled, has its secret, and (Slack, Notion) the relay forwards it. */
  #developerAvailability(environment, providerId, id, name) {
    const scope = {organizationId: environment.organizationId, projectId: environment.projectId, environmentId: environment.id};
    const record = this.registry && this.stores ? this.developer(scope, id) : null;
    if (!record || record.providerId !== providerId) return {state: 'setup_required', reason: `The chosen ${name} app is not registered in this environment.`};
    if (this.status(record, this.#env(scope)) === 'disabled') return {state: 'setup_required', reason: `This ${name} client id is registered in another environment; register a client of your own.`};
    if (!this.secret(scope, id)) return {state: 'setup_required', reason: `The ${name} app's client secret is missing; send it again.`};
    if (relayed(this.definitions(providerId)) && !(this.relay?.base && this.relay.appsReady === true)) return {state: 'setup_required', reason: `${name} sign-in through your own app needs Fabric's callback relay, which is not ready yet.`};
    return {state: 'ready', providerApp: {kind: 'developer', id}};
  }
  /**
   * N9: whether another account in this environment, on the same provider and the same provider app, still holds one
   * of these tokens (pending accounts included). Slack and Notion can hand one person the same token again, so such a
   * token is only erased here; revoking it would sign the other account out too. Compared by digest in constant time.
   */
  tokenHeldElsewhere(env, record, tokens = env.vault.get(record.id)) {
    const digest = value => createHash('sha256').update(value).digest();
    const values = item => [item?.accessToken, item?.refreshToken].filter(value => typeof value === 'string' && value.length > 0).map(digest);
    const mine = values(tokens);
    if (!mine.length) return false;
    const providerOf = item => item.providerId ?? signInOf(item.appId)?.providerId, appKey = item => item?.providerApp?.kind === 'developer' ? `developer:${item.providerApp.id}` : 'shared';
    return env.repository.list('connections').some(other => other.id !== record.id && other.status !== 'revoked' && providerOf(other) === providerOf(record) && appKey(other) === appKey(record)
      && values(env.vault.get(other.id)).some(theirs => mine.some(ours => timingSafeEqual(ours, theirs))));
  }
  /**
   * N9 and D4: whether a disconnect may revoke at the provider. On a shared app whose revocation removes the whole grant
   * (Google), never: it would sign the same person out of every other developer's app. On the developer's own app it may,
   * only when asked (remote: true) and after the sibling confirm (F10.4, TenantAccounts). Token-scoped providers revoke.
   */
  revocationPolicy(definition, providerApp = {kind: 'shared'}) {
    if (definition.revocation?.covers === 'grant') return providerApp?.kind === 'developer' ? 'provider' : 'local_only';
    return definition.revocation ? 'provider' : 'none';
  }
}

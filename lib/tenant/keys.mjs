// F03.1: service keys for a developer's server. A key reads fab_sk_dev.<keyId>.<secret> (or fab_sk_prod...), is shown
// once, and is stored only as a SHA-256 hash. verify() takes the same time for unknown, revoked, expired and wrong keys,
// and answers every failure the same way. Scopes live on the service client, stored literally; rotation keeps the
// client (so connections and grants survive) and lets the old key run for seven more days.
import {createHash, randomBytes, timingSafeEqual} from 'node:crypto';
import {PRESETS, validName, validScopes, assertRecordId, TenantRecordError} from '../../contracts/tenant.mts';
import {newId} from './registry.mjs';

const TOKEN = /^(fab_sk_dev|fab_sk_prod)\.(key_[a-z2-7]{26})\.([A-Za-z0-9_-]{43})$/;
const ROTATION_GRACE_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_ACTIVE_KEYS = 2;
const sha256 = value => createHash('sha256').update(value).digest('hex');
// Compared against when the key id is unknown, so a miss costs the same as a hit.
const DUMMY_HASH = sha256(randomBytes(32));

export class KeyError extends Error {
  constructor() { super('The API key is missing, wrong, expired or revoked.'); this.name = 'KeyError'; this.code = 'unauthorized'; this.status = 401; }
}

export class ServiceKeys {
  #registry;
  constructor(registry) { this.#registry = registry; }
  #now() { return Date.parse(this.#registry.now()); }
  #active(key) { return !key.revokedAt && (!key.expiresAt || Date.parse(key.expiresAt) > this.#now()); }
  #roomFor(client) {
    if (this.#registry.list('serviceKeys').filter(key => key.serviceClientId === client.id && this.#active(key)).length >= MAX_ACTIVE_KEYS) throw new TenantRecordError('This client already has two active keys; revoke one first.');
  }
  #issue(client, environment) {
    this.#roomFor(client);
    const id = newId('serviceKey'), secret = randomBytes(32).toString('base64url'), prefix = environment.kind === 'production' ? 'fab_sk_prod' : 'fab_sk_dev';
    this.#registry.put('serviceKeys', {id, serviceClientId: client.id, environmentId: environment.id, prefix, secretHash: sha256(secret), createdAt: this.#registry.now(), expiresAt: null, revokedAt: null, lastUsedDay: null});
    this.#registry.audit({type: 'tenant.key_created', serviceClientId: client.id, keyId: id, environmentId: environment.id});
    return {keyId: id, serviceClientId: client.id, token: `${prefix}.${id}.${secret}`};
  }
  /** A new service client for one environment, with its first key. Scopes come from a preset or an explicit list. */
  mint({environmentId, name, preset, scopes}) {
    const environment = this.#registry.get('environments', assertRecordId(environmentId, 'environment'));
    if (!environment) throw new TenantRecordError('No such environment.');
    if (preset !== undefined && !Object.hasOwn(PRESETS, preset)) throw new TenantRecordError(`Unknown preset: ${String(preset).slice(0, 40)}.`);
    const literal = validScopes(scopes ?? PRESETS[preset ?? 'standard']);
    const client = {id: newId('serviceClient'), organizationId: environment.organizationId, projectId: environment.projectId, environmentId: environment.id, name: validName(name ?? 'Server key'), scopes: literal, preset: preset ?? null, status: 'active', createdAt: this.#registry.now()};
    this.#registry.put('serviceClients', client);
    return {...this.#issue(client, environment), scopes: literal};
  }
  /** A new key for the same client; the old ones stop after seven days unless revoked sooner. */
  rotate(serviceClientId) {
    const client = this.#registry.get('serviceClients', assertRecordId(serviceClientId, 'serviceClient'));
    if (!client || client.status !== 'active') throw new TenantRecordError('No such active client.');
    // The limit first: a refused rotation changes no key (setting an expiry never changes which keys are active).
    this.#roomFor(client);
    const expiresAt = new Date(this.#now() + ROTATION_GRACE_MS).toISOString();
    for (const key of this.#registry.list('serviceKeys')) if (key.serviceClientId === client.id && this.#active(key) && !key.expiresAt) this.#registry.put('serviceKeys', {...key, expiresAt});
    return this.#issue(client, this.#registry.get('environments', client.environmentId));
  }
  /** Revokes a key. With withAgentTokens, every agent token it minted stops too (L8); without it, they keep working. */
  revoke(keyId, {withAgentTokens = false} = {}) {
    const key = this.#registry.get('serviceKeys', assertRecordId(keyId, 'serviceKey'));
    if (!key) throw new TenantRecordError('No such key.');
    if (!key.revokedAt) { this.#registry.put('serviceKeys', {...key, revokedAt: this.#registry.now()}); this.#registry.audit({type: 'tenant.key_revoked', keyId}); }
    if (withAgentTokens) {
      let count = 0;
      for (const route of this.#registry.list('agentTokenRoutes')) if (route.mintedByKeyId === key.id && route.environmentId === key.environmentId && !route.revokedAt) { this.#registry.put('agentTokenRoutes', {...route, revokedAt: this.#registry.now()}); count++; }
      this.#registry.audit({type: 'tenant.key_agent_tokens_revoked', keyId, count});
      return {agentTokensRevoked: count};
    }
    return {agentTokensRevoked: 0};
  }
  /** The only way an existing client gains or loses scopes; audited. */
  updateScopes(serviceClientId, scopes) {
    const client = this.#registry.get('serviceClients', assertRecordId(serviceClientId, 'serviceClient'));
    if (!client) throw new TenantRecordError('No such client.');
    const literal = validScopes(scopes);
    this.#registry.put('serviceClients', {...client, scopes: literal});
    this.#registry.audit({type: 'tenant.scopes_updated', serviceClientId, from: client.scopes, to: literal});
    return literal;
  }
  /** Keys of one environment, without their hashes. */
  list(environmentId) {
    return this.#registry.list('serviceKeys').filter(key => key.environmentId === environmentId).map(({secretHash, ...key}) => ({...key, active: this.#active(key)}));
  }
  /**
   * The caller's environment and scopes, or a uniform 401. Refuses suspended organizations and environments, and
   * production before the operator enables it.
   */
  verify(token) {
    const match = typeof token === 'string' && token.length < 200 ? TOKEN.exec(token) : null;
    const key = match ? this.#registry.get('serviceKeys', match[2]) : null;
    const presented = Buffer.from(sha256(match ? match[3] : 'x'), 'hex'), stored = Buffer.from(key?.secretHash ?? DUMMY_HASH, 'hex');
    const same = timingSafeEqual(presented, stored);
    if (!match || !key || !same || key.prefix !== match[1] || !this.#active(key)) throw new KeyError();
    const client = this.#registry.get('serviceClients', key.serviceClientId), environment = this.#registry.get('environments', key.environmentId);
    const organization = environment && this.#registry.get('organizations', environment.organizationId);
    if (!client || client.status !== 'active' || !environment || environment.status !== 'active' || !organization || organization.status !== 'active') throw new KeyError();
    if (environment.kind === 'production' && !environment.productionEnabled) throw new KeyError();
    const day = this.#registry.now().slice(0, 10);
    if (key.lastUsedDay !== day) this.#registry.put('serviceKeys', {...key, lastUsedDay: day});
    return Object.freeze({serviceClientId: client.id, keyId: key.id, scopes: Object.freeze([...client.scopes]), environment, scope: Object.freeze(this.#registry.scopeOf(environment))});
  }
}

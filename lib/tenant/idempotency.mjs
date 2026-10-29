// F03.7 (docs/F03-DEVELOPER-LAYER.md section 5.1): Idempotency-Key for /v1 writes. A key is scoped by environment,
// service client, route and key, and kept 24 hours. The lookup runs after the scope and ownership checks. The same key
// with the same body replays the first answer (an Execution is re-read, a refusal is answered again); the same key with
// a different body is idempotency_conflict. A reservation that never got its job is never run again.
import {createHash} from 'node:crypto';
import {canonicalHash} from '../compiler.mjs';
import {stampOwner, ownedBy, tenantDeployment} from './deployment.mjs';
import {TenantError} from './errors.mjs';

export const IDEMPOTENCY = 'idempotencyKeys';
const KEY = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/, TTL_MS = 24 * 3600 * 1000;

export class IdempotencyKeys {
  constructor({registry}) { this.registry = registry; }
  /** The header's key, or invalid_request. */
  static checked(value) {
    if (typeof value !== 'string' || !KEY.test(value)) throw new TenantError(400, 'invalid_request', 'Send an Idempotency-Key header of 1 to 128 characters: letters, digits and . _ : @ -');
    return value;
  }
  #id(env, caller, route, key) { return createHash('sha256').update(JSON.stringify([env.repository.scopeKey, caller.serviceClientId, route, key])).digest('hex'); }
  /**
   * Reserves the key for this request, or returns what it already holds: {record, replay: true}. A different body under
   * the same key is idempotency_conflict. The record is owned by the end user, so deleting them erases it.
   */
  begin(env, caller, {route, key, body, owner, callRef}) {
    let requestHash;
    // A name no JSON request may carry (such as __proto__) is a clean refusal, never an internal error.
    try { requestHash = canonicalHash(body); } catch { throw new TenantError(400, 'invalid_request', 'The request holds a name Fabric never accepts, such as __proto__.', {code: 'unsafe_property'}); }
    const id = this.#id(env, caller, route, key), now = Date.parse(this.registry.now());
    const existing = env.repository.get(IDEMPOTENCY, id);
    if (existing && Date.parse(existing.expiresAt) > now) {
      // A record held for another end user (a deleted one whose external id came back, say) is never replayed to this
      // one, matched on both owner ids.
      if (!ownedBy(existing, owner, tenantDeployment(env.scope))) throw new TenantError(409, 'idempotency_conflict', 'This Idempotency-Key was already used for another request.');
      if (existing.requestHash !== requestHash) throw new TenantError(409, 'idempotency_conflict', 'This Idempotency-Key was already used with a different request.');
      return {record: existing, replay: true};
    }
    const record = stampOwner({id, route, serviceClientId: caller.serviceClientId, keyId: caller.keyId, requestHash, status: 'reserved', callRef, createdAt: this.registry.now(), expiresAt: new Date(now + TTL_MS).toISOString()}, owner);
    env.repository.put(IDEMPOTENCY, record);
    return {record, replay: false};
  }
  recorded(env, record) { const next = {...record, status: 'recorded'}; env.repository.put(IDEMPOTENCY, next); return next; }
  /** A refusal is kept so the same request gets the same answer. */
  refused(env, record, error) {
    const next = {...record, status: 'refused', refusal: {status: error.status, code: error.code, message: error.message, ...(error.details ? {details: error.details} : {})}};
    env.repository.put(IDEMPOTENCY, next); return next;
  }
}

// F03.9b (docs/F03-DEVELOPER-LAYER.md section 5.12, docs/F03.9-BUILD-MAP.md slice A): agent tokens. The developer's
// server mints a token for one end user's agent, bound to exact (account, operation) pairs and proxy rows of that user
// only. The token is shown once and stored only as a hash; agents see account aliases, never accountRefs, and never
// decide anything. Each grant records the key that minted it (N13), and is erased with its end user.
import {createHash, createHmac, randomBytes, randomUUID} from 'node:crypto';
import {TenantError, notFound, invalid} from './errors.mjs';
import {ownedBy, stampOwner, tenantDeployment} from './deployment.mjs';
import {capabilityPermissionHash, permissionEffect, sameRoute, resourceDependent, ACTION_WORDS} from '../permissions.mjs';
import {signInOf} from './views.mjs';
import {LOCK_WORDS, AGENT_LOCK_WORDS} from '../row-locks.mjs';
import {UNAVAILABLE_REASONS} from '../permission-groups.mjs';

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567', NAME = /^[^\u0000-\u001f\u007f]{1,80}$/;
const sha256 = value => createHash('sha256').update(value).digest('hex');
const ROUTE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const TOKEN = /^fab_client\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/;

/** An account's alias for one grant: acct_ plus 26 base32 characters of HMAC-SHA256(grant.aliasKey, accountRef). */
export function aliasOf(grant, accountRef) {
  const digest = createHmac('sha256', Buffer.from(grant.aliasKey, 'base64url')).update(accountRef).digest();
  return `acct_${[...digest].slice(0, 26).map(byte => BASE32[byte & 31]).join('')}`;
}
/** The accountRef behind an alias, searched only in this grant's own bindings and proxy entries; null otherwise. */
export function resolveAlias(grant, alias) {
  if (typeof alias !== 'string' || !/^acct_[a-z2-7]{26}$/.test(alias)) return null;
  const refs = new Set([...(grant.bindings || []).map(binding => binding.connectionId), ...(grant.proxy || []).map(entry => entry.connectionId)]);
  return [...refs].find(ref => aliasOf(grant, ref) === alias) ?? null;
}

export class TenantAgentTokens {
  /** @param {{runtimes: any, accounts: any, registry: any}} deps */
  constructor(deps) { Object.assign(this, deps); }

  #fields(value, allowed, what = 'The body') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid(`${what} must be a JSON object.`);
    const unknown = Object.keys(value).find(key => !allowed.includes(key));
    if (unknown) throw invalid(`Unknown field: ${unknown.slice(0, 40)}.`);
  }
  #owner(env, externalUserId) {
    const user = this.accounts.user(env, externalUserId);
    if (!user) throw notFound();
    return this.accounts.ownerOf(user);
  }
  #mine(env, owner, id) {
    const grant = typeof id === 'string' && ROUTE_ID.test(id) ? env.repository.get('clientGrants', id) : null;
    if (!grant || grant.kind !== 'agent_token' || !ownedBy(grant, owner, tenantDeployment(env.scope))) throw notFound();
    return grant;
  }
  #status(grant) {
    if (grant.status !== 'active') return grant.status;
    // A token whose route was revoked (its key revoked with its agent tokens, L8) is revoked, whatever its own record says.
    if (this.registry.get('agentTokenRoutes', grant.id)?.revokedAt) return 'revoked';
    return Date.parse(grant.expiresAt) <= Date.parse(this.registry.now()) ? 'expired' : 'active';
  }
  #view(grant) { return {id: grant.id, name: grant.name, expiresAt: grant.expiresAt, status: this.#status(grant)}; }

  /** POST /v1/users/:ext/agent-tokens */
  create(caller, externalUserId, body) {
    this.#fields(body, ['name', 'expiresInSeconds', 'bindings', 'requestable', 'proxy', 'apps']);
    const bundle = this.runtimes.bundle(caller.scope), env = bundle.env, owner = this.#owner(env, externalUserId);
    // Per-app grants are reserved for I06 (P17); request-only operations arrive with held executions for agents.
    if (body.apps !== undefined) throw new TenantError(422, 'not_available', 'Grants for whole apps are not available yet; bind accounts and operations.');
    if (typeof body.name !== 'string' || !NAME.test(body.name.trim()) || !body.name.trim()) throw invalid('Give the token a name of up to 80 visible characters.');
    const lifetime = body.expiresInSeconds ?? 86_400;
    if (!Number.isSafeInteger(lifetime) || lifetime < 60 || lifetime > 30 * 86_400) throw invalid('expiresInSeconds is a whole number from 60 to 2592000.');
    const bindings = body.bindings ?? [], proxy = body.proxy ?? [], requestable = body.requestable ?? [];
    if (!Array.isArray(bindings) || bindings.length > 100 || !Array.isArray(proxy) || proxy.length > 20 || !Array.isArray(requestable) || requestable.length > 50 || bindings.length + proxy.length + requestable.length < 1)
      throw invalid('Bind between 1 and 100 account and operation pairs, proxy rows for up to 20 accounts, or up to 50 operations the agent may ask for.');
    // F03.9e: operations the agent may ask the person to connect an account for. It never runs them on accounts it was
    // not given; each request becomes a hold the person answers on Fabric's page.
    const requestedIds = new Set();
    const requested = requestable.map(item => {
      this.#fields(item, ['capabilityId'], 'A requestable entry');
      const cap = typeof item.capabilityId === 'string' ? env.repository.get('capabilities', item.capabilityId) : null;
      // F10.11 part m: an API operation, or an action (it runs on its app's http account) this environment runs now.
      if (!cap || cap.status !== 'active' || !sameRoute({appId: cap.appId, driver: 'http'}, cap) || (cap.driver === 'action' && bundle.permissions.actions?.entryOf?.(cap)?.status !== 'active') || !signInOf(cap.appId)) throw notFound();
      // One described by the resource it acts on is described once an account exists, never asked for before.
      if (resourceDependent(cap)) throw invalid(ACTION_WORDS.describe);
      // T4 (F10.3): an operation Fabric (or this environment) locks is never requested; no hold could ever run it.
      if (bundle.permissions.lockOf(cap)) throw new TenantError(403, 'permission_denied', AGENT_LOCK_WORDS);
      // F10.6 (T3): nor is one no sign-in can ever run.
      const unavailable = bundle.permissions.unavailableOf(cap);
      if (unavailable) throw new TenantError(403, 'permission_denied', UNAVAILABLE_REASONS[unavailable]);
      if (requestedIds.has(cap.id)) throw invalid('Each requestable operation once.');
      requestedIds.add(cap.id);
      return {appId: cap.appId, capabilityId: cap.id, capabilityVersion: Number.isSafeInteger(cap.version) ? cap.version : 1, definitionHash: capabilityPermissionHash(cap), effect: permissionEffect(cap), providerId: signInOf(cap.appId).providerId};
    });
    const seen = new Set();
    const bound = bindings.map(binding => {
      this.#fields(binding, ['accountRef', 'capabilityId'], 'A binding');
      if (typeof binding.accountRef !== 'string' || typeof binding.capabilityId !== 'string') throw invalid('A binding names an accountRef and a capabilityId.');
      // Another user's or an unknown account answers exactly like a missing one.
      const connection = this.accounts.ownedAccount(env, owner, binding.accountRef), cap = env.repository.get('capabilities', binding.capabilityId);
      if (!cap || cap.status !== 'active' || cap.appId !== connection.appId) throw notFound();
      const key = `${connection.id}\n${cap.id}`;
      if (seen.has(key)) throw invalid('Each account and operation pair once.');
      seen.add(key);
      let decision;
      try { decision = bundle.permissions.decision(connection, cap); } catch { decision = null; }
      if (!decision?.executable) throw new TenantError(403, 'permission_denied', decision?.locked ? LOCK_WORDS : 'Only operations this account currently allows or asks about can be given to an agent.');
      return {connectionId: connection.id, capabilityId: cap.id, definitionHash: capabilityPermissionHash(cap), bindingHash: decision.bindingHash};
    });
    const policy = bundle.runtime.proxyPolicy, accountsSeen = new Set();
    const proxied = proxy.map(entry => {
      this.#fields(entry, ['accountRef', 'rows'], 'A proxy entry');
      const connection = this.accounts.ownedAccount(env, owner, entry.accountRef);
      if (accountsSeen.has(connection.id)) throw invalid('Each account once in proxy.');
      accountsSeen.add(connection.id);
      if (!Array.isArray(entry.rows) || !entry.rows.length || entry.rows.length > 45 || new Set(entry.rows).size !== entry.rows.length || entry.rows.some(row => typeof row !== 'string' || row.length > 200)) throw invalid('Choose between 1 and 45 distinct proxy rows.');
      let context;
      try { context = policy.route(connection.id); } catch { throw new TenantError(422, 'proxy_unavailable', 'This account cannot use the proxy.'); }
      const rows = policy.rows(context);
      return {connectionId: connection.id, appId: connection.appId, configHash: context.config.configHash, rows: entry.rows.map(row => {
        const known = rows.find(candidate => candidate.row === row);
        if (!known) throw invalid(`${row.slice(0, 80)} is not a proxy row of this app.`);
        if (known.locked) throw new TenantError(403, 'permission_denied', LOCK_WORDS);
        if (policy.base(context, known).mode === 'deny') throw new TenantError(403, 'permission_denied', `"${known.label}" is set to Never, so it cannot be given to an agent.`);
        return {row, bindingHash: policy.binding(context, row)};
      })};
    });
    const id = randomUUID(), secret = randomBytes(32).toString('base64url'), token = `fab_client.${id}.${secret}`, now = this.registry.now();
    const expiresAt = new Date(Date.parse(now) + lifetime * 1000).toISOString();
    const grant = stampOwner({id, kind: 'agent_token', name: body.name.trim(), bindings: bound, ...(proxied.length ? {proxy: proxied} : {}), ...(requested.length ? {requestable: requested} : {}), status: 'active', createdAt: now, expiresAt, tokenHash: sha256(token),
      delegatedBy: {kind: 'product_user', id: owner.subjectId}, delegationId: id, aliasKey: randomBytes(32).toString('base64url'), mintedByKeyId: caller.keyId, mintedByServiceClientId: caller.serviceClientId}, owner);
    env.repository.put('clientGrants', grant);
    this.registry.put('agentTokenRoutes', {id, ...caller.scope, expiresAt, mintedByKeyId: caller.keyId, revokedAt: null});
    env.repository.audit({type: 'agent.token_granted', agentId: id, userRecordId: owner.userRecordId, operations: bound.length, proxyAccounts: proxied.length, byKey: caller.keyId});
    return {status: 201, body: {agentToken: {id, name: grant.name, expiresAt}, token}};
  }
  /** GET /v1/users/:ext/agent-tokens: this user's tokens only, never a token, hash, alias key or binding. */
  list(caller, externalUserId) {
    const env = this.runtimes.bundle(caller.scope).env, user = this.accounts.user(env, externalUserId);
    if (!user) return {agentTokens: []};
    const owner = this.accounts.ownerOf(user), deployment = tenantDeployment(env.scope);
    const mine = env.repository.list('clientGrants').filter(grant => grant?.kind === 'agent_token' && ownedBy(grant, owner, deployment)).sort((a, b) => a.createdAt < b.createdAt ? -1 : 1);
    return {agentTokens: mine.map(grant => this.#view(grant))};
  }
  /** POST /v1/users/:ext/agent-tokens/:id/revoke */
  async revoke(caller, externalUserId, id) {
    const env = this.runtimes.bundle(caller.scope).env, owner = this.#owner(env, externalUserId), grant = this.#mine(env, owner, id), now = this.registry.now();
    if (grant.status !== 'revoked') {
      env.repository.put('clientGrants', {...grant, status: 'revoked', revokedAt: now, revokedByKeyId: caller.keyId});
      const route = this.registry.get('agentTokenRoutes', grant.id);
      if (route && !route.revokedAt) this.registry.put('agentTokenRoutes', {...route, revokedAt: now});
      env.repository.audit({type: 'agent.token_revoked', agentId: grant.id, userRecordId: owner.userRecordId, byKey: caller.keyId});
      // The token's account requests still waiting close with it: a later confirm resumes nothing.
      for (const hold of env.repository.list('continuations').filter(item => item?.kind === 'hold' && item.status === 'waiting' && item.source?.kind === 'client' && item.source.clientId === grant.id)) {
        await this.executions?.closeHold(caller.scope, env, hold, 'agent_revoked', {cancelledByKey: caller.keyId});
      }
    }
    return {agentToken: this.#view(env.repository.get('clientGrants', grant.id))};
  }
}

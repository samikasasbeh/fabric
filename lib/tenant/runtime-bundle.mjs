// F03.7 (docs/F03.7-BUILD-MAP.md slice 1): one runtime per open developer environment. Each environment's handle gets
// exactly one bundle: a ConnectionManager with every configured shared sign-in adapter bound (so token refreshes are
// shared), a PermissionManager whose ceilings are read live from the registry (N7), and one Runtime holding the write
// locks and the running set. Jobs are dispatched detached while their environment is pinned, so it is never evicted
// mid-run, and a caller can wait a bounded time for the outcome.
import {Runtime, sweepRetention} from '../runtime.mjs';
import {PermissionManager} from '../permissions.mjs';
import {ProxyPolicy} from '../proxy-policy.mjs';
import {ConnectionManager} from '../connections.mjs';
import {OAuth2Provider} from '../providers/oauth2.mjs';
import {definitionFor, reviewedProviderIds} from '../providers/definitions.mjs';
import {tenantDeployment} from './deployment.mjs';
import {scopeKey} from '../repositories/tenant.mts';
import {TenantAgentProtocol} from './agent-protocol.mjs';

export class EnvironmentRuntimes {
  #bundles = new WeakMap(); #inflight = new Map();
  /** `actions` is the action catalog every bundle's runtime reads (F10.11 part e), null until part p loads one at start; `slackDistribution`
   *  how Fabric's Slack app is installed (F10.21, lib/slack-limits.mjs), read once by the developer server.
   *  @param {{stores: any, registry: any, providerApps: any, origin: string, request?: Function, actions?: any, slackDistribution?: string}} deps */
  constructor({stores, registry, providerApps, origin, request, actions = null, slackDistribution = 'internal'}) { Object.assign(this, {stores, registry, providerApps, origin, request, actions, slackDistribution}); }

  /** The environment's bundle, built once per open handle (a re-opened environment gets a fresh one). */
  bundle(scope) {
    const env = this.stores.open(scope), cached = this.#bundles.get(env);
    if (cached) return cached;
    const deployment = tenantDeployment(env.scope), clock = () => Date.parse(this.registry.now()), request = this.request ? {request: this.request} : {};
    const connections = new ConnectionManager({store: env.repository, vault: env.vault, deployment, clock, ...request});
    const adapters = new Map();
    for (const providerId of reviewedProviderIds()) {
      // N11: only explicit operator settings; a provider without them has no adapter here (setup_required).
      const credentials = this.providerApps.credentials(providerId);
      if (!credentials) continue;
      const definition = definitionFor(providerId);
      // N9: on a shared app whose revocation covers the whole grant (Google), this adapter never asks the provider to revoke.
      const revocationPolicy = this.providerApps.revocationPolicy(definition, {kind: 'shared'}) === 'local_only' ? 'local_only' : 'provider';
      // N11, F10.4: consent days come from the shared app's own record (Google's Testing mode: 7), never the machine's environment.
      const consentDays = this.providerApps.shared(providerId).testing?.expiresAfterDays ?? null;
      const adapter = new OAuth2Provider(definition, {store: env.repository, vault: env.vault, connections, clock, clientId: credentials.clientId, clientSecret: credentials.clientSecret,
        redirectUri: `${this.origin}/api/oauth/${providerId}/callback`, publishing: 'testing', consentDays, revocationPolicy, ...request});
      connections.setOAuthProvider(adapter); adapters.set(providerId, adapter);
    }
    // N7: the developer's ceilings are read at every decision, so a change applies to the next one.
    const ceilingOf = (appId, groupId) => { const ceiling = this.registry.get('environments', env.scope.environmentId)?.apps?.[appId]?.ceilings?.[groupId]; return ceiling === 'ask' || ceiling === 'deny' ? ceiling : null; };
    // F10.5: a scope a granted parent grants is held, in every decision.
    const permissions = new PermissionManager({store: env.repository, ceilingOf, scopesOf: connection => connections.effectiveScopes(connection)});
    // The proxy keeps the person's row floor (c8). T4 is held by the rows Fabric locks, the same in every deployment (F10.3).
    const proxyPolicy = new ProxyPolicy({store: env.repository, permissions, rowFloor: true});
    const runtime = new Runtime({store: env.repository, connections, permissions, deployment, clock, slackDistribution: this.slackDistribution, proxyPolicy, actions: this.actions, ...request});
    // Only a fresh bundle recovers, and a fresh one exists only when nothing in this environment is in flight (pins).
    runtime.recover();
    // F03.8: a developer's own provider apps, built lazily per record revision, so a changed secret applies to the next
    // sign-in while refreshes in flight keep their adapter. Never bound as the provider's adapter (that is the shared one).
    const developer = new Map();
    connections.setDeveloperAdapters(id => this.#developerAdapter(env, developer, connections, clock, request, id));
    // F03.9c: agent tokens. Every agent-sourced job is checked against its token at creation and again when it runs.
    const agents = new TenantAgentProtocol({env, scope: env.scope, runtime, permissions, registry: this.registry, runtimes: this, executions: this.executions, usage: this.usage});
    runtime.authorizeSource = job => agents.authorizeJob(job);
    const bundle = Object.freeze({env, connections, adapters, developer, permissions, runtime, agents});
    this.#bundles.set(env, bundle);
    return bundle;
  }
  /** The adapter of one of this environment's own provider apps, or null when it is unknown, disabled or has no secret. */
  developerAdapter(scope, id) {
    const bundle = this.bundle(scope);
    return this.#developerAdapter(bundle.env, bundle.developer, bundle.connections, () => Date.parse(this.registry.now()), this.request ? {request: this.request} : {}, id);
  }
  #developerAdapter(env, cache, connections, clock, request, id) {
    const record = this.providerApps.developer(env.scope, id);
    if (!record || this.providerApps.status(record, env) === 'disabled') return null;
    const secret = this.providerApps.secret(env.scope, id), redirectUri = this.providerApps.redirectUri(record.providerId, id);
    // N11: a missing secret or relay address means no adapter at all; nothing falls back to the machine's environment.
    if (!secret || !redirectUri) return null;
    const key = `${id}:${record.revision}`;
    if (cache.has(key)) return cache.get(key);
    const definition = definitionFor(record.providerId);
    const revocationPolicy = this.providerApps.revocationPolicy(definition, {kind: 'developer', id}) === 'local_only' ? 'local_only' : 'provider';
    const adapter = new OAuth2Provider(definition, {store: env.repository, vault: env.vault, connections, clock, clientId: record.clientId, clientSecret: secret, redirectUri, allowHostedRedirect: redirectUri.startsWith('https:'),
      publishing: record.publishing, consentDays: record.consentDays ?? null, revocationPolicy, providerAppId: id, ...request});
    for (const stale of [...cache.keys()].filter(item => item.startsWith(`${id}:`))) cache.delete(stale);
    cache.set(key, adapter);
    return adapter;
  }
  /** Runs one queued job detached, with its environment pinned until it settles. Returns the settled job (or null). */
  dispatch(scope, jobId) {
    const bundle = this.bundle(scope), key = `${scopeKey(bundle.env.scope)}:${jobId}`;
    if (this.#inflight.has(key)) return this.#inflight.get(key);
    this.stores.pin(scope);
    const running = bundle.runtime.execute(jobId).catch(() => null).finally(() => { this.#inflight.delete(key); try { this.stores.unpin(scope); } catch { /* closed */ } });
    this.#inflight.set(key, running);
    return running;
  }
  /** Waits up to ms for a dispatched job; resolves either way (the caller re-reads the stored job). */
  async wait(scope, jobId, ms) {
    const running = this.#inflight.get(`${scopeKey(this.stores.open(scope).scope)}:${jobId}`);
    if (!running || !(ms > 0)) return;
    let timer;
    await Promise.race([running, new Promise(resolve => { timer = setTimeout(resolve, ms); timer.unref?.(); })]);
    clearTimeout(timer);
  }
  /** Everything dispatched, settled: shutdown waits for this before closing the environments. */
  drain() { return Promise.allSettled([...this.#inflight.values()]); }
  /** F10.21 (lib/retention.mjs): sweeps every open environment's expired Slack data, through its runtime when it has one, else on its store
   *  alone (an environment with no runtime has nothing running, and its runtime sweeps again when it is built). */
  sweepOpen() {
    for (const handle of this.stores.openHandles()) {
      const bundle = this.#bundles.get(handle);
      if (bundle) bundle.runtime.sweepRetention(); else sweepRetention(handle.repository, Date.parse(this.registry.now()));
    }
  }
  /** Tests only (exit check 1): the environment-scoped keys of jobs running now. Changes nothing. */
  [Symbol.for('fabric.test.maps')]() { return {inflight: [...this.#inflight.keys()]}; }
}

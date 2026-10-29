import { randomUUID } from 'node:crypto';
import { canonicalHash, validateCapability } from './compiler.mjs';
import { DiscoveryEngine } from './discovery.mjs';
import { AcquisitionEngine } from './acquisition.mjs';
import { safeRequest } from './network.mjs';
import { scrubAuthorization } from './redaction.mjs';

const now = () => new Date().toISOString();
const APP_ID = /^[a-z][a-z0-9-]{0,63}$/;
const normalizedHash = capability => canonicalHash({ ...capability, status: 'candidate' });
const message = cause => scrubAuthorization(cause?.message || cause).slice(0, 800);
const assert = (condition, reason) => { if (!condition) throw new Error(reason); };

// A factory builds reviewable request definitions. Account authentication,
// activation, permission decisions and execution remain separate services.
export class AdapterFactory {
  constructor({ store, catalog, discovery, acquisition, runtime, connections, request = safeRequest }) {
    this.store = store;
    this.catalog = typeof catalog === 'function' ? catalog : () => catalog;
    this.acquisition = acquisition || new AcquisitionEngine({ store, catalog: this.catalog, request });
    this.discovery = discovery || new DiscoveryEngine({ store, catalog: this.catalog, acquisition: this.acquisition, request });
    this.runtime = runtime;
    this.connections = connections;
    this.running = new Map();
  }

  list({ appId } = {}) {
    if (appId !== undefined) assert(typeof appId === 'string' && APP_ID.test(appId), 'Choose a valid catalog application.');
    return this.store.list('adapterBuilds').filter(build => !appId || build.appId === appId).reverse().slice(0, 100);
  }

  async build({ appId } = {}) {
    assert(typeof appId === 'string' && APP_ID.test(appId), 'Choose a valid catalog application.');
    if (this.running.has(appId)) return this.running.get(appId);
    const pending = this.buildOnce(appId);
    this.running.set(appId, pending);
    try { return await pending; } finally { this.running.delete(appId); }
  }

  authority(appId) {
    const app = this.catalog()?.find(item => item.id === appId);
    assert(app, 'Unknown catalog application.');
    assert(app.discovery && ['openapi', 'google-discovery'].includes(app.discovery.kind), 'This application has no declared, supported schema source. A browser connection does not supply an API schema.');
    const url = new URL(app.discovery.url);
    assert(url.protocol === 'https:' && !url.username && !url.password && !url.hash && !url.port, 'The declared schema source must use credential-free HTTPS.');
    const origins = app.apiOrigins || app.allowedOrigins;
    assert(Array.isArray(origins) && origins.length && origins.every(origin => typeof origin === 'string'), 'This application has no declared API origin boundary.');
    return { kind: app.discovery.kind, url: url.href, origins: [...new Set(origins)].sort() };
  }

  async buildOnce(appId) {
    const createdAt = now();
    const report = {
      id: randomUUID(), appId, status: 'blocked', source: null, capabilityIds: [], capabilities: [], unsupported: [],
      validation: { passed: false, checks: [] }, lifecycle: [{ stage: 'requested', at: createdAt }],
      executions: [], createdAt, completedAt: null, connectionCreated: false, permissionsGranted: false,
      accountVerified: false,
      limits: ['Declarative HTTP adapters from a declared OpenAPI or Google REST Discovery source only.', 'Build validation is not live execution, account access, exhaustive API coverage, or independent effect verification.', 'No arbitrary generated code, CLI installation, UI exploration or automatic adapter repair is performed.'],
    };
    // Keep an attempt receipt even if the process stops before the final report.
    this.store.audit({ type: 'adapter.build.requested', buildId: report.id, appId });
    try {
      const authority = this.authority(appId);
      report.source = { kind: authority.kind, url: authority.url, documentHash: null };
      report.lifecycle.push({ stage: 'fetching-source', at: now() });
      // Discovery uses the existing bounded fetch, schema traversal and compiler;
      // AcquisitionEngine persists immutable candidates without promotion.
      const map = await this.discovery.discover({ appId });
      assert(canonicalHash(authority) === canonicalHash(this.authority(appId)), 'The catalog source or API authority changed during this build. Build again against the current declaration.');
      assert(map.appId === appId && map.sourceUrl === authority.url && map.sourceKind === authority.kind, 'Discovery returned a map outside the selected source boundary.');
      assert(Array.isArray(map.operations) && map.operations.length <= 500, 'The discovered operation set exceeds factory limits.');
      const source = this.store.get('discoverySources', `${appId}:${map.fingerprint}`);
      assert(source?.appId === appId && source.sourceUrl === authority.url && source.fingerprint === map.fingerprint, 'The persisted source evidence is missing or mismatched.');
      assert(canonicalHash(source.document) === map.fingerprint, 'The persisted source document does not match its provenance hash.');
      const persistedMap = this.store.get('applicationMaps', appId);
      assert(persistedMap && canonicalHash(persistedMap) === canonicalHash(map), 'The persisted application map changed during this build.');
      report.source.documentHash = map.fingerprint;
      report.lifecycle.push({ stage: 'source-observed', at: now(), documentHash: map.fingerprint });
      report.validation.checks.push('source-document-hash', 'catalog-authority-unchanged', 'persisted-map-matches');
      const capabilities = [];
      const ids = new Set();
      for (const operation of map.operations) {
        if (operation.support !== 'candidate' || !operation.capabilityId) {
          report.unsupported.push({ operationId: operation.id, method: operation.method, path: operation.path, reason: message(operation.reason || 'No supported request function could be compiled.') });
          continue;
        }
        assert(!ids.has(operation.capabilityId), 'Two documented operations mapped to the same capability.');
        ids.add(operation.capabilityId);
        const cap = this.store.get('capabilities', operation.capabilityId);
        assert(cap, 'A compiled candidate is missing from the store.');
        validateCapability(cap);
        assert(cap.appId === appId && cap.driver === 'http', 'A candidate belongs to a different application or driver.');
        assert(authority.origins.includes(new URL(cap.request.url).origin), 'A candidate request exceeds the selected API origins.');
        assert(cap.provenance.source === authority.url && cap.provenance.kind === 'openapi', 'Candidate provenance is not the declared compiled source.');
        assert(cap.provenance.path === operation.path && cap.provenance.method.toUpperCase() === operation.method && cap.request.method.toUpperCase() === operation.method, 'A candidate request does not match its documented operation.');
        const expectedEffect = ['GET', 'HEAD'].includes(operation.method) ? 'read' : 'write';
        assert(cap.effect === expectedEffect, 'The request effect does not match its HTTP method.');
        capabilities.push({ id: cap.id, definitionHash: normalizedHash(cap), operationId: operation.id, method: operation.method, effect: operation.effect, status: cap.status, gaps: (operation.gaps || []).map(message) });
      }
      report.capabilities = capabilities;
      report.capabilityIds = capabilities.map(cap => cap.id);
      report.validation.checks.push('immutable-capability-schema', 'api-origin-boundary', 'operation-method-and-path', 'conservative-effect-classification');
      report.validation.passed = true;
      report.lifecycle.push({ stage: 'validated', at: now(), candidates: capabilities.length, unsupported: report.unsupported.length });
      assert(capabilities.length, 'The source was observed, but no operation is supported by the current compiler. See unsupported reasons.');
      report.status = 'built';
      report.counts = { total: map.operations.length, built: capabilities.length, unsupported: report.unsupported.length };
      report.changes = map.changes;
    } catch (cause) {
      report.error = message(cause);
      // Discovery candidates, if any, remain unpromoted. Previously reviewed
      // capabilities and grants are never rewritten by this reporting layer.
    }
    report.completedAt = now();
    report.lifecycle.push({ stage: report.status, at: report.completedAt });
    this.store.put('adapterBuilds', report);
    this.store.audit({ type: 'adapter.build.completed', buildId: report.id, appId, status: report.status, count: report.capabilityIds.length, documentHash: report.source?.documentHash || null });
    return report;
  }

  // Attach an already completed Runtime job, never execute one implicitly.
  // The report stores evidence metadata only, not account content or arguments.
  recordExecution({ buildId, jobId } = {}) {
    const report = this.store.get('adapterBuilds', buildId);
    assert(report?.status === 'built', 'Choose a completed adapter build.');
    const existing = report.executions.find(item => item.jobId === jobId);
    if (existing) return report;
    assert(report.executions.length < 100, 'This build has reached its execution-evidence limit.');
    const job = this.store.get('jobs', jobId);
    assert(job && ['succeeded', 'failed', 'uncertain'].includes(job.status), 'Only a completed runtime job can supply execution evidence.');
    const artifact = report.capabilities.find(item => item.id === job.capabilityId);
    assert(artifact, 'This runtime job does not belong to the selected build.');
    const cap = this.store.get('capabilities', artifact.id);
    validateCapability(cap);
    assert(normalizedHash(cap) === artifact.definitionHash && canonicalHash({ ...cap, status: 'active' }) === job.capabilityHash, 'Runtime execution used a different capability definition.');
    const connection = this.store.get('connections', job.connectionId);
    assert(connection?.appId === report.appId && connection.driver === 'http', 'The runtime connection belongs to another application or driver.');
    assert(job.identityHash === canonicalHash(connection.identity || {}), 'The account identity changed after this runtime job.');
    const verification = job.result?.verification;
    const publicEndpoint = connection.authMethod === 'public-no-auth';
    const evidence = {
      jobId: job.id, capabilityId: cap.id, definitionHash: artifact.definitionHash, status: job.status, effect: job.effect,
      scope: publicEndpoint ? 'public-endpoint' : 'authorized-connection', authentication: connection.authMethod || 'unspecified',
      verification: { status: verification?.status || 'none', kind: verification?.kind || 'none', ...(Number.isInteger(verification?.httpStatus) ? { httpStatus: verification.httpStatus } : {}) },
      startedAt: job.createdAt, completedAt: job.updatedAt, recordedAt: now(),
    };
    report.executions.push(evidence);
    report.lifecycle.push({ stage: 'execution-recorded', at: evidence.recordedAt, jobId: job.id, status: job.status });
    // Observing a public response never verifies a user's account. For account
    // jobs, inspect the separate connection identity/consent evidence instead.
    this.store.put('adapterBuilds', report);
    this.store.audit({ type: 'adapter.execution.recorded', buildId, jobId, appId: report.appId, status: job.status, scope: evidence.scope });
    return report;
  }
}

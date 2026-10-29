import {canonicalHash} from '../lib/compiler.mjs';
import {assertSameScope, validatePrincipal, validateScope} from './identity.mts';
import type {Principal, Scope} from './identity.mts';

// These are evidence contracts, not authenticated attestations. Only trusted
// service code may accept evidence into a future certification registry.
export type CheckResult = Readonly<{id: string; outcome: 'passed' | 'failed' | 'not_run'; artifactId?: string}>;
export type AuthBinding = Readonly<{authKind: 'oauth2' | 'api-key' | 'none'; configurationGeneration: number}>;
export type ProviderReadiness = Readonly<{
  schemaVersion: 1; id: string; scope: Scope; appId: string;
  status: 'not_configured' | 'testing' | 'production_ready';
  owner: string; backupOwner: string; accountTypes: readonly string[]; supportedScopes: readonly string[];
  checks: readonly CheckResult[]; checkedAt: string; expiresAt: string;
}> & AuthBinding;
export type CertificationEvidence = Readonly<{
  schemaVersion: 1; id: string; scope: Scope; appId: string;
  packageHash: string; capabilityId: string; definitionHash: string;
  accountType: string; requiredScopes: readonly string[]; grantedScopes: readonly string[]; environment: 'fixture' | 'live';
  performedBy: Principal; checks: readonly CheckResult[];
  startedAt: string; completedAt: string; expiresAt: string;
}> & AuthBinding;
export type CertificationTarget = Readonly<{
  schemaVersion: 1; scope: Scope; appId: string; packageHash: string;
  capabilityId: string; definitionHash: string; accountType: string; requiredScopes: readonly string[];
  effect: 'read' | 'write' | 'delete';
}> & AuthBinding;
export type CertificationAssessment = Readonly<{
  schemaVersion: 1; status: 'blocked' | 'ready_for_release_review';
  assessedAt: string; blockers: readonly string[]; evidenceIds: readonly string[];
  publicationAuthorized: false;
}>;

const ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const APP = /^[a-z][a-z0-9-]{0,63}$/;
const HASH = /^[a-f0-9]{64}$/;
const CHECK_IDS = new Set(['registration', 'callback', 'scope-mapping', 'credential-flow', 'access-route', 'identity', 'input-validation', 'output-validation', 'policy-denial', 'read', 'write', 'delete', 'readback', 'restart', 'revocation', 'renewal']);
function reject(): never { throw new Error('Invalid certification contract.'); }
const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
function shape(value: unknown, required: readonly string[], optional: readonly string[] = []): asserts value is Record<string, unknown> {
  if (!isRecord(value) || required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) reject();
}
function safe(value: unknown): void { try { canonicalHash(value); } catch { reject(); } }
function id(value: unknown): asserts value is string { if (typeof value !== 'string' || !ID.test(value)) reject(); }
function hash(value: unknown): asserts value is string { if (typeof value !== 'string' || !HASH.test(value)) reject(); }
function app(value: unknown): asserts value is string { if (typeof value !== 'string' || !APP.test(value)) reject(); }
function auth(value: Record<string, unknown>): void {
  if (!['oauth2', 'api-key', 'none'].includes(value.authKind as string) || !Number.isSafeInteger(value.configurationGeneration) || (value.configurationGeneration as number) < 1) reject();
}
function scopes(value: unknown): asserts value is string[] {
  if (!Array.isArray(value) || value.length > 64 || new Set(value).size !== value.length || value.some(item => typeof item !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/.test(item))) reject();
}
function stamp(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) reject();
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== (value.length === 20 ? value.replace('Z', '.000Z') : value)) reject();
  return time;
}
function frozen<T>(value: T): T {
  const result = structuredClone(value);
  function freeze(item: unknown): void {
    if (item && typeof item === 'object') { for (const child of Object.values(item)) freeze(child); Object.freeze(item); }
  }
  freeze(result); return result;
}
function checks(value: unknown): void {
  if (!Array.isArray(value) || value.length < 1 || value.length > CHECK_IDS.size) reject();
  const seen = new Set();
  for (const item of value) {
    shape(item, ['id', 'outcome'], ['artifactId']); id(item.id);
    if (!CHECK_IDS.has(item.id) || seen.has(item.id) || !['passed', 'failed', 'not_run'].includes(item.outcome as string)) reject();
    seen.add(item.id);
    if (item.outcome === 'passed' && !Object.hasOwn(item, 'artifactId')) reject();
    if (Object.hasOwn(item, 'artifactId')) id(item.artifactId);
  }
}

export function validateProviderReadiness(value: unknown): ProviderReadiness {
  safe(value);
  shape(value, ['schemaVersion', 'id', 'scope', 'appId', 'authKind', 'configurationGeneration', 'status', 'owner', 'backupOwner', 'accountTypes', 'supportedScopes', 'checks', 'checkedAt', 'expiresAt']);
  auth(value);
  if (value.schemaVersion !== 1 || !['oauth2', 'api-key', 'none'].includes(value.authKind as string) || !['not_configured', 'testing', 'production_ready'].includes(value.status as string)) reject();
  id(value.id); app(value.appId); validateScope(value.scope); id(value.owner); id(value.backupOwner);
  if (value.owner.toLowerCase() === value.backupOwner.toLowerCase()) reject();
  if (!Array.isArray(value.accountTypes) || !value.accountTypes.length || value.accountTypes.length > 16 || new Set(value.accountTypes).size !== value.accountTypes.length) reject();
  value.accountTypes.forEach(id); scopes(value.supportedScopes); checks(value.checks);
  if (value.authKind === 'none' && value.supportedScopes.length) reject();
  if (stamp(value.checkedAt) >= stamp(value.expiresAt)) reject();
  return frozen(value as unknown as ProviderReadiness);
}

export function validateCertificationEvidence(value: unknown): CertificationEvidence {
  safe(value);
  shape(value, ['schemaVersion', 'id', 'scope', 'appId', 'authKind', 'configurationGeneration', 'packageHash', 'capabilityId', 'definitionHash', 'accountType', 'requiredScopes', 'grantedScopes', 'environment', 'performedBy', 'checks', 'startedAt', 'completedAt', 'expiresAt']);
  auth(value);
  if (value.schemaVersion !== 1 || !['fixture', 'live'].includes(value.environment as string)) reject();
  id(value.id); app(value.appId); hash(value.packageHash); id(value.capabilityId); hash(value.definitionHash); id(value.accountType);
  const scope = validateScope(value.scope), principal = validatePrincipal(value.performedBy);
  assertSameScope(scope, principal.scope);
  scopes(value.requiredScopes); scopes(value.grantedScopes); checks(value.checks);
  if (value.authKind === 'none' && (value.requiredScopes.length || value.grantedScopes.length)) reject();
  if (stamp(value.startedAt) > stamp(value.completedAt) || stamp(value.completedAt) >= stamp(value.expiresAt)) reject();
  return frozen(value as unknown as CertificationEvidence);
}

export function validateCertificationTarget(value: unknown): CertificationTarget {
  safe(value);
  shape(value, ['schemaVersion', 'scope', 'appId', 'authKind', 'configurationGeneration', 'packageHash', 'capabilityId', 'definitionHash', 'accountType', 'requiredScopes', 'effect']);
  auth(value);
  if (value.schemaVersion !== 1 || !['read', 'write', 'delete'].includes(value.effect as string)) reject();
  validateScope(value.scope); app(value.appId); hash(value.packageHash); id(value.capabilityId); hash(value.definitionHash); id(value.accountType); scopes(value.requiredScopes);
  if (value.authKind === 'none' && value.requiredScopes.length) reject();
  return frozen(value as unknown as CertificationTarget);
}

// Supplies deterministic release-review prerequisites only. Artifact existence,
// evidence authenticity, registered client setup and live effects must be
// independently checked by the registry/verifier before publication.
export function assessCertification(input: unknown): CertificationAssessment {
  safe(input); shape(input, ['target', 'readiness', 'evidence', 'now']);
  const target = validateCertificationTarget(input.target);
  const readiness = validateProviderReadiness(input.readiness);
  const now = stamp(input.now);
  assertSameScope(target.scope, readiness.scope);
  if (target.appId !== readiness.appId || target.authKind !== readiness.authKind || target.configurationGeneration !== readiness.configurationGeneration || stamp(readiness.checkedAt) > now) reject();
  if (!Array.isArray(input.evidence) || input.evidence.length > 64) reject();
  const records = input.evidence.map(validateCertificationEvidence);
  const seen = new Set();
  for (const record of records) {
    assertSameScope(target.scope, record.scope);
    if (record.authKind !== target.authKind || record.configurationGeneration !== target.configurationGeneration) reject();
    if (record.appId !== target.appId || record.packageHash !== target.packageHash || record.capabilityId !== target.capabilityId || record.definitionHash !== target.definitionHash || record.accountType !== target.accountType || canonicalHash([...record.requiredScopes].sort()) !== canonicalHash([...target.requiredScopes].sort()) || stamp(record.completedAt) > now || seen.has(record.id)) reject();
    seen.add(record.id);
  }
  const blockers: string[] = [];
  if (readiness.status !== 'production_ready') blockers.push('provider_not_production_ready');
  if (stamp(readiness.expiresAt) <= now) blockers.push('provider_readiness_expired');
  if (!readiness.accountTypes.includes(target.accountType)) blockers.push('account_type_unsupported');
  if (target.requiredScopes.some(scope => !readiness.supportedScopes.includes(scope))) blockers.push('provider_scope_unsupported');
  const authChecks = readiness.authKind === 'oauth2' ? ['registration', 'callback', 'scope-mapping'] : readiness.authKind === 'api-key' ? ['credential-flow', 'scope-mapping'] : ['access-route'];
  for (const name of authChecks) if (!readiness.checks.some(check => check.id === name && check.outcome === 'passed')) blockers.push(`provider_check_missing:${name}`);
  if (readiness.checks.some(check => check.outcome === 'failed')) blockers.push('provider_check_failed');
  const evidenceIds: string[] = [];
  for (const environment of ['fixture', 'live'] as const) {
    const candidates = records.filter(record => record.environment === environment);
    // A newer failed run invalidates an older pass. Equal-time runs must all
    // meet the checks, preventing input order from selecting a convenient pass.
    const latestTime = Math.max(...candidates.map(record => stamp(record.completedAt)));
    const latest = candidates.filter(record => stamp(record.completedAt) === latestTime);
    if (!latest.length) { blockers.push(`${environment}_evidence_missing`); continue; }
    const required = environment === 'fixture' ? ['input-validation', 'output-validation', 'policy-denial'] : ['identity', ...(target.effect === 'read' ? ['read'] : [target.effect, 'readback'])];
    for (const record of latest) {
      evidenceIds.push(record.id);
      if (stamp(record.expiresAt) <= now) blockers.push(`${environment}_evidence_expired`);
      if (environment === 'live' && target.requiredScopes.some(scope => !record.grantedScopes.includes(scope))) blockers.push('live_scope_missing');
      if (record.checks.some(check => check.outcome === 'failed')) blockers.push(`${environment}_check_failed`);
      for (const name of required) if (!record.checks.some(check => check.id === name && check.outcome === 'passed')) blockers.push(`${environment}_check_missing:${name}`);
    }
  }
  return frozen({schemaVersion: 1, status: blockers.length ? 'blocked' : 'ready_for_release_review', assessedAt: new Date(now).toISOString(), blockers: [...new Set(blockers)].sort(), evidenceIds: evidenceIds.sort(), publicationAuthorized: false});
}

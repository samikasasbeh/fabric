import { isIP } from 'node:net';
import { canonicalHash, compileOpenApi, validateCapability } from './compiler.mjs';

// This is an offline preparation pipeline. Manifests and observations describe
// operator input; neither grants authorization nor certifies a live connection.
const APP_ID = /^[a-z][a-z0-9-]{0,63}$/;
const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const HASH = /^[a-f0-9]{64}$/;
const DAY_MS = 86_400_000;
const MAX_BATCH = 25;
const GATES = Object.freeze([
  'scope-resource-mapping-review',
  'identity-auth-setup',
  'fixture-certification',
  'live-certification',
  'release-approval',
]);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const has = (value, key) => Object.hasOwn(value, key);
const fail = message => { throw new Error(message); };
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function keys(value, allowed, label) {
  if (!record(value)) fail(`${label}: object required`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${label}: unsupported field ${key}`);
}

function text(value, label, max = 160) {
  if (typeof value !== 'string' || !value.length || value.length > max || value !== value.trim() || /[\u0000-\u001f\u007f]/.test(value)) fail(`${label}: bounded, nonblank text required`);
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${label}: lowercase SHA-256 required`);
}

function publicUrl(value, label, originOnly = false) {
  text(value, label, 2048);
  if (!value.startsWith('https://')) fail(`${label}: lowercase https:// scheme required`);
  if (/[\s\\{}?#]/.test(value)) fail(`${label}: invalid URL; query and fragment are unsupported`);
  let url;
  try { url = new URL(value); } catch { fail(`${label}: invalid URL`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash) fail(`${label}: credential-free HTTPS without query or fragment required`);
  const hostname = url.hostname;
  if (isIP(hostname.replace(/^\[|\]$/g, '')) || !hostname.includes('.') || hostname.length > 253 || /(?:^|\.)(?:localhost|local|internal|lan|test|invalid)$/.test(hostname) || !hostname.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) fail(`${label}: public DNS hostname required`);
  const authority = value.match(/^https:\/\/([^/]+)/)?.[1];
  if (!authority || /[%{}@]/.test(authority)) fail(`${label}: encoded, templated or credential-bearing authority is unsupported`);
  const rawPath = value.slice(value.indexOf(authority) + authority.length) || '/';
  if (/%|\/\/|(?:^|\/)\.{1,2}(?:\/|$)/.test(rawPath)) fail(`${label}: encoded or traversing path is unsupported`);
  if (originOnly && rawPath !== '/') fail(`${label}: origin must not contain a path`);
  return url;
}

// JSON validation happens before property reads, including getters and toJSON.
// Stable property order also makes the compiler's bounded work deterministic.
function orderedCopy(value) {
  if (Array.isArray(value)) return value.map(orderedCopy);
  if (record(value)) return Object.fromEntries(Object.keys(value).sort(compare).map(key => [key, orderedCopy(value[key])]));
  return value;
}

export function validateIntegrationManifest(manifest) {
  canonicalHash(manifest);
  if (Buffer.byteLength(JSON.stringify(manifest)) > 32_768) fail('Manifest exceeds 32768 bytes');
  keys(manifest, ['schemaVersion', 'appId', 'version', 'source', 'auth', 'maintenance'], 'Manifest');
  if (manifest.schemaVersion !== 1) fail('Manifest schemaVersion must be 1');
  if (typeof manifest.appId !== 'string' || !APP_ID.test(manifest.appId)) fail('Manifest appId is invalid');
  if (typeof manifest.version !== 'string' || manifest.version.length > 64 || !VERSION.test(manifest.version)) fail('Manifest version must be major.minor.patch without leading zeroes');
  keys(manifest.source, ['kind', 'url', 'allowedOrigins', 'sourceHash'], 'Manifest source');
  if (manifest.source.kind !== 'openapi') fail('Manifest source kind must be openapi');
  publicUrl(manifest.source.url, 'Manifest source URL');
  if (has(manifest.source, 'sourceHash')) hash(manifest.source.sourceHash, 'Manifest sourceHash');
  const origins = manifest.source.allowedOrigins;
  if (!Array.isArray(origins) || !origins.length || origins.length > 16) fail('Manifest allowedOrigins requires 1–16 origins');
  const normalizedOrigins = origins.map(origin => publicUrl(origin, 'Manifest allowedOrigin', true).origin);
  if (new Set(normalizedOrigins).size !== normalizedOrigins.length) fail('Manifest allowedOrigins contains duplicate origins');
  keys(manifest.auth, ['kind'], 'Manifest auth');
  if (!['oauth2', 'api-key', 'none'].includes(manifest.auth.kind)) fail('Manifest auth kind must be oauth2, api-key, or none');
  keys(manifest.maintenance, ['owner', 'backupOwner', 'tier', 'reviewIntervalDays'], 'Manifest maintenance');
  text(manifest.maintenance.owner, 'Maintenance owner');
  text(manifest.maintenance.backupOwner, 'Maintenance backupOwner');
  if (manifest.maintenance.owner.toLowerCase() === manifest.maintenance.backupOwner.toLowerCase()) fail('Maintenance primary and backup owners must be distinct');
  if (!['pilot', 'standard'].includes(manifest.maintenance.tier)) fail('Maintenance tier must be pilot or standard');
  if (!Number.isSafeInteger(manifest.maintenance.reviewIntervalDays) || manifest.maintenance.reviewIntervalDays < 1 || manifest.maintenance.reviewIntervalDays > 365) fail('Maintenance reviewIntervalDays must be an integer from 1 to 365');
  const validated = orderedCopy(manifest);
  validated.source.allowedOrigins = normalizedOrigins.sort(compare);
  return validated;
}

function assertAllowedRequest(request, allowedOrigins, label) {
  // The existing compiler validates request URL templates and credentials.
  if (!allowedOrigins.includes(new URL(request.url).origin)) fail(`${label}: request origin is outside manifest allowedOrigins`);
}

function checkServerDeclarations(document, allowedOrigins) {
  function servers(value) {
    if (!Array.isArray(value) || !value.length || value.length > 16) fail('OpenAPI servers must be a bounded nonempty array');
    for (const server of value) {
      if (!record(server) || has(server, 'variables')) fail('OpenAPI servers must use fixed URLs');
      const origin = publicUrl(server.url, 'OpenAPI server').origin;
      if (!allowedOrigins.includes(origin)) fail('OpenAPI server origin is outside manifest allowedOrigins');
    }
  }
  // Check server declarations in actual OpenAPI path/operation positions, even
  // when the compiler would skip an unsupported operation. Schema properties
  // named "servers" are not server declarations.
  function resolvedReference(item, seen = new Set()) {
    if (!record(item) || !has(item, '$ref')) return item;
    if (typeof item.$ref !== 'string' || !item.$ref.startsWith('#/') || item.$ref.includes('%')) fail('Only internal OpenAPI references are supported');
    if (seen.size >= 24 || seen.has(item.$ref)) fail('OpenAPI server inspection reference cycle or depth limit');
    const nextSeen = new Set(seen).add(item.$ref);
    let resolved = document;
    for (const part of item.$ref.slice(2).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'))) {
      resolved = record(resolved) && has(resolved, part) ? resolved[part] : undefined;
    }
    return resolvedReference(resolved, nextSeen);
  }
  function pathItem(item) {
    if (!record(item)) return;
    const resolved = resolvedReference(item);
    if (resolved !== item) pathItem(resolved);
    if (has(item, 'servers')) servers(item.servers);
    for (const method of ['get', 'head', 'post', 'put', 'patch', 'delete', 'options', 'trace']) {
      const operation = item[method];
      if (record(operation) && has(operation, 'servers')) servers(operation.servers);
      const resolvedOperation = resolvedReference(operation);
      if (record(resolvedOperation) && has(resolvedOperation, 'servers')) servers(resolvedOperation.servers);
    }
  }
  if (has(document, 'servers')) servers(document.servers);
  if (record(document.paths)) for (const item of Object.values(document.paths)) pathItem(item);
  if (record(document.webhooks)) for (const item of Object.values(document.webhooks)) pathItem(item);
  if (record(document.components?.pathItems)) for (const item of Object.values(document.components.pathItems)) pathItem(item);
}

function capabilityCounts(capabilities) {
  return {
    capabilities: capabilities.length,
    read: capabilities.filter(capability => capability.effect === 'read').length,
    write: capabilities.filter(capability => capability.effect === 'write').length,
  };
}

export function buildIntegrationPackage(input) {
  canonicalHash(input);
  keys(input, ['manifest', 'document'], 'Integration entry');
  const manifest = validateIntegrationManifest(input.manifest);
  const sourceHash = canonicalHash(input.document);
  if (manifest.source.sourceHash && manifest.source.sourceHash !== sourceHash) fail('Supplied document does not match manifest sourceHash');
  if (!record(input.document)) fail('OpenAPI document must be an object');
  checkServerDeclarations(input.document, manifest.source.allowedOrigins);
  const compiled = compileOpenApi({ appId: manifest.appId, document: orderedCopy(input.document), sourceUrl: manifest.source.url });
  const capabilities = compiled.capabilities.sort((left, right) => compare(left.id, right.id));
  const operationIds = new Set();
  for (const capability of capabilities) {
    if (capability.status !== 'candidate') fail('Compiler must produce candidate capabilities');
    if (operationIds.has(capability.provenance.operationId)) fail('Compiled OpenAPI operationIds must be unique');
    operationIds.add(capability.provenance.operationId);
    assertAllowedRequest(capability.request, manifest.source.allowedOrigins, 'Capability');
    if (capability.verification.kind === 'http-readback') assertAllowedRequest(capability.verification.request, manifest.source.allowedOrigins, 'Readback');
  }
  const prepared = {
    schemaVersion: 1,
    status: 'candidate',
    manifest,
    sourceHash,
    capabilities,
    warnings: [...compiled.warnings].sort(compare),
    counts: capabilityCounts(capabilities),
    requiredGates: [...GATES],
  };
  return { ...prepared, packageHash: canonicalHash(prepared) };
}

function validateBatchContainer(entries) {
  if (!Array.isArray(entries) || !entries.length || entries.length > MAX_BATCH) fail(`Integration batch requires 1–${MAX_BATCH} entries`);
  if (Object.getPrototypeOf(entries) !== Array.prototype) fail('Integration batch must be a plain JSON array');
  if (Object.getOwnPropertySymbols(entries).length) fail('Integration batch cannot contain symbol properties');
  const descriptors = Object.getOwnPropertyDescriptors(entries);
  for (let index = 0; index < entries.length; index++) {
    const descriptor = descriptors[index];
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) fail('Integration batch requires dense data entries without accessors');
  }
  for (const key of Object.keys(descriptors)) if (key !== 'length' && !/^(?:0|[1-9][0-9]*)$/.test(key)) fail('Integration batch has unsupported properties');
}

export function buildIntegrationBatch(entries) {
  validateBatchContainer(entries);
  const identities = new Map();
  const prepared = entries.map((entry, index) => {
    const result = { index };
    try {
      canonicalHash(entry);
      // Retain a safe identity before rejecting wrapper or manifest fields, so
      // malformed duplicate entries cannot leave a competing candidate intact.
      if (record(entry) && record(entry.manifest) && typeof entry.manifest.appId === 'string' && APP_ID.test(entry.manifest.appId) && typeof entry.manifest.version === 'string' && entry.manifest.version.length <= 64 && VERSION.test(entry.manifest.version)) {
        result.appId = entry.manifest.appId;
        result.version = entry.manifest.version;
        const key = `${result.appId}@${result.version}`;
        identities.set(key, (identities.get(key) || 0) + 1);
      }
      keys(entry, ['manifest', 'document'], 'Integration entry');
      validateIntegrationManifest(entry.manifest);
    } catch (error) {
      result.errors = [error.message];
    }
    return result;
  });
  const results = prepared.map(result => {
    if (result.appId && identities.get(`${result.appId}@${result.version}`) > 1) return { ...result, status: 'blocked', errors: [...(result.errors || []), 'Duplicate appId/version in integration batch'] };
    if (result.errors) return { ...result, status: 'blocked' };
    try {
      return { ...result, status: 'candidate', package: buildIntegrationPackage(entries[result.index]) };
    } catch (error) {
      return { ...result, status: 'blocked', errors: [error.message] };
    }
  });
  const candidate = results.filter(result => result.status === 'candidate').length;
  return {
    schemaVersion: 1,
    status: candidate === results.length ? 'candidate' : 'blocked',
    counts: { total: results.length, candidate, blocked: results.length - candidate, capabilities: results.reduce((count, result) => count + (result.package?.counts.capabilities || 0), 0) },
    results,
  };
}

function validatePackage(pkg) {
  canonicalHash(pkg);
  keys(pkg, ['schemaVersion', 'status', 'manifest', 'sourceHash', 'capabilities', 'warnings', 'counts', 'requiredGates', 'packageHash'], 'Integration package');
  hash(pkg.packageHash, 'Package hash');
  const { packageHash, ...content } = pkg;
  if (canonicalHash(content) !== packageHash) fail('Integration package integrity mismatch');
  if (pkg.schemaVersion !== 1 || pkg.status !== 'candidate') fail('Integration package must remain a schemaVersion 1 candidate');
  const manifest = validateIntegrationManifest(pkg.manifest);
  hash(pkg.sourceHash, 'Package sourceHash');
  if (manifest.source.sourceHash && manifest.source.sourceHash !== pkg.sourceHash) fail('Package sourceHash differs from manifest pin');
  if (!Array.isArray(pkg.capabilities) || !pkg.capabilities.length || pkg.capabilities.length > 256) fail('Package requires 1–256 candidate capabilities');
  const ids = new Set();
  const operationIds = new Set();
  for (const capability of pkg.capabilities) {
    validateCapability(capability);
    if (capability.status !== 'candidate' || capability.appId !== manifest.appId || capability.provenance.kind !== 'openapi' || capability.provenance.fingerprint !== pkg.sourceHash || capability.provenance.source !== manifest.source.url) fail('Package capability identity or candidate provenance mismatch');
    if (ids.has(capability.id)) fail('Package contains duplicate capability IDs');
    ids.add(capability.id);
    if (operationIds.has(capability.provenance.operationId)) fail('Package contains duplicate OpenAPI operationIds');
    operationIds.add(capability.provenance.operationId);
    assertAllowedRequest(capability.request, manifest.source.allowedOrigins, 'Capability');
    if (capability.verification.kind === 'http-readback') assertAllowedRequest(capability.verification.request, manifest.source.allowedOrigins, 'Readback');
  }
  if (canonicalHash(pkg.counts) !== canonicalHash(capabilityCounts(pkg.capabilities))) fail('Package capability counts mismatch');
  if (canonicalHash(pkg.requiredGates) !== canonicalHash(GATES)) fail('Package requires all next review gates');
  if (!Array.isArray(pkg.warnings) || pkg.warnings.some(warning => typeof warning !== 'string')) fail('Package warnings are invalid');
  return manifest;
}

function timestamp(value, label) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) fail(`${label}: ISO UTC timestamp required`);
  const time = Date.parse(value);
  const normalized = value.includes('.') ? value : value.replace('Z', '.000Z');
  if (!Number.isFinite(time) || new Date(time).toISOString() !== normalized) fail(`${label}: invalid timestamp`);
  return time;
}

export function assessMaintenance(input) {
  canonicalHash(input);
  keys(input, ['package', 'observation', 'now'], 'Maintenance assessment');
  const manifest = validatePackage(input.package);
  const { observation } = input;
  keys(observation, ['packageHash', 'checkedAt', 'sourceHash', 'lastReviewedAt'], 'Maintenance observation');
  hash(observation.packageHash, 'Observation packageHash');
  if (observation.packageHash !== input.package.packageHash) fail('Observation packageHash does not match the assessed package');
  hash(observation.sourceHash, 'Observation sourceHash');
  const now = timestamp(input.now, 'now');
  const checkedAt = timestamp(observation.checkedAt, 'checkedAt');
  if (checkedAt > now) fail('Observation checkedAt cannot be in the future');
  const lastReviewedAt = has(observation, 'lastReviewedAt') ? timestamp(observation.lastReviewedAt, 'lastReviewedAt') : null;
  if (lastReviewedAt !== null && lastReviewedAt > checkedAt) fail('lastReviewedAt cannot be later than checkedAt');
  const interval = manifest.maintenance.reviewIntervalDays * DAY_MS;
  const nextReviewAt = lastReviewedAt === null ? null : lastReviewedAt + interval;
  const nextCheckAt = checkedAt + interval;
  const reviewDue = nextReviewAt === null || now >= nextReviewAt;
  const observationStale = now >= nextCheckAt;
  const sourceDrift = observation.sourceHash !== input.package.sourceHash;
  const requiredActions = [];
  if (reviewDue) requiredActions.push('maintenance-review');
  if (observationStale) requiredActions.push('source-check');
  if (sourceDrift) requiredActions.push('source-change-review');
  return {
    schemaVersion: 1,
    appId: manifest.appId,
    version: manifest.version,
    status: requiredActions.length ? 'blocked' : 'candidate',
    assessedAt: new Date(now).toISOString(),
    checkedAt: new Date(checkedAt).toISOString(),
    reviewDue,
    nextReviewAt: nextReviewAt === null ? null : new Date(nextReviewAt).toISOString(),
    observationStale,
    nextCheckAt: new Date(nextCheckAt).toISOString(),
    sourceDrift,
    requiredActions,
  };
}

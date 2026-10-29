import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { canonicalHash, compileOpenApi, finalizeCapability } from './compiler.mjs';
import { safeRequest } from './network.mjs';
import { securityRequirements, assertServable, credentialLocations, exchangeUrls } from './openapi-security.mjs';
import { sensitivity, SENSITIVITY_VERSION } from './sensitivity.mjs';

const MAX_OPERATIONS = 500;
const METHODS = new Set(['get', 'head', 'post', 'put', 'patch', 'delete', 'options', 'trace', 'query']);
const UNSAFE = new Set(['__proto__', 'constructor', 'prototype']);
const NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const AUTH_PARAMETER = /^(?:key|token|access_token|oauth_token|refresh_token|api[_-]?key|authorization|password|client_secret)$/i;
const SCHEMA_KEYS = new Set(['type', '$ref', 'description', 'id', 'properties', 'items', 'required', 'annotations', 'readOnly', 'additionalProperties', 'enum', 'enumDescriptions', 'enumDeprecated', 'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'format', 'default', 'pattern', 'deprecated', 'location', 'repeated', 'parameterName']);
const has = (object, key) => Object.hasOwn(object, key);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const clone = value => JSON.parse(JSON.stringify(value));
const error = message => { throw new Error(message); };
const effect = method => method === 'DELETE' ? 'delete' : ['GET', 'HEAD'].includes(method) ? 'read' : 'write';
const message = reason => String(reason?.message || reason).slice(0, 1200);

function sourceUrl(value, kind) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\\u0000-\u001f\u007f]/.test(value)) error('Discovery needs a fixed public HTTPS catalog URL.');
  let url;
  try { url = new URL(value); } catch { error('Invalid catalog discovery URL.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.port) error('Discovery source must be credential-free HTTPS on port 443.');
  const host = url.hostname;
  if (isIP(host.replace(/^\[|\]$/g, '')) || !host.includes('.') || host.endsWith('.') || /(?:^|\.)(?:localhost|local|internal|lan|test|invalid)$/.test(host)) error('Discovery source must have a public DNS hostname.');
  if (kind === 'google-discovery' && !/^[a-z0-9-]+\.googleapis\.com$/.test(host)) error('Google discovery must use an official Google APIs catalog source.');
  return url;
}

function allowedBase(value, allowedOrigins) {
  const url = sourceUrl(value, 'openapi');
  if (url.search || /[{}%]|(?:^|\/)\.{1,2}(?:\/|$)/.test(value.replace(/^https:\/\/[^/]+/, ''))) error('API base URL cannot contain query, templates, encoding, or traversal.');
  if (!allowedOrigins.includes(url.origin)) error('Discovered API origin is outside the selected application catalog authority.');
  return url.toString().replace(/\/$/, '');
}

// OAS server URLs may be relative to their containing source document. Resolve
// that URL only against the fetched source, never a guessed application domain.
// The independently declared API-origin boundary remains mandatory.
function relativeOpenApiBase(document, source, allowedOrigins) {
  const servers = document.servers;
  if (!Array.isArray(servers) || servers.length !== 1 || !object(servers[0]) || servers[0].variables) return undefined;
  const value = servers[0].url;
  if (typeof value !== 'string' || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value)) return undefined;
  if (!value || value.length > 4096 || value.startsWith('//') || /[\s\\{}%?#\u0000-\u001f\u007f]/.test(value)) error('Relative OpenAPI server must be a fixed, unencoded path.');
  return allowedBase(new URL(value, source).href, allowedOrigins);
}

function readPointer(document, ref) {
  if (typeof ref !== 'string' || !ref.startsWith('#/') || ref.includes('%') || /~(?![01])/.test(ref)) error('Only unencoded internal OpenAPI references are supported.');
  let current = document;
  const parts = ref.slice(2).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'));
  if (parts.length > 24 || parts.some(part => UNSAFE.has(part))) error('Unsafe or overly deep OpenAPI reference.');
  for (const part of parts) {
    if (!object(current) && !Array.isArray(current) || !has(current, part)) error(`Missing OpenAPI reference ${ref}.`);
    current = current[part];
  }
  return current;
}

function resolve(document, value, seen = []) {
  if (!object(value) || !has(value, '$ref')) return value;
  if (seen.length >= 24 || seen.includes(value.$ref)) error('Cyclic or overly deep OpenAPI reference.');
  if (Object.keys(value).some(key => key !== '$ref')) error('OpenAPI reference siblings are unsupported.');
  return resolve(document, readPointer(document, value.$ref), [...seen, value.$ref]);
}

// Keep referenced schemas as metadata rather than recursively expanding response
// objects. Recursive output resources are normal and do not imply input support.
function googleSchemaGraph(document, root) {
  if (!root) return null;
  const schemas = {};
  const visited = new Set();
  let nodes = 0;
  function walk(value, depth = 0, position = 'schema') {
    if (++nodes > 20_000 || depth > 40) error('Google schema metadata exceeds inspection limits.');
    if (Array.isArray(value)) { value.forEach(item => walk(item, depth + 1, position === 'schema-list' ? 'schema' : 'metadata')); return; }
    if (!object(value)) return;
    if (position === 'schema' && has(value, '$ref')) {
      const name = value.$ref;
      if (typeof name !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,199}$/.test(name)) error('Invalid Google schema reference.');
      if (!object(document.schemas) || !has(document.schemas, name)) error(`Missing Google schema ${name}.`);
      if (!visited.has(name)) {
        if (visited.size >= 256) error('Too many referenced Google schemas.');
        visited.add(name);
        schemas[name] = clone(document.schemas[name]);
        walk(document.schemas[name], depth + 1);
      }
    }
    for (const [key, item] of Object.entries(value)) {
      if (position === 'schema' && key === '$ref') continue;
      // A properties map contains names, not schema keywords. In particular,
      // properties.$ref is a field's schema rather than a reference string.
      // Still walk all metadata to preserve the existing depth/node budget.
      const childPosition = position === 'properties' ? 'schema'
        : position === 'schema' && key === 'properties' ? 'properties'
        : position === 'schema' && ['items', 'additionalProperties'].includes(key) ? 'schema'
        : position === 'schema' && key === 'variant' ? 'variant'
        : position === 'variant' && key === 'map' ? 'schema-list'
        : 'metadata';
      walk(item, depth + 1, childPosition);
    }
  }
  walk(root);
  return { dialect: 'google-discovery', root: clone(root), schemas };
}

function numericBound(value, name) {
  const number = typeof value === 'string' && /^-?\d+(?:\.\d+)?$/.test(value) ? Number(value) : value;
  if (typeof number !== 'number' || !Number.isFinite(number)) error(`Unsupported ${name} constraint.`);
  return number;
}

function requiredProperty(schema, methodId) {
  if (!object(schema)) return false;
  if (schema.required === true) return true;
  const annotated = schema.annotations?.required;
  if (annotated !== undefined && (!Array.isArray(annotated) || annotated.some(item => typeof item !== 'string'))) error('Invalid method-specific required annotation.');
  return Boolean(annotated?.includes(methodId));
}

function googleInput(document, original, methodId, gaps, label, seen = [], budget = { nodes: 0 }) {
  if (++budget.nodes > 4096 || seen.length > 24 || !object(original)) error(`${label}: unsupported or overly complex input schema.`);
  let schema = original;
  if (has(original, '$ref')) {
    const name = original.$ref;
    if (typeof name !== 'string' || seen.includes(name) || !object(document.schemas?.[name])) error(`${label}: missing or recursive input schema ${name}.`);
    if (Object.keys(original).some(key => !['$ref', 'description', 'annotations', 'required', 'readOnly', 'parameterName'].includes(key))) error(`${label}: unsupported reference constraints.`);
    schema = { ...document.schemas[name], ...Object.fromEntries(Object.entries(original).filter(([key]) => key !== '$ref')) };
    seen = [...seen, name];
  }
  for (const key of Object.keys(schema)) if (!SCHEMA_KEYS.has(key)) error(`${label}: unsupported Google input keyword ${key}.`);
  if (schema.parameterName !== undefined && typeof schema.parameterName !== 'string') error(`${label}: invalid request parameterName annotation.`);
  if (schema.pattern !== undefined) error(`${label}: pattern constraints require an unsupported validator.`);
  if (schema.required !== undefined && typeof schema.required !== 'boolean' && !Array.isArray(schema.required)) error(`${label}: unsupported required constraint.`);
  if (schema.readOnly !== undefined && typeof schema.readOnly !== 'boolean') error(`${label}: invalid readOnly constraint.`);
  const type = schema.type;
  if (!['string', 'integer', 'number', 'boolean', 'object', 'array'].includes(type)) error(`${label}: explicit supported input type required.`);
  const result = { type };
  if (typeof schema.description === 'string') result.description = schema.description;
  if (has(schema, 'enum')) {
    if (!Array.isArray(schema.enum)) error(`${label}: enum must be an array.`);
    result.enum = clone(schema.enum);
  }
  for (const key of ['minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems']) if (has(schema, key)) result[key] = numericBound(schema[key], key);
  if (schema.format) {
    if (schema.format === 'uint32' && type === 'integer') {
      result.minimum = Math.max(0, result.minimum ?? 0);
      result.maximum = Math.min(4294967295, result.maximum ?? 4294967295);
    } else if (['int32', 'int64'].includes(schema.format) && type === 'integer') result.format = schema.format;
    else if (['float', 'double'].includes(schema.format) && type === 'number') result.format = schema.format;
    else if (['date', 'date-time'].includes(schema.format) && type === 'string') result.format = schema.format;
    else error(`${label}: format ${schema.format} cannot be enforced by the current compiler.`);
  }
  // Defaults are documentation, not mandatory request values. Discovery encodes
  // numeric/boolean defaults as strings; do not coerce or inject them.
  if (type === 'object') {
    if (schema.additionalProperties !== undefined && schema.additionalProperties !== false) error(`${label}: dynamic input property maps are unsupported.`);
    if (schema.properties !== undefined && !object(schema.properties)) error(`${label}: invalid object properties.`);
    result.properties = {};
    result.additionalProperties = false;
    result.required = [];
    const names = Array.isArray(schema.required) ? schema.required : [];
    if (names.some(name => typeof name !== 'string' || !has(schema.properties || {}, name))) error(`${label}: required property is undeclared.`);
    for (const [name, child] of Object.entries(schema.properties || {}).sort(([a], [b]) => a.localeCompare(b))) {
      const required = names.includes(name) || requiredProperty(child, methodId);
      if (child?.readOnly === true) {
        if (required) error(`${label}.${name}: required read-only input cannot be synthesized.`);
        gaps.push(`${label}.${name}: output-only field is not an input.`);
        continue;
      }
      try { result.properties[name] = googleInput(document, child, methodId, gaps, `${label}.${name}`, seen, budget); }
      catch (cause) {
        if (required) throw cause;
        gaps.push(`Optional input omitted: ${message(cause)}`);
        continue;
      }
      if (required) result.required.push(name);
    }
  }
  if (type === 'array') result.items = googleInput(document, schema.items, methodId, gaps, `${label}[]`, seen, budget);
  return result;
}

function googleParameters(document, method, methodId, gaps) {
  const result = [];
  for (const [name, raw] of Object.entries({ ...(document.parameters || {}), ...(method.parameters || {}) }).sort(([a], [b]) => a.localeCompare(b))) {
    if (!object(raw)) error(`Invalid parameter ${name}.`);
    const required = raw.required === true;
    const inherited = !has(method.parameters || {}, name);
    if (AUTH_PARAMETER.test(name) || (inherited && ['alt', '$.xgafv', 'uploadType', 'upload_protocol', 'callback'].includes(name))) {
      if (required) error(`Required transport/authentication parameter ${name} is not available to generated functions.`);
      gaps.push(`Transport parameter ${name} is reserved to the broker or omitted; JSON response route only.`);
      continue;
    }
    try {
      if (!NAME.test(name) || UNSAFE.has(name) || !['query', 'path'].includes(raw.location)) error(`Unsupported parameter name or location: ${name}.`);
      let schema = googleInput(document, raw, methodId, gaps, `parameter.${name}`);
      if (raw.repeated !== undefined && typeof raw.repeated !== 'boolean') error(`Invalid repeated parameter ${name}.`);
      if (raw.repeated) {
        if (raw.location !== 'query') error(`Repeated path parameter ${name} is unsupported.`);
        schema = { type: 'array', items: schema };
      }
      result.push({ name, in: raw.location, required, schema });
    } catch (cause) {
      if (required || raw.location === 'path') throw cause;
      gaps.push(`Optional input omitted: ${message(cause)}`);
    }
  }
  return result;
}

function googleMethods(document) {
  const entries = [];
  function visit(node, resource = '', depth = 0) {
    if (!object(node) || depth > 24) error('Malformed or overly nested Google resources.');
    if (node.methods !== undefined && !object(node.methods)) error('Google methods must be an object.');
    for (const [name, method] of Object.entries(node.methods || {})) {
      if (entries.length >= MAX_OPERATIONS) error(`Discovery exceeds ${MAX_OPERATIONS} documented methods; choose a scoped source.`);
      entries.push({ name, resource: resource || document.name || 'api', method });
    }
    if (node.resources !== undefined && !object(node.resources)) error('Google resources must be an object.');
    for (const [name, child] of Object.entries(node.resources || {})) visit(child, resource ? `${resource}.${name}` : name, depth + 1);
  }
  visit(document);
  return entries;
}

function googleOperation(document, entry, base, appId) {
  const { method: raw, name, resource } = entry;
  if (!object(raw) || typeof raw.id !== 'string' || !raw.id || raw.id.length > 512) error('Google discovery method lacks a bounded provider method ID.');
  const method = typeof raw.httpMethod === 'string' ? raw.httpMethod.toUpperCase() : '';
  const path = typeof raw.path === 'string' ? `/${raw.path.replace(/^\//, '')}` : '';
  const gaps = [];
  const operation = { id: raw.id, capabilityId: null, name: raw.id, description: typeof raw.description === 'string' ? raw.description : '', method, path, effect: effect(method), resource, requiredScopes: [], scopeSets: [], support: 'unsupported', gaps };
  let requestGraph = null;
  let responseGraph = null;
  try {
    if (raw.scopes !== undefined && (!Array.isArray(raw.scopes) || raw.scopes.some(scope => typeof scope !== 'string' || scope.length > 2048))) error('Invalid documented Google OAuth scopes.');
    operation.requiredScopes = [...new Set(raw.scopes || [])];
    operation.scopeSets = operation.requiredScopes.map(scope => [scope]);
    requestGraph = googleSchemaGraph(document, raw.request);
    responseGraph = googleSchemaGraph(document, raw.response);
    if (responseGraph) operation.responseSchema = responseGraph;
    if (!method || !path || !METHODS.has(method.toLowerCase())) error('Unsupported or missing provider HTTP method/path.');
    const parameters = googleParameters(document, raw, raw.id, gaps);
    const converted = { operationId: raw.id, summary: `${resource}: ${name}`, description: operation.description, parameters, responses: { default: { description: 'Documented provider response; not independent effect verification.' } } };
    if (raw.request) converted.requestBody = { required: true, content: { 'application/json': { schema: googleInput(document, raw.request, raw.id, gaps, 'body') } } };
    const scoped = {
      openapi: '3.1.0', info: { title: `${document.name || appId} discovered operation`, version: String(document.version || '1') },
      servers: [{ url: base }], paths: { [path]: { [method.toLowerCase()]: converted } },
      'x-fabric-source': { dialect: 'google-discovery', operation: clone(raw), requestSchema: requestGraph, responseSchema: responseGraph, commonParameters: clone(document.parameters || {}) },
    };
    return { operation, scoped, semantic: { raw, base, requestGraph, responseGraph, commonParameters: document.parameters || {} } };
  } catch (cause) {
    operation.reason = message(cause);
    return { operation, scoped: null, semantic: { raw, base, requestGraph, responseGraph, commonParameters: document.parameters || {} } };
  }
}

function scopedOpenApi(document, path, method, pathItem, operation) {
  const paths = { [path]: { ...(pathItem.parameters ? { parameters: clone(pathItem.parameters) } : {}), ...(pathItem.servers ? { servers: clone(pathItem.servers) } : {}), [method]: clone(operation) } };
  const scoped = { openapi: document.openapi, info: { title: 'Discovered operation', version: '1' }, servers: clone(document.servers || []), paths };
  if (document.security) scoped.security = clone(document.security);
  const components = {};
  const refs = new Set();
  let nodes = 0;
  function walk(value, depth = 0) {
    if (++nodes > 30_000 || depth > 40) error('OpenAPI referenced metadata exceeds limits.');
    if (Array.isArray(value)) { value.forEach(item => walk(item, depth + 1)); return; }
    if (!object(value)) return;
    if (has(value, '$ref')) {
      const ref = value.$ref;
      if (typeof ref !== 'string' || !/^#\/components\/[A-Za-z][A-Za-z0-9_]*\/[A-Za-z][A-Za-z0-9_.-]*$/.test(ref)) error('Only standard internal component references are supported for discovery.');
      if (!refs.has(ref)) {
        if (refs.size >= 512) error('Too many referenced OpenAPI components.');
        refs.add(ref);
        const resolved = readPointer(document, ref);
        const [, , section, name] = ref.split('/');
        components[section] ||= {};
        components[section][name] = clone(resolved);
        walk(resolved, depth + 1);
      }
    }
    for (const [key, item] of Object.entries(value)) if (key !== '$ref') walk(item, depth + 1);
  }
  walk(paths);
  // Security scheme definitions affect the connection requirements even though
  // the request compiler never obtains or injects their credentials.
  for (const requirement of operation.security ?? document.security ?? []) {
    if (!object(requirement)) error('Invalid OpenAPI security requirements.');
    for (const name of Object.keys(requirement)) {
      const schema = document.components?.securitySchemes?.[name];
      if (!schema) error(`Missing security scheme ${name}.`);
      components.securitySchemes ||= {};
      components.securitySchemes[name] = clone(schema);
    }
  }
  if (Object.keys(components).length) scoped.components = components;
  return scoped;
}

// Scopes come only from security alternatives Fabric can serve (lib/openapi-security.mjs). Dropped alternatives
// are recorded as gaps; an operation with none left is unsupported.
function openApiScopes(document, operation, gaps) {
  const requirements = assertServable(securityRequirements(document, operation));
  for (const { schemes, reason } of requirements.dropped) gaps.push(`Security alternative ${schemes.join(' + ') || 'none'} left out: ${reason}`);
  const sets = requirements.alternatives.map(alternative => alternative.scopes);
  return { scopeSets: sets, requiredScopes: [...new Set(sets.flat())] };
}

function openApiMethods(document) {
  if (typeof document.openapi !== 'string' || !/^3\.(?:0|1|2)\.\d+$/.test(document.openapi) || !object(document.paths)) error('Discovery source must be an OpenAPI 3.x JSON document.');
  const result = [];
  for (const [path, raw] of Object.entries(document.paths)) {
    const pathItem = resolve(document, raw);
    if (!object(pathItem)) error(`Invalid OpenAPI path ${path}.`);
    for (const [method, rawOperation] of Object.entries(pathItem)) {
      if (!METHODS.has(method)) continue;
      if (result.length >= MAX_OPERATIONS) error(`Discovery exceeds ${MAX_OPERATIONS} documented methods.`);
      const operation = resolve(document, rawOperation);
      if (!object(operation)) error(`Invalid OpenAPI operation ${method} ${path}.`);
      result.push({ path, method, pathItem, operation });
    }
  }
  return result;
}

function openApiOperation(document, entry) {
  const { path, method, pathItem, operation: raw } = entry;
  const id = typeof raw.operationId === 'string' && raw.operationId ? raw.operationId : `${method.toUpperCase()} ${path}`;
  const operation = { id, capabilityId: null, name: typeof raw.summary === 'string' ? raw.summary : id, description: typeof raw.description === 'string' ? raw.description : '', method: method.toUpperCase(), path, effect: effect(method.toUpperCase()), resource: Array.isArray(raw.tags) && typeof raw.tags[0] === 'string' ? raw.tags[0] : path.split('/').find(Boolean) || 'api', requiredScopes: [], scopeSets: [], support: 'unsupported', gaps: [] };
  try {
    Object.assign(operation, openApiScopes(document, raw, operation.gaps));
    const scoped = scopedOpenApi(document, path, method, pathItem, raw);
    operation.responseSchema = { dialect: 'openapi', responses: clone(raw.responses || {}), components: clone(scoped.components || {}) };
    return { operation, scoped, semantic: scoped };
  } catch (cause) {
    operation.reason = message(cause);
    return { operation, scoped: null, semantic: { path, method, raw, parameters: pathItem.parameters || [], servers: pathItem.servers || document.servers || [] } };
  }
}

function changesBetween(previous, operations) {
  const old = new Map((previous?.operations || []).map(operation => [operation.id, operation]));
  const current = new Map(operations.map(operation => [operation.id, operation]));
  const changes = { added: [], changed: [], removed: [], unchanged: 0 };
  for (const operation of operations) {
    if (!old.has(operation.id)) changes.added.push(operation.id);
    else if (old.get(operation.id).fingerprint !== operation.fingerprint || old.get(operation.id).capabilityId !== operation.capabilityId || old.get(operation.id).support !== operation.support) changes.changed.push(operation.id);
    else changes.unchanged++;
  }
  for (const id of old.keys()) if (!current.has(id)) changes.removed.push(id);
  return changes;
}

export class DiscoveryEngine {
  /** `onMapStored(appId, map)` (F10.11 part p) is called once an app's map is stored, so a server can load that app's actions again. */
  constructor({ store, catalog, acquisition, request = safeRequest, onMapStored = null }) { Object.assign(this, { store, catalog, acquisition, request, onMapStored }); }

  async discover({ appId } = {}) {
    if (typeof appId !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(appId)) error('Choose a valid catalog application.');
    const applications = typeof this.catalog === 'function' ? this.catalog() : this.catalog;
    const app = applications?.find(item => item.id === appId);
    if (!app) error('Unknown catalog application.');
    const discovery = app.discovery;
    if (!object(discovery) || !['google-discovery', 'openapi'].includes(discovery.kind)) error('This application has no supported catalog discovery source. No interface was invented.');
    const source = sourceUrl(discovery.url, discovery.kind);
    const response = await this.request({ url: source.href, method: 'GET', headers: { Accept: 'application/json' }, allowedOrigins: [source.origin], timeoutMs: 30_000, maxBytes: 2 * 1024 * 1024 });
    if (response.status !== 200) error(`Application discovery returned HTTP ${response.status}; previous map remains unchanged.`);
    const document = response.data;
    if (!object(document)) error('Application discovery did not return a JSON object.');
    const fingerprint = canonicalHash(document); // Includes bounded plain-JSON validation.
    const allowedOrigins = app.apiOrigins || app.allowedOrigins || [];
    if (!Array.isArray(allowedOrigins) || !allowedOrigins.length) error('Application has no approved API origins.');
    let descriptors;
    if (discovery.kind === 'google-discovery') {
      if (document.kind !== 'discovery#restDescription' || document.discoveryVersion !== 'v1' || document.protocol !== 'rest') error('Source is not a supported Google REST Discovery document.');
      const base = allowedBase(document.baseUrl || `${document.rootUrl || ''}${document.servicePath || ''}`, allowedOrigins);
      descriptors = googleMethods(document).map(entry => googleOperation(document, entry, base, appId));
    } else {
      descriptors = openApiMethods(document).map(entry => openApiOperation(document, entry));
    }
    // Credential locations and OAuth endpoints come from the whole source, since each operation compiles alone.
    let credentials;
    if (discovery.kind === 'openapi') {
      let server;
      try { server = typeof document.servers?.[0]?.url === 'string' ? new URL(document.servers[0].url, source).href.replace(/\/$/, '') : undefined; } catch { server = undefined; }
      credentials = { locations: credentialLocations(document), exchanges: exchangeUrls(document, server), ...(object(document.components?.securitySchemes) ? { schemes: document.components.securitySchemes } : {}) };
    }
    const ids = new Set();
    const candidates = [];
    for (const descriptor of descriptors) {
      const { operation, scoped, semantic } = descriptor;
      if (ids.has(operation.id)) error(`Discovery contains duplicate provider operation ID ${operation.id}; map not replaced.`);
      ids.add(operation.id);
      operation.fingerprint = canonicalHash(semantic);
      if (!scoped) continue;
      try {
        const baseUrl = discovery.kind === 'openapi' ? relativeOpenApiBase(scoped, source, allowedOrigins) : undefined;
        const compiled = compileOpenApi({ appId, document: scoped, ...(baseUrl === undefined ? {} : { baseUrl }), ...(credentials ? { credentials } : {}) });
        if (compiled.capabilities.length !== 1) error('Expected exactly one compiled operation.');
        let cap = compiled.capabilities[0];
        if (!allowedOrigins.includes(new URL(cap.request.url).origin)) error('Discovered request origin is outside the selected application catalog authority.');
        cap = finalizeCapability({ ...cap, provenance: { ...cap.provenance, source: source.href } });
        candidates.push(cap);
        operation.capabilityId = cap.id;
        operation.support = 'candidate';
        // Returns credentials, or a GET named like a change: never a default Allow (docs/F09-COMPILER-COVERAGE.md I9).
        operation.sensitive = sensitivity(cap, operation);
        operation.gaps.push(...compiled.warnings);
        if (operation.effect !== 'read') operation.gaps.push('Requires reviewed account-specific consent (Ask per job or explicit Allow); provider acknowledgement alone is not independently verified success.');
      } catch (cause) { operation.reason = message(cause); }
    }
    // Validate the entire candidate batch before any application-map replacement.
    this.acquisition.saveCandidates(appId, candidates);
    const previous = this.store.get('applicationMaps', appId);
    const operations = descriptors.map(descriptor => descriptor.operation).sort((a, b) => a.id.localeCompare(b.id));
    const counts = { total: operations.length, candidate: 0, unsupported: 0, read: 0, write: 0, delete: 0 };
    for (const operation of operations) { counts[operation.support]++; counts[operation.effect]++; }
    const discoveredAt = new Date().toISOString();
    const changes = changesBetween(previous, operations);
    const historicalCapabilityIds = [...new Set([...(previous?.historicalCapabilityIds || []), ...(previous?.operations || []).map(operation => operation.capabilityId).filter(Boolean), ...operations.map(operation => operation.capabilityId).filter(Boolean)])];
    const map = {
      id: appId, appId, name: app.name || appId, status: !counts.total ? 'unsupported' : counts.unsupported ? 'partial' : 'ready', sourceKind: discovery.kind, sourceUrl: source.href,
      fingerprint, discoveredAt, operations, counts, changes, historicalCapabilityIds, classifierVersion: SENSITIVITY_VERSION,
      gaps: [
        'This map describes the provider interface, not account contents or granted permissions. Discovery performs no account-data requests.',
        'Candidate means a restricted request function was compiled, not activated or validated against a live account.',
        'Provider business rules described only in prose remain provider-enforced; unsupported optional inputs are explicitly omitted, never accepted unchecked.',
        ...(!counts.total ? ['The source currently documents no available methods. Previously discovered capabilities are retained as history, not current support.'] : []),
        ...(counts.unsupported ? [`${counts.unsupported} documented operations are unsupported; inspect their reasons before designing additional adapters.`] : []),
      ],
    };
    this.store.put('applicationMaps', map);
    this.onMapStored?.(appId, map);
    this.store.put('applicationMapHistory', { id: `${appId}:${randomUUID()}`, appId, sourceUrl: source.href, fingerprint, discoveredAt, counts, changes, operations: operations.map(({ id, fingerprint, capabilityId, support }) => ({ id, fingerprint, capabilityId, support })) });
    this.store.put('discoverySources', { id: `${appId}:${fingerprint}`, appId, sourceUrl: source.href, fingerprint, discoveredAt, document });
    this.store.audit({ type: 'application.discovered', appId, fingerprint, counts, changes });
    return map;
  }
}

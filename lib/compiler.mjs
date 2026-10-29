import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { securityRequirements, assertServable, credentialLocations, exchangeUrls, reachesEndpoint } from './openapi-security.mjs';

// A deliberately small, declarative compiler. No supplied code, external $refs,
// executable templates, credentials, or permissive unknown schema keywords.
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_DEPTH = 40;
const MAX_NODES = 50_000;
const UNSAFE_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const READ_METHODS = new Set(['GET', 'HEAD']);
const NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const APP_ID = /^[a-z][a-z0-9-]{0,63}$/;
const SECRET_PARAMETER = /^(?:authorization|cookie|password|passwd|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|token|key)$/i;
/** F10.9: a parameter name that is a credential as a whole, in any case. It catches `key`, which credentialName() leaves out. */
export const secretParameter = name => SECRET_PARAMETER.test(name);
// F09.1: names that carry a credential, read at word boundaries (AuthToken, appKey, api_secret, x-api-key, password).
// Identifiers of credentials (secret_name, key_id, pageToken, syncToken, publicKey) are not credentials.
// "secrets" (plural) is left out: as a field it names a collection or a permission level (GitHub's "secrets": "read").
const CREDENTIAL_WORDS = new Set(['password', 'passwd', 'passphrase', 'pwd', 'secret', 'credential', 'credentials', 'cookie', 'authorization', 'bearer', 'apikey', 'appkey', 'apisecret', 'clientsecret', 'accesstoken', 'authtoken', 'refreshtoken', 'idtoken', 'sessiontoken', 'sessionid', 'privatekey', 'secretkey', 'accesskey']);
const STRONG_WORDS = new Set(['password', 'passwd', 'passphrase', 'secret', 'credential', 'credentials', 'apikey', 'apisecret', 'clientsecret', 'privatekey', 'secretkey']);
const IDENTIFIER_HEADS = new Set(['name', 'names', 'id', 'ids', 'uuid', 'guid', 'slug', 'number', 'num', 'index', 'label', 'arn', 'ref', 'handle', 'alias', 'type', 'types', 'policy', 'policies', 'length', 'strength', 'expires', 'expiry', 'expiration', 'at', 'required', 'enabled', 'hint', 'rules', 'count', 'url', 'uri', 'sid', 'scope', 'scopes', 'status', 'prefix', 'version', 'fingerprint']);
// Words that end a name holding a credential's value (secret_value, privateKeyData, passwordConfirmation), and words
// that start a yes-or-no flag about one (hide_secret, has_password, include_secrets).
const VALUE_HEADS = new Set(['value', 'values', 'data', 'plaintext', 'raw', 'string', 'text', 'encoded', 'base64', 'b64', 'material', 'pem', 'confirmation', 'confirm', 'repeat', 'hash']);
const FLAG_STARTS = new Set(['has', 'is', 'hide', 'show', 'include', 'includes', 'exclude', 'with', 'without', 'mask', 'masked', 'redact', 'redacted', 'reveal', 'require', 'requires', 'allow', 'allows', 'enable', 'disable', 'use', 'uses', 'can', 'should', 'needs', 'supports']);
const TOKEN_QUALIFIERS = new Set(['auth', 'access', 'refresh', 'id', 'bearer', 'api', 'session', 'oauth', 'oidc', 'sas', 'csrf', 'xsrf', 'security', 'app', 'user', 'client', 'install', 'installation', 'registration', 'personal', 'private', 'secret', 'jwt', 'service', 'bot', 'webhook', 'device', 'admin', 'master']);
const KEY_QUALIFIERS = new Set(['api', 'app', 'access', 'secret', 'private', 'client', 'auth', 'subscription', 'license', 'licence', 'master', 'signing', 'encryption', 'consumer', 'developer', 'partner', 'service', 'account', 'admin', 'webhook', 'integration', 'session', 'user']);
const EXCHANGE_FIELDS = new Set(['client_secret', 'client_assertion', 'client_assertion_type', 'refresh_token', 'grant_type', 'code_verifier', 'assertion', 'subject_token', 'actor_token']);
/** A name's words, lowercased: AuthToken, X-Api-Key and api.key all read as their parts. */
export const nameWords = name => (String(name).match(/[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+/g) || []).map(word => word.toLowerCase());
export function credentialName(name) {
  if (typeof name !== 'string') return false;
  const words = nameWords(name);
  const head = words.at(-1), previous = words.at(-2);
  if (!head || (words.length > 1 && FLAG_STARTS.has(words[0])) || IDENTIFIER_HEADS.has(head)) return false;
  if (CREDENTIAL_WORDS.has(words.join('')) || CREDENTIAL_WORDS.has(head)) return true;
  if (head === 'token' || head === 'tokens') return words.length === 1 || TOKEN_QUALIFIERS.has(previous);
  if (head === 'key' || head === 'keys') return KEY_QUALIFIERS.has(previous);
  // The value of a credential named earlier (secret_value, privateKeyData, passwordConfirmation, auth_token_hash).
  if (VALUE_HEADS.has(head)) return words.slice(0, -1).some((word, index, before) => STRONG_WORDS.has(word) || CREDENTIAL_WORDS.has(word)
    || (['token', 'tokens'].includes(word) && TOKEN_QUALIFIERS.has(before[index - 1])) || (['key', 'keys'].includes(word) && KEY_QUALIFIERS.has(before[index - 1])));
  return false;
}
/** An OAuth exchange field in any spelling: grant_type, grantType, Grant-Type. */
export const exchangeField = name => typeof name === 'string' && EXCHANGE_FIELDS.has(nameWords(name).join('_'));
const SCHEMA_KEYS = new Set(['type', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'format', 'description', 'title', 'default', 'examples']);
const FORMATS = new Set(['date', 'date-time', 'email', 'uuid', 'uri', 'int32', 'int64', 'float', 'double']);
const has = (object, key) => Object.hasOwn(object, key);
const fail = (message) => { throw new Error(message); };
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const clone = (value) => JSON.parse(JSON.stringify(value));
const assertKeys = (value, allowed, label) => {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${label}: unsupported field ${key}`);
};

function assertJson(value, label = 'JSON') {
  let nodes = 0;
  const active = new Set();
  function visit(item, depth) {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) fail(`${label}: nesting or size limit exceeded`);
    if (item === null || typeof item === 'boolean' || typeof item === 'string') return;
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) fail(`${label}: numbers must be finite`);
      return;
    }
    if (typeof item !== 'object') fail(`${label}: only JSON values are supported`);
    if (active.has(item)) fail(`${label}: cyclic object`);
    // Array subclasses/custom prototypes can inherit serializers or iteration
    // hooks. Reject them before JSON.stringify or canonical traversal runs.
    if (Array.isArray(item) ? Object.getPrototypeOf(item) !== Array.prototype : ![Object.prototype, null].includes(Object.getPrototypeOf(item))) fail(`${label}: objects and arrays must be plain JSON`);
    if (Object.getOwnPropertySymbols(item).length) fail(`${label}: symbol properties are unsupported`);
    active.add(item);
    const descriptors = Object.getOwnPropertyDescriptors(item);
    if (Array.isArray(item)) {
      for (let i = 0; i < item.length; i++) if (!has(descriptors, String(i))) fail(`${label}: sparse arrays are unsupported`);
    }
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (Array.isArray(item) && key === 'length') continue;
      if (UNSAFE_KEYS.has(key)) fail(`${label}: unsafe property ${key}`);
      if (Array.isArray(item) && !/^(?:0|[1-9]\d*)$/.test(key)) fail(`${label}: extra array properties are unsupported`);
      if (!('value' in descriptor) || !descriptor.enumerable) fail(`${label}: accessors/non-enumerable properties are unsupported`);
      visit(descriptor.value, depth + 1);
    }
    active.delete(item);
  }
  visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_BYTES) fail(`${label}: document exceeds ${MAX_BYTES} bytes`);
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (record(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

export function canonicalHash(value) {
  assertJson(value);
  return createHash('sha256').update(canonical(value)).digest('hex');
}

export function checkSchema(schema, path = '$schema', depth = 0) {
  if (depth > 24 || !record(schema)) fail(`${path}: schema must be an object within nesting limits`);
  for (const key of Object.keys(schema)) if (!SCHEMA_KEYS.has(key)) fail(`${path}: unsupported schema keyword ${key}`);
  if (!['object', 'array', 'string', 'integer', 'number', 'boolean', 'null'].includes(schema.type)) fail(`${path}: one explicit supported type is required`);
  for (const key of ['description', 'title']) if (has(schema, key) && typeof schema[key] !== 'string') fail(`${path}.${key}: must be text`);
  if (has(schema, 'enum') && (!Array.isArray(schema.enum) || !schema.enum.length || schema.enum.length > 256)) fail(`${path}.enum: must be a nonempty bounded array`);
  if (has(schema, 'examples') && !Array.isArray(schema.examples)) fail(`${path}.examples: must be an array`);
  if (has(schema, 'format') && !FORMATS.has(schema.format)) fail(`${path}: unsupported format ${schema.format}`);
  const allowedForType = {
    object: ['properties', 'required', 'additionalProperties'], array: ['items', 'minItems', 'maxItems'],
    string: ['minLength', 'maxLength', 'format'], integer: ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'format'],
    number: ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'format'], boolean: [], null: [],
  }[schema.type];
  for (const key of ['properties', 'required', 'additionalProperties', 'items', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'format']) {
    if (has(schema, key) && !allowedForType.includes(key)) fail(`${path}: ${key} is invalid for ${schema.type}`);
  }
  if (schema.format) {
    const numeric = ['int32', 'int64', 'float', 'double'].includes(schema.format);
    if (numeric !== ['number', 'integer'].includes(schema.type)) fail(`${path}: format does not match type`);
    if (['int32', 'int64'].includes(schema.format) && schema.type !== 'integer') fail(`${path}: integer format requires integer type`);
  }
  for (const key of ['minLength', 'maxLength', 'minItems', 'maxItems']) {
    if (has(schema, key) && (!Number.isSafeInteger(schema[key]) || schema[key] < 0 || schema[key] > 1_000_000)) fail(`${path}.${key}: invalid bound`);
  }
  for (const [a, b] of [['minLength', 'maxLength'], ['minItems', 'maxItems'], ['minimum', 'maximum']]) {
    if (has(schema, a) && has(schema, b) && schema[a] > schema[b]) fail(`${path}: inconsistent bounds`);
  }
  for (const key of ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum']) if (has(schema, key) && typeof schema[key] !== 'number') fail(`${path}.${key}: must be a number`);
  if (schema.type === 'object') {
    if (!record(schema.properties) || schema.additionalProperties !== false) fail(`${path}: objects require properties and additionalProperties:false`);
    if (Object.keys(schema.properties).length > 256) fail(`${path}: too many properties`);
    if (has(schema, 'required') && (!Array.isArray(schema.required) || schema.required.some(key => typeof key !== 'string' || !has(schema.properties, key)) || new Set(schema.required).size !== schema.required.length)) fail(`${path}.required: must contain unique declared property names`);
    for (const [key, sub] of Object.entries(schema.properties)) checkSchema(sub, `${path}.properties.${key}`, depth + 1);
  }
  if (schema.type === 'array') checkSchema(schema.items, `${path}.items`, depth + 1);
  if (has(schema, 'enum')) {
    const seen = new Set();
    for (const item of schema.enum) {
      const encoded = canonical(item);
      if (seen.has(encoded)) fail(`${path}.enum: duplicate entry`);
      seen.add(encoded);
      validateValue({ ...schema, enum: undefined }, item, path, true);
    }
  }
  if (has(schema, 'default')) validateValue(schema, schema.default, `${path}.default`);
  if (has(schema, 'const')) {
    const unconstrained = { ...schema };
    delete unconstrained.const;
    validateValue(unconstrained, schema.const, `${path}.const`);
  }
}

function validDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const d = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

export function validateValue(schema, value, path, ignoreEnum = false) {
  const type = schema.type;
  const fits = type === 'object' ? record(value) : type === 'array' ? Array.isArray(value) : type === 'null' ? value === null : type === 'integer' ? Number.isSafeInteger(value) : type === 'number' ? typeof value === 'number' && Number.isFinite(value) : typeof value === type;
  if (!fits) fail(`${path}: expected ${type}`);
  if (!ignoreEnum && schema.enum && !schema.enum.some(item => canonical(item) === canonical(value))) fail(`${path}: value is not in enum`);
  if (has(schema, 'const') && canonical(schema.const) !== canonical(value)) fail(`${path}: must equal const`);
  if (type === 'object') {
    for (const key of schema.required || []) if (!has(value, key)) fail(`${path}.${key}: required`);
    for (const key of Object.keys(value)) {
      if (!has(schema.properties, key)) fail(`${path}.${key}: undeclared property`);
      validateValue(schema.properties[key], value[key], `${path}.${key}`);
    }
  }
  if (type === 'array') {
    if (value.length > (schema.maxItems ?? 10_000) || value.length < (schema.minItems ?? 0)) fail(`${path}: array length outside bounds`);
    value.forEach((item, index) => validateValue(schema.items, item, `${path}[${index}]`));
  }
  if (type === 'string') {
    const length = [...value].length;
    if (length > (schema.maxLength ?? 1_000_000) || length < (schema.minLength ?? 0)) fail(`${path}: string length outside bounds`);
    if (schema.format === 'date' && !validDate(value)) fail(`${path}: invalid date`);
    if (schema.format === 'date-time' && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) || !validDate(value.slice(0, 10)) || !Number.isFinite(Date.parse(value)))) fail(`${path}: invalid date-time with timezone`);
    if (schema.format === 'email' && (value.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))) fail(`${path}: invalid email`);
    if (schema.format === 'uuid' && !/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(value)) fail(`${path}: invalid UUID`);
    if (schema.format === 'uri') { try { new URL(value); } catch { fail(`${path}: invalid URI`); } }
  }
  if (['number', 'integer'].includes(type)) {
    for (const [key, invalid] of [['minimum', value < schema.minimum], ['maximum', value > schema.maximum], ['exclusiveMinimum', value <= schema.exclusiveMinimum], ['exclusiveMaximum', value >= schema.exclusiveMaximum]]) if (has(schema, key) && invalid) fail(`${path}: outside ${key}`);
    if (schema.format === 'int32' && (value < -2147483648 || value > 2147483647)) fail(`${path}: outside int32`);
  }
}

export function validateInput(schema, value) {
  assertJson(schema, 'Schema');
  assertJson(value, 'Input');
  checkSchema(schema);
  validateValue(schema, value, '$input');
  return value;
}

function publicUrl(value, label, { template = false } = {}) {
  if (typeof value !== 'string' || value.length > 8192 || /[\s\\\u0000-\u001f\u007f]/.test(value)) fail(`${label}: invalid URL`);
  let url;
  try { url = new URL(value); } catch { fail(`${label}: invalid URL`); }
  const hostname = url.hostname;
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash) fail(`${label}: requires credential-free HTTPS on port 443 without query or fragment`);
  if (isIP(hostname.replace(/^\[|\]$/g, '')) || !hostname.includes('.') || /(?:^|\.)(?:localhost|local|internal|lan|test|invalid)$/.test(hostname) || hostname.endsWith('.') || !/^[a-z0-9.-]+$/.test(hostname)) fail(`${label}: public DNS hostname required`);
  const authority = value.match(/^https:\/\/([^/]+)/i)?.[1];
  if (!authority || /[{}%]/.test(authority)) fail(`${label}: URL authority cannot be templated or encoded`);
  const rawPath = value.slice(value.indexOf(authority) + authority.length) || '/';
  if (/%|\/\/|(?:^|\/)\.{1,2}(?:\/|$)/.test(rawPath)) fail(`${label}: encoded or traversing paths are unsupported`);
  if (!template && /[{}]/.test(rawPath)) fail(`${label}: templates are not allowed`);
  return url;
}

function validateHeaders(headers = {}) {
  if (!record(headers)) fail('Request headers must be an object');
  const names = new Set();
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (!['accept', 'content-type', 'x-github-api-version'].includes(lower)) fail(`Unsupported or credential-bearing header: ${key}`);
    if (names.has(lower)) fail(`Duplicate header: ${key}`);
    names.add(lower);
    if (typeof value !== 'string' || value.length > 256 || /[\r\n\u0000-\u001f{}]/.test(value)) fail(`Invalid header: ${key}`);
    if (lower === 'content-type' && value !== 'application/json') fail('Only application/json request bodies are supported');
    if (lower === 'accept' && !/^[a-zA-Z0-9.+*-]+\/[a-zA-Z0-9.+*-]+(?:\s*,\s*[a-zA-Z0-9.+*-]+\/[a-zA-Z0-9.+*-]+)*$/.test(value)) fail('Invalid Accept header');
    if (lower === 'x-github-api-version' && !validDate(value)) fail('Invalid GitHub API version');
  }
}

function validateParameterNames(names, label) {
  if (!Array.isArray(names) || new Set(names).size !== names.length || names.some(name => typeof name !== 'string' || !NAME.test(name) || UNSAFE_KEYS.has(name) || SECRET_PARAMETER.test(name) || credentialName(name) || exchangeField(name))) fail(`${label}: invalid, duplicate or credential-bearing parameter`);
}

function validateRequest(request, inputSchema, label = 'Request') {
  if (!record(request)) fail(`${label}: object required`);
  assertKeys(request, ['method', 'url', 'headers', 'pathParameters', 'queryParameters', 'bodyParameter'], label);
  if (!METHODS.has(request.method)) fail(`${label}: unsupported HTTP method`);
  const url = publicUrl(request.url, label, { template: true });
  validateHeaders(request.headers);
  const pathNames = request.pathParameters ?? [];
  const queryNames = request.queryParameters ?? [];
  validateParameterNames(pathNames, `${label}.pathParameters`);
  validateParameterNames(queryNames, `${label}.queryParameters`);
  const found = [];
  const templatePath = request.url.replace(/^https:\/\/[^/]+/i, '') || '/';
  for (const segment of templatePath.split('/')) {
    if (segment.includes('{') || segment.includes('}')) {
      const match = segment.match(/^\{([A-Za-z][A-Za-z0-9_-]{0,63})\}$/);
      if (!match) fail(`${label}: placeholders must occupy entire path segments`);
      found.push(match[1]);
    }
  }
  if (new Set(found).size !== found.length || canonical([...found].sort()) !== canonical([...pathNames].sort())) fail(`${label}: path placeholders do not match declared parameters`);
  const names = [...pathNames, ...queryNames];
  if (request.bodyParameter !== undefined) {
    validateParameterNames([request.bodyParameter], `${label}.bodyParameter`);
    if (READ_METHODS.has(request.method)) fail(`${label}: read requests cannot have a body`);
    names.push(request.bodyParameter);
  }
  if (new Set(names).size !== names.length) fail(`${label}: a parameter cannot occupy multiple locations`);
  for (const name of names) if (!has(inputSchema.properties, name)) fail(`${label}: parameter ${name} not in input schema`);
  for (const name of Object.keys(inputSchema.properties)) if (!names.includes(name)) fail(`${label}: input ${name} is not consumed by the request`);
  for (const name of pathNames) {
    if (!(inputSchema.required || []).includes(name)) fail(`${label}: path parameter ${name} must be required`);
    if (!['string', 'integer', 'number', 'boolean'].includes(inputSchema.properties[name].type)) fail(`${label}: path parameter ${name} must be primitive`);
  }
  for (const name of queryNames) {
    const schema = inputSchema.properties[name];
    if (!['string', 'integer', 'number', 'boolean'].includes(schema.type) && !(schema.type === 'array' && ['string', 'integer', 'number', 'boolean'].includes(schema.items.type))) fail(`${label}: query parameters must be primitive or primitive arrays`);
  }
  return url;
}

function pointerParts(pointer) {
  if (typeof pointer !== 'string' || pointer.length > 1024 || (pointer !== '' && !pointer.startsWith('/')) || /~(?![01])/.test(pointer)) fail('Invalid JSON pointer');
  const parts = pointer === '' ? [] : pointer.slice(1).split('/').map(item => item.replace(/~1/g, '/').replace(/~0/g, '~'));
  if (parts.some(part => UNSAFE_KEYS.has(part)) || parts.length > 24) fail('Unsafe or overly deep JSON pointer');
  return parts;
}

function readPointer(value, pointer) {
  let current = value;
  for (const part of pointerParts(pointer)) {
    if (current === null || typeof current !== 'object' || !has(current, part)) fail(`Verification pointer missing: ${pointer}`);
    current = current[part];
  }
  return current;
}

function validateVerification(bundle) {
  const verification = bundle.verification;
  if (!record(verification)) fail('Verification descriptor required');
  if (verification.kind === 'response') {
    assertKeys(verification, ['kind', 'description'], 'Response verification');
    if (typeof verification.description !== 'string') fail('Verification description required');
    return;
  }
  if (verification.kind !== 'http-readback') fail('Unsupported verification kind');
  assertKeys(verification, ['kind', 'description', 'request', 'bindings', 'assertions'], 'Readback verification');
  if (!record(verification.bindings) || !Array.isArray(verification.assertions) || !verification.assertions.length || verification.assertions.length > 32) fail('Readback requires bindings and bounded assertions');
  if (verification.request?.method !== 'GET') fail('Readback must use GET');
  const properties = {};
  for (const [name, binding] of Object.entries(verification.bindings)) {
    if (!record(binding)) fail('Invalid readback binding');
    assertKeys(binding, ['from', 'pointer', 'schema'], 'Readback binding');
    if (!['input', 'response'].includes(binding.from)) fail('Readback binding must use input or response');
    pointerParts(binding.pointer);
    checkSchema(binding.schema);
    if (!['string', 'integer', 'number', 'boolean'].includes(binding.schema.type)) fail('Readback bindings must be primitive');
    properties[name] = binding.schema;
  }
  const inputSchema = { type: 'object', properties, additionalProperties: false, required: Object.keys(properties) };
  const readbackUrl = validateRequest(verification.request, inputSchema, 'Readback request');
  if (readbackUrl.origin !== new URL(bundle.request.url).origin) fail('Readback must remain on the capability origin');
  let identity = false;
  for (const assertion of verification.assertions) {
    if (!record(assertion)) fail('Invalid readback assertion');
    assertKeys(assertion, ['pointer', 'equalsInput', 'equalsResponse', 'equals'], 'Readback assertion');
    pointerParts(assertion.pointer);
    const choices = ['equalsInput', 'equalsResponse', 'equals'].filter(key => has(assertion, key));
    if (choices.length !== 1) fail('Readback assertion requires exactly one comparison');
    if (has(assertion, 'equalsInput')) pointerParts(assertion.equalsInput);
    if (has(assertion, 'equalsResponse')) {
      pointerParts(assertion.equalsResponse);
      // An explicit provider identity match is mandatory, not just a 200 response.
      if (assertion.pointer === '/id' && assertion.equalsResponse === '/id') identity = true;
    }
  }
  if (!identity) fail('Readback must assert /id equals the write response /id');
  if (!Object.values(verification.bindings).some(binding => binding.from === 'response' && binding.pointer === '/id')) fail('Readback request must bind the provider response /id');
}

// Credentials come only from the connection, at dispatch. No input at any depth may carry or exchange one (F09.1).
export function assertNoCredentialInputs(schema, path) {
  if (schema.type === 'object') for (const [key, sub] of Object.entries(schema.properties)) {
    if (credentialName(key) || exchangeField(key)) fail(`${path}.${key}: credentials and credential exchanges are not agent inputs`);
    assertNoCredentialInputs(sub, `${path}.${key}`);
  }
  if (schema.type === 'array') assertNoCredentialInputs(schema.items, `${path}[]`);
}

export function validateCapability(bundle) {
  assertJson(bundle, 'Capability');
  if (!record(bundle)) fail('Capability must be an object');
  assertKeys(bundle, ['id', 'specVersion', 'version', 'appId', 'name', 'description', 'driver', 'effect', 'status', 'inputSchema', 'request', 'provenance', 'verification'], 'Capability');
  if (bundle.specVersion !== 'fabric/0.1' || bundle.version !== 1) fail('Unsupported capability specification/version');
  if (bundle.driver !== 'http') fail('Compiler validation supports HTTP capabilities only');
  if (typeof bundle.id !== 'string' || !/^[a-z][a-z0-9._-]{1,199}$/.test(bundle.id)) fail('Invalid capability ID');
  if (!APP_ID.test(bundle.appId)) fail('Invalid app ID');
  if (typeof bundle.name !== 'string' || !bundle.name.trim() || bundle.name.length > 200 || typeof bundle.description !== 'string' || bundle.description.length > 10_000) fail('Invalid capability name or description');
  if (!['candidate', 'active', 'disabled'].includes(bundle.status)) fail('Invalid capability status');
  checkSchema(bundle.inputSchema);
  if (bundle.inputSchema.type !== 'object') fail('Capability inputs must be an object');
  assertNoCredentialInputs(bundle.inputSchema, '$input');
  validateRequest(bundle.request, bundle.inputSchema);
  const actualEffect = READ_METHODS.has(bundle.request.method) ? 'read' : 'write';
  if (bundle.effect !== actualEffect) fail('Declared effect does not match conservative HTTP method classification');
  if (!record(bundle.provenance)) fail('Provenance is required');
  assertKeys(bundle.provenance, ['kind', 'fingerprint', 'source', 'operationId', 'path', 'method'], 'Provenance');
  if (!['openapi', 'manual', 'model'].includes(bundle.provenance.kind) || !/^[a-f0-9]{64}$/.test(bundle.provenance.fingerprint) || typeof bundle.provenance.source !== 'string' || bundle.provenance.source.length > 2048) fail('Invalid provenance');
  for (const key of ['operationId', 'path', 'method']) if (has(bundle.provenance, key) && (typeof bundle.provenance[key] !== 'string' || bundle.provenance[key].length > 2048)) fail('Invalid provenance metadata');
  validateVerification(bundle);
  const content = { ...bundle, status: 'candidate' };
  delete content.id;
  if (!bundle.id.startsWith(`${bundle.appId}.`) || !bundle.id.endsWith(`.${canonicalHash(content).slice(0, 24)}`)) fail('Capability ID does not match its immutable content hash');
  return bundle;
}

// Use after reviewing a model/manual capability or adding a verifier. Editing
// executable content creates a new candidate; it never preserves active status.
export function finalizeCapability(bundle) {
  assertJson(bundle, 'Capability');
  const result = clone(bundle);
  delete result.id;
  result.status = 'candidate';
  const digest = canonicalHash(result);
  result.id = `${result.appId}.generated.${digest.slice(0, 24)}`;
  return validateCapability(result);
}

function interpolate(request, args) {
  let urlText = request.url;
  for (const name of request.pathParameters ?? []) {
    const value = String(args[name]);
    if (!value || value === '.' || value === '..' || /[/%\\\u0000-\u001f\u007f]/.test(value)) fail(`Unsafe path parameter ${name}`);
    let encoded;
    try { encoded = encodeURIComponent(value).replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`); } catch { fail(`Invalid Unicode in path parameter ${name}`); }
    urlText = urlText.replace(`{${name}}`, encoded);
  }
  const url = new URL(urlText);
  for (const name of request.queryParameters ?? []) {
    if (!has(args, name)) continue;
    const values = Array.isArray(args[name]) ? args[name] : [args[name]];
    for (const value of values) url.searchParams.append(name, String(value));
  }
  const headers = { ...(request.headers || {}) };
  let body;
  if (request.bodyParameter && has(args, request.bodyParameter)) {
    body = JSON.stringify(args[request.bodyParameter]);
    if (!Object.keys(headers).some(name => name.toLowerCase() === 'content-type')) headers['Content-Type'] = 'application/json';
  }
  if (url.toString().length > 16_384) fail('Prepared URL exceeds size limit');
  return { url: url.toString(), method: request.method, headers, body };
}

export function prepareRequest(bundle, args) {
  validateCapability(bundle);
  validateInput(bundle.inputSchema, args);
  return interpolate(bundle.request, args);
}

// Returns expected values rather than claiming success. The broker performs this
// second GET and compares every assertion against the independently observed data.
export function prepareVerification(bundle, args, responseData) {
  validateCapability(bundle);
  validateInput(bundle.inputSchema, args);
  assertJson(responseData, 'Provider response');
  if (bundle.verification.kind !== 'http-readback') fail('Capability has no independent HTTP readback');
  const verification = bundle.verification;
  const bound = {};
  for (const [name, binding] of Object.entries(verification.bindings)) {
    bound[name] = readPointer(binding.from === 'input' ? args : responseData, binding.pointer);
    validateInput(binding.schema, bound[name]);
  }
  const assertions = verification.assertions.map(assertion => ({
    pointer: assertion.pointer,
    equals: clone(has(assertion, 'equalsInput') ? readPointer(args, assertion.equalsInput) : has(assertion, 'equalsResponse') ? readPointer(responseData, assertion.equalsResponse) : assertion.equals),
  }));
  return { request: interpolate(verification.request, bound), assertions };
}

export function resolveInternal(document, value, stack = [], depth = 0) {
  if (depth > 24) fail('Reference expansion exceeds depth limit');
  if (!record(value) || !has(value, '$ref')) return value;
  if (Object.keys(value).some(key => key !== '$ref')) fail('$ref siblings are unsupported');
  const ref = value.$ref;
  if (typeof ref !== 'string' || !ref.startsWith('#/') || ref.includes('%')) fail('Only unencoded internal JSON Pointer $refs are supported');
  if (stack.includes(ref)) fail(`Reference cycle: ${ref}`);
  const resolved = readPointer(document, ref.slice(1));
  return resolveInternal(document, resolved, [...stack, ref], depth + 1);
}

function importSchema(document, raw, warnings, path, stack = [], depth = 0, budget = { nodes: 0 }) {
  if (depth > 24 || ++budget.nodes > 4096) fail(`${path}: schema expansion exceeds depth/size limit`);
  let schema = raw;
  let nextStack = stack;
  if (record(schema) && schema.$ref) {
    if (stack.includes(schema.$ref)) fail(`${path}: recursive schemas are unsupported`);
    nextStack = [...stack, schema.$ref];
    schema = resolveInternal(document, schema);
  }
  if (!record(schema)) fail(`${path}: schema must be an object`);
  const result = { ...schema };
  if (result.type === 'object') {
    if (result.additionalProperties === undefined) {
      result.additionalProperties = false;
      warnings.push(`${path}: undeclared object properties are deliberately disallowed by Fabric`);
    }
    result.properties = result.properties ?? {};
    if (!record(result.properties)) fail(`${path}: invalid properties`);
    const required = Array.isArray(result.required) ? result.required : [];
    const kept = [];
    for (const [key, sub] of Object.entries(result.properties)) {
      // A credential-exchange field marks the whole operation as an exchange; a credential field is left out when optional.
      if (exchangeField(key)) fail(`${path}.${key}: this operation exchanges credentials; it is not an agent capability`);
      if (credentialName(key)) {
        if (required.includes(key)) fail(`${path}.${key}: credentials and credential exchanges are not agent inputs`);
        warnings.push(`${path}.${key}: optional credential-shaped input omitted; credentials come only from the connection`);
        continue;
      }
      kept.push([key, importSchema(document, sub, warnings, `${path}.${key}`, nextStack, depth + 1, budget)]);
    }
    result.properties = Object.fromEntries(kept);
  }
  if (result.type === 'array') result.items = importSchema(document, result.items, warnings, `${path}[]`, nextStack, depth + 1, budget);
  checkSchema(result, path);
  return result;
}

function serverBase(document, baseUrl) {
  if (baseUrl !== undefined) return publicUrl(baseUrl, 'Base URL').toString().replace(/\/$/, '');
  if (!Array.isArray(document.servers) || document.servers.length !== 1 || !record(document.servers[0]) || document.servers[0].variables) fail('Exactly one fixed OpenAPI server or explicit baseUrl is required');
  return publicUrl(document.servers[0].url, 'OpenAPI server').toString().replace(/\/$/, '');
}

/**
 * `credentials` is passed by discovery, which compiles one scoped operation at a time: the API-key locations and
 * OAuth endpoints of the whole source document. A direct import reads them from the document itself.
 * Its `schemes` are the source's security schemes, so a scoped document's references to them still resolve.
 * @param {{appId?: string, document?: any, baseUrl?: string, sourceUrl?: string, credentials?: {locations?: Set<string>, exchanges?: Set<string>, schemes?: Record<string, unknown>}}} [input]
 */
export function compileOpenApi({ appId, document, baseUrl, sourceUrl, credentials } = {}) {
  if (typeof appId !== 'string' || !APP_ID.test(appId)) fail('Invalid app ID');
  assertJson(document, 'OpenAPI');
  if (!record(document) || typeof document.openapi !== 'string' || !/^3\.(?:0|1|2)\.\d+$/.test(document.openapi) || !record(document.paths)) fail('An OpenAPI 3.x JSON document with paths is required');
  if (sourceUrl !== undefined) publicUrl(sourceUrl, 'Source URL');
  const base = serverBase(document, baseUrl);
  const locations = credentials?.locations ?? credentialLocations(document);
  const exchanges = credentials?.exchanges ?? exchangeUrls(document, base);
  const fingerprint = canonicalHash(document);
  const warnings = [];
  const capabilities = [];
  const schemaBudget = { nodes: 0 };
  let count = 0;
  for (const [path, unresolved] of Object.entries(document.paths)) {
    if (!path.startsWith('/') || path.startsWith('//') || path.length > 2048) { warnings.push(`Skipped invalid path ${path.slice(0, 100)}`); continue; }
    let pathItem;
    try { pathItem = resolveInternal(document, unresolved); } catch (error) { warnings.push(`Skipped ${path}: ${error.message}`); continue; }
    if (!record(pathItem)) { warnings.push(`Skipped ${path}: path item must be an object`); continue; }
    for (const [methodKey, rawOperation] of Object.entries(pathItem)) {
      const method = methodKey.toUpperCase();
      if (!METHODS.has(method) || methodKey !== methodKey.toLowerCase()) continue;
      if (++count > 256) fail('OpenAPI import exceeds 256 operation limit; import a scoped document');
      const label = `${method} ${path}`;
      try {
        const operation = resolveInternal(document, rawOperation);
        if (!record(operation)) fail('operation must be an object');
        if (pathItem.servers || operation.servers) fail('Per-path/operation servers are unsupported; create a separately scoped document');
        if (operation.callbacks) fail('Callbacks require a separate capability and are unsupported');
        // Only alternatives Fabric can serve; an operation with none is refused rather than sent with a bearer token.
        assertServable(securityRequirements(document, operation, credentials?.schemes ? { schemes: credentials.schemes } : {}));
        // A path that reaches a declared OAuth endpoint, literally or through a template segment, exchanges credentials.
        if (reachesEndpoint(`${base}${path}`, exchanges)) fail('This operation exchanges credentials; it is not an agent capability');
        const properties = {};
        const required = [];
        const pathParameters = [];
        const queryParameters = [];
        const parameterMap = new Map();
        for (const list of [pathItem.parameters ?? [], operation.parameters ?? []]) {
          if (!Array.isArray(list)) fail('parameters must be arrays');
          const seen = new Set();
          for (const raw of list) {
            const parameter = resolveInternal(document, raw);
            if (!record(parameter) || !['path', 'query'].includes(parameter.in)) fail('Only path/query parameters are supported; credentials belong in the connection vault');
            // A parameter that carries a credential is never an input: refused when required, left out when optional.
            if (SECRET_PARAMETER.test(parameter.name) || credentialName(parameter.name) || exchangeField(parameter.name) || locations.has(`${parameter.in}:${String(parameter.name).toLowerCase()}`)) {
              if (parameter.in === 'path' || parameter.required === true || exchangeField(parameter.name)) fail(`Parameter ${String(parameter.name).slice(0, 64)} carries a credential; credentials come only from the connection`);
              warnings.push(`Optional credential-shaped parameter ${String(parameter.name).slice(0, 64)} omitted; credentials come only from the connection`);
              continue;
            }
            validateParameterNames([parameter.name], 'OpenAPI parameter');
            const key = `${parameter.in}:${parameter.name}`;
            if (seen.has(key)) fail(`duplicate parameter ${key}`);
            seen.add(key);
            parameterMap.set(key, parameter);
          }
        }
        for (const parameter of parameterMap.values()) {
          const name = parameter.name;
          if (has(properties, name)) fail(`Parameter name ${name} occurs in multiple locations`);
          if (parameter.content || parameter.allowReserved || parameter.allowEmptyValue) fail(`Unsupported parameter encoding for ${name}`);
          const expectedStyle = parameter.in === 'path' ? 'simple' : 'form';
          if (parameter.style !== undefined && parameter.style !== expectedStyle) fail(`Unsupported parameter style for ${name}`);
          if (parameter.explode !== undefined && parameter.explode !== (parameter.in === 'query')) fail(`Unsupported parameter explode for ${name}`);
          if (parameter.required !== undefined && typeof parameter.required !== 'boolean') fail(`Invalid required flag for ${name}`);
          if (parameter.in === 'path' && parameter.required !== true) fail(`Path parameter ${name} must be required`);
          properties[name] = importSchema(document, parameter.schema, warnings, `${label}:${name}`, [], 0, schemaBudget);
          (parameter.in === 'path' ? pathParameters : queryParameters).push(name);
          if (parameter.required) required.push(name);
        }
        let bodyParameter;
        if (operation.requestBody) {
          const requestBody = resolveInternal(document, operation.requestBody);
          if (!record(requestBody) || !record(requestBody.content) || Object.keys(requestBody.content).length !== 1 || !requestBody.content['application/json']) fail('Only a single application/json request body is supported');
          if (READ_METHODS.has(method)) fail('GET/HEAD request bodies are unsupported');
          if (has(properties, 'body')) fail('body parameter name collides with requestBody');
          bodyParameter = 'body';
          properties.body = importSchema(document, requestBody.content['application/json'].schema, warnings, `${label}:body`, [], 0, schemaBudget);
          if (requestBody.required) required.push('body');
        }
        const operationId = typeof operation.operationId === 'string' ? operation.operationId : `${method.toLowerCase()}-${path}`;
        const stem = operationId.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-|-$/g, '').slice(0, 70) || method.toLowerCase();
        const bundle = {
          specVersion: 'fabric/0.1', version: 1, appId,
          name: typeof operation.summary === 'string' ? operation.summary.slice(0, 200) : operationId.slice(0, 200),
          description: typeof operation.description === 'string' ? operation.description.slice(0, 10_000) : `Imported ${label}. Provider authorization and account access are required.`,
          driver: 'http', effect: READ_METHODS.has(method) ? 'read' : 'write', status: 'candidate',
          inputSchema: { type: 'object', properties, required, additionalProperties: false },
          request: { method, url: `${base}${path}`, headers: { Accept: 'application/json' }, pathParameters, queryParameters, ...(bodyParameter ? { bodyParameter } : {}) },
          provenance: { kind: 'openapi', fingerprint, source: sourceUrl || 'uploaded', operationId, path, method },
          verification: { kind: 'response', description: 'Observed provider response only; this is not independent effect verification. Writes remain uncertain without a reviewed readback verifier.' },
        };
        const digest = canonicalHash(bundle);
        bundle.id = `${appId}.${stem}.${digest.slice(0, 24)}`;
        validateCapability(bundle);
        capabilities.push(bundle);
      } catch (error) { warnings.push(`Skipped ${label}: ${error.message}`); }
    }
  }
  if (!capabilities.length) fail(`No supported capabilities were compiled. ${warnings.slice(0, 8).join('; ')}`);
  return { capabilities, warnings: [...new Set(warnings)], fingerprint };
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonicalHash, compileOpenApi, finalizeCapability, prepareRequest, prepareVerification, validateCapability, validateInput } from '../lib/compiler.mjs';

const copy = value => structuredClone(value);
const load = file => JSON.parse(readFileSync(new URL(`../examples/${file}`, import.meta.url), 'utf8'));
const googleDocument = load('google-calendar.openapi.json');
const githubDocument = load('github.openapi.json');
const compile = document => compileOpenApi({ appId: 'test-app', document });
const eventCapability = name => compileOpenApi({ appId: 'google-calendar', document: googleDocument }).capabilities.find(item => item.provenance.operationId === name);
const minimal = () => ({ openapi: '3.1.0', info: { title: 'Fixture', version: '1' }, servers: [{ url: 'https://api.example.com/v1' }], paths: { '/items/{id}': { get: { operationId: 'get-item', parameters: [{ in: 'path', name: 'id', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Item' } } } } } });
const empty = { type: 'object', properties: {}, additionalProperties: false };

test('canonical hashes ignore object order but preserve array order and values', () => {
  assert.equal(canonicalHash({ a: 1, b: { c: 2, d: 3 } }), canonicalHash({ b: { d: 3, c: 2 }, a: 1 }));
  assert.notEqual(canonicalHash([1, 2]), canonicalHash([2, 1]));
  assert.match(canonicalHash({}), /^[a-f0-9]{64}$/);
});

test('JSON guard rejects prototype pollution, accessors and non-JSON without invoking getters', () => {
  for (const value of [undefined, () => 1, 1n, NaN, Infinity, new Date(), new Map(), JSON.parse('{"__proto__":{"polluted":true}}'), JSON.parse('{"x":{"constructor":{}}}')]) assert.throws(() => canonicalHash(value));
  let getterCalled = false;
  const obj = { get value() { getterCalled = true; return 'bad'; } };
  assert.throws(() => canonicalHash(obj), /accessors/);
  assert.equal(getterCalled, false);
  assert.equal({}.polluted, undefined);
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => canonicalHash(cyclic), /cyclic/);
  assert.throws(() => canonicalHash(Array(2)), /sparse/);
  assert.throws(() => canonicalHash({ a: 'x'.repeat(2 * 1024 * 1024) }), /bytes/);
});

test('strict schemas reject unknown properties and missing/incorrect input types', () => {
  const schema = { type: 'object', additionalProperties: false, properties: { title: { type: 'string', minLength: 1, maxLength: 5 }, count: { type: 'integer', minimum: 1, maximum: 5 }, tags: { type: 'array', items: { type: 'string' }, maxItems: 2 } }, required: ['title'] };
  const input = { title: 'hello', count: 3, tags: ['a', 'b'] };
  assert.equal(validateInput(schema, input), input);
  for (const value of [{}, { title: '' }, { title: 'longer' }, { title: 'hi', x: true }, { title: 'hi', count: 1.5 }, { title: 'hi', count: '2' }, { title: 'hi', tags: ['a', 'b', 'c'] }]) assert.throws(() => validateInput(schema, value));
  assert.throws(() => validateInput(schema, JSON.parse('{"title":"hi","__proto__":{}}')), /unsafe/);
});

test('schema annotations do not fill defaults or coerce arguments', () => {
  const schema = { type: 'object', additionalProperties: false, properties: { count: { type: 'integer', default: 2 } } };
  const value = {};
  validateInput(schema, value);
  assert.deepEqual(value, {});
  assert.throws(() => validateInput(schema, { count: '2' }), /integer/);
});

test('unsupported schema forms fail closed including expensive regular expressions', () => {
  const candidates = [{ ...empty, additionalProperties: true }, { ...empty, oneOf: [{ type: 'object' }] }, { type: ['string', 'null'] }, { type: 'string', pattern: '(a+)+$' }, { type: 'string', nullable: true }, { type: 'string', format: 'unknown' }, { type: 'boolean', minimum: 0 }, { type: 'array' }, { type: 'object', properties: {}, additionalProperties: false, required: ['missing'] }, { type: 'string', enum: [] }, { type: 'string', enum: ['same', 'same'] }];
  for (const schema of candidates) assert.throws(() => validateInput(schema, null));
});

test('formats, enums, const, numeric bounds and safe integers are enforced', () => {
  validateInput({ type: 'string', format: 'date-time' }, '2026-09-30T12:00:00+03:00');
  for (const value of ['2026-09-30T12:00:00', '2026-02-31T12:00:00Z', 'no']) assert.throws(() => validateInput({ type: 'string', format: 'date-time' }, value));
  assert.throws(() => validateInput({ type: 'string', format: 'date' }, '2026-02-29'));
  validateInput({ type: 'string', format: 'date' }, '2028-02-29');
  validateInput({ type: 'string', format: 'email' }, 'someone@example.com');
  assert.throws(() => validateInput({ type: 'string', format: 'email' }, 'bad'));
  assert.throws(() => validateInput({ type: 'integer' }, Number.MAX_SAFE_INTEGER + 1));
  assert.throws(() => validateInput({ type: 'integer', format: 'int32' }, 2147483648));
  assert.throws(() => validateInput({ type: 'number', exclusiveMinimum: 1 }, 1));
  assert.throws(() => validateInput({ type: 'string', enum: ['a', 'b'] }, 'c'));
  assert.throws(() => validateInput({ type: 'string', const: 'a' }, 'b'));
  assert.throws(() => validateInput({ type: 'string', const: 42 }, 'anything'));
});

test('Google and GitHub examples compile real endpoints, not mock connections', () => {
  const google = compileOpenApi({ appId: 'google-calendar', document: googleDocument, sourceUrl: 'https://developers.google.com/workspace/calendar/api/v3/reference' });
  assert.equal(google.capabilities.length, 5);
  assert.equal(google.warnings.length, 0);
  assert.equal(compileOpenApi({ appId: 'github', document: githubDocument }).capabilities.length, 4);
  for (const bundle of google.capabilities) {
    assert.equal(bundle.status, 'candidate');
    assert.equal(bundle.provenance.kind, 'openapi');
    assert.equal(bundle.verification.kind, 'response');
    assert.match(bundle.id, /\.[a-f0-9]{24}$/);
    validateCapability(bundle);
  }
});

test('deterministic imports and immutable identity survive status promotion, not edits', () => {
  const first = compile(minimal()).capabilities[0];
  const second = compile(minimal()).capabilities[0];
  assert.equal(first.id, second.id);
  first.status = 'active';
  validateCapability(first);
  first.description = 'changed executable provenance bundle';
  assert.throws(() => validateCapability(first), /immutable/);
  const rebuilt = finalizeCapability(first);
  assert.equal(rebuilt.status, 'candidate');
  assert.notEqual(rebuilt.id, second.id);
  validateCapability(rebuilt);
});

test('path and query arguments serialize exactly and do not inject a destination', () => {
  const bundle = eventCapability('list-events');
  const request = prepareRequest(bundle, { calendarId: 'someone@example.com', maxResults: 10, singleEvents: true, timeMin: '2026-09-30T00:00:00Z', q: 'a&token=bad#fragment' });
  const url = new URL(request.url);
  assert.equal(url.origin, 'https://www.googleapis.com');
  assert.equal(url.pathname, '/calendar/v3/calendars/someone%40example.com/events');
  assert.equal(url.searchParams.get('q'), 'a&token=bad#fragment');
  assert.equal(url.searchParams.has('token'), false);
  assert.equal(url.searchParams.get('singleEvents'), 'true');
  assert.equal(request.body, undefined);
  assert.deepEqual(request.headers, { Accept: 'application/json' });
});

test('path traversal, encoded separators, malformed unicode and empty path values are rejected', () => {
  const bundle = compile(minimal()).capabilities[0];
  for (const id of ['.', '..', 'a/b', 'a\\b', '%2e%2e', '%252f', 'x\0y', '', '\ud800']) assert.throws(() => prepareRequest(bundle, { id }));
  assert.equal(new URL(prepareRequest(bundle, { id: 'a?b#c' }).url).pathname, '/v1/items/a%3Fb%23c');
  assert.equal(new URL(prepareRequest(bundle, { id: 'hello.world' }).url).pathname, '/v1/items/hello.world');
});

test('JSON bodies use explicit bodyParameter and cannot leak into query/header', () => {
  const bundle = eventCapability('insert-event');
  const body = { summary: 'Review', start: { dateTime: '2026-10-01T10:00:00Z' }, end: { dateTime: '2026-10-01T11:00:00Z' } };
  const request = prepareRequest(bundle, { calendarId: 'primary', sendUpdates: 'none', body });
  assert.equal(request.method, 'POST');
  assert.equal(request.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(request.body), body);
  assert.equal(new URL(request.url).searchParams.has('body'), false);
  assert.throws(() => prepareRequest(bundle, { calendarId: 'primary', body: { ...body, arbitrary: 'ignored?' } }), /undeclared/);
});

test('query arrays use repeated form parameters and reject unsupported encodings', () => {
  const document = minimal();
  document.paths['/items/{id}'].get.parameters.push({ in: 'query', name: 'labels', schema: { type: 'array', items: { type: 'string' } } });
  const bundle = compile(document).capabilities[0];
  assert.deepEqual(new URL(prepareRequest(bundle, { id: 'x', labels: ['one', 'two'] }).url).searchParams.getAll('labels'), ['one', 'two']);
  document.paths['/items/{id}'].get.parameters[1].explode = false;
  assert.throws(() => compile(document), /explode/);
});

test('parameter overrides work but cross-location and duplicate names fail', () => {
  const document = minimal();
  document.paths['/items/{id}'].parameters = [{ in: 'path', name: 'id', required: true, schema: { type: 'integer' } }];
  assert.equal(compile(document).capabilities[0].inputSchema.properties.id.type, 'string');
  document.paths['/items/{id}'].get.parameters.push({ in: 'query', name: 'id', schema: { type: 'string' } });
  assert.throws(() => compile(document), /multiple locations/);
  const dup = minimal();
  dup.paths['/items/{id}'].get.parameters.push(copy(dup.paths['/items/{id}'].get.parameters[0]));
  assert.throws(() => compile(dup), /duplicate/);
});

test('internal refs resolve parameter/body schemas; external/cyclic refs fail without fetching', () => {
  const document = minimal();
  document.components = { schemas: { Id: { type: 'string' } } };
  document.paths['/items/{id}'].get.parameters[0].schema = { $ref: '#/components/schemas/Id' };
  assert.equal(compile(document).capabilities.length, 1);
  for (const ref of ['https://attacker.example/schema', 'file:///etc/passwd', '#/components/schemas/missing', '#/components/schemas/%49d']) {
    document.paths['/items/{id}'].get.parameters[0].schema = { $ref: ref };
    assert.throws(() => compile(document));
  }
  document.components.schemas.Id = { $ref: '#/components/schemas/Id' };
  document.paths['/items/{id}'].get.parameters[0].schema = { $ref: '#/components/schemas/Id' };
  assert.throws(() => compile(document), /cycle/);
});

test('recursive schemas and reference expansion bombs are bounded', () => {
  const document = minimal();
  const operation = document.paths['/items/{id}'].get;
  operation.parameters[0].schema = { $ref: '#/components/schemas/A' };
  document.components = { schemas: { A: { type: 'object', properties: { next: { $ref: '#/components/schemas/A' } }, additionalProperties: false } } };
  assert.throws(() => compile(document), /recursive/);
  const schemas = {};
  for (let i = 0; i < 15; i++) schemas[`N${i}`] = { type: 'object', additionalProperties: false, properties: { a: { $ref: `#/components/schemas/N${i + 1}` }, b: { $ref: `#/components/schemas/N${i + 1}` } } };
  schemas.N15 = { type: 'string' };
  document.components.schemas = schemas;
  operation.parameters[0].schema = { $ref: '#/components/schemas/N0' };
  assert.throws(() => compile(document), /size limit/);
});

test('unsupported operations are skipped with warnings, not approximated', () => {
  const document = minimal();
  document.paths['/unsafe'] = { post: { requestBody: { content: { 'multipart/form-data': { schema: { type: 'string' } } } } } };
  const result = compile(document);
  assert.equal(result.capabilities.length, 1);
  assert.ok(result.warnings.some(item => item.includes('multipart') || item.includes('application/json')));
  document.paths['/items/{id}'].get.parameters[0].schema.oneOf = [{ type: 'integer' }];
  assert.throws(() => compile(document), /No supported/);
});

test('objects without additionalProperties are narrowed explicitly, not left open', () => {
  const document = copy(googleDocument);
  delete document.components.schemas.NewTimedEvent.additionalProperties;
  const result = compile(document);
  assert.ok(result.warnings.some(item => item.includes('deliberately disallowed')));
  assert.equal(result.capabilities.find(item => item.request.method === 'POST').inputSchema.properties.body.additionalProperties, false);
});

test('public HTTPS origin and fixed server restrictions are enforced before execution', () => {
  for (const base of ['http://api.example.com', 'https://localhost', 'https://127.0.0.1', 'https://[::1]', 'https://169.254.169.254', 'https://metadata.google.internal', 'https://api.example.com:8080', 'https://user:pass@api.example.com', 'https://api.example.com?key=secret', 'https://api.example.com/#x', 'https://api.example.com/../admin', 'https://api.example.com/%2e%2e/admin', 'https://{tenant}.example.com']) assert.throws(() => compileOpenApi({ appId: 'test-app', document: minimal(), baseUrl: base }));
  const document = minimal();
  document.servers.push({ url: 'https://other.example.com' });
  assert.throws(() => compile(document), /Exactly one/);
  assert.equal(compileOpenApi({ appId: 'test-app', document, baseUrl: 'https://api.example.com/v2' }).capabilities.length, 1);
  document.paths['/items/{id}'].get.servers = [{ url: 'https://evil.example.com' }];
  assert.throws(() => compileOpenApi({ appId: 'test-app', document, baseUrl: 'https://api.example.com/v2' }), /Per-path/);
});

test('unsafe URL templates and path definitions fail', () => {
  for (const path of ['/../x', '/a/%2f/{id}', '/a//{id}', '/a/{id}.json', '/a/{id}?token=x', '/a/{host}/{id}']) {
    const document = minimal();
    document.paths = { [path]: document.paths['/items/{id}'] };
    assert.throws(() => compile(document));
  }
});

test('credential fields and headers cannot be supplied by a bundle or schema', () => {
  // F09.1: a credential parameter is never an input. Required, it refuses the operation; optional, it is left out.
  for (const name of ['token', 'access_token', 'refresh-token', 'api_key', 'Authorization', 'client_secret', 'password']) {
    const required = minimal();
    required.paths['/items/{id}'].get.parameters.push({ in: 'query', name, required: true, schema: { type: 'string' } });
    assert.throws(() => compile(required), /carries a credential/, name);
    const optional = minimal();
    optional.paths['/items/{id}'].get.parameters.push({ in: 'query', name, schema: { type: 'string' } });
    if (['refresh-token', 'client_secret'].includes(name)) { assert.throws(() => compile(optional), /carries a credential/, `${name} marks a credential exchange`); continue; }
    const capability = compile(optional).capabilities[0];
    assert.equal(Object.hasOwn(capability.inputSchema.properties, name), false, name);
    assert.equal(capability.request.queryParameters.includes(name), false, name);
  }
  for (const header of ['Authorization', 'Cookie', 'Host', 'Proxy-Authorization', 'X-Api-Key']) {
    const bundle = compile(minimal()).capabilities[0];
    bundle.request.headers[header] = 'secret';
    assert.throws(() => finalizeCapability(bundle), /header/);
  }
  const bundle = compile(minimal()).capabilities[0];
  bundle.request.headers.Accept = 'application/json\r\nAuthorization: secret';
  assert.throws(() => finalizeCapability(bundle), /header/);
});

test('GET/HEAD alone are read; incorrect effects and arbitrary executable fields fail', () => {
  const bundle = eventCapability('insert-event');
  bundle.effect = 'read';
  assert.throws(() => finalizeCapability(bundle), /classification/);
  const read = compile(minimal()).capabilities[0];
  read.code = 'process.exit()';
  assert.throws(() => finalizeCapability(read), /unsupported field/);
  delete read.code;
  read.driver = 'browser';
  assert.throws(() => finalizeCapability(read), /HTTP/);
});

function readbackBundle() {
  const bundle = eventCapability('insert-event');
  bundle.verification = {
    kind: 'http-readback',
    description: 'Read the exact new event and compare its identity and title',
    request: { method: 'GET', url: 'https://www.googleapis.com/calendar/v3/calendars/{calendarId}/events/{eventId}', pathParameters: ['calendarId', 'eventId'], queryParameters: [] },
    bindings: {
      calendarId: { from: 'input', pointer: '/calendarId', schema: { type: 'string' } },
      eventId: { from: 'response', pointer: '/id', schema: { type: 'string' } },
    },
    assertions: [{ pointer: '/id', equalsResponse: '/id' }, { pointer: '/summary', equalsInput: '/body/summary' }],
  };
  return finalizeCapability(bundle);
}

test('readback binds provider identity to same-origin GET and returns explicit comparisons', () => {
  const bundle = readbackBundle();
  const args = { calendarId: 'primary', body: { summary: 'Review', start: { dateTime: '2026-10-01T10:00:00Z' }, end: { dateTime: '2026-10-01T11:00:00Z' } } };
  const prepared = prepareVerification(bundle, args, { id: 'event123', summary: 'Review' });
  assert.equal(prepared.request.url, 'https://www.googleapis.com/calendar/v3/calendars/primary/events/event123');
  assert.equal(prepared.request.method, 'GET');
  assert.deepEqual(prepared.assertions, [{ pointer: '/id', equals: 'event123' }, { pointer: '/summary', equals: 'Review' }]);
  assert.throws(() => prepareVerification(bundle, args, {}), /pointer missing/);
  assert.throws(() => prepareVerification(bundle, args, { id: '../../evil' }), /Unsafe path/);
  assert.throws(() => prepareVerification(eventCapability('insert-event'), args, { id: '123' }), /no independent/);
});

test('readback refuses unbound identity, arbitrary destinations, mutations and unsafe pointers', () => {
  for (const change of [
    bundle => { bundle.verification.request.method = 'POST'; },
    bundle => { bundle.verification.request.url = bundle.verification.request.url.replace('www.googleapis.com', 'attacker.example.com'); },
    bundle => { bundle.verification.assertions = [{ pointer: '/summary', equalsInput: '/body/summary' }]; },
    bundle => { bundle.verification.bindings.eventId.from = 'input'; },
    bundle => { bundle.verification.assertions[0].equalsResponse = '/__proto__/id'; },
    bundle => { bundle.verification.assertions[0].equals = 'also supplied'; },
  ]) {
    const bundle = readbackBundle();
    change(bundle);
    assert.throws(() => finalizeCapability(bundle));
  }
});

test('import rejects wrong versions, malformed documents and overlarge operation counts', () => {
  assert.throws(() => compile({ swagger: '2.0', paths: {} }), /OpenAPI 3/);
  assert.throws(() => compileOpenApi({ appId: '../bad', document: minimal() }), /app ID/);
  assert.throws(() => compileOpenApi({ appId: 'x', document: minimal(), sourceUrl: 'file:///tmp/x' }));
  const document = minimal();
  document.paths = Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`/items${i}`, { get: { responses: {} } }]));
  assert.throws(() => compile(document), /256 operation/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../lib/store.mjs';
import { AcquisitionEngine } from '../lib/acquisition.mjs';
import { DiscoveryEngine } from '../lib/discovery.mjs';
import { prepareRequest } from '../lib/compiler.mjs';

// Controlled interface descriptions, not fetched accounts or live-provider
// claims. Every remote request below is injected; SQLite persistence is real.
const googleSource = 'https://gmail.googleapis.com/$discovery/rest?version=v1';
const googleOrigin = 'https://gmail.googleapis.com';
const schemaSource = 'https://schemas.example.com/approved/openapi.json';
const copy = value => structuredClone(value);
const userId = () => ({ type: 'string', location: 'path', required: true, default: 'me' });

function googleDocument() {
  const readScopes = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify'];
  const parameters = { userId: userId() };
  return {
    kind: 'discovery#restDescription', discoveryVersion: 'v1', protocol: 'rest', name: 'gmail', version: 'v1', revision: 'fixture-1',
    rootUrl: `${googleOrigin}/`, servicePath: '', baseUrl: `${googleOrigin}/`,
    parameters: { fields: { type: 'string', location: 'query' }, key: { type: 'string', location: 'query' }, alt: { type: 'string', location: 'query', enum: ['json', 'media'] } },
    schemas: {
      Message: { id: 'Message', type: 'object', properties: { id: { type: 'string', readOnly: true }, title: { type: 'string' }, children: { type: 'array', items: { $ref: 'Message' } } } },
      ListMessagesResponse: { type: 'object', properties: { messages: { type: 'array', items: { $ref: 'Message' } }, nextPageToken: { type: 'string' } } },
      NewMessage: { type: 'object', properties: { title: { type: 'string', annotations: { required: ['gmail.users.messages.create'] } }, optionalMetadata: { type: 'object', additionalProperties: { type: 'string' } } } },
      BinaryInput: { type: 'object', properties: { payload: { type: 'string', format: 'byte', required: true } } },
    },
    resources: { users: { resources: { messages: { methods: {
      list: { id: 'gmail.users.messages.list', httpMethod: 'GET', path: 'gmail/v1/users/{userId}/messages', description: 'List one documented message page.', parameters: { ...parameters, maxResults: { type: 'integer', format: 'uint32', minimum: '1', maximum: '500', location: 'query', default: '100' }, labelIds: { type: 'string', repeated: true, location: 'query' } }, scopes: readScopes, response: { $ref: 'ListMessagesResponse' } },
      get: { id: 'gmail.users.messages.get', httpMethod: 'GET', path: 'gmail/v1/users/{userId}/messages/{id}', description: 'Get a documented message.', parameters: { ...parameters, id: { type: 'string', location: 'path', required: true } }, scopes: readScopes, response: { $ref: 'Message' } },
      create: { id: 'gmail.users.messages.create', httpMethod: 'POST', path: 'gmail/v1/users/{userId}/messages', description: 'Controlled test write; not an official Gmail method name.', parameters, scopes: ['https://www.googleapis.com/auth/gmail.modify'], request: { $ref: 'NewMessage' }, response: { $ref: 'Message' } },
      delete: { id: 'gmail.users.messages.delete', httpMethod: 'DELETE', path: 'gmail/v1/users/{userId}/messages/{id}', parameters: { ...parameters, id: { type: 'string', location: 'path', required: true } }, scopes: ['https://mail.google.com/'] },
      binary: { id: 'gmail.users.messages.binary', httpMethod: 'POST', path: 'gmail/v1/users/{userId}/binary', parameters, request: { $ref: 'BinaryInput' }, scopes: ['https://mail.google.com/'] },
    } } } } },
  };
}

function openApiDocument() {
  return {
    openapi: '3.1.0', info: { title: 'Controlled API description', version: '1' }, servers: [{ url: 'https://api.example.com/v1' }],
    components: {
      securitySchemes: { user: { type: 'oauth2', flows: { authorizationCode: { authorizationUrl: 'https://auth.example.com/authorize', tokenUrl: 'https://auth.example.com/token', scopes: { read: 'Read', write: 'Write', admin: 'Admin' } } } } },
      schemas: { Item: { type: 'object', properties: { name: { type: 'string' } }, additionalProperties: false }, Unrelated: { type: 'string' } },
    },
    security: [{ user: ['read', 'write'] }, { user: ['admin'] }],
    paths: {
      '/items': { get: { operationId: 'listItems', summary: 'List items', tags: ['items'], responses: { 200: { description: 'List', content: { 'application/json': { schema: { type: 'array', items: { $ref: '#/components/schemas/Item' } } } } } } } },
      '/items/{id}': { parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], delete: { operationId: 'deleteItem', security: [{ user: ['write'] }], responses: { 204: { description: 'No content' } } } },
      '/unsupported': { post: { operationId: 'unsupportedMultipart', requestBody: { required: true, content: { 'multipart/form-data': { schema: { type: 'object' } } } }, responses: {} } },
    },
  };
}

async function setup(t, { kind = 'google-discovery', document = googleDocument(), discoveryUrl, allowedOrigins, request: suppliedRequest } = {}) {
  const dataDir = await mkdtemp(join(tmpdir(), 'fabric-discovery-test-'));
  const store = new Store({ dataDir });
  t.after(async () => { store.close(); await rm(dataDir, { recursive: true, force: true }); });
  const source = discoveryUrl || (kind === 'google-discovery' ? googleSource : schemaSource);
  const apps = [{ id: 'fixture', name: 'Fixture application', allowedOrigins: allowedOrigins || [kind === 'google-discovery' ? googleOrigin : 'https://api.example.com'], discovery: { kind, url: source } }];
  const catalog = () => apps;
  const acquisition = new AcquisitionEngine({ store, catalog, modelUrl: null, modelKey: null, modelName: null, request: async () => { throw new Error('No model call is allowed during discovery'); } });
  const calls = [];
  const current = { document };
  const discovery = new DiscoveryEngine({ store, catalog, acquisition, request: suppliedRequest || (async request => { calls.push(request); return { status: 200, headers: { 'content-type': 'application/json' }, data: copy(current.document) }; }) });
  return { store, discovery, acquisition, apps, current, calls };
}

test('Google resource traversal maps all real-shaped documented methods, scopes and response schemas', async t => {
  const { discovery, store, calls } = await setup(t);
  const map = await discovery.discover({ appId: 'fixture' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, googleSource);
  assert.equal(calls[0].method, 'GET');
  assert.deepEqual(calls[0].allowedOrigins, [googleOrigin]);
  assert.deepEqual(calls[0].headers, { Accept: 'application/json' });
  assert.equal(calls[0].body, undefined);
  assert.equal(map.status, 'partial');
  assert.deepEqual(map.counts, { total: 5, candidate: 4, unsupported: 1, read: 2, write: 2, delete: 1 });
  assert.equal(map.changes.added.length, 5);
  const get = map.operations.find(operation => operation.id === 'gmail.users.messages.get');
  assert.equal(get.resource, 'users.messages');
  assert.equal(get.responseSchema.schemas.Message.properties.children.items.$ref, 'Message');
  assert.equal(get.requiredScopes.length, 2);
  assert.deepEqual(get.scopeSets, get.requiredScopes.map(scope => [scope]));
  const deleted = map.operations.find(operation => operation.method === 'DELETE');
  assert.equal(deleted.effect, 'delete');
  assert.equal(store.get('capabilities', deleted.capabilityId).effect, 'write');
  assert.equal(store.get('applicationMaps', 'fixture').fingerprint, map.fingerprint);
  assert.equal(store.list('applicationMapHistory').length, 1);
  assert.equal(store.list('discoverySources').length, 1);
  assert.equal(store.list('connections').length, 0);
  assert.equal(store.list('jobs').length, 0);
});

test('discovery creates constrained request functions and explicitly reports optional omitted inputs', async t => {
  const { discovery, store } = await setup(t);
  const map = await discovery.discover({ appId: 'fixture' });
  const list = store.get('capabilities', map.operations.find(operation => operation.id.endsWith('.list')).capabilityId);
  assert.equal(list.status, 'candidate');
  assert.equal(list.provenance.source, googleSource);
  const prepared = prepareRequest(list, { userId: 'me', maxResults: 20, labelIds: ['INBOX', 'UNREAD'] });
  assert.equal(new URL(prepared.url).pathname, '/gmail/v1/users/me/messages');
  assert.deepEqual(new URL(prepared.url).searchParams.getAll('labelIds'), ['INBOX', 'UNREAD']);
  assert.throws(() => prepareRequest(list, { userId: 'me', maxResults: 501 }), /maximum/);
  assert.throws(() => prepareRequest(list, { userId: 'me', key: 'credential' }), /undeclared/);
  const created = map.operations.find(operation => operation.id.endsWith('.create'));
  const write = store.get('capabilities', created.capabilityId);
  assert.ok(created.gaps.some(gap => gap.includes('optionalMetadata')));
  assert.deepEqual(write.inputSchema.properties.body.required, ['title']);
  assert.throws(() => prepareRequest(write, { userId: 'me', body: {} }), /required/);
  assert.throws(() => prepareRequest(write, { userId: 'me', body: { title: 'hello', optionalMetadata: { anything: true } } }), /undeclared/);
  assert.equal(write.verification.kind, 'response');
});

test('unsupported required input schema remains visible with reason and no candidate function', async t => {
  const { discovery, store } = await setup(t);
  const map = await discovery.discover({ appId: 'fixture' });
  const blocked = map.operations.find(operation => operation.id.endsWith('.binary'));
  assert.equal(blocked.support, 'unsupported');
  assert.equal(blocked.capabilityId, null);
  assert.match(blocked.reason, /format byte cannot be enforced/);
  assert.equal(store.list('capabilities').length, 4);
});

test('Calendar-style parameterName request annotation does not change JSON body mapping', async t => {
  const document = googleDocument();
  document.resources.users.resources.messages.methods.create.request.parameterName = 'resource';
  const { discovery, store } = await setup(t, { document });
  const map = await discovery.discover({ appId: 'fixture' });
  const operation = map.operations.find(operation => operation.id.endsWith('.create'));
  assert.equal(operation.support, 'candidate');
  const cap = store.get('capabilities', operation.capabilityId);
  assert.equal(cap.request.bodyParameter, 'body');
  assert.deepEqual(JSON.parse(prepareRequest(cap, { userId: 'me', body: { title: 'Test' } }).body), { title: 'Test' });
});

test('Google output property names such as $ref are data, while nested schema references still resolve', async t => {
  const document = googleDocument();
  document.schemas.Message.properties.$ref = { type: 'string', description: 'A literal output field named $ref, as in the Discovery JsonSchema resource.' };
  document.schemas.Message.properties.properties = { type: 'object', additionalProperties: { $ref: 'Message' } };
  document.schemas.Message.properties.definitions = { type: 'object', properties: { $ref: { $ref: 'LiteralReferenceValue' } } };
  document.schemas.LiteralReferenceValue = { type: 'object', properties: { value: { type: 'string' } } };
  document.schemas.Message.variant = { discriminant: 'kind', map: [{ type: 'alternative', $ref: 'VariantValue' }] };
  document.schemas.VariantValue = { type: 'object', properties: { alternative: { type: 'boolean' } } };
  const { discovery, store } = await setup(t, { document });
  const map = await discovery.discover({ appId: 'fixture' });
  const operation = map.operations.find(operation => operation.id.endsWith('.get'));
  assert.equal(operation.support, 'candidate', operation.reason);
  assert.equal(operation.responseSchema.schemas.Message.properties.$ref.type, 'string');
  assert.equal(operation.responseSchema.schemas.Message.properties.properties.additionalProperties.$ref, 'Message');
  assert.equal(operation.responseSchema.schemas.LiteralReferenceValue.properties.value.type, 'string');
  assert.equal(operation.responseSchema.schemas.VariantValue.properties.alternative.type, 'boolean');
  assert.equal(store.get('capabilities', operation.capabilityId).status, 'candidate');
  assert.equal(store.list('connections').length, 0);
});

test('malformed actual Google output schema references remain unsupported', async t => {
  for (const malformed of [{}, ['Message'], 42, null, 'https://attacker.example.com/schema', 'MissingSchema']) {
    const document = googleDocument();
    document.schemas.Message.properties.nested = { type: 'array', items: { $ref: malformed } };
    const { discovery, store } = await setup(t, { document });
    const map = await discovery.discover({ appId: 'fixture' });
    const operation = map.operations.find(operation => operation.id.endsWith('.get'));
    assert.equal(operation.support, 'unsupported');
    assert.equal(operation.capabilityId, null);
    assert.match(operation.reason, /Invalid Google schema reference|Missing Google schema/);
    assert.equal(store.list('connections').length, 0);
  }
});

test('unchanged and revision-only rediscovery reuses immutable promoted capability definitions', async t => {
  const { discovery, store, current } = await setup(t);
  const first = await discovery.discover({ appId: 'fixture' });
  const capId = first.operations.find(operation => operation.support === 'candidate').capabilityId;
  const promoted = { ...store.get('capabilities', capId), status: 'active' };
  store.put('capabilities', promoted);
  const second = await discovery.discover({ appId: 'fixture' });
  assert.deepEqual(second.changes, { added: [], changed: [], removed: [], unchanged: 5 });
  assert.deepEqual(store.get('capabilities', capId), promoted);
  current.document.revision = 'fixture-2-only-global-revision';
  const third = await discovery.discover({ appId: 'fixture' });
  assert.notEqual(third.fingerprint, first.fingerprint);
  assert.deepEqual(third.changes, { added: [], changed: [], removed: [], unchanged: 5 });
  assert.equal(store.list('capabilities').length, 4);
  assert.equal(store.list('applicationMapHistory').length, 3);
});

test('provider JSON object key reordering does not churn generated parameter arrays or capability identities', async t => {
  const { discovery, current } = await setup(t);
  const first = await discovery.discover({ appId: 'fixture' });
  const reverseKeys = value => Array.isArray(value) ? value.map(reverseKeys) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reverseKeys(item)])) : value;
  current.document = reverseKeys(current.document);
  const second = await discovery.discover({ appId: 'fixture' });
  assert.equal(second.fingerprint, first.fingerprint);
  assert.deepEqual(second.changes, { added: [], changed: [], removed: [], unchanged: 5 });
  assert.deepEqual(second.operations.map(operation => operation.capabilityId), first.operations.map(operation => operation.capabilityId));
});

test('added, changed and removed methods preserve historical artifacts and identify unavailable old versions', async t => {
  const { discovery, store, current } = await setup(t);
  const first = await discovery.discover({ appId: 'fixture' });
  const originalGet = first.operations.find(operation => operation.id.endsWith('.get'));
  const originalDelete = first.operations.find(operation => operation.id.endsWith('.delete'));
  const methods = current.document.resources.users.resources.messages.methods;
  methods.get.description = 'A changed operation contract description';
  delete methods.delete;
  methods.metadata = { ...copy(methods.get), id: 'gmail.users.messages.metadata', path: 'gmail/v1/users/{userId}/messages/{id}/metadata' };
  const second = await discovery.discover({ appId: 'fixture' });
  assert.deepEqual(second.changes.added, ['gmail.users.messages.metadata']);
  assert.deepEqual(second.changes.changed, ['gmail.users.messages.get']);
  assert.deepEqual(second.changes.removed, ['gmail.users.messages.delete']);
  assert.notEqual(second.operations.find(operation => operation.id === originalGet.id).capabilityId, originalGet.capabilityId);
  assert.ok(second.historicalCapabilityIds.includes(originalGet.capabilityId));
  assert.ok(second.historicalCapabilityIds.includes(originalDelete.capabilityId));
  assert.ok(!second.operations.some(operation => operation.capabilityId === originalDelete.capabilityId));
  assert.ok(store.get('capabilities', originalDelete.capabilityId));
  assert.ok(store.get('capabilities', originalGet.capabilityId));
});

test('required schema drift from supported to unsupported exposes the gap without reusing stale function', async t => {
  const { discovery, current } = await setup(t);
  const first = await discovery.discover({ appId: 'fixture' });
  const created = first.operations.find(operation => operation.id.endsWith('.create'));
  current.document.schemas.NewMessage.properties.title.format = 'unsupported-wire-format';
  const second = await discovery.discover({ appId: 'fixture' });
  const changed = second.operations.find(operation => operation.id === created.id);
  assert.equal(changed.support, 'unsupported');
  assert.equal(changed.capabilityId, null);
  assert.ok(second.changes.changed.includes(created.id));
  assert.ok(second.historicalCapabilityIds.includes(created.capabilityId));
});

test('a valid empty provider interface records all former methods as removed without deleting evidence', async t => {
  const { discovery, current, store } = await setup(t);
  const first = await discovery.discover({ appId: 'fixture' });
  current.document.resources = {};
  const second = await discovery.discover({ appId: 'fixture' });
  assert.equal(second.status, 'unsupported');
  assert.equal(second.counts.total, 0);
  assert.equal(second.changes.removed.length, first.operations.length);
  assert.equal(second.historicalCapabilityIds.length, first.historicalCapabilityIds.length);
  assert.equal(store.list('capabilities').length, 4);
});

test('source is selected only from trusted catalog metadata and public HTTPS is required before fetch', async t => {
  for (const url of ['http://gmail.googleapis.com/doc', 'https://localhost/doc', 'https://127.0.0.1/doc', 'https://metadata.google.internal/doc', 'https://user:secret@gmail.googleapis.com/doc', 'https://gmail.googleapis.com:8080/doc', 'https://attacker.example.com/doc']) {
    let calls = 0;
    const { discovery, store } = await setup(t, { discoveryUrl: url, request: async () => { calls++; return { status: 200, data: googleDocument() }; } });
    await assert.rejects(discovery.discover({ appId: 'fixture' }));
    assert.equal(calls, 0);
    assert.equal(store.list('applicationMaps').length, 0);
  }
  const { discovery, calls } = await setup(t);
  await assert.rejects(discovery.discover({ appId: 'missing' }), /Unknown/);
  await discovery.discover({ appId: 'fixture', url: 'https://attacker.example.com/ignored' });
  assert.equal(calls[0].url, googleSource);
});

test('discovered API authority cannot escape selected app origins or smuggle account credentials', async t => {
  const document = googleDocument(); document.baseUrl = 'https://attacker.example.com/';
  const { discovery, store } = await setup(t, { document });
  await assert.rejects(discovery.discover({ appId: 'fixture' }), /outside/);
  assert.equal(store.list('capabilities').length, 0);
  assert.equal(store.list('applicationMaps').length, 0);
  const untrusted = googleDocument();
  untrusted.resources.users.resources.messages.methods.list.path = 'https://attacker.example.com/leak';
  const other = await setup(t, { document: untrusted });
  const map = await other.discovery.discover({ appId: 'fixture' });
  assert.equal(map.operations.find(operation => operation.id.endsWith('.list')).support, 'unsupported');
});

test('provider failures, malformed JSON and duplicate method IDs do not replace a known map', async t => {
  const { discovery, store, current } = await setup(t);
  const previous = await discovery.discover({ appId: 'fixture' });
  discovery.request = async () => ({ status: 403, data: { error: 'not public' } });
  await assert.rejects(discovery.discover({ appId: 'fixture' }), /HTTP 403/);
  assert.equal(store.get('applicationMaps', 'fixture').fingerprint, previous.fingerprint);
  discovery.request = async () => ({ status: 200, data: 'not JSON' });
  await assert.rejects(discovery.discover({ appId: 'fixture' }), /JSON object/);
  current.document.resources.users.resources.messages.methods.duplicate = copy(current.document.resources.users.resources.messages.methods.list);
  discovery.request = async () => ({ status: 200, data: current.document });
  await assert.rejects(discovery.discover({ appId: 'fixture' }), /duplicate/);
  assert.equal(store.get('applicationMaps', 'fixture').fingerprint, previous.fingerprint);
  assert.equal(store.list('applicationMapHistory').length, 1);
});

test('generic OpenAPI discovery compiles supported methods while preserving scopes and unsupported routes', async t => {
  const { discovery, store, calls } = await setup(t, { kind: 'openapi', document: openApiDocument() });
  const map = await discovery.discover({ appId: 'fixture' });
  assert.equal(calls[0].url, schemaSource);
  assert.deepEqual(calls[0].allowedOrigins, ['https://schemas.example.com']);
  assert.deepEqual(map.counts, { total: 3, candidate: 2, unsupported: 1, read: 1, write: 1, delete: 1 });
  const list = map.operations.find(operation => operation.id === 'listItems');
  assert.deepEqual(list.scopeSets, [['read', 'write'], ['admin']]);
  assert.equal(list.responseSchema.components.schemas.Item.properties.name.type, 'string');
  assert.equal(list.responseSchema.components.schemas.Unrelated, undefined);
  const cap = store.get('capabilities', list.capabilityId);
  assert.equal(prepareRequest(cap, {}).url, 'https://api.example.com/v1/items');
  assert.equal(map.operations.find(operation => operation.id === 'unsupportedMultipart').capabilityId, null);
});

test('unrelated OpenAPI components do not churn existing capability IDs but relevant schema changes do', async t => {
  const { discovery, current } = await setup(t, { kind: 'openapi', document: openApiDocument() });
  const first = await discovery.discover({ appId: 'fixture' });
  current.document.components.schemas.Unrelated = { type: 'integer' };
  const second = await discovery.discover({ appId: 'fixture' });
  assert.deepEqual(second.changes, { added: [], changed: [], removed: [], unchanged: 3 });
  assert.deepEqual(first.operations.map(operation => operation.capabilityId), second.operations.map(operation => operation.capabilityId));
  current.document.components.schemas.Item.properties.extra = { type: 'boolean' };
  const third = await discovery.discover({ appId: 'fixture' });
  assert.deepEqual(third.changes.changed, ['listItems']);
});

test('external references and unsupported authentication appear as unsupported, never fetched', async t => {
  const document = openApiDocument();
  document.paths['/items'].get.responses[200].content['application/json'].schema.items.$ref = 'https://attacker.example.com/schema.json';
  document.components.securitySchemes.user = { type: 'apiKey', in: 'query', name: 'secret' };
  const { discovery, calls, store } = await setup(t, { kind: 'openapi', document });
  const map = await discovery.discover({ appId: 'fixture' });
  assert.equal(calls.length, 1);
  assert.equal(map.counts.candidate, 0);
  assert.equal(map.counts.unsupported, 3);
  assert.equal(store.list('capabilities').length, 0);
  assert.ok(map.operations.every(operation => operation.reason.includes('bearer-credential')));
});

test('unsafe or excessive discovery JSON is rejected before compile or store mutation', async t => {
  for (const data of [JSON.parse('{"kind":"discovery#restDescription","__proto__":{}}'), { text: 'x'.repeat(2 * 1024 * 1024) }]) {
    const { discovery, store } = await setup(t, { document: data });
    await assert.rejects(discovery.discover({ appId: 'fixture' }));
    assert.equal(store.list('applicationMaps').length, 0);
    assert.equal(store.list('capabilities').length, 0);
  }
});

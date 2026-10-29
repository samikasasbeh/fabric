import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {compileOpenApi} from '../lib/compiler.mjs';
import {validatePermissionGroups} from '../lib/permission-groups.mjs';
import {suspectedWrite, mentionsCredential, responseSecretFields, sensitivity, SENSITIVITY_VERSION} from '../lib/sensitivity.mjs';
import {credentialValues, secretContext, scrubString, scrubValue, secretKey, scrubAuthorization} from '../lib/redaction.mjs';
import {groupDefault, operationDefault, operationSensitivity, mapIndex, PermissionManager} from '../lib/permissions.mjs';
import {needsConfirm, confirmText} from '../public/hosted-app.js';
import {Store} from '../lib/store.mjs';
import {fixture} from './fixtures/signin-fixture.mjs';
import {loadManifest, runCoverage} from '../scripts/coverage.mjs';
import {fileURLToPath} from 'node:url';

// F09.1b safety floor (docs/F09-COMPILER-COVERAGE.md I6, I9): operations that return credentials or are GETs named
// like a change never get a standing Allow by default, and value redaction covers every spelling.
const http = (method, operationId, name = operationId) => ({driver: 'http', name, request: {method}, provenance: {operationId}});

test('suspected writes: a GET or HEAD whose name starts with a change, or ends with one without starting with a read', () => {
  for (const id of ['deleteThing', 'Items_Delete', 'get-/things/delete', 'cancelOrder', 'sendInvite', 'actions/re-run-job', 'refundCharge'])
    assert.equal(suspectedWrite(http('GET', id)), true, id);
  for (const id of ['repos/list-for-org', 'calendar.events.list', 'listDeletedItems', 'getAccount', 'meta/root', 'get-/items', 'searchCode', 'download-tarball'])
    assert.equal(suspectedWrite(http('GET', id)), false, id);
  assert.equal(suspectedWrite(http('POST', 'deleteThing')), false, 'a POST is already a write');
  assert.equal(suspectedWrite({driver: 'workspace', action: {op: 'read'}}), false);
});

test('documented responses decide "returns secrets"; with none, the operation name does', () => {
  const openapi = {dialect: 'openapi', responses: {200: {content: {'application/json': {schema: {$ref: '#/components/schemas/Account'}}}}},
    components: {schemas: {Account: {type: 'object', properties: {sid: {type: 'string'}, owner: {$ref: '#/components/schemas/Account'}, keys: {type: 'array', items: {type: 'object', properties: {auth_token: {type: 'string'}}}}}}}}};
  assert.deepEqual(responseSecretFields(openapi), ['auth_token'], 'follows references, terminates on cycles, finds nested array items');
  const google = {dialect: 'google-discovery', root: {$ref: 'Key'}, schemas: {Key: {type: 'object', properties: {privateKeyData: {type: 'string'}, name: {type: 'string'}}}}};
  assert.deepEqual(responseSecretFields(google), ['privateKeyData']);
  assert.deepEqual(responseSecretFields({dialect: 'openapi', responses: {200: {content: {'application/json': {schema: {type: 'object', properties: {nextPageToken: {type: 'string'}, key: {type: 'string'}, publicKey: {type: 'string'}, properties: {type: 'object', properties: {name: {type: 'string'}}}}}}}}}}), []);
  assert.equal(responseSecretFields({dialect: 'openapi', responses: {}}), null);
  assert.equal(responseSecretFields(undefined), null);
  const huge = {dialect: 'openapi', responses: {200: {content: {'application/json': {schema: {type: 'object', properties: Object.fromEntries(Array.from({length: 12000}, (_, i) => [`f${i}`, {type: 'string'}]))}}}}}};
  assert.deepEqual(responseSecretFields(huge), ['(too large to inspect)'], 'a response too large to inspect counts as sensitive');
  assert.equal(mentionsCredential('actions/create-registration-token-for-repo'), true);
  assert.equal(mentionsCredential('listRepoSecrets'), true);
  for (const name of ['getAccount', 'listItems', 'pageToken', 'apps/create-from-manifest']) assert.equal(mentionsCredential(name), false, name);
  const named = http('POST', 'createRegistrationToken');
  assert.equal(sensitivity(named, null), 'secrets', 'no map: the name decides');
  const plain = {responseSchema: {dialect: 'openapi', responses: {201: {content: {'application/json': {schema: {type: 'object', properties: {id: {type: 'string'}}}}}}}}};
  // A documented response decides alone: public keys and secret metadata are not credentials (GitHub).
  for (const id of ['createRegistrationToken', 'createWidget', 'actions/list-repo-secrets', 'actions/get-repo-public-key', 'actions/get-repo-secret', 'actions/delete-repo-secret', 'registry_get_dockerCredentials'])
    assert.equal(sensitivity(http(id.includes('delete') ? 'DELETE' : /^create/.test(id) ? 'POST' : 'GET', id), plain), null, id);
  assert.equal(sensitivity(http('GET', 'registry_get_dockerCredentials'), null), 'secrets', 'with no documented response the name decides');
  assert.equal(sensitivity(http('GET', 'getAccount'), {responseSchema: openapi}), 'secrets');
  assert.equal(sensitivity(http('GET', 'deleteThing'), null), 'suspected-write');
});

test('sensitive operations default to Ask even inside a reviewed Allow group; a Never group stays Never', () => {
  const read = http('GET', 'getAccount');
  assert.equal(groupDefault(null, read, 'read'), 'allow');
  assert.equal(groupDefault(null, read, 'read', {sensitive: 'secrets'}), 'ask');
  assert.equal(groupDefault({defaultMode: 'allow', effect: 'read'}, read, 'read', {sensitive: 'suspected-write'}), 'ask');
  assert.equal(groupDefault({defaultMode: 'deny', effect: 'read'}, read, 'read', {sensitive: 'secrets'}), 'deny');
  const groups = new Map([['app', validatePermissionGroups({schemaVersion: 1, appId: 'app', groups: [{id: 'app.read', label: 'Read', effect: 'read', defaultMode: 'allow', requests: ['GET /accounts/{sid}']}]})]]);
  const capability = {...read, appId: 'app'};
  const operation = {id: 'getAccount', method: 'GET', path: '/accounts/{sid}', responseSchema: {dialect: 'openapi', responses: {200: {content: {'application/json': {schema: {type: 'object', properties: {auth_token: {type: 'string'}}}}}}}}};
  assert.equal(operationDefault(groups, capability, operation), 'ask');
  const current = {classifierVersion: SENSITIVITY_VERSION};
  assert.equal(operationSensitivity(capability, {...operation, sensitive: null}, current), null, 'a verdict recorded by the current classifier is used as is');
  assert.equal(operationDefault(groups, capability, operation, operationSensitivity(capability, {...operation, sensitive: null}, current)), 'allow');
  assert.equal(operationSensitivity(capability, {...operation, sensitive: null}, {classifierVersion: 0}), 'secrets', 'a verdict from older rules is classified again');
  assert.equal(operationSensitivity(capability, {...operation, sensitive: null}, undefined), 'secrets', 'a map from before the classifier is classified again');
  assert.equal(operationSensitivity(capability, {...operation, sensitive: 'bogus'}, current), 'secrets', 'an unknown recorded value counts as secrets');
});

test('redaction: every spelling of a credential value, and every credential-named field, is removed', () => {
  assert.deepEqual(credentialValues({Authorization: 'Basic dXNlcjpwYXNz', 'X-Other': 'visible'}), ['Basic dXNlcjpwYXNz', 'dXNlcjpwYXNz']);
  const secret = 'sk live/with+odd chars&=';
  const ctx = secretContext([secret]);
  for (const spelling of [secret, JSON.stringify(secret).slice(1, -1), encodeURIComponent(secret), new URLSearchParams({v: secret}).toString().slice(2)])
    assert.doesNotMatch(scrubString(`before ${spelling} after`, ctx), /odd/, spelling);
  assert.equal(scrubString('https://api.example.com/x?appid=sk%20live%2Fwith%2Bodd%20chars%26%3D', ctx).includes('odd'), false);
  // Each spelling is cut out in place, so the text around it survives.
  for (const spelling of [JSON.stringify(secret).slice(1, -1), encodeURIComponent(secret), new URLSearchParams({v: secret}).toString().slice(2)])
    assert.equal(scrubString(`before ${spelling} after`, secretContext([secret])), 'before [redacted] after', spelling);
  const body = scrubValue({auth_token: 'abc', secret: 'abc', webhook_secret: 'abc', pem: '-----BEGIN RSA PRIVATE KEY-----\nMII', encoded_jit_config: 'abc', token: 'abc', nextPageToken: 'n1', key: 'PROJ-1', publicKey: 'ssh-ed25519 AAAA',
    certificate: {pem: '-----BEGIN CERTIFICATE-----\nMII'}, nested: [{client_secret: 'abc'}]}, secretContext([]));
  assert.deepEqual(body, {auth_token: '[redacted]', secret: '[redacted]', webhook_secret: '[redacted]', pem: '[redacted]', encoded_jit_config: '[redacted]', token: '[redacted]', nextPageToken: 'n1', key: 'PROJ-1', publicKey: 'ssh-ed25519 AAAA',
    certificate: {pem: '-----BEGIN CERTIFICATE-----\nMII'}, nested: [{client_secret: '[redacted]'}]}, 'a pem keeps its value unless it holds a private key');
  for (const name of ['auth_token', 'AuthToken', 'secret', 'privateKey', 'Authorization']) assert.equal(secretKey(name), true, name);
});

test('audit records drop basic as well as bearer authorization values', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-audit-'));
  const store = new Store({dataDir: dir});
  t.after(async () => {store.close(); await rm(dir, {recursive: true, force: true});});
  store.audit({type: 'test', note: 'sent Basic dXNlcjpwYXNz and Bearer abc.def'});
  const entry = store.list('activity').find(item => item.type === 'test');
  assert.equal(entry.note, 'sent [redacted] and [redacted]');
});

test('a batch of decisions reads the application map once, with the same answers', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-index-'));
  const store = new Store({dataDir: dir});
  t.after(async () => {store.close(); await rm(dir, {recursive: true, force: true});});
  const document = {openapi: '3.0.3', info: {title: 'Index', version: '1'}, servers: [{url: 'https://api.example.com'}], paths: Object.fromEntries(Array.from({length: 12}, (_, i) => [`/r${i}`, {get: {operationId: `listR${i}`, responses: {200: {description: 'OK'}}}}]))};
  const caps = compileOpenApi({appId: 'app', document}).capabilities.map(cap => ({...cap, status: 'active'}));
  for (const cap of caps) store.put('capabilities', cap);
  store.put('applicationMaps', {id: 'app', appId: 'app', operations: caps.map(cap => ({id: cap.provenance.operationId, capabilityId: cap.id, method: 'GET', path: cap.provenance.path}))});
  store.put('connections', {id: 'c1', appId: 'app', driver: 'http', status: 'ready', authMethod: 'token', identity: {id: 'u'}});
  const permissions = new PermissionManager({store});
  const one = caps.map(cap => permissions.decision(store.get('connections', 'c1'), cap));
  let reads = 0;
  const get = store.get.bind(store);
  store.get = (collection, id) => { if (collection === 'applicationMaps') reads++; return get(collection, id); };
  const listed = permissions.list('c1');
  assert.equal(reads, 1);
  assert.deepEqual(listed.map(item => [item.capabilityId, item.mode, item.policyHash]).sort(), one.map(item => [item.capabilityId, item.mode, item.policyHash]).sort());
  assert.equal(mapIndex(null).operations.size, 0);
  assert.throws(() => mapIndex({operations: [null]}), /malformed/);
});

test('discovery records each candidate\'s classification in the application map', async () => {
  const [spec] = (await loadManifest(path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'coverage', 'manifest.json'))).filter(item => item.appId === 'coverage');
  const {discovery} = await runCoverage(spec), byId = Object.fromEntries(discovery.operations.map(operation => [operation.id, operation]));
  assert.equal(discovery.classifierVersion, SENSITIVITY_VERSION, 'the map says which rules classified it');
  assert.deepEqual(['getAccount', 'createKey', 'deleteThing', 'getPlain', 'postPlain'].map(id => [id, byId[id].sensitive]),
    [['getAccount', 'secrets'], ['createKey', 'secrets'], ['deleteThing', 'suspected-write'], ['getPlain', null], ['postPlain', null]]);
});

// The owner's app screen: sensitive operations sit in their own rows, and Allow there always needs confirming.
const doc = {openapi: '3.0.3', info: {title: 'Synthetic GitHub', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
  '/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}},
  '/user/keys': {get: {operationId: 'listKeys', responses: {200: {description: 'Keys'}}}},
  '/user/things/delete': {get: {operationId: 'deleteThing', responses: {200: {description: 'Gone'}}}}}};
const groups = validatePermissionGroups({schemaVersion: 1, appId: 'github', groups: [
  {id: 'github.user.read', label: 'See your account', effect: 'read', defaultMode: 'allow', requests: ['GET /user/repos', 'GET /user/keys', 'GET /user/things/delete']}]});

test('the app screen keeps sensitive operations out of reviewed rows, defaults them to Ask, and asks to confirm Allow', async t => {
  const f = await fixture(t);
  const caps = compileOpenApi({appId: 'github', document: doc}).capabilities.map(cap => ({...cap, status: 'active'}));
  for (const cap of caps) f.app.store.put('capabilities', cap);
  const id = name => caps.find(cap => cap.provenance.operationId === name).id;
  const keysResponse = {dialect: 'openapi', responses: {200: {content: {'application/json': {schema: {type: 'array', items: {type: 'object', properties: {id: {type: 'integer'}, secret: {type: 'string'}}}}}}}}};
  f.app.store.put('applicationMaps', {id: 'github', operations: [
    {id: 'listRepos', capabilityId: id('listRepos'), method: 'GET', path: '/user/repos', requiredScopes: []},
    {id: 'listKeys', capabilityId: id('listKeys'), method: 'GET', path: '/user/keys', requiredScopes: [], responseSchema: keysResponse},
    {id: 'deleteThing', capabilityId: id('deleteThing'), method: 'GET', path: '/user/things/delete', requiredScopes: []}]});
  f.app.runtime.permissions.groups = new Map([['github', groups]]);
  const response = await f.owned('POST', '/api/oauth/github/start', {appId: 'github', writeAccess: true});
  const started = {body: await response.json(), flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie'))[1]};
  assert.equal((await f.callback(started)).location, '/?oauth=connected');
  const account = f.connections().find(connection => connection.status === 'ready');
  const view = async () => (await f.json('GET', '/api/ui/apps/github')).body;
  const rows = v => v.sections.flatMap(section => section.rows);
  const first = await view();
  // F10.6 correction 3: the fixture's own GET /user/repos, which this map leaves out, sits in the row its request does, so the row sets it too.
  assert.deepEqual(rows(first).map(row => [row.label, row.mode, row.operations, row.sensitive ?? null]), [['See your account', 'allow', 2, null], ['Reads that may change something', 'ask', 1, 'suspected-write'], ['Reads that return keys or secrets', 'ask', 1, 'secrets']]);
  const secrets = rows(first).find(row => row.sensitive === 'secrets');
  assert.equal(needsConfirm(secrets, 'allow'), 'allow', 'the owner screen asks before Allow on a sensitive read row');
  assert.match(confirmText(secrets, 'allow', 'allow'), /can return keys or secrets/);
  assert.match(confirmText({...secrets, reviewRequired: true}, 'allow', 'review'), /generated from the provider's documentation.*can return keys or secrets/, 'a first-time review of a secrets row also warns about secrets');
  assert.doesNotMatch(confirmText({...secrets, reviewRequired: true}, 'ask', 'review'), /keys or secrets/, 'Ask needs no Allow warning');
  const post = body => f.json('POST', `/api/ui/apps/github/accounts/${encodeURIComponent(account.id)}/permissions`, body);
  const refused = await post({groupId: secrets.groupId, mode: 'allow', etag: secrets.etag});
  assert.equal(refused.body.code, 'confirm_required'); assert.match(refused.body.error, /can return keys or secrets/);
  // Changing the reviewed row never reaches the sensitive members.
  const account_row = rows(first).find(row => row.groupId === 'github.user.read');
  assert.equal((await post({groupId: account_row.groupId, mode: 'ask', etag: account_row.etag})).status, 200);
  const relisted = await view();
  const allowed = rows(relisted).find(row => row.groupId === 'github.user.read');
  assert.equal((await post({groupId: allowed.groupId, mode: 'allow', etag: allowed.etag})).status, 200);
  const decision = name => f.app.runtime.permissions.decision(f.app.store.get('connections', account.id), f.app.store.get('capabilities', id(name)));
  assert.deepEqual(['listRepos', 'listKeys', 'deleteThing'].map(name => decision(name).mode), ['allow', 'ask', 'ask']);
  const now = rows(await view()).find(row => row.sensitive === 'secrets');
  assert.equal((await post({groupId: now.groupId, mode: 'allow', etag: now.etag, confirmAllow: true})).status, 200);
  assert.equal(decision('listKeys').mode, 'allow', 'the owner can still allow it explicitly');
});

test('the response classifier finds credentials by name and schema, and leaves out what cannot be one', () => {
  const openapi = (properties, components = {}) => ({dialect: 'openapi', responses: {200: {content: {'application/json': {schema: {type: 'object', properties}}}}}, components});
  // DigitalOcean docker credentials: a map of registries, each with a base64 "auth".
  assert.deepEqual(responseSecretFields(openapi({auths: {type: 'object', additionalProperties: {type: 'object', properties: {auth: {type: 'string'}}}}})), ['auth']);
  // GitHub runner downloads: a short-lived download token.
  assert.deepEqual(responseSecretFields(openapi({download_url: {type: 'string'}, temp_download_token: {type: 'string'}})), ['temp_download_token']);
  assert.deepEqual(responseSecretFields(openapi({nextPageToken: {type: 'string'}, tokens: {type: 'integer'}, has_password: {type: 'boolean'}, password_strength: {type: 'string', enum: ['weak', 'strong']},
    secret_count: {type: 'number'}, user_has_strong_password: {type: 'boolean'}, api_key: {type: 'string', writeOnly: true}})), [], 'numbers, flags, enums and write-only fields are not returned credentials');
  // Google's own words: Gmail SmtpMsa.password is never returned; S/MIME and CSE certificates are public.
  const gmail = {dialect: 'google-discovery', root: {$ref: 'SendAs'}, schemas: {SendAs: {type: 'object', properties: {smtpMsa: {$ref: 'SmtpMsa'}, pem: {type: 'string', description: 'PEM formatted X509 concatenated certificate string. Format used for returning key, which includes public key as well as certificate chain (not private key).'}}},
    SmtpMsa: {type: 'object', properties: {password: {type: 'string', description: 'The password that will be used for authentication with the SMTP service. This is a write-only field that can be specified in requests to create or update SendAs settings; it is never populated in responses.'}}}}};
  assert.deepEqual(responseSecretFields(gmail), []);
  assert.deepEqual(responseSecretFields({dialect: 'google-discovery', root: {$ref: 'KeyPair'}, schemas: {KeyPair: {type: 'object', properties: {pem: {type: 'string', description: 'Output only. The public key and its certificate chain, in PEM format.'}, privateKeyPem: {type: 'string'}}}}}), ['privateKeyPem']);
  // Calendar conference join codes are meeting content, not account credentials; other passwords still count.
  const calendar = {dialect: 'google-discovery', root: {$ref: 'Events'}, schemas: {Events: {type: 'object', properties: {items: {type: 'array', items: {$ref: 'Event'}}}}, Event: {type: 'object', properties: {conferenceData: {$ref: 'ConferenceData'}}},
    ConferenceData: {type: 'object', properties: {entryPoints: {type: 'array', items: {$ref: 'EntryPoint'}}}}, EntryPoint: {type: 'object', properties: {password: {type: 'string'}, passcode: {type: 'string'}, pin: {type: 'string'}}}}};
  assert.deepEqual(responseSecretFields(calendar), []);
  assert.deepEqual(responseSecretFields({...calendar, schemas: {...calendar.schemas, ConferenceData: {type: 'object', properties: {entryPoints: {type: 'array', items: {$ref: 'EntryPoint'}}, adminPassword: {type: 'string'}}}}}), ['adminPassword']);
});

test('a saved Allow made before an operation was classified sensitive goes stale and asks again', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-stale-'));
  const store = new Store({dataDir: dir});
  t.after(async () => {store.close(); await rm(dir, {recursive: true, force: true});});
  const document = {openapi: '3.0.3', info: {title: 'Stale', version: '1'}, servers: [{url: 'https://api.example.com'}], paths: {'/account': {get: {operationId: 'getAccount', responses: {200: {description: 'OK'}}}}}};
  const [capability] = compileOpenApi({appId: 'app', document}).capabilities.map(cap => ({...cap, status: 'active'}));
  store.put('capabilities', capability);
  const operation = {id: 'getAccount', capabilityId: capability.id, method: 'GET', path: '/account'};
  store.put('applicationMaps', {id: 'app', appId: 'app', classifierVersion: SENSITIVITY_VERSION, operations: [{...operation, sensitive: null}]});
  store.put('connections', {id: 'c1', appId: 'app', driver: 'http', status: 'ready', authMethod: 'token', identity: {id: 'u'}});
  const permissions = new PermissionManager({store});
  permissions.set({connectionId: 'c1', capabilityId: capability.id, mode: 'allow'});
  assert.equal(permissions.decision(store.get('connections', 'c1'), capability).mode, 'allow');
  // Re-discovery finds the response returns an auth token.
  store.put('applicationMaps', {id: 'app', appId: 'app', classifierVersion: SENSITIVITY_VERSION, operations: [{...operation, sensitive: 'secrets'}]});
  const decision = permissions.decision(store.get('connections', 'c1'), capability);
  assert.deepEqual([decision.mode, decision.stale, decision.sensitivity], ['ask', true, 'secrets']);
});

test('a direct import is classified from the response its stored description documents', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-import-'));
  const store = new Store({dataDir: dir});
  t.after(async () => {store.close(); await rm(dir, {recursive: true, force: true});});
  const document = {openapi: '3.0.3', info: {title: 'Imported', version: '1'}, servers: [{url: 'https://api.example.com'}], paths: {
    '/hooks/{id}': {get: {operationId: 'getHook', parameters: [{name: 'id', in: 'path', required: true, schema: {type: 'string'}}], responses: {200: {description: 'OK', content: {'application/json': {schema: {$ref: '#/components/schemas/Hook'}}}}}}},
    '/items': {get: {operationId: 'listItems', responses: {200: {description: 'OK', content: {'application/json': {schema: {type: 'array', items: {type: 'object', properties: {id: {type: 'string'}}}}}}}}}}},
    components: {schemas: {Hook: {type: 'object', properties: {url: {type: 'string'}, secret: {type: 'string'}}}}}};
  const compiled = compileOpenApi({appId: 'app', document});
  for (const cap of compiled.capabilities) store.put('capabilities', {...cap, status: 'active'});
  store.put('surfaces', {id: `app:${compiled.fingerprint}`, appId: 'app', document});
  store.put('connections', {id: 'c1', appId: 'app', driver: 'http', status: 'ready', authMethod: 'token', identity: {id: 'u'}});
  const permissions = new PermissionManager({store});
  const decide = name => permissions.decision(store.get('connections', 'c1'), compiled.capabilities.find(cap => cap.provenance.operationId === name));
  assert.deepEqual([decide('getHook').sensitivity, decide('getHook').mode], ['secrets', 'ask']);
  assert.deepEqual([decide('listItems').sensitivity, decide('listItems').mode], [null, 'allow']);
  // Path items and operations given by reference are read as the compiler read them.
  const referenced = {openapi: '3.1.0', info: {title: 'Referenced', version: '1'}, servers: [{url: 'https://api.example.com'}], paths: {'/account': {$ref: '#/components/pathItems/Account'}},
    components: {pathItems: {Account: {get: {operationId: 'getAccount', responses: {200: {description: 'OK', content: {'application/json': {schema: {type: 'object', properties: {sid: {type: 'string'}, auth_token: {type: 'string'}}}}}}}}}}}};
  const [account] = compileOpenApi({appId: 'app', document: referenced}).capabilities;
  store.put('capabilities', {...account, status: 'active'});
  store.put('surfaces', {id: `app:${account.provenance.fingerprint}`, appId: 'app', document: referenced});
  assert.deepEqual([permissions.decision(store.get('connections', 'c1'), account).sensitivity, permissions.decision(store.get('connections', 'c1'), account).mode], ['secrets', 'ask']);
  // A stored description that cannot be read classifies as secrets, so it asks.
  const broken = {...referenced, components: {pathItems: {Account: {get: {operationId: 'getAccount', responses: {$ref: '#/components/responses/Missing'}}}}}};
  const [unreadable] = compileOpenApi({appId: 'app', document: {...referenced, info: {title: 'Unreadable', version: '2'}}}).capabilities;
  store.put('capabilities', {...unreadable, status: 'active'});
  store.put('surfaces', {id: `app:${unreadable.provenance.fingerprint}`, appId: 'app', document: {...broken, paths: {'/account': {$ref: '#/components/pathItems/Gone'}}}});
  assert.equal(permissions.decision(store.get('connections', 'c1'), unreadable).sensitivity, 'secrets');
});

test('a row change is all or nothing: Never always applies, Allow and Ask refuse while a member was made by older rules', async t => {
  const f = await fixture(t);
  const legacy = compileOpenApi({appId: 'github', document: {openapi: '3.0.3', info: {title: 'Legacy', version: '1'}, servers: [{url: 'https://api.github.com'}], paths: {
    '/user/repos': {get: {operationId: 'listRepos', responses: {200: {description: 'Repos'}}}},
    '/user/hooks': {post: {operationId: 'createHook', requestBody: {required: true, content: {'application/json': {schema: {type: 'object', properties: {url: {type: 'string'}}}}}}, responses: {201: {description: 'Created'}}}}}}}).capabilities;
  const {finalizeCapability: _unused, canonicalHash} = await import('../lib/compiler.mjs');
  // A capability shaped like one the pre-F09.1 compiler stored: its body takes a webhook secret.
  const write = legacy.find(cap => cap.provenance.operationId === 'createHook'), read = legacy.find(cap => cap.provenance.operationId === 'listRepos');
  const content = {...write, status: 'candidate', inputSchema: {...write.inputSchema, properties: {body: {type: 'object', additionalProperties: false, properties: {url: {type: 'string'}, secret: {type: 'string'}}}}}};
  delete content.id;
  const stale = {...content, id: `github.createhook.${canonicalHash(content).slice(0, 24)}`, status: 'active'};
  for (const cap of [{...read, status: 'active'}, stale]) f.app.store.put('capabilities', cap);
  f.app.store.put('applicationMaps', {id: 'github', operations: [{id: 'listRepos', capabilityId: read.id, method: 'GET', path: '/user/repos', requiredScopes: []}, {id: 'createHook', capabilityId: stale.id, method: 'POST', path: '/user/hooks', requiredScopes: []}]});
  f.app.runtime.permissions.groups = new Map([['github', validatePermissionGroups({schemaVersion: 1, appId: 'github', groups: [{id: 'github.all', label: 'Everything', effect: 'write', defaultMode: 'ask', requests: ['GET /user/repos', 'POST /user/hooks']}]})]]);
  const response = await f.owned('POST', '/api/oauth/github/start', {appId: 'github', writeAccess: true});
  const started = {body: await response.json(), flowId: /fabric_oauth=([^;]+)/.exec(response.headers.get('set-cookie'))[1]};
  await f.callback(started);
  const account = f.connections().find(connection => connection.status === 'ready');
  const rowOf = async () => (await f.json('GET', '/api/ui/apps/github')).body.sections.flatMap(section => section.rows).find(row => row.groupId === 'github.all');
  const post = body => f.json('POST', `/api/ui/apps/github/accounts/${encodeURIComponent(account.id)}/permissions`, body);
  const before = await rowOf();
  const refused = await post({groupId: 'github.all', mode: 'allow', etag: before.etag, confirmAllow: true});
  assert.equal(refused.body.code, 'rediscover_required'); assert.match(refused.body.error, /Discover .* again .*Nothing was changed/);
  const modes = () => [read.id, stale.id].map(id => f.app.runtime.permissions.decision(f.app.store.get('connections', account.id), f.app.store.get('capabilities', id)).mode);
  assert.deepEqual(modes(), ['ask', 'ask'], 'no member changed');
  assert.equal((await post({groupId: 'github.all', mode: 'deny', etag: (await rowOf()).etag})).status, 200);
  assert.deepEqual(modes(), ['deny', 'deny'], 'Never applied to every member, including the stale one');
  await assert.rejects(f.app.runtime.createJob({connectionId: account.id, capabilityId: stale.id, args: {body: {url: 'https://hooks.example.com', secret: 's'}}}), /made by older rules .*discover or import the app again/);
});

test('redaction keeps numbers, flags and permission levels under credential-like names, and scrubs logs without eating words', () => {
  const body = scrubValue({usage: {tokens: 1834}, permissions: {organization_personal_access_tokens: 'read', secrets: 'write'}, user_has_strong_password: false, password: true,
    temp_download_token: 'tdt-1', nextPageToken: 'n2', Token: {id: 'p1', type: 'title'}, access_tokens: ['a', 'b']}, secretContext([]));
  assert.deepEqual(body, {usage: {tokens: 1834}, permissions: {organization_personal_access_tokens: 'read', secrets: 'write'}, user_has_strong_password: false, password: '[redacted]',
    temp_download_token: '[redacted]', nextPageToken: 'n2', Token: {id: 'p1', type: 'title'}, access_tokens: ['a', 'b']});
  assert.equal(scrubAuthorization('Authorization:\\nBearer gho_abc and HTTP_AUTHORIZATION_Bearer gho_def'), 'Authorization:\\n[redacted] and HTTP_AUTHORIZATION_[redacted]');
  assert.equal(scrubAuthorization('Security scheme basic is not supported; header was Basic dXNlcjpwYXNzd29yZA=='), 'Security scheme basic is not supported; header was [redacted]');
});

test('a capability stored before F09.1 that takes a declared API-key location as input cannot run', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-stored-key-'));
  const store = new Store({dataDir: dir});
  t.after(async () => {store.close(); await rm(dir, {recursive: true, force: true});});
  const {Runtime} = await import('../lib/runtime.mjs');
  // What the pre-F09.1 compiler produced: appid, the document's declared key location, as an agent input.
  const withKey = {openapi: '3.0.3', info: {title: 'Weather', version: '1'}, servers: [{url: 'https://api.example.com'}], components: {securitySchemes: {key: {type: 'apiKey', in: 'query', name: 'appid'}}},
    paths: {'/weather': {get: {operationId: 'getWeather', parameters: [{name: 'appid', in: 'query', required: true, schema: {type: 'string'}}, {name: 'q', in: 'query', schema: {type: 'string'}}], responses: {200: {description: 'OK'}}}}}};
  const {components, ...withoutScheme} = withKey;
  const [compiled] = compileOpenApi({appId: 'weather', document: withoutScheme}).capabilities;
  const {canonicalHash, finalizeCapability} = await import('../lib/compiler.mjs');
  const stored = {...finalizeCapability({...compiled, provenance: {...compiled.provenance, fingerprint: canonicalHash(withKey)}}), status: 'active'};
  store.put('capabilities', stored);
  store.put('surfaces', {id: `weather:${canonicalHash(withKey)}`, appId: 'weather', document: withKey});
  store.put('connections', {id: 'c1', appId: 'weather', driver: 'http', status: 'ready', authMethod: 'token', identity: {id: 'u'}});
  const runtime = new Runtime({store, connections: {credentials: async () => ({headers: {}, allowedOrigins: ['https://api.example.com']})}});
  await assert.rejects(runtime.createJob({connectionId: 'c1', capabilityId: stored.id, args: {appid: 'SECRET-KEY-123', q: 'Halifax'}}), /takes the account's API key \(query parameter appid\)/);
  assert.equal(store.list('jobs').length, 0, 'no job, no preview carrying the key');
});

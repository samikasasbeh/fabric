import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';
import {parseTemplate} from '../lib/permission-groups.mjs';
import {methodPaths, methodMap, reviewedIds, checkPaths, serialize, recordPaths, GOOGLE_APPS, PATHS_FILE, SCOPES_FILE} from '../scripts/google-method-paths.mjs';
import {templateChecks} from '../scripts/app-template-check.mjs';
import {actionIds} from '../lib/actions.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {googleMap, googlePaths, googleScopes} from './fixtures/access/google-maps.mjs';

// F10.11 part a (docs/F10.11-BUILD-MAP.md part a and section 3): Google's method paths, recorded from the public Discovery documents into
// test/fixtures/access/google-method-paths.json beside the scope facts, which never change here. No test reads the network: the recorder
// runs only by hand with --record, and the one recorder test below answers it with a scripted document.
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = file => readFileSync(path.join(ROOT, file));

/** A small Discovery document: nested resources, a flatPath that differs from path, and methods nobody reviewed. */
const DOCUMENT = () => ({kind: 'discovery#restDescription', discoveryVersion: 'v1', protocol: 'rest', revision: '20261020', resources: {users: {
  methods: {getProfile: {id: 'gmail.users.getProfile', httpMethod: 'get', path: 'gmail/v1/users/{userId}/profile', flatPath: 'gmail/v1/users/{usersId}/profile'}},
  resources: {messages: {methods: {send: {id: 'gmail.users.messages.send', httpMethod: 'post', path: 'gmail/v1/users/{userId}/messages/send', flatPath: 'gmail/v1/users/{usersId}/messages/send'},
    list: {id: 'gmail.users.messages.list', httpMethod: 'GET', path: '/gmail/v1/users/{userId}/messages'}},
  resources: {attachments: {methods: {get: {id: 'gmail.users.messages.attachments.get', httpMethod: 'GET', path: 'gmail/v1/users/{userId}/messages/{messageId}/attachments/{id}'}}}}}}}}});
const IDS = ['gmail.users.getProfile', 'gmail.users.messages.attachments.get', 'gmail.users.messages.send'];
const GMAIL = {prefixes: ['/gmail/v1/']};

test('methodPaths() walks nested resources, upper-cases methods, prefixes /, reads path and never flatPath, and ignores methods nobody reviewed', () => {
  const recorded = methodPaths(DOCUMENT(), IDS, GMAIL);
  assert.deepEqual(recorded, {revision: '20261020', methods: {
    'gmail.users.getProfile': {method: 'GET', path: '/gmail/v1/users/{userId}/profile'},
    'gmail.users.messages.attachments.get': {method: 'GET', path: '/gmail/v1/users/{userId}/messages/{messageId}/attachments/{id}'},
    'gmail.users.messages.send': {method: 'POST', path: '/gmail/v1/users/{userId}/messages/send'}}});
  assert.deepEqual(Object.keys(recorded.methods), [...IDS].sort(), 'ids sorted');
  assert.ok(!JSON.stringify(recorded).includes('usersId'), 'flatPath is never read');
  assert.ok(!Object.hasOwn(recorded.methods, 'gmail.users.messages.list'), 'an unreviewed method is left out');
});

test('methodPaths() refuses a missing reviewed id, a duplicate, a document that is not v1 REST, a method outside the five, a path outside the prefixes and a path it cannot read', () => {
  const refused = (change, pattern, ids = IDS, options = GMAIL) => { const document = DOCUMENT(); change(document); assert.throws(() => methodPaths(document, ids, options), pattern); };
  refused(() => {}, /lacks 1 reviewed method\(s\): gmail\.users\.drafts\.get/, [...IDS, 'gmail.users.drafts.get']);
  refused(document => { document.resources.users.resources.messages.methods.again = {...document.resources.users.methods.getProfile}; }, /lists gmail\.users\.getProfile twice/);
  refused(document => { document.resources.users.resources.messages.methods.again = {...document.resources.users.resources.messages.methods.list}; }, /lists gmail\.users\.messages\.list twice/);
  for (const [field, value] of [['kind', 'discovery#directoryList'], ['discoveryVersion', 'v2'], ['protocol', 'rpc']]) refused(document => { document[field] = value; }, /not a supported Google REST Discovery document/);
  for (const verb of ['HEAD', 'OPTIONS', 'TRACE', undefined]) refused(document => { document.resources.users.methods.getProfile.httpMethod = verb; }, /gmail\.users\.getProfile: .* is not GET, POST, PUT, PATCH or DELETE/);
  refused(document => { document.resources.users.methods.getProfile.path = 'upload/gmail/v1/users/{userId}/profile'; }, /\/upload\/gmail\/v1\/users\/\{userId\}\/profile is outside the app's proxy path prefixes/);
  refused(document => { delete document.resources.users.methods.getProfile.path; }, /gmail\.users\.getProfile: the method has no path/);
  for (const bad of ['gmail/v1/users//profile', 'gmail/v1/users/{+userId}/profile', 'gmail/v1/users/a{userId}/profile']) refused(document => { document.resources.users.methods.getProfile.path = bad; }, /gmail\.users\.getProfile: Template GET /);
  refused(document => { document.resources = {users: 'nothing'}; }, /Malformed or overly nested Google resources/);
});

test('the committed file holds the reviewed ids of both apps with their paths, each placing through the proxy prefix, as the recorder writes it', () => {
  const paths = googlePaths(), scopes = googleScopes();
  assert.deepEqual(checkPaths(paths, scopes), []);
  assert.equal(read(PATHS_FILE).toString('utf8'), serialize(paths), '1-space indent and a final newline');
  assert.deepEqual(Object.keys(paths.apps), GOOGLE_APPS);
  for (const [appId, count] of [['gmail', 79], ['google-calendar', 38]]) {
    const entry = paths.apps[appId], ids = Object.keys(entry.methods);
    assert.equal(ids.length, count, appId);
    assert.deepEqual(ids, reviewedIds(appId), `${appId}: exactly the reviewed ids, sorted`);
    assert.deepEqual(ids, Object.keys(scopes.apps[appId].methods).sort(), `${appId}: exactly the scope facts' ids`);
    assert.equal(entry.source, scopes.apps[appId].source, appId);
    assert.match(entry.revision, /^[0-9]{8}$/);
    for (const [id, {method, path: location}] of Object.entries(entry.methods)) {
      assert.ok(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method), id);
      assert.ok(PROXY_CONFIGS.get(appId).pathPrefixes.some(prefix => location.startsWith(prefix)), `${id}: ${location}`);
      assert.doesNotThrow(() => parseTemplate(`${method} ${location}`), id);
    }
    // googleMap() is the map DiscoveryEngine would store: every reviewed operation, with Discovery's scopes beside its path.
    const map = googleMap(appId);
    assert.deepEqual(Object.keys(map), ['id', 'appId', 'operations']);
    assert.deepEqual([map.id, map.appId, map.operations.length], [appId, appId, count]);
    for (const operation of map.operations) {
      assert.deepEqual(Object.keys(operation), ['id', 'method', 'path', 'requiredScopes', 'scopeSets']);
      assert.deepEqual(operation.requiredScopes, scopes.apps[appId].methods[operation.id]);
      assert.deepEqual(operation.scopeSets, operation.requiredScopes.map(scope => [scope]));
    }
    assert.ok(templatesFor(PERMISSION_GROUPS.get(appId), PROXY_CONFIGS.get(appId), map), `${appId}: the map places every reviewed row`);
  }
  assert.equal(methodMap(paths, scopes, 'github'), null, 'no entry, no map');
});

test('checkPaths() names a file that lost a reviewed id, moved a path outside the prefix or no longer matches the scope facts', () => {
  const scopes = googleScopes(), edited = change => { const paths = structuredClone(googlePaths()); change(paths); return checkPaths(paths, scopes); };
  assert.ok(edited(paths => { delete paths.apps.gmail.methods['gmail.users.getProfile']; }).some(problem => /gmail: the method ids are not exactly the 79 reviewed ones/.test(problem)));
  assert.ok(edited(paths => { paths.apps.gmail.methods['gmail.users.getProfile'].path = '/upload/gmail/v1/users/{userId}/profile'; }).some(problem => /outside the proxy path prefixes/.test(problem)));
  assert.ok(edited(paths => { paths.apps['google-calendar'].source = 'https://example.com/rest'; }).some(problem => /source is not the scope facts' source/.test(problem)));
  assert.ok(edited(paths => { paths.apps.gmail.methods['gmail.users.getProfile'].method = 'HEAD'; }).length);
  assert.deepEqual(checkPaths({note: 'x'}, scopes), ['The file holds exactly note and apps.']);
});

test('the recorder writes the file from what Google serves, reports scope differences, and never writes the scope facts', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-google-paths-'));
  try {
    mkdirSync(path.join(root, 'test', 'fixtures', 'access'), {recursive: true});
    writeFileSync(path.join(root, SCOPES_FILE), read(SCOPES_FILE));
    // The served documents: the committed paths, with the scope facts, at a newer revision; one Gmail method's scopes moved.
    const served = appId => {
      const methods = {}, entry = googlePaths().apps[appId];
      for (const [id, fact] of Object.entries(entry.methods)) methods[id.replace(/\./g, '_')] = {id, httpMethod: fact.method.toLowerCase(), path: fact.path.slice(1), flatPath: 'x/y', scopes: [...googleScopes().apps[appId].methods[id]]};
      if (appId === 'gmail') methods.gmail_users_getProfile.scopes = ['https://mail.google.com/'];
      return {kind: 'discovery#restDescription', discoveryVersion: 'v1', protocol: 'rest', revision: '20261020', resources: {all: {methods}}};
    };
    const calls = [];
    const request = async options => { calls.push(options); return {status: 200, headers: {}, data: served(GOOGLE_APPS.find(appId => googleScopes().apps[appId].source === options.url))}; };
    const {paths, differences} = await recordPaths({root, request});
    assert.deepEqual(calls.map(call => [call.url, call.method, call.headers, call.allowedOrigins, call.timeoutMs, call.maxBytes]), GOOGLE_APPS.map(appId => {
      const source = new URL(googleScopes().apps[appId].source);
      return [source.href, 'GET', {Accept: 'application/json'}, [source.origin], 30_000, 4 * 1024 * 1024];
    }), 'one credential-free GET per source');
    assert.deepEqual(paths.apps.gmail.methods, googlePaths().apps.gmail.methods);
    assert.equal(paths.apps.gmail.revision, '20261020', 'the revision Google serves');
    assert.deepEqual(differences.length, 1);
    assert.match(differences[0], /^gmail \(revision 20261020, scope facts 20261005\) gmail\.users\.getProfile: served https:\/\/mail\.google\.com\/; recorded /);
    assert.equal(readFileSync(path.join(root, SCOPES_FILE)).toString('utf8'), read(SCOPES_FILE).toString('utf8'), 'the scope facts are never written');
    assert.equal(readFileSync(path.join(root, PATHS_FILE), 'utf8'), serialize(paths));
    // A source that does not answer 200 writes nothing.
    rmSync(path.join(root, PATHS_FILE));
    await assert.rejects(recordPaths({root, request: async () => ({status: 503, headers: {}, data: null})}), /gmail: the Discovery source answered HTTP 503; nothing was written/);
  } finally { rmSync(root, {recursive: true, force: true}); }
});

test('the script reaches the network only from --record, sends no credential and reads no environment; no test runs the recorder against Google', () => {
  // The code without its comments, which say what the recorder never sends.
  const text = read('scripts/google-method-paths.mjs').toString('utf8').split('\n').filter(line => !/^\s*(?:\/\/|\/\*\*|\*)/.test(line)).join('\n');
  assert.equal(text.match(/network\.mjs/g)?.length, 1, 'one reference to the network module');
  const record = text.slice(text.indexOf('export async function recordPaths'), text.indexOf('\nif (process.argv[1]'));
  assert.ok(record.includes("import('../lib/network.mjs')"), 'loaded only inside recordPaths()');
  for (const forbidden of [/process\.env/, /Authorization/i, /\bfetch\(/, /\bkey=/, /[Cc]ookie/, /node:https?['"]/]) assert.doesNotMatch(text, forbidden, String(forbidden));
  const main = text.slice(text.indexOf('\nif (process.argv[1]'));
  assert.equal(main.match(/recordPaths\(/g)?.length, 1);
  assert.match(main, /if \(args\.includes\('--record'\)\) \{\n {4}const \{paths, differences\} = await recordPaths\(\);/);
});

test('google-method-scopes.json, which feeds the signed defaults, keeps its bytes', () => {
  assert.equal(createHash('sha256').update(read(SCOPES_FILE)).digest('hex'), '1508dbf5e0943c1d3113b026482419c675be99862aadbc2577eaf4a90f5edc1e');
});

test('the template check places a Gmail-shaped file through the paths, so "cannot be placed" stays only for a provider with no paths file', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-template-google-'));
  try {
    for (const folder of ['catalog/actions', 'catalog/permissions', 'test/fixtures/access', 'lib/transforms']) mkdirSync(path.join(root, folder), {recursive: true});
    for (const file of ['catalog/permissions/gmail.json', SCOPES_FILE, PATHS_FILE, 'lib/transforms/pins.json']) writeFileSync(path.join(root, file), read(file));
    const ok = {status: [200], require: []};
    const file = {schemaVersion: 1, appId: 'gmail', specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {userId: 'me'}, actions: [{id: 'gmail.action.read-profile.v1.000000000000000000000000',
      key: 'read-profile', version: 1, name: 'Read profile', description: 'Reads the account\'s address.', effect: 'read', row: 'gmail.messages.read',
      hints: {readOnly: true, destructive: false, idempotent: false, openWorld: true}, inputSchema: {type: 'object', properties: {}, additionalProperties: false},
      outputSchema: {type: 'object', properties: {address: {type: 'string', maxLength: 254}}, required: [], additionalProperties: false}, guards: [], prepare: [],
      perform: [{id: 'profile', method: 'GET', path: '/gmail/v1/users/{userId}/profile', expect: ok}], output: {address: {step: 'profile', pointer: '/emailAddress'}}, preview: [], definitive: [404]}]};
    // The id an author writes: the validator computes it from the content alone, so it is the same placed or not.
    file.actions[0].id = actionIds(file, {identities: new Map([['gmail', definitionFor('google')]])}).get('read-profile v1').id;
    writeFileSync(path.join(root, 'catalog/actions/gmail.json'), JSON.stringify(file));
    const reason = () => templateChecks('gmail', {root, codeHashes: () => ({})}).find(item => item.id === 'actions').reason;
    assert.equal(reason(), 'the action file is a candidate: no reviewer has marked it reviewed yet (I8)', 'placed on Google\'s path, it waits only for its review');
    rmSync(path.join(root, PATHS_FILE));
    assert.match(reason(), /^1 of 1 actions cannot be placed: gmail is reviewed by operation id, and the check has no method table for it/);
  } finally { rmSync(root, {recursive: true, force: true}); }
});

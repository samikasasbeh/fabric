import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {validatePermissionGroups, memberData, PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {validateOptionSources} from '../lib/option-sources.mjs';
import {templatesFor, matchRequest} from '../lib/proxy-match.mjs';
import * as compiler from '../lib/compiler.mjs';
import {secretKey} from '../lib/redaction.mjs';
import {TRANSFORMS as SHIPPED, checkEntry} from '../lib/transforms/index.mjs';
import {runEntry, runIn} from '../lib/transforms/run.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {defaultsTable, dataHash, filesHash, reviewText} from '../scripts/defaults-golden.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {checkExpression, checkTest, checkCall, assertPerformSources, newBudget, STEP_HEADERS, PERFORM_SOURCES, POLL_ITEM_FIELDS, checkPointer, readsOnly, READ_SOURCES, SOURCES, STEP_SOURCES,
  REGISTRATION_NAMES} from '../lib/action-expressions.mjs';
import {validateActionFile, checkOutput, checkPreview, checkRequest, runPlan, SENDER_SOURCES, SENDER_ARGUMENTS, REMOVALS, REFUSALS, DEFINITIVE_CODES, FABRIC_HEADERS, NOTION_RESERVED, BOUNDS,
  actionIds, actionCapability, loadActions, jobKey, pollHash, CURSOR_KINDS, ITEM_TIME_FORMATS} from '../lib/actions.mjs';
import {capabilityPermissionHash, PermissionManager} from '../lib/permissions.mjs';
import {lockedRowOf, memberRoutes, rowMemberOf} from '../lib/row-locks.mjs';
import {AcquisitionEngine} from '../lib/acquisition.mjs';
import {Runtime} from '../lib/runtime.mjs';
import {Store} from '../lib/store.mjs';
import {RESOLVING_WRITES} from '../lib/action-placement.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {FIXTURE_APPS, fixtureRows, fixtureGroups, fixtureConfigs, fixtureMap, fixtureOptions, fixtureChoices, fixtureActions, reposAnswer, withIds, actionSchema, fixtureSignIn} from './fixtures/actions/fixture-app.mjs';
import {STUBS, TRANSFORMS, PINS} from './fixtures/actions/registry.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// F10.9 (docs/F10.9-BUILD-MAP.md section 4): the action file validator, on the fixture app of test/fixtures/actions. Parts a to h are
// built: the fixture app and registry (part a), the shared checks the validator imports (part b, no behaviour change, I1), the row
// data whose readers land in this step, bindContent and sensitive (part c), the expression grammar (part d), the file validator (part
// f, with part e's placement), ids, the capability, the loader and job keys (part g), the poll block (part h), and the action schema,
// which every file this suite accepts must pass (part l, the last test). Each test was written first and seen to fail before its code
// landed.
const at = (definition, id) => definition.groups.find(group => group.id === id);
const withGroup = (id, change, appId = 'fixture') => {
  const rows = fixtureRows(appId);
  return {...rows, groups: rows.groups.map(group => group.id === id ? change(structuredClone(group)) : group)};
};
const refused = (definition, pattern, message) => assert.throws(() => validatePermissionGroups(definition), pattern, message);

// ---- part a: the fixture app and the fixture registry ---------------------------------------------------------------------------
test('the fixture app loads through the shipped validators: its rows, proxy settings, map and version 1 options', () => {
  const groups = fixtureGroups(), configs = fixtureConfigs(groups), rows = groups.get('fixture');
  assert.deepEqual([...groups.keys()], FIXTURE_APPS);
  assert.deepEqual(rows.groups.map(group => [group.id, group.effect, group.defaultMode]), [
    ['fixture.items.read', 'read', 'allow'], ['fixture.keys.read', 'read', 'ask'], ['fixture.labels.write', 'write', 'allow'], ['fixture.items.edit', 'write', 'ask'],
    ['fixture.messages.send', 'write', 'ask'], ['fixture.items.delete', 'delete', 'ask'], ['fixture.access.grant', 'write', 'deny']]);
  const read = at(rows, 'fixture.items.read');
  assert.deepEqual([read.reviewedReads, read.unavailable], [['POST /items/search'], {'GET /items/{item_id}/history': 'not-requested'}]);
  assert.ok(read.requests.includes('POST /items/export'), 'a POST in a read row that is not a reviewed read');
  assert.equal(at(rows, 'fixture.labels.write').stayInAccount, true);
  assert.equal(at(rows, 'fixture.messages.send').audience, true);
  assert.deepEqual(at(rows, 'fixture.items.edit').bodyRoutes.map(route => route.to), ['fixture.items.delete', 'fixture.items.delete', 'fixture.access.grant']);
  assert.equal(at(rows, 'fixture.access.grant').locked, 'fabric');
  assert.deepEqual([configs.get('fixture').style, configs.get('fixture-rpc').style], ['rest', 'rpc']);
  // The typed operation places through the map; without it templatesFor() has nothing for the app, as for Gmail and Calendar.
  assert.equal(templatesFor(rows, configs.get('fixture'), null), null);
  const templates = templatesFor(rows, configs.get('fixture'), fixtureMap());
  assert.deepEqual([matchRequest(templates, {method: 'GET', segments: ['items']}).groupId, matchRequest(templates, {method: 'GET', segments: ['items']}).member], ['fixture.items.read', 'fixture.items.list']);
  assert.equal(validateOptionSources(fixtureOptions(), groups)[0].operation, 'fixture.items.list');
  const twin = at(groups.get('fixture-rpc'), 'fixture-rpc.messages.read');
  assert.deepEqual([twin.reviewedReads, twin.requests.includes('POST /messages.history')], [['POST /canvases.read'], true]);
});

// F10.17 and F10.19 listed churn: collections.stringValues@1, notion.schema@1 and notion.propertyValues@1 ship, so their stubs are gone and
// the fixture registry holds the shipped entries in their real shape: an outputMap result, a schema entry, and a resolvedValues argument
// with an outputFrom result.
test('the fixture registry is the shipped registry plus one stub in the real entry shape, with its own pin (R17, open point Minor 2)', () => {
  assert.deepEqual(STUBS.map(({entry}) => `${entry.name}@${entry.version}`), ['ids.linkPage@1']);
  for (const {file, entry} of STUBS) assert.doesNotThrow(() => checkEntry(entry, file), file);
  for (const [id, entry] of SHIPPED) assert.equal(TRANSFORMS.get(id), entry, id);
  assert.equal(TRANSFORMS.size, SHIPPED.size + 1);
  const byId = Object.fromEntries(STUBS.map(({entry}) => [`${entry.name}@${entry.version}`, entry]));
  assert.equal(SHIPPED.get('notion.schema@1').kind, 'schema');
  assert.deepEqual(Object.keys(SHIPPED.get('notion.propertyValues@1').resolvedValues), ['values']);
  assert.ok(Object.hasOwn(SHIPPED.get('notion.propertyValues@1'), 'outputFrom') && !Object.hasOwn(SHIPPED.get('notion.propertyValues@1'), 'output'));
  assert.equal(TRANSFORMS.get('collections.stringValues@1'), SHIPPED.get('collections.stringValues@1'), 'the shipped outputMap transform');
  assert.ok(Object.hasOwn(SHIPPED.get('collections.stringValues@1'), 'outputMap') && !Object.hasOwn(SHIPPED.get('collections.stringValues@1'), 'output'));
  // Every id has a pin; the real transforms keep their shipped pins.
  const shipped = JSON.parse(readFileSync(new URL('../lib/transforms/pins.json', import.meta.url), 'utf8')).transforms;
  assert.deepEqual(Object.keys(PINS).sort(), [...TRANSFORMS.keys()].sort());
  for (const id of SHIPPED.keys()) assert.equal(PINS[id], shipped[id], id);
  for (const id of Object.keys(byId)) assert.match(PINS[id], /^[a-f0-9]{64}$/, id);
  // The stubs run through the harness: a repeated or unsafe workflow input name refuses, a propertyValues key is a bound id.
  assert.deepEqual(runIn(TRANSFORMS, 'collections.stringValues@1', {values: [{name: 'env', value: 'prod'}]}), {env: 'prod'});
  for (const values of [[{name: 'a', value: '1'}, {name: 'a', value: '2'}], [{name: '1abc', value: '1'}], [{name: 'a b', value: '1'}]]) {
    assert.throws(() => runIn(TRANSFORMS, 'collections.stringValues@1', {values}), error => error instanceof TransformError, JSON.stringify(values));
  }
  assert.deepEqual(runIn(TRANSFORMS, 'ids.linkPage@1', {link: '<https://api.fixture.test/other?page=2>; rel="next"', url: 'https://api.fixture.test/items', param: 'page'}), {}, 'another path is never a next page');
});

test('the fixture GitHub answer carries temp_clone_token in each repository, which secretKey() names a secret and "0" does not', () => {
  const answer = reposAnswer();
  assert.equal(answer.length, 2);
  for (const repository of answer) assert.equal(typeof repository.temp_clone_token, 'string');
  assert.deepEqual([secretKey('temp_clone_token'), secretKey('0'), secretKey('full_name'), secretKey('nextPageToken')], [true, false, false, false]);
});

test('the fixture action file names only fixture rows, fixture transforms and fixture sources (part g checks its ids)', () => {
  const file = fixtureActions(), rows = new Set(fixtureRows().groups.map(group => group.id));
  assert.deepEqual([file.schemaVersion, file.appId, file.specVersion], [1, 'fixture', 'fabric/0.2']);
  for (const action of file.actions) {
    assert.ok(rows.has(action.row), `${action.key} names its row`);
    assert.match(action.id, new RegExp(`^fixture\\.action\\.${action.key}\\.v${action.version}\\.[a-f0-9]{24}$`), action.key);
  }
  const named = JSON.stringify(file).match(/"transform": ?"[^"]+"/g)?.map(text => text.replace(/^"transform": ?"|"$/g, '')) ?? [];
  for (const id of named) assert.ok(TRANSFORMS.has(id), id);
});

// ---- part b: the shared checks become exports (no behaviour change, I1) ---------------------------------------------------------
test('lib/compiler.mjs exports validateValue, assertNoCredentialInputs and secretParameter, which behave as they did inside it', () => {
  for (const name of ['validateValue', 'assertNoCredentialInputs', 'secretParameter', 'checkSchema']) assert.equal(typeof compiler[name], 'function', name);
  const schema = {type: 'object', properties: {name: {type: 'string', maxLength: 3}, nested: {type: 'object', properties: {refresh_token: {type: 'string'}}, additionalProperties: false}}, additionalProperties: false};
  assert.doesNotThrow(() => compiler.validateValue(schema, {name: 'abc'}, '$input'));
  assert.throws(() => compiler.validateValue(schema, {name: 'abcd'}, '$input'), /\$input\.name: string length outside bounds/);
  assert.throws(() => compiler.validateValue(schema, {other: 1}, '$input'), /\$input\.other: undeclared property/);
  assert.throws(() => compiler.assertNoCredentialInputs(schema, '$input'), /\$input\.nested\.refresh_token: credentials and credential exchanges are not agent inputs/);
  assert.throws(() => compiler.assertNoCredentialInputs({type: 'object', properties: {list: {type: 'array', items: {type: 'object', properties: {client_secret: {type: 'string'}}, additionalProperties: false}}}, additionalProperties: false}, '$input'), /\$input\.list\[\]\.client_secret/);
  assert.doesNotThrow(() => compiler.assertNoCredentialInputs({type: 'object', properties: {pageToken: {type: 'string'}, key_id: {type: 'string'}}, additionalProperties: false}, '$input'));
  // secretParameter() is SECRET_PARAMETER: whole names only, any case. It catches `key`, which credentialName() does not.
  for (const name of ['key', 'KEY', 'token', 'api_key', 'apiKey', 'api-key', 'client_secret', 'access_token', 'Authorization', 'cookie', 'password']) assert.equal(compiler.secretParameter(name), true, name);
  for (const name of ['pageToken', 'keyId', 'monkey', 'tokens', 'secretName', 'labelIds']) assert.equal(compiler.secretParameter(name), false, name);
  assert.deepEqual([compiler.credentialName('key'), compiler.secretParameter('key')], [false, true]);
});

// ---- part c: bindContent and sensitive row data -----------------------------------------------------------------------------------
test('bindContent and sensitive are version 2 fields: a version 1 file refuses them', () => {
  for (const [key, value] of [['bindContent', {'POST /items': {kind: 'sha', at: 'body:/sha'}}], ['sensitive', {'POST /items': 'secrets'}]]) {
    const v1 = {schemaVersion: 1, appId: 'fixture', groups: [{id: 'fixture.items.edit', label: 'Edit items', effect: 'write', defaultMode: 'ask', requests: ['POST /items'], [key]: value}]};
    refused(v1, new RegExp(`carries ${key}, which needs schemaVersion 2`), key);
  }
});

test('bindContent is {kind, at} per member, keyed by member key and frozen; sensitive is "secrets" per member; both emitted only when declared', () => {
  const rows = validatePermissionGroups(fixtureRows()), send = at(rows, 'fixture.messages.send'), keys = at(rows, 'fixture.keys.read');
  assert.deepEqual(send.bindContent, {'POST /drafts/{draft_id}/send': {kind: 'resend', at: 'body:/raw'}, 'PUT /files/{path}': {kind: 'sha', at: 'body:/sha'}, 'PATCH /events/{event_id}': {kind: 'etag', at: 'header:If-Match'}},
    '{+path} and {path} are one member, stored by member key');
  assert.deepEqual(keys.sensitive, {'GET /keys/{key_id}': 'secrets'});
  assert.ok(Object.isFrozen(send.bindContent) && Object.values(send.bindContent).every(Object.isFrozen) && Object.isFrozen(keys.sensitive));
  const EIGHT = ['id', 'label', 'effect', 'defaultMode', 'stayInAccount', 'operations', 'requests', 'reviewedReads'];
  assert.deepEqual(Object.keys(send), [...EIGHT, 'audience', 'conditionalScopes', 'bindContent'], 'after the F10.6 data');
  assert.deepEqual(Object.keys(keys), [...EIGHT, 'sensitive']);
  const routed = validatePermissionGroups(withGroup('fixture.items.edit', group => ({...group, sensitive: {'POST /items': 'secrets'}})));
  assert.deepEqual(Object.keys(at(routed, 'fixture.items.edit')), [...EIGHT, 'sensitive', 'bodyRoutes'], 'before the body routes');
  for (const group of rows.groups.filter(item => item !== send && item !== keys)) assert.ok(!Object.hasOwn(group, 'bindContent') && !Object.hasOwn(group, 'sensitive'), `${group.id} declares neither`);
  // The output loads again to itself, and no shipped row declares either field but the content bindings F10.13 adds to Calendar's
  // "Create, edit and invite people to events" (listed churn, test/f10-13-churn.test.mjs) and F10.17 to GitHub's "Open and merge pull
  // requests" and "Push code and manage repositories" (listed churn, test/f10-17-churn.test.mjs).
  assert.deepEqual(validatePermissionGroups(JSON.parse(JSON.stringify(rows))), rows);
  const SHIPPED_BINDINGS = {'google-calendar google-calendar.events.write': {'calendar.events.patch': {kind: 'etag', at: 'header:If-Match'}, 'calendar.events.update': {kind: 'etag', at: 'header:If-Match'}},
    'github github.pulls.write': {'PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge': {kind: 'sha', at: 'body:/sha'}},
    'github github.code.write': {'PUT /repos/{owner}/{repo}/contents/{path}': {kind: 'sha', at: 'body:/sha'}}};
  for (const [appId, definition] of PERMISSION_GROUPS) for (const group of definition.groups) {
    if (Object.hasOwn(SHIPPED_BINDINGS, `${appId} ${group.id}`)) {
      assert.deepEqual([group.bindContent, Object.hasOwn(group, 'sensitive')], [SHIPPED_BINDINGS[`${appId} ${group.id}`], false], `${appId} ${group.id}`);
      continue;
    }
    // F10.15 listed churn (test/f10-15-churn.test.mjs): Gmail's "Send emails" binds drafts.send to the message read first.
    if (`${appId} ${group.id}` === 'gmail gmail.messages.send') {
      assert.deepEqual([group.bindContent, Object.hasOwn(group, 'sensitive')], [{'gmail.users.drafts.send': {kind: 'resend', at: 'body:/message/raw'}}, false]);
      continue;
    }
    assert.ok(!Object.hasOwn(group, 'bindContent') && !Object.hasOwn(group, 'sensitive'), `${appId} ${group.id}`);
  }
});

test('bindContent refuses a locked row, a non-member, an unavailable member, an unknown kind and a location its kind cannot take', () => {
  const bind = value => group => ({...group, bindContent: value});
  refused(withGroup('fixture.access.grant', bind({'POST /hooks': {kind: 'sha', at: 'body:/sha'}})), /fixture\.access\.grant is locked by Fabric, so it has no content binding and no sensitive members/, 'locked row');
  refused(withGroup('fixture.messages.send', bind({'POST /items': {kind: 'sha', at: 'body:/sha'}})), /POST \/items is in fixture\.messages\.send bindContent but is not a member/, 'non-member');
  refused(withGroup('fixture.items.read', bind({'GET /items/{item_id}/history': {kind: 'etag', at: 'header:If-Match'}})), /GET \/items\/\{item_id\}\/history is unavailable in fixture\.items\.read, so it has no content binding/, 'unavailable member');
  refused(withGroup('fixture.messages.send', bind({})), /bindContent must name at least one member/, 'empty');
  refused(withGroup('fixture.messages.send', bind({'POST /messages': {kind: 'sha', at: 'body:/a'}, 'POST /messages ': {kind: 'sha', at: 'body:/b'}})), /not a member/, 'a near name');
  for (const [entry, pattern] of [
    [{kind: 'hash', at: 'body:/sha'}, /must be \{kind, at\} with kind etag, sha or resend/],
    [{kind: 'sha'}, /must be \{kind, at\}/], [{kind: 'sha', at: 'body:/sha', also: 1}, /must be \{kind, at\}/], ['sha', /must be \{kind, at\}/], [null, /must be \{kind, at\}/], [['sha'], /must be \{kind, at\}/],
    [{kind: 'etag', at: 'body:/etag'}, /carries an etag, which goes only in header:If-Match/], [{kind: 'etag', at: 'header:if-match'}, /goes only in header:If-Match/],
    [{kind: 'sha', at: 'header:If-Match'}, /carries a sha at body:<pointer>/], [{kind: 'resend', at: '/raw'}, /carries a resend at body:<pointer>/],
    [{kind: 'sha', at: 'body:'}, /1 to 32 non-empty tokens/], [{kind: 'sha', at: 'body:sha'}, /1 to 32 non-empty tokens/], [{kind: 'sha', at: 'body:/a//b'}, /1 to 32 non-empty tokens/],
    [{kind: 'sha', at: 'body:/__proto__'}, /1 to 32 non-empty tokens/], [{kind: 'sha', at: 'body:/a~2'}, /1 to 32 non-empty tokens/], [{kind: 'sha', at: `body:${'/a'.repeat(33)}`}, /1 to 32 non-empty tokens/],
    [{kind: 'resend', at: `body:/${'r'.repeat(200)}`}, /in at most 200 characters/]]) {
    refused(withGroup('fixture.messages.send', bind({'POST /messages': entry})), pattern, JSON.stringify(entry));
  }
  for (const entry of [{kind: 'sha', at: `body:${'/a'.repeat(32)}`}, {kind: 'resend', at: 'body:/message/raw'}, {kind: 'sha', at: 'body:/a~1b'}]) {
    assert.doesNotThrow(() => validatePermissionGroups(withGroup('fixture.messages.send', bind({'POST /messages': entry}))), JSON.stringify(entry));
  }
});

test('sensitive refuses a locked row, a non-member, an unavailable member and any value other than "secrets"', () => {
  const mark = value => group => ({...group, sensitive: value});
  refused(withGroup('fixture.access.grant', mark({'POST /hooks': 'secrets'})), /fixture\.access\.grant is locked by Fabric, so it has no content binding and no sensitive members/, 'locked row');
  refused(withGroup('fixture.keys.read', mark({'GET /items/{item_id}': 'secrets'})), /GET \/items\/\{item_id\} is in fixture\.keys\.read sensitive but is not a member/, 'non-member');
  refused(withGroup('fixture.items.read', mark({'GET /items/{item_id}/history': 'secrets'})), /GET \/items\/\{item_id\}\/history is unavailable in fixture\.items\.read, so it has no content binding and is not marked sensitive/, 'unavailable member');
  refused(withGroup('fixture.keys.read', mark({})), /sensitive must name at least one member/, 'empty');
  for (const value of ['secret', 'Secrets', true, 'credentials', null, ['secrets'], {}]) refused(withGroup('fixture.keys.read', mark({'GET /keys': value})), /sensitive for GET \/keys must be "secrets"/, JSON.stringify(value));
  // A write row may mark a member too: its answer can carry a secret whatever the row does.
  assert.deepEqual(at(validatePermissionGroups(withGroup('fixture.labels.write', mark({'POST /labels': 'secrets'}))), 'fixture.labels.write').sensitive, {'POST /labels': 'secrets'});
});

test('memberData() returns a member\'s bindContent and sensitive mark only when its row declares them', () => {
  const rows = validatePermissionGroups(fixtureRows()), send = at(rows, 'fixture.messages.send'), keys = at(rows, 'fixture.keys.read');
  assert.deepEqual(memberData(send, 'PUT /files/{+path}'), {scopeSets: null, unavailable: null, unsupported: null, conditions: null, bindContent: {kind: 'sha', at: 'body:/sha'}});
  assert.deepEqual(memberData(send, 'PATCH /events/{event_id}').bindContent, {kind: 'etag', at: 'header:If-Match'});
  assert.deepEqual(memberData(keys, 'GET /keys/{key_id}'), {scopeSets: null, unavailable: null, unsupported: null, conditions: null, sensitive: 'secrets'});
  for (const [group, member] of [[send, 'POST /messages'], [keys, 'GET /keys'], [at(rows, 'fixture.items.read'), 'GET /labels']]) {
    assert.deepEqual(memberData(group, member), {scopeSets: null, unavailable: null, unsupported: null, conditions: null}, member);
  }
  for (const member of ['__proto__', 'constructor', 'toString', 7, null]) assert.deepEqual(memberData(send, member), {scopeSets: null, unavailable: null, unsupported: null, conditions: null}, String(member));
});

// ---- part c: the defaults table -----------------------------------------------------------------------------------------------------
// The fixture app's sign-in lives in test/fixtures/actions/fixture-app.mjs since F10.11 part b.
const FIXTURE_SIGN_IN = () => fixtureSignIn();
const stripped = rows => ({...rows, groups: rows.groups.map(({bindContent, sensitive, ...group}) => (void bindContent, void sensitive, group))});

test('the defaults table shows bindContent and sensitive only on a row that declares them, so they move that table\'s data hash', () => {
  const definition = FIXTURE_SIGN_IN(), groups = validatePermissionGroups(fixtureRows()), config = fixtureConfigs().get('fixture');
  const table = defaultsTable({appId: 'fixture', definition, groups, config}), without = defaultsTable({appId: 'fixture', definition, groups: validatePermissionGroups(stripped(fixtureRows())), config});
  const row = id => table.rows.find(item => item.id === id);
  assert.deepEqual(row('fixture.messages.send').bindContent, [
    {member: 'PATCH /events/{event_id}', kind: 'etag', at: 'header:If-Match'}, {member: 'POST /drafts/{draft_id}/send', kind: 'resend', at: 'body:/raw'}, {member: 'PUT /files/{path}', kind: 'sha', at: 'body:/sha'}],
    'member, kind and location, sorted by member');
  assert.deepEqual(row('fixture.keys.read').sensitive, ['GET /keys/{key_id}']);
  for (const item of table.rows.filter(entry => !['fixture.messages.send', 'fixture.keys.read'].includes(entry.id))) assert.ok(!Object.hasOwn(item, 'bindContent') && !Object.hasOwn(item, 'sensitive'), item.id);
  for (const item of without.rows) assert.ok(!Object.hasOwn(item, 'bindContent') && !Object.hasOwn(item, 'sensitive'), `${item.id} without the fields`);
  assert.notEqual(dataHash('fixture', table), dataHash('fixture', without), 'declaring either moves the data hash, so the app is signed again');
  assert.deepEqual({...table, rows: table.rows.map(({bindContent, sensitive, ...item}) => (void bindContent, void sensitive, item))}, without, 'nothing else in the table moves');
  // The review document gives one line per member, after the table, only when some row declares one.
  const entry = data => ({name: 'Fixture', provider: 'fixture', dataHash: dataHash('fixture', data), filesHash: filesHash('fixture', {}), files: {}, table: data});
  const text = reviewText({apps: {fixture: entry(table)}}), plain = reviewText({apps: {fixture: entry(without)}});
  for (const line of ['**Content binding**: a change through one of these must carry exactly what Fabric read first, so it never replaces a newer version (T5).',
    '- `PATCH /events/{event_id}` (Send messages and change shared files): the version tag read first, sent in the If-Match header.',
    '- `POST /drafts/{draft_id}/send` (Send messages and change shared files): the content read first, sent again unchanged at `/raw` in the body.',
    '- `PUT /files/{path}` (Send messages and change shared files): the sha read first, sent at `/sha` in the body.',
    '**Answers that can carry a secret**: an action with any step on one of these is sensitive, so it never defaults to Allow (T8).',
    '- `GET /keys/{key_id}` (Access keys)']) {
    assert.ok(text.split('\n').includes(line), line);
    assert.ok(!plain.split('\n').includes(line), `without the fields: ${line}`);
  }
  assert.ok(text.indexOf('**Content binding**') > text.indexOf('| Permission |'), 'after the table, never inside it');
});

// ---- part d: the expression grammar (lib/action-expressions.mjs) ------------------------------------------------------------------
// The scopes below stand in for what parts f, h and k build per position: the slot, the inputs, the steps that ran before it and what
// each step's data is (its source), the account's reviewed identity, the item a forEach or poll item field reads, and the cursors.
const PAIR_ITEM = {type: 'object', properties: {name: {type: 'string', minLength: 1, maxLength: 100}, value: {type: 'string', maxLength: 1000}}, required: ['name', 'value'], additionalProperties: false};
const INPUTS = {type: 'object', properties: {
  name: {type: 'string', minLength: 1, maxLength: 200},
  names: {type: 'array', maxItems: 10, items: {type: 'string', minLength: 1, maxLength: 100}},
  change: {type: 'string', enum: ['rename', 'label']},
  count: {type: 'integer', minimum: 0, maximum: 10},
  flag: {type: 'boolean'},
  owner: {type: 'object', properties: {address: {type: 'string', minLength: 3, maxLength: 254}}, required: ['address'], additionalProperties: false},
  pairs: {type: 'array', maxItems: 100, items: PAIR_ITEM},
  values: {type: 'object', properties: {}, additionalProperties: false},
  other: {type: 'object', properties: {}, additionalProperties: false},
}, required: ['name'], additionalProperties: false};
const STEPS = new Map([
  ['profile', {source: 'prepare'}], ['labels', {source: 'prepare'}], ['event', {source: 'prepare'}], ['table', {source: 'schema'}],
  ['list', {source: 'perform-read'}], ['send', {source: 'perform-write', skippable: true}], ['rename', {source: 'perform-write', skippable: true}],
  ['open', {source: 'resolving'}], ['check', {source: 'verify'}]]);
const IDENTITY = Object.fromEntries(['google', 'github', 'notion', 'slack'].map(provider => [provider, definitionFor(provider).identity]));
const scoped = (slot, more = {}) => ({where: '$e', slot, transforms: TRANSFORMS, inputSchema: INPUTS, resolvedInputs: ['values', 'other'], steps: STEPS, identity: IDENTITY.google, ...more});
const ok = (node, slot = 'body', more) => checkExpression(node, scoped(slot, more));
const no = (node, pattern, slot = 'body', more) => assert.throws(() => checkExpression(node, scoped(slot, more)), pattern, JSON.stringify(node));
const sources = result => [...result.sources].sort();
const overList = (list, from = 'forEach') => ({item: {from, list: ok(list, 'forEach')}});
const labelIds = names => ({transform: 'collections.labelIds@1', args: {list: {step: 'labels', pointer: ''}, names}});
const propertyValues = (schema = {resolved: 'values'}, values = {input: '/values'}) => ({transform: 'notion.propertyValues@1', args: {schema, values}});
const stringValues = {transform: 'collections.stringValues@1', args: {values: {input: '/pairs'}}};
const each = (list, body, max = 100, as = 'entry') => ({each: list, as, max, do: body});
const LABEL_EXCLUDES = {values: ['SENT', 'DRAFT', 'TRASH', 'SPAM'], fold: 'ascii'};

test('part d: a node is an object with exactly one grammar key and its named fields; anything else is refused', () => {
  for (const node of [{const: 1, extra: 2}, {input: '/name', pointer: '/name'}, {step: 'list', pointer: '/a', header: 'etag'}, {step: 'list'}, {pick: {step: 'list', pointer: ''}},
    {each: {input: '/names'}, as: 'entry', do: {var: 'entry'}}, {transform: 'text.truncate@1'}, {concat: [{const: 'a'}]}, {when: {present: {input: '/name'}}}]) {
    no(node, /takes exactly/);
  }
  for (const node of [{const: 1, input: '/name'}, {nothing: 1}, {}]) no(node, /an expression has exactly one grammar key/);
  for (const node of ['literal', 7, null, [{const: 1}], true]) no(node, /an expression is an object with one grammar key/);
  no({now: {at: 1}}, /\{now\} takes \{\}/);
  assert.throws(() => checkTest({present: {input: '/name'}, extra: 1}, scoped('when')), /\{present\} takes exactly present/);
  assert.throws(() => checkTest({input: '/name'}, scoped('when')), /a test has exactly one test key/);
  assert.equal(ok({const: 1}).kind, 'const');
  assert.equal(ok({step: 'list', pointer: '/a'}, 'output').kind, 'step');
});

test('part d: {item} reads the forEach element, or the poll item in the poll-item scope only, and carries its list\'s provenance (open point Important 4)', () => {
  no({item: ''}, /\{item\} is read only inside a forEach step, or in a poll item field \(itemId, filter, event and dedupe fields\)/, 'path');
  no({item: '/id'}, /\{item\} is read only inside a forEach step, or in a poll item field/, 'poll');
  // The element has the list's sources, never a class of its own: over an input list it is input, over a write's answer a write.
  const name = ok({item: ''}, 'path', overList({input: '/names'}));
  assert.deepEqual([sources(name), name.type], [['input'], INPUTS.properties.names.items]);
  assert.deepEqual(sources(ok({item: '/id'}, 'body', overList({step: 'send', pointer: '/created'}))), ['perform-write']);
  // So an If-Match from an item over an input list is refused: a header value never comes from an input, whatever carries it.
  no({item: ''}, /a header value comes only from constants, a prepare step's answer or a poll cursor \(spec line 741\)/, 'header', overList({input: '/names'}));
  assert.deepEqual(sources(ok({item: '/etag'}, 'header', overList({step: 'labels', pointer: '/labels'}))), ['prepare']);
  assert.throws(() => checkExpression({item: ''}, {...scoped('body'), item: {from: 'elsewhere', list: ok({input: '/names'}, 'forEach')}}), /item.from is forEach or poll/);
  assert.deepEqual(POLL_ITEM_FIELDS, ['itemId', 'filter', 'event.id', 'event.occurredAt', 'event.fields', 'event.summary', 'dedupe.fields']);
  // The tested trigger fixtures read their poll items at poll level (section 8): each item field passes in the poll-item scope, with the
  // provenance of poll.items, and is refused without it.
  for (const appId of ['google-calendar', 'github']) {
    const [trigger] = JSON.parse(readFileSync(new URL(`./fixtures/triggers/${appId}.json`, import.meta.url), 'utf8')).triggers, poll = trigger.poll;
    const base = {transforms: TRANSFORMS, inputSchema: trigger.inputSchema, steps: new Map(poll.source.steps.map(step => [step.id, {source: 'perform-read'}])), trigger: true, slot: 'poll'};
    const item = {from: 'poll', list: checkExpression(poll.items, {...base, where: 'poll.items'})};
    const fields = [['poll.itemId', poll.itemId, false], ['event.id', trigger.event.id, false], ['event.occurredAt', trigger.event.occurredAt, false],
      ...Object.entries(trigger.event.fields).map(([field, node]) => [`event.fields.${field}`, node, true]), ...trigger.event.summary.map((line, index) => [`event.summary[${index}]`, line.expr, false])];
    for (const [where, node, member] of fields) assert.doesNotThrow(() => checkExpression(node, {...base, where, member, item}), `${appId} ${where}`);
    assert.deepEqual(sources(checkExpression(poll.itemId, {...base, item})), ['perform-read'], `${appId}: the item has the provenance of poll.items`);
    assert.throws(() => checkExpression(poll.itemId, {...base, where: 'poll.itemId'}), /\{item\} is read only inside a forEach step, or in a poll item field/, appId);
    assert.throws(() => checkExpression(trigger.event.fields.title, {...base, where: 'event.fields.title', member: true}), /\{item\} is read only inside/, appId);
  }
  const [list] = fixtureActions().actions;
  const pollItems = ok({step: 'list', pointer: ''}, 'poll');
  assert.doesNotThrow(() => ok(list.poll.itemId, 'poll', {item: {from: 'poll', list: pollItems}}), 'the fixture action\'s poll itemId');
});

test('part d: {var} reads only the element its {each} binds, or a trigger\'s resource.as, with the provenance of that list', () => {
  no({var: 'entry'}, /\{var: 'entry'\} is read only inside the \{each\} that binds it, or in a trigger's poll when its resource\.as binds it/);
  no(each({input: '/names'}, {concat: [{var: 'other'}], max: 100}, 10), /\{var: 'other'\} is read only inside the \{each\} that binds it/);
  const names = ok(each({input: '/names'}, {var: 'entry'}, 10));
  assert.deepEqual([names.type, sources(names)], [{type: 'array', maxItems: 10, items: INPUTS.properties.names.items}, ['input']]);
  no(each({input: '/names'}, each({input: '/names'}, {var: 'entry'}, 10), 10), /\{each\} binds entry, which an enclosing \{each\} or the trigger's resource already binds/);
  const channel = ok({var: 'channel'}, 'path', {trigger: true, vars: new Map([['channel', ok({input: '/names'}, 'poll')]])});
  assert.deepEqual([sources(channel), channel.type], [['input'], INPUTS.properties.names.items]);
});

test('part d: {now} is only an argument of a transform that declares usesClock, read once when the perform bytes are built', () => {
  const build = now => ({transform: 'rfc5322.build@1', args: {from: {object: {address: {account: 'email'}}}, subject: {const: 'Hello'}, text: {input: '/name'}, now}});
  assert.deepEqual(sources(ok(build({now: {}}))), ['account', 'clock', 'constant', 'input']);
  no({now: {}}, /\{now\} is only an argument of a transform that declares usesClock \(spec line 734\)/);
  no({object: {at: {now: {}}}}, /\{now\} is only an argument of a transform that declares usesClock/);
  no(build({concat: [{now: {}}], max: 20}), /\{now\} is only an argument of a transform that declares usesClock/, 'body');
  no({transform: 'text.truncate@1', args: {text: {now: {}}, max: {const: 100}}}, /text\.truncate@1 does not declare usesClock, so it never takes \{now\}/);
  assert.doesNotThrow(() => checkCall('time.window@1', {start: {const: '2026-10-20T10:00:00Z'}, now: {now: {}}}, scoped('guard'), ['guard']));
});

test('part d: {account} reads a field the app\'s reviewed identity yields, never in a header', () => {
  no({account: 'id'}, /\{account\} is never a header value/, 'header', {identity: IDENTITY.slack});
  no({account: 'name'}, /\{account\} is one of id, email, workspaceId and userId/);
  for (const [provider, field, yields] of [['slack', 'userId', true], ['slack', 'workspaceId', true], ['slack', 'email', false], ['google', 'email', true], ['google', 'userId', false],
    ['google', 'workspaceId', false], ['github', 'email', false], ['github', 'userId', false], ['notion', 'email', true], ['notion', 'workspaceId', false], ['notion', 'userId', false]]) {
    if (yields) assert.deepEqual(sources(ok({account: field}, 'body', {identity: IDENTITY[provider]})), ['account'], `${provider} ${field}`);
    else no({account: field}, new RegExp(`\\{account: '${field}'\\} needs the app's reviewed identity to yield ${field}, and this app's does not`), 'body', {identity: IDENTITY[provider]});
  }
  for (const provider of ['google', 'github', 'notion', 'slack']) assert.doesNotThrow(() => ok({account: 'id'}, 'path', {identity: IDENTITY[provider]}), provider);
  assert.doesNotThrow(() => ok({account: 'id'}, 'query', {identity: null}), 'id needs no attribute');
  // S5: a direct message to self opens the channel with the bare Slack user id; S4 reads it in an assertion.
  assert.doesNotThrow(() => ok({object: {users: {account: 'userId'}}}, 'body', {identity: IDENTITY.slack}));
  assert.doesNotThrow(() => ok({account: 'userId'}, 'assert', {identity: IDENTITY.slack}));
});

test('part d: {resolved} is only the schema argument beside its resolvedValues, and a resource-dependent input is read only there (R14)', () => {
  const placed = ok({object: {parent: {object: {id: {input: '/name'}}}, properties: propertyValues()}});
  assert.deepEqual(placed.members.get('properties').keyed, {form: 'outputFrom', argument: 'schema', input: 'values'});
  assert.deepEqual(sources(placed), ['input', 'resolved']);
  no({resolved: 'values'}, /\{resolved\} is only the schema argument of a transform that declares resolvedValues \(R14\)/);
  no({object: {schema: {resolved: 'values'}}}, /\{resolved\} is only the schema argument/);
  no({transform: 'text.truncate@1', args: {text: {resolved: 'values'}, max: {const: 100}}}, /\{resolved\} is only the schema argument/);
  no({resolved: 'name'}, /\{resolved\} names a resource-dependent input of this action/);
  for (const [node, slot] of [[{input: '/values'}, 'body'], [{object: {properties: {input: '/values'}}}, 'body'], [{input: '/values'}, 'path'], [{input: '/values'}, 'query']]) {
    no(node, /values is a resource-dependent input: it is read only whole, as a resolvedValues argument beside \{resolved: 'values'\} in the same transform call \(R14\)/, slot);
  }
  no(propertyValues({resolved: 'other'}), /args\.values: takes only \{input: '\/other'\}, the input whose \{resolved\} schema takes \(R14\)/);
  no(propertyValues({step: 'table', pointer: ''}), /args\.schema: takes only \{resolved\} of the resource-dependent input that values takes the values of \(R14\)/);
  no(propertyValues({resolved: 'values'}, {input: '/name'}), /args\.values: takes only \{input: '\/values'\}/);
});

test('part d: object keys are constants, {when} sits only where a value can be left out, and tests nest at most 2 deep', () => {
  no({object: [{key: {input: '/name'}, value: {const: 1}}]}, /\{object\} maps constant keys to expressions; a key is never computed/);
  for (const node of [JSON.parse('{"object": {"__proto__": {"const": 1}}}'), {object: {'': {const: 1}}}, {object: {constructor: {const: 1}}}, {object: {['k'.repeat(257)]: {const: 1}}}]) {
    no(node, /an object key is 1 to 256 characters and never __proto__, prototype or constructor/);
  }
  const maybe = {when: {present: {input: '/name'}}, then: {input: '/name'}};
  for (const [node, slot] of [[{object: {a: maybe}}, 'body'], [{array: [maybe]}, 'body'], [maybe, 'query'], [{transform: 'text.joinList@1', args: {items: {when: {present: {input: '/names'}}, then: {input: '/names'}}}}, 'preview']]) {
    const result = ok(node, slot);
    assert.ok(result.kind === 'when' ? result.optional : true, JSON.stringify(node));
  }
  assert.equal(ok({object: {a: maybe}}).type.required.length, 0, 'a member under {when} is not required');
  for (const [node, slot] of [[maybe, 'path'], [maybe, 'body'], [maybe, 'output'], [{concat: [maybe], max: 10}, 'body'], [{transform: 'text.truncate@1', args: {text: maybe, max: {const: 100}}}, 'body'],
    [{object: {a: {when: {present: {input: '/name'}}, then: maybe}}}, 'body']]) {
    no(node, /\{when\} sits only where a value can be left out: an object member, an array item, a transform argument that is not required, or a query value/, slot);
  }
  const when = node => checkTest(node, scoped('when'));
  assert.doesNotThrow(() => when({anyOf: [{present: {input: '/name'}}, {equals: [{input: '/change'}, {const: 'rename'}]}, {status: {step: 'profile', in: [200, 404]}}]}));
  assert.throws(() => when({anyOf: [{anyOf: [{present: {input: '/name'}}]}]}), /tests nest at most 2 deep/);
  assert.throws(() => when({equals: [{input: '/change'}, {input: '/name'}]}), /\{equals\} compares an expression with a \{const\}/);
  assert.throws(() => when({equals: [{input: '/change'}]}), /\{equals\} compares an expression with a \{const\}/);
  assert.throws(() => when({equals: [{input: '/change'}, {const: 'move'}]}), /\{equals\} can never hold/);
  for (const status of [{step: 'later', in: [200]}, {step: 'profile', in: []}, {step: 'profile', in: [99]}, {step: 'profile', in: [200, 200]}, {step: 'profile'}, {step: 'profile', in: Array.from({length: 17}, (_, index) => 200 + index)}]) {
    assert.throws(() => when({status}), /\{status\} names an earlier step and 1 to 16 HTTP status codes/, JSON.stringify(status));
  }
  assert.throws(() => when({anyOf: []}), /\{anyOf\} holds 1 to 8 tests/);
  assert.deepEqual(sources(when({nonEmpty: {step: 'labels', pointer: '/labels'}})), ['prepare']);
});

test('part d: {either} takes a skippable first branch, and both branches have one type when both are known', () => {
  assert.deepEqual(sources(ok({either: [{step: 'rename', pointer: '/name'}, {step: 'profile', pointer: '/name'}]}, 'output')), ['perform-write', 'prepare']);
  for (const node of [{either: [{step: 'profile', pointer: '/name'}, {step: 'rename', pointer: '/name'}]}, {either: [{input: '/name'}, {step: 'rename', pointer: '/name'}]}]) {
    no(node, /the first branch of \{either\} must read a step that can be skipped: an optional step, a step with when, or a forEach that may run zero times/, 'output');
  }
  const found = {pick: {transform: 'collections.findBy@1', args: {list: {step: 'send', pointer: ''}, items: {const: ''}, field: {const: '/name'}, id: {const: '/id'}, value: {input: '/name'}, fold: {const: 'ascii'}, require: {const: 'any'}}}, pointer: '/matches/0/id'};
  no({either: [found, {input: '/count'}]}, /both branches of \{either\} have the same type/, 'output');
  assert.equal(ok({either: [found, {input: '/name'}]}, 'output').type.type, 'string');
  no({either: [found]}, /\{either\} takes two expressions/, 'output');
});

test('part d: receiver, secret, kept and subscriptionKey belong to trigger registration and are refused in any action', () => {
  for (const kind of ['receiver', 'secret', 'kept', 'subscriptionKey']) {
    const node = {[kind]: kind === 'receiver' ? 'github' : 'hook'};
    no(node, new RegExp(`\\{${kind}\\} belongs to trigger registration; it is refused in an action`));
    no(node, new RegExp(`\\{${kind}\\} is read only in a trigger's register, renew or teardown step`), 'body', {trigger: true});
    assert.deepEqual(sources(ok(node, 'body', {trigger: true, registration: true})), [kind]);
  }
  assert.throws(() => checkExpression({const: 1}, {...scoped('body'), registration: true}), /registration is only in a trigger scope/);
});

test('part d: a step header is one the requester keeps, and link and location stay inside requests (open point Minor 7)', () => {
  assert.deepEqual(STEP_HEADERS, ['etag', 'last-modified', 'link', 'location', 'retry-after']);
  for (const header of ['content-type', 'set-cookie', 'x-poll-interval', 'ETag', 'authorization']) no({step: 'profile', header}, /a step header is one of etag, last-modified, link, location and retry-after/, 'output');
  for (const header of ['etag', 'last-modified', 'retry-after']) for (const slot of ['output', 'preview', 'assert', 'poll']) assert.doesNotThrow(() => ok({step: 'profile', header}, slot), `${header} in ${slot}`);
  for (const header of ['link', 'location']) {
    for (const slot of ['output', 'preview', 'assert', 'poll', 'body', 'query']) no({step: 'list', header}, new RegExp(`the ${header} header is read only inside a request, as a transform argument: a redirect Location can carry a signed token`), slot);
    no({transform: 'text.truncate@1', args: {text: {step: 'list', header}, max: {const: 100}}}, /is read only inside a request, as a transform argument/, 'preview');
    assert.throws(() => checkCall('collections.oneOf@1', {value: {step: 'list', header}, set: {const: ['a']}, fold: {const: 'none'}}, scoped('guard'), ['guard']), /is read only inside a request/);
  }
  const next = ok({pick: {transform: 'ids.linkPage@1', args: {link: {step: 'profile', header: 'link'}, url: {const: 'https://api.fixture.test/items'}, param: {const: 'page'}}}, pointer: '/page'}, 'query');
  assert.deepEqual(sources(next), ['constant', 'prepare']);
  // In a header, step data comes only from a prepare step; an input and the account never.
  assert.deepEqual(sources(ok({step: 'profile', header: 'etag'}, 'header')), ['prepare']);
  for (const node of [{step: 'list', header: 'etag'}, {step: 'send', pointer: '/etag'}, {step: 'check', pointer: '/etag'}]) no(node, /a header value reads only a prepare step's answer/, 'header');
  no({input: '/name'}, /a header value never comes from an input/, 'header');
  for (const node of [{jobKey: 'move'}, {concat: [{const: 'W/'}, {step: 'profile', header: 'etag'}, {jobKey: 'x'}], max: 300}]) no(node, /a header value comes only from constants, a prepare step's answer or a poll cursor/, 'header');
});

test('part d: every pointer that reads provider data refuses a secret-shaped token wherever it appears (R11)', () => {
  const over = overList({step: 'list', pointer: ''});
  for (const [node, slot, more] of [[{step: 'list', pointer: '/0/temp_clone_token'}, 'output'], [{pick: {step: 'list', pointer: '/0'}, pointer: '/temp_clone_token'}, 'preview'],
    [{item: '/access_token'}, 'body', over], [{step: 'profile', pointer: '/refresh_token'}, 'query'], [{pick: {var: 'entry'}, pointer: '/client_secret'}, 'output']]) {
    const wrapped = node.pick?.var ? each({step: 'list', pointer: ''}, node, 10) : node;
    no(wrapped, /reads [a-z_]+, a field that carries a secret, so it is refused wherever it appears \(R11\)/, slot, more);
  }
  assert.throws(() => checkTest({present: {step: 'list', pointer: '/temp_clone_token'}}, scoped('when')), /a field that carries a secret/);
  for (const pointer of ['/nextPageToken', '/response_metadata/next_cursor', '/nextSyncToken', '/0/full_name']) assert.doesNotThrow(() => ok({step: 'list', pointer}, 'output'), pointer);
  no({step: 'later', pointer: '/id'}, /reads step "later", which has not run before this point/);
  for (const pointer of ['id', '/a//b', '/', '/~2', `${'/a'.repeat(33)}`, 7]) no({step: 'list', pointer}, /is not a JSON pointer of at most 32 non-empty tokens/, 'output');
  no({step: 'list', pointer: '/__proto__'}, /a pointer never reads __proto__, prototype or constructor/, 'output');
});

test('part d: a transform call names a registered map or guard entry, and each argument is checked against its schema (type mismatch refused)', () => {
  no({transform: 'text.nothing@1', args: {}}, /names the transform text\.nothing@1, which the registry does not hold/);
  no({transform: 'notion.schema@1', args: {dataSource: {step: 'table', pointer: ''}}}, /notion\.schema@1 is a schema entry; here only map or guard entries run/);
  no({transform: 'text.truncate@1', args: [{const: 'a'}]}, /transform arguments are an object of expressions/);
  no({transform: 'text.truncate@1', args: {text: {input: '/name'}, max: {const: 100}, extra: {const: 1}}}, /text\.truncate@1 has no argument extra/);
  no({transform: 'text.truncate@1', args: {text: {input: '/name'}}}, /text\.truncate@1 needs the argument max/);
  for (const max of [{const: 'big'}, {const: 50}, {const: 100.5}]) no({transform: 'text.truncate@1', args: {text: {input: '/name'}, max}}, /args\.max: the constant does not fit text\.truncate@1's max/);
  for (const value of [{input: '/count'}, {input: '/names'}, {input: '/owner'}]) no({transform: 'text.truncate@1', args: {text: value, max: {const: 100}}}, /args\.text: its type does not fit text\.truncate@1's text/);
  no({transform: 'text.joinList@1', args: {items: {input: '/pairs'}}}, /args\.items: its type does not fit text\.joinList@1's items/);
  no({transform: 'collections.findBy@1', args: {list: {step: 'list', pointer: ''}, items: {const: ''}, field: {const: '/name'}, id: {const: '/id'}, value: {input: '/name'}, fold: {const: 'unicode'}, require: {const: 'one'}}},
    /args\.fold: the constant does not fit collections\.findBy@1's fold/);
  // Known types that fit pass; step data in a closed argument is checked by the registry at run time.
  const truncated = ok({transform: 'text.truncate@1', args: {text: {input: '/name'}, max: {const: 300}}});
  assert.deepEqual([truncated.type, [...truncated.transforms], truncated.refuses], [TRANSFORMS.get('text.truncate@1').output, ['text.truncate@1'], []]);
  assert.doesNotThrow(() => ok({transform: 'text.joinList@1', args: {items: {input: '/names'}}}, 'preview'));
  assert.doesNotThrow(() => ok({transform: 'collections.mergeEmails@1', args: {event: {step: 'event', pointer: ''}, add: {array: []}, remove: {array: []}, owner: {pick: {step: 'profile', pointer: '/x'}, pointer: '/y'}}}));
  no({transform: 'collections.mergeEmails@1', args: {event: {step: 'event', pointer: ''}, add: {input: '/names'}, remove: {array: []}, owner: {account: 'email'}}}, /args\.add: its type does not fit collections\.mergeEmails@1's add/);
  assert.doesNotThrow(() => ok({transform: 'text.joinList@1', args: {mailboxes: {array: [{object: {address: {account: 'email'}}}, {input: '/owner'}]}}}, 'preview'));
  // A guard is a call of a guard entry; a map entry is not one.
  const guard = checkCall('collections.oneOf@1', {value: {step: 'event', pointer: '/eventType'}, set: {const: ['default']}, fold: {const: 'none'}}, scoped('guard'), ['guard']);
  assert.deepEqual([guard.kind, sources(guard), guard.refuses], ['transform', ['constant', 'prepare'], ['not_one_of']]);
  assert.throws(() => checkCall('text.truncate@1', {text: {input: '/name'}, max: {const: 100}}, scoped('guard'), ['guard']), /text\.truncate@1 is a map entry; here only guard entries run/);
});

test('part d: a step-data argument takes only step data of an earlier step (F10.8 open point Minor 14)', () => {
  const merge = event => ({transform: 'collections.mergeEmails@1', args: {event, add: {array: []}, remove: {array: []}, owner: {account: 'email'}}});
  for (const event of [{step: 'event', pointer: ''}, {pick: {step: 'event', pointer: ''}, pointer: '/event'}]) assert.doesNotThrow(() => ok(merge(event)), JSON.stringify(event));
  for (const event of [{input: '/owner'}, {object: {attendees: {array: []}}}, {const: {attendees: []}}, {account: 'email'}, {pick: labelIds({input: '/names'}), pointer: '/labels'}, {either: [{step: 'rename', pointer: ''}, {step: 'event', pointer: ''}]}]) {
    no(merge(event), /args\.event: collections\.mergeEmails@1's event takes step data of an earlier step: a \{step, pointer\}, a pick of one, or an item or var over step data; never an input, a constant, a built object or a transform result \(F10\.8 open point Minor 14\)/);
  }
  // An item or var is step data only when its list is.
  assert.doesNotThrow(() => ok(merge({item: ''}), 'body', overList({step: 'labels', pointer: '/events'})));
  no(merge({item: ''}), /args\.event: collections\.mergeEmails@1's event takes step data/, 'body', overList({input: '/names'}));
  assert.doesNotThrow(() => ok(each({step: 'list', pointer: '/messages'}, {pick: {transform: 'rfc5322.decodeGmailPayload@1', args: {message: {var: 'entry'}}}, pointer: '/summary'}, 25), 'output'));
  no(each({input: '/pairs'}, {pick: merge({var: 'entry'}), pointer: '/added'}, 10), /args\.event: collections\.mergeEmails@1's event takes step data/);
});

test('part d check: an element of a list built in the file is not step data, so no built object reaches a step-data argument through {each} or a forEach (F10.8 open point Minor 14)', () => {
  const merge = event => ({transform: 'collections.mergeEmails@1', args: {event, add: {array: []}, remove: {array: []}, owner: {account: 'email'}}});
  const refusal = /args\.event: collections\.mergeEmails@1's event takes step data of an earlier step/;
  // Every value below comes from a prepare step, but the attendee object around them is written in the file.
  const built = {object: {attendees: {array: [{object: {email: {step: 'profile', pointer: '/emailAddress'}, responseStatus: {step: 'event', pointer: '/status'}}}]}}};
  no(merge(built), refusal);
  for (const list of [{array: [built, {step: 'event', pointer: ''}]}, {array: [{step: 'event', pointer: ''}]},
    {either: [{step: 'rename', pointer: '/events'}, {step: 'event', pointer: '/events'}]}, {either: [{array: [{object: {a: {step: 'rename', pointer: '/x'}}}]}, {step: 'event', pointer: '/events'}]}]) {
    no(each(list, {pick: merge({var: 'entry'}), pointer: '/added'}, 2), refusal, 'body');
    no(merge({item: ''}), refusal, 'body', overList(list));
    no(each(list, each({pick: {var: 'entry'}, pointer: '/events'}, {pick: merge({var: 'inner'}), pointer: '/added'}, 2, 'inner'), 2), refusal, 'body');
  }
  // A list that is itself step data passes down a chain of picks, items and vars.
  for (const list of [{step: 'event', pointer: '/events'}, {pick: {step: 'labels', pointer: ''}, pointer: '/events'}]) {
    assert.doesNotThrow(() => ok(each(list, {pick: merge({var: 'entry'}), pointer: '/added'}, 10)), JSON.stringify(list));
    assert.doesNotThrow(() => ok(merge({item: ''}), 'body', overList(list)), JSON.stringify(list));
    assert.doesNotThrow(() => ok(each(list, each({pick: {var: 'entry'}, pointer: '/events'}, {pick: merge({var: 'inner'}), pointer: '/added'}, 2, 'inner'), 2)), JSON.stringify(list));
    assert.doesNotThrow(() => ok(merge({pick: {item: '/event'}, pointer: '/inner'}), 'body', overList(list)), JSON.stringify(list));
  }
});

test('part d check: an {each} over step data copies no element whole, not even through an {either} (I6, I9)', () => {
  for (const body of [{either: [{var: 'entry'}, {step: 'profile', pointer: '/x'}]}, {either: [{step: 'rename', pointer: '/x'}, {var: 'entry'}]},
    {either: [{step: 'rename', pointer: '/x'}, {either: [{var: 'entry'}, {step: 'profile', pointer: '/x'}]}]}]) {
    no(each({step: 'send', pointer: ''}, body, 10), /an \{each\} over step data copies no element whole/, 'output');
  }
  assert.doesNotThrow(() => ok(each({step: 'send', pointer: ''}, {either: [{pick: {var: 'entry'}, pointer: '/name'}, {step: 'profile', pointer: '/name'}]}, 10), 'output'));
  // Over an input list the element is the caller's own value, so a var stays allowed there.
  assert.doesNotThrow(() => ok(each({input: '/names'}, {either: [{step: 'rename', pointer: '/x'}, {var: 'entry'}]}, 10), 'output'));
});

test('part d: pointer arguments take only a constant written in the file, each token checked with secretKey() (R11)', () => {
  const findBy = (id, list = {step: 'list', pointer: ''}) => ({transform: 'collections.findBy@1', args: {list, items: {const: ''}, field: {const: '/name'}, id, value: {input: '/name'}, fold: {const: 'none'}, require: {const: 'one'}}});
  const found = ok({pick: findBy({const: '/id'}), pointer: '/matches/0/id'}, 'output');
  assert.deepEqual(found.type, TRANSFORMS.get('collections.findBy@1').output.properties.matches.items.properties.id);
  no(findBy({const: '/temp_clone_token'}), /args\.id: the pointer \/temp_clone_token reads temp_clone_token, a field that carries a secret, so it is refused wherever it appears \(R11\)/);
  no(findBy({const: '/owner/access_token'}), /reads access_token, a field that carries a secret/);
  for (const id of [{input: '/name'}, {pick: {transform: 'text.truncate@1', args: {text: {input: '/name'}, max: {const: 100}}}, pointer: '/text'}, {step: 'profile', pointer: '/field'}, {concat: [{const: '/id'}], max: 10}]) {
    no(findBy(id), /args\.id: collections\.findBy@1's id holds a pointer into step data, so it takes only a constant written in the file \(R11\)/, 'body');
  }
  no(findBy({const: 'id'}), /args\.id: "id" is not a JSON pointer of at most 32 non-empty tokens/);
  // The harness checks only that the pointer is well formed: run alone, it would copy the token into a field named id. The static check is what stops it.
  const leaked = runIn(TRANSFORMS, 'collections.findBy@1', {list: reposAnswer(), items: '', field: '/name', id: '/temp_clone_token', value: 'fixture-two', fold: 'none', require: 'one'});
  assert.equal(leaked.matches[0].id, 'FIXTURE-TEMP-CLONE-TWO');
  assert.equal(runIn(TRANSFORMS, 'collections.findBy@1', {list: reposAnswer(), items: '', field: '/name', id: '/node_id', value: 'fixture-two', fold: 'none', require: 'one'}).matches[0].id, 'R_fixture_1002');
  no({transform: 'collections.missing@1', args: {list: {step: 'labels', pointer: ''}, items: {const: '/labels'}, field: {const: '/secret'}, name: {input: '/name'}, fold: {const: 'ascii'}}}, /reads secret, a field that carries a secret/);
});

test('part d: projections (R1): pick is typed from the output schema and keeps an exclusion only for the field it names', () => {
  const ids = ok({pick: labelIds({input: '/names'}), pointer: '/ids'});
  assert.deepEqual(ids.type, TRANSFORMS.get('collections.labelIds@1').output.properties.ids);
  assert.deepEqual(ids.excludes, [{pointer: '', items: true, ...LABEL_EXCLUDES}]);
  assert.deepEqual(ok({pick: labelIds({input: '/names'}), pointer: '/ids/3'}).excludes, [{pointer: '', items: false, ...LABEL_EXCLUDES}], 'one element of the list');
  assert.deepEqual(ok(labelIds({input: '/names'})).excludes, [{pointer: '/ids', items: true, ...LABEL_EXCLUDES}]);
  for (const pointer of ['/labels', '/labels/0/name', '/labels/0/id']) assert.deepEqual(ok({pick: labelIds({input: '/names'}), pointer}).excludes, [], `${pointer} carries no exclusion`);
  assert.deepEqual(ok({pick: {transform: 'collections.diff@1', args: {before: {input: '/names'}, after: {array: []}}}, pointer: '/add'}).excludes, [], 'diff declares none');
  for (const node of [{concat: [{pick: labelIds({input: '/names'}), pointer: '/ids/0'}], max: 100}, {object: {ids: {pick: labelIds({input: '/names'}), pointer: '/ids'}}},
    {array: [{pick: labelIds({input: '/names'}), pointer: '/ids/0'}]}, {transform: 'text.joinList@1', args: {items: {pick: labelIds({input: '/names'}), pointer: '/ids'}}}]) {
    assert.deepEqual(ok(node, 'body').excludes, [], `${Object.keys(node)[0]} drops every exclusion`);
  }
  assert.deepEqual(ok(each({pick: labelIds({input: '/names'}), pointer: '/ids'}, {var: 'entry'})).excludes, [{pointer: '', items: true, ...LABEL_EXCLUDES}], 'an each that keeps each element keeps it');
  assert.deepEqual(ok(each({pick: labelIds({input: '/names'}), pointer: '/labels'}, {pick: {var: 'entry'}, pointer: '/name'})).excludes, []);
  for (const pointer of ['/nothing', '/ids/100', '/labels/0/colour', '/ids/x']) no({pick: labelIds({input: '/names'}), pointer}, /names no declared field of the value it picks from/);
  no({pick: labelIds({input: '/names'}), pointer: ''}, /\{pick\} names one field: its pointer is never empty/);
  for (const inner of [{input: '/owner'}, {const: {a: 1}}, {object: {a: {const: 1}}}, {account: 'id'}, {step: 'profile', header: 'etag'}, {concat: [{const: 'a'}], max: 5}]) {
    no({pick: inner, pointer: '/a'}, /\{pick\} takes one field of a transform result, step data, an item or a var/);
  }
  assert.equal(ok({pick: {step: 'list', pointer: '/0'}, pointer: '/name'}, 'output').type, null, 'step data is unknown');
});

test('part d: {each} is a bounded map: max 1 to 100, never copies step data whole, and is typed from its do', () => {
  const names = ok(each({pick: labelIds({input: '/names'}), pointer: '/labels'}, {pick: {var: 'entry'}, pointer: '/name'}, 100));
  assert.deepEqual(names.type, {type: 'array', maxItems: 100, items: TRANSFORMS.get('collections.labelIds@1').output.properties.labels.items.properties.name});
  for (const max of [101, 0, 1.5, '10']) no(each({input: '/names'}, {var: 'entry'}, max), /\{each\} takes a max of 1 to 100; a longer list refuses, never truncates/);
  for (const as of ['', 'Entry', '1x', 'a-b', 'x'.repeat(33)]) no(each({input: '/names'}, {var: as}, 10, as), /\{each\} binds a name of 1 to 32 letters and digits, starting with a lowercase letter/);
  no(each({input: '/name'}, {var: 'entry'}, 10), /\{each\} walks a list/);
  no(each({step: 'list', pointer: ''}, {var: 'entry'}, 10), /an \{each\} over step data copies no element whole: its do picks fields \(I6, I9\)/, 'output');
  const repos = ok(each({step: 'list', pointer: ''}, {object: {name: {pick: {var: 'entry'}, pointer: '/name'}, full: {pick: {var: 'entry'}, pointer: '/full_name'}}}, 100), 'output');
  assert.deepEqual([repos.type.type, repos.type.maxItems, sources(repos)], ['array', 100, ['perform-read']]);
});

test('part d: results typed at run time (outputFrom, outputMap) are placed whole at one request body position, never picked into', () => {
  const body = ok({object: {parent: {object: {id: {input: '/name'}}}, properties: propertyValues()}});
  assert.equal(body.members.get('properties').keyed.form, 'outputFrom');
  assert.equal(ok(propertyValues()).keyed.form, 'outputFrom', 'the whole body');
  const dispatch = ok({object: {ref: {const: 'main'}, inputs: stringValues}});
  assert.deepEqual(dispatch.members.get('inputs').keyed, {form: 'outputMap', value: TRANSFORMS.get('collections.stringValues@1').outputMap.value});
  assert.doesNotThrow(() => ok({array: [stringValues]}));
  for (const node of [propertyValues(), stringValues]) {
    no({pick: node, pointer: '/title'}, /result has no declared field, so nothing picks into it: it is placed whole at one request body position/);
    for (const slot of ['output', 'preview', 'guard', 'query', 'path', 'assert', 'poll', 'forEach']) no(node, /result is placed whole at one request body position/, slot);
    for (const wrapped of [{transform: 'text.truncate@1', args: {text: node, max: {const: 100}}}, {object: {p: {when: {present: {input: '/name'}}, then: node}}}, {concat: [node], max: 10},
      {either: [{step: 'rename', pointer: ''}, node]}, each({input: '/names'}, node, 10)]) {
      no(wrapped, /result is placed whole at one request body position/);
    }
  }
  // runEntry() checks them at run time, through the fixture stubs.
  const values = TRANSFORMS.get('notion.propertyValues@1');
  assert.deepEqual(runEntry(values, values.example.input), values.example.output);
  for (const output of [{unbound: {number: 1}}, {c1: {number: 'three'}}, {'a%3Bb': {select: {name: 7}}}]) {
    assert.throws(() => runEntry({...values, run: () => output}, values.example.input), error => error instanceof TransformError && error.code === 'output_invalid', JSON.stringify(output));
  }
  assert.throws(() => runEntry(values, {...values.example.input, values: {Status: 'Unknown'}}), error => error.code === 'input_invalid', 'a value outside the derived schema');
  const pairs = TRANSFORMS.get('collections.stringValues@1');
  assert.deepEqual(runEntry(pairs, {values: [{name: 'env', value: 'prod'}, {name: '_x', value: ''}]}), {env: 'prod', _x: ''});
  for (const list of [[{name: 'a', value: '1'}, {name: 'a', value: '2'}], [{name: '1abc', value: '1'}], [{name: 'a b', value: '1'}]]) {
    assert.throws(() => runEntry(pairs, {values: list}), error => error instanceof TransformError, JSON.stringify(list));
  }
});

test('part d: {concat} joins strings and safe integers within its max, and drops every exclusion', () => {
  const joined = ok({concat: [{const: 'n'}, {input: '/count'}, {step: 'list', pointer: '/ts'}, {jobKey: 'id'}], max: 65_536});
  assert.deepEqual([joined.type, sources(joined)], [{type: 'string', maxLength: 65_536}, ['constant', 'input', 'jobKey', 'perform-read']]);
  for (const max of [65_537, 0, 2.5]) no({concat: [{const: 'a'}], max}, /\{concat\} takes a max of 1 to 65,536 characters/);
  no({concat: [], max: 10}, /\{concat\} joins at least one part/);
  for (const part of [{input: '/flag'}, {const: 1.5}, {const: true}, {const: null}, {object: {}}, {input: '/names'}, {const: 2 ** 53}]) {
    no({concat: [{const: 'x'}, part], max: 10}, /\{concat\} joins strings and safe integers written in plain decimal/);
  }
});

test('part d: bounds (I7): depth 16 counting levels inside a constant, constants of depth 8 and 16 KiB, and 2,000 nodes counting each as max times its do', () => {
  const nest = (levels, leaf) => levels === 1 ? leaf : {array: [nest(levels - 1, leaf)]};
  const deep = levels => levels === 0 ? 'x' : [deep(levels - 1)];
  assert.doesNotThrow(() => ok(nest(16, {const: 'x'})));
  no(nest(17, {const: 'x'}), /nests deeper than 16 levels \(I7\)/);
  assert.doesNotThrow(() => ok(nest(8, {const: deep(8)})));
  no(nest(9, {const: deep(8)}), /nests deeper than 16 levels \(I7\)/, 'body');
  no({const: deep(9)}, /a constant nests at most 8 levels \(I7\)/);
  assert.doesNotThrow(() => ok({const: 'x'.repeat(4_096)}));
  no({const: {list: ['x'.repeat(4_097)]}}, /a string in a constant holds at most 4,096 characters \(I7\)/);
  no({const: Array.from({length: 5}, () => 'x'.repeat(4_000))}, /a constant holds at most 16 KiB \(I7\)/);
  for (const value of [Number.NaN, Infinity, JSON.parse('{"__proto__": 1}'), () => 1]) no({const: value}, /a constant is plain JSON/);
  // Nodes: every node inside a constant counts, and an {each} counts max times its do.
  const keys = count => Array.from({length: count}, () => ({jobKey: 'k'}));
  assert.deepEqual([ok({const: [1, 2, 3]}).nodes, ok({array: keys(1_999)}).nodes], [5, 2_000]);
  no({array: keys(2_000)}, /the expressions of one action hold at most 2,000 nodes, an \{each\} counting max times its do \(I7\)/);
  no({array: [...keys(1_996), {const: [1, 2]}]}, /at most 2,000 nodes/, 'body');
  assert.equal(ok({array: [...keys(1_995), {const: [1, 2]}]}).nodes, 2_000);
  const doTwenty = {concat: Array.from({length: 19}, () => ({var: 'entry'})), max: 1_000};
  assert.equal(ok(each({input: '/names'}, {concat: [{var: 'entry'}], max: 100}, 100)).nodes, 202);
  no(each({input: '/names'}, doTwenty, 100), /at most 2,000 nodes/);
  // One budget across the expressions of an action.
  const budget = newBudget();
  assert.equal(ok({array: keys(1_499)}, 'body', {budget}).nodes, 1_500);
  assert.throws(() => checkExpression({array: keys(500)}, scoped('output', {budget})), /at most 2,000 nodes/);
  assert.equal(budget.nodes, 1_500);
  assert.equal(checkTest({present: {array: keys(498)}}, scoped('when', {budget})).nodes, 500);
  assert.equal(budget.nodes, 2_000);
  assert.throws(() => checkExpression({const: 1}, scoped('body', {budget})), /at most 2,000 nodes/);
});

test('part d: the deepest valid expression at the deepest position a file allows still hashes under canonicalHash\'s depth 40', () => {
  // resolvedInputs[].schema.steps[].body is the deepest expression position: the body sits at JSON depth 8.
  const deep = levels => levels === 0 ? 'x' : {k: deep(levels - 1)};
  const chain = (levels, leaf, wrap) => levels === 0 ? leaf : wrap(chain(levels - 1, leaf, wrap));
  // Each of these wrappers adds two JSON levels per grammar level, the most any node adds.
  const twoLevel = [inner => ({array: [inner]}), inner => ({object: {k: inner}}), inner => ({either: [{step: 'rename', pointer: '/a'}, inner]}), inner => ({concat: [{const: 'a'}, inner], max: 10})];
  const at = body => ({actions: [{resolvedInputs: [{schema: {steps: [{body}]}}]}]});
  for (const [index, wrap] of twoLevel.entries()) {
    const leaf = index === 1 || index === 0 ? {const: 'x'} : {input: '/name'};
    const expression = chain(15, leaf, wrap);
    assert.doesNotThrow(() => ok(expression, 'body'), `wrapper ${index}`);
    assert.doesNotThrow(() => compiler.canonicalHash(at(expression)), `wrapper ${index} hashes`);
    no(chain(16, leaf, wrap), /nests deeper than 16 levels/, 'body');
  }
  const constant = chain(7, {const: deep(8)}, twoLevel[1]);
  assert.doesNotThrow(() => ok(constant));
  assert.doesNotThrow(() => compiler.canonicalHash(at(constant)));
  const tested = chain(11, {when: {anyOf: [{status: {step: 'profile', in: [200]}}]}, then: {const: 'x'}}, twoLevel[1]);
  assert.doesNotThrow(() => ok(tested));
  assert.doesNotThrow(() => compiler.canonicalHash(at(tested)));
  no(chain(12, {when: {anyOf: [{status: {step: 'profile', in: [200]}}]}, then: {const: 'x'}}, twoLevel[1]), /nests deeper than 16 levels/);
});

test('part d: the perform-step source rule as F10.9 widened it (R2, open question 41)', () => {
  assert.deepEqual(PERFORM_SOURCES, ['constant', 'input', 'account', 'jobKey', 'prepare', 'schema', 'resolved', 'clock', 'cursor', 'resolving']);
  const pass = (node, slot = 'body', more) => assert.doesNotThrow(() => assertPerformSources(ok(node, slot, more), 'perform[0].body'), JSON.stringify(node));
  pass({object: {a: {const: 1}, b: {input: '/name'}, c: {account: 'id'}, d: {jobKey: 'meet'}, e: {step: 'profile', pointer: '/x'}}});
  pass({object: {properties: propertyValues()}});
  pass({transform: 'rfc5322.build@1', args: {from: {object: {address: {account: 'email'}}}, subject: {const: 'Hi'}, text: {input: '/name'}, now: {now: {}}}});
  pass({cursor: 'since'}, 'query', {cursors: ['since']});
  pass({step: 'open', pointer: '/channel/id'}, 'body');
  pass({item: ''}, 'path', overList({input: '/names'}));
  pass(each({step: 'labels', pointer: '/labels'}, {pick: {var: 'entry'}, pointer: '/id'}, 10));
  pass({step: 'table', pointer: '/properties'});
  for (const [node, words, more] of [[{step: 'list', pointer: '/id'}, 'another perform step\'s answer'], [{step: 'send', pointer: '/id'}, 'a write step\'s answer'],
    [{step: 'check', pointer: '/id'}, 'a verify step\'s answer'], [{item: '/id'}, 'a write step\'s answer', overList({step: 'send', pointer: '/created'})],
    [{pick: {transform: 'text.truncate@1', args: {text: {step: 'check', pointer: '/x'}, max: {const: 100}}}, pointer: '/text'}, 'a verify step\'s answer']]) {
    assert.throws(() => assertPerformSources(ok(node, 'body', more), 'perform[1].body'), new RegExp(`perform\\[1\\]\\.body reads ${words}, which a perform step's bytes never read: they come only from what exists before the owner approves them \\(T5, R2\\)`), JSON.stringify(node));
  }
  // A cursor is read only in its poll step, and only in a query, a header or the body there.
  no({cursor: 'since'}, /\{cursor: 'since'\} is read only in the poll step of a read action whose poll block names that cursor/, 'query');
  for (const slot of ['path', 'output', 'guard', 'preview']) no({cursor: 'since'}, /a cursor sits only in a query, a header or the body of its poll step/, slot, {cursors: ['since']});
  no({concat: [{cursor: 'since'}], max: 10}, /a cursor is dropped when none is bound, so it sits only where a value can be left out/, 'query', {cursors: ['since']});
  assert.deepEqual(sources(ok({cursor: 'etag'}, 'header', {cursors: ['etag']})), ['cursor']);
  assert.deepEqual([...ok({object: {filter: {cursor: 'since'}}}, 'body', {cursors: ['since']}).cursors], ['since']);
});

// ---- part f: the file validator (lib/actions.mjs) -----------------------------------------------------------------------------------
// The fixture app's dependencies: its rows and proxy settings, its map, the fixture registry and its pins, its choice sources and its
// sign-in (FIXTURE_SIGN_IN above: one required scope, an identity that yields only id). The shipped apps' come from the catalog, with
// F10.7's synthetic maps for Gmail and Calendar (test/actions-placement.test.mjs says why they are not Google's paths).
const FIXTURE_DEPS = (() => {
  const groups = fixtureGroups();
  return {groups, configs: fixtureConfigs(groups), maps: new Map([['fixture', fixtureMap()]]), transforms: TRANSFORMS, pins: PINS,
    choices: new Map([['fixture', fixtureChoices().sources]]), identities: new Map([['fixture', FIXTURE_SIGN_IN()]])};
})();
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const SYNTHETIC = json('./fixtures/access/f10-7-bindings.before.json').maps, METHOD_SCOPES = json('./fixtures/access/google-method-scopes.json').apps;
// F10.7's synthetic Gmail map sends every id that does not end .get or .list as a POST; the profile read is a GET here, as it is at Google.
const GMAIL_MAP = {...SYNTHETIC.gmail, operations: SYNTHETIC.gmail.operations.map(operation => operation.id === 'gmail.users.getProfile' ? {...operation, method: 'GET'} : operation)};
const CALENDAR_MAP = {...SYNTHETIC['google-calendar'], operations: SYNTHETIC['google-calendar'].operations.map(operation => ({...operation, scopeSets: (METHOD_SCOPES['google-calendar'].methods[operation.id] ?? []).map(scope => [scope])}))};
const PROVIDERS = {gmail: 'google', 'google-calendar': 'google', github: 'github', notion: 'notion', slack: 'slack'};
const APP_DEPS = {groups: PERMISSION_GROUPS, configs: PROXY_CONFIGS, maps: new Map([['gmail', GMAIL_MAP], ['google-calendar', CALENDAR_MAP]]), transforms: TRANSFORMS, pins: PINS,
  choices: new Map(), identities: new Map(Object.entries(PROVIDERS).map(([appId, provider]) => [appId, definitionFor(provider)]))};
// Part g: each stored id must equal the computed one, so these helpers write the computed ids first (withIds(), as an author does); the
// id tests of part g call validateActionFile() on the file as written. Part l: validate() keeps a copy of every file the validator
// accepts, and the schema test at the end of this file checks each against schemas/action.schema.json, so the two cannot drift apart.
const ACCEPTED = [];
const validate = (file, deps = FIXTURE_DEPS) => {
  const written = withIds(file, deps), result = validateActionFile(written, deps);
  ACCEPTED.push(structuredClone(written));
  return result;
};
const ZEROS = '0'.repeat(24);
/** The fixture file holding only the action `key`, changed by `change` (given a fresh copy), without the superseded list, which names list-items. */
function fileWith(key, change = action => action) {
  const {superseded, ...file} = fixtureActions();
  void superseded;
  return {...file, actions: [change(structuredClone(file.actions.find(entry => entry.key === key)))]};
}
const entryOf = (file, deps) => validate(file, deps).actions[0];
const refusedFile = (file, pattern, deps = FIXTURE_DEPS, message) => assert.throws(() => validate(file, deps), pattern, message);
/** fileWith() plus an edit that returns nothing: `edit` changes the copy in place. */
const edited = (key, edit) => fileWith(key, action => { edit(action); return action; });
const fileOf = (appId, actions, more = {}) => ({schemaVersion: 1, appId, specVersion: 'fabric/0.2', reviewStatus: 'candidate', pinnedParameters: {}, ...more, actions});
const closed = (properties, required = Object.keys(properties)) => ({type: 'object', properties, required, additionalProperties: false});
const words = (max = 200) => ({type: 'string', minLength: 1, maxLength: max});
const OK = {status: [200], require: []};
// F10.21 listed churn: a Slack step requires /ok true (apiSuccessRequire), so the Slack actions below carry it.
const SLACK_OK = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]};
const WRITE_HINTS = {readOnly: false, destructive: false, idempotent: false, openWorld: true}, READ_HINTS = {readOnly: true, destructive: false, idempotent: true, openWorld: true};
/** An action of a shipped app: `fields` fills or replaces the rest. */
const actionOf = (appId, key, fields) => ({id: `${appId}.action.${key}.v1.${ZEROS}`, key, version: 1, name: key, description: `The ${key} test action.`, guards: [], prepare: [],
  preview: [], definitive: [400], ...fields});

test('part f: the fixture action file validates whole: each action placed, with its effect, row, paths, lookups and the transforms it names', () => {
  const result = validate(fixtureActions());
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.actions) && result.actions.every(Object.isFrozen));
  assert.equal(result.appId, 'fixture');
  assert.deepEqual(result.actions.map(entry => [entry.key, entry.version, entry.effect, entry.row, entry.unplaced, entry.sensitive, entry.twoPhase]), [
    ['list-items', 1, 'read', 'fixture.items.read', false, false, false], ['update-item', 1, 'write', 'fixture.items.edit', false, false, false],
    ['remove-labels', 1, 'delete', 'fixture.items.delete', false, false, false], ['put-file', 1, 'write', 'fixture.messages.send', false, false, false],
    ['reschedule-event', 1, 'write', 'fixture.messages.send', false, false, false], ['send-draft', 1, 'write', 'fixture.messages.send', false, false, false],
    ['add-row', 1, 'write', 'fixture.items.edit', false, false, false]]);
  const [list, update] = result.actions;
  assert.deepEqual(list.placements.map(placement => [placement.stepId, placement.phase, placement.groupId]), [['choice:labelId', 'lookup', 'fixture.items.read'], ['profile', 'prepare', 'fixture.items.read'], ['list', 'perform', 'fixture.items.read']]);
  assert.deepEqual(list.paths, [{input: null, value: null, perform: ['list'], verify: []}]);
  assert.deepEqual(update.paths, [{input: 'change', value: 'rename', perform: ['rename'], verify: ['check']}, {input: 'change', value: 'label', perform: ['label'], verify: ['check']}]);
  assert.deepEqual(update.placements.map(placement => [placement.stepId, placement.phase, placement.groupId]), [['item', 'prepare', 'fixture.items.read'], ['labels', 'prepare', 'fixture.items.read'],
    ['rename', 'perform', 'fixture.items.edit'], ['label', 'perform', 'fixture.items.edit'], ['check', 'verify', 'fixture.items.read']]);
  // R12: a choice with a lookup is resolved at validation, placed as a read and counted as a step; F10.9 part g hashes it into the id.
  assert.deepEqual(list.lookups, {labelId: {source: 'label', method: 'GET', template: 'GET /labels/{label_id}', operation: null, row: 'fixture.items.read', args: {label_id: {value: true}}, items: '', value: '/id', label: ['/name']}});
  assert.deepEqual(update.lookups, {});
  assert.deepEqual(update.transforms, ['collections.labelIds@1', 'collections.oneOf@1', 'text.joinList@1']);
  assert.deepEqual(result.actions.find(entry => entry.key === 'reschedule-event').transforms, ['time.window@1']);
  assert.deepEqual(result.actions.find(entry => entry.key === 'add-row').transforms, ['notion.propertyValues@1', 'notion.schema@1']);
  // The action itself comes back as written, frozen, with nothing computed inside it.
  assert.deepEqual(update.action, fixtureActions().actions[1]);
  assert.ok(Object.isFrozen(update.action.perform[0].body));
});

test('part f: the spec\'s refusals (spec lines 757-786): paths, parameters, headers, inputs, effects, steps and references', () => {
  refusedFile(edited('update-item', action => { action.perform[0].path = 'https://api.fixture.test/items/{item_id}'; }), /a step path is relative to the app's reviewed API base, never a URL/);
  refusedFile(edited('list-items', action => { action.prepare[0].params = {account: {input: '/labelId'}}; }), /prepare\[0\] \(profile\)\.params\.account: account is a pinned parameter, filled only by pinnedParameters, never by a step \(spec line 740\)/);
  refusedFile(edited('list-items', action => { action.perform[0].query.quotaUser = {const: 'q'}; }), /perform\[0\] \(list\)\.query\.quotaUser: quotaUser is a reserved query name: an action step never sends it \(spec line 740\)/);
  refusedFile(edited('update-item', action => { action.perform[0].headers = {'If-Match': {input: '/name'}}; }), /a header value never comes from an input/);
  refusedFile(edited('update-item', action => { action.inputSchema.properties.apiKey = words(); }), /the input \$input\.apiKey is named like a credential: an action input never carries one \(I3\)/);
  refusedFile(edited('update-item', action => { action.inputSchema.properties.extra = words(); }), /the input \/extra is never used: every input reaches a request, a guard, a step's when, forEach\.over or requiresScope\.when, or the output through a transform over step data \(spec line 742\)/);
  // Declared read on a POST: a POST in a read row that is not a reviewed read is a write.
  refusedFile(edited('list-items', action => {
    action.perform[0] = {id: 'list', method: 'POST', path: '/items/export', body: {object: {kind: {input: '/kind'}, label: {input: '/labelId'}}}, expect: OK};
    delete action.poll;
  }), /declares effect read, but its steps compute write/);
  refusedFile(edited('update-item', action => { action.prepare[0] = {id: 'item', method: 'POST', path: '/items/export', body: {object: {id: {input: '/itemId'}}}, expect: OK}; }),
    /prepare\[0\] \(item\): a prepare step is a read \(spec line 711\), and POST \/items\/export is a write/);
  refusedFile(edited('update-item', action => { action.perform[1].body.object.labels.pick.transform = 'collections.nothing@1'; }), /names the transform collections\.nothing@1, which the registry does not hold/);
  refusedFile(edited('update-item', action => { action.preview[2].expr.pick.args.items = {input: '/name'}; }), /its type does not fit text\.joinList@1's items/);
  refusedFile(edited('update-item', action => { delete action.verify; }), /update-item v1: a write needs a verify block with an identity \(spec line 748\)/);
  refusedFile(edited('update-item', action => { action.verify.identity = []; }), /verify\.identity names 1 to 4 identities: a write is read back by what it is \(spec line 748\)/);
  refusedFile(edited('update-item', action => { action.perform[0].body.object.name = {step: 'label', pointer: '/name'}; }), /reads step "label", which has not run before this point/);
  refusedFile(edited('update-item', action => { action.prepare[0].params.item_id = {step: 'labels', pointer: '/id'}; action.prepare[1].params = {}; }), /reads step "labels", which has not run before this point/, FIXTURE_DEPS, 'a cycle starts with a forward reference');
  refusedFile(edited('remove-labels', action => { action.perform[0].forEach = {over: {input: '/names'}}; }), /forEach is \{over, max\}, with a max of 1 to 25 \(I7\)/);
  refusedFile(edited('update-item', action => {
    for (const id of ['a', 'b', 'c', 'd']) action.prepare.push({id, method: 'GET', path: '/labels/{label_id}', params: {label_id: {input: '/itemId'}}, expect: OK});
  }), /update-item v1: declares 9 steps; an action holds at most 8, counting schema steps and choice lookups \(I7\)/);
  refusedFile(edited('update-item', action => {
    action.perform = ['a', 'b', 'c', 'd'].map(id => ({id, method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, body: {object: {name: {input: '/name'}}}, expect: OK}));
  }), /on the path where change is rename, 4 perform steps can run; at most 3 on any one path \(R4\)/);
  refusedFile(edited('update-item', action => {
    action.perform = ['a', 'b', 'c', 'd'].map(id => ({id, method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, body: {object: {name: {input: '/name'}}}, expect: OK}));
    action.verify.assert = [];
  }), /on its one path, 4 perform steps can run; at most 3 on any one path \(R4\)/);
});

test('part f: inputs are closed, carry no credential-shaped name at any depth, and are each used', () => {
  for (const [name, schema] of [['key', words()], ['client_secret', words()], ['grant_type', words()], ['nested', closed({refresh_token: words()})], ['list', {type: 'array', maxItems: 2, items: closed({password: words()})}]]) {
    refusedFile(edited('update-item', action => { action.inputSchema.properties[name] = schema; }), /is named like a credential: an action input never carries one \(I3\)/, FIXTURE_DEPS, name);
  }
  refusedFile(edited('update-item', action => { action.inputSchema = {...action.inputSchema, additionalProperties: true}; }), /inputSchema: .*objects require properties and additionalProperties:false/);
  refusedFile(edited('update-item', action => { action.inputSchema = {type: 'string'}; }), /inputSchema is a closed object schema/);
  // Used only in the preview: unused. A nested property nothing reads: unused, though its parent is read elsewhere.
  refusedFile(edited('update-item', action => { action.inputSchema.properties.note = words(); action.preview.push({label: 'Note', expr: {input: '/note'}}); }), /the input \/note is never used/);
  refusedFile(edited('update-item', action => {
    action.inputSchema.properties.owner = closed({address: words(254), name: words(100)});
    action.perform[0].body.object.owner = {input: '/owner/address'};
  }), /the input \/owner\/name is never used/);
  // Reading a parent uses the whole subtree; reading a child uses its parent.
  const parent = edited('update-item', action => { action.inputSchema.properties.owner = closed({address: words(254), name: words(100)}); action.perform[0].body.object.owner = {input: '/owner'}; });
  assert.equal(entryOf(parent).key, 'update-item');
  const child = edited('update-item', action => { action.inputSchema.properties.owner = closed({address: words(254)}); action.perform[0].body.object.owner = {input: '/owner/address'}; });
  assert.equal(entryOf(child).key, 'update-item');
  // Used only in a step's when, or only in requiresScope.when: used (update-item's change; put-file's kind).
  assert.equal(entryOf(fileWith('put-file')).key, 'put-file');
  // Open point Important 6: an input that reaches the output only through a transform over step data is used (Notion Find person).
  const find = value => edited('list-items', action => {
    action.inputSchema.properties.name = words();
    action.inputSchema.required.push('name');
    action.outputSchema.properties.match = {type: 'string', maxLength: 1000};
    action.outputSchema.required.push('match');
    action.output.match = value;
  });
  const findBy = {transform: 'collections.findBy@1', args: {list: {step: 'list', pointer: ''}, items: {const: ''}, field: {const: '/name'}, id: {const: '/id'}, value: {input: '/name'}, fold: {const: 'ascii'}, require: {const: 'any'}}};
  assert.equal(entryOf(find({pick: findBy, pointer: '/matches/0/id'})).key, 'list-items');
  refusedFile(find({input: '/name'}), /the input \/name is never used/, FIXTURE_DEPS, 'echoed into the output, it is not used');
  refusedFile(find({pick: {transform: 'text.truncate@1', args: {text: {input: '/name'}, max: {const: 100}}}, pointer: '/text'}), /the input \/name is never used/, FIXTURE_DEPS, 'a transform over the input alone does not use it');
});

test('part f: outputs and secrets (R11): no secret-named output field, no secret pointer anywhere, and output keys equal the schema\'s', () => {
  refusedFile(edited('list-items', action => { action.outputSchema.properties.temp_clone_token = words(); action.outputSchema.required.push('temp_clone_token'); action.output.temp_clone_token = {step: 'profile', pointer: '/name'}; }),
    /outputSchema declares \$output\.temp_clone_token, a field that carries a secret \(R11\)/);
  refusedFile(edited('list-items', action => { action.outputSchema.properties.items.items.properties.access_token = words(); }), /outputSchema declares \$output\.items\[\]\.access_token, a field that carries a secret \(R11\)/);
  // A benign name fed from a secret pointer: through the step, a pick, an item or a preview.
  const secret = /reads temp_clone_token, a field that carries a secret, so it is refused wherever it appears \(R11\)/;
  refusedFile(edited('list-items', action => { action.output.account = {step: 'list', pointer: '/0/temp_clone_token'}; }), secret);
  refusedFile(edited('list-items', action => { action.output.account = {pick: {step: 'list', pointer: '/0'}, pointer: '/temp_clone_token'}; }), secret);
  refusedFile(edited('list-items', action => { action.preview.push({label: 'Clone', expr: {step: 'profile', pointer: '/temp_clone_token'}}); }), secret);
  refusedFile(edited('remove-labels', action => { action.perform[0].params.name = {item: '/temp_clone_token'}; }), secret);
  refusedFile(edited('update-item', action => { action.verify.assert[0].equals.pointer = '/access_token'; }), /the pointer \/access_token reads access_token, a field that carries a secret/);
  refusedFile(edited('remove-labels', action => { action.verify.identity[0].listLacks.where[0].field = '/refresh_token'; }), /reads refresh_token, a field that carries a secret/);
  refusedFile(edited('list-items', action => { action.perform[0].page.next = {pointer: '/refresh_token'}; }), /reads refresh_token, a field that carries a secret/);
  // Position markers pass: the fixture pages by /nextPageToken.
  assert.equal(entryOf(fileWith('list-items')).key, 'list-items');
  refusedFile(edited('list-items', action => { delete action.output.account; }), /output names exactly the properties of outputSchema: account and items/);
  refusedFile(edited('list-items', action => { action.output.extra = {const: 'x'}; }), /output names exactly the properties of outputSchema/);
});

test('part f: step data in outputs and previews ends in a scalar: refused statically where the schema says so, and at run time by checkOutput() and checkPreview()', () => {
  const answer = reposAnswer();
  // At an object or list position of outputSchema, a raw step-data value is refused before anything runs.
  const whole = /copies step data whole: a raw step-data value sits only at a string, integer, number or boolean of outputSchema, and this one sits at an? (object|array) \(I6, I9\)/;
  refusedFile(edited('list-items', action => { action.output.items = {step: 'list', pointer: ''}; }), whole);
  refusedFile(edited('list-items', action => { action.output.items.do = {array: [{var: 'entry'}]}; action.outputSchema.properties.items.items = {type: 'array', maxItems: 1, items: closed({id: words(64)})}; }), whole);
  refusedFile(edited('list-items', action => {
    action.outputSchema.properties.items.items.properties.repo = closed({id: words(64)});
    action.outputSchema.properties.items.items.required.push('repo');
    action.output.items.do.object.repo = {var: 'entry'};
  }), whole, FIXTURE_DEPS, 'a var inside an object, at an object position');
  refusedFile(edited('list-items', action => { action.output.items.do = {var: 'entry'}; }), /an \{each\} over step data copies no element whole/);
  refusedFile(edited('list-items', action => { action.output.items.do.object.extra = {const: 'x'}; }), /output\.items\.do\.extra is not a field of outputSchema/);
  // At a scalar position the static check passes, and checkOutput() holds the value to the closed schema at run time.
  const atString = entryOf(edited('list-items', action => { action.output.account = {step: 'list', pointer: '/0'}; action.output.items.do.object.name = {var: 'entry'}; }));
  const items = [{id: 'r1', name: 'one', updated: '2026-10-20T00:00:00Z'}];
  assert.deepEqual(checkOutput(atString, {account: 'me', items}), {account: 'me', items});
  assert.throws(() => checkOutput(atString, {account: answer[0], items}), /the output does not fit its outputSchema \(\$output\.account: expected string\)/);
  assert.throws(() => checkOutput(atString.action, {account: 'me', items: [{...items[0], name: answer[0]}]}), /\$output\.items\[0\]\.name: expected string/, 'checkOutput() takes the action itself too');
  assert.throws(() => checkOutput(atString, {account: 'me', items, extra: 1}), /\$output\.extra: undeclared property/);
  assert.doesNotThrow(() => checkOutput(atString, {account: 'x'.repeat(200), items: Array.from({length: 100}, () => ({id: 'x'.repeat(64), name: 'x'.repeat(200), updated: 'x'.repeat(64)}))}), 'within bounds passes');
  assert.throws(() => checkOutput(atString, {account: 'x'.repeat(1_100_000), items}), /list-items: the output is [0-9,]+ bytes; at most 1 MiB \(I7\)/);
  // Previews: /0 passes statically (step data is typed only at run time) and checkPreview() refuses it on the fixture answer.
  const preview = entryOf(edited('list-items', action => { action.preview.push({label: 'First', expr: {step: 'profile', pointer: '/0'}}); }));
  assert.deepEqual(checkPreview(preview, ['all', 'Label_1', 'one']), ['all', 'Label_1', 'one']);
  assert.deepEqual(checkPreview(preview, ['all', undefined, 7]), ['all', undefined, 7], 'an absent optional value shows nothing');
  for (const value of [answer[0], answer, true, null]) assert.throws(() => checkPreview(preview, ['all', 'L', value]), /preview\[2\] \(First\) is (an object|a list|a boolean|null): a preview shows a string or a number/, JSON.stringify(value));
  assert.throws(() => checkPreview(preview, ['all']), /checkPreview\(\) takes one value per preview line: 3, not 1/);
  // Statically, a value whose type is known to be a list or an object is refused; a list reaches a card through text.joinList@1.
  refusedFile(edited('update-item', action => { action.preview[2].expr = {input: '/labels'}; }), /preview\[2\] \(Labels\): a preview shows a string or a number: a list reaches it as one string through text\.joinList@1/);
  // A preview shows what exists when the owner approves the perform bytes: never a perform or verify step's answer.
  for (const expr of [{step: 'rename', pointer: '/name'}, {step: 'check', pointer: '/name'}]) {
    refusedFile(edited('update-item', action => { action.preview.push({label: 'After', expr}); }), /preview\[3\] \(After\): a preview shows only what exists before the owner approves the perform bytes \(T5\)/, FIXTURE_DEPS, expr.step);
  }
  // Headers: link and location never reach an output, a preview or a guard; etag does.
  refusedFile(edited('reschedule-event', action => { action.output.etag = {step: 'move', header: 'location'}; }), /the location header is read only inside a request/);
  refusedFile(edited('reschedule-event', action => { action.preview.push({label: 'Where', expr: {step: 'event', header: 'location'}}); }), /the location header is read only inside a request/);
  refusedFile(edited('update-item', action => { action.guards[0].args.value = {step: 'item', header: 'link'}; }), /the link header is read only inside a request/);
  assert.equal(entryOf(fileWith('reschedule-event')).key, 'reschedule-event', 'etag reaches the output');
  // An each over step data picking fields is accepted (the fixture's list-items picks /id, /name and /updated).
  const repos = entryOf(edited('list-items', action => { action.output.items.do.object.name = {pick: {var: 'entry'}, pointer: '/full_name'}; }));
  assert.equal(repos.key, 'list-items');
});

test('part f: requests carry step data only as scalars (open point Important 2): never a raw body root, and checkRequest() holds every raw position at run time', () => {
  const whole = edited('update-item', action => { action.perform[0].body.object.description = {step: 'item', pointer: '/0'}; });
  const entry = entryOf(whole), answer = reposAnswer();
  assert.deepEqual(entry.rawAt.rename, ['/body/description']);
  assert.deepEqual(entry.rawAt.label, []);
  assert.deepEqual(entry.rawAt.check, []);
  assert.ok(Object.isFrozen(entry.rawAt) && Object.isFrozen(entry.rawAt.rename));
  const request = description => ({params: {item_id: 'i1'}, body: {name: 'n', description}});
  assert.deepEqual(checkRequest(entry, 'rename', request('a string')), request('a string'));
  for (const value of [7, true, null]) assert.doesNotThrow(() => checkRequest(entry, 'rename', request(value)), JSON.stringify(value));
  assert.throws(() => checkRequest(entry, 'rename', request(answer[0])), /rename copies a whole provider value at \/body\/description: only a string, a number, a boolean or null sits there \(I6, T4\)/);
  assert.throws(() => checkRequest(entry, 'rename', request(answer)), /copies a whole provider value at \/body\/description/);
  assert.throws(() => checkRequest(entry, 'nothing', request('x')), /update-item has no step nothing/);
  // Positions under an {each} hold for every element; path parameters and query values too.
  const each = entryOf(edited('update-item', action => {
    action.perform[0].body.object.ids = {each: {step: 'item', pointer: '/children'}, as: 'child', max: 10, do: {pick: {var: 'child'}, pointer: '/id'}};
    action.verify.requests[0].params.item_id = {step: 'rename', pointer: '/id'};
  }));
  assert.deepEqual([each.rawAt.rename, each.rawAt.check], [['/body/ids/*'], ['/params/item_id']]);
  assert.doesNotThrow(() => checkRequest(each, 'rename', {params: {item_id: 'i'}, body: {name: 'n', ids: ['a', 'b']}}));
  assert.throws(() => checkRequest(each, 'rename', {params: {item_id: 'i'}, body: {name: 'n', ids: ['a', {id: 'b'}]}}), /copies a whole provider value at \/body\/ids\/1/);
  assert.throws(() => checkRequest(each, 'check', {params: {item_id: {id: 'x'}}}), /copies a whole provider value at \/params\/item_id/);
  // A whole step value as the body root is refused statically: a body is built in the file or by a transform.
  refusedFile(edited('update-item', action => { action.perform[0].body = {step: 'item', pointer: ''}; }), /perform\[0\] \(rename\)\.body: a body is built in the file or by a transform, never a raw step-data value \(I6, T4\)/);
  // A transform's step-data argument is not a request position: it never reaches the wire as it is.
  const merged = entryOf(edited('reschedule-event', action => {
    action.inputSchema.properties.owner = {type: 'string', minLength: 3, maxLength: 254};
    action.inputSchema.required.push('owner');
    action.perform[0].body.object.attendees = {pick: {transform: 'collections.mergeEmails@1', args: {event: {step: 'event', pointer: ''}, add: {array: []}, remove: {array: []}, owner: {input: '/owner'}}}, pointer: '/attendees'};
  }));
  assert.deepEqual(merged.rawAt.move, []);
});

test('part f: sensitivity (R13, T8, open point Important 3): any step on a member marked sensitive makes the action sensitive, beside it, whatever reaches the output', () => {
  const keyRead = {id: 'key', method: 'GET', path: '/keys/{key_id}', params: {key_id: {input: '/itemId'}}, maxResponseBytes: 65_536, expect: OK};
  // A prepare step on fixture.keys.read's GET /keys/{key_id}, whose data reaches nothing.
  const small = action => { for (const step of action.prepare) step.maxResponseBytes = 65_536; };
  const prepared = edited('update-item', action => { small(action); action.prepare.push(keyRead); });
  const entry = entryOf(prepared);
  assert.equal(entry.sensitive, true);
  assert.ok(!Object.hasOwn(entry.action, 'sensitive'), 'beside the action, never inside it');
  // Its data in a perform body, in the output, or a verify request on the member: each sensitive.
  assert.equal(entryOf(edited('update-item', action => { small(action); action.prepare.push(keyRead); action.perform[0].body.object.note = {step: 'key', pointer: '/name'}; })).sensitive, true);
  assert.equal(entryOf(edited('update-item', action => { action.verify.requests.push({...keyRead, id: 'keyCheck'}); })).sensitive, true);
  assert.equal(entryOf(edited('list-items', action => { action.prepare[0].maxResponseBytes = 65_536; action.prepare.push(keyRead); action.inputSchema.properties.itemId = words(64); action.inputSchema.required.push('itemId'); action.output.account = {step: 'key', pointer: '/name'}; })).sensitive, true);
  // A lookup or a schema step on it counts too.
  const lookup = {...FIXTURE_DEPS, choices: new Map([['fixture', fixtureChoices().sources.map(source => source.id === 'label' ? {...source, read: {request: 'GET /keys/{key_id}'}, row: 'fixture.keys.read', args: {key_id: {value: true}}} : source)]])};
  assert.equal(entryOf(fileWith('list-items'), lookup).sensitive, true);
  assert.equal(entryOf(edited('add-row', action => { action.resolvedInputs[0].schema.steps[0] = {...keyRead, id: 'table', params: {key_id: {input: '/tableId'}}}; })).sensitive, true);
  // No step on it: not sensitive. The mark is row data, so it never changes the action returned.
  const plain = entryOf(fileWith('update-item'));
  assert.equal(plain.sensitive, false);
  const unmarked = withGroup('fixture.keys.read', group => { delete group.sensitive; return group; }), groups = new Map([...FIXTURE_DEPS.groups, ['fixture', validatePermissionGroups(unmarked)]]);
  const without = entryOf(prepared, {...FIXTURE_DEPS, groups});
  assert.equal(without.sensitive, false);
  assert.deepEqual(without.action, entry.action);
});

test('part f: data flow (R2): a perform step\'s bytes read only what exists before the owner approves them', () => {
  // A perform step reading an earlier perform step: in its body, a path parameter, forEach.over or when; the refusal names every slot.
  const second = change => edited('update-item', action => { delete action.perform[1].when; change(action.perform[1]); });
  refusedFile(second(step => { step.body.object.name = {step: 'rename', pointer: '/name'}; }), /perform\[1\] \(label\): body reads a write step's answer, which a perform step's bytes never read: they come only from what exists before the owner approves them \(T5, R2\)/);
  refusedFile(second(step => { step.params.item_id = {step: 'rename', pointer: '/id'}; }), /perform\[1\] \(label\): params\.item_id reads a write step's answer/);
  refusedFile(second(step => { step.when = {nonEmpty: {step: 'rename', pointer: '/name'}}; }), /perform\[1\] \(label\): when reads a write step's answer/);
  refusedFile(second(step => { step.forEach = {over: {step: 'rename', pointer: '/labels'}, max: 5}; step.body.object.name = {item: '/name'}; }),
    /perform\[1\] \(label\): each of forEach\.over and body reads a write step's answer/);
  refusedFile(second(step => { step.when = {status: {step: 'rename', in: [200]}}; }), /perform\[1\] \(label\): when reads a write step's answer/);
  // page is only on a read.
  refusedFile(edited('update-item', action => { action.perform[0].page = {next: {pointer: '/next'}, into: {query: 'cursor'}, items: '/items', max: 2}; }), /perform\[0\] \(rename\): page is only on a read step, and PATCH \/items\/\{item_id\} is a write/);
  // A cursor only in a read action's poll step.
  refusedFile(edited('list-items', action => { action.poll.step = 'profile'; }), /\{cursor: 'since'\} is read only in the poll step of a read action whose poll block names that cursor/);
  refusedFile(edited('list-items', action => { delete action.poll; }), /\{cursor: 'since'\} is read only in the poll step/);
  refusedFile(edited('update-item', action => { action.perform[0].query = {since: {cursor: 'since'}}; action.poll = {step: 'rename', cursors: [{name: 'since'}]}; }), /\{cursor: 'since'\} is read only in the poll step/, FIXTURE_DEPS, 'never in a write action');
  // An If-Match from an item over an input list: a header value never comes from an input, whatever carries it.
  refusedFile(edited('reschedule-event', action => {
    action.inputSchema.properties.tags = {type: 'array', maxItems: 3, items: words(64)};
    action.inputSchema.required.push('tags');
    action.perform[0].forEach = {over: {input: '/tags'}, max: 3};
    action.perform[0].headers['If-Match'] = {item: ''};
  }), /a header value comes only from constants, a prepare step's answer or a poll cursor/);
  // A transform's step-data argument from an input is refused; from the prepare read it passes.
  refusedFile(edited('reschedule-event', action => {
    action.inputSchema.properties.owner = {type: 'string', minLength: 3, maxLength: 254};
    action.inputSchema.required.push('owner');
    action.perform[0].body.object.attendees = {pick: {transform: 'collections.mergeEmails@1', args: {event: {input: '/owner'}, add: {array: []}, remove: {array: []}, owner: {input: '/owner'}}}, pointer: '/attendees'};
  }), /collections\.mergeEmails@1's event takes step data of an earlier step/);
});

// ---- part f: the shipped apps -------------------------------------------------------------------------------------------------------
const build = from => ({transform: 'rfc5322.build@1', args: {from, to: {input: '/to'}, subject: {input: '/subject'}, text: {input: '/text'}, now: {now: {}}}});
/** Gmail Send email through the synthetic map, its raw built by rfc5322.build@1 with `from`; `more` adds inputs and prepare steps. */
const sendEmail = (from, {inputs = {}, prepare = [{id: 'profile', method: 'GET', path: '/gmail/v1/users/{userId}/getProfile', expect: OK}]} = {}) => fileOf('gmail', [actionOf('gmail', 'send-email', {
  effect: 'write', row: 'gmail.messages.send', hints: WRITE_HINTS,
  inputSchema: closed({to: {type: 'array', minItems: 1, maxItems: 10, items: closed({address: words(254)})}, subject: words(), text: {type: 'string', maxLength: 100_000}, ...inputs}),
  outputSchema: closed({id: words(64)}), prepare,
  perform: [{id: 'send', method: 'POST', path: '/gmail/v1/users/{userId}/messages/send', body: {object: {raw: {pick: build(from), pointer: '/raw'}}}, expect: OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/gmail/v1/users/{userId}/messages/get', query: {id: {step: 'send', pointer: '/id'}}, expect: OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'send', pointer: '/id'}}], assert: []},
  output: {id: {step: 'send', pointer: '/id'}},
  preview: [{label: 'To', expr: {pick: {transform: 'text.joinList@1', args: {mailboxes: {input: '/to'}}}, pointer: '/text'}}, {label: 'Subject', expr: {input: '/subject'}}]})], {pinnedParameters: {userId: 'me'}});

test('part f: Send email builds its raw with {now} inside rfc5322.build@1, and the sender comes only from the account or the prepared profile (F10.8 open point Minor 5)', () => {
  assert.deepEqual(SENDER_SOURCES, {gmail: ['gmail.users.getProfile']});
  assert.deepEqual(SENDER_ARGUMENTS, {'rfc5322.build@1': ['from']});
  assert.ok(Object.isFrozen(SENDER_SOURCES) && Object.isFrozen(SENDER_SOURCES.gmail) && Object.isFrozen(SENDER_ARGUMENTS));
  const profile = {object: {address: {step: 'profile', pointer: '/emailAddress'}}};
  const send = entryOf(sendEmail(profile), APP_DEPS);
  assert.deepEqual([send.effect, send.row, send.unplaced, send.placements.map(placement => placement.member)], ['write', 'gmail.messages.send', false, ['gmail.users.getProfile', 'gmail.users.messages.send', 'gmail.users.messages.get']]);
  assert.ok(send.transforms.includes('rfc5322.build@1'));
  assert.equal(entryOf(sendEmail({object: {address: {pick: {step: 'profile', pointer: ''}, pointer: '/emailAddress'}}}), APP_DEPS).key, 'send-email');
  assert.equal(entryOf(sendEmail({object: {address: {account: 'email'}}}, {prepare: []}), APP_DEPS).key, 'send-email', 'Create draft\'s form: the account\'s own address');
  const sender = /rfc5322\.build@1's from reads only \{account: 'email'\} or the answer of a prepare step on a member of SENDER_SOURCES, through object and pick: an agent never chooses the sender \(F10\.8 open point Minor 5\)/;
  refusedFile(sendEmail({object: {address: {input: '/sender'}}}, {inputs: {sender: words(254)}}), sender, APP_DEPS, 'an input address');
  refusedFile(sendEmail({const: {address: 'someone@example.com'}}), sender, APP_DEPS, 'a constant address');
  refusedFile(sendEmail({object: {address: {account: 'email'}, name: {input: '/name'}}}, {inputs: {name: words(100)}, prepare: []}), sender, APP_DEPS, 'an input display name');
  refusedFile(sendEmail({object: {address: {account: 'id'}}}, {prepare: []}), sender, APP_DEPS, 'the account id is not an address');
  // Reply: the parent message's From, directly, through rfc5322.decodeGmailPayload@1 or through rfc5322.replyHeaders@1. None is the owner's.
  const parent = [{id: 'profile', method: 'GET', path: '/gmail/v1/users/{userId}/getProfile', expect: OK}, {id: 'parent', method: 'GET', path: '/gmail/v1/users/{userId}/messages/get', query: {id: {input: '/messageId'}}, expect: OK}];
  const reply = from => sendEmail(from, {inputs: {messageId: words(64)}, prepare: parent});
  const header = {pick: {transform: 'collections.findBy@1', args: {list: {step: 'parent', pointer: '/payload/headers'}, items: {const: ''}, field: {const: '/name'}, id: {const: '/value'},
    value: {const: 'From'}, fold: {const: 'ascii'}, require: {const: 'one'}}}, pointer: '/matches/0/id'};
  for (const from of [{object: {address: {pick: {step: 'parent', pointer: '/payload'}, pointer: '/from'}}}, {object: {address: header}},
    {pick: {transform: 'rfc5322.replyHeaders@1', args: {parent: {step: 'parent', pointer: ''}, owner: {object: {address: {step: 'profile', pointer: '/emailAddress'}}}, replyAll: {const: false}}}, pointer: '/to/0'}]) {
    refusedFile(reply(from), sender, APP_DEPS, JSON.stringify(from));
  }
  // Through rfc5322.decodeGmailPayload@1, the decoded From has no length bound, so it never even fits the sender's type.
  refusedFile(reply({pick: {transform: 'rfc5322.decodeGmailPayload@1', args: {message: {step: 'parent', pointer: ''}}}, pointer: '/summary/from/0'}), /its type does not fit rfc5322\.build@1's from/, APP_DEPS);
  // Edit draft: the prepared draft's From, directly or through rfc5322.decodeRaw@1.
  const draft = from => sendEmail(from, {inputs: {draftId: words(64)}, prepare: [{id: 'draft', method: 'GET', path: '/gmail/v1/users/{userId}/drafts/get', query: {id: {input: '/draftId'}}, expect: OK}]});
  refusedFile(draft({object: {address: {step: 'draft', pointer: '/message/from'}}}), sender, APP_DEPS);
  refusedFile(draft({pick: {transform: 'rfc5322.decodeRaw@1', args: {raw: {step: 'draft', pointer: '/message/raw'}}}, pointer: '/summary/from/0'}), /its type does not fit rfc5322\.build@1's from/, APP_DEPS);
  // Without a map Gmail is unplaced: valid in shape, never runnable, and the sender is checked once it places.
  const unplaced = entryOf(sendEmail(profile), {...APP_DEPS, maps: new Map()});
  assert.deepEqual([unplaced.unplaced, unplaced.effect, unplaced.sensitive], [true, 'write', null], 'sensitivity is unknown until every step places');
  assert.ok(unplaced.placements.every(placement => placement.unplaced));
  // Unplaced, the declared effect is still never weaker than the methods say.
  const {verify, ...unverified} = sendEmail(profile).actions[0];
  assert.ok(verify);
  refusedFile(fileOf('gmail', [{...unverified, effect: 'read', row: 'gmail.messages.read', hints: READ_HINTS}], {pinnedParameters: {userId: 'me'}}),
    /declares effect read, but its methods say at least write/, {...APP_DEPS, maps: new Map()});
  // The pinned userId never comes from a step.
  refusedFile(fileOf('gmail', sendEmail(profile).actions.map(action => ({...action, prepare: [{...action.prepare[0], params: {userId: {const: 'me'}}}]})), {pinnedParameters: {userId: 'me'}}),
    /params\.userId: userId is a pinned parameter, filled only by pinnedParameters, never by a step \(spec line 740\)/, APP_DEPS);
});

test('part f: Notion bodies (spec line 751): reserved keys never written, in_trash only the constant false, /properties only from notion.propertyValues@1 or a constant title (open point Important 8)', () => {
  const page = (body, fields = {}) => fileOf('notion', [actionOf('notion', 'restore-page', {
    effect: 'delete', row: 'notion.content.trash', hints: {...WRITE_HINTS, destructive: true},
    inputSchema: closed({pageId: words(64), ...(fields.inputs ?? {})}), outputSchema: closed({id: words(64)}),
    perform: [{id: 'restore', method: 'PATCH', path: '/v1/pages/{page_id}', params: {page_id: {input: '/pageId'}}, body, expect: OK}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: {input: '/pageId'}}, expect: OK}],
      identity: [{kind: 'address', step: 'check', of: 'restore'}], assert: [{step: 'check', equals: {pointer: '/in_trash', value: {const: false}}}]},
    output: {id: {step: 'check', pointer: '/id'}}, preview: [{label: 'Page', expr: {input: '/pageId'}}], ...(fields.action ?? {})})]);
  const restore = entryOf(page({object: {in_trash: {const: false}}}), APP_DEPS);
  assert.deepEqual([restore.effect, restore.row, restore.placements[0].groupId, restore.placements[0].routedFrom.groupId], ['delete', 'notion.content.trash', 'notion.content.trash', 'notion.content.edit']);
  assert.deepEqual(NOTION_RESERVED, ['erase_content', 'allow_deleting_content', 'is_locked', 'display_name', 'archived', 'is_archived']);
  refusedFile(page({object: {in_trash: {const: true}}}), /perform\[0\] \(restore\)\.body\.in_trash: in_trash is only the constant false \(spec line 751\)/, APP_DEPS);
  refusedFile(page({object: {in_trash: {input: '/flag'}}}, {inputs: {flag: {type: 'boolean'}}}), /in_trash is only the constant false/, APP_DEPS);
  refusedFile(page({const: {in_trash: true}}), /in_trash is only the constant false/, APP_DEPS);
  for (const key of ['archived', 'is_archived', 'display_name', 'erase_content', 'allow_deleting_content', 'is_locked']) {
    refusedFile(page({object: {in_trash: {const: false}, [key]: {const: false}}}), new RegExp(`writes ${key}, a field notion reserves: an action body never writes it, at any depth \\(spec line 751\\)`), APP_DEPS, key);
    refusedFile(page({object: {in_trash: {const: false}, icon: {const: {deep: {[key]: 1}}}}}), new RegExp(`writes ${key}, a field notion reserves`), APP_DEPS, `${key} inside a constant`);
  }
  // Create page and Add database row: /properties takes notion.propertyValues@1's whole result, or one constant title key built from text.chunk@1.
  const create = (properties, {inputs = {title: words(2000)}, resolved = false} = {}) => fileOf('notion', [actionOf('notion', 'create-page', {
    effect: 'write', row: 'notion.content.create', hints: WRITE_HINTS,
    inputSchema: closed({parentId: words(64), ...inputs, ...(resolved ? {values: {type: 'object', properties: {}, additionalProperties: false}} : {})}), outputSchema: closed({id: words(64)}),
    ...(resolved ? {resolvedInputs: [{input: 'values', dependsOn: ['parentId'], schema: {steps: [{id: 'source', method: 'GET', path: '/v1/data_sources/{data_source_id}', params: {data_source_id: {input: '/parentId'}}, expect: OK}],
      derive: {transform: 'notion.schema@1', args: {dataSource: {step: 'source', pointer: ''}}}}, maxProperties: 100}]} : {}),
    perform: [{id: 'create', method: 'POST', path: '/v1/pages', body: {object: {parent: {object: {page_id: {input: '/parentId'}}}, properties}}, expect: OK}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: {step: 'create', pointer: '/id'}}, expect: OK}],
      identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'create', pointer: '/id'}}], assert: []},
    output: {id: {step: 'create', pointer: '/id'}}, preview: [{label: 'Parent', expr: {input: '/parentId'}}]})]);
  const chunks = {each: {pick: {transform: 'text.chunk@1', args: {text: {input: '/title'}}}, pointer: '/chunks'}, as: 'part', max: 100, do: {object: {text: {object: {content: {var: 'part'}}}}}};
  assert.equal(entryOf(create({object: {title: chunks}}), APP_DEPS).key, 'create-page');
  const values = {transform: 'notion.propertyValues@1', args: {schema: {resolved: 'values'}, values: {input: '/values'}}};
  const added = entryOf(create(values, {resolved: true, inputs: {}}), APP_DEPS);
  assert.deepEqual(added.placements.map(placement => [placement.stepId, placement.phase]), [['source', 'schema'], ['create', 'perform'], ['check', 'verify']]);
  const properties = /perform\[0\] \(create\)\.body\.properties: Notion's \/properties takes only notion\.propertyValues@1's whole result, or the one constant key title built from text\.chunk@1 \(open question 10, open point Important 8\)/;
  refusedFile(create({object: {Name: {input: '/title'}}}), properties, APP_DEPS, 'keys written in the file from inputs');
  refusedFile(create({object: {title: {input: '/title'}}}), properties, APP_DEPS, 'a title not built from text.chunk@1');
  refusedFile(create({object: {title: chunks, Status: {const: 'Open'}}}), properties, APP_DEPS, 'another key beside the title');
  refusedFile(create({input: '/props'}, {inputs: {title: words(2000), props: closed({a: words()})}}), properties, APP_DEPS, 'an input whole');
  refusedFile(create({const: {display_name: 'x'}}), /writes display_name, a field notion reserves/, APP_DEPS);
  // A property the owner named display_name is sent under its property id, which the harness checks against the derived bindings.
  const pair = {schema: {type: 'object', properties: {display_name: {type: 'string', maxLength: 2000}}, additionalProperties: false}, bindings: [{name: 'display_name', id: 'p%3Ax', type: 'rich_text'}]};
  assert.deepEqual(runEntry(TRANSFORMS.get('notion.propertyValues@1'), {schema: pair, values: {display_name: 'mine'}}), {'p%3Ax': {rich_text: [{text: {content: 'mine'}}]}});
});

test('part f: alternatives (R4): when tests over one closed enum input, proved by enumerating its values; a when over anything else counts on every path', () => {
  const MOVES = ['trash-message', 'restore-message', 'trash-thread', 'restore-thread'];
  const on = (input, value) => ({equals: [{input: `/${input}`}, {const: value}]});
  const moveFile = (perform, inputs = {}) => fileOf('fixture', [actionOf('fixture', 'move-item', {
    effect: 'delete', row: 'fixture.items.delete', hints: {readOnly: false, destructive: true, idempotent: true, openWorld: true},
    inputSchema: closed({itemId: words(64), move: {type: 'string', enum: MOVES}, ...inputs}), outputSchema: closed({id: words(64)}),
    perform, verify: {requests: [{id: 'check', method: 'GET', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, expect: {status: [200, 404], require: []}}],
      identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {input: '/itemId'}}], assert: [{step: 'check', statusIn: [200, 404]}]},
    output: {id: {input: '/itemId'}}, preview: [{label: 'Item', expr: {input: '/itemId'}}, {label: 'Move', expr: {input: '/move'}}]})]);
  const step = (id, when, label) => label === undefined
    ? {id, method: 'DELETE', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, when, expect: OK}
    : {id, method: 'DELETE', path: '/items/{item_id}/labels/{name}', params: {item_id: {input: '/itemId'}, name: {const: label}}, when, expect: OK};
  // Move to trash or restore: one action, four perform steps, one per value of move; each path holds one.
  const four = [step('tm', on('move', 'trash-message')), step('rm', on('move', 'restore-message'), 'TRASH'), step('tt', on('move', 'trash-thread')), step('rt', on('move', 'restore-thread'), 'THREAD')];
  const entry = entryOf(moveFile(four));
  assert.deepEqual(entry.paths, MOVES.map((value, index) => ({input: 'move', value, perform: [['tm', 'rm', 'tt', 'rt'][index]], verify: ['check']})));
  // anyOf of values of the same input counts as each of them.
  const either = entryOf(moveFile([step('trash', {anyOf: [on('move', 'trash-message'), on('move', 'trash-thread')]}), step('restore', {anyOf: [on('move', 'restore-message'), on('move', 'restore-thread')]}, 'TRASH')]));
  assert.deepEqual(either.paths.map(path => path.perform), [['trash'], ['restore'], ['trash'], ['restore']]);
  // Tests on two different inputs are not proved exclusive.
  refusedFile(moveFile([step('tm', on('move', 'trash-message')), step('rm', on('move', 'restore-message'), 'TRASH'), step('tt', on('scope', 'thread')), step('rt', on('scope', 'message'), 'THREAD')],
    {scope: {type: 'string', enum: ['message', 'thread']}}), /perform steps choose their path by when tests over one closed enum input; these read move and scope \(R4\)/);
  // An optional enum input adds the path where it is absent.
  const optional = entryOf(fileOf('fixture', [{...moveFile(four).actions[0], inputSchema: {...closed({itemId: words(64), move: {type: 'string', enum: MOVES}}), required: ['itemId']}}]));
  assert.deepEqual(optional.paths.at(-1), {input: 'move', value: null, perform: [], verify: ['check']});
  // A when over step data, or over an input that is not an enum, counts on every path.
  const counted = entryOf(edited('update-item', action => {
    action.perform.push({id: 'extra', method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, when: {present: {step: 'item', pointer: '/extra'}}, body: {object: {name: {input: '/name'}}}, expect: OK});
  }));
  assert.deepEqual(counted.paths.map(path => path.perform), [['rename', 'extra'], ['label', 'extra']]);
  refusedFile(edited('update-item', action => {
    for (const id of ['x1', 'x2', 'x3']) action.perform.push({id, method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, when: {present: {input: '/name'}}, body: {object: {name: {input: '/name'}}}, expect: OK});
  }), /on the path where change is rename, 4 perform steps can run; at most 3 on any one path \(R4\)/);
  // Verify requests and assertions take the same shape on the same input, so each path reads back its own write.
  refusedFile(edited('update-item', action => { action.verify.requests[0].when = {present: {input: '/name'}}; }), /verify\.requests\[0\] \(check\)\.when: a verify request or assertion takes a when only over the closed enum input its perform steps choose by \(R4\)/);
  refusedFile(edited('update-item', action => { action.verify.assert[0].when = {present: {input: '/name'}}; }), /verify\.assert\[0\]\.when: a verify request or assertion takes a when only over the closed enum input/);
  // Every path with a write reads it back.
  refusedFile(edited('update-item', action => { action.verify.requests[0].when = on('change', 'rename'); }), /on the path where change is label, no verify request reads back the write: each path with a write is read back by 1 or 2 \(spec line 748\)/);
  // And by an identity of one of that path's own verify requests.
  refusedFile(edited('update-item', action => {
    action.verify.requests[0].when = on('change', 'rename');
    action.verify.requests.push({...action.verify.requests[0], id: 'checkLabels', when: on('change', 'label')});
  }), /on the path where change is label, no identity reads back the write \(spec line 748\)/);
});

const ZONE = {either: [{step: 'zone', pointer: '/value'}, {step: 'primary', pointer: '/timeZone'}]};
/** Calendar Find events with the time zone (spec line 989): settings.get, which needs an optional scope, and calendarList.get as its fallback. */
const zoneFile = (change = action => action) => fileOf('google-calendar', [change(actionOf('google-calendar', 'find-events', {
  effect: 'read', row: 'google-calendar.events.read', hints: READ_HINTS,
  inputSchema: closed({query: words()}), outputSchema: closed({zone: {type: 'string', maxLength: 100}, first: {type: 'string', maxLength: 1000}}),
  prepare: [{id: 'zone', method: 'GET', path: '/settings/get', optional: true, expect: OK}, {id: 'primary', method: 'GET', path: '/calendarList/get', fallbackFor: 'zone', expect: OK}],
  perform: [{id: 'events', method: 'GET', path: '/events/list', query: {q: {input: '/query'}, timeZone: ZONE}, expect: OK}],
  output: {zone: ZONE, first: {step: 'events', pointer: '/items/0/summary'}}, preview: [{label: 'Search', expr: {input: '/query'}}]}))]);

test('part f: optional steps (R7): each optional read has exactly one fallback after it, and runPlan() runs the fallback when the optional scope is missing (open point Minor 3)', () => {
  const entry = entryOf(zoneFile(), APP_DEPS);
  assert.deepEqual(entry.placements.map(placement => [placement.stepId, placement.member, placement.groupId]), [['zone', 'calendar.settings.get', 'google-calendar.settings.read'],
    ['primary', 'calendar.calendarList.get', 'google-calendar.calendars.read'], ['events', 'calendar.events.list', 'google-calendar.events.read']]);
  const missing = placement => placement.stepId === 'zone' ? 'missing' : 'granted', allow = () => 'allow';
  assert.deepEqual(runPlan(entry, {accessOf: missing, modeOf: allow}), {refused: null, access: 'granted', run: ['primary', 'events'], skipped: ['zone']}, 'the fallback runs; a skipped optional step adds nothing to access');
  assert.deepEqual(runPlan(entry, {accessOf: () => 'granted', modeOf: allow}), {refused: null, access: 'granted', run: ['zone', 'events'], skipped: ['primary']});
  assert.equal(runPlan(entry, {accessOf: placement => placement.stepId === 'events' ? 'missing' : 'granted', modeOf: allow}).access, 'missing');
  assert.equal(runPlan(entry, {accessOf: placement => placement.stepId === 'events' ? 'unknown' : 'granted', modeOf: allow}).access, 'unknown');
  // Its row's Never still refuses the action before any call, though the step would be skipped.
  const never = runPlan(entry, {accessOf: missing, modeOf: placement => placement.groupId === 'google-calendar.settings.read' ? 'deny' : 'allow'});
  assert.equal(never.refused, 'google-calendar.settings.read is Never, so the action is refused before any call, even where its step would be skipped (R7, T8).');
  assert.ok(Object.isFrozen(never) && Object.isFrozen(never.run));
  // A choice lookup runs too, as a prepare read; verify requests are listed with the rest.
  const list = validate(fixtureActions()).actions[0], update = validate(fixtureActions()).actions[1];
  assert.deepEqual(runPlan(list, {accessOf: () => 'granted', modeOf: allow}).run, ['choice:labelId', 'profile', 'list']);
  assert.deepEqual(runPlan(update, {accessOf: () => 'granted', modeOf: allow}).run, ['item', 'labels', 'rename', 'label', 'check']);
  assert.match(runPlan(update, {accessOf: () => 'granted', modeOf: placement => placement.phase === 'verify' ? 'deny' : 'allow'}).refused, /fixture\.items\.read is Never/, 'verify rows count, as T8 reads (open question 2)');
  // The pairing.
  refusedFile(zoneFile(action => { delete action.prepare[0].optional; return action; }), /prepare\[1\] \(primary\): fallbackFor names zone, which is not an optional step declared before it \(R7\)/, APP_DEPS);
  refusedFile(zoneFile(action => {
    action.prepare.pop();
    action.perform[0].query.timeZone = {either: [{step: 'zone', pointer: '/value'}, {const: 'UTC'}]};
    action.output.zone = action.perform[0].query.timeZone;
    return action;
  }), /prepare\[0\] \(zone\): the optional step zone has no fallback: each optional step has exactly one, declared after it \(R7\)/, APP_DEPS);
  refusedFile(zoneFile(action => { action.prepare.push({id: 'other', method: 'GET', path: '/calendarList/get', fallbackFor: 'zone', expect: OK}); return action; }), /the optional step zone has two fallbacks: each optional step has exactly one \(R7\)/, APP_DEPS);
  refusedFile(zoneFile(action => { action.prepare = [action.prepare[1], action.prepare[0]]; return action; }), /prepare\[0\] \(primary\): fallbackFor names zone, which is not an optional step declared before it/, APP_DEPS);
  refusedFile(edited('update-item', action => { action.verify.requests[0].optional = true; }), /verify\.requests\[0\] \(check\): optional and fallbackFor mark only a prepare step, or a perform step of a read action \(R7\)/);
  refusedFile(edited('update-item', action => { action.perform[0].fallbackFor = 'item'; }), /perform\[0\] \(rename\): optional and fallbackFor mark only a prepare step, or a perform step of a read action \(R7\)/);
});

test('part f: bounds (I7): nodes across one action, forEach 25, page.max 10, 64 requests, response caps, 16 MiB per job, 4 MiB prepared, 1 or 2 verify requests', () => {
  assert.deepEqual(BOUNDS, {steps: 8, perform: 3, verifyPerPath: 2, forEach: 25, pages: 10, requests: 64, responseBytes: 2_097_152, jobBytes: 16_777_216, preparedBytes: 4_194_304, outputBytes: 1_048_576});
  // One node budget for every expression of the action: a body that fits alone does not fit beside the rest.
  const keys = count => Array.from({length: count}, () => ({jobKey: 'k'}));
  refusedFile(edited('update-item', action => { action.perform[0].body.object.extra = {array: keys(1_950)}; }), /the expressions of one action hold at most 2,000 nodes/);
  assert.doesNotThrow(() => validate(edited('update-item', action => { action.perform[0].body.object.extra = {array: keys(1_800)}; })));
  refusedFile(edited('remove-labels', action => { action.perform[0].forEach.max = 26; action.inputSchema.properties.names.maxItems = 26; }), /forEach is \{over, max\}, with a max of 1 to 25 \(I7\)/);
  refusedFile(edited('list-items', action => { action.perform[0].page.max = 11; }), /page is \{next, into, items, max\} and may hold while, with a max of 1 to 10 \(I7\)/);
  refusedFile(edited('list-items', action => { delete action.perform[0].page.items; }), /page is \{next, into, items, max\}/, FIXTURE_DEPS, 'open point Important 5: a paged step names the list it joins');
  refusedFile(edited('list-items', action => { action.perform[0].forEach = {over: {const: ['a']}, max: 1}; }), /a step repeats with forEach or pages, never both/);
  refusedFile(edited('list-items', action => { action.perform[0].maxResponseBytes = 2_097_153; }), /maxResponseBytes is 1 to 2,097,152/);
  // Worst-case requests: each step times its forEach and page maxima, on the path with the most.
  const requests = last => edited('list-items', action => {
    action.inputSchema.properties.ids = {type: 'array', maxItems: 25, items: words(64)};
    action.prepare[0].maxResponseBytes = 65_536;
    for (const [id, max] of [['p1', 25], ['p2', 25], ['p3', last]]) action.prepare.push({id, method: 'GET', path: '/labels/{label_id}', params: {label_id: {item: ''}}, forEach: {over: {input: '/ids'}, max}, maxResponseBytes: 1_024, expect: OK});
  });
  refusedFile(requests(10), /can send 65 provider requests in the worst case; at most 64 \(I7\)/);
  assert.doesNotThrow(() => validate(requests(9)));
  // A 25-way forEach at the default 2 MiB per response reads more than 16 MiB: it must declare a smaller cap.
  refusedFile(edited('remove-labels', action => { action.perform[0].forEach.max = 25; action.inputSchema.properties.names.maxItems = 25; delete action.perform[0].maxResponseBytes; }),
    /can read 54,525,952 bytes of responses in the worst case; at most 16 MiB \(I7\)/);
  refusedFile(edited('update-item', action => { action.prepare.push({id: 'third', method: 'GET', path: '/labels', expect: OK}); }), /prepares 6,291,456 bytes in the worst case; at most 4 MiB \(I7\)/);
  refusedFile(edited('update-item', action => { for (const id of ['v2', 'v3']) action.verify.requests.push({...action.verify.requests[0], id}); }),
    /on the path where change is rename, 3 verify requests can run; a write is read back by 1 or 2 \(spec line 748\)/);
  // The deepest valid body still validates and hashes under canonicalHash's depth 40.
  const chain = (levels, leaf) => levels === 0 ? leaf : {object: {k: chain(levels - 1, leaf)}};
  const deepest = edited('update-item', action => { action.perform[0].body.object.extra = chain(12, {const: {a: {b: 'x'}}}); });
  assert.doesNotThrow(() => validate(deepest));
  assert.doesNotThrow(() => compiler.canonicalHash(deepest));
  refusedFile(edited('update-item', action => { action.perform[0].body.object.extra = chain(13, {const: {a: {b: 'x'}}}); }), /nests deeper than 16 levels \(I7\)/);
});

test('part f: headers, reserved names and query values (spec lines 740-741)', () => {
  assert.deepEqual(FABRIC_HEADERS, ['Authorization', 'Notion-Version', 'X-GitHub-Api-Version', 'User-Agent', 'Content-Type']);
  for (const name of FABRIC_HEADERS) {
    refusedFile(edited('update-item', action => { action.perform[0].headers = {[name]: {const: 'x'}}; }), new RegExp(`headers\\.${name}: ${name} is never a step header: Fabric sends it itself, or it carries a credential`), FIXTURE_DEPS, name);
  }
  for (const name of ['X-Custom', 'accept', 'Cookie']) refusedFile(edited('update-item', action => { action.perform[0].headers = {[name]: {const: 'x'}}; }),
    /is not a header an action step sends: only Accept, If-Match, If-None-Match, If-Modified-Since and If-Unmodified-Since/, FIXTURE_DEPS, name);
  refusedFile(edited('put-file', action => { action.prepare[0].headers.Accept = {const: 'text/html'}; }), /headers\.Accept: Accept is one of the app's accept types: application\/json, application\/vnd\.fixture\.raw\+json/);
  refusedFile(edited('put-file', action => { action.perform[0].headers = {Accept: {step: 'current', pointer: '/type'}}; }), /Accept is one of the app's accept types/);
  // If-Match and If-Unmodified-Since from a prepare step only; If-None-Match and If-Modified-Since from a poll cursor too.
  refusedFile(edited('list-items', action => { action.perform[0].headers = {'If-Match': {cursor: 'since'}}; delete action.perform[0].query.updatedAfter; }), /headers\.If-Match: If-Match comes only from a prepare step's answer/);
  const tagged = entryOf(edited('list-items', action => {
    action.perform[0].headers = {'If-None-Match': {cursor: 'tag'}};
    action.poll.cursors.push({name: 'tag', kind: 'etag@1', next: {step: 'list', header: 'etag'}});
  }));
  assert.equal(tagged.key, 'list-items');
  refusedFile(edited('update-item', action => {
    action.perform[1].headers = {'If-Match': {step: 'rename', header: 'etag'}};
    delete action.perform[1].when;
  }), /a header value reads only a prepare step's answer/);
  // Reserved query names (the proxy's list and the app's own), any case.
  for (const name of ['key', 'KEY', 'alt', 'callback', 'access_token', 'userIp']) {
    refusedFile(edited('list-items', action => { action.perform[0].query[name] = {const: 'x'}; }), new RegExp(`query\\.${name}: ${name} is a reserved query name: an action step never sends it`), FIXTURE_DEPS, name);
  }
  refusedFile(edited('list-items', action => { action.perform[0].page.into = {query: 'quotaUser'}; }), /page\.into: quotaUser is a reserved query name/);
  refusedFile(edited('list-items', action => { action.perform[0].query['a b'] = {const: 'x'}; }), /query names are 1 to 128 letters, digits and _ \. ~ : \[ \] -/);
  // Query values: scalars, or lists of them for the app's array parameters only.
  refusedFile(edited('list-items', action => { action.perform[0].query.kind = {array: [{input: '/kind'}]}; }), /query\.kind: a query value is a string, a number, a boolean or, for one of the app's array parameters \(labelIds\), a list of them/);
  refusedFile(edited('list-items', action => { action.perform[0].query.kind = {const: {a: 1}}; }), /query\.kind: a query value is a string, a number, a boolean/);
  refusedFile(edited('update-item', action => { action.perform[0].params.item_id = {input: '/labels'}; }), /params\.item_id: a path parameter is one string, number or boolean/);
  refusedFile(edited('update-item', action => { action.perform[0].params.other = {const: 'x'}; }), /params\.other names no parameter of PATCH \/items\/\{item_id\}/);
  refusedFile(edited('update-item', action => { delete action.perform[0].params; }), /the path parameter item_id is filled neither by params nor by pinnedParameters/);
  // Reserved body fields at any depth: Slack's token, here through the fixture's RPC twin.
  const rpc = (body, change = step => step) => fileOf('fixture-rpc', [actionOf('fixture-rpc', 'post-message', {effect: 'write', row: 'fixture-rpc.messages.send', hints: WRITE_HINTS,
    inputSchema: closed({channel: words(64), text: words(4000)}), outputSchema: closed({ts: words(64)}),
    perform: [change({id: 'post', method: 'POST', path: '/messages.post', body, expect: OK})],
    verify: {requests: [{id: 'check', method: 'GET', path: '/messages.list', query: {channel: {input: '/channel'}, ts: {step: 'post', pointer: '/ts'}}, expect: OK}],
      identity: [{kind: 'readback', step: 'check', pointer: '/messages/0/ts', equals: {step: 'post', pointer: '/ts'}}], assert: []},
    output: {ts: {step: 'post', pointer: '/ts'}}, preview: [{label: 'Text', expr: {input: '/text'}}]})]);
  const rpcDeps = {...FIXTURE_DEPS, identities: new Map()}, message = {channel: {input: '/channel'}, text: {input: '/text'}};
  assert.equal(entryOf(rpc({object: message}), rpcDeps).key, 'post-message');
  refusedFile(rpc({object: {...message, meta: {object: {token: {const: 'x'}}}}}), /body\.meta\.token: the body writes token, a field fixture-rpc reserves: an action body never writes it, at any depth/, rpcDeps);
  refusedFile(rpc({object: {...message, meta: {const: [{token: 'x'}]}}}), /writes token, a field fixture-rpc reserves/, rpcDeps);
  refusedFile(rpc({object: message}, step => ({...step, query: {Token: {const: 'x'}}})), /query\.Token: Token is a reserved query name/, rpcDeps);
  refusedFile(rpc({object: message}, step => ({...step, query: {channel: {input: '/channel'}}})), /a POST to an RPC app sends its arguments in the body, never the query/, rpcDeps);
});

test('part f: content binding (spec line 749, T5): a write on a bound member carries exactly what a prepare step read', () => {
  refusedFile(edited('put-file', action => { delete action.perform[0].bindContent; }), /perform\[0\] \(put\): its member is listed in fixture\.messages\.send's bindContent, so the step declares bindContent: 'sha' \(spec line 749, T5\)/);
  refusedFile(edited('put-file', action => { action.perform[0].bindContent = 'etag'; }), /so the step declares bindContent: 'sha'/);
  refusedFile(edited('update-item', action => { action.perform[0].bindContent = 'etag'; }), /perform\[0\] \(rename\): bindContent on a member its row does not list/);
  refusedFile(edited('update-item', action => { action.prepare[0].bindContent = 'etag'; }), /prepare\[0\] \(item\): bindContent is only on a perform step/);
  // The value at the row's location is the prepared datum, unchanged; for a sha, under when present of that same datum.
  const reason = kind => new RegExp(`bindContent ${kind} puts at (header:If-Match|body:/(sha|raw)) exactly what a prepare step read, unchanged, and this value is something else \\(spec line 749, T5\\)`);
  refusedFile(edited('send-draft', action => { action.perform[0].body.object.raw = {pick: {transform: 'encoding.base64urlEncode@1', args: {text: {input: '/draftId'}}}, pointer: '/encoded'}; }), reason('resend'));
  refusedFile(edited('send-draft', action => { action.perform[0].body.object.raw = {concat: [{step: 'draft', pointer: '/raw'}], max: 1_000}; }), reason('resend'));
  refusedFile(edited('send-draft', action => { delete action.perform[0].body.object.raw; }), reason('resend'));
  refusedFile(edited('reschedule-event', action => { delete action.perform[0].headers; }), reason('etag'));
  refusedFile(edited('put-file', action => { action.perform[0].body.object.sha = {when: {present: {step: 'current', pointer: '/other'}}, then: {step: 'current', pointer: '/sha'}}; }), reason('sha'));
  refusedFile(edited('put-file', action => { action.perform[0].body.object.sha = {const: 'abc'}; }), reason('sha'));
  assert.equal(entryOf(fileWith('put-file')).key, 'put-file', 'a sha under when present of the same prepare read');
  assert.equal(entryOf(edited('put-file', action => { action.perform[0].body.object.sha = {step: 'current', pointer: '/sha'}; })).key, 'put-file');
  assert.equal(entryOf(edited('reschedule-event', action => { action.perform[0].headers['If-Match'] = {step: 'event', pointer: '/etag'}; })).key, 'reschedule-event', 'an etag read from the prepared body');
  // An item counts when its forEach.over is that prepare step's list.
  const each = over => edited('send-draft', action => {
    action.perform[0].forEach = {over, max: 5};
    action.perform[0].maxResponseBytes = 65_536;
    action.perform[0].body.object.raw = {item: '/raw'};
    action.output.id = {step: 'send', pointer: '/0/id'};
    action.verify.identity[0].equals = {step: 'send', pointer: '/0/id'};
    action.verify.requests[0].params.item_id = {step: 'send', pointer: '/0/id'};
  });
  assert.equal(entryOf(each({step: 'draft', pointer: '/messages'})).key, 'send-draft');
  refusedFile(each({const: [{raw: 'x'}]}), reason('resend'));
  // Scope conditions: requiresScope names one of the row's conditional scopes.
  refusedFile(edited('put-file', action => { action.perform[0].requiresScope.scope = 'files.admin'; }), /perform\[0\] \(put\)\.requiresScope: requiresScope names files\.admin, which is not a conditional scope of fixture\.messages\.send/);
});

/** A fixture delete: DELETE /items/{item_id}, read back at the same address. */
const deleteItem = (fields = {}) => fileOf('fixture', [actionOf('fixture', 'delete-item', {effect: 'delete', row: 'fixture.items.delete', hints: {readOnly: false, destructive: true, idempotent: true, openWorld: true},
  inputSchema: closed({itemId: words(64)}), outputSchema: closed({id: words(64)}),
  perform: [{id: 'remove', method: 'DELETE', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, expect: {status: [204], require: []}}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, expect: {status: [404, 410], require: []}}],
    identity: [{kind: 'address', step: 'check', of: 'remove'}], assert: [{step: 'check', statusIn: [404, 410]}]},
  output: {id: {input: '/itemId'}}, preview: [{label: 'Item', expr: {input: '/itemId'}}], ...fields})]);

test('part f: verification (spec line 748): identity by readback, address or membership, with closed assertions', () => {
  assert.equal(entryOf(deleteItem()).key, 'delete-item', 'a delete read back at its own address, gone');
  const anyOf = deleteItem({verify: {...deleteItem().actions[0].verify, assert: [{anyOf: [{step: 'check', statusIn: [404]}, {step: 'check', statusIn: [410]}]}]}});
  assert.equal(entryOf(anyOf).key, 'delete-item');
  refusedFile(edited('update-item', action => { action.verify.identity[0].equals = {const: 'x'}; }),
    /verify\.identity\[0\] reads only constants: it reads what a perform step answered, or equals an expression a perform step sent \(spec line 748\)/);
  refusedFile(edited('update-item', action => { action.verify.identity[0].equals = {input: '/change'}; }), /verify\.identity\[0\] neither reads what a perform step answered nor equals an expression a perform step sent \(spec line 748\)/);
  // A value a transform consumed was not sent: labels reach the wire only as collections.labelIds@1's ids.
  refusedFile(edited('update-item', action => { action.verify.identity[0].equals = {input: '/labels'}; }), /verify\.identity\[0\] neither reads what a perform step answered nor equals an expression a perform step sent/);
  assert.equal(entryOf(edited('update-item', action => { action.verify.identity[0].equals = action.perform[1].body.object.labels; })).key, 'update-item', 'the transform result itself was sent');
  refusedFile(edited('update-item', action => { action.verify.identity[0].step = 'item'; }), /verify\.identity\[0\]\.step names a verify request/);
  // Address identity: only a delete or a removal in REMOVALS, at the same path with the same parameters (open point Minor 6: no singletons).
  assert.deepEqual(REMOVALS, {slack: ['POST /chat.deleteScheduledMessage', 'POST /reactions.remove']});
  refusedFile(edited('put-file', action => { action.verify.identity = [{kind: 'address', step: 'check', of: 'put'}]; delete action.records; }), /verify\.identity\[0\]: address identity is only for a delete or a member of REMOVALS \(spec line 748\)/);
  refusedFile(deleteItem({verify: {...deleteItem().actions[0].verify, requests: [{id: 'check', method: 'GET', path: '/labels/{label_id}', params: {label_id: {input: '/itemId'}}, expect: {status: [404], require: []}}]}}),
    /verify\.identity\[0\]: address identity reads the same path with the same parameters as remove/);
  refusedFile(deleteItem({verify: {...deleteItem().actions[0].verify, identity: [{kind: 'address', step: 'check', of: 'nothing'}]}}), /verify\.identity\[0\]\.of names a perform step/);
  // Membership: listHas and listLacks with 1 to 3 conditions, one of which equals what a perform step sent.
  assert.equal(entryOf(fileWith('remove-labels')).key, 'remove-labels');
  refusedFile(edited('remove-labels', action => { action.verify.identity[0].listLacks.where = Array.from({length: 4}, () => ({field: '/name', equals: {item: ''}})); }), /where holds 1 to 3 conditions/);
  refusedFile(edited('remove-labels', action => { action.verify.identity[0].listLacks.where = [{field: '/name', equals: {const: 'x'}}]; }), /verify\.identity\[0\] reads only constants/);
  refusedFile(edited('remove-labels', action => { action.verify.identity[0].forEach = 'check'; }), /verify\.identity\[0\]\.forEach names a perform step that repeats with forEach/);
  // Assertions are closed.
  for (const [assertion, pattern] of [[{step: 'check', matches: {pointer: '/a'}}, /an assertion is one of equals, contains, present, absent, statusIn, listHas, listLacks and anyOf/],
    [{step: 'check', statusIn: [99]}, /statusIn holds 1 to 16 HTTP status codes/], [{step: 'nothing', statusIn: [200]}, /names step nothing, which has not run before this point/],
    [{anyOf: [{step: 'check', statusIn: [200]}]}, /anyOf holds 2 to 4 assertions/], [{anyOf: [{step: 'check', statusIn: [200]}, {anyOf: [{step: 'check', statusIn: [200]}, {step: 'check', statusIn: [404]}]}]}, /an anyOf never nests/],
    [{step: 'check', equals: {pointer: '/a'}}, /equals is \{pointer, value\}/], [{statusIn: [200]}, /names the step it reads/]]) {
    refusedFile(edited('remove-labels', action => { action.verify.assert = [assertion]; }), pattern, FIXTURE_DEPS, JSON.stringify(assertion));
  }
  // expect: the step's own answer, never another step's.
  refusedFile(edited('update-item', action => { delete action.perform[0].expect; }), /perform\[0\] \(rename\): a step holds id, method, path and expect/);
  refusedFile(edited('update-item', action => { action.perform[0].expect.status = [700]; }), /expect\.status holds 1 to 16 HTTP status codes/);
  refusedFile(edited('update-item', action => { action.perform[0].expect.require = [{step: 'item', statusIn: [200]}]; }), /expect\.require reads the step's own answer: its assertions name no step/);
  // A read action has nothing to read back.
  refusedFile(edited('list-items', action => { action.verify = fileWith('update-item').actions[0].verify; }), /list-items v1: a read action has no verify block: nothing changed to read back/);
});

test('part f: the shipped Slack removals: S1 cancels a scheduled message read back by address and listLacks, S4 reacts read back by listHas with the owner\'s user id', () => {
  const slack = (key, fields) => fileOf('slack', [actionOf('slack', key, {effect: 'write', row: 'slack.messages.send', hints: WRITE_HINTS, ...fields})]);
  const cancel = slack('cancel-scheduled', {inputSchema: closed({channel: words(64), scheduledId: words(64)}), outputSchema: closed({id: words(64)}),
    perform: [{id: 'cancel', method: 'POST', path: '/chat.deleteScheduledMessage', body: {object: {channel: {input: '/channel'}, scheduled_message_id: {input: '/scheduledId'}}}, expect: SLACK_OK}],
    verify: {requests: [{id: 'list', method: 'GET', path: '/chat.scheduledMessages.list', query: {channel: {input: '/channel'}}, expect: SLACK_OK}],
      identity: [{kind: 'address', step: 'list', of: 'cancel'}], assert: [{step: 'list', listLacks: {list: '/scheduled_messages', where: [{field: '/id', equals: {input: '/scheduledId'}}]}}]},
    output: {id: {input: '/scheduledId'}}, preview: [{label: 'Message', expr: {input: '/scheduledId'}}]});
  const s1 = entryOf(cancel, APP_DEPS);
  assert.deepEqual([s1.effect, s1.row, s1.placements.map(placement => placement.groupId)], ['write', 'slack.messages.send', ['slack.messages.send', 'slack.messages.read']]);
  refusedFile(fileOf('slack', [{...cancel.actions[0], verify: {...cancel.actions[0].verify, requests: [{...cancel.actions[0].verify.requests[0], query: {channel: {const: 'C1'}}}]}}]),
    /address identity reads the same path with the same parameters as cancel/, APP_DEPS);
  const react = where => slack('react', {inputSchema: closed({channel: words(64), ts: words(64), emoji: words(100)}), outputSchema: closed({ok: {type: 'boolean'}}),
    perform: [{id: 'react', method: 'POST', path: '/reactions.add', body: {object: {channel: {input: '/channel'}, timestamp: {input: '/ts'}, name: {input: '/emoji'}}}, expect: SLACK_OK}],
    verify: {requests: [{id: 'get', method: 'GET', path: '/reactions.get', query: {channel: {input: '/channel'}, timestamp: {input: '/ts'}}, expect: SLACK_OK}],
      identity: [{kind: 'membership', step: 'get', listHas: {list: '/message/reactions', where}}], assert: []},
    output: {ok: {step: 'get', pointer: '/ok'}}, preview: [{label: 'Reaction', expr: {input: '/emoji'}}]});
  const s4 = entryOf(react([{field: '/name', equals: {input: '/emoji'}}, {field: '/users', contains: {account: 'userId'}}]), APP_DEPS);
  assert.equal(s4.key, 'react');
  refusedFile(react([{field: '/users', contains: {account: 'userId'}}]), /verify\.identity\[0\] neither reads what a perform step answered nor equals an expression a perform step sent/, APP_DEPS);
});

test('part f: guards (spec line 715; R16, R20): a guard entry with the action\'s own refusal code, before any request or after a prepare step it names', () => {
  assert.ok(Object.isFrozen(REFUSALS) && Object.keys(REFUSALS).length > 0);
  for (const [code, reason] of Object.entries(REFUSALS)) assert.match(code, /^[a-z][a-z_]{0,31}$/, reason);
  refusedFile(edited('update-item', action => { action.guards[0].refuse = 'not_open'; }), /guards\[0\]\.refuse: refuse is one of the action's codes in REFUSALS/);
  refusedFile(edited('update-item', action => { action.guards[0].args.value = {step: 'labels', pointer: '/status'}; }), /reads step "labels", which has not run before this point/);
  refusedFile(edited('update-item', action => { delete action.guards[0].after; }), /guards\[0\].*reads step "item", which has not run before this point/);
  refusedFile(edited('update-item', action => { action.guards[0].after = 'rename'; }), /guards\[0\]\.after names a prepare step/);
  refusedFile(edited('update-item', action => { action.guards[0].transform = 'collections.labelIds@1'; }), /collections\.labelIds@1 is a map entry; here only guard entries run/);
  refusedFile(edited('update-item', action => { action.guards[0].extra = 1; }), /guards\[0\]: a guard is \{transform, args, refuse\} and may hold after/);
  // Create label: find or create, with a forEach of at most 1 over collections.missing@1 (R20).
  const found = {pick: {transform: 'collections.findBy@1', args: {list: {step: 'labels', pointer: ''}, items: {const: '/labels'}, field: {const: '/name'}, id: {const: '/id'}, value: {input: '/name'}, fold: {const: 'ascii'}, require: {const: 'any'}}}, pointer: '/matches/0/id'};
  const either = {either: [{step: 'create', pointer: '/0/id'}, found]};
  const createLabel = fileOf('fixture', [actionOf('fixture', 'create-label', {effect: 'write', row: 'fixture.labels.write', hints: WRITE_HINTS,
    inputSchema: closed({name: words(100)}), outputSchema: closed({id: words(1000)}),
    prepare: [{id: 'labels', method: 'GET', path: '/labels', expect: OK}],
    perform: [{id: 'create', method: 'POST', path: '/labels', body: {object: {name: {item: ''}}}, expect: OK,
      forEach: {over: {pick: {transform: 'collections.missing@1', args: {list: {step: 'labels', pointer: ''}, items: {const: '/labels'}, field: {const: '/name'}, name: {input: '/name'}, fold: {const: 'ascii'}}}, pointer: '/missing'}, max: 1}}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/labels/{label_id}', params: {label_id: either}, expect: OK}], identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: either}], assert: []},
    output: {id: either}, preview: [{label: 'Label', expr: {input: '/name'}}]})]);
  const created = entryOf(createLabel);
  assert.deepEqual([created.effect, created.row, created.transforms], ['write', 'fixture.labels.write', ['collections.findBy@1', 'collections.missing@1']]);
  // Edit my message's guard: the prepared message's user is the owner's own Slack user id.
  const mine = checkCall('collections.oneOf@1', {value: {step: 'message', pointer: '/messages/0/user'}, set: {array: [{account: 'userId'}]}, fold: {const: 'none'}},
    {slot: 'guard', where: '$guard', transforms: TRANSFORMS, steps: new Map([['message', {source: 'prepare'}]]), identity: IDENTITY.slack}, ['guard']);
  assert.deepEqual([...mine.sources].sort(), ['account', 'constant', 'prepare']);
  // Open point Minor 1: a map transform in the perform bytes refuses the job with its own code when they are built; it is never a guard.
  const update = entryOf(fileWith('update-item'));
  assert.ok(update.transforms.includes('collections.labelIds@1'));
  assert.throws(() => runEntry(TRANSFORMS.get('collections.labelIds@1'), {list: {labels: [{id: 'L1', name: 'One'}]}, names: ['Two']}), error => error.code === 'label_unknown');
});

test('part f: askUnless, records and hints (decision 6) agree with the steps', () => {
  refusedFile(edited('put-file', action => { action.askUnless.createdByFabric.input = 'message'; }), /askUnless\.createdByFabric\.input is a required input that fills a path parameter of the last perform step on every path/);
  refusedFile(edited('update-item', action => { action.askUnless.createdByFabric.input = 'name'; }), /askUnless\.createdByFabric\.input is a required input/);
  refusedFile(edited('put-file', action => { action.askUnless.createdByFabric.kind = 'A file'; }), /askUnless is \{createdByFabric: \{kind, input\}\}/);
  refusedFile(edited('put-file', action => { action.records.pointer = '/path'; }), /records\.pointer is the pointer of a readback identity: what Fabric records as made by it is what it verified/);
  refusedFile(edited('list-items', action => { action.records = {kind: 'item', pointer: '/id'}; }), /a read action makes nothing, so it records nothing/);
  refusedFile(edited('update-item', action => { action.hints.readOnly = true; }), /hints\.readOnly is true exactly when the effect is read/);
  refusedFile(edited('remove-labels', action => { action.hints.destructive = false; }), /hints\.destructive is true exactly when the effect is delete or a step is routed into a delete row/);
  const trash = [{id: 'remove', method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, body: {object: {in_trash: {const: true}}}, expect: OK}];
  refusedFile(deleteItem({perform: trash, hints: {readOnly: false, destructive: true, idempotent: false, openWorld: true},
    verify: {...deleteItem().actions[0].verify, requests: [{id: 'check', method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, expect: OK}]}}),
  /verify\.requests\[0\] \(check\): a verify request is a read in a read row/, FIXTURE_DEPS, 'a verify request that writes');
  refusedFile(deleteItem({perform: trash, hints: {readOnly: false, destructive: false, idempotent: false, openWorld: true}}), /hints\.destructive is true exactly when the effect is delete or a step is routed into a delete row/);
  assert.equal(entryOf(deleteItem({perform: trash, hints: {readOnly: false, destructive: true, idempotent: false, openWorld: true}})).placements[0].routedFrom.groupId, 'fixture.items.edit');
  refusedFile(edited('send-draft', action => { action.hints.idempotent = true; }), /hints\.idempotent may be true only when every write that can run is a PUT, a DELETE, bound by If-Match or a sha, or a resolving write/);
  refusedFile(edited('add-row', action => { action.perform[0].body.object.requestId = {jobKey: 'row'}; action.hints.idempotent = true; }), /hints\.idempotent may be true only when/, FIXTURE_DEPS, 'a job key is new for every job');
  refusedFile(edited('update-item', action => { action.hints.openWorld = false; }), /hints\.openWorld is true: an action reaches a provider/);
  refusedFile(edited('update-item', action => { action.hints = {readOnly: false}; }), /hints is \{readOnly, destructive, idempotent, openWorld\}, each true or false/);
});

test('part f: the file and its lifecycle fields: shape, definitive codes, pins, superseded ids (R9) and certified', () => {
  const file = fixtureActions();
  for (const [change, pattern] of [
    [{extra: 1}, /Actions for fixture: an action file holds exactly schemaVersion, appId, specVersion, reviewStatus, pinnedParameters and actions, and may hold superseded/],
    [{schemaVersion: 2}, /Actions for fixture: schemaVersion is 1/], [{specVersion: 'fabric/0.1'}, /specVersion is fabric\/0\.2/],
    [{reviewStatus: 'active'}, /reviewStatus is reviewed or candidate/], [{pinnedParameters: {account: 7}}, /pinnedParameters maps names to constant path segments/],
    [{actions: []}, /actions holds 1 to 100 actions/], [{appId: 'nothing'}, /Actions for nothing: the app has no reviewed permission rows and proxy settings/]]) {
    refusedFile({...file, ...change}, pattern, FIXTURE_DEPS, JSON.stringify(change));
  }
  assert.throws(() => validate(null), /an action file is an object/);
  refusedFile({...file, actions: [...file.actions, file.actions[0]]}, /list-items v1 is declared twice/);
  for (const [change, pattern] of [[{key: 'List'}, /key is 1 to 48 lowercase letters, digits and hyphens, starting with a letter/], [{version: 0}, /version is a whole number from 1 to 9999/],
    [{effect: 'erase'}, /effect is read, write or delete/], [{row: 'fixture.nothing'}, /row names a row of fixture/], [{name: ''}, /name is 1 to 100 characters/],
    [{extra: 1}, /an action holds exactly .* and may hold/], [{id: 'fixture.action.list-items.v2.000000000000000000000000'}, /id is fixture\.action\.list-items\.v1\.<24 hex characters>/]]) {
    refusedFile(edited('list-items', action => Object.assign(action, change)), pattern, FIXTURE_DEPS, JSON.stringify(change));
  }
  refusedFile(edited('list-items', action => { action.row = 'fixture.keys.read'; }), /the last perform step on every path lands in its row: list lands in fixture\.items\.read, not fixture\.keys\.read/);
  // Definitive codes: client errors that mean nothing changed (lib/runtime.mjs:20), plus 409 and 429.
  const runtimeText = readFileSync(new URL('../lib/runtime.mjs', import.meta.url), 'utf8'), runtimeCodes = JSON.parse(`[${/const CLIENT_ERRORS=new Set\(\[([0-9,]+)\]\)/.exec(runtimeText)[1]}]`);
  assert.deepEqual(DEFINITIVE_CODES, [...runtimeCodes, 409, 429].sort((a, b) => a - b));
  for (const definitive of [[500], [404, 404], [200], 'all']) refusedFile(edited('list-items', action => { action.definitive = definitive; }), /definitive lists distinct codes of DEFINITIVE_CODES/, FIXTURE_DEPS, JSON.stringify(definitive));
  assert.equal(entryOf(edited('list-items', action => { action.definitive = [409, 429]; })).key, 'list-items');
  // Every transform the action names has a pin (open point Minor 2: the pins are a dependency, the shipped ones by default).
  const {['text.joinList@1']: joinList, ...fewer} = PINS;
  assert.ok(joinList);
  refusedFile(fileWith('update-item'), /update-item v1: names text\.joinList@1, which has no pin, so its id could not bind its code \(decision 4\)/, {...FIXTURE_DEPS, pins: fewer});
  // Superseded ids (R9).
  const superseded = entry => ({...file, superseded: [entry]}), old = file.superseded[0];
  assert.doesNotThrow(() => validate(file));
  for (const [entry, pattern] of [[{...old, id: file.actions[0].id}, /superseded\[0\]\.id is the current id of list-items v1/],
    [{...old, id: 'github.action.list-items.v1.0123456789abcdef01234567'}, /superseded\[0\]\.id is not an action id of fixture/],
    [{...old, id: 'fixture.action.list-items.v1.short'}, /superseded\[0\]\.id is not an action id of fixture/], [{...old, replacedBy: {key: 'nothing', version: 1}}, /superseded\[0\]\.replacedBy names no action of this file/],
    [{...old, stopsAfter: undefined}, /superseded\[0\] is \{id, replacedBy: \{key, version\}, reason, stopsAfter\}/], [{...old, stopsAfter: '2026-02-30'}, /superseded\[0\]\.stopsAfter is a real date/],
    [{...old, reason: 'tidy'}, /superseded\[0\]\.reason is safety or change/]]) {
    refusedFile(superseded(JSON.parse(JSON.stringify(entry))), pattern, FIXTURE_DEPS, JSON.stringify(entry));
  }
  refusedFile({...file, superseded: [old, old]}, /superseded lists fixture\.action\.list-items\.v1\.0123456789abcdef01234567 twice/);
  refusedFile({...file, superseded: []}, /superseded holds 1 to 100 entries/);
  // certified: the evidence path the template check reads, and a definition hash.
  refusedFile(edited('list-items', action => { action.certified.evidence = 'docs/live-evidence/fixture-2026-10-20.json'; }), /certified\.evidence is docs\/live-evidence\/fixture\/actions\.json/);
  refusedFile(edited('list-items', action => { action.certified.definitionHash = 'abc'; }), /certified is \{evidence, definitionHash\}, with a definition hash of 64 hex characters/);
});

test('part f: lookups (R12): a choice lookup is a read of a lookup source, in that source\'s row, counted as a step', () => {
  const sources = change => ({...FIXTURE_DEPS, choices: new Map([['fixture', fixtureChoices().sources.map(source => source.id === 'label' ? change({...source}) : source)]])});
  refusedFile(fileWith('list-items'), /list-items v1: the lookup of labelId: a lookup is a read in its source's row fixture\.keys\.read, and it lands in fixture\.items\.read with effect read \(R12\)/, sources(source => ({...source, row: 'fixture.keys.read'})));
  refusedFile(fileWith('list-items'), /the lookup of labelId: a lookup is a read in its source's row fixture\.items\.read, and it lands in fixture\.labels\.write with effect write \(R12\)/, sources(source => ({...source, read: {request: 'POST /labels'}})));
  refusedFile(edited('list-items', action => { action.choices[0].lookup = 'labels'; }), /choices\[0\] names the lookup source labels, which fixture's choice sources do not hold as a lookup \(R12\)/);
  refusedFile(edited('list-items', action => { action.choices[0].input = 'nothing'; }), /choices\[0\] is \{input, source\} for a declared input/);
  // An {operation} source places through the map; without it the lookup, and so the action, is unplaced.
  const operation = sources(source => ({...source, read: {operation: 'fixture.items.list'}}));
  const listed = entryOf(fileWith('list-items'), operation);
  assert.deepEqual([listed.lookups.labelId.operation, listed.lookups.labelId.template, listed.placements[0].member], ['fixture.items.list', null, 'fixture.items.list']);
  const unmapped = entryOf(fileWith('list-items'), {...operation, maps: new Map()});
  assert.deepEqual([unmapped.unplaced, unmapped.placements[0].unplaced], [true, true]);
  // It counts toward the 8 steps.
  refusedFile(edited('list-items', action => {
    for (const id of ['a', 'b', 'c', 'd', 'e', 'f']) action.prepare.push({id, method: 'GET', path: '/labels', maxResponseBytes: 1_024, expect: OK});
  }), /declares 9 steps; an action holds at most 8, counting schema steps and choice lookups \(I7\)/);
});

test('part f: checkPointer() is the R11 pointer check outside expressions', () => {
  assert.deepEqual(checkPointer('/a/b~1c', '$p'), ['a', 'b/c']);
  assert.throws(() => checkPointer('/0/temp_clone_token', '$p'), /\$p: the pointer \/0\/temp_clone_token reads temp_clone_token, a field that carries a secret/);
  assert.throws(() => checkPointer('a', '$p'), /is not a JSON pointer/);
});

test('part f check: an {array} item that can be left out moves the items after it, so a raw step-data value after one is held at every element (open point Important 2)', () => {
  const tags = items => edited('update-item', action => { action.inputSchema.properties.tag = words(64); action.perform[0].body.object.tags = {array: items}; });
  const tag = {when: {present: {input: '/tag'}}, then: {input: '/tag'}}, whole = reposAnswer()[0];
  const moved = entryOf(tags([tag, {step: 'item', pointer: '/0'}]));
  assert.deepEqual(moved.rawAt.rename, ['/body/tags/*']);
  const request = list => ({params: {item_id: 'i1'}, body: {name: 'n', tags: list}});
  assert.doesNotThrow(() => checkRequest(moved, 'rename', request(['t', 'x'])));
  assert.doesNotThrow(() => checkRequest(moved, 'rename', request(['x'])), 'the tag left out');
  // With the tag left out, the whole object sits at index 0, not at the index the file wrote.
  assert.throws(() => checkRequest(moved, 'rename', request([whole])), /rename copies a whole provider value at \/body\/tags\/0: only a string, a number, a boolean or null sits there \(I6, T4\)/);
  // Before the first item that can be left out a position is fixed.
  const fixed = entryOf(tags([{step: 'item', pointer: '/0'}, tag, {step: 'item', pointer: '/1'}]));
  assert.deepEqual(fixed.rawAt.rename, ['/body/tags/0', '/body/tags/*']);
  assert.deepEqual(entryOf(tags([tag, {const: 'a'}])).rawAt.rename, [], 'no raw value, nothing to hold');
});

test('part f check: Notion\'s /properties rule holds on every branch of a body that is an {either} (open question 10, open point Important 8)', () => {
  const chunks = {each: {pick: {transform: 'text.chunk@1', args: {text: {input: '/title'}}}, pointer: '/chunks'}, as: 'part', max: 100, do: {object: {text: {object: {content: {var: 'part'}}}}}};
  const branch = (parent, properties) => ({object: {parent: {object: {page_id: parent}}, properties}});
  const create = (first, second) => fileOf('notion', [actionOf('notion', 'create-page', {
    effect: 'write', row: 'notion.content.create', hints: WRITE_HINTS,
    inputSchema: closed({parentId: words(64), title: words(2000)}), outputSchema: closed({id: words(64)}),
    prepare: [{id: 'parent', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: {input: '/parentId'}}, when: {present: {input: '/parentId'}}, expect: OK}],
    perform: [{id: 'create', method: 'POST', path: '/v1/pages', body: {either: [branch({step: 'parent', pointer: '/id'}, first), branch({input: '/parentId'}, second)]}, expect: OK}],
    verify: {requests: [{id: 'check', method: 'GET', path: '/v1/pages/{page_id}', params: {page_id: {step: 'create', pointer: '/id'}}, expect: OK}],
      identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {step: 'create', pointer: '/id'}}], assert: []},
    output: {id: {step: 'create', pointer: '/id'}}, preview: [{label: 'Parent', expr: {input: '/parentId'}}]})]);
  assert.equal(entryOf(create({object: {title: chunks}}, {object: {title: chunks}}), APP_DEPS).key, 'create-page');
  const properties = /perform\[0\] \(create\)\.body\.properties: Notion's \/properties takes only notion\.propertyValues@1's whole result, or the one constant key title built from text\.chunk@1/;
  refusedFile(create({object: {Name: {input: '/title'}}}, {object: {title: chunks}}), properties, APP_DEPS, 'a key written in the file on the first branch');
  refusedFile(create({object: {title: chunks}}, {object: {Name: {input: '/title'}}}), properties, APP_DEPS, 'a key written in the file on the second branch');
});

// ---- part g: ids, the capability shape, the loader and job keys (lib/actions.mjs) ------------------------------------------------
const idOf = (file, deps) => entryOf(file, deps).id;
const escaped = text => text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

test('part g: an action id hashes its content without id, certified and poll, the pins of the transforms it names and its lookups; the fixture file carries the computed ids (spec line 753)', () => {
  const file = fixtureActions(), result = validateActionFile(file, FIXTURE_DEPS), computed = actionIds(file, FIXTURE_DEPS);
  assert.deepEqual([...computed.keys()], file.actions.map(action => `${action.key} v${action.version}`));
  for (const [index, entry] of result.actions.entries()) {
    assert.deepEqual([entry.id, computed.get(`${entry.key} v${entry.version}`).id], [file.actions[index].id, file.actions[index].id], entry.key);
    assert.ok(!entry.id.endsWith(ZEROS), `${entry.key} carries its computed id`);
  }
  // The rule, recomputed: kind fabric-action over the file's fields and the action without id, certified and poll, beside the pin of
  // each transform it names and the resolved request of each lookup.
  for (const entry of result.actions.slice(0, 2)) {
    const {id, certified, poll, ...content} = file.actions.find(action => action.key === entry.key);
    void id, void certified, void poll;
    const hash = compiler.canonicalHash({kind: 'fabric-action', schemaVersion: 1, appId: 'fixture', specVersion: 'fabric/0.2', pinnedParameters: {account: 'me'}, action: content,
      transforms: Object.fromEntries(entry.transforms.map(name => [name, PINS[name]])), lookups: entry.lookups});
    assert.equal(entry.id, `fixture.action.${entry.key}.v1.${hash.slice(0, 24)}`, entry.key);
  }
  assert.deepEqual(Object.keys(result.actions[0].lookups), ['labelId']);
  // A stored id that does not match is refused, naming the id the content hashes to, so a review sees every id change.
  const changed = edited('update-item', action => { action.description = 'Renames one item, or labels it.'; }), now = actionIds(changed, FIXTURE_DEPS).get('update-item v1').id;
  assert.notEqual(now, file.actions[1].id);
  assert.throws(() => validateActionFile(changed, FIXTURE_DEPS), new RegExp(`update-item v1: id is ${escaped(file.actions[1].id)}, but its content hashes to ${escaped(now)}: a changed action gets a new id \\(spec line 753\\)`));
  assert.throws(() => validateActionFile(edited('update-item', action => { action.id = `fixture.action.update-item.v1.${ZEROS}`; }), FIXTURE_DEPS),
    /update-item v1: id is fixture\.action\.update-item\.v1\.0{24}, but its content hashes to fixture\.action\.update-item\.v1\.[a-f0-9]{24}/);
  // actionIds() runs every other check, and a duplicate key and version is refused before any id.
  assert.throws(() => actionIds(edited('update-item', action => { delete action.verify; }), FIXTURE_DEPS), /a write needs a verify block with an identity/);
  refusedFile({...file, actions: [file.actions[0], file.actions[0]]}, /list-items v1 is declared twice/);
});

test('part g: the id stays with lifecycle data and the poll block, and moves with any content, a transform version or pin, a choice or a lookup request (R9, R12, decision 4)', () => {
  const [list, update] = fixtureActions().actions.map(action => action.id), reschedule = fixtureActions().actions[4].id;
  // Lifecycle data and the poll block are not content.
  for (const [label, file] of [['reviewStatus', {...fileWith('list-items'), reviewStatus: 'reviewed'}], ['superseded', {...fileWith('list-items'), superseded: fixtureActions().superseded}],
    ['certified', edited('list-items', action => { delete action.certified; })],
    ['the poll block', edited('list-items', action => { action.poll.minIntervalSeconds = 300; action.poll.order = 'unordered'; action.poll.cursors[0].overlapSeconds = 600; })]]) {
    assert.equal(idOf(file), list, label);
  }
  // Content moves it, a {cursor} slot included: the slots sit in the step.
  for (const [label, file] of [['pinnedParameters', {...fileWith('list-items'), pinnedParameters: {account: 'self'}}],
    ['the description', edited('list-items', action => { action.description = 'Lists your items.'; })],
    ['a preview label', edited('list-items', action => { action.preview[0].label = 'Which'; })],
    ['a choices entry', edited('list-items', action => { action.choices[0].source = 'found'; })],
    ['a cursor slot', edited('list-items', action => { const {updatedAfter, ...query} = action.perform[0].query; action.perform[0].query = {...query, since: updatedAfter}; })]]) {
    assert.notEqual(idOf(file), list, label);
  }
  // A transform version, and a transform's pin (open point Minor 2: the pins are a dependency, the fixture registry's here).
  const joinList = TRANSFORMS.get('text.joinList@1');
  const versioned = {...FIXTURE_DEPS, transforms: new Map([...TRANSFORMS, ['text.joinList@2', {...joinList, version: 2}]]), pins: {...PINS, 'text.joinList@2': PINS['text.joinList@1']}};
  assert.notEqual(idOf(edited('update-item', action => { action.preview[2].expr.pick.transform = 'text.joinList@2'; }), versioned), update, 'a transform version');
  const repinned = {...FIXTURE_DEPS, pins: {...PINS, 'text.joinList@1': 'f'.repeat(64)}};
  assert.notEqual(idOf(fileWith('update-item'), repinned), update, 'a re-pin of a transform it names');
  assert.equal(idOf(fileWith('reschedule-event'), repinned), reschedule, 'a re-pin of a transform it does not name');
  // R12: a lookup's resolved request is content; a list-only source is advisory and stays out.
  const sources = change => ({...FIXTURE_DEPS, choices: new Map([['fixture', fixtureChoices().sources.map(source => change({...source}))]])});
  for (const [label, change] of [['label pointers', source => ({...source, label: ['/title']})], ['arguments', source => ({...source, args: {label_id: {value: true}, view: {const: 'full'}}})],
    ['request', source => ({...source, read: {request: 'GET /items/{item_id}'}, args: {item_id: {value: true}}})]]) {
    assert.notEqual(idOf(fileWith('list-items'), sources(source => source.id === 'label' ? change(source) : source)), list, `a lookup source's ${label}`);
  }
  assert.equal(idOf(fileWith('list-items'), sources(source => source.id === 'labels' ? {...source, exclude: ['TRASH'], maxItems: 100} : source)), list, 'a list-only source');
});

test('part g: definitionHash is capabilityPermissionHash(actionCapability()), certified.definitionHash must equal it, and certifying or a poll edit never moves it', () => {
  const file = fixtureActions(), [list] = validateActionFile(file, FIXTURE_DEPS).actions;
  assert.equal(list.definitionHash, capabilityPermissionHash(actionCapability(file, list)));
  assert.equal(file.actions[0].certified.definitionHash, list.definitionHash);
  assert.equal(entryOf(edited('list-items', action => { delete action.certified; })).definitionHash, list.definitionHash, 'certifying');
  assert.equal(entryOf(edited('list-items', action => { action.poll.minIntervalSeconds = 300; })).definitionHash, list.definitionHash, 'a poll edit');
  assert.notEqual(entryOf(edited('list-items', action => { action.description = 'Lists your items.'; })).definitionHash, list.definitionHash, 'a content edit');
  assert.throws(() => validateActionFile(edited('list-items', action => { action.certified.definitionHash = 'a'.repeat(64); }), FIXTURE_DEPS),
    new RegExp(`list-items v1: certified\\.definitionHash is not ${list.definitionHash}, the hash of the definition grants bind: evidence certifies exactly that definition`));
});

test('part g: an action id has five dot parts and hashes kind fabric-action, so it never equals a compiled id, and the longest fits both id rules', () => {
  const document = {openapi: '3.0.3', info: {title: 'Fixture', version: '1'}, servers: [{url: 'https://api.example.com'}], paths: {'/items': {get: {operationId: 'listItems', responses: {200: {description: 'Items'}}}}}};
  const [compiled] = compiler.compileOpenApi({appId: 'fixture', document}).capabilities;
  for (const id of [compiled.id, compiler.finalizeCapability(compiled).id]) assert.equal(id.split('.').length, 3, id);
  for (const entry of validateActionFile(fixtureActions(), FIXTURE_DEPS).actions) assert.equal(entry.id.split('.').length, 5, entry.id);
  // The longest: a 64-character app id, a 48-character key and version 9999 (lib/compiler.mjs:349; lib/store.mjs:63).
  const longest = `${'a'.repeat(64)}.action.${'k'.repeat(48)}.v9999.${'f'.repeat(24)}`;
  assert.equal(longest.length, 151);
  assert.match(longest, /^[a-z][a-z0-9._-]{1,199}$/);
  assert.ok(longest.length <= 256);
});

test('part g: I2 and I8: actionCapability() is a candidate with driver action, never active, and validateCapability(), saveCandidates(), effectOf() and decision() each refuse it', t => {
  const file = {...fixtureActions(), reviewStatus: 'reviewed'}, [list, update] = validateActionFile(file, FIXTURE_DEPS).actions;
  const capability = actionCapability(file, list);
  assert.deepEqual(Object.keys(capability), ['id', 'specVersion', 'version', 'appId', 'kind', 'driver', 'name', 'description', 'effect', 'status', 'inputSchema', 'outputSchema', 'action', 'provenance']);
  assert.deepEqual([capability.id, capability.specVersion, capability.version, capability.appId, capability.kind, capability.driver, capability.effect, capability.status],
    [list.id, 'fabric/0.2', 1, 'fixture', 'action', 'action', 'read', 'candidate'], 'a reviewed, certified file is still a candidate');
  assert.deepEqual(capability.provenance, {kind: 'reviewed-action', file: 'catalog/actions/fixture.json'});
  assert.deepEqual(Object.keys(capability.action), ['key', 'pinnedParameters', 'steps', 'guards', 'output', 'preview', 'definitive', 'hints', 'choices']);
  assert.deepEqual(capability.action.steps, {prepare: list.action.prepare, perform: list.action.perform});
  assert.deepEqual(Object.keys(actionCapability(file, update).action), ['key', 'pinnedParameters', 'steps', 'verify', 'guards', 'output', 'preview', 'askUnless', 'definitive', 'hints', 'choices']);
  assert.deepEqual(actionCapability(file, list.action), capability, 'the action as written gives the same capability');
  // I2 holds by driver: validateCapability() refuses it, and would refuse it as fabric/0.1 too.
  assert.throws(() => compiler.validateCapability(capability), /Capability: unsupported field kind/);
  const {kind, outputSchema, action, ...rest} = capability;
  void kind, void outputSchema, void action;
  assert.throws(() => compiler.validateCapability({...rest, specVersion: 'fabric/0.1', version: 1}), /Compiler validation supports HTTP capabilities only/);
  // saveCandidates() stores nothing.
  const puts = [];
  const engine = new AcquisitionEngine({store: {get: () => null, put: (...args) => puts.push(args)}, catalog: () => [{id: 'fixture', allowedOrigins: ['https://api.fixture.test']}],
    modelUrl: null, modelKey: null, modelName: null, request: async () => { throw new Error('No network call is expected.'); }});
  assert.throws(() => engine.saveCandidates('fixture', [capability]), /Capability: unsupported field kind/);
  assert.equal(puts.length, 0);
  // F10.11 parts e and h (listed churn): effectOf() reads an action's effect from its catalog entry, so with no action catalog injected it
  // refuses, and decision() reads an action on an http connection of its app from its steps, unsupported with no catalog: it never runs.
  assert.throws(() => Runtime.prototype.effectOf(capability), /^Error: Actions are not loaded in this Fabric, so this action cannot run\.$/);
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-actions-decision-')), store = new Store({dataDir: dir});
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  const connection = {id: 'account-1', appId: 'fixture', driver: 'http', authMethod: 'token', authRevision: 'first-authorization', status: 'ready', identity: {id: 'user-1'},
    allowedOrigins: ['https://api.fixture.test'], createdAt: '2026-10-20T00:00:00.000Z'};
  store.put('connections', connection);
  const decision = new PermissionManager({store}).decision(connection, capability);
  assert.deepEqual([decision.executable, decision.status, decision.reason], [false, 'unsupported', 'Actions are not loaded in this Fabric, so this action cannot run.']);
  // R15: lock and route lookups answer for an action from its step placements only through an action catalog (F10.11 part f); with none
  // given they answer nothing, and the action is already unsupported.
  assert.deepEqual([lockedRowOf(FIXTURE_DEPS.groups, FIXTURE_DEPS.configs, capability), memberRoutes(FIXTURE_DEPS.groups, FIXTURE_DEPS.configs, capability),
    rowMemberOf(FIXTURE_DEPS.groups, FIXTURE_DEPS.configs, capability)], [null, [], null]);
});

/** Each file in a folder with the sha256 of its bytes. */
const folder = dir => readdirSync(dir).sort().map(name => `${name}:${createHash('sha256').update(readFileSync(path.join(dir, name))).digest('hex')}`);

test('part g: loadActions() reads one *.json per app, named after it, validates each, ignores README.md, loads a missing or empty folder as empty, and writes nothing', t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-actions-load-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const dir = path.join(root, 'actions');
  assert.equal(loadActions(dir, FIXTURE_DEPS).size, 0, 'a missing folder');
  mkdirSync(dir);
  assert.equal(loadActions(dir, FIXTURE_DEPS).size, 0, 'an empty folder');
  writeFileSync(path.join(dir, 'README.md'), 'Reviewed action files, one per app.\n');
  writeFileSync(path.join(dir, 'fixture.json'), JSON.stringify(fixtureActions()));
  const before = folder(dir), loaded = loadActions(dir, FIXTURE_DEPS);
  assert.deepEqual([...loaded.keys()], ['fixture']);
  assert.deepEqual(loaded.get('fixture'), validateActionFile(fixtureActions(), FIXTURE_DEPS));
  assert.deepEqual(folder(dir), before, 'it writes nothing');
  writeFileSync(path.join(dir, 'other.json'), JSON.stringify(fixtureActions()));
  assert.throws(() => loadActions(dir, FIXTURE_DEPS), /Action file other\.json must be named after its appId/);
  // Gmail without a stored map: valid in shape and unplaced, never runnable.
  const gmail = path.join(root, 'gmail'), deps = {...APP_DEPS, maps: new Map()};
  mkdirSync(gmail);
  writeFileSync(path.join(gmail, 'gmail.json'), JSON.stringify(withIds(sendEmail({object: {address: {account: 'email'}}}, {prepare: []}), deps)));
  const [send] = loadActions(gmail, deps).get('gmail').actions;
  assert.deepEqual([send.key, send.unplaced, send.sensitive], ['send-email', true, null]);
  // F10.13 listed churn: the shipped folder holds its README and Calendar's file, which loads with Google's recorded map and is refused
  // without one (Find free time places only through it); lib/actions.mjs only reads files and never reaches the store. F10.15 listed churn:
  // Gmail's file loads beside it, placed with Gmail's map and unplaced without one, never refused (none of its actions is a reviewed-read POST).
  // F10.17, F10.19 and F10.21 listed churn: GitHub's, Notion's and Slack's files load beside them, with no map.
  const shipped = loadActions(undefined, {maps: new Map([['google-calendar', googleMap('google-calendar')]])});
  assert.deepEqual([...shipped.keys()].sort(), ['github', 'gmail', 'google-calendar', 'notion', 'slack']);
  assert.ok(shipped.get('gmail').actions.every(entry => entry.unplaced === true));
  const placed = loadActions(undefined, {maps: new Map(['google-calendar', 'gmail'].map(appId => [appId, googleMap(appId)]))});
  assert.ok(placed.get('gmail').actions.every(entry => entry.unplaced === false));
  assert.throws(() => loadActions(), /find-free-time v1: declares effect read, but its methods say at least write/);
  assert.deepEqual(readdirSync(new URL('../catalog/actions/', import.meta.url)).sort(), ['README.md', 'github.json', 'gmail.json', 'google-calendar.json', 'notion.json', 'slack.json']);
  const source = readFileSync(new URL('../lib/actions.mjs', import.meta.url), 'utf8');
  assert.match(source, /^import \{readdirSync, readFileSync\} from 'node:fs';$/m);
  assert.ok(!/store\.mjs/.test(source), 'lib/actions.mjs never imports the store');
});

test('part g: jobKey() is the first 32 hex characters of a hash of the job id, the action id and the name: stable within a job, new across jobs (spec line 735)', () => {
  const [, update] = fixtureActions().actions.map(action => action.id), key = jobKey('job-1', update, 'move');
  assert.match(key, /^[a-f0-9]{32}$/);
  assert.equal(jobKey('job-1', update, 'move'), key);
  assert.equal(key, compiler.canonicalHash({kind: 'fabric-job-key', jobId: 'job-1', actionId: update, name: 'move'}).slice(0, 32));
  for (const [label, other] of [['another job', jobKey('job-2', update, 'move')], ['another action', jobKey('job-1', fixtureActions().actions[4].id, 'move')], ['another name', jobKey('job-1', update, 'meet')]]) {
    assert.notEqual(other, key, label);
  }
  for (const args of [[], ['', update, 'move'], ['job-1', '', 'move'], ['job-1', update, 'Move it'], [7, update, 'move']]) assert.throws(() => jobKey(...args), /jobKey\(\) takes a job id, an action id and a key name/, JSON.stringify(args));
});

// ---- part h: the poll block on read actions (section 8) --------------------------------------------------------------------------
/** list-items with `edit(action, poll, step)` applied to its poll block and its list step, the poll step. */
const polled = edit => edited('list-items', action => edit(action, action.poll, action.perform[0]));
const sinceGone = step => { delete step.query.updatedAfter; };

test('part h: a read action\'s poll block: pollHash binds the block, the action id and the pins of the transforms it names, and never moves the id or the definition hash (section 8)', () => {
  const file = fixtureActions(), entries = validateActionFile(file, FIXTURE_DEPS).actions, [list] = entries;
  assert.deepEqual(list.pollTransforms, ['time.rfc3339ToEpochSeconds@1']);
  assert.equal(list.pollHash, compiler.canonicalHash({kind: 'fabric-action-poll', version: 1, actionId: list.id, poll: file.actions[0].poll,
    transforms: {'time.rfc3339ToEpochSeconds@1': PINS['time.rfc3339ToEpochSeconds@1']}}));
  assert.equal(pollHash(list, PINS), list.pollHash);
  assert.ok(entries.slice(1).every(entry => entry.pollHash === null && entry.pollTransforms.length === 0), 'no poll block, no poll hash');
  // A poll edit, and a re-pin of a transform the block names, move the poll hash and nothing the action binds.
  const tuned = entryOf(polled((action, poll) => { poll.minIntervalSeconds = 300; }));
  const repinned = entryOf(fileWith('list-items'), {...FIXTURE_DEPS, pins: {...PINS, 'time.rfc3339ToEpochSeconds@1': 'e'.repeat(64)}});
  for (const entry of [tuned, repinned]) assert.deepEqual([entry.id, entry.definitionHash, entry.pollHash === list.pollHash], [list.id, list.definitionHash, false]);
  // The block names its cursors' compares, its item time format's transform and the transforms its itemId calls, each by its pin.
  const named = entryOf(polled((action, poll) => {
    Object.assign(poll.cursors[0], {next: {step: 'list', pointer: '/newest'}, compare: 'time.decimalCompare@1'});
    poll.itemTime.format = 'slack-ts';
    poll.itemId = {pick: {transform: 'text.truncate@1', args: {text: {item: '/id'}, max: {const: 100}}}, pointer: '/text'};
  }));
  assert.deepEqual(named.pollTransforms, ['text.truncate@1', 'time.decimalCompare@1', 'time.slackTs@1']);
  assert.deepEqual([named.transforms, named.id === list.id], [list.transforms, true], 'none of them is the action\'s');
  // Every transform the block names has a pin (open point Minor 2), and the registry holds it.
  const {['time.rfc3339ToEpochSeconds@1']: compare, ...unpinned} = PINS;
  assert.ok(compare);
  refusedFile(fileWith('list-items'), /list-items v1: poll names time\.rfc3339ToEpochSeconds@1, which has no pin, so the poll hash could not bind its code \(decision 4\)/, {...FIXTURE_DEPS, pins: unpinned});
  const withoutCompare = new Map([...TRANSFORMS].filter(([id]) => id !== 'time.rfc3339ToEpochSeconds@1'));
  refusedFile(fileWith('list-items'), /list-items v1: poll names time\.rfc3339ToEpochSeconds@1, which the registry does not hold/, {...FIXTURE_DEPS, transforms: withoutCompare});
  // The cursor kinds, versioned, and the item time formats, each ordered by a shipped, pinned transform.
  assert.deepEqual(Object.keys(CURSOR_KINDS), ['history-id@1', 'sync-token@1', 'high-water-time@1', 'high-water-ts@1', 'etag@1', 'last-modified@1', 'snapshot@1']);
  assert.deepEqual(ITEM_TIME_FORMATS, {rfc3339: 'time.rfc3339ToEpochSeconds@1', 'epoch-ms-string': 'time.decimalCompare@1', 'epoch-seconds': 'time.decimalCompare@1', 'slack-ts': 'time.slackTs@1'});
  for (const id of [...Object.values(CURSOR_KINDS).flatMap(kind => kind.compare), ...Object.values(ITEM_TIME_FORMATS)]) assert.ok(SHIPPED.has(id) && typeof PINS[id] === 'string', id);
  // The tested trigger fixtures' cursors use these kinds and compares.
  for (const appId of ['google-calendar', 'github', 'notion']) {
    for (const cursor of JSON.parse(readFileSync(new URL(`./fixtures/triggers/${appId}.json`, import.meta.url), 'utf8')).triggers[0].poll.cursors) {
      assert.ok(Object.hasOwn(CURSOR_KINDS, cursor.kind) && (cursor.compare === undefined || CURSOR_KINDS[cursor.kind].compare.includes(cursor.compare)), `${appId} ${cursor.name}`);
    }
  }
});

test('part h: a poll block sits only on a read action, closed, and its step is one of the action\'s own reads, whose list the items come from', () => {
  refusedFile(edited('update-item', action => { action.poll = structuredClone(fixtureActions().actions[0].poll); }), /update-item v1: poll is only on a read action: a polling trigger reuses a read \(section 8\)/);
  refusedFile(polled((action, poll) => { poll.extra = 1; }), /list-items v1: poll is \{step, items, itemId, itemVersion, order, cursors, resync, resourceKey, filterInputs, minIntervalSeconds\} and may hold itemTime \(section 8\)/);
  refusedFile(polled((action, poll, step) => { sinceGone(step); poll.step = 'nothing'; }), /list-items v1: poll\.step names nothing, which is not a prepare or perform step of this action/);
  refusedFile(polled((action, poll, step) => { sinceGone(step); poll.step = 'choice:labelId'; }), /list-items v1: poll\.step names choice:labelId, which is not a prepare or perform step of this action/, FIXTURE_DEPS, 'a choice lookup');
  refusedFile(polled((action, poll, step) => { sinceGone(step); action.prepare[0].query = {after: {cursor: 'since'}}; poll.step = 'profile'; }),
    /list-items v1: poll\.items \(\/items\) never reads profile, the poll step: the items a poll sees are the list its poll step reads/);
  // F10.10 flipped this case: a reviewed-read POST built from reads, a poll cursor included, is a read, so it is a poll step (as Notion's
  // row trigger, part k). servesSource goes, since the items source lists through fixture.items.list.
  const search = entryOf(polled((action, poll, step) => {
    Object.assign(step, {method: 'POST', path: '/items/search', body: {object: {kind: {input: '/kind'}, labelIds: step.query.labelIds, after: {cursor: 'since'}}}});
    delete step.query;
    delete step.page;
    delete action.servesSource;
  }));
  assert.deepEqual([search.effect, search.placements.find(placement => placement.stepId === 'list').effect, search.rawAt.list], ['read', 'read', ['/body/after']]);
});

test('part h: items, itemId, itemVersion and itemTime resolve inside the closed output schema, and the item is read only in the poll-item scope (open point Important 4)', () => {
  for (const items of ['/account', '/nothing', '']) refusedFile(polled((action, poll) => { poll.items = items; }), /poll\.items \(.*\) points at a list of objects in outputSchema/, FIXTURE_DEPS, items);
  refusedFile(polled((action, poll) => { poll.items = '/items/0/temp_clone_token'; }), /reads temp_clone_token, a field that carries a secret/);
  refusedFile(polled((action, poll) => {
    action.outputSchema.properties.names = {type: 'array', maxItems: 100, items: {type: 'string', maxLength: 200}};
    action.outputSchema.required.push('names');
    action.output.names = {each: {step: 'list', pointer: ''}, as: 'entry', max: 100, do: {pick: {var: 'entry'}, pointer: '/name'}};
    poll.items = '/names';
  }), /poll\.items \(\/names\) points at a list of objects in outputSchema/, FIXTURE_DEPS, 'a list of strings');
  refusedFile(polled((action, poll) => { poll.itemId = {item: '/nope'}; }), /list-items v1: poll\.itemId: \/nope names no declared field of the value it picks from/);
  refusedFile(polled((action, poll) => { poll.itemId = {item: ''}; }), /list-items v1: poll\.itemId is a string or an integer/);
  refusedFile(polled((action, poll) => { poll.itemId = {step: 'list', pointer: '/0/id'}; }), /poll\.itemId: reads step "list", which has not run before this point/);
  refusedFile(polled((action, poll) => { poll.itemId = {cursor: 'since'}; }), /poll\.itemId: \{cursor: 'since'\} is read only in the poll step/);
  const keyed = entryOf(polled((action, poll) => { poll.itemId = {concat: [{input: '/kind'}, {const: ':'}, {item: '/id'}], max: 200}; }));
  assert.equal(keyed.key, 'list-items');
  for (const itemVersion of ['/nope', '', 7]) refusedFile(polled((action, poll) => { poll.itemVersion = itemVersion; }), /poll\.itemVersion is null or a pointer to a string or integer field of each item/, FIXTURE_DEPS, JSON.stringify(itemVersion));
  assert.equal(entryOf(polled((action, poll) => { poll.itemVersion = null; })).key, 'list-items');
  const itemTime = /poll\.itemTime is \{pointer, format\}: a string field of each item, in one of the formats rfc3339, epoch-ms-string, epoch-seconds and slack-ts, and an integer only for epoch-seconds/;
  for (const change of [{format: 'unix'}, {pointer: '/nope'}, {extra: 1}]) refusedFile(polled((action, poll) => { Object.assign(poll.itemTime, change); }), itemTime, FIXTURE_DEPS, JSON.stringify(change));
  refusedFile(polled((action, poll) => { poll.order = 'random'; }), /poll\.order is asc, desc or unordered/);
});

test('part h check: poll.itemId reads the poll item and never the clock or a job key, so each item keeps one id from poll to poll (section 8)', () => {
  // An id that never reads the item gives every item the same id, so a poll stores one change and drops the rest under its dedupe key.
  const unread = /list-items v1: poll\.itemId reads the poll item: each item's id comes from the item, so two items never share one \(section 8\)/;
  for (const itemId of [{const: 'same'}, {input: '/kind'}, {account: 'id'}, {jobKey: 'poll'}]) refusedFile(polled((action, poll) => { poll.itemId = itemId; }), unread, FIXTURE_DEPS, JSON.stringify(itemId));
  // A job key is new for every job and the clock moves, so an id built from either changes between polls and the same item is stored again.
  const moving = /list-items v1: poll\.itemId never reads the clock or a job key: an item keeps its id from one poll to the next, so each change is stored once \(section 8\)/;
  refusedFile(polled((action, poll) => { poll.itemId = {concat: [{jobKey: 'poll'}, {item: '/id'}], max: 200}; }), moving, FIXTURE_DEPS, 'a job key');
  const stamped = {pick: {transform: 'rfc5322.build@1', args: {from: {const: {address: 'a@example.test'}}, subject: {const: 's'}, text: {const: 't'}, now: {now: {}}}}, pointer: '/raw'};
  refusedFile(polled((action, poll) => { poll.itemId = {concat: [{item: '/id'}, stamped], max: 65_536}; }), moving, FIXTURE_DEPS, 'the clock');
  // The item, alone or beside constants, inputs and the account (each fixed for one subscription), passes.
  for (const itemId of [{item: '/id'}, {pick: {item: ''}, pointer: '/id'}, {concat: [{account: 'id'}, {const: ':'}, {input: '/kind'}, {const: ':'}, {item: '/id'}], max: 2_200}]) {
    assert.equal(entryOf(polled((action, poll) => { poll.itemId = itemId; })).key, 'list-items', JSON.stringify(itemId));
  }
});

test('part h: each cursor names a versioned kind, is never an input, and takes its next value only from the poll step\'s answer, compared by its kind\'s pinned transform', () => {
  const cursor = change => polled((action, poll) => { Object.assign(poll.cursors[0], change); });
  // f109-poll-input: a cursor name that is also an input.
  refusedFile(polled((action, poll, step) => { poll.cursors[0].name = 'kind'; step.query.updatedAfter = {cursor: 'kind'}; }), /poll\.cursors\[0\]\.name kind is also an input: a cursor never comes from an input \(spec line 1663\)/);
  refusedFile(polled((action, poll) => { poll.cursors.push({...poll.cursors[0]}); }), /list-items v1: poll\.cursors names since twice/);
  refusedFile(polled((action, poll, step) => { sinceGone(step); poll.cursors = []; }), /poll\.cursors holds 1 to 4 cursors/);
  refusedFile(cursor({extra: 1}), /poll\.cursors\[0\] is \{name, kind\} and may hold next, compare, lastPageOnly, overlapSeconds and excludes/);
  const kind = /poll\.cursors\[0\]\.kind is one of history-id@1, sync-token@1, high-water-time@1, high-water-ts@1, etag@1, last-modified@1 and snapshot@1: a cursor kind carries its version/;
  for (const value of ['high-water-time', 'high-water-time@2']) refusedFile(cursor({kind: value}), kind, FIXTURE_DEPS, value);
  // An ordered kind names its comparison; one passed back as it came names none.
  const compare = /poll\.cursors\[0\]\.compare names how high-water-time@1 values are ordered: one of time\.rfc3339ToEpochSeconds@1 and time\.decimalCompare@1/;
  refusedFile(polled((action, poll) => { delete poll.cursors[0].compare; }), compare);
  refusedFile(cursor({compare: 'time.slackTs@1'}), compare);
  refusedFile(cursor({compare: 'time.decimalCompare@1'}), /poll\.cursors\[0\]\.compare is time\.rfc3339ToEpochSeconds@1, the transform that orders rfc3339 item times/);
  // next: the poll step's answer, or the latest item time for a high-water mark.
  const next = /poll\.cursors\[0\]\.next is \{step: 'list', pointer\} or \{max: 'itemTime'\}: a cursor value comes only from the poll step's answer \(spec line 1661\)/;
  for (const value of [{step: 'profile', pointer: '/since'}, {step: 'list', header: 'etag'}, {max: 'itemId'}, undefined]) refusedFile(cursor({next: value}), next, FIXTURE_DEPS, JSON.stringify(value));
  refusedFile(cursor({next: {step: 'list', pointer: '/access_token'}}), /reads access_token, a field that carries a secret/);
  refusedFile(polled((action, poll) => { delete poll.itemTime; }), /poll\.cursors\[0\]\.next is the latest item time, so poll\.itemTime is declared/);
  assert.equal(entryOf(cursor({next: {step: 'list', pointer: '/newest'}, compare: 'time.decimalCompare@1'})).key, 'list-items', 'a provider high-water value');
  // Only a high-water mark takes the latest item time.
  refusedFile(polled((action, poll, step) => { poll.cursors.push({name: 'sync', kind: 'sync-token@1', next: {max: 'itemTime'}}); step.query.syncToken = {cursor: 'sync'}; }),
    /poll\.cursors\[1\]\.next is \{step: 'list', pointer\}: a cursor value comes only from the poll step's answer \(spec line 1661\)/);
  // An etag or last-modified cursor is that header of the poll step's answer, and goes back in its conditional header.
  const etag = (change = {}) => polled((action, poll, step) => {
    poll.cursors.push({name: 'tag', kind: 'etag@1', next: {step: 'list', header: 'etag'}, ...change});
    step.headers = {'If-None-Match': {cursor: 'tag'}};
  });
  assert.equal(entryOf(etag()).key, 'list-items');
  for (const change of [{next: {step: 'list', header: 'last-modified'}}, {next: {step: 'list', pointer: '/etag'}}, {next: {step: 'list', header: 'location'}}]) {
    refusedFile(etag(change), /poll\.cursors\[1\]\.next is \{step: 'list', header: 'etag'\}: an etag@1 cursor is the etag the poll step answered/, FIXTURE_DEPS, JSON.stringify(change));
  }
  refusedFile(etag({compare: 'time.decimalCompare@1'}), /poll\.cursors\[1\]: an etag@1 cursor goes back to the provider as it came, so it names no compare/);
  refusedFile(etag({overlapSeconds: 60}), /poll\.cursors\[1\]\.overlapSeconds is 1 to 3,600 seconds, and only on a high-water mark/);
  for (const value of [0, 3601, 1.5]) refusedFile(cursor({overlapSeconds: value}), /poll\.cursors\[0\]\.overlapSeconds is 1 to 3,600 seconds/, FIXTURE_DEPS, String(value));
  // lastPageOnly: only for a value read from the answer of a poll step that pages.
  const lastPage = /lastPageOnly is true or absent, and only for a value read from the answer of a poll step that pages/;
  refusedFile(cursor({lastPageOnly: true}), lastPage, FIXTURE_DEPS, 'the latest item time');
  refusedFile(etag({lastPageOnly: false}), lastPage);
  assert.equal(entryOf(etag({lastPageOnly: true})).key, 'list-items');
  refusedFile(polled((action, poll, step) => { delete step.page; poll.cursors.push({name: 'tag', kind: 'etag@1', next: {step: 'list', header: 'etag'}, lastPageOnly: true}); step.headers = {'If-None-Match': {cursor: 'tag'}}; }), lastPage, FIXTURE_DEPS, 'a step with no pages');
  // A snapshot re-reads the list and compares its ids through collections.diff@1: no next, no slot.
  const snapshot = (change = {}) => polled((action, poll) => { poll.cursors.push({name: 'seen', kind: 'snapshot@1', compare: 'collections.diff@1', ...change}); });
  assert.equal(entryOf(snapshot()).key, 'list-items');
  refusedFile(snapshot({next: {step: 'list', pointer: '/ids'}}), /poll\.cursors\[1\]: a snapshot re-reads the list and compares its ids, so it has no next/);
});

test('part h: each cursor has exactly one {cursor} slot in the poll step, alone where a value can be left out: the query or the body, or an etag\'s or last-modified\'s conditional header', () => {
  refusedFile(polled((action, poll, step) => { sinceGone(step); }), /list-items v1: the cursor since has 0 \{cursor\} slots in the poll step list; a high-water-time@1 cursor has exactly one \(section 8\)/);
  refusedFile(polled((action, poll, step) => { step.query.since = {cursor: 'since'}; }), /the cursor since has 2 \{cursor\} slots in the poll step list/);
  refusedFile(polled((action, poll) => { poll.cursors.push({name: 'seen', kind: 'snapshot@1', compare: 'collections.diff@1'}); action.perform[0].query.seen = {cursor: 'seen'}; }),
    /the cursor seen has 1 \{cursor\} slots in the poll step list; a snapshot@1 cursor has none: it re-reads the list/);
  // f109-poll-slot: never the path; never a guard, the output or another step (part d's grammar).
  refusedFile(polled((action, poll, step) => { sinceGone(step); Object.assign(step, {path: '/labels/{label_id}', params: {label_id: {cursor: 'since'}}}); }), /a cursor sits only in a query, a header or the body of its poll step/);
  refusedFile(polled(action => { action.guards = [{transform: 'collections.oneOf@1', args: {value: {cursor: 'since'}, set: {const: ['a']}, fold: {const: 'none'}}, refuse: 'wrong_state'}]; }), /guards\[0\]\.args\.value: \{cursor: 'since'\} is read only in the poll step/);
  refusedFile(polled(action => { action.output.account = {cursor: 'since'}; }), /output\.account: \{cursor: 'since'\} is read only in the poll step/);
  // Never a transform argument: the slot holds the cursor alone, so an ordinary call leaves it out exactly.
  refusedFile(polled((action, poll, step) => { step.query.updatedAfter = {pick: {transform: 'text.gmailQuery@1', args: {words: {cursor: 'since'}}}, pointer: '/q'}; }),
    /list-items v1: the cursor since is a transform argument: a cursor slot holds the cursor alone, so an ordinary call leaves it out and the engine's value sits at one request position/);
  // The query or the body for most kinds; its conditional header for an etag or last-modified cursor.
  refusedFile(polled((action, poll, step) => { sinceGone(step); step.headers = {'If-Modified-Since': {cursor: 'since'}}; }), /the high-water-time@1 cursor since sits in the query or the body of the poll step, never a header/);
  refusedFile(polled((action, poll, step) => { poll.cursors.push({name: 'tag', kind: 'etag@1', next: {step: 'list', header: 'etag'}}); step.query.tag = {cursor: 'tag'}; }), /the etag@1 cursor tag sits in the If-None-Match header of the poll step/);
  refusedFile(polled((action, poll, step) => { poll.cursors.push({name: 'changed', kind: 'last-modified@1', next: {step: 'list', header: 'last-modified'}}); step.headers = {'If-None-Match': {cursor: 'changed'}}; }),
    /the last-modified@1 cursor changed sits in the If-Modified-Since header of the poll step/);
  // Never at a reserved body field (the proxy's list), and never at or above a body-route pointer (part e).
  refusedFile(polled((action, poll, step) => {
    Object.assign(step, {method: 'POST', path: '/items/search', body: {object: {kind: {input: '/kind'}, labelIds: step.query.labelIds, erase_content: {cursor: 'since'}}}});
    delete step.query;
    delete step.page;
  }), /body\.erase_content: the body writes erase_content, a field fixture reserves/);
  refusedFile(polled((action, poll, step) => { Object.assign(step, {method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/labelId'}}, body: {object: {in_trash: {cursor: 'since'}}}}); sinceGone(step); delete step.page; }),
    /the body's \/in_trash could be present, which routes this step from fixture\.items\.edit to fixture\.items\.delete/);
});

test('part h: a sync token\'s step sends none of the query names it excludes, and resync, the resource key, the filter inputs and the interval are closed', () => {
  const sync = (excludes, change = () => {}) => polled((action, poll, step) => {
    poll.cursors.push({name: 'sync', kind: 'sync-token@1', next: {step: 'list', pointer: '/nextSyncToken'}, lastPageOnly: true, ...(excludes ? {excludes} : {})});
    step.query.syncToken = {cursor: 'sync'};
    change(action, poll, step);
  });
  assert.equal(entryOf(sync(['orderBy', 'q', 'updatedMin'])).key, 'list-items');
  assert.equal(entryOf(sync(undefined)).key, 'list-items');
  // f109-poll-excludes: Calendar's orderBy beside a sync token.
  refusedFile(sync(['orderBy'], (action, poll, step) => { step.query.orderBy = {const: 'startTime'}; }), /list-items v1: the poll step list sends orderBy, which the sync token sync excludes \(section 8\)/);
  refusedFile(sync(['pageToken']), /the poll step list sends pageToken, which the sync token sync excludes/, FIXTURE_DEPS, 'its page parameter');
  for (const excludes of [[], ['a', 'a'], ['a b']]) refusedFile(sync(excludes), /poll\.cursors\[1\]\.excludes lists 1 to 32 distinct query names, and only on a sync token/, FIXTURE_DEPS, JSON.stringify(excludes));
  refusedFile(polled((action, poll) => { poll.cursors[0].excludes = ['orderBy']; }), /poll\.cursors\[0\]\.excludes lists 1 to 32 distinct query names, and only on a sync token/);
  refusedFile(sync(['orderBy'], (action, poll) => { poll.cursors[1].compare = 'time.decimalCompare@1'; }), /poll\.cursors\[1\]: a sync-token@1 cursor goes back to the provider as it came, so it names no compare/);
  // resync: 404, 410, both or neither.
  for (const statusIn of [[500], [404, 404], 'all']) refusedFile(polled((action, poll) => { poll.resync = {statusIn}; }), /poll\.resync is \{statusIn\}, holding 404, 410, both or neither/, FIXTURE_DEPS, JSON.stringify(statusIn));
  assert.equal(entryOf(polled((action, poll) => { poll.resync = {statusIn: [404, 410]}; })).key, 'list-items');
  // The inputs that pick the resource and those that only narrow it: declared inputs, each at most once between the two lists.
  const keys = /poll\.resourceKey and poll\.filterInputs name inputs of the action, each at most once between them/;
  for (const [resourceKey, filterInputs] of [[['kind'], ['kind']], [[], ['kind', 'kind']], [['nothing'], []], ['kind', []]]) {
    refusedFile(polled((action, poll) => { Object.assign(poll, {resourceKey, filterInputs}); }), keys, FIXTURE_DEPS, JSON.stringify([resourceKey, filterInputs]));
  }
  assert.equal(entryOf(polled((action, poll) => { Object.assign(poll, {resourceKey: ['labelId'], filterInputs: ['kind']}); })).key, 'list-items');
  // At least 30 seconds between polls (lib/heartbeat.mjs:13).
  for (const value of [29, 86_401, 60.5]) refusedFile(polled((action, poll) => { poll.minIntervalSeconds = value; }), /poll\.minIntervalSeconds is 30 to 86,400 \(I7\)/, FIXTURE_DEPS, String(value));
  assert.equal(entryOf(polled((action, poll) => { poll.minIntervalSeconds = 30; })).key, 'list-items');
});

test('part h: an ordinary call binds no cursor: without its poll block and cursor slot the action places, runs and reads exactly as with them, and checkRequest() holds a cursor\'s value to a scalar', () => {
  const [list] = validateActionFile(fixtureActions(), FIXTURE_DEPS).actions;
  // Each cursor slot sits alone where a value can be left out, so leaving it out is what an unbound cursor does.
  const plain = entryOf(edited('list-items', action => { delete action.poll; delete action.perform[0].query.updatedAfter; }));
  for (const field of ['effect', 'row', 'placements', 'paths', 'unplaced', 'sensitive', 'twoPhase', 'lookups', 'transforms']) assert.deepEqual(plain[field], list[field], field);
  const {updatedAfter, ...query} = list.action.perform[0].query;
  assert.deepEqual(updatedAfter, {cursor: 'since'});
  assert.deepEqual(plain.action.perform, [{...list.action.perform[0], query}], 'the steps differ only at the slot');
  assert.deepEqual([plain.pollHash, plain.pollTransforms], [null, []]);
  // The cursor's value is a provider value at one request position, held to a scalar as a raw step-data value is.
  assert.deepEqual([list.rawAt.list, plain.rawAt.list], [['/query/updatedAfter'], []]);
  assert.doesNotThrow(() => checkRequest(list, 'list', {query: {kind: 'all', updatedAfter: '2026-10-20T00:00:00Z'}}));
  assert.doesNotThrow(() => checkRequest(list, 'list', {query: {kind: 'all'}}), 'an ordinary call leaves it out');
  assert.throws(() => checkRequest(list, 'list', {query: {kind: 'all', updatedAfter: {in_trash: true}}}), /list-items: list copies a whole provider value at \/query\/updatedAfter/);
});

// ---- F10.10: reviewed reads in actions (docs/F10.10-BUILD-MAP.md section 3) ----------------------------------------------------------
// A POST step on a member its read row lists in reviewedReads is a read when everything it sends, or tests, reads only constants, closed
// inputs, the account, the clock, a resolved schema, a poll cursor and earlier steps that are themselves reads built from reads (I5). The
// four first actions that waited on this step validate as read actions; a member that is not listed, a job key, or a write's answer,
// directly or through another step, in any slot, keeps the step a write.
const RR_LIST = {type: 'array', maxItems: 100, items: closed({id: words(64)})};
const rrIds = (step, pointer = '') => ({each: {step, pointer}, as: 'entry', max: 100, do: {object: {id: {pick: {var: 'entry'}, pointer: '/id'}}}});
const rrRead = (appId, key, fields) => fileOf(appId, [actionOf(appId, key, {effect: 'read', hints: READ_HINTS, ...fields})]);
/** Notion Search (spec line 1441): POST /v1/search from the agent's words, paged through its body cursor; `change` edits the action. */
function notionSearch(change = () => {}) {
  const file = rrRead('notion', 'search', {row: 'notion.search.read', inputSchema: closed({query: words(200)}), outputSchema: closed({pages: RR_LIST}),
    perform: [{id: 'search', method: 'POST', path: '/v1/search', body: {object: {query: {input: '/query'}, page_size: {const: 100}}},
      page: {next: {pointer: '/next_cursor'}, into: {body: '/start_cursor'}, items: '/results', while: '/has_more', max: 3}, expect: OK}],
    output: {pages: rrIds('search')}});
  change(file.actions[0]);
  return file;
}
/** Notion Find rows (spec line 1444): the data source id from an input, or from a prepare read of its database. */
const findRows = throughDatabase => rrRead('notion', 'find-rows', {row: 'notion.content.read', inputSchema: closed(throughDatabase ? {databaseId: words(36)} : {dataSourceId: words(36)}),
  outputSchema: closed({rows: RR_LIST}),
  prepare: throughDatabase ? [{id: 'database', method: 'GET', path: '/v1/databases/{database_id}', params: {database_id: {input: '/databaseId'}}, expect: OK}] : [],
  perform: [{id: 'rows', method: 'POST', path: '/v1/data_sources/{data_source_id}/query',
    params: {data_source_id: throughDatabase ? {step: 'database', pointer: '/data_sources/0/id'} : {input: '/dataSourceId'}}, body: {object: {page_size: {const: 100}}}, expect: OK}],
  output: {rows: rrIds('rows', '/results')}});
/** Calendar Find free time (spec line 1318), placed through F10.7's synthetic map (Google's own paths are not recorded yet). */
const freeTime = () => rrRead('google-calendar', 'find-free-time', {row: 'google-calendar.availability.read', inputSchema: closed({calendarId: words(200), from: words(64), to: words(64)}),
  outputSchema: closed({kind: words(64)}),
  perform: [{id: 'free', method: 'POST', path: '/freebusy/query', body: {object: {timeMin: {input: '/from'}, timeMax: {input: '/to'}, items: {array: [{object: {id: {input: '/calendarId'}}}]}}}, expect: OK}],
  output: {kind: {step: 'free', pointer: '/kind'}}});
/** Slack Read a canvas (spec line 1521): an RPC POST listed in slack.files.read. */
function readCanvas(change = () => {}) {
  const file = rrRead('slack', 'read-canvas', {row: 'slack.files.read', inputSchema: closed({canvasId: words(64)}), outputSchema: closed({title: words(200)}),
    perform: [{id: 'canvas', method: 'POST', path: '/canvases.getContent', body: {object: {canvas_id: {input: '/canvasId'}}}, expect: SLACK_OK}],
    output: {title: {step: 'canvas', pointer: '/title'}}});
  change(file.actions[0]);
  return file;
}

test('F10.10: the four first actions that waited on reviewed reads validate as read actions: Notion Search and Find rows, Calendar Find free time and Slack Read a canvas', () => {
  for (const [label, file] of [['Notion Search', notionSearch()], ['Notion Find rows by its data source id', findRows(false)], ['Notion Find rows through its database', findRows(true)],
    ['Calendar Find free time', freeTime()], ['Slack Read a canvas', readCanvas()]]) {
    const entry = entryOf(file, APP_DEPS), counted = entry.placements.filter(placement => placement.phase === 'prepare' || placement.phase === 'perform');
    assert.deepEqual([entry.effect, entry.unplaced, entry.action.hints], ['read', false, READ_HINTS], label);
    assert.ok(counted.length && counted.every(placement => placement.effect === 'read' && placement.fromReads === true), label);
    assert.equal(actionCapability(file, entry).effect, 'read', label);
  }
  const placed = file => entryOf(file, APP_DEPS).placements.at(-1);
  assert.deepEqual(['member', 'groupId', 'reviewedRead'].map(key => placed(notionSearch())[key]), ['POST /v1/search', 'notion.search.read', true]);
  assert.deepEqual(['member', 'groupId', 'reviewedRead'].map(key => placed(findRows(true))[key]), ['POST /v1/data_sources/{data_source_id}/query', 'notion.content.read', true]);
  assert.deepEqual(['member', 'groupId', 'reviewedRead'].map(key => placed(freeTime())[key]), ['calendar.freebusy.query', 'google-calendar.availability.read', true]);
  assert.deepEqual(['member', 'groupId', 'reviewedRead'].map(key => placed(readCanvas())[key]), ['POST /canvases.getContent', 'slack.files.read', true]);
  // Without Calendar's map the step is unplaced, and the fail-closed floor still refuses it declared read (open question 7).
  refusedFile(freeTime(), /find-free-time v1: declares effect read, but its methods say at least write \(spec line 750\)/, {...APP_DEPS, maps: new Map()});
});

test('F10.10 adversarial: a POST its read row does not list in reviewedReads stays a write, whatever it reads', () => {
  refusedFile(rrRead('notion', 'query-view', {row: 'notion.content.read', inputSchema: closed({viewId: words(36)}), outputSchema: closed({rows: RR_LIST}),
    perform: [{id: 'rows', method: 'POST', path: '/v1/views/{view_id}/queries', params: {view_id: {input: '/viewId'}}, body: {object: {page_size: {const: 100}}}, expect: OK}],
    output: {rows: rrIds('rows', '/results')}}), /query-view v1: declares effect read, but its steps compute write \(spec line 750\)/, APP_DEPS);
  refusedFile(edited('list-items', action => {
    action.perform[0] = {id: 'list', method: 'POST', path: '/items/export', body: {object: {kind: {input: '/kind'}, label: {input: '/labelId'}}}, expect: OK};
    delete action.poll;
  }), /list-items v1: declares effect read, but its steps compute write/);
});

/** Slack: open a direct message (the resolving write), read a canvas by the channel it answered, then post; `later` is the post's channel. */
const canvasAfterOpen = later => fileOf('slack', [actionOf('slack', 'open-canvas', {effect: 'write', row: 'slack.messages.send', hints: WRITE_HINTS,
  inputSchema: closed({user: words(64), text: words(4000)}), outputSchema: closed({channel: words(64), ts: words(64)}),
  perform: [
    {id: 'open', method: 'POST', path: '/conversations.open', body: {object: {users: {input: '/user'}}}, resolves: true, expect: {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}, {present: {pointer: '/channel/id'}}]}},
    {id: 'canvas', method: 'POST', path: '/canvases.getContent', body: {object: {canvas_id: {step: 'open', pointer: '/channel/id'}}}, expect: SLACK_OK},
    {id: 'post', method: 'POST', path: '/chat.postMessage', body: {object: {channel: later, text: {pick: {transform: 'text.slackEscape@1', args: {text: {input: '/text'}}}, pointer: '/text'}}}, expect: SLACK_OK}],
  verify: {requests: [{id: 'link', method: 'GET', path: '/chat.getPermalink', query: {channel: {step: 'post', pointer: '/channel'}, message_ts: {step: 'post', pointer: '/ts'}}, expect: SLACK_OK}],
    identity: [{kind: 'readback', step: 'link', pointer: '/channel', equals: {step: 'post', pointer: '/channel'}}], assert: []},
  output: {channel: {step: 'post', pointer: '/channel'}, ts: {step: 'post', pointer: '/ts'}}})]);

test('F10.10 adversarial: a reviewed-read POST fed by a write\'s answer, in any slot, is a write, and its own answer is a write\'s', () => {
  // The body reads the perform write's answer: a verify request is a read, so it is refused.
  refusedFile(edited('update-item', action => { action.verify.requests[0] = {id: 'check', method: 'POST', path: '/items/search', body: {object: {id: {step: 'rename', pointer: '/id'}}}, expect: OK}; }),
    /update-item v1: verify\.requests\[0\] \(check\): a verify request is a read in a read row \(spec line 748\)/);
  // Every slot counts: here only the path parameter reads the write's answer, and the body is a constant.
  const notionEdit = parameter => fileOf('notion', [actionOf('notion', 'edit-page', {effect: 'write', row: 'notion.content.edit', hints: WRITE_HINTS,
    inputSchema: closed({pageId: words(36), dataSourceId: words(36)}), outputSchema: closed({id: words(64)}),
    perform: [{id: 'edit', method: 'PATCH', path: '/v1/pages/{page_id}', params: {page_id: {input: '/pageId'}}, body: {object: {icon: {const: null}}}, expect: OK}],
    verify: {requests: [{id: 'check', method: 'POST', path: '/v1/data_sources/{data_source_id}/query', params: {data_source_id: parameter}, body: {object: {page_size: {const: 1}}}, expect: OK}],
      identity: [{kind: 'readback', step: 'check', pointer: '/results/0/id', equals: {input: '/pageId'}}], assert: []},
    output: {id: {step: 'edit', pointer: '/id'}}})]);
  refusedFile(notionEdit({step: 'edit', pointer: '/parent/data_source_id'}), /edit-page v1: verify\.requests\[0\] \(check\): a verify request is a read in a read row/, APP_DEPS);
  // A perform canvases.getContent that reads the resolving write's answer is a write, so its own answer is a write step's (T5).
  const [open] = validate(canvasAfterOpen({step: 'open', pointer: '/channel/id'}), APP_DEPS).actions;
  assert.deepEqual(open.placements.map(placement => [placement.stepId, placement.groupId, placement.effect]), [['open', 'slack.conversations.mark', 'write'], ['canvas', 'slack.files.read', 'write'],
    ['post', 'slack.messages.send', 'write'], ['link', 'slack.messages.read', 'read']]);
  refusedFile(canvasAfterOpen({step: 'canvas', pointer: '/channel_id'}), /open-canvas v1: perform\[2\] \(post\): body reads a write step's answer, which a perform step's bytes never read/, APP_DEPS);
});

test('F10.10 adversarial: transitive: a verify read of the written id is not built from reads, so a reviewed-read POST fed by it is a write; one from inputs only is a read', () => {
  refusedFile(edited('add-row', action => { action.verify.requests.push({id: 'found', method: 'POST', path: '/items/search', body: {object: {id: {step: 'check', pointer: '/id'}}}, expect: OK}); }),
    /add-row v1: verify\.requests\[1\] \(found\): a verify request is a read in a read row \(spec line 748\)/);
  const found = entryOf(edited('add-row', action => { action.verify.requests.push({id: 'found', method: 'POST', path: '/items/search', body: {object: {id: {input: '/tableId'}}}, expect: OK}); }));
  assert.deepEqual(['phase', 'groupId', 'effect', 'fromReads'].map(key => found.placements.find(placement => placement.stepId === 'found')[key]), ['verify', 'fixture.items.read', 'read', true]);
});

test('F10.10 adversarial: a job key in a reviewed-read POST makes it a write: in prepare, in a read action and as a poll step', () => {
  const key = {jobKey: 'search'};
  refusedFile(edited('update-item', action => { action.prepare[0] = {id: 'item', method: 'POST', path: '/items/search', body: {object: {id: {input: '/itemId'}, key}}, expect: OK}; }),
    /update-item v1: prepare\[0\] \(item\): a prepare step is a read \(spec line 711\), and POST \/items\/search is a write/);
  refusedFile(edited('list-items', action => {
    action.perform[0] = {id: 'list', method: 'POST', path: '/items/search', body: {object: {kind: {input: '/kind'}, label: {input: '/labelId'}, key}}, expect: OK};
    delete action.poll;
    delete action.servesSource;
  }), /list-items v1: declares effect read, but its steps compute write \(spec line 750\)/);
  refusedFile(polled((action, poll, step) => {
    Object.assign(step, {method: 'POST', path: '/items/search', body: {object: {kind: {input: '/kind'}, labelIds: step.query.labelIds, after: {cursor: 'since'}, key}}});
    delete step.query;
    delete step.page;
    delete action.servesSource;
  }), /list-items v1: poll\.step list's computed effect is write: a poll step is a read, and a reviewed-read POST is a read only when everything it sends is built from reads \(F10\.10, I5\)/);
});

test('F10.10: a prepare or schema step may be a reviewed-read POST built from reads (F10.9 refused both), and its answer is labelled as its phase', () => {
  const prepared = entryOf(edited('update-item', action => {
    action.prepare[0] = {id: 'item', method: 'POST', path: '/items/search', body: {object: {id: {input: '/itemId'}}}, expect: OK};
    // A perform step's bytes may read a prepare step's answer, never another perform step's, so this shows the label is prepare.
    action.perform[0].body.object.title = {step: 'item', pointer: '/title'};
  }));
  assert.deepEqual(['phase', 'effect', 'fromReads'].map(key => prepared.placements.find(placement => placement.stepId === 'item')[key]), ['prepare', 'read', true]);
  const schema = entryOf(edited('add-row', action => {
    action.resolvedInputs[0].schema.steps[0] = {id: 'table', method: 'POST', path: '/items/search', body: {object: {id: {input: '/tableId'}}}, expect: OK};
  }));
  assert.deepEqual(['phase', 'effect'].map(key => schema.placements.find(placement => placement.stepId === 'table')[key]), ['schema', 'read']);
});

/** list-items reading POST /items/search, paged into its body at `into`; the poll block and servesSource go. */
const searchPaged = (into, body = {object: {kind: {input: '/kind'}, label: {input: '/labelId'}}}) => edited('list-items', action => {
  delete action.poll;
  delete action.servesSource;
  action.perform[0] = {id: 'list', method: 'POST', path: '/items/search', body, page: {next: {pointer: '/next'}, into: {body: into}, items: '/items', max: 3}, expect: OK};
});

test('F10.10: a paged reviewed read sends the provider\'s next cursor at a body field it does not write, never a reserved field, never the body itself and never at a body route', () => {
  const paged = entryOf(searchPaged('/cursor'));
  assert.deepEqual([paged.effect, paged.rawAt.list], ['read', ['/body/cursor']], 'the cursor position is held to a scalar at run time');
  // A key the step's body writes, at its top level or below it, on any branch.
  for (const pointer of ['/kind', '/kind/next', '/label']) refusedFile(searchPaged(pointer), new RegExp(`list-items v1: perform\\[0\\] \\(list\\)\\.page\\.into: ${pointer.replace(/\//g, '\\/')} lands on ${pointer.split('/')[1]}, a key the step's body writes: the provider's next cursor never replaces what the step sends \\(F10\\.10\\)`), FIXTURE_DEPS, pointer);
  refusedFile(searchPaged('/scope', {object: {kind: {input: '/kind'}, label: {input: '/labelId'}, scope: {when: {present: {input: '/labelId'}}, then: {const: 'all'}}}}),
    /page\.into: \/scope lands on scope, a key the step's body writes/, FIXTURE_DEPS, 'a key the body writes only sometimes');
  const either = into => edited('list-items', action => {
    delete action.poll;
    delete action.servesSource;
    action.prepare[0].maxResponseBytes = 65_536;
    action.prepare.push({id: 'labels', method: 'GET', path: '/labels', when: {present: {input: '/labelId'}}, maxResponseBytes: 65_536, expect: OK});
    action.perform[0] = {id: 'list', method: 'POST', path: '/items/search', body: {either: [{object: {kind: {input: '/kind'}, scope: {step: 'labels', pointer: '/id'}}}, {object: {kind: {input: '/kind'}, label: {input: '/labelId'}}}]},
      page: {next: {pointer: '/next'}, into: {body: into}, items: '/items', max: 3}, expect: OK};
  });
  refusedFile(either('/scope'), /page\.into: \/scope lands on scope, a key the step's body writes/, FIXTURE_DEPS, 'a key on one branch of an either');
  assert.deepEqual(entryOf(either('/cursor')).rawAt.list, ['/body/scope', '/body/cursor'], 'the same body paged into a field it never writes');
  refusedFile(searchPaged('/kind', {const: {kind: 'all'}}), /page\.into: \/kind lands on kind, a key the step's body writes/, FIXTURE_DEPS, 'a constant body');
  // A reserved field, or the body itself.
  refusedFile(searchPaged('/erase_content'), /perform\[0\] \(list\)\.page\.into: \/erase_content names a body field the app reserves, or the body itself\./);
  refusedFile(searchPaged('/next/erase_content'), /page\.into: \/next\/erase_content names a body field the app reserves, or the body itself\./, FIXTURE_DEPS, 'at any depth');
  refusedFile(searchPaged(''), /perform\[0\] \(list\)\.page\.into:  names a body field the app reserves, or the body itself\./);
  refusedFile(notionSearch(action => { action.perform[0].page.into.body = '/in_trash'; }), /search v1: perform\[0\] \(search\)\.page\.into: \/in_trash names a body field the app reserves, or the body itself\./, APP_DEPS);
  refusedFile(notionSearch(action => { action.perform[0].page.into.body = '/query'; }), /search v1: perform\[0\] \(search\)\.page\.into: \/query lands on query, a key the step's body writes/, APP_DEPS);
  refusedFile(readCanvas(action => { action.perform[0].page = {next: {pointer: '/next'}, into: {body: '/token'}, items: '/items', max: 2}; }), /token/, APP_DEPS, 'Slack token');
  // A GET has no body to page into.
  refusedFile(edited('list-items', action => { action.perform[0].page.into = {body: '/cursor'}; }), /list-items v1: perform\[0\] \(list\)\.page\.into: a GET has no body: it pages into the query\./);
  // On, above or below a body-route pointer of the step's member: a route reads the body as sent, so the cursor never decides the row.
  const rows = fixtureRows();
  rows.groups.find(group => group.id === 'fixture.items.read').bodyRoutes = [{member: 'POST /items/search', pointer: '/scope', equals: 'all', to: 'fixture.keys.read'},
    {member: 'POST /items/search', pointer: '/filter/state', equals: 'hidden', to: 'fixture.keys.read'}];
  const routed = {...FIXTURE_DEPS, groups: new Map([...FIXTURE_DEPS.groups, ['fixture', validatePermissionGroups(rows)]])};
  for (const [pointer, route] of [['/scope', '/scope'], ['/scope/next', '/scope'], ['/filter', '/filter/state'], ['/filter/state', '/filter/state']]) {
    refusedFile(searchPaged(pointer), new RegExp(`page\\.into: ${pointer.replace(/\//g, '\\/')} sits on, above or below ${route.replace(/\//g, '\\/')}, which fixture\\.items\\.read routes to fixture\\.keys\\.read: the provider's next cursor never decides where a step lands \\(spec line 738\\)`), routed, pointer);
  }
  assert.deepEqual(entryOf(searchPaged('/cursor'), routed).rawAt.list, ['/body/cursor'], 'beside the routes');
  // Notion Search records its body cursor, and checkRequest() holds a provider's next cursor there to a scalar (I6, T4).
  const search = entryOf(notionSearch(), APP_DEPS);
  assert.deepEqual(search.rawAt.search, ['/body/start_cursor']);
  assert.doesNotThrow(() => checkRequest(search, 'search', {body: {query: 'plans', page_size: 100, start_cursor: 'c-2'}}));
  assert.doesNotThrow(() => checkRequest(search, 'search', {body: {query: 'plans', page_size: 100}}), 'the first page sends none');
  assert.throws(() => checkRequest(search, 'search', {body: {query: 'plans', start_cursor: {id: 'x', in_trash: true}}}), /search: search copies a whole provider value at \/body\/start_cursor/);
});

// F10.10 check: the keys a body writes include those of a whole input or a transform result, which their closed schemas name, and a body
// whose keys are not known on some branch (a scalar, a list, an outputMap result) has no field the provider's next cursor may take.
/** list-items reading POST /items/search with both inputs in its query, so its body may be any value, paged into the body at `into`. */
const searchAnyBody = (body, into, change = () => {}) => edited('list-items', action => {
  delete action.poll;
  delete action.servesSource;
  change(action);
  action.perform[0] = {id: 'list', method: 'POST', path: '/items/search', query: {kind: {input: '/kind'}, label: {input: '/labelId'}}, body,
    page: {next: {pointer: '/next'}, into: {body: into}, items: '/items', max: 3}, expect: OK};
});
/** list-items whose body is the whole input q, a closed object that declares kind and cursor, or an {either} of a built object and q. */
const wholeInput = (into, either = false) => edited('list-items', action => {
  delete action.poll;
  delete action.servesSource;
  delete action.choices;
  action.inputSchema = closed({q: closed({kind: words(64), cursor: words(64)}, ['kind']), labelId: words(64)}, ['q']);
  action.preview = [{label: 'Show', expr: {input: '/q/kind'}}];
  if (either) {
    action.prepare[0].maxResponseBytes = 65_536;
    action.prepare.push({id: 'labels', method: 'GET', path: '/labels', when: {present: {input: '/labelId'}}, maxResponseBytes: 65_536, expect: OK});
  } else action.inputSchema = closed({q: action.inputSchema.properties.q});
  action.perform[0] = {id: 'list', method: 'POST', path: '/items/search', body: either ? {either: [{object: {scope: {step: 'labels', pointer: '/id'}}}, {input: '/q'}]} : {input: '/q'},
    page: {next: {pointer: '/next'}, into: {body: into}, items: '/items', max: 3}, expect: OK};
});

test('F10.10 check: a whole input or a transform result writes the keys its closed schema names, so the provider\'s next cursor never lands on one', () => {
  const lands = (pointer, key) => new RegExp(`list-items v1: perform\\[0\\] \\(list\\)\\.page\\.into: ${pointer.replace(/\//g, '\\/')} lands on ${key}, a key the step's body writes: the provider's next cursor never replaces what the step sends \\(F10\\.10\\)`);
  // The whole input q declares cursor, so the cursor would replace the agent's own value on the second page.
  refusedFile(wholeInput('/cursor'), lands('/cursor', 'cursor'), FIXTURE_DEPS, 'a key the whole input declares');
  refusedFile(wholeInput('/cursor', true), lands('/cursor', 'cursor'), FIXTURE_DEPS, 'a key the input declares on one branch of an either');
  assert.deepEqual(entryOf(wholeInput('/after')).rawAt.list, ['/body/after'], 'a key the input does not declare');
  assert.deepEqual(entryOf(wholeInput('/after', true)).rawAt.list, ['/body/scope', '/body/after']);
  // text.truncate's closed output declares text and truncated.
  const truncated = {transform: 'text.truncate@1', args: {text: {input: '/labelId'}, max: {const: 100}}};
  for (const key of ['text', 'truncated']) refusedFile(searchAnyBody(truncated, `/${key}/more`), lands(`/${key}/more`, key), FIXTURE_DEPS, key);
  assert.deepEqual(entryOf(searchAnyBody(truncated, '/cursor')).rawAt.list, ['/body/cursor']);
});

test('F10.10 check: a body whose keys are not known on every branch (a scalar, a list, an outputMap result) has no field for the provider\'s next cursor', () => {
  const unknown = /list-items v1: perform\[0\] \(list\)\.page\.into: \/cursor takes a field of the body, so the body is an object whose keys are known on every branch: built in the file, or a whole input or transform result of a closed object schema \(F10\.10\)/;
  const pairs = action => { action.inputSchema.properties.pairs = {type: 'array', maxItems: 100, items: closed({name: words(100), value: {type: 'string', maxLength: 1000}})}; };
  const skippable = action => {
    action.prepare[0].maxResponseBytes = 65_536;
    action.prepare.push({id: 'labels', method: 'GET', path: '/labels', when: {present: {input: '/labelId'}}, maxResponseBytes: 65_536, expect: OK});
  };
  for (const [label, body, change] of [
    ['a constant string', {const: 'all'}], ['a constant list', {const: ['all']}], ['a list', {array: [{input: '/kind'}]}], ['a string input', {input: '/kind'}],
    ['a string picked from a transform result', {pick: {transform: 'ids.slackLink@1', args: {link: {input: '/labelId'}}}, pointer: '/parent'}],
    ['an outputMap result, whose keys come at run time', {transform: 'collections.stringValues@1', args: {values: {input: '/pairs'}}}, pairs],
    ['an {either} of two strings', {either: [{concat: [{step: 'labels', pointer: '/id'}], max: 64}, {input: '/kind'}]}, skippable],
  ]) refusedFile(searchAnyBody(body, '/cursor', change), unknown, FIXTURE_DEPS, label);
  // A POST with no body takes the cursor as its one field.
  assert.deepEqual(entryOf(edited('list-items', action => {
    delete action.poll;
    delete action.servesSource;
    action.perform[0] = {id: 'list', method: 'POST', path: '/items/search', query: {kind: {input: '/kind'}, label: {input: '/labelId'}}, page: {next: {pointer: '/next'}, into: {body: '/cursor'}, items: '/items', max: 3}, expect: OK};
  })).rawAt.list, ['/body/cursor']);
});

test('F10.10 check: readsOnly() reads only READ_SOURCES and step answers, each judged by its step id: a job key and the four registration names are never reads', () => {
  assert.deepEqual(READ_SOURCES, ['constant', 'input', 'account', 'clock', 'cursor', 'resolved']);
  assert.ok(Object.isFrozen(READ_SOURCES));
  assert.deepEqual(SOURCES.filter(source => !READ_SOURCES.includes(source) && !STEP_SOURCES.includes(source)), ['jobKey', ...REGISTRATION_NAMES], 'every other source is named here');
  const fact = (sources, steps = []) => ({sources: new Set(sources), steps: new Set(steps)});
  for (const source of READ_SOURCES) assert.equal(readsOnly(fact(['constant', source]), () => false), true, source);
  for (const source of ['jobKey', ...REGISTRATION_NAMES]) assert.equal(readsOnly(fact(['constant', source]), () => true), false, source);
  // A step's answer counts by its id alone, whatever its label says.
  for (const source of STEP_SOURCES) {
    assert.equal(readsOnly(fact([source], ['a']), id => id === 'a'), true, source);
    assert.equal(readsOnly(fact([source], ['a', 'b']), id => id === 'a'), false, source);
  }
});

// ---- part l: the action schema (schemas/action.schema.json) ---------------------------------------------------------------------------
// The schema documents the format for editors and reviewers; validateActionFile() stays the authority. Every file this suite accepted
// above (validate() keeps each), and the fixture file, must pass it; a file the schema does not describe fails it. Run on its own, this
// test still checks the fixture file.
test('part l: the fixture action file and every action file this suite accepts pass schemas/action.schema.json under ajv; a file the schema does not describe fails it', () => {
  const check = actionSchema();
  for (const [index, file] of [fixtureActions(), ...ACCEPTED].entries()) assert.ok(check(file), `file ${index} (${file?.appId}): ${JSON.stringify(check.errors?.slice(0, 3))}`);
  const node = (key, node) => edited(key, action => { action.output[Object.keys(action.output)[0]] = node; });
  for (const [label, file] of [
    ['an unknown file field', {...fixtureActions(), extra: 1}],
    ['an unknown action field', edited('list-items', action => { action.extra = 1; })],
    ['an id of another shape', edited('list-items', action => { action.id = 'fixture.list-items.f4275b116c7968cfc43f563d'; })],
    ['openWorld false', edited('list-items', action => { action.hints.openWorld = false; })],
    ['an unknown step field', edited('list-items', action => { action.perform[0].retries = 2; })],
    ['a method outside the five', edited('list-items', action => { action.perform[0].method = 'HEAD'; })],
    ['a forEach over 25', edited('remove-labels', action => { action.perform[0].forEach.max = 26; })],
    ['a header outside the caller headers', edited('list-items', action => { action.perform[0].headers = {Authorization: {const: 'Bearer x'}}; })],
    ['an expression with an unknown key', node('list-items', {query: '/kind'})],
    ['a node with an extra key', node('list-items', {step: 'profile', pointer: '/name', extra: 1})],
    ['a trigger registration name in an action', node('list-items', {receiver: 'fixture'})],
    ['an each over 100', node('list-items', {each: {step: 'list', pointer: ''}, as: 'entry', max: 101, do: {pick: {var: 'entry'}, pointer: '/id'}})],
    ['a test nested in an unknown key', edited('update-item', action => { action.prepare[1].when = {either: [{input: '/change'}]}; })],
    ['an assertion of two kinds', edited('update-item', action => { action.verify.assert.push({step: 'check', present: {pointer: '/id'}, absent: {pointer: '/name'}}); })],
    ['a cursor kind without its version', edited('list-items', action => { action.poll.cursors[0].kind = 'high-water-time'; })],
    ['a malformed superseded id', {...fixtureActions(), superseded: [{...fixtureActions().superseded[0], id: 'fixture.action.list-items.v1.short'}]}],
  ]) assert.equal(check(file), false, label);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {AppDetailService} from '../lib/app-detail.mjs';
import {OAuth2Provider} from '../lib/providers/oauth2.mjs';
import {Vault} from '../lib/vault.mjs';
import {validateAuthDefinition} from '../contracts/auth-definition.mts';
import {actionHarness, certifiedFile, EVIDENCE} from './fixtures/actions/runtime-fixture.mjs';
import {fixtureActions, fixtureSignIn} from './fixtures/actions/fixture-app.mjs';
import {REST_ORIGIN} from './fixtures/provider-simulators/fixture.mjs';

// F10.11 part k (docs/F10.11-BUILD-MAP.md part k, section 3): actions on the owner's rows. Only an active action joins a row, in its
// declared row or its sensitive row; proxy members still join a row that holds actions, and its access, working and total stay theirs.
// setRow() writes each action's record after a catalog check of every action in the row (all or nothing) and never promotes one. The
// upgrade card, the callback wall, the not-granted notice, Add access and rowsNeeding() read an action's steps through one helper.
// Run on the fake app's run harness (test/fixtures/actions/runtime-fixture.mjs): nothing here sends a request.

const OK = {status: [200], require: []};
const closed = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
/** Trash an item: PATCH /items/{item_id} with in_trash, which a body route of fixture.items.edit moves to fixture.items.delete, so its
 *  last perform step lands in its declared row while its member lives in another (test/actions-permissions.test.mjs has the same). */
const trashItem = () => ({id: `fixture.action.trash-item.v1.${'0'.repeat(24)}`, key: 'trash-item', version: 1, name: 'Trash an item', description: 'Moves one item to the trash.',
  effect: 'delete', row: 'fixture.items.delete', hints: {readOnly: false, destructive: true, idempotent: false, openWorld: true}, guards: [], prepare: [], definitive: [400],
  inputSchema: closed({itemId: {type: 'string', minLength: 1, maxLength: 64}}), outputSchema: closed({id: {type: 'string', maxLength: 64}}),
  perform: [{id: 'trash', method: 'PATCH', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, body: {object: {in_trash: {const: true}}}, expect: OK}],
  verify: {requests: [{id: 'check', method: 'GET', path: '/items/{item_id}', params: {item_id: {input: '/itemId'}}, expect: OK}],
    identity: [{kind: 'readback', step: 'check', pointer: '/id', equals: {input: '/itemId'}}], assert: []},
  output: {id: {step: 'trash', pointer: '/id'}}, preview: [{label: 'Item', expr: {input: '/itemId'}}], certified: {evidence: EVIDENCE, definitionHash: '0'.repeat(64)}});
const ZONE = {either: [{step: 'zone', pointer: '/value'}, {step: 'primary', pointer: '/name'}]};
/** Find with an optional read (R7): GET /keys is optional, GET /labels is its fallback. */
const findWithZone = () => ({id: `fixture.action.find-with-zone.v1.${'0'.repeat(24)}`, key: 'find-with-zone', version: 1, name: 'Find with a zone', description: 'Lists items in a zone.',
  effect: 'read', row: 'fixture.items.read', hints: {readOnly: true, destructive: false, idempotent: true, openWorld: true}, guards: [], definitive: [400],
  inputSchema: closed({kind: {type: 'string', enum: ['all', 'open']}}), outputSchema: closed({zone: {type: 'string', maxLength: 100}}),
  prepare: [{id: 'zone', method: 'GET', path: '/keys', optional: true, expect: OK}, {id: 'primary', method: 'GET', path: '/labels', fallbackFor: 'zone', expect: OK}],
  perform: [{id: 'list', method: 'GET', path: '/items', query: {kind: {input: '/kind'}, zone: ZONE}, expect: OK}], output: {zone: ZONE}, preview: [{label: 'Show', expr: {input: '/kind'}}],
  certified: {evidence: EVIDENCE, definitionHash: '0'.repeat(64)}});
/** The fixture file, reviewed and certified, with the two extra actions. */
const withExtra = () => certifiedFile(file => { file.actions.push(trashItem(), findWithZone()); });
/** Rows that say what their members need: reading items needs fixture:read (or the broad fixture:all), editing them fixture:edit,
 *  deleting them fixture:delete, and keys fixture:keys. */
const SCOPED = rows => ({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.read' ? {...group, scopeSets: [['fixture:read'], ['fixture:all']]}
  : group.id === 'fixture.items.edit' ? {...group, scopeSets: [['fixture:edit']]} : group.id === 'fixture.items.delete' ? {...group, scopeSets: [['fixture:delete']]}
  : group.id === 'fixture.keys.read' ? {...group, scopeSets: [['fixture:keys']]} : group)});
/** A sign-in that can ask for each of them: fixture:read always (so the fallback of an optional step needs only it, R7), the others as
 *  optional scopes, and fixture:edit only in the context of the Edit items row, so it is usable on that row and no other. */
function scopedSignIn() {
  const definition = structuredClone(fixtureSignIn());
  definition.apps[0].access.levels.full = {required: ['fixture:read'], optional: ['fixture:all', 'fixture:keys', 'fixture:delete'], inContext: [{scope: 'fixture:edit', rows: ['fixture.items.edit']}]};
  return validateAuthDefinition(definition);
}
/** One ready OAuth account on the fake app holding `scopes`, stored. */
function oauthAccount(h, scopes, id = 'fixture-oauth') {
  h.store.put('connections', {id, appId: 'fixture', providerId: 'fixture', driver: 'http', authMethod: 'oauth', authRevision: 'o1', signInRevision: 's1', status: 'ready', label: 'Fixture',
    identity: {id: 'acct-2'}, allowedOrigins: [REST_ORIGIN], scopes, createdAt: '2026-10-23T09:00:00.000Z'});
  return h.store.get('connections', id);
}
function service(h, provider = null) {
  return new AppDetailService({store: h.store, runtime: h.runtime, catalog: () => [{id: 'fixture', name: 'Fixture'}], accessLevels: () => [], accessLevelOf: () => 'custom', oauthProviderFor: () => provider});
}
const keyOf = h => id => h.catalog.entries.get(id)?.entry.key ?? id;
const actionKeys = (h, row) => row.members.filter(member => member.capability).map(member => keyOf(h)(member.capability.id)).sort();
const byId = rows => new Map(rows.map(row => [row.id, row]));
const pick = (view, names) => Object.fromEntries(names.filter(name => Object.hasOwn(view, name)).map(name => [name, view[name]]));
const ACCESS = ['access', 'accessReason', 'working', 'total', 'addAccess', 'addBlocked'];

test('part k: an active action joins its declared row; proxy members still join; access, working and total stay the provider members\'; only rows that gain an action move their etag', t => {
  const h = actionHarness(t, {file: withExtra(), rows: SCOPED, signIn: scopedSignIn()}), app = service(h), account = h.store.get('connections', h.account);
  const joined = byId(app.rows({id: 'fixture'}, account));
  // The same account with no catalog: no action can run, so none is on a row, and each row is what it was before step 11.
  h.permissions.actions = null;
  const before = byId(app.rows({id: 'fixture'}, account));
  h.permissions.actions = h.catalog;
  assert.deepEqual(Object.fromEntries([...joined].map(([id, row]) => [id, actionKeys(h, row)])), {
    'fixture.items.read': ['find-with-zone', 'list-items'], 'fixture.keys.read': [], 'fixture.labels.write': [], 'fixture.items.edit': ['add-row', 'update-item'],
    'fixture.messages.send': ['put-file', 'reschedule-event', 'send-draft'],
    // Trash an item lands in its declared row, fixture.items.delete, though the member its step sends is fixture.items.edit's.
    'fixture.items.delete': ['remove-labels', 'trash-item'], 'fixture.access.grant': []});
  assert.deepEqual([...before.values()].map(row => actionKeys(h, row).length), [0, 0, 0, 0, 0, 0, 0]);
  for (const [id, row] of joined) {
    assert.deepEqual(row.members.filter(member => !member.capability).map(member => member.member), before.get(id).members.map(member => member.member), `${id}: every provider member still joins`);
    assert.deepEqual(pick(row.view, ACCESS), pick(before.get(id).view, ACCESS), `${id}: access, working and total are the provider members'`);
    assert.equal(row.view.etag === before.get(id).view.etag, actionKeys(h, row).length === 0, `${id}: the etag moves only when the row gained an action`);
    assert.equal(row.view.reviewRequired, false, `${id}: no candidate is on a row`);
  }
  // A row with an unavailable member keeps counting its provider members only: 10 of 11 work, the actions not counted.
  assert.deepEqual(pick(joined.get('fixture.items.read').view, ['working', 'total']), {working: 10, total: 11});
  // Each action member carries its T8 decision: its own row and mode, never a provider member's.
  const update = joined.get('fixture.items.edit').members.find(member => keyOf(h)(member.capability?.id) === 'update-item');
  assert.deepEqual([update.decision.kind, update.decision.groupId, update.decision.mode, update.decision.status], ['action', 'fixture.items.edit', 'ask', 'active']);
});

test('part k: an action with a step on a member its row marks secrets sits in the sensitive row, never its declared row; a row of actions alone reads their access', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-rows-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const marked = rows => SCOPED({...rows, groups: rows.groups.map(group => group.id === 'fixture.items.read' ? {...group, sensitive: {'GET /items/{item_id}': 'secrets'}} : group)});
  const h = actionHarness(t, {rows: marked, signIn: scopedSignIn()});
  const provider = new OAuth2Provider(scopedSignIn(), {store: h.store, vault: new Vault(dir), connections: {}, clientId: 'fixture-client', clientSecret: 'fixture-secret', redirectUri: 'http://127.0.0.1:59999/api/oauth/fixture/callback'});
  const rows = byId(service(h, provider).rows({id: 'fixture'}, oauthAccount(h, ['fixture:edit'])));
  // Rename or label an item reads GET /items/{item_id} first: a change that returns keys or secrets.
  assert.deepEqual(actionKeys(h, rows.get('sensitive.secrets.write')), ['add-row', 'send-draft', 'update-item']);
  assert.equal(rows.get('sensitive.secrets.write').label, 'Changes that return keys or secrets');
  assert.deepEqual(actionKeys(h, rows.get('fixture.items.edit')), []);
  assert.deepEqual(actionKeys(h, rows.get('sensitive.secrets.delete')), ['remove-labels']);
  assert.deepEqual(rows.get('sensitive.secrets.write').view.mode, 'ask', 'a sensitive action defaults to Ask');
  // The sensitive row holds no provider member, so its access is its actions': they read items, which this account cannot.
  assert.deepEqual([rows.get('sensitive.secrets.write').view.access, rows.get('sensitive.secrets.write').view.addAccess.body.scopes], ['missing', ['fixture:read']]);
});

test('part k: setRow() writes each action\'s record, so Allow on a row its proxy record held alone has a record to live in; reset() resets them; nothing is promoted', t => {
  const h = actionHarness(t), app = service(h), account = h.store.get('connections', h.account), stored = structuredClone(h.store.list('capabilities'));
  app.view = () => 'the page';
  const edit = () => byId(app.rows({id: 'fixture'}, account)).get('fixture.items.edit');
  // The row's proxy record cannot take Allow (fixture.items.edit is not in proxyAllowable); its action members can.
  assert.deepEqual([edit().view.mode, edit().view.allowedModes], ['ask', ['allow', 'ask', 'deny']]);
  assert.equal(app.setRow('fixture', h.account, {groupId: 'fixture.items.edit', mode: 'allow', etag: edit().view.etag, confirmAllow: true}), 'the page');
  const records = () => h.store.list('permissions').filter(record => record.kind !== 'proxy-row' && record.connectionId === h.account).map(record => [keyOf(h)(record.capabilityId), record.mode, record.followsDefault === true]).sort();
  assert.deepEqual(records(), [['add-row', 'allow', false], ['update-item', 'allow', false]]);
  assert.deepEqual([edit().view.mode, edit().view.notes], ['allow', ['raw_requests_ask']], 'the row reads its actions\' mode; raw requests into it still ask');
  assert.equal(h.permissions.decision(account, h.capability('update-item v1')).mode, 'allow');
  assert.equal(h.store.list('permissions').some(record => record.kind === 'proxy-row' && record.row === 'group:fixture.items.edit'), false, 'the proxy record follows its default');
  assert.deepEqual(h.store.list('capabilities'), stored, 'no capability record changed: nothing is promoted or rewritten');
  app.reset('fixture', h.account, {groupIds: ['fixture.items.edit']});
  assert.deepEqual(records(), [['add-row', 'allow', true], ['update-item', 'allow', true]]);
  assert.equal(edit().view.mode, 'ask', 'reset puts the actions back on their default');
});

test('part k: setRow() checks every action of the row against the catalog before writing anything, for every mode', t => {
  for (const mode of ['allow', 'ask', 'deny']) {
    const h = actionHarness(t), app = service(h), account = h.store.get('connections', h.account);
    app.view = () => 'the page';
    const shown = app.rows({id: 'fixture'}, account), row = shown.find(item => item.id === 'fixture.items.edit');
    // The catalog stops holding Add a row between the page being read and the change (a reload of the app found its file changed).
    h.catalog.entries.delete(h.idOf('add-row v1'));
    app.rows = () => shown;
    assert.throws(() => app.setRow('fixture', h.account, {groupId: 'fixture.items.edit', mode, etag: row.view.etag, confirmAllow: true}),
      error => error.code === 'capability_changed' && /^Add a row: This action no longer matches its reviewed file, so it cannot run\. .*Nothing was changed\.$/.test(error.message), mode);
    assert.deepEqual(h.store.list('permissions'), [], `${mode}: no action record and no proxy record was written`);
  }
});

test('part k: the upgrade card lists an action newly on at a default Allow, and the callback wall pins it at Ask when the card did not cover it', t => {
  const h = actionHarness(t, {file: withExtra(), rows: SCOPED, signIn: scopedSignIn()}), app = service(h);
  const before = oauthAccount(h, ['fixture:edit']);
  const rows = app.rows({id: 'fixture'}, before), list = byId(rows).get('fixture.items.read').members.find(member => keyOf(h)(member.capability?.id) === 'list-items');
  assert.deepEqual([list.decision.providerAccess, list.decision.mode, list.decision.policySource], ['missing', 'allow', 'default']);
  // With fixture:read the reads of List items run at their default Allow: its row is carded as a typed row, not only as a proxy row.
  const card = app.upgradeCard(before, rows, ['fixture:edit', 'fixture:read']);
  assert.deepEqual(card.rows, [{groupId: 'fixture.items.read', label: 'Access items', typed: true, proxy: true}]);
  h.permissions.actions = null;
  const plain = app.upgradeCard(before, app.rows({id: 'fixture'}, before), ['fixture:edit', 'fixture:read']);
  h.permissions.actions = h.catalog;
  assert.deepEqual(plain.rows, [{groupId: 'fixture.items.read', label: 'Access items', typed: false, proxy: true}]);
  assert.notEqual(card.etag, plain.etag, 'the card binds the actions it turns on');
  // Nothing an action needs is gained: no card row.
  assert.deepEqual(app.upgradeCard(before, rows, ['fixture:edit', 'fixture:keys']).rows, []);
  // The callback wall: the provider granted fixture:read, which the confirmed card did not cover.
  const ownModes = store => Object.fromEntries(store.list('permissions').filter(record => record.kind !== 'proxy-row' && record.connectionId === 'fixture-oauth').map(record => [keyOf(h)(record.capabilityId), record.mode]));
  const after = oauthAccount(h, ['fixture:edit', 'fixture:read']);
  app.pinUnconfirmed(before, after, ['fixture:edit']);
  assert.deepEqual(ownModes(h.store), {'find-with-zone': 'ask', 'list-items': 'ask'}, 'each action newly on at a default Allow is pinned at Ask');
  assert.equal(h.permissions.decision(after, h.capability('list-items v1')).mode, 'ask');
  // A card that covered fixture:read pins nothing: GET /keys, the optional step of Find with a zone it did not cover, never counts.
  const h2 = actionHarness(t, {file: withExtra(), rows: SCOPED, signIn: scopedSignIn()}), app2 = service(h2);
  const first = oauthAccount(h2, ['fixture:edit']), next = oauthAccount(h2, ['fixture:edit', 'fixture:read']);
  app2.pinUnconfirmed(first, next, ['fixture:edit', 'fixture:read']);
  assert.deepEqual(ownModes(h2.store), {});
});

test('part k: the not-granted notice names a row whose action needs a scope the sign-in did not get', t => {
  const h = actionHarness(t, {rows: SCOPED, signIn: scopedSignIn()}), app = service(h);
  // The account holds what Edit items' own members need, but not what Rename or label an item reads first.
  const account = oauthAccount(h, ['fixture:edit', 'fixture:delete']);
  const notice = app.notGranted({...account, grant: {missing: ['fixture:read']}}, {kind: 'not_granted', count: 1}, app.rows({id: 'fixture'}, account));
  assert.deepEqual(notice.rows.map(row => row.groupId), ['fixture.items.read', 'fixture.items.edit', 'fixture.messages.send', 'fixture.items.delete']);
});

test('part k: rowsNeeding() counts an active action; Add access asks for each missing step\'s least-privileged scope, usable on that step\'s row; an optional step asks nothing', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-action-rows-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const h = actionHarness(t, {file: withExtra(), rows: SCOPED, signIn: scopedSignIn()});
  const provider = new OAuth2Provider(scopedSignIn(), {store: h.store, vault: new Vault(dir), connections: {}, clientId: 'fixture-client', clientSecret: 'fixture-secret', redirectUri: 'http://127.0.0.1:59999/api/oauth/fixture/callback'});
  const app = service(h, provider);
  // Without fixture:read and fixture:all, every action that reads items is left without access, in its declared row.
  assert.deepEqual(app.rowsNeeding('fixture', ['fixture:read', 'fixture:all']).map(row => row.groupId), ['fixture.items.read', 'fixture.items.edit', 'fixture.messages.send', 'fixture.items.delete']);
  // fixture:all alone still reads items; an optional step (GET /keys) leaves nothing without access.
  assert.deepEqual(app.rowsNeeding('fixture', ['fixture:read']), []);
  assert.deepEqual(app.rowsNeeding('fixture', ['fixture:keys']), []);
  // Trash an item's step is PATCH /items/{item_id}, a member of fixture.items.edit that a body route sends to fixture.items.delete: it
  // needs what that member needs.
  assert.deepEqual(app.rowsNeeding('fixture', ['fixture:edit']), [{groupId: 'fixture.items.edit', label: 'Edit items'}, {groupId: 'fixture.items.delete', label: 'Delete items'}]);
  const account = oauthAccount(h, []), rows = byId(app.rows({id: 'fixture'}, account));
  // Edit items' own members need fixture:edit; its actions also read items, which needs fixture:read, never the broad fixture:all.
  assert.deepEqual(rows.get('fixture.items.edit').view.addAccess.body, {connectionId: 'fixture-oauth', level: 'full', scopes: ['fixture:edit', 'fixture:read']});
  // Find with a zone's optional GET /keys asks nothing.
  assert.deepEqual(rows.get('fixture.items.read').view.addAccess.body.scopes, ['fixture:read']);
  // Delete items' own members need fixture:delete; Trash an item's step needs fixture:edit, which is usable on its member's row, Edit
  // items, and on no other: it is asked for all the same.
  assert.deepEqual(rows.get('fixture.items.delete').view.addAccess.body.scopes, ['fixture:delete', 'fixture:edit', 'fixture:read']);
  h.permissions.actions = null;
  const plain = byId(app.rows({id: 'fixture'}, account));
  assert.deepEqual([plain.get('fixture.items.edit').view.addAccess.body.scopes, plain.get('fixture.items.delete').view.addAccess.body.scopes], [['fixture:edit'], ['fixture:delete']], 'the provider members alone ask for less');
});

test('part k: a candidate is on no row and needs no access; reviewRequired stays false and N6 finds no member to hold at Never', t => {
  const h = actionHarness(t, {file: certifiedFile(file => { file.reviewStatus = fixtureActions().reviewStatus; }), rows: SCOPED, signIn: scopedSignIn()}), app = service(h);
  assert.equal([...h.catalog.entries.values()].every(item => item.status === 'candidate'), true);
  for (const row of app.rows({id: 'fixture'}, h.store.get('connections', h.account))) {
    assert.deepEqual(actionKeys(h, row), [], row.id);
    assert.equal(row.view.reviewRequired, false, row.id);
    // N6 (lib/tenant/app-pages.mjs inactive()): a member whose capability is not active holds a row at Never. Candidates never join.
    assert.equal(row.members.some(member => member.capability && member.capability.status !== 'active'), false, row.id);
  }
  assert.deepEqual(app.rowsNeeding('fixture', ['fixture:read', 'fixture:all']), [], 'a candidate needs nothing from a sign-in');
});

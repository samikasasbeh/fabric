import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';
import {canonicalHash, compileOpenApi} from '../lib/compiler.mjs';
import {Store} from '../lib/store.mjs';
import {appEntry, checkSigned, dataHash, readGolden, REVIEW_PATH, ROOT} from '../scripts/defaults-golden.mjs';
import {actionIds, validateActionFile} from '../lib/actions.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {googleMap} from './fixtures/access/google-maps.mjs';

// F10.15 (docs/F10.15-BUILD-MAP.md sections 3 and 6, test/f10-15-churn.test.mjs): what step 15 must not move. Part 1 adds row data to three
// Gmail rows, as spec line 1106 names it: "Draft emails" marks gmail.users.drafts.create and gmail.users.drafts.update unsupported (their
// plain form carries no whole message, so it saves an empty draft or blanks one), "Send emails" marks gmail.users.drafts.send unsupported
// (it sends by id alone) and binds it to the content read first, and "Import emails" marks gmail.users.messages.import unsupported. The
// proxy never reads unsupported and nothing that decides a raw request reads bindContent, so no binding, proxy setting, proxy decision or
// connection generation moves; the four members' typed decisions read unsupported, which their policy hash covers, while their capability
// ids and bytes stay (I1). Gmail's defaults table, and so its data hash, moves: Sami signs Gmail again (S15.1). The snapshots compared
// with are F10.9's, recorded before its part b. Later steps take Gmail's facts out of their own churn tests and leave them here.
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const LOADERS = json('./fixtures/access/f10-9-loaders.before.json');
const BEFORE = json('./fixtures/access/f10-9-bindings.before.json');
const F107 = json('./fixtures/access/f10-7-bindings.before.json');
const DRAFTS = 'gmail.drafts.write', SEND = 'gmail.messages.send', IMPORT = 'gmail.messages.import';
const DRAFT_WORDS = 'Fabric\'s plain form of this operation cannot carry a whole message, so it would save an empty draft or blank one. Fabric writes drafts through its reviewed Gmail actions.';
const SEND_WORDS = 'It sends a draft by its id alone, so a draft changed after approval would go out. Fabric sends drafts through its reviewed Send draft action, which binds the message.';
const IMPORT_WORDS = 'Fabric\'s plain form of this operation cannot carry a message, so it would import nothing. No reviewed action imports email.';
/** Exactly the row data spec line 1106 names, by row. */
const MARKERS = Object.freeze({
  [DRAFTS]: {unsupported: {'gmail.users.drafts.create': DRAFT_WORDS, 'gmail.users.drafts.update': DRAFT_WORDS}},
  [SEND]: {unsupported: {'gmail.users.drafts.send': SEND_WORDS}, bindContent: {'gmail.users.drafts.send': {kind: 'resend', at: 'body:/message/raw'}}},
  [IMPORT]: {unsupported: {'gmail.users.messages.import': IMPORT_WORDS}},
});
const MARKED = Object.freeze({'gmail.users.drafts.create': DRAFT_WORDS, 'gmail.users.drafts.update': DRAFT_WORDS, 'gmail.users.drafts.send': SEND_WORDS, 'gmail.users.messages.import': IMPORT_WORDS});
/** The typed-only refusal, spec line 1109. */
const TYPED_ONLY_WORDS = 'This operation runs only through a reviewed action, so the exact message can be shown. Use the Send email action.';
/** Sami's sign-off of Gmail's defaults, 2026-10-20: the table before step 15. */
const SIGNED = Object.freeze({by: 'Sami', date: '2026-10-20', dataHash: '12b50a7bc996b592fa910e872e143a1ea931688b4aec7309a61cd200c94e92fe'});
/** The other apps' current sign-offs: three from 2026-10-20 (F10.9's recorded hashes) and Calendar's of 2026-10-24 (after step 13). */
// F10.17's listed churn moves GitHub's rows and data hash (two content bindings), so GitHub's facts are test/f10-17-churn.test.mjs's.
const OTHERS = Object.freeze({notion: BEFORE.dataHashes.notion, slack: BEFORE.dataHashes.slack, 'google-calendar': '11c31be5c85edefbdfa84f87b5bfcbe302bc36971a7d933a9830789dc2999da9'});
const MODIFY = 'https://www.googleapis.com/auth/gmail.modify', BASIC = 'https://www.googleapis.com/auth/gmail.settings.basic';
const plain = value => JSON.parse(JSON.stringify(value));
const raw = () => JSON.parse(readFileSync(path.join(ROOT, 'catalog', 'permissions', 'gmail.json'), 'utf8'));
/** Gmail's shipped rows with this step's row data taken out: the rows Sami signed. */
function unmarked() {
  const file = raw();
  for (const group of file.groups) { delete group.unsupported; delete group.bindContent; }
  return validatePermissionGroups(file);
}
const withRows = rows => new Map([...PERMISSION_GROUPS, ['gmail', rows]]);

function temporaryStore(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-f10-15-churn-')), store = new Store({dataDir: dir, localAuthority: 'new'});
  t.after(() => {store.close(); rmSync(dir, {recursive: true, force: true});});
  return store;
}
/** Every proxy-row binding of one account, over the recorded synthetic map, as F10.9's snapshot was recorded. */
function proxyRowsOf(connection, groups = PERMISSION_GROUPS) {
  const config = PROXY_CONFIGS.get(connection.appId), definition = groups.get(connection.appId), policy = new ProxyPolicy({store: null});
  const templates = templatesFor(definition, config, F107.maps[connection.appId]);
  return Object.fromEntries(policy.rows({config, definition}).map(({row}) => [row, policy.binding({connection, config, templates, definition}, row)]));
}
/** The capabilities of a map's operations, compiled as F10.9's snapshot compiled them. */
function compiled(operations) {
  const paths = {};
  for (const operation of operations) paths[operation.path] = {...paths[operation.path], [operation.method.toLowerCase()]: {operationId: operation.id,
    parameters: [...operation.path.matchAll(/\{(\w+)\}/g)].map(match => ({name: match[1], in: 'path', required: true, schema: {type: 'string'}})), responses: {200: {description: 'ok'}}}};
  return compileOpenApi({appId: 'gmail', document: {openapi: '3.0.3', info: {title: 'gmail', version: '1'}, servers: [{url: 'https://gmail.googleapis.com'}], paths}})
    .capabilities.map(cap => ({...cap, status: 'active'}));
}
/** Every typed decision of one account over a map's operations, under `groups`: {name: decision}. */
function typedOf(t, connection, operations, groups = PERMISSION_GROUPS) {
  const store = temporaryStore(t), caps = compiled(operations);
  store.put('connections', connection);
  for (const cap of caps) store.put('capabilities', cap);
  store.put('applicationMaps', {id: 'gmail', appId: 'gmail', operations: operations.map(operation => ({...operation, capabilityId: caps.find(cap => cap.name === operation.id).id}))});
  const permissions = new PermissionManager({store, groups}), stored = store.get('connections', connection.id);
  return {caps, decisions: Object.fromEntries(caps.map(cap => [cap.name, plain(permissions.decision(stored, cap))]).sort(([a], [b]) => a < b ? -1 : 1))};
}
/** A ready Gmail account with both of Fabric's scopes on a store holding Google's recorded method map, decided under `groups`. */
function gmailPolicy(t, groups) {
  const store = temporaryStore(t), map = googleMap('gmail');
  store.put('connections', {...BEFORE.connections.gmail, scopes: [MODIFY, BASIC]});
  store.put('applicationMaps', {...map, id: 'gmail'});
  const permissions = new PermissionManager({store, groups}), policy = new ProxyPolicy({store, permissions, groups, configs: PROXY_CONFIGS});
  return {policy, map, connectionId: BEFORE.connections.gmail.id};
}
/** Every reviewed Gmail method as one concrete raw request (a whole message on writes), decided; a refusal is kept as its code. */
function decisions(t, groups) {
  const {policy, map, connectionId} = gmailPolicy(t, groups), body = {message: {raw: Buffer.from('To: owner@example.com\r\nSubject: x\r\n\r\nHi').toString('base64url')}};
  return Object.fromEntries(map.operations.map(operation => {
    const request = {method: operation.method, path: operation.path.replace(/\{\+?(\w+)\}/g, (_, name) => name === 'userId' ? 'me' : `${name}-1`), ...(['POST', 'PATCH', 'PUT'].includes(operation.method) ? {body} : {})};
    try { return [operation.id, plain(policy.decide(connectionId, request))]; } catch (error) { return [operation.id, {refused: error.code ?? error.message}]; }
  }));
}

test('Gmail\'s rows load to F10.9\'s recorded output plus exactly the four unsupported markers and the one content binding; Notion\'s and Slack\'s load as before, and Calendar\'s but for its own binding (GitHub\'s: test/f10-17-churn.test.mjs)', () => {
  const expected = structuredClone(LOADERS.permissionGroups.gmail);
  for (const [id, data] of Object.entries(MARKERS)) Object.assign(expected.groups.find(group => group.id === id), structuredClone(data));
  assert.deepStrictEqual(plain(PERMISSION_GROUPS.get('gmail')), expected);
  assert.deepStrictEqual(plain(unmarked()), LOADERS.permissionGroups.gmail, 'without them, the rows Sami signed');
  for (const appId of ['notion', 'slack']) assert.deepStrictEqual(plain(PERMISSION_GROUPS.get(appId)), LOADERS.permissionGroups[appId], `${appId} rows`);
  const calendar = plain(PERMISSION_GROUPS.get('google-calendar'));
  delete calendar.groups.find(group => group.id === 'google-calendar.events.write').bindContent;
  assert.deepStrictEqual(calendar, LOADERS.permissionGroups['google-calendar'], 'Calendar: its own step 13 binding only');
  const file = raw();
  assert.deepEqual(file.groups.filter(group => group.unsupported !== undefined).map(group => group.id), [DRAFTS, SEND, IMPORT]);
  assert.deepEqual(file.groups.filter(group => group.bindContent !== undefined || group.sensitive !== undefined).map(group => group.id), [SEND], 'one binding, and no member marked sensitive');
  assert.equal(new Set([...Object.values(MARKED)]).size, 3, 'the two draft members share one reason, so the row says it');
});

test('no proxy-row binding, typed binding, proxy setting, raw decision or connection generation moves', t => {
  assert.deepEqual(proxyRowsOf(BEFORE.connections.gmail), BEFORE.proxyRows.gmail, 'proxy-row bindings, as F10.9 recorded them');
  assert.deepEqual(proxyRowsOf(BEFORE.connections.gmail, withRows(unmarked())), BEFORE.proxyRows.gmail);
  const {decisions: typed} = typedOf(t, BEFORE.connections.gmail, F107.maps.gmail.operations);
  assert.deepEqual(Object.fromEntries(Object.entries(typed).map(([name, decision]) => [name, decision.bindingHash])), BEFORE.typed.gmail, 'typed bindings, every member\'s, as F10.9 recorded them');
  const config = plain(PROXY_CONFIGS.get('gmail'));
  assert.deepStrictEqual({...config, documented: {count: config.documented.length, hash: canonicalHash(config.documented)}}, LOADERS.proxyConfigs.gmail, 'the proxy settings and their configHash');
  // With the row data and without it, on Google's own method map: every raw decision is the same, connection generation and policy hash
  // included, a POST /drafts carrying a whole message among them.
  const now = decisions(t, PERMISSION_GROUPS), then = decisions(t, withRows(unmarked()));
  assert.deepEqual(now, then);
  assert.equal(Object.keys(now).length, 79, 'every Gmail method');
  assert.ok(Object.values(now).every(decision => decision.refused === undefined && decision.connectionGeneration === 1), 'each decided, on generation 1');
  const draft = now['gmail.users.drafts.create'];
  assert.deepEqual([draft.row, draft.mode, draft.match.member, draft.executable], [`group:${DRAFTS}`, 'ask', 'gmail.users.drafts.create', true],
    'a raw draft with its whole message still runs, at Ask as before');
});

test('the four marked members\' typed decisions read unsupported with the row\'s words and cannot run; their capability ids, bytes and binding hashes stay (I1)', t => {
  const connection = {...BEFORE.connections.gmail, scopes: [MODIFY, BASIC]};
  const now = typedOf(t, connection, F107.maps.gmail.operations), then = typedOf(t, connection, F107.maps.gmail.operations, withRows(unmarked()));
  assert.deepEqual(now.caps, then.caps, 'the compiled capabilities, ids and bytes, do not depend on row data');
  for (const [name, decision] of Object.entries(now.decisions)) {
    const before = then.decisions[name];
    assert.equal(decision.capabilityId, before.capabilityId, name);
    assert.equal(decision.bindingHash, before.bindingHash, name);
    if (Object.hasOwn(MARKED, name)) {
      assert.deepEqual([decision.status, decision.reason, decision.executable, before.status, before.executable], ['unsupported', MARKED[name], false, 'active', true], name);
      assert.notEqual(decision.policyHash, before.policyHash, `${name}: the policy hash covers the status, so a pending typed approval on it is refused`);
    } else assert.deepEqual(decision, before, `${name}: unchanged`);
  }
});

test('a raw messages.send, drafts.send, messages.import or messages.insert is refused as typed only, with words that point to the Send email action', t => {
  const {policy, connectionId} = gmailPolicy(t, PERMISSION_GROUPS);
  const message = Buffer.from('To: owner@example.com\r\nSubject: x\r\n\r\nHi').toString('base64url');
  for (const [request, member] of [[{method: 'POST', path: '/gmail/v1/users/me/messages/send', body: {raw: message}}, 'gmail.users.messages.send'],
    [{method: 'POST', path: '/gmail/v1/users/me/drafts/send', body: {id: 'r1', message: {raw: message}}}, 'gmail.users.drafts.send'],
    [{method: 'POST', path: '/gmail/v1/users/me/messages/import', body: {raw: message}}, 'gmail.users.messages.import'],
    [{method: 'POST', path: '/gmail/v1/users/me/messages', body: {raw: message}}, 'gmail.users.messages.insert']]) {
    const decision = policy.decide(connectionId, request);
    assert.deepEqual([decision.match.member, decision.mode, decision.executable, decision.clamps.includes('typed_only'), decision.reason], [member, 'deny', false, true, TYPED_ONLY_WORDS], member);
  }
});

test('notion, slack and Calendar keep their signed data hashes; Gmail\'s table differs from the one Sami signed only by the row data, so it waits for his sign-off', () => {
  const golden = readGolden();
  for (const [appId, hash] of Object.entries(OTHERS)) {
    assert.equal(appEntry(ROOT, appId).dataHash, hash, `${appId} data hash`);
    assert.equal(golden.apps[appId].signedOff.dataHash, hash, `${appId} is signed for it`);
  }
  assert.deepEqual(checkSigned().filter(problem => !problem.startsWith('gmail: ') && !problem.startsWith('github: ')), [], 'the golden is current and the other apps but GitHub (its own churn test) stay signed');
  const gmail = appEntry(ROOT, 'gmail'), recorded = golden.apps.gmail;
  assert.equal(BEFORE.dataHashes.gmail, SIGNED.dataHash);
  assert.equal(recorded.dataHash, gmail.dataHash, 'the golden records the table the data gives now');
  assert.notEqual(gmail.dataHash, SIGNED.dataHash, 'the row data moves Gmail\'s data hash');
  const table = structuredClone(gmail.table), row = id => table.rows.find(item => item.id === id);
  assert.deepEqual(row(DRAFTS).unsupported, [{member: 'gmail.users.drafts.create', words: DRAFT_WORDS}, {member: 'gmail.users.drafts.update', words: DRAFT_WORDS}]);
  assert.deepEqual(row(SEND).unsupported, [{member: 'gmail.users.drafts.send', words: SEND_WORDS}]);
  assert.deepEqual(row(IMPORT).unsupported, [{member: 'gmail.users.messages.import', words: IMPORT_WORDS}]);
  assert.deepEqual(row(SEND).bindContent, [{member: 'gmail.users.drafts.send', kind: 'resend', at: 'body:/message/raw'}]);
  assert.deepEqual(table.rows.filter(item => item.unsupported.length || item.bindContent).map(item => item.id), [DRAFTS, SEND, IMPORT], 'no other row');
  for (const id of [DRAFTS, SEND, IMPORT]) row(id).unsupported = [];
  delete row(SEND).bindContent;
  assert.equal(dataHash('gmail', table), SIGNED.dataHash, 'without the markers and the binding the table hashes to what Sami signed');
  // His 2026-10-20 sign-off is kept as the previous one. Until S15.1 there is no current one; after it the current one binds the new table.
  assert.deepEqual(recorded.previousSignedOff, SIGNED);
  if (recorded.signedOff === null) assert.deepEqual(checkSigned().filter(problem => problem.startsWith('gmail: ')), ['gmail: the defaults table is not signed yet']);
  else assert.equal(recorded.signedOff.dataHash, gmail.dataHash);
  // The review document shows the lines Sami reads before he signs.
  const review = readFileSync(path.join(ROOT, REVIEW_PATH), 'utf8');
  for (const [member, words] of Object.entries(MARKED)) {
    const label = member === 'gmail.users.drafts.send' ? 'Send emails' : member === 'gmail.users.messages.import' ? 'Import emails' : 'Draft emails';
    assert.ok(review.includes(`- \`${member}\` (${label}): ${words}`), member);
  }
  assert.ok(review.includes('- `gmail.users.drafts.send` (Send emails): the content read first, sent again unchanged at `/message/raw` in the body.'));
});

// Part 2: the shipped ids are checked here, not in test/actions-gmail.test.mjs, which recomputes them (withIds()) so a seeded fault inside
// the file reaches behaviour instead of tripping the id check.
test('Gmail\'s shipped action file holds current ids: each stored id is the one its content hashes to, and the file validates with them, placed and unplaced', () => {
  const file = JSON.parse(readFileSync(path.join(ROOT, 'catalog', 'actions', 'gmail.json'), 'utf8'));
  const deps = map => ({identities: new Map([['gmail', definitionFor('google')]]), maps: new Map(map ? [['gmail', googleMap('gmail')]] : [])});
  const ids = actionIds(file, deps(true));
  assert.deepEqual(file.actions.map(action => action.id), file.actions.map(action => ids.get(`${action.key} v${action.version}`).id));
  assert.deepEqual([file.reviewStatus, validateActionFile(file, deps(true)).actions.length, validateActionFile(file, deps(false)).actions.every(entry => entry.unplaced)], ['reviewed', 13, true]);
});

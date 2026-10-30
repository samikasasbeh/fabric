import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {PERMISSION_GROUPS, memberKey, validatePermissionGroups} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';
import {Store} from '../lib/store.mjs';
import {appEntry, checkSigned, dataHash, readGolden, REVIEW_PATH, ROOT} from '../scripts/defaults-golden.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {actionIds, validateActionFile} from '../lib/actions.mjs';

// F10.17 (docs/F10.17-BUILD-MAP.md sections 3 and 6, test/f10-17-churn.test.mjs): what step 17 must not move. Part 1 adds one field to two
// GitHub rows: "Push code and manage repositories" binds the contents PUT, and "Open and merge pull requests" the merge, each to the sha
// read first (spec line 1421, F10.9 open question 1). Nothing that decides a request reads bindContent (lib/proxy-policy.mjs hashes
// templates and the config, a row etag folds member states that leave it out), so only GitHub's defaults table, and so its data hash,
// moves: Sami signs GitHub again (S17.1). Part 1 also gives GitHub's sign-in the grant header (grantHeader, spec line 1144), which moves
// the definition's bytes and its files hash, never its sign-in URLs or its data hash. The snapshots compared with are F10.9's, recorded
// before its part b.
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const LOADERS = json('./fixtures/access/f10-9-loaders.before.json');
const BEFORE = json('./fixtures/access/f10-9-bindings.before.json');
const F107 = json('./fixtures/access/f10-7-bindings.before.json');
const CODE = 'github.code.write', PULLS = 'github.pulls.write';
// The rows file names the contents member as its request is written ({+path}); loaded rows, the table and the review key it by member key.
const CONTENTS_REQUEST = 'PUT /repos/{owner}/{repo}/contents/{+path}', CONTENTS = memberKey(CONTENTS_REQUEST), MERGE = 'PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge';
const BINDINGS = Object.freeze({[CODE]: {[CONTENTS]: {kind: 'sha', at: 'body:/sha'}}, [PULLS]: {[MERGE]: {kind: 'sha', at: 'body:/sha'}}});
/** Sami's sign-off of GitHub's defaults, 2026-10-20: the table before step 17. */
const SIGNED = Object.freeze({by: 'Sami', date: '2026-10-20', dataHash: '8e8689ca1f508db2985fa48c978bf42964fceaba8a452f9120e35a7598074f26'});
/** catalog/auth/github.json before step 17, read with LF line ends (test/f10-12-churn.test.mjs records the same digest). */
const AUTH_DIGEST = 'de0c61db7cb3a5ff8f6cad8a9b9d2ab31c34f67a1072d5325fd200a4267535f9';
const GRANT_HEADER_LINE = '  "grantHeader": "x-oauth-scopes",\n';
// F10.15's listed churn moves Gmail's rows and data hash (four unsupported markers and one content binding), so Gmail's facts are
// test/f10-15-churn.test.mjs's.
const OTHERS = ['google-calendar', 'notion', 'slack'];
const FIVE = ['read:user', 'repo', 'read:org', 'gist', 'workflow'];
const plain = value => JSON.parse(JSON.stringify(value));
const raw = () => JSON.parse(readFileSync(path.join(ROOT, 'catalog', 'permissions', 'github.json'), 'utf8'));
/** GitHub's shipped rows with the content bindings taken out: the rows Sami signed. */
function unbound() {
  const file = raw();
  for (const id of Object.keys(BINDINGS)) delete file.groups.find(group => group.id === id).bindContent;
  return validatePermissionGroups(file);
}
/** Calendar's rows as F10.9 recorded them, plus the binding step 13 added on purpose. */
function calendarRecorded() {
  const rows = structuredClone(LOADERS.permissionGroups['google-calendar']);
  rows.groups.find(group => group.id === 'google-calendar.events.write').bindContent = {'calendar.events.patch': {kind: 'etag', at: 'header:If-Match'}, 'calendar.events.update': {kind: 'etag', at: 'header:If-Match'}};
  return rows;
}

function temporaryStore(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-f10-17-churn-')), store = new Store({dataDir: dir, localAuthority: 'new'});
  t.after(() => {store.close(); rmSync(dir, {recursive: true, force: true});});
  return store;
}
/** Every proxy-row binding of one account, over the recorded synthetic maps, as F10.9's snapshot was recorded (GitHub's rows list their
 *  templates, so it needs no map). */
function proxyRowsOf(connection, groups = PERMISSION_GROUPS) {
  const config = PROXY_CONFIGS.get(connection.appId), definition = groups.get(connection.appId), policy = new ProxyPolicy({store: null});
  const templates = templatesFor(definition, config, F107.maps[connection.appId] ?? null);
  return Object.fromEntries(policy.rows({config, definition}).map(({row}) => [row, policy.binding({connection, config, templates, definition}, row)]));
}
/** A ready GitHub account with the five scopes, decided under `groups`. */
function githubPolicy(t, groups) {
  const store = temporaryStore(t);
  store.put('connections', {...BEFORE.connections.github, scopes: FIVE});
  const permissions = new PermissionManager({store, groups}), policy = new ProxyPolicy({store, permissions, groups, configs: PROXY_CONFIGS});
  return {policy, store, connectionId: BEFORE.connections.github.id};
}
/** Every member state of every GitHub row (the row etag folds them), keyed by row and member. */
function memberStates(t, groups) {
  const {policy, connectionId} = githubPolicy(t, groups), context = policy.route(connectionId), rows = policy.rows(context);
  return Object.fromEntries(context.templates.filter(template => !template.unreviewed && template.groupId).map(template => {
    const entry = rows.find(item => item.group?.id === template.groupId);
    return [`${template.groupId} ${template.member}`, plain(policy.memberState(context, entry, template.member))];
  }));
}

test('GitHub\'s rows load to F10.9\'s recorded output plus exactly the two bindContent blocks; Notion\'s and Slack\'s load unchanged and Calendar\'s but for its step 13 binding (Gmail\'s: test/f10-15-churn.test.mjs)', () => {
  const expected = structuredClone(LOADERS.permissionGroups.github);
  for (const [id, binding] of Object.entries(BINDINGS)) expected.groups.find(group => group.id === id).bindContent = binding;
  assert.deepStrictEqual(plain(PERMISSION_GROUPS.get('github')), expected);
  assert.deepStrictEqual(plain(unbound()), LOADERS.permissionGroups.github, 'without the bindings, the rows Sami signed');
  for (const appId of ['notion', 'slack']) assert.deepStrictEqual(plain(PERMISSION_GROUPS.get(appId)), LOADERS.permissionGroups[appId], `${appId} rows`);
  assert.deepStrictEqual(plain(PERMISSION_GROUPS.get('google-calendar')), calendarRecorded(), 'Calendar\'s rows, with step 13\'s binding only');
  assert.deepEqual(raw().groups.filter(group => group.bindContent !== undefined || group.sensitive !== undefined).map(group => group.id), [PULLS, CODE], 'no other row binds content, and none is marked sensitive');
});

test('no proxy-row binding, member state (the row etag folds them), decision, policy hash or connection generation moves; GitHub has no typed binding', t => {
  for (const appId of ['github', ...OTHERS]) assert.deepEqual(proxyRowsOf(BEFORE.connections[appId]), BEFORE.proxyRows[appId], `${appId} proxy-row bindings, as F10.9 recorded them`);
  assert.equal(Object.hasOwn(BEFORE.typed, 'github'), false, 'GitHub has no typed operations');
  const before = new Map([...PERMISSION_GROUPS, ['github', unbound()]]);
  assert.deepEqual(proxyRowsOf(BEFORE.connections.github, before), BEFORE.proxyRows.github);
  const now = memberStates(t, PERMISSION_GROUPS), then = memberStates(t, before);
  assert.deepEqual(now, then);
  assert.ok(Object.keys(now).length > 300, 'every reviewed GitHub template');
});

test('a raw proxied contents PUT and merge are decided exactly as before: the same row, mode, policy hash and binding hash', t => {
  const requests = [[CONTENTS, CODE, {method: 'PUT', path: '/repos/octo-a/fabric-sandbox/contents/docs/a.md', body: {message: 'Change', content: 'eA==', sha: 'a'.repeat(40)}}],
    [MERGE, PULLS, {method: 'PUT', path: '/repos/octo-a/fabric-sandbox/pulls/4/merge', body: {sha: 'b'.repeat(40), merge_method: 'merge'}}]];
  for (const [member, row, request] of requests) {
    const decide = groups => { const {policy, connectionId} = githubPolicy(t, groups); return plain(policy.decide(connectionId, request)); };
    const now = decide(PERMISSION_GROUPS), then = decide(new Map([...PERMISSION_GROUPS, ['github', unbound()]]));
    assert.deepEqual([now.row, now.mode, now.requiresApproval, now.match.groupId, now.match.member, now.connectionGeneration], [`group:${row}`, 'ask', true, row, member, 1], member);
    assert.deepEqual(now, then, member);
  }
});

test('google-calendar, notion and slack keep their signed data hashes; GitHub\'s table differs from the one Sami signed only by the two bindings, so it waits for his sign-off', () => {
  const golden = readGolden();
  for (const appId of OTHERS) {
    const now = appEntry(ROOT, appId).dataHash;
    assert.equal(golden.apps[appId].signedOff.dataHash, now, `${appId} is signed for the data it gives now`);
    assert.equal(golden.apps[appId].dataHash, now, `${appId} data hash`);
  }
  for (const appId of ['notion', 'slack']) assert.equal(appEntry(ROOT, appId).dataHash, BEFORE.dataHashes[appId], `${appId} as F10.9 recorded it`);
  assert.deepEqual(checkSigned().filter(problem => !problem.startsWith('github: ') && !problem.startsWith('gmail: ')), [], 'the golden is current and the other apps but Gmail (its own churn test) stay signed');
  const github = appEntry(ROOT, 'github'), recorded = golden.apps.github;
  assert.equal(BEFORE.dataHashes.github, SIGNED.dataHash);
  assert.equal(recorded.dataHash, github.dataHash, 'the golden records the table the data gives now');
  assert.notEqual(github.dataHash, SIGNED.dataHash, 'the bindings move GitHub\'s data hash');
  const table = structuredClone(github.table);
  assert.deepEqual(table.rows.filter(row => row.bindContent).map(row => [row.id, row.bindContent]),
    [[PULLS, [{member: MERGE, kind: 'sha', at: 'body:/sha'}]], [CODE, [{member: CONTENTS, kind: 'sha', at: 'body:/sha'}]]]);
  for (const row of table.rows) delete row.bindContent;
  assert.equal(dataHash('github', table), SIGNED.dataHash, 'without its two bindContent entries the table hashes to what Sami signed');
  // His 2026-10-20 sign-off is kept as the previous one. Until S17.1 there is no current one; after it the current one binds the new table.
  assert.deepEqual(recorded.previousSignedOff, SIGNED);
  if (recorded.signedOff === null) assert.deepEqual(checkSigned().filter(problem => problem.startsWith('github: ')), ['github: the defaults table is not signed yet']);
  else assert.equal(recorded.signedOff.dataHash, github.dataHash);
  // The review document shows the two lines Sami reads before he signs.
  const review = readFileSync(path.join(ROOT, REVIEW_PATH), 'utf8');
  assert.ok(review.includes(`- \`${CONTENTS}\` (Push code and manage repositories): the sha read first, sent at \`/sha\` in the body.`));
  assert.ok(review.includes(`- \`${MERGE}\` (Open and merge pull requests): the sha read first, sent at \`/sha\` in the body.`));
});

test('catalog/auth/github.json differs from its recorded bytes only by the grant header, which no other definition carries and which moves no data hash', () => {
  const text = readFileSync(path.join(ROOT, 'catalog/auth/github.json'), 'utf8').replace(/\r\n/g, '\n');
  assert.equal(text.split(GRANT_HEADER_LINE).length, 2, 'the grant header line, once');
  assert.equal(createHash('sha256').update(text.replace(GRANT_HEADER_LINE, '')).digest('hex'), AUTH_DIGEST, 'the rest is byte for byte the recorded definition');
  assert.equal(definitionFor('github').grantHeader, 'x-oauth-scopes');
  for (const providerId of ['google', 'notion', 'slack']) assert.equal(Object.hasOwn(definitionFor(providerId), 'grantHeader'), false, providerId);
  const golden = readGolden(), now = appEntry(ROOT, 'github');
  assert.equal(golden.apps.github.filesHash, now.filesHash, 'the golden records the files hash the definition gives now');
});

// Part 2 (docs/F10.17-BUILD-MAP.md section 3): the shipped file's ids are current, so a seeded fault inside it is caught by behaviour in
// test/actions-github.test.mjs, which recomputes them, and the shipped file itself never carries a stale id.
test('GitHub\'s shipped action file holds current ids: each stored id is the one its content hashes to, and the file validates with them and no map', () => {
  const file = JSON.parse(readFileSync(path.join(ROOT, 'catalog', 'actions', 'github.json'), 'utf8'));
  const deps = {identities: new Map([['github', definitionFor('github')]]), maps: new Map()};
  const ids = actionIds(file, deps);
  assert.deepEqual(file.actions.map(action => action.id), file.actions.map(action => ids.get(`${action.key} v${action.version}`).id));
  assert.equal(validateActionFile(file, deps).actions.length, 15);
  // Step 18's live pass (run 5XBI3UND) certified all 15: each names the shipped evidence, and test/live-evidence.test.mjs holds the hashes.
  assert.ok(file.actions.every(action => action.certified?.evidence === 'docs/live-evidence/github/actions.json'), 'each certified by step 18\'s evidence');
});

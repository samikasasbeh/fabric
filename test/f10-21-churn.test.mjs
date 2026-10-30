import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {canonicalHash} from '../lib/compiler.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {PermissionManager} from '../lib/permissions.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';
import {Store} from '../lib/store.mjs';
import {actionIds, validateActionFile} from '../lib/actions.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {appEntry, checkSigned, readGolden, ROOT} from '../scripts/defaults-golden.mjs';
import {authorizationUrls} from './fixtures/auth-v1/urls.mjs';
import {versionTwoUrls, catalogDefinition} from './fixtures/auth-v2/urls.mjs';

// F10.21 part 1 (docs/F10.21-BUILD-MAP.md section 6 and part 1 g, test/f10-21-churn.test.mjs): what step 21 must not move. Part 1 adds one
// provider field, apiSuccessRequire, to catalog/auth/slack.json. The defaults table reads only a definition's scopes, consent and
// implications (scripts/defaults-golden.mjs), so no table and no data hash moves and nobody signs again: only Slack's files hash and that
// file's own hash move in the golden and the review document. Nothing that decides a request reads the auth definition's new field: rows,
// proxy settings, bindings, policy hashes and connection generations are the ones recorded before. The values below are 3129ac4's.
const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const LOADERS = json('./fixtures/access/f10-9-loaders.before.json');
const BEFORE = json('./fixtures/access/f10-9-bindings.before.json');
const F107 = json('./fixtures/access/f10-7-bindings.before.json');
const APPS = ['github', 'gmail', 'google-calendar', 'notion', 'slack'];
/** 3129ac4's defaults golden: each app's data hash (and so its sign-off) and its files hash. */
const DATA_HASHES = Object.freeze({github: '8e8689ca1f508db2985fa48c978bf42964fceaba8a452f9120e35a7598074f26', gmail: '12b50a7bc996b592fa910e872e143a1ea931688b4aec7309a61cd200c94e92fe',
  'google-calendar': '11c31be5c85edefbdfa84f87b5bfcbe302bc36971a7d933a9830789dc2999da9', notion: '33fee7708e0dda65c2ea5a6f1ea3a9832d5bfd7794cad67d609e0bd6f65c5e81',
  slack: '244d633bced5054bcfe409061a5a4c853f98520c3754a76c003f1f73b4fd5d54'});
const FILES_HASHES = Object.freeze({github: '00c50397060682d2dde753c64f300ffe47e29b1fae421ec2f08822025c1f7605', gmail: '87dd6f12fd565cd436c2ef28634c6f22bfd4f98f15b1ff6aa3499b67a9b3dca2',
  'google-calendar': 'c4f94675d06c45e53dcb955e7851b1d7e5fbedca91f9cdb923acb720f5159235', notion: 'b13b2725703c946732e924a7b9117434a8947bb8e59330c00c6dfa00ece8c686',
  slack: '7b789bbb0b07a82ccb6d6bfed615d3c1b1c11422fdd4b6448f5a420593ba6ce2'});
const SLACK_FILES = Object.freeze({'catalog/auth/slack.json': '791934a1f77347c6c14db55acc2b079a3f2048f8c0eecef70d1a2f00fccf5fe4',
  'catalog/permissions/slack.json': 'a8578c6af8f0b057fec6d8ec2ca9f866b6309651e0ad1ae34487e13e02771267', 'catalog/proxy/slack.json': 'aeba6af0bda14e448df8114ed861a66baf3b3057fbd5d1b47eefe1064ba775f8'});
/** Step 21's files hash of Slack and the new hash of its auth file. */
const SLACK_NOW = Object.freeze({filesHash: 'd553a33e16912ff5fafcc897d57147e3b9d344571b78b545174c9c9055e95c88', auth: 'ca64b3db93302fb0d7318f9993c56fa52f7d71ea9085ae8f83d1d49186471881'});
/** The block step 21 adds, and 3129ac4's digest of the file, text read with LF line ends (test/f10-12-churn.test.mjs records the same). */
const SLACK_RULE = ',\n  "apiSuccessRequire": [\n    {\n      "pointer": "/ok",\n      "equals": true\n    }\n  ]\n}';
const SLACK_AUTH_BEFORE = 'd10ce54cb494add088f022bc5c19b8d83a31c0c22709bd32a5958ba15a53200a';
const plain = value => JSON.parse(JSON.stringify(value));
const withoutRule = definition => { const {apiSuccessRequire: _rule, ...rest} = definition; return rest; };

/** Every proxy-row binding of one account, over the recorded synthetic map, as F10.9's snapshot was recorded. */
function proxyRowsOf(connection) {
  const config = PROXY_CONFIGS.get(connection.appId), definition = PERMISSION_GROUPS.get(connection.appId), policy = new ProxyPolicy({store: null});
  const templates = templatesFor(definition, config, F107.maps[connection.appId]);
  return Object.fromEntries(policy.rows({config, definition}).map(({row}) => [row, policy.binding({connection, config, templates, definition}, row)]));
}

test('Slack\'s definition differs from 3129ac4\'s by exactly apiSuccessRequire: /ok true, nothing else', () => {
  const text = readFileSync(path.join(ROOT, 'catalog', 'auth', 'slack.json'), 'utf8').replace(/\r\n/g, '\n');
  assert.equal(text.split(SLACK_RULE).length, 2, 'the block, once');
  assert.equal(createHash('sha256').update(text.replace(SLACK_RULE, '\n}')).digest('hex'), SLACK_AUTH_BEFORE, 'without it, byte for byte the recorded file');
  const now = JSON.parse(text);
  assert.deepEqual(now.apiSuccessRequire, [{pointer: '/ok', equals: true}]);
  for (const providerId of ['google', 'github', 'notion']) assert.equal(Object.hasOwn(catalogDefinition(providerId), 'apiSuccessRequire'), false, providerId);
});

test('Slack\'s rows and proxy settings load to F10.9\'s recorded output, and no proxy-row binding of any app moves', () => {
  assert.deepStrictEqual(plain(PERMISSION_GROUPS.get('slack')), LOADERS.permissionGroups.slack);
  const config = plain(PROXY_CONFIGS.get('slack'));
  assert.deepStrictEqual({...config, documented: {count: config.documented.length, hash: canonicalHash(config.documented)}}, LOADERS.proxyConfigs.slack);
  for (const appId of APPS) assert.deepEqual(proxyRowsOf(BEFORE.connections[appId]), BEFORE.proxyRows[appId], `${appId} proxy-row bindings`);
});

// F10.19's listed churn moves Notion's files hash too (its Notion-Version line and its action file; test/f10-19-churn.test.mjs pins why).
const NOTION_FILES_NOW = 'c4ad629ba73b7b9f0f90fd18d6c24048c88d5adc0dcd8b591c2f6e11fc5b7aed';
test('no data hash or sign-off moves; only Slack\'s files hash and its auth file\'s hash do, so nobody signs again', () => {
  const golden = readGolden();
  // F10.15's and F10.17's listed churn move Gmail's and GitHub's data and files hashes, and their sign-offs wait for Sami (S15.1, S17.1);
  // test/f10-15-churn.test.mjs and test/f10-17-churn.test.mjs pin both.
  for (const appId of APPS.filter(appId => appId !== 'gmail' && appId !== 'github')) {
    const entry = appEntry(ROOT, appId);
    assert.equal(entry.dataHash, DATA_HASHES[appId], `${appId} data hash`);
    assert.equal(golden.apps[appId].signedOff.dataHash, DATA_HASHES[appId], `${appId} stays signed`);
    assert.equal(entry.filesHash, appId === 'slack' ? SLACK_NOW.filesHash : appId === 'notion' ? NOTION_FILES_NOW : FILES_HASHES[appId], `${appId} files hash`);
    assert.equal(golden.apps[appId].filesHash, entry.filesHash, `${appId} golden files hash`);
  }
  assert.deepEqual(appEntry(ROOT, 'slack').files, {...SLACK_FILES, 'catalog/auth/slack.json': SLACK_NOW.auth}, 'only the auth file moved');
  assert.deepEqual(checkSigned().filter(problem => !problem.startsWith('gmail: ') && !problem.startsWith('github: ')), [], 'every app but Gmail and GitHub is signed and current');
});

test('a Slack account\'s decisions, member states (the row etag) and connection generation are the same with and without the new field', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'fabric-f10-21-churn-')), store = new Store({dataDir: dir, localAuthority: 'new'});
  t.after(() => { store.close(); rmSync(dir, {recursive: true, force: true}); });
  const connection = {...BEFORE.connections.slack, scopes: ['channels:read', 'channels:history', 'chat:write', 'reactions:write', 'users.profile:write']};
  store.put('connections', connection);
  const permissions = new PermissionManager({store}), policy = new ProxyPolicy({store, permissions});
  const decide = request => { try { return plain(policy.decide(connection.id, request)); } catch (error) { return {refused: error.code ?? error.message}; } };
  const requests = [{method: 'GET', path: '/conversations.history', query: {channel: 'C1'}}, {method: 'POST', path: '/chat.postMessage', body: {channel: 'C1', text: 'x'}},
    {method: 'POST', path: '/reactions.add', body: {channel: 'C1', timestamp: '1.000001', name: 'eyes'}}, {method: 'POST', path: '/users.profile.set', body: {profile: {status_text: 'x'}}},
    {method: 'POST', path: '/chat.delete', body: {channel: 'C1', ts: '1.000001'}}];
  const decisions = requests.map(decide);
  assert.ok(decisions.every(decision => decision.refused === undefined && decision.connectionGeneration === 1), 'each decided, on generation 1');
  assert.deepEqual(decisions.map(decision => `${decision.row} ${decision.mode}`), ['group:slack.messages.read allow', 'group:slack.messages.send ask', 'group:slack.messages.send ask',
    'group:slack.profile.write ask', 'group:slack.permanent.delete deny']);
  assert.equal(store.connectionGeneration(connection.id), 1);
  const context = policy.route(connection.id), rows = policy.rows(context);
  const states = context.templates.filter(template => !template.unreviewed && template.groupId).map(template => plain(policy.memberState(context, rows.find(item => item.group?.id === template.groupId), template.member)));
  assert.ok(states.length > 50);
  // Nothing above reads the auth definition, so the same calls give the same answers once more, and the account record never moved.
  assert.deepEqual(requests.map(decide), decisions);
  assert.equal(store.connectionGeneration(connection.id), 1);
});

test('the version 1 and version 2 authorization URL goldens are unchanged, and the new field moves no URL', () => {
  assert.deepEqual(authorizationUrls(), json('./fixtures/auth-v1/urls.golden.json'), 'T6: version 1 URLs byte for byte');
  const golden = json('./fixtures/auth-v2/urls.golden.json');
  assert.deepEqual(versionTwoUrls(), golden);
  assert.deepEqual(versionTwoUrls(providerId => withoutRule(catalogDefinition(providerId))), golden, 'without apiSuccessRequire, the same URLs');
});

// Part 2: the shipped ids are checked here, not in test/actions-slack.test.mjs, which recomputes them (withIds()) so a seeded fault inside
// the file reaches behaviour instead of tripping the id check. Slack's file needs no map: its rows are request templates.
test('Slack\'s shipped action file holds current ids: each stored id is the one its content hashes to, and the file validates with them, each certified by step 22', () => {
  const file = JSON.parse(readFileSync(path.join(ROOT, 'catalog', 'actions', 'slack.json'), 'utf8'));
  const deps = {identities: new Map([['slack', definitionFor('slack')]]), maps: new Map()};
  const ids = actionIds(file, deps);
  assert.deepEqual(file.actions.map(action => action.id), file.actions.map(action => ids.get(`${action.key} v${action.version}`).id));
  assert.equal(validateActionFile(file, deps).actions.length, 13);
  assert.equal(file.actions.filter(action => action.certified?.evidence === 'docs/live-evidence/slack/actions.json').length, 13, 'certified by step 22\'s evidence');
});

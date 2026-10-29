import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ROOT, GOLDEN_PATH, REVIEW_PATH, RATCHET_PATH, catalogApps, appEntry, defaultsTable, dataHash, filesHash, readGolden, goldenStatus, goldenDifferences, t3Problems, reviewText,
  writeGolden, signOff, checkSigned, validDate, treeCommitted} from '../scripts/defaults-golden.mjs';
import {templateChecks} from '../scripts/app-template-check.mjs';
import {validateAuthDefinition} from '../contracts/auth-definition.mts';
import {validatePermissionGroups} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {v1Definition} from './fixtures/auth-v1/urls.mjs';
import {definitionOf, rows} from './fixtures/access/f10-6-fixtures.mjs';

// F10.7 part i (docs/F10.7-BUILD-MAP.md, decisions 2 to 4): the defaults golden records, per app, the table of what every
// permission does before anyone changes it, its data hash (the hash of that table, which a sign-off binds) and a files hash for
// information. The gate is strict on currency and lenient on signing: the golden must be what the catalog gives now, and a sign-off
// is either absent or binds exactly the current table. Every sign-off below is written into a temporary folder, never the shipped
// golden: only Sami's explicit approval signs that.
const SCRIPT = fileURLToPath(new URL('../scripts/defaults-golden.mjs', import.meta.url));
const G = 'https://www.googleapis.com/auth/';
const SHIPPED = ['catalog/auth', 'catalog/permissions', 'catalog/proxy', 'catalog/apps.json', 'test/fixtures/access/google-method-scopes.json', RATCHET_PATH, 'test/fixtures/auth-v1'];
const SIGNER = 'Test signer', DAY = '2026-10-18';
const json = (root, file) => JSON.parse(readFileSync(path.join(root, file), 'utf8'));
const put = (root, file, value, text = `${JSON.stringify(value, null, 1)}\n`) => {mkdirSync(path.dirname(path.join(root, file)), {recursive: true}); writeFileSync(path.join(root, file), text);};
const change = (root, file, edit) => {const value = json(root, file); edit(value); put(root, file, value);};
const reversed = value => Array.isArray(value) ? value.map(reversed) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reversed(item)])) : value;

/** A temporary copy of everything the golden reads, without the golden itself. */
function copyRoot(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-defaults-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  for (const part of SHIPPED) cpSync(path.join(ROOT, part), path.join(root, part), {recursive: true});
  return root;
}
/** The same copy with the four version 1 sign-in definitions of test/fixtures/auth-v1, as the catalog was before F10.7's flip. */
function versionOneRoot(t) {
  const root = copyRoot(t);
  for (const providerId of ['google', 'github', 'notion', 'slack']) put(root, `catalog/auth/${providerId}.json`, v1Definition(providerId), `${JSON.stringify(v1Definition(providerId), null, 2)}\n`);
  return root;
}
/** A temporary catalog with one version 2 provider: `demo` passes T3, `demo-two` has a member with no scope data. */
function demoRoot(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-defaults-demo-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const level = (required, optional = []) => ({full: {required, optional, inContext: []}, read: null});
  put(root, 'catalog/auth/demo.json', {...v1Definition('github'), schemaVersion: 2, providerId: 'demo', displayName: 'Demo', credentialEnvironment: {clientId: 'FABRIC_DEMO_CLIENT_ID', clientSecret: 'FABRIC_DEMO_CLIENT_SECRET'},
    apps: [{appId: 'demo', accessProbe: null, access: {default: 'full', grant: 'scope', levels: level(['demo:read'], ['demo:write'])}, neverRequest: ['demo:admin']},
      {appId: 'demo-two', accessProbe: null, access: {default: 'full', grant: 'scope', levels: level(['two:read'])}, neverRequest: []}],
    scopeImplications: {}, consentPolicy: {testing: 'full', production: 'required'}});
  put(root, 'catalog/permissions/demo.json', {schemaVersion: 2, appId: 'demo', groups: [
    {id: 'demo.read', label: 'Read things', effect: 'read', defaultMode: 'allow', requests: ['GET /things', 'GET /things/{id}'], scopeSets: [['demo:read']]},
    {id: 'demo.write', label: 'Change things', effect: 'write', defaultMode: 'ask', requests: ['POST /things'], scopeSets: [['demo:write']]},
    {id: 'demo.purge', label: 'Purge things', effect: 'delete', defaultMode: 'deny', requests: ['DELETE /things/{id}'], unavailable: {'DELETE /things/{id}': 'not-requested'}},
    // Typed read rows that need the optional scope: the notes gain it at an upgrade; the archive's only member that would is unavailable.
    {id: 'demo.notes', label: 'Read the notes', effect: 'read', defaultMode: 'allow', operations: ['demo.notes.list'], scopeSets: [['demo:write']]},
    {id: 'demo.archive', label: 'Read the archive', effect: 'read', defaultMode: 'allow', operations: ['demo.archive.list', 'demo.archive.get'], scopeSets: [['demo:write']],
      memberScopeSets: {'demo.archive.list': [['demo:read']]}, unavailable: {'demo.archive.get': 'no-oauth-scope'}}]});
  put(root, 'catalog/permissions/demo-two.json', {schemaVersion: 2, appId: 'demo-two', groups: [{id: 'demo-two.read', label: 'Read the other things', effect: 'read', defaultMode: 'allow', requests: ['GET /other']}]});
  put(root, RATCHET_PATH, {note: 'test', apps: {demo: {defaults: false}, 'demo-two': {defaults: false}}});
  return root;
}

test('the defaults golden is current: every app\'s table, files and hashes equal what the catalog gives now', () => {
  const golden = readGolden(ROOT);
  assert.ok(golden, `${GOLDEN_PATH} is missing: run node scripts/defaults-golden.mjs --write`);
  assert.equal(readFileSync(path.join(ROOT, GOLDEN_PATH), 'utf8'), `${JSON.stringify(golden, null, 1)}\n`, 'one-space indentation and a final newline');
  assert.equal(golden.schema, 1);
  assert.deepEqual(catalogApps(ROOT), ['github', 'gmail', 'google-calendar', 'notion', 'slack']);
  assert.deepEqual(Object.keys(golden.apps), catalogApps(ROOT));
  for (const appId of catalogApps(ROOT)) {
    const {signedOff, previousSignedOff, ...recorded} = golden.apps[appId];
    assert.deepEqual(recorded, appEntry(ROOT, appId), `${appId}: the defaults golden is stale; run node scripts/defaults-golden.mjs --write and review what changed`);
  }
  assert.deepEqual(goldenDifferences(ROOT), [], 'run node scripts/defaults-golden.mjs --write');
});

test('a sign-off binds exactly the current table: none, or a name, a real date and the current data hash', () => {
  for (const [appId, entry] of Object.entries(readGolden(ROOT).apps)) {
    assert.ok(Object.hasOwn(entry, 'signedOff'), appId);
    for (const signature of [entry.signedOff, entry.previousSignedOff].filter(item => item !== null && item !== undefined)) {
      assert.deepEqual(Object.keys(signature).sort(), ['by', 'dataHash', 'date'], appId);
      assert.ok(typeof signature.by === 'string' && signature.by.trim().length >= 1 && signature.by.length <= 100, `${appId}: by is 1 to 100 characters`);
      assert.ok(validDate(signature.date), `${appId}: ${signature.date} is a real date`);
      assert.match(signature.dataHash, /^[a-f0-9]{64}$/, appId);
    }
    if (entry.signedOff) assert.equal(entry.signedOff.dataHash, entry.dataHash, `${appId}: the sign-off binds the current table`);
  }
  // The date check reads no clock: a UTC round trip of the written day.
  for (const day of ['2026-02-28', '2024-02-29', '2026-12-31']) assert.equal(validDate(day), true, day);
  for (const day of ['2026-02-30', '2025-02-29', '2026-13-01', '2026-00-10', '2026-1-01', '26-01-01', '2026-01-01T00:00:00Z', '', null]) assert.equal(validDate(day), false, String(day));
});

test('owner invariants hold in every table: deletes, locked rows, rows that reach other people and the upgrade lists', () => {
  const golden = readGolden(ROOT);
  for (const [appId, {table}] of Object.entries(golden.apps)) {
    const upgrade = new Set(Object.values(table.upgrade).flatMap(list => list ?? [])), hasLocked = table.rows.some(row => row.locked);
    for (const row of table.rows) {
      const where = `${appId} ${row.id}`, {declared, typed, raw} = row.defaults;
      // Deletes never default to Allow (spec line 608), on either side.
      if (row.effect === 'delete') assert.ok(![declared, typed, raw].includes('allow'), where);
      // T4: a locked row is Never on both sides, offers Never only, is never proxy-allowable and never on an upgrade list.
      if (row.locked) {
        assert.deepEqual([declared, typed, raw], ['deny', 'deny', 'deny'], where);
        assert.ok(row.rawModes === null || (row.rawModes.length === 1 && row.rawModes[0] === 'deny'), where);
        assert.equal(row.proxyAllowable, false, where);
        assert.ok(!upgrade.has(row.id), where);
      }
      // A row that reaches other people never defaults to Allow and is never proxy-allowable.
      if (row.audience) {assert.ok(typed !== 'allow' && raw !== 'allow', where); assert.equal(row.proxyAllowable, false, where);}
      if (row.proxyAllowable) assert.ok(row.rawModes.includes('allow'), where);
      // Every listed upgrade row defaults to Allow on the side that lists it.
      if (upgrade.has(row.id)) assert.ok((typed === 'allow' && row.typedMembers > 0) || raw === 'allow', where);
    }
    // T4: an app with a locked row keeps its GraphQL row Never, with no other choice.
    const graphql = table.otherRows.find(row => row.row === 'graphql');
    if (hasLocked && graphql) assert.deepEqual([graphql.default, graphql.modes], ['deny', ['deny']], appId);
  }
  // The spec's adversarial rows: Fabric's locked "Give access" rows are Never everywhere.
  for (const [appId, id] of [['gmail', 'gmail.access.grant'], ['github', 'github.access.grant'], ['google-calendar', 'google-calendar.access.grant']]) {
    const row = golden.apps[appId].table.rows.find(item => item.id === id);
    assert.deepEqual([row.locked, row.defaults.raw, row.rawModes], [true, 'deny', ['deny']], id);
  }
  // F10.7 part e: deleting a whole repository is unavailable, because Fabric never asks for delete_repo.
  const purge = golden.apps.github.table.rows.find(item => item.id === 'github.permanent.delete');
  assert.deepEqual(purge.unavailable.find(item => item.member === 'DELETE /repos/{owner}/{repo}'), {member: 'DELETE /repos/{owner}/{repo}', reason: 'not-requested'});
  assert.deepEqual([purge.defaults.raw, purge.access.full.covered, purge.members], ['deny', 22, 28]);
  // Typed and raw defaults differ exactly where a write row allows typed operations and raw requests ask (measured at 95f5aff).
  const split = Object.values(golden.apps).flatMap(({table}) => table.rows.filter(row => row.defaults.typed !== row.defaults.raw).map(row => `${row.id}:${row.defaults.typed}/${row.defaults.raw}`)).sort();
  assert.deepEqual(split, ['github.notifications.manage:allow/ask', 'gmail.drafts.write:allow/ask', 'gmail.labels.manage:allow/ask', 'google-calendar.calendarlist.write:allow/ask', 'slack.conversations.mark:allow/ask']);
});

test('the upgrade lists follow upgradeCard(): on section 5\'s definitions and the F10.6 rows they list what the build map measured', () => {
  const facts = JSON.parse(readFileSync(path.join(ROOT, 'test/fixtures/access/google-method-scopes.json'), 'utf8')), provider = {gmail: 'google', 'google-calendar': 'google', github: 'github', notion: 'notion', slack: 'slack'};
  const lists = {};
  for (const [appId, providerId] of Object.entries(provider)) {
    const table = defaultsTable({appId, definition: validateAuthDefinition(definitionOf(providerId)), groups: validatePermissionGroups(rows(appId)), config: PROXY_CONFIGS.get(appId),
      facts: providerId === 'google' ? facts : null, v1: validateAuthDefinition(v1Definition(providerId))});
    const label = id => table.rows.find(row => row.id === id).label;
    lists[appId] = Object.fromEntries(Object.entries(table.upgrade).filter(([, list]) => list !== null).map(([from, list]) => [from, list.map(label)]));
  }
  // From the version 1 read and write grant (the live card's baseline), from the required scopes only, and from Gmail's read level.
  assert.deepEqual(lists, {
    gmail: {fromV1ReadWrite: ['Manage labels'], fromRequired: [], fromRead: ['Draft emails', 'Manage labels']},
    'google-calendar': {fromV1ReadWrite: ['Check your availability', 'Access settings and calendar sharing', 'Organize your calendar list'], fromRequired: ['Check your availability', 'Access settings and calendar sharing']},
    github: {fromV1ReadWrite: ['Access profiles, activity and notifications', 'Access gists'], fromRequired: ['Access profiles, activity and notifications', 'Access gists']},
    notion: {fromV1ReadWrite: [], fromRequired: []},
    slack: {fromV1ReadWrite: ['Search messages and files', 'Access files, canvases, pins and reactions', 'Access profiles, user groups and workspace details'],
      fromRequired: ['Search messages and files', 'Access files, canvases, pins and reactions', 'Access profiles, user groups and workspace details']},
  });
});

test('the upgrade lists never count a member that can never work through a sign-in', t => {
  const root = demoRoot(t), {table} = appEntry(root, 'demo');
  assert.deepEqual(table.upgrade, {fromV1ReadWrite: null, fromRequired: ['demo.notes'], fromRead: null});
  assert.deepEqual(table.rows.find(row => row.id === 'demo.archive').access.full, {status: 'works', covered: 1, missing: 0, cannotWork: 0, noScopeData: 0});
});

test('the table reads T3 as the template check does: closure under full access, with scope data for every member', t => {
  const golden = readGolden(ROOT);
  for (const appId of catalogApps(ROOT)) {
    const checks = Object.fromEntries(templateChecks(appId).map(item => [item.id, item.pass]));
    assert.equal(t3Problems(golden.apps[appId].table).length === 0, checks.closure && checks['row-scope-data'], appId);
  }
  // F10.7: every shipped definition is version 2 and every app passes T3; a version 1 sign-in never does, and the words say why.
  for (const appId of catalogApps(ROOT)) assert.deepEqual(t3Problems(golden.apps[appId].table), [], appId);
  assert.match(t3Problems(appEntry(versionOneRoot(t), 'gmail').table)[0], /version 1/);
  // On section 5's version 2 definitions and the F10.6 rows, the T3 refusal of a sign-off says what the template check says.
  const facts = JSON.parse(readFileSync(path.join(ROOT, 'test/fixtures/access/google-method-scopes.json'), 'utf8')), provider = {gmail: 'google', 'google-calendar': 'google', github: 'github', notion: 'notion', slack: 'slack'};
  for (const [appId, providerId] of Object.entries(provider)) {
    const definition = validateAuthDefinition(definitionOf(providerId)), groups = validatePermissionGroups(rows(appId)), scopeFacts = providerId === 'google' ? facts : null;
    const checks = Object.fromEntries(templateChecks(appId, {definitions: [definition], groups, scopeFacts}).map(item => [item.id, item]));
    const problems = t3Problems(defaultsTable({appId, definition, groups, config: PROXY_CONFIGS.get(appId), facts: scopeFacts}));
    assert.equal(problems.join('; '), checks.closure.pass ? '' : checks.closure.reason, appId);
    assert.equal(problems.length === 0, checks.closure.pass && checks['row-scope-data'].pass, appId);
  }
  // Every kind of gap, each once, on a small version 2 app: a member whose scope sign-in does not ask for, one that needs a scope
  // Fabric never asks for and is not marked, one with no scope data, and an asked-for scope no member uses.
  const definition = validateAuthDefinition({...v1Definition('github'), schemaVersion: 2, providerId: 'demo', displayName: 'Demo', credentialEnvironment: {clientId: 'FABRIC_DEMO_CLIENT_ID', clientSecret: 'FABRIC_DEMO_CLIENT_SECRET'},
    apps: [{appId: 'demo', accessProbe: null, access: {default: 'full', grant: 'scope', levels: {full: {required: ['demo:read'], optional: ['demo:spare'], inContext: []}, read: null}}, neverRequest: ['demo:admin']}],
    scopeImplications: {}, consentPolicy: {testing: 'full', production: 'required'}});
  const groups = validatePermissionGroups({schemaVersion: 2, appId: 'demo', groups: [
    {id: 'demo.read', label: 'Read things', effect: 'read', defaultMode: 'allow', requests: ['GET /things'], scopeSets: [['demo:read']]},
    {id: 'demo.more', label: 'Read more things', effect: 'read', defaultMode: 'allow', requests: ['GET /more'], scopeSets: [['demo:write']]},
    {id: 'demo.admin', label: 'Administer things', effect: 'write', defaultMode: 'ask', requests: ['POST /admin'], scopeSets: [['demo:admin']]},
    {id: 'demo.plain', label: 'Read plain things', effect: 'read', defaultMode: 'allow', requests: ['GET /plain']}]});
  const problems = t3Problems(defaultsTable({appId: 'demo', definition, groups}));
  assert.deepEqual(problems, ['1 member(s) lack a scope', '1 member(s) can never work and are not marked unavailable', '1 member(s) have no scope data', 'unjustified scopes: demo:spare']);
  assert.equal(problems.join('; '), templateChecks('demo', {definitions: [definition], groups, scopeFacts: null}).find(item => item.id === 'closure').reason);
});

test('check 4 reads the table the golden records: on the shipped catalog a sign-off of each recorded data hash passes it, and a change of meaning does not', t => {
  const root = copyRoot(t), defaults = appId => templateChecks(appId, {root}).find(item => item.id === 'defaults');
  writeGolden({root});
  for (const appId of catalogApps(root)) assert.equal(defaults(appId).reason, 'the defaults table is not signed yet', appId);
  // Signed by hand in this temporary copy only, as signOff() would sign each recorded data hash (it refuses version 1 sign-ins).
  change(root, GOLDEN_PATH, golden => {for (const entry of Object.values(golden.apps)) entry.signedOff = {by: SIGNER, date: DAY, dataHash: entry.dataHash};});
  for (const appId of catalogApps(root)) assert.deepEqual([defaults(appId).pass, defaults(appId).reason], [true, 'passes'], `${appId}: check 4 computes the golden's table`);
  // The copy's proxy settings and Discovery facts are what check 4 reads, beside the loaded definition and rows.
  change(root, 'catalog/proxy/gmail.json', config => {config.proxyAllowable = [];});
  change(root, 'test/fixtures/access/google-method-scopes.json', facts => {facts.apps['google-calendar'].methods['calendar.events.list'] = [`${G}calendar`];});
  assert.deepEqual(catalogApps(root).filter(appId => !defaults(appId).pass), ['gmail', 'google-calendar']);
  assert.equal(defaults('gmail').reason, 'the data changed since the owner signed the defaults');
});

test('treeCommitted() asks git: true only at the top of a work tree with nothing uncommitted under the files a sign-off rests on', t => {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), 'fabric-defaults-git-')));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  // Git with no user or system settings, so no hook, signing or global ignore rule takes part, and never a repository above this folder.
  const git = (...args) => {const run = spawnSync('git', ['-C', root, '-c', 'user.name=Test signer', '-c', 'user.email=signer@example.invalid', '-c', 'commit.gpgsign=false', ...args],
    {encoding: 'utf8', env: {PATH: process.env.PATH, HOME: root, XDG_CONFIG_HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CEILING_DIRECTORIES: path.dirname(root)}}); assert.equal(run.status, 0, run.stderr); return run.stdout;};
  assert.equal(treeCommitted(root), false, 'not a git work tree');
  git('init', '-q');
  for (const file of ['catalog/auth/demo.json', 'test/fixtures/access/demo.json', 'test/fixtures/auth-v1/demo.json', REVIEW_PATH, 'notes.txt', '.gitignore']) put(root, file, null, file === '.gitignore' ? 'copy/\n' : `${file}\n`);
  git('add', '.');
  assert.equal(treeCommitted(root), false, 'staged, not committed');
  git('commit', '-q', '-m', 'first');
  assert.equal(treeCommitted(root), true);
  const dirty = (edit, message) => {edit(); assert.equal(treeCommitted(root), false, message); git('checkout', '-q', 'HEAD', '--', '.'); git('clean', '-q', '-f', '--', '.'); assert.equal(treeCommitted(root), true, `${message}, put back`);};
  dirty(() => writeFileSync(path.join(root, 'catalog/auth/demo.json'), 'changed\n'), 'a changed catalog file');
  dirty(() => writeFileSync(path.join(root, 'test/fixtures/access/new.json'), '{}\n'), 'a new file beside the golden');
  dirty(() => rmSync(path.join(root, 'test/fixtures/auth-v1/demo.json')), 'a removed version 1 fixture');
  dirty(() => writeFileSync(path.join(root, REVIEW_PATH), 'changed\n'), 'a changed review document');
  // A change outside those files does not count.
  writeFileSync(path.join(root, 'notes.txt'), 'changed\n');
  assert.equal(treeCommitted(root), true);
  // A folder git ignores shows nothing in git status, yet nothing in it is committed: it is not the top of a work tree.
  for (const part of ['catalog/auth/demo.json', REVIEW_PATH]) put(path.join(root, 'copy'), part, null, 'copied\n');
  assert.equal(git('status', '--porcelain', '--untracked-files=all'), ' M notes.txt\n');
  assert.equal(treeCommitted(path.join(root, 'copy')), false);
});

test('the data hash is the hash of the table and the files hash covers the four files: formatting moves neither, a change of meaning moves them, each app only its own', t => {
  // Known answers pin both algorithms.
  assert.equal(dataHash('demo', {rows: []}), '60be2c400bd3440006c2e61ccf4ff2c17ee433f49dafe71d64340cdefeeb3413');
  assert.equal(filesHash('demo', {'catalog/auth/demo.json': '0'.repeat(64)}), '947b2c075d08c0bfb33eb940097c568b1295304096ab25ef08e04778699e7418');
  const root = copyRoot(t), entries = () => Object.fromEntries(catalogApps(root).map(appId => [appId, appEntry(root, appId)])), base = entries();
  assert.deepEqual(base, Object.fromEntries(catalogApps(ROOT).map(appId => [appId, appEntry(ROOT, appId)])), 'a copy of the catalog gives the same entries');
  assert.deepEqual(Object.keys(base.gmail.files), ['catalog/auth/google.json', 'catalog/permissions/gmail.json', 'catalog/proxy/gmail.json']);
  assert.deepEqual(Object.keys(base.github.files), ['catalog/auth/github.json', 'catalog/permissions/github.json', 'catalog/proxy/github.json', 'catalog/proxy/github.routes.json']);
  const moves = (file, edit, expected, message) => {
    const text = readFileSync(path.join(root, file), 'utf8');
    try {
      edit(file);
      const now = entries(), moved = key => Object.keys(now).filter(appId => now[appId][key] !== base[appId][key]).sort();
      assert.deepEqual({data: moved('dataHash'), files: moved('filesHash')}, expected, message);
    } finally {writeFileSync(path.join(root, file), text);}
  };
  const reformat = file => put(root, file, null, JSON.stringify(reversed(json(root, file)), null, 4).replace(/\n/g, '\r\n'));
  moves('catalog/permissions/gmail.json', reformat, {data: [], files: []}, 'indentation, line endings and key order move nothing');
  moves('catalog/auth/google.json', reformat, {data: [], files: []}, 'nor in an auth file');
  moves('catalog/proxy/github.json', reformat, {data: [], files: []}, 'nor in a proxy file');
  moves('catalog/permissions/gmail.json', file => change(root, file, rows => {rows.groups[0].label = 'Read drafts'}), {data: ['gmail'], files: ['gmail']}, 'one changed value');
  moves('catalog/permissions/gmail.json', file => change(root, file, rows => {rows.groups[0].operations.push('gmail.users.example.get')}), {data: ['gmail'], files: ['gmail']}, 'an added member');
  moves('catalog/proxy/gmail.json', file => change(root, file, config => {config.proxyAllowable = []}), {data: ['gmail'], files: ['gmail']}, 'a changed proxyAllowable');
  moves('catalog/proxy/github.routes.json', file => change(root, file, routes => {routes.retrieved = '2026-10-13'}), {data: [], files: ['github']}, 'the routes file counts for GitHub, as information');
  moves('catalog/auth/google.json', file => change(root, file, definition => {definition.authorization.identityScopes.push('profile')}), {data: ['gmail', 'google-calendar'], files: ['gmail', 'google-calendar']},
    'a Google sign-in change moves Gmail and Calendar, never GitHub');
  moves('catalog/auth/google.json', file => change(root, file, definition => {definition.apps[1].accessProbe.url = 'https://gmail.googleapis.com/gmail/v1/users/me/profile?fields=historyId'}),
    {data: [], files: ['gmail', 'google-calendar']}, 'a change the table does not show moves only the files hash');
});

test('--write never signs; it keeps a sign-off while the table is the one signed, and otherwise moves it aside, turns the ratchet off and says so', t => {
  const root = copyRoot(t), first = writeGolden({root});
  assert.deepEqual(first.messages, []);
  for (const entry of Object.values(first.golden.apps)) assert.equal(entry.signedOff, null);
  assert.equal(readFileSync(path.join(root, REVIEW_PATH), 'utf8'), reviewText(first.golden));
  assert.deepEqual(goldenDifferences(root), []);
  // A sign-off as signOff() records one (signOff() needs version 2; see the next test), written into this temporary copy only.
  const signed = {by: SIGNER, date: DAY, dataHash: first.golden.apps.gmail.dataHash};
  change(root, GOLDEN_PATH, golden => {golden.apps.gmail.signedOff = signed;});
  change(root, RATCHET_PATH, ratchet => {ratchet.apps.gmail.defaults = true;});
  assert.equal(goldenStatus('gmail', {root}).pass, true);
  // A change to the files alone (Gmail's access probe) moves the files hash and keeps the sign-off.
  change(root, 'catalog/auth/google.json', definition => {definition.apps[1].accessProbe.url = 'https://gmail.googleapis.com/gmail/v1/users/me/profile?fields=historyId';});
  let result = writeGolden({root});
  assert.deepEqual(result.messages, []);
  assert.deepEqual(result.golden.apps.gmail.signedOff, signed);
  assert.notEqual(result.golden.apps.gmail.filesHash, first.golden.apps.gmail.filesHash);
  assert.equal(json(root, RATCHET_PATH).apps.gmail.defaults, true);
  // A change to the table alone (Discovery's facts: listing messages now needs gmail.modify; no catalog file moves) needs a new sign-off.
  const files = result.golden.apps.gmail.filesHash;
  change(root, 'test/fixtures/access/google-method-scopes.json', facts => {facts.apps.gmail.methods['gmail.users.messages.list'] = [`${G}gmail.modify`];});
  result = writeGolden({root});
  assert.deepEqual(result.messages, ['Sami must sign gmail again']);
  assert.equal(result.golden.apps.gmail.signedOff, null);
  assert.deepEqual(result.golden.apps.gmail.previousSignedOff, signed);
  assert.equal(result.golden.apps.gmail.filesHash, files, 'no catalog file moved');
  assert.equal(json(root, RATCHET_PATH).apps.gmail.defaults, false);
  assert.equal(goldenStatus('gmail', {root}).reason, 'the defaults table is not signed yet');
  // The aside sign-off stays on later writes, and nothing else signs.
  result = writeGolden({root});
  assert.deepEqual([result.messages, result.golden.apps.gmail.previousSignedOff], [[], signed]);
  assert.ok(Object.values(result.golden.apps).every(entry => entry.signedOff === null));
});

test('signOff() records a sign-off only for named apps whose table is current, whose sign-in is version 2 and passes T3, with the printed prefix, a name and a real date, on a committed tree', t => {
  const root = demoRoot(t);
  writeGolden({root});
  const golden = readGolden(root), review = readFileSync(path.join(root, REVIEW_PATH), 'utf8'), prefix = golden.apps.demo.dataHash.slice(0, 12);
  const ok = {root, apps: ['demo'], by: SIGNER, date: DAY, prefixes: {demo: prefix}, committed: () => true};
  const refuses = (overrides, pattern) => {
    assert.throws(() => signOff({...ok, ...overrides}), pattern);
    assert.deepEqual(readGolden(root), golden, 'a refused sign-off writes nothing');
    assert.equal(json(root, RATCHET_PATH).apps.demo.defaults, false);
  };
  refuses({prefixes: {demo: 'f'.repeat(12)}}, /prefix/);
  refuses({prefixes: {demo: golden.apps.demo.dataHash.slice(0, 11)}}, /prefix/);
  refuses({prefixes: {}}, /prefix/);
  refuses({by: ''}, /name/);
  refuses({by: '   '}, /name/);
  refuses({by: 'x'.repeat(101)}, /name/);
  refuses({by: 'someone@example.com'}, /email/);
  refuses({date: '2026-02-30'}, /date/);
  refuses({date: '18-10-2026'}, /date/);
  refuses({apps: []}, /Name the apps/);
  refuses({apps: ['nothing']}, /nothing is not in the defaults golden/);
  refuses({apps: ['demo-two'], prefixes: {'demo-two': golden.apps['demo-two'].dataHash.slice(0, 12)}}, /demo-two does not pass T3: 1 member\(s\) have no scope data; unjustified scopes: two:read/);
  refuses({committed: () => false}, /committed/);
  refuses({committed: undefined}, /committed/);
  // A stale golden: the data moved after the review was written.
  const rows = readFileSync(path.join(root, 'catalog/permissions/demo.json'), 'utf8');
  change(root, 'catalog/permissions/demo.json', value => {value.groups[0].label = 'Read every thing';});
  refuses({}, /not current.*--write/s);
  writeFileSync(path.join(root, 'catalog/permissions/demo.json'), rows);
  // A version 1 sign-in is never signed.
  const shipped = versionOneRoot(t);
  writeGolden({root: shipped});
  assert.throws(() => signOff({root: shipped, apps: ['gmail'], by: SIGNER, date: DAY, prefixes: {gmail: readGolden(shipped).apps.gmail.dataHash.slice(0, 12)}, committed: () => true}), /gmail signs in with version 1/);
  assert.equal(readGolden(shipped).apps.gmail.signedOff, null);

  // Everything right: only the named app is signed, and its ratchet entry turns on.
  assert.deepEqual(signOff({...ok, prefixes: {demo: prefix.toUpperCase()}}), {signed: ['demo']});
  const after = readGolden(root);
  assert.deepEqual(after.apps.demo.signedOff, {by: SIGNER, date: DAY, dataHash: golden.apps.demo.dataHash});
  assert.equal(after.apps['demo-two'].signedOff, null, 'only the named apps are signed');
  assert.deepEqual(json(root, RATCHET_PATH).apps, {demo: {defaults: true}, 'demo-two': {defaults: false}});
  // Decision 4: the review document ignores the signature, so signing leaves it byte for byte and the golden stays current.
  assert.equal(readFileSync(path.join(root, REVIEW_PATH), 'utf8'), review);
  assert.deepEqual(goldenDifferences(root), []);
  assert.deepEqual(goldenStatus('demo', {root}), {state: 'signed', pass: true, reason: 'passes'});
  // A change of meaning after signing: the sign-off no longer counts, and --write moves it aside.
  change(root, 'catalog/permissions/demo.json', value => {value.groups[1].defaultMode = 'deny';});
  assert.equal(goldenStatus('demo', {root}).reason, 'the data changed since the owner signed the defaults');
  assert.deepEqual(writeGolden({root}).messages, ['Sami must sign demo again']);
  assert.deepEqual(json(root, RATCHET_PATH).apps.demo, {defaults: false});
});

test('--check-signed fails while any app of a version 2 sign-in is unsigned or signed against another table, and the command line says why', t => {
  const root = demoRoot(t);
  writeGolden({root});
  assert.deepEqual(checkSigned({root}), ['demo: the defaults table is not signed yet', 'demo-two: the defaults table is not signed yet']);
  signOff({root, apps: ['demo'], by: SIGNER, date: DAY, prefixes: {demo: readGolden(root).apps.demo.dataHash.slice(0, 12)}, committed: () => true});
  assert.deepEqual(checkSigned({root}), ['demo-two: the defaults table is not signed yet']);
  // A signature against another table does not count.
  change(root, GOLDEN_PATH, golden => {golden.apps.demo.signedOff.dataHash = '0'.repeat(64);});
  assert.deepEqual(checkSigned({root}), ['demo: the table changed since the owner signed the defaults', 'demo-two: the defaults table is not signed yet']);
  // Version 1 sign-ins are not asked for: they widen nothing. Since F10.7 every shipped sign-in is version 2, so each app waits for Sami.
  const shipped = versionOneRoot(t), flipped = copyRoot(t);
  writeGolden({root: shipped}); writeGolden({root: flipped});
  assert.deepEqual(checkSigned({root: shipped}), []);
  assert.deepEqual(checkSigned({root: flipped}), catalogApps(flipped).map(appId => `${appId}: the defaults table is not signed yet`));

  const run = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], {encoding: 'utf8'});
  const signedCheck = run('--check-signed', '--root', root);
  assert.equal(signedCheck.status, 1);
  assert.match(signedCheck.stderr, /demo-two: the defaults table is not signed yet/);
  assert.equal(run('--check', '--root', shipped).status, 0);
  change(shipped, 'catalog/proxy/gmail.json', config => {config.proxyAllowable = [];});
  const stale = run('--check', '--root', shipped);
  assert.equal(stale.status, 1);
  assert.match(stale.stderr, /gmail: dataHash differs/);
  assert.match(stale.stderr, /node scripts\/defaults-golden\.mjs --write/);
  assert.equal(run('--sign', '--root', root).status, 2, 'a sign-off names its apps, signer, date and prefixes');
});

test('the review document is what reviewText() writes from the golden: every row, every prefix, plain words, and no signature', () => {
  const golden = readGolden(ROOT), text = readFileSync(path.join(ROOT, REVIEW_PATH), 'utf8');
  assert.equal(text, reviewText(golden), `${REVIEW_PATH} is stale: run node scripts/defaults-golden.mjs --write`);
  assert.ok(!text.includes('\u2014'), 'no em dash');
  for (const [appId, entry] of Object.entries(golden.apps)) {
    assert.ok(text.includes(`\`${entry.dataHash}\``) && text.includes(`\`${entry.dataHash.slice(0, 12)}\``), `${appId}: the data hash and its prefix`);
    for (const row of entry.table.rows) assert.ok(text.includes(`| ${row.label} (\`${row.id}\`) |`), `${appId}: ${row.id}`);
  }
  assert.match(text, /node scripts\/defaults-golden\.mjs --sign --apps /);
  for (const step of ['F10.9', 'F10.15', 'F10.17', 'F10.19', 'F10.21']) assert.ok(text.includes(step), step);
  // Decision 4: signing leaves the document byte for byte.
  const signed = structuredClone(golden);
  for (const entry of Object.values(signed.apps)) {entry.signedOff = {by: SIGNER, date: DAY, dataHash: entry.dataHash}; entry.previousSignedOff = {by: SIGNER, date: '2026-10-01', dataHash: '0'.repeat(64)};}
  assert.equal(reviewText(signed), text);
});

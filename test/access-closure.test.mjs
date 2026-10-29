import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {closure, rowCoverage, operationsFromScopeLists, operationsFromRows, alternativesOf, grantedFor, unscopedOperations} from '../lib/access-closure.mjs';
import {accessReport} from '../scripts/coverage.mjs';
import {PERMISSION_GROUPS, validatePermissionGroups} from '../lib/permission-groups.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {v1Definition, PROVIDERS} from './fixtures/auth-v1/urls.mjs';
import {definitionOf} from './fixtures/access/f10-6-fixtures.mjs';

// F10.1 access closure (five apps deep). Offline: Google's documented scopes per method come from a facts-only
// fixture (test/fixtures/access/google-method-scopes.json, Discovery revision 20261005). The golden file is a ratchet:
// it records what each sign-in covers today, and every later slice changes it on purpose with the reason in its commit.
// F10.7: the historical runs read the version 1 Google definition in test/fixtures/auth-v1, so they keep their keys; their results move
// only with the rows (the Gmail delete split). Version 2 readings use the section 5 definitions of test/fixtures/access/f10-6-fixtures.mjs,
// and the `:full` runs read each app's shipped definition at its full level, with its own never list (T3).
const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'access');
const SCOPES = JSON.parse(readFileSync(path.join(FIXTURES, 'google-method-scopes.json'), 'utf8'));
const GOLDEN = JSON.parse(readFileSync(path.join(FIXTURES, 'closure.golden.json'), 'utf8'));
const G = 'https://www.googleapis.com/auth/';
const NEVER = ['https://mail.google.com/', `${G}gmail.settings.sharing`, `${G}gmail.metadata`, `${G}gmail.insert`];
const google = v1Definition('google');
const run = (appId, level, scopes, never = NEVER) => closure({definition: google, appId, level, scopes: scopes?.map(scope => G + scope), groups: PERMISSION_GROUPS.get(appId).groups,
  operations: operationsFromScopeLists(SCOPES.apps[appId].methods), neverRequest: never});
// Decision 2 (docs/F10-FIVE-APPS-DEEP.md section 6): Calendar's default is six narrow scopes and the broad `calendar` scope is never requested.
const CALENDAR_SIX = ['calendar.events', 'calendar.calendarlist', 'calendar.calendars', 'calendar.acls', 'calendar.settings.readonly', 'calendar.freebusy'];
// What the golden file keeps: the summary and, for every row that does not fully work, exactly which members fall short, and which
// can never work through a sign-in and say why (F10.6).
const shape = report => ({summary: report.summary, unjustified: report.unjustified, gaps: report.rows.filter(row => row.status !== 'works').map(row => ({row: row.id, status: row.status,
  missing: row.missing.map(item => item.member), cannotWork: row.cannotWork.map(item => item.member), unmapped: row.unmapped, noScopes: row.noScopes, unavailable: row.unavailable.map(item => item.member)}))});
const RUNS = {'gmail:read': ['gmail', 'read'], 'gmail:write': ['gmail', 'write'], 'gmail:full-proposed': ['gmail', null, ['gmail.modify', 'gmail.settings.basic']],
  'google-calendar:read': ['google-calendar', 'read'], 'google-calendar:write': ['google-calendar', 'write'], 'google-calendar:full-proposed': ['google-calendar', null, ['calendar']],
  'google-calendar:six-scopes': ['google-calendar', null, CALENDAR_SIX, [`${G}calendar`]]};
// T3 (F10.7): every app's shipped sign-in at its full level, over Discovery's facts where Google publishes them and the rows' own data.
const PROVIDER = {gmail: 'google', 'google-calendar': 'google', github: 'github', notion: 'notion', slack: 'slack'};
const full = appId => {
  const groups = PERMISSION_GROUPS.get(appId).groups;
  return closure({definition: definitionFor(PROVIDER[appId]), appId, level: 'full', groups, operations: operationsFromRows(groups, SCOPES.apps[appId]?.methods ?? null)});
};
const FULL = Object.keys(PROVIDER).map(appId => `${appId}:full`);

test('the closure of every Google sign-in level, and of every app at its shipped full level, matches the recorded ratchet', () => {
  for (const [key, [appId, level, scopes, never]] of Object.entries(RUNS)) assert.deepEqual(shape(run(appId, level, scopes, never)), GOLDEN[key], key);
  for (const key of FULL) assert.deepEqual(shape(full(key.split(':')[0])), GOLDEN[key], key);
  assert.deepEqual(Object.keys(GOLDEN).sort(), [...Object.keys(RUNS), ...FULL].sort());
});

test('T3: under its full level every app has no missing member, no unmarked member that cannot work and no unjustified scope', () => {
  for (const appId of Object.keys(PROVIDER)) {
    const report = full(appId), rows = report.rows;
    assert.deepEqual([rows.flatMap(row => row.missing), rows.flatMap(row => row.cannotWork), rows.flatMap(row => [...row.unmapped, ...row.noScopes]), report.unjustified], [[], [], [], []], appId);
  }
  assert.deepEqual(full('gmail').summary, {rows: 14, works: 12, partial: 0, blocked: 0, unknown: 0, locked: 1, unavailable: 1, members: 79, coveredMembers: 55, unavailableMembers: 24});
  assert.deepEqual([full('google-calendar').summary.coveredMembers, full('google-calendar').summary.members], [38, 38]);
  // GitHub: the delete row works for 22 of its 28 members; the other six say why.
  const deletes = full('github').rows.find(row => row.id === 'github.permanent.delete');
  assert.deepEqual([deletes.status, deletes.covered, deletes.total, deletes.unavailable.length], ['works', 22, 28, 6]);
});

test('version 1 Gmail "read and write" leaves eight rows short; the full set leaves only members that say why they can never work by sign-in', () => {
  // F10.7: the delete split adds a row, which version 1's grant leaves short too.
  const write = run('gmail', 'write');
  assert.equal(write.rows.filter(row => row.status !== 'works').length, 8);
  const full = run('gmail', null, ['gmail.modify', 'gmail.settings.basic']);
  assert.deepEqual(full.rows.flatMap(row => row.missing), [], 'nothing missing that a requestable scope could add');
  // The three full-mailbox deletes are marked not-requested now (F10.7), so none is left that cannot work without saying why.
  assert.deepEqual(full.rows.flatMap(row => row.cannotWork.map(item => item.member)), []);
  // The members a sign-in can never use say so instead (F10.6): the eight sharing-only members among the 24 the rows mark.
  const unavailable = full.rows.flatMap(row => row.unavailable.map(item => item.member));
  assert.equal(unavailable.length, 24);
  assert.deepEqual(full.rows.find(row => row.id === 'gmail.permanent.delete').unavailable.map(item => [item.member, item.reason]),
    [['gmail.users.messages.delete', 'not-requested'], ['gmail.users.messages.batchDelete', 'not-requested'], ['gmail.users.threads.delete', 'not-requested'], ['gmail.users.settings.cse.keypairs.obliterate', 'workspace-cse-only']]);
  assert.deepEqual(full.rows.find(row => row.id === 'gmail.access.grant').unavailable.map(item => item.member).sort(), ['gmail.users.settings.delegates.create', 'gmail.users.settings.delegates.delete',
    'gmail.users.settings.forwardingAddresses.create', 'gmail.users.settings.forwardingAddresses.delete', 'gmail.users.settings.sendAs.create', 'gmail.users.settings.sendAs.delete',
    'gmail.users.settings.sendAs.verify', 'gmail.users.settings.updateAutoForwarding']);
  // The row Fabric locks has its own status (F10.6): its members are still measured, and its scopes justify nothing.
  const LOCKED_ROW = {rows: 12, works: 11, partial: 0, blocked: 0, unknown: 0, locked: 1, unavailable: 0, members: 38, coveredMembers: 38, unavailableMembers: 0};
  assert.deepEqual(run('google-calendar', null, ['calendar']).summary, LOCKED_ROW);
  // The six narrow Calendar scopes cover the same 38 methods with `calendar` never requested, and each of them is used.
  const narrow = run('google-calendar', null, CALENDAR_SIX, [`${G}calendar`]);
  assert.deepEqual(narrow.summary, LOCKED_ROW);
  assert.deepEqual(narrow.unjustified, []);
  // Dropping any one of the six leaves some row short: none is spare.
  for (const scope of CALENDAR_SIX) assert.ok(run('google-calendar', null, CALENDAR_SIX.filter(item => item !== scope), [`${G}calendar`]).summary.coveredMembers < 38, scope);
});

test('apps whose rows carry proxy requests, read with no scope data, report every member as unknown, never blocked, apart from the members no sign-in can use', async () => {
  // F10.7 marked GitHub's never-requested deletes and locked-row members, and Slack's admin and app-setup methods.
  for (const [appId, locked, unavailable, unavailableMembers] of [['github', 1, 0, 68], ['notion', 0, 1, 3], ['slack', 0, 0, 182]]) {
    const {groups} = PERMISSION_GROUPS.get(appId), members = groups.reduce((sum, group) => sum + group.operations.length + group.requests.length, 0);
    const report = rowCoverage({groups, operations: unscopedOperations(groups), granted: []});
    assert.ok(members > 0, appId);
    assert.deepEqual(report.summary, {rows: groups.length, works: 0, partial: 0, blocked: 0, unknown: groups.length - locked - unavailable, locked, unavailable, members, coveredMembers: 0, unavailableMembers}, appId);
  }
  // The command-line report reads the same facts: Gmail write from the fixture, GitHub from its rows' own scope data (F10.7). Both read
  // the version 1 definitions, whose levels are read and write.
  assert.equal((await accessReport('google:gmail:write', {definition: v1Definition('google')})).summary.works, 6);
  const github = (await accessReport('github:github:write', {definition: v1Definition('github')})).summary;
  assert.deepEqual([github.works, github.unknown, github.locked], [8, 0, 1], 'read:user and repo; the row Fabric locks is locked, not unknown');
  const calendar = await accessReport('google:google-calendar:read', {grant: [`${G}calendar`], definition: v1Definition('google')});
  assert.deepEqual([calendar.summary.works, calendar.summary.locked], [11, 1]);
  await assert.rejects(accessReport('google:gmail'), /needs <providerId>:<appId>:<level>/);
});

test('adversarial: an unused scope is unjustified, a member needing only a never-request scope cannot work, unknown members are reported', () => {
  const groups = [{id: 'app.read', label: 'Read', effect: 'read', defaultMode: 'allow', operations: ['op.list', 'op.ghost', 'op.open']}, {id: 'app.purge', label: 'Purge', effect: 'delete', defaultMode: 'deny', operations: ['op.purge']}];
  const operations = new Map([['op.list', {scopeSets: [['read']]}], ['op.purge', {requiredScopes: ['root']}], ['op.open', {}]]);
  const report = rowCoverage({groups, operations, granted: ['read', 'drive', 'openid'], identityScopes: ['openid'], neverRequest: ['root']});
  assert.deepEqual(report.unjustified, ['drive'], 'a granted scope no member uses is flagged; identity scopes are not');
  assert.deepEqual(report.rows[0].unmapped, ['op.ghost']);
  assert.deepEqual(report.rows[0].noScopes, ['op.open']);
  assert.equal(report.rows[0].status, 'partial');
  assert.deepEqual(report.rows[1].cannotWork, [{member: 'op.purge', alternatives: [['root']]}]);
  assert.equal(report.rows[1].status, 'blocked');
  // An alternative that needs two scopes counts only when both are granted.
  assert.equal(rowCoverage({groups: [{id: 'x', label: 'X', effect: 'read', defaultMode: 'allow', operations: ['both']}], operations: new Map([['both', {scopeSets: [['a', 'b']]}]]), granted: ['a']}).rows[0].status, 'blocked');
  assert.deepEqual(alternativesOf({requiredScopes: ['b', 'a']}), [['b'], ['a']]);
  assert.deepEqual(alternativesOf({scopeSets: [['b', 'a', 'a']]}), [['a', 'b']]);
  // Slack asks for its scopes as user scopes; they are part of what the sign-in grants.
  assert.deepEqual(grantedFor(v1Definition('slack'), 'slack', 'write'), ['channels:history', 'channels:read', 'chat:write', 'users:read']);
  assert.throws(() => grantedFor(google, 'gmail', 'everything'), /No everything scope set for gmail/);
  assert.throws(() => rowCoverage({groups, operations: {}, granted: []}), /needs groups, an operation map/);
});

const cannot = report => report.rows.flatMap(row => row.cannotWork.map(item => item.member)).sort();
const missing = report => report.rows.flatMap(row => row.missing.map(item => item.member)).sort();
// The three Gmail members whose only scope is the full mailbox, which Gmail's version 2 never list holds.
const FULL_MAILBOX_ONLY = ['gmail.users.messages.batchDelete', 'gmail.users.messages.delete', 'gmail.users.threads.delete'];

test('F10.7: a version 2 sign-in is read through its levels: full is every full-level scope, read is the read level, and write is refused', () => {
  const v2 = definitionOf('google'), IDENTITY = v2.authorization.identityScopes, gmail = scopes => [...IDENTITY, ...scopes.map(scope => G + scope)].sort();
  assert.deepEqual(grantedFor(v2, 'gmail', 'full'), gmail(['gmail.modify', 'gmail.settings.basic']));
  assert.deepEqual(grantedFor(v2, 'gmail', 'read'), gmail(['gmail.readonly']));
  assert.deepEqual(grantedFor(v2, 'google-calendar', 'full'), gmail(CALENDAR_SIX), 'required and optional scopes');
  // The full level holds its in-context scopes too (Slack's channels:write and groups:write); a pages grant asks for no scope.
  const slack = definitionOf('slack'), {full} = slack.apps[0].access.levels;
  assert.deepEqual(grantedFor(slack, 'slack', 'full'), [...full.required, ...full.optional, 'channels:write', 'groups:write'].sort());
  assert.deepEqual(grantedFor(definitionOf('notion'), 'notion', 'full'), []);
  // write is a version 1 word; a level the sign-in does not have, or an app it does not carry, is refused.
  assert.throws(() => grantedFor(v2, 'gmail', 'write'), /^Error: No write scope set for gmail: a version 2 sign-in definition calls it full\.$/);
  assert.throws(() => grantedFor(v2, 'google-calendar', 'read'), /^Error: No read scope set for google-calendar: its sign-in has no read level\.$/);
  assert.throws(() => grantedFor(v2, 'gmail', 'everything'), /^Error: No everything scope set for gmail\.$/);
  assert.throws(() => grantedFor(v2, 'drive', 'full'), /^Error: No full scope set for drive\.$/);
  // Version 1 keeps read and write, and reads full as write, so either version answers full.
  for (const providerId of PROVIDERS) {
    const v1 = v1Definition(providerId);
    for (const {appId} of v1.apps) assert.deepEqual(grantedFor(v1, appId, 'full'), grantedFor(v1, appId, 'write'), appId);
  }
  assert.deepEqual(grantedFor(v1Definition('google'), 'gmail', 'full'), gmail(['gmail.compose', 'gmail.readonly']));
  assert.deepEqual(grantedFor(v1Definition('google'), 'gmail', 'read'), gmail(['gmail.readonly']));
});

// The Gmail rows as F10.6 shipped them, before part e marked the three full-mailbox deletes not-requested: there only the never list
// says they cannot work, so they show whether it is read.
const F10_6_GMAIL = validatePermissionGroups(JSON.parse(readFileSync(path.join(FIXTURES, 'f10-6-rows.snapshot.json'), 'utf8')).apps.gmail);

test("F10.7: closure() and accessReport() read the app's own never list unless one is passed", async t => {
  const shipped = PERMISSION_GROUPS.get('gmail');
  PERMISSION_GROUPS.set('gmail', F10_6_GMAIL);
  t.after(() => PERMISSION_GROUPS.set('gmail', shipped));
  const v2 = definitionOf('google'), groups = PERMISSION_GROUPS.get('gmail').groups, operations = operationsFromScopeLists(SCOPES.apps.gmail.methods);
  const own = closure({definition: v2, appId: 'gmail', level: 'full', groups, operations});
  assert.equal(own.level, 'full');
  assert.deepEqual(own.granted, grantedFor(v2, 'gmail', 'full'));
  assert.deepEqual(cannot(own), FULL_MAILBOX_ONLY, 'the full mailbox is on Gmail\'s never list');
  assert.deepEqual(shape(own), shape(run('gmail', null, ['gmail.modify', 'gmail.settings.basic'])), 'the historical run passes the same list by hand');
  // A list passed in still wins, and a version 1 app has none: the three members then lack a scope a sign-in could add.
  const none = closure({definition: v2, appId: 'gmail', level: 'full', groups, operations, neverRequest: []});
  assert.deepEqual([cannot(none), missing(none)], [[], FULL_MAILBOX_ONLY]);
  const v1 = closure({definition: v1Definition('google'), appId: 'gmail', level: 'full', groups, operations});
  assert.deepEqual([v1.level, v1.granted, cannot(v1)], ['full', grantedFor(v1Definition('google'), 'gmail', 'write'), []]);
  // An explicit scope list reads the app's never list too; an app the definition does not carry has none to read.
  assert.deepEqual(cannot(closure({definition: v2, appId: 'gmail', scopes: [`${G}gmail.modify`], groups, operations})), FULL_MAILBOX_ONLY);
  assert.throws(() => closure({definition: v2, appId: 'drive', scopes: [], groups, operations}), /^Error: No sign-in for drive in the google definition\.$/);
  // Calendar's never list holds the broad scope: a grant of it alone covers everything, and nothing it would add is asked for.
  const calendar = closure({definition: v2, appId: 'google-calendar', level: 'full', groups: PERMISSION_GROUPS.get('google-calendar').groups, operations: operationsFromScopeLists(SCOPES.apps['google-calendar'].methods)});
  assert.deepEqual(shape(calendar), shape(run('google-calendar', null, CALENDAR_SIX, [`${G}calendar`])));
  // The command-line report: the app's never list by default, --never in its place, the level words of each version.
  assert.deepEqual(cannot(await accessReport('google:gmail:full', {definition: v2})), FULL_MAILBOX_ONLY);
  assert.deepEqual(cannot(await accessReport('google:gmail:full', {definition: v2, never: []})), []);
  assert.deepEqual(cannot(await accessReport('google:gmail:full', {definition: v2, never: [`${G}gmail.settings.basic`]})), []);
  assert.deepEqual((await accessReport('google:gmail:full', {definition: v1Definition('google')})).summary, (await accessReport('google:gmail:write', {definition: v1Definition('google')})).summary);
  await assert.rejects(accessReport('google:gmail:write', {definition: v2}), /No write scope set for gmail: a version 2 sign-in definition calls it full/);
  await assert.rejects(accessReport('google:gmail'), /for example google:gmail:full\./);
});

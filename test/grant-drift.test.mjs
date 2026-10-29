import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {grantHeaderOf, observeGrant, takeGrantHeader} from '../lib/grant-drift.mjs';
import {current, scopesSubject, shownNotice} from '../lib/connection-notices.mjs';
import {PREPARED} from '../lib/actions-runtime.mjs';
import {AppDetailService} from '../lib/app-detail.mjs';
import {catalog} from '../lib/connections.mjs';
import {describeApp} from '../public/hosted-app.js';
import {capabilityPermissionHash} from '../lib/permissions.mjs';
import {githubHarness, probeFile, SANDBOX, FIVE, TOKEN} from './fixtures/actions/github-harness.mjs';
import {calendarHarness} from './fixtures/actions/calendar-harness.mjs';
import {developerHarness} from './fixtures/actions/developer-fixture.mjs';
import {RESTRICTION} from './fixtures/provider-simulators/github.mjs';

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1 and section 3, spec lines 1144-1147, B7, critique test 17): GitHub lists what a token holds
// in X-OAuth-Scopes on every answer. Fabric reads it, for a provider whose sign-in names the header (grantHeader), in both runtimes that
// reach GitHub: an action's requests and a raw proxied request, on the owner's Fabric and in a developer environment. A header that lists
// less than Fabric recorded narrows the account once and raises one grant_narrowed notice; a header never widens anything. GitHub's
// documented refusal for an organization's OAuth App restriction raises org_restricted, naming the organization. The header itself never
// reaches a job, a step answer, a card, an output or an audit row. Everything runs on the GitHub simulator; nothing calls GitHub.
const [OWNER, REPO] = SANDBOX.split('/');
const readIssue = (h, repository = SANDBOX, number = 1) => { const [owner, repo] = repository.split('/'); return h.run('read-issue v1', {owner, repo, number}); };
const notices = (h, kind) => h.store.list('activity').filter(event => event.type === 'connection.health' && event.connectionId === h.account && (!kind || event.kind === kind));
const missingRows = h => {
  const service = new AppDetailService({store: h.store, runtime: h.runtime, catalog: () => catalog, oauthProviderFor: () => null, accessLevels: () => ['full'], accessLevelOf: () => null});
  return describeApp(service.view('github', h.account)).sections.flatMap(section => section.rows).filter(row => row.accessNote === 'Needs more access').map(row => row.label);
};
const GIST_ROWS = ['Access gists', 'Create and edit gists', 'Permanently delete repos, comments, releases and gists'];

test('the grant header is read only for a provider whose reviewed sign-in names it, and taken off the answer whole', () => {
  assert.equal(grantHeaderOf('github'), 'x-oauth-scopes');
  for (const providerId of ['google', 'notion', 'slack', 'fixture', 'nope', '', undefined, 7]) assert.equal(grantHeaderOf(providerId), null, String(providerId));
  assert.deepEqual(takeGrantHeader({'content-type': 'application/json', 'x-oauth-scopes': 'repo, gist', etag: '"e"'}, 'github'), {value: 'repo, gist', headers: {'content-type': 'application/json', etag: '"e"'}});
  assert.deepEqual(takeGrantHeader({'content-type': 'application/json'}, 'github'), {value: null, headers: {'content-type': 'application/json'}});
  assert.deepEqual(takeGrantHeader({'x-oauth-scopes': 'repo'}, 'google'), {value: null, headers: {'x-oauth-scopes': 'repo'}}, 'another app never asks for it, so nothing is taken');
  assert.deepEqual(takeGrantHeader(undefined, 'github'), {value: null, headers: {}});
});

test('critique test 17: a header listing fewer scopes than recorded narrows the account once, raises exactly one grant_narrowed, and the rows that needed the scope read Needs more access', async t => {
  const h = githubHarness(t, {file: probeFile()});
  assert.deepEqual(missingRows(h), []);
  h.simulator.grant(['read:user', 'repo', 'read:org', 'workflow']);
  const first = await readIssue(h);
  assert.deepEqual([first.status, first.result.data], ['succeeded', {title: 'Issue A'}], 'the job that saw the header keeps its answer');
  assert.deepEqual(h.connection().scopes, ['read:user', 'repo', 'read:org', 'workflow']);
  assert.deepEqual(h.connection().grantCeiling, FIVE, 'the ceiling is what the owner approved; only the grant narrows');
  const [notice] = notices(h);
  assert.deepEqual([notices(h).length, notice.kind, notice.subjectKey, notice.count], [1, 'grant_narrowed', scopesSubject(['gist']), 1]);
  assert.equal(JSON.stringify(notice).includes('gist'), false, 'a notice never names a scope');
  // The same header again, on another answer: the record already says so, so nothing changes and no second notice is raised.
  assert.equal((await readIssue(h, SANDBOX, 2)).status, 'succeeded');
  assert.deepEqual([notices(h).length, notices(h)[0].count, h.connection().scopes], [1, 1, ['read:user', 'repo', 'read:org', 'workflow']]);
  assert.deepEqual(missingRows(h), GIST_ROWS);
  assert.deepEqual(current(h.store, h.connection()).map(shownNotice).map(item => item.kind), ['grant_narrowed']);
});

test('a header listing more or the same never widens or changes anything; a scope a listed parent grants is not lost; no header changes nothing', async t => {
  const h = githubHarness(t, {file: probeFile()});
  const before = h.connection();
  for (const scopes of [[...FIVE, 'admin:org', 'user'], [...FIVE], ['read:user', 'repo', 'admin:org', 'gist', 'workflow'], ['user', 'repo', 'write:org', 'gist', 'workflow']]) {
    h.simulator.grant(scopes);
    assert.equal((await readIssue(h)).status, 'succeeded', scopes.join());
    assert.deepEqual(h.connection(), before, scopes.join());
  }
  assert.deepEqual(notices(h), []);
  // No header, or one that is not a scope list, changes nothing.
  for (const value of [null, undefined, 'repo; drop table', 'read:user,, repo', `${'a'.repeat(300)}`]) {
    assert.equal(observeGrant(h.runtime, h.connection(), {providerId: 'github', value, status: 200, data: {}}), null, String(value));
  }
  assert.deepEqual([h.connection(), notices(h)], [before, []]);
});

test('a header on another sign-in of the account, a revoked account or another provider changes nothing', async t => {
  const h = githubHarness(t, {file: probeFile()});
  const seen = h.connection();
  h.store.put('connections', {...seen, authRevision: 'r2', signInRevision: 's2'});
  assert.equal(observeGrant(h.runtime, seen, {providerId: 'github', value: 'repo', status: 200, data: {}}), null, 'the header came from the sign-in before');
  h.store.put('connections', {...seen, status: 'revoked'});
  assert.equal(observeGrant(h.runtime, seen, {providerId: 'github', value: 'repo', status: 200, data: {}}), null);
  h.store.put('connections', seen);
  assert.equal(observeGrant(h.runtime, seen, {providerId: 'google', value: 'repo', status: 200, data: {}}), null);
  assert.deepEqual([h.connection().scopes, notices(h)], [FIVE, []]);
  assert.deepEqual(observeGrant(h.runtime, seen, {providerId: 'github', value: 'repo', status: 200, data: {}}).lost, ['read:user', 'read:org', 'gist', 'workflow']);
});

test('a Calendar answer carrying x-oauth-scopes changes nothing: Google\'s sign-in names no grant header, so Fabric never asks for it', async t => {
  const h = calendarHarness(t), before = h.store.get('connections', h.account);
  h.simulator.fail('GET /users/me/calendarList', {status: 200, headers: {'x-oauth-scopes': ''}, data: {kind: 'calendar#calendarList', items: []}});
  const job = await h.run('list-calendars v1', {});
  assert.equal(job.status, 'succeeded', JSON.stringify(job.error));
  assert.deepEqual(h.store.get('connections', h.account), before);
  assert.deepEqual(h.store.list('activity').filter(event => event.type === 'connection.health'), []);
  assert.equal(h.simulator.calls.at(-1).route, 'GET /users/me/calendarList');
});

test('the header never reaches a proxy job\'s stored result, an action\'s step answers, its prepared row or card, its output or an audit row', async t => {
  const h = githubHarness(t, {file: probeFile()});
  // The token lost workflow, which none of these requests needs: every answer lists the four left, so the header was read on each.
  h.simulator.grant(['read:user', 'repo', 'read:org', 'gist']);
  const read = await readIssue(h), raw = await h.proxy('GET', `/repos/${SANDBOX}/issues/1`);
  const asking = await h.run('comment v1', {owner: OWNER, repo: REPO, number: 1, body: 'Hello'}), card = h.card(asking), prepared = h.prepared(asking);
  const done = await h.approve(asking);
  // Rename reads the issue first: that answer, its headers included, waits in the prepared row with the card until the owner decides.
  const renaming = await h.run('rename-issue v1', {owner: OWNER, repo: REPO, number: 2, title: 'Renamed'}), renameCard = h.card(renaming), renamePrepared = h.prepared(renaming);
  assert.deepEqual(h.fields(renaming), {'Title now': '[SYNTHETIC] Issue B', 'New title': 'Renamed'});
  assert.ok(renamePrepared.content.answers.issue.headers['content-type'], 'the prepared row keeps the headers the step asked for');
  const renamed = await h.approve(renaming);
  assert.deepEqual([read.status, raw.status, done.status, renamed.status], ['succeeded', 'succeeded', 'succeeded', 'succeeded']);
  assert.ok(h.simulator.calls.length === 7 && h.simulator.calls.every(call => call.status < 400), 'every request was answered, each with X-OAuth-Scopes');
  assert.deepEqual(h.connection().scopes, ['read:user', 'repo', 'read:org', 'gist'], 'the header reached Fabric');
  const stored = JSON.stringify([h.store.list('jobs'), h.store.list(PREPARED), prepared, card, renamePrepared, renameCard, h.store.list('activity'), h.store.list('proxyResponses'), h.runtime.proxyResponse(raw)]);
  for (const leak of ['x-oauth-scopes', 'read:user, repo', TOKEN]) assert.equal(stored.toLowerCase().includes(leak.toLowerCase()), false, leak);
  assert.ok(raw.result.response.headers['content-type'], 'the proxy keeps the headers it shows');
  assert.equal(Object.hasOwn(raw.result.response.headers, 'x-oauth-scopes'), false);
});

test('an organization\'s OAuth App restriction raises one org_restricted naming it, and the app page lists it; another 403 or a name that is no GitHub owner raises nothing', async t => {
  const h = githubHarness(t, {file: probeFile()});
  h.simulator.restrict('octo-org');
  const refused = await readIssue(h, 'octo-org/platform');
  assert.deepEqual([refused.status, refused.errorCode, refused.providerStatus], ['failed', 'provider_failed', 403]);
  assert.equal((await h.proxy('GET', '/repos/octo-org/platform/issues/1')).result.response.status, 403);
  const [notice] = notices(h, 'org_restricted');
  assert.deepEqual([notices(h, 'org_restricted').length, notice.subjectKey, notice.count], [1, 'org:octo-org', 2], 'one notice per organization; seeing it again counts it');
  assert.deepEqual(current(h.store, h.connection()).map(shownNotice).filter(item => item.kind === 'org_restricted').map(item => item.organization), ['octo-org']);
  const service = new AppDetailService({store: h.store, runtime: h.runtime, catalog: () => catalog, oauthProviderFor: () => null, accessLevels: () => ['full'], accessLevelOf: () => null});
  assert.deepEqual(describeApp(service.view('github', h.account)).notices.map(item => item.text), ['octo-org: this organization limits what Fabric can reach. Ask its admin to approve Fabric.']);
  assert.deepEqual(h.connection().scopes, FIVE, 'a restriction narrows nothing');
  const route = 'GET /repos/{owner}/{repo}/issues/{issue_number}';
  for (const message of ['Resource not accessible by integration', 'API rate limit exceeded for user ID 101.', RESTRICTION('bad name'), RESTRICTION('a--b'), RESTRICTION('-x'), `Note: ${RESTRICTION('acme')}`]) {
    h.simulator.fail(route, {status: 403, data: {message, documentation_url: 'https://docs.github.com/rest'}});
    assert.equal((await readIssue(h)).providerStatus, 403, message);
  }
  h.simulator.fail(route, {status: 404, data: {message: RESTRICTION('acme')}});
  await readIssue(h);
  assert.deepEqual(notices(h, 'org_restricted').map(item => item.subjectKey), ['org:octo-org'], 'only GitHub\'s documented 403 names an organization');
});

test('a proxy read that sees a narrowing keeps its own answer; the next request is decided on the narrowed grant', async t => {
  const h = githubHarness(t, {file: probeFile()});
  h.simulator.grant(['read:user', 'repo', 'read:org', 'workflow']);
  const seen = await h.proxy('GET', '/gists');
  assert.deepEqual([seen.status, h.runtime.proxyResponse(seen).body.map(gist => gist.public)], ['succeeded', [true]], 'the answer that showed the narrowing is kept');
  assert.deepEqual([h.connection().scopes, notices(h, 'grant_narrowed').length], [['read:user', 'repo', 'read:org', 'workflow'], 1]);
  await assert.rejects(h.proxy('GET', '/gists'), error => error.code === 'provider_access_missing');
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /gists').length, 1, 'the next request was refused before sending');
});

test('an action that sees a narrowing keeps its own answer, and the next action on that scope is refused before it sends', async t => {
  const h = githubHarness(t, {file: probeFile()});
  h.simulator.grant(['read:user', 'repo', 'read:org', 'workflow']);
  const seen = await h.run('list-gists v1', {});
  assert.deepEqual([seen.status, seen.result?.data], ['succeeded', {first: 'a1b2c3d4e5f60718293a'}], 'the job that saw the header keeps its answer');
  assert.deepEqual(h.connection().scopes, ['read:user', 'repo', 'read:org', 'workflow']);
  await assert.rejects(h.run('list-gists v1', {}), /required provider scope/);
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /gists').length, 1);
});

test('a narrowing one answer shows is applied before the job\'s next request: a later step on the lost scope is refused, and nothing more is sent', async t => {
  const h = githubHarness(t, {file: probeFile()});
  h.simulator.grant(['read:user', 'repo', 'read:org', 'workflow']);
  const job = await h.run('issue-then-gists v1', {owner: OWNER, repo: REPO, number: 1});
  assert.equal(job.status, 'failed', 'fail closed: the second step runs on the narrowed grant');
  assert.deepEqual(h.simulator.calls.map(call => call.route), ['GET /repos/{owner}/{repo}/issues/{issue_number}'], 'the gists read was never sent');
  assert.deepEqual([h.connection().scopes, notices(h, 'grant_narrowed').length], [['read:user', 'repo', 'read:org', 'workflow'], 1]);
});

test('in a developer environment an action answer that lists less narrows the person\'s own account and raises one notice for that person only', async t => {
  const d = await developerHarness(t, {users: ['u1', 'u2']}), gists = d.capability('list-gists v1');
  const execute = user => d.call(d.keys.standard, 'POST', '/v1/executions', {externalUserId: user, capabilityId: gists.id, definitionHash: capabilityPermissionHash(gists), args: {}, waitMs: 5000}, {'Idempotency-Key': randomUUID()});
  d.fail('GET /gists', {status: 200, headers: {'content-type': 'application/json', 'x-oauth-scopes': 'read:user, repo'}, data: [{id: 'g1'}]});
  const ran = await execute('u1');
  assert.deepEqual([ran.status, ran.body.status, ran.body.result], [200, 'succeeded', {first: 'g1'}], JSON.stringify(ran.body));
  const one = d.repo().get('connections', d.accounts.u1.github), two = d.repo().get('connections', d.accounts.u2.github);
  assert.deepEqual([one.scopes, two.scopes], [['read:user', 'repo'], ['read:user', 'repo', 'gist']]);
  const raised = d.repo().list('activity').filter(event => event.type === 'connection.health');
  assert.deepEqual(raised.map(event => [event.kind, event.connectionId, event.subjectKey, event.ownership?.owner?.id]), [['grant_narrowed', one.id, scopesSubject(['gist']), 'u1']]);
  assert.equal(JSON.stringify([d.repo().list('jobs'), d.repo().list('activity')]).includes('x-oauth-scopes'), false);
  const refused = await execute('u1');
  assert.notEqual(refused.body.status, 'succeeded', 'the next call is decided on the narrowed grant');
  assert.equal(d.callsOf('GET /gists').length, 1);
});

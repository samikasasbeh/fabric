import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createHmac, randomBytes} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createGuard, newRunId, GUARD_WORDS, LIMITS, GUEST, SHARE_RULE, PERMANENT_DELETE, NOTION_PERMANENT_DELETE, RULES, guardFile, signInFile} from '../lib/live-guard.mjs';

// F10.12 part 1 (docs/F10.12-BUILD-MAP.md section 3, test/live-guard.test.mjs): the live guard on its own, pure, with no network. A
// scripted inner requester stands for the provider, so a request the guard passes is answered and one it refuses never reaches it.

const KEY = randomBytes(32), RUN = 'ABCDEFGH', OWNER = 'owner@fabric-owner.test';
const CAL = 'https://www.googleapis.com/calendar/v3', GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me', GH = 'https://api.github.com';
const SANDBOX = `${GH}/repos/samikasasbeh/fabric-sandbox-test`;
// The run date 2026-10-24 in America/Toronto: the window is 2026-10-31 (day 7, still -04:00) to 2026-11-06 (day 13, -05:00 after the
// change on 2026-11-01), ending before 2026-11-07 00:00 -05:00.
const OWNER_FACTS = {email: OWNER, timeZone: 'America/Toronto', runDate: '2026-10-24', recorded: {c9Event: 'c9event1'}};
const RUN_A = 'run-a@group.calendar.google.com', RUN_B = 'run-b@group.calendar.google.com';

function folderOf(t) {
  const folder = mkdtempSync(path.join(tmpdir(), 'fabric-live-guard-'));
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  return folder;
}
/** A guard over a fresh folder (or the one given), its clock movable. */
function guardOf(t, {appId = 'google-calendar', runId = RUN, folder = folderOf(t), key = KEY, start = Date.parse('2026-10-24T12:00:00.000Z'), rules} = {}) {
  let now = start;
  const guard = createGuard({appId, runId, folder, key, clock: () => now, ...(rules ? {rules} : {})});
  return {guard, folder, advance: ms => { now += ms; }};
}
/** A scripted provider: each call is recorded with its options; answers are taken in order, then a plain 200. */
function provider(answers = []) {
  const calls = [];
  return {calls, inner: async options => { calls.push(options); const next = answers.shift(); return typeof next === 'function' ? next(options) : next ?? {status: 200, headers: {}, data: {}}; }};
}
const query = values => values ? `?${new URLSearchParams(values)}` : '';
const at = (base, method, route, {q, body, headers = {}} = {}) => ({url: `${base}${route}${query(q)}`, method, headers, ...(body !== undefined ? {body: typeof body === 'string' ? body : JSON.stringify(body)} : {})});
const cal = (method, route, options) => at(CAL, method, route, options);
const enc = id => encodeURIComponent(id);
const text = (test, words = 'item') => `[SYNTHETIC] Fabric ${test} ${RUN} ${words}`;
/** Asserts the guard refuses the request under the named rule, with that rule's words. */
function refuses(guard, request, rule, note) {
  const verdict = guard.check(request);
  assert.equal(verdict.allowed, false, `${note ?? request.method + ' ' + request.url}: expected a refusal`);
  assert.equal(verdict.rule, rule, `${note ?? request.method + ' ' + request.url}: rule`);
  assert.equal(verdict.words, GUARD_WORDS[rule]);
}
function passes(guard, request, note) {
  const verdict = guard.check(request);
  assert.equal(verdict.allowed, true, `${note ?? request.method + ' ' + request.url}: expected a pass, got ${verdict.rule}`);
  return verdict;
}
/** A Calendar guard with the owner set and the run's two calendars made in C1, through the guard itself. */
async function calendarRun(t, {owner = OWNER_FACTS, ...options} = {}) {
  const made = guardOf(t, options), {guard} = made;
  guard.setOwner(owner);
  const {inner} = provider([{status: 200, data: {id: RUN_A}}, {status: 200, data: {id: RUN_B}}]);
  const send = guard.wrap(inner);
  guard.begin('C1');
  await send(cal('POST', '/calendars', {body: {summary: text('C1', 'A'), timeZone: 'America/Toronto'}}));
  await send(cal('POST', '/calendars', {body: {summary: text('C1', 'B'), timeZone: 'America/Toronto'}}));
  guard.end();
  return {...made, send};
}
const event = (test, extra = {}) => ({summary: text(test), start: {dateTime: '2026-11-02T10:00:00-05:00', timeZone: 'America/Toronto'}, end: {dateTime: '2026-11-02T10:30:00-05:00', timeZone: 'America/Toronto'}, ...extra});
const insert = (calendar, body, q = {sendUpdates: 'none'}) => cal('POST', `/calendars/${enc(calendar)}/events`, {q, body});
/** A raw RFC 5322 message, base64url as Gmail takes it. */
const raw = lines => Buffer.from(`${lines.join('\r\n')}\r\n\r\nBody text.\r\n`, 'utf8').toString('base64url');

test('guard 1: text that is not synthetic is refused: a plain summary, another test or run in the prefix, a plain description or location, a plain Quick add text', async t => {
  const {guard} = await calendarRun(t);
  guard.begin('C2');
  passes(guard, insert(RUN_A, event('C2')));
  passes(guard, insert(RUN_A, event('C2', {summary: `[SYNTHETIC] Fabric C2 ${RUN}`})), 'the prefix alone');
  refuses(guard, insert(RUN_A, event('C2', {summary: 'Team sync'})), 'text');
  refuses(guard, insert(RUN_A, event('C2', {summary: `[SYNTHETIC] Fabric C3 ${RUN} item`})), 'text', 'another test id');
  refuses(guard, insert(RUN_A, event('C2', {summary: '[SYNTHETIC] Fabric C2 ZZZZZZZZ item'})), 'text', 'another run id');
  refuses(guard, insert(RUN_A, event('C2', {summary: `[SYNTHETIC] Fabric C2 ${RUN}X item`})), 'text', 'a longer run id');
  refuses(guard, insert(RUN_A, event('C2', {description: 'Notes'})), 'text', 'a plain description');
  refuses(guard, insert(RUN_A, event('C2', {location: 'Room 4'})), 'text', 'a plain location');
  refuses(guard, insert(RUN_A, event('C2', {summary: 42})), 'text', 'a summary that is not text');
  refuses(guard, cal('POST', `/calendars/${enc(RUN_A)}/events/quickAdd`, {q: {text: 'Lunch 2026-11-03 3pm', sendUpdates: 'none'}}), 'text');
  passes(guard, cal('POST', `/calendars/${enc(RUN_A)}/events/quickAdd`, {q: {text: `${text('C2')} 2026-11-03 3pm`, sendUpdates: 'none'}}));
  refuses(guard, cal('POST', `/calendars/${enc(RUN_A)}/events/quickAdd`, {q: {text: `${text('C2')} 3pm`, sendUpdates: 'none'}}), 'window', 'Quick add text with no ISO date');
  refuses(guard, cal('POST', `/calendars/${enc(RUN_A)}/events/quickAdd`, {q: {text: `${text('C2')} 2026-11-09 3pm`, sendUpdates: 'none'}}), 'window', 'Quick add text with a date outside');
  const {guard: fresh} = guardOf(t, {folder: folderOf(t)});
  fresh.setOwner(OWNER_FACTS);
  fresh.begin('C1');
  refuses(fresh, cal('POST', '/calendars', {body: {summary: 'My calendar'}}), 'text', 'a plain calendar name');
  refuses(fresh, cal('POST', '/calendars', {body: {summary: text('C1'), description: 'Mine'}}), 'text', 'a plain calendar description');
  passes(fresh, cal('POST', '/calendars', {body: {summary: text('C1'), timeZone: 'America/Toronto'}}));
});

test('guard 2: Gmail sends only to the own address, in every To, Cc, Bcc and Reply-To, folded or encoded; a plain Subject is refused; drafts must be this run\'s and carry raw', async t => {
  const {guard} = guardOf(t, {appId: 'gmail'});
  guard.setOwner(OWNER_FACTS);
  guard.begin('G1');
  const send = lines => at(GMAIL, 'POST', '/messages/send', {body: {raw: raw(lines)}});
  const subject = `Subject: ${text('G1')}`;
  passes(guard, send([`To: ${OWNER}`, subject]));
  passes(guard, send(['To: Owner <OWNER@Fabric-Owner.TEST>', subject]), 'the own address in another letter case');
  for (const name of ['To', 'Cc', 'Bcc', 'Reply-To']) refuses(guard, send([`To: ${OWNER}`, `${name}: other@elsewhere.test`, subject]), 'recipient', name);
  refuses(guard, send([`To: ${OWNER}`, 'To: other@elsewhere.test', subject]), 'recipient', 'a second To header');
  refuses(guard, send([`To: ${OWNER},`, ' other@elsewhere.test', subject]), 'recipient', 'a folded header');
  refuses(guard, send([`To: =?utf-8?B?${Buffer.from('other@elsewhere.test').toString('base64')}?=`, subject]), 'recipient', 'an RFC 2047 B word');
  refuses(guard, send(['To: =?iso-8859-1?Q?other=40elsewhere.test?=', subject]), 'recipient', 'an RFC 2047 Q word');
  refuses(guard, send([`To: "${OWNER}" <other@elsewhere.test>`, subject]), 'recipient', 'the own address only as a display name');
  refuses(guard, send([`To: f${OWNER}.evil.test`, subject]), 'recipient', 'an address that holds the own one');
  refuses(guard, send([`To: ${OWNER}`, 'Subject: Hello']), 'text', 'a plain Subject');
  refuses(guard, send([`To: ${OWNER}`]), 'text', 'no Subject');
  refuses(guard, at(GMAIL, 'POST', '/messages/send', {body: {}}), 'body', 'no raw');
  // Drafts: only one this run created, and only with its whole message.
  const draftsSend = body => at(GMAIL, 'POST', '/drafts/send', {body});
  refuses(guard, draftsSend({id: 'r-real', message: {raw: raw([`To: ${OWNER}`, subject])}}), 'draft', 'a draft the guard did not see created');
  refuses(guard, at(GMAIL, 'PUT', '/drafts/r-real', {body: {message: {raw: raw([`To: ${OWNER}`, subject])}}}), 'draft', 'an update of a real draft');
  const {inner} = provider([{status: 200, data: {id: 'r-made', message: {id: 'm1'}}}]);
  await guard.wrap(inner)(at(GMAIL, 'POST', '/drafts', {body: {message: {raw: raw([`To: ${OWNER}`, subject])}}}));
  passes(guard, draftsSend({id: 'r-made', message: {raw: raw([`To: ${OWNER}`, subject])}}));
  passes(guard, at(GMAIL, 'PUT', '/drafts/r-made', {body: {id: 'r-made', message: {raw: raw([`To: ${OWNER}`, subject])}}}));
  refuses(guard, draftsSend({id: 'r-made'}), 'draft', 'an id-only drafts.send');
  refuses(guard, draftsSend({id: 'r-made', message: {raw: raw(['To: other@elsewhere.test', subject])}}), 'recipient');
  refuses(guard, at(GMAIL, 'PUT', '/drafts/r-made', {body: {id: 'r-other', message: {raw: raw([`To: ${OWNER}`, subject])}}}), 'draft', 'a body id that differs from the path');
  // Labels: a synthetic name only. Step 15's other Gmail rules are guards 19 to 21.
  passes(guard, at(GMAIL, 'POST', '/labels', {body: {name: text('G1')}}));
  refuses(guard, at(GMAIL, 'POST', '/labels', {body: {name: 'Receipts'}}), 'text');
  refuses(guard, at(GMAIL, 'POST', '/messages/m1/trash'), 'mailbox', 'a message this run did not send');
  refuses(guard, at(GMAIL, 'POST', '/settings/forwardingAddresses', {body: {forwardingEmail: OWNER}}), 'locked');
});

test('guard 3: GitHub reaches only samikasasbeh/fabric-sandbox-test, segment by segment, and never its admin paths, with synthetic text or none', t => {
  const {guard} = guardOf(t, {appId: 'github'});
  guard.begin('H2');
  const issue = {title: text('H2'), body: text('H2', 'body')};
  passes(guard, at(SANDBOX, 'POST', '/issues', {body: issue}));
  passes(guard, at(SANDBOX, 'GET', '/issues/1'));
  refuses(guard, at(SANDBOX, 'POST', '/issues', {body: {title: 'Bug', body: text('H2')}}), 'text', 'a plain title');
  refuses(guard, at(SANDBOX, 'POST', '/issues/1/comments', {body: {body: 'Thanks'}}), 'text', 'a plain body');
  for (const route of ['/repos/samikasasbeh/other/issues', '/repos/samikasasbeh/fabric-sandbox-test-2/issues', '/repos/someone/fabric-sandbox-test/issues', '/repos/samikasasbeh/fabric-sandbox-test/../other/issues', '/gists', '/graphql']) {
    refuses(guard, at(GH, 'POST', route, {body: issue}), 'repository', route);
  }
  // F10.17: H11 lists your gists (a read outside the sandbox); writing one stays refused.
  passes(guard, at(GH, 'GET', '/gists'));
  refuses(guard, at(GH, 'POST', '/repos/samikasasbeh/fabric-sandbox-test%2Fx/issues', {body: issue}), 'not_allowlisted', 'an encoded slash');
  const admin = [['PUT', '/collaborators/bob'], ['POST', '/hooks'], ['GET', '/hooks'], ['POST', '/keys'], ['POST', '/transfer'], ['POST', '/forks'], ['PUT', '/actions/secrets/TOKEN'],
    ['GET', '/actions/secrets'], ['PUT', '/environments/prod'], ['PATCH', '/invitations/7']];
  for (const [method, route] of admin) {
    refuses(guard, at(SANDBOX, method, route, method === 'GET' ? {} : {body: issue}), 'repository_admin', `${method} ${route} with synthetic text`);
    if (method !== 'GET') refuses(guard, at(SANDBOX, method, route, {body: {}}), 'repository_admin', `${method} ${route} with none`);
  }
  refuses(guard, at(SANDBOX, 'DELETE', ''), 'not_allowlisted', 'deleting the repository');
});

// F10.17 part 2 (docs/F10.17-BUILD-MAP.md part 2): the GitHub rules narrowed to step 17's placements and the plan's proxied writes. Each rule
// passes its own case and refuses its neighbour.
const OWN = `fabric/test-${RUN}`, sha = 'a'.repeat(40);
async function githubRun(t) {
  const made = guardOf(t, {appId: 'github'}), {guard} = made;
  guard.setOwner({...OWNER_FACTS, recorded: {issueB: '2', issueBTitle: '[SYNTHETIC] Issue B as Muse wrote it'}});
  return made;
}
test('guard 19 (F10.17): GitHub reads outside the sandbox only GET /user, /user/repos, /gists, /user/orgs and a search holding the sandbox qualifier', async t => {
  const {guard} = await githubRun(t);
  guard.begin('H1');
  for (const route of ['/user', '/user/repos', '/gists', '/user/orgs']) passes(guard, at(GH, 'GET', route), route);
  for (const route of ['/users/someone/repos', '/gists/abc123', '/orgs/octo-org/repos', '/user/emails', '/user/keys', '/user/repos/x', '/repos/someone/else']) refuses(guard, at(GH, 'GET', route), 'repository', route);
  passes(guard, at(GH, 'GET', '/search/issues', {q: {q: 'is:issue repo:samikasasbeh/fabric-sandbox-test "[SYNTHETIC]"', per_page: '25'}}));
  for (const [q, note] of [['is:issue "[SYNTHETIC]"', 'no qualifier'], ['is:issue repo:samikasasbeh/fabric-sandbox-test repo:someone/else', 'a second repository'],
    ['is:issue "repo:samikasasbeh/fabric-sandbox-test"', 'the qualifier quoted, so only a word'], ['is:issue org:octo-org repo:samikasasbeh/fabric-sandbox-test', 'an organization'],
    ['is:issue user:someone repo:samikasasbeh/fabric-sandbox-test', 'a user']]) refuses(guard, at(GH, 'GET', '/search/issues', {q: {q}}), 'repository', note);
  refuses(guard, at(GH, 'GET', '/search/issues'), 'repository', 'no q at all');
  refuses(guard, at(GH, 'GET', '/search/code', {q: {q: 'repo:samikasasbeh/fabric-sandbox-test x'}}), 'repository', 'another search');
});

test('guard 20 (F10.17): GitHub branches: refs, contents and deletes only on this run\'s branches; a pull opens from one, into main or one; a merge only of a pull this run opened into its own branch', async t => {
  const {guard} = await githubRun(t);
  guard.begin('H7');
  for (const name of [OWN, `${OWN}-head`, `${OWN}-base`]) passes(guard, at(SANDBOX, 'POST', '/git/refs', {body: {ref: `refs/heads/${name}`, sha}}), name);
  for (const ref of ['refs/heads/main', 'refs/heads/fabric/test-ZZZZZZZZ', `refs/heads/${OWN}-Head`, `refs/heads/${OWN}-${'x'.repeat(17)}`, `refs/heads/${OWN}/deeper`, `refs/tags/${OWN}`, `refs/heads/x${OWN}`]) {
    refuses(guard, at(SANDBOX, 'POST', '/git/refs', {body: {ref, sha}}), 'branch', ref);
  }
  refuses(guard, at(SANDBOX, 'POST', '/git/refs', {body: {ref: `refs/heads/${OWN}`, sha, force: true}}), 'body', 'a field the action never sends');
  passes(guard, at(SANDBOX, 'DELETE', `/git/refs/heads/${OWN}`));
  passes(guard, at(SANDBOX, 'DELETE', `/git/refs/heads/${OWN}-base`));
  refuses(guard, at(SANDBOX, 'DELETE', '/git/refs/heads/main'), 'branch');
  refuses(guard, at(SANDBOX, 'DELETE', `/git/refs/tags/${OWN}`), 'branch');
  refuses(guard, at(SANDBOX, 'PATCH', `/git/refs/heads/${OWN}`, {body: {sha}}), 'not_allowlisted', 'moving a ref is not on the list');
  const file = {message: text('H7', 'add notes'), content: Buffer.from('x').toString('base64'), branch: OWN};
  passes(guard, at(SANDBOX, 'PUT', '/contents/notes/run.md', {body: file}));
  passes(guard, at(SANDBOX, 'PUT', '/contents/.github/workflows/fabric-h11.yml', {body: {...file, sha}}));
  refuses(guard, at(SANDBOX, 'PUT', '/contents/notes/run.md', {body: {...file, branch: 'main'}}), 'branch', 'the default branch');
  refuses(guard, at(SANDBOX, 'PUT', '/contents/notes/run.md', {body: {message: file.message, content: file.content}}), 'branch', 'no branch: the default one');
  refuses(guard, at(SANDBOX, 'PUT', '/contents/notes/run.md', {body: {...file, message: 'Add notes'}}), 'text', 'a plain commit message');
  refuses(guard, at(SANDBOX, 'PUT', '/contents/notes/run.md', {body: {...file, committer: {name: 'x', email: 'x@example.com'}}}), 'body');
  const pull = {title: text('H7', 'draft'), head: OWN, base: 'main', draft: true};
  passes(guard, at(SANDBOX, 'POST', '/pulls', {body: pull}));
  refuses(guard, at(SANDBOX, 'POST', '/pulls', {body: {...pull, head: 'main', base: OWN}}), 'branch', 'a head that is not a run branch');
  refuses(guard, at(SANDBOX, 'POST', '/pulls', {body: {...pull, base: 'release'}}), 'branch', 'a base other than main or a run branch');
  refuses(guard, at(SANDBOX, 'POST', '/pulls', {body: {...pull, title: 'Draft'}}), 'text');
  refuses(guard, at(SANDBOX, 'PATCH', '/pulls/7', {body: {title: text('H7')}}), 'not_allowlisted', 'PATCH pulls left the list');
  // A pull this run opens into one of its branches is recorded by its number; a merge passes only for such a pull.
  const {inner} = provider([{status: 201, data: {id: 9001, number: 7}}, {status: 201, data: {id: 9002, number: 8}}]), send = guard.wrap(inner);
  await send(at(SANDBOX, 'POST', '/pulls', {body: {...pull, head: `${OWN}-head`, base: `${OWN}-base`, draft: false}}));
  await send(at(SANDBOX, 'POST', '/pulls', {body: pull}));
  // Every create is recorded by the id it answers, as step 12 records it (the evidence's created identity, and what a stopped run left in
  // place); only the pull into a run branch is also recorded by its number, as its merge path names it, so a pull into main never merges.
  assert.deepEqual(guard.created().map(item => [item.kind, item.id, item.number ?? null]), [['pull', '9001', '7'], ['item', '9002', null]]);
  assert.deepEqual(guard.trace('H7').map(entry => [entry.path, entry.status, entry.identity]),
    [['/repos/samikasasbeh/fabric-sandbox-test/pulls', 201, '9001'], ['/repos/samikasasbeh/fabric-sandbox-test/pulls', 201, '9002']]);
  const merge = {sha, merge_method: 'merge'};
  passes(guard, at(SANDBOX, 'PUT', '/pulls/7/merge', {body: merge}));
  passes(guard, at(SANDBOX, 'PUT', '/pulls/7/merge', {body: {...merge, commit_title: text('H7', 'merge'), commit_message: text('H7', 'why')}}));
  for (const number of ['8', '6', '9001']) refuses(guard, at(SANDBOX, 'PUT', `/pulls/${number}/merge`, {body: merge}), 'merge', `pull ${number}`);
  refuses(guard, at(SANDBOX, 'PUT', '/pulls/7/merge', {body: {...merge, commit_title: 'Merge it'}}), 'text', 'a plain commit title');
  refuses(guard, at(SANDBOX, 'PUT', '/pulls/7/merge', {body: {...merge, commit_message: 'Because'}}), 'text', 'a plain commit message');
});

test('guard 21 (F10.17): GitHub text, labels, reviews, dispatches, H3\'s restore and the comment delete: each passes as planned and refuses its neighbour', async t => {
  const made = guardOf(t, {appId: 'github'}), {guard} = made;
  guard.setOwner({...OWNER_FACTS, recorded: {issueB: '2', issueBTitle: '[SYNTHETIC] Issue B as Muse wrote it'}});
  // Each create is recorded by the id GitHub answers, as step 12 records it: the evidence's created identity, and what a stopped run left in
  // place. A label list (an array) and a dispatch (no answer) make nothing with an id.
  const {inner} = provider([{status: 201, data: {id: 7001, number: 9}}, {status: 200, data: [{id: 1, name: 'fabric-test'}]}, {status: 200, data: {id: 8801, state: 'COMMENTED'}},
    {status: 204, data: null}, {status: 201, data: {id: 5501}}]), send = guard.wrap(inner);
  guard.begin('H6');
  // A new issue takes synthetic text and no label but fabric-test: GitHub creates a label a new issue names that the repository lacks.
  const issue = {title: text('H6', 'issue')};
  passes(guard, at(SANDBOX, 'POST', '/issues', {body: issue}));
  passes(guard, at(SANDBOX, 'POST', '/issues', {body: {...issue, body: text('H6', 'body'), labels: ['fabric-test']}}));
  for (const labels of [['bug'], ['fabric-test', 'bug'], [], 'fabric-test', null]) refuses(guard, at(SANDBOX, 'POST', '/issues', {body: {...issue, labels}}), 'label', JSON.stringify(labels));
  refuses(guard, at(SANDBOX, 'POST', '/issues', {body: {title: 'Plain'}}), 'text');
  refuses(guard, at(SANDBOX, 'POST', '/issues', {body: {...issue, assignees: ['someone']}}), 'body');
  await send(at(SANDBOX, 'POST', '/issues', {body: issue}));
  guard.end();
  guard.begin('H4');
  passes(guard, at(SANDBOX, 'POST', '/issues/3/labels', {body: {labels: ['fabric-test']}}));
  for (const labels of [['bug'], ['fabric-test', 'bug'], [], 'fabric-test']) refuses(guard, at(SANDBOX, 'POST', '/issues/3/labels', {body: {labels}}), 'label', JSON.stringify(labels));
  passes(guard, at(SANDBOX, 'DELETE', '/issues/3/labels/fabric-test'));
  refuses(guard, at(SANDBOX, 'DELETE', '/issues/3/labels/bug'), 'label');
  refuses(guard, at(SANDBOX, 'DELETE', '/issues/3/labels'), 'not_allowlisted', 'removing every label');
  await send(at(SANDBOX, 'POST', '/issues/3/labels', {body: {labels: ['fabric-test']}}));
  guard.end();
  guard.begin('H8');
  const review = {event: 'COMMENT', body: text('H8', 'review'), commit_id: sha};
  passes(guard, at(SANDBOX, 'POST', '/pulls/7/reviews', {body: review}));
  for (const event of ['APPROVE', 'REQUEST_CHANGES', undefined]) refuses(guard, at(SANDBOX, 'POST', '/pulls/7/reviews', {body: {...review, event}}), 'review', String(event));
  refuses(guard, at(SANDBOX, 'POST', '/pulls/7/reviews', {body: {...review, body: 'Looks good'}}), 'text');
  await send(at(SANDBOX, 'POST', '/pulls/7/reviews', {body: review}));
  guard.end();
  guard.begin('H10');
  passes(guard, at(SANDBOX, 'POST', '/actions/workflows/fabric-synthetic.yml/dispatches', {body: {ref: 'main', inputs: {}}}));
  passes(guard, at(SANDBOX, 'POST', '/actions/workflows/fabric-synthetic.yml/dispatches', {body: {ref: OWN}}));
  refuses(guard, at(SANDBOX, 'POST', '/actions/workflows/deploy.yml/dispatches', {body: {ref: 'main', inputs: {}}}), 'workflow');
  refuses(guard, at(SANDBOX, 'POST', '/actions/workflows/12345/dispatches', {body: {ref: 'main', inputs: {}}}), 'workflow', 'by id');
  refuses(guard, at(SANDBOX, 'POST', '/actions/workflows/fabric-synthetic.yml/dispatches', {body: {ref: 'release', inputs: {}}}), 'branch');
  refuses(guard, at(SANDBOX, 'POST', '/actions/workflows/fabric-synthetic.yml/dispatches', {body: {ref: 'main', inputs: {greeting: 'hi'}}}), 'workflow', 'an input');
  await send(at(SANDBOX, 'POST', '/actions/workflows/fabric-synthetic.yml/dispatches', {body: {ref: 'main', inputs: {}}}));
  guard.end();
  guard.begin('H3');
  passes(guard, at(SANDBOX, 'PATCH', '/issues/2', {body: {title: text('H3', 'renamed')}}));
  passes(guard, at(SANDBOX, 'PATCH', '/issues/2', {body: {title: '[SYNTHETIC] Issue B as Muse wrote it'}}), 'the restore, byte for byte');
  refuses(guard, at(SANDBOX, 'PATCH', '/issues/3', {body: {title: '[SYNTHETIC] Issue B as Muse wrote it'}}), 'text', 'the recorded title on another issue');
  refuses(guard, at(SANDBOX, 'PATCH', '/issues/2', {body: {title: '[SYNTHETIC] Issue B as Muse wrote it '}}), 'text', 'not byte for byte');
  refuses(guard, at(SANDBOX, 'PATCH', '/issues/2', {body: {body: '[SYNTHETIC] Issue B as Muse wrote it'}}), 'text', 'only the title is restored');
  passes(guard, at(SANDBOX, 'PATCH', '/issues/3', {body: {state: 'closed', state_reason: 'not_planned'}}));
  refuses(guard, at(SANDBOX, 'PATCH', '/issues/3', {body: {assignees: ['someone']}}), 'body');
  guard.end();
  guard.begin('H2');
  passes(guard, at(SANDBOX, 'POST', '/issues/1/comments', {body: {body: text('H2', 'comment')}}));
  await send(at(SANDBOX, 'POST', '/issues/1/comments', {body: {body: text('H2', 'comment')}}));
  refuses(guard, at(SANDBOX, 'DELETE', '/issues/comments/55'), 'comment_delete', 'outside the one-time Ask');
  guard.beginOneTimeAsk('github.code.write');
  refuses(guard, at(SANDBOX, 'DELETE', '/issues/comments/55'), 'comment_delete', 'in another row\'s Ask');
  guard.beginOneTimeAsk('github.permanent.delete');
  passes(guard, at(SANDBOX, 'DELETE', '/issues/comments/55'));
  guard.endOneTimeAsk();
  refuses(guard, at(SANDBOX, 'DELETE', '/issues/comments/55'), 'comment_delete', 'after it');
  guard.end();
  assert.deepEqual(guard.created().map(item => [item.test, item.kind, item.id]), [['H6', 'item', '7001'], ['H8', 'item', '8801'], ['H2', 'item', '5501']]);
  assert.deepEqual(['H6', 'H4', 'H8', 'H10', 'H2'].map(id => guard.trace(id).map(entry => entry.identity)), [['7001'], [null], ['8801'], [null], ['5501']]);
});

test('guard 4: Calendar refuses sendUpdates=all, externalOnly or missing, and sendNotifications=true', async t => {
  const {guard} = await calendarRun(t);
  guard.begin('C2');
  passes(guard, insert(RUN_A, event('C2')));
  passes(guard, insert(RUN_A, event('C2'), {sendUpdates: 'none', sendNotifications: 'false'}));
  refuses(guard, insert(RUN_A, event('C2'), {sendUpdates: 'all'}), 'notifications');
  refuses(guard, insert(RUN_A, event('C2'), {sendUpdates: 'externalOnly'}), 'notifications');
  refuses(guard, insert(RUN_A, event('C2'), {}), 'notifications', 'a missing sendUpdates');
  refuses(guard, insert(RUN_A, event('C2'), {sendUpdates: 'none', sendNotifications: 'true'}), 'notifications');
  refuses(guard, cal('DELETE', `/calendars/${enc(RUN_A)}/events/e1`), 'notifications', 'a delete without sendUpdates');
  refuses(guard, cal('PATCH', `/calendars/${enc(RUN_A)}/events/e1`, {q: {sendUpdates: 'all'}, body: {summary: text('C2')}}), 'notifications');
});

test('guard 5: dates fall from day 7 at 00:00 to day 13 at 23:59 in the owner\'s zone, across a daylight-saving change; lists and free time are checked; recurrences are expanded', async t => {
  const {guard} = await calendarRun(t);
  guard.begin('C4');
  const timed = (start, end) => insert(RUN_A, {summary: text('C4'), start: {dateTime: start}, end: {dateTime: end}});
  passes(guard, timed('2026-10-31T00:00:00-04:00', '2026-10-31T00:30:00-04:00'), 'day 7 at 00:00');
  passes(guard, timed('2026-11-06T23:00:00-05:00', '2026-11-06T23:59:00-05:00'), 'day 13 at 23:59, after the change');
  passes(guard, timed('2026-11-07T04:00:00Z', '2026-11-07T04:59:00Z'), 'UTC times that are still day 13 in Toronto');
  refuses(guard, timed('2026-10-30T23:59:00-04:00', '2026-10-31T00:30:00-04:00'), 'window', 'day 6 at 23:59');
  refuses(guard, timed('2026-11-06T23:00:00-05:00', '2026-11-07T00:00:00-05:00'), 'window', 'day 14 at 00:00');
  refuses(guard, timed('2026-10-31T03:30:00Z', '2026-10-31T05:00:00Z'), 'window', 'another offset that lands on day 6 in Toronto');
  refuses(guard, timed('2026-11-02T10:00:00', '2026-11-02T10:30:00'), 'window', 'a time without its offset');
  const allDay = (start, end) => insert(RUN_A, {summary: text('C4'), start: {date: start}, end: {date: end}});
  passes(guard, allDay('2026-11-06', '2026-11-07'), 'an all-day end on day 14, which is exclusive');
  refuses(guard, allDay('2026-11-06', '2026-11-08'), 'window', 'an all-day end on day 15');
  refuses(guard, allDay('2026-10-30', '2026-10-31'), 'window', 'an all-day start on day 6');
  // A list and free time: both bounds.
  const list = (timeMin, timeMax) => cal('GET', `/calendars/${enc(RUN_A)}/events`, {q: {timeMin, timeMax}});
  passes(guard, list('2026-10-31T00:00:00-04:00', '2026-11-06T23:59:00-05:00'));
  refuses(guard, list('2026-10-30T12:00:00-04:00', '2026-11-06T23:59:00-05:00'), 'window', 'a list from day 6');
  refuses(guard, list('2026-10-31T00:00:00-04:00', '2026-11-07T00:00:00-05:00'), 'window', 'a list to day 14');
  const free = (timeMin, timeMax, items = [{id: RUN_A}, {id: RUN_B}]) => cal('POST', '/freeBusy', {body: {timeMin, timeMax, timeZone: 'America/Toronto', items}});
  assert.equal(passes(guard, free('2026-10-31T00:00:00-04:00', '2026-11-06T23:59:00-05:00')).write, false, 'free time is a read');
  refuses(guard, free('2026-10-31T00:00:00-04:00', '2026-11-07T01:00:00-05:00'), 'window', 'free time to day 14');
  refuses(guard, free('2026-10-31T00:00:00-04:00', '2026-11-06T23:59:00-05:00', [{id: 'primary'}]), 'primary', 'free time on the primary calendar');
  refuses(guard, cal('POST', '/freeBusy', {body: {timeMin: '2026-10-31T00:00:00-04:00', timeMax: '2026-11-06T23:59:00-05:00', items: [{id: RUN_A}], groupExpansionMax: 5}}), 'body', 'an unknown key');
  // Recurrences: every occurrence, in the event's own zone.
  const repeating = (rule, start = '2026-11-04T10:00:00-05:00', end = '2026-11-04T10:30:00-05:00') => insert(RUN_A, {summary: text('C4'), start: {dateTime: start, timeZone: 'America/Toronto'},
    end: {dateTime: end, timeZone: 'America/Toronto'}, recurrence: [rule]});
  passes(guard, repeating('RRULE:FREQ=DAILY;COUNT=3'), 'daily, 3 times, on days 11 to 13');
  refuses(guard, repeating('RRULE:FREQ=DAILY;COUNT=3', '2026-11-05T10:00:00-05:00', '2026-11-05T10:30:00-05:00'), 'window', 'daily from day 12 reaches day 14');
  refuses(guard, repeating('RRULE:FREQ=WEEKLY;COUNT=3'), 'window', 'weekly, 3 times');
  refuses(guard, repeating('RRULE:FREQ=WEEKLY'), 'recurrence', 'no COUNT');
  refuses(guard, repeating('RRULE:FREQ=DAILY;UNTIL=20261106T000000Z'), 'recurrence', 'UNTIL');
  refuses(guard, repeating('RRULE:FREQ=DAILY;COUNT=4'), 'recurrence', 'COUNT over 3');
  refuses(guard, repeating('RRULE:FREQ=DAILY;COUNT=2;BYDAY=MO'), 'recurrence', 'another rule part');
  refuses(guard, insert(RUN_A, {...event('C4'), recurrence: ['RRULE:FREQ=DAILY;COUNT=2', 'EXDATE:20261103T100000']}), 'recurrence', 'a second line');
  // Occurrences keep their wall time in the event's zone, as Google expands them. With the run date 2026-10-19 the window ends at
  // 2026-11-02 00:00 -05:00, the day after the change: a daily event from 2026-10-31 23:30 to 00:30 (-04:00) repeats on 2026-11-01 from
  // 23:30 to 00:30 (-05:00), past the window, though 24 hours after its first end is still inside it.
  const {guard: change} = await calendarRun(t, {owner: {...OWNER_FACTS, runDate: '2026-10-19'}});
  change.begin('C4');
  refuses(change, repeating('RRULE:FREQ=DAILY;COUNT=2', '2026-10-31T23:30:00-04:00', '2026-11-01T00:30:00-04:00'), 'window', 'the second occurrence ends on day 14 in wall time');
  passes(change, repeating('RRULE:FREQ=DAILY;COUNT=2', '2026-10-31T22:00:00-04:00', '2026-10-31T23:00:00-04:00'), 'the second occurrence ends at 23:00 on day 13');
  refuses(change, insert(RUN_A, {summary: text('C4'), start: {dateTime: '2026-10-31T22:00:00-04:00'}, end: {dateTime: '2026-10-31T23:00:00-04:00'}, recurrence: ['RRULE:FREQ=DAILY;COUNT=2']}),
    'recurrence', 'a timed recurrence without its zone');
  // A dated write before the owner is set is refused.
  const {guard: early} = guardOf(t);
  early.begin('C1');
  await early.wrap(provider([{status: 200, data: {id: RUN_A}}]).inner)(cal('POST', '/calendars', {body: {summary: text('C1')}}));
  early.end();
  early.begin('C2');
  refuses(early, insert(RUN_A, event('C2')), 'owner_unset');
});

test('guard 6: the primary calendar is refused except the recorded C9 event and the owner\'s one response', async t => {
  const {guard} = await calendarRun(t);
  guard.begin('C9');
  const respond = (body, {calendar = 'primary', eventId = 'c9event1', method = 'PATCH', q = {sendUpdates: 'none'}} = {}) => cal(method, `/calendars/${enc(calendar)}/events/${eventId}`, {q, body});
  const answer = status => ({attendeesOmitted: true, attendees: [{email: OWNER, responseStatus: status}]});
  for (const status of ['accepted', 'tentative', 'declined']) passes(guard, respond(answer(status)), status);
  passes(guard, respond(answer('accepted'), {calendar: OWNER}), 'the owner\'s own calendar id');
  refuses(guard, respond({...answer('accepted'), summary: text('C9')}), 'primary', 'an extra body key');
  refuses(guard, respond({attendeesOmitted: true, attendees: [{email: OWNER, responseStatus: 'accepted'}, {email: GUEST, responseStatus: 'accepted'}]}), 'primary', 'a second attendee');
  refuses(guard, respond({attendeesOmitted: true, attendees: [{email: 'other@elsewhere.test', responseStatus: 'accepted'}]}), 'primary', 'another attendee');
  refuses(guard, respond({attendeesOmitted: true, attendees: [{email: OWNER, responseStatus: 'accepted', comment: 'x'}]}), 'primary', 'another attendee field');
  refuses(guard, respond({attendeesOmitted: false, attendees: [{email: OWNER, responseStatus: 'accepted'}]}), 'primary', 'attendeesOmitted false');
  refuses(guard, respond(answer('needsAction')), 'primary', 'another response');
  refuses(guard, respond(answer('accepted'), {eventId: 'other-event'}), 'primary', 'another event id');
  refuses(guard, respond(undefined, {method: 'DELETE'}), 'primary', 'a delete');
  refuses(guard, respond(answer('accepted'), {method: 'PUT'}), 'primary', 'a full update');
  refuses(guard, respond(answer('accepted'), {q: {}}), 'notifications', 'a missing sendUpdates=none');
  refuses(guard, insert('primary', event('C9')), 'primary', 'a new event on primary');
  refuses(guard, insert(OWNER, event('C9')), 'primary', 'a new event on the owner\'s calendar id');
  // Reads: that event, and a synthetic search inside the window.
  passes(guard, cal('GET', '/calendars/primary/events/c9event1'));
  refuses(guard, cal('GET', '/calendars/primary/events/other-event'), 'primary');
  const search = q => cal('GET', '/calendars/primary/events', {q});
  passes(guard, search({q: '[SYNTHETIC]', timeMin: '2026-10-31T00:00:00-04:00', timeMax: '2026-11-06T23:59:00-05:00', singleEvents: 'true'}));
  refuses(guard, search({timeMin: '2026-10-31T00:00:00-04:00', timeMax: '2026-11-06T23:59:00-05:00'}), 'primary', 'no q');
  refuses(guard, search({q: 'dentist', timeMin: '2026-10-31T00:00:00-04:00', timeMax: '2026-11-06T23:59:00-05:00'}), 'primary', 'a q that is not synthetic');
  refuses(guard, search({q: '[SYNTHETIC]', timeMin: '2026-10-31T00:00:00-04:00'}), 'primary', 'one bound');
  refuses(guard, search({q: '[SYNTHETIC]', timeMin: '2026-10-01T00:00:00-04:00', timeMax: '2026-11-06T23:59:00-05:00'}), 'window', 'a bound outside');
  refuses(guard, cal('GET', '/calendars/primary/acl'), 'primary');
  // With no recorded event, nothing on primary passes.
  const {guard: plain} = guardOf(t, {runId: 'CDEFGHJK'});
  plain.setOwner({...OWNER_FACTS, recorded: {}});
  plain.begin('C9');
  refuses(plain, respond(answer('accepted')), 'primary', 'no recorded event');
});

test('guard 7: guests other than fabric-guest@example.com are refused, another example.com address included; the owner\'s own entry passes', async t => {
  const {guard} = await calendarRun(t);
  guard.begin('C7');
  const guests = attendees => cal('PATCH', `/calendars/${enc(RUN_A)}/events/e1`, {q: {sendUpdates: 'none'}, body: {attendees}});
  passes(guard, guests([{email: GUEST}]));
  passes(guard, guests([{email: GUEST, responseStatus: 'needsAction'}, {email: OWNER, responseStatus: 'accepted', organizer: true, self: true}]), 'the owner\'s own entry kept whole');
  passes(guard, guests([{email: RUN_A, organizer: true}, {email: GUEST}]), 'the run calendar as organizer');
  refuses(guard, guests([{email: 'other@example.com'}]), 'guest', 'another example.com address');
  refuses(guard, guests([{email: GUEST}, {email: 'bob@elsewhere.test'}]), 'guest');
  refuses(guard, guests([{displayName: 'No address'}]), 'guest', 'an entry without an address');
  refuses(guard, insert(RUN_A, event('C7', {attendees: [{email: 'other@example.com'}]})), 'guest', 'on create too');
  refuses(guard, cal('POST', `/calendars/${enc(RUN_A)}/events/quickAdd`, {q: {text: `${text('C7')} 2026-11-03 with bob@elsewhere.test`, sendUpdates: 'none'}}), 'guest', 'an address in Quick add text');
});

test('guard 8: two calendars per run, never cleared, deleted only in the one-time Ask, shared rules only fabric-share; calendars come only from passed creates and survive a restart', async t => {
  const {guard, folder, send} = await calendarRun(t);
  guard.begin('C10');
  refuses(guard, cal('POST', '/calendars', {body: {summary: text('C10')}}), 'calendar_cap', 'a third calendar');
  refuses(guard, cal('POST', `/calendars/${enc(RUN_A)}/clear`), 'not_allowlisted', 'calendars.clear');
  refuses(guard, cal('POST', `/calendars/${enc(RUN_A)}/events/import`, {q: {sendUpdates: 'none'}, body: event('C10')}), 'not_allowlisted', 'events.import');
  passes(guard, cal('DELETE', `/calendars/${enc(RUN_A)}/acl/${enc(SHARE_RULE)}`));
  passes(guard, cal('GET', `/calendars/${enc(RUN_A)}/acl/${enc(SHARE_RULE)}`));
  passes(guard, cal('GET', `/calendars/${enc(RUN_A)}/acl`));
  refuses(guard, cal('DELETE', `/calendars/${enc(RUN_A)}/acl/${enc('user:other@example.com')}`), 'sharing');
  refuses(guard, cal('GET', `/calendars/${enc(RUN_A)}/acl/${enc('user:other@example.com')}`), 'sharing');
  guard.end();
  // The delete: only between beginOneTimeAsk(the permanent-delete row) and endOneTimeAsk().
  guard.begin('C13');
  const remove = cal('DELETE', `/calendars/${enc(RUN_A)}`);
  refuses(guard, remove, 'one_time_ask', 'outside the one-time Ask');
  guard.beginOneTimeAsk('google-calendar.calendars.write');
  refuses(guard, remove, 'one_time_ask', 'under another row');
  guard.endOneTimeAsk();
  guard.beginOneTimeAsk(PERMANENT_DELETE);
  passes(guard, remove);
  refuses(guard, cal('DELETE', '/calendars/primary'), 'primary', 'the primary calendar, even then');
  refuses(guard, cal('DELETE', `/calendars/${enc('theirs@group.calendar.google.com')}`), 'calendar', 'a calendar the run did not create, even then');
  guard.endOneTimeAsk();
  refuses(guard, remove, 'one_time_ask', 'after endOneTimeAsk()');
  guard.end();
  // A calendar read from the calendar list is never a run calendar.
  guard.begin('C0');
  await send(cal('GET', '/users/me/calendarList/primary'));
  const {inner} = provider([{status: 200, data: {id: 'theirs@group.calendar.google.com', summary: 'Theirs'}}, {status: 200, data: {items: [{id: 'theirs@group.calendar.google.com'}]}}]);
  await guard.wrap(inner)(cal('GET', '/users/me/calendarList/primary'));
  await guard.wrap(inner)(cal('GET', '/users/me/calendarList'));
  guard.end();
  guard.begin('C2');
  refuses(guard, insert('theirs@group.calendar.google.com', event('C2')), 'calendar', 'a calendar read from calendarList');
  refuses(guard, cal('GET', `/users/me/calendarList/${enc('theirs@group.calendar.google.com')}`), 'calendar');
  passes(guard, insert(RUN_A, event('C2')));
  guard.end();
  const counts = guard.counts();
  // A new guard over the same run file keeps both calendars and every counter.
  const again = createGuard({appId: 'google-calendar', runId: RUN, folder, key: randomBytes(32), clock: () => Date.parse('2026-10-24T13:00:00.000Z')});
  again.setOwner(OWNER_FACTS);
  assert.deepEqual(again.counts(), counts);
  again.begin('C2');
  passes(again, insert(RUN_A, event('C2')));
  passes(again, insert(RUN_B, event('C2')));
  refuses(again, cal('POST', '/calendars', {body: {summary: text('C2')}}), 'calendar_cap', 'a third calendar after a restart');
  assert.throws(() => again.setOwner({...OWNER_FACTS, runDate: '2026-10-25'}), /fixed/);
  assert.equal(statSync(guardFile(folder, 'google-calendar', RUN)).mode & 0o777, 0o600);
});

test('guard 9: every reviewed revocation URL is refused, inside and outside a test', t => {
  const urls = [['POST', 'https://oauth2.googleapis.com/revoke'], ['POST', 'https://oauth2.googleapis.com/revoke?token=abc'], ['DELETE', 'https://api.github.com/applications/client-123/token'],
    ['POST', 'https://api.notion.com/v1/oauth/revoke'], ['POST', 'https://slack.com/api/auth.revoke']];
  for (const appId of ['google-calendar', 'gmail', 'github', 'notion', 'slack']) {
    const {guard} = guardOf(t, {appId});
    guard.setOwner(OWNER_FACTS);
    for (const [method, url] of urls) refuses(guard, {url, method, headers: {}, body: 'token=abc'}, 'revocation', `${appId} outside a test: ${url}`);
    guard.begin('T1');
    for (const [method, url] of urls) refuses(guard, {url, method, headers: {}, body: 'token=abc'}, 'revocation', `${appId} in a test: ${url}`);
  }
});

test('guard 10: outside a test every write is refused; sign-in URLs and Discovery documents pass at any time, count as no write and never enter a trace', async t => {
  const {guard, send} = await calendarRun(t);
  const counts = guard.counts();
  refuses(guard, cal('DELETE', `/calendars/${enc(RUN_A)}/acl/${enc(SHARE_RULE)}`), 'outside_test');
  refuses(guard, cal('POST', '/calendars', {body: {summary: text('C1')}}), 'outside_test');
  refuses(guard, cal('GET', '/users/me/calendarList'), 'outside_test', 'a read too');
  refuses(guard, {url: 'https://www.google.com/s2/favicons?domain=calendar.google.com', method: 'GET', headers: {}}, 'outside_test', 'an app icon');
  const signIn = [['POST', 'https://oauth2.googleapis.com/token'], ['GET', 'https://openidconnect.googleapis.com/v1/userinfo'],
    ['GET', 'https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1&fields=kind'], ['GET', 'https://gmail.googleapis.com/gmail/v1/users/me/profile?fields=emailAddress'],
    ['GET', 'https://www.googleapis.com/discovery/v1/apis/calendar/v3/rest'], ['GET', 'https://gmail.googleapis.com/$discovery/rest?version=v1'],
    ['POST', 'https://github.com/login/oauth/access_token'], ['GET', 'https://api.github.com/user'], ['POST', 'https://slack.com/api/oauth.v2.access'], ['POST', 'https://api.notion.com/v1/oauth/token']];
  for (const [method, url] of signIn) assert.deepEqual([guard.check({url, method, headers: {}}).allowed, guard.check({url, method, headers: {}}).kind], [true, 'signin'], `${method} ${url}`);
  // The calendar list probe is a sign-in URL only as written: another query is an ordinary read.
  refuses(guard, cal('GET', '/users/me/calendarList', {q: {maxResults: '2'}}), 'outside_test');
  for (const [method, url] of signIn) await send({url, method, headers: {}});
  guard.begin('C2');
  for (const [method, url] of signIn) await send({url, method, headers: {}});
  assert.deepEqual(guard.trace('C2'), []);
  assert.deepEqual(guard.counts(), counts, 'sign-in counts as no write');
  refuses(guard, {url: 'https://www.google.com/s2/favicons?domain=calendar.google.com', method: 'GET', headers: {}}, 'origin', 'an app icon in a test');
  refuses(guard, {url: 'https://oauth2.googleapis.com/tokeninfo?access_token=x', method: 'GET', headers: {}}, 'origin', 'another path on the token origin');
});

// F10.19 listed churn: Notion has its own rules now (guards N1 to N3 below), and F10.21's Slack rules want the owner first, so guard 11 keeps a
// Slack write with no owner set; Notion's writes are refused by the Slack and Calendar guards, and a Notion write outside its rules by Notion's.
test('guard 11: a Slack write with no owner set is refused, and a Notion write outside Notion\'s guard (F10.19 and F10.21 listed churn)', t => {
  const writes = [['https://api.notion.com/v1/pages', 'POST'], ['https://api.notion.com/v1/blocks/abc/children', 'PATCH'], ['https://slack.com/api/chat.postMessage', 'POST'], ['https://slack.com/api/conversations.open', 'POST']];
  for (const appId of ['slack']) {
    const {guard} = guardOf(t, {appId});
    guard.begin('N1');
    for (const [url, method] of writes) {
      const verdict = guard.check({url, method, headers: {}, body: JSON.stringify({text: text('N1')})});
      assert.equal(verdict.allowed, false, `${appId}: ${url}`);
      assert.equal(verdict.rule, !new URL(url).hostname.includes(appId) ? 'origin' : appId === 'slack' ? 'owner_unset' : 'no_rule');
    }
  }
  const {guard} = guardOf(t);
  guard.begin('C2');
  for (const [url, method] of writes) refuses(guard, {url, method, headers: {}, body: '{}'}, 'origin', `the Calendar guard: ${url}`);
  const notion = guardOf(t, {appId: 'notion'}).guard;
  notion.begin('N1');
  refuses(notion, {url: writes[0][0], method: 'POST', headers: {}, body: JSON.stringify({text: text('N1')})}, 'body', 'a page with no parent');
  refuses(notion, {url: writes[1][0], method: 'PATCH', headers: {}, body: '{}'}, 'not_allowlisted', 'block children are no Notion test\'s route');
  for (const [url, method] of writes.slice(2)) refuses(notion, {url, method, headers: {}, body: '{}'}, 'origin', `the Notion guard: ${url}`);
});

test('guard 12: the 13th write of a test and the 121st of a run are refused', async t => {
  const {guard, send} = await calendarRun(t);
  const remove = id => cal('DELETE', `/calendars/${enc(RUN_A)}/events/${id}`, {q: {sendUpdates: 'none'}});
  // C1 made two calendars; ten more writes fill it, and the 13th is refused.
  guard.begin('C1');
  for (let index = 0; index < LIMITS.testWrites - 2; index++) await send(remove(`c1-${index}`));
  await assert.rejects(send(remove('c1-13')), error => error.details?.rule === 'test_cap');
  passes(guard, cal('GET', `/calendars/${enc(RUN_A)}/events/e1`), 'a read still passes');
  guard.end();
  // Nine more tests of 12 writes make 120 in the run.
  for (let number = 2; number <= 10; number++) {
    guard.begin(`T${number}`);
    for (let index = 0; index < LIMITS.testWrites; index++) await send(remove(`t${number}-${index}`));
    guard.end();
  }
  assert.equal(guard.counts().writes, LIMITS.runWrites);
  guard.begin('T11');
  refuses(guard, remove('t11-0'), 'run_cap');
});

test('guard 13: a refusal carries sent: false, code action_refused, details.reason live_guard and its rule, and never calls the inner requester', async t => {
  const {guard} = await calendarRun(t);
  const {calls, inner} = provider();
  guard.begin('C2');
  const send = guard.wrap(inner);
  await assert.rejects(send(insert(RUN_A, event('C2', {summary: 'Plain'}))), error => {
    assert.deepEqual([error.sent, error.code, error.details, error.message], [false, 'action_refused', {reason: 'live_guard', rule: 'text'}, GUARD_WORDS.text]);
    return true;
  });
  await assert.rejects(send({url: 'https://oauth2.googleapis.com/revoke', method: 'POST', headers: {}, body: 'token=x'}), error => error.sent === false && error.details.rule === 'revocation');
  assert.equal(calls.length, 0);
  for (const words of Object.values(GUARD_WORDS)) assert.match(words, /Nothing was sent\.$/);
  for (const words of Object.values(GUARD_WORDS)) assert.doesNotMatch(words, /\u2014/);
});

test('guard 14: GitHub sign-ins: 5 an hour from a file log a restart keeps, an elsewhere count required, and 10 live tokens per scope set in total refused', t => {
  const folder = folderOf(t), scopes = ['repo', 'read:user', 'gist'], other = ['repo', 'read:user'];
  const {guard, advance} = guardOf(t, {appId: 'github', folder});
  assert.throws(() => guard.signIn('github', scopes), {code: 'rate_limited', message: GUARD_WORDS.github_elsewhere}, 'no elsewhere count');
  guard.setElsewhere('github', scopes, 0);
  for (let index = 0; index < LIMITS.githubHourly; index++) guard.signIn('github', [...scopes].reverse());
  assert.throws(() => guard.signIn('github', scopes), {code: 'rate_limited', message: GUARD_WORDS.github_hourly}, 'a sixth within the hour');
  // Another guard over the same folder (a restart) sees the earlier five.
  const restarted = createGuard({appId: 'github', runId: 'JKLMNPQR', folder, key: randomBytes(32), clock: () => Date.parse('2026-10-24T12:30:00.000Z')});
  restarted.setElsewhere('github', scopes, 0);
  assert.throws(() => restarted.signIn('github', scopes), {message: GUARD_WORDS.github_hourly});
  advance(60 * 60_000);
  guard.signIn('github', scopes);
  assert.equal(JSON.parse(readFileSync(signInFile(folder), 'utf8')).signIns.length, 6);
  assert.equal(statSync(signInFile(folder)).mode & 0o777, 0o600);
  // The lifetime count: this folder's sign-ins for a scope set plus those live elsewhere, refused at 10 in total; another set counts apart.
  const {guard: lifetime} = guardOf(t, {appId: 'github'});
  lifetime.setElsewhere('github', scopes, 7);
  lifetime.signIn('github', scopes);
  lifetime.signIn('github', scopes);
  assert.throws(() => lifetime.signIn('github', scopes), {code: 'rate_limited', message: GUARD_WORDS.github_tokens}, 'the 10th token');
  lifetime.setElsewhere('github', other, 7);
  lifetime.signIn('github', other);
  assert.throws(() => lifetime.setElsewhere('github', scopes, -1));
  // Google sign-ins are not counted.
  for (let index = 0; index < 8; index++) guard.signIn('google', ['openid', 'email']);
  assert.equal(JSON.parse(readFileSync(signInFile(folder), 'utf8')).signIns.filter(entry => entry.providerId !== 'github').length, 0);
});

test('guard 15: the trace holds method, path, an HMAC of the body, the status and the created identity, never a header or a body', async t => {
  const {guard, folder} = await calendarRun(t);
  const body = JSON.stringify(event('C2', {description: text('C2', 'canary-body-4471')}));
  // While the provider answers, the write is already counted in the run file: a crash mid-send never resets a cap.
  const writesBefore = guard.counts().writes;
  const {inner} = provider([() => {
    assert.equal(JSON.parse(readFileSync(guardFile(folder, 'google-calendar', RUN), 'utf8')).writes, writesBefore + 1);
    return {status: 200, data: {id: 'evt-1', summary: 'canary-answer-9012'}};
  }]);
  guard.begin('C2');
  await guard.wrap(inner)({url: `${CAL}/calendars/${enc(RUN_A)}/events?sendUpdates=none`, method: 'POST', headers: {Authorization: 'Bearer canary-token-1234', 'X-Canary': 'canary-header-5678'}, body});
  const [entry] = guard.trace('C2');
  assert.deepEqual(Object.keys(entry).sort(), ['bodyHmac', 'identity', 'method', 'path', 'status']);
  assert.deepEqual([entry.method, entry.path, entry.status, entry.identity], ['POST', `/calendar/v3/calendars/${enc(RUN_A)}/events`, 200, 'evt-1']);
  assert.equal(entry.bodyHmac, createHmac('sha256', KEY).update(body).digest('hex'));
  assert.notEqual(entry.bodyHmac, createHash('sha256').update(body).digest('hex'), 'not the body\'s plain sha256');
  const [made] = guard.trace('C1');
  assert.match(made.identity, /^hmac:[0-9a-f]{32}$/, 'an email-shaped created id is an HMAC');
  assert.equal(made.identity, `hmac:${createHmac('sha256', KEY).update(RUN_A).digest('hex').slice(0, 32)}`);
  const stored = readFileSync(guardFile(folder, 'google-calendar', RUN), 'utf8');
  for (const canary of ['canary-body-4471', 'canary-token-1234', 'canary-header-5678', 'canary-answer-9012', KEY.toString('hex'), KEY.toString('base64')]) {
    assert.ok(!JSON.stringify(guard.trace('C2')).includes(canary) && !stored.includes(canary), canary);
  }
});

test('guard 16: method and path pairs: a move needs a run calendar destination, the locked row is refused by name, and a method the list does not pair with a path is refused', async t => {
  const {guard} = await calendarRun(t);
  guard.begin('C8');
  const move = destination => cal('POST', `/calendars/${enc(RUN_A)}/events/e1/move`, {q: {sendUpdates: 'none', ...(destination === undefined ? {} : {destination})}});
  passes(guard, move(RUN_B), 'to the other run calendar');
  for (const destination of [undefined, 'primary', OWNER, 'theirs@group.calendar.google.com']) refuses(guard, move(destination), 'calendar', `to ${destination}`);
  refuses(guard, cal('POST', '/calendars/primary/events/c9event1/move', {q: {sendUpdates: 'none', destination: RUN_B}}), 'primary', 'from primary');
  const locked = [['POST', `/calendars/${enc(RUN_A)}/events/watch`], ['POST', '/users/me/calendarList/watch'], ['POST', '/users/me/settings/watch'], ['POST', `/calendars/${enc(RUN_A)}/acl/watch`],
    ['POST', '/channels/stop'], ['POST', `/calendars/${enc(RUN_A)}/acl`], ['PATCH', `/calendars/${enc(RUN_A)}/acl/${enc(SHARE_RULE)}`], ['PUT', `/calendars/${enc(RUN_A)}/acl/${enc(SHARE_RULE)}`],
    ['POST', `/calendars/${enc(RUN_A)}/transferOwnership`]];
  for (const [method, route] of locked) refuses(guard, cal(method, route, {q: {sendUpdates: 'none'}, body: {role: 'reader', scope: {type: 'user', value: GUEST}, summary: text('C8')}}), 'locked', `${method} ${route}`);
  refuses(guard, cal('POST', `/calendars/${enc(RUN_A)}/events/e1`, {q: {sendUpdates: 'none'}, body: {summary: text('C8')}}), 'not_allowlisted', 'POST on an event');
  refuses(guard, cal('PUT', `/calendars/${enc(RUN_A)}`, {body: {summary: text('C8')}}), 'not_allowlisted', 'calendars.update');
  refuses(guard, cal('PATCH', `/calendars/${enc(RUN_A)}`, {body: {summary: text('C8')}}), 'not_allowlisted', 'calendars.patch');
  refuses(guard, cal('GET', '/colors'), 'not_allowlisted');
  refuses(guard, cal('GET', `/calendars/${enc(RUN_A)}/events/e1`, {body: {}}), 'body', 'a read with a body');
  refuses(guard, cal('POST', `/calendars/${enc(RUN_A)}/events`, {q: {sendUpdates: 'none'}, body: 'not json'}), 'body');
  refuses(guard, {url: `${CAL}/calendars/${enc(RUN_A)}/events?sendUpdates=none&sendUpdates=all`, method: 'POST', headers: {}, body: JSON.stringify(event('C8'))}, 'not_allowlisted', 'a repeated query key');
});

// F10.12 check: each of these held in the code, but a hand-made fault that dropped it from one route was caught by no test.
test('guard 17 (F10.12 check): another origin is refused on the app\'s own paths; every Calendar request that names a calendar passes only on a run calendar, reads included; guests, calendar names and dates have no side door', async t => {
  const {guard} = await calendarRun(t);
  guard.begin('C2');
  // Another origin, even with the reviewed base path below it.
  for (const origin of ['https://evil.test', 'https://www.googleapis.com.evil.test', 'https://gmail.googleapis.com', 'https://www.googleapis.com:8443']) {
    refuses(guard, {url: `${origin}/calendar/v3/calendars/${enc(RUN_A)}/events?sendUpdates=none`, method: 'POST', headers: {}, body: JSON.stringify(event('C2'))}, 'origin', `${origin}: a write`);
    refuses(guard, {url: `${origin}/calendar/v3/calendars/${enc(RUN_A)}/events/e1`, method: 'GET', headers: {}}, 'origin', `${origin}: a read`);
  }
  // Every route that names a calendar: a run calendar passes; a calendar the run did not create and the primary calendar are refused.
  const none = {sendUpdates: 'none'}, window = {timeMin: '2026-10-31T00:00:00-04:00', timeMax: '2026-11-06T23:59:00-05:00'};
  const routes = id => [
    ['an event', cal('POST', `/calendars/${enc(id)}/events`, {q: none, body: event('C2')})],
    ['a quick add', cal('POST', `/calendars/${enc(id)}/events/quickAdd`, {q: {text: `${text('C2')} 2026-11-03 10:00`, sendUpdates: 'none'}})],
    ['a patch', cal('PATCH', `/calendars/${enc(id)}/events/e1`, {q: none, body: {summary: text('C2')}})],
    ['an update', cal('PUT', `/calendars/${enc(id)}/events/e1`, {q: none, body: event('C2')})],
    ['an event delete', cal('DELETE', `/calendars/${enc(id)}/events/e1`, {q: none})],
    ['a move', cal('POST', `/calendars/${enc(id)}/events/e1/move`, {q: {sendUpdates: 'none', destination: RUN_B}})],
    ['a sharing removal', cal('DELETE', `/calendars/${enc(id)}/acl/${enc(SHARE_RULE)}`)],
    ['the calendar', cal('GET', `/calendars/${enc(id)}`)],
    ['its events', cal('GET', `/calendars/${enc(id)}/events`, {q: {q: '[SYNTHETIC]', ...window}})],
    ['an event read', cal('GET', `/calendars/${enc(id)}/events/e1`)],
    ['its instances', cal('GET', `/calendars/${enc(id)}/events/e1/instances`)],
    ['its sharing list', cal('GET', `/calendars/${enc(id)}/acl`)],
    ['its sharing rule', cal('GET', `/calendars/${enc(id)}/acl/${enc(SHARE_RULE)}`)],
  ];
  for (const [name, request] of routes(RUN_A)) passes(guard, request, `${name} on a run calendar`);
  for (const other of ['theirs@group.calendar.google.com', 'colleague@elsewhere.test']) for (const [name, request] of routes(other)) refuses(guard, request, 'calendar', `${name} on ${other}`);
  for (const primary of ['primary', OWNER]) {
    for (const [name, request] of routes(primary).filter(([name]) => name !== 'its events')) refuses(guard, request, 'primary', `${name} on ${primary}`);
  }
  refuses(guard, cal('GET', '/calendars/primary/events/c9event1/instances'), 'primary', 'the instances of the recorded C9 event');
  // Guests: a group calendar the run did not create is no organizer entry.
  const invite = attendees => cal('PATCH', `/calendars/${enc(RUN_A)}/events/e1`, {q: none, body: {attendees}});
  passes(guard, invite([{email: RUN_B}, {email: GUEST}]), 'the other run calendar');
  for (const email of ['team@group.calendar.google.com', 'theirs@group.calendar.google.com']) refuses(guard, invite([{email}, {email: GUEST}]), 'guest', email);
  // A new calendar always names itself with synthetic text, and a start or end is a date or a time, never both.
  refuses(guard, cal('POST', '/calendars', {body: {timeZone: 'America/Toronto'}}), 'text', 'a calendar with no summary');
  refuses(guard, insert(RUN_A, {summary: text('C2'), start: {date: '2026-11-02', dateTime: '2026-11-02T10:00:00-05:00'}, end: {date: '2026-11-03'}}), 'window', 'a date and a time in one start');
});

// F10.12 check: the guard split headers on CRLF and LF only, so a lone CR (or another line break some mail parsers honor) hid a Bcc inside
// the Subject the guard read whole. A header block the guard cannot split the one way every parser does is refused.
test('guard 18 (F10.12 check): a Gmail header block with a line break other than CRLF or LF, or another control character, is refused, so no recipient can hide in a header the guard read whole', t => {
  const {guard} = guardOf(t, {appId: 'gmail'});
  guard.setOwner(OWNER_FACTS);
  guard.begin('G1');
  const sendText = message => at(GMAIL, 'POST', '/messages/send', {body: {raw: Buffer.from(message, 'utf8').toString('base64url')}});
  const subject = `Subject: ${text('G1')}`;
  passes(guard, sendText(`To: ${OWNER}\r\n${subject}\r\n\r\nBody`), 'CRLF');
  passes(guard, sendText(`To: ${OWNER}\n${subject}\n\nBody`), 'LF alone');
  passes(guard, sendText(`To: ${OWNER},\r\n\t${OWNER}\r\n${subject}\r\n\r\nBody\rwith a lone CR\u0000 in the body`), 'a tab fold, and controls in the body only');
  for (const [name, mark] of [['a lone CR', '\r'], ['a NEL', '\u0085'], ['a line separator', '\u2028'], ['a paragraph separator', '\u2029'], ['a vertical tab', '\u000b'], ['a form feed', '\u000c'], ['a NUL', '\u0000'], ['a DEL', '\u007f']]) {
    refuses(guard, sendText(`To: ${OWNER}\r\n${subject}${mark}Bcc: other@elsewhere.test\r\n\r\nBody`), 'body', `${name} before a hidden Bcc`);
  }
  refuses(guard, sendText(`To: ${OWNER}\r\n${subject}\r\r\n\r\nBody`), 'body', 'a lone CR at the end of the headers');
  refuses(guard, at(GMAIL, 'POST', '/drafts', {body: {message: {raw: Buffer.from(`To: ${OWNER}\r\n${subject}\rCc: other@elsewhere.test\r\n\r\nBody`).toString('base64url')}}}), 'body', 'a draft too');
});

// ---- F10.21 part 2: Slack's rules (docs/F10.21-BUILD-MAP.md part 2) --------------------------------------------------------------------
const SLACK_API = 'https://slack.com/api', SLACK_START = Date.parse('2026-10-26T15:00:00.000Z'), NOW_SECONDS = SLACK_START / 1000;
const SLACK_RECORDED = {fabricTest: 'C0FABTEST1', selfDm: 'D0OWNER01', ownerUser: 'U0OWNER01', synthetic1: '1793019600.000000', synthetic2: '1793023200.000000', canvas: 'F0CANVAS01'};
const slackCall = (method, name, body, q) => at(SLACK_API, method, `/${name}`, {q, ...(body !== undefined ? {body} : {})});
/** A Slack guard with the owner set and the recorded test areas, its clock at the harness's start. */
function slackRun(t) {
  const made = guardOf(t, {appId: 'slack', start: SLACK_START});
  made.guard.setOwner({email: 'owner@example.com', timeZone: 'UTC', runDate: '2026-10-26', recorded: SLACK_RECORDED});
  return made;
}
const post = (test, extra = {}) => slackCall('POST', 'chat.postMessage', {channel: 'C0FABTEST1', text: text(test, 'v1'), parse: 'none', link_names: false, unfurl_links: false, unfurl_media: false, ...extra});

test('guard 19 (F10.21): Slack posts only in the recorded #fabric-test or your self-DM, synthetic, with parse none and link_names false; replies only in synthetic1\'s thread; chat.delete never; reads pass', t => {
  const {guard} = slackRun(t);
  refuses(guard, post('S2'), 'outside_test');
  guard.begin('S2');
  passes(guard, post('S2'));
  passes(guard, post('S2', {channel: 'D0OWNER01'}), 'your self-DM');
  refuses(guard, post('S2', {channel: 'C0GENERAL1'}), 'slack_channel');
  refuses(guard, post('S2', {channel: 'D0ADA0001'}), 'slack_channel', 'another person\'s DM');
  for (const [value, note] of [['plain words', 'not synthetic'], [text('S3'), 'another test'], [`[SYNTHETIC] Fabric S2 ZZZZZZZZ v1`, 'another run']]) refuses(guard, post('S2', {text: value}), 'text', note);
  for (const [extra, note] of [[{parse: 'full'}, 'parse full'], [{link_names: true}, 'link_names'], [{unfurl_links: true}, 'unfurl'], [{blocks: []}, 'blocks'], [{reply_broadcast: true}, 'a broadcast reply'],
    [{token: 'xoxp-1'}, 'a token argument']]) refuses(guard, post('S2', extra), 'body', note);
  refuses(guard, slackCall('POST', 'chat.postMessage', {channel: 'C0FABTEST1', text: text('S2')}), 'body', 'parse and link_names left to Slack');
  guard.end();
  guard.begin('S3');
  passes(guard, post('S3', {thread_ts: SLACK_RECORDED.synthetic1, reply_broadcast: false}));
  refuses(guard, post('S3', {thread_ts: SLACK_RECORDED.synthetic2}), 'slack_channel', 'another thread');
  for (const request of [slackCall('POST', 'chat.delete', {channel: 'C0FABTEST1', ts: SLACK_RECORDED.synthetic1}), slackCall('POST', 'chat.delete', {channel: 'C0FABTEST1', ts: SLACK_RECORDED.synthetic1, as_user: true})]) {
    refuses(guard, request, 'slack_delete');
  }
  for (const name of ['chat.postEphemeral', 'chat.meMessage', 'pins.add', 'conversations.join', 'conversations.kick', 'files.upload', 'conversations.mark']) {
    refuses(guard, slackCall('POST', name, {channel: 'C0FABTEST1', text: text('S3')}), 'not_allowlisted', name);
  }
  for (const request of [slackCall('GET', 'conversations.history', undefined, {channel: 'C0GENERAL1', limit: '15'}), slackCall('GET', 'users.list', undefined, {limit: '100'}),
    slackCall('GET', 'auth.test'), slackCall('POST', 'canvases.getContent', {canvas_id: 'F0CANVAS01', content_type: 'markdown'})]) {
    assert.equal(passes(guard, request).write, false, request.url);
  }
});

test('guard 20 (F10.21): Slack edits only a message this run posted, reacts only with white_check_mark, opens only your self-DM, schedules at most a day ahead and cancels only its own, and sets only a status that clears within an hour', async t => {
  const {guard} = slackRun(t), posted = '1793026800.000100';
  const {inner} = provider([{status: 200, data: {ok: true, channel: 'C0FABTEST1', ts: posted}}, {status: 200, data: {ok: true, channel: 'C0FABTEST1', scheduled_message_id: 'Q000000001', post_at: NOW_SECONDS + 7200}}]);
  const send = guard.wrap(inner);
  const update = (extra = {}) => slackCall('POST', 'chat.update', {channel: 'C0FABTEST1', ts: posted, text: text('S2', 'v2'), attachments: [], parse: 'none', link_names: false, ...extra});
  guard.begin('S2');
  refuses(guard, update(), 'slack_message', 'not posted yet');
  await send(post('S2'));
  passes(guard, update());
  refuses(guard, update({ts: SLACK_RECORDED.synthetic1}), 'slack_message', 'a message this run did not post');
  refuses(guard, update({text: 'plain'}), 'text');
  refuses(guard, update({channel: 'C0GENERAL1'}), 'slack_channel');
  refuses(guard, update({parse: 'full'}), 'body');
  refuses(guard, update({blocks: []}), 'body');
  guard.end();
  guard.begin('S4');
  const reaction = (name, extra = {}) => slackCall('POST', name, {channel: 'C0FABTEST1', timestamp: SLACK_RECORDED.synthetic2, name: 'white_check_mark', ...extra});
  passes(guard, reaction('reactions.add'));
  passes(guard, reaction('reactions.remove'));
  refuses(guard, reaction('reactions.add', {name: 'thumbsup'}), 'slack_reaction');
  refuses(guard, reaction('reactions.add', {name: 'white_check_mark::skin-tone-2'}), 'slack_reaction');
  refuses(guard, reaction('reactions.add', {channel: 'C0GENERAL1'}), 'slack_channel');
  guard.end();
  guard.begin('S5');
  passes(guard, slackCall('POST', 'conversations.open', {users: 'U0OWNER01'}));
  for (const users of ['U0ADA0001', 'U0OWNER01,U0ADA0001', '']) refuses(guard, slackCall('POST', 'conversations.open', {users}), 'slack_dm', users);
  refuses(guard, slackCall('POST', 'conversations.open', {channel: 'D0OWNER01'}), 'slack_dm', 'a channel to resume');
  guard.end();
  guard.begin('S1');
  const schedule = (postAt, extra = {}) => slackCall('POST', 'chat.scheduleMessage', {channel: 'C0FABTEST1', text: text('S1', 'scheduled'), post_at: postAt, parse: 'none', link_names: false,
    unfurl_links: false, unfurl_media: false, ...extra});
  const cancel = (id, extra = {}) => slackCall('POST', 'chat.deleteScheduledMessage', {channel: 'C0FABTEST1', scheduled_message_id: id, ...extra});
  refuses(guard, cancel('Q000000001'), 'slack_message', 'not scheduled yet');
  for (const [postAt, note] of [[NOW_SECONDS - 60, 'in the past'], [NOW_SECONDS + 86_400 + 1, 'a day and a second ahead'], [String(NOW_SECONDS + 7200), 'as text'], [NOW_SECONDS + 7200.5, 'a fraction']]) {
    refuses(guard, schedule(postAt), 'slack_schedule', note);
  }
  refuses(guard, schedule(NOW_SECONDS + 7200, {channel: 'C0GENERAL1'}), 'slack_channel');
  refuses(guard, schedule(NOW_SECONDS + 7200, {text: 'plain'}), 'text');
  await send(schedule(NOW_SECONDS + 7200));
  passes(guard, cancel('Q000000001'));
  refuses(guard, cancel('Q000000002'), 'slack_message');
  refuses(guard, cancel('Q000000001', {channel: 'C0GENERAL1'}), 'slack_channel');
  guard.end();
  guard.begin('S6');
  const status = profile => slackCall('POST', 'users.profile.set', {profile});
  passes(guard, status({status_text: text('S6', 'status'), status_emoji: ':calendar:', status_expiration: NOW_SECONDS + 600}));
  passes(guard, status({status_text: '', status_emoji: '', status_expiration: 0}), 'the clear form');
  for (const [profile, note] of [[{status_text: text('S6'), status_emoji: ':calendar:', status_expiration: NOW_SECONDS + 3601}, 'past an hour'],
    [{status_text: text('S6'), status_emoji: ':calendar:', status_expiration: 0}, 'never clears'], [{status_text: text('S6'), status_emoji: ':calendar:', status_expiration: NOW_SECONDS - 1}, 'already over'],
    [{status_text: text('S6'), status_emoji: ':calendar:', status_expiration: NOW_SECONDS + 600, real_name: 'x'}, 'another field'], [{status_text: '', status_emoji: ':calendar:', status_expiration: 0}, 'half a clear']]) {
    refuses(guard, status(profile), 'slack_status', note);
  }
  refuses(guard, status({status_text: 'plain', status_emoji: ':calendar:', status_expiration: NOW_SECONDS + 600}), 'text');
  refuses(guard, slackCall('POST', 'users.profile.set', {user: 'U0OWNER01', profile: {status_text: '', status_emoji: '', status_expiration: 0}}), 'slack_status', 'never user');
  guard.end();
  assert.deepEqual(guard.created().map(item => [item.kind, item.id]), [['slack-message', posted], ['slack-scheduled', 'Q000000001']]);
});

/** Every read the shipped Slack actions and the live plan send: each GET step of catalog/actions/slack.json and each read step of catalog/live-tests/slack.json. */
function slackReads() {
  const file = JSON.parse(readFileSync(new URL('../catalog/actions/slack.json', import.meta.url), 'utf8'));
  const plan = JSON.parse(readFileSync(new URL('../catalog/live-tests/slack.json', import.meta.url), 'utf8'));
  const steps = file.actions.flatMap(action => [...action.prepare, ...action.perform, ...(action.verify?.requests ?? [])]).filter(step => step.method === 'GET');
  const planned = plan.tests.flatMap(item => [...item.steps, ...(item.undo?.steps ?? [])]).filter(step => step.read);
  return [...new Set([...steps.map(step => step.path), ...planned.map(step => step.read.path)].map(route => route.slice(1)))].sort();
}

test('guard 21 (F10.21 check): Slack reads a GET\'s query as any method\'s arguments, so a GET passes only for the reads the actions and the plan send; a write with a query is refused', t => {
  const {guard} = slackRun(t);
  guard.begin('S2');
  // Each of these writes in Slack when sent as a GET: the guard never reads the verb as the effect.
  for (const [name, q] of [['chat.postMessage', {channel: 'C0GENERAL1', text: 'hello'}], ['chat.update', {channel: 'C0GENERAL1', ts: SLACK_RECORDED.synthetic1, text: 'x'}],
    ['chat.scheduleMessage', {channel: 'C0GENERAL1', text: 'x', post_at: String(NOW_SECONDS + 600)}], ['chat.deleteScheduledMessage', {channel: 'C0FABTEST1', scheduled_message_id: 'Q000000001'}],
    ['reactions.add', {channel: 'C0GENERAL1', timestamp: SLACK_RECORDED.synthetic1, name: 'thumbsup'}], ['reactions.remove', {channel: 'C0GENERAL1', timestamp: SLACK_RECORDED.synthetic1, name: 'thumbsup'}],
    ['conversations.open', {users: 'U0ADA0001'}], ['users.profile.set', {profile: JSON.stringify({status_text: 'x'})}], ['conversations.kick', {channel: 'C0GENERAL1', user: 'U0ADA0001'}],
    ['conversations.archive', {channel: 'C0FABTEST1'}], ['conversations.mark', {channel: 'C0GENERAL1', ts: SLACK_RECORDED.synthetic1}], ['files.delete', {file: 'F0CANVAS01'}],
    ['canvases.delete', {canvas_id: 'F0CANVAS01'}], ['canvases.getContent', {canvas_id: 'F0CANVAS01'}], ['users.info/U0ADA0001', undefined]]) {
    refuses(guard, slackCall('GET', name, undefined, q), 'not_allowlisted', `GET ${name}`);
  }
  refuses(guard, slackCall('GET', 'chat.delete', undefined, {channel: 'C0FABTEST1', ts: SLACK_RECORDED.synthetic1}), 'slack_delete');
  // A write carries its arguments in its JSON body only: Slack also reads a query beside it, so any query is refused, whatever it says.
  const body = JSON.parse(post('S2').body);
  passes(guard, slackCall('POST', 'chat.postMessage', body));
  for (const q of [{channel: 'C0GENERAL1'}, {channel: 'C0FABTEST1'}, {link_names: 'true'}, {thread_ts: SLACK_RECORDED.synthetic2}]) refuses(guard, slackCall('POST', 'chat.postMessage', body, q), 'body', JSON.stringify(q));
  refuses(guard, slackCall('POST', 'conversations.open', {users: 'U0OWNER01'}, {users: 'U0ADA0001'}), 'body', 'a second person in the query');
  refuses(guard, slackCall('POST', 'canvases.getContent', {canvas_id: 'F0CANVAS01', content_type: 'markdown'}, {canvas_id: 'F0OTHER001'}), 'body', 'the reviewed read too');
  // Every read the shipped actions and the plan send passes, as a read, in any channel; auth.test is the sign-in's identity read.
  const reads = slackReads();
  assert.deepEqual(reads, ['chat.getPermalink', 'chat.scheduledMessages.list', 'conversations.history', 'conversations.info', 'conversations.replies', 'reactions.get', 'search.messages',
    'users.conversations', 'users.info', 'users.list', 'users.lookupByEmail', 'users.profile.get'], 'a new read in the file or the plan is added to the guard\'s list first');
  for (const name of [...reads, 'auth.test']) assert.equal(passes(guard, slackCall('GET', name, undefined, {channel: 'C0GENERAL1'})).write, false, name);
  guard.end();
});

// F10.15 part 1 (docs/F10.15-BUILD-MAP.md part 1): Gmail's rules for what G0 to G10 send, and nothing more. A Gmail run records the read
// pass's message and conversation and the owner's hand draft; G3 sends one message (m3 in thread t3), makes a draft and a label.
const GMAIL_FACTS = {...OWNER_FACTS, recorded: {readMessage: 'read-m', readThread: 'read-t', handDraft: 'r-hand'}};
async function gmailRun(t) {
  const made = guardOf(t, {appId: 'gmail'}), {guard} = made;
  guard.setOwner(GMAIL_FACTS);
  const {inner} = provider([{status: 200, data: {id: 'm3', threadId: 't3', labelIds: ['SENT', 'INBOX', 'UNREAD']}}, {status: 200, data: {id: 'r-made', message: {id: 'dm1', threadId: 'dm1'}}},
    {status: 200, data: {id: 'Label_5', name: text('G3'), type: 'user'}}]);
  const send = guard.wrap(inner);
  guard.begin('G3');
  await send(at(GMAIL, 'POST', '/messages/send', {body: {raw: raw([`To: ${OWNER}`, `Subject: ${text('G3')}`])}}));
  await send(at(GMAIL, 'POST', '/drafts', {body: {message: {raw: raw([`To: ${OWNER}`, `Subject: ${text('G3')}`])}}}));
  await send(at(GMAIL, 'POST', '/labels', {body: {name: text('G3')}}));
  guard.end();
  return {...made, send};
}
const search = q => at(GMAIL, 'GET', '/messages', {q: {q, maxResults: '5'}});
/** Epoch milliseconds, as text, of an instant in the owner's zone. */
const millis = instant => String(Date.parse(instant));

test('guard 19 (F10.15): Gmail reads only the run\'s mail, what a synthetic search found and the recorded read-pass message, conversation and hand draft', async t => {
  const {guard} = await gmailRun(t);
  guard.begin('G0');
  for (const route of ['/profile', '/labels', '/settings/vacation']) passes(guard, at(GMAIL, 'GET', route));
  // A search reads only synthetic mail: Fabric's query form with a quoted phrase starting [SYNTHETIC] Fabric, and nothing that widens it.
  passes(guard, search('"[SYNTHETIC] Fabric read pass"'));
  passes(guard, search('from:"owner@fabric-owner.test" subject:"[SYNTHETIC] Fabric read pass" -has:attachment after:1793000000 before:1794000000'));
  for (const [q, note] of [['"Invoices"', 'no synthetic phrase'], ['', 'no query'], ['-"[SYNTHETIC] Fabric read pass"', 'the phrase negated'],
    ['"[SYNTHETIC] Fabric read pass" OR from:"boss@elsewhere.test"', 'OR'], ['{"[SYNTHETIC] Fabric read pass" "Invoices"}', 'a group'],
    ['in:anywhere "[SYNTHETIC] Fabric read pass"', 'another operator'], ['"[SYNTHETIC] Fabric read pass" boss', 'a bare word'],
    ['label:"[SYNTHETIC] Fabric read pass"', 'the phrase under another operator'], ['"[SYNTHETIC] Fabric read pass"  "x"', 'two spaces']]) {
    refuses(guard, search(q), 'mailbox', note);
  }
  refuses(guard, at(GMAIL, 'GET', '/messages', {q: {q: '"[SYNTHETIC] Fabric read pass"', includeSpamTrash: 'true'}}), 'mailbox', 'another parameter');
  // What a search answers is remembered: its messages and threads may be read, and nothing else is; a failed search remembers nothing.
  for (const [method, route] of [['GET', '/messages/found-m'], ['GET', '/threads/found-t'], ['GET', '/messages/other-m'], ['GET', '/threads/other-t'], ['GET', '/drafts/r-other']]) {
    refuses(guard, at(GMAIL, method, route), 'mailbox', `${route} before the search`);
  }
  const {inner} = provider([{status: 500, data: {messages: [{id: 'lost-m', threadId: 'lost-t'}]}}, {status: 200, data: {messages: [{id: 'found-m', threadId: 'found-t'}], resultSizeEstimate: 1}}]);
  const send = guard.wrap(inner);
  await send(search('"[SYNTHETIC] Fabric read pass"'));
  await send(search('"[SYNTHETIC] Fabric read pass"'));
  refuses(guard, at(GMAIL, 'GET', '/messages/lost-m'), 'mailbox', 'a failed search\'s answer');
  passes(guard, at(GMAIL, 'GET', '/messages/found-m', {q: {format: 'full'}}));
  passes(guard, {url: `${GMAIL}/messages/found-m?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`, method: 'GET', headers: {}}, 'metadataHeaders repeated, as Find emails reads them');
  refuses(guard, {url: `${GMAIL}/messages/found-m?format=full&format=raw`, method: 'GET', headers: {}}, 'not_allowlisted', 'another parameter repeated');
  passes(guard, at(GMAIL, 'GET', '/threads/found-t', {q: {format: 'full'}}));
  for (const route of ['/messages/m3', '/threads/t3', '/messages/read-m', '/threads/read-t', '/drafts/r-made', '/drafts/r-hand']) passes(guard, at(GMAIL, 'GET', route), route);
  for (const route of ['/messages/other-m', '/threads/other-t', '/drafts/r-other', '/messages/read-t', '/threads/read-m', '/threads/m3', '/drafts/m3']) refuses(guard, at(GMAIL, 'GET', route), 'mailbox', route);
  passes(guard, at(GMAIL, 'GET', '/labels/Label_5'));
  for (const label of ['INBOX', 'Label_9']) refuses(guard, at(GMAIL, 'GET', `/labels/${label}`), 'label', label);
  refuses(guard, at(GMAIL, 'GET', '/settings/filters/ANe1BmOther'), 'filter');
  assert.deepEqual(guard.counts().testWrites.G0 ?? 0, 0, 'reads count as no write');
  // Recorded values name nothing on a guard that recorded none.
  const {guard: bare} = guardOf(t, {appId: 'gmail', folder: folderOf(t)});
  bare.setOwner(OWNER_FACTS);
  bare.begin('G0');
  for (const route of ['/messages/read-m', '/threads/read-t', '/drafts/r-hand', '/messages/undefined']) refuses(bare, at(GMAIL, 'GET', route), 'mailbox', `${route} with nothing recorded`);
});

test('guard 20 (F10.15): Gmail changes only the run\'s mail, labels and drafts, the hand draft by its edit, the vacation reply by the rules and one synthetic filter', async t => {
  const {guard, send} = await gmailRun(t);
  guard.begin('G4');
  const message = (extra = {}) => ({raw: raw([`To: ${OWNER}`, `Subject: ${text('G4')}`]), ...extra});
  // A send or a draft names only a thread this run made.
  passes(guard, at(GMAIL, 'POST', '/messages/send', {body: message({threadId: 't3'})}));
  for (const thread of ['read-t', 'other-t', 'm-other', '']) refuses(guard, at(GMAIL, 'POST', '/messages/send', {body: message({threadId: thread})}), 'mailbox', `a send into ${thread}`);
  refuses(guard, at(GMAIL, 'POST', '/drafts', {body: {message: message({threadId: 'read-t'})}}), 'mailbox', 'a draft in another thread');
  refuses(guard, at(GMAIL, 'PUT', '/drafts/r-made', {body: {id: 'r-made', message: message({threadId: 'other-t'})}}), 'mailbox', 'a draft edit into another thread');
  passes(guard, at(GMAIL, 'POST', '/drafts', {body: {message: message({threadId: 't3'})}}));
  // The hand draft may be edited, never sent; any other draft the run did not make is refused.
  passes(guard, at(GMAIL, 'PUT', '/drafts/r-hand', {body: {id: 'r-hand', message: message()}}));
  refuses(guard, at(GMAIL, 'PUT', '/drafts/r-other', {body: {id: 'r-other', message: message()}}), 'draft');
  refuses(guard, at(GMAIL, 'POST', '/drafts/send', {body: {id: 'r-hand', message: message()}}), 'draft', 'the hand draft is never sent');
  refuses(guard, at(GMAIL, 'PUT', '/drafts/r-hand', {body: {id: 'r-hand'}}), 'draft', 'the hand draft without its whole message');
  // Labels: only the run's own and INBOX, UNREAD, STARRED and IMPORTANT, on the run's own messages and threads.
  const modify = body => at(GMAIL, 'POST', '/messages/batchModify', {body});
  passes(guard, modify({ids: ['m3'], addLabelIds: ['Label_5'], removeLabelIds: ['UNREAD', 'INBOX']}));
  passes(guard, modify({ids: ['m3'], addLabelIds: ['STARRED', 'IMPORTANT']}));
  for (const label of ['TRASH', 'SPAM', 'SENT', 'DRAFT', 'Label_9', 'CATEGORY_SOCIAL']) {
    refuses(guard, modify({ids: ['m3'], addLabelIds: [label]}), 'label', `adding ${label}`);
    refuses(guard, modify({ids: ['m3'], removeLabelIds: [label]}), 'label', `removing ${label}`);
  }
  for (const ids of [['found-m'], ['read-m'], ['m3', 'other-m'], [], 'm3']) refuses(guard, modify({ids, addLabelIds: ['STARRED']}), 'mailbox', `ids ${JSON.stringify(ids)}`);
  refuses(guard, modify({ids: ['m3'], addLabelIds: ['STARRED'], deleteAll: true}), 'body', 'another key');
  refuses(guard, modify({ids: ['m3'], addLabelIds: 'STARRED'}), 'label', 'labels that are not a list');
  passes(guard, at(GMAIL, 'POST', '/threads/t3/modify', {body: {addLabelIds: ['Label_5'], removeLabelIds: ['INBOX']}}));
  refuses(guard, at(GMAIL, 'POST', '/threads/read-t/modify', {body: {addLabelIds: ['STARRED']}}), 'mailbox');
  refuses(guard, at(GMAIL, 'POST', '/threads/t3/modify', {body: {addLabelIds: ['TRASH']}}), 'label');
  refuses(guard, at(GMAIL, 'POST', '/threads/t3/modify', {body: {ids: ['m3'], addLabelIds: ['STARRED']}}), 'body');
  // Trash and restore: the run's own message or thread, with no body.
  for (const route of ['/messages/m3/trash', '/messages/m3/untrash', '/threads/t3/trash', '/threads/t3/untrash']) passes(guard, at(GMAIL, 'POST', route), route);
  for (const route of ['/messages/read-m/trash', '/messages/found-m/untrash', '/threads/read-t/trash', '/threads/other-t/untrash']) refuses(guard, at(GMAIL, 'POST', route), 'mailbox', route);
  refuses(guard, at(GMAIL, 'POST', '/messages/m3/trash', {body: {}}), 'body', 'a trash with a body');
  // The vacation reply: off, or on for contacts only, with synthetic text, both times inside the run's days 7 to 13.
  const vacation = body => at(GMAIL, 'PUT', '/settings/vacation', {body});
  const on = {enableAutoReply: true, responseSubject: text('G4', 'away'), responseBodyPlainText: text('G4', 'back soon'), restrictToContacts: true,
    startTime: millis('2026-10-31T09:00:00-04:00'), endTime: millis('2026-11-01T09:00:00-05:00')};
  passes(guard, vacation({enableAutoReply: false}));
  passes(guard, vacation(on));
  passes(guard, vacation({...on, startTime: millis('2026-10-31T00:00:00-04:00'), endTime: millis('2026-11-06T23:59:00-05:00')}), 'the window\'s first and last minutes');
  for (const [note, body] of [['on for everyone', {...on, restrictToContacts: false}], ['on with no contacts flag', (({restrictToContacts, ...rest}) => rest)(on)],
    ['on for the domain', {...on, restrictToDomain: true}], ['an HTML body', {...on, responseBodyHtml: '<p>away</p>'}], ['on with no times', (({startTime, endTime, ...rest}) => rest)(on)],
    ['off with text', {enableAutoReply: false, responseSubject: text('G4')}], ['nothing', {}], ['a time that is a number', {...on, startTime: Date.parse('2026-10-31T09:00:00-04:00')}]]) {
    refuses(guard, vacation(body), 'vacation', note);
  }
  refuses(guard, vacation({...on, responseSubject: 'Away'}), 'text', 'a plain subject');
  refuses(guard, vacation({...on, responseBodyPlainText: 'Back Monday.'}), 'text', 'a plain text');
  refuses(guard, vacation({...on, startTime: millis('2026-10-30T23:59:00-04:00')}), 'window', 'a start before day 7');
  refuses(guard, vacation({...on, endTime: millis('2026-11-07T00:00:00-05:00')}), 'window', 'an end at day 14');
  // One filter: mail from the synthetic sender gets one label this run made; never a forward, another sender or a second label.
  const filter = (criteria, action) => at(GMAIL, 'POST', '/settings/filters', {body: {criteria, action}});
  const sender = {from: 'synthetic-sender@example.invalid'};
  const made = await send(filter(sender, {addLabelIds: ['Label_5']}));
  assert.equal(made.status, 200);
  for (const [note, criteria, action] of [['a forward', sender, {addLabelIds: ['Label_5'], forward: OWNER}], ['a forward alone', sender, {forward: OWNER}],
    ['another sender', {from: 'boss@elsewhere.test'}, {addLabelIds: ['Label_5']}], ['another criterion', {...sender, query: 'x'}, {addLabelIds: ['Label_5']}],
    ['two labels', sender, {addLabelIds: ['Label_5', 'STARRED']}], ['a removal', sender, {addLabelIds: ['Label_5'], removeLabelIds: ['INBOX']}]]) {
    refuses(guard, filter(criteria, action), 'filter', note);
  }
  for (const label of ['TRASH', 'Label_9', 'INBOX']) refuses(guard, filter(sender, {addLabelIds: [label]}), 'label', label);
  refuses(guard, at(GMAIL, 'POST', '/settings/filters', {body: {id: 'x', criteria: sender, action: {addLabelIds: ['Label_5']}}}), 'filter', 'another key');
  guard.end();
});

test('guard 21 (F10.15): Gmail\'s locked row is refused by name, whatever the method; every delete, import and insert, and every other route, is off the list', async t => {
  const {guard} = await gmailRun(t);
  guard.begin('G10');
  const locked = [['POST', '/watch'], ['POST', '/stop'], ['GET', '/settings/sendAs'], ['POST', '/settings/sendAs'], ['PATCH', '/settings/sendAs/owner%40fabric-owner.test'],
    ['PUT', '/settings/sendAs/x'], ['DELETE', '/settings/sendAs/x'], ['POST', '/settings/sendAs/x/verify'], ['POST', '/settings/sendAs/x/smimeInfo'], ['GET', '/settings/forwardingAddresses'],
    ['POST', '/settings/forwardingAddresses'], ['DELETE', '/settings/forwardingAddresses/x'], ['GET', '/settings/delegates'], ['POST', '/settings/delegates'], ['DELETE', '/settings/delegates/x'],
    ['GET', '/settings/autoForwarding'], ['PUT', '/settings/autoForwarding']];
  for (const [method, route] of locked) {
    refuses(guard, at(GMAIL, method, route, method === 'GET' || method === 'DELETE' ? {} : {body: {topicName: 'projects/x/topics/y', forwardingEmail: OWNER, delegateEmail: OWNER, enabled: true}}), 'locked', `${method} ${route}`);
  }
  for (const [method, route, body] of [['DELETE', '/messages/m3'], ['DELETE', '/threads/t3'], ['DELETE', '/drafts/r-made'], ['DELETE', '/labels/Label_5'], ['DELETE', '/settings/filters/f1'],
    ['POST', '/messages/batchDelete', {ids: ['m3']}], ['POST', '/messages/import', {raw: raw([`To: ${OWNER}`, `Subject: ${text('G10')}`])}], ['POST', '/messages', {raw: raw([`To: ${OWNER}`, `Subject: ${text('G10')}`])}],
    ['POST', '/messages/m3/modify', {addLabelIds: ['STARRED']}], ['PUT', '/labels/Label_5', {name: text('G10')}], ['PATCH', '/labels/Label_5', {name: text('G10')}], ['PUT', '/settings/imap', {enabled: false}],
    ['GET', '/history'], ['GET', '/drafts'], ['GET', '/threads'], ['GET', '/settings/filters'], ['GET', '/messages/m3/attachments/a1']]) {
    refuses(guard, at(GMAIL, method, route, body === undefined ? {} : {body}), 'not_allowlisted', `${method} ${route}`);
  }
  // checkPlan() (lib/live-certify.mjs) compares each write placement with the list: the reads and writes above, below Gmail's base.
  const pairs = RULES.gmail.allowlist.map(pair => `${pair.method} ${pair.path}`);
  for (const pair of ['POST messages/send', 'POST drafts', 'PUT drafts/:draft', 'POST drafts/send', 'POST labels', 'POST messages/batchModify', 'POST threads/:id/modify', 'POST messages/:id/trash',
    'POST messages/:id/untrash', 'POST threads/:id/trash', 'POST threads/:id/untrash', 'PUT settings/vacation', 'POST settings/filters', 'GET messages', 'GET messages/:id', 'GET threads/:id',
    'GET drafts/:draft', 'GET labels', 'GET labels/:label', 'GET settings/vacation', 'GET settings/filters/:filter', 'GET profile']) assert.ok(pairs.includes(pair), pair);
  assert.equal(pairs.length, 22, 'nothing more');
  for (const word of ['mailbox', 'label', 'vacation', 'filter']) assert.match(GUARD_WORDS[word], /Nothing was sent\.$/);
});

test('guard 22 (F10.15): a sent message\'s thread joins the run only from a passed send\'s answer, once, and survives a restart; a draft\'s does not', async t => {
  const {guard, folder} = await gmailRun(t);
  assert.deepEqual(guard.created().map(item => [item.kind, item.id]), [['message', 'm3'], ['thread', 't3'], ['draft', 'r-made'], ['label', 'Label_5']]);
  const {inner} = provider([{status: 200, data: {id: 'm4', threadId: 't3'}}, {status: 400, data: {error: {code: 400}}}, {status: 200, data: {id: 'm5', threadId: 't5'}}]);
  const send = guard.wrap(inner);
  guard.begin('G8');
  await send(at(GMAIL, 'POST', '/messages/send', {body: {raw: raw([`To: ${OWNER}`, `Subject: ${text('G8')}`]), threadId: 't3'}}));
  await send(at(GMAIL, 'POST', '/messages/send', {body: {raw: raw([`To: ${OWNER}`, `Subject: ${text('G8')}`])}}));
  await send(at(GMAIL, 'POST', '/drafts/send', {body: {id: 'r-made', message: {raw: raw([`To: ${OWNER}`, `Subject: ${text('G8')}`])}}}));
  guard.end();
  assert.deepEqual(guard.created().slice(4).map(item => [item.kind, item.id, item.test]), [['message', 'm4', 'G8'], ['message', 'm5', 'G8'], ['thread', 't5', 'G8']], 'a thread once; a refused send adds nothing');
  const restarted = createGuard({appId: 'gmail', runId: RUN, folder, key: KEY});
  restarted.begin('G9');
  for (const route of ['/messages/m5', '/threads/t5']) passes(restarted, at(GMAIL, 'GET', route), `${route} after a restart`);
});

test('guard 23 (F10.15 part 2): a reply\'s Subject is "Re: " and the synthetic text of a message this run sent, as Reply builds it; anything else is refused', async t => {
  const {guard} = await gmailRun(t);
  guard.begin('G4');
  const reply = subject => at(GMAIL, 'POST', '/messages/send', {body: {raw: raw([`To: ${OWNER}`, `Subject: ${subject}`, 'In-Reply-To: <g3@mail.gmail.com>']), threadId: 't3'}});
  for (const subject of [`Re: ${text('G3', 'email')}`, `RE: ${text('G3')}`, `re:${text('G3')}`, `Re: ${text('G4')}`, `Re: ${text('G10', 'filter')}`]) passes(guard, reply(subject), subject);
  for (const subject of ['Re: Hello', `Re: Re: ${text('G3')}`, `Fwd: ${text('G3')}`, `Re: [SYNTHETIC] Fabric G3 ZZZZZZZZ email`, `Re: [SYNTHETIC] Fabric G3 ${RUN}x`, `Re: x ${text('G3')}`, 'Re:',
    `Re: [SYNTHETIC] Fabric ${RUN}`]) {
    refuses(guard, reply(subject), 'text', subject);
  }
  // A draft's Subject follows the same rule, and a plain one is still refused.
  passes(guard, at(GMAIL, 'POST', '/drafts', {body: {message: {raw: raw([`To: ${OWNER}`, `Subject: Re: ${text('G3')}`])}}}));
  refuses(guard, at(GMAIL, 'POST', '/drafts', {body: {message: {raw: raw([`To: ${OWNER}`, 'Subject: Re: Plans'])}}}), 'text');
  guard.end();
});

test('the guard: a run id is 8 base32 characters; its key, folder and app are checked; only one test runs at a time', t => {
  assert.match(newRunId(), /^[A-Z2-7]{8}$/);
  assert.notEqual(newRunId(), newRunId());
  const folder = folderOf(t);
  assert.throws(() => createGuard({appId: 'google-calendar', runId: 'abc', folder, key: KEY}), /run id/);
  assert.throws(() => createGuard({appId: 'google-calendar', runId: RUN, folder, key: randomBytes(8)}), /key/);
  assert.throws(() => createGuard({appId: 'google-calendar', runId: RUN, folder: 'relative/folder', key: KEY}), /absolute/);
  const guard = createGuard({appId: 'google-calendar', runId: RUN, folder, key: KEY});
  guard.begin('C1');
  assert.throws(() => guard.begin('C2'), /test/);
  guard.end();
  assert.throws(() => guard.beginOneTimeAsk(PERMANENT_DELETE), /test/);
  assert.throws(() => guard.setOwner({...OWNER_FACTS, timeZone: 'Mars/Olympus'}), /time zone/);
  assert.throws(() => guard.setOwner({...OWNER_FACTS, runDate: '2026-02-30'}), /date/);
  assert.equal(statSync(path.join(folder, 'live-certify')).mode & 0o777, 0o700);
});

// ---- F10.19 part 2: Notion's rules (docs/F10.19-BUILD-MAP.md section 2, the live guard) ----------------------------------------------
const NOTION = 'https://api.notion.com/v1';
const PAGE_A = '1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a', PAGE_B = '2b2b2b2b-2b2b-4b2b-8b2b-2b2b2b2b2b2b', SOURCE = '3c3c3c3c-3c3c-4c3c-8c3c-3c3c3c3c3c3c';
const ROW_1 = '4d4d4d4d-4d4d-4d4d-8d4d-4d4d4d4d4d4d', DATABASE = '5e5e5e5e-5e5e-4e5e-8e5e-5e5e5e5e5e5e', OTHER = '6f6f6f6f-6f6f-4f6f-8f6f-6f6f6f6f6f6f';
const MADE = '7a7a7a7a-7a7a-4a7a-8a7a-7a7a7a7a7a7a', COMMENT = '8b8b8b8b-8b8b-4b8b-8b8b-8b8b8b8b8b8b', DISCUSSION = '9c9c9c9c-9c9c-4c9c-8c9c-9c9c9c9c9c9c';
// Muse may record an id as Notion's links show it, without hyphens: the guard reads both forms as one id.
const NOTION_FACTS = {email: OWNER, timeZone: 'UTC', runDate: '2026-10-24',
  recorded: {pageA: PAGE_A.replace(/-/g, ''), pageB: PAGE_B, database: DATABASE, dataSource: SOURCE.replace(/-/g, ''), row1: ROW_1, ownerName: 'Avery Owner'}};
const notion = (method, route, options) => at(NOTION, method, route, options);
const pieces = (...parts) => parts.map(content => ({text: {content}}));
const titled = (test, words) => ({title: {title: pieces(text(test, words))}});
/** A Notion guard with the owner set, a page N1 made under A, and N9's comment on A, each through the guard itself. */
async function notionRun(t) {
  const made = guardOf(t, {appId: 'notion'}), {guard} = made;
  guard.setOwner(NOTION_FACTS);
  const {inner, calls} = provider([{status: 200, data: {object: 'page', id: MADE}}, {status: 200, data: {object: 'comment', id: COMMENT, discussion_id: DISCUSSION}}]);
  const send = guard.wrap(inner);
  guard.begin('N1');
  await send(notion('POST', '/pages', {body: {parent: {page_id: PAGE_A}, properties: titled('N1', 'page'), markdown: text('N1', 'body')}}));
  guard.end();
  guard.begin('N9');
  await send(notion('POST', '/comments', {body: {parent: {page_id: PAGE_A}, rich_text: pieces(text('N9', 'comment'))}}));
  guard.end();
  assert.deepEqual(guard.created().map(item => [item.id, item.kind, item.test]), [[MADE, 'page', 'N1'], [COMMENT, 'comment', 'N9'], [DISCUSSION, 'discussion', 'N9']]);
  return {...made, send, calls};
}

test('guard N1: Notion reads pass; a page is made only under A, B or the recorded data source, and changed only on A, B, row 1 or a page the run made', async t => {
  const {guard} = await notionRun(t);
  guard.begin('N4');
  for (const request of [notion('GET', `/pages/${OTHER}`), notion('GET', `/pages/${OTHER}/markdown`), notion('GET', '/users', {q: {page_size: '100'}}), notion('POST', '/search', {body: {page_size: 100}}),
    notion('POST', `/data_sources/${SOURCE}/query`, {body: {page_size: 25}}), notion('GET', `/comments`, {q: {block_id: PAGE_A}})]) assert.equal(passes(guard, request).write, false);
  // Making a page: under A or B (any id form), or a row of the recorded data source.
  passes(guard, notion('POST', '/pages', {body: {parent: {page_id: PAGE_A.toUpperCase()}, properties: titled('N4', 'page')}}));
  passes(guard, notion('POST', '/pages', {body: {parent: {type: 'page_id', page_id: PAGE_B.replace(/-/g, '')}, properties: titled('N4', 'page'), markdown: text('N4', 'text')}}));
  passes(guard, notion('POST', '/pages', {body: {parent: {type: 'data_source_id', data_source_id: SOURCE}, properties: {title: {title: pieces(text('N4', 'row'))}, s: {select: {name: 'Open'}}, c: {number: 2}}}}));
  refuses(guard, notion('POST', '/pages', {body: {parent: {page_id: OTHER}, properties: titled('N4', 'page')}}), 'notion_area', 'under a page outside the test area');
  refuses(guard, notion('POST', '/pages', {body: {parent: {page_id: MADE}, properties: titled('N4', 'page')}}), 'notion_area', 'under a page the run made');
  refuses(guard, notion('POST', '/pages', {body: {parent: {data_source_id: OTHER}, properties: titled('N4', 'row')}}), 'notion_area', 'in another data source');
  refuses(guard, notion('POST', '/pages', {body: {parent: {database_id: DATABASE}, properties: titled('N4', 'row')}}), 'body', 'a database parent');
  // Changing a page: A, B, row 1 or the run's page; values a test writes, never people, files or relations, never in_trash true or archived.
  for (const page of [PAGE_A, PAGE_B, ROW_1.replace(/-/g, ''), MADE]) passes(guard, notion('PATCH', `/pages/${page}`, {body: {properties: titled('N4', 'renamed')}}), page);
  passes(guard, notion('PATCH', `/pages/${ROW_1}`, {body: {properties: {c: {number: 7}, s: {select: {name: 'Done'}}, tags: {multi_select: [{name: 'red'}]}, d: {date: {start: '2026-11-02'}}}}}));
  passes(guard, notion('PATCH', `/pages/${MADE}`, {body: {in_trash: false}}), 'Restore');
  refuses(guard, notion('PATCH', `/pages/${OTHER}`, {body: {properties: titled('N4', 'renamed')}}), 'notion_area', 'a page outside the test area');
  refuses(guard, notion('PATCH', `/pages/${DATABASE}`, {body: {properties: titled('N4', 'renamed')}}), 'notion_area', 'the database itself');
  refuses(guard, notion('PATCH', `/pages/${MADE}`, {body: {in_trash: true}}), 'body', 'in_trash true');
  for (const body of [{archived: false}, {properties: titled('N4', 'x'), is_locked: true}, {}, {properties: {o: {people: [{object: 'user', id: OTHER}]}}}, {properties: {r: {relation: [{id: OTHER}]}}},
    {properties: {f: {files: []}}}, {properties: {title: {title: [{type: 'mention', mention: {user: {id: OTHER}}}]}}}, {properties: {title: {title: [{text: {content: text('N4'), link: {url: 'https://elsewhere.example'}}}]}}}]) {
    refuses(guard, notion('PATCH', `/pages/${MADE}`, {body}), 'body', JSON.stringify(body));
  }
  // Every title and text starts with this test's marker, whole pieces joined.
  refuses(guard, notion('PATCH', `/pages/${MADE}`, {body: {properties: {title: {title: pieces('Renamed')}}}}), 'text', 'no marker');
  refuses(guard, notion('PATCH', `/pages/${MADE}`, {body: {properties: titled('N1', 'renamed')}}), 'text', 'another test\'s marker');
  passes(guard, notion('PATCH', `/pages/${MADE}`, {body: {properties: {title: {title: pieces('[SYNTHETIC] Fabric N4 ', `${RUN} long`)}}}}), 'pieces joined');
  refuses(guard, notion('POST', '/pages', {body: {parent: {page_id: PAGE_A}, properties: titled('N4', 'page'), markdown: 'Plain text'}}), 'text', 'markdown without the marker');
  refuses(guard, notion('POST', '/pages', {body: {parent: {page_id: PAGE_A}, properties: titled('N4', 'page'), markdown: `${text('N4')} <mention-user url="user://${OTHER}"/>`}}), 'body', 'a tag in markdown');
});

test('guard N2: Notion markdown takes insert or one find and replace, never replace_content or a deleting flag; moves and trash touch only the run\'s pages; comments stay on A or the run\'s discussions', async t => {
  const {guard} = await notionRun(t);
  guard.begin('N3');
  const markdown = (page, body) => notion('PATCH', `/pages/${page}/markdown`, {body});
  passes(guard, markdown(MADE, {type: 'insert_content', insert_content: {content: text('N3', 'line')}}));
  passes(guard, markdown(PAGE_B, {type: 'update_content', update_content: {content_updates: [{old_str: 'anything', new_str: text('N3', 'edited')}]}}));
  passes(guard, markdown(MADE, {type: 'update_content', update_content: {content_updates: [{old_str: text('N2', 'marker'), new_str: ''}]}}), 'an empty replacement removes a marker');
  refuses(guard, markdown(OTHER, {type: 'insert_content', insert_content: {content: text('N3', 'line')}}), 'notion_area');
  refuses(guard, markdown(MADE, {type: 'replace_content', replace_content: {new_str: text('N3', 'all')}}), 'body', 'replace_content');
  refuses(guard, markdown(MADE, {type: 'update_content', update_content: {content_updates: [{old_str: 'x', new_str: text('N3')}], allow_deleting_content: true}}), 'body', 'allow_deleting_content');
  refuses(guard, markdown(MADE, {type: 'update_content', update_content: {content_updates: [{old_str: 'x', new_str: text('N3'), replace_all_matches: true}]}}), 'body', 'replace_all_matches');
  refuses(guard, markdown(MADE, {type: 'update_content', update_content: {content_updates: [{old_str: 'x', new_str: text('N3')}, {old_str: 'y', new_str: text('N3')}]}}), 'body', 'two edits');
  refuses(guard, markdown(MADE, {type: 'update_content', update_content: {content_updates: [{old_str: 'x', new_str: 'Plain'}]}}), 'text', 'a replacement without the marker');
  refuses(guard, markdown(MADE, {type: 'insert_content', insert_content: {content: text('N3'), position: 'start'}}), 'body', 'an unknown member');
  // Moves: only the run's page, only under A or B.
  passes(guard, notion('POST', `/pages/${MADE}/move`, {body: {parent: {type: 'page_id', page_id: PAGE_B}}}));
  refuses(guard, notion('POST', `/pages/${PAGE_A}/move`, {body: {parent: {type: 'page_id', page_id: PAGE_B}}}), 'notion_area', 'moving A');
  refuses(guard, notion('POST', `/pages/${MADE}/move`, {body: {parent: {type: 'page_id', page_id: OTHER}}}), 'notion_area', 'out of the test area');
  refuses(guard, notion('POST', `/pages/${MADE}/move`, {body: {parent: {type: 'data_source_id', data_source_id: SOURCE}}}), 'body', 'into a data source');
  // Trash: only a page the run made.
  passes(guard, notion('DELETE', `/blocks/${MADE.replace(/-/g, '')}`));
  for (const block of [PAGE_A, ROW_1, OTHER]) refuses(guard, notion('DELETE', `/blocks/${block}`), 'notion_area', block);
  // Comments: on A, or in a discussion the run made; text pieces only, with the marker; never a display name.
  passes(guard, notion('POST', '/comments', {body: {parent: {page_id: PAGE_A}, rich_text: pieces(text('N3', 'comment'))}}));
  passes(guard, notion('POST', '/comments', {body: {discussion_id: DISCUSSION, rich_text: pieces(text('N3', 'reply'))}}));
  refuses(guard, notion('POST', '/comments', {body: {parent: {page_id: PAGE_B}, rich_text: pieces(text('N3'))}}), 'notion_area', 'a comment on B');
  refuses(guard, notion('POST', '/comments', {body: {discussion_id: OTHER, rich_text: pieces(text('N3'))}}), 'notion_area', 'someone else\'s discussion');
  refuses(guard, notion('POST', '/comments', {body: {parent: {page_id: PAGE_A}, discussion_id: DISCUSSION, rich_text: pieces(text('N3'))}}), 'body', 'both');
  refuses(guard, notion('POST', '/comments', {body: {parent: {page_id: PAGE_A}, rich_text: pieces(text('N3')), display_name: {type: 'custom', custom: {name: 'Sami'}}}}), 'body', 'display_name');
  refuses(guard, notion('POST', '/comments', {body: {parent: {page_id: PAGE_A}, rich_text: pieces('Hello')}}), 'text', 'no marker');
  refuses(guard, notion('PATCH', `/comments/${COMMENT}`, {body: {rich_text: pieces(text('N3'))}}), 'not_allowlisted', 'editing a comment');
});

test('guard N3: a comment is deleted only during the one-time Ask on "Permanently delete comments and views", and only one the run made', async t => {
  const {guard, send, calls} = await notionRun(t);
  guard.begin('N11');
  refuses(guard, notion('DELETE', `/comments/${COMMENT}`), 'comment_delete', 'outside the one-time Ask');
  guard.beginOneTimeAsk(NOTION_PERMANENT_DELETE);
  passes(guard, notion('DELETE', `/comments/${COMMENT}`));
  refuses(guard, notion('DELETE', `/comments/${OTHER}`), 'comment_delete', 'a comment the run did not make');
  refuses(guard, notion('DELETE', `/views/${OTHER}`), 'not_allowlisted', 'a view');
  await send(notion('DELETE', `/comments/${COMMENT}`));
  guard.endOneTimeAsk();
  refuses(guard, notion('DELETE', `/comments/${COMMENT}`), 'comment_delete', 'after the one-time Ask');
  guard.beginOneTimeAsk(PERMANENT_DELETE);
  refuses(guard, notion('DELETE', `/comments/${COMMENT}`), 'comment_delete', 'Calendar\'s row is not Notion\'s');
  assert.equal(calls.filter(call => call.method === 'DELETE').length, 1);
  assert.equal(NOTION_PERMANENT_DELETE, 'notion.permanent.delete');
  assert.deepEqual(Object.keys(GUARD_WORDS).filter(rule => ['notion_area', 'comment_delete'].includes(rule)), ['notion_area', 'comment_delete']);
  for (const rule of ['notion_area', 'comment_delete']) assert.match(GUARD_WORDS[rule], /Nothing was sent\.$/);
});

test('guard N4: Notion\'s token introspection passes as sign-in, inside a test or not, and is never traced; Notion\'s list pairs each write with its path', async t => {
  const {guard, send, calls} = await notionRun(t);
  const introspect = {url: 'https://api.notion.com/v1/oauth/introspect', method: 'POST', headers: {}, body: JSON.stringify({token: 'ntn_x'})};
  assert.deepEqual([guard.check(introspect).allowed, guard.check(introspect).kind], [true, 'signin']);
  await send(introspect);
  guard.begin('N0');
  assert.equal(guard.check(introspect).kind, 'signin');
  await send(introspect);
  guard.end();
  assert.deepEqual([guard.trace('N0'), calls.filter(call => call.url.endsWith('/oauth/introspect')).length], [[], 2]);
  assert.deepEqual(guard.counts().writes, 2, 'only N1\'s page and N9\'s comment count');
  refuses(guard, {url: 'https://api.notion.com/v1/oauth/revoke', method: 'POST', headers: {}, body: '{}'}, 'revocation');
  assert.deepEqual(RULES.notion.allowlist.filter(pair => pair.method !== 'GET').map(pair => `${pair.method} ${pair.path}`).sort(),
    ['DELETE blocks/:block', 'DELETE comments/:comment', 'PATCH pages/:page', 'PATCH pages/:page/markdown', 'POST comments', 'POST data_sources/:source/query', 'POST pages', 'POST pages/:page/move', 'POST search']);
});

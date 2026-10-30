import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {GitHubSimulator, ORIGIN, FIVE, RESTRICTION} from './fixtures/provider-simulators/github.mjs';

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1 and section 3): the GitHub simulator GitHub's actions run against in step 17. It must
// keep the network seam's contract (lib/network.mjs) and GitHub's documented REST behaviour, as its own header comment names it. It is
// written from that comment and from GitHub's REST reference, never from GitHub's action file, rows or sign-in, so an action bug and a
// simulator bug cannot cancel out. Nothing here calls GitHub.
const TOKEN = 'gho_simulatortoken0000000000000000000000', AUTH = {Authorization: `Bearer ${TOKEN}`};
const OWNER = {login: 'octo-a', id: 101};
const SANDBOX = 'octo-a/fabric-sandbox', ORG_REPO = 'octo-org/platform';
const ALL_HEADERS = ['content-type', 'link', 'x-oauth-scopes', 'x-accepted-oauth-scopes', 'retry-after'];
const sim = (options = {}) => new GitHubSimulator({token: TOKEN, owner: OWNER, scopes: [...FIVE], clock: () => Date.parse('2026-10-23T13:00:00.000Z'), ...options});
/** One request through the seam, with the account's token unless `headers` says otherwise. */
const send = (simulator, method, path, {body, headers = AUTH, query, responseHeaders = ALL_HEADERS, ...more} = {}) => {
  const url = new URL(`${ORIGIN}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) for (const item of [value].flat()) url.searchParams.append(name, String(item));
  return simulator.request({url: url.href, method, headers: {Accept: 'application/vnd.github+json', ...headers, ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
    ...(body === undefined ? {} : {body: JSON.stringify(body)}), allowedOrigins: [ORIGIN], responseHeaders, ...more});
};
const b64 = text => Buffer.from(text, 'utf8').toString('base64');
const fromContent = content => Buffer.from(content.replace(/\n/g, ''), 'base64').toString('utf8');
const repoPath = (repo, rest) => `/repos/${repo}${rest}`;
const getFile = (simulator, path, {repo = SANDBOX, ref} = {}) => send(simulator, 'GET', repoPath(repo, `/contents/${path}`), {query: ref === undefined ? {} : {ref}});
const putFile = (simulator, path, body, {repo = SANDBOX} = {}) => send(simulator, 'PUT', repoPath(repo, `/contents/${path}`), {body: {message: 'Change', ...body}});
const branchFrom = async (simulator, name, from = 'main', repo = SANDBOX) => {
  const base = await send(simulator, 'GET', repoPath(repo, `/git/ref/heads/${from}`));
  return send(simulator, 'POST', repoPath(repo, '/git/refs'), {body: {ref: `refs/heads/${name}`, sha: base.data.object.sha}});
};
/** A branch with one new file, and a pull request from it into main. */
async function openPull(simulator, {name = 'feature/one', draft = false} = {}) {
  await branchFrom(simulator, name);
  await putFile(simulator, `notes/${name.replace(/\//g, '-')}.md`, {content: b64('New notes\n'), branch: name});
  return send(simulator, 'POST', repoPath(SANDBOX, '/pulls'), {body: {title: 'Add notes', head: name, base: 'main', draft}});
}

test('the seam: only the headers asked for come back, an answer over maxBytes throws sent true, and requests refused before sending are never recorded', async () => {
  const simulator = sim();
  const user = await simulator.request({url: `${ORIGIN}/user`, method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]});
  assert.deepEqual(Object.keys(user.headers).sort(), ['content-type'], 'the seam\'s default list: content-type, etag, retry-after, x-ratelimit-remaining');
  assert.deepEqual([user.status, user.data.login, user.data.id], [200, 'octo-a', 101]);
  assert.deepEqual(Object.keys((await send(simulator, 'GET', '/user', {responseHeaders: ['x-oauth-scopes']})).headers), ['x-oauth-scopes']);
  await assert.rejects(send(simulator, 'GET', '/user/repos', {maxBytes: 64}), error => error.sent === true && /size limit/.test(error.message));
  const before = simulator.calls.length;
  for (const [label, request] of [['an origin outside the grant', {url: `${ORIGIN}/user`, method: 'GET', headers: AUTH, allowedOrigins: ['https://uploads.github.com']}],
    ['plain http', {url: 'http://api.github.com/user', method: 'GET', headers: AUTH, allowedOrigins: [ORIGIN]}],
    ['an unsafe header', {url: `${ORIGIN}/user`, method: 'GET', headers: {...AUTH, Host: 'x'}, allowedOrigins: [ORIGIN]}],
    ['a body that is not serialized', {url: `${ORIGIN}/repos/${SANDBOX}/issues`, method: 'POST', headers: AUTH, body: {title: 'x'}, allowedOrigins: [ORIGIN]}],
    ['a body over 1 MiB', {url: `${ORIGIN}/repos/${SANDBOX}/issues`, method: 'POST', headers: AUTH, body: JSON.stringify({title: 'x'.repeat(1024 * 1024)}), allowedOrigins: [ORIGIN]}],
    ['an origin the simulator does not serve', {url: 'https://uploads.github.com/x', method: 'GET', headers: AUTH, allowedOrigins: ['https://uploads.github.com']}]]) {
    await assert.rejects(simulator.request(request), error => error.sent === false, label);
  }
  assert.equal(simulator.calls.length, before, 'refused before sending: never recorded');
  const unknown = await send(simulator, 'GET', '/nothing/here');
  assert.deepEqual([unknown.status, unknown.data.message, simulator.calls.at(-1).route], [404, 'Not Found', null]);
});

test('401 Bad credentials without the token, in GitHub\'s error shape, changing nothing; calls are recorded without Authorization', async () => {
  const simulator = sim();
  for (const headers of [{}, {Authorization: 'Bearer wrong'}, {Authorization: `token ${TOKEN}x`}]) {
    const answer = await send(simulator, 'POST', repoPath(SANDBOX, '/issues'), {body: {title: 'Nope'}, headers});
    assert.equal(answer.status, 401);
    assert.deepEqual(answer.data, {message: 'Bad credentials', documentation_url: 'https://docs.github.com/rest'});
    assert.equal(answer.headers['x-oauth-scopes'], undefined, 'no scopes header without a token');
  }
  assert.equal(simulator.state().repos[SANDBOX].issues.length, 3, 'nothing was made');
  assert.equal((await send(simulator, 'GET', '/user', {headers: {Authorization: `token ${TOKEN}`}})).status, 200, 'GitHub takes the token scheme too');
  assert.equal(JSON.stringify(simulator.calls).includes(TOKEN), false, 'the token is never recorded');
  assert.ok(simulator.calls.every(call => !Object.keys(call.headers).some(name => /authorization/i.test(name))));
});

test('X-OAuth-Scopes lists the token\'s scopes on every authenticated answer and follows grant(); a missing scope answers 404 on repository data and 403 elsewhere, with X-Accepted-OAuth-Scopes', async () => {
  const simulator = sim();
  for (const answer of [await send(simulator, 'GET', '/user'), await send(simulator, 'GET', repoPath(SANDBOX, '/issues/99')), await send(simulator, 'POST', repoPath(SANDBOX, '/issues'), {body: {}})]) {
    assert.equal(answer.headers['x-oauth-scopes'], 'read:user, repo, read:org, gist, workflow');
  }
  simulator.grant(['read:user', 'repo']);
  assert.equal((await send(simulator, 'GET', '/user')).headers['x-oauth-scopes'], 'read:user, repo');
  const orgs = await send(simulator, 'GET', '/user/orgs');
  assert.deepEqual([orgs.status, orgs.headers['x-accepted-oauth-scopes'], orgs.headers['x-oauth-scopes']], [403, 'admin:org, read:org, write:org', 'read:user, repo']);
  const narrow = sim({scopes: ['read:user']});
  for (const [method, path, body] of [['GET', repoPath(SANDBOX, '')], ['GET', repoPath(SANDBOX, '/issues/1')], ['GET', repoPath(SANDBOX, '/contents/README.md')], ['POST', repoPath(SANDBOX, '/issues'), {title: 'x'}]]) {
    const answer = await send(narrow, method, path, {body});
    assert.deepEqual([answer.status, answer.data.message, answer.headers['x-accepted-oauth-scopes']], [404, 'Not Found', 'repo'], `${method} ${path}: GitHub hides a private repository the token cannot see`);
  }
  assert.equal(narrow.state().repos[SANDBOX].issues.length, 3);
  assert.deepEqual((await send(narrow, 'GET', '/user/repos')).data.map(repo => repo.full_name), ['octo-a/public-notes'], 'without repo, only public repositories are listed');
  assert.equal((await send(narrow, 'GET', repoPath('octo-a/public-notes', '/contents/README.md'))).status, 200, 'a public repository reads with no scope');
  assert.deepEqual((await send(narrow, 'GET', '/gists')).data.map(gist => gist.public), [true], 'secret gists need gist');
  assert.deepEqual((await send(sim(), 'GET', '/gists')).data.map(gist => gist.public), [true, false]);
  // admin:org covers read:org, as GitHub documents.
  assert.equal((await send(sim({scopes: ['admin:org']}), 'GET', '/user/orgs')).status, 200);
});

test('repositories: /user/repos pages with per_page, page and a Link header, and each item carries temp_clone_token; GET a repository', async () => {
  const simulator = sim();
  const first = await send(simulator, 'GET', '/user/repos', {query: {per_page: 2, sort: 'updated'}});
  assert.deepEqual(first.data.map(repo => repo.full_name), ['octo-a/fabric-sandbox', 'octo-org/platform']);
  assert.equal(first.headers.link, '<https://api.github.com/user/repos?per_page=2&sort=updated&page=2>; rel="next", <https://api.github.com/user/repos?per_page=2&sort=updated&page=2>; rel="last"');
  assert.ok(first.data.every(repo => typeof repo.temp_clone_token === 'string' && repo.temp_clone_token.length > 0));
  assert.deepEqual(first.data.map(repo => [repo.private, repo.default_branch, repo.archived, repo.permissions.push]), [[true, 'main', false, true], [true, 'main', false, true]]);
  const second = await send(simulator, 'GET', '/user/repos', {query: {per_page: 2, page: 2, sort: 'updated'}});
  assert.deepEqual([second.data.map(repo => repo.full_name), second.headers.link], [['octo-a/public-notes'], '<https://api.github.com/user/repos?per_page=2&page=1&sort=updated>; rel="prev", <https://api.github.com/user/repos?per_page=2&page=1&sort=updated>; rel="first"']);
  assert.equal((await send(simulator, 'GET', '/user/repos', {query: {per_page: 101}})).status, 422);
  const one = await send(simulator, 'GET', repoPath(SANDBOX, ''));
  assert.deepEqual([one.data.full_name, one.data.owner.login, typeof one.data.temp_clone_token], [SANDBOX, 'octo-a', 'string']);
  assert.equal((await send(simulator, 'GET', repoPath('octo-a/missing', ''))).status, 404);
});

test('contents: a file comes base64 with a line feed every 60 characters, a folder is a list, a file over 1 MB has encoding none, and a missing path or ref answers 404', async () => {
  const simulator = sim(), text = 'Fabric line\n'.repeat(40);
  const made = await putFile(simulator, 'docs/read me.md', {content: b64(text)});
  assert.equal(made.status, 201);
  const file = await getFile(simulator, 'docs/read%20me.md');
  assert.deepEqual([file.status, file.data.type, file.data.encoding, file.data.path, file.data.size, file.data.sha], [200, 'file', 'base64', 'docs/read me.md', Buffer.byteLength(text), made.data.content.sha]);
  const lines = file.data.content.split('\n');
  assert.ok(lines.length > 3 && lines.slice(0, -2).every(line => line.length === 60) && lines.at(-2).length <= 60, 'wrapped at 60, as GitHub sends it');
  assert.equal(lines.at(-1), '', 'and ending in a line feed');
  assert.equal(fromContent(file.data.content), text);
  assert.match(file.data.sha, /^[0-9a-f]{40}$/);
  const folder = await getFile(simulator, 'docs');
  assert.ok(Array.isArray(folder.data));
  assert.deepEqual(folder.data.map(entry => [entry.type, entry.path]), [['file', 'docs/read me.md']]);
  const root = await send(simulator, 'GET', repoPath(SANDBOX, '/contents'));
  assert.deepEqual(root.data.map(entry => `${entry.type} ${entry.path}`), ['dir .github', 'file README.md', 'dir docs']);
  simulator.seedFile(SANDBOX, 'main', 'big.bin', Buffer.alloc(1024 * 1024 + 1, 0x61));
  const big = await getFile(simulator, 'big.bin');
  assert.deepEqual([big.status, big.data.type, big.data.encoding, big.data.content, big.data.size], [200, 'file', 'none', '', 1024 * 1024 + 1]);
  assert.equal((await getFile(simulator, 'nope.md')).status, 404);
  assert.equal((await getFile(simulator, 'README.md', {ref: 'no-such-branch'})).status, 404);
  assert.equal(fromContent((await getFile(simulator, 'README.md', {ref: simulator.head(SANDBOX, 'main')})).data.content), '# Fabric sandbox\n', 'a commit sha is a ref too');
});

test('contents PUT: a stale sha answers 409 and changes nothing, no sha on an existing file answers 422, a sha on a new file answers 409; 201 creates, 200 updates', async () => {
  const simulator = sim();
  const current = await getFile(simulator, 'README.md'), head = simulator.head(SANDBOX, 'main');
  const stale = await putFile(simulator, 'README.md', {content: b64('Mine\n'), sha: '0'.repeat(40)});
  assert.deepEqual([stale.status, stale.data.message], [409, `README.md does not match ${'0'.repeat(40)}`]);
  const missing = await putFile(simulator, 'README.md', {content: b64('Mine\n')});
  assert.deepEqual([missing.status, missing.data.message], [422, 'Invalid request.\n\n"sha" wasn\'t supplied.']);
  assert.equal((await putFile(simulator, 'brand-new.md', {content: b64('x'), sha: current.data.sha})).status, 409);
  assert.deepEqual([fromContent((await getFile(simulator, 'README.md')).data.content), simulator.head(SANDBOX, 'main')], ['# Fabric sandbox\n', head], 'nothing changed');
  const updated = await putFile(simulator, 'README.md', {content: b64('# Changed\n'), sha: current.data.sha});
  assert.deepEqual([updated.status, updated.data.content.path, updated.data.commit.parents.map(parent => parent.sha)], [200, 'README.md', [head]]);
  assert.notEqual(updated.data.content.sha, current.data.sha);
  assert.equal(simulator.head(SANDBOX, 'main'), updated.data.commit.sha, 'the branch moved to the new commit');
  assert.equal((await getFile(simulator, 'README.md')).data.sha, updated.data.content.sha);
  for (const [body, label] of [[{content: 'not base64!'}, 'content that is not base64'], [{content: b64('x'), message: undefined}, 'no message'], [{content: b64('x'), branch: 'nowhere'}, 'a branch that does not exist']]) {
    assert.ok([404, 422].includes((await putFile(simulator, 'other.md', body)).status), label);
  }
  // A dot segment never reaches GitHub (a URL resolves it before sending), so an empty one stands for a malformed path.
  assert.equal((await putFile(simulator, 'a//b.md', {content: b64('x')})).status, 422, 'an empty path component');
});

test('a path under .github/workflows/ is refused without the workflow scope and written with it', async () => {
  const refused = sim({scopes: ['read:user', 'repo']}), head = refused.head(SANDBOX, 'main');
  const answer = await putFile(refused, '.github/workflows/new.yml', {content: b64('on: workflow_dispatch\n')});
  assert.equal(answer.status, 403);
  assert.equal(answer.data.message, 'refusing to allow an OAuth App to create or update workflow `.github/workflows/new.yml` without `workflow` scope');
  assert.equal(answer.headers['x-accepted-oauth-scopes'], 'workflow');
  assert.deepEqual([(await getFile(refused, '.github/workflows/new.yml')).status, refused.head(SANDBOX, 'main')], [404, head]);
  assert.equal((await putFile(refused, '.github/other/new.yml', {content: b64('x')})).status, 201, 'another folder needs no workflow scope');
  assert.equal((await putFile(sim(), '.github/workflows/new.yml', {content: b64('on: workflow_dispatch\n')})).status, 201);
});

test('refs: a branch with a slash is created and read through the {+ref} path; a ref that exists answers 422; DELETE removes it', async () => {
  const simulator = sim(), main = await send(simulator, 'GET', repoPath(SANDBOX, '/git/ref/heads/main'));
  assert.deepEqual([main.status, main.data.ref, main.data.object.type, main.data.object.sha], [200, 'refs/heads/main', 'commit', simulator.head(SANDBOX, 'main')]);
  const made = await branchFrom(simulator, 'fabric/test-run1');
  assert.deepEqual([made.status, made.data.ref, made.data.object.sha], [201, 'refs/heads/fabric/test-run1', main.data.object.sha]);
  const read = await send(simulator, 'GET', repoPath(SANDBOX, '/git/ref/heads/fabric/test-run1'));
  assert.deepEqual([read.status, read.data.ref, read.data.object.sha], [200, 'refs/heads/fabric/test-run1', main.data.object.sha]);
  assert.equal(simulator.reads().at(-1).route, 'GET /repos/{owner}/{repo}/git/ref/{+ref}');
  const again = await branchFrom(simulator, 'fabric/test-run1');
  assert.deepEqual([again.status, again.data.message], [422, 'Reference already exists']);
  assert.equal((await send(simulator, 'POST', repoPath(SANDBOX, '/git/refs'), {body: {ref: 'refs/heads/x', sha: 'f'.repeat(40)}})).status, 422, 'an object that does not exist');
  assert.equal((await send(simulator, 'POST', repoPath(SANDBOX, '/git/refs'), {body: {ref: 'heads/x', sha: main.data.object.sha}})).status, 422, 'a ref outside refs/');
  const gone = await send(simulator, 'DELETE', repoPath(SANDBOX, '/git/refs/heads/fabric/test-run1'));
  assert.equal(gone.status, 204);
  assert.equal((await send(simulator, 'GET', repoPath(SANDBOX, '/git/ref/heads/fabric/test-run1'))).status, 404);
  assert.equal((await send(simulator, 'DELETE', repoPath(SANDBOX, '/git/refs/heads/fabric/test-run1'))).status, 422);
});

test('pull requests: open needs a head with something new; mergeable is null on the first read after a change, then computed; the issue of a pull carries pull_request', async () => {
  const simulator = sim();
  await branchFrom(simulator, 'empty');
  const nothing = await send(simulator, 'POST', repoPath(SANDBOX, '/pulls'), {body: {title: 'x', head: 'empty', base: 'main'}});
  assert.deepEqual([nothing.status, nothing.data.errors?.[0]?.message], [422, 'No commits between main and empty']);
  assert.equal((await send(simulator, 'POST', repoPath(SANDBOX, '/pulls'), {body: {title: 'x', head: 'missing', base: 'main'}})).status, 422);
  const opened = await openPull(simulator, {draft: true});
  assert.deepEqual([opened.status, opened.data.number, opened.data.draft, opened.data.state, opened.data.merged, opened.data.head.ref, opened.data.base.ref], [201, 4, true, 'open', false, 'feature/one', 'main'],
    'numbers are shared with issues');
  const pull = number => send(simulator, 'GET', repoPath(SANDBOX, `/pulls/${number}`));
  assert.deepEqual([(await pull(4)).data.mergeable, (await pull(4)).data.mergeable], [null, true]);
  simulator.push(SANDBOX, 'feature/one');
  const after = await pull(4);
  assert.deepEqual([after.data.mergeable, after.data.mergeable_state, after.data.head.sha], [null, 'unknown', simulator.head(SANDBOX, 'feature/one')]);
  assert.equal((await pull(4)).data.mergeable, true);
  const issue = await send(simulator, 'GET', repoPath(SANDBOX, '/issues/4'));
  assert.ok(issue.data.pull_request && issue.data.title === 'Add notes');
  assert.equal((await send(simulator, 'GET', repoPath(SANDBOX, '/issues/1'))).data.pull_request, undefined);
  const files = await send(simulator, 'GET', repoPath(SANDBOX, '/pulls/4/files'), {query: {per_page: 50}});
  assert.deepEqual(files.data.map(file => [file.filename, file.status]), [['notes/feature-one.md', 'added'], ['pushed.txt', 'added']]);
  assert.match(files.data[0].patch, /^@@ .* @@\n\+New notes$/);
});

test('merge: a sha that is not the head answers 409 and merges nothing; a draft or a merged pull answers 405; the right sha merges and sets merge_commit_sha', async () => {
  const simulator = sim();
  const draft = await openPull(simulator, {name: 'draft-one', draft: true});
  const refused = await send(simulator, 'PUT', repoPath(SANDBOX, `/pulls/${draft.data.number}/merge`), {body: {sha: draft.data.head.sha, merge_method: 'merge'}});
  assert.deepEqual([refused.status, refused.data.message], [405, 'Pull Request is still a draft']);
  const opened = await openPull(simulator, {name: 'feature/two'}), number = opened.data.number, head = opened.data.head.sha, main = simulator.head(SANDBOX, 'main');
  simulator.push(SANDBOX, 'feature/two');
  const stale = await send(simulator, 'PUT', repoPath(SANDBOX, `/pulls/${number}/merge`), {body: {sha: head, merge_method: 'squash'}});
  assert.deepEqual([stale.status, stale.data.message], [409, 'Head branch was modified. Review and try the merge again.']);
  assert.deepEqual([(await send(simulator, 'GET', repoPath(SANDBOX, `/pulls/${number}`))).data.merged, simulator.head(SANDBOX, 'main')], [false, main], 'nothing merged');
  assert.equal((await send(simulator, 'PUT', repoPath(SANDBOX, `/pulls/${number}/merge`), {body: {sha: simulator.head(SANDBOX, 'feature/two'), merge_method: 'fast'}})).status, 422);
  const merged = await send(simulator, 'PUT', repoPath(SANDBOX, `/pulls/${number}/merge`), {body: {sha: simulator.head(SANDBOX, 'feature/two'), merge_method: 'merge', commit_title: 'Merge two'}});
  assert.deepEqual([merged.status, merged.data.merged, merged.data.message], [200, true, 'Pull Request successfully merged']);
  assert.equal(simulator.head(SANDBOX, 'main'), merged.data.sha, 'main moved to the merge commit');
  const read = await send(simulator, 'GET', repoPath(SANDBOX, `/pulls/${number}`));
  assert.deepEqual([read.data.merged, read.data.state, read.data.merge_commit_sha], [true, 'closed', merged.data.sha]);
  assert.equal(fromContent((await getFile(simulator, 'notes/feature-two.md')).data.content), 'New notes\n', 'the head\'s file is on main');
  const twice = await send(simulator, 'PUT', repoPath(SANDBOX, `/pulls/${number}/merge`), {body: {sha: read.data.head.sha}});
  assert.equal(twice.status, 405);
});

test('reviews: no event leaves the review PENDING; COMMENT and REQUEST_CHANGES need a body; approving your own pull answers 422; commit_id is kept as sent', async () => {
  const simulator = sim(), opened = await openPull(simulator), number = opened.data.number, head = opened.data.head.sha;
  const review = body => send(simulator, 'POST', repoPath(SANDBOX, `/pulls/${number}/reviews`), {body});
  const pending = await review({body: 'Later'});
  assert.deepEqual([pending.status, pending.data.state, pending.data.submitted_at], [200, 'PENDING', undefined]);
  for (const event of ['COMMENT', 'REQUEST_CHANGES']) assert.equal((await review({event, commit_id: head})).status, 422, event);
  assert.equal((await review({event: 'APPROVE', commit_id: head})).status, 422, 'your own pull');
  assert.equal((await review({event: 'MAYBE', body: 'x'})).status, 422);
  simulator.push(SANDBOX, 'feature/one');
  const commented = await review({event: 'COMMENT', body: 'Looks fine', commit_id: head});
  assert.deepEqual([commented.status, commented.data.state, commented.data.commit_id, typeof commented.data.submitted_at], [200, 'COMMENTED', head, 'string'], 'pinned to the commit sent, not the new head');
  const read = await send(simulator, 'GET', repoPath(SANDBOX, `/pulls/${number}/reviews/${commented.data.id}`));
  assert.deepEqual([read.data.id, read.data.commit_id, read.data.state, read.data.body], [commented.data.id, head, 'COMMENTED', 'Looks fine']);
  assert.equal((await review({event: 'COMMENT', body: 'x', commit_id: 'f'.repeat(40)})).status, 422, 'a commit that does not exist');
  // Another person's pull can be approved, and commit_id defaults to its head.
  const theirs = await openPull(simulator, {name: 'feature/three'});
  simulator.author(SANDBOX, theirs.data.number, {login: 'octo-c', id: 303});
  const approved = await send(simulator, 'POST', repoPath(SANDBOX, `/pulls/${theirs.data.number}/reviews`), {body: {event: 'APPROVE'}});
  assert.deepEqual([approved.status, approved.data.state, approved.data.commit_id], [200, 'APPROVED', theirs.data.head.sha], 'commit_id defaults to the head');
});

test('issues: create, get, patch with state_reason, comments 50 a page, labels added as a list (an empty list removes every label) and removed one at a time (404 when absent)', async () => {
  const simulator = sim(), path = rest => repoPath(SANDBOX, rest);
  const made = await send(simulator, 'POST', path('/issues'), {body: {title: 'New', labels: ['bug', 'brand-new']}});
  assert.deepEqual([made.status, made.data.number, made.data.body, made.data.state, made.data.labels.map(label => label.name)], [201, 4, null, 'open', ['bug', 'brand-new']]);
  assert.equal((await send(simulator, 'POST', path('/issues'), {body: {body: 'no title'}})).status, 422);
  const closed = await send(simulator, 'PATCH', path('/issues/4'), {body: {state: 'closed', state_reason: 'not_planned'}});
  assert.deepEqual([closed.data.state, closed.data.state_reason, typeof closed.data.closed_at], ['closed', 'not_planned', 'string']);
  assert.equal((await send(simulator, 'PATCH', path('/issues/4'), {body: {state: 'open', state_reason: 'completed'}})).status, 422, 'an open issue cannot be completed');
  const reopened = await send(simulator, 'PATCH', path('/issues/4'), {body: {state: 'open'}});
  assert.deepEqual([reopened.data.state, reopened.data.state_reason, reopened.data.closed_at], ['open', 'reopened', null]);
  const renamed = await send(simulator, 'PATCH', path('/issues/4'), {body: {title: 'Renamed', state_reason: 'not_planned'}});
  assert.deepEqual([renamed.data.title, renamed.data.state, renamed.data.state_reason], ['Renamed', 'open', 'reopened'], 'state_reason is ignored unless the state changes');
  for (let index = 0; index < 51; index++) await send(simulator, 'POST', path('/issues/1/comments'), {body: {body: `Comment ${index}`}});
  const page = await send(simulator, 'GET', path('/issues/1/comments'), {query: {per_page: 50}});
  assert.deepEqual([page.data.length, page.data[0].body, /rel="next"/.test(page.headers.link)], [50, 'Comment 0', true]);
  const comment = await send(simulator, 'GET', path(`/issues/comments/${page.data[0].id}`));
  assert.deepEqual([comment.data.id, comment.data.body, comment.data.user.login], [page.data[0].id, 'Comment 0', 'octo-a']);
  assert.equal((await send(simulator, 'GET', path('/issues/1'))).data.comments, 51);
  assert.equal((await send(simulator, 'POST', path('/issues/1/comments'), {body: {}})).status, 422);
  assert.equal((await send(simulator, 'DELETE', path(`/issues/comments/${page.data[0].id}`))).status, 204);
  assert.equal((await send(simulator, 'GET', path(`/issues/comments/${page.data[0].id}`))).status, 404);
  const added = await send(simulator, 'POST', path('/issues/1/labels'), {body: {labels: ['fabric-test', 'bug']}});
  assert.deepEqual([added.status, added.data.map(label => label.name)], [200, ['fabric-test', 'bug']]);
  const removed = await send(simulator, 'DELETE', path('/issues/1/labels/fabric-test'));
  assert.deepEqual([removed.status, removed.data.map(label => label.name)], [200, ['bug']]);
  const absent = await send(simulator, 'DELETE', path('/issues/1/labels/fabric-test'));
  assert.deepEqual([absent.status, absent.data.message], [404, 'Label does not exist']);
  const emptied = await send(simulator, 'POST', path('/issues/1/labels'), {body: {labels: []}});
  assert.deepEqual([emptied.status, emptied.data, (await send(simulator, 'GET', path('/issues/1'))).data.labels], [200, [], []], 'an empty list removes every label, as GitHub documents');
  assert.equal((await send(simulator, 'GET', path('/issues/999'))).status, 404);
  simulator.deleteIssue(SANDBOX, 3);
  assert.equal((await send(simulator, 'GET', path('/issues/3'))).status, 410);
});

test('search: is:issue or is:pull-request is required, repo:, the @me qualifiers, is:open or is:closed and quoted words are read, anything else answers 422', async () => {
  const simulator = sim();
  await openPull(simulator);
  const search = q => send(simulator, 'GET', '/search/issues', {query: {q, per_page: 25}});
  const missing = await search('repo:octo-a/fabric-sandbox "Issue"');
  assert.deepEqual([missing.status, missing.data.errors[0].message], [422, 'Query must include \'is:issue\' or \'is:pull-request\'']);
  const issues = await search('is:issue repo:octo-a/fabric-sandbox is:open "issue"');
  assert.deepEqual([issues.status, issues.data.total_count, issues.data.incomplete_results, issues.data.items.map(item => item.number)], [200, 3, false, [1, 2, 3]]);
  assert.deepEqual((await search('is:issue repo:octo-a/fabric-sandbox "SYNTHETIC"')).data.items.map(item => item.number), [2]);
  assert.deepEqual((await search('is:pull-request author:@me')).data.items.map(item => [item.number, Boolean(item.pull_request)]), [[4, true]]);
  assert.deepEqual((await search('is:issue is:closed author:@me')).data.items, []);
  for (const q of ['is:issue org:octo-org', 'is:issue repo:octo-a/fabric-sandbox in:title "x"', 'is:issue author:octo-b', 'is:issue "unclosed', 'is:issue is:pull-request author:@me']) {
    assert.equal((await search(q)).status, 422, q);
  }
});

test('workflows: by id or file name with state; a dispatch needs an existing ref and declared string inputs (204); the run is listed only after runLag reads', async () => {
  const simulator = sim(), path = rest => repoPath(SANDBOX, rest);
  const byName = await send(simulator, 'GET', path('/actions/workflows/fabric-synthetic.yml'));
  assert.deepEqual([byName.status, byName.data.path, byName.data.state], [200, '.github/workflows/fabric-synthetic.yml', 'active']);
  assert.equal((await send(simulator, 'GET', path(`/actions/workflows/${byName.data.id}`))).data.name, byName.data.name);
  const dispatch = body => send(simulator, 'POST', path('/actions/workflows/fabric-synthetic.yml/dispatches'), {body});
  assert.equal((await dispatch({ref: 'main', inputs: {nope: 'x'}})).status, 422, 'an input the workflow does not declare');
  assert.equal((await dispatch({ref: 'main', inputs: {greeting: 3}})).status, 422, 'an input that is not a string');
  assert.equal((await dispatch({ref: 'no-such-branch'})).status, 422);
  simulator.runLag(2);
  const sent = await dispatch({ref: 'main', inputs: {greeting: 'hi'}});
  assert.deepEqual([sent.status, sent.data], [204, null]);
  const runs = () => send(simulator, 'GET', path('/actions/workflows/fabric-synthetic.yml/runs'), {query: {event: 'workflow_dispatch', branch: 'main', per_page: 10}});
  assert.equal((await runs()).data.total_count, 0);
  assert.equal((await runs()).data.total_count, 0);
  const listed = await runs();
  assert.deepEqual([listed.data.total_count, listed.data.workflow_runs[0].event, listed.data.workflow_runs[0].head_branch, listed.data.workflow_runs[0].head_sha], [1, 'workflow_dispatch', 'main', simulator.head(SANDBOX, 'main')]);
  assert.equal(simulator.state().repos[SANDBOX].runs[0].inputs.greeting, 'hi');
  simulator.addWorkflow(SANDBOX, {file: 'off.yml', name: 'Off', state: 'disabled_manually'});
  assert.equal((await send(simulator, 'POST', path('/actions/workflows/off.yml/dispatches'), {body: {ref: 'main'}})).status, 422);
  const checks = simulator.addCheckRun(SANDBOX, simulator.head(SANDBOX, 'main'), {name: 'ci', status: 'completed', conclusion: 'success'});
  const listedChecks = await send(simulator, 'GET', path(`/commits/${simulator.head(SANDBOX, 'main')}/check-runs`), {query: {per_page: 50}});
  assert.deepEqual([listedChecks.data.total_count, listedChecks.data.check_runs[0].id, listedChecks.data.check_runs[0].conclusion], [1, checks.id, 'success']);
});

test('workflows: a dispatch with return_run_details answers 200 with the new run, which reads back by its id at once while the list still lags', async () => {
  const simulator = sim(), path = rest => repoPath(SANDBOX, rest);
  const dispatch = body => send(simulator, 'POST', path('/actions/workflows/fabric-synthetic.yml/dispatches'), {body});
  assert.equal((await dispatch({ref: 'main', return_run_details: 'yes'})).status, 422, 'return_run_details is a boolean');
  assert.deepEqual(simulator.state().repos[SANDBOX].runs, [], 'a refused dispatch records no run');
  simulator.runLag(5);
  const sent = await dispatch({ref: 'main', return_run_details: true}), id = sent.data.workflow_run_id;
  assert.deepEqual([sent.status, Object.keys(sent.data).sort(), sent.data.run_url, sent.data.html_url],
    [200, ['html_url', 'run_url', 'workflow_run_id'], `https://api.github.com/repos/${SANDBOX}/actions/runs/${id}`, `https://github.com/${SANDBOX}/actions/runs/${id}`]);
  const run = await send(simulator, 'GET', path(`/actions/runs/${id}`));
  assert.deepEqual([run.status, run.data.id, run.data.event, run.data.head_branch, run.data.head_sha, run.data.html_url, Object.hasOwn(run.data, 'inputs'), Object.hasOwn(run.data, 'hiddenReads')],
    [200, id, 'workflow_dispatch', 'main', simulator.head(SANDBOX, 'main'), sent.data.html_url, false, false]);
  assert.equal((await send(simulator, 'GET', path('/actions/workflows/fabric-synthetic.yml/runs'), {query: {per_page: 10}})).data.total_count, 0, 'the list still lags');
  assert.deepEqual([(await dispatch({ref: 'main', return_run_details: false})).status, (await dispatch({ref: 'main'})).status], [204, 204], 'false or absent answers 204');
  assert.equal((await send(simulator, 'GET', path(`/actions/runs/${id + 1000}`))).status, 404);
});

test('a restricted organization answers 403 with GitHub\'s documented message on its repositories only; organizations and gists read with their scopes', async () => {
  const simulator = sim();
  assert.equal((await send(simulator, 'GET', repoPath(ORG_REPO, '/issues/1'))).status, 404, 'no issue 1 there, but reachable');
  simulator.restrict('octo-org');
  for (const [method, path] of [['GET', repoPath(ORG_REPO, '')], ['GET', repoPath(ORG_REPO, '/contents/README.md')], ['POST', repoPath(ORG_REPO, '/issues')]]) {
    const answer = await send(simulator, method, path, {body: method === 'POST' ? {title: 'x'} : undefined});
    assert.deepEqual([answer.status, answer.data.message, answer.data.documentation_url], [403, RESTRICTION('octo-org'), 'https://docs.github.com/articles/restricting-access-to-your-organization-s-data/'], path);
  }
  assert.match(RESTRICTION('octo-org'), /^Although you appear to have the correct authorization credentials, the `octo-org` organization has enabled OAuth App access restrictions/);
  assert.equal((await send(simulator, 'GET', repoPath(SANDBOX, '/issues/1'))).status, 200, 'the owner\'s own repository is not restricted');
  assert.deepEqual((await send(simulator, 'GET', '/user/orgs')).data.map(org => org.login), ['octo-org']);
});

test('writes() carry the clock time each write arrived; switches fail, drop, swallow, oversize and hold act on the next call to one route', async () => {
  let now = Date.parse('2026-10-23T13:00:00.000Z');
  const simulator = sim({clock: () => now}), route = 'POST /repos/{owner}/{repo}/issues/{issue_number}/comments', comment = text => send(simulator, 'POST', repoPath(SANDBOX, '/issues/1/comments'), {body: {body: text}});
  await comment('one');
  now += 1500;
  await comment('two');
  assert.deepEqual(simulator.writes().map(call => [call.route, call.at]), [[route, Date.parse('2026-10-23T13:00:00.000Z')], [route, Date.parse('2026-10-23T13:00:01.500Z')]]);
  simulator.fail(route, {status: 500, data: {message: 'Server Error'}});
  assert.equal((await comment('three')).status, 500);
  simulator.drop(route);
  await assert.rejects(comment('four'), error => error.sent === true);
  simulator.swallow(route);
  assert.equal((await comment('five')).status, 201);
  assert.deepEqual(simulator.state().repos[SANDBOX].comments.map(item => item.body), ['one', 'two', 'four'], 'fail changes nothing, drop applies, swallow does not');
  simulator.oversize('GET /repos/{owner}/{repo}/issues/{issue_number}', 4096);
  await assert.rejects(send(simulator, 'GET', repoPath(SANDBOX, '/issues/1'), {maxBytes: 2048}), error => error.sent === true);
  const gate = simulator.hold(route), running = comment('six');
  await gate.reached;
  assert.equal(simulator.state().repos[SANDBOX].comments.length, 3, 'held: not applied yet');
  gate.release();
  assert.equal((await running).status, 201);
  assert.ok(simulator.reads().every(call => !call.write) && simulator.writes().every(call => call.write));
});

// F10.17 part 2: a swallowed write that makes new content (a file's blob) answers as applied, from the copy it changed, and the state keeps
// nothing of it; Create or update a file's unverified case needs it (test/actions-github.test.mjs).
test('swallow on a contents PUT answers 201 with the new blob, and the file is not there afterwards', async () => {
  const simulator = sim();
  simulator.swallow('PUT /repos/{owner}/{repo}/contents/{+path}');
  const answer = await putFile(simulator, 'docs/swallowed.md', {content: b64('Gone.\n')});
  assert.deepEqual([answer.status, answer.data.content.path, typeof answer.data.content.sha, answer.data.content.size], [201, 'docs/swallowed.md', 'string', 6]);
  assert.equal((await getFile(simulator, 'docs/swallowed.md')).status, 404);
  assert.equal(simulator.state().blobs[answer.data.content.sha], undefined, 'the blob it made is not kept');
});

test('the simulator imports only node built-ins: never lib/, catalog/, an action file or the GitHub sign-in', () => {
  const text = readFileSync(new URL('./fixtures/provider-simulators/github.mjs', import.meta.url), 'utf8');
  const specifiers = [...text.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)(['"`])([^'"`]+)\1/g)].map(match => match[2]);
  assert.ok(specifiers.length > 0);
  assert.deepEqual(specifiers.filter(specifier => !specifier.startsWith('node:')), []);
});

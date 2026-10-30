import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {validateActionFile} from '../lib/actions.mjs';
import {ACTION_REFUSED, PREPARED, RUN_WORDS} from '../lib/actions-runtime.mjs';
import {STATUS_WORDS} from '../lib/action-catalog.mjs';
import {FabricProtocol} from '../lib/fabric-protocol.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {RULES, createGuard} from '../lib/live-guard.mjs';
import {checkPlan, evidenceRecords, fillPlaceholders} from '../lib/live-certify.mjs';
import {githubHarness, githubDeps, githubFile, SANDBOX, FIVE, TOKEN, LOGIN, OWNER} from './fixtures/actions/github-harness.mjs';
import {ORIGIN} from './fixtures/provider-simulators/github.mjs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {actionSchema, withIds} from './fixtures/actions/fixture-app.mjs';

// F10.17 part 2 (docs/F10.17-BUILD-MAP.md section 3, part 2): GitHub's 15 actions (catalog/actions/github.json) on the GitHub simulator,
// through the action runtime, as an agent's call and the owner's approval run them; every case of GitHub's simulator case list
// (test/fixtures/provider-simulators/github.cases.json) through caseTests(); and the live plan H0 to H11 (catalog/live-tests/github.json)
// against step 12's plan check and the narrowed guard. Nothing here reaches GitHub. Every test reads the file with its ids recomputed
// (withIds()), so a seeded fault inside it is caught by what the action does; test/f10-17-churn.test.mjs checks the shipped ids.

const READ = {readOnly: true, destructive: false, idempotent: true, openWorld: true}, WRITE = {readOnly: false, destructive: false, idempotent: false, openWorld: true};
const BOUND = {readOnly: false, destructive: false, idempotent: true, openWorld: true}, LABELS = {readOnly: false, destructive: true, idempotent: false, openWorld: true};
/** Section 2's table: each action's row, effect and hints. */
const TABLE = Object.freeze({
  'list-repos': ['github.repos.read', 'read', READ], 'find-issues': ['github.issues.read', 'read', READ], 'read-conversation': ['github.issues.read', 'read', READ],
  'create-issue': ['github.issues.write', 'write', WRITE], 'update-issue': ['github.issues.write', 'write', WRITE], 'update-labels': ['github.issues.write', 'delete', LABELS],
  'comment': ['github.comments.write', 'write', WRITE], 'read-file': ['github.repos.read', 'read', READ], 'put-file': ['github.code.write', 'write', BOUND],
  'create-branch': ['github.code.write', 'write', WRITE], 'open-pull': ['github.pulls.write', 'write', WRITE], 'review-pull': ['github.issues.read', 'read', READ],
  'submit-review': ['github.comments.write', 'write', WRITE], 'merge-pull': ['github.pulls.write', 'write', BOUND], 'run-workflow': ['github.actions.run', 'write', WRITE]});
const REPO = SANDBOX, [OWNER_LOGIN, REPO_NAME] = SANDBOX.split('/');
const OTHER = {login: 'octo-b', id: 202};
const ROUTES = Object.freeze({
  issues: 'POST /repos/{owner}/{repo}/issues', issue: 'GET /repos/{owner}/{repo}/issues/{issue_number}', patch: 'PATCH /repos/{owner}/{repo}/issues/{issue_number}',
  addLabels: 'POST /repos/{owner}/{repo}/issues/{issue_number}/labels', removeLabel: 'DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}',
  comment: 'POST /repos/{owner}/{repo}/issues/{issue_number}/comments', comments: 'GET /repos/{owner}/{repo}/issues/{issue_number}/comments',
  put: 'PUT /repos/{owner}/{repo}/contents/{+path}', contents: 'GET /repos/{owner}/{repo}/contents/{+path}', refs: 'POST /repos/{owner}/{repo}/git/refs', ref: 'GET /repos/{owner}/{repo}/git/ref/{+ref}',
  pulls: 'POST /repos/{owner}/{repo}/pulls', pull: 'GET /repos/{owner}/{repo}/pulls/{pull_number}', files: 'GET /repos/{owner}/{repo}/pulls/{pull_number}/files',
  merge: 'PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge', review: 'POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews', checks: 'GET /repos/{owner}/{repo}/commits/{ref}/check-runs',
  dispatch: 'POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches', runs: 'GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs',
  run: 'GET /repos/{owner}/{repo}/actions/runs/{run_id}',
  repos: 'GET /user/repos', search: 'GET /search/issues'});
const GITHUB_ERROR = (status, message) => ({status, data: {message, documentation_url: 'https://docs.github.com/rest'}});

/** Asserts how a job ended, and any of its fields. */
function ended(job, status, errorCode, extra = {}) {
  assert.deepEqual([job.status, job.errorCode ?? null], [status, errorCode], `${job.error} ${JSON.stringify(job.details ?? job.reason ?? '')}`);
  for (const [key, value] of Object.entries(extra)) assert.deepEqual(job[key], value, key);
  return job;
}
/** An action refusal: failed, action_refused, its reason (and transform) in details. */
const refusedAs = (job, reason) => { ended(job, 'failed', ACTION_REFUSED); assert.equal(job.details?.reason, reason, JSON.stringify(job.details)); return job; };
const writes = h => h.simulator.writes().map(call => `${call.method} ${call.path}`);
const routes = h => h.simulator.calls.map(call => call.route);
/** A write job prepared to its one card: awaiting the owner, phase final, nothing written yet. */
async function prepared(h, key, input) {
  const before = h.simulator.writes().length, job = await h.run(key, input);
  assert.deepEqual([job.status, job.action?.phase, h.simulator.writes().length], ['awaiting_approval', 'final', before], `${key}: ${job.error ?? ''} ${JSON.stringify(job.details ?? '')}`);
  return job;
}
const approved = async (h, key, input) => h.approve(await prepared(h, key, input));
/** The exact body a prepared job will send, parsed. */
const bodyOf = (h, job, index = 0) => JSON.parse(h.prepared(job).content.perform[index].body);
const urlOf = (h, job, index = 0) => new URL(h.prepared(job).content.perform[index].url);
/** A request straight to the simulator with the account's token, for test setup: never through Fabric. */
async function api(h, method, path, body) {
  return h.simulator.request({url: `${ORIGIN}${path}`, method, headers: {Authorization: `Bearer ${TOKEN}`}, ...(body !== undefined ? {body: JSON.stringify(body)} : {}), allowedOrigins: [ORIGIN]});
}
/** A branch from main with one new file on it, and a pull request from it: its number and head. Setup only. */
async function pullOf(h, {head = 'feature', base = 'main', draft = false, path = 'notes/feature.txt', text = 'A feature.\n', title = 'Feature'} = {}) {
  await api(h, 'POST', `/repos/${REPO}/git/refs`, {ref: `refs/heads/${head}`, sha: h.simulator.head(REPO, base)});
  h.simulator.seedFile(REPO, head, path, text);
  const opened = await api(h, 'POST', `/repos/${REPO}/pulls`, {title, head, base, draft});
  assert.equal(opened.status, 201, JSON.stringify(opened.data));
  return {number: opened.data.number, head: h.simulator.head(REPO, head)};
}
const issueOf = (h, number) => h.simulator.state().repos[REPO].issues.find(item => item.number === number);
const fileOf = (h, path, branch = 'main') => {
  const state = h.simulator.state(), repo = state.repos[REPO], blob = repo.commits[repo.branches[branch]].tree[path];
  return blob === undefined ? null : Buffer.from(state.blobs[blob], 'base64').toString('utf8');
};

// ---- the file ---------------------------------------------------------------------------------------------------------------------------
/** GitHub's shipped file with each id recomputed from its content, as an author writes them. */
const currentFile = (deps = githubDeps()) => withIds(githubFile(), deps);

// F10.18 listed churn: step 18's live pass (run 5XBI3UND) certified all 15, each naming the shipped evidence; that each names the hash of
// exactly its definition, with a passing record, is test/live-evidence.test.mjs's, so an edit of the file is caught here by what it breaks.
test('the file: 15 actions, each placed in its row with its effect and hints (section 2), with no map; each certified by step 18\'s evidence, no superseded id', () => {
  const file = currentFile(), {actions} = validateActionFile(file, githubDeps());
  assert.deepEqual(actions.map(entry => entry.key), Object.keys(TABLE));
  for (const entry of actions) {
    const [row, effect, hints] = TABLE[entry.key];
    assert.deepEqual([entry.version, entry.row, entry.effect, entry.action.hints, entry.unplaced, entry.sensitive], [1, row, effect, hints, false, false], entry.key);
    assert.ok(entry.placements.every(placement => !placement.unplaced && placement.groupId.startsWith('github.')), entry.key);
    assert.equal(entry.placements.filter(placement => placement.phase === 'perform').at(-1).groupId, row, `${entry.key}: the last perform step lands in its row`);
    assert.deepEqual([Object.keys(entry.action.certified), entry.action.certified.evidence], [['evidence', 'definitionHash'], 'docs/live-evidence/github/actions.json'], `${entry.key}: certified by step 18's evidence`);
    assert.deepEqual(entry.action.pinnedParameters, undefined);
    // Every step asks for GitHub's JSON as a constant; Fabric adds User-Agent, X-GitHub-Api-Version and Authorization itself.
    for (const step of [...entry.action.prepare, ...entry.action.perform, ...(entry.action.verify?.requests ?? [])]) assert.deepEqual(step.headers, {Accept: {const: 'application/vnd.github+json'}}, `${entry.key} ${step.id}`);
  }
  assert.deepEqual([file.specVersion, file.pinnedParameters, file.superseded, ['candidate', 'reviewed'].includes(file.reviewStatus)], ['fabric/0.2', {}, undefined, true]);
  const schema = actionSchema();
  assert.ok(schema(file), JSON.stringify(schema.errors));
  // Bounds (section 2): at most 8 steps; Add or remove labels is the largest in requests (1 read, up to 20 writes, 1 readback).
  assert.ok(actions.every(entry => entry.placements.length <= 8));
  const labels = actions.find(entry => entry.key === 'update-labels').action;
  assert.deepEqual(labels.perform.map(step => [step.id, step.method, step.forEach.max]), [['add', 'POST', 10], ['remove', 'DELETE', 10]]);
  // The two content bindings and the one conditional scope (spec lines 1140 and 1421).
  const step = (key, id) => actions.find(entry => entry.key === key).action.perform.find(item => item.id === id);
  assert.deepEqual([step('put-file', 'put').bindContent, step('merge-pull', 'merge').bindContent, step('put-file', 'put').requiresScope.scope], ['sha', 'sha', 'workflow']);
});

test('at start without live evidence: 15 candidates that never run and that no agent can be given; no map is stored or needed', async t => {
  const h = githubHarness(t, {evidence: false});
  assert.deepEqual([...h.catalog.entries.values()].map(item => [item.status, item.reason]), Array(15).fill(['candidate', STATUS_WORDS.evidence]));
  assert.ok(h.store.list('capabilities').filter(capability => capability.driver === 'action').every(capability => capability.status === 'candidate'));
  assert.equal(h.store.list('applicationMaps').length, 0);
  await assert.rejects(h.run('list-repos v1', {}));
  const protocol = new FabricProtocol({store: h.store, runtime: h.runtime, clock: () => h.now, origin: 'http://127.0.0.1:59996'});
  assert.throws(() => protocol.createClient({name: 'GitHub agent', bindings: [{connectionId: h.account, capabilityId: h.idOf('list-repos v1')}]}, OWNER), {code: 'permission_denied'});
  assert.deepEqual([h.simulator.calls.length, h.store.list('clientGrants').length], [0, 0]);
});

// ---- paths and ref names (spec lines 1149 and 1150) ------------------------------------------------------------------------------------
test('paths: .., %2e and a backslash refuse path_invalid with nothing sent, for Read a file and for Create or update a file; a space in a name is read', async t => {
  const h = githubHarness(t);
  for (const path of ['../secrets.txt', 'docs/../README.md', '%2e%2e/x', 'docs\\a.md', '.', 'a//b', '/README.md']) {
    refusedAs(await h.run('read-file v1', {repository: REPO, path}), 'path_invalid');
    refusedAs(await h.run('put-file v1', {repository: REPO, path, branch: 'main', message: 'Edit', content: 'x'}), 'path_invalid');
  }
  assert.deepEqual(h.simulator.calls, [], 'refused before any request');
  h.simulator.seedFile(REPO, 'main', 'docs/read me.md', 'Spaced.\n');
  const read = ended(await h.run('read-file v1', {repository: REPO, path: 'docs/read me.md'}), 'succeeded', null);
  assert.deepEqual([read.result.data.text, h.simulator.calls.at(-1).path], ['Spaced.\n', `/repos/${REPO}/contents/docs/read%20me.md`]);
});

test('ref names: a..b, -x, x.lock, a b, x:y and @ refuse ref_invalid with nothing written, for Create a branch, Open a pull request, Read a file and Run a workflow', async t => {
  const h = githubHarness(t);
  for (const bad of ['a..b', '-x', 'x.lock', 'a b', 'x:y', '@']) {
    refusedAs(await h.run('create-branch v1', {repository: REPO, name: bad, from: 'main'}), 'ref_invalid');
    refusedAs(await h.run('create-branch v1', {repository: REPO, name: 'fine', from: bad}), 'ref_invalid');
    refusedAs(await h.run('open-pull v1', {repository: REPO, title: 'T', head: bad, base: 'main', draft: true}), 'ref_invalid');
    refusedAs(await h.run('open-pull v1', {repository: REPO, title: 'T', head: 'fine', base: bad, draft: true}), 'ref_invalid');
    refusedAs(await h.run('read-file v1', {repository: REPO, path: 'README.md', ref: bad}), 'ref_invalid');
    refusedAs(await h.run('run-workflow v1', {repository: REPO, workflow: 'fabric-synthetic.yml', branch: bad, inputs: []}), 'ref_invalid');
  }
  assert.deepEqual(writes(h), [], 'nothing written');
  // A ref the first request carries refuses before any request: only Create a branch's base read (a good from, a bad new name) and Run a
  // workflow's workflow read (a bad branch, which only the dispatch carries) went out.
  assert.deepEqual([...new Set(routes(h))].sort(), [ROUTES.ref, 'GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}'].sort());
  // A fork's owner:branch is a ref name with a colon: same repository only.
  refusedAs(await h.run('open-pull v1', {repository: REPO, title: 'T', head: 'octo-b:feature', base: 'main', draft: false}), 'ref_invalid');
});

// ---- content binding (spec line 1151, T5) -----------------------------------------------------------------------------------------------
test('a merge after the head moved: one PUT answered 409, the job fails content_changed with its words, and nothing merges', async t => {
  const h = githubHarness(t), pull = await pullOf(h);
  await api(h, 'GET', `/repos/${REPO}/pulls/${pull.number}`);
  const job = await prepared(h, 'merge-pull v1', {repository: REPO, number: pull.number, method: 'squash'});
  assert.deepEqual(bodyOf(h, job), {sha: pull.head, merge_method: 'squash'}, 'the merge carries the head read first');
  const fields = h.fields(job);
  assert.deepEqual([fields['Head commit'], fields['Merge method'], fields['Mergeable now'], fields['Pull request'], fields['Title now']], [pull.head, 'squash', 'yes', pull.number, 'Feature']);
  const moved = h.simulator.push(REPO, 'feature');
  const before = h.simulator.writes().length;
  ended(await h.approve(job), 'failed', 'provider_failed', {providerStatus: 409, reason: 'content_changed', error: RUN_WORDS.content_changed});
  assert.deepEqual(h.simulator.writes().slice(before).map(call => [call.route, call.status]), [[ROUTES.merge, 409]]);
  assert.deepEqual([issueOf(h, pull.number).state, issueOf(h, pull.number).pull.merged, h.simulator.head(REPO, 'feature')], ['open', false, moved]);
  // Asked again, the card reads the new head and the merge lands, read back by /merge_commit_sha.
  const merged = ended(await approved(h, 'merge-pull v1', {repository: REPO, number: pull.number, method: 'merge'}), 'succeeded', null);
  assert.deepEqual([merged.result.verification.status, merged.result.data.sha, issueOf(h, pull.number).pull.merge_commit_sha], ['verified', h.simulator.head(REPO, 'main'), h.simulator.head(REPO, 'main')]);
  assert.equal(h.simulator.calls.at(-1).route, ROUTES.pull, 'read back on the pull request');
});

test('the same race for a file: two jobs prepared on one version; the first lands, the second fails 409 content_changed, and the file is the first one\'s', async t => {
  const h = githubHarness(t), input = {repository: REPO, path: 'README.md', branch: 'main', message: 'Edit the readme'};
  const sha = (await api(h, 'GET', `/repos/${REPO}/contents/README.md`)).data.sha;
  const first = await prepared(h, 'put-file v1', {...input, content: 'First.\n'}), second = await prepared(h, 'put-file v1', {...input, content: 'Second.\n'});
  assert.deepEqual([bodyOf(h, first).sha, bodyOf(h, second).sha, h.fields(first)['Replaces version']], [sha, sha, sha], 'both bound to the blob read first');
  const landed = ended(await h.approve(first), 'succeeded', null);
  ended(await h.approve(second), 'failed', 'provider_failed', {providerStatus: 409, reason: 'content_changed', error: RUN_WORDS.content_changed});
  assert.deepEqual([fileOf(h, 'README.md'), landed.result.data.sha, landed.result.verification.status], ['First.\n', (await api(h, 'GET', `/repos/${REPO}/contents/README.md`)).data.sha, 'verified']);
  // A new file is created with no sha, and its card has no "Replaces version" line.
  const created = await prepared(h, 'put-file v1', {...input, path: 'docs/new.md', content: 'New.\n'});
  assert.deepEqual([Object.hasOwn(bodyOf(h, created), 'sha'), h.fields(created)['Replaces version']], [false, undefined]);
  ended(await h.approve(created), 'succeeded', null);
  assert.equal(fileOf(h, 'docs/new.md'), 'New.\n');
});

// ---- the workflow scope (spec line 1140) ------------------------------------------------------------------------------------------------
test('the workflow scope: without it a workflow path refuses scope_missing with no write; with it the card says so and the file is written; a folded path is flagged too', async t => {
  const four = FIVE.filter(scope => scope !== 'workflow'), input = {repository: REPO, branch: 'main', message: 'Add a workflow', content: 'on: workflow_dispatch\n'};
  let h = githubHarness(t, {scopes: four});
  for (const path of ['.github/workflows/new.yml', '.GitHub/Workflows/new.yml', '.github/WORKFLOWS/new.yml']) refusedAs(await h.run('put-file v1', {...input, path}), 'scope_missing');
  assert.deepEqual(writes(h), []);
  // Any other file needs no workflow scope; its card says so.
  const plain = await prepared(h, 'put-file v1', {...input, path: '.github/notes.md'});
  assert.deepEqual([h.fields(plain)['Workflow file'], h.fields(plain).File], ['no', '.github/notes.md']);
  h = githubHarness(t);
  const job = await prepared(h, 'put-file v1', {...input, path: '.github/workflows/new.yml'});
  assert.deepEqual(h.fields(job), {Repository: REPO, Branch: 'main', File: '.github/workflows/new.yml', 'Workflow file': 'yes', 'Commit message': 'Add a workflow', 'New content (first 10,000 characters)': 'on: workflow_dispatch\n'});
  ended(await h.approve(job), 'succeeded', null);
  assert.equal(fileOf(h, '.github/workflows/new.yml'), 'on: workflow_dispatch\n');
  assert.equal(h.fields(await prepared(h, 'put-file v1', {...input, path: '.GitHub/Workflows/other.yml'}))['Workflow file'], 'yes', 'flagged with ASCII folding');
});

test('a scope lost through a narrowed grant header makes the next workflow write refuse scope_missing, while a plain file is still written', async t => {
  const h = githubHarness(t), input = {repository: REPO, branch: 'main', message: 'Add a workflow', content: 'on: workflow_dispatch\n'};
  h.simulator.grant(FIVE.filter(scope => scope !== 'workflow'));
  ended(await h.run('read-file v1', {repository: REPO, path: 'README.md'}), 'succeeded', null);
  assert.deepEqual(h.connection().scopes, ['read:user', 'repo', 'read:org', 'gist']);
  refusedAs(await h.run('put-file v1', {...input, path: '.github/workflows/new.yml'}), 'scope_missing');
  assert.deepEqual(writes(h), []);
  ended(await approved(h, 'put-file v1', {...input, path: 'docs/plain.md'}), 'succeeded', null);
});

// ---- readback ------------------------------------------------------------------------------------------------------------------------------
test('readback: Create issue and Open a pull request read back by /number, Create or update a file by /sha, Merge by /merge_commit_sha; a swallowed write ends unverified', async t => {
  const h = githubHarness(t);
  const issue = ended(await approved(h, 'create-issue v1', {repository: REPO, title: 'Made by Fabric'}), 'succeeded', null);
  assert.deepEqual([issue.result.data.number, issue.result.verification.status, h.simulator.calls.at(-1).path], [4, 'verified', `/repos/${REPO}/issues/4`]);
  await api(h, 'POST', `/repos/${REPO}/git/refs`, {ref: 'refs/heads/topic', sha: h.simulator.head(REPO, 'main')});
  h.simulator.seedFile(REPO, 'topic', 'topic.txt', 'Topic.\n');
  const pull = ended(await approved(h, 'open-pull v1', {repository: REPO, title: 'Topic', head: 'topic', base: 'main', draft: false}), 'succeeded', null);
  assert.deepEqual([pull.result.data.number, pull.result.verification.status, h.simulator.calls.at(-1).path], [5, 'verified', `/repos/${REPO}/pulls/5`]);
  const file = ended(await approved(h, 'put-file v1', {repository: REPO, path: 'docs/a.md', branch: 'topic', message: 'Add a', content: 'A.\n'}), 'succeeded', null);
  assert.deepEqual([file.result.verification.status, file.result.data.sha, h.simulator.calls.at(-1).route, h.simulator.calls.at(-1).query.ref], ['verified', (await api(h, 'GET', `/repos/${REPO}/contents/docs/a.md?ref=topic`)).data.sha, ROUTES.contents, 'topic']);
  const merged = ended(await approved(h, 'merge-pull v1', {repository: REPO, number: 5, method: 'merge'}), 'succeeded', null);
  assert.equal(merged.result.verification.status, 'verified');
  // A write GitHub answers but does not apply: the readback cannot confirm it, so the job ends uncertain, never failed and never retried.
  h.simulator.swallow(ROUTES.issues);
  const swallowed = ended(await approved(h, 'create-issue v1', {repository: REPO, title: 'Lost'}), 'uncertain', 'outcome_uncertain');
  assert.deepEqual([swallowed.result.verification.status, h.simulator.writes().filter(call => call.route === ROUTES.issues).length], ['unverified', 2]);
});

// ---- reviews ---------------------------------------------------------------------------------------------------------------------------------
test('reviews: event is required and never blank; commit_id is the head read first even when the head moves after the card; a closed pull refuses wrong_state', async t => {
  const h = githubHarness(t), pull = await pullOf(h);
  const sent = h.simulator.calls.length;
  await assert.rejects(h.run('submit-review v1', {repository: REPO, number: pull.number, body: 'Looks good'}), 'event is required');
  await assert.rejects(h.run('submit-review v1', {repository: REPO, number: pull.number, event: '', body: 'Looks good'}));
  await assert.rejects(h.run('submit-review v1', {repository: REPO, number: pull.number, event: 'PENDING', body: 'Looks good'}));
  assert.equal(h.simulator.calls.length, sent, 'refused before any call');
  const job = await prepared(h, 'submit-review v1', {repository: REPO, number: pull.number, event: 'COMMENT', body: 'Read it, @octo-b'});
  assert.deepEqual(bodyOf(h, job), {event: 'COMMENT', commit_id: pull.head, body: 'Read it, @octo-b'});
  const fields = h.fields(job);
  assert.deepEqual([fields['Pull request'], fields['Title now'], fields['Pinned to commit'], fields['Your review'], fields.Review, fields['Mentions (GitHub notifies them)']],
    [pull.number, 'Feature', pull.head, 'COMMENT', 'Read it, @octo-b', '@octo-b']);
  h.simulator.push(REPO, 'feature');
  const done = ended(await h.approve(job), 'succeeded', null);
  const review = h.simulator.state().repos[REPO].reviews.at(-1);
  assert.deepEqual([review.commit_id, review.state, done.result.data.commitId, done.result.verification.status], [pull.head, 'COMMENTED', pull.head, 'verified'], 'pinned to the commit the owner saw');
  await api(h, 'PATCH', `/repos/${REPO}/issues/${pull.number}`, {state: 'closed'});
  const closed = refusedAs(await h.run('submit-review v1', {repository: REPO, number: pull.number, event: 'COMMENT', body: 'Late'}), 'wrong_state');
  assert.deepEqual([closed.details.transform, closed.details.transformReason], ['collections.oneOf@1', 'not_one_of']);
  assert.equal(h.simulator.state().repos[REPO].reviews.length, 1);
});

// ---- labels ----------------------------------------------------------------------------------------------------------------------------------
test('labels: one POST per added label, never an empty list; removing an absent label counts as done; a name with / or % refuses with nothing written', async t => {
  const h = githubHarness(t);
  const job = await prepared(h, 'update-labels v1', {repository: REPO, number: 1, add: ['bug', 'fabric-test'], remove: ['wontfix']});
  assert.deepEqual(h.prepared(job).content.perform.map(item => [item.method, new URL(item.url).pathname, item.body === null ? null : JSON.parse(item.body)]), [
    ['POST', `/repos/${REPO}/issues/1/labels`, {labels: ['bug']}], ['POST', `/repos/${REPO}/issues/1/labels`, {labels: ['fabric-test']}], ['DELETE', `/repos/${REPO}/issues/1/labels/wontfix`, null]]);
  assert.deepEqual([h.fields(job).Issue, h.fields(job)['Title now'], h.fields(job)['Labels now'], h.fields(job)['Labels to add (GitHub creates any the repository lacks)'], h.fields(job)['Labels to remove']],
    [1, 'Issue A', '', 'bug\nfabric-test', 'wontfix']);
  const done = ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual([issueOf(h, 1).labels, done.result.data.labels, done.result.verification.status], [['bug', 'fabric-test'], ['bug', 'fabric-test'], 'verified']);
  assert.deepEqual(h.simulator.writes().map(call => call.status), [200, 200, 404], 'the absent label answered 404, and the end state holds');
  // Only removals: no POST at all, so never an empty list (which would remove every label).
  const removal = await prepared(h, 'update-labels v1', {repository: REPO, number: 1, add: [], remove: ['bug']});
  assert.deepEqual(h.prepared(removal).content.perform.map(item => item.method), ['DELETE']);
  assert.equal(h.fields(removal)['Labels now'], 'bug\nfabric-test');
  ended(await h.approve(removal), 'succeeded', null);
  assert.deepEqual(issueOf(h, 1).labels, ['fabric-test']);
  const before = h.simulator.writes().length;
  for (const name of ['a/b', 'x%2Fy', '..']) refusedAs(await h.run('update-labels v1', {repository: REPO, number: 1, add: [], remove: [name]}), 'request_invalid');
  assert.equal(h.simulator.writes().length, before, 'nothing written');
  assert.ok(h.simulator.calls.slice(-3).every(call => call.route === ROUTES.issue), 'only the issue was read');
});

// ---- mentions ----------------------------------------------------------------------------------------------------------------------------------
test('mentions: Comment\'s card lists @octo-b and @org/team; a body with none shows an empty line; Create issue without a body still builds its card', async t => {
  const h = githubHarness(t);
  const job = await prepared(h, 'comment v1', {repository: REPO, number: 1, body: 'Thanks @octo-b and @octo-org/platform-team, mail a@b.com.'});
  assert.deepEqual(h.fields(job), {Repository: REPO, Issue: 1, 'Title now': 'Issue A', Comment: 'Thanks @octo-b and @octo-org/platform-team, mail a@b.com.', 'Mentions (GitHub notifies them)': '@octo-b\n@octo-org/platform-team'});
  assert.equal(h.fields(await prepared(h, 'comment v1', {repository: REPO, number: 1, body: 'No one here.'}))['Mentions (GitHub notifies them)'], '');
  assert.deepEqual(h.fields(await prepared(h, 'create-issue v1', {repository: REPO, title: 'Bare'})), {Repository: REPO, Title: 'Bare', 'Labels to add (GitHub creates any the repository lacks)': '', 'Mentions (GitHub notifies them)': ''});
  assert.equal(h.fields(await prepared(h, 'open-pull v1', {repository: REPO, title: 'P', head: 'x', base: 'main', draft: true, body: 'cc @octo-b'}))['Mentions (GitHub notifies them)'], '@octo-b');
  assert.equal(h.fields(await prepared(h, 'update-issue v1', {repository: REPO, number: 2, body: 'cc @octo-b'}))['Mentions (GitHub notifies them)'], '@octo-b');
  assert.equal(h.fields(await prepared(h, 'update-issue v1', {repository: REPO, number: 2, title: 'Renamed'}))['Mentions (GitHub notifies them)'], '', 'a change with no body notifies no one new');
});

// ---- find issues -----------------------------------------------------------------------------------------------------------------------------------
test('Find issues: q always holds is:issue or is:pull-request; a word holding a quote refuses; no repository and no involvement refuses query_scope_missing', async t => {
  const h = githubHarness(t), pull = await pullOf(h, {title: 'Synthetic pull'});
  const issues = ended(await h.run('find-issues v1', {type: 'issue', repository: REPO, text: 'synthetic'}), 'succeeded', null);
  assert.deepEqual([h.simulator.calls.at(-1).query.q, h.simulator.calls.at(-1).query.per_page], [`is:issue repo:${REPO} "synthetic"`, '25']);
  assert.deepEqual(issues.result.data.items.map(item => item.number), [2]);
  const pulls = ended(await h.run('find-issues v1', {type: 'pull-request', involvement: 'author', state: 'open', page: 1}), 'succeeded', null);
  assert.deepEqual([h.simulator.calls.at(-1).query.q, h.simulator.calls.at(-1).query.page], ['is:pull-request author:@me is:open', '1']);
  assert.deepEqual([pulls.result.data.totalCount, pulls.result.data.incomplete, pulls.result.data.items.map(item => [item.number, item.title, item.author])], [1, false, [[pull.number, 'Synthetic pull', LOGIN]]]);
  // A user's qualifier stays a quoted word.
  ended(await h.run('find-issues v1', {type: 'issue', repository: REPO, text: 'repo:octo-org/platform'}), 'succeeded', null);
  assert.equal(h.simulator.calls.at(-1).query.q, `is:issue repo:${REPO} "repo:octo-org/platform"`);
  const sent = h.simulator.calls.length;
  refusedAs(await h.run('find-issues v1', {type: 'issue', repository: REPO, text: 'foo" repo:x/y "bar'}), 'query_value_invalid');
  refusedAs(await h.run('find-issues v1', {type: 'issue', text: 'anything'}), 'query_scope_missing');
  refusedAs(await h.run('find-issues v1', {type: 'issue', repository: 'not/a/repo'}), 'repo_invalid');
  assert.equal(h.simulator.calls.length, sent, 'refused before any call');
  await assert.rejects(h.run('find-issues v1', {repository: REPO}), 'type is required');
});

// ---- read conversation ------------------------------------------------------------------------------------------------------------------------------
test('Read conversation: a null body and a null comment body read as left out; a pull request adds its pull block; long text comes back cut with the marker', async t => {
  const h = githubHarness(t);
  const plain = ended(await h.run('read-conversation v1', {repository: REPO, number: 1}), 'succeeded', null).result.data;
  assert.deepEqual([plain.number, plain.title, plain.state, plain.author, plain.labels, plain.comments, Object.hasOwn(plain, 'body'), Object.hasOwn(plain, 'pull')], [1, 'Issue A', 'open', LOGIN, [], [], false, false]);
  assert.ok(!h.simulator.calls.some(call => call.route === ROUTES.pull), 'an issue sends no pull read');
  // A long body and a long comment, cut with the marker; a comment GitHub answers with a null body reads as left out.
  await api(h, 'PATCH', `/repos/${REPO}/issues/1`, {body: 'b'.repeat(9000)});
  await api(h, 'POST', `/repos/${REPO}/issues/1/comments`, {body: 'c'.repeat(5000)});
  await api(h, 'POST', `/repos/${REPO}/issues/1/comments`, {body: 'Short.'});
  const listed = (await api(h, 'GET', `/repos/${REPO}/issues/1/comments`)).data;
  h.simulator.fail(ROUTES.comments, {status: 200, data: [...listed, {...listed[1], id: 2999999, body: null}]});
  const long = ended(await h.run('read-conversation v1', {repository: REPO, number: 1}), 'succeeded', null).result.data;
  assert.deepEqual([[...long.body].length, long.body.endsWith('\n[truncated]'), long.bodyTruncated], [8000, true, true]);
  assert.deepEqual(long.comments.map(item => [item.id, item.body === undefined ? null : [...item.body].length, item.body?.endsWith('\n[truncated]') ?? false]),
    [[listed[0].id, 4000, true], [listed[1].id, 6, false], [2999999, null, false]]);
  assert.deepEqual([h.simulator.calls.at(-1).query.per_page, long.commentCount], ['50', 2]);
  const pull = await pullOf(h);
  const read = ended(await h.run('read-conversation v1', {repository: REPO, number: pull.number}), 'succeeded', null).result.data;
  assert.deepEqual(read.pull, {headRef: 'feature', headSha: pull.head, baseRef: 'main', draft: false, merged: false});
  assert.ok(h.simulator.calls.some(call => call.route === ROUTES.pull));
});

// ---- review changes and checks ------------------------------------------------------------------------------------------------------------------------------
test('Review changes and checks: mergeable null on the first read sends the second read; still null leaves it out; the checks read uses the head read first', async t => {
  const h = githubHarness(t), pull = await pullOf(h);
  h.simulator.addCheckRun(REPO, pull.head, {name: 'ci', conclusion: 'success'});
  h.simulator.addCheckRun(REPO, pull.head, {name: 'lint', status: 'in_progress'});
  const job = ended(await h.run('review-pull v1', {repository: REPO, number: pull.number}), 'succeeded', null), data = job.result.data;
  assert.deepEqual(routes(h).slice(-4), [ROUTES.pull, ROUTES.checks, ROUTES.files, ROUTES.pull], 'the pull, its checks, its files, and the pull again while mergeable was null');
  assert.equal(h.simulator.calls.find(call => call.route === ROUTES.checks).path, `/repos/${REPO}/commits/${pull.head}/check-runs`);
  assert.deepEqual([data.mergeable, data.mergeableState, data.head, data.base.ref, data.changedFiles, data.additions], [true, 'clean', {ref: 'feature', sha: pull.head}, 'main', 1, 1]);
  assert.deepEqual(data.checks.map(item => [item.name, item.status, item.conclusion]), [['ci', 'completed', 'success'], ['lint', 'in_progress', undefined]]);
  assert.deepEqual(data.files, [{filename: 'notes/feature.txt', status: 'added', additions: 1, deletions: 0, patch: '@@ -0,0 +1 @@\n+A feature.'}]);
  // Known on the first read: no second read.
  const again = h.simulator.calls.length;
  ended(await h.run('review-pull v1', {repository: REPO, number: pull.number}), 'succeeded', null);
  assert.deepEqual(routes(h).slice(again), [ROUTES.pull, ROUTES.checks, ROUTES.files]);
  // Still null on the second read: left out, and the state says unknown.
  const view = (await api(h, 'GET', `/repos/${REPO}/pulls/${pull.number}`)).data;
  h.simulator.fail(ROUTES.pull, {status: 200, data: {...view, mergeable: null, mergeable_state: 'unknown'}}, {times: 2});
  const unknown = ended(await h.run('review-pull v1', {repository: REPO, number: pull.number}), 'succeeded', null).result.data;
  assert.deepEqual([Object.hasOwn(unknown, 'mergeable'), unknown.mergeableState], [false, 'unknown']);
  // A long patch is cut at 3,000 code points with the marker.
  h.simulator.seedFile(REPO, 'feature', 'big.txt', 'x'.repeat(4000));
  const big = ended(await h.run('review-pull v1', {repository: REPO, number: pull.number}), 'succeeded', null).result.data.files.find(item => item.filename === 'big.txt');
  assert.deepEqual([[...big.patch].length, big.patch.endsWith('\n[truncated]')], [3000, true]);
});

// ---- run a workflow ------------------------------------------------------------------------------------------------------------------------------
test('Run a workflow: inputs arrive as strings and GitHub answers the new run, which is read back by its id; a repeated name refuses name_repeated; a disabled workflow refuses wrong_state', async t => {
  const h = githubHarness(t);
  const job = await prepared(h, 'run-workflow v1', {repository: REPO, workflow: 'fabric-synthetic.yml', branch: 'main', inputs: [{name: 'greeting', value: 'hello'}]});
  assert.deepEqual(bodyOf(h, job), {ref: 'main', inputs: {greeting: 'hello'}, return_run_details: true});
  assert.deepEqual([h.fields(job).Workflow, h.fields(job).Branch, h.fields(job).Inputs], ['Fabric synthetic (.github/workflows/fabric-synthetic.yml)', 'main', 'greeting']);
  const done = ended(await h.approve(job), 'succeeded', null);
  const run = h.simulator.state().repos[REPO].runs.at(-1);
  assert.deepEqual([run.inputs, run.head_branch, run.event, done.result.verification.status], [{greeting: 'hello'}, 'main', 'workflow_dispatch', 'verified']);
  assert.deepEqual([done.result.data.runId, done.result.data.runUrl, done.result.data.branch], [run.id, run.html_url, 'main']);
  const read = h.simulator.calls.at(-1);
  assert.deepEqual([read.route, read.path.endsWith(`/actions/runs/${run.id}`)], [ROUTES.run, true], 'the readback reads the run by the id GitHub answered');
  assert.equal(h.simulator.calls.filter(call => call.route === ROUTES.runs).length, 0, 'the runs list is never read');
  refusedAs(await h.run('run-workflow v1', {repository: REPO, workflow: 'fabric-synthetic.yml', branch: 'main', inputs: [{name: 'greeting', value: 'a'}, {name: 'GREETING', value: 'b'}]}), 'name_repeated');
  refusedAs(await h.run('run-workflow v1', {repository: REPO, workflow: 'fabric-synthetic.yml', branch: 'main', inputs: [{name: '1abc', value: 'a'}]}), 'name_invalid');
  h.simulator.addWorkflow(REPO, {file: 'off.yml', name: 'Off', state: 'disabled_manually'});
  refusedAs(await h.run('run-workflow v1', {repository: REPO, workflow: 'off.yml', branch: 'main', inputs: []}), 'wrong_state');
  assert.equal(h.simulator.writes().length, 1, 'nothing more dispatched');
});

// F10.17 open question 4, closed by reading the run by id: a run the list shows only a moment later still verifies, and an earlier run on the
// same branch never verifies a dispatch that did not happen.
test('Run a workflow: a run the list does not show yet verifies; an earlier run on the branch does not verify a swallowed dispatch; a run answered for another branch, event, workflow or id does not verify', async t => {
  const lag = githubHarness(t);
  lag.simulator.runLag(3);
  assert.equal(ended(await approved(lag, 'run-workflow v1', WORKFLOW), 'succeeded', null).result.verification.status, 'verified');
  const earlier = githubHarness(t);
  await api(earlier, 'POST', `/repos/${REPO}/actions/workflows/fabric-synthetic.yml/dispatches`, {ref: 'main'});
  await swallowed(earlier, ROUTES.dispatch, 'run-workflow v1', WORKFLOW);
  assert.equal(earlier.simulator.state().repos[REPO].runs.length, 1, 'only the earlier run exists');
  // The same crafted answer with nothing changed verifies, so each refusal below is its one field.
  const answered = (h, change) => {
    const id = 5_000_000 + h.simulator.state().next.run, workflow = h.simulator.state().repos[REPO].workflows.find(item => item.path.endsWith('/fabric-synthetic.yml'));
    h.simulator.fail(ROUTES.run, {status: 200, data: {id, workflow_id: workflow.id, event: 'workflow_dispatch', head_branch: 'main', ...change}});
  };
  const same = githubHarness(t);
  answered(same, {});
  assert.equal(ended(await approved(same, 'run-workflow v1', WORKFLOW), 'succeeded', null).result.verification.status, 'verified');
  for (const change of [{head_branch: 'other'}, {event: 'push'}, {workflow_id: 1}, {id: 1}]) {
    const h = githubHarness(t);
    answered(h, change);
    const job = ended(await approved(h, 'run-workflow v1', WORKFLOW), 'uncertain', 'outcome_uncertain');
    assert.deepEqual([job.result.verification.status, h.simulator.writes().length], ['unverified', 1], `${JSON.stringify(change)}: never retried`);
  }
});

// ---- spacing, modes and secrets ------------------------------------------------------------------------------------------------------------------------------
test('spacing: a labels job with two adds and one removal sends its three writes at least 1,000 ms apart, and its reads never wait', async t => {
  const h = githubHarness(t);
  await api(h, 'POST', `/repos/${REPO}/issues/1/labels`, {labels: ['wontfix']});
  const before = h.simulator.writes().length;
  ended(await approved(h, 'update-labels v1', {repository: REPO, number: 1, add: ['bug', 'fabric-test'], remove: ['wontfix']}), 'succeeded', null);
  const at = h.simulator.writes().slice(before).map(call => call.at);
  assert.equal(at.length, 3);
  for (let index = 1; index < at.length; index++) assert.ok(at[index] - at[index - 1] >= 1000, `write ${index + 1} came ${at[index] - at[index - 1]} ms after the one before`);
  assert.deepEqual(h.waits.map(wait => wait.ms), [1000, 1000]);
});

test('modes: reads run at Allow with no card and no lock; a write asks once under the defaults; with "Access issues and pull requests" at Ask it stops twice', async t => {
  const h = githubHarness(t);
  for (const [key, input] of [['list-repos v1', {}], ['read-file v1', {repository: REPO, path: 'README.md'}], ['read-conversation v1', {repository: REPO, number: 1}]]) {
    const job = ended(await h.run(key, input), 'succeeded', null, {effect: 'read'});
    assert.deepEqual([job.action.modes, job.action.approvals, [...h.runtime.writeLocks]], [{prepare: 'allow', resolve: null, perform: 'allow'}, [], []], key);
  }
  const once = await prepared(h, 'update-issue v1', {repository: REPO, number: 1, title: 'One stop'});
  assert.deepEqual(once.action.modes, {prepare: 'allow', resolve: null, perform: 'ask'});
  h.setRow('github.issues.read', 'ask');
  const reads = await h.run('update-issue v1', {repository: REPO, number: 1, title: 'Two stops'});
  assert.deepEqual([reads.status, reads.action.phase], ['awaiting_approval', 'reads']);
  const final = await h.approve(reads);
  assert.deepEqual([final.status, final.action.phase, h.simulator.writes().length], ['awaiting_approval', 'final', 0]);
  ended(await h.approve(final), 'succeeded', null);
  assert.equal(issueOf(h, 1).title, 'Two stops');
  // "Comment and review" is an audience row: it never runs at Allow, even when the owner tries.
  assert.throws(() => h.setRow('github.comments.write', 'allow'));
});

test('secrets: the token, temp_clone_token and the grant header never reach a job, prepared bytes, a card, an audit row or an output; evidence stays under the temp root', async t => {
  const shipped = new URL('../docs/live-evidence/github/actions.json', import.meta.url), before = existsSync(shipped) ? readFileSync(shipped, 'utf8') : null;
  const h = githubHarness(t), pull = await pullOf(h);
  await api(h, 'PATCH', `/repos/${REPO}/issues/1`, {body: `Pasted ${TOKEN} here`});
  const clone = h.simulator.state().repos[REPO].tempCloneToken;
  const repos = ended(await h.run('list-repos v1', {}), 'succeeded', null);
  const read = ended(await h.run('read-conversation v1', {repository: REPO, number: 1}), 'succeeded', null);
  const job = await prepared(h, 'merge-pull v1', {repository: REPO, number: pull.number, method: 'merge'});
  const card = h.card(job), bytes = h.prepared(job).content.perform, done = ended(await h.approve(job), 'succeeded', null);
  assert.equal(read.result.data.body, 'Pasted [redacted] here', 'the token an answer echoes is scrubbed before anything reads it');
  assert.deepEqual(Object.keys(repos.result.data.repositories[0]).sort(), ['archived', 'canPush', 'defaultBranch', 'description', 'fullName', 'private']);
  for (const [name, value] of [['jobs', h.store.list('jobs')], ['card', card], ['audit', h.store.list('activity')], ['outputs', [repos.result, read.result, done.result]], ['prepared bytes', bytes]]) {
    for (const secret of [TOKEN, clone, 'x-oauth-scopes']) assert.ok(!JSON.stringify(value).includes(secret), `${name}: ${secret.slice(0, 12)}`);
  }
  for (const row of h.store.list(PREPARED)) assert.ok(!JSON.stringify(row).includes(TOKEN) && !JSON.stringify(row).includes('x-oauth-scopes'), 'no prepared row holds the token or the header');
  assert.ok(existsSync(`${h.root}/docs/live-evidence/github/actions.json`));
  assert.equal(existsSync(shipped) ? readFileSync(shipped, 'utf8') : null, before, 'the shipped evidence is never written by a test');
});

// ---- the independent review (docs/F10.17-BUILD-MAP.md section 9, "Independent review") ------------------------------------------------------
test('Update issue refuses a close reason without closing, before any request, since GitHub ignores state_reason unless the state changes: its card never shows a reason that is not applied', async t => {
  const h = githubHarness(t);
  for (const input of [{closeAs: 'not_planned'}, {state: 'open', closeAs: 'completed'}, {title: 'Renamed', closeAs: 'not_planned'}]) {
    const job = refusedAs(await h.run('update-issue v1', {repository: REPO, number: 1, ...input}), 'wrong_state');
    assert.deepEqual([job.details.transform, job.details.transformReason], ['collections.oneOf@1', 'not_one_of'], JSON.stringify(input));
  }
  assert.deepEqual(h.simulator.calls, [], 'refused before any request');
  // Every other shape still asks once: no field, a title, a state alone, and a close with its reason, which closes as asked.
  for (const input of [{}, {title: 'Renamed'}, {state: 'open'}, {state: 'closed'}]) await prepared(h, 'update-issue v1', {repository: REPO, number: 1, ...input});
  const done = ended(await approved(h, 'update-issue v1', {repository: REPO, number: 1, state: 'closed', closeAs: 'not_planned'}), 'succeeded', null);
  assert.deepEqual([issueOf(h, 1).state, issueOf(h, 1).state_reason, done.result.data.stateReason], ['closed', 'not_planned', 'not_planned']);
});

test('labels GitHub creates: the cards of Create issue and Add or remove labels say GitHub creates a label to add that the repository lacks, as GitHub does (open question 7)', async t => {
  const h = githubHarness(t), line = 'Labels to add (GitHub creates any the repository lacks)';
  const issue = await prepared(h, 'create-issue v1', {repository: REPO, title: 'New', labels: ['brand-new']});
  const labels = await prepared(h, 'update-labels v1', {repository: REPO, number: 1, add: ['also-new'], remove: []});
  assert.deepEqual([h.fields(issue)[line], h.fields(labels)[line]], ['brand-new', 'also-new']);
  for (const job of [issue, labels]) ended(await h.approve(job), 'succeeded', null);
  assert.deepEqual(h.simulator.state().repos[REPO].labels.map(label => label.name), ['bug', 'fabric-test', 'brand-new', 'also-new'], 'both labels were made in the repository');
});

// ---- every card -----------------------------------------------------------------------------------------------------------------------------
test('every write\'s card shows what its request sends and the item as read first: the repository, the number and title, the branch, the sha it is bound to', async t => {
  const h = githubHarness(t), pull = await pullOf(h);
  await api(h, 'PATCH', `/repos/${REPO}/issues/3`, {state: 'closed'});
  const setup = h.simulator.writes().length;
  const card = async (key, input) => h.fields(await prepared(h, key, input));
  assert.deepEqual(await card('create-issue v1', {repository: REPO, title: 'New', body: 'Body text', labels: ['bug']}),
    {Repository: REPO, Title: 'New', Body: 'Body text', 'Labels to add (GitHub creates any the repository lacks)': 'bug', 'Mentions (GitHub notifies them)': ''});
  assert.deepEqual(await card('update-issue v1', {repository: REPO, number: 3, title: 'Again', state: 'open'}),
    {Repository: REPO, Issue: 3, 'Title now': 'Issue C', 'State now': 'closed', 'New title': 'Again', 'New state': 'open', 'Mentions (GitHub notifies them)': ''});
  assert.deepEqual(await card('update-issue v1', {repository: REPO, number: 1, state: 'closed', closeAs: 'not_planned'}),
    {Repository: REPO, Issue: 1, 'Title now': 'Issue A', 'State now': 'open', 'New state': 'closed', 'Close as': 'not_planned', 'Mentions (GitHub notifies them)': ''});
  const branch = await prepared(h, 'create-branch v1', {repository: REPO, name: 'fabric/test-run', from: 'main'});
  assert.deepEqual(h.fields(branch), {Repository: REPO, 'New branch': 'fabric/test-run', 'From branch': 'main', 'From commit': h.simulator.head(REPO, 'main')});
  assert.deepEqual(bodyOf(h, branch), {ref: 'refs/heads/fabric/test-run', sha: h.simulator.head(REPO, 'main')});
  assert.deepEqual(await card('open-pull v1', {repository: REPO, title: 'Draft', head: 'feature', base: 'main', draft: true}),
    {Repository: REPO, Title: 'Draft', 'Head branch': 'feature', 'Base branch': 'main', Draft: 'yes', 'Mentions (GitHub notifies them)': ''});
  assert.deepEqual(await card('merge-pull v1', {repository: REPO, number: pull.number, method: 'rebase', commitTitle: 'Ship it'}),
    {Repository: REPO, 'Pull request': pull.number, 'Title now': 'Feature', 'Head branch': 'feature', 'Base branch': 'main', 'Head commit': pull.head, 'Merge method': 'rebase',
      'Mergeable now': 'not known yet', 'Commit title': 'Ship it'});
  assert.deepEqual(await card('run-workflow v1', {repository: REPO, workflow: 'fabric-synthetic.yml', branch: 'main', inputs: []}),
    {Repository: REPO, Workflow: 'Fabric synthetic (.github/workflows/fabric-synthetic.yml)', Branch: 'main', Inputs: ''});
  // A read that asks shows what it reads.
  h.setRow('github.repos.read', 'ask');
  const file = await h.run('read-file v1', {repository: REPO, path: 'README.md', ref: 'main'});
  assert.deepEqual([file.status, h.fields(file)], ['awaiting_approval', {Repository: REPO, File: 'README.md', Branch: 'main'}]);
  assert.equal(h.simulator.writes().length, setup, 'nothing written before an approval');
});

// ---- evidence (step 20's review) -------------------------------------------------------------------------------------------------
test('Evidence: a request of a step\'s shape that landed on a sibling member never fits: only a step a body route moved may stand in by its template', () => {
  const read = validateActionFile(currentFile(), githubDeps()).actions.find(entry => entry.key === 'read-conversation');
  const run = {appId: 'github', runId: 'ABCDEFGH', order: ['H1'], rows: [], results: {H1: {id: 'H1', passed: true, calls: [{action: 'read-conversation@1', actionId: read.id, jobs: []}], proxies: [], reads: [], checks: [], undo: {kind: 'none', why: 'test'}}}};
  const passed = path => evidenceRecords(run, {key: Buffer.alloc(32, 1), entries: [read], trace: () => [{method: 'GET', path, bodyHmac: null, status: 200}], job: () => null}).records[read.id].passed;
  assert.equal(passed('/repos/o/r/issues/7'), true);
  assert.equal(passed('/repos/o/r/issues/events'), false, 'issues/events has the shape of issues/{issue_number}, and is another member');
});

// ---- the simulator case list (check 5) ---------------------------------------------------------------------------------------------------------
const MANIFEST = JSON.parse(readFileSync(new URL('./fixtures/provider-simulators/github.cases.json', import.meta.url), 'utf8'));
const ENTRIES = validateActionFile(currentFile(), githubDeps()).actions;
const lost = async (h, route, key, input) => { h.simulator.drop(route); return ended(await approved(h, key, input), 'uncertain', 'outcome_uncertain'); };
const swallowed = async (h, route, key, input) => {
  h.simulator.swallow(route);
  const job = ended(await approved(h, key, input), 'uncertain', 'outcome_uncertain');
  assert.equal(job.result.verification.status, 'unverified');
  return job;
};
const refusedNever = async (h, row, key, input) => {
  h.setRow(row, 'deny');
  await assert.rejects(h.run(key, input), error => error.code === 'permission_denied' || /Never/.test(error.message));
  assert.equal(h.simulator.calls.length, 0);
};
const failedWith = async (h, key, input, status) => ended(await (TABLE[key.split(' ')[0]][1] === 'read' ? h.run(key, input) : approved(h, key, input)), 'failed', 'provider_failed', {providerStatus: status});
const ISSUE = {repository: REPO, title: 'Plan'}, FILE = {repository: REPO, path: 'docs/plan.md', branch: 'main', message: 'Add the plan', content: 'Plan.\n'};
const WORKFLOW = {repository: REPO, workflow: 'fabric-synthetic.yml', branch: 'main', inputs: []};
/** A branch with something new on it, for Open a pull request. */
async function topic(h, name = 'topic') {
  await api(h, 'POST', `/repos/${REPO}/git/refs`, {ref: `refs/heads/${name}`, sha: h.simulator.head(REPO, 'main')});
  h.simulator.seedFile(REPO, name, `${name}.txt`, 'Topic.\n');
  return {repository: REPO, title: 'Topic', head: name, base: 'main', draft: false};
}
const IMPLEMENTATIONS = {
  'list-repos v1/succeeds': async t => { const h = githubHarness(t); assert.deepEqual(ended(await h.run('list-repos v1', {}), 'succeeded', null).result.data.repositories.map(item => item.fullName), [REPO, 'octo-org/platform', `${LOGIN}/public-notes`]); },
  'list-repos v1/refused': async t => refusedNever(githubHarness(t), 'github.repos.read', 'list-repos v1', {}),
  'list-repos v1/provider-refusal': async t => { const h = githubHarness(t); h.simulator.fail(ROUTES.repos, GITHUB_ERROR(403, 'Forbidden')); await failedWith(h, 'list-repos v1', {}, 403); },
  'find-issues v1/succeeds': async t => { const h = githubHarness(t); assert.deepEqual(ended(await h.run('find-issues v1', {type: 'issue', repository: REPO, text: 'SYNTHETIC'}), 'succeeded', null).result.data.items.map(item => item.number), [2]); },
  'find-issues v1/refused': async t => { const h = githubHarness(t); refusedAs(await h.run('find-issues v1', {type: 'issue'}), 'query_scope_missing'); assert.equal(h.simulator.calls.length, 0); },
  'find-issues v1/provider-refusal': async t => { const h = githubHarness(t); h.simulator.fail(ROUTES.search, GITHUB_ERROR(422, 'Validation Failed')); await failedWith(h, 'find-issues v1', {type: 'issue', repository: REPO}, 422); },
  'read-conversation v1/succeeds': async t => { const h = githubHarness(t); assert.equal(ended(await h.run('read-conversation v1', {repository: REPO, number: 2}), 'succeeded', null).result.data.title, '[SYNTHETIC] Issue B'); },
  'read-conversation v1/refused': async t => refusedNever(githubHarness(t), 'github.issues.read', 'read-conversation v1', {repository: REPO, number: 1}),
  'read-conversation v1/provider-refusal': async t => { const h = githubHarness(t); h.simulator.deleteIssue(REPO, 1); await failedWith(h, 'read-conversation v1', {repository: REPO, number: 1}, 410); },
  'create-issue v1/succeeds': async t => {
    const h = githubHarness(t), job = ended(await approved(h, 'create-issue v1', {...ISSUE, body: 'Steps', labels: ['bug']}), 'succeeded', null);
    assert.deepEqual([job.result.verification.status, issueOf(h, 4).title, issueOf(h, 4).labels], ['verified', 'Plan', ['bug']]);
  },
  'create-issue v1/refused': async t => { const h = githubHarness(t); refusedAs(await h.run('create-issue v1', {...ISSUE, repository: 'octo-a/../x'}), 'repo_invalid'); assert.equal(h.simulator.calls.length, 0); },
  'create-issue v1/provider-refusal': async t => {
    const h = githubHarness(t);
    h.simulator.fail(ROUTES.issues, GITHUB_ERROR(410, 'Issues are disabled for this repo'));
    await failedWith(h, 'create-issue v1', ISSUE, 410);
    assert.equal(h.simulator.state().repos[REPO].issues.length, 3);
  },
  'create-issue v1/unverified': async t => swallowed(githubHarness(t), ROUTES.issues, 'create-issue v1', ISSUE),
  'create-issue v1/lost-answer': async t => { const h = githubHarness(t); await lost(h, ROUTES.issues, 'create-issue v1', ISSUE); assert.equal(h.simulator.state().repos[REPO].issues.length, 4, 'applied'); },
  'update-issue v1/succeeds': async t => {
    const h = githubHarness(t), job = ended(await approved(h, 'update-issue v1', {repository: REPO, number: 3, state: 'closed', closeAs: 'not_planned'}), 'succeeded', null);
    assert.deepEqual([issueOf(h, 3).state, issueOf(h, 3).state_reason, job.result.data.stateReason, job.result.verification.status], ['closed', 'not_planned', 'not_planned', 'verified']);
    ended(await approved(h, 'update-issue v1', {repository: REPO, number: 3, state: 'open'}), 'succeeded', null);
    assert.deepEqual([issueOf(h, 3).state, issueOf(h, 3).state_reason], ['open', 'reopened']);
  },
  'update-issue v1/refused': async t => refusedNever(githubHarness(t), 'github.issues.write', 'update-issue v1', {repository: REPO, number: 1, title: 'X'}),
  'update-issue v1/provider-refusal': async t => {
    // GitHub refuses the change (422), and nothing changes. (A close reason with state open never reaches GitHub: the action refuses it.)
    const h = githubHarness(t);
    await api(h, 'PATCH', `/repos/${REPO}/issues/3`, {state: 'closed'});
    h.simulator.fail(ROUTES.patch, GITHUB_ERROR(422, 'Validation Failed'));
    await failedWith(h, 'update-issue v1', {repository: REPO, number: 3, state: 'open'}, 422);
    assert.equal(issueOf(h, 3).state, 'closed');
  },
  'update-issue v1/unverified': async t => swallowed(githubHarness(t), ROUTES.patch, 'update-issue v1', {repository: REPO, number: 1, title: 'Renamed'}),
  'update-issue v1/lost-answer': async t => { const h = githubHarness(t); await lost(h, ROUTES.patch, 'update-issue v1', {repository: REPO, number: 1, title: 'Renamed'}); assert.equal(issueOf(h, 1).title, 'Renamed'); },
  'update-labels v1/succeeds': async t => { const h = githubHarness(t); ended(await approved(h, 'update-labels v1', {repository: REPO, number: 2, add: ['bug'], remove: []}), 'succeeded', null); assert.deepEqual(issueOf(h, 2).labels, ['bug']); },
  'update-labels v1/refused': async t => { const h = githubHarness(t); refusedAs(await h.run('update-labels v1', {repository: REPO, number: 2, add: [], remove: ['a/b']}), 'request_invalid'); assert.deepEqual(writes(h), []); },
  'update-labels v1/provider-refusal': async t => {
    const h = githubHarness(t);
    h.simulator.fail(ROUTES.addLabels, GITHUB_ERROR(403, 'Must have push access'));
    await failedWith(h, 'update-labels v1', {repository: REPO, number: 2, add: ['bug'], remove: []}, 403);
    assert.deepEqual(issueOf(h, 2).labels, []);
  },
  'update-labels v1/unverified': async t => swallowed(githubHarness(t), ROUTES.addLabels, 'update-labels v1', {repository: REPO, number: 2, add: ['bug'], remove: []}),
  'update-labels v1/lost-answer': async t => { const h = githubHarness(t); await lost(h, ROUTES.addLabels, 'update-labels v1', {repository: REPO, number: 2, add: ['bug'], remove: []}); assert.deepEqual(issueOf(h, 2).labels, ['bug']); },
  'comment v1/succeeds': async t => {
    const h = githubHarness(t), job = ended(await approved(h, 'comment v1', {repository: REPO, number: 1, body: 'Noted.'}), 'succeeded', null);
    assert.deepEqual([job.result.verification.status, h.simulator.state().repos[REPO].comments.map(item => item.body)], ['verified', ['Noted.']]);
  },
  'comment v1/refused': async t => refusedNever(githubHarness(t), 'github.comments.write', 'comment v1', {repository: REPO, number: 1, body: 'Hi'}),
  'comment v1/provider-refusal': async t => {
    const h = githubHarness(t);
    h.simulator.fail(ROUTES.comment, GITHUB_ERROR(403, 'Unable to create comment because issue is locked.'));
    await failedWith(h, 'comment v1', {repository: REPO, number: 1, body: 'Hi'}, 403);
    assert.deepEqual(h.simulator.state().repos[REPO].comments, []);
  },
  'comment v1/unverified': async t => swallowed(githubHarness(t), ROUTES.comment, 'comment v1', {repository: REPO, number: 1, body: 'Hi'}),
  'comment v1/lost-answer': async t => { const h = githubHarness(t); await lost(h, ROUTES.comment, 'comment v1', {repository: REPO, number: 1, body: 'Hi'}); assert.equal(h.simulator.state().repos[REPO].comments.length, 1); },
  'read-file v1/succeeds': async t => { const h = githubHarness(t); assert.deepEqual(ended(await h.run('read-file v1', {repository: REPO, path: 'README.md'}), 'succeeded', null).result.data.text, '# Fabric sandbox\n'); },
  'read-file v1/refused': async t => { const h = githubHarness(t); refusedAs(await h.run('read-file v1', {repository: REPO, path: '../README.md'}), 'path_invalid'); assert.equal(h.simulator.calls.length, 0); },
  'read-file v1/provider-refusal': async t => failedWith(githubHarness(t), 'read-file v1', {repository: REPO, path: 'missing.md'}, 404),
  'put-file v1/succeeds': async t => {
    const h = githubHarness(t), job = ended(await approved(h, 'put-file v1', FILE), 'succeeded', null);
    assert.deepEqual([fileOf(h, 'docs/plan.md'), job.result.verification.status, h.simulator.writes()[0].status], ['Plan.\n', 'verified', 201]);
  },
  'put-file v1/refused': async t => {
    const h = githubHarness(t, {scopes: FIVE.filter(scope => scope !== 'workflow')});
    refusedAs(await h.run('put-file v1', {...FILE, path: '.github/workflows/plan.yml'}), 'scope_missing');
    assert.deepEqual(writes(h), []);
  },
  'put-file v1/provider-refusal': async t => {
    const h = githubHarness(t), job = await prepared(h, 'put-file v1', {...FILE, path: 'README.md'});
    h.simulator.push(REPO, 'main', {path: 'README.md', text: 'Changed elsewhere.\n'});
    ended(await h.approve(job), 'failed', 'provider_failed', {providerStatus: 409, reason: 'content_changed'});
    assert.equal(fileOf(h, 'README.md'), 'Changed elsewhere.\n');
  },
  'put-file v1/unverified': async t => swallowed(githubHarness(t), ROUTES.put, 'put-file v1', FILE),
  'put-file v1/lost-answer': async t => { const h = githubHarness(t); await lost(h, ROUTES.put, 'put-file v1', FILE); assert.equal(fileOf(h, 'docs/plan.md'), 'Plan.\n'); },
  'create-branch v1/succeeds': async t => {
    const h = githubHarness(t), job = ended(await approved(h, 'create-branch v1', {repository: REPO, name: 'fabric/test-one', from: 'main'}), 'succeeded', null);
    assert.deepEqual([h.simulator.head(REPO, 'fabric/test-one'), job.result.data.ref, job.result.verification.status], [h.simulator.head(REPO, 'main'), 'refs/heads/fabric/test-one', 'verified']);
    assert.equal(h.simulator.calls.at(-1).path, `/repos/${REPO}/git/ref/heads/fabric/test-one`, 'read back through the {+ref} route');
  },
  'create-branch v1/refused': async t => { const h = githubHarness(t); refusedAs(await h.run('create-branch v1', {repository: REPO, name: 'a..b', from: 'main'}), 'ref_invalid'); assert.deepEqual(writes(h), []); },
  'create-branch v1/provider-refusal': async t => failedWith(githubHarness(t), 'create-branch v1', {repository: REPO, name: 'main', from: 'main'}, 422),
  'create-branch v1/unverified': async t => swallowed(githubHarness(t), ROUTES.refs, 'create-branch v1', {repository: REPO, name: 'topic', from: 'main'}),
  'create-branch v1/lost-answer': async t => { const h = githubHarness(t); await lost(h, ROUTES.refs, 'create-branch v1', {repository: REPO, name: 'topic', from: 'main'}); assert.ok(h.simulator.head(REPO, 'topic')); },
  'open-pull v1/succeeds': async t => {
    const h = githubHarness(t), job = ended(await approved(h, 'open-pull v1', {...await topic(h), body: 'Adds the topic.'}), 'succeeded', null);
    assert.deepEqual([job.result.data.number, issueOf(h, 4).pull.head, job.result.verification.status], [4, 'topic', 'verified']);
  },
  'open-pull v1/refused': async t => { const h = githubHarness(t); refusedAs(await h.run('open-pull v1', {repository: REPO, title: 'T', head: 'octo-b:topic', base: 'main', draft: false}), 'ref_invalid'); assert.equal(h.simulator.calls.length, 0); },
  'open-pull v1/provider-refusal': async t => {
    const h = githubHarness(t);
    await api(h, 'POST', `/repos/${REPO}/git/refs`, {ref: 'refs/heads/same', sha: h.simulator.head(REPO, 'main')});
    await failedWith(h, 'open-pull v1', {repository: REPO, title: 'Nothing new', head: 'same', base: 'main', draft: false}, 422);
  },
  'open-pull v1/unverified': async t => { const h = githubHarness(t); await swallowed(h, ROUTES.pulls, 'open-pull v1', await topic(h)); },
  'open-pull v1/lost-answer': async t => { const h = githubHarness(t); await lost(h, ROUTES.pulls, 'open-pull v1', await topic(h)); assert.ok(issueOf(h, 4).pull); },
  'review-pull v1/succeeds': async t => { const h = githubHarness(t), pull = await pullOf(h); assert.equal(ended(await h.run('review-pull v1', {repository: REPO, number: pull.number}), 'succeeded', null).result.data.files.length, 1); },
  'review-pull v1/refused': async t => refusedNever(githubHarness(t), 'github.repos.read', 'review-pull v1', {repository: REPO, number: 4}),
  'review-pull v1/provider-refusal': async t => failedWith(githubHarness(t), 'review-pull v1', {repository: REPO, number: 99}, 404),
  'submit-review v1/succeeds': async t => {
    const h = githubHarness(t), pull = await pullOf(h);
    h.simulator.author(REPO, pull.number, OTHER);
    const job = ended(await approved(h, 'submit-review v1', {repository: REPO, number: pull.number, event: 'APPROVE'}), 'succeeded', null);
    assert.deepEqual([job.result.data.state, job.result.verification.status], ['APPROVED', 'verified']);
  },
  'submit-review v1/refused': async t => {
    const h = githubHarness(t), pull = await pullOf(h);
    await api(h, 'PATCH', `/repos/${REPO}/issues/${pull.number}`, {state: 'closed'});
    refusedAs(await h.run('submit-review v1', {repository: REPO, number: pull.number, event: 'COMMENT', body: 'Late'}), 'wrong_state');
  },
  'submit-review v1/provider-refusal': async t => { const h = githubHarness(t), pull = await pullOf(h); await failedWith(h, 'submit-review v1', {repository: REPO, number: pull.number, event: 'APPROVE'}, 422); },
  'submit-review v1/unverified': async t => { const h = githubHarness(t), pull = await pullOf(h); await swallowed(h, ROUTES.review, 'submit-review v1', {repository: REPO, number: pull.number, event: 'COMMENT', body: 'Hm'}); },
  'submit-review v1/lost-answer': async t => { const h = githubHarness(t), pull = await pullOf(h); await lost(h, ROUTES.review, 'submit-review v1', {repository: REPO, number: pull.number, event: 'COMMENT', body: 'Hm'}); },
  'merge-pull v1/succeeds': async t => {
    const h = githubHarness(t), pull = await pullOf(h), job = ended(await approved(h, 'merge-pull v1', {repository: REPO, number: pull.number, method: 'merge'}), 'succeeded', null);
    assert.deepEqual([job.result.data.merged, issueOf(h, pull.number).state, fileOf(h, 'notes/feature.txt')], [true, 'closed', 'A feature.\n']);
  },
  'merge-pull v1/refused': async t => {
    const h = githubHarness(t), pull = await pullOf(h);
    await api(h, 'PATCH', `/repos/${REPO}/issues/${pull.number}`, {state: 'closed'});
    refusedAs(await h.run('merge-pull v1', {repository: REPO, number: pull.number, method: 'merge'}), 'wrong_state');
    assert.equal(h.simulator.calls.filter(call => call.route === ROUTES.merge).length, 0);
  },
  'merge-pull v1/provider-refusal': async t => {
    // A draft cannot be merged: GitHub answers 405, and nothing merges.
    const h = githubHarness(t), pull = await pullOf(h, {draft: true});
    await failedWith(h, 'merge-pull v1', {repository: REPO, number: pull.number, method: 'merge'}, 405);
    assert.equal(issueOf(h, pull.number).pull.merged, false);
  },
  'merge-pull v1/unverified': async t => { const h = githubHarness(t), pull = await pullOf(h); await swallowed(h, ROUTES.merge, 'merge-pull v1', {repository: REPO, number: pull.number, method: 'merge'}); },
  'merge-pull v1/lost-answer': async t => { const h = githubHarness(t), pull = await pullOf(h); await lost(h, ROUTES.merge, 'merge-pull v1', {repository: REPO, number: pull.number, method: 'merge'}); assert.equal(issueOf(h, pull.number).pull.merged, true); },
  'run-workflow v1/succeeds': async t => { const h = githubHarness(t); assert.equal(ended(await approved(h, 'run-workflow v1', WORKFLOW), 'succeeded', null).result.verification.status, 'verified'); },
  'run-workflow v1/refused': async t => { const h = githubHarness(t); refusedAs(await h.run('run-workflow v1', {...WORKFLOW, inputs: [{name: 'a', value: '1'}, {name: 'a', value: '2'}]}), 'name_repeated'); assert.deepEqual(writes(h), []); },
  'run-workflow v1/provider-refusal': async t => { const h = githubHarness(t); await failedWith(h, 'run-workflow v1', {...WORKFLOW, inputs: [{name: 'undeclared', value: 'x'}]}, 422); assert.deepEqual(h.simulator.state().repos[REPO].runs, []); },
  'run-workflow v1/unverified': async t => swallowed(githubHarness(t), ROUTES.dispatch, 'run-workflow v1', WORKFLOW),
  'run-workflow v1/lost-answer': async t => { const h = githubHarness(t); await lost(h, ROUTES.dispatch, 'run-workflow v1', WORKFLOW); assert.equal(h.simulator.state().repos[REPO].runs.length, 1); },
};
caseTests(test, MANIFEST, ENTRIES, IMPLEMENTATIONS);

// ---- the live plan (step 18's H0 to H11) ---------------------------------------------------------------------------------------------------------
const PLAN = () => JSON.parse(readFileSync(new URL('../catalog/live-tests/github.json', import.meta.url), 'utf8'));
const planDeps = () => ({entries: ENTRIES, superseded: [], groups: PERMISSION_GROUPS.get('github'), config: PROXY_CONFIGS.get('github'), rules: RULES});

test('the live plan H0 to H12 passes step 12\'s plan check against the shipped file and the narrowed guard, calls all 15 actions, and keeps H7, H9 and H2 as planned, their deletes in the cleanup at the end', () => {
  const checked = checkPlan(PLAN(), planDeps());
  assert.deepEqual(checked.plan.tests.map(item => item.id), ['H0', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'H7', 'H8', 'H11', 'H7-undo', 'H9', 'H10', 'H2-undo', 'H12']);
  assert.deepEqual([...checked.actions.keys()].sort(), ENTRIES.map(entry => `${entry.key}@${entry.version}`).sort());
  assert.deepEqual([checked.plan.readRows, Object.keys(checked.plan.recorded)], [['github.repos.read', 'github.issues.read', 'github.gists.read', 'github.profile.read'], ['issueA', 'issueB', 'issueBTitle', 'issueC']]);
  const steps = id => checked.plan.tests.find(item => item.id === id).steps, kinds = id => steps(id).map(step => Object.keys(step)[0]);
  // Every write test has an undo; H2's comment goes through the one-time Ask on the Never row; branches are deleted on an Ask row.
  for (const item of checked.plan.tests) {
    const writes = [...item.steps, ...(item.undo?.steps ?? [])].some(step => ['oneTimeAsk', 'ask'].includes(Object.keys(step)[0]) || ((step.call ?? step.race) && checked.actions.get((step.call ?? step.race).action).effect !== 'read'));
    if (writes) assert.ok(item.undo, `${item.id} has an undo`);
  }
  assert.deepEqual(checked.plan.tests.find(item => item.id === 'H2').undo, {test: 'H2-undo'});
  assert.equal(steps('H2-undo')[0].oneTimeAsk.row, 'github.permanent.delete');
  assert.deepEqual(kinds('H9'), ['call', 'call', 'call', 'call', 'race', 'owner', 'call', 'call', 'read']);
  assert.deepEqual([steps('H9')[4].race.status, steps('H9')[6].call.expect], [409, {failed: 409}]);
  // The deletes are cleanup at the end, which the owner may leave (--leave; Sami, 2026-10-29): H2-undo deletes H2's comment and H12 this
  // run's three branches. No action test waits on a delete, so leaving them never touches an action's evidence.
  const undoOf = id => checked.plan.tests.find(item => item.id === id).undo;
  assert.deepEqual(['H7', 'H11', 'H7-undo', 'H9'].map(undoOf), [{test: 'H7-undo'}, {test: 'H12'}, {test: 'H12'}, {test: 'H12'}]);
  assert.deepEqual(kinds('H7-undo'), ['call']);
  // H10 reads its run back by the id GitHub answers, inside the action, so it waits on no list and needs no owner step.
  assert.deepEqual([kinds('H10'), steps('H10')[0].call.checks], [['call'], [{pointer: '/branch', equals: 'main'}, {pointer: '/runId', present: true}]]);
  assert.deepEqual(checked.plan.tests.filter(item => item.cleanup).map(item => item.id), ['H2-undo', 'H12']);
  assert.ok(checked.plan.tests.filter(item => !item.cleanup).every(item => ![...item.steps, ...(item.undo?.steps ?? [])].some(step => step.ask || step.oneTimeAsk)), 'no action test asks for a delete');
  // Every repository the plan names is the sandbox.
  const named = JSON.stringify(PLAN()).match(/"repository": ?"[^"]+"/g);
  assert.ok(named.length > 20 && named.every(text => text.endsWith('"samikasasbeh/fabric-sandbox-test"')));
  assert.deepEqual([steps('H12')[0].ask.row, steps('H12')[0].ask.requests.map(request => request.params.branch.$branch)], ['github.code.write', ['', 'base', 'head']]);
});

test('the plan\'s H7 and H9, their placeholders filled for a run, build bytes the narrowed guard passes and run on the simulator: the race, the wrong head refused with 409, the merge', async t => {
  const h = githubHarness(t), plan = PLAN(), runId = 'ABCDEFGH', folder = mkdtempSync(path.join(tmpdir(), 'fabric-github-plan-'));
  t.after(() => rmSync(folder, {recursive: true, force: true}));
  const recorded = {issueA: '1', issueB: '2', issueBTitle: '[SYNTHETIC] Issue B', issueC: '3'};
  const run = {runId, runDate: '2026-10-23', timeZone: 'UTC', recorded, saved: {}};
  const guard = createGuard({appId: 'github', runId, folder, key: randomBytes(32), clock: () => h.now});
  guard.setOwner({email: 'owner@example.com', timeZone: 'UTC', runDate: run.runDate, recorded});
  // The simulator's sandbox stands for samikasasbeh/fabric-sandbox-test: the guard reads each exact request as it would go to GitHub.
  const live = request => ({url: request.url.replace(`/repos/${REPO}/`, '/repos/samikasasbeh/fabric-sandbox-test/'), method: request.method, body: request.body});
  const checked = (key, job) => {
    for (const request of h.prepared(job).content.perform) {
      const verdict = guard.check(live(request));
      assert.equal(verdict.allowed, true, `${key}: ${request.method} ${request.url}: ${verdict.rule}`);
    }
    return job;
  };
  const save = (call, data) => { for (const [name, pointer] of Object.entries(call.save ?? {})) run.saved[name] = pointer.slice(1).split('/').reduce((value, part) => value?.[part], data); };
  for (const id of ['H7', 'H9']) {
    const item = plan.tests.find(test => test.id === id);
    guard.begin(id);
    for (const step of item.steps) {
      const call = step.call ?? step.race;
      if (!call) continue;
      const key = call.action.replace('@', ' v'), args = {...fillPlaceholders(call.args, {run, account: {email: null}}, item), repository: REPO};
      if (TABLE[key.split(' ')[0]][1] === 'read') { save(call, ended(await h.run(key, args), 'succeeded', null).result.data); continue; }
      if (step.race) {
        // Both prepared before either is approved: one lands, one is refused 409, as the runner's race step expects.
        const jobs = [checked(key, await prepared(h, key, args)), checked(key, await prepared(h, key, args))];
        const ends = [await h.approve(jobs[0]), await h.approve(jobs[1])];
        assert.deepEqual(ends.map(job => [job.status, job.providerStatus ?? null]), [['succeeded', null], ['failed', 409]]);
        continue;
      }
      const job = checked(key, await prepared(h, key, args)), sent = h.prepared(job).content.perform.map(live);
      if (call.expect?.failed === 409) {
        // The owner's hand commit on the head branch between the card and its approval.
        h.simulator.push(REPO, fillPlaceholders({$branch: 'head'}, {run, account: {}}, item), {path: 'fabric-live/h9.md', text: 'By hand.\n'});
        ended(await h.approve(job), 'failed', 'provider_failed', {providerStatus: 409, reason: 'content_changed'});
        continue;
      }
      const done = ended(await h.approve(job), 'succeeded', null);
      save(call, done.result.data);
      // A pull this run opened goes through the guard's own wrap, which records it by its number, as the live run does.
      if (key === 'open-pull v1') await guard.wrap(async () => ({status: 201, data: {id: 900000 + done.result.data.number, number: done.result.data.number}}))(sent[0]);
    }
    guard.end();
  }
  const pull = issueOf(h, run.saved.h9Pull);
  assert.deepEqual([pull.pull.merged, pull.pull.base, issueOf(h, run.saved.h7Pull).pull.draft], [true, `fabric/test-${runId}-base`, true]);
  assert.deepEqual(guard.created().filter(entry => entry.kind === 'pull').map(entry => entry.number), [String(run.saved.h9Pull)], 'only H9\'s pull, into a run branch, is recorded');
});

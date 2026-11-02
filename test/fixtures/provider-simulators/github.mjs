// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1): a GitHub simulator for the GitHub actions' tests. It is written from GitHub's REST
// reference (docs.github.com/rest, API version 2022-11-28) and from this comment, and it imports only node built-ins: never lib/, catalog/,
// GitHub's action file or its sign-in, so an action bug and a simulator bug cannot cancel out. Test data only: nothing in lib/ imports it,
// and nothing here calls GitHub.
//
// The service: https://api.github.com (ORIGIN), no base path. One account, the owner {login, id}, whose token holds `scopes` (by default
// FIVE, the scopes of Fabric's GitHub sign-in). The owner has a private sandbox <login>/fabric-sandbox (default branch main, README.md, the
// workflow .github/workflows/fabric-synthetic.yml, the labels bug and fabric-test, issues 1 to 3), a public <login>/public-notes, a secret
// and a public gist, and membership in the organization octo-org, whose private octo-org/platform the owner can push to. Routes (named
// "METHOD /template", as the switches take them):
//   GET    /user, /user/repos, /user/orgs, /gists, /search/issues
//   GET    /repos/{owner}/{repo}, .../contents (the root folder) and .../contents/{+path}; PUT .../contents/{+path}
//   GET    .../git/ref/{+ref}; POST .../git/refs; DELETE .../git/refs/{+ref}
//   POST   .../issues; GET and PATCH .../issues/{issue_number}; GET and POST .../issues/{issue_number}/comments;
//   GET    and DELETE .../issues/comments/{comment_id}; POST .../issues/{issue_number}/labels; DELETE .../issues/{issue_number}/labels/{name}
//   POST   .../pulls; GET .../pulls/{pull_number}; GET .../pulls/{pull_number}/files; PUT .../pulls/{pull_number}/merge;
//   POST   .../pulls/{pull_number}/reviews; GET .../pulls/{pull_number}/reviews/{review_id}
//   GET    .../commits/{ref}/check-runs; GET .../actions/workflows/{workflow_id}; POST .../actions/workflows/{workflow_id}/dispatches;
//   GET    .../actions/workflows/{workflow_id}/runs; GET .../actions/runs/{run_id}
//   Iteration 9 step 6 adds what a poll reads (docs/I07-BUILD-MAP.md step 6): GET .../issues; GET .../issues/comments; GET .../activity; GET .../actions/runs; GET and POST
//   .../releases; GET /notifications and GET .../notifications
//
// Errors use GitHub's shape {message, documentation_url}, a 422 adding errors. Without "Authorization: Bearer <token>" (or "token
// <token>") every route answers 401 Bad credentials. Every authenticated answer carries X-OAuth-Scopes, the token's scopes as "a, b, c",
// and a route that checks scopes carries X-Accepted-OAuth-Scopes. The simulator's own scope table, from GitHub's scopes page: a private
// repository needs repo (else 404 Not Found, as GitHub hides what a token cannot see), a public one reads with no scope and writes with
// public_repo or repo; GET /user/orgs needs read:org (or write:org, admin:org, user: else 403); secret gists list only with gist; a file
// under .github/workflows/ is written only with workflow (else 403, the words GitHub uses for a push). A parent grants its children (repo
// grants public_repo, admin:org and write:org grant read:org, user grants read:user). An unknown route, repository or object answers 404.
// An organization the owner restricted (restrict(org)) answers every request on its repositories 403 with GitHub's documented words.
//
// GitHub's behaviour, as its reference documents it (and, where it is silent, the simulator's own reading, named so):
// - Repositories: GET /user/repos pages by per_page (1 to 100, default 30) and page, newest push first, with a Link header (next, last,
//   prev, first; the request's own query with page set). Every repository answer carries temp_clone_token, as GitHub's schema allows.
// - Git: a commit's tree maps paths to blob shas (git's blob hash). A file answers {type: 'file', encoding: 'base64', content, sha, size}
//   with a line feed after every 60 base64 characters; a folder answers a list sorted by name; a file over 1 MB answers encoding 'none'
//   and empty content. ref is a branch or a commit sha (404 for neither). A contents PUT takes {message, content (base64), sha?, branch?}:
//   for an existing file a sha that is not its blob answers 409 and none answers 422; a sha for a new file answers 409; 201 creates, 200
//   updates, each as a new commit on the branch: {content: {path, sha, ...}, commit: {sha, parents, ...}}. An empty path component answers
//   422. Refs: GET git/ref/heads/<branch> (slashes allowed), POST git/refs {ref: refs/..., sha} (422 when it exists, for an unknown object
//   or a ref outside refs/ with fewer than two slashes), DELETE git/refs/heads/<branch> (204; 422 when it is not there). Deleting a branch
//   closes the open pull requests from it.
// - Issues and pull requests share one number sequence, and every pull request is an issue (GET .../issues/{n} carries pull_request).
//   Create needs a title; labels it names that the repository lacks are created (the simulator's reading). PATCH changes only the fields
//   given; state_reason is read only when state changes (as documented): closing sets completed unless not_planned or duplicate is given,
//   reopening sets reopened, and a reason that does not fit the new state answers 422. Comments: create (body required), list oldest first
//   (per_page, page, Link), get, delete (204). Labels: POST {labels} adds to the issue's labels and answers them all; an empty list removes
//   every label, as GitHub documents; DELETE .../labels/{name} answers the labels left, or 404 Label does not exist. deleteIssue() makes an
//   issue answer 410.
// - Search: q must hold is:issue or is:pull-request (exactly one, else 422); it reads repo:<owner>/<name>, author, assignee, mentions,
//   involves and review-requested as :@me, is:open or is:closed, and quoted words (each in the title or body, any case). Anything else
//   answers 422: the simulator reads only what Fabric writes. Items are issues by number; a private repository the token cannot see and a
//   restricted organization's are left out.
// - Pull requests: open needs head and base branches of the repository (head may be "<owner>:<branch>" for the owner), something new on
//   the head (else 422 No commits between), and no open pull request for the same head (422). mergeable is null, mergeable_state unknown,
//   on the first read after the pull was made or either branch moved, then computed (false with dirty when both sides changed a file the
//   merge base holds differently); a draft reads draft. Files: the three-dot diff, sorted by name, per_page and page, with a unified patch
//   of whole files. Merge: a draft answers 405 Pull Request is still a draft, a closed or merged pull 405 Pull Request is not mergeable; a
//   sha that is not the head answers 409 Head branch was modified (nothing merges); merge_method is merge, squash or rebase (else 422); a
//   conflict answers 405. Success makes one commit on the base (merge: two parents, squash and rebase: one), closes the pull and sets
//   merge_commit_sha: {sha, merged: true, message}.
// - Reviews: event APPROVE, REQUEST_CHANGES or COMMENT, or none, which leaves the review PENDING; COMMENT and REQUEST_CHANGES need a body;
//   approving or requesting changes on your own pull answers 422; commit_id is kept as sent (the head when absent) and must be a commit of
//   the repository. GET .../reviews/{id} reads one back.
// - Check runs per commit (addCheckRun()). Workflows by id or file name, with state. A dispatch {ref, inputs?} needs an active workflow, a
//   branch, and only the inputs the workflow declares, each a string, its required ones present (else 422); it answers 204 and records a
//   workflow_dispatch run on the ref's head, which the runs list (event, branch, per_page, page; newest first) shows only once runLag(n)
//   reads of it have passed. With return_run_details true (a boolean, else 422) it answers 200 {workflow_run_id, run_url, html_url}
//   instead, and GET .../actions/runs/{run_id} reads that run at once, whatever the list's lag, as GitHub does.
// - What a poll reads, from GitHub's REST reference and pagination page; where they are silent the reading is the simulator's own, until a live probe moves it. The issues list
//   takes state (default open), sort (created or updated, default created), direction (default desc) and since (inclusive, on updated_at), and holds pull requests, each with
//   pull_request. The comments list is ascending id by default, takes sort, since and direction, and ignores direction without sort. The activity list holds one row per ref
//   change, newest first, with a nullable actor, one activity_type, and opaque after and before. The runs list is newest created first, a run keeping its place when it finishes or
//   runs again; status takes statuses and conclusions, exclude_pull_requests empties pull_requests, and total_count counts the whole list. A release's created_at is its commit's
//   date, published_at is null on a draft, and a draft is listed only with push access. Notifications are unread only unless all is true, take participating and since, cap at 50
//   (a repository's at 100, 30 by default), have string ids, and carry Last-Modified, the newest thread's second, and X-Poll-Interval. A submitted review and a head push each
//   move a pull request's updated_at (probes 4 and 5).
// - Every list, a GET answering a list or an object with total_count, carries a weak etag of its bytes. A matching If-None-Match answers a body-less 304, and If-Modified-Since
//   does when it equals Last-Modified as a string. A per_page past a list's cap is cut in silence. A repository's list links its pages by /repositories/<id>, as GitHub's page shows.
// - The rate count: all five x-ratelimit headers on every authenticated answer. A request spends one, a 304 spends none, and the count fills at its reset. A spent count answers
//   403, or 429 with exhaust({status}), until then. A renamed repository answers 301 with a location on /repositories/<id>. A retired X-GitHub-Api-Version answers 410.
//
// The network contract is lib/network.mjs's seam: `request` takes its options and answers {status, headers, data}. Refused before sending,
// with sent false: a URL that is not https on 443 or carries credentials, an origin outside allowedOrigins or not GitHub's API, an
// unsupported method or response handling, an unsafe header, a body that is not a string or Buffer, a body over 1 MiB. After sending, with
// sent true: an answer over maxBytes, and drop(). Only the response headers asked for come back (the seam's default list when none are
// named). A 3xx comes back as the seam gives it: under redirect 'report' a body-less answer marked notModified for a 304 and redirected otherwise, with a location only on the
// request's own origin, and under any other handling a failure with sent true.
//
// Every request that reaches the simulator is recorded in `calls`, without its Authorization header: {method, origin, path, route, query,
// headers, body, write, status, at}, `at` being the clock time it arrived. writes() and reads() are the calls to write and read routes;
// state() is a copy of the state. Switches, each for the next call to one route unless {times} says how many: fail(route, {status,
// headers?, data?}) answers that instead and changes nothing; drop(route) applies the call, then throws as a lost answer; swallow(route)
// answers as if applied but changes nothing; oversize(route, bytes) pads the answer; hold(route) returns {reached, release()}. Changes from
// elsewhere: push(repo, branch, {path, text, force, actor}) is someone else committing (the head and the file's sha move); grant(scopes) sets what the
// token holds, and so what X-OAuth-Scopes lists; restrict(org); runLag(n); listLag(route, reads); setPollInterval(n); rename(old, new); retire(version); rateLeft(n);
// exhaust({status}); secondaryLimit({status, retryAfter, times}); editComment(), startRun(), finishRun(), rerun(), publishRelease(), deleteRelease(), notify(), markRead().
// Test data: seedFile(), seedIssues(), author(), deleteIssue(), addWorkflow(), addCheckRun(), addRun(), addRelease(), head().
import {createHash} from 'node:crypto';

export const ORIGIN = 'https://api.github.com';
/** The scopes of Fabric's GitHub sign-in, in the order its consent asks for them. */
export const FIVE = Object.freeze(['read:user', 'repo', 'read:org', 'gist', 'workflow']);
const DOCS = 'https://docs.github.com/rest';
const RESTRICTION_DOCS = 'https://docs.github.com/articles/restricting-access-to-your-organization-s-data/';
/** GitHub's documented words when an organization restricts OAuth App access. */
export const RESTRICTION = org => `Although you appear to have the correct authorization credentials, the \`${org}\` organization has enabled OAuth App access restrictions, meaning that data access to third-parties is limited. For more information on these restrictions, including how to approve this app, visit ${RESTRICTION_DOCS}`;
const DEFAULT_RESPONSE_HEADERS = ['content-type', 'etag', 'retry-after', 'x-ratelimit-remaining'];
const UNSAFE_HEADER = /^(host|connection|transfer-encoding|content-length|upgrade|proxy-.*|forwarded|x-forwarded-.*)$/i;
/** Each parent scope with the scopes it grants, from GitHub's scopes page. */
const IMPLIES = Object.freeze({repo: ['public_repo', 'repo:status', 'repo_deployment', 'repo:invite', 'security_events'], 'admin:org': ['write:org', 'read:org'], 'write:org': ['read:org'],
  user: ['read:user', 'user:email', 'user:follow'], 'admin:repo_hook': ['write:repo_hook', 'read:repo_hook']});
const ORG_SCOPES = 'admin:org, read:org, write:org';
const WORKFLOWS = '.github/workflows/';
const MAX_FILE = 1024 * 1024;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const NUMBER = /^[1-9][0-9]{0,9}$/;
const SHA = /^[0-9a-f]{40}$/;
const NO_SHA = '0'.repeat(40);
const RATE_LIMIT = 5000, HOUR_SECONDS = 3600;

const notSent = message => Object.assign(new Error(message), {sent: false});
const lost = message => Object.assign(new Error(message), {sent: true});
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const sha1 = value => createHash('sha1').update(value).digest('hex');
const blobSha = bytes => sha1(Buffer.concat([Buffer.from(`blob ${bytes.length}\0`), bytes]));
const iso = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const byName = (a, b) => a < b ? -1 : a > b ? 1 : 0;
/** A refusal a handler throws: the GitHub error it answers with. Handlers check everything before they change anything. */
class Refusal extends Error { constructor(answer) { super(answer.data.message); this.answer = answer; } }
const githubError = (status, message, {headers = {}, docs = DOCS, ...extra} = {}) => ({status, headers, data: {message, documentation_url: docs, ...extra}});
const refuse = (status, message, extra) => { throw new Refusal(githubError(status, message, extra)); };
const invalid = (message, field = undefined) => refuse(422, 'Validation Failed', {errors: [{resource: 'Issue', code: 'custom', ...(field ? {field} : {}), message}]});
const notFound = (extra = {}) => refuse(404, 'Not Found', extra);
const ok = (data, headers = {}) => ({status: 200, headers, data});
const created = data => ({status: 201, headers: {}, data});
const empty = () => ({status: 204, headers: {}, data: null});

export class GitHubSimulator {
  /** clock() gives the time changes carry; token is the bearer token the account sends; owner is {login, id}; scopes are the token's scopes. */
  constructor({clock = () => Date.parse('2026-10-23T13:00:00.000Z'), token = 'gho_simulator', owner = {login: 'octo-a', id: 101}, scopes = FIVE} = {}) {
    if (!record(owner) || typeof owner.login !== 'string' || !Number.isSafeInteger(owner.id)) throw new Error('owner is {login, id}.');
    this.clock = clock;
    this.token = token;
    this.scopes = [...scopes];
    this.calls = [];
    this.switches = new Map();
    this.holds = new Map();
    this.restricted = new Set();
    this.lag = 0;
    this.lags = new Map();
    this.retired = new Set();
    this.pollInterval = 60;
    this.secondary = null;
    this.started = this.clock();
    this.rate = {used: 0, reset: Math.floor(this.started / 1000) + HOUR_SECONDS, status: 403};
    const user = {login: owner.login, id: owner.id, type: 'User'};
    this.data = {owner: user, orgs: [{login: 'octo-org', id: 9001, description: 'A synthetic organization'}], repos: {}, blobs: {}, threads: [], renamed: {},
      gists: [{id: 'a1b2c3d4e5f60718293a', public: true, description: 'Public notes'}, {id: 'b2c3d4e5f60718293a4b', public: false, description: 'Secret notes'}],
      next: {repo: 1, issue: 1, comment: 1, review: 1, run: 1, check: 1, workflow: 1, commit: 1, release: 1, activity: 1, thread: 1}};
    const at = this.clock();
    this.#repo({owner: user, name: 'fabric-sandbox', private: true, pushedAt: at,
      files: {'README.md': '# Fabric sandbox\n', [`${WORKFLOWS}fabric-synthetic.yml`]: 'name: Fabric synthetic\non:\n  workflow_dispatch:\n    inputs:\n      greeting:\n        required: false\njobs:\n  echo:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo synthetic\n'},
      labels: ['bug', 'fabric-test'], issues: ['Issue A', '[SYNTHETIC] Issue B', 'Issue C'], workflows: [{file: 'fabric-synthetic.yml', name: 'Fabric synthetic', inputs: {greeting: {required: false}}}]});
    this.#repo({owner: {login: 'octo-org', id: 9001, type: 'Organization'}, name: 'platform', private: true, pushedAt: at - 60_000, files: {'README.md': '# Platform\n'}});
    this.#repo({owner: user, name: 'public-notes', private: false, pushedAt: at - 120_000, files: {'README.md': '# Notes\n'}});
    this.request = this.request.bind(this);
  }
  state() { return structuredClone(this.data); }
  writes() { return this.calls.filter(call => call.write); }
  reads() { return this.calls.filter(call => call.route && !call.write); }
  #switch(kind, route, extra = {}, {times = 1} = {}) {
    if (!Number.isSafeInteger(times) && times !== Infinity) throw new Error('times is a whole number or Infinity.');
    this.switches.set(route, {kind, left: times, ...extra});
    return this;
  }
  fail(route, answer, options) { return this.#switch('fail', route, {answer: structuredClone(answer)}, options); }
  drop(route, options) { return this.#switch('drop', route, {}, options); }
  swallow(route, options) { return this.#switch('swallow', route, {}, options); }
  oversize(route, bytes, options) { return this.#switch('oversize', route, {bytes}, options); }
  hold(route) {
    let reach, release;
    const reached = new Promise(resolve => { reach = resolve; }), released = new Promise(resolve => { release = resolve; });
    this.holds.set(route, {reached, released, reach, release: () => { this.holds.delete(route); release(); }});
    return {reached, release: this.holds.get(route).release};
  }
  #take(route) {
    const entry = this.switches.get(route);
    if (!entry) return null;
    if (--entry.left <= 0) this.switches.delete(route);
    return entry;
  }

  // ---- changes from elsewhere and test data ---------------------------------------------------------------------------------------------
  /** Sets the scopes the token holds: what the simulator enforces and what X-OAuth-Scopes lists. */
  grant(scopes) { this.scopes = [...scopes]; return this; }
  /** The organization restricts OAuth App access: its repositories answer 403 with GitHub's words. */
  restrict(org) { this.restricted.add(org); return this; }
  /** A dispatched run shows in the runs list only after `reads` reads of it. */
  runLag(reads) { if (!Number.isSafeInteger(reads) || reads < 0) throw new Error('runLag takes a whole number of reads.'); this.lag = reads; return this; }
  /** A list shows its state as of now for the next `reads` reads of it. */
  listLag(route, reads) { if (!Number.isSafeInteger(reads) || reads < 1) throw new Error('listLag takes a positive number of reads.'); this.lags.set(route, {left: reads, state: structuredClone(this.data)}); return this; }
  /** The seconds X-Poll-Interval names. */
  setPollInterval(seconds) { this.pollInterval = seconds; return this; }
  /** How many requests the rate count has left. */
  rateLeft(count) { this.rate.used = RATE_LIMIT - count; return this; }
  /** The primary limit is spent: every request answers `status` until the reset. */
  exhaust({status = 403} = {}) { Object.assign(this.rate, {used: RATE_LIMIT, status}); return this; }
  /** The next `times` requests hit a secondary limit, with a retry-after only when one is given. */
  secondaryLimit({status = 403, retryAfter, times = 1} = {}) { this.secondary = {status, retryAfter, left: times}; return this; }
  /** The repository takes a new name, and its old path answers 301. */
  rename(oldName, newName) {
    const repo = this.#own(oldName);
    delete this.data.repos[oldName];
    Object.assign(repo, {name: newName.split('/')[1], fullName: newName});
    this.data.repos[newName] = repo;
    this.data.renamed[oldName] = repo.id;
    return this;
  }
  /** GitHub retires an API version: a request that names it answers 410. */
  retire(version) { this.retired.add(version); return this; }
  /** The head commit of a branch. */
  head(fullName, branch) { return this.#own(fullName).branches[branch] ?? null; }
  /** Someone else commits on the branch: the file at `path` changes, so the head and that file's sha move. Returns the new head. `actor` null lists no actor on the activity row. */
  push(fullName, branch, {path = 'pushed.txt', text, force = false, actor} = {}) {
    const repo = this.#own(fullName), count = this.data.next.commit;
    return this.#commitFiles(this.data, repo, branch, {[path]: Buffer.from(text ?? `Pushed by someone else (${count})\n`)}, 'Someone else\'s commit', {type: force ? 'force_push' : 'push', actor});
  }
  /** `count` issues at one call, each `spacingMs` after the last. */
  seedIssues(fullName, count, {at = this.clock(), spacingMs = 1000} = {}) {
    const repo = this.#own(fullName), first = repo.issues.length;
    for (let index = 0; index < count; index++) this.#newIssue(this.data, repo, {title: `Seeded issue ${first + index + 1}`, user: this.data.owner, at: at + index * spacingMs});
    return this;
  }
  /** Someone edits a comment: its body and updated_at move. */
  editComment(fullName, id, body) {
    const comment = this.#own(fullName).comments.find(item => item.id === id);
    if (!comment) throw new Error(`No comment ${id}.`);
    Object.assign(comment, {body, updated_at: iso(this.clock())});
    return this;
  }
  /** A run that started outside a dispatch, finished when a conclusion is given. Returns its id. */
  addRun(fullName, {branch = 'main', event = 'push', conclusion = null, at = this.clock(), pullRequests = []} = {}) {
    const repo = this.#own(fullName), [workflow] = repo.workflows, id = 5_000_000 + this.data.next.run++, title = workflow?.name ?? 'A run';
    repo.runs.push({id, name: title, display_title: title, workflow_id: workflow?.id ?? 70000, event, head_branch: branch, head_sha: repo.branches[branch], status: conclusion === null ? 'queued' : 'completed', conclusion, run_attempt: 1,
      created_at: iso(at), updated_at: iso(at), html_url: `https://github.com/${fullName}/actions/runs/${id}`, pull_requests: structuredClone(pullRequests), inputs: {}, hiddenReads: 0});
    return id;
  }
  #run(id) {
    const run = Object.values(this.data.repos).flatMap(repo => repo.runs).find(item => item.id === id);
    if (!run) throw new Error(`No run ${id}.`);
    return run;
  }
  startRun(id) { Object.assign(this.#run(id), {status: 'in_progress', updated_at: iso(this.clock())}); return this; }
  finishRun(id, conclusion = 'success') { Object.assign(this.#run(id), {status: 'completed', conclusion, updated_at: iso(this.clock())}); return this; }
  /** Someone runs it again: the same id, the next attempt, and the same place in the list. */
  rerun(id) { const run = this.#run(id); Object.assign(run, {status: 'queued', conclusion: null, run_attempt: run.run_attempt + 1, updated_at: iso(this.clock())}); return this; }
  /** A release, as a run elsewhere would make it. `commitAt` is the date of its commit, and so its created_at. Returns its id. */
  addRelease(fullName, {tag, draft = false, at = this.clock(), commitAt = at, body = null} = {}) {
    const repo = this.#own(fullName);
    return this.#newRelease(this.data, repo, {tag_name: tag, target_commitish: repo.defaultBranch, name: null, body, draft, prerelease: false, created_at: iso(commitAt), published_at: draft ? null : iso(at)}).id;
  }
  #releaseOf(fullName, id) {
    const release = this.#own(fullName).releases.find(item => item.id === id);
    if (!release) throw new Error(`No release ${id}.`);
    return release;
  }
  publishRelease(fullName, id) { Object.assign(this.#releaseOf(fullName, id), {draft: false, published_at: iso(this.clock())}); return this; }
  deleteRelease(fullName, id) { const repo = this.#own(fullName); this.#releaseOf(fullName, id); repo.releases = repo.releases.filter(item => item.id !== id); return this; }
  /** News on a thread: a new one unless `thread` names one. Returns its id, a string as GitHub's is. */
  notify(fullName, {thread, reason, type, title, participating} = {}) {
    const state = this.data, repo = this.#own(fullName), at = iso(this.clock()), held = state.threads.find(item => item.id === thread);
    if (thread !== undefined && !held) throw new Error(`No thread ${thread}.`);
    if (held) { Object.assign(held, {...(reason ? {reason} : {}), ...(title ? {title} : {}), unread: true, updated_at: at}); return held.id; }
    const id = String(9_000_000 + state.next.thread++);
    state.threads.push({id, repo: repo.id, reason: reason ?? 'subscribed', type: type ?? 'Issue', title: title ?? 'A synthetic thread', participating: participating === true, unread: true, updated_at: at});
    return id;
  }
  markRead(thread) { Object.assign(this.data.threads.find(item => item.id === thread), {unread: false}); return this; }
  /** Commits a file (text or bytes) on a branch, unrecorded. Returns the new head. */
  seedFile(fullName, branch, path, content) {
    return this.#commitFiles(this.data, this.#own(fullName), branch, {[path]: Buffer.isBuffer(content) ? content : Buffer.from(String(content))}, `Add ${path}`);
  }
  /** Makes another account the author of an issue or pull request. */
  author(fullName, number, user) { this.#issueOf(this.#own(fullName), number).user = {login: user.login, id: user.id, type: 'User'}; return this; }
  /** The issue was deleted: it answers 410. */
  deleteIssue(fullName, number) { this.#issueOf(this.#own(fullName), number).deleted = true; return this; }
  addWorkflow(fullName, {file, name = file, inputs = {}, state = 'active'}) {
    const repo = this.#own(fullName), workflow = {id: 70000 + this.data.next.workflow++, name, path: `${WORKFLOWS}${file}`, state, inputs: structuredClone(inputs)};
    repo.workflows.push(workflow);
    return structuredClone(workflow);
  }
  addCheckRun(fullName, sha, {name = 'ci', status = 'completed', conclusion = 'success'} = {}) {
    const repo = this.#own(fullName), run = {id: 40000 + this.data.next.check++, name, head_sha: sha, status, conclusion: status === 'completed' ? conclusion : null,
      started_at: iso(this.clock()), completed_at: status === 'completed' ? iso(this.clock()) : null, output: {title: name, summary: `${name} ${conclusion ?? status}`}};
    repo.checks.push(run);
    return structuredClone(run);
  }
  #own(fullName) { const repo = this.data.repos[fullName]; if (!repo) throw new Error(`No repository ${fullName}.`); return repo; }
  #issueOf(repo, number) { const issue = repo.issues.find(item => item.number === number); if (!issue) throw new Error(`No issue ${number}.`); return issue; }

  // ---- the repository model ------------------------------------------------------------------------------------------------------------
  #repo({owner, name, private: hidden, pushedAt, files, labels = [], issues = [], workflows = []}) {
    const state = this.data, fullName = `${owner.login}/${name}`, id = 500_000 + state.next.repo++;
    const repo = {id, name, fullName, owner, private: hidden, defaultBranch: 'main', archived: false, pushedAt, createdAt: pushedAt, description: `${name} (synthetic)`,
      tempCloneToken: `TEMPCLONE${sha1(`clone:${fullName}`).slice(0, 24).toUpperCase()}`, commits: {}, branches: {}, labels: [], issues: [], comments: [], reviews: [], checks: [], workflows: [], runs: [], activity: [], releases: []};
    state.repos[fullName] = repo;
    const tree = {};
    for (const [path, text] of Object.entries(files)) tree[path] = this.#blob(state, Buffer.from(text));
    repo.branches.main = this.#commit(state, repo, {tree, parents: [], message: 'Initial commit'});
    for (const label of labels) this.#label(state, repo, label);
    for (const title of issues) this.#newIssue(state, repo, {title, user: owner, at: pushedAt});
    for (const workflow of workflows) this.addWorkflow(fullName, workflow);
    return repo;
  }
  #blob(state, bytes) { const sha = blobSha(bytes); state.blobs[sha] = bytes.toString('base64'); return sha; }
  #commit(state, repo, {tree, parents, message}) {
    const sha = sha1(JSON.stringify({tree: Object.entries(tree).sort(([a], [b]) => byName(a, b)), parents, message, n: state.next.commit++}));
    repo.commits[sha] = {sha, tree, parents, message, at: this.clock()};
    return sha;
  }
  /** One row of the activity list: a ref change. */
  #activity(state, repo, {type, branch, before, after, actor = state.owner}) {
    repo.activity.push({id: 8_000_000 + state.next.activity++, node_id: `A_${state.next.activity}`, before, after, ref: `refs/heads/${branch}`, timestamp: iso(this.clock()), activity_type: type, actor: actor === null ? null : {...actor}});
  }
  #commitFiles(state, repo, branch, files, message, {type = 'push', actor} = {}) {
    const parent = repo.branches[branch];
    if (!parent) throw new Error(`No branch ${branch}.`);
    const tree = {...repo.commits[parent].tree};
    for (const [path, bytes] of Object.entries(files)) tree[path] = this.#blob(state, bytes);
    repo.branches[branch] = this.#commit(state, repo, {tree, parents: [parent], message});
    repo.pushedAt = this.clock();
    this.#activity(state, repo, {type, branch, before: parent, after: repo.branches[branch], actor});
    for (const issue of repo.issues.filter(item => item.pull?.head === branch && item.state === 'open')) this.#touch(issue);
    return repo.branches[branch];
  }
  #label(state, repo, name) {
    let label = repo.labels.find(item => item.name.toLowerCase() === name.toLowerCase());
    if (!label) { label = {id: 300_000 + repo.labels.length + 1, name, color: 'ededed'}; repo.labels.push(label); }
    return label;
  }
  #newIssue(state, repo, {title, body = null, user, at, labels = [], pull = null}) {
    const number = repo.issues.length + 1, issue = {id: 1_000_000 + state.next.issue++, number, title, body, state: 'open', state_reason: null, user: {...user}, labels: labels.map(name => this.#label(state, repo, name).name),
      created_at: iso(at), updated_at: iso(at), closed_at: null, ...(pull ? {pull} : {})};
    repo.issues.push(issue);
    return issue;
  }
  #newRelease(state, repo, fields) {
    const release = {id: 6_000_000 + state.next.release++, ...fields, author: {...state.owner}};
    repo.releases.push(release);
    return release;
  }
  /** Every commit reachable from a commit, itself included. */
  #ancestors(repo, sha) {
    const seen = new Set(), queue = [sha];
    while (queue.length) { const next = queue.shift(); if (!next || seen.has(next) || !repo.commits[next]) continue; seen.add(next); queue.push(...repo.commits[next].parents); }
    return seen;
  }
  #mergeBase(repo, a, b) {
    const reach = this.#ancestors(repo, a), queue = [b], seen = new Set();
    while (queue.length) { const next = queue.shift(); if (seen.has(next)) continue; seen.add(next); if (reach.has(next)) return next; queue.push(...(repo.commits[next]?.parents ?? [])); }
    return null;
  }
  /** The tree a merge of head into base gives, or null on a conflict: a path both sides changed differently from the merge base. */
  #merged(repo, baseSha, headSha) {
    const base = repo.commits[baseSha].tree, head = repo.commits[headSha].tree, origin = repo.commits[this.#mergeBase(repo, baseSha, headSha)]?.tree ?? {}, out = {};
    for (const path of new Set([...Object.keys(base), ...Object.keys(head), ...Object.keys(origin)])) {
      const [b, h, o] = [base[path], head[path], origin[path]];
      const value = h === o ? b : b === o || b === h ? h : Symbol.for('conflict');
      if (value === Symbol.for('conflict')) return null;
      if (value !== undefined) out[path] = value;
    }
    return out;
  }
  #headOf(repo, issue) { return issue.pull.headSha ?? repo.branches[issue.pull.head] ?? null; }
  /** The mergeable a read shows: null on the first read after the pull was made or a branch moved, then computed. */
  #mergeable(repo, issue) {
    const pull = issue.pull;
    if (issue.state !== 'open') return null;
    const pair = `${this.#headOf(repo, issue)}..${repo.branches[pull.base]}`;
    if (pull.computedFor !== pair) { pull.computedFor = pair; return null; }
    return this.#merged(repo, repo.branches[pull.base], this.#headOf(repo, issue)) !== null;
  }
  #diff(repo, issue) {
    const head = repo.commits[this.#headOf(repo, issue)].tree, base = repo.commits[this.#mergeBase(repo, repo.branches[issue.pull.base] ?? issue.pull.baseSha, this.#headOf(repo, issue))]?.tree ?? {};
    const lines = sha => sha ? Buffer.from(this.data.blobs[sha], 'base64').toString('utf8').split('\n').filter((line, index, all) => index < all.length - 1 || line !== '') : [];
    return [...new Set([...Object.keys(head), ...Object.keys(base)])].filter(path => head[path] !== base[path]).sort(byName).map(path => {
      const before = lines(base[path]), after = lines(head[path]), status = !base[path] ? 'added' : !head[path] ? 'removed' : 'modified';
      const range = (start, count) => count === 1 ? `${start}` : `${count ? start : 0},${count}`;
      const patch = [`@@ -${range(1, before.length)} +${range(1, after.length)} @@`, ...before.map(line => `-${line}`), ...after.map(line => `+${line}`)].join('\n');
      return {sha: head[path] ?? base[path], filename: path, status, additions: after.length, deletions: before.length, changes: after.length + before.length, patch};
    });
  }

  // ---- what answers look like ----------------------------------------------------------------------------------------------------------
  #repoView(repo) {
    const url = `${ORIGIN}/repos/${repo.fullName}`;
    return {id: repo.id, node_id: `R_${repo.id}`, name: repo.name, full_name: repo.fullName, private: repo.private, owner: {...repo.owner}, html_url: `https://github.com/${repo.fullName}`,
      description: repo.description, fork: false, url, archived: repo.archived, disabled: false, visibility: repo.private ? 'private' : 'public', default_branch: repo.defaultBranch,
      pushed_at: iso(repo.pushedAt), created_at: iso(repo.createdAt), updated_at: iso(repo.pushedAt), permissions: {admin: true, maintain: true, push: true, triage: true, pull: true},
      temp_clone_token: repo.tempCloneToken};
  }
  #labelView(repo, name) { const label = repo.labels.find(item => item.name === name); return {id: label.id, node_id: `LA_${label.id}`, name: label.name, color: label.color, default: false, description: null}; }
  #issueView(repo, issue) {
    const url = `${ORIGIN}/repos/${repo.fullName}/issues/${issue.number}`, html = `https://github.com/${repo.fullName}/${issue.pull ? 'pull' : 'issues'}/${issue.number}`;
    return {url, html_url: html, id: issue.id, node_id: `I_${issue.id}`, number: issue.number, title: issue.title, user: {...issue.user}, labels: issue.labels.map(name => this.#labelView(repo, name)),
      state: issue.state, state_reason: issue.state_reason, locked: false, assignees: [], comments: repo.comments.filter(item => item.issue === issue.number).length,
      created_at: issue.created_at, updated_at: issue.updated_at, closed_at: issue.closed_at, author_association: issue.user.id === this.data.owner.id ? 'OWNER' : 'CONTRIBUTOR', body: issue.body,
      ...(issue.pull ? {draft: issue.pull.draft, pull_request: {url: `${ORIGIN}/repos/${repo.fullName}/pulls/${issue.number}`, html_url: html, merged_at: issue.pull.merged_at}} : {})};
  }
  /** A pull request; only a read (`read`) computes mergeable, so the answer that made the pull leaves the first read its null. */
  #pullView(repo, issue, {read = false} = {}) {
    const pull = issue.pull, head = this.#headOf(repo, issue), mergeable = read ? this.#mergeable(repo, issue) : null;
    const side = (ref, sha) => ({label: `${repo.owner.login}:${ref}`, ref, sha, user: {...repo.owner}, repo: this.#repoView(repo)});
    const files = issue.state === 'open' || pull.merged ? this.#diff(repo, issue) : [];
    return {url: `${ORIGIN}/repos/${repo.fullName}/pulls/${issue.number}`, id: issue.id + 5_000_000, node_id: `PR_${issue.id}`, html_url: `https://github.com/${repo.fullName}/pull/${issue.number}`,
      number: issue.number, state: issue.state, locked: false, title: issue.title, user: {...issue.user}, body: issue.body, created_at: issue.created_at, updated_at: issue.updated_at,
      closed_at: issue.closed_at, merged_at: pull.merged_at, merge_commit_sha: pull.merge_commit_sha, draft: pull.draft, head: side(pull.head, head),
      base: side(pull.base, repo.branches[pull.base] ?? pull.baseSha), merged: pull.merged, mergeable,
      mergeable_state: mergeable === null ? 'unknown' : pull.draft ? 'draft' : mergeable ? 'clean' : 'dirty', merged_by: pull.merged ? {...this.data.owner} : null,
      comments: repo.comments.filter(item => item.issue === issue.number).length, review_comments: 0, commits: 1,
      additions: files.reduce((sum, file) => sum + file.additions, 0), deletions: files.reduce((sum, file) => sum + file.deletions, 0), changed_files: files.length};
  }
  #commentView(repo, comment) {
    return {id: comment.id, node_id: `IC_${comment.id}`, url: `${ORIGIN}/repos/${repo.fullName}/issues/comments/${comment.id}`, html_url: `https://github.com/${repo.fullName}/issues/${comment.issue}#issuecomment-${comment.id}`,
      issue_url: `${ORIGIN}/repos/${repo.fullName}/issues/${comment.issue}`, body: comment.body, user: {...comment.user}, created_at: comment.created_at, updated_at: comment.updated_at};
  }
  #reviewView(repo, review) {
    return {id: review.id, node_id: `PRR_${review.id}`, user: {...review.user}, body: review.body, state: review.state, commit_id: review.commit_id,
      html_url: `https://github.com/${repo.fullName}/pull/${review.pull}#pullrequestreview-${review.id}`, pull_request_url: `${ORIGIN}/repos/${repo.fullName}/pulls/${review.pull}`,
      ...(review.submitted_at ? {submitted_at: review.submitted_at} : {})};
  }
  #releaseView(repo, release) {
    const {id, tag_name, ...rest} = release;
    return {url: `${ORIGIN}/repos/${repo.fullName}/releases/${id}`, html_url: `https://github.com/${repo.fullName}/releases/tag/${tag_name}`, id, node_id: `RE_${id}`, tag_name, ...structuredClone(rest)};
  }
  #threadView(repo, thread) {
    const url = `${ORIGIN}/notifications/threads/${thread.id}`;
    return {id: thread.id, unread: thread.unread, reason: thread.reason, updated_at: thread.updated_at, last_read_at: null, subject: {title: thread.title, url: null, latest_comment_url: null, type: thread.type},
      repository: {id: repo.id, name: repo.name, full_name: repo.fullName, private: repo.private, owner: {...repo.owner}, html_url: `https://github.com/${repo.fullName}`}, url, subscription_url: `${url}/subscription`};
  }
  #workflowView(repo, workflow) {
    return {id: workflow.id, node_id: `W_${workflow.id}`, name: workflow.name, path: workflow.path, state: workflow.state, created_at: iso(repo.createdAt), updated_at: iso(repo.createdAt),
      url: `${ORIGIN}/repos/${repo.fullName}/actions/workflows/${workflow.id}`, html_url: `https://github.com/${repo.fullName}/blob/main/${workflow.path}`};
  }
  /** A file as GitHub answers it; `blobs` is the state the answer is read from (a swallowed write's copy holds the blob it made). */
  #fileView(repo, path, sha, ref, blobs = this.data.blobs) {
    const bytes = Buffer.from(blobs[sha], 'base64'), url = `${ORIGIN}/repos/${repo.fullName}/contents/${path}?ref=${ref}`, big = bytes.length > MAX_FILE;
    const content = big ? '' : bytes.toString('base64').replace(/.{60}/g, '$&\n').replace(/\n?$/, '\n');
    return {type: 'file', encoding: big ? 'none' : 'base64', size: bytes.length, name: path.split('/').at(-1), path, content, sha, url, html_url: `https://github.com/${repo.fullName}/blob/${ref}/${path}`};
  }

  // ---- shared checks ------------------------------------------------------------------------------------------------------------------
  /** True when the token holds the scope, or a parent that grants it. */
  #has(scope) { return this.scopes.includes(scope) || this.scopes.some(parent => (IMPLIES[parent] ?? []).includes(scope)); }
  /** The repository a path names, as the token may reach it: 404 when it is not there or hidden, 403 when its organization restricts Fabric. */
  #reach(state, params, {write = false} = {}) {
    const repo = state.repos[`${params.owner}/${params.repo}`];
    if (!repo) notFound();
    if (this.restricted.has(repo.owner.login)) refuse(403, RESTRICTION(repo.owner.login), {docs: RESTRICTION_DOCS});
    if (repo.private ? !this.#has('repo') : write && !this.#has('public_repo')) notFound({headers: {'x-accepted-oauth-scopes': 'repo'}});
    return repo;
  }
  #issue(repo, value, {pull = false} = {}) {
    if (!NUMBER.test(String(value))) notFound();
    const issue = repo.issues.find(item => item.number === Number(value));
    if (!issue || (pull && !issue.pull)) notFound();
    if (issue.deleted) refuse(410, 'This issue was deleted');
    return issue;
  }
  /** A commit sha for a ref: a branch or a commit sha of the repository. */
  #resolve(repo, ref) {
    const name = ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref;
    if (repo.branches[name]) return repo.branches[name];
    if (SHA.test(ref) && repo.commits[ref]) return ref;
    return null;
  }
  /** A list's page size: its default, and past its cap the cap, in silence. */
  #perPage(query, most = 100, fallback = 30) {
    const asked = query.get('per_page') === null ? fallback : Number(query.get('per_page'));
    if (!Number.isSafeInteger(asked) || asked < 1) refuse(422, 'Validation Failed', {errors: [{resource: 'Search', field: 'per_page', code: 'invalid'}]});
    return Math.min(asked, most);
  }
  /** The path a list's links name: a repository's by its id, as GitHub writes them, so they outlast a rename. */
  #linkPath(path) {
    const match = /^\/repos\/([^/]+\/[^/]+)(.*)$/.exec(path);
    return match ? `/repositories/${this.data.repos[match[1]].id}${match[2]}` : path;
  }
  /** per_page and page of a list, 30 a page by default and 100 at most unless the list says otherwise, with GitHub's Link header built on the request's own query. */
  #page(items, query, path, {most, fallback} = {}) {
    const per = this.#perPage(query, most, fallback), page = query.get('page') === null ? 1 : Number(query.get('page'));
    if (!Number.isSafeInteger(page) || page < 1) refuse(422, 'Validation Failed', {errors: [{resource: 'Search', field: 'per_page', code: 'invalid'}]});
    const last = Math.max(1, Math.ceil(items.length / per)), link = (rel, number) => { const next = new URLSearchParams(query); next.set('page', String(number)); return `<${ORIGIN}${this.#linkPath(path)}?${next}>; rel="${rel}"`; };
    const links = [...(page < last ? [link('next', page + 1), link('last', last)] : []), ...(page > 1 ? [link('prev', page - 1), link('first', 1)] : [])];
    return {items: items.slice((page - 1) * per, page * per), headers: links.length ? {link: links.join(', ')} : {}};
  }
  /** A list paged by opaque cursors. `rows` are newest first, with ids that fall: after reads what is older than its row, and before what is newer. */
  #cursorPage(rows, query, path) {
    const per = this.#perPage(query), token = row => Buffer.from(`row:${row.id}`).toString('base64url'), rowOf = name => { const text = query.get(name); return text === null ? null : Number(Buffer.from(text, 'base64url').toString().slice(4)); };
    const after = rowOf('after'), before = rowOf('before'), items = after !== null ? rows.filter(row => row.id < after).slice(0, per) : before !== null ? rows.filter(row => row.id > before).slice(-per) : rows.slice(0, per);
    const link = (rel, name, row) => { const next = new URLSearchParams(query); next.delete('after'); next.delete('before'); next.set(name, token(row)); return `<${ORIGIN}${this.#linkPath(path)}?${next}>; rel="${rel}"`; };
    const links = [...(items.length && rows.at(-1).id < items.at(-1).id ? [link('next', 'after', items.at(-1))] : []), ...(items.length && rows[0].id > items[0].id ? [link('prev', 'before', items[0])] : [])];
    return {items, headers: links.length ? {link: links.join(', ')} : {}};
  }
  /** A list's since, in milliseconds, or null. */
  #since(query) {
    const text = query.get('since'), time = text === null ? null : Date.parse(text);
    if (time !== null && !Number.isFinite(time)) refuse(422, 'Validation Failed', {errors: [{resource: 'Search', field: 'since', code: 'invalid'}]});
    return time;
  }
  #touch(issue) { issue.updated_at = iso(this.clock()); }

  // ---- the routes --------------------------------------------------------------------------------------------------------------------
  #routes = null;
  get routes() {
    const R = (method, template, handle, extra = {}) => ({method, template, handle, ...extra, key: `${method} ${template}`,
      parts: template.slice(1).split('/').map(part => /^\{\+\w+\}$/.test(part) ? {rest: part.slice(2, -1)} : /^\{\w+\}$/.test(part) ? {param: part.slice(1, -1)} : {literal: part})});
    const repo = path => `/repos/{owner}/{repo}${path}`;
    return this.#routes ??= [
      R('GET', '/user', ({state}) => ok({...state.owner, name: 'Octo A', node_id: `U_${state.owner.id}`})),
      R('GET', '/user/repos', ({state, query}) => {
        const list = Object.values(state.repos).filter(item => !this.restricted.has(item.owner.login) && (!item.private || this.#has('repo'))).sort((a, b) => b.pushedAt - a.pushedAt);
        const {items, headers} = this.#page(list, query, '/user/repos');
        return ok(items.map(item => this.#repoView(item)), headers);
      }),
      R('GET', '/user/orgs', ({state}) => {
        if (!this.#has('read:org')) refuse(403, 'You need at least read:org scope or user scope to list your organizations.', {headers: {'x-accepted-oauth-scopes': ORG_SCOPES}});
        return ok(state.orgs.map(org => ({...org})), {'x-accepted-oauth-scopes': ORG_SCOPES});
      }),
      R('GET', '/gists', ({state}) => ok(state.gists.filter(gist => gist.public || this.#has('gist')).map(gist => ({...gist, owner: {...state.owner}, files: {}})))),
      R('GET', '/search/issues', ctx => this.#search(ctx)),
      R('GET', repo(''), ({state, params}) => ok(this.#repoView(this.#reach(state, params)), {'x-accepted-oauth-scopes': 'repo'})),
      R('GET', repo('/contents'), ctx => this.#contents(ctx, '')),
      R('GET', repo('/contents/{+path}'), ctx => this.#contents(ctx, ctx.params.path)),
      R('PUT', repo('/contents/{+path}'), ctx => this.#putFile(ctx), {write: true}),
      R('GET', repo('/git/ref/{+ref}'), ({state, params}) => {
        const found = this.#reach(state, params), name = params.ref.startsWith('heads/') ? params.ref.slice('heads/'.length) : null;
        if (!name || !found.branches[name]) notFound();
        return ok({ref: `refs/heads/${name}`, node_id: `REF_${sha1(name).slice(0, 12)}`, url: `${ORIGIN}/repos/${found.fullName}/git/refs/heads/${name}`,
          object: {sha: found.branches[name], type: 'commit', url: `${ORIGIN}/repos/${found.fullName}/git/commits/${found.branches[name]}`}});
      }),
      R('POST', repo('/git/refs'), ({state, params, body}) => {
        const found = this.#reach(state, params, {write: true});
        if (!record(body) || typeof body.ref !== 'string' || !/^refs\/[^/]+\/./.test(body.ref)) refuse(422, 'Reference name must start with \'refs/\' and have at least two slashes.');
        if (typeof body.sha !== 'string' || !found.commits[body.sha]) refuse(422, 'Object does not exist');
        if (!body.ref.startsWith('refs/heads/')) refuse(422, 'The simulator keeps branches only (refs/heads/).');
        const name = body.ref.slice('refs/heads/'.length);
        if (found.branches[name]) refuse(422, 'Reference already exists');
        found.branches[name] = body.sha;
        this.#activity(state, found, {type: 'branch_creation', branch: name, before: NO_SHA, after: body.sha});
        return {status: 201, headers: {}, data: {ref: body.ref, node_id: `REF_${sha1(name).slice(0, 12)}`, url: `${ORIGIN}/repos/${found.fullName}/git/${body.ref}`,
          object: {sha: body.sha, type: 'commit', url: `${ORIGIN}/repos/${found.fullName}/git/commits/${body.sha}`}}};
      }, {write: true}),
      R('DELETE', repo('/git/refs/{+ref}'), ({state, params}) => {
        const found = this.#reach(state, params, {write: true}), name = params.ref.startsWith('heads/') ? params.ref.slice('heads/'.length) : null;
        if (!name || !found.branches[name]) refuse(422, 'Reference does not exist');
        for (const issue of found.issues.filter(item => item.pull?.head === name && item.state === 'open')) { issue.pull.headSha = found.branches[name]; issue.state = 'closed'; issue.closed_at = iso(this.clock()); this.#touch(issue); }
        this.#activity(state, found, {type: 'branch_deletion', branch: name, before: found.branches[name], after: NO_SHA});
        delete found.branches[name];
        return empty();
      }, {write: true}),
      R('GET', '/notifications', ctx => this.#threads(ctx, {path: '/notifications', most: 50, fallback: 50})),
      R('GET', repo('/notifications'), ctx => { const found = this.#reach(ctx.state, ctx.params); return this.#threads(ctx, {only: found, path: `/repos/${found.fullName}/notifications`, most: 100, fallback: 30}); }),
      R('GET', repo('/activity'), ({state, params, query}) => {
        const found = this.#reach(state, params), kind = query.get('activity_type'), rows = found.activity.filter(row => kind === null || row.activity_type === kind).reverse();
        const {items, headers} = this.#cursorPage(rows, query, `/repos/${found.fullName}/activity`);
        return ok(structuredClone(items), headers);
      }),
      R('GET', repo('/issues'), ctx => this.#issues(ctx)),
      R('GET', repo('/issues/comments'), ctx => this.#comments(ctx)),
      R('GET', repo('/actions/runs'), ({state, params, query}) => {
        const found = this.#reach(state, params), status = query.get('status'), plain = query.get('exclude_pull_requests') === 'true';
        const runs = found.runs.filter(run => --run.hiddenReads < 0).filter(run => status === null || run.status === status || run.conclusion === status).sort((a, b) => byName(b.created_at, a.created_at) || b.id - a.id);
        const {items, headers} = this.#page(runs, query, `/repos/${found.fullName}/actions/runs`);
        return ok({total_count: runs.length, workflow_runs: items.map(({hiddenReads, inputs, ...run}) => (void hiddenReads, void inputs, {...run, pull_requests: plain ? [] : run.pull_requests}))}, headers);
      }),
      R('GET', repo('/releases'), ({state, params, query}) => {
        const found = this.#reach(state, params), pushes = this.#has(found.private ? 'repo' : 'public_repo');
        const list = found.releases.filter(item => !item.draft || pushes).sort((a, b) => byName(b.created_at, a.created_at) || b.id - a.id), {items, headers} = this.#page(list, query, `/repos/${found.fullName}/releases`);
        return ok(items.map(item => this.#releaseView(found, item)), headers);
      }),
      R('POST', repo('/releases'), ctx => this.#release(ctx), {write: true}),
      R('POST', repo('/issues'), ({state, params, body}) => {
        const found = this.#reach(state, params, {write: true});
        if (!record(body) || typeof body.title !== 'string' || !body.title) invalid('title wasn\'t supplied.', 'title');
        if (body.body !== undefined && body.body !== null && typeof body.body !== 'string') invalid('body is not a string.', 'body');
        if (body.labels !== undefined && (!Array.isArray(body.labels) || body.labels.some(name => typeof name !== 'string' || !name))) invalid('labels is not a list of names.', 'labels');
        return created(this.#issueView(found, this.#newIssue(state, found, {title: body.title, body: body.body ?? null, user: state.owner, at: this.clock(), labels: body.labels ?? []})));
      }, {write: true}),
      R('GET', repo('/issues/{issue_number}'), ({state, params}) => { const found = this.#reach(state, params); return ok(this.#issueView(found, this.#issue(found, params.issue_number))); }),
      R('PATCH', repo('/issues/{issue_number}'), ctx => this.#patchIssue(ctx), {write: true}),
      R('GET', repo('/issues/{issue_number}/comments'), ({state, params, query}) => {
        const found = this.#reach(state, params), issue = this.#issue(found, params.issue_number);
        const {items, headers} = this.#page(found.comments.filter(item => item.issue === issue.number), query, `/repos/${found.fullName}/issues/${issue.number}/comments`);
        return ok(items.map(item => this.#commentView(found, item)), headers);
      }),
      R('POST', repo('/issues/{issue_number}/comments'), ({state, params, body}) => {
        const found = this.#reach(state, params, {write: true}), issue = this.#issue(found, params.issue_number);
        if (!record(body) || typeof body.body !== 'string' || !body.body) invalid('body wasn\'t supplied.', 'body');
        const at = iso(this.clock()), comment = {id: 2_000_000 + state.next.comment++, issue: issue.number, body: body.body, user: {...state.owner}, created_at: at, updated_at: at};
        found.comments.push(comment);
        this.#touch(issue);
        return created(this.#commentView(found, comment));
      }, {write: true}),
      R('GET', repo('/issues/comments/{comment_id}'), ({state, params}) => {
        const found = this.#reach(state, params), comment = found.comments.find(item => String(item.id) === params.comment_id);
        return comment ? ok(this.#commentView(found, comment)) : notFound();
      }),
      R('DELETE', repo('/issues/comments/{comment_id}'), ({state, params}) => {
        const found = this.#reach(state, params, {write: true}), index = found.comments.findIndex(item => String(item.id) === params.comment_id);
        if (index < 0) notFound();
        found.comments.splice(index, 1);
        return empty();
      }, {write: true}),
      R('POST', repo('/issues/{issue_number}/labels'), ({state, params, body}) => {
        const found = this.#reach(state, params, {write: true}), issue = this.#issue(found, params.issue_number), names = Array.isArray(body) ? body : body?.labels;
        if (!Array.isArray(names) || names.some(name => typeof name !== 'string' || !name)) invalid('labels is not a list of names.', 'labels');
        if (names.length === 0) issue.labels = [];
        for (const name of names) { const label = this.#label(state, found, name); if (!issue.labels.includes(label.name)) issue.labels.push(label.name); }
        this.#touch(issue);
        return ok(issue.labels.map(name => this.#labelView(found, name)));
      }, {write: true}),
      R('DELETE', repo('/issues/{issue_number}/labels/{name}'), ({state, params}) => {
        const found = this.#reach(state, params, {write: true}), issue = this.#issue(found, params.issue_number), name = issue.labels.find(item => item.toLowerCase() === params.name.toLowerCase());
        if (!name) refuse(404, 'Label does not exist');
        issue.labels = issue.labels.filter(item => item !== name);
        this.#touch(issue);
        return ok(issue.labels.map(item => this.#labelView(found, item)));
      }, {write: true}),
      R('POST', repo('/pulls'), ctx => this.#openPull(ctx), {write: true}),
      R('GET', repo('/pulls/{pull_number}'), ({state, params}) => { const found = this.#reach(state, params); return ok(this.#pullView(found, this.#issue(found, params.pull_number, {pull: true}), {read: true})); }),
      R('GET', repo('/pulls/{pull_number}/files'), ({state, params, query}) => {
        const found = this.#reach(state, params), issue = this.#issue(found, params.pull_number, {pull: true});
        const {items, headers} = this.#page(this.#diff(found, issue), query, `/repos/${found.fullName}/pulls/${issue.number}/files`);
        return ok(items, headers);
      }),
      R('PUT', repo('/pulls/{pull_number}/merge'), ctx => this.#merge(ctx), {write: true}),
      R('POST', repo('/pulls/{pull_number}/reviews'), ctx => this.#review(ctx), {write: true}),
      R('GET', repo('/pulls/{pull_number}/reviews/{review_id}'), ({state, params}) => {
        const found = this.#reach(state, params), issue = this.#issue(found, params.pull_number, {pull: true}), review = found.reviews.find(item => item.pull === issue.number && String(item.id) === params.review_id);
        return review ? ok(this.#reviewView(found, review)) : notFound();
      }),
      R('GET', repo('/commits/{ref}/check-runs'), ({state, params, query}) => {
        const found = this.#reach(state, params), sha = this.#resolve(found, params.ref);
        if (!sha) refuse(422, `No commit found for SHA: ${params.ref}`);
        const runs = found.checks.filter(item => item.head_sha === sha), {items, headers} = this.#page(runs, query, `/repos/${found.fullName}/commits/${params.ref}/check-runs`);
        return ok({total_count: runs.length, check_runs: items.map(item => ({...structuredClone(item), html_url: `https://github.com/${found.fullName}/runs/${item.id}`}))}, headers);
      }),
      R('GET', repo('/actions/workflows/{workflow_id}'), ({state, params}) => { const found = this.#reach(state, params); return ok(this.#workflowView(found, this.#workflow(found, params.workflow_id))); }),
      R('POST', repo('/actions/workflows/{workflow_id}/dispatches'), ctx => this.#dispatch(ctx), {write: true}),
      R('GET', repo('/actions/workflows/{workflow_id}/runs'), ({state, params, query}) => {
        const found = this.#reach(state, params), workflow = this.#workflow(found, params.workflow_id);
        const runs = found.runs.filter(run => run.workflow_id === workflow.id).filter(run => run.hiddenReads-- <= 0)
          .filter(run => (query.get('event') === null || run.event === query.get('event')) && (query.get('branch') === null || run.head_branch === query.get('branch'))).reverse();
        const {items, headers} = this.#page(runs, query, `/repos/${found.fullName}/actions/workflows/${params.workflow_id}/runs`);
        return ok({total_count: runs.length, workflow_runs: items.map(({hiddenReads, inputs, ...run}) => (void hiddenReads, void inputs, {...run}))}, headers);
      }),
      R('GET', repo('/actions/runs/{run_id}'), ({state, params}) => {
        const found = this.#reach(state, params), run = found.runs.find(item => String(item.id) === params.run_id);
        if (!run) notFound();
        const {hiddenReads, inputs, ...view} = run;
        void hiddenReads, void inputs;
        return ok(view);
      }),
    ];
  }

  #issues({state, params, query}) {
    const found = this.#reach(state, params), wanted = query.get('state') ?? 'open', sort = query.get('sort') ?? 'created', direction = query.get('direction') ?? 'desc', since = this.#since(query), field = {created: 'created_at', updated: 'updated_at'}[sort];
    if (!['open', 'closed', 'all'].includes(wanted) || !field || !['asc', 'desc'].includes(direction)) refuse(422, 'Validation Failed', {errors: [{resource: 'Search', code: 'invalid'}]});
    const list = found.issues.filter(item => !item.deleted && (wanted === 'all' || item.state === wanted) && (since === null || Date.parse(item.updated_at) >= since)).sort((a, b) => (direction === 'asc' ? 1 : -1) * (byName(a[field], b[field]) || a.number - b.number));
    const {items, headers} = this.#page(list, query, `/repos/${found.fullName}/issues`);
    return ok(items.map(item => this.#issueView(found, item)), headers);
  }
  #comments({state, params, query}) {
    const found = this.#reach(state, params), sort = query.get('sort'), direction = query.get('direction') ?? 'asc', since = this.#since(query), field = {created: 'created_at', updated: 'updated_at'}[sort ?? 'created'];
    if (!field || !['asc', 'desc'].includes(direction)) refuse(422, 'Validation Failed', {errors: [{resource: 'Search', code: 'invalid'}]});
    const list = found.comments.filter(item => since === null || Date.parse(item.updated_at) >= since), rank = (a, b) => (sort === null || direction === 'asc' ? 1 : -1) * (sort === null ? a.id - b.id : byName(a[field], b[field]) || a.id - b.id);
    const {items, headers} = this.#page(list.sort(rank), query, `/repos/${found.fullName}/issues/comments`);
    return ok(items.map(item => this.#commentView(found, item)), headers);
  }
  #release({state, params, body}) {
    const found = this.#reach(state, params, {write: true}), given = record(body) ? body : {}, target = given.target_commitish ?? found.defaultBranch, sha = typeof target === 'string' ? this.#resolve(found, target) : null;
    const invalidRelease = (field, code) => refuse(422, 'Validation Failed', {errors: [{resource: 'Release', field, code}]});
    if (typeof given.tag_name !== 'string' || !given.tag_name) invalidRelease('tag_name', 'missing_field');
    if (found.releases.some(item => item.tag_name === given.tag_name)) invalidRelease('tag_name', 'already_exists');
    if (!sha) invalidRelease('target_commitish', 'invalid');
    return created(this.#releaseView(found, this.#newRelease(state, found, {tag_name: given.tag_name, target_commitish: target, name: given.name ?? null, body: given.body ?? null, draft: given.draft === true, prerelease: given.prerelease === true,
      created_at: iso(found.commits[sha].at), published_at: given.draft === true ? null : iso(this.clock())})));
  }
  /** The notifications an account or one repository (`only`) lists. Last-Modified is the newest thread's second, whatever this query shows. */
  #threads({state, query}, {only = null, path, most, fallback}) {
    if (!this.#has('notifications') && !this.#has('repo')) refuse(403, 'Resource not accessible by integration');
    const since = this.#since(query), all = query.get('all') === 'true', mine = query.get('participating') === 'true', repos = new Map(Object.values(state.repos).map(repo => [repo.id, repo]));
    const threads = state.threads.filter(item => !this.restricted.has(repos.get(item.repo).owner.login) && (only === null || item.repo === only.id));
    const shown = threads.filter(item => (all || item.unread) && (!mine || item.participating) && (since === null || Date.parse(item.updated_at) >= since)).sort((a, b) => byName(b.updated_at, a.updated_at) || Number(b.id) - Number(a.id));
    const {items, headers} = this.#page(shown, query, path, {most, fallback}), newest = threads.reduce((high, item) => Math.max(high, Date.parse(item.updated_at)), this.started);
    return ok(items.map(item => this.#threadView(repos.get(item.repo), item)), {...headers, 'last-modified': new Date(newest).toUTCString(), 'x-poll-interval': this.pollInterval});
  }
  #contents({state, params, query}, path) {
    const found = this.#reach(state, params), ref = query.get('ref') ?? found.defaultBranch, sha = this.#resolve(found, ref);
    if (!sha) refuse(404, `No commit found for the ref ${ref}`);
    const tree = found.commits[sha].tree;
    if (path && tree[path]) return ok(this.#fileView(found, path, tree[path], ref), {'x-accepted-oauth-scopes': 'repo'});
    const prefix = path ? `${path}/` : '', entries = new Map();
    for (const [file, blob] of Object.entries(tree)) {
      if (!file.startsWith(prefix)) continue;
      const [name, ...rest] = file.slice(prefix.length).split('/');
      entries.set(name, rest.length ? {type: 'dir', name, path: `${prefix}${name}`, sha: sha1(`tree:${prefix}${name}:${sha}`), size: 0} : {type: 'file', name, path: file, sha: blob, size: Buffer.from(state.blobs[blob], 'base64').length});
    }
    if (!entries.size) notFound();
    return ok([...entries.values()].sort((a, b) => byName(a.name, b.name)), {'x-accepted-oauth-scopes': 'repo'});
  }
  #putFile({state, params, body}) {
    const found = this.#reach(state, params, {write: true}), path = params.path;
    if (path.split('/').some(part => part === '' || part === '.' || part === '..')) refuse(422, 'path contains a malformed path component');
    if (path.startsWith(WORKFLOWS) && !this.#has('workflow')) refuse(403, `refusing to allow an OAuth App to create or update workflow \`${path}\` without \`workflow\` scope`, {headers: {'x-accepted-oauth-scopes': 'workflow'}});
    if (!record(body) || typeof body.message !== 'string' || !body.message) invalid('message wasn\'t supplied.', 'message');
    if (typeof body.content !== 'string' || !BASE64.test(body.content) || body.content.length % 4 !== 0) invalid('content is not valid Base64', 'content');
    const branch = body.branch ?? found.defaultBranch;
    if (typeof branch !== 'string' || !found.branches[branch]) refuse(404, `Branch ${branch} not found`);
    const current = found.commits[found.branches[branch]].tree[path];
    if (current && body.sha === undefined) refuse(422, 'Invalid request.\n\n"sha" wasn\'t supplied.');
    if (current ? body.sha !== current : body.sha !== undefined) refuse(409, `${path} does not match ${body.sha}`);
    const parent = found.branches[branch], head = this.#commitFiles(state, found, branch, {[path]: Buffer.from(body.content, 'base64')}, body.message), blob = found.commits[head].tree[path];
    const view = this.#fileView(found, path, blob, branch, state.blobs), {content: _content, encoding: _encoding, ...shown} = view;
    return {status: current ? 200 : 201, headers: {}, data: {content: shown, commit: {sha: head, message: body.message, parents: [{sha: parent}], url: `${ORIGIN}/repos/${found.fullName}/git/commits/${head}`}}};
  }
  #patchIssue({state, params, body}) {
    const found = this.#reach(state, params, {write: true}), issue = this.#issue(found, params.issue_number);
    if (!record(body)) invalid('The body is not an object.');
    for (const field of ['title', 'body']) if (body[field] !== undefined && body[field] !== null && typeof body[field] !== 'string') invalid(`${field} is not a string.`, field);
    if (body.title !== undefined && !body.title) invalid('title cannot be blank.', 'title');
    if (body.state !== undefined && !['open', 'closed'].includes(body.state)) invalid('state is open or closed.', 'state');
    if (body.state_reason !== undefined && body.state_reason !== null && !['completed', 'not_planned', 'duplicate', 'reopened'].includes(body.state_reason)) invalid('state_reason is not valid.', 'state_reason');
    const changes = body.state !== undefined && body.state !== issue.state;
    if (changes && body.state === 'open' && body.state_reason && body.state_reason !== 'reopened') invalid(`state_reason ${body.state_reason} does not fit an open issue.`, 'state_reason');
    if (changes && body.state === 'closed' && body.state_reason === 'reopened') invalid('state_reason reopened does not fit a closed issue.', 'state_reason');
    if (body.title !== undefined) issue.title = body.title;
    if (body.body !== undefined) issue.body = body.body;
    if (changes) {
      issue.state = body.state;
      issue.state_reason = body.state === 'open' ? 'reopened' : body.state_reason ?? 'completed';
      issue.closed_at = body.state === 'closed' ? iso(this.clock()) : null;
      if (issue.pull && body.state === 'closed') issue.pull.headSha = found.branches[issue.pull.head] ?? issue.pull.headSha;
      if (issue.pull && body.state === 'open') issue.pull.headSha = null;
    }
    this.#touch(issue);
    return ok(this.#issueView(found, issue));
  }
  #openPull({state, params, body}) {
    const found = this.#reach(state, params, {write: true});
    if (!record(body) || typeof body.title !== 'string' || !body.title) refuse(422, 'Validation Failed', {errors: [{resource: 'PullRequest', field: 'title', code: 'missing_field'}]});
    const head = typeof body.head === 'string' && body.head.startsWith(`${found.owner.login}:`) ? body.head.slice(found.owner.login.length + 1) : body.head;
    for (const [field, name] of [['head', head], ['base', body.base]]) if (typeof name !== 'string' || !found.branches[name]) refuse(422, 'Validation Failed', {errors: [{resource: 'PullRequest', field, code: 'invalid'}]});
    if (body.draft !== undefined && typeof body.draft !== 'boolean') refuse(422, 'Validation Failed', {errors: [{resource: 'PullRequest', field: 'draft', code: 'invalid'}]});
    if (this.#ancestors(found, found.branches[body.base]).has(found.branches[head])) refuse(422, 'Validation Failed', {errors: [{resource: 'PullRequest', code: 'custom', message: `No commits between ${body.base} and ${head}`}]});
    if (found.issues.some(item => item.pull?.head === head && item.state === 'open')) refuse(422, 'Validation Failed', {errors: [{resource: 'PullRequest', code: 'custom', message: `A pull request already exists for ${found.owner.login}:${head}.`}]});
    const pull = {head, base: body.base, baseSha: found.branches[body.base], headSha: null, draft: body.draft === true, merged: false, merged_at: null, merge_commit_sha: null, computedFor: null};
    return created(this.#pullView(found, this.#newIssue(state, found, {title: body.title, body: typeof body.body === 'string' ? body.body : null, user: state.owner, at: this.clock(), pull})));
  }
  #merge({state, params, body}) {
    const found = this.#reach(state, params, {write: true}), issue = this.#issue(found, params.pull_number, {pull: true}), pull = issue.pull;
    if (pull.draft) refuse(405, 'Pull Request is still a draft');
    if (issue.state !== 'open') refuse(405, 'Pull Request is not mergeable');
    const given = record(body) ? body : {}, head = this.#headOf(found, issue), method = given.merge_method ?? 'merge';
    if (given.sha !== undefined && given.sha !== head) refuse(409, 'Head branch was modified. Review and try the merge again.');
    if (!['merge', 'squash', 'rebase'].includes(method)) refuse(422, 'Validation Failed', {errors: [{resource: 'PullRequest', field: 'merge_method', code: 'invalid'}]});
    const baseSha = found.branches[pull.base], tree = this.#merged(found, baseSha, head);
    if (tree === null) refuse(405, 'Pull Request is not mergeable');
    const title = typeof given.commit_title === 'string' ? given.commit_title : `Merge pull request #${issue.number}`;
    const sha = this.#commit(state, found, {tree, parents: method === 'merge' ? [baseSha, head] : [baseSha], message: typeof given.commit_message === 'string' ? `${title}\n\n${given.commit_message}` : title});
    found.branches[pull.base] = sha;
    found.pushedAt = this.clock();
    this.#activity(state, found, {type: 'pr_merge', branch: pull.base, before: baseSha, after: sha});
    Object.assign(pull, {merged: true, merged_at: iso(this.clock()), merge_commit_sha: sha, headSha: head});
    Object.assign(issue, {state: 'closed', state_reason: 'completed', closed_at: iso(this.clock())});
    this.#touch(issue);
    return ok({sha, merged: true, message: 'Pull Request successfully merged'});
  }
  #review({state, params, body}) {
    const found = this.#reach(state, params, {write: true}), issue = this.#issue(found, params.pull_number, {pull: true}), given = record(body) ? body : {};
    const event = given.event, text = typeof given.body === 'string' ? given.body : '';
    if (event !== undefined && !['APPROVE', 'REQUEST_CHANGES', 'COMMENT'].includes(event)) refuse(422, 'Unprocessable Entity', {errors: [`${event} is not a review event.`]});
    if ((event === 'COMMENT' || event === 'REQUEST_CHANGES') && !text) refuse(422, 'Unprocessable Entity', {errors: ['Body is required for comment and request changes events.']});
    if ((event === 'APPROVE' || event === 'REQUEST_CHANGES') && issue.user.id === state.owner.id) refuse(422, 'Unprocessable Entity', {errors: [`Can not ${event === 'APPROVE' ? 'approve' : 'request changes on'} your own pull request`]});
    const commit = given.commit_id ?? this.#headOf(found, issue);
    if (typeof commit !== 'string' || !found.commits[commit]) refuse(422, 'Unprocessable Entity', {errors: ['commit_id is not part of the pull request']});
    const stateOf = {APPROVE: 'APPROVED', REQUEST_CHANGES: 'CHANGES_REQUESTED', COMMENT: 'COMMENTED'};
    const review = {id: 3_000_000 + state.next.review++, pull: issue.number, user: {...state.owner}, body: text, commit_id: commit,
      state: event === undefined ? 'PENDING' : stateOf[event], ...(event === undefined ? {} : {submitted_at: iso(this.clock())})};
    found.reviews.push(review);
    if (event !== undefined) this.#touch(issue);
    return ok(this.#reviewView(found, review));
  }
  #workflow(repo, id) {
    const workflow = repo.workflows.find(item => String(item.id) === id || item.path === `${WORKFLOWS}${id}`);
    return workflow ?? notFound();
  }
  #dispatch({state, params, body}) {
    const found = this.#reach(state, params, {write: true}), workflow = this.#workflow(found, params.workflow_id), given = record(body) ? body : {};
    if (workflow.state !== 'active') refuse(422, `Cannot trigger a 'workflow_dispatch' on a ${workflow.state} workflow`);
    const ref = typeof given.ref === 'string' && given.ref.startsWith('refs/heads/') ? given.ref.slice('refs/heads/'.length) : given.ref;
    if (typeof ref !== 'string' || !found.branches[ref]) refuse(422, `No ref found for: ${given.ref}`);
    const inputs = given.inputs ?? {};
    if (!record(inputs)) refuse(422, 'inputs is not an object');
    const unexpected = Object.keys(inputs).filter(name => !Object.hasOwn(workflow.inputs, name));
    if (unexpected.length) refuse(422, `Unexpected inputs provided: ${JSON.stringify(unexpected)}`);
    if (Object.values(inputs).some(value => typeof value !== 'string')) refuse(422, 'Invalid value for inputs: every input is a string');
    const required = Object.entries(workflow.inputs).filter(([name, spec]) => spec.required && inputs[name] === undefined).map(([name]) => name);
    if (required.length) refuse(422, `Required input '${required[0]}' not provided`);
    if (given.return_run_details !== undefined && typeof given.return_run_details !== 'boolean') refuse(422, 'return_run_details is not a boolean');
    const id = 5_000_000 + state.next.run++, htmlUrl = `https://github.com/${found.fullName}/actions/runs/${id}`;
    found.runs.push({id, name: workflow.name, display_title: workflow.name, workflow_id: workflow.id, event: 'workflow_dispatch', head_branch: ref, head_sha: found.branches[ref], status: 'queued',
      conclusion: null, run_attempt: 1, created_at: iso(this.clock()), updated_at: iso(this.clock()), html_url: htmlUrl, pull_requests: [], inputs: {...inputs}, hiddenReads: this.lag});
    if (given.return_run_details !== true) return empty();
    return ok({workflow_run_id: id, run_url: `https://api.github.com/repos/${found.fullName}/actions/runs/${id}`, html_url: htmlUrl});
  }
  #search({state, query}) {
    const q = query.get('q') ?? '', tokens = q.match(/"[^"]*"|\S+/g) ?? [];
    if ((q.match(/"/g) ?? []).length % 2) invalid('The query has an unclosed quote.', 'q');
    const terms = {type: [], repo: null, me: [], state: null, words: []};
    for (const token of tokens) {
      let match;
      if (token.startsWith('"')) terms.words.push(token.slice(1, -1).toLowerCase());
      else if (token === 'is:issue' || token === 'is:pull-request') terms.type.push(token.slice(3));
      else if (token === 'is:open' || token === 'is:closed') terms.state = token.slice(3);
      else if ((match = /^repo:([^/\s]+)\/([^/\s]+)$/.exec(token))) terms.repo = `${match[1]}/${match[2]}`;
      else if ((match = /^(author|assignee|mentions|involves|review-requested):@me$/.exec(token))) terms.me.push(match[1]);
      else invalid(`The simulator does not read ${token}.`, 'q');
    }
    if (terms.type.length !== 1) refuse(422, 'Validation Failed', {errors: [{resource: 'Search', field: 'q', code: 'invalid', message: 'Query must include \'is:issue\' or \'is:pull-request\''}]});
    const login = state.owner.login, mine = (issue, repo) => ({
      author: issue.user.login === login, assignee: false, mentions: (issue.body ?? '').includes(`@${login}`), 'review-requested': false,
      involves: issue.user.login === login || (issue.body ?? '').includes(`@${login}`) || repo.comments.some(item => item.issue === issue.number && item.user.login === login)});
    const items = [];
    for (const repo of Object.values(state.repos)) {
      if (this.restricted.has(repo.owner.login) || (repo.private && !this.#has('repo')) || (terms.repo && repo.fullName !== terms.repo)) continue;
      for (const issue of repo.issues) {
        if (issue.deleted || Boolean(issue.pull) !== (terms.type[0] === 'pull-request') || (terms.state && issue.state !== terms.state)) continue;
        if (!terms.me.every(kind => mine(issue, repo)[kind])) continue;
        const text = `${issue.title}\n${issue.body ?? ''}`.toLowerCase();
        if (terms.words.every(word => text.includes(word))) items.push({...this.#issueView(repo, issue), score: 1});
      }
    }
    const {items: page, headers} = this.#page(items, query, '/search/issues');
    return ok({total_count: items.length, incomplete_results: false, items: page}, headers);
  }

  /** The route a method and decoded path take, with its parameters; literals win over parameters, and a {+rest} takes the remaining segments. */
  #routeOf(method, path) {
    const segments = path === '/' ? [] : path.slice(1).split('/').map(segment => { try { return decodeURIComponent(segment); } catch { return segment; } });
    let best = null;
    for (const route of this.routes) {
      if (route.method !== method) continue;
      const params = {};
      let score = 0, matched = true;
      for (let index = 0; index < route.parts.length && matched; index++) {
        const part = route.parts[index];
        if (part.rest) { if (index >= segments.length) matched = false; else params[part.rest] = segments.slice(index).join('/'); break; }
        if (index >= segments.length) matched = false;
        else if (part.literal !== undefined) { if (part.literal === segments[index]) score += 2; else matched = false; }
        else if (segments[index] === '') matched = false;
        else { params[part.param] = segments[index]; score += 1; }
      }
      if (matched && !route.parts.some(part => part.rest) && route.parts.length !== segments.length) matched = false;
      if (matched && (!best || score > best.score)) best = {route, params, score};
    }
    return best;
  }

  /** The rate count as of now: a new hour fills it. */
  #rateNow() {
    if (this.clock() >= this.rate.reset * 1000) Object.assign(this.rate, {used: 0, reset: Math.floor(this.clock() / 1000) + HOUR_SECONDS});
    return this.rate;
  }
  /** What a limit answers, or null: a spent primary count until its reset, and a secondary limit for as many answers as the switch says. */
  #limited() {
    const {used, status} = this.#rateNow(), {secondary} = this;
    if (used >= RATE_LIMIT) return githubError(status, `API rate limit exceeded for user ID ${this.data.owner.id}.`);
    if (!secondary) return null;
    if (--secondary.left <= 0) this.secondary = null;
    return githubError(secondary.status, 'You have exceeded a secondary rate limit. Please wait a few minutes before you try again.', {headers: secondary.retryAfter === undefined ? {} : {'retry-after': secondary.retryAfter}});
  }
  /** The 301 of a repository's old path, or null. */
  #moved(target) {
    const [, root, owner, name, ...rest] = target.pathname.split('/'), id = root === 'repos' ? this.data.renamed[`${owner}/${name}`] : undefined;
    if (id === undefined) return null;
    const location = `${[`${ORIGIN}/repositories/${id}`, ...rest].join('/')}${target.search}`;
    return {status: 301, headers: {location}, data: {message: 'Moved Permanently', url: location, documentation_url: DOCS}};
  }
  /** The etag of a list's bytes, and the 304 a matching condition gives. If-Modified-Since matches by its exact string. A 304 costs nothing, and a next link has no page to name. */
  #conditional(answer, method, headers) {
    const list = method === 'GET' && answer.status === 200 && (Array.isArray(answer.data) || Number.isSafeInteger(answer.data?.total_count));
    if (!list) return answer;
    const etag = `W/"${sha1(JSON.stringify(answer.data))}"`, {link: _link, ...bare} = {...answer.headers, etag}, modified = answer.headers['last-modified'];
    return headers['if-none-match'] === etag || (modified !== undefined && headers['if-modified-since'] === modified) ? {status: 304, headers: bare, data: null} : {...answer, headers: {...answer.headers, etag}};
  }
  /** A 3xx as the seam gives it (lib/network.mjs): body-less, with the headers asked for and a location only on the request's own origin. A 304 is an answer, not a redirect. */
  #reported(status, headers, target, {redirect, responseHeaders}) {
    if (redirect !== 'report') throw lost('Provider redirects are not followed.');
    const kept = {};
    for (const key of responseHeaders) if (key !== 'location' && headers[key] !== undefined) kept[key] = headers[key];
    if (status !== 304 && headers.location) { const next = new URL(headers.location, target); if (next.origin === target.origin) kept.location = next.href; }
    return {status, headers: kept, data: null, ...(status === 304 ? {notModified: true} : {redirected: true})};
  }

  async request({url, method = 'GET', headers = {}, body, allowedOrigins, maxBytes = 2 * 1024 * 1024, responseType = 'json', redirect = 'error', responseHeaders = DEFAULT_RESPONSE_HEADERS, timeoutMs = 15000}) {
    let target;
    try { target = new URL(url); } catch { throw notSent('Invalid request URL.'); }
    if (target.protocol !== 'https:' || target.username || target.password || target.hash || (target.port && target.port !== '443')) throw notSent('Only credential-free HTTPS URLs on port 443 are allowed.');
    if (!Array.isArray(allowedOrigins) || !allowedOrigins.includes(target.origin)) throw notSent('Request origin is outside the connection grant.');
    if (!['json', 'buffer'].includes(responseType) || !['error', 'report'].includes(redirect) || !Array.isArray(responseHeaders)) throw notSent('Unsupported response handling.');
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000 || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 10 * 1024 * 1024) throw notSent('Invalid request limits.');
    if (!/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(method)) throw notSent('Unsupported HTTP method.');
    const lower = {};
    for (const [name, value] of Object.entries(headers)) {
      if (UNSAFE_HEADER.test(name) || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name) || typeof value !== 'string' || /[\r\n]/.test(value)) throw notSent('Unsafe request header.');
      lower[name.toLowerCase()] = value;
    }
    if (body !== undefined && !(typeof body === 'string' || Buffer.isBuffer(body))) throw notSent('Request body must be serialized.');
    if (body !== undefined && Buffer.byteLength(body) > 1024 * 1024) throw notSent('Request body is too large.');
    if (target.origin !== ORIGIN) throw notSent('Provider DNS lookup failed or timed out.');
    // Sent from here on: the call is recorded, without its Authorization header, with the clock time it arrived.
    const found = this.#routeOf(method, target.pathname);
    const raw = body === undefined ? undefined : Buffer.isBuffer(body) ? body.toString('utf8') : body;
    let parsed;
    if (raw !== undefined) { try { parsed = JSON.parse(raw); } catch { parsed = raw; } }
    const query = {};
    for (const [name, value] of target.searchParams) query[name] = Object.hasOwn(query, name) ? [query[name]].flat().concat(value) : value;
    const {authorization, ...kept} = lower;
    const call = {method, origin: target.origin, path: target.pathname, route: found?.route.key ?? null, query, headers: kept, body: parsed, write: found?.route.write === true, status: null, at: this.clock()};
    this.calls.push(call);
    const gate = found ? this.holds.get(found.route.key) : null;
    if (gate) { gate.reach(); await gate.released; }
    const chosen = found ? this.#take(found.route.key) : null, lag = found ? this.lags.get(found.route.key) : null;
    const authorized = authorization === `Bearer ${this.token}` || authorization === `token ${this.token}`;
    const limited = authorized ? this.#limited() : null, retired = this.retired.has(lower['x-github-api-version']), moved = this.#moved(target);
    let answer;
    if (!authorized) answer = githubError(401, 'Bad credentials');
    else if (limited) answer = limited;
    else if (retired) answer = githubError(410, `API version ${lower['x-github-api-version']} is no longer supported.`);
    else if (moved) answer = moved;
    else if (!found) answer = githubError(404, 'Not Found');
    else if (chosen?.kind === 'fail') answer = structuredClone(chosen.answer);
    else {
      const state = lag?.state ?? (chosen?.kind === 'swallow' ? structuredClone(this.data) : this.data);
      try {
        if (raw !== undefined && typeof parsed === 'string') refuse(400, 'Problems parsing JSON');
        answer = this.#conditional(found.route.handle({params: found.params, query: target.searchParams, body: parsed, headers: lower, state}), method, lower);
      } catch (error) {
        if (!(error instanceof Refusal)) throw error;
        answer = error.answer;
      }
      if (lag && --lag.left <= 0) this.lags.delete(found.route.key);
      if (chosen?.kind === 'drop') { call.status = answer.status; throw lost('Provider connection failed.'); }
      if (chosen?.kind === 'oversize') answer = {...answer, data: {...answer.data, padding: 'x'.repeat(Math.max(0, chosen.bytes))}};
    }
    call.status = answer.status;
    const headersOut = Object.fromEntries(Object.entries(answer.headers ?? {}).map(([name, value]) => [name.toLowerCase(), String(value)]));
    if (authorized) {
      headersOut['x-oauth-scopes'] = this.scopes.join(', ');
      const rate = this.rate;
      if (answer.status !== 304 && rate.used < RATE_LIMIT) rate.used++;
      const count = {'x-ratelimit-limit': RATE_LIMIT, 'x-ratelimit-remaining': RATE_LIMIT - rate.used, 'x-ratelimit-reset': rate.reset, 'x-ratelimit-used': rate.used, 'x-ratelimit-resource': 'core'};
      for (const [name, value] of Object.entries(count)) headersOut[name] ??= String(value);
    }
    if (answer.status >= 300 && answer.status < 400) return this.#reported(answer.status, headersOut, target, {redirect, responseHeaders});
    const bytes = answer.data === null || answer.data === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(answer.data), 'utf8');
    if (bytes.length > maxBytes) throw lost('Provider response exceeded the size limit.');
    if (bytes.length) headersOut['content-type'] ??= 'application/json; charset=utf-8';
    const shown = {};
    for (const key of responseHeaders) if (headersOut[key] !== undefined) shown[key] = headersOut[key];
    // A fresh parse of the bytes, so nothing the caller holds shares memory with the simulator's state.
    return {status: answer.status, headers: shown, data: responseType === 'buffer' ? bytes : bytes.length ? JSON.parse(bytes.toString('utf8')) : null};
  }
}

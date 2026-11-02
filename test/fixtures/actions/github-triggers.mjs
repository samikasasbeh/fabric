// Iteration 9 step 6 (docs/I07-BUILD-MAP.md step 6): what test/triggers-github.test.mjs and test/triggers-github-walk.test.mjs share, on top of the harness every app shares
// (trigger-harness.mjs). Writes reach the simulator on its own routes or its own test data, never through an action, so a test holds the trigger alone. Test data only: nothing in lib/ imports it.
import assert from 'node:assert/strict';
import {SANDBOX, TOKEN} from './github-harness.mjs';
import {shippedTriggers, triggerWorld} from './trigger-harness.mjs';
import {ORIGIN} from '../provider-simulators/github.mjs';

export const SECOND = 1000, MINUTE = 60_000, HOUR = 3_600_000;
export const ISSUES = 'GET /repos/{owner}/{repo}/issues', COMMENTS = 'GET /repos/{owner}/{repo}/issues/comments', ACTIVITY = 'GET /repos/{owner}/{repo}/activity', RUNS = 'GET /repos/{owner}/{repo}/actions/runs';
export const RELEASES = 'GET /repos/{owner}/{repo}/releases', NOTIFICATIONS = 'GET /notifications', ISSUE_ROW = 'github.issues.read', REPO_ROW = 'github.repos.read', PROFILE_ROW = 'github.profile.read';
export const REPO = Object.freeze({repository: SANDBOX}), BIG_ETAG = 'x'.repeat(513);
export const TRIGGERS = shippedTriggers('github').triggers, triggerOf = key => TRIGGERS.find(item => item.key === key);

/** A call as the account, on the simulator's own route. */
export const api = (world, method, path, body) => world.simulator.request({url: `${ORIGIN}${path}`, method, headers: {Authorization: `Bearer ${TOKEN}`, ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
  ...(body === undefined ? {} : {body: JSON.stringify(body)}), allowedOrigins: [ORIGIN]});
export const newIssue = async (world, title = 'A new issue', repository = SANDBOX) => (await api(world, 'POST', `/repos/${repository}/issues`, {title})).data.number;
export const newComment = async (world, number = 1, body = 'A new comment') => (await api(world, 'POST', `/repos/${SANDBOX}/issues/${number}/comments`, {body})).data.id;
let branches = 0;
/** A draft pull request from a new branch. Returns its number. */
export async function newPull(world, title = 'A new pull', {draft = true} = {}) {
  const branch = `side-${++branches}`;
  await api(world, 'POST', `/repos/${SANDBOX}/git/refs`, {ref: `refs/heads/${branch}`, sha: world.simulator.head(SANDBOX, 'main')});
  world.simulator.seedFile(SANDBOX, branch, `${branch}.txt`, branch);
  return (await api(world, 'POST', `/repos/${SANDBOX}/pulls`, {title, head: branch, base: 'main', draft})).data.number;
}
export const finished = (world, more = {}) => world.simulator.addRun(SANDBOX, {conclusion: 'success', ...more});
let tags = 0;
export const released = (world, more = {}) => world.simulator.addRelease(SANDBOX, {tag: `v${++tags}`, ...more});
export const times = (count, make) => Array.from({length: count}, (_, index) => make(index));

/**
 * What each trigger needs from a test. `args` subscribe, `route` is the list it polls, `row` the row it reads, `write` one change that gives one event and answers the event's `field`, `cursor` a stored
 * cursor with a value of the wrong form, `header` the conditional header, and `flood(world, count)` more changes than one poll reads.
 */
export const RECIPES = Object.freeze({
  'issue-changed': {args: REPO, route: ISSUES, row: ISSUE_ROW, field: 'number', cursor: ['updated', 'yesterday'], header: 'etag', write: world => newIssue(world),
    flood: (world, count) => world.simulator.seedIssues(SANDBOX, count, {at: world.now}), burst: (world, count) => world.simulator.seedIssues(SANDBOX, count, {at: world.now, spacingMs: 0})},
  'comment-changed': {args: REPO, route: COMMENTS, row: ISSUE_ROW, field: 'commentId', cursor: ['updated', 'yesterday'], header: 'etag', write: world => newComment(world),
    flood: async (world, count) => { for (let index = 0; index < count; index++) { await newComment(world, 1, `Comment ${index}`); world.advance(SECOND); } },
    burst: async (world, count) => { for (let index = 0; index < count; index++) await newComment(world, 1, `Comment ${index}`); }},
  'pull-changed': {args: REPO, route: ISSUES, row: ISSUE_ROW, field: 'number', cursor: ['updated', 'yesterday'], header: 'etag', write: world => newPull(world),
    flood: (world, count) => world.simulator.seedIssues(SANDBOX, count, {at: world.now}), burst: (world, count) => world.simulator.seedIssues(SANDBOX, count, {at: world.now, spacingMs: 0})},
  push: {args: REPO, route: ACTIVITY, row: REPO_ROW, field: 'after', cursor: ['etag', BIG_ETAG], header: 'etag', write: async world => world.simulator.push(SANDBOX, 'main'),
    flood: (world, count) => times(count, () => world.simulator.push(SANDBOX, 'main'))},
  'workflow-run-finished': {args: REPO, route: RUNS, row: REPO_ROW, field: 'runId', cursor: ['etag', BIG_ETAG], header: 'etag', write: async world => finished(world), flood: (world, count) => times(count, () => finished(world))},
  notification: {args: {}, route: NOTIFICATIONS, row: PROFILE_ROW, field: 'threadId', cursor: ['updated', 'yesterday'], header: 'last-modified', write: async world => world.simulator.notify(SANDBOX, {reason: 'mention', title: 'A thread'}),
    flood: (world, count) => times(count, index => world.simulator.notify(SANDBOX, {title: `Thread ${index}`}))},
  'release-published': {args: REPO, route: RELEASES, row: REPO_ROW, field: 'releaseId', cursor: ['etag', BIG_ETAG], header: 'etag', write: async world => released(world), flood: (world, count) => times(count, () => released(world))},
});
export const WINDOW_KEYS = Object.freeze(['push', 'workflow-run-finished', 'release-published']);

/** Calls that reached one route. */
export const reads = (world, route) => world.simulator.calls.filter(call => call.route === route);
/** What a harness keeps of one watch's first feed. */
export const feedOf = (world, id) => world.store.get('triggerFeeds', world.record(id).feeds[0]);
export const lastRun = (world, id) => world.store.get('triggerRuns', feedOf(world, id).id).runs.at(-1);
/** A watch past its first poll, on a world of its own or on `world`, with the clock past that poll. */
export async function watching(t, key, {world = triggerWorld(t, 'github', {keys: [key]}), args = RECIPES[key].args} = {}) {
  const {id} = await world.subscribe(key, args);
  assert.equal(world.approve(id).status, 'starting');
  assert.equal((await world.pollNow(id)).status, 'active', `${key}: the first poll reached the present`);
  world.advance(MINUTE);
  return {world, id, feed: () => feedOf(world, id), run: () => lastRun(world, id)};
}
/** Every event a world holds from here on, however many pages that takes. */
export async function drained(world) {
  const all = [];
  for (;;) {
    const {events} = await world.events();
    all.push(...events);
    if (!events.length) return all;
  }
}
export const kinds = events => events.map(event => [event.type, event.fields?.reason ?? null]);
/** Makes the next write of a feed's cursors throw after a stored poll that `when` picks, as a crash between the two stores would. */
export function crashAtCursor(world, when = () => true) {
  const {put, appendPoll} = world.store;
  let stored = false;
  world.store.appendPoll = poll => { const answer = appendPoll.call(world.store, poll); if (when(poll)) { stored = true; world.store.appendPoll = appendPoll; } return answer; };
  world.store.put = (collection, document) => {
    if (stored && collection === 'triggerFeeds') { world.store.put = put; throw new Error('crashed before the cursor moved'); }
    return put.call(world.store, collection, document);
  };
}
/** Fills the runs list, oldest first, one second apart and all finished, so the newest stand at the top. */
export const fillRuns = (world, count) => times(count, index => finished(world, {at: world.now - (count - index) * SECOND}));
export const fillReleases = (world, count) => times(count, index => released(world, {at: world.now - (count - index) * SECOND}));

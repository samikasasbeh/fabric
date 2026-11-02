import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {PINS} from '../lib/transform-pins.mjs';
import {triggerIds} from '../lib/triggers.mjs';
import {githubDeps, SANDBOX, TOKEN} from './fixtures/actions/github-harness.mjs';
import {COMMENTS, HOUR, ISSUES, ISSUE_ROW, MINUTE, NOTIFICATIONS, RECIPES, REPO, SECOND, TRIGGERS, WINDOW_KEYS, api, crashAtCursor, drained, feedOf, fillReleases, kinds, newComment, newIssue, newPull, reads, released, times, triggerOf, watching} from './fixtures/actions/github-triggers.mjs';
import {shippedTriggers, triggerWorld} from './fixtures/actions/trigger-harness.mjs';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';
import {ORIGIN} from './fixtures/provider-simulators/github.mjs';

// Iteration 9 step 6 (docs/I07-BUILD-MAP.md step 6): GitHub's seven sources on its simulator. Each runs on the shipped rows and proxy settings through the shared harness, so a watch walks the path a
// person's would: subscribe, approve, poll, read. Nothing here listens on a port or reaches GitHub. The kinds of test/fixtures/provider-simulators/github.trigger-cases.json run for every trigger, and the
// app's own promises follow them. test/triggers-github-walk.test.mjs holds how a walk reads GitHub's answers, apart from this file, so the seeded faults on those lines run in seconds.
const MANIFEST = JSON.parse(readFileSync(new URL('./fixtures/provider-simulators/github.trigger-cases.json', import.meta.url), 'utf8'));

// ---- the kinds every trigger runs -----------------------------------------------------------------------------------------------------------
const implementations = {};
for (const [key, recipe] of Object.entries(RECIPES)) {
  const name = kind => `${key} v1/${kind}`, bounds = triggerOf(key).bounds, {route} = recipe;
  implementations[name('baseline-silent')] = async t => {
    const world = triggerWorld(t, 'github', {keys: [key]});
    await recipe.write(world);
    world.advance(MINUTE);
    const {id} = await watching(t, key, {world});
    assert.ok(reads(world, route).length > 0, 'it read the list');
    assert.deepEqual((await world.events()).events, [], 'what was there before the watch is no event');
    await world.pollNow(id);
    assert.deepEqual((await world.events()).events, [], 'on a later poll either');
  };
  implementations[name('one-then-zero')] = async t => {
    const {world, id} = await watching(t, key), value = await recipe.write(world);
    await world.pollNow(id);
    const {events} = await world.events();
    assert.deepEqual(events.map(event => [event.type, event.subscriptionId, event.fields[recipe.field]]), [['trigger.event', id, value]]);
    const sent = reads(world, route).length;
    world.advance(MINUTE);
    await world.pollNow(id);
    assert.equal(reads(world, route).length, sent + 1, 'the re-poll asked GitHub');
    assert.deepEqual((await world.events()).events, [], 'and a re-poll gives zero');
  };
  implementations[name('crash-before-cursor')] = async t => {
    const {world, id, feed} = await watching(t, key);
    await recipe.write(world);
    const before = feed().lastGoodAt;
    crashAtCursor(world);
    await assert.rejects(world.pollNow(id), /crashed before the cursor moved/);
    assert.equal(feed().lastGoodAt, before, 'the crash left the feed behind');
    assert.equal((await world.events()).events.length, 1);
    world.advance(MINUTE);
    await world.pollNow(id);
    assert.deepEqual((await world.events()).events, [], 'the replay found its seen rows current');
    if (!recipe.burst) return;
    // A stall, on a block that can reach one: the replay ends the same gap, and stores no second one.
    await recipe.burst(world, bounds.items + 20);
    crashAtCursor(world, poll => poll.events?.some(row => row.kind === 'trigger.gap'));
    let crashes = 0;
    for (let poll = 0; poll < 4 && !crashes; poll++) await world.pollNow(id).catch(error => { assert.match(error.message, /crashed before the cursor moved/); crashes++; });
    assert.equal(crashes, 1, 'the stall came');
    world.advance(MINUTE);
    await world.pollNow(id);
    const told = await drained(world), events = told.filter(event => event.type === 'trigger.event');
    assert.deepEqual(kinds(told.filter(event => event.type === 'trigger.gap')), [['trigger.gap', 'stall']], 'one gap, not two');
    assert.equal(new Set(events.map(event => event.id)).size, events.length, 'and no event twice');
  };
  implementations[name('background-never')] = async t => {
    const {world, id} = await watching(t, key);
    await recipe.write(world);
    world.store.put('backgroundPolicies', {id: world.account, connectionId: world.account, mode: 'deny', updatedAt: 'x'});
    const sent = world.simulator.calls.length, watch = await world.pollNow(id);
    assert.deepEqual([watch.status, watch.reason, world.simulator.calls.length], ['paused', 'background_off', sent]);
    assert.deepEqual((await world.events()).events, []);
  };
  implementations[name('row-never-mid-poll')] = async t => {
    const {world, id, feed} = await watching(t, key);
    await recipe.write(world);
    const {cursors} = feed(), held = world.simulator.hold(route), flight = world.pollNow(id);
    await held.reached;
    world.setRow(recipe.row, 'deny');
    held.release();
    const watch = await flight;
    assert.deepEqual([watch.status, watch.reason], ['paused', 'permission_changed']);
    assert.deepEqual(feed().cursors, cursors, 'the cursor stayed');
    assert.deepEqual((await world.events()).events, [], 'and the answer was dropped');
  };
  implementations[name('malformed-cursor')] = async t => {
    const stored = await watching(t, key), [cursor, bad] = recipe.cursor, feed = stored.feed();
    stored.world.store.put('triggerFeeds', {...feed, cursors: {...feed.cursors, [cursor]: bad}});
    const sent = stored.world.simulator.calls.length, watch = await stored.world.pollNow(stored.id);
    assert.deepEqual([watch.status, watch.reason, stored.world.simulator.calls.length], ['paused', 'cursor_invalid', sent]);
    // One GitHub sends is held the same way: a cursor comes only from a provider, and only in its form.
    const answered = await watching(t, key);
    answered.world.simulator.fail(route, {status: 200, headers: {[recipe.header]: 'x'.repeat(600)}, data: []});
    const refused = await answered.world.pollNow(answered.id);
    assert.deepEqual([refused.status, refused.reason], ['paused', 'cursor_invalid']);
  };
  implementations[name('caps')] = async t => {
    const {world, id, run} = await watching(t, key);
    await recipe.flood(world, bounds.items + 40);
    const sent = reads(world, route).length;
    await world.pollNow(id);
    assert.ok(reads(world, route).length - sent <= bounds.pages, 'no more pages than the block says');
    assert.ok(run().requests <= bounds.pages, 'and no more requests');
    assert.ok(run().items <= bounds.items, `and no more items: ${run().items}`);
  };
  if (WINDOW_KEYS.includes(key)) implementations[name('resync-gap')] = async t => {
    const {world, id} = await watching(t, key);
    await recipe.flood(world, bounds.items + 40);
    await world.pollNow(id);
    assert.deepEqual(kinds((await world.events()).events), [['trigger.gap', 'overflow']], 'a window all new at once is one gap, and no flood of events');
    world.advance(MINUTE);
    await world.pollNow(id);
    assert.deepEqual((await world.events()).events, [], 'and what it read stays known');
  };
  implementations[name('pause-on-refusal')] = async t => {
    const {world, id, feed} = await watching(t, key), {cursors} = feed();
    world.simulator.fail(route, {status: 403, data: {message: 'Resource not accessible by integration'}});
    const watch = await world.pollNow(id);
    assert.deepEqual([watch.status, watch.reason, typeof watch.detail], ['paused', 'provider_refused', 'string']);
    assert.deepEqual(feed().cursors, cursors);
    const sent = world.simulator.calls.length;
    await world.pollNow(id);
    assert.equal(world.simulator.calls.length, sent, 'a paused watch reads nothing');
  };
}
caseTests(test, MANIFEST, TRIGGERS, implementations);

// ---- the file --------------------------------------------------------------------------------------------------------------------------------
test('the shipped file is the seven reviewed sources, a candidate until its live pass, under the ids its own transforms give', () => {
  const file = shippedTriggers('github'), ids = triggerIds(file, githubDeps());
  assert.deepEqual([file.reviewStatus, file.triggers.map(item => item.key)], ['candidate', ['issue-changed', 'comment-changed', 'pull-changed', 'push', 'workflow-run-finished', 'notification', 'release-published']]);
  for (const trigger of file.triggers) assert.equal(trigger.id, ids.get(`${trigger.key} v${trigger.version}`), trigger.key);
  assert.deepEqual(file.triggers.filter(item => item.delivery.method === 'webhook').map(item => [item.key, item.delivery.fallback]), TRIGGERS.filter(item => item.key !== 'notification').map(item => [item.key, 'polling']));
  assert.deepEqual([triggerOf('notification').delivery.method], ['polling'], 'GitHub has no webhook for notifications');
  assert.ok(file.triggers.every(item => item.poll.resync.statusIn.length === 0), 'GitHub has no cursor that expires, so nothing here resyncs');
  assert.ok(/^[a-f0-9]{64}$/.test(PINS.transforms['ids.linkPage@1']), 'the Link reader is pinned');
});

test('each draft-only promise a card makes: what polling cannot see is written in its description', () => {
  for (const key of ['issue-changed', 'comment-changed', 'pull-changed', 'workflow-run-finished', 'notification', 'release-published']) assert.match(triggerOf(key).description, /can skip one item/, key);
  assert.match(triggerOf('issue-changed').description, /A deleted issue is not reported/);
  assert.match(triggerOf('workflow-run-finished').description, /a run or a re-run that finishes behind the 100 newest can be missed/);
  assert.match(triggerOf('release-published').description, /a release on a commit older than the 90 newest can be missed/);
});

// ---- what each source reports ----------------------------------------------------------------------------------------------------------------
test('an issue: opened, edited and closed each give one event, a latest version only, and a comment moves it too', async t => {
  const {world, id} = await watching(t, 'issue-changed'), number = await newIssue(world, 'First title');
  await world.pollNow(id);
  world.advance(MINUTE);
  await api(world, 'PATCH', `/repos/${SANDBOX}/issues/${number}`, {state: 'closed', state_reason: 'not_planned'});
  await world.pollNow(id);
  world.advance(MINUTE);
  await newComment(world, number);
  await world.pollNow(id);
  world.advance(MINUTE);
  await api(world, 'PATCH', `/repos/${SANDBOX}/issues/${number}`, {title: 'Second title'});
  world.advance(SECOND);
  await api(world, 'PATCH', `/repos/${SANDBOX}/issues/${number}`, {title: 'Third title'});
  await world.pollNow(id);
  const {events} = await world.events();
  assert.deepEqual(events.map(event => [event.fields.number, event.fields.state, event.fields.title]), [[number, 'open', 'First title'], [number, 'closed', 'First title'], [number, 'closed', 'First title'], [number, 'closed', 'Third title']], 'changes between polls collapse');
  const [first, closed] = events;
  assert.deepEqual([first.fields.repository, first.fields.author, typeof first.fields.createdAt, first.fields.updatedAt, first.fields.url, closed.fields.stateReason, first.fields.stateReason], [SANDBOX, 'octo-a', 'string', first.occurredAt, `https://github.com/${SANDBOX}/issues/${number}`, 'not_planned', undefined]);
  assert.deepEqual(first.summary, [{label: 'Issue', value: 'First title'}, {label: 'State', value: 'open'}]);
});

test('a pull request is no issue, and an issue no pull request: one list, two lenses, one request', async t => {
  const world = triggerWorld(t, 'github', {keys: ['issue-changed', 'pull-changed']}), issues = await watching(t, 'issue-changed', {world}), pulls = await watching(t, 'pull-changed', {world});
  assert.deepEqual(world.record(issues.id).feeds, world.record(pulls.id).feeds, 'one feed');
  const pull = await newPull(world, 'A pull'), number = await newIssue(world, 'An issue'), sent = reads(world, ISSUES).length;
  await world.pollNow(issues.id);
  assert.equal(reads(world, ISSUES).length, sent + 1, 'one request serves both');
  const {events} = await world.events();
  assert.deepEqual(events.map(event => [event.subscriptionId, event.fields.number, event.fields.draft]).sort(([a], [b]) => a === issues.id ? -1 : b === issues.id ? 1 : 0), [[issues.id, number, undefined], [pulls.id, pull, true]]);
});

test('a review and a push to its branch each report a pull request, and merging it reports when', async t => {
  const {world, id} = await watching(t, 'pull-changed'), number = await newPull(world, 'A pull', {draft: false});
  world.simulator.author(SANDBOX, number, {login: 'someone', id: 77});
  await world.pollNow(id);
  await world.events();
  world.advance(MINUTE);
  await api(world, 'POST', `/repos/${SANDBOX}/pulls/${number}/reviews`, {event: 'APPROVE'});
  await world.pollNow(id);
  assert.equal((await world.events()).events.length, 1, 'a review');
  world.advance(MINUTE);
  world.simulator.push(SANDBOX, world.simulator.state().repos[SANDBOX].issues.find(item => item.number === number).pull.head);
  await world.pollNow(id);
  assert.equal((await world.events()).events.length, 1, 'a push');
  world.advance(MINUTE);
  await api(world, 'PUT', `/repos/${SANDBOX}/pulls/${number}/merge`, {});
  await world.pollNow(id);
  const {events: [merged]} = await world.events();
  assert.deepEqual([merged.fields.state, typeof merged.fields.mergedAt], ['closed', 'string']);
});

test('a comment: added and edited each give one event, a deleted one gives none', async t => {
  const {world, id} = await watching(t, 'comment-changed'), comment = await newComment(world, 2, 'Words');
  await world.pollNow(id);
  world.advance(MINUTE);
  world.simulator.editComment(SANDBOX, comment, 'Other words');
  await world.pollNow(id);
  world.advance(MINUTE);
  await api(world, 'DELETE', `/repos/${SANDBOX}/issues/comments/${comment}`);
  await world.pollNow(id);
  const {events} = await world.events();
  assert.deepEqual(events.map(event => [event.fields.commentId, event.summary[0].value]), [[comment, 'Words'], [comment, 'Other words']]);
  assert.deepEqual([events[0].fields.issueUrl, events[0].fields.author, events[0].fields.url], [`${ORIGIN}/repos/${SANDBOX}/issues/2`, 'octo-a', `https://github.com/${SANDBOX}/issues/2#issuecomment-${comment}`]);
});

test('a ref change: a push, a force push, a new branch, a deleted branch and a merge each give one event, and a row with no actor still reports', async t => {
  const {world, id} = await watching(t, 'push'), {simulator} = world, sha = simulator.head(SANDBOX, 'main');
  await api(world, 'POST', `/repos/${SANDBOX}/git/refs`, {ref: 'refs/heads/feature', sha});
  const head = simulator.push(SANDBOX, 'feature', {text: 'one'});
  simulator.push(SANDBOX, 'feature', {text: 'two', force: true, actor: null});
  await api(world, 'DELETE', `/repos/${SANDBOX}/git/refs/heads/feature`);
  await world.pollNow(id);
  const {events} = await world.events();
  assert.deepEqual(events.map(event => [event.fields.activityType, event.fields.ref]).sort(), [['branch_creation', 'refs/heads/feature'], ['branch_deletion', 'refs/heads/feature'], ['force_push', 'refs/heads/feature'], ['push', 'refs/heads/feature']]);
  const pushed = events.find(event => event.fields.activityType === 'push');
  assert.deepEqual([pushed.fields.before, pushed.fields.after, pushed.fields.actor, pushed.fields.repository], [sha, head, 'octo-a', SANDBOX]);
  assert.equal(events.find(event => event.fields.activityType === 'force_push').fields.actor, undefined);
  assert.deepEqual(events[0].summary.map(line => line.label), ['Change', 'Ref']);
});

test('a run seen queued, running and completed gives one event, and a re-run gives a second with its attempt', async t => {
  const {world, id} = await watching(t, 'workflow-run-finished'), {simulator} = world, run = simulator.addRun(SANDBOX);
  await world.pollNow(id);
  simulator.startRun(run);
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, [], 'queued and running are not reported');
  world.advance(MINUTE);
  simulator.finishRun(run, 'failure');
  await world.pollNow(id);
  world.advance(MINUTE);
  await world.pollNow(id);
  const {events: [first, ...more]} = await world.events();
  assert.deepEqual([first.fields.runId, first.fields.attempt, first.fields.conclusion, more], [run, 1, 'failure', []]);
  assert.deepEqual([first.fields.workflowName, first.fields.cause, first.fields.branch, first.fields.url, first.summary[0].label], ['Fabric synthetic', 'push', 'main', `https://github.com/${SANDBOX}/actions/runs/${run}`, 'Run']);
  world.advance(MINUTE);
  simulator.rerun(run);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, [], 'a re-run under way is off the finished list');
  world.advance(MINUTE);
  simulator.finishRun(run);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events.map(event => [event.fields.runId, event.fields.attempt, event.fields.conclusion]), [[run, 2, 'success']]);
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, []);
});

test('a notification: new, and news on the same thread, each give one event, with the repository from the thread', async t => {
  const {world, id} = await watching(t, 'notification'), thread = world.simulator.notify(SANDBOX, {reason: 'ci_activity', type: 'CheckSuite', title: 'Run failed'});
  await world.pollNow(id);
  world.advance(MINUTE);
  world.simulator.notify(SANDBOX, {thread, title: 'Run failed again'});
  await world.pollNow(id);
  const {events} = await world.events();
  assert.deepEqual(events.map(event => [event.fields.threadId, event.fields.reason, event.fields.repository, event.fields.subjectType, event.fields.title]),
    [[thread, 'ci_activity', SANDBOX, 'CheckSuite', 'Run failed'], [thread, 'ci_activity', SANDBOX, 'CheckSuite', 'Run failed again']]);
  assert.deepEqual(events[0].summary, [{label: 'Subject', value: 'Run failed'}, {label: 'Why', value: 'ci_activity'}]);
});

test('a burst past the notification list\'s bounds gives one gap for what it could not read, and a later thread is reached', async t => {
  const {world, id} = await watching(t, 'notification'), {simulator} = world;
  times(540, index => simulator.notify(SANDBOX, {title: `Thread ${index}`}));
  await world.pollNow(id);
  const told = await drained(world);
  assert.deepEqual([told.filter(event => event.type === 'trigger.event').length, kinds(told.filter(event => event.type === 'trigger.gap'))], [500, [['trigger.gap', 'bound']]]);
  world.advance(2 * MINUTE);
  const thread = simulator.notify(SANDBOX, {title: 'Later'});
  await world.pollNow(id);
  assert.ok((await drained(world)).some(event => event.fields.threadId === thread));
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual(await drained(world), [], 'once the mark has passed the burst, nothing more is told');
});

test('a draft gives none and counts as nothing lost, publishing gives one, and a later edit gives none', async t => {
  const {world, id, run} = await watching(t, 'release-published'), {simulator} = world, draft = released(world, {draft: true});
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, [], 'a draft is no release yet');
  assert.equal(run().skipped, 0, 'and it is not an item Fabric failed to read, so the owner\'s row says nothing of it');
  world.advance(MINUTE);
  simulator.publishRelease(SANDBOX, draft);
  await world.pollNow(id);
  const {events} = await world.events();
  assert.deepEqual(events.map(event => [event.fields.releaseId, typeof event.fields.tag, event.fields.prerelease, event.fields.author]), [[draft, 'string', false, 'octo-a']]);
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, []);
});

test('deleting a release in a full window gives none: what slides in from past the bound is older than the baseline', async t => {
  const world = triggerWorld(t, 'github', {keys: ['release-published']}), ids = fillReleases(world, 95), {id} = await watching(t, 'release-published', {world});
  world.simulator.deleteRelease(SANDBOX, ids.at(-1));
  await world.pollNow(id);
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, []);
  assert.equal(world.record(id).status, 'active');
});

// ---- empty and large lists ---------------------------------------------------------------------------------------------------------------------
test('an empty repository: its seed finds no row, and its first item is one event', async t => {
  const world = triggerWorld(t, 'github', {keys: ['issue-changed']}), repository = 'octo-a/public-notes', {id} = await watching(t, 'issue-changed', {world, args: {repository}});
  assert.equal(feedOf(world, id).cursors.updated, undefined, 'no cursor, and baselined all the same');
  const number = await newIssue(world, 'The first', repository);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events.map(event => event.fields.number), [number]);
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, []);
});

test('10,000 issues: the baseline reads one item and the last minute, and a backlog drains within the bounds of each poll, each item once', async t => {
  const world = triggerWorld(t, 'github', {keys: ['issue-changed']}), {simulator} = world, {bounds} = triggerOf('issue-changed');
  simulator.seedIssues(SANDBOX, 10_000, {at: world.now - 20_000 * SECOND});
  const {id, run} = await watching(t, 'issue-changed', {world});
  const baseline = reads(world, ISSUES);
  assert.deepEqual(baseline.map(call => [call.query.per_page, call.query.direction]), [['1', 'desc'], ['30', 'asc']], 'the seed reads one, and the poll reads on from it');
  assert.equal(run().items, 3, 'the three updated in the last minute');
  world.advance(10 * MINUTE);
  simulator.seedIssues(SANDBOX, 650, {at: world.now - 650 * SECOND});
  let told = 0, polls = 0;
  for (; polls < 10; polls++) {
    world.advance(MINUTE);
    await world.pollNow(id);
    const last = run();
    assert.ok(last.requests <= bounds.pages && last.items <= bounds.items, `poll ${polls}: ${last.requests} requests, ${last.items} items`);
    told += last.events[id] ?? 0;
    if (last.outcome === 'not_modified' || last.requests === 1) break;
  }
  assert.equal(told, 650, 'each change once, with no gap and none twice');
  assert.deepEqual([...new Set(kinds(await drained(world)).map(([type]) => type))], ['trigger.event']);
});

test('more than 300 issues in one second trigger the stall rule: one gap, then the mark passes that second and a later edit is reached', async t => {
  const {world, id, feed} = await watching(t, 'issue-changed');
  world.simulator.seedIssues(SANDBOX, 340, {at: world.now, spacingMs: 0});
  await world.pollNow(id);
  assert.ok((await drained(world)).every(event => event.type === 'trigger.event'), 'the first poll reads what it can');
  world.advance(MINUTE);
  await world.pollNow(id);
  await drained(world);
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual(kinds(await drained(world)), [['trigger.gap', 'stall']], 'the next poll to find nothing new, with more to read, says so');
  assert.ok(feed().floor, 'the floor passes that second');
  world.advance(MINUTE);
  const number = await newIssue(world, 'Later');
  await world.pollNow(id);
  assert.deepEqual((await drained(world)).map(event => event.fields?.number), [number]);
});

// ---- 304s, and what a walk may keep ---------------------------------------------------------------------------------------------------------
test('a next link on /repositories/<id> reads page 2 on the request\'s own path, and each page holds to the walk', async t => {
  const {world, id} = await watching(t, 'comment-changed'), {simulator} = world;
  await RECIPES['comment-changed'].burst(world, 35);
  await world.pollNow(id);
  const walk = reads(world, COMMENTS).slice(-2);
  assert.deepEqual(walk.map(call => [call.path, call.query.page ?? '1']), [[`/repos/${SANDBOX}/issues/comments`, '1'], [`/repos/${SANDBOX}/issues/comments`, '2']], 'a page number, never the URL GitHub named');
  assert.equal((await drained(world)).length, 35);
  assert.match(simulator.calls.at(-1).path, /^\/repos\//);
});

for (const [label, link] of [['another path', '<https://api.github.com/user/issues?page=2>; rel="next"'], ['another origin', `<https://evil.example/repos/${SANDBOX}/issues?page=2>; rel="next"`],
  ['another repository\'s list form', '<https://api.github.com/repositories/500001/pulls?page=2>; rel="next"'], ['no page number', '<https://api.github.com/repositories/500001/issues?after=Y3Vyc29y>; rel="next"']]) {
  test(`a next link on ${label} pauses with link_invalid: it is never followed and never read as the end of the list`, async t => {
    const {world, id, feed} = await watching(t, 'issue-changed'), {cursors} = feed(), sent = world.simulator.calls.length;
    world.simulator.fail(ISSUES, {status: 200, headers: {link}, data: []});
    const watch = await world.pollNow(id);
    assert.deepEqual([watch.status, watch.reason, watch.detail], ['paused', 'provider_refused', 'link_invalid']);
    assert.equal(world.simulator.calls.length, sent + 1, 'nothing was sent after the link');
    assert.deepEqual(feed().cursors, cursors);
  });
}

test('per_page beyond the cap is cut in silence, and paging still ends on Link, with every item read once', async t => {
  const file = shippedTriggers('github');
  file.triggers.find(item => item.key === 'issue-changed').poll.source.steps[0].query.per_page.const = 200;
  const world = triggerWorld(t, 'github', {keys: ['issue-changed'], file}), {id} = await watching(t, 'issue-changed', {world}), sent = reads(world, ISSUES).length;
  world.simulator.seedIssues(SANDBOX, 130);
  world.advance(5 * MINUTE);
  await world.pollNow(id);
  assert.deepEqual(reads(world, ISSUES).slice(sent).map(call => call.query.page ?? '1'), ['1', '2']);
  assert.equal((await drained(world)).length, 130);
});

// ---- what pauses, and what waits -------------------------------------------------------------------------------------------------------------
test('X-Poll-Interval of 300 delays the next poll by at least 300 seconds, whatever the block says', async t => {
  const {world, id, feed} = await watching(t, 'notification');
  world.simulator.setPollInterval(300);
  await world.pollNow(id);
  const at = world.now, sent = reads(world, NOTIFICATIONS).length;
  assert.ok(feed().notBefore >= at + 300 * SECOND, 'the floor is the provider\'s');
  world.advance(299 * SECOND);
  await world.engine.tick();
  assert.equal(reads(world, NOTIFICATIONS).length, sent, 'not a second early, though the interval has passed');
  world.advance(SECOND);
  await world.engine.tick();
  assert.equal(reads(world, NOTIFICATIONS).length, sent + 1);
});

for (const [status, retryAfter, least] of [[403, 120, 120], [429, 120, 120], [403, undefined, 60], [429, undefined, 60]]) {
  test(`a secondary limit ${status} ${retryAfter === undefined ? 'with no retry-after waits at least a minute' : `honours retry-after ${retryAfter}`}, and pauses nothing`, async t => {
    const {world, id, feed} = await watching(t, 'issue-changed');
    world.simulator.secondaryLimit({status, retryAfter});
    const at = world.now, watch = await world.pollNow(id);
    assert.equal(watch.status, 'active');
    assert.ok(feed().wait.until >= at + least * SECOND, `${feed().wait.until - at}`);
    assert.equal(feed().failures, 1, 'then it backs off');
  });
}

test('no poll while GitHub\'s own count stands under 500, until its reset', async t => {
  const {world, id} = await watching(t, 'issue-changed'), {simulator} = world;
  simulator.rateLeft(450);
  await newIssue(world, 'One');
  await world.pollNow(id);
  const sent = reads(world, ISSUES).length;
  world.advance(5 * MINUTE);
  await world.engine.tick();
  assert.equal(reads(world, ISSUES).length, sent, 'the count is the owner\'s to spend on actions');
  world.advance(HOUR);
  await world.engine.tick();
  assert.equal(reads(world, ISSUES).length, sent + 1);
});

test('a row at Never pauses every watch on it, on every feed, and leaves the others', async t => {
  const world = triggerWorld(t, 'github', {keys: ['issue-changed', 'comment-changed', 'pull-changed', 'push']}), {id: first} = await watching(t, 'issue-changed', {world});
  const {id: second} = await watching(t, 'comment-changed', {world}), {id: third} = await watching(t, 'pull-changed', {world}), {id: other} = await watching(t, 'push', {world});
  world.setRow(ISSUE_ROW, 'deny');
  const sent = world.simulator.calls.length;
  for (const id of [first, second, third]) assert.deepEqual([(await world.pollNow(id)).status, world.record(id).reason], ['paused', 'permission_changed']);
  assert.equal(world.simulator.calls.length, sent, 'and nothing was read for them');
  assert.equal((await world.pollNow(other)).status, 'active');
});

test('one repository in two spellings is one watch and one feed: GitHub reads a name in any case', async t => {
  const world = triggerWorld(t, 'github', {keys: ['issue-changed']}), first = await world.subscribe('issue-changed', {repository: 'Octo-A/Fabric-Sandbox'});
  assert.equal(world.record(first.id).args.repository, SANDBOX);
  assert.equal((await world.subscribe('issue-changed', REPO)).id, first.id);
});

test('a token in a title never reaches an event, and a poll writes no audit row', async t => {
  const {world, id} = await watching(t, 'issue-changed'), audit = world.store.list('activity').length;
  assert.ok(audit > 0, 'a subscribe and an approval did write theirs');
  await newIssue(world, `Paste of ${TOKEN} by mistake`);
  await world.pollNow(id);
  world.advance(MINUTE);
  await world.pollNow(id);
  const {events} = await world.events();
  assert.equal(events.length, 1);
  assert.ok(!JSON.stringify(events).includes(TOKEN));
  assert.equal(world.store.list('activity').length, audit);
});

test('a cursor comes only from GitHub\'s own answer: the since sent is the newest item, less the block\'s overlap', async t => {
  const {world, id} = await watching(t, 'issue-changed'), number = await newIssue(world);
  await world.pollNow(id);
  const {events: [event]} = await world.events();
  world.simulator.seedIssues(SANDBOX, 1);
  await world.pollNow(id);
  assert.equal(event.fields.number, number);
  assert.equal(reads(world, ISSUES).at(-1).query.since, new Date(Date.parse(event.occurredAt) - MINUTE).toISOString());
});

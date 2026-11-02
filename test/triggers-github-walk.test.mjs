import test from 'node:test';
import assert from 'node:assert/strict';
import {SANDBOX} from './fixtures/actions/github-harness.mjs';
import {HOUR, ISSUES, MINUTE, NOTIFICATIONS, RECIPES, RELEASES, RUNS, SECOND, drained, fillReleases, fillRuns, finished, kinds, newIssue, reads, released, times, triggerOf, watching} from './fixtures/actions/github-triggers.mjs';
import {triggerWorld} from './fixtures/actions/trigger-harness.mjs';

// Iteration 9 step 6 (docs/I07-BUILD-MAP.md step 6): how a walk reads GitHub's answers, on its simulator: what a 304 saves and a long walk may not keep, what pauses and what waits, what a subscribe refuses,
// and a window over a list that is not in order. These lines hold most of the step's seeded faults, so this file stays small, and each fault runs in seconds.

// ---- 304s, and what a walk may keep ---------------------------------------------------------------------------------------------------------
test('an idle one-page feed is a 304: no body, no event, and the rate count stays', async t => {
  const {world, id, feed} = await watching(t, 'issue-changed'), {simulator} = world, spent = simulator.rate.used;
  assert.match(feed().cursors.etag, /^W\//, 'a one-page walk keeps its etag');
  await world.pollNow(id);
  const [last] = reads(world, ISSUES).slice(-1);
  assert.deepEqual([last.status, last.headers['if-none-match'], simulator.rate.used], [304, feed().cursors.etag, spent]);
  assert.deepEqual((await world.events()).events, []);
  assert.equal(world.record(id).status, 'active');
});

test('an idle notification list is a 304 by its Last-Modified, sent by its exact string', async t => {
  const world = triggerWorld(t, 'github', {keys: ['notification']});
  world.simulator.notify(SANDBOX, {title: 'Old news'});
  world.advance(MINUTE);
  const {id, feed} = await watching(t, 'notification', {world});
  assert.equal(feed().cursors.modified, new Date(world.now - 2 * MINUTE).toUTCString());
  await world.pollNow(id);
  const [last] = reads(world, NOTIFICATIONS).slice(-1);
  assert.deepEqual([last.status, last.headers['if-modified-since']], [304, feed().cursors.modified]);
});

test('an idle multi-page feed reads every page and keeps no etag, a change on its last page gives one event, and only page 1 could ever be conditional', async t => {
  const {world, id, feed} = await watching(t, 'issue-changed'), {simulator} = world;
  simulator.seedIssues(SANDBOX, 45, {at: world.now, spacingMs: 0});
  await world.pollNow(id);
  assert.equal((await drained(world)).length, 45);
  assert.equal(feed().cursors.etag, undefined, 'neither page\'s etag can speak for the list');
  const sent = reads(world, ISSUES).length;
  world.advance(SECOND);
  await world.pollNow(id);
  const idle = reads(world, ISSUES).slice(sent);
  assert.deepEqual(idle.map(call => [call.status, call.query.page ?? '1', call.headers['if-none-match']]), [[200, '1', undefined], [200, '2', undefined]], 'every page, in full');
  assert.deepEqual(await drained(world), []);
  world.advance(SECOND);
  const number = await newIssue(world, 'On the last page');
  await world.pollNow(id);
  assert.deepEqual((await drained(world)).map(event => event.fields.number), [number]);
});

// ---- what pauses, and what waits -------------------------------------------------------------------------------------------------------------
test('a 404 or a 410 pauses each of the seven and re-baselines nothing: GitHub has no cursor that expires, so a resync would lose the list in silence', async t => {
  for (const status of [404, 410]) {
    const world = triggerWorld(t, 'github'), watches = [];
    for (const key of Object.keys(RECIPES)) watches.push({key, ...await watching(t, key, {world})});
    for (const {key, id, feed} of watches) {
      const before = feed();
      world.simulator.fail(RECIPES[key].route, {status, data: {message: 'Gone'}});
      const watch = await world.pollNow(id), after = feed();
      assert.deepEqual([key, watch.status, watch.reason, watch.detail], [key, 'paused', 'provider_refused', `http_${status}`]);
      assert.deepEqual([after.cursors, after.baselined, after.lastGoodAt], [before.cursors, true, before.lastGoodAt], `${key}: nothing was thrown away`);
    }
    assert.deepEqual((await world.events()).events, [], 'and no gap says otherwise');
  }
});

test('a retired API version answers 410 on every read, and each watch pauses with its cursor kept', async t => {
  const {world, id, feed} = await watching(t, 'issue-changed'), {cursors} = feed(), [{headers}] = reads(world, ISSUES);
  world.simulator.retire(headers['x-github-api-version']);
  const watch = await world.pollNow(id);
  assert.deepEqual([watch.status, watch.reason, watch.detail], ['paused', 'provider_refused', 'http_410']);
  assert.deepEqual(feed().cursors, cursors);
});

test('a renamed repository answers 301, which is never followed: every watch on it pauses, moved, with its place kept', async t => {
  const world = triggerWorld(t, 'github'), watches = [];
  for (const key of Object.keys(RECIPES).filter(name => name !== 'notification')) watches.push({key, ...await watching(t, key, {world})});
  world.simulator.rename(SANDBOX, 'octo-a/renamed');
  for (const {key, id, feed} of watches) {
    const {cursors} = feed(), sent = world.simulator.calls.length, watch = await world.pollNow(id);
    assert.deepEqual([key, watch.status, watch.reason, watch.detail], [key, 'paused', 'provider_refused', 'moved']);
    assert.ok(world.simulator.calls.length <= sent + 1, `${key}: at most one request, to the name the owner approved`);
    assert.deepEqual(feed().cursors, cursors);
  }
});

test('a primary limit spent waits for x-ratelimit-reset, on every feed of the account, and on either status', async t => {
  for (const status of [403, 429]) {
    const world = triggerWorld(t, 'github', {keys: ['issue-changed', 'release-published']}), issues = await watching(t, 'issue-changed', {world}), releases = await watching(t, 'release-published', {world});
    world.simulator.exhaust({status});
    const watch = await world.pollNow(issues.id), {reset} = world.simulator.rate;
    assert.equal(watch.status, 'active', 'a limit waits, and pauses nothing');
    assert.ok(issues.feed().wait.until >= reset * SECOND, `the wait runs to the reset: ${status}`);
    assert.ok(releases.feed().wait.until >= reset * SECOND, 'for every feed on the token');
    assert.deepEqual(world.simulator.calls.at(-1).status, status);
    const sent = world.simulator.calls.length;
    world.advance(HOUR - 3 * MINUTE);
    await world.engine.tick();
    assert.equal(world.simulator.calls.length, sent, 'nothing is sent before it');
    world.advance(4 * MINUTE);
    assert.equal((await world.pollNow(issues.id)).status, 'active');
    assert.equal(world.simulator.calls.at(-1).status, 304, 'and after it the feed reads on');
  }
});

test('.. in a repository is refused at subscribe, and each other form of owner/name, so no request is built from one', async t => {
  const world = triggerWorld(t, 'github', {keys: ['issue-changed']}), sent = world.simulator.calls.length;
  for (const repository of ['octo-a/..', '../octo-a', 'octo-a/.', 'octo-a', 'a/b/c', 'octo-a/fabric sandbox', '%2e%2e/x']) {
    await assert.rejects(world.subscribe('issue-changed', {repository}), error => error.code === 'action_refused', repository);
  }
  assert.equal(world.simulator.calls.length, sent);
  assert.deepEqual(world.store.list('subscriptions'), [], 'nothing was stored');
});

// ---- a window over a list that is not in order (section 12, the reviews' open case) ------------------------------------------------------------
test('the runs list sorts by start, not by finish: a run that finishes at the far end of what Fabric reads tells of what may lie past it, with one gap, and its event stands', async t => {
  const world = triggerWorld(t, 'github', {keys: ['workflow-run-finished']}), {simulator} = world, ids = fillRuns(world, 150), {id} = await watching(t, 'workflow-run-finished', {world});
  assert.equal(ids.length, 150);
  const near = simulator.addRun(SANDBOX, {at: world.now - 130 * SECOND}), far = simulator.addRun(SANDBOX, {at: world.now - 190 * SECOND});
  simulator.finishRun(near);
  simulator.finishRun(far);
  await world.pollNow(id);
  const {events} = await world.events();
  assert.deepEqual(kinds(events), [['trigger.event', null], ['trigger.gap', 'bound']]);
  assert.equal(events[0].fields.runId, near, 'the one in reach is reported');
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, [], 'and the next poll finds nothing new, so it says nothing');
});

test('the same on the releases list, which sorts by commit date: a release that lands on the last page read gives its event and one gap', async t => {
  const world = triggerWorld(t, 'github', {keys: ['release-published']}), {simulator} = world;
  fillReleases(world, 120);
  const {id} = await watching(t, 'release-published', {world}), old = released(world, {commitAt: world.now - 150 * SECOND, at: world.now});
  await world.pollNow(id);
  const {events} = await world.events();
  assert.deepEqual(kinds(events), [['trigger.event', null], ['trigger.gap', 'bound']]);
  assert.equal(events[0].fields.releaseId, old);
  simulator.deleteRelease(SANDBOX, old);
});

test('a long list stays quiet: new items at the top of a list always cut by its bound give their events and no gap, or a busy repository would read a gap with every run', async t => {
  const world = triggerWorld(t, 'github', {keys: ['workflow-run-finished']});
  fillRuns(world, 150);
  const {id} = await watching(t, 'workflow-run-finished', {world}), run = finished(world);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events.map(event => [event.type, event.fields.runId]), [['trigger.event', run]]);
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, [], 'and a list cut by its bound with nothing new says nothing');
});

test('what lies past the bound with nothing new in reach cannot be told: no gap, and the card says it can be missed', async t => {
  const world = triggerWorld(t, 'github', {keys: ['workflow-run-finished']}), {simulator} = world;
  fillRuns(world, 150);
  const {id} = await watching(t, 'workflow-run-finished', {world}), far = simulator.addRun(SANDBOX, {at: world.now - 190 * SECOND});
  simulator.finishRun(far);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, []);
  assert.match(triggerOf('workflow-run-finished').description, /can be missed/);
});

test('a new run near the top says nothing of one past the bound: its event stands with no gap, since only the far end of a read is a sign, and the card says what that costs', async t => {
  const world = triggerWorld(t, 'github', {keys: ['workflow-run-finished']}), {simulator} = world;
  fillRuns(world, 150);
  const {id} = await watching(t, 'workflow-run-finished', {world}), near = finished(world), far = simulator.addRun(SANDBOX, {at: world.now - 190 * SECOND});
  simulator.finishRun(far);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events.map(event => [event.type, event.fields.runId]), [['trigger.event', near]]);
  assert.match(triggerOf('workflow-run-finished').description, /can be missed/);
});

test('a burst past the activity list\'s one page is an overflow: it has no next link to read, so a full page of new rows is what says so', async t => {
  const {world, id} = await watching(t, 'push'), {simulator} = world;
  times(150, () => simulator.push(SANDBOX, 'main'));
  await world.pollNow(id);
  assert.deepEqual(kinds(await drained(world)), [['trigger.gap', 'overflow']]);
  world.advance(MINUTE);
  const head = simulator.push(SANDBOX, 'main');
  await world.pollNow(id);
  assert.deepEqual((await drained(world)).map(event => event.fields.after), [head], 'and the next change reads as one');
});

test('a smaller burst on the activity list fires each row, since the list sorts newest first and nothing lies past a known row', async t => {
  const {world, id} = await watching(t, 'push'), {simulator} = world;
  simulator.push(SANDBOX, 'main');
  await world.pollNow(id);
  await drained(world);
  world.advance(MINUTE);
  times(99, () => simulator.push(SANDBOX, 'main'));
  await world.pollNow(id);
  const events = await drained(world);
  assert.deepEqual([events.length, [...new Set(events.map(event => event.type))]], [99, ['trigger.event']], 'a full page with a known row in it');
});

test('release notes at their longest stay inside one answer: 80 releases of 125,000 characters pause nothing, and the next is told', async t => {
  const world = triggerWorld(t, 'github', {keys: ['release-published']}), body = 'n'.repeat(125_000);
  times(80, index => released(world, {at: world.now - (80 - index) * SECOND, body}));
  const {id, run} = await watching(t, 'release-published', {world}), fresh = released(world, {body});
  await world.pollNow(id);
  assert.deepEqual([world.record(id).status, run().outcome], ['active', 'done']);
  assert.deepEqual((await drained(world)).map(event => event.fields.releaseId), [fresh]);
});

// ---- a read that cannot get further waits its turn, and a cut says so once (section 12) ------------------------------------------------------
for (const [key, route, fill, reach, every] of [['workflow-run-finished', RUNS, fillRuns, 120, 2], ['release-published', RELEASES, fillReleases, 100, 5]]) {
  test(`${key}: a long list cut by its bound waits its normal interval, since reading the window again gets no further and the owner's token pays for each read`, async t => {
    const world = triggerWorld(t, 'github', {keys: [key]});
    fill(world, reach);
    const {id} = await watching(t, key, {world}), spent = world.simulator.rate.used, sent = reads(world, route).length;
    await world.ticking(10 * MINUTE);
    assert.equal(reads(world, route).length - sent, 10 / every * triggerOf(key).bounds.pages, 'one walk for each interval that passed');
    assert.ok(world.simulator.rate.used - spent <= 10 / every * triggerOf(key).bounds.pages, 'and the owner\'s token pays for that alone');
    assert.equal(world.record(id).status, 'active');
    assert.deepEqual(await drained(world), []);
  });
}

test('more than 500 threads inside the overlap give one gap for one run of the cut and not one a poll, and the poll whose mark moves past what was unread tells the rest of that run', async t => {
  const {world, id} = await watching(t, 'notification'), {simulator} = world;
  times(540, index => simulator.notify(SANDBOX, {title: `Thread ${index}`}));
  await world.pollNow(id);
  const told = await drained(world), first = told.find(event => event.type === 'trigger.gap');
  assert.deepEqual([told.filter(event => event.type === 'trigger.event').length, first.fields.reason], [500, 'bound']);
  for (const poll of [1, 2, 3, 4, 5]) {
    world.advance(MINUTE);
    await world.pollNow(id);
    assert.deepEqual(await drained(world), [], `poll ${poll} read the same threads, cut at the same place`);
  }
  world.advance(MINUTE);
  const thread = simulator.notify(SANDBOX, {title: 'After the burst'});
  await world.pollNow(id);
  const closing = await drained(world);
  assert.deepEqual([closing[0].type, closing[0].fields.threadId, closing.slice(1).map(event => event.fields.reason)], ['trigger.event', thread, ['bound']]);
  assert.equal(closing[1].fields.from, first.fields.to, 'it starts where the first ended, so no stretch goes untold');
  world.advance(MINUTE);
  await world.pollNow(id);
  assert.deepEqual(await drained(world), [], 'the mark passed the burst, so the read fits and the run is over');
  times(540, index => simulator.notify(SANDBOX, {title: `Next ${index}`}));
  await world.pollNow(id);
  assert.deepEqual(kinds(await drained(world)).filter(([type]) => type === 'trigger.gap'), [['trigger.gap', 'bound']], 'a new burst is a new run');
});

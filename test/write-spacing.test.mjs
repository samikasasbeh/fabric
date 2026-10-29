import test from 'node:test';
import assert from 'node:assert/strict';
import {WRITE_SPACING_MS, spaceWrite} from '../lib/write-spacing.mjs';
import {githubHarness, probeFile, SANDBOX} from './fixtures/actions/github-harness.mjs';
import {calendarHarness} from './fixtures/actions/calendar-harness.mjs';

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1 and section 3, spec line 1143): GitHub's writes run one at a time (the account's write
// lock) and at least 1 second apart, whichever path sends them: an action or a raw proxied request. The wait goes through the runtime's
// wait(ms) seam, which the harness turns into a move of its fake clock, so these tests take no real time. Reads never wait, and an app the
// reviewed table does not name (Calendar) never waits. Everything runs on the GitHub simulator; nothing calls GitHub.
const [OWNER, REPO] = SANDBOX.split('/');
const comment = (h, body) => h.run('comment v1', {owner: OWNER, repo: REPO, number: 1, body});
const sentAt = h => h.simulator.writes().map(call => call.at);

test('the reviewed table spaces GitHub writes 1 second apart and names no other app', () => {
  assert.deepEqual(WRITE_SPACING_MS, {github: 1000});
  assert.ok(Object.isFrozen(WRITE_SPACING_MS));
});

test('spaceWrite() waits what is left of the gap since the account\'s last write, through runtime.wait, then records this write; another account or app is apart', async () => {
  let now = 10_000;
  const waits = [], runtime = {clock: () => now, wait: async ms => { waits.push(ms); now += ms; }};
  assert.equal(await spaceWrite(runtime, {appId: 'github', connectionId: 'a'}), 0, 'a first write waits nothing');
  now += 300;
  assert.equal(await spaceWrite(runtime, {appId: 'github', connectionId: 'a'}), 700);
  assert.equal(await spaceWrite(runtime, {appId: 'github', connectionId: 'b'}), 0, 'each account has its own gap');
  now += 1000;
  assert.equal(await spaceWrite(runtime, {appId: 'github', connectionId: 'a'}), 0, 'a gap already passed waits nothing');
  for (const appId of ['google-calendar', 'gmail', 'notion', 'slack', 'fixture']) {
    assert.equal(await spaceWrite(runtime, {appId, connectionId: 'a'}), 0, appId);
    assert.equal(await spaceWrite(runtime, {appId, connectionId: 'a'}), 0, `${appId}, right after`);
  }
  assert.deepEqual(waits, [700]);
  const other = {clock: () => now, wait: async ms => { waits.push(ms); now += ms; }};
  assert.equal(await spaceWrite(other, {appId: 'github', connectionId: 'a'}), 0, 'each runtime keeps its own times');
});

test('two GitHub action writes on one account arrive at least 1,000 ms apart on the fake clock, the second having waited the rest of the gap; nothing is sent during the wait', async t => {
  const h = githubHarness(t, {file: probeFile()});
  const first = await h.approve(await comment(h, 'one'));
  assert.equal(first.status, 'succeeded', JSON.stringify(first.error));
  h.advance(400);
  const second = await h.approve(await comment(h, 'two'));
  assert.equal(second.status, 'succeeded');
  assert.deepEqual(sentAt(h).map(at => at - sentAt(h)[0]), [0, 1000]);
  assert.deepEqual(h.waits, [{ms: 600, writesBefore: 1}], 'the second write waited the rest of the gap, and was not sent until it had');
  // Each write was read back right after it: the readbacks never waited.
  assert.equal(h.simulator.reads().filter(call => call.route === 'GET /repos/{owner}/{repo}/issues/comments/{comment_id}').length, 2);
  h.advance(1500);
  assert.equal((await h.approve(await h.run('create-issue v1', {owner: OWNER, repo: REPO, title: 'Later'}))).status, 'succeeded');
  assert.equal(h.waits.length, 1, 'a write 1,500 ms after the last one waits nothing');
});

test('reads never wait, even right after a write', async t => {
  const h = githubHarness(t, {file: probeFile()});
  await h.approve(await comment(h, 'one'));
  for (let index = 0; index < 3; index++) assert.equal((await h.run('read-issue v1', {owner: OWNER, repo: REPO, number: 1})).status, 'succeeded');
  assert.equal((await h.proxy('GET', `/repos/${SANDBOX}/issues/1`)).status, 'succeeded');
  assert.deepEqual(h.waits, []);
});

test('proxied GitHub writes are spaced too, and with an action\'s writes on the same account', async t => {
  const h = githubHarness(t, {file: probeFile()});
  const post = body => h.proxy('POST', `/repos/${SANDBOX}/issues/1/comments`, {body: {body}});
  const first = await post('raw one');
  assert.equal(first.status, 'awaiting_approval');
  await h.approve(first);
  await h.approve(await post('raw two'));
  await h.approve(await comment(h, 'action three'));
  assert.deepEqual(sentAt(h).map(at => at - sentAt(h)[0]), [0, 1000, 2000]);
  assert.deepEqual(h.waits, [{ms: 1000, writesBefore: 1}, {ms: 1000, writesBefore: 2}]);
  assert.deepEqual(h.simulator.state().repos[SANDBOX].comments.map(item => item.body), ['raw one', 'raw two', 'action three']);
});

test('a Calendar write never waits: Calendar is not in the reviewed table', async t => {
  const h = calendarHarness(t), waits = [];
  h.runtime.wait = async ms => { waits.push(ms); };
  const create = summary => h.run('create-event v1', {calendarId: 'primary', kind: 'timed', summary, notify: 'none', start: '2026-11-02T10:00:00', end: '2026-11-02T10:30:00'});
  for (const summary of ['One', 'Two']) {
    const job = await create(summary);
    assert.equal(job.status, 'awaiting_approval', JSON.stringify(job.error));
    assert.equal((await h.approve(job)).status, 'succeeded');
  }
  assert.equal(h.simulator.writes().length, 2);
  assert.deepEqual(waits, []);
});

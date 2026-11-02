import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {triggerEvidencePasses} from '../lib/action-catalog.mjs';
import {PINS} from '../lib/transform-pins.mjs';
import {IDS} from './fixtures/provider-simulators/slack.mjs';
import {shippedTriggers, triggerWorld, TRIGGER_APPS} from './fixtures/actions/trigger-harness.mjs';

// Iteration 9 part 3h (docs/I07-BUILD-MAP.md step 3): the harness steps 4 to 8 share. It holds no rule of its own, so these tests ask only that it is what those steps need: a real trigger of each
// app active in a temp copy, and one whole round on a real simulator. Nothing here listens on a port or reaches a provider. Until an app's step ships its file, the harness reads its draft.
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const INTERVAL = 150_000, CHANNEL = IDS.fabricTest, MESSAGES = 'slack.messages.read';
/** A trigger of each app that names no transform its own step has yet to ship. */
const LOADS_TODAY = Object.freeze({slack: ['new-message', {channels: [CHANNEL]}], notion: ['new-comment', {pages: ['0f0e0d0c0b0a49088706050403020100']}], github: ['push', {repository: 'octo-a/fabric-sandbox'}],
  gmail: ['new-email-matching-search', {search: {subject: '[SYNTHETIC] Fabric x'}}], 'google-calendar': ['new-event', {calendarId: 'run-a@group.calendar.google.com'}]});
const conversation = world => world.simulator.calls.filter(call => call.name === 'conversations.history');
/** Lets anything a call started and left running reach its first request: a poll runs behind promise turns, so an assertion straight after the call cannot see one. */
async function settled(world) {
  for (let turn = 0; turn < 5; turn++) await new Promise(resolve => setImmediate(resolve));
  await world.engine.running;
}
/** What a world must leave as it found it in the repository: whether the evidence exists, and the bytes of the file it copies. */
const repository = appId => ({evidence: existsSync(path.join(ROOT, 'docs', 'live-evidence', appId, 'triggers.json')), file: JSON.stringify(shippedTriggers(appId))});

test('each app: a temp copy with computed ids is reviewed and certified there alone, its evidence passes the real check, and a subscribe sends nothing', async t => {
  assert.deepEqual(Object.keys(LOADS_TODAY).sort(), [...TRIGGER_APPS].sort());
  for (const [appId, [key, args]] of Object.entries(LOADS_TODAY)) {
    const before = repository(appId), world = triggerWorld(t, appId, {keys: [key]}), id = world.triggerId(key), {status, reason, entry} = world.catalog.triggerOf(id);
    assert.deepEqual([appId, status, reason], [appId, 'active', null]);
    assert.deepEqual(world.triggerFile.triggers.map(item => [item.key, item.id === id]), [[key, true]], 'only the keys asked for, under the id the validator computes');
    assert.equal(world.triggerFile.reviewStatus, 'reviewed');
    assert.deepEqual(entry.trigger.certified, {evidence: `docs/live-evidence/${appId}/triggers.json`});
    // The evidence and the file sit under the temp root, and the repository stays as it was, whatever a live pass has written there.
    const evidence = JSON.parse(readFileSync(path.join(world.root, 'docs', 'live-evidence', appId, 'triggers.json'), 'utf8'));
    assert.equal(triggerEvidencePasses(entry, evidence[id], PINS.transforms), true);
    assert.ok(existsSync(path.join(world.root, 'catalog', 'triggers', `${appId}.json`)));
    assert.ok(path.relative(ROOT, world.root).startsWith('..'), 'the temp root is outside the repository');
    assert.deepEqual(repository(appId), before);
    const listed = (await world.call('triggers.list')).result.triggers.find(item => item.id === id);
    assert.deepEqual([listed.status, listed.connectionIds], ['available', [world.account]], `${appId}: ${listed.reason}`);
    const sent = [], send = world.runtime.request;
    world.runtime.request = options => { sent.push(options.url); return send(options); };
    const watch = await world.subscribe(key, args);
    assert.deepEqual([watch.status, watch.approvalRequired], ['awaiting_approval', true]);
    assert.equal(world.approve(watch.id).status, 'starting');
    await settled(world);
    assert.deepEqual(sent, [], 'neither a subscribe nor an approval reads anything');
  }
});

test('one round on Slack\'s simulator: the first poll is silent, one write gives one event, a re-poll gives zero, and a row at Never stops the reads and holds the watch', async t => {
  const world = triggerWorld(t, 'slack', {keys: ['new-message']}), {id} = await world.subscribe('new-message', {channels: [CHANNEL]});
  assert.equal(world.approve(id).status, 'starting');
  world.simulator.seed(CHANNEL, {text: 'Before the watch'});
  assert.equal((await world.pollNow(id)).status, 'active', 'the first poll reached the present');
  assert.deepEqual((await world.events()).events, [], 'a baseline stores nothing');
  world.advance(INTERVAL);
  const ts = world.simulator.seed(CHANNEL, {text: 'After the watch'});
  await world.pollNow(id);
  const first = await world.events();
  assert.deepEqual(first.events.map(event => [event.type, event.fields.ts, event.subscriptionId]), [['trigger.event', ts, id]]);
  world.advance(INTERVAL);
  await world.pollNow(id);
  assert.deepEqual((await world.events()).events, [], 'events reads on from where the last page ended, so a re-poll gives zero');
  world.setRow(MESSAGES, 'ask');
  const reads = conversation(world).length;
  world.advance(INTERVAL);
  assert.deepEqual([(await world.pollNow(id)).status, world.record(id).reason, conversation(world).length], ['paused', 'permission_changed', reads]);
  // The row back at Allow leaves it paused until the owner resumes it, and the resume reads the digest as the page shows it.
  world.setRow(MESSAGES, 'allow');
  assert.equal(world.resume(id).status, 'starting');
  world.advance(INTERVAL);
  assert.equal((await world.pollNow(id)).status, 'active');
  const {events} = await world.events();
  assert.deepEqual(events.map(event => [event.type, event.fields.reason]), [['trigger.gap', 'resume']]);
});

test('Slack\'s history row opens on any of four scopes, so a scope Slack says is gone pauses the watch itself: access_missing, not a backoff or a change of account', async t => {
  const world = triggerWorld(t, 'slack', {keys: ['new-message']}), {id} = await world.subscribe('new-message', {channels: [CHANNEL]});
  world.approve(id);
  await world.pollNow(id);
  world.advance(INTERVAL);
  world.simulator.revokeScope('channels:history');
  const watch = await world.pollNow(id);
  assert.deepEqual([watch.status, watch.reason, watch.detail], ['paused', 'access_missing', 'missing_scope']);
  assert.equal(world.subscriptions.health(watch).state, 'access_missing');
  // A Resume reads once more, is told the same, and pauses again: it never sits at `starting` retrying.
  world.advance(INTERVAL);
  assert.equal(world.resume(id).status, 'starting');
  const again = await world.pollNow(id);
  assert.deepEqual([again.status, again.reason], ['paused', 'access_missing']);
});

test('a watch on an object resource reads its parts: Gmail\'s search reaches the query, as the card shows it', async t => {
  const world = triggerWorld(t, 'gmail', {keys: ['new-email-matching-search']}), {id} = await world.subscribe('new-email-matching-search', {search: {subject: 'Quarterly numbers'}}), sent = [], send = world.runtime.request;
  world.runtime.request = options => { sent.push(new URL(options.url).searchParams.get('q')); return send(options); };
  assert.equal(world.approve(id).status, 'starting');
  await world.pollNow(id);
  assert.deepEqual(sent, ['subject:"Quarterly numbers" newer_than:7d']);
});

test('a Notion link, a dashed id and a plain id name one watch, for a data source as for a page, on the real path from subscribe', async t => {
  const dashed = '1429989f-e8ac-4eff-bc8f-57f56486db54', plain = dashed.replaceAll('-', ''), link = `https://www.notion.so/My-Source-${plain}`;
  const world = triggerWorld(t, 'notion', {keys: ['new-row', 'new-comment']}), first = await world.subscribe('new-row', {dataSourceId: link});
  assert.equal(world.record(first.id).args.dataSourceId, dashed);
  for (const spelling of [dashed, plain]) assert.equal((await world.subscribe('new-row', {dataSourceId: spelling})).id, first.id);
  const pages = await world.subscribe('new-comment', {pages: [link, dashed, plain]});
  assert.deepEqual(world.record(pages.id).args.pages, [dashed]);
  await assert.rejects(world.subscribe('new-row', {dataSourceId: 'https://example.com/not-notion-at-all-1429989fe8ac4eff'}), error => error.code !== undefined, 'a link of another host is no Notion id');
});

test('a provider wait passes on the fake clock, so pollNow never sits out a real one', async t => {
  const world = triggerWorld(t, 'slack', {keys: ['new-message']}), {id} = await world.subscribe('new-message', {channels: [CHANNEL]}), started = world.now;
  world.approve(id);
  await world.pollNow(id);
  const {feeds: [feedId]} = world.record(id), feed = world.store.get('triggerFeeds', feedId);
  world.store.put('triggerFeeds', {...feed, notBefore: started + 90_000});
  const at = performance.now();
  await world.pollNow(id);
  assert.ok(performance.now() - at < 5000);
  assert.ok(world.now >= started + 90_000, 'the fake clock moved through it');
});

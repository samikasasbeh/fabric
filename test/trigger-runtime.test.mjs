import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {CURSOR_CHECKS, POLL_HEADERS, judgeAnswer, normalizeArgs, waitOf, windowRule} from '../lib/trigger-runtime.mjs';
import {credentialContext, holdsCredential} from '../lib/actions-runtime.mjs';
import {TRANSFORMS} from '../lib/transforms/index.mjs';
import {triggerIds, triggerLens, validateTriggerFile} from '../lib/triggers.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';
import {feedTriggers, triggerHarness} from './fixtures/actions/trigger-fixture.mjs';
import {TOKEN, slackHarness} from './fixtures/actions/runtime-fixture.mjs';
import {FIVE, githubHarness, probeFile} from './fixtures/actions/github-harness.mjs';

// Iteration 9 part 2b (docs/I07-BUILD-MAP.md sections 2.2 to 2.4): one poll, on the fixture app's feed. runPoll() makes no store write of its own, so these
// tests stand in for the scheduler of part 2c: keep() stores what a poll returned in the order section 2.4 names. Nothing here reaches a provider.
const DAY = 86_400_000, HOUR = 3_600_000, MINUTE = 60_000;
const pass = () => ({ok: true});
const sha = text => createHash('sha256').update(text).digest('hex');
const FEED_FIELDS = ['cursors', 'page', 'floor', 'draining', 'budgetStops', 'recordFailures', 'unreadTo', 'notBefore', 'baselined', 'lastGoodAt'];
const ITEM_EVENT = {schema: {type: 'object', properties: {id: {type: 'string', minLength: 1, maxLength: 64}}, required: ['id'], additionalProperties: false}, id: {item: '/id'}, occurredAt: {item: '/id'}, fields: {id: {item: '/id'}}, summary: []};

/** The fixture triggers with one changed, by key. */
const edited = (key, change) => feedTriggers().map(item => { const copy = structuredClone(item); if (item.key === key) change(copy); return copy; });
const DETAIL = () => ({id: 'detail', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, maxResponseBytes: 65_536, expect: {status: [200], require: []}});
/** One trigger's copy under a new key, on the same poll. */
const twin = (key, name, change = () => {}) => { const copy = structuredClone(feedTriggers().find(item => item.key === key)); Object.assign(copy, {key: name, id: `fixture.trigger.${name}.v1.${'0'.repeat(24)}`}); change(copy); return copy; };
/** A poll held to `pages` pages, by its step's own limit too, as the validator asks. */
const pagesOf = (item, pages) => { item.bounds.pages = pages; item.poll.source.steps[0].page.max = pages; };
/** A small polling trigger on a real app's rows, for what only a reviewed sign-in holds. */
const gistTrigger = () => ({id: `github.trigger.gists.v1.${'0'.repeat(24)}`, key: 'gists', version: 1, name: 'A gist appeared', description: 'A gist appeared.', delivery: {method: 'polling', intervalSeconds: {default: 120, min: 60}},
  inputSchema: {type: 'object', properties: {}, additionalProperties: false}, resource: [], poll: {source: {steps: [{id: 'list', method: 'GET', path: '/gists', expect: {status: [200], require: []}}]}, items: {step: 'list', pointer: ''}, itemId: {item: '/id'}, itemVersion: null, order: 'unordered',
    cursors: [{name: 'seen', kind: 'snapshot@1', compare: 'collections.diff@1'}], resync: {statusIn: []}, minIntervalSeconds: 60}, dedupe: {kind: 'id'}, event: ITEM_EVENT, backfill: {default: 0, max: 0}, retention: {days: 7}, bounds: {pages: 1, items: 100, pollSeconds: 10}, rows: ['github.gists.read']});
/** The fixture app with only this trigger, its feed step's expect replaced, and no actions, as an app whose sign-in sets a success rule needs. */
const ruled = async () => {
  const {fixtureSignIn} = await import('./fixtures/actions/fixture-app.mjs');
  return {signIn: {...fixtureSignIn(), apiSuccessRequire: [{pointer: '/ok', equals: true}]}, file: {schemaVersion: 1, appId: 'fixture', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, actions: []},
    triggers: edited('feed-listed', item => { item.poll.source.steps[0].expect = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]}; }).filter(item => item.key === 'feed-listed')};
};
/** The harness, with what the scheduler of part 2c will do. `feedOf()` builds a feed as attach() will; resource values are a list by index, as `bound()` numbers them. */
function rig(t, options) {
  const h = triggerHarness(t, options);
  h.stored = 0;
  const entriesOf = feed => h.catalog.triggersOnPoll('fixture', feed.pollHash);
  return Object.assign(h, {entriesOf,
    feedOf: (key, {resource = [], tracked = [key], ...fields} = {}) => ({id: `feed-${key}`, appId: 'fixture', connectionId: h.account, pollHash: h.itemOf(key).pollHash, resource, epoch: 0, lenses: tracked.flatMap(name => h.itemOf(name).lenses), cursors: {},
      page: null, baselined: false, floor: null, draining: false, budgetStops: 0, recordFailures: 0, lastGoodAt: null, nextPollAt: 0, notBefore: null, failures: 0, wait: null, createdAt: new Date(h.now).toISOString(), ...fields}),
    read: (feed, subscriptions, options = {}) => h.catalog.runPoll({runtime: h.runtime, feed, entries: entriesOf(feed), subscriptions, memo: new Map(), authority: pass, ...options}),
    keep(feed, result) {
      h.stored += h.store.appendPoll({feedId: feed.id, seen: result.seen, seenLimits: result.seenLimits, events: result.events}).added['client-1'] ?? 0;
      for (const name of FEED_FIELDS) feed[name] = result[name];
      return result;
    },
    async poll(feed, subscriptions, options) { return h.keep(feed, await h.read(feed, subscriptions, options)); },
    /** Polls until a poll reaches the live edge. */
    async settle(feed, subscriptions, options, most = 60) {
      for (let count = 0; count < most; count++) { const result = await h.poll(feed, subscriptions, options); if (result.reachedEdge) return result; h.advance(1000); }
      throw new Error('The feed never reached the live edge.');
    },
    /** A baselined feed and one active watch on it. */
    async watching(key, {args = {}, resource = [], tracked} = {}, options) {
      const feed = h.feedOf(key, {resource, ...(tracked ? {tracked} : {})}), watch = h.watch(key, {args, feeds: [feed.id]});
      await h.settle(feed, [watch], options);
      h.advance(MINUTE);
      return {feed, watch};
    },
    events: (client = 'client-1') => h.store.listEvents(client, 0, 5000),
    feedReads: () => h.simulator.calls.filter(call => call.route === 'GET /feed'),
    payloads: result => result.events.map(row => row.payload)});
}
const gaps = result => result.events.filter(row => row.kind === 'trigger.gap');
const fired = result => result.events.filter(row => row.kind === 'trigger.event');

const KINDS = [['feed-synced', {}, []], ['feed-logged', {}, []], ['feed-updated', {kinds: ['note']}, ['note']], ['feed-posted', {}, []], ['feed-tagged', {}, []], ['feed-modified', {}, []], ['feed-listed', {}, []]];

// ---- baseline and the fire table -----------------------------------------------------------------------------------------------------------
for (const [key, args, resource] of KINDS) {
  test(`spec 1860 and 1861, ${key}: the baseline emits nothing, even for an item edited inside the overlap, then one write gives one event and a re-poll none`, async t => {
    const h = rig(t), [first] = h.simulator.seed(3, {at: h.now - 10_000});
    h.advance(5_000);
    h.simulator.touch(first.id, {name: 'Edited just before the subscribe'});
    const feed = h.feedOf(key, {resource}), watch = h.watch(key, {args});
    const baseline = await h.settle(feed, [watch]);
    assert.equal(baseline.baselined, true);
    assert.equal(h.stored, 0, 'a baseline is silent');
    h.advance(MINUTE);
    await h.poll(feed, [watch]);
    assert.equal(h.stored, 0, 'the overlap reads the edited item again and finds it current');
    h.advance(MINUTE);
    h.simulator.write({name: 'New'});
    h.advance(1000);
    const one = await h.poll(feed, [watch]);
    assert.equal(fired(one).length, 1, 'one write, one event');
    assert.equal(h.stored, 1);
    h.advance(MINUTE);
    const again = await h.poll(feed, [watch]);
    assert.equal(fired(again).length, 0, 'a re-poll fires nothing');
    assert.equal(h.stored, 1);
  });
  test(`${key}: an empty resource has no cursor and is baselined, so its first item is a real event`, async t => {
    const h = rig(t), feed = h.feedOf(key, {resource}), watch = h.watch(key, {args});
    const baseline = await h.settle(feed, [watch]);
    assert.equal(baseline.baselined, true, 'baseline done is a flag, never "the cursor is set"');
    h.advance(MINUTE);
    h.simulator.write({name: 'First'});
    h.advance(1000);
    assert.equal(fired(await h.poll(feed, [watch])).length, 1);
  });
}

test('a seed sets the cursor, and the feed stays silent until its walk reaches the edge, because baselined is its own flag', async t => {
  const h = rig(t, {triggers: edited('feed-updated', item => { pagesOf(item, 1); })});
  h.simulator.seed(120, {spacingMs: 100});
  const feed = h.feedOf('feed-updated', {resource: ['note']}), watch = h.watch('feed-updated', {args: {kinds: ['note']}});
  const first = await h.poll(feed, [watch]);
  assert.equal(first.baselined, false, 'its bound cut the first walk');
  assert.ok(feed.cursors.since, 'though the seed gave the cursor');
  const rest = await h.settle(feed, [watch]);
  assert.equal(rest.baselined, true);
  assert.equal(h.stored, 0, 'a set cursor is not a finished baseline');
  assert.equal(h.feedReads().filter(call => call.query.limit === '1').length, 1, 'and a seed is read once');
});

test('step 3: an id built from parts the item lacks is a partial item, and an integer id is an id', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.itemId = {concat: [{const: 'item-'}, {item: '/number'}], max: 40}; item.event = {...ITEM_EVENT, id: {item: '/number'}, occurredAt: {item: '/number'}, fields: {id: {const: 'x'}}}; })}), {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'none'}, {number: 7}]}});
  const result = await h.read(feed, [watch]);
  assert.equal(fired(result).length, 1);
  assert.equal(result.run.skipped, 1);
  const plain = rig(t, {triggers: edited('feed-listed', item => { item.poll.itemId = {item: '/number'}; })}), other = await plain.watching('feed-listed');
  const updated = new Date(plain.now).toISOString();
  plain.simulator.fail('GET /feed', {status: 200, data: {items: [{number: 7, id: 'A', name: 'x', updated}, {number: 1.5, id: 'B', name: 'x', updated}, {number: '', id: 'C', name: 'x', updated}]}});
  const read = await plain.read(other.feed, [other.watch]);
  assert.equal(fired(read).length, 1);
  assert.equal(read.run.skipped, 2);
});

test('a joiner receives nothing while its pending list holds this feed, and the next item once it does not', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  const joiner = h.watch('feed-synced', {status: 'starting', pending: [feed.id]}), other = h.watch('feed-synced', {status: 'starting', pending: []});
  h.simulator.write();
  const result = await h.poll(feed, [watch, joiner, other]);
  assert.deepEqual(fired(result).map(row => row.subscriptionId).sort(), [watch.id, other.id].sort(), 'an active watch and a starting one that finished this feed');
  assert.equal(result.reachedEdge, true);
});

test('dedupe id: a seen item never reads again, and id+version fires each new version', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced'), item = h.simulator.write();
  assert.equal(fired(await h.poll(feed, [watch])).length, 1);
  h.advance(1000);
  h.simulator.touch(item.id, {name: 'Second'});
  assert.equal(fired(await h.poll(feed, [watch])).length, 1, 'id+version');
});

test('A to B to A fires twice, and every return gets its own key', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { item.dedupe = {kind: 'content-hash', fields: [{item: '/name'}]}; })});
  const [item] = h.simulator.seed(1, {name: 'Item'}), {feed, watch} = await h.watching('feed-synced');
  const change = async name => { h.advance(1000); h.simulator.touch(item.id, {name}); return fired(await h.poll(feed, [watch])); };
  assert.equal((await change('B')).length, 1, 'A to B');
  assert.equal((await change(`Item ${item.feedSerial}`)).length, 1, 'B to A');
  assert.equal((await change('B')).length, 1, 'A to B again');
  assert.equal(h.stored, 3, 'three changes, three stored events: the generation keeps the second B apart from the first');
});

test('a crash before the cursor moves replays the poll and fires nothing twice', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  h.simulator.write();
  const result = await h.read(feed, [watch]);
  h.store.appendPoll({feedId: feed.id, seen: result.seen, seenLimits: result.seenLimits, events: result.events});
  const replay = await h.read(feed, [watch]);
  assert.equal(replay.events.length, 0, 'the seen rows are current');
  assert.equal(h.events().length, 1);
});

test('a crash before anything was stored computes the same event key, so a store that kept it holds one', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  h.simulator.write();
  const [first] = (await h.read(feed, [watch])).events, [second] = (await h.read(feed, [watch])).events;
  assert.equal(first.dedupeKey, second.dedupeKey);
});

test('dedupe.knownBy: a create is silent, a first edit fires, and a first edit of an occurrence passes', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { item.dedupe = {kind: 'content-hash', fields: [{item: '/name'}], knownBy: [{item: '/labels/0'}, {item: '/id'}]}; })});
  const [master] = h.simulator.seed(1), {feed, watch} = await h.watching('feed-synced');
  const created = h.simulator.write({name: 'Created'});
  assert.equal(fired(await h.poll(feed, [watch])).length, 0, 'known by nothing yet: a create says nothing');
  h.advance(1000);
  h.simulator.touch(created.id, {name: 'Edited'});
  assert.equal(fired(await h.poll(feed, [watch])).length, 1, 'its first edit fires');
  h.advance(1000);
  h.simulator.write({name: 'Occurrence'});
  h.advance(1000);
  const occurrence = h.simulator.state().items.find(item => item.name === 'Occurrence');
  h.simulator.touch(occurrence.id, {labels: [master.id]});
  assert.equal(fired(await h.poll(feed, [watch])).length, 1, 'its master is known, so this occurrence is a change, not a create');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: master.id, name: 'Null first', labels: [null], updated: new Date(h.now).toISOString()}]}});
  assert.equal(fired(await h.poll(feed, [watch])).length, 1, 'a null value is an absent one, so the next key answers');
});

test('an absent dedupe field hashes as null, so absent and null are one value', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.dedupe = {kind: 'content-hash', fields: [{item: '/missing'}]}; })}), [item] = h.simulator.seed(1);
  const {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: item.id, name: 'x', missing: null, updated: item.updated}]}});
  assert.equal(fired(await h.poll(feed, [watch])).length, 0);
});

test('a seen row and a dedupe key hold only hashes, so no address lands there', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), address = 'guest@fixture.test';
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: address, name: 'x', updated: new Date(h.now).toISOString()}]}});
  const result = await h.poll(feed, [watch]), [row] = result.seen, lens = feed.lenses[0];
  assert.equal(row.itemKey, sha(`${feed.id}|${lens}|${address}`));
  assert.doesNotMatch(JSON.stringify(result.seen), /guest/);
  assert.doesNotMatch(result.events[0].dedupeKey, /guest/);
  assert.equal(result.events[0].dedupeKey, `${row.itemKey}|${row.valueHash}|1`);
});

test('a filter runs before the seen row: a draft is unseen, and publishing it fires', async t => {
  const filter = [{equals: [{item: '/status'}, {const: 'published'}]}];
  const h = rig(t, {triggers: edited('feed-listed', item => { item.filter = filter; })}), [draft] = h.simulator.seed(1, {status: 'draft'});
  const {feed, watch} = await h.watching('feed-listed');
  assert.equal((await h.poll(feed, [watch])).seen.length, 0, 'filtered out, so no row');
  h.simulator.touch(draft.id, {status: 'published'});
  assert.equal(fired(await h.poll(feed, [watch])).length, 1);
});

test('step 2 of the item pipeline: a mark reads the raw items, so a run of filtered ones moves the cursor', async t => {
  const h = rig(t, {triggers: edited('feed-updated', item => { item.filter = [{equals: [{item: '/status'}, {const: 'published'}]}]; })});
  const {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  const [notice] = h.simulator.seed(1, {status: 'draft'});
  const result = await h.poll(feed, [watch]);
  assert.equal(result.events.length, 0);
  assert.equal(result.cursors.since, notice.updated, 'a join notice filtered out still moves the mark');
});

test('step 3: a partial item with no id, or with no time its format can read where its block has one, is skipped and counted, and adds no mark', async t => {
  const h = rig(t, {triggers: edited('feed-updated', item => { item.event = ITEM_EVENT; })}), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  const updated = new Date(h.now).toISOString();
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{name: 'No id', updated}, {id: 'A', name: 'No time'}, {id: 'C', name: 'A time of no form', updated: 'yesterday'}, {id: 'B', name: 'Whole', updated}]}});
  const result = await h.poll(feed, [watch]);
  assert.equal(fired(result).length, 1);
  assert.equal(result.run.skipped, 3);
  assert.equal(result.run.items, 4);
  assert.equal(result.cursors.since, updated);
});

test('an item time in a number format reads as its text', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.itemTime = {pointer: '/number', format: 'epoch-seconds'}; })}), {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{number: 1_800_000_000, id: 'A', name: 'x', updated: new Date(h.now).toISOString()}]}});
  const [row] = (await h.read(feed, [watch])).events;
  assert.equal(row.itemTime, 1_800_000_000);
});

test('one poll that reads an item twice compares with what it just read', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), updated = new Date(h.now).toISOString(), same = {id: 'A', name: 'x', updated};
  h.simulator.fail('GET /feed', {status: 200, data: {items: [same, same]}});
  assert.equal(fired(await h.read(feed, [watch])).length, 1, 'kind id');
  const versions = rig(t), running = await versions.watching('feed-synced');
  versions.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: 'x', updated}, {id: 'A', name: 'x', updated: new Date(versions.now + 1000).toISOString()}]}});
  const result = await versions.read(running.feed, [running.watch]);
  assert.equal(fired(result).length, 2, 'two versions');
  assert.equal(result.seen.length, 1);
  assert.equal(result.seen[0].generation, 2);
});

test('an item with no version hashes as null and stops nothing', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: 'x'}]}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual(result.lensPauses, []);
  assert.equal(result.seen.length, 1);
});

// ---- events --------------------------------------------------------------------------------------------------------------------------------
test('an event is built with its subscription\'s own args, in the stored shape, and held by its trigger\'s retention', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note', 'task']}, resource: ['note']}), item = h.simulator.write({name: 'Named'});
  const [row] = (await h.poll(feed, [watch])).events;
  assert.equal(row.kind, 'trigger.event');
  assert.equal(row.clientId, 'client-1');
  assert.equal(row.connectionId, h.account);
  assert.equal(row.createdAt, h.now);
  assert.equal(row.expiresAt, h.now + 7 * DAY);
  assert.deepEqual(row.payload, {type: 'trigger.event', id: item.id, occurredAt: item.updated, fields: {id: item.id, name: 'Named'}, summary: [{label: 'Item', value: 'Named'}]});
  assert.equal(row.itemTime, Date.parse(item.updated));
});

test('an event and a gap carry their subscription\'s owner, so an erasure reaches them', async t => {
  const h = rig(t), {feed} = await h.watching('feed-synced'), watch = h.watch('feed-synced', {userRecordId: 'usr_1'});
  h.simulator.write();
  assert.equal((await h.read(feed, [watch])).events[0].userRecordId, 'usr_1');
  h.simulator.expireCursors();
  assert.equal(gaps(await h.read(feed, [watch]))[0].userRecordId, 'usr_1');
});

test('two subscriptions of one lens each get an event built with their own args', async t => {
  const h = rig(t, {triggers: edited('feed-updated', item => { item.event.fields.name = {input: '/kinds/0'}; })}), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note', 'task']}, resource: ['note']});
  const other = h.watch('feed-updated', {args: {kinds: ['task', 'note']}, clientId: 'client-2'});
  h.simulator.write();
  const rows = (await h.read(feed, [watch, other])).events;
  assert.deepEqual(rows.map(row => row.payload.fields.name), ['note', 'task']);
  assert.deepEqual(rows.map(row => row.clientId), ['client-1', 'client-2']);
});

test('two triggers that share a lens each get the event and the retention of their own trigger', async t => {
  const h = rig(t, {triggers: [...feedTriggers(), twin('feed-listed', 'feed-listed-short', item => { item.event = {...ITEM_EVENT, occurredAt: {item: '/updated'}, summary: [{label: 'Short', expr: {item: '/id'}}]}; item.retention = {hours: 1}; })]});
  assert.deepEqual(h.itemOf('feed-listed').lenses, h.itemOf('feed-listed-short').lenses, 'only the event and the retention differ, and neither is in a lens');
  const feed = h.feedOf('feed-listed'), long = h.watch('feed-listed', {feeds: [feed.id]}), short = h.watch('feed-listed-short', {feeds: [feed.id]});
  await h.settle(feed, [long, short]);
  h.advance(MINUTE);
  h.simulator.write({name: 'For both'});
  const rows = fired(await h.read(feed, [long, short])), of = watch => rows.find(row => row.subscriptionId === watch.id);
  assert.deepEqual(Object.keys(of(short).payload.fields), ['id'], 'a watch reads only what its own card lists');
  assert.deepEqual(of(short).payload.summary.map(line => line.label), ['Short']);
  assert.equal(of(short).expiresAt - of(short).createdAt, HOUR);
  assert.deepEqual(Object.keys(of(long).payload.fields), ['id', 'name']);
  assert.deepEqual(of(long).payload.summary.map(line => line.label), ['Item']);
  assert.equal(of(long).expiresAt - of(long).createdAt, 7 * DAY);
});

test('two triggers that name one resource differently share a lens, and each event reads it by its own name', async t => {
  const renamed = item => {
    item.resource = {each: '/kinds', as: 'sort'};
    item.poll.source.steps[0].query.kind = {var: 'sort'};
    item.poll.seed.step.query.kind = {var: 'sort'};
    item.event = {schema: {type: 'object', properties: {id: {type: 'string', minLength: 1, maxLength: 64}, sort: {type: 'string', minLength: 1, maxLength: 64}}, required: ['id', 'sort'], additionalProperties: false}, id: {item: '/id'}, occurredAt: {item: '/updated'}, fields: {id: {item: '/id'}, sort: {var: 'sort'}}, summary: []};
  };
  const h = rig(t, {triggers: [...feedTriggers(), twin('feed-updated', 'feed-updated-sorted', renamed)]});
  assert.equal(h.itemOf('feed-updated').pollHash, h.itemOf('feed-updated-sorted').pollHash, 'the name of a resource never moves a poll');
  assert.deepEqual(h.itemOf('feed-updated').lenses, h.itemOf('feed-updated-sorted').lenses, 'nor a lens');
  const feed = h.feedOf('feed-updated', {resource: ['note']}), watch = h.watch('feed-updated-sorted', {args: {kinds: ['note']}, feeds: [feed.id]});
  await h.settle(feed, [watch]);
  h.advance(MINUTE);
  h.simulator.write({kind: 'note'});
  const [row] = fired(await h.read(feed, [watch]));
  assert.equal(row.payload.fields.sort, 'note');
});

test('a summary line is cut to its truncate', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: 'x'.repeat(150), updated: new Date(h.now).toISOString()}]}});
  assert.deepEqual((await h.poll(feed, [watch])).events[0].payload.summary, [{label: 'Item', value: 'x'.repeat(120)}]);
});

test('a null summary value counts as absent', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.event.summary = [{label: 'Name', expr: {item: '/nothing'}}, {label: 'Id', expr: {item: '/id'}}]; })}), {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: 'x', nothing: null, updated: new Date(h.now).toISOString()}]}});
  assert.deepEqual((await h.poll(feed, [watch])).events[0].payload.summary, [{label: 'Id', value: 'A'}]);
});

test('an event that fails checkEvent is skipped and counted, and never blocks the cursor', async t => {
  const h = rig(t, {triggers: edited('feed-updated', item => { item.event.fields.name = {item: '/name'}; })}), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  const updated = new Date(h.now).toISOString();
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: 'y'.repeat(201), updated}, {id: 'B', name: 'fine', updated}]}});
  const result = await h.poll(feed, [watch]);
  assert.deepEqual(fired(result).map(row => row.payload.id), ['B']);
  assert.equal(result.run.skipped, 1);
  assert.equal(result.cursors.since, updated);
});

test('an event past 8,192 bytes is held here, where it skips one item, and not at the store, where it would refuse the whole poll', async t => {
  const lines = Array.from({length: 8}, (_, index) => ({label: `Line ${index}`, expr: {item: '/name'}, truncate: 1000}));
  const h = rig(t, {triggers: edited('feed-listed', item => { item.event.summary = lines; })}), {feed, watch} = await h.watching('feed-listed');
  const updated = new Date(h.now).toISOString();
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: '"'.repeat(1000), updated}, {id: 'B', name: 'fine', updated}]}});
  const result = await h.poll(feed, [watch]);
  assert.deepEqual(fired(result).map(row => row.payload.id), ['B']);
  assert.equal(result.run.skipped, 1);
  assert.equal(result.seen.length, 2, 'its row is written, so it is not read again');
});

test('a real item whose event fails is told as one gap, however many fail in a poll, and a poll with none gives none', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { item.event.fields.name = {item: '/name'}; })}), {feed, watch} = await h.watching('feed-synced'), updated = new Date(h.now).toISOString(), from = new Date(feed.lastGoodAt).toISOString();
  const answer = {status: 200, data: {items: [{id: 'A', name: 'y'.repeat(201), updated}, {id: 'B', name: 'y'.repeat(201), updated}, {id: 'C', name: 'fine', updated}], nextSyncToken: 's1'}};
  h.simulator.fail('GET /feed', answer);
  const result = await h.poll(feed, [watch]);
  assert.deepEqual([fired(result).map(row => row.payload.id), result.run.skipped], [['C'], 2]);
  assert.deepEqual(gaps(result).map(row => [row.payload.fields.reason, row.payload.fields.from, row.subscriptionId]), [['stall', from, watch.id]]);
  h.advance(MINUTE);
  h.simulator.fail('GET /feed', answer);
  assert.equal((await h.poll(feed, [watch])).events.length, 0, 'its seen row keeps it from coming back');
});

test('an event a watch that is still catching up would not get tells it of nothing', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { item.event.fields.name = {item: '/name'}; })}), {feed} = await h.watching('feed-synced'), watch = h.watch('feed-synced', {status: 'starting', pending: [feed.id]}), updated = new Date(h.now).toISOString();
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: 'y'.repeat(201), updated}], nextSyncToken: 's1'}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual([result.events, result.run.skipped], [[], 0]);
});

// ---- lenses --------------------------------------------------------------------------------------------------------------------------------
test('a lens with no live subscription sends no enrich read, fires nothing and writes no row on a history feed', async t => {
  const h = rig(t), tracked = ['feed-logged', 'feed-logged-detail', 'feed-logged-keys'];
  const {feed, watch} = await h.watching('feed-logged', {tracked});
  h.simulator.write();
  const result = await h.poll(feed, [watch]);
  assert.equal(fired(result).length, 1);
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /items/{item_id}' || call.route === 'GET /keys').length, 0, 'a watch reads only what its own card lists');
  assert.deepEqual([...new Set(result.seen.map(row => row.lens))], h.itemOf('feed-logged').lenses, 'no row for a lens nobody watches');
});

test('an unwatched lens writes rows only where it can tell an item: no row with an enrich step on a list, and none on a history feed', async t => {
  const triggers = [...feedTriggers(), twin('feed-listed', 'feed-listed-detail', item => { item.poll.enrich = {max: 25, steps: [DETAIL()]}; }), twin('feed-logged', 'feed-logged-plain', item => { item.filter = [{present: {item: '/id'}}]; })];
  const h = rig(t, {triggers}), listed = await h.watching('feed-listed', {tracked: ['feed-listed', 'feed-listed-detail']});
  h.simulator.write();
  assert.deepEqual([...new Set((await h.read(listed.feed, [listed.watch])).seen.map(row => row.lens))], h.itemOf('feed-listed').lenses);
  const logged = await h.watching('feed-logged', {tracked: ['feed-logged', 'feed-logged-plain']});
  h.simulator.write();
  assert.deepEqual([...new Set((await h.read(logged.feed, [logged.watch])).seen.map(row => row.lens))], h.itemOf('feed-logged').lenses);
});

test('a new subscription on a running sync feed needs no second walk: an unwatched lens keeps its rows at the current value', async t => {
  const triggers = [...feedTriggers(), twin('feed-synced', 'feed-synced-names', item => { item.dedupe = {kind: 'content-hash', fields: [{item: '/name'}]}; })];
  const h = rig(t, {triggers}), tracked = ['feed-synced', 'feed-synced-names'], [item] = h.simulator.seed(1);
  assert.notEqual(h.itemOf('feed-synced').lenses[0], h.itemOf('feed-synced-names').lenses[0]);
  assert.equal(h.itemOf('feed-synced').pollHash, h.itemOf('feed-synced-names').pollHash);
  const {feed, watch} = await h.watching('feed-synced', {tracked});
  h.simulator.touch(item.id, {name: 'Changed'});
  const unwatched = await h.poll(feed, [watch]);
  assert.equal(unwatched.seen.filter(row => row.lens === h.itemOf('feed-synced-names').lenses[0]).length, 1, 'the unwatched lens took the new value');
  assert.equal(fired(unwatched).length, 1, 'and only the watched lens fired');
  const joiner = h.watch('feed-synced-names');
  h.advance(MINUTE);
  const calls = h.feedReads().length, next = await h.poll(feed, [watch, joiner]);
  assert.equal(h.feedReads().length, calls + 1, 'one read, no second walk');
  assert.equal(fired(next).length, 0, 'no false new event');
});

test('authority(trigger) drops only that lens: its enrich reads stop and the other lens still fires', async t => {
  const h = rig(t), tracked = ['feed-logged', 'feed-logged-detail'], {feed, watch} = await h.watching('feed-logged', {tracked}), detail = h.watch('feed-logged-detail');
  h.simulator.seed(3);
  const asked = [], lens = h.itemOf('feed-logged-detail').entry.id;
  const result = await h.read(feed, [watch, detail], {authority: item => { asked.push(item?.entry.id ?? null); return {ok: item?.entry.id !== lens}; }});
  assert.ok(asked.includes(null), 'a page asks with no trigger');
  assert.ok(asked.includes(lens), 'an enrich read asks with its own trigger');
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /items/{item_id}').length, 0);
  assert.equal(fired(result).length, 3, 'the plain lens read all three');
  assert.deepEqual([...new Set(result.events.map(row => row.subscriptionId))], [watch.id]);
});

test('a skip at any gate of the poll discards everything and keeps the cursor', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced'), before = structuredClone(feed.cursors);
  h.simulator.seed(120);
  let asks = 0;
  const result = await h.read(feed, [watch], {authority: () => ++asks <= 2 ? {ok: true} : {ok: false, skip: true, detail: 'reconnect_required'}});
  assert.equal(result.outcome, 'skipped');
  assert.deepEqual([result.events, result.seen], [[], []]);
  assert.deepEqual(result.cursors, before);
});

test('spec 1867: with no live subscription left at a page, the poll ends, discards what it read and keeps the cursor', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced'), before = structuredClone(feed.cursors);
  h.simulator.seed(120);
  const reads = h.feedReads().length;
  let asks = 0;
  const result = await h.read(feed, [watch], {authority: () => ({ok: ++asks <= 2})});
  assert.equal(result.outcome, 'withheld');
  assert.equal(h.feedReads().length, reads + 1, 'the first page went out, and the second did not');
  assert.deepEqual([result.events, result.seen], [[], []]);
  assert.deepEqual(result.cursors, before);
});

test('spec 1866: when the first gate fails there is no credentials call and no network', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed');
  let fetched = 0, calls = h.simulator.calls.length;
  const credentials = h.connections.credentials;
  h.connections.credentials = async id => { fetched++; return credentials(id); };
  const result = await h.read(feed, [watch], {authority: () => ({ok: false})});
  assert.equal(result.outcome, 'withheld');
  assert.equal(fetched, 0, 'a refresh is a network call');
  assert.equal(h.simulator.calls.length, calls);
});

test('the gate runs before and after credentials, for every request', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  const log = [], credentials = h.connections.credentials;
  h.connections.credentials = async id => { log.push('credentials'); return credentials(id); };
  const request = h.runtime.request;
  h.runtime.request = input => { log.push('request'); return request(input); };
  await h.read(feed, [watch], {authority: () => { log.push('gate'); return {ok: true}; }});
  assert.deepEqual(log, ['gate', 'credentials', 'gate', 'request']);
});

test('a value that cannot be hashed belongs to its lens too, and a provider cannot crash a poll with it', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.dedupe = {kind: 'content-hash', fields: [{item: '/odd'}]}; })}), {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: 'x', updated: new Date(h.now).toISOString(), odd: JSON.parse('{"__proto__": 1}')}]}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual(result.lensPauses.map(({code}) => code), ['value_unreadable']);
  assert.equal(result.outcome, 'withheld');
});

test('a transform refusal in a filter belongs to its lens: only that lens stops, and the other still fires', async t => {
  const triggers = edited('feed-logged', item => { item.filter = [{equals: [{pick: {transform: 'time.rfc3339ToEpochSeconds@1', args: {time: {item: '/id'}}}, pointer: '/seconds'}, {const: 1}]}]; });
  const h = rig(t, {triggers}), tracked = ['feed-logged', 'feed-logged-detail'], {feed, watch} = await h.watching('feed-logged', {tracked}), detail = h.watch('feed-logged-detail');
  h.simulator.write();
  const result = await h.read(feed, [watch, detail]);
  assert.deepEqual(result.lensPauses, [{lens: h.itemOf('feed-logged').lenses[0], code: 'time_invalid', reason: 'too_many_items'}]);
  assert.deepEqual(result.events.map(row => row.subscriptionId), [detail.id]);
  assert.equal(result.pause, undefined);
});

test('a lens that was dropped stays out of the rest of the walk', async t => {
  const refusing = [{equals: [{pick: {transform: 'time.rfc3339ToEpochSeconds@1', args: {time: {item: '/id'}}}, pointer: '/seconds'}, {const: 1}]}];
  const triggers = [...edited('feed-logged', item => { item.filter = refusing; }), twin('feed-logged', 'feed-logged-plain', item => { item.filter = [{present: {item: '/id'}}]; })];
  const h = rig(t, {triggers}), {feed, watch} = await h.watching('feed-logged', {tracked: ['feed-logged', 'feed-logged-plain']}), plain = h.watch('feed-logged-plain');
  h.simulator.seed(60);
  const result = await h.read(feed, [watch, plain]);
  assert.equal(fired(result).length, 60, 'the other lens read both pages');
  assert.equal(result.lensPauses.length, 1, 'and the refused one paused once');
});

test('a lens that hangs on a subscription\'s input reads with that input, and two such subscriptions each read their own', async t => {
  const triggers = edited('feed-listed', item => { item.inputSchema = {type: 'object', properties: {kind: {type: 'string', maxLength: 20}}, required: ['kind'], additionalProperties: false}; item.filter = [{nonEmpty: {input: '/kind'}}]; });
  const h = rig(t, {triggers}), entry = h.entryOf('feed-listed'), kept = h.watch('feed-listed', {args: {kind: 'note'}}), empty = h.watch('feed-listed', {args: {kind: ''}});
  assert.deepEqual(h.itemOf('feed-listed').lenses, [], 'this trigger gives no lens of its own');
  const feed = h.feedOf('feed-listed', {tracked: [], lenses: [triggerLens(entry, kept.args), triggerLens(entry, empty.args)]});
  await h.settle(feed, [kept, empty]);
  h.simulator.write();
  assert.deepEqual((await h.read(feed, [kept, empty])).events.map(row => row.subscriptionId), [kept.id], 'each lens read with its own subscription\'s value');
});

test('a resource value reaches the request by its index, whatever the input is called', async t => {
  const h = rig(t);
  await h.read(h.feedOf('feed-updated', {resource: ['task']}), [h.watch('feed-updated', {args: {kinds: ['note', 'task']}})]);
  assert.equal(h.feedReads().at(-1).query.kind, 'task', 'an {each} value');
  const named = rig(t, {triggers: edited('feed-updated', item => {
    item.inputSchema = {type: 'object', properties: {kind: {type: 'string', enum: ['note', 'task']}}, required: ['kind'], additionalProperties: false};
    item.resource = ['kind'];
    for (const step of [item.poll.seed.step, item.poll.source.steps[0]]) step.query.kind = {input: '/kind'};
  })});
  await named.read(named.feedOf('feed-updated', {resource: ['task']}), [named.watch('feed-updated', {args: {kind: 'task'}})]);
  assert.equal(named.feedReads().at(-1).query.kind, 'task', 'a named one');
});

test('each lens reads its own items expression over one page, and a value that is not a list is a list of one', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.items = {pick: {step: 'feed', pointer: ''}, pointer: '/0'}; })});
  h.simulator.seed(3);
  const {feed, watch} = await h.watching('feed-listed');
  assert.equal(feed.baselined, true);
  assert.equal((await h.read(feed, [watch])).run.items, 1, 'one object is a list of one');
});

// ---- the sender ----------------------------------------------------------------------------------------------------------------------------
test('POLL_HEADERS asks for every header the outcome table reads, beside what an action asks for', () => {
  for (const name of ['content-type', 'etag', 'last-modified', 'link', 'retry-after', 'x-poll-interval', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'x-ratelimit-used']) assert.ok(POLL_HEADERS.includes(name), name);
});

test('the sender sends the built bytes with report redirects, a timeout within the budget, the credential and the poll\'s own header list', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed');
  let seen;
  const request = h.runtime.request;
  h.runtime.request = input => { seen = input; return request(input); };
  const credentials = h.connections.credentials;
  h.connections.credentials = async id => ({...await credentials(id), allowedOrigins: ['https://api.fixture.test', 'https://other.fixture.test']});
  await h.read(feed, [watch], {deadline: h.now + 4000});
  assert.equal(seen.redirect, 'report');
  assert.equal(seen.timeoutMs, 4000);
  assert.equal(seen.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(seen.headers.Accept, 'application/json');
  assert.deepEqual(seen.allowedOrigins, ['https://api.fixture.test']);
  assert.deepEqual(seen.responseHeaders, POLL_HEADERS);
  assert.equal(seen.maxBytes, 262_144);
});

test('a built request that holds the credential is refused before it is sent', async t => {
  const h = rig(t), feed = h.feedOf('feed-updated', {resource: [TOKEN], baselined: true}), watch = h.watch('feed-updated', {args: {kinds: ['note']}});
  const calls = h.simulator.calls.length, result = await h.read(feed, [watch]);
  assert.equal(h.simulator.calls.length, calls, 'nothing left');
  assert.equal(result.outcome, 'backoff');
  assert.equal(result.run.code, 'credential_in_request');
});

test('a subscription\'s args that hold the credential stop the poll too', async t => {
  const h = rig(t), {feed} = await h.watching('feed-listed'), watch = h.watch('feed-listed', {args: {note: TOKEN}});
  const calls = h.simulator.calls.length, result = await h.read(feed, [watch]);
  assert.equal(h.simulator.calls.length, calls);
  assert.equal(result.run.code, 'credential_in_request');
});

test('the sender checks the account again after credentials: another identity or a revoked account ends the poll, and an account of no address sends nothing', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), calls = h.simulator.calls.length, credentials = h.connections.credentials;
  h.connections.credentials = async id => { h.store.put('connections', {...h.connection(), identity: {id: 'acct-2'}}); return credentials(id); };
  assert.equal((await h.read(feed, [watch])).outcome, 'withheld');
  assert.equal(h.simulator.calls.length, calls);
  h.store.put('connections', {...h.connection(), identity: {id: 'acct-1'}});
  h.connections.credentials = async id => { h.store.put('connections', {...h.connection(), status: 'revoked'}); return credentials(id); };
  assert.equal((await h.read(feed, [watch])).outcome, 'withheld');
  assert.equal(h.simulator.calls.length, calls);
  h.store.put('connections', {...h.connection(), status: 'ready'});
  h.connections.credentials = async id => ({...await credentials(id), allowedOrigins: ['https://elsewhere.fixture.test']});
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'backoff');
  assert.equal(h.simulator.calls.length, calls);
});

test('the headers Fabric adds are computed again and compared: a difference sends nothing', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), calls = h.simulator.calls.length, credentials = h.connections.credentials;
  h.connections.credentials = async id => { const granted = await credentials(id); return {...granted, headers: {...granted.headers, 'X-Fixture-Version': '2'}}; };
  const result = await h.read(feed, [watch]);
  assert.equal(result.run.code, 'prepared_changed');
  assert.equal(h.simulator.calls.length, calls);
});

test('every built request is placed again: one that lands off its step\'s reviewed member is refused before it is sent', async t => {
  const h = rig(t), item = structuredClone(h.itemOf('feed-listed'));
  item.entry.trigger.poll.source.steps[0].path = '/keys';
  delete item.entry.trigger.poll.source.steps[0].query;
  const result = await h.read(h.feedOf('feed-listed'), [h.watch('feed-listed')], {entries: [item]});
  assert.equal(result.outcome, 'backoff');
  assert.equal(result.run.code, 'not_on_member');
  assert.equal(h.simulator.calls.length, 0);
});

test('an account the proxy cannot route ends the poll with nothing sent, and a trigger with no steps of its own has no run path', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), calls = h.simulator.calls.length, item = structuredClone(h.itemOf('feed-listed'));
  item.entry.trigger.poll = {source: {action: {key: 'read', version: 1}, args: {}}};
  assert.equal((await h.read(feed, [watch], {entries: [item]})).run.code, 'no_run_path');
  h.store.put('connections', {...h.connection(), status: 'reconnect_required'});
  assert.equal((await h.read(feed, [watch])).run.code, 'proxy_unavailable');
  assert.equal(h.simulator.calls.length, calls);
});

test('a subscription of a lens this feed does not track reads nothing', async t => {
  const h = rig(t), feed = h.feedOf('feed-logged'), watch = h.watch('feed-logged-detail');
  assert.equal((await h.read(feed, [watch])).outcome, 'withheld');
  assert.equal(h.simulator.calls.length, 0);
});

test('a step filled by the file\'s pinned parameters builds with them', async t => {
  const h = rig(t), item = structuredClone(h.itemOf('feed-logged-detail'));
  delete item.entry.trigger.poll.enrich.steps[0].params;
  item.pinnedParameters = {item_id: 'F1'};
  item.lenses = [triggerLens(item.entry)];
  h.simulator.seed(1);
  const feed = h.feedOf('feed-logged', {tracked: [], lenses: item.lenses, baselined: true, cursors: {history: String(2n ** 53n)}});
  await h.read(feed, [h.watch('feed-logged-detail')], {entries: [item]});
  assert.equal(h.simulator.calls.at(-1).path, '/items/F1');
});

test('the pages of one poll stay within every trigger\'s bounds, as read from the catalog\'s items', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), item = structuredClone(h.itemOf('feed-listed')), before = h.feedReads().length;
  h.simulator.seed(120);
  item.entry.trigger.bounds.pages = 1;
  await h.read(feed, [watch], {entries: [item], windows: () => ({seconds: null})});
  assert.equal(h.feedReads().length - before, 1);
});

test('a poll writes no audit row', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), before = h.store.list('activity').length;
  h.simulator.write();
  await h.poll(feed, [watch]);
  assert.equal(h.store.list('activity').length, before);
});

test('the grant header is asked for, read and taken off the answer before anything can read it', async t => {
  const h = rig(t);
  h.simulator.seed(2);
  h.store.put('connections', {...h.connection(), providerId: 'github'});
  const request = h.runtime.request;
  let asked = [];
  h.runtime.request = async input => { asked = input.responseHeaders; const answer = await request(input); return {...answer, headers: {...answer.headers, 'x-oauth-scopes': 'repo'}}; };
  const item = structuredClone(h.itemOf('feed-listed'));
  item.entry.trigger.poll.itemId = {step: 'feed', header: 'x-oauth-scopes'};
  item.lenses = [triggerLens(item.entry)];
  const feed = {...h.feedOf('feed-listed', {tracked: []}), lenses: item.lenses}, result = await h.read(feed, [h.watch('feed-listed')], {entries: [item]});
  assert.ok(asked.includes('x-oauth-scopes'));
  assert.equal(result.run.items, 2);
  assert.equal(result.run.skipped, 2, 'an expression reads no such header, so an id read from it is absent');
});

test('a stored cursor that holds the credential puts it in the built bytes, and the bytes are refused', async t => {
  const h = rig(t), feed = h.feedOf('feed-synced', {baselined: true, cursors: {sync: TOKEN}}), watch = h.watch('feed-synced');
  const result = await h.read(feed, [watch]);
  assert.equal(h.simulator.calls.length, 0);
  assert.equal(result.run.code, 'credential_in_request');
});

for (const [label, spelling, pages] of [['in base64, on a walk its bounds stop', Buffer.from(TOKEN).toString('base64'), 1], ['in base64, on a walk that would read on', Buffer.from(TOKEN).toString('base64'), 3], ['in plain text, which scrubbing turns to [redacted]', TOKEN, 1]]) {
  test(`a next page that carries the credential ${label} is no place: it pauses cursor_invalid, and nothing stores it`, async t => {
    const h = rig(t, {triggers: edited('feed-synced', item => { pagesOf(item, pages); })}), {feed, watch} = await h.watching('feed-synced'), calls = h.feedReads().length, {sync} = feed.cursors;
    h.simulator.fail('GET /feed', {status: 200, data: {items: [], nextPageToken: spelling}});
    const result = await h.read(feed, [watch]);
    assert.equal(h.feedReads().length, calls + 1, 'the token goes no further than the answer that held it');
    assert.deepEqual([result.outcome, result.pause, result.page, result.cursors.sync], ['paused', {reason: 'cursor_invalid', detail: 'page'}, null, sync]);
    assert.equal(holdsCredential(JSON.stringify(result), credentialContext({Authorization: `Bearer ${TOKEN}`})), false);
  });
}

test('a next page that is a number or a plain token stays a place', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { pagesOf(item, 1); })}), {feed, watch} = await h.watching('feed-synced');
  for (const token of ['opaque-token-2', 4]) {
    h.simulator.fail('GET /feed', {status: 200, data: {items: [], nextPageToken: token}});
    const result = await h.read(feed, [watch]);
    assert.deepEqual([result.outcome, result.page], ['cut', {token, walk: 'delta'}]);
  }
});

test('a poll keeps to Slack\'s limit for a distributed app, if a gate ever lets one reach it', async t => {
  const h = slackHarness(t), deps = {configs: PROXY_CONFIGS, maps: new Map(), identities: new Map([['slack', definitionFor('slack')]])};
  const step = {id: 'list', method: 'GET', path: '/conversations.history', query: {channel: {var: 'channel'}, limit: {const: 100}}, expect: {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]}};
  const trigger = {id: `slack.trigger.history.v1.${'0'.repeat(24)}`, key: 'history', version: 1, name: 'A message', description: 'A message.', delivery: {method: 'polling', intervalSeconds: {default: 120, min: 60}},
    inputSchema: {type: 'object', properties: {channels: {type: 'array', minItems: 1, maxItems: 20, items: {type: 'string', minLength: 9, maxLength: 21}}}, required: ['channels'], additionalProperties: false}, resource: {each: '/channels', as: 'channel'},
    poll: {source: {steps: [step]}, items: {step: 'list', pointer: '/messages'}, itemId: {item: '/ts'}, itemVersion: null, order: 'unordered', cursors: [{name: 'seen', kind: 'snapshot@1', compare: 'collections.diff@1'}], resync: {statusIn: []}, minIntervalSeconds: 60},
    dedupe: {kind: 'id'}, event: {...ITEM_EVENT, id: {item: '/ts'}, occurredAt: {item: '/ts'}, fields: {id: {item: '/ts'}}}, backfill: {default: 0, max: 0}, retention: {hours: 24}, bounds: {pages: 1, items: 100, pollSeconds: 10}, rows: ['slack.messages.read']};
  const file = {schemaVersion: 1, appId: 'slack', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, triggers: [trigger]};
  const ids = triggerIds(file, deps), [entry] = validateTriggerFile({...file, triggers: [{...trigger, id: ids.get('history v1')}]}, deps).triggers, lens = triggerLens(entry);
  h.runtime.slackDistribution = 'distributed';
  const feed = {id: 'feed-slack', appId: 'slack', connectionId: h.account, resource: ['C0123456789'], lenses: [lens], cursors: {}, page: null, baselined: true, createdAt: new Date(h.now).toISOString()};
  const result = await h.catalog.runPoll({runtime: h.runtime, feed, entries: [{appId: 'slack', entry, pinnedParameters: {}, lenses: [lens]}], subscriptions: [{id: 'w', clientId: 'c', status: 'active', triggerId: entry.id, args: {channels: ['C0123456789']}}], memo: new Map(), authority: pass});
  assert.equal(result.outcome, 'limited');
  assert.equal(result.run.code, 'slack_page_limit');
  assert.equal(result.wait.method, 'conversations.history');
  assert.equal(h.script.calls.length, 0, 'nothing was sent');
});

test('a grant header that lost a scope narrows the account, as an action\'s answer does, and the header is on no answer', async t => {
  const h = githubHarness(t, {file: probeFile()}), trigger = gistTrigger();
  const deps = {groups: h.groups, configs: PROXY_CONFIGS, maps: new Map(), identities: new Map([['github', definitionFor('github')]])};
  const file = {schemaVersion: 1, appId: 'github', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, triggers: [trigger]};
  const ids = triggerIds(file, deps), [entry] = validateTriggerFile({...file, triggers: [{...trigger, id: ids.get('gists v1')}]}, deps).triggers, lens = triggerLens(entry);
  const item = {appId: 'github', entry, status: 'active', pinnedParameters: {}, lenses: [lens]}, feed = {id: 'feed-gists', appId: 'github', connectionId: h.account, resource: [], lenses: [lens], cursors: {}, page: null, baselined: true, createdAt: new Date(h.now).toISOString()};
  h.simulator.grant(FIVE.filter(scope => scope !== 'gist'));
  const result = await h.catalog.runPoll({runtime: h.runtime, feed, entries: [item], subscriptions: [{id: 'w', clientId: 'c', status: 'active', triggerId: entry.id, args: {}, pending: []}], memo: new Map(), authority: pass});
  assert.equal(result.run.status, 200);
  assert.ok(!h.connection().scopes.includes('gist'), 'the next gate reads the narrowed grant');
  assert.doesNotMatch(JSON.stringify(result), /x-oauth-scopes/);
});

test('a narrowed grant is decided on before the next request of the same poll', async t => {
  const h = githubHarness(t, {file: probeFile()}), trigger = gistTrigger();
  trigger.poll.source.steps.unshift({id: 'first', method: 'GET', path: '/gists', expect: {status: [200], require: []}});
  const deps = {groups: h.groups, configs: PROXY_CONFIGS, maps: new Map(), identities: new Map([['github', definitionFor('github')]])};
  const file = {schemaVersion: 1, appId: 'github', specVersion: 'fabric/0.2', reviewStatus: 'reviewed', pinnedParameters: {}, triggers: [trigger]};
  const ids = triggerIds(file, deps), [entry] = validateTriggerFile({...file, triggers: [{...trigger, id: ids.get('gists v1')}]}, deps).triggers, lens = triggerLens(entry), request = h.runtime.request, held = [];
  const feed = {id: 'feed-gists', appId: 'github', connectionId: h.account, resource: [], lenses: [lens], cursors: {}, page: null, baselined: true, createdAt: new Date(h.now).toISOString()};
  h.simulator.grant(FIVE.filter(scope => scope !== 'gist'));
  h.runtime.request = input => { held.push(h.connection().scopes.includes('gist')); return request(input); };
  await h.catalog.runPoll({runtime: h.runtime, feed, entries: [{appId: 'github', entry, pinnedParameters: {}, lenses: [lens]}], subscriptions: [{id: 'w', clientId: 'c', status: 'active', triggerId: entry.id, args: {}, pending: []}], memo: new Map(), authority: pass});
  assert.deepEqual(held, [true, false]);
});

test('a live guard refusal ends the poll on a source step, and skips one item on an enrich step', async t => {
  const refused = () => Object.assign(new Error('Refused by the guard.'), {sent: false, code: 'action_refused', details: {reason: 'live_guard'}});
  const h = rig(t), {feed} = await h.watching('feed-logged-detail'), watch = h.watch('feed-logged-detail'), request = h.runtime.request;
  h.simulator.seed(2);
  h.runtime.request = input => input.url.includes('/items/') ? Promise.reject(refused()) : request(input);
  const skipped = await h.read(feed, [watch]);
  assert.equal(skipped.run.skipped, 2);
  assert.equal(skipped.events.length, 0);
  assert.equal(skipped.outcome, 'done');
  h.runtime.request = () => Promise.reject(refused());
  const ended = await h.read(feed, [watch]);
  assert.equal(ended.outcome, 'backoff');
  assert.equal(ended.run.code, 'live_guard');
});

// ---- the outcome table ---------------------------------------------------------------------------------------------------------------------
test('judgeAnswer reads each row of the outcome table, by app', () => {
  const step = {expect: {status: [200], require: []}}, listed = {expect: {status: [200, 404], require: []}}, frame = {steps: new Map()};
  const slack = {require: [{pointer: '/ok', equals: true}], scopes: ['channels:history']}, ofSlack = (error, more = {}) => ({status: 200, headers: {}, data: {ok: false, error, ...more}});
  for (const [label, app, rule, used, answer, expected] of [
    ['a 2xx', 'gmail', null, step, {status: 200, headers: {}, data: {}}, {is: 'ok'}],
    ['a 304, before any status test', 'github', null, step, {status: 304, headers: {}, data: null, notModified: true}, {is: 'not_modified'}],
    ['a 301', 'github', null, step, {status: 301, headers: {}, data: null, redirected: true}, {is: 'refused', detail: 'moved'}],
    ['a 429', 'gmail', null, step, {status: 429, headers: {}, data: null}, {is: 'limited'}],
    ['a 529', 'notion', null, step, {status: 529, headers: {}, data: null}, {is: 'limited'}],
    ['Gmail\'s limit 403', 'gmail', null, step, {status: 403, headers: {}, data: {error: {errors: [{reason: 'rateLimitExceeded'}]}}}, {is: 'limited'}],
    ['Calendar\'s limit 403', 'google-calendar', null, step, {status: 403, headers: {}, data: {error: {errors: [{domain: 'usageLimits'}]}}}, {is: 'limited'}],
    ['GitHub\'s limit 403', 'github', null, step, {status: 403, headers: {'x-ratelimit-remaining': '0'}, data: {}}, {is: 'limited'}],
    ['any other 403', 'github', null, step, {status: 403, headers: {'x-ratelimit-remaining': '12'}, data: {message: 'no'}}, {is: 'refused', detail: 'http_403'}],
    ['a 500', 'notion', null, step, {status: 500, headers: {}, data: null}, {is: 'failed', detail: 'http_500'}],
    ['a 503', 'notion', null, step, {status: 503, headers: {}, data: null}, {is: 'failed', detail: 'http_503'}],
    ['a 401', 'notion', null, step, {status: 401, headers: {}, data: null}, {is: 'failed', detail: 'http_401'}],
    ['a 400', 'github', null, step, {status: 400, headers: {}, data: null}, {is: 'refused', detail: 'http_400'}],
    ['a 404 the step does not list', 'github', null, step, {status: 404, headers: {}, data: null}, {is: 'refused', detail: 'http_404'}],
    ['a 404 the step lists', 'gmail', null, listed, {status: 404, headers: {}, data: null}, {is: 'ok'}],
    ['a listed status that is no 2xx answers no require', 'gmail', null, {expect: {status: [200, 404], require: [{present: {pointer: '/id'}}]}}, {status: 404, headers: {}, data: null}, {is: 'ok'}],
    ['Notion, not shared', 'notion', null, step, {status: 404, headers: {}, data: {code: 'object_not_found'}}, {is: 'refused', detail: 'not_shared'}],
    ['Notion, a capability off', 'notion', null, step, {status: 403, headers: {}, data: {code: 'restricted_resource'}}, {is: 'refused', detail: 'capability_off'}],
    ['a 2xx the step does not list', 'gmail', null, step, {status: 204, headers: {}, data: null}, {is: 'failed', detail: 'http_204'}],
    ['Slack, ok', 'slack', slack, step, {status: 200, headers: {}, data: {ok: true}}, {is: 'ok'}],
    ['Slack, not in the channel', 'slack', slack, step, ofSlack('not_in_channel'), {is: 'refused', detail: 'not_in_channel'}],
    ['Slack, a revoked token', 'slack', slack, step, ofSlack('token_revoked'), {is: 'refused', detail: 'token_revoked'}],
    ['Slack, a bad cursor', 'slack', slack, step, ofSlack('invalid_cursor'), {is: 'failed', detail: 'invalid_cursor'}],
    ['Slack, its own fault', 'slack', slack, step, ofSlack('internal_error'), {is: 'failed', detail: 'internal_error'}],
    ['Slack, no answer in the shape', 'slack', slack, step, {status: 200, headers: {}, data: {}}, {is: 'failed', detail: 'unknown'}]]) {
    assert.deepEqual(judgeAnswer({appId: app, apiRule: rule}, used, answer, frame), expected, label);
  }
  const scope = judgeAnswer({appId: 'slack', apiRule: slack}, step, ofSlack('missing_scope', {needed: 'channels:history', provided: ''}), frame);
  assert.equal(scope.is, 'scope');
  assert.deepEqual(scope.verdict.needed, ['channels:history']);
  const alternative = {expect: {status: [200], require: [{anyOf: [{equals: {pointer: '/ok', value: {const: true}}}, {equals: {pointer: '/error', value: {const: 'already_reacted'}}}]}]}};
  assert.deepEqual(judgeAnswer({appId: 'slack', apiRule: slack}, alternative, ofSlack('already_reacted'), frame), {is: 'ok'}, 'a reviewed alternative stands, as an action reads it');
});

test('waitOf: Retry-After in full, GitHub\'s reset, and a Slack wait names its method', () => {
  const now = 1_000_000;
  assert.deepEqual(waitOf('gmail', {headers: {'retry-after': '7200'}}, {path: '/x'}, now), {until: now + 7_200_000, reason: 'limited'}, 'honoured above the backoff cap');
  assert.deepEqual(waitOf('gmail', {headers: {}}, {path: '/x'}, now), {until: null, reason: 'limited'}, 'no answer, so the backoff decides');
  assert.deepEqual(waitOf('gmail', {headers: {'retry-after': 'soon'}}, {path: '/x'}, now), {until: null, reason: 'limited'});
  assert.deepEqual(waitOf('github', {headers: {'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '5000'}}, {path: '/x'}, now), {until: 5_000_000, reason: 'limited'});
  assert.deepEqual(waitOf('github', {headers: {'x-ratelimit-remaining': '4000', 'x-ratelimit-reset': '9000'}}, {path: '/x'}, now), {until: now + 60_000, reason: 'limited'}, 'a secondary limit waits at least 60 seconds, not until a reset every answer names');
  assert.deepEqual(waitOf('github', {headers: {'x-ratelimit-remaining': '10'}}, {path: '/x'}, now), {until: now + 60_000, reason: 'limited'});
  assert.deepEqual(waitOf('github', {headers: {'retry-after': '5', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '5000'}}, {path: '/x'}, now), {until: now + 5000, reason: 'limited'}, 'Retry-After wins');
  assert.deepEqual(waitOf('slack', {headers: {'retry-after': '30'}}, {path: '/conversations.history'}, now), {until: now + 30_000, reason: 'limited', method: 'conversations.history'});
});

for (const [label, answer, outcome, check] of [
  ['spec 1865: a 429 with Retry-After stores nothing and waits', {status: 429, headers: {'Retry-After': '120'}, data: null}, 'limited', (h, result) => assert.equal(result.wait.until, h.now + 120_000)],
  ['a 429 of 7,200 seconds is honoured in full', {status: 429, headers: {'Retry-After': '7200'}, data: null}, 'limited', (h, result) => assert.equal(result.wait.until, h.now + 7_200_000)],
  ['a 500 backs off', {status: 500, data: null}, 'backoff', (h, result) => assert.equal(result.run.code, 'http_500')],
  ['a 401 backs off', {status: 401, data: null}, 'backoff', (h, result) => assert.equal(result.pause, undefined)],
  ['a 301 is never followed and pauses', {status: 301, headers: {location: 'https://api.fixture.test/moved'}, data: null}, 'paused', (h, result) => assert.deepEqual(result.pause, {reason: 'provider_refused', detail: 'moved'})],
  ['another 4xx pauses, with its code', {status: 403, data: {error: 'no'}}, 'paused', (h, result) => assert.deepEqual(result.pause, {reason: 'provider_refused', detail: 'http_403'})],
  ['a page that holds no list refuses before any lens reads it', {status: 200, data: {items: 'oops'}}, 'paused', (h, result) => assert.deepEqual(result.pause, {reason: 'too_many_items', detail: 'page_items'})],
  ['a next page that is not text or a number refuses before any lens reads it', {status: 200, data: {items: [], nextPageToken: {nested: true}}}, 'paused', (h, result) => assert.deepEqual(result.pause, {reason: 'too_many_items', detail: 'page_cursor'})]]) {
  test(`the outcome table: ${label}`, async t => {
    const h = rig(t), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']}), before = structuredClone(feed.cursors);
    const calls = h.simulator.calls.length;
    h.simulator.fail('GET /feed', answer);
    const result = await h.read(feed, [watch]);
    assert.equal(result.outcome, outcome);
    assert.deepEqual([result.events, result.seen], [[], []], 'nothing stored');
    assert.deepEqual(result.cursors, before, 'the cursor is unchanged');
    assert.equal(h.simulator.calls.length, calls + 1, 'one request, and no redirect was followed');
    check(h, result);
  });
}

test('the outcome table: a 200 that fails expect.require pauses nothing and backs off', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.source.steps[0].expect.require = [{present: {pointer: '/items'}}]; })}), {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {other: true}});
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'backoff');
  assert.equal(result.run.code, 'require_failed');
  assert.equal(result.pause, undefined);
});

test('the outcome table: a timeout or a lost connection backs off, and an answer too large pauses', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed');
  h.simulator.drop('GET /feed');
  const lost = await h.read(feed, [watch]);
  assert.equal(lost.outcome, 'backoff');
  assert.equal(lost.run.code, 'connection_failed');
  const request = h.runtime.request;
  h.runtime.request = () => Promise.reject(Object.assign(new Error('Provider request timed out.'), {sent: true}));
  assert.equal((await h.read(feed, [watch])).run.code, 'timeout');
  h.runtime.request = request;
  h.simulator.oversize('GET /feed', 300_000);
  const large = await h.read(feed, [watch]);
  assert.equal(large.outcome, 'paused');
  assert.deepEqual(large.pause, {reason: 'too_many_items', detail: 'response_too_large'});
});

test('the outcome table: credentials() refusing stores nothing, pauses nothing and backs off', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), calls = h.simulator.calls.length;
  h.connections.credentials = async () => { throw new Error('The renewal failed.'); };
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'backoff');
  assert.equal(result.run.code, 'credentials');
  assert.equal(result.pause, undefined);
  assert.equal(h.simulator.calls.length, calls);
});

test('the outcome table: a next link that its transform refuses pauses provider_refused, link_invalid', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.source.steps[0].page = {next: {link: 'next', param: 'page'}, into: {query: 'page'}, items: '/items', max: 10}; })});
  const {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, headers: {link: '<not a url>; rel="next"'}, data: {items: []}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual(result.pause, {reason: 'provider_refused', detail: 'link_invalid'});
});

test('Link paging walks by the page number the transform gives', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.source.steps[0].page = {next: {link: 'next', param: 'page'}, into: {query: 'page'}, items: '/items', max: 10}; })});
  const {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, headers: {link: '<https://api.fixture.test/feed?page=2>; rel="next"'}, data: {items: []}});
  await h.read(feed, [watch]);
  assert.equal(h.feedReads().at(-1).query.page, '2');
});

test('Slack missing_scope narrows the account, stores nothing and leaves the pause to the scheduler', async t => {
  const h = rig(t, await ruled()), feed = h.feedOf('feed-listed', {baselined: true}), watch = h.watch('feed-listed');
  h.store.put('connections', {...h.connection(), scopes: ['fixture:all']});
  h.simulator.fail('GET /feed', {status: 200, data: {ok: false, error: 'missing_scope', needed: 'fixture:all', provided: ''}});
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'scope_missing');
  assert.deepEqual(h.connection().scopes, []);
  assert.deepEqual([result.events, result.seen], [[], []]);
  assert.equal(result.pause, undefined);
});

test('an answer the app\'s success rule refuses, with a code of PAUSE_ERRORS, pauses with that code', async t => {
  const h = rig(t, await ruled());
  h.simulator.fail('GET /feed', {status: 200, data: {ok: false, error: 'channel_not_found'}});
  assert.deepEqual((await h.read(h.feedOf('feed-listed', {baselined: true}), [h.watch('feed-listed')])).pause, {reason: 'provider_refused', detail: 'channel_not_found'});
});

// ---- what a provider cannot throw over ----------------------------------------------------------------------------------------------------
const POISON = '{"__proto__": {"x": 1}, "a": 2}';
test('a value a filter cannot compare refuses its lens, as any value that cannot be read does: a provider cannot throw a poll over', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.filter = [{equals: [{item: '/kind'}, {const: 'note'}]}]; })}), {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: 'x', kind: JSON.parse(POISON), updated: new Date(h.now).toISOString()}]}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual(result.lensPauses, [{lens: h.itemOf('feed-listed').lenses[0], code: 'value_unreadable', reason: 'too_many_items'}]);
});

test('a late filter that cannot compare one item\'s enrich answer skips that item alone, with a seen row and one gap, and a provider cannot throw a poll over it', async t => {
  const triggers = edited('feed-logged-detail', item => { item.filter = [{equals: [{step: 'detail', pointer: '/kind'}, {const: 'note'}]}]; });
  const h = rig(t, {triggers}), tracked = ['feed-logged-detail'], feed = h.feedOf('feed-logged-detail', {tracked}), watch = h.watch('feed-logged-detail');
  await h.settle(feed, [watch]);
  h.advance(MINUTE);
  h.simulator.seed(2);
  h.simulator.fail('GET /items/{item_id}', {status: 200, data: {id: 'A', kind: JSON.parse(POISON)}});
  const result = await h.poll(feed, [watch]);
  assert.deepEqual([result.lensPauses, result.run.skipped, gaps(result).map(row => row.payload.fields.reason)], [[], 1, ['stall']]);
  assert.equal(result.seen.length, 2, 'the skipped item keeps its seen row, so it is not read again');
});

test('a reviewed require that cannot compare an answer holds no more than a false one: it backs off and pauses nothing', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.source.steps[0].expect = {status: [200], require: [{equals: {pointer: '/ok', value: {const: true}}}]}; })}), watch = h.watch('feed-listed'), feed = h.feedOf('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {ok: JSON.parse(POISON), items: []}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual([result.outcome, result.run.code, result.pause], ['backoff', 'require_failed', undefined]);
});

test('an id no URL can carry skips that item on an enrich read, and the poll goes on', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged-detail', {tracked: ['feed-logged', 'feed-logged-detail']}), mark = BigInt(feed.cursors.history);
  const history = [{id: String(mark + 1n), messagesAdded: [{message: {id: '\ud800', threadId: 'T'}}]}];
  h.simulator.fail('GET /feed', {status: 200, data: {history, historyId: String(mark + 1n)}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual([result.outcome, result.run.skipped, fired(result).length], ['done', 1, 0]);
  assert.equal(result.cursors.history, String(mark + 1n), 'one bad id never holds the feed');
});

test('a success rule\'s /error branch that cannot compare an answer holds nothing, so it reads as the refusal it is', async t => {
  const {signIn, file, triggers} = await ruled();
  triggers[0].poll.source.steps[0].expect = {status: [200], require: [{anyOf: [{equals: {pointer: '/ok', value: {const: true}}}, {equals: {pointer: '/error', value: {const: 'already_there'}}}]}]};
  const h = rig(t, {signIn, file, triggers}), watch = h.watch('feed-listed'), feed = h.feedOf('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {ok: false, error: JSON.parse(POISON)}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual([result.outcome, result.pause], ['backoff', undefined]);
});

test('a local fault is nobody\'s refusal: it leaves the poll as it came, and no lens pauses for it', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), {seenRows} = h.store;
  h.simulator.write();
  h.store.seenRows = () => { throw new Error('database is locked'); };
  await assert.rejects(h.read(feed, [watch]), /database is locked/);
  h.store.seenRows = seenRows;
});

test('an answer nested too deep to read is a whole answer too large: a source step pauses, and an enrich read skips its item', async t => {
  const nested = JSON.parse('['.repeat(20_000) + ']'.repeat(20_000)), h = rig(t), {request} = h.runtime, source = h.watch('feed-listed');
  h.runtime.request = async () => ({status: 200, headers: {}, data: {items: nested}});
  assert.deepEqual((await h.read(h.feedOf('feed-listed'), [source])).pause, {reason: 'too_many_items', detail: 'response_too_large'});
  h.runtime.request = request;
  const {feed, watch} = await h.watching('feed-logged-detail', {tracked: ['feed-logged', 'feed-logged-detail']}), mark = BigInt(feed.cursors.history);
  const history = {history: [{id: String(mark + 1n), messagesAdded: [{message: {id: 'F1', threadId: 'T'}}]}], historyId: String(mark + 1n)};
  h.runtime.request = async ({url}) => ({status: 200, headers: {}, data: url.includes('/feed') ? history : {name: nested}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual([result.outcome, result.run.skipped, fired(result).length], ['done', 1, 0]);
});

test('a page token no URL can carry backs off, with nothing stored and nothing thrown', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  feed.page = {token: '\ud800', walk: 'delta'};
  const result = await h.read(feed, [watch]);
  assert.ok(['backoff', 'paused'].includes(result.outcome), result.outcome);
  assert.deepEqual([result.events, result.seen], [[], []]);
});

// ---- resync --------------------------------------------------------------------------------------------------------------------------------
test('spec 1864, with no seed: a 410 drops the cursor, walks silently in this run, and stores one gap once the cursor is replaced, seen rows kept', async t => {
  const h = rig(t), [item] = h.simulator.seed(1), {feed, watch} = await h.watching('feed-synced'), good = feed.lastGoodAt;
  h.simulator.expireCursors();
  h.simulator.write();
  h.advance(1000);
  const result = await h.poll(feed, [watch]);
  assert.equal(fired(result).length, 0, 'the walk is silent');
  const [gap] = gaps(result), from = new Date(good).toISOString();
  assert.deepEqual(gap.payload.fields, {from, to: new Date(h.now).toISOString(), reason: 'resync'});
  assert.equal(gap.dedupeKey, `gap|resync|${from}`);
  assert.deepEqual(gap.payload, {type: 'trigger.gap', id: gap.dedupeKey, occurredAt: new Date(h.now).toISOString(), fields: gap.payload.fields, summary: [{label: 'Gap', value: gap.payload.summary[0].value}]});
  assert.deepEqual(result.gap, gap.payload.fields);
  assert.equal(gaps(result).length, 1);
  assert.deepEqual(result.run.events, {}, 'a run counts events, and a gap is none');
  assert.notEqual(feed.cursors.sync, undefined);
  assert.equal(result.reachedEdge, true);
  assert.equal(result.lastGoodAt, h.now);
  h.simulator.touch(item.id, {name: 'Later'});
  assert.equal(fired(await h.poll(feed, [watch])).length, 1, 'then the next write gives one');
});

test('a resync replayed after a crash computes the same gap key, so one gap is stored', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  h.simulator.expireCursors();
  const first = await h.read(feed, [watch]);
  h.store.appendPoll({feedId: feed.id, seen: first.seen, events: first.events});
  h.advance(5000);
  const second = await h.read(feed, [watch]);
  h.store.appendPoll({feedId: feed.id, seen: second.seen, events: second.events});
  assert.equal(gaps(first)[0].dedupeKey, gaps(second)[0].dedupeKey);
  assert.equal(h.events().length, 1);
});

test('a silent resync walk that its bounds cut carries across ticks, and the gap waits for the new cursor', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  h.simulator.seed(600);
  h.simulator.expireCursors();
  const cut = await h.poll(feed, [watch]);
  assert.deepEqual(cut.page, {token: 'p500', walk: 'baseline'});
  assert.equal(feed.cursors.sync, undefined, 'dropped, and not yet replaced');
  assert.equal(cut.events.length, 0, 'no gap yet');
  assert.equal(cut.reachedEdge, false);
  const done = await h.poll(feed, [watch]);
  assert.equal(gaps(done).length, 1);
  assert.equal(fired(done).length, 0);
  assert.equal(done.page, null);
  assert.notEqual(feed.cursors.sync, undefined);
});

test('a resync walk that spans polls keeps its range: the gap starts where the cursor was last good, not at the walk\'s last poll', async t => {
  for (const [key, options, change] of [['feed-synced', {}, () => {}], ['feed-updated', {args: {kinds: ['note']}, resource: ['note']}, item => { delete item.poll.seed; item.poll.resync = {statusIn: [410]}; }]]) {
    const h = rig(t, {triggers: edited(key, change)}), {feed, watch} = await h.watching(key, options);
    h.simulator.write();
    await h.poll(feed, [watch]);
    const good = feed.lastGoodAt;
    h.advance(HOUR);
    h.simulator.seed(700);
    if (key === 'feed-synced') h.simulator.expireCursors(); else h.simulator.fail('GET /feed', {status: 410, data: {error: 'gone'}});
    const cut = await h.poll(feed, [watch]);
    assert.notEqual(cut.page, null, 'the walk needs a second poll');
    assert.equal(cut.lastGoodAt, good, `${key}: nothing is good until the walk ends`);
    h.advance(HOUR);
    const done = await h.poll(feed, [watch]);
    assert.equal(gaps(done)[0].payload.fields.from, new Date(good).toISOString(), key);
    assert.equal(done.lastGoodAt, h.now, 'and the new cursor moves it');
  }
});

test('a resync\'s gap ends at the moment its cursor is replaced, so what landed during the poll sits inside its range', async t => {
  for (const key of ['feed-logged', 'feed-synced']) {
    const h = rig(t), {feed, watch} = await h.watching(key), {request} = h.runtime, started = h.now;
    h.simulator.expireCursors();
    h.runtime.request = async (...args) => { h.advance(5000); return request(...args); };
    const [gap] = gaps(await h.read(feed, [watch])), ended = new Date(h.now).toISOString();
    assert.ok(h.now > started, 'the poll took time');
    assert.deepEqual([gap.payload.fields.to, gap.payload.occurredAt], [ended, ended], key);
  }
});

test('only a lost place reads when the feed last reached the present: any other gap keeps lastGoodAt, so each gets a key of its own', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-posted'), good = feed.lastGoodAt;
  feed.readAt = good - HOUR;
  h.simulator.seed(600);
  const {gap} = await h.read(feed, [watch]);
  assert.deepEqual([gap.reason, gap.from], ['bound', new Date(good).toISOString()]);
});

test('a silent walk with no sync token carries across ticks too, drain by drain, and the gap waits for its end', async t => {
  const h = rig(t, {triggers: edited('feed-updated', item => { delete item.poll.seed; item.poll.resync = {statusIn: [410]}; })}), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  h.simulator.write();
  await h.poll(feed, [watch]);
  h.simulator.seed(700);
  h.simulator.fail('GET /feed', {status: 410, data: {error: 'gone'}});
  const cut = await h.poll(feed, [watch]);
  assert.deepEqual(cut.page, {token: null, walk: 'baseline'});
  assert.equal(cut.events.length, 0);
  const done = await h.poll(feed, [watch]);
  assert.equal(fired(done).length, 0);
  assert.equal(gaps(done).length, 1);
  assert.equal(done.page, null);
});

test('with a seed: a 404 reads the seed in this run, replaces the cursor, runs no silent poll, and the next write fires', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged'), old = feed.cursors.history;
  h.simulator.expireCursors();
  const calls = h.feedReads().length, result = await h.poll(feed, [watch]);
  assert.equal(result.outcome, 'resynced');
  assert.equal(h.feedReads().length, calls + 2, 'the poll, then the seed, and nothing after');
  assert.notEqual(feed.cursors.history, old);
  assert.equal(gaps(result).length, 1);
  assert.equal(result.reachedEdge, true);
  h.simulator.write();
  assert.equal(fired(await h.poll(feed, [watch])).length, 1, 'no overlap reaches behind a seed, and none is needed');
});

test('a seed that names no value on a resync keeps the old cursor and backs off', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged'), old = feed.cursors.history, request = h.runtime.request;
  h.simulator.expireCursors();
  let calls = 0;
  h.runtime.request = input => ++calls === 2 ? Promise.resolve({status: 200, headers: {}, data: {}}) : request(input);
  const result = await h.read(feed, [watch]);
  assert.equal(result.run.code, 'seed_empty');
  assert.equal(result.cursors.history, old);
});

test('a seed with no budget left sends nothing, and the feed tries again', async t => {
  const h = rig(t), feed = h.feedOf('feed-logged'), result = await h.read(feed, [h.watch('feed-logged')], {deadline: h.now + 500});
  assert.equal(result.outcome, 'backoff');
  assert.equal(result.run.code, 'budget');
  assert.equal(h.simulator.calls.length, 0);
});

test('a failed seed read keeps the old cursor and stores nothing', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged'), old = feed.cursors.history, request = h.runtime.request;
  h.simulator.expireCursors();
  let calls = 0;
  h.runtime.request = input => ++calls === 2 ? Promise.resolve({status: 500, headers: {}, data: null}) : request(input);
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'backoff');
  assert.equal(result.cursors.history, old);
  assert.deepEqual([result.events, result.seen], [[], []]);
});

test('a status outside statusIn resyncs nothing: it pauses and keeps the cursor', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged'), old = feed.cursors.history;
  h.simulator.fail('GET /feed', {status: 410, data: {error: 'gone'}});
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'paused');
  assert.deepEqual(result.pause, {reason: 'provider_refused', detail: 'http_410'});
  assert.equal(result.cursors.history, old);
  assert.equal(gaps(result).length, 0);
});

test('a refused walk that was still a baseline starts again with no gap: nothing was delivered yet', async t => {
  const h = rig(t), feed = h.feedOf('feed-synced', {page: {token: 'p50', walk: 'baseline'}}), watch = h.watch('feed-synced');
  h.simulator.fail('GET /feed', {status: 410, data: {error: 'gone'}});
  const result = await h.read(feed, [watch]);
  assert.equal(result.events.length, 0);
  assert.equal(result.baselined, true);
});

test('a seed read on a feed still at its baseline stays a baseline', async t => {
  const h = rig(t), feed = h.feedOf('feed-logged', {cursors: {history: String(2n ** 53n + 1n)}, baselined: false}), watch = h.watch('feed-logged');
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'resynced');
  assert.equal(result.events.length, 0);
  assert.equal(result.baselined, false);
  assert.equal(result.reachedEdge, false);
});

test('a resync status with no cursor to refresh is a refusal, not a loop', async t => {
  const h = rig(t), feed = h.feedOf('feed-synced'), watch = h.watch('feed-synced');
  h.simulator.fail('GET /feed', {status: 410, data: {error: 'gone'}});
  assert.deepEqual((await h.read(feed, [watch])).pause, {reason: 'provider_refused', detail: 'http_410'});
});

test('a second resync in one run ends the run: nothing loops', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  h.simulator.fail('GET /feed', {status: 410, data: {error: 'gone'}}, {times: Infinity});
  const before = h.feedReads().length, result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'paused', 'the walk from no cursor answers 410 too, which nothing can refresh');
  assert.equal(h.feedReads().length, before + 2);
});

// ---- catching up ---------------------------------------------------------------------------------------------------------------------------------
for (const [label, key, args, resource] of [['an asc feed', 'feed-updated', {kinds: ['note']}, ['note']], ['a history feed', 'feed-logged', {}, []], ['a sync walk that its bounds cut', 'feed-synced', {}, []]]) {
  test(`1,000 items of backlog on ${label} reach the active watch once each and never a joiner, whose feed then gives it the next write`, async t => {
    const h = rig(t), {feed, watch} = await h.watching(key, {args, resource}), joiner = h.watch(key, {args, status: 'starting', pending: [feed.id]});
    h.simulator.seed(1000);
    let polls = 0;
    for (let result; !result?.reachedEdge; polls++) {
      assert.ok(polls < 10);
      h.advance(1000);
      result = await h.poll(feed, [watch, joiner]);
      assert.deepEqual(result.events.filter(row => row.subscriptionId === joiner.id), [], 'nothing from before it joined, on any catch-up poll');
      assert.equal(gaps(result).length, 0);
    }
    assert.ok(polls > 1, 'the backlog took more than one poll');
    assert.equal(h.stored, 1000);
    joiner.pending = [];
    h.advance(1000);
    h.simulator.write();
    h.advance(1000);
    assert.equal(fired(await h.poll(feed, [watch, joiner])).length, 2);
  });
}

test('spec 1869, a last-page feed: 10,000 changes resume across polls within the bounds, with no gap, each once', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced'), old = feed.cursors.sync;
  h.simulator.seed(10_000);
  let polls = 0;
  for (let result; !result?.reachedEdge; polls++) {
    assert.ok(polls < 30);
    h.advance(1000);
    const before = h.feedReads().length;
    result = await h.poll(feed, [watch]);
    assert.ok(h.feedReads().length - before <= 10);
    assert.equal(gaps(result).length, 0);
    assert.equal(feed.cursors.sync === old, !result.reachedEdge, 'the token moves on the last page alone');
  }
  assert.equal(polls, 20);
  assert.equal(h.stored, 10_000);
});

// ---- the seven cursor kinds ------------------------------------------------------------------------------------------------------------------
test('CURSOR_CHECKS holds each kind to its form', () => {
  for (const [kind, good, bad] of [
    ['history-id@1', ['1', '9'.repeat(20)], ['', 'a1', '9'.repeat(21), 12]],
    ['sync-token@1', ['s1', 'x'.repeat(2048), 'a b'], ['', 'x'.repeat(2049), 'a\nb', 12]],
    ['high-water-time@1', ['2026-10-23T09:00:00Z', '2026-10-23T09:00:00.123Z', '2026-10-23T09:00:00+02:00'], ['2026-10-23', 'yesterday', '2026-13-23T09:00:00Z', '']],
    ['high-water-ts@1', ['1761210000.000100', '1.000000'], ['1761210000', '1761210000.1', '12345678901.000000', 1761210000.0001]],
    ['etag@1', ['W/"a"', 'x'.repeat(512)], ['', 'x'.repeat(513), 'a\r\nb']],
    ['last-modified@1', ['Fri, 23 Oct 2026 09:00:00 GMT', 'x'.repeat(64)], ['', 'x'.repeat(65)]]]) {
    for (const value of good) assert.equal(CURSOR_CHECKS[kind](value), true, `${kind}: ${value}`);
    for (const value of bad) assert.equal(CURSOR_CHECKS[kind](value), false, `${kind}: ${value}`);
  }
  assert.equal(Object.hasOwn(CURSOR_CHECKS, 'snapshot@1'), false, 'a snapshot\'s cursor is its seen rows');
});

for (const [key, name, value, resource] of [['feed-logged', 'history', 'not a number', []], ['feed-synced', 'sync', '', []], ['feed-updated', 'since', 'yesterday', ['note']], ['feed-posted', 'ts', '12', []], ['feed-tagged', 'etag', 'a\nb', []], ['feed-modified', 'changed', 'x'.repeat(65), []]]) {
  test(`spec 1870, ${key}: a malformed stored cursor pauses cursor_invalid, keeps its value and sends nothing`, async t => {
    const h = rig(t), feed = h.feedOf(key, {resource, baselined: true, cursors: {[name]: value}}), watch = h.watch(key, {args: resource.length ? {kinds: resource} : {}});
    const result = await h.read(feed, [watch]);
    assert.equal(result.pause.reason, 'cursor_invalid');
    assert.equal(result.cursors[name], value);
    assert.equal(h.simulator.calls.length, 0, 'no network after it');
    assert.deepEqual([result.events, result.seen], [[], []]);
  });
}

test('a stored page token that is not one pauses too', async t => {
  const h = rig(t), feed = h.feedOf('feed-synced', {baselined: true, page: {token: 'a\nb', walk: 'delta'}, cursors: {sync: 's1'}});
  assert.equal((await h.read(feed, [h.watch('feed-synced')])).pause.reason, 'cursor_invalid');
  assert.equal(h.simulator.calls.length, 0);
});

test('spec 1870: a malformed incoming cursor keeps the old one and pauses, and the page it came with is not stored', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced'), old = feed.cursors.sync;
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', updated: new Date(h.now).toISOString()}], nextSyncToken: 'x'.repeat(2049)}});
  const result = await h.read(feed, [watch]);
  assert.equal(result.pause.reason, 'cursor_invalid');
  assert.equal(result.cursors.sync, old);
  assert.deepEqual([result.events, result.seen], [[], []]);
});

test('an absent next value keeps the old one and is no fault', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged'), old = feed.cursors.history;
  for (const data of [{}, {historyId: null}]) {
    h.simulator.fail('GET /feed', {status: 200, data});
    const result = await h.read(feed, [watch]);
    assert.equal(result.outcome, 'done');
    assert.equal(result.cursors.history, old);
  }
});

test('a history id compares as a whole number past 2^53, and never falls', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged');
  assert.equal(feed.cursors.history, String(2n ** 53n));
  h.simulator.write();
  const result = await h.poll(feed, [watch]);
  assert.equal(feed.cursors.history, String(2n ** 53n + 1n), 'a Number rounds this id back to the old one');
  h.simulator.fail('GET /feed', {status: 200, data: {historyId: String(2n ** 53n)}});
  assert.equal((await h.read(feed, [watch])).cursors.history, feed.cursors.history, 'lower than the stored value');
  assert.equal(fired(result).length, 1);
});

test('a sync token is read only from the last page', async t => {
  const h = rig(t, {triggers: edited('feed-synced', item => { pagesOf(item, 1); })}), {feed, watch} = await h.watching('feed-synced'), old = feed.cursors.sync;
  h.simulator.fail('GET /feed', {status: 200, data: {items: [], nextPageToken: 'p9', nextSyncToken: 's9'}});
  const result = await h.read(feed, [watch]);
  assert.equal(result.cursors.sync, old, 'a page with a next page holds no usable token');
  assert.deepEqual(result.page, {token: 'p9', walk: 'delta'});
});

test('a sync token is stored as it came, with no comparison, and a cut delta resumes with its page token and the same query', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced'), old = feed.cursors.sync;
  h.simulator.seed(600);
  const cut = await h.poll(feed, [watch]);
  assert.equal(cut.outcome, 'cut');
  assert.deepEqual(cut.page, {token: 'p500', walk: 'delta'});
  assert.equal(feed.cursors.sync, old);
  assert.equal(cut.reachedEdge, false);
  const done = await h.poll(feed, [watch]), first = h.feedReads().at(-2);
  assert.deepEqual([first.query.syncToken, first.query.pageToken], [old, 'p500'], 'it does not restart from the old token');
  assert.equal(done.page, null);
  assert.equal(h.stored, 600, 'every change once');
  assert.notEqual(feed.cursors.sync, old);
  assert.equal(done.reachedEdge, true);
});

test('a refused resume resyncs', async t => {
  for (const status of [410, 400]) {
    const h = rig(t), {feed, watch} = await h.watching('feed-synced');
    h.simulator.seed(600);
    await h.poll(feed, [watch]);
    h.simulator.fail('GET /feed', {status, data: {error: 'stale'}});
    const result = await h.poll(feed, [watch]);
    assert.equal(result.pause, undefined, `${status}`);
    assert.deepEqual(result.page, {token: 'p500', walk: 'baseline'}, 'a silent walk from the top');
  }
});

test('a cut history walk stores the last whole record, on the record id, and the next poll reads on from it', async t => {
  const h = rig(t, {triggers: edited('feed-logged', item => { pagesOf(item, 1); })}), {feed, watch} = await h.watching('feed-logged'), start = BigInt(feed.cursors.history);
  h.simulator.seed(70);
  const cut = await h.poll(feed, [watch]);
  assert.equal(cut.outcome, 'cut');
  assert.equal(feed.cursors.history, String(start + 50n), 'the last record of the page');
  assert.equal(cut.reachedEdge, false, 'a cut history walk has not reached the edge, whatever its order says');
  const done = await h.poll(feed, [watch]);
  assert.equal(h.stored, 70);
  assert.equal(done.reachedEdge, true);
  assert.equal(feed.cursors.history, String(start + 70n));
});

test('a record too large for its page: throughRecordId cuts the walk at a whole record', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged'), start = BigInt(feed.cursors.history);
  h.simulator.seed(600, {perRecord: 200});
  const cut = await h.poll(feed, [watch]);
  assert.equal(fired(cut).length, 400);
  assert.equal(feed.cursors.history, String(start + 2n));
  assert.equal(cut.reachedEdge, false);
  await h.settle(feed, [watch]);
  assert.equal(h.stored, 600);
});

test('a record id that is no number is a place Fabric cannot trust: it pauses cursor_invalid and throws nothing', async t => {
  const h = rig(t, {triggers: edited('feed-logged', item => { pagesOf(item, 1); })}), {feed, watch} = await h.watching('feed-logged'), old = feed.cursors.history;
  h.simulator.fail('GET /feed', {status: 200, data: {history: [{id: 'nonsense', messagesAdded: [{message: {id: 'A', threadId: 'A'}}]}], nextPageToken: 'p1', historyId: String(2n ** 53n + 9n)}});
  assert.equal((await h.read(feed, [watch])).pause.reason, 'cursor_invalid');
  assert.equal(feed.cursors.history, old);
});

test('a whole page with no item for any lens still finishes its records, or a cut walk would read them for ever', async t => {
  const h = rig(t, {triggers: edited('feed-logged', item => { pagesOf(item, 1); })}), {feed, watch} = await h.watching('feed-logged');
  const record = String(2n ** 53n + 9n);
  h.simulator.fail('GET /feed', {status: 200, data: {history: [{id: record}], nextPageToken: 'p1', historyId: record}});
  assert.equal((await h.read(feed, [watch])).cursors.history, record);
});

test('with a cut walk, a history cursor is the lowest record any live lens finished, and a lens that dropped out does not hold it back', async t => {
  const triggers = edited('feed-logged-detail', item => { item.poll.enrich.max = 2; });
  const h = rig(t, {triggers}), tracked = ['feed-logged', 'feed-logged-detail'], {feed, watch} = await h.watching('feed-logged', {tracked}), start = BigInt(feed.cursors.history), detail = h.watch('feed-logged-detail');
  h.simulator.seed(6);
  const result = await h.read(feed, [watch, detail]);
  assert.equal(result.cursors.history, String(start + 2n), 'the detail lens read two, the plain lens all six');
  assert.equal(result.outcome, 'cut');
  const dropped = await h.read(feed, [watch, detail], {authority: item => ({ok: item === undefined || item.entry.key !== 'feed-logged-detail'})});
  assert.equal(dropped.cursors.history, String(start + 6n));
});

test('a mark is the highest raw item time, sent less its overlap, and never below the floor', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  const item = h.simulator.write();
  await h.poll(feed, [watch]);
  assert.equal(feed.cursors.since, item.updated);
  await h.poll(feed, [watch]);
  assert.equal(h.feedReads().at(-1).query.updatedAfter, new Date(Date.parse(item.updated) - 60_000).toISOString());
  feed.floor = new Date(Date.parse(item.updated) + 5000).toISOString();
  await h.poll(feed, [watch]);
  assert.equal(h.feedReads().at(-1).query.updatedAfter, feed.floor);
});

test('a Slack mark is sent less its overlap in whole seconds, with no float, and an older item never lowers it', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-posted');
  const item = h.simulator.write(), [whole, fraction] = item.ts.split('.');
  await h.poll(feed, [watch]);
  assert.equal(feed.cursors.ts, item.ts);
  await h.poll(feed, [watch]);
  assert.equal(h.feedReads().at(-1).query.oldest, `${Number(whole) - 30}.${fraction}`);
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'old', name: 'x', updated: item.updated, ts: '1000000.000001'}]}});
  assert.equal((await h.read(feed, [watch])).cursors.ts, item.ts);
  await h.read({...feed, cursors: {ts: '10.000001'}}, [watch]);
  assert.equal(h.feedReads().at(-1).query.oldest, '0.000001', 'a ts never falls below zero');
});

test('a Slack mark moves by one microsecond, past what a float can tell', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-posted');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'A', name: 'x', updated: new Date(h.now).toISOString(), ts: '9999999999.000002'}]}});
  assert.equal((await h.read({...feed, cursors: {ts: '9999999999.000001'}}, [watch])).cursors.ts, '9999999999.000002');
  assert.equal(Number('9999999999.000002'), Number('9999999999.000001'), 'a Number cannot tell these two apart');
});

test('an event sorts by its item time, whatever the format', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-posted'), item = h.simulator.write();
  assert.equal((await h.read(feed, [watch])).events[0].itemTime, Number(item.ts));
});

test('an asc poll that its bounds cut moves the mark and drains: the next poll sends the mark less one second, not the overlap', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  h.simulator.seed(700);
  const cut = await h.poll(feed, [watch]);
  assert.equal(cut.outcome, 'cut');
  assert.equal(cut.draining, true);
  assert.equal(cut.reachedEdge, false);
  assert.equal(gaps(cut).length, 0, 'no gap on an asc feed');
  const mark = feed.cursors.since, done = await h.poll(feed, [watch]);
  assert.equal(h.feedReads().at(-1).query.updatedAfter ?? h.feedReads().at(-2).query.updatedAfter, new Date(Date.parse(mark) - 1000).toISOString());
  assert.equal(done.draining, false);
  assert.equal(h.stored, 700);
  await h.poll(feed, [watch]);
  assert.equal(h.feedReads().at(-1).query.updatedAfter, new Date(Date.parse(feed.cursors.since) - 60_000).toISOString(), 'back at the live edge, the overlap');
});

test('an asc mark stops at what a stopped lens finished, however far another lens read, or the items it left would be passed for good', async t => {
  const triggers = [...edited('feed-updated', item => { item.poll.enrich = {max: 2, steps: [DETAIL()]}; }), twin('feed-updated', 'feed-updated-plain', item => { delete item.poll.enrich; item.filter = [{present: {item: '/id'}}]; })];
  const h = rig(t, {triggers}), args = {kinds: ['note']}, {feed, watch} = await h.watching('feed-updated', {args, resource: ['note'], tracked: ['feed-updated', 'feed-updated-plain']}), plain = h.watch('feed-updated-plain', {args}), made = h.simulator.seed(5);
  const result = await h.poll(feed, [watch, plain]);
  assert.equal(result.outcome, 'cut');
  assert.equal(result.cursors.since, made[2].updated, 'a mark is taken before the item it would stop at is read');
  assert.equal(result.draining, true);
  await h.settle(feed, [watch, plain]);
  assert.equal(h.events().filter(row => row.subscriptionId === watch.id).length, 5, 'every item reaches the stopped lens');
});

test('with two stopped lenses an asc mark is the lower of them', async t => {
  const triggers = [...edited('feed-updated', item => { item.poll.enrich = {max: 2, steps: [DETAIL()]}; }), twin('feed-updated', 'feed-updated-less', item => { item.poll.enrich = {max: 1, steps: [DETAIL()]}; item.filter = [{present: {item: '/id'}}]; })];
  const h = rig(t, {triggers}), args = {kinds: ['note']}, {feed, watch} = await h.watching('feed-updated', {args, resource: ['note'], tracked: ['feed-updated', 'feed-updated-less']}), less = h.watch('feed-updated-less', {args}), made = h.simulator.seed(5);
  assert.equal((await h.read(feed, [watch, less])).cursors.since, made[1].updated);
});

test('a poll that a budget stopped before its first request leaves the drain and the conditional cursors as they were', async t => {
  const h = rig(t);
  h.simulator.seed(2);
  const {feed, watch} = await h.watching('feed-tagged'), tag = feed.cursors.etag;
  const tagged = await h.read(feed, [watch], {deadline: h.now + 500});
  assert.equal(tagged.cursors.etag, tag);
  const other = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  assert.equal((await h.read({...other.feed, draining: false}, [other.watch], {deadline: h.now + 500})).draining, false);
  assert.equal((await h.read({...other.feed, draining: true}, [other.watch], {deadline: h.now + 500})).draining, true);
});

test('a poll a budget stopped before its first request read nothing, so it counts as no budget stop and three give no gap', async t => {
  const h = rig(t);
  h.simulator.seed(2);
  const {feed, watch} = await h.watching('feed-posted'), mark = feed.cursors.ts;
  for (let count = 0; count < 4; count++) {
    const result = await h.poll(feed, [watch], {deadline: h.now + 500});
    assert.deepEqual([result.outcome, result.budgetStops, result.reachedEdge, gaps(result).length, result.run.requests], ['cut', 0, false, 0, 0], `poll ${count}`);
    assert.equal(feed.cursors.ts, mark);
  }
  feed.budgetStops = 2;
  assert.equal((await h.read(feed, [watch], {deadline: h.now + 500})).budgetStops, 2, 'and it leaves a count already held');
});

test('a desc mark stays where it was when an enrich read fails, with no budget stop counted', async t => {
  const h = rig(t, {triggers: edited('feed-posted', item => { item.poll.enrich = {max: 25, steps: [DETAIL()]}; })}), {feed, watch} = await h.watching('feed-posted');
  h.simulator.seed(2);
  h.simulator.fail('GET /items/{item_id}', {status: 500, data: null});
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'backoff');
  assert.equal(result.cursors.ts, undefined);
  assert.equal(result.budgetStops, 0);
});

test('a conditional cursor is not sent on a resumed walk, which has passed page 1', async t => {
  const triggers = edited('feed-synced', item => { const [step] = item.poll.source.steps; step.headers = {'If-None-Match': {cursor: 'tag'}}; step.expect = {status: [200, 304], require: []}; item.poll.cursors.push({name: 'tag', kind: 'etag@1', next: {step: 'feed', header: 'etag'}}); });
  const h = rig(t, {triggers}), feed = h.feedOf('feed-synced', {baselined: true, cursors: {sync: 's0', tag: 'W/"x"'}, page: {token: 'p0', walk: 'delta'}});
  await h.read(feed, [h.watch('feed-synced')]);
  assert.equal(h.feedReads()[0].headers['if-none-match'], undefined);
});

test('etag: stored from a one-page walk and sent on page 1, a 304 is a no-op that keeps it, and its poll reaches the edge', async t => {
  const h = rig(t);
  h.simulator.seed(2);
  const {feed, watch} = await h.watching('feed-tagged'), tag = feed.cursors.etag;
  assert.match(tag, /^W\//);
  const result = await h.poll(feed, [watch]);
  assert.equal(result.outcome, 'not_modified');
  assert.equal(h.feedReads().at(-1).headers['if-none-match'], tag);
  assert.equal(result.cursors.etag, tag);
  assert.equal(result.reachedEdge, true);
  assert.equal(result.run.status, 304);
  assert.deepEqual([result.events, result.seen], [[], []]);
});

test('a conditional cursor is held to its form too', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-tagged');
  h.simulator.fail('GET /feed', {status: 200, headers: {etag: 'x'.repeat(513)}, data: {items: []}});
  assert.equal((await h.read(feed, [watch])).pause.reason, 'cursor_invalid');
});

test('etag: the second page sends no If-None-Match, and a walk of more than one page clears it', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-tagged');
  h.simulator.seed(70);
  const result = await h.poll(feed, [watch]), reads = h.feedReads().slice(-2);
  assert.equal(reads[0].headers['if-none-match'] !== undefined, true, 'page 1 sends it');
  assert.equal(reads[1].headers['if-none-match'], undefined, 'a cursor sent on page 1 only');
  assert.equal(result.cursors.etag, undefined);
});

test('last-modified: the same, and its value goes back as it came', async t => {
  const h = rig(t);
  h.simulator.seed(2);
  const {feed, watch} = await h.watching('feed-modified'), changed = feed.cursors.changed;
  assert.match(changed, /GMT$/);
  const result = await h.poll(feed, [watch]);
  assert.equal(result.outcome, 'not_modified');
  assert.equal(h.feedReads().at(-1).headers['if-modified-since'], changed);
  h.simulator.seed(70);
  assert.equal((await h.poll(feed, [watch])).cursors.changed, undefined);
});

test('a cut lens clears a conditional cursor, or a 304 would hide what it left unread', async t => {
  const triggers = edited('feed-tagged', item => { item.poll.enrich = {max: 1, steps: [{id: 'detail', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, maxResponseBytes: 65_536, expect: {status: [200], require: []}}]}; });
  const h = rig(t, {triggers}), {feed, watch} = await h.watching('feed-tagged');
  h.simulator.seed(3);
  const result = await h.poll(feed, [watch]);
  assert.equal(fired(result).length, 1);
  assert.equal(result.outcome, 'cut');
  assert.equal(result.cursors.etag, undefined);
  await h.settle(feed, [watch]);
  assert.equal(h.stored, 3);
});

test('x-poll-interval sets a floor on every answer: a 304, a cut walk and a failure carry it too', async t => {
  const h = rig(t);
  h.simulator.seed(2);
  const {feed, watch} = await h.watching('feed-tagged');
  h.simulator.pollInterval(300);
  assert.equal((await h.read(feed, [watch])).notBefore, h.now + 300_000, 'on a 304');
  h.simulator.fail('GET /feed', {status: 500, headers: {'x-poll-interval': '600'}, data: null});
  assert.equal((await h.read(feed, [watch])).notBefore, h.now + 600_000, 'on a failure');
  h.simulator.fail('GET /feed', {status: 200, headers: {'x-poll-interval': 'soon'}, data: {items: []}});
  assert.equal((await h.read(feed, [watch])).notBefore, feed.notBefore, 'a value that is not a number sets nothing');
  h.simulator.fail('GET /feed', {status: 200, headers: {'x-poll-interval': '60'}, data: {items: []}});
  assert.equal((await h.read({...feed, notBefore: h.now + 600_000}, [watch])).notBefore, h.now + 600_000, 'a floor only rises');
});

// ---- stop rules ----------------------------------------------------------------------------------------------------------------------------
test('spec 1868: bounds.pages and bounds.items stop the next request, and the page in hand is processed whole', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.bounds.items = 120; })}), {feed, watch} = await h.watching('feed-listed');
  const start = h.feedReads().length;
  h.simulator.seed(400);
  const result = await h.read(feed, [watch], {windows: () => ({seconds: null})});
  assert.equal(h.feedReads().length - start, 3, '50, 100, 150: the third request came at 100, under the bound');
  assert.equal(result.run.items, 150);
  assert.equal(result.seen.length, 150, 'nothing of a read page is dropped');
  const paged = rig(t), other = await paged.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']}), before = paged.feedReads().length;
  paged.simulator.seed(1000);
  const walked = await paged.read(other.feed, [other.watch]);
  assert.equal(paged.feedReads().length - before, 10, 'ten pages');
  assert.equal(walked.run.items, 500);
});

test('a shared feed runs under the strictest bounds of its triggers, never whichever comes first', async t => {
  const h = rig(t, {triggers: edited('feed-logged-keys', item => { item.bounds.items = 120; item.bounds.pollSeconds = 3; })}), {feed, watch} = await h.watching('feed-logged'), before = h.feedReads().length, request = h.runtime.request;
  h.simulator.seed(400);
  assert.notEqual(h.entriesOf(feed)[0].entry.key, 'feed-logged-keys', 'the strict one does not come first');
  const result = await h.read(feed, [watch]);
  assert.equal(h.feedReads().length - before, 3, '50, 100, 150: items by the strictest trigger, though it has no subscriber');
  assert.equal(result.outcome, 'cut');
  h.runtime.request = input => { h.advance(2500); return request(input); };
  await h.read(feed, [watch]);
  assert.equal(h.feedReads().length - before, 4, 'and three seconds by the same rule: after one request, 500 ms is left, under the second that stops a walk');
});

test('spec 1868: 10 seconds a poll by the clock, each timeout within what is left, and a budget under one second stops the walk', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']}), request = h.runtime.request, timeouts = [];
  h.simulator.seed(400);
  h.runtime.request = input => { timeouts.push(input.timeoutMs); h.advance(3000); return request(input); };
  const result = await h.read(feed, [watch]);
  assert.deepEqual(timeouts, [10_000, 7000, 4000, 1000]);
  assert.equal(result.outcome, 'cut');
  assert.equal(result.reachedEdge, false);
});

test('a deadline earlier than the poll\'s own budget wins', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed'), calls = h.simulator.calls.length;
  const result = await h.read(feed, [watch], {deadline: h.now + 500});
  assert.equal(h.simulator.calls.length, calls);
  assert.equal(result.outcome, 'cut');
  assert.equal(result.reachedEdge, false);
});

test('spec 1868: 64 requests a poll', async t => {
  const step = (id, limit) => ({id, method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, query: {limit: {const: limit}}, maxResponseBytes: 65_536, expect: {status: [200], require: []}});
  const triggers = edited('feed-logged-detail', item => { item.poll.enrich.steps = [step('one', 1), step('two', 2), step('three', 3)]; item.event = {schema: {type: 'object', properties: {id: {type: 'string', minLength: 1, maxLength: 64}}, required: ['id'], additionalProperties: false}, id: {item: '/id'}, occurredAt: {item: '/recordId'}, fields: {id: {item: '/id'}}, summary: []}; item.poll.enrich.max = 25; });
  const h = rig(t, {triggers}), {feed, watch} = await h.watching('feed-logged-detail'), start = BigInt(feed.cursors.history);
  h.simulator.seed(40);
  const result = await h.read(feed, [watch]);
  assert.equal(result.run.requests, 64);
  assert.equal(result.outcome, 'cut');
  assert.equal(result.reachedEdge, false);
  assert.equal(fired(result).length, 21, 'three reads an item, and the twenty-second never finished');
  assert.equal(result.cursors.history, String(start + 21n), 'and the cursor stops before it');
});

test('16 MiB a poll stops before the next request', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.source.steps[0].maxResponseBytes = 2_097_152; })}), {feed, watch} = await h.watching('feed-listed'), request = h.runtime.request;
  let calls = 0;
  h.runtime.request = async input => {
    calls++;
    await request(input);
    return {status: 200, headers: {}, data: {items: [{id: `A${calls}`, name: 'x', updated: new Date(h.now).toISOString(), padding: 'y'.repeat(2_000_000)}], nextPageToken: `p${calls}`}};
  };
  const result = await h.read(feed, [watch], {windows: () => ({seconds: null})});
  assert.equal(calls, 9, 'eight answers come to 16 MB, under the limit, and the ninth passes it');
  assert.equal(result.outcome, 'cut');
  assert.equal(result.reachedEdge, false);
});

for (const [label, spacingMs] of [['one a second', 1000], ['5 a second', 200], ['20 a second', 50]]) {
  test(`spec 1869, asc, ${label}: 10,000 items drain within the page bounds, each poll under them, with no gap`, async t => {
    const h = rig(t), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
    h.simulator.seed(10_000, {spacingMs});
    let polls = 0, read = 0;
    for (;;) {
      h.advance(1000);
      const before = h.feedReads().length, result = await h.poll(feed, [watch]);
      polls++;
      read += result.events.length;
      assert.ok(h.feedReads().length - before <= 10);
      assert.equal(gaps(result).length, 0);
      if (result.reachedEdge) break;
      assert.ok(polls < 40);
    }
    assert.equal(h.stored, 10_000, 'each item once');
    assert.equal(read, 10_000);
  });
}

for (const key of ['desc', 'unordered']) {
  test(`spec 1869, ${key}: 10,000 items end within the bounds with one gap, and the mark jumps to the newest`, async t => {
    const triggers = edited('feed-posted', item => { item.poll.order = key; item.poll.source.steps[0].query.order = {const: key}; });
    const h = rig(t, {triggers}), {feed, watch} = await h.watching('feed-posted');
    const made = h.simulator.seed(10_000);
    const result = await h.poll(feed, [watch]);
    assert.equal(gaps(result).length, 1);
    assert.equal(gaps(result)[0].payload.fields.reason, 'bound');
    assert.equal(fired(result).length, 500, 'what was read fires');
    assert.equal(result.reachedEdge, true);
    if (key === 'desc') assert.equal(feed.cursors.ts, made.at(-1).ts);
    const after = await h.poll(feed, [watch]);
    assert.equal(gaps(after).length, 0);
    if (key === 'desc') assert.equal(fired(after).length, 0);
  });
}

const unorderedFeed = () => edited('feed-posted', item => { item.poll.order = 'unordered'; item.poll.source.steps[0].query.order = {const: 'unordered'}; });
const reasonsOf = result => gaps(result).map(row => row.payload.fields.reason);

test('an unordered feed cut by its bounds tells once for one run of the cut: the mark held, so an item past the bound stays inside the next read, and the gap the mark\'s next move owes covers it', async t => {
  const h = rig(t, {triggers: unorderedFeed()}), {feed, watch} = await h.watching('feed-posted');
  h.simulator.seed(1000, {spacingMs: 1});
  assert.deepEqual(reasonsOf(await h.poll(feed, [watch])), ['bound'], 'all thousand sit inside the overlap, past what one walk can read');
  h.advance(1000);
  const mark = feed.cursors.ts, held = feed.lastGoodAt, item = h.simulator.write();
  h.advance(1000);
  for (const poll of [1, 2, 3]) {
    const result = await h.poll(feed, [watch]);
    assert.deepEqual([fired(result).length, feed.cursors.ts, reasonsOf(result)], [0, mark, []], `poll ${poll}: ${item.id} sorted past the bound, and the read found nothing new, so nothing was added to what the gap said`);
    h.advance(1000);
  }
  let moved;
  for (let tries = 0; !moved; tries++) {
    assert.ok(tries < 200, 'a write that sorts inside the read');
    h.simulator.write();
    h.advance(1000);
    const result = await h.poll(feed, [watch]);
    if (fired(result).length) moved = result;
  }
  assert.deepEqual(reasonsOf(moved), ['bound'], 'the mark moved past what was left unread, so the run of the cut ends with one gap');
  assert.equal(gaps(moved)[0].payload.fields.from, new Date(held).toISOString(), 'from where the mark last moved, so no stretch of the run goes untold');
});

test('an unordered feed\'s first stop owes one gap even with nothing new: a silent baseline cut by its bounds told nobody, and the read cannot show what lies past it', async t => {
  const h = rig(t, {triggers: unorderedFeed()}), feed = h.feedOf('feed-posted'), watch = h.watch('feed-posted');
  h.simulator.seed(1000, {spacingMs: 1});
  const baseline = await h.poll(feed, [watch]);
  assert.deepEqual([baseline.outcome, baseline.baselined, baseline.unreadTo, gaps(baseline).length], ['cut', true, undefined, 0]);
  h.advance(1000);
  const first = await h.poll(feed, [watch]);
  assert.deepEqual([fired(first).length, reasonsOf(first)], [0, ['bound']]);
  assert.equal(first.unreadTo, h.now);
  h.advance(1000);
  assert.deepEqual(reasonsOf(await h.poll(feed, [watch])), [], 'and not again');
});

test('a read that reaches the end ends the run of the cut, so a later cut tells again', async t => {
  const h = rig(t, {triggers: unorderedFeed()}), {feed, watch} = await h.watching('feed-posted');
  h.simulator.seed(1000, {spacingMs: 1});
  assert.deepEqual(reasonsOf(await h.poll(feed, [watch])), ['bound']);
  h.advance(40_000);
  for (let tries = 0, moved = false; !moved; tries++) {
    assert.ok(tries < 200, 'a write that sorts inside the read');
    h.simulator.write();
    moved = fired(await h.poll(feed, [watch])).length > 0;
  }
  h.advance(40_000);
  h.simulator.write();
  const read = await h.poll(feed, [watch]);
  assert.deepEqual([read.outcome, read.unreadTo, reasonsOf(read)], ['done', undefined, []], 'the mark is past the burst, and the read fits');
  h.advance(1000);
  h.simulator.seed(1000, {spacingMs: 1});
  assert.deepEqual(reasonsOf(await h.poll(feed, [watch])), ['bound']);
});

test('a time-budget stop in a run of the cut keeps the run, since it read no further than the stop before', async t => {
  const h = rig(t, {triggers: unorderedFeed()}), {feed, watch} = await h.watching('feed-posted');
  h.simulator.seed(1000, {spacingMs: 1});
  const told = await h.poll(feed, [watch]), request = h.runtime.request;
  h.advance(1000);
  h.runtime.request = input => { h.advance(6000); return request(input); };
  const stopped = await h.poll(feed, [watch]);
  assert.deepEqual([stopped.outcome, stopped.unreadTo, reasonsOf(stopped)], ['cut', told.unreadTo, []]);
});

test('a desc baseline that its bounds cut stays silent, with no gap, and its mark jump finishes it', async t => {
  const h = rig(t), made = h.simulator.seed(700, {spacingMs: 10}), feed = h.feedOf('feed-posted'), watch = h.watch('feed-posted');
  const result = await h.poll(feed, [watch]);
  assert.equal(result.outcome, 'cut');
  assert.equal(result.events.length, 0);
  assert.equal(result.baselined, true);
  assert.equal(result.cursors.ts, made.at(-1).ts);
});

test('a time-budget stop on a desc feed keeps the mark with no gap, and the third in a row acts as a bounds stop', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-posted');
  const made = h.simulator.seed(300), request = h.runtime.request;
  h.runtime.request = input => { h.advance(6000); return request(input); };
  for (const stops of [1, 2]) {
    const cut = await h.poll(feed, [watch]);
    assert.equal(cut.budgetStops, stops);
    assert.equal(cut.cursors.ts, undefined, 'the mark stays');
    assert.equal(gaps(cut).length, 0);
    assert.equal(cut.reachedEdge, false);
    h.advance(MINUTE);
  }
  const third = await h.poll(feed, [watch]);
  assert.equal(gaps(third).length, 1);
  assert.equal(gaps(third)[0].payload.fields.reason, 'bound');
  assert.equal(third.cursors.ts, made.at(-1).ts);
  assert.equal(third.budgetStops, 0);
  assert.equal(third.reachedEdge, true);
});

test('a stall of 600 rows in one second gives one gap and sets the floor past the mark, and a later edit still arrives', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  const made = h.simulator.seed(600, {spacingMs: 0}), mark = made[0].updated;
  assert.equal(gaps(await h.poll(feed, [watch])).length, 0, 'the first 500 are new');
  const stalled = await h.poll(feed, [watch]);
  assert.equal(gaps(stalled).length, 1);
  assert.equal(gaps(stalled)[0].payload.fields.reason, 'stall');
  assert.equal(stalled.floor, new Date(Date.parse(mark) + 1000).toISOString());
  assert.equal(stalled.reachedEdge, false);
  const after = await h.poll(feed, [watch]);
  assert.equal(after.outcome, 'done');
  assert.equal(h.feedReads().at(-1).query.updatedAfter, stalled.floor);
  h.advance(5000);
  h.simulator.write();
  assert.equal(fired(await h.poll(feed, [watch])).length, 1, 'a later edit still arrives');
  assert.equal(gaps(await h.poll(feed, [watch])).length, 0);
});

test('a poll that reads a new key is no stall, however still its mark stands', async t => {
  const h = rig(t), at = h.now - 1000;
  h.simulator.seed(3, {spacingMs: 0, at});
  const {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  h.simulator.seed(600, {spacingMs: 0, at});
  assert.equal(gaps(await h.poll(feed, [watch])).length, 0, 'the mark stood still, but 497 keys were new');
  assert.equal(gaps(await h.poll(feed, [watch])).length, 1, 'then none are, and that is a stall');
});

test('a stall replayed after a crash stores one gap', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  h.simulator.seed(600, {spacingMs: 0});
  await h.poll(feed, [watch]);
  const first = await h.read(feed, [watch]);
  h.store.appendPoll({feedId: feed.id, seen: first.seen, events: first.events});
  const second = await h.read(feed, [watch]);
  assert.equal(gaps(first)[0].dedupeKey, gaps(second)[0].dedupeKey);
});

test('a run of filtered rows past the bound moves the mark, so it is no stall', async t => {
  const h = rig(t, {triggers: edited('feed-updated', item => { item.filter = [{equals: [{item: '/status'}, {const: 'published'}]}]; })});
  const {feed, watch} = await h.watching('feed-updated', {args: {kinds: ['note']}, resource: ['note']});
  h.simulator.seed(1200, {status: 'draft'});
  for (const poll of [1, 2]) {
    const result = await h.poll(feed, [watch]);
    assert.equal(result.outcome, 'cut', `poll ${poll}`);
    assert.equal(gaps(result).length, 0);
    assert.equal(result.floor, null);
  }
});

test('a stall at baseline sets the floor and says nothing', async t => {
  const h = rig(t);
  h.simulator.seed(600, {spacingMs: 0});
  const feed = h.feedOf('feed-updated', {resource: ['note']}), watch = h.watch('feed-updated', {args: {kinds: ['note']}});
  await h.settle(feed, [watch]);
  assert.equal(h.stored, 0);
  assert.notEqual(feed.floor, null);
  assert.equal(feed.baselined, true);
});

test('overflow: a window read where every item is unseen and the bound was hit gives one gap, no events and marks them seen, and two a day apart give two', async t => {
  const windows = () => ({seconds: null}), h = rig(t);
  h.simulator.seed(2);
  const feed = h.feedOf('feed-tagged'), watch = h.watch('feed-tagged');
  await h.settle(feed, [watch], {windows});
  const overflow = async () => {
    h.advance(HOUR);
    h.simulator.seed(600);
    const result = await h.poll(feed, [watch], {windows});
    assert.equal(fired(result).length, 0, 'a full window of unseen items fires none of them');
    assert.equal(gaps(result).length, 1);
    assert.equal(gaps(result)[0].payload.fields.reason, 'overflow');
    assert.equal(result.seen.length, 500, 'they are marked seen');
    assert.equal(result.reachedEdge, true);
    const again = await h.poll(feed, [watch], {windows});
    assert.deepEqual([fired(again).length, gaps(again).length], [0, 0]);
    h.advance(DAY);
  };
  await overflow();
  await overflow();
  assert.equal(h.events().length, 2, 'two gaps, each with its own key');
});

test('a window whose read is all filtered out has nothing to report, so it is no overflow', async t => {
  const windows = () => ({seconds: null}), h = rig(t, {triggers: edited('feed-tagged', item => { item.filter = [{equals: [{item: '/status'}, {const: 'published'}]}]; })});
  const feed = h.feedOf('feed-tagged'), watch = h.watch('feed-tagged');
  await h.settle(feed, [watch], {windows});
  h.simulator.seed(600, {status: 'draft'});
  assert.equal((await h.poll(feed, [watch], {windows})).events.length, 0);
});

for (const kind of ['id', 'id+version']) {
  test(`a window re-read keeps its rows fresh, kind ${kind}, so the oldest are the ones that left it`, async t => {
    const windows = () => ({seconds: null}), h = rig(t, {triggers: edited('feed-listed', item => { item.dedupe = {kind}; item.poll.itemVersion = kind === 'id' ? null : '/updated'; })});
    h.simulator.seed(2);
    const feed = h.feedOf('feed-listed'), watch = h.watch('feed-listed');
    await h.settle(feed, [watch], {windows});
    assert.equal((await h.read(feed, [watch], {windows})).seen.length, 2);
    assert.equal((await h.read(feed, [watch])).seen.length, 2, 'a whole list holds its rows the same way');
  });
}

test('triggers that share a snapshot share a window only if each reads one, and its shortest reach holds', async t => {
  const triggers = [...feedTriggers(), twin('feed-listed', 'feed-listed-too', item => { item.dedupe = {kind: 'id+version'}; item.poll.itemVersion = '/updated'; })];
  const h = rig(t, {triggers}), feed = h.feedOf('feed-listed', {tracked: ['feed-listed', 'feed-listed-too']}), watch = h.watch('feed-listed'), asked = [];
  const reaches = {'feed-listed': 7200, 'feed-listed-too': 3600}, windows = (appId, key) => { asked.push(key); return {seconds: reaches[key]}; };
  await h.settle(feed, [watch], {windows});
  assert.deepEqual([...new Set(asked)].sort(), ['feed-listed', 'feed-listed-too']);
  h.advance(90 * MINUTE);
  assert.equal(gaps(await h.poll(feed, [watch], {windows})).length, 1, 'an hour and a half is past the shorter reach');
  h.simulator.seed(600);
  assert.equal((await h.read(feed, [watch], {windows: (appId, key) => key === 'feed-listed' ? {seconds: null} : null})).pause?.reason, 'too_many_items', 'one whole-list trigger makes it a whole list');
});

test('a window read with a seen item in it is no overflow: the unseen items fire', async t => {
  const windows = () => ({seconds: null}), h = rig(t, {triggers: edited('feed-tagged', item => { pagesOf(item, 1); })});
  h.simulator.seed(2);
  const feed = h.feedOf('feed-tagged'), watch = h.watch('feed-tagged');
  await h.settle(feed, [watch], {windows});
  h.advance(HOUR);
  h.simulator.seed(30);
  h.simulator.fail('GET /feed', {status: 200, data: {items: h.simulator.state().items.filter(item => item.feedSerial).map(({id, name, updated}) => ({id, name, updated})).slice(0, 32), nextPageToken: 'p32'}});
  const result = await h.poll(feed, [watch], {windows});
  assert.equal(fired(result).length, 30);
  assert.equal(gaps(result).length, 0);
});

test('a window snapshot cut by its bounds on every poll still reaches the edge', async t => {
  const windows = () => ({seconds: null}), h = rig(t, {triggers: edited('feed-tagged', item => { pagesOf(item, 1); })});
  h.simulator.seed(120);
  const feed = h.feedOf('feed-tagged'), watch = h.watch('feed-tagged', {status: 'starting', pending: [feed.id]});
  const result = await h.poll(feed, [watch], {windows});
  assert.equal(result.reachedEdge, true);
  assert.equal(result.baselined, true);
});

test('a whole list cut by its bounds pauses, at baseline or later, and one cut by the budget changes nothing', async t => {
  const h = rig(t);
  h.simulator.seed(600);
  const feed = h.feedOf('feed-listed'), watch = h.watch('feed-listed');
  const baseline = await h.read(feed, [watch]);
  assert.deepEqual(baseline.pause, {reason: 'too_many_items', detail: 'bounds'});
  assert.deepEqual([baseline.events, baseline.seen], [[], []]);
  const later = rig(t), running = await later.watching('feed-listed');
  later.simulator.seed(600);
  assert.equal((await later.read(running.feed, [running.watch])).pause?.reason, 'too_many_items');
  const request = later.runtime.request;
  later.runtime.request = input => { later.advance(6000); return request(input); };
  const cut = await later.read(running.feed, [running.watch]);
  assert.equal(cut.pause, undefined);
  assert.equal(cut.outcome, 'cut');
  assert.equal(cut.reachedEdge, false);
  assert.equal(cut.lastGoodAt, running.feed.lastGoodAt, 'only a finished poll moves a snapshot\'s cursor');
  assert.equal(cut.baselined, true);
});

test('a budget stop on a snapshot leaves lastGoodAt alone, even when it clears a conditional cursor', async t => {
  const h = rig(t);
  h.simulator.seed(2);
  const {feed, watch} = await h.watching('feed-tagged'), good = feed.lastGoodAt, request = h.runtime.request;
  h.simulator.seed(200);
  h.advance(MINUTE);
  h.runtime.request = input => { h.advance(6000); return request(input); };
  const cut = await h.read(feed, [watch]);
  assert.equal(cut.outcome, 'cut');
  assert.equal(cut.cursors.etag, undefined);
  assert.equal(cut.lastGoodAt, good);
});

test('a timed window slept past gives one gap and re-baselines, and two sleeps give two', async t => {
  const windows = () => ({seconds: 3600}), h = rig(t), feed = h.feedOf('feed-tagged'), watch = h.watch('feed-tagged');
  await h.settle(feed, [watch], {windows});
  const sleep = async () => {
    h.advance(2 * HOUR);
    h.simulator.write();
    const result = await h.poll(feed, [watch], {windows});
    assert.equal(gaps(result).length, 1);
    assert.equal(gaps(result)[0].payload.fields.reason, 'window');
    assert.equal(fired(result).length, 0, 're-baselined: what arrived in the sleep is absorbed');
  };
  await sleep();
  await sleep();
  assert.equal(h.events().length, 2);
  h.advance(MINUTE);
  h.simulator.write();
  assert.equal(fired(await h.poll(feed, [watch], {windows})).length, 1, 'then the next write fires');
});

test('a silent poll owes no sleep gap: nothing was delivered yet', async t => {
  const windows = () => ({seconds: 3600}), h = rig(t), feed = h.feedOf('feed-tagged', {lastGoodAt: h.now - DAY});
  assert.equal((await h.read(feed, [h.watch('feed-tagged')], {windows})).events.length, 0);
});

test('one poll can owe two gaps, and both are stored', async t => {
  const windows = () => ({seconds: 3600, alerts: true}), h = rig(t, {triggers: edited('feed-tagged', item => { item.poll.enrich = {max: 25, steps: [DETAIL()]}; })}), feed = h.feedOf('feed-tagged'), watch = h.watch('feed-tagged');
  await h.settle(feed, [watch], {windows});
  h.advance(2 * HOUR);
  h.simulator.write();
  h.simulator.fail('GET /items/{item_id}', {status: 500, data: null});
  const result = await h.read({...feed, recordFailures: 4}, [watch], {windows});
  assert.deepEqual(gaps(result).map(row => row.payload.fields.reason), ['window', 'stall']);
  assert.equal(result.gap.reason, 'window');
});

test('a window gap ends when its silent read ends, so what that read marks as seen sits inside it', async t => {
  const windows = () => ({seconds: 3600}), h = rig(t), feed = h.feedOf('feed-tagged'), watch = h.watch('feed-tagged');
  await h.settle(feed, [watch], {windows});
  h.advance(4 * HOUR);
  const held = h.simulator.hold('GET /feed'), flight = h.poll(feed, [watch], {windows});
  await held.reached;
  h.advance(3000);
  const written = h.now;
  h.simulator.write({name: 'During the read'});
  held.release();
  const result = await flight, [gap] = gaps(result);
  assert.deepEqual([fired(result), gap.payload.fields.reason], [[], 'window']);
  assert.ok(Date.parse(gap.payload.fields.to) >= written, `written at ${new Date(written).toISOString()}, and the gap ends ${gap.payload.fields.to}`);
  assert.equal(gap.dedupeKey, `gap|window|${gap.payload.fields.from}`);
});

test('the real table of windows: a lead a subscription sets alerts, a set reach does not, and a whole list has no window', () => {
  assert.deepEqual(windowRule('google-calendar', 'starting-soon', {calendarId: 'a', leadMinutes: 30}), {seconds: 1800, alerts: true});
  assert.deepEqual(windowRule('gmail', 'new-email-matching-search', {}), {seconds: 604_800, alerts: false});
  assert.deepEqual(windowRule('github', 'push', {}), {seconds: null, alerts: false});
  assert.equal(windowRule('notion', 'new-comment', {}), null);
});

test('a window a meeting alert uses gives its gap and then runs normally, so an alert still ahead keeps its place', async t => {
  const windows = () => ({seconds: 3600, alerts: true}), h = rig(t), feed = h.feedOf('feed-tagged'), watch = h.watch('feed-tagged');
  await h.settle(feed, [watch], {windows});
  h.advance(2 * HOUR);
  h.simulator.write();
  const result = await h.poll(feed, [watch], {windows});
  assert.equal(gaps(result).length, 1);
  assert.equal(fired(result).length, 1);
});

test('a snapshot with itemTime drops an unseen item older than its baseline, so a deleted one does not make an older one look new', async t => {
  const windows = () => ({seconds: null}), h = rig(t, {triggers: edited('feed-tagged', item => { pagesOf(item, 1); })});
  const made = h.simulator.seed(55);
  const feed = h.feedOf('feed-tagged'), watch = h.watch('feed-tagged');
  await h.settle(feed, [watch], {windows});
  assert.equal(feed.floor, made.at(-1).updated);
  h.simulator.remove(made.at(-1).id);
  h.advance(1000);
  const result = await h.poll(feed, [watch], {windows});
  assert.equal(fired(result).length, 0, 'the older one came into view, and it is not new');
  assert.equal(gaps(result).length, 0);
  h.advance(1000);
  h.simulator.write();
  assert.equal(fired(await h.poll(feed, [watch], {windows})).length, 1);
  assert.equal(feed.floor, made.at(-1).updated, 'the floor is the baseline\'s, for good');
});

test('windowOf reads the real table by default: the fixture app has no window', async t => {
  const h = rig(t);
  h.simulator.seed(600);
  assert.equal((await h.read(h.feedOf('feed-tagged'), [h.watch('feed-tagged')])).pause?.reason, 'too_many_items');
});

// ---- enrich --------------------------------------------------------------------------------------------------------------------------------
test('an enrich step reads at most enrich.max items a poll and stops at the last whole record, and filters, dedupe and the event read its answer', async t => {
  const triggers = edited('feed-logged-detail', item => { item.poll.enrich.max = 2; });
  const h = rig(t, {triggers}), {feed, watch} = await h.watching('feed-logged-detail'), start = BigInt(feed.cursors.history);
  const made = h.simulator.seed(3);
  const result = await h.poll(feed, [watch]);
  assert.deepEqual(result.events.map(row => row.payload.fields.read), made.slice(0, 2).map(item => item.name));
  assert.equal(result.outcome, 'cut');
  assert.equal(feed.cursors.history, String(start + 2n));
  await h.settle(feed, [watch]);
  assert.equal(h.stored, 3);
});

test('step 5: a retried poll never reads a stored item again', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.enrich = {max: 25, steps: [{id: 'detail', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, maxResponseBytes: 65_536, expect: {status: [200], require: []}}]}; })});
  h.simulator.seed(1);
  const {feed, watch} = await h.watching('feed-listed'), reads = () => h.simulator.calls.filter(call => call.route === 'GET /items/{item_id}').length;
  assert.equal(reads(), 0, 'a baseline runs no enrich step');
  h.simulator.write();
  assert.equal(fired(await h.poll(feed, [watch])).length, 1);
  assert.equal(reads(), 1, 'the baseline\'s item has a row, so only the new one reads');
  await h.poll(feed, [watch]);
  assert.equal(reads(), 1);
});

test('one enrich request reads once in a poll, whichever lens asks', async t => {
  const triggers = [...feedTriggers()];
  const copy = structuredClone(triggers.find(item => item.key === 'feed-logged-detail'));
  copy.key = 'feed-logged-copy';
  copy.id = `fixture.trigger.feed-logged-copy.v1.${'0'.repeat(24)}`;
  copy.filter = [{status: {step: 'detail', in: [200]}}];
  const h = rig(t, {triggers: [...triggers, copy]}), tracked = ['feed-logged-detail', 'feed-logged-copy'], {feed, watch} = await h.watching('feed-logged-detail', {tracked}), other = h.watch('feed-logged-copy');
  h.simulator.seed(2);
  const result = await h.read(feed, [watch, other]);
  assert.equal(fired(result).length, 4);
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /items/{item_id}').length, 2);
  const dropped = await h.read(feed, [watch, other], {authority: item => ({ok: item?.entry.key !== 'feed-logged-copy'})});
  assert.deepEqual([...new Set(fired(dropped).map(row => row.subscriptionId))], [watch.id], 'a reused answer still asks for its own lens');
});

test('a 404 or an answer too large on an enrich read skips that item only', async t => {
  const h = rig(t, {triggers: edited('feed-logged-detail', item => { item.poll.enrich.steps[0].expect = {status: [200], require: []}; })}), {feed, watch} = await h.watching('feed-logged-detail');
  const made = h.simulator.seed(3);
  h.simulator.fail('GET /items/{item_id}', {status: 404, data: {error: 'gone'}});
  const missing = await h.read(feed, [watch]);
  assert.deepEqual(missing.events.map(row => row.payload.id), made.slice(1).map(item => item.id));
  assert.equal(missing.run.skipped, 1);
  assert.equal(missing.outcome, 'done');
  assert.equal(missing.seen.length, 2, 'a 404 is an item that went, so nothing was lost and no gap says so');
  h.simulator.oversize('GET /items/{item_id}', 70_000);
  const large = await h.read(feed, [watch]);
  assert.deepEqual(fired(large).map(row => row.payload.id), made.slice(1).map(item => item.id));
  assert.equal(large.run.skipped, 1);
  assert.deepEqual([gaps(large).map(row => row.payload.fields.reason), large.seen.length], [['stall'], 3], 'an item too large to read is real: a gap says so, and its row keeps it from coming back');
});

test('an enrich answer its step refuses, or a read that cannot be built, is a real item given up too: one gap and a seen row', async t => {
  const h = rig(t, {triggers: edited('feed-logged-detail', item => { item.poll.enrich.steps[0].page = {next: {pointer: '/next'}, into: {query: 'page'}, items: '/lines', max: 2}; })});
  const {feed, watch} = await h.watching('feed-logged-detail', {tracked: ['feed-logged', 'feed-logged-detail']});
  h.simulator.seed(1);
  h.simulator.fail('GET /items/{item_id}', {status: 200, data: {lines: 'oops'}});
  const refused = await h.read(feed, [watch]);
  assert.deepEqual([refused.outcome, fired(refused).length, gaps(refused).length, refused.seen.length], ['done', 0, 1, 1]);
  const badId = {history: [{id: String(BigInt(feed.cursors.history) + 2n), messagesAdded: [{message: {id: '\ud800', threadId: 'T'}}]}], historyId: String(BigInt(feed.cursors.history) + 2n)};
  h.simulator.fail('GET /feed', {status: 200, data: badId});
  const unbuilt = await h.read(feed, [watch]);
  assert.deepEqual([unbuilt.outcome, fired(unbuilt).length, gaps(unbuilt).length, unbuilt.seen.length], ['done', 0, 1, 1]);
});

test('a read the live guard refuses is no provider\'s answer, so it gives no gap and no seen row, and the item is read again', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged-detail', {tracked: ['feed-logged', 'feed-logged-detail']}), {request} = h.runtime;
  h.simulator.seed(1);
  h.runtime.request = input => input.url.includes('/items/') ? Promise.reject(Object.assign(new Error('refused'), {sent: false, code: 'action_refused', details: {reason: 'guard'}})) : request(input);
  const result = await h.read(feed, [watch]);
  assert.deepEqual([result.outcome, result.run.skipped, gaps(result).length, result.seen.length], ['done', 1, 0, 0]);
});

test('a snapshot that reads an item too large for its enrich step gives one gap for it, and not one at every poll', async t => {
  const triggers = edited('feed-tagged', item => { item.poll.enrich = {max: 25, steps: [{id: 'detail', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, maxResponseBytes: 65_536, expect: {status: [200], require: []}}]}; });
  const h = rig(t, {triggers}), {feed, watch} = await h.watching('feed-tagged');
  h.simulator.write();
  h.simulator.oversize('GET /items/{item_id}', 70_000);
  assert.equal(gaps(await h.poll(feed, [watch])).length, 1);
  h.advance(MINUTE);
  h.simulator.oversize('GET /items/{item_id}', 70_000);
  assert.equal(gaps(await h.poll(feed, [watch])).length, 0);
});

test('an enrich request that cannot be built skips that item only', async t => {
  const h = rig(t), item = structuredClone(h.itemOf('feed-logged-detail'));
  item.entry.trigger.poll.enrich.steps[0].params.item_id = {item: '/missing'};
  item.lenses = [triggerLens(item.entry)];
  h.simulator.seed(1);
  const feed = h.feedOf('feed-logged', {tracked: [], lenses: item.lenses, baselined: true, cursors: {history: String(2n ** 53n)}}), result = await h.read(feed, [h.watch('feed-logged-detail')], {entries: [item]});
  assert.equal(result.run.skipped, 1);
  assert.equal(result.outcome, 'done');
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /items/{item_id}').length, 0);
});

test('the filter tests that read an enrich step run after it, and an item they drop takes no seen row', async t => {
  const h = rig(t, {triggers: edited('feed-logged-detail', item => { item.filter = [{status: {step: 'detail', in: [200]}}]; })}), {feed, watch} = await h.watching('feed-logged-detail'), [gone, kept] = h.simulator.seed(2);
  h.simulator.fail('GET /items/{item_id}', {status: 404, data: {error: 'gone'}});
  const result = await h.read(feed, [watch]);
  assert.deepEqual(result.events.map(row => row.payload.id), [kept.id]);
  assert.equal(result.seen.length, 1, gone.id);
  assert.equal(h.simulator.calls.filter(call => call.route === 'GET /items/{item_id}').length, 2, 'a test on a step reads that step first');
});

test('a limit on an enrich read keeps the whole records before it, moves the cursor to the last one and sets the wait', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged-detail'), start = BigInt(feed.cursors.history), request = h.runtime.request;
  h.simulator.seed(4);
  let reads = 0;
  h.runtime.request = input => input.url.includes('/items/') && ++reads === 3 ? Promise.resolve({status: 429, headers: {'retry-after': '120'}, data: null}) : request(input);
  const result = await h.poll(feed, [watch]);
  assert.equal(result.outcome, 'limited');
  assert.equal(result.wait.until, h.now + 120_000);
  assert.equal(fired(result).length, 2);
  assert.equal(feed.cursors.history, String(start + 2n));
  assert.equal(result.reachedEdge, false);
  assert.equal(result.recordFailures, 1);
});

for (const [label, answer, outcome] of [['a 500', {status: 500, headers: {}, data: null}, 'backoff'], ['a 401', {status: 401, headers: {}, data: null}, 'backoff'], ['a 200 that fails its rule', null, 'backoff']]) {
  test(`${label} on an enrich read ends the walk at the last whole record and backs off`, async t => {
    const h = rig(t, {triggers: edited('feed-logged-detail', item => { item.poll.enrich.steps[0].expect = {status: [200], require: [{present: {pointer: '/name'}}]}; })});
    const {feed, watch} = await h.watching('feed-logged-detail'), request = h.runtime.request;
    h.simulator.seed(2);
    let reads = 0;
    h.runtime.request = input => input.url.includes('/items/') && ++reads === 2 ? Promise.resolve(answer ?? {status: 200, headers: {}, data: {}}) : request(input);
    const result = await h.read(feed, [watch]);
    assert.equal(result.outcome, outcome);
    assert.equal(fired(result).length, 1);
    assert.equal(result.pause, undefined);
  });
}

test('a timeout on an enrich read ends the walk the same way', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged-detail'), request = h.runtime.request;
  h.simulator.seed(1);
  h.runtime.request = input => input.url.includes('/items/') ? Promise.reject(Object.assign(new Error('Provider request timed out.'), {sent: true})) : request(input);
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'backoff');
  assert.equal(result.run.code, 'timeout');
  assert.equal(result.cursors.history, feed.cursors.history);
});

test('a refusal on an enrich read belongs to its lens: it pauses provider_refused, and the other lens still fires', async t => {
  const h = rig(t), tracked = ['feed-logged', 'feed-logged-detail'], {feed, watch} = await h.watching('feed-logged', {tracked}), detail = h.watch('feed-logged-detail');
  h.simulator.seed(1);
  h.simulator.fail('GET /items/{item_id}', {status: 403, data: {error: 'no'}});
  const result = await h.read(feed, [watch, detail]);
  assert.deepEqual(result.lensPauses, [{lens: h.itemOf('feed-logged-detail').lenses[0], code: 'http_403', reason: 'provider_refused'}]);
  assert.deepEqual(result.events.map(row => row.subscriptionId), [watch.id]);
  assert.equal(result.pause, undefined);
});

test('when the last live lens goes, the poll ends with nothing stored, and the lens pause still reaches the scheduler', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged-detail');
  h.simulator.seed(1);
  h.simulator.fail('GET /items/{item_id}', {status: 403, data: {error: 'no'}});
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'withheld');
  assert.equal(result.lensPauses.length, 1);
  assert.deepEqual([result.events, result.seen], [[], []]);
});

test('a limit on one lens\'s enrich read ends the page for the others too: no more requests', async t => {
  const triggers = [...feedTriggers(), twin('feed-logged-keys', 'feed-logged-more', item => { item.rows = ['fixture.items.read']; item.poll.enrich.steps = [{...DETAIL(), id: 'keys', query: {limit: {const: 1}}}]; })];
  const h = rig(t, {triggers}), tracked = ['feed-logged-detail', 'feed-logged-more'], {feed, watch} = await h.watching('feed-logged-detail', {tracked}), other = h.watch('feed-logged-more');
  h.simulator.seed(1);
  h.simulator.fail('GET /items/{item_id}', {status: 429, data: null});
  const before = h.simulator.calls.length, result = await h.read(feed, [watch, other]);
  assert.equal(result.outcome, 'limited');
  assert.equal(h.simulator.calls.length, before + 2, 'the page, then the one that was refused');
});

test('with two live lenses the cursor is the lowest either finished, in whichever order they stand, and a lens that finished nothing holds it', async t => {
  const triggers = edited('feed-logged-detail', item => { item.poll.enrich.max = 2; });
  for (const tracked of [['feed-logged', 'feed-logged-detail'], ['feed-logged-detail', 'feed-logged']]) {
    const h = rig(t, {triggers}), {feed, watch} = await h.watching('feed-logged', {tracked}), start = BigInt(feed.cursors.history), detail = h.watch('feed-logged-detail');
    h.simulator.seed(6);
    assert.equal((await h.read(feed, [watch, detail])).cursors.history, String(start + 2n), tracked.join());
    h.simulator.fail('GET /items/{item_id}', {status: 500, data: null});
    assert.equal((await h.read(feed, [watch, detail])).cursors.history, String(start), 'the failing lens finished nothing');
  }
});

test('after 5 polls fail on one record its item is skipped with one stall gap, so one message cannot hold a feed', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged-detail'), request = h.runtime.request, [bad, good] = h.simulator.seed(2);
  h.runtime.request = input => input.url.endsWith(`/items/${bad.id}`) ? Promise.resolve({status: 500, headers: {}, data: null}) : request(input);
  for (const count of [1, 2, 3, 4]) {
    const result = await h.poll(feed, [watch]);
    assert.equal(result.recordFailures, count);
    assert.equal(result.events.length, 0);
    assert.equal(result.outcome, 'backoff');
    h.advance(MINUTE);
  }
  const fifth = await h.poll(feed, [watch]);
  assert.equal(gaps(fifth).length, 1);
  assert.equal(gaps(fifth)[0].payload.fields.reason, 'stall');
  assert.equal(fifth.recordFailures, 0);
  h.advance(MINUTE);
  const next = await h.poll(feed, [watch]);
  assert.deepEqual(next.events.map(row => row.payload.id), [good.id], 'the next poll reads past it');
  assert.equal(next.outcome, 'done');
});

test('a poll with no failure clears the count, and a poll that stored nothing leaves it', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged-detail');
  assert.equal((await h.read({...feed, recordFailures: 3}, [watch])).recordFailures, 0);
  h.simulator.fail('GET /feed', {status: 500, data: null});
  assert.equal((await h.read({...feed, recordFailures: 3}, [watch])).recordFailures, 3);
});

test('a poll that makes progress before it fails counts one, not one more', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-logged-detail'), request = h.runtime.request, [first, second] = h.simulator.seed(2);
  feed.recordFailures = 3;
  h.runtime.request = input => input.url.endsWith(`/items/${second.id}`) ? Promise.resolve({status: 500, headers: {}, data: null}) : request(input);
  assert.equal((await h.read(feed, [watch])).recordFailures, 1, first.id);
});

test('a snapshot\'s walk ends at the failing item, and a skipped item takes a seen row', async t => {
  const triggers = edited('feed-tagged', item => { item.poll.enrich = {max: 25, steps: [{id: 'detail', method: 'GET', path: '/items/{item_id}', params: {item_id: {item: '/id'}}, maxResponseBytes: 65_536, expect: {status: [200], require: []}}]}; });
  const h = rig(t, {triggers}), {feed, watch} = await h.watching('feed-tagged'), bad = h.simulator.write(), request = h.runtime.request;
  h.runtime.request = input => input.url.endsWith(`/items/${bad.id}`) ? Promise.resolve({status: 500, headers: {}, data: null}) : request(input);
  feed.recordFailures = 4;
  const result = await h.poll(feed, [watch]);
  assert.equal(result.seen.length, 1);
  assert.equal(gaps(result).length, 1);
  let asked = 0;
  h.runtime.request = input => { if (input.url.endsWith(`/items/${bad.id}`)) asked++; return request(input); };
  assert.equal(gaps(await h.poll(feed, [watch])).length, 0);
  assert.equal(asked, 0, 'its seen row keeps the next poll from asking again');
});

// ---- the body cursor ---------------------------------------------------------------------------------------------------------------------------
const searched = () => edited('feed-updated', item => {
  item.poll.source = {steps: [{id: 'rows', method: 'POST', path: '/items/search', body: {object: {query: {const: ''}, since: {object: {on_or_after: {cursor: 'since'}}}}}, page: {next: {pointer: '/next_cursor'}, into: {body: '/start_cursor'}, items: '/results', while: '/has_more', max: 10}, maxResponseBytes: 262_144, expect: {status: [200], require: []}}]};
  item.poll.items = {step: 'rows', pointer: ''};
  delete item.poll.itemTime;
  item.poll.itemVersion = null;
  item.poll.seed = {step: {id: 'latest', method: 'GET', path: '/feed', query: {order: {const: 'desc'}, limit: {const: 1}}, maxResponseBytes: 4096, expect: {status: [200], require: []}}, cursor: {name: 'since', pointer: '/items/0/updated'}};
  item.poll.cursors = [{name: 'since', kind: 'high-water-time@1', next: {step: 'rows', pointer: '/asOf'}, compare: 'time.rfc3339ToEpochSeconds@1', overlapSeconds: 60}];
  item.inputSchema = {type: 'object', properties: {}, additionalProperties: false, required: []};
  item.resource = [];
  item.dedupe = {kind: 'id'};
  item.event = ITEM_EVENT;
});

test('a body cursor with no value: at baseline the seed runs in place of the poll step, and after it the poll binds the constant, so the first row fires', async t => {
  const h = rig(t, {triggers: searched()}), feed = h.feedOf('feed-updated'), watch = h.watch('feed-updated');
  const baseline = await h.poll(feed, [watch]);
  assert.equal(baseline.baselined, true);
  assert.equal(baseline.reachedEdge, true);
  assert.equal(h.simulator.calls.filter(call => call.route === 'POST /items/search').length, 0, 'no empty created_time object is sent');
  assert.deepEqual(feed.cursors, {});
  const first = await h.poll(feed, [watch]), [call] = h.simulator.calls.filter(item => item.route === 'POST /items/search');
  assert.equal(call.body.since.on_or_after, '1970-01-01T00:00:00.000Z');
  assert.equal(call.headers['content-type'], 'application/json; charset=utf-8');
  assert.deepEqual(feed.cursors, {}, 'a constant is not a provider value, so it is never stored');
  assert.ok(fired(first).length > 0, 'the source was empty, so every row is new');
});

test('a body cursor that resyncs reads the constant, and a second refusal in one run ends it', async t => {
  const triggers = searched().map(item => { if (item.key === 'feed-updated') { item.poll.resync = {statusIn: [410]}; delete item.poll.seed; } return item; });
  const h = rig(t, {triggers}), feed = h.feedOf('feed-updated', {baselined: true, cursors: {since: new Date(h.now).toISOString()}}), watch = h.watch('feed-updated');
  h.simulator.fail('POST /items/search', {status: 410, data: {error: 'gone'}}, {times: Infinity});
  const result = await h.read(feed, [watch]);
  assert.equal(h.simulator.calls.filter(call => call.route === 'POST /items/search').length, 2);
  assert.equal(result.outcome, 'paused');
});

test('a high-water cursor that reads its next value from the answer takes it as it takes any mark', async t => {
  const h = rig(t, {triggers: searched()}), [item] = h.simulator.seed(1), feed = h.feedOf('feed-updated'), watch = h.watch('feed-updated');
  await h.poll(feed, [watch]);
  const later = new Date(h.now + 5000).toISOString();
  h.simulator.fail('POST /items/search', {status: 200, data: {results: [], has_more: false, asOf: later}});
  assert.equal((await h.read(feed, [watch])).cursors.since, later, item.id);
});

test('a body cursor with a seed value is bound as any mark is', async t => {
  const h = rig(t, {triggers: searched()}), [item] = h.simulator.seed(1), feed = h.feedOf('feed-updated'), watch = h.watch('feed-updated');
  await h.poll(feed, [watch]);
  const [call] = h.simulator.calls.filter(entry => entry.route === 'POST /items/search');
  assert.equal(call.body.since.on_or_after, new Date(Date.parse(item.updated) - 60_000).toISOString());
  assert.equal(h.stored, 0, 'and that walk is the silent poll');
});

// ---- several steps -----------------------------------------------------------------------------------------------------------------------------
test('source steps run in order, and only a page step pages', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.source.steps.unshift({id: 'names', method: 'GET', path: '/labels', maxResponseBytes: 65_536, expect: {status: [200], require: []}}); })});
  h.simulator.seed(60);
  await h.watching('feed-listed');
  assert.deepEqual(h.simulator.calls.map(call => call.route), ['GET /labels', 'GET /feed', 'GET /feed'], 'one read of the first step, then the poll step\'s pages');
});

const pagedEarlier = () => edited('feed-listed', item => {
  item.poll.source.steps.unshift({id: 'names', method: 'GET', path: '/labels', page: {next: {pointer: '/nextPageToken'}, into: {query: 'pageToken'}, items: '/labels', max: 2}, maxResponseBytes: 65_536, expect: {status: [200], require: []}});
  item.poll.source.steps[1].page = undefined;
  delete item.poll.source.steps[1].page;
  item.poll.items = {array: [{object: {id: {step: 'names', pointer: '/1/id'}, first: {step: 'feed', pointer: '/items/0/id'}}}]};
  item.event = ITEM_EVENT;
});

test('an earlier step that pages reads in full, and its pages join for the items to read', async t => {
  const h = rig(t, {triggers: pagedEarlier()}), request = h.runtime.request;
  let reads = 0;
  h.runtime.request = input => input.url.includes('/labels') ? Promise.resolve(++reads === 1 ? {status: 200, headers: {}, data: {labels: [{id: 'L1'}], nextPageToken: 'more'}} : {status: 200, headers: {}, data: {labels: [{id: 'L2'}]}}) : request(input);
  const feed = h.feedOf('feed-listed'), result = await h.read(feed, [h.watch('feed-listed')]);
  assert.equal(reads, 2);
  assert.equal(result.seen[0].itemKey, sha(`${feed.id}|${feed.lenses[0]}|L2`));
});

test('an earlier step past its own page limit refuses as a whole answer does: only the poll step\'s walk stops short', async t => {
  const h = rig(t, {triggers: pagedEarlier()}), request = h.runtime.request;
  h.runtime.request = input => input.url.includes('/labels') ? Promise.resolve({status: 200, headers: {}, data: {labels: [], nextPageToken: 'more'}}) : request(input);
  assert.deepEqual((await h.read(h.feedOf('feed-listed'), [h.watch('feed-listed')])).pause, {reason: 'too_many_items', detail: 'too_many_pages'});
});

test('a failure of an earlier step is a source step\'s failure', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.poll.source.steps.unshift({id: 'names', method: 'GET', path: '/labels', maxResponseBytes: 65_536, expect: {status: [200], require: []}}); })});
  const {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /labels', {status: 500, data: null});
  const result = await h.read(feed, [watch]);
  assert.equal(result.outcome, 'backoff');
  assert.equal(h.simulator.calls.at(-1).route, 'GET /labels');
});

// ---- no secrets out ----------------------------------------------------------------------------------------------------------------------------
test('credentials never appear in an event, a run, a cursor or a seen row, by the action runner\'s own scan', async t => {
  const context = credentialContext({Authorization: `Bearer ${TOKEN}`}), encoded = Buffer.from(TOKEN).toString('base64');
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  const updated = new Date(h.now).toISOString();
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: 'plain', name: `Bearer ${TOKEN}`, updated}, {id: 'hidden', name: encoded, updated}, {id: 'clean', name: 'fine', updated}], nextSyncToken: 's7'}});
  const result = await h.read(feed, [watch]);
  assert.equal(holdsCredential({events: result.events, run: result.run, cursors: result.cursors, seen: result.seen}, context), false);
  assert.equal(fired(result).length, 2, 'the spelled one was scrubbed from the answer; the encoded one is refused at the event');
  assert.equal(result.run.skipped, 1);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(TOKEN));
});

test('a raw item value that hides the credential is held at the event, where no transform saw it', async t => {
  const h = rig(t), encoded = Buffer.from(TOKEN).toString('base64'), {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, data: {items: [{id: encoded, name: 'fine', updated: new Date(h.now).toISOString()}]}});
  const result = await h.read(feed, [watch]);
  assert.equal(fired(result).length, 0);
  assert.equal(result.run.skipped, 1);
  assert.equal(JSON.stringify(result.events).includes(encoded), false, 'the gap that tells of it holds nothing of it');
});

test('a seed\'s value is held to its cursor\'s form: a bad one pauses cursor_invalid and stores nothing, at a baseline and at a resync', async t => {
  const h = rig(t), watch = h.watch('feed-logged'), feed = h.feedOf('feed-logged');
  h.simulator.fail('GET /feed', {status: 200, data: {historyId: 'not-a-number'}});
  const first = await h.read(feed, [watch]);
  assert.deepEqual([first.outcome, first.pause, first.cursors, first.baselined], ['paused', {reason: 'cursor_invalid', detail: 'history-id@1'}, {}, false]);
  await h.settle(feed, [watch]);
  const {history} = feed.cursors;
  h.simulator.expireCursors();
  const {request} = h.runtime;
  h.runtime.request = input => new URL(input.url).searchParams.get('limit') === '1' ? Promise.resolve({status: 200, headers: {}, data: {historyId: 'x1'}}) : request(input);
  const again = await h.read(feed, [watch]);
  assert.deepEqual([again.outcome, again.pause?.reason, again.cursors.history, again.events], ['paused', 'cursor_invalid', history, []]);
});

test('a seed that carries the credential in any spelling is no cursor', async t => {
  const seeded = () => edited('feed-synced', item => { item.poll.seed = {step: {id: 'start', method: 'GET', path: '/feed', query: {limit: {const: 1}}, maxResponseBytes: 4096, expect: {status: [200], require: []}}, cursor: {name: 'sync', pointer: '/nextSyncToken'}}; });
  for (const spelling of [Buffer.from(TOKEN).toString('base64'), TOKEN]) {
    const h = rig(t, {triggers: seeded()}), feed = h.feedOf('feed-synced');
    h.simulator.fail('GET /feed', {status: 200, data: {nextSyncToken: spelling}});
    const result = await h.read(feed, [h.watch('feed-synced')]);
    assert.deepEqual([result.outcome, result.pause, result.cursors], ['paused', {reason: 'cursor_invalid', detail: 'sync-token@1'}, {}]);
  }
});

test('an incoming cursor that holds the credential is no cursor', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  for (const value of [Buffer.from(TOKEN).toString('base64'), TOKEN]) {
    h.simulator.fail('GET /feed', {status: 200, data: {items: [], nextSyncToken: value}});
    const result = await h.read(feed, [watch]);
    assert.equal(result.pause.reason, 'cursor_invalid');
    assert.equal(result.cursors.sync, feed.cursors.sync);
  }
});

// ---- the seen limit and retention ---------------------------------------------------------------------------------------------------------------
test('seenLimits say each lens\'s limit, and which kinds drop their oldest rows silently', async t => {
  const windows = () => ({seconds: null}), h = rig(t);
  for (const [key, resource, expected, options] of [['feed-updated', ['note'], {limit: 5000, evict: true}, {}], ['feed-logged', [], {limit: 5000, evict: true}, {}], ['feed-synced', [], {limit: 5000, evict: false}, {}], ['feed-tagged', [], {limit: 2000, evict: true}, {windows}], ['feed-listed', [], {limit: 2000, evict: false}, {}]]) {
    const feed = h.feedOf(key, {resource}), watch = h.watch(key, {args: resource.length ? {kinds: resource} : {}});
    assert.deepEqual(Object.values((await h.read(feed, [watch], options)).seenLimits), [expected], key);
  }
});

test('a gap is kept by the longest retention of its feed\'s triggers', async t => {
  const h = rig(t, {triggers: edited('feed-logged-keys', item => { item.retention = {hours: 2}; })});
  const {feed, watch} = await h.watching('feed-logged');
  h.simulator.expireCursors();
  assert.equal(gaps(await h.read(feed, [watch]))[0].expiresAt, h.now + 7 * DAY);
});

test('a gap goes to each active subscription and each starting one past this feed, once, and no further', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced'), twin = h.watch('feed-synced', {clientId: 'client-2'}), joiner = h.watch('feed-synced', {status: 'starting', pending: [feed.id]});
  h.grant('client-2');
  h.simulator.expireCursors();
  const result = await h.read(feed, [watch, twin, joiner]);
  assert.deepEqual(gaps(result).map(row => row.subscriptionId).sort(), [watch.id, twin.id].sort());
  assert.deepEqual(gaps(result).map(row => row.clientId).sort(), ['client-1', 'client-2']);
});

test('an event is kept by its own trigger\'s retention, in hours too', async t => {
  const h = rig(t, {triggers: edited('feed-listed', item => { item.retention = {hours: 24}; })}), {feed, watch} = await h.watching('feed-listed');
  h.simulator.write();
  assert.equal((await h.read(feed, [watch])).events[0].expiresAt, h.now + DAY);
});

// ---- the run ----------------------------------------------------------------------------------------------------------------------------------
test('every poll returns the same plain shape, and its run counts each subscription\'s events', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced');
  h.simulator.seed(3);
  const result = await h.read(feed, [watch]);
  assert.deepEqual(Object.keys(result).sort(), ['baselined', 'budgetStops', 'cursors', 'draining', 'events', 'floor', 'lastGoodAt', 'lensPauses', 'notBefore', 'outcome', 'page', 'reachedEdge', 'recordFailures', 'run', 'seen', 'seenLimits']);
  assert.deepEqual(result.run, {at: h.now, outcome: 'done', status: 200, requests: 1, items: 3, skipped: 0, events: {[watch.id]: 3}});
  assert.equal(JSON.stringify(JSON.parse(JSON.stringify(result))), JSON.stringify(result));
  h.simulator.fail('GET /feed', {status: 500, data: null});
  assert.deepEqual(Object.keys(await h.read(feed, [watch])).sort(), ['baselined', 'budgetStops', 'cursors', 'draining', 'events', 'floor', 'lastGoodAt', 'lensPauses', 'notBefore', 'outcome', 'page', 'reachedEdge', 'recordFailures', 'run', 'seen', 'seenLimits']);
});

test('GitHub\'s remaining count comes back, so the scheduler can hold the rule of 500', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-listed');
  h.simulator.fail('GET /feed', {status: 200, headers: {'x-ratelimit-remaining': '12', 'x-ratelimit-reset': '1800000000'}, data: {items: []}});
  assert.deepEqual((await h.read(feed, [watch])).rate, {remaining: 12, resetAt: 1_800_000_000_000});
  h.simulator.fail('GET /feed', {status: 200, headers: {'x-ratelimit-remaining': 'many'}, data: {items: []}});
  assert.equal((await h.read(feed, [watch])).rate, undefined);
});

test('a poll leaves its feed and subscriptions untouched, and writes no document', async t => {
  const h = rig(t), {feed, watch} = await h.watching('feed-synced'), copy = structuredClone(feed), sub = structuredClone(watch), writes = [], put = h.store.put.bind(h.store);
  h.store.put = (...args) => { writes.push(args[0]); return put(...args); };
  h.simulator.write();
  await h.read(feed, [watch]);
  assert.deepEqual(feed, copy);
  assert.deepEqual(watch, sub);
  assert.deepEqual(writes, []);
});

test('a poll runs on a designated store too', async t => {
  const h = rig(t, {designated: true}), {feed, watch} = await h.watching('feed-listed');
  h.simulator.write();
  assert.equal(fired(await h.poll(feed, [watch])).length, 1);
});

// ---- normalizeArgs ------------------------------------------------------------------------------------------------------------------------------
const NOTION = '1429989f-e8ac-4eff-bc8f-57f56486db54', LINK = 'https://www.notion.so/My-Page-1429989fe8ac4effbc8f57f56486db54', PLAIN = '1429989fe8ac4effbc8f57f56486db54';
const notionEntry = resource => ({id: 'notion.trigger.x.v1.aaaaaaaaaaaaaaaaaaaaaaaa', trigger: {resource}});

test('normalizeArgs: a Notion link, a dashed id and a plain id give one value, and a repeated resource value goes', () => {
  assert.deepEqual(normalizeArgs(notionEntry({each: '/pages', as: 'page'}), {pages: [LINK, NOTION, PLAIN]}, TRANSFORMS), {pages: [NOTION]});
  assert.deepEqual(normalizeArgs(notionEntry(['dataSourceId']), {dataSourceId: LINK}, TRANSFORMS), {dataSourceId: NOTION});
});

test('normalizeArgs: any other app keeps its values, and only repeats go', () => {
  const entry = {id: 'slack.trigger.x.v1.aaaaaaaaaaaaaaaaaaaaaaaa', trigger: {resource: {each: '/threads', as: 'thread'}}};
  const same = {channel: 'C1', ts: '1.000001'}, args = {threads: [same, {ts: '1.000001', channel: 'C1'}, {channel: 'C2', ts: '1.000001'}]};
  assert.deepEqual(normalizeArgs(entry, args, TRANSFORMS), {threads: [same, {channel: 'C2', ts: '1.000001'}]});
  assert.equal(args.threads.length, 3, 'the input is not changed');
  assert.deepEqual(normalizeArgs({id: 'gmail.trigger.x.v1.a', trigger: {resource: ['search']}}, {search: {words: 'x'}}, TRANSFORMS), {search: {words: 'x'}});
});

test('normalizeArgs: a value that is no Notion id refuses with its own code', () => {
  assert.throws(() => normalizeArgs(notionEntry(['dataSourceId']), {dataSourceId: 'https://example.com/x'}, TRANSFORMS), error => error.code === 'action_refused' && error.details.reason === 'notion_id_invalid');
});

test('the catalog carries runPoll and normalizeArgs, and lib/trigger-runtime.mjs stays inside the wall', t => {
  const h = rig(t);
  assert.deepEqual(h.catalog.normalizeArgs(h.entryOf('feed-updated'), {kinds: ['note', 'note', 'task']}), {kinds: ['note', 'task']});
  assert.equal(typeof h.catalog.runPoll, 'function');
  const text = readFileSync(new URL('../lib/action-catalog.mjs', import.meta.url), 'utf8');
  assert.match(text, /from '\.\/trigger-runtime\.mjs'/);
});

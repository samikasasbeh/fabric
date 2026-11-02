import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../lib/store.mjs';
import {LocalRepository} from '../lib/repositories/local.mts';
import {TenantRepository} from '../lib/repositories/tenant.mts';
import {ConnectionManager} from '../lib/connections.mjs';
import {forgetTriggers} from '../lib/trigger-data.mjs';
import {createApp} from '../server.mjs';

// Iteration 9, part 1a (docs/I07-BUILD-MAP.md section 2.1): the three trigger tables beside `documents`. A store nobody subscribes on keeps
// its single table, a replayed poll stores nothing twice and uses no number, and each client reads its own contiguous sequence by primary key.
const DAY = 86_400_000, NOW = Date.UTC(2026, 9, 31, 12);
const hash = text => createHash('sha256').update(text).digest('hex');
const range = (count, from = 1) => Array.from({length: count}, (_, index) => from + index);
const TOPOLOGY = ['documents', 'trigger_events', 'trigger_seen', 'trigger_sequences'];

function fixture(t, options = {}) {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'fabric-trigger-store-'));
  const rig = {dataDir, now: NOW, advance(ms) { rig.now += ms; }, open(extra = {}) { rig.store = new Store({dataDir, clock: () => rig.now, ...options, ...extra}); return rig.store; }};
  rig.open();
  t.after(() => { try { rig.store.close(); } catch { /* a test closed it */ } rmSync(dataDir, {recursive: true, force: true}); });
  return rig;
}
const tables = store => store.db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all().map(row => row.name);
const event = (n, overrides = {}) => ({clientId: 'client-a', subscriptionId: 'sub-1', dedupeKey: `key-${n}`, connectionId: 'account-1', userRecordId: null, kind: 'trigger.event',
  createdAt: NOW, expiresAt: NOW + 7 * DAY, payload: {type: 'trigger.event', id: String(n)}, ...overrides});
const seen = (n, overrides = {}) => ({lens: 'lens-1', itemKey: hash(`item-${n}`), valueHash: hash(`value-${n}`), generation: 1, connectionId: 'account-1', ...overrides});
const sequences = (store, client = 'client-a') => store.listEvents(client, 0, 5000).map(row => row.sequence);

test('a store nobody subscribes on keeps its single table: no read, delete or sweep makes one, and the first write makes all three', t => {
  const {store} = fixture(t);
  assert.deepEqual(store.seenRows('feed', 'lens-1', [hash('item-1')]), new Map());
  assert.deepEqual(store.listEvents('client-a', 0, 10), []);
  assert.equal(store.latestSequence('client-a'), 0);
  assert.equal(store.deleteSubscriptionEvents('sub-1'), 0);
  assert.equal(store.deleteConnectionTriggerData('account-1'), 0);
  assert.equal(store.deleteFeedSeen('feed'), 0);
  assert.equal(store.deleteLensSeen('feed', 'lens-1'), 0);
  assert.equal(store.sweepEvents(NOW + 30 * DAY), 0);
  assert.deepEqual(tables(store), ['documents'], 'every read and delete above answered empty');
  store.appendPoll({feedId: 'feed', seen: [seen(1)], events: [event(1)]});
  assert.deepEqual(tables(store), TOPOLOGY);
  assert.deepEqual(store.db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL AND name LIKE 'trigger_%' ORDER BY name").all().map(row => row.name),
    ['trigger_events_connection', 'trigger_events_expiry', 'trigger_seen_age', 'trigger_seen_connection']);
});

test('a read made before the tables exist does not stop this handle seeing them once another handle writes', t => {
  const rig = fixture(t), first = rig.store;
  assert.deepEqual(first.listEvents('client-a', 0, 10), [], 'no tables yet');
  const second = new Store({dataDir: rig.dataDir, clock: () => rig.now});
  t.after(() => second.close());
  second.appendPoll({feedId: 'feed', events: [event(1)]});
  assert.deepEqual(sequences(first), [1]);
  assert.equal(first.deleteSubscriptionEvents('sub-1'), 1, 'and a delete reaches them');
});

test('the tables and their indexes land together: a create that stops part way leaves none of them, and the next write makes them all', t => {
  const {store} = fixture(t), poll = {feedId: 'feed', seen: [seen(1)], events: [event(1)]}, blocker = 'trigger_seen_connection';
  const indexes = () => store.db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL AND name LIKE 'trigger_%' ORDER BY name").all().map(row => row.name);
  // The last statement of the create fails on a name already taken, as a full disk or a crash stops it. Three tables standing would read as done for good.
  store.db.exec(`CREATE TABLE ${blocker} (blocker TEXT)`);
  assert.throws(() => store.appendPoll(poll), /already a table named trigger_seen_connection/);
  assert.equal(store.db.isTransaction, false);
  assert.deepEqual(tables(store), ['documents', blocker], 'no table stands without its indexes');
  assert.deepEqual(indexes(store), []);
  assert.deepEqual(store.listEvents('client-a', 0, 10), [], 'and reads still answer empty');
  store.db.exec(`DROP TABLE ${blocker}`);
  store.appendPoll(poll);
  assert.deepEqual(tables(store), TOPOLOGY);
  assert.deepEqual(indexes(store), ['trigger_events_connection', 'trigger_events_expiry', 'trigger_seen_age', 'trigger_seen_connection']);
});

test('500 events and seen rows stored twice add nothing the second time and use no sequence: a replay finds them all', t => {
  const {store} = fixture(t);
  const poll = {feedId: 'feed', seen: range(500).map(n => seen(n)), events: range(500).map(n => event(n))};
  assert.deepEqual(store.appendPoll(poll), {added: {'client-a': 500}, overLimit: []});
  assert.equal(store.latestSequence('client-a'), 500);
  assert.deepEqual(store.appendPoll(poll), {added: {}, overLimit: []}, 'the same poll again stores nothing and does not throw');
  assert.equal(store.latestSequence('client-a'), 500, 'no number was used');
  store.appendPoll({feedId: 'feed', events: [event(501)]});
  assert.deepEqual(sequences(store), range(501), 'the next new event takes the very next number');
});

test('a gap stored again with a later end takes a new number in place of the first, so an agent that read the first still hears, and the same gap twice stays one', t => {
  const {store} = fixture(t), gap = to => event(1, {kind: 'trigger.gap', dedupeKey: 'gap|resync|from', payload: {type: 'trigger.gap', id: 'gap|resync|from', fields: {to}}});
  assert.deepEqual(store.appendPoll({feedId: 'feed', events: [gap('first')]}).added, {'client-a': 1});
  assert.deepEqual(store.appendPoll({feedId: 'feed', events: [gap('first')]}).added, {}, 'an exact replay stores nothing and uses no number');
  store.appendPoll({feedId: 'feed', events: [event(2)]});
  assert.deepEqual(store.appendPoll({feedId: 'feed', events: [gap('later')]}).added, {'client-a': 1});
  assert.deepEqual(store.listEvents('client-a', 0, 10).map(row => [row.sequence, row.kind, row.payload.fields?.to]), [[2, 'trigger.event', undefined], [3, 'trigger.gap', 'later']], 'one row, and past the number an agent already read');
  assert.equal(store.latestSequence('client-a'), 3);
});

test('an event stored again with other bytes stays as it was: only a gap moves, since its end is the one thing a replay can learn', t => {
  const {store} = fixture(t);
  store.appendPoll({feedId: 'feed', events: [event(1)]});
  assert.deepEqual(store.appendPoll({feedId: 'feed', events: [event(1, {payload: {type: 'trigger.event', id: 'other'}})]}).added, {});
  assert.deepEqual(store.listEvents('client-a', 0, 10).map(row => [row.sequence, row.payload.id]), [[1, '1']]);
});

test('sequences are per client and contiguous, and no prune, sweep or erase ever gives a number back', t => {
  const {store} = fixture(t), other = {clientId: 'client-b', subscriptionId: 'sub-2', connectionId: 'account-2'};
  assert.deepEqual(store.appendPoll({feedId: 'feed', events: [event(1), event(1, other), event(2), event(2, other), event(3)]}).added, {'client-a': 3, 'client-b': 2});
  assert.deepEqual(sequences(store), [1, 2, 3], 'one client\'s numbers have no gap that another client\'s event made');
  assert.deepEqual(sequences(store, 'client-b'), [1, 2]);
  // A prune: 1,002 more on a subscription of its own.
  store.appendPoll({feedId: 'feed', events: range(1002, 4).map(n => event(n, {subscriptionId: 'sub-3'}))});
  assert.equal(store.latestSequence('client-a'), 1005);
  assert.deepEqual(sequences(store).slice(0, 4), [1, 2, 3, 6], 'sub-3 lost its two oldest; the holes count what was trimmed');
  store.appendPoll({feedId: 'feed', events: [event(9000, {subscriptionId: 'sub-3'})]});
  assert.equal(store.latestSequence('client-a'), 1006, 'the counter survives the prune');
  // A sweep and an erase take every row of a client: its counter stays, or an agent reading after 2 would miss what comes next.
  store.sweepEvents(NOW + 30 * DAY);
  assert.deepEqual([store.listEvents('client-b', 0, 10), store.latestSequence('client-b')], [[], 2]);
  store.appendPoll({feedId: 'feed', events: [event(3, {...other, expiresAt: NOW + 40 * DAY})]});
  assert.deepEqual(sequences(store, 'client-b'), [3]);
  store.deleteConnectionTriggerData('account-2');
  store.appendPoll({feedId: 'feed', events: [event(4, {...other, expiresAt: NOW + 40 * DAY})]});
  assert.deepEqual(sequences(store, 'client-b'), [4]);
  assert.equal(store.latestSequence('client-b'), 4);
});

test('appendPoll inside a caller\'s transaction refuses, and makes no table in it', t => {
  const {store} = fixture(t);
  store.db.exec('BEGIN');
  assert.throws(() => store.appendPoll({feedId: 'feed', seen: [seen(1)], events: [event(1)]}), /own transaction/);
  store.db.exec('ROLLBACK');
  assert.deepEqual(tables(store), ['documents']);
  store.appendPoll({feedId: 'feed', seen: [seen(1)], events: [event(1)]});
  assert.deepEqual(sequences(store), [1], 'the store still works once that transaction ends');
});

test('a subscription keeps its newest 1,000 events and no more; another subscription of the client keeps its own', t => {
  const {store} = fixture(t);
  assert.deepEqual(store.appendPoll({feedId: 'feed', events: range(1200).map(n => event(n))}).added, {'client-a': 1200}, 'added counts what went in');
  assert.deepEqual(sequences(store), range(1000, 201), 'the newest thousand');
  store.appendPoll({feedId: 'feed', events: [event(5000, {subscriptionId: 'sub-2'}), event(1201)]});
  assert.deepEqual(sequences(store).slice(0, 2), [202, 203], 'one new event moves its own subscription\'s window by one');
  assert.equal(store.listEvents('client-a', 0, 5000).filter(row => row.subscriptionId === 'sub-2').length, 1);
});

test('one event is at most 8,192 bytes as stored; past that the whole poll refuses and nothing lands', t => {
  const {store} = fixture(t);
  assert.deepEqual(store.appendPoll({feedId: 'feed', events: [event(1, {payload: 'x'.repeat(8190)})]}).added, {'client-a': 1}, 'exactly 8,192 bytes with its quotes');
  for (const payload of ['x'.repeat(8191), 'x'.repeat(9000), 'é'.repeat(4096)]) {
    assert.throws(() => store.appendPoll({feedId: 'feed', seen: [seen(2)], events: [event(2), event(3, {payload})]}), /8,192 bytes/);
  }
  assert.equal(store.latestSequence('client-a'), 1, 'no event of a refused poll landed');
  assert.deepEqual(store.seenRows('feed', 'lens-1', [hash('item-2')]), new Map(), 'and no seen row');
  assert.throws(() => store.appendPoll({feedId: 'feed', events: [event(4, {payload: undefined})]}), /8,192 bytes/, 'an event always has a payload');
});

test('an event with a field missing refuses: INSERT OR IGNORE would have skipped it as quietly as a duplicate', t => {
  const {store} = fixture(t);
  for (const bad of [{kind: null}, {connectionId: undefined}, {dedupeKey: ''}, {subscriptionId: 7}, {clientId: null}, {createdAt: 'soon'}, {expiresAt: null}, {itemTime: 'yesterday'}, {itemTime: Number.NaN}]) {
    assert.throws(() => store.appendPoll({feedId: 'feed', events: [event(1, bad)]}), /trigger event/, JSON.stringify(bad));
  }
  assert.throws(() => store.appendPoll({seen: [seen(1)]}), /names its feed/);
  assert.throws(() => store.appendPoll({feedId: 'feed', seenLimits: {'lens-1': {limit: 0, evict: true}}}), /seen limit/);
  assert.throws(() => store.appendPoll({feedId: 'feed', seenLimits: {'lens-1': {limit: 10}}}), /seen limit/);
  assert.equal(store.latestSequence('client-a'), 0);
});

test('20,000 events read through the primary key, with no sort and no scan (critique test 14)', t => {
  const {store} = fixture(t), asked = [], prepare = store.db.prepare;
  store.db.prepare = function (text) { asked.push(text); return prepare.call(this, text); };
  for (const part of range(20)) store.appendPoll({feedId: 'feed', events: range(1000).map(n => event(n, {subscriptionId: `sub-${part}`}))});
  assert.equal(store.latestSequence('client-a'), 20_000);
  assert.deepEqual(store.listEvents('client-a', 19_900, 100).map(row => row.sequence), range(100, 19_901));
  const page = asked.filter(text => /FROM trigger_events WHERE client_id=\?/.test(text));
  assert.equal(page.length, 1, 'one query reads a page');
  assert.deepEqual(store.db.prepare(`EXPLAIN QUERY PLAN ${page[0]}`).all('client-a', 19_900, NOW, 100).map(row => row.detail),
    ['SEARCH trigger_events USING INDEX sqlite_autoindex_trigger_events_1 (client_id=? AND seq>?)']);
});

test('a page answers in sequence from `after`, holds what an event was given, and leaves out what has expired before any sweep', t => {
  const rig = fixture(t), {store} = rig;
  store.appendPoll({feedId: 'feed', events: [event(1, {userRecordId: 'usr_1'}), event(2, {expiresAt: NOW + DAY}), event(3)]});
  assert.deepEqual(store.listEvents('client-a', 0, 1), [{sequence: 1, subscriptionId: 'sub-1', dedupeKey: 'key-1', connectionId: 'account-1', userRecordId: 'usr_1', kind: 'trigger.event',
    createdAt: NOW, expiresAt: NOW + 7 * DAY, payload: {type: 'trigger.event', id: '1'}}]);
  assert.deepEqual(store.listEvents('client-a', 1, 10).map(row => row.sequence), [2, 3]);
  assert.deepEqual(store.listEvents('client-a', 3, 10), []);
  assert.deepEqual(store.listEvents('client-b', 0, 10), [], 'another client\'s page');
  rig.advance(DAY - 1);
  assert.deepEqual(sequences(store), [1, 2, 3]);
  rig.advance(1);
  assert.deepEqual(sequences(store), [1, 3], 'hidden the moment it expires, as a proxied body is');
  for (const [after, limit] of [[-1, 10], [0, 0], [0, -1], ['0', 10], [0, 1.5]]) assert.throws(() => store.listEvents('client-a', after, limit), /page/);
});

test('sweepEvents takes what has expired and nothing else, on a plain store and on one with no table', t => {
  const {store} = fixture(t);
  assert.equal(store.sweepEvents(NOW), 0);
  store.appendPoll({feedId: 'feed', seen: [seen(1)], events: [event(1, {expiresAt: NOW + DAY}), event(2, {expiresAt: NOW + 7 * DAY})]});
  assert.equal(store.sweepEvents(NOW + DAY - 1), 0);
  assert.equal(store.sweepEvents(NOW + DAY), 1, 'gone at the moment it expires');
  assert.equal(store.db.prepare('SELECT count(*) AS count FROM trigger_events').get().count, 1);
  assert.equal(store.seenRows('feed', 'lens-1', [hash('item-1')]).size, 1, 'a seen key outlasts its event, or a swept item would fire again');
});

test('a designated store stays valid with the tables in it and reopens with require', t => {
  const rig = fixture(t, {localAuthority: 'new'}), connection = {id: 'account-1', appId: 'gmail', driver: 'http', status: 'ready', identity: {id: 'one'}};
  rig.store.put('connections', connection);
  rig.store.appendPoll({feedId: 'feed', seen: [seen(1)], events: [event(1)]});
  assert.equal(rig.store.connectionGeneration('account-1'), 1, 'the authority ledger is not disturbed');
  rig.store.close();
  const reopened = rig.open({localAuthority: 'require'});
  assert.equal(reopened.connectionGeneration('account-1'), 1);
  assert.deepEqual(sequences(reopened), [1]);
  assert.deepEqual(tables(reopened), [...TOPOLOGY, '_fabric_local_authority_counters', '_fabric_local_authority_meta'].sort());
  reopened.put('connections', {...connection, identity: {id: 'two'}});
  assert.equal(reopened.connectionGeneration('account-1'), 2, 'and it still counts changes');
});

test('events and seen rows roll back together: a failed seen row leaves no event and uses no number', t => {
  const {store} = fixture(t), poll = bad => ({feedId: 'feed', seen: [seen(1), seen(2, bad)], events: [event(1), event(2)]});
  assert.throws(() => store.appendPoll(poll({valueHash: null})), /NOT NULL/);
  assert.equal(store.db.isTransaction, false);
  assert.deepEqual(store.listEvents('client-a', 0, 10), []);
  assert.equal(store.latestSequence('client-a'), 0);
  assert.deepEqual(store.seenRows('feed', 'lens-1', [hash('item-1'), hash('item-2')]), new Map());
  assert.deepEqual(store.appendPoll(poll({})).added, {'client-a': 2}, 'the store works on');
  assert.equal(store.seenRows('feed', 'lens-1', [hash('item-1'), hash('item-2')]).size, 2);
});

test('a poll\'s `desc` events take ascending sequences; events with no time keep their order, after the timed ones', t => {
  const {store} = fixture(t);
  store.appendPoll({feedId: 'feed', events: [event('new', {itemTime: 300}), event('middle', {itemTime: 200}), event('old', {itemTime: 100}), event('twin', {itemTime: 200})]});
  assert.deepEqual(store.listEvents('client-a', 0, 10).map(row => row.dedupeKey), ['key-old', 'key-middle', 'key-twin', 'key-new'], 'an equal time keeps the order it came in');
  store.appendPoll({feedId: 'feed', events: [event('first'), event('timed', {itemTime: 1}), event('second')]});
  assert.deepEqual(store.listEvents('client-a', 4, 10).map(row => row.dedupeKey), ['key-timed', 'key-first', 'key-second']);
});

test('seen rows hold the latest value and generation under the key they were given, and answer only for their feed and lens', t => {
  const {store} = fixture(t), key = hash('item-1');
  store.appendPoll({feedId: 'feed', seen: [seen(1)]});
  assert.deepEqual([...store.seenRows('feed', 'lens-1', [key, hash('never')])], [[key, {valueHash: hash('value-1'), generation: 1}]], 'a key with no row is not in the answer');
  store.appendPoll({feedId: 'feed', seen: [seen(1, {valueHash: hash('value-2'), generation: 2})]});
  assert.deepEqual(store.seenRows('feed', 'lens-1', [key]).get(key), {valueHash: hash('value-2'), generation: 2}, 'the latest, never a set: A to B to A must fire twice');
  assert.equal(store.seenRows('feed', 'lens-2', [key]).size, 0);
  assert.equal(store.seenRows('feed-2', 'lens-1', [key]).size, 0);
  assert.deepEqual(store.db.prepare('SELECT item_key, value_hash FROM trigger_seen').all().map(row => ({...row})), [{item_key: key, value_hash: hash('value-2')}], 'only hashes reach the table');
});

test('past a lens\'s limit the oldest rows go when evict is true, and the lens is reported, rows kept, when it is false', t => {
  const rig = fixture(t), {store} = rig, keys = numbers => numbers.map(n => hash(`item-${n}`));
  const within = {'lens-1': {limit: 3, evict: true}};
  store.appendPoll({feedId: 'feed', seen: [seen(1), seen(2)], seenLimits: within});
  rig.advance(1000);
  store.appendPoll({feedId: 'feed', seen: [seen(3)], seenLimits: within});
  rig.advance(1000);
  store.appendPoll({feedId: 'feed', seen: [seen(1)], seenLimits: within});
  rig.advance(1000);
  assert.deepEqual(store.appendPoll({feedId: 'feed', seen: [seen(4), seen(5)], seenLimits: within}).overLimit, [], 'an eviction is silent');
  assert.deepEqual([...store.seenRows('feed', 'lens-1', keys([1, 2, 3, 4, 5])).keys()].sort(), keys([1, 4, 5]).sort(), 'item 1 was seen again, so it is not among the oldest');
  const held = {'lens-2': {limit: 2, evict: false}};
  const second = n => seen(n, {lens: 'lens-2'});
  assert.deepEqual(store.appendPoll({feedId: 'feed', seen: [second(1), second(2)], seenLimits: held}).overLimit, [], 'at the limit is not past it');
  assert.deepEqual(store.appendPoll({feedId: 'feed', seen: [second(3)], seenLimits: held}).overLimit, [{lens: 'lens-2', count: 3}]);
  assert.equal(store.seenRows('feed', 'lens-2', keys([1, 2, 3])).size, 3, 'nothing is dropped: past the limit new cannot be told from changed, so the engine pauses');
  assert.deepEqual(store.appendPoll({feedId: 'feed', seenLimits: held}).overLimit, [{lens: 'lens-2', count: 3}], 'a replay with no new row still reports it');
  assert.equal(store.seenRows('feed', 'lens-1', keys([1, 4, 5])).size, 3, 'one lens\'s limit is its own');
});

test('each delete takes its own rows and no others', t => {
  const {store} = fixture(t), mark = (feed, lens, connectionId) => seen(`${feed}-${lens}-${connectionId}`, {lens, connectionId});
  const poll = (feedId, lens, connectionId, subscriptionId) => store.appendPoll({feedId, seen: [mark(feedId, lens, connectionId)], events: [event(`${feedId}-${lens}`, {connectionId, subscriptionId})]});
  poll('feed-1', 'lens-1', 'account-1', 'sub-1');
  poll('feed-1', 'lens-2', 'account-1', 'sub-2');
  poll('feed-2', 'lens-1', 'account-1', 'sub-3');
  poll('feed-3', 'lens-1', 'account-2', 'sub-4');
  const left = (query, name) => store.db.prepare(query).all().map(row => row[name]).sort();
  const subscriptions = () => left('SELECT subscription_id FROM trigger_events', 'subscription_id'), lenses = () => left("SELECT feed_id || '/' || lens AS row FROM trigger_seen", 'row');
  assert.equal(store.deleteSubscriptionEvents('sub-2'), 1);
  assert.deepEqual(subscriptions(), ['sub-1', 'sub-3', 'sub-4']);
  assert.equal(lenses().length, 4, 'a subscription\'s events go, not the keys its lens still needs');
  assert.equal(store.deleteLensSeen('feed-1', 'lens-2'), 1);
  assert.deepEqual(lenses(), ['feed-1/lens-1', 'feed-2/lens-1', 'feed-3/lens-1']);
  assert.equal(store.deleteFeedSeen('feed-2'), 1);
  assert.deepEqual(lenses(), ['feed-1/lens-1', 'feed-3/lens-1']);
  assert.deepEqual(subscriptions(), ['sub-1', 'sub-3', 'sub-4'], 'a feed\'s seen rows go, not events gathered from it');
  assert.equal(store.deleteConnectionTriggerData('account-1'), 3, 'its two events and its seen row');
  assert.deepEqual(subscriptions(), ['sub-4']);
  assert.deepEqual(lenses(), ['feed-3/lens-1']);
});

test('the repositories: a local one delegates every member and a tenant one only its erase and its sweep; a store without them answers empty', t => {
  const {store} = fixture(t), repository = new LocalRepository({store});
  assert.deepEqual(repository.appendPoll({feedId: 'feed', seen: [seen(1)], events: [event(1), event(2, {connectionId: 'account-2', subscriptionId: 'sub-2'})]}).added, {'client-a': 2});
  assert.equal(repository.seenRows('feed', 'lens-1', [hash('item-1')]).size, 1);
  assert.deepEqual(repository.listEvents('client-a', 0, 10).map(row => row.sequence), [1, 2]);
  assert.equal(repository.latestSequence('client-a'), 2);
  assert.equal(repository.deleteSubscriptionEvents('sub-1'), 1);
  assert.equal(repository.deleteLensSeen('feed', 'lens-1'), 1);
  assert.equal(repository.deleteFeedSeen('feed'), 0);
  assert.equal(repository.sweepEvents(NOW + 8 * DAY), 1);
  assert.equal(repository.deleteConnectionTriggerData('account-2'), 0);
  assert.equal(repository.guarantees.transactions, false, 'no general transaction API');
  const bare = new LocalRepository({store: {get: () => null, list: () => []}});
  assert.throws(() => bare.appendPoll({feedId: 'feed'}), error => error.code === 'unsupported_repository_operation');
  assert.deepEqual([bare.seenRows('feed', 'lens-1', ['key']).size, bare.listEvents('client-a', 0, 10), bare.latestSequence('client-a'), bare.deleteSubscriptionEvents('sub-1'),
    bare.deleteConnectionTriggerData('account-1'), bare.deleteFeedSeen('feed'), bare.deleteLensSeen('feed', 'lens-1'), bare.sweepEvents(NOW)], [0, [], 0, 0, 0, 0, 0, 0]);
  const tenant = inner => new TenantRepository({store: inner, scope: {schemaVersion: 1, kind: 'tenant', organizationId: 'org', projectId: 'project', environmentId: 'env'}});
  const environment = tenant(store);
  store.appendPoll({feedId: 'feed', seen: [seen(2)], events: [event(3, {expiresAt: NOW - 1}), event(4)]});
  assert.equal(environment.sweepEvents(NOW), 1);
  assert.equal(environment.deleteConnectionTriggerData('account-1'), 2);
  for (const member of ['appendPoll', 'seenRows', 'listEvents', 'latestSequence', 'deleteSubscriptionEvents', 'deleteFeedSeen', 'deleteLensSeen']) assert.equal(environment[member], undefined, `${member}: tenant polling waits for hosting`);
  assert.deepEqual([tenant({}).deleteConnectionTriggerData('account-1'), tenant({}).sweepEvents(NOW)], [0, 0]);
});

test('the owner\'s store overwrites what it deletes: a swept event leaves no bytes in the file', async t => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'fabric-trigger-secure-'));
  t.after(() => rmSync(dataDir, {recursive: true, force: true}));
  const app = await createApp({dataDir, port: 0, clock: () => NOW}), marker = `[SYNTHETIC] event text ${hash('marker')}`, file = path.join(dataDir, 'fabric.sqlite');
  app.store.appendPoll({feedId: 'feed', events: [event(1, {payload: {summary: marker}, expiresAt: NOW + 1})]});
  assert.equal(readFileSync(file).includes(marker), true, 'the event is in the file until it expires');
  assert.equal(app.store.sweepEvents(NOW + 1), 1);
  await app.close();
  assert.equal(readFileSync(file).includes(marker), false);
});

// Part 1b: a disconnect pauses the watches on the account and erases what they gathered. The account's feeds, runs, seen rows and events go, so
// the app page's "Fabric no longer holds this account's access" stays true.
const subscription = (id, status, connectionId = 'account-1') => ({id, clientId: 'client-a', appId: 'github', connectionId, status, revision: 1, createdAt: 'then', updatedAt: 'then'});
function disconnected(t) {
  const rig = fixture(t), repository = new LocalRepository({store: rig.store});
  const account = (id, appId = 'github') => repository.put('connections', {id, appId, driver: 'http', authMethod: 'token', status: 'ready', identity: {id}, allowedOrigins: ['https://api.github.com']});
  account('account-1'); account('account-2');
  const manager = new ConnectionManager({store: repository, vault: {delete() {}, get: () => null}, clock: () => rig.now});
  return {rig, repository, manager};
}
const count = (store, table) => store.db.prepare(`SELECT count(*) AS count FROM ${table}`).get().count;
function gathered(repository, connectionId, n, subscriptionId) {
  repository.put('triggerFeeds', {id: `feed-${n}`, connectionId, cursors: {sync: 'a value only a provider gave'}});
  repository.put('triggerRuns', {id: `feed-${n}`, connectionId, runs: [{at: 'then', outcome: 'ok'}]});
  repository.appendPoll({feedId: `feed-${n}`, seen: [seen(n, {connectionId})], events: [event(n, {connectionId, subscriptionId})]});
}

test('disconnect pauses what waits on or reads the account, leaves the rest as they are, and deletes its feeds, runs, seen rows and events', t => {
  const {rig, repository, manager} = disconnected(t), {store} = rig;
  const open = ['awaiting_approval', 'starting', 'active'], closed = ['paused', 'declined', 'expired', 'removed'];
  for (const status of [...open, ...closed]) repository.put('subscriptions', subscription(`on-${status}`, status));
  repository.put('subscriptions', subscription('other', 'active', 'account-2'));
  const before = closed.map(status => repository.get('subscriptions', `on-${status}`)), other = repository.get('subscriptions', 'other');
  gathered(repository, 'account-1', 1, 'on-active');
  gathered(repository, 'account-2', 2, 'other');
  rig.advance(5000);
  assert.equal(manager.revoke('account-1').status, 'revoked');
  for (const status of open) {
    const {status: now, reason, revision, pausedAt, updatedAt} = repository.get('subscriptions', `on-${status}`), at = new Date(rig.now).toISOString();
    assert.deepEqual({now, reason, revision, pausedAt, updatedAt}, {now: 'paused', reason: 'account_changed', revision: 2, pausedAt: at, updatedAt: at}, status);
  }
  assert.deepEqual(closed.map(status => repository.get('subscriptions', `on-${status}`)), before, 'a watch already stopped keeps its own reason: a Resume must not read a paused one as a disconnect');
  assert.deepEqual(repository.get('subscriptions', 'other'), other, 'another account\'s watch is not touched');
  assert.deepEqual([repository.list('triggerFeeds').map(row => row.id), repository.list('triggerRuns').map(row => row.id)], [['feed-2'], ['feed-2']], 'cursors go with the feed');
  assert.deepEqual([count(store, 'trigger_seen'), count(store, 'trigger_events')], [1, 1], 'only the other account\'s rows are left');
  assert.deepEqual(store.db.prepare('SELECT DISTINCT connection_id FROM trigger_seen UNION SELECT DISTINCT connection_id FROM trigger_events').all().map(row => row.connection_id), ['account-2']);
  assert.equal(store.latestSequence('client-a'), 2, 'the numbers stay, so an agent reading after them misses nothing later');
});

test('a disconnect keeps the first paused time of a watch still catching up, and says when each watch last heard everything', t => {
  const {rig, repository, manager} = disconnected(t), at = new Date(rig.now).toISOString();
  repository.put('subscriptions', {...subscription('catching-up', 'starting'), pausedAt: 'the first pause', heardTo: 5, feeds: ['feed-1']});
  repository.put('subscriptions', {...subscription('reading', 'active'), feeds: ['feed-1', 'feed-2']});
  repository.put('subscriptions', {...subscription('new', 'starting'), feeds: ['feed-3']});
  repository.put('triggerFeeds', {id: 'feed-1', connectionId: 'account-1', readAt: 7000});
  repository.put('triggerFeeds', {id: 'feed-2', connectionId: 'account-1', readAt: 9000});
  repository.put('triggerFeeds', {id: 'feed-3', connectionId: 'account-1'});
  manager.revoke('account-1');
  const fields = id => { const {pausedAt, heardTo} = repository.get('subscriptions', id); return {pausedAt, heardTo}; };
  assert.deepEqual(fields('catching-up'), {pausedAt: 'the first pause', heardTo: 5}, 'its one gap covers the whole range');
  assert.deepEqual(fields('reading'), {pausedAt: at, heardTo: 7000}, 'the feed read longest ago decides');
  assert.deepEqual(fields('new'), {pausedAt: at, heardTo: undefined}, 'a feed never read says nothing');
});

test('each pause writes one audit row with ids only, and a second disconnect pauses nothing again', t => {
  const {rig, repository} = disconnected(t);
  repository.put('subscriptions', subscription('live', 'active'));
  repository.put('subscriptions', subscription('waiting', 'awaiting_approval'));
  repository.put('subscriptions', subscription('stopped', 'removed'));
  forgetTriggers(repository, 'account-1', rig.now);
  forgetTriggers(repository, 'account-1', rig.now + 1000);
  const rows = repository.list('activity').filter(row => row.type === 'trigger.paused');
  assert.deepEqual(rows.map(({id: _id, createdAt: _at, ...row}) => row).sort((a, b) => a.subscriptionId.localeCompare(b.subscriptionId)), [
    {type: 'trigger.paused', subscriptionId: 'live', connectionId: 'account-1', appId: 'github', reason: 'account_changed'},
    {type: 'trigger.paused', subscriptionId: 'waiting', connectionId: 'account-1', appId: 'github', reason: 'account_changed'}]);
  assert.equal(repository.get('subscriptions', 'live').revision, 2, 'the second pass found it paused and left it');
});

test('a disconnect on a store nobody subscribes on makes no table, and a store with nothing but documents passes through', t => {
  const {rig, manager} = disconnected(t);
  manager.revoke('account-1');
  assert.deepEqual(tables(rig.store), ['documents']);
  const plain = new Map();
  const bare = {list: collection => plain.get(collection) ?? [], put: (collection, row) => plain.set(collection, [row]), delete: () => true, audit: () => {}};
  plain.set('subscriptions', [subscription('live', 'active')]);
  assert.doesNotThrow(() => forgetTriggers(bare, 'account-1', NOW), 'no listWhere and no trigger tables');
  assert.equal(plain.get('subscriptions')[0].status, 'paused');
});

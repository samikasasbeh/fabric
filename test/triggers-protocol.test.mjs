import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {performance} from 'node:perf_hooks';
import {DatabaseSync} from 'node:sqlite';
import {FabricProtocol, FABRIC_PROTOCOL, protocolManifest} from '../lib/fabric-protocol.mjs';
import {SubscriptionService, approvalDigest} from '../lib/subscriptions.mjs';
import {TriggerEngine} from '../lib/trigger-engine.mjs';
import {argsHashOf, authorityOf} from '../lib/trigger-gate.mjs';
import {gapPayload} from '../lib/trigger-rules.mjs';
import {createApp} from '../server.mjs';
import {feedTriggers, triggerHarness} from './fixtures/actions/trigger-fixture.mjs';

// Iteration 9 parts 3a and 3b (docs/I07-BUILD-MAP.md step 3): the four protocol methods, each on a plain and a designated store, since a default Fabric is plain.
// Everything runs on the fixture app and its simulator, through FabricProtocol.handle(), and nothing listens on a port. Waits use real timers, so a test that
// expects a wait to end races it against a short timer of its own, and reports what it saw rather than sitting out the 25 seconds.
const ORIGIN = 'http://127.0.0.1:59994', MINUTE = 60_000, DAY = 86_400_000, INTERVAL = 150_000;
const appName = id => `${id} app`;
const both = (name, body) => { for (const designated of [false, true]) test(`${name} (${designated ? 'a designated' : 'a plain'} store)`, {timeout: 30_000}, t => body(t, designated)); };
const later = ms => new Promise(resolve => setTimeout(resolve, ms));
/** What a promise gave within this time, or 'still waiting'. The timer here holds the process open, since a wait's own timer does not. */
const within = (promise, ms = 1000) => Promise.race([promise, later(ms).then(() => 'still waiting')]);
const pending = async promise => await within(promise, 30) === 'still waiting';

/** The fixture harness with fabric/0.1 over it and the engine beside it, as server.mjs wires them. agent(name) is a client with a real token that holds the fixture account. */
function world(t, {designated = false, ...options} = {}) {
  const h = triggerHarness(t, {designated, ...options}), clock = () => h.now;
  const protocol = new FabricProtocol({store: h.store, runtime: h.runtime, clock, origin: ORIGIN, appName});
  const engine = new TriggerEngine({store: h.store, runtime: h.runtime, clock, random: () => 0});
  const subscriptions = new SubscriptionService({store: h.store, runtime: h.runtime, protocol, triggers: engine, clock, origin: ORIGIN, appName});
  protocol.subscriptions = subscriptions;
  engine.notify = clientId => subscriptions.notify(clientId);
  t.after(() => subscriptions.close());
  const agent = (name = 'Fixture agent', extra = {}) => {
    const {client, token} = protocol.createClient({name, bindings: [{connectionId: h.account, capabilityId: h.idOf('list-items v1')}], ...extra}, h.owner ?? undefined);
    return {id: client.id, client, call: (method, params = {}, id = randomUUID()) => protocol.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id, method, params})};
  };
  return {h, protocol, engine, subscriptions, agent,
    record: id => h.store.get('subscriptions', id), audits: type => h.store.list('activity').filter(row => row.type === type),
    subscribe: (who, key, args = {}, extra = {}, id) => who.call('triggers.subscribe', {triggerId: h.triggerId(key), connectionId: h.account, args, ...extra}, id)};
}
/** An active watch of this agent on a baselined feed, as an approval and a first poll leave it. */
async function running(w, who, key = 'feed-synced', args = {}) {
  const watch = w.engine.attach(w.h.watch(key, {args, status: 'starting', clientId: who.id}));
  await w.engine.pollNow(watch.id);
  assert.equal(w.record(watch.id).status, 'active');
  return w.record(watch.id);
}
/** One new item, read by the next poll. */
async function written(w, watch, name = 'New') {
  w.h.advance(INTERVAL);
  w.h.simulator.write({name});
  await w.engine.pollNow(watch.id);
}
const eventRow = (watch, n, {at, kept = DAY, kind = 'trigger.event', payload} = {}) => ({clientId: watch.clientId, subscriptionId: watch.id, dedupeKey: `key-${randomUUID()}`, connectionId: watch.connectionId, userRecordId: null, kind, createdAt: at, expiresAt: at + kept,
  payload: payload ?? {type: kind, id: `item-${n}`, occurredAt: '2026-10-23T08:00:00.000Z', fields: {id: `item-${n}`, name: `Name ${n}`}, summary: [{label: 'Item', value: `Name ${n}`}]}});
/** Stores `count` events straight in the table, as a poll would, and wakes the waits as the engine does. */
function stored(w, watch, count = 1, options = {}) {
  const {added} = w.h.store.appendPoll({feedId: 'feed', events: Array.from({length: count}, (_, n) => eventRow(watch, n + 1, {at: w.h.now, ...options}))});
  for (const client of Object.keys(added)) w.subscriptions.notify(client);
}
const page = async (who, params = {}) => { const {result, error} = await who.call('events.list', params); assert.equal(error, undefined, error?.message); return result; };
/** Everything a subscribe could leave behind. */
const counts = w => ({subscriptions: w.h.store.list('subscriptions').length, requests: w.h.store.list('protocolRequests').length, feeds: w.h.store.list('triggerFeeds').length,
  audits: w.h.store.list('activity').filter(row => row.type.startsWith('trigger.')).length});
const NOTHING = {subscriptions: 0, requests: 0, feeds: 0, audits: 0};

// ---- the manifest ----------------------------------------------------------------------------------------------------------------------------

test('the manifest lists the four new methods and says triggers poll', () => {
  assert.deepEqual(protocolManifest.methods.slice(-4), ['triggers.list', 'triggers.subscribe', 'events.list', 'triggers.unsubscribe']);
  assert.equal(protocolManifest.features.triggers, 'polling');
});

test('a Fabric with no subscription service answers method_not_found, as for any method it does not have', async t => {
  const w = world(t), who = w.agent();
  w.protocol.subscriptions = null;
  for (const method of ['triggers.list', 'triggers.subscribe', 'triggers.unsubscribe', 'events.list']) assert.equal((await who.call(method)).error.code, 'method_not_found', method);
});

// ---- triggers.list ---------------------------------------------------------------------------------------------------------------------------

both('triggers.list: one entry per active trigger, with the accounts this client holds and nothing of any account or cursor', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent();
  const {result} = await who.call('triggers.list');
  assert.equal(result.triggers.length, feedTriggers().length);
  assert.deepEqual(result.subscriptions, []);
  const item = h.itemOf('feed-updated'), {trigger} = item.entry;
  assert.deepEqual(result.triggers.find(entry => entry.id === item.entry.id), {id: item.entry.id, appId: 'fixture', name: trigger.name, description: trigger.description, inputSchema: trigger.inputSchema, eventFields: ['id', 'name'],
    intervalSeconds: 120, retention: {days: 7}, rows: ['Access items'], connectionIds: [h.account], status: 'available'});
  const text = JSON.stringify(result);
  for (const secret of ['acct-1', 'cursors', 'lenses', 'pollHash']) assert.equal(text.includes(secret), false, secret);
});

test('triggers.list: a trigger names the inputs a choice list can fill', async t => {
  const triggers = feedTriggers(), updated = triggers.find(item => item.key === 'feed-updated');
  updated.inputSchema.properties.kinds.items = {type: 'string', minLength: 1, maxLength: 20};
  updated.choices = [{input: 'kinds', source: 'labels'}];
  const w = world(t, {triggers}), {result} = await w.agent().call('triggers.list');
  assert.deepEqual(result.triggers.find(entry => entry.id === w.h.triggerId('feed-updated')).choices, [{input: 'kinds', dependsOn: []}]);
  assert.equal(Object.hasOwn(result.triggers.find(entry => entry.id === w.h.triggerId('feed-synced')), 'choices'), false);
});

both('triggers.list: a trigger this client cannot start says why, and still names its accounts', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), entryOf = async key => (await who.call('triggers.list')).result.triggers.find(entry => entry.id === w.h.triggerId(key));
  const {status, reason, connectionIds} = await entryOf('feed-logged-keys');
  assert.deepEqual([status, reason, connectionIds], ['unavailable', 'permission_changed', [w.h.account]], 'a read row at Ask cannot run in the background');
  w.h.setRow('fixture.keys.read', 'allow');
  assert.equal((await entryOf('feed-logged-keys')).status, 'available');
  assert.equal(Object.hasOwn(await entryOf('feed-logged-keys'), 'reason'), false);
  w.h.store.put('connections', {...w.h.connection(), status: 'reconnect_required'});
  assert.deepEqual([(await entryOf('feed-synced')).status, (await entryOf('feed-synced')).reason], ['unavailable', 'reconnect']);
});

both('triggers.list: an account is held through a binding or a proxy grant; with neither the trigger is still offered, as unavailable', (t, designated) => {
  const w = world(t, {designated}), {h} = w, listed = client => w.subscriptions.list(client).triggers.find(entry => entry.id === h.triggerId('feed-synced'));
  assert.deepEqual([listed({id: 'c', bindings: []}).connectionIds, listed({id: 'c', bindings: []}).status, listed({id: 'c', bindings: []}).reason], [[], 'unavailable', 'no_account']);
  assert.deepEqual(listed({id: 'c', bindings: [], proxy: [{connectionId: h.account}]}).connectionIds, [h.account]);
  assert.deepEqual(listed({id: 'c', bindings: [{connectionId: h.rpcAccount}, {connectionId: 'gone'}]}).connectionIds, [], 'an account of another app, and one that is gone');
});

both('triggers.list: two accounts of one app make one entry; it is available while one of them can start', (t, designated) => {
  const w = world(t, {designated}), {h} = w, second = {...h.connection(), id: 'second-account', status: 'reconnect_required'};
  h.store.put('connections', second);
  h.grant('both-accounts');
  const listed = w.subscriptions.list({id: 'both-accounts', bindings: [{connectionId: 'second-account'}, {connectionId: h.account}, {connectionId: h.account}]}).triggers.filter(entry => entry.id === h.triggerId('feed-synced'));
  assert.deepEqual(listed.map(entry => [entry.connectionIds, entry.status]), [[['second-account', h.account], 'available']]);
});

test('a candidate is never listed and answers as an unknown trigger; a certification Fabric offers it', async t => {
  const w = world(t, {reviewed: false}), who = w.agent();
  assert.deepEqual((await who.call('triggers.list')).result.triggers, []);
  const unknown = await who.call('triggers.subscribe', {triggerId: 'no.such.trigger', connectionId: w.h.account});
  assert.deepEqual(await w.subscribe(who, 'feed-synced').then(answer => answer.error), unknown.error);
  assert.equal(unknown.error.code, 'not_found');
  assert.deepEqual(counts(w), NOTHING);
  w.h.permissions.certification = true;
  assert.equal((await who.call('triggers.list')).result.triggers.length, feedTriggers().length);
  assert.equal((await w.subscribe(who, 'feed-synced')).result.status, 'awaiting_approval');
});

test('with no catalog nothing is listed or started, and a watch is left as it stands', async t => {
  const w = world(t), who = w.agent(), watch = await running(w, who);
  w.h.runtime.actions = null;
  assert.deepEqual((await who.call('triggers.list')).result.triggers, []);
  assert.equal((await w.subscribe(who, 'feed-listed')).error.code, 'not_found');
  assert.equal(w.record(watch.id).status, 'active', 'a local fault pauses nothing');
});

both('triggers.list shows a client its own subscriptions only', async (t, designated) => {
  const w = world(t, {designated}), mine = w.agent('Mine'), theirs = w.agent('Theirs'), {result: {id}} = await w.subscribe(theirs, 'feed-synced');
  assert.deepEqual((await mine.call('triggers.list')).result.subscriptions, []);
  assert.deepEqual((await theirs.call('triggers.list')).result.subscriptions.map(row => row.id), [id]);
});

both('triggers.list: a waiting request carries its approval link, and a listed row holds no args, cursor or digest', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), {result} = await w.subscribe(who, 'feed-updated', {kinds: ['note']}), [row] = (await who.call('triggers.list')).result.subscriptions;
  assert.deepEqual(row, {id: result.id, triggerId: h.triggerId('feed-updated'), connectionId: h.account, status: 'awaiting_approval', createdAt: result.createdAt, updatedAt: result.updatedAt, approval: result.approval, health: null});
});

// ---- health ----------------------------------------------------------------------------------------------------------------------------------

const healthOf = async (who, id) => (await who.call('triggers.list')).result.subscriptions.find(row => row.id === id).health;
const iso = time => new Date(time).toISOString();

both('health: starting, then quiet, then found with its own count, with the check times of its feed', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), first = w.engine.attach(h.watch('feed-synced', {status: 'starting', clientId: who.id}));
  assert.deepEqual(await healthOf(who, first.id), {state: 'starting', lastCheckedAt: null, nextCheckAt: iso(h.store.get('triggerFeeds', first.feeds[0]).nextPollAt)});
  await w.engine.pollNow(first.id);
  const checked = h.now, feed = h.store.get('triggerFeeds', first.feeds[0]);
  assert.deepEqual(await healthOf(who, first.id), {state: 'quiet', lastCheckedAt: iso(checked), nextCheckAt: iso(feed.nextPollAt)});
  await written(w, first);
  const after = h.store.get('triggerFeeds', first.feeds[0]);
  assert.deepEqual(await healthOf(who, first.id), {state: 'found', lastCheckedAt: iso(h.now), nextCheckAt: iso(after.nextPollAt), events: 1});
  await w.engine.pollNow(first.id);
  assert.equal((await healthOf(who, first.id)).state, 'quiet', 'a later check that found nothing');
});

both('health holds this watch\'s own count, never a feed-wide count or another watch\'s', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, a = w.agent('A'), b = w.agent('B'), mine = await running(w, a), theirs = await running(w, b);
  assert.equal(mine.feeds[0], theirs.feeds[0], 'one shared feed');
  h.store.put('triggerRuns', {id: mine.feeds[0], connectionId: h.account, runs: [{at: h.now, outcome: 'done', status: 200, requests: 1, items: 40, skipped: 5, events: {[mine.id]: 3, [theirs.id]: 7}}]});
  assert.deepEqual([(await healthOf(a, mine.id)).state, (await healthOf(a, mine.id)).events], ['found', 3], 'a run\'s skipped count is feed-wide, so it does not speak for this watch');
  assert.equal((await healthOf(b, theirs.id)).events, 7);
  const text = JSON.stringify((await a.call('triggers.list')).result.subscriptions);
  for (const other of [theirs.id, '"items"', '"skipped"']) assert.equal(text.includes(other), false, other);
});

both('health: a wait, a run of failures, a bucket and an account that must reconnect each read as their own state, in that order of weight', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who), id = watch.feeds[0], feed = () => h.store.get('triggerFeeds', id);
  const put = fields => h.store.put('triggerFeeds', {...feed(), ...fields}), clean = feed(), until = h.now + 40 * MINUTE;
  put({behind: true});
  assert.equal((await healthOf(who, watch.id)).state, 'behind');
  put({behind: false, failures: 2, nextPollAt: h.now + MINUTE});
  h.store.put('triggerRuns', {id, connectionId: h.account, runs: [{at: h.now - 1000, outcome: 'backoff', status: 503, requests: 1, items: 0, skipped: 0, events: {}, code: 'provider_unavailable'}]});
  assert.deepEqual(await healthOf(who, watch.id), {state: 'failing', lastCheckedAt: iso(h.now - 1000), nextCheckAt: iso(h.now + MINUTE), errorCode: 'provider_unavailable'});
  put({wait: {until, reason: 'rate_limited'}});
  assert.deepEqual([(await healthOf(who, watch.id)).state, (await healthOf(who, watch.id)).nextCheckAt], ['waiting', iso(until)], 'the next check is the wait\'s end, not the next due time');
  h.store.put('connections', {...h.connection(), status: 'reconnect_required'});
  assert.equal((await healthOf(who, watch.id)).state, 'reconnect');
  h.store.put('connections', {...h.connection(), status: 'ready'});
  put({...clean, wait: {until: h.now - 1, reason: 'rate_limited'}});
  assert.equal((await healthOf(who, watch.id)).state, 'quiet', 'a wait that has ended is no wait');
  put({wait: null, notBefore: h.now + 5 * MINUTE, nextPollAt: h.now + MINUTE});
  assert.equal((await healthOf(who, watch.id)).nextCheckAt, iso(h.now + 5 * MINUTE), 'a floor from x-poll-interval counts');
});

both('health: of two feeds, the check longest ago and the soonest next check speak for the watch', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = w.engine.attach(h.watch('feed-updated', {args: {kinds: ['note', 'task']}, status: 'starting', clientId: who.id}));
  const [one, two] = watch.feeds;
  for (const [id, at, next] of [[one, h.now - 5000, h.now + 9000], [two, h.now - 1000, h.now + 3000]]) {
    h.store.put('triggerRuns', {id, connectionId: h.account, runs: [{at, outcome: 'done', status: 200, requests: 1, items: 0, skipped: 0, events: {}}]});
    h.store.put('triggerFeeds', {...h.store.get('triggerFeeds', id), nextPollAt: next});
  }
  h.store.put('subscriptions', {...w.record(watch.id), status: 'active', pending: []});
  assert.deepEqual(await healthOf(who, watch.id), {state: 'quiet', lastCheckedAt: iso(h.now - 5000), nextCheckAt: iso(h.now + 3000)});
});

both('health: a paused watch reads its reason, with its detail as the code, and names no next check', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who);
  h.store.put('subscriptions', {...w.record(watch.id), status: 'paused', reason: 'provider_refused', detail: 'not_in_channel'});
  assert.deepEqual(await healthOf(who, watch.id), {state: 'provider_refused', lastCheckedAt: iso(h.now), errorCode: 'not_in_channel'});
  h.store.put('subscriptions', {...w.record(watch.id), status: 'paused', reason: 'owner_paused', detail: undefined});
  assert.deepEqual(await healthOf(who, watch.id), {state: 'owner_paused', lastCheckedAt: iso(h.now)});
  assert.deepEqual((await who.call('triggers.list')).result.subscriptions[0].reason, 'owner_paused');
});

// ---- triggers.subscribe ----------------------------------------------------------------------------------------------------------------------

both('subscribe: stores a waiting record, sends no provider request, and answers the shape of part 3a with a card', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), {result} = await w.subscribe(who, 'feed-updated', {kinds: ['note']}, {task: {title: 'Watch my notes'}});
  const at = iso(h.now), expiresAt = iso(h.now + 30 * MINUTE), id = result.id, {card, ...view} = result;
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-/);
  assert.deepEqual(view, {id, status: 'awaiting_approval', triggerId: h.triggerId('feed-updated'), connectionId: h.account, createdAt: at, updatedAt: at, approvalRequired: true, approval: {url: `${ORIGIN}/approve/${id}`, expiresAt}});
  assert.equal(h.simulator.calls.length, 0, 'nothing reaches the provider before an approval');
  assert.deepEqual([card.kind, card.state, card.app.name, card.operation.name, card.operation.effect, card.requester.name], ['approval_request', 'awaiting_approval', 'fixture app', h.entryOf('feed-updated').trigger.name, 'read', 'Fixture agent']);
  assert.deepEqual(card.actions.map(action => action.url), [`${ORIGIN}/approve/${id}`]);
  const record = w.record(id);
  assert.deepEqual(record, {id, clientId: who.id, appId: 'fixture', triggerId: h.triggerId('feed-updated'), triggerKey: 'feed-updated', connectionId: h.account, args: {kinds: ['note']}, argsHash: argsHashOf({kinds: ['note']}), task: {title: 'Watch my notes'}, revision: 1,
    status: 'awaiting_approval', approvalDigest: record.approvalDigest, approvalExpiresAt: expiresAt, feeds: [], pending: [], createdAt: at, updatedAt: at});
  assert.match(record.approvalDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(w.audits('trigger.requested').map(({type, subscriptionId, clientId, connectionId, appId, triggerId}) => ({type, subscriptionId, clientId, connectionId, appId, triggerId})),
    [{type: 'trigger.requested', subscriptionId: id, clientId: who.id, connectionId: h.account, appId: 'fixture', triggerId: h.triggerId('feed-updated')}]);
  assert.equal(JSON.stringify(w.audits('trigger.requested')).includes('note'), false, 'an audit row holds ids only, never args');
});

both('subscribe: a cursor, or any key the schema does not name, is refused and stores nothing; so does a field past the four', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent();
  for (const args of [{cursor: 'stale-history-id'}, {historyId: '1'}, {kinds: ['note'], since: '2026-01-01T00:00:00Z'}]) assert.equal((await w.subscribe(who, 'feed-updated', args)).error.code, 'invalid_request', Object.keys(args).join());
  for (const extra of [{destination: 'https://example.test/hook'}, {webhook: {url: 'https://example.test/hook'}}, {cursor: '5'}]) assert.equal((await w.subscribe(who, 'feed-updated', {kinds: ['note']}, extra)).error.code, 'invalid_request', Object.keys(extra).join());
  assert.deepEqual(counts(w), NOTHING);
  assert.equal(w.h.simulator.calls.length, 0);
});

both('subscribe: a malformed request is refused', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), triggerId = h.triggerId('feed-synced');
  for (const params of [{}, {connectionId: h.account}, {triggerId}, {triggerId: 7, connectionId: h.account}, {triggerId, connectionId: 7}, {triggerId, connectionId: h.account, args: []}, {triggerId, connectionId: h.account, args: 'x'}, [],
    {triggerId, connectionId: h.account, task: {title: ''}}, {triggerId, connectionId: h.account, task: {title: 'x', extra: 1}}]) assert.equal((await who.call('triggers.subscribe', params)).error.code, 'invalid_request', JSON.stringify(params));
  assert.deepEqual(counts(w), NOTHING);
});

both('subscribe: an account the client does not hold answers exactly as one that does not exist', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), triggerId = h.triggerId('feed-synced');
  const held = await who.call('triggers.subscribe', {triggerId, connectionId: h.rpcAccount}), missing = await who.call('triggers.subscribe', {triggerId, connectionId: 'no-such-account'});
  assert.equal(held.error.code, 'permission_denied');
  assert.deepEqual(held.error, missing.error);
  h.store.delete('connections', h.account);
  assert.deepEqual((await w.subscribe(who, 'feed-synced')).error, missing.error, 'an account the grant names that has since gone reads the same');
  assert.deepEqual(counts(w), NOTHING);
});

both('subscribe: the same request id and params replay; different params conflict; a refused request leaves its id free', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), other = w.agent('Other');
  assert.equal((await w.subscribe(who, 'feed-updated', {kinds: ['nope']}, {}, 'request-1')).error.code, 'invalid_request');
  const first = await w.subscribe(who, 'feed-updated', {kinds: ['note']}, {}, 'request-1'), again = await w.subscribe(who, 'feed-updated', {kinds: ['note']}, {}, 'request-1');
  assert.deepEqual(again.result, first.result);
  assert.equal((await w.subscribe(who, 'feed-updated', {kinds: ['task']}, {}, 'request-1')).error.code, 'idempotency_conflict');
  assert.equal(w.audits('trigger.requested').length, 1);
  assert.notEqual((await w.subscribe(other, 'feed-updated', {kinds: ['note']}, {}, 'request-1')).result.id, first.result.id, 'a request id is one client\'s');
  w.h.advance(31 * MINUTE);
  assert.equal((await w.subscribe(who, 'feed-updated', {kinds: ['note']}, {}, 'request-1')).result.status, 'expired', 'a replay shows the record as it stands');
  assert.equal(Object.hasOwn((await w.subscribe(who, 'feed-updated', {kinds: ['note']}, {}, 'request-1')).result, 'approval'), false);
});

both('subscribe: a request id spent on another method conflicts, and an earlier record that went cannot be replayed', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), list = h.idOf('list-items v1');
  await who.call('calls.create', {connectionId: h.account, capabilityId: list, definitionHash: who.client.bindings[0].definitionHash, args: {kind: 'note'}}, 'shared-id');
  assert.equal((await w.subscribe(who, 'feed-synced', {}, {}, 'shared-id')).error.code, 'idempotency_conflict');
  const {result} = await w.subscribe(who, 'feed-listed', {}, {}, 'gone-id');
  h.store.delete('subscriptions', result.id);
  assert.equal((await w.subscribe(who, 'feed-listed', {}, {}, 'gone-id')).error.code, 'outcome_unknown');
});

both('subscribe: the same client, trigger, account and args return the record they hold, whatever its key order, while it stands', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), first = (await w.subscribe(who, 'feed-updated', {kinds: ['note', 'task']})).result;
  assert.deepEqual((await w.subscribe(who, 'feed-updated', {kinds: ['note', 'task']})).result, first);
  assert.equal(w.audits('trigger.requested').length, 1, 'an agent loop cannot stack approvals');
  assert.equal(h.store.list('subscriptions').length, 1);
  assert.notEqual((await w.subscribe(who, 'feed-updated', {kinds: ['task']})).result.id, first.id, 'other args are another watch');
  assert.notEqual((await w.subscribe(w.agent('Other'), 'feed-updated', {kinds: ['note', 'task']})).result.id, first.id, 'another client is another watch');
  for (const status of ['starting', 'active', 'paused']) {
    h.store.put('subscriptions', {...w.record(first.id), status});
    const again = (await w.subscribe(who, 'feed-updated', {kinds: ['note', 'task']})).result;
    assert.deepEqual([again.id, again.status, again.approvalRequired, Object.hasOwn(again, 'approval'), Object.hasOwn(again, 'card')], [first.id, status, false, false, false], status);
  }
  for (const status of ['declined', 'expired', 'removed']) {
    h.store.put('subscriptions', {...w.record(first.id), status});
    assert.notEqual((await w.subscribe(who, 'feed-updated', {kinds: ['note', 'task']})).result.id, first.id, status);
    for (const row of h.store.list('subscriptions')) if (row.id !== first.id) h.store.delete('subscriptions', row.id);
  }
});

both('subscribe: a paused record comes back with its reason, even when the gate would refuse a new one', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who);
  h.setRow('fixture.items.read', 'deny');
  h.store.put('subscriptions', {...w.record(watch.id), status: 'paused', reason: 'permission_changed'});
  const {result, error} = await w.subscribe(who, 'feed-synced');
  assert.equal(error, undefined);
  assert.deepEqual([result.id, result.status, result.reason], [watch.id, 'paused', 'permission_changed']);
});

both('subscribe: a repeated resource value collapses, so it makes the one record', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), first = (await w.subscribe(who, 'feed-updated', {kinds: ['note', 'note', 'task']})).result;
  assert.deepEqual(w.record(first.id).args, {kinds: ['note', 'task']});
  assert.equal((await w.subscribe(who, 'feed-updated', {kinds: ['note', 'task', 'task']})).result.id, first.id);
});

test('subscribe: what normalizeArgs() gives is what is stored and hashed, so a Notion link, a dashed id and a plain id are one watch', async t => {
  const w = world(t), {h} = w, who = w.agent(), real = h.catalog;
  // The real transform has its own test in test/trigger-runtime.test.mjs, and only a Notion trigger reads it. Here three values reach one through the member the service calls.
  h.runtime.actions = {...real, normalizeArgs: (entry, args) => ({...args, kinds: ['note']})};
  const ids = [];
  for (const kinds of [['task'], ['row'], ['note']]) ids.push((await w.subscribe(who, 'feed-updated', {kinds})).result.id);
  assert.equal(new Set(ids).size, 1);
  assert.deepEqual(w.record(ids[0]).args, {kinds: ['note']});
  assert.equal(w.record(ids[0]).argsHash, argsHashOf({kinds: ['note']}));
});

test('subscribe: an empty list behind {each} is refused, since such a watch would never leave starting', async t => {
  const triggers = feedTriggers();
  delete triggers.find(item => item.key === 'feed-updated').inputSchema.properties.kinds.minItems;
  const w = world(t, {triggers}), {error} = await w.subscribe(w.agent(), 'feed-updated', {kinds: []});
  assert.equal(error.code, 'invalid_request');
  assert.match(error.message, /at least one/);
  assert.deepEqual(counts(w), NOTHING);
});

test('subscribe: subscribeRefusal() reads the normalised args and the facts Fabric holds, and its words reach the agent', async t => {
  const w = world(t), {h} = w, who = w.agent(), item = h.itemOf('feed-synced');
  const as = (appId, key) => { h.runtime.actions = {...h.catalog, pinned: () => true, triggerOf: id => id === item.entry.id ? {...item, appId, entry: {...item.entry, key}} : h.catalog.triggerOf(id)}; };
  const asked = () => who.call('triggers.subscribe', {triggerId: item.entry.id, connectionId: h.account}).then(answer => answer.error);
  as('gmail', 'new-email-matching-search');
  assert.deepEqual(await asked(), {code: 'invalid_request', message: 'Say what to search for: an empty search matches every email.'});
  as('slack', 'new-message');
  h.runtime.slackDistribution = 'distributed';
  assert.match((await asked()).message, /distributed outside the Slack Marketplace/);
  h.runtime.slackDistribution = 'internal';
  as('google-calendar', 'calendar-sharing-changed');
  assert.match((await asked()).message, /has not allowed that/);
  h.store.put('connections', {...h.connection(), scopes: ['https://www.googleapis.com/auth/calendar.acls']});
  assert.doesNotMatch((await asked()).message, /has not allowed that/, 'with the scope held, the gate decides');
  assert.deepEqual(counts(w), NOTHING);
});

both('subscribe: any gate failure refuses and stores nothing, a failed renewal included; a persistent browser account refuses cleanly', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), ready = h.connection();
  const refused = async (label, change, undo, key = 'feed-synced') => {
    change();
    const {error} = await w.subscribe(who, key);
    assert.equal(error?.code, 'permission_denied', label);
    assert.deepEqual(counts(w), NOTHING, label);
    undo();
  };
  await refused('Background off', () => h.store.put('backgroundPolicies', {id: h.account, connectionId: h.account, mode: 'deny', updatedAt: 'x'}), () => h.store.delete('backgroundPolicies', h.account));
  await refused('a row at Never', () => h.setRow('fixture.items.read', 'deny'), () => h.setRow('fixture.items.read', 'allow'));
  await refused('a row at Ask', () => {}, () => {}, 'feed-logged-keys');
  await refused('a failed renewal', () => h.store.put('connections', {...ready, status: 'reconnect_required'}), () => h.store.put('connections', ready));
  await refused('a disconnected account', () => h.store.put('connections', {...ready, status: 'revoked'}), () => h.store.put('connections', ready));
  await refused('a saved browser session', () => h.store.put('connections', {...ready, driver: 'browser', transport: 'persistent'}), () => h.store.put('connections', ready));
});

both('subscribe: a same-args answer keeps its request id, so a retry after the watch was removed replays that record and makes no new card', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), first = (await w.subscribe(who, 'feed-listed')).result, request = randomUUID(), held = await w.subscribe(who, 'feed-listed', {}, {}, request);
  assert.deepEqual([held.result.id, held.result.approvalRequired], [first.id, true]);
  w.subscriptions.remove(first.id, h.owner ?? undefined);
  const before = counts(w), retry = await w.subscribe(who, 'feed-listed', {}, {}, request);
  assert.deepEqual([retry.result?.id, retry.result?.status, retry.result?.approvalRequired], [first.id, 'removed', false]);
  assert.deepEqual(counts(w), before);
  assert.equal((await w.subscribe(who, 'feed-listed', {}, {}, randomUUID())).result.status, 'awaiting_approval', 'a new request id asks again');
});

both('subscribe: the 21st watch on an account is refused, across clients, and only standing records count', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), far = iso(h.now + 20 * MINUTE), statuses = ['active', 'starting', 'paused', 'awaiting_approval'];
  for (let n = 0; n < 19; n++) h.watch('feed-listed', {clientId: `client-${n}`, args: {n}, status: statuses[n % 4], approvalExpiresAt: far});
  for (const status of ['declined', 'expired', 'removed']) h.watch('feed-listed', {clientId: 'ended', status});
  const before = counts(w), twentieth = await w.subscribe(who, 'feed-synced');
  assert.equal(twentieth.result.status, 'awaiting_approval');
  const {error} = await w.subscribe(who, 'feed-listed');
  assert.equal(error.code, 'subscription_limit');
  assert.equal(counts(w).subscriptions, before.subscriptions + 1);
  assert.equal((await w.subscribe(who, 'feed-synced')).result.id, twentieth.result.id, 'the record it holds still comes back at the cap');
});

both('subscribe: a waiting request past its time stops counting at the caps', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), far = iso(h.now + 20 * MINUTE), near = iso(h.now + MINUTE);
  for (let n = 0; n < 19; n++) h.watch('feed-listed', {clientId: `client-${n}`, args: {n}, status: 'awaiting_approval', approvalExpiresAt: far});
  h.watch('feed-listed', {clientId: 'late', args: {late: true}, status: 'awaiting_approval', approvalExpiresAt: near});
  assert.equal((await w.subscribe(who, 'feed-synced')).error.code, 'subscription_limit');
  h.advance(2 * MINUTE);
  assert.equal((await w.subscribe(who, 'feed-synced')).result.status, 'awaiting_approval');
  assert.equal(w.audits('trigger.expired').length, 1);
});

both('subscribe: the 11th waiting request of a client and the 51st in all are refused, as the handoff limits are', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), far = iso(h.now + 20 * MINUTE);
  const waiting = (clientId, connectionId, n) => h.watch('feed-listed', {clientId, connectionId, args: {n}, status: 'awaiting_approval', approvalExpiresAt: far});
  for (let n = 0; n < 9; n++) waiting(who.id, 'other-account', n);
  assert.equal((await w.subscribe(who, 'feed-synced')).result.status, 'awaiting_approval', 'the tenth');
  assert.equal((await w.subscribe(who, 'feed-listed')).error.code, 'pending_limit', 'the eleventh');
  const other = w.agent('Other');
  assert.equal((await w.subscribe(other, 'feed-listed')).result.status, 'awaiting_approval', 'another client has its own ten');
  for (let n = 0; n < 38; n++) waiting(`client-${n}`, `account-${n}`, n);
  const at = (await w.subscribe(other, 'feed-tagged'));
  assert.equal(at.result.status, 'awaiting_approval', 'the fiftieth');
  assert.equal(h.store.list('subscriptions').filter(row => row.status === 'awaiting_approval').length, 50);
  assert.equal((await w.subscribe(w.agent('Third'), 'feed-synced')).error.code, 'pending_limit', 'the fifty-first');
});

both('subscribe: an approval waits 30 minutes, capped by the grant, so it never outlives the agent\'s access', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, short = w.agent('Short', {expiresInSeconds: 600}), {result} = await w.subscribe(short, 'feed-synced');
  assert.equal(result.approval.expiresAt, iso(h.now + 600_000));
  assert.equal(Object.hasOwn(w.record(result.id), 'task'), false, 'a request with no task stores none');
  assert.equal(w.record(result.id).approvalExpiresAt, iso(h.now + 600_000));
});

both('the stored digest binds the id, the arguments and each row\'s policy, so a row moved after the view gives another digest', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), {result} = await w.subscribe(who, 'feed-synced'), record = w.record(result.id);
  const digest = (subscription = record) => approvalDigest(subscription, h.connection(), h.permissions.triggerDecision(h.connection(), h.entryOf('feed-synced')));
  assert.equal(digest(), record.approvalDigest);
  assert.notEqual(digest({...record, id: randomUUID()}), record.approvalDigest);
  assert.notEqual(digest({...record, revision: 2}), record.approvalDigest);
  assert.notEqual(digest({...record, argsHash: 'other'}), record.approvalDigest);
  assert.notEqual(digest({...record, triggerId: 'other'}), record.approvalDigest);
  assert.notEqual(digest({...record, connectionId: 'other'}), record.approvalDigest);
  h.setRow('fixture.items.read', 'ask');
  assert.notEqual(digest(), record.approvalDigest, 'a row that moved');
});

test('the digest holds the account generation on a designated store only, and the identity on both', async t => {
  const plain = world(t), designated = world(t, {designated: true}), digestOf = (w, identity) => {
    const connection = {...w.h.connection(), identity}, decision = w.h.permissions.triggerDecision(w.h.connection(), w.h.entryOf('feed-synced'));
    return approvalDigest({id: 'x', revision: 1, triggerId: 't', connectionId: 'c', argsHash: 'a'}, connection, decision);
  };
  assert.notEqual(digestOf(plain, {id: 'one'}), digestOf(plain, {id: 'two'}));
  const decision = designated.h.permissions.triggerDecision(designated.h.connection(), designated.h.entryOf('feed-synced')), record = {id: 'x', revision: 1, triggerId: 't', connectionId: 'c', argsHash: 'a'};
  assert.equal(typeof decision.connectionGeneration, 'number');
  assert.notEqual(approvalDigest(record, designated.h.connection(), decision), approvalDigest(record, designated.h.connection(), {...decision, connectionGeneration: decision.connectionGeneration + 1}));
  assert.equal(approvalDigest(record, plain.h.connection(), {rows: []}), approvalDigest(record, plain.h.connection(), {rows: [], connectionGeneration: undefined}));
});

// ---- touch and revoke ------------------------------------------------------------------------------------------------------------------------

both('expiry lands on a read, with one audit row, and frees the same args for a new request', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), {result} = await w.subscribe(who, 'feed-synced');
  h.advance(30 * MINUTE - 1);
  assert.equal((await who.call('triggers.list')).result.subscriptions[0].status, 'awaiting_approval');
  assert.equal(w.record(result.id).status, 'awaiting_approval');
  h.advance(1);
  const [row] = (await who.call('triggers.list')).result.subscriptions;
  assert.deepEqual([row.status, row.health, Object.hasOwn(row, 'approval')], ['expired', null, false]);
  await who.call('triggers.list');
  assert.deepEqual(w.audits('trigger.expired').map(({subscriptionId, clientId, connectionId}) => ({subscriptionId, clientId, connectionId})), [{subscriptionId: result.id, clientId: who.id, connectionId: h.account}]);
  assert.equal(w.record(result.id).updatedAt, iso(h.now));
  assert.notEqual((await w.subscribe(who, 'feed-synced')).result.id, result.id);
});

test('touch leaves everything but a waiting record alone', t => {
  const w = world(t), watch = w.h.watch('feed-synced', {status: 'active'});
  w.h.advance(DAY);
  assert.deepEqual(w.subscriptions.touch(watch), watch);
  assert.equal(w.audits('trigger.expired').length, 0);
});

both('a client revoked while a request waits closes it, with one audit row, and an active watch is left to the gate', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), other = w.agent('Other'), waiting = (await w.subscribe(who, 'feed-listed')).result, theirs = (await w.subscribe(other, 'feed-listed')).result, watch = await running(w, who);
  w.protocol.revokeClient(who.id);
  assert.deepEqual([w.record(waiting.id).status, w.record(waiting.id).reason], ['expired', 'client_ended']);
  assert.equal(w.record(theirs.id).status, 'awaiting_approval', 'another client\'s stands');
  assert.equal(w.record(watch.id).status, 'active', 'it pauses at its next gate, as any other change does');
  assert.equal(w.audits('trigger.expired').length, 1);
  h.advance(INTERVAL);
  await w.engine.pollNow(watch.id);
  assert.deepEqual([w.record(watch.id).status, w.record(watch.id).reason], ['paused', 'client_ended']);
});

const seenRows = ({root}) => { const db = new DatabaseSync(path.join(root, 'data', 'fabric.sqlite'), {readOnly: true}); try { return db.prepare('SELECT count(*) AS rows FROM trigger_seen').get().rows; } finally { db.close(); } };

both('a client\'s end takes what its watch gathered at the next gate: its events, its feed and its seen rows, and the record stays to show who held it', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who), [feedId] = watch.feeds;
  await written(w, watch);
  assert.deepEqual([h.store.listEvents(who.id, 0, 10).length, seenRows(h) > 0], [1, true]);
  w.protocol.revokeClient(who.id);
  h.advance(INTERVAL);
  await w.engine.pollNow(watch.id);
  const closed = w.record(watch.id);
  assert.deepEqual([closed.status, closed.reason, closed.feeds, closed.pending], ['paused', 'client_ended', [], []]);
  assert.deepEqual([h.store.listEvents(who.id, 0, 10), h.store.get('triggerFeeds', feedId), h.store.get('triggerRuns', feedId), seenRows(h)], [[], null, null, 0]);
  assert.equal(w.audits('trigger.paused').length, 1);
  assert.equal(w.subscriptions.ownerList().length, 1, 'the owner still sees that this agent held a watch');
});

both('a grant that lapses does the same, at the next tick, and a feed another agent reads stays with its events', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent('Short'), other = w.agent('Long'), mine = await running(w, who), theirs = await running(w, other);
  assert.deepEqual(mine.feeds, theirs.feeds);
  await written(w, theirs);
  h.store.put('clientGrants', {...h.store.get('clientGrants', who.id), expiresAt: new Date(h.now + 1000).toISOString()});
  h.advance(INTERVAL);
  await w.engine.tick();
  assert.deepEqual([w.record(mine.id).status, w.record(mine.id).reason, w.record(mine.id).feeds, h.store.listEvents(who.id, 0, 10)], ['paused', 'client_ended', [], []]);
  assert.deepEqual([w.record(theirs.id).status, w.record(theirs.id).feeds, h.store.listEvents(other.id, 0, 10).length], ['active', theirs.feeds, 1]);
  assert.ok(h.store.get('triggerFeeds', theirs.feeds[0]));
});

both('a poll in flight when a client ends stores nothing, and its feed stays gone', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who), [feedId] = watch.feeds;
  h.advance(INTERVAL);
  h.simulator.write({name: 'New'});
  const held = h.simulator.hold('GET /feed'), flight = w.engine.pollNow(watch.id);
  await held.reached;
  w.protocol.revokeClient(who.id);
  held.release();
  await flight;
  assert.deepEqual([w.record(watch.id).reason, h.store.get('triggerFeeds', feedId), h.store.get('triggerRuns', feedId), h.store.listEvents(who.id, 0, 10)], ['client_ended', null, null, []]);
});

both('a paused watch has no poll to find its client\'s end: a revoke closes it at once, and a lapse when the owner\'s list reads it', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), lapsing = w.agent('Lapsing'), principal = h.owner ?? undefined, revoked = await running(w, who), [feedId] = revoked.feeds, lapsed = await running(w, lapsing, 'feed-listed');
  await written(w, revoked);
  w.subscriptions.pause(revoked.id, principal);
  w.subscriptions.pause(lapsed.id, principal);
  w.protocol.revokeClient(who.id);
  assert.deepEqual([w.record(revoked.id).status, w.record(revoked.id).reason, w.record(revoked.id).feeds, h.store.listEvents(who.id, 0, 10), h.store.get('triggerFeeds', feedId)], ['paused', 'client_ended', [], [], null]);
  h.store.put('clientGrants', {...h.store.get('clientGrants', lapsing.id), expiresAt: new Date(h.now - 1).toISOString()});
  assert.equal(w.record(lapsed.id).reason, 'owner_paused', 'nothing has read it yet');
  const row = w.subscriptions.ownerList().find(item => item.id === lapsed.id);
  assert.deepEqual([row.status, row.reason, row.feeds], ['paused', 'client_ended', []]);
  assert.equal(w.audits('trigger.paused').filter(item => item.reason === 'client_ended').length, 2, 'each once');
  w.subscriptions.ownerList();
  assert.equal(w.audits('trigger.paused').filter(item => item.reason === 'client_ended').length, 2);
});

both('a watch whose client ended holds no slot: it can never resume, so it does not count toward the 20 on an account', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, gone = w.agent('Gone'), next = w.agent('Next');
  for (let n = 0; n < 20; n++) h.watch('feed-listed', {clientId: gone.id, status: 'paused', reason: 'owner_paused', args: {n}});
  assert.equal((await w.subscribe(next, 'feed-listed')).error?.code, 'subscription_limit', 'while its client stands, a paused watch holds its slot');
  w.protocol.revokeClient(gone.id);
  assert.equal((await w.subscribe(next, 'feed-listed')).result.status, 'awaiting_approval');
});

both('a lapsed grant gives its paused watches\' slots back when the owner\'s list reads them', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, gone = w.agent('Gone'), next = w.agent('Next');
  for (let n = 0; n < 20; n++) h.watch('feed-listed', {clientId: gone.id, status: 'paused', reason: 'owner_paused', args: {n}});
  h.store.put('clientGrants', {...h.store.get('clientGrants', gone.id), expiresAt: new Date(h.now - 1).toISOString()});
  w.subscriptions.ownerList();
  assert.equal((await w.subscribe(next, 'feed-listed')).result.status, 'awaiting_approval');
});

// ---- triggers.unsubscribe --------------------------------------------------------------------------------------------------------------------

both('unsubscribe: an agent removes its own watch: its events and its feed go, one audit row is written, and a repeat changes nothing', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who);
  await written(w, watch);
  assert.equal((await page(who)).events.length, 1);
  h.advance(1000);
  const {result} = await who.call('triggers.unsubscribe', {subscriptionId: watch.id});
  assert.deepEqual(result, {id: watch.id, status: 'removed', triggerId: watch.triggerId, connectionId: h.account, createdAt: watch.createdAt, updatedAt: iso(h.now), approvalRequired: false});
  assert.deepEqual([w.record(watch.id).status, w.record(watch.id).feeds, w.record(watch.id).pending], ['removed', [], []]);
  assert.equal(h.store.list('triggerFeeds').length, 0, 'polling registered nothing, so there is nothing else to take down');
  assert.deepEqual((await page(who)).events, []);
  const calls = h.simulator.calls.length;
  assert.deepEqual((await who.call('triggers.unsubscribe', {subscriptionId: watch.id})).result, result);
  assert.deepEqual(w.audits('trigger.removed').map(({subscriptionId, clientId, connectionId, appId, triggerId}) => ({subscriptionId, clientId, connectionId, appId, triggerId})), [{subscriptionId: watch.id, clientId: who.id, connectionId: h.account, appId: 'fixture', triggerId: watch.triggerId}]);
  assert.equal(h.simulator.calls.length, calls, 'removing a watch sends nothing');
});

both('unsubscribe: a foreign or unknown id answers not_found, alike, and the watch stands', async (t, designated) => {
  const w = world(t, {designated}), mine = w.agent('Mine'), theirs = w.agent('Theirs'), watch = await running(w, theirs);
  const foreign = await mine.call('triggers.unsubscribe', {subscriptionId: watch.id}), unknown = await mine.call('triggers.unsubscribe', {subscriptionId: randomUUID()});
  assert.equal(foreign.error.code, 'not_found');
  assert.deepEqual(foreign.error, unknown.error);
  assert.equal(w.record(watch.id).status, 'active');
  assert.equal(w.audits('trigger.removed').length, 0);
});

both('unsubscribe: a request still waiting goes too, a paused watch goes, and a removed record stays out of the way of a new one', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), waiting = (await w.subscribe(who, 'feed-synced')).result, watch = await running(w, who, 'feed-listed');
  assert.equal((await who.call('triggers.unsubscribe', {subscriptionId: waiting.id})).result.status, 'removed');
  h.store.put('subscriptions', {...w.record(watch.id), status: 'paused', reason: 'owner_paused'});
  assert.equal((await who.call('triggers.unsubscribe', {subscriptionId: watch.id})).result.status, 'removed');
  assert.notEqual((await w.subscribe(who, 'feed-synced')).result.id, waiting.id);
});

both('unsubscribe: a shared feed stays for the other watch, and a malformed request is refused', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, a = w.agent('A'), b = w.agent('B'), first = await running(w, a), second = await running(w, b);
  assert.equal((await a.call('triggers.unsubscribe', {subscriptionId: first.id})).result.status, 'removed');
  assert.ok(h.store.get('triggerFeeds', second.feeds[0]));
  for (const params of [{}, {subscriptionId: 7}, {subscriptionId: first.id, extra: 1}]) assert.equal((await a.call('triggers.unsubscribe', params)).error.code, 'invalid_request', JSON.stringify(params));
});

// ---- events.list -----------------------------------------------------------------------------------------------------------------------------

both('events.list: answers the shape of part 3b, in order, with what the watch was built to carry', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who);
  await written(w, watch, 'First');
  const result = await page(who), {events: [event], ...rest} = result;
  assert.deepEqual(rest, {next: 1, latest: 1, trimmed: 0});
  const {id, occurredAt} = event, stored = h.store.listEvents(who.id, 0, 1)[0];
  assert.deepEqual(event, {sequence: 1, subscriptionId: watch.id, triggerId: watch.triggerId, connectionId: h.account, type: 'trigger.event', id, occurredAt, detectedAt: iso(stored.createdAt), fields: stored.payload.fields, summary: stored.payload.summary});
  assert.equal(event.fields.name, 'First');
  assert.deepEqual(event.summary, [{label: 'Item', value: 'First'}]);
});

both('events.list: a gap has the same shape, and an integer occurredAt passes through', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who), gap = gapPayload('resume', iso(h.now - MINUTE), iso(h.now));
  stored(w, watch, 1, {kind: 'trigger.gap', payload: gap});
  stored(w, watch, 1, {payload: {type: 'trigger.event', id: 'x', occurredAt: 1_761_210_000, fields: {}, summary: []}});
  const {events: [first, second]} = await page(who);
  assert.deepEqual(first, {sequence: 1, subscriptionId: watch.id, triggerId: watch.triggerId, connectionId: h.account, type: 'trigger.gap', id: gap.id, occurredAt: gap.occurredAt, detectedAt: iso(h.now), fields: gap.fields, summary: gap.summary});
  assert.equal(second.occurredAt, 1_761_210_000);
});

both('events.list: bad numbers and extra fields are refused', async (t, designated) => {
  const who = world(t, {designated}).agent();
  for (const params of [{limit: 101}, {limit: 0}, {limit: 1.5}, {limit: '5'}, {waitSeconds: 26}, {waitSeconds: -1}, {waitSeconds: 0.5}, {after: -1}, {after: 1.5}, {after: '1'}, {after: 2 ** 53}, {subscriptionId: 'x'}, []]) assert.equal((await who.call('events.list', params)).error.code, 'invalid_request', JSON.stringify(params));
  for (const params of [{limit: 100}, {limit: 1}, {waitSeconds: 25}, {after: 0}, {}]) assert.equal((await who.call('events.list', params)).error, undefined, JSON.stringify(params));
});

both('events.list: 50 by default, `limit` and `after` page, and a repeated `after` sees the same sequence, since Fabric holds no read position', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), watch = await running(w, who);
  stored(w, watch, 60);
  const first = await page(who);
  assert.deepEqual([first.events.length, first.next, first.latest, first.trimmed], [50, 50, 60, 0]);
  const second = await page(who, {after: 50, limit: 4});
  assert.deepEqual(second.events.map(event => event.sequence), [51, 52, 53, 54]);
  assert.deepEqual((await page(who, {after: 50, limit: 4})).events, second.events);
  assert.deepEqual(await page(who, {after: 60}), {events: [], next: 60, latest: 60, trimmed: 0});
  assert.deepEqual(await page(who, {after: 70}), {events: [], next: 70, latest: 60, trimmed: 0}, 'past the end, `next` stays where the client is');
});

both('events.list: a client reads its own events only, with its own numbers', async (t, designated) => {
  const w = world(t, {designated}), a = w.agent('A'), b = w.agent('B'), mine = await running(w, a);
  stored(w, mine, 3);
  assert.deepEqual(await page(b), {events: [], next: 0, latest: 0, trimmed: 0});
});

both('events.list: `trimmed` is exact after a sweep, and a page past a hole says so', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who);
  stored(w, watch, 2);
  stored(w, watch, 2, {kept: 1000});
  stored(w, watch, 2);
  h.advance(2000);
  h.store.sweepEvents(h.now);
  const {events, next, latest, trimmed} = await page(who);
  assert.deepEqual([events.map(event => event.sequence), next, latest, trimmed], [[1, 2, 5, 6], 6, 6, 2]);
  const part = await page(who, {after: 2, limit: 1});
  assert.deepEqual([part.events.map(event => event.sequence), part.next, part.trimmed], [[5], 5, 2]);
  const hidden = world(t, {designated}), other = hidden.agent(), seen = await running(hidden, other);
  stored(hidden, seen, 2, {kept: 1000});
  stored(hidden, seen, 1);
  hidden.h.advance(2000);
  assert.deepEqual([(await page(other)).events.map(event => event.sequence), (await page(other)).trimmed], [[3], 2], 'an expired row reads as trimmed before the sweep reaches it');
});

both('events.list: with every row past `after` swept, `next` is `latest`, `trimmed` the difference, and a wait answers at once', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who);
  stored(w, watch, 5, {kept: 1000});
  h.advance(2000);
  h.store.sweepEvents(h.now);
  assert.deepEqual(await within(page(who, {after: 2, waitSeconds: 25})), {events: [], next: 5, latest: 5, trimmed: 3});
});

both('events.list writes no document, no audit row and no request row', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who);
  stored(w, watch, 3);
  await who.call('triggers.list');
  const writes = [];
  for (const name of ['put', 'delete', 'audit', 'appendPoll']) { const real = h.store[name].bind(h.store); h.store[name] = (...args) => { writes.push(name); return real(...args); }; }
  await page(who);
  await page(who, {after: 3, waitSeconds: 0});
  assert.deepEqual(writes, []);
});

test('critique test 14: at 20,000 events a page reads by primary key, gates each watch once, and stays within budget', async t => {
  const w = world(t), {h} = w, who = w.agent(), watches = Array.from({length: 20}, (_, n) => h.watch('feed-listed', {clientId: who.id, args: {n}}));
  for (const watch of watches) h.store.appendPoll({feedId: 'feed', events: Array.from({length: 1000}, (_, n) => eventRow(watch, n, {at: h.now}))});
  assert.equal(h.store.latestSequence(who.id), 20_000);
  const list = h.store.list.bind(h.store), read = [], real = h.permissions.triggerDecision.bind(h.permissions);
  let decisions = 0;
  h.store.list = collection => { read.push(collection); return list(collection); };
  h.permissions.triggerDecision = (...args) => { decisions++; return real(...args); };
  const started = performance.now(), {events, next, latest, trimmed} = await page(who, {after: 19_900, limit: 100}), elapsed = performance.now() - started;
  assert.deepEqual([events.length, events[0].sequence, next, latest, trimmed], [100, 19_901, 20_000, 20_000, 0]);
  assert.ok(read.every(collection => collection === 'capabilities'), 'Store.list parses a whole collection, so a page asks it only for what the gate reads of the typed rows');
  assert.equal(decisions, 1, 'a page of one watch gates it once');
  assert.ok(elapsed < 500, `a page took ${elapsed} ms`);
});

// ---- authority at read -----------------------------------------------------------------------------------------------------------------------

both('events.list: each watch in a page passes the gate once a call, and a second call asks again', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), one = await running(w, who), two = await running(w, who, 'feed-listed'), real = h.permissions.triggerDecision.bind(h.permissions);
  stored(w, one, 3);
  stored(w, two, 3);
  let decisions = 0;
  h.permissions.triggerDecision = (...args) => { decisions++; return real(...args); };
  await page(who);
  assert.equal(decisions, 2);
  await page(who);
  assert.equal(decisions, 4);
});

both('events.list: a watch that fails the gate is withheld: no id, no time, no fields, and the cursor still moves', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who), other = await running(w, who, 'feed-listed'), gap = gapPayload('resync', iso(h.now - MINUTE), iso(h.now));
  stored(w, watch, 2);
  stored(w, watch, 1, {kind: 'trigger.gap', payload: gap});
  stored(w, other, 1);
  h.setRow('fixture.items.read', 'deny');
  const {events, next, latest, trimmed} = await page(who);
  assert.deepEqual([next, latest, trimmed], [4, 4, 0]);
  assert.deepEqual(events[0], {sequence: 1, subscriptionId: watch.id, triggerId: watch.triggerId, connectionId: h.account, type: 'trigger.event', id: null, occurredAt: null, detectedAt: iso(h.now), fields: null, summary: [], withheld: true});
  assert.deepEqual(events[2], {sequence: 3, subscriptionId: watch.id, triggerId: watch.triggerId, connectionId: h.account, type: 'trigger.gap', id: null, occurredAt: null, detectedAt: iso(h.now), fields: null, summary: [], withheld: true});
  const text = JSON.stringify(events);
  for (const leak of ['item-1', 'Name 1', 'gap|', '08:00:00']) assert.equal(text.includes(leak), false, leak);
  h.setRow('fixture.items.read', 'allow');
  assert.equal((await page(who)).events[0].withheld, true, 'a row back at Allow is a new setting, so only the owner\'s Resume opens this again');
  const record = w.record(watch.id), connection = h.connection();
  h.store.put('subscriptions', {...record, authority: authorityOf(record, connection, h.permissions.triggerDecision(connection, h.entryOf('feed-synced')))});
  assert.deepEqual([(await page(who)).events[0].id, (await page(who)).events[0].withheld], ['item-1', undefined], 'the same sequence then reads again');
});

both('events.list: of two watches, only the one that failed is withheld', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), plain = await running(w, who), other = h.watch('feed-logged-keys', {clientId: who.id, status: 'active', authority: undefined});
  stored(w, plain, 1);
  stored(w, other, 1);
  const {events} = await page(who);
  assert.deepEqual(events.map(event => [event.subscriptionId, event.id === null]), [[plain.id, false], [other.id, true]]);
});

both('events.list: an owner\'s Pause withholds what was gathered at once, as the card promises, a Resume shows it again, and a pause nobody chose withholds nothing', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who), principal = h.owner ?? undefined;
  stored(w, watch, 1);
  w.subscriptions.pause(watch.id, principal);
  assert.deepEqual((await page(who)).events.map(event => [event.id, event.occurredAt, event.fields, event.withheld, event.subscriptionId]), [[null, null, null, true, watch.id]]);
  w.subscriptions.resume(watch.id, w.subscriptions.ownerFacts(w.record(watch.id)).digest, principal);
  assert.equal((await page(who)).events[0].id, 'item-1');
  h.store.put('subscriptions', {...w.record(watch.id), status: 'paused', reason: 'provider_refused'});
  assert.equal((await page(who)).events[0].id, 'item-1', 'what was gathered lawfully stays readable after a provider\'s refusal');
  h.store.delete('subscriptions', watch.id);
  const [event] = (await page(who)).events;
  assert.deepEqual([event.id, event.withheld, event.triggerId, event.subscriptionId], [null, true, null, watch.id]);
});

test('events.list: with no catalog an event is withheld, and nothing pauses', async t => {
  const w = world(t), who = w.agent(), watch = await running(w, who);
  stored(w, watch, 1);
  w.h.runtime.actions = null;
  assert.equal((await page(who)).events[0].withheld, true);
  assert.equal(w.record(watch.id).status, 'active');
});

// ---- waiting ---------------------------------------------------------------------------------------------------------------------------------

both('a wait: an append answers before the timer, for each of the client\'s waits, and for no other client', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), other = w.agent('Other'), watch = await running(w, who);
  await running(w, other, 'feed-listed');
  const first = page(who, {waitSeconds: 25}), second = page(who, {waitSeconds: 25}), theirs = page(other, {waitSeconds: 25});
  assert.equal(await pending(first), true);
  await written(w, watch);
  const [one, two] = await within(Promise.all([first, second]));
  assert.deepEqual([one.events.length, two.events.length, one.next], [1, 1, 1]);
  assert.equal(await pending(theirs), true, 'the other client waits on');
  assert.equal(h.simulator.calls.length > 0, true);
});

both('a wait ends at its timer with an empty page, and waits no longer than it was asked', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent();
  await running(w, who);
  const started = performance.now(), answer = await within(page(who, {waitSeconds: 1}), 3000), elapsed = performance.now() - started;
  assert.deepEqual(answer, {events: [], next: 0, latest: 0, trimmed: 0});
  assert.ok(elapsed >= 900 && elapsed < 2500, `waited ${elapsed} ms`);
});

test('a wait\'s timer keeps no process alive', async t => {
  const w = world(t), who = w.agent(), real = globalThis.setTimeout, handles = [];
  await running(w, who);
  globalThis.setTimeout = (...args) => { const handle = real(...args); handles.push(handle); return handle; };
  t.after(() => { globalThis.setTimeout = real; });
  const waiting = who.call('events.list', {waitSeconds: 25});
  globalThis.setTimeout = real;
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(handles.map(handle => handle.hasRef()), [false]);
  w.subscriptions.close();
  await within(waiting);
});

both('a client with no live watch answers at once, however long it asked to wait', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent();
  assert.deepEqual(await within(page(who, {waitSeconds: 25})), {events: [], next: 0, latest: 0, trimmed: 0}, 'no watch at all');
  await w.subscribe(who, 'feed-synced');
  assert.notEqual(await within(page(who, {waitSeconds: 25})), 'still waiting', 'a request still waiting for its approval is no live watch');
  const paused = h.watch('feed-listed', {clientId: who.id, status: 'paused'});
  assert.notEqual(await within(page(who, {waitSeconds: 25})), 'still waiting', 'nor is a paused one');
  h.store.put('subscriptions', {...paused, status: 'starting'});
  assert.equal(await pending(page(who, {waitSeconds: 25})), true, 'a watch catching up is live');
});

both('at most four waits a client: the fifth answers wait_limit, an answer that needs no wait is never refused, and a sixth passes once one ends', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), other = w.agent('Other'), watch = await running(w, who);
  await running(w, other, 'feed-listed');
  const short = page(who, {waitSeconds: 1}), held = [1, 2, 3].map(() => page(who, {waitSeconds: 25}));
  assert.equal(await pending(held[2]), true);
  const fifth = await who.call('events.list', {waitSeconds: 25});
  assert.equal(fifth.error.code, 'wait_limit');
  assert.equal((await who.call('events.list', {waitSeconds: 0})).error, undefined, 'a read that does not wait');
  assert.equal(await pending(page(other, {waitSeconds: 25})), true, 'the limit is one client\'s');
  await within(short, 3000);
  const sixth = page(who, {waitSeconds: 25});
  assert.equal(await pending(sixth), true);
  assert.equal((await who.call('events.list', {waitSeconds: 25})).error.code, 'wait_limit');
  stored(w, watch, 1);
  await within(Promise.all([...held, sixth]));
  assert.equal(await pending(page(who, {after: 1, waitSeconds: 25})), true, 'all the slots came back');
});

both('a client revoked during a wait gets unauthorized at once, and never data', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), watch = await running(w, who), waiting = who.call('events.list', {waitSeconds: 25});
  assert.equal(await pending(waiting), true);
  w.h.store.appendPoll({feedId: 'feed', events: [eventRow(watch, 1, {at: w.h.now})]});
  w.protocol.revokeClient(who.id);
  const answer = await within(waiting);
  assert.deepEqual([answer.error?.code, answer.result], ['unauthorized', undefined]);
});

both('a client whose grant ran out during a wait gets unauthorized', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), watch = await running(w, who), waiting = who.call('events.list', {waitSeconds: 25});
  assert.equal(await pending(waiting), true);
  w.h.advance(2 * DAY);
  stored(w, watch, 1);
  assert.equal((await within(waiting)).error?.code, 'unauthorized');
});

both('a Never during a wait gives a withheld event, with no id and no time', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), watch = await running(w, who), waiting = page(who, {waitSeconds: 25});
  assert.equal(await pending(waiting), true);
  w.h.setRow('fixture.items.read', 'deny');
  stored(w, watch, 1);
  const {events: [event], next} = await within(waiting);
  assert.deepEqual([event.withheld, event.id, event.occurredAt, event.fields, event.summary, next], [true, null, null, null, [], 1]);
});

both('a skip during a wait still serves the events, which were gathered lawfully', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who), waiting = page(who, {waitSeconds: 25});
  assert.equal(await pending(waiting), true);
  h.store.put('connections', {...h.connection(), status: 'reconnect_required'});
  stored(w, watch, 1);
  const {events: [event]} = await within(waiting);
  assert.deepEqual([event.id, event.withheld], ['item-1', undefined]);
});

both('a row at Never while the account reads reconnect_required is withheld: a failure wins over a skip', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), watch = await running(w, who);
  stored(w, watch, 1);
  h.setRow('fixture.items.read', 'deny');
  h.store.put('connections', {...h.connection(), status: 'reconnect_required'});
  const {events: [event]} = await page(who);
  assert.deepEqual([event.withheld, event.id], [true, null]);
});

both('close() ends every wait at once, and a later wait does not start', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), other = w.agent('Other');
  await running(w, who);
  await running(w, other, 'feed-listed');
  const one = page(who, {waitSeconds: 25}), two = page(other, {waitSeconds: 25});
  assert.equal(await pending(one), true);
  w.subscriptions.close();
  assert.deepEqual(await within(Promise.all([one, two])), [{events: [], next: 0, latest: 0, trimmed: 0}, {events: [], next: 0, latest: 0, trimmed: 0}]);
  assert.deepEqual(await within(page(who, {waitSeconds: 25})), {events: [], next: 0, latest: 0, trimmed: 0});
});

// ---- part 3c: the owner's approval. Every check runs in the owner's service, and the routes that reach it are test/watches-page.test.mjs ---------------

const asked = async (w, who, key = 'feed-synced', args = {}) => (await w.subscribe(who, key, args)).result.id;
const digestOf = (w, id) => w.subscriptions.ownerFacts(w.record(id)).digest;
const approve = (w, id, digest = digestOf(w, id)) => w.subscriptions.approve(id, digest, w.h.owner ?? undefined);
const decline = (w, id) => w.subscriptions.decline(id, w.h.owner ?? undefined);
const refused = (run, code) => assert.throws(run, error => error.code === code, code);

both('approve: the record starts with its authority, on its feeds, and sends nothing itself', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), id = await asked(w, who), digest = digestOf(w, id), at = new Date(h.now).toISOString(), calls = h.simulator.calls.length;
  const answer = approve(w, id, digest), record = w.record(id), {entry} = h.itemOf('feed-synced');
  assert.deepEqual(answer, {id, status: 'starting', updatedAt: at});
  assert.equal(h.simulator.calls.length, calls, 'an approval sends nothing');
  assert.deepEqual([record.status, record.approvedAt, record.approvalDigest, record.feeds.length, record.pending], ['starting', at, digest, 1, record.feeds]);
  assert.deepEqual(record.authority, authorityOf(record, h.connection(), h.permissions.triggerDecision(h.connection(), entry)));
  assert.deepEqual(record.approvedBy, designated ? h.owner : undefined);
  await w.engine.pollNow(id);
  assert.equal(w.record(id).status, 'active');
});

both('one approval, one write, one event, and a re-poll gives none', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), id = await asked(w, who);
  approve(w, id);
  await w.engine.pollNow(id);
  await written(w, w.record(id), 'Hello');
  const first = await page(who);
  assert.deepEqual(first.events.map(event => [event.subscriptionId, event.fields.name]), [[id, 'Hello']]);
  await w.engine.pollNow(id);
  assert.equal((await page(who, {after: first.next})).events.length, 0);
});

both('approve: a row moved between view and approve refuses, and the page\'s next read carries the new digest', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), id = await asked(w, who), shown = digestOf(w, id), frozen = w.record(id);
  h.setRow('fixture.items.read', 'allow');
  refused(() => approve(w, id, shown), 'digest_mismatch');
  assert.deepEqual(w.record(id), frozen, 'a refusal stores nothing');
  assert.equal(w.audits('trigger.approved').length, 0);
  assert.equal(approve(w, id).status, 'starting');
});

both('approve: no digest, a digest of another shape and another record\'s digest refuse', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), id = await asked(w, who), other = await asked(w, who, 'feed-listed');
  for (const digest of [undefined, null, 7, '', 'f'.repeat(64), digestOf(w, other), w.record(id).authority]) refused(() => w.subscriptions.approve(id, digest, w.h.owner ?? undefined), 'digest_mismatch');
  assert.equal(w.record(id).status, 'awaiting_approval');
});

both('approve: the digest compared is the one shown now, not the one stored at subscribe', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), id = await asked(w, who), atSubscribe = w.record(id).approvalDigest;
  assert.equal(digestOf(w, id), atSubscribe);
  h.setRow('fixture.items.read', 'allow');
  assert.notEqual(digestOf(w, id), atSubscribe);
  refused(() => approve(w, id, atSubscribe), 'digest_mismatch');
});

both('approve: expired refuses, whether it lapsed just now or earlier', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), id = await asked(w, who), digest = digestOf(w, id);
  h.advance(30 * MINUTE);
  refused(() => approve(w, id, digest), 'approval_expired');
  assert.deepEqual([w.record(id).status, w.audits('trigger.expired').length], ['expired', 1]);
  refused(() => approve(w, id, digest), 'approval_expired');
  assert.equal(w.audits('trigger.expired').length, 1);
});

both('approve: a second approve answers not_awaiting_approval, and so does a decided request', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), id = await asked(w, who), digest = digestOf(w, id), other = await asked(w, who, 'feed-listed');
  approve(w, id, digest);
  refused(() => approve(w, id, digest), 'not_awaiting_approval');
  assert.equal(w.audits('trigger.approved').length, 1);
  decline(w, other);
  refused(() => approve(w, other, 'd'), 'not_awaiting_approval');
  refused(() => decline(w, other), 'not_awaiting_approval');
  refused(() => decline(w, id), 'not_awaiting_approval');
});

both('an unknown id answers not_found', async (t, designated) => {
  const w = world(t, {designated});
  refused(() => approve(w, randomUUID(), 'd'), 'not_found');
  refused(() => decline(w, randomUUID()), 'not_found');
});

both('approve: any gate failure refuses, a failed renewal included, and stores nothing', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), id = await asked(w, who), frozen = w.record(id);
  const stands = change => { const undo = change(); refused(() => approve(w, id), 'permission_denied'); assert.deepEqual(w.record(id), frozen); undo(); };
  stands(() => { h.setRow('fixture.items.read', 'deny'); return () => h.setRow('fixture.items.read', 'allow'); });
  stands(() => { const account = h.connection(); h.store.put('connections', {...account, status: 'reconnect_required'}); return () => h.store.put('connections', account); });
  stands(() => { const grant = h.store.get('clientGrants', who.id); h.store.put('clientGrants', {...grant, status: 'revoked'}); return () => h.store.put('clientGrants', grant); });
  assert.equal(approve(w, id).status, 'starting');
});

both('approve: a client revoked while the request waits closes it, and an approval finds it closed', async (t, designated) => {
  const w = world(t, {designated}), who = w.agent(), id = await asked(w, who), digest = digestOf(w, id);
  w.protocol.revokeClient(who.id);
  assert.deepEqual([w.record(id).status, w.record(id).reason], ['expired', 'client_ended']);
  refused(() => approve(w, id, digest), 'approval_expired');
});

both('approve: the 21st watch on an account is refused there too, and the 20th is not refused by itself', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), last = await asked(w, who), id = await asked(w, who, 'feed-listed');
  for (let n = 0; n < 18; n++) h.watch('feed-tagged', {args: {n}, clientId: 'client-1'});
  assert.equal(approve(w, id).status, 'starting', 'it is the 20th, counting the request that is still waiting');
  h.watch('feed-tagged', {args: {n: 18}, clientId: 'client-1'});
  const frozen = w.record(last);
  refused(() => approve(w, last), 'subscription_limit');
  assert.deepEqual(w.record(last), frozen);
  assert.equal(w.audits('trigger.approved').length, 1);
});

both('approve: the 11th waiting request of a client is refused there too, and the 10th is not refused by itself', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), id = await asked(w, who), later = new Date(h.now + 10 * MINUTE).toISOString();
  const others = Array.from({length: 10}, (_, n) => h.watch('feed-listed', {status: 'awaiting_approval', clientId: who.id, args: {n}, approvalExpiresAt: later}));
  refused(() => approve(w, id), 'pending_limit');
  h.store.put('subscriptions', {...others[0], status: 'removed'});
  assert.equal(approve(w, id).status, 'starting');
});

both('approve: the answer checks what attach() wrote, since it pauses when it refuses', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), id = await asked(w, who);
  h.runtime.actions = {...h.runtime.actions, triggerPollInputs: () => ['label']};
  const answer = approve(w, id);
  assert.deepEqual([answer.status, answer.reason], ['paused', 'definition_changed']);
  assert.equal(w.record(id).detail, 'poll_input');
  assert.equal(w.audits('trigger.approved').length, 1);
  assert.equal(w.audits('trigger.paused').length, 1);
});

both('decline: the request closes, sends nothing, and frees the same args', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), id = await asked(w, who);
  assert.deepEqual(decline(w, id), {id, status: 'declined', updatedAt: new Date(h.now).toISOString()});
  assert.deepEqual([w.record(id).status, w.record(id).feeds, h.simulator.calls.length], ['declined', [], 0]);
  assert.notEqual(await asked(w, who), id);
  assert.equal(w.subscriptions.health(w.record(id)), null);
});

both('each change of standing writes one audit row with ids only, and polls write none', async (t, designated) => {
  const w = world(t, {designated}), {h} = w, who = w.agent(), search = {kinds: ['note']}, id = await asked(w, who, 'feed-updated', search), second = await asked(w, who, 'feed-listed'), principal = h.owner ?? undefined;
  const ids = (type, subscriptionId, triggerId) => ({type, subscriptionId, clientId: who.id, connectionId: h.account, appId: 'fixture', triggerId});
  const rows = () => h.store.list('activity').filter(row => row.type.startsWith('trigger.')).map(({id: _id, createdAt: _at, at: _when, ...row}) => row);
  decline(w, second);
  approve(w, id);
  await w.engine.pollNow(id);
  await written(w, w.record(id));
  await w.engine.pollNow(id);
  w.subscriptions.pause(id, principal);
  w.subscriptions.resume(id, digestOf(w, id), principal);
  w.subscriptions.remove(id, principal);
  assert.deepEqual(rows(), [ids('trigger.requested', id, h.triggerId('feed-updated')), ids('trigger.requested', second, h.triggerId('feed-listed')), ids('trigger.declined', second, h.triggerId('feed-listed')), ids('trigger.approved', id, h.triggerId('feed-updated')),
    {...ids('trigger.paused', id, h.triggerId('feed-updated')), reason: 'owner_paused'}, ids('trigger.resumed', id, h.triggerId('feed-updated')), ids('trigger.removed', id, h.triggerId('feed-updated'))]);
  assert.equal(JSON.stringify(rows()).includes('note'), false, 'never args');
  assert.deepEqual([w.record(id).status, Boolean(w.record(id).approvedAt)], ['removed', true], 'after a Remove the record still says it was approved');
  assert.deepEqual(w.record(id).approvedBy, designated ? h.owner : undefined);
});

// ---- server.mjs: nothing here listens on a port ------------------------------------------------------------------------------------------------

test('createApp wires the service to the protocol and the engine, and close() ends a wait promptly', {timeout: 30_000}, async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-subscriptions-server-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const app = await createApp({dataDir: path.join(root, 'data'), port: 0}), connection = {id: randomUUID(), appId: 'workspace', driver: 'workspace', authMethod: 'workspace', status: 'ready', identity: {id: 'test-workspace'}, allowedOrigins: [], createdAt: new Date().toISOString()};
  assert.ok(app.subscriptions instanceof SubscriptionService);
  assert.equal(app.protocol.subscriptions, app.subscriptions);
  app.store.put('connections', connection);
  const {client, token} = app.protocol.createClient({name: 'Agent', bindings: [{connectionId: connection.id, capabilityId: 'workspace.list.v1'}]});
  app.store.put('subscriptions', {id: randomUUID(), clientId: client.id, connectionId: connection.id, status: 'active'});
  const ask = params => app.protocol.handle(`Bearer ${token}`, {protocol: FABRIC_PROTOCOL, id: randomUUID(), method: 'events.list', params});
  const woken = ask({waitSeconds: 25});
  assert.equal(await pending(woken), true);
  app.triggers.notify(client.id);
  assert.equal((await within(woken)).result.latest, 0, 'the engine reaches a wait through notify');
  assert.deepEqual((await ask({})).result, {events: [], next: 0, latest: 0, trimmed: 0});
  const waiting = ask({waitSeconds: 25}), started = performance.now();
  assert.equal(await pending(waiting), true);
  await app.close();
  assert.ok(performance.now() - started < 5000, 'server.close() is not held up by a wait');
  assert.equal((await within(waiting)).result.latest, 0);
});

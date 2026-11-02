import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {hostedSetup} from './fixtures/hosted-fixture.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';
import {Store} from '../lib/store.mjs';

// Section 8, room left for triggers and events (Iteration 9): the subscriptions collection is already in the end-user
// delete cascade, and eventDestinations is reserved on every environment and cannot be set yet.
test('deleting an end user also erases their subscriptions; eventDestinations is reserved and refused', async t => {
  const {app, keys, call, repo, account, userOf} = await hostedSetup(t);
  const ref = await account('u1', 'g-1'), user = userOf('u1');
  await account('u2', 'g-2');
  const theirs = stampOwner({id: randomUUID(), kind: 'reserved'}, {subjectId: 'u1', userRecordId: user.id});
  const byAccount = {id: randomUUID(), connectionId: ref}, other = stampOwner({id: randomUUID(), kind: 'reserved'}, {subjectId: 'u2', userRecordId: userOf('u2').id});
  for (const row of [theirs, byAccount, other]) repo().put('subscriptions', row);
  assert.equal((await call(keys.full, 'DELETE', '/v1/users/u1')).status, 200);
  assert.deepEqual(repo().list('subscriptions').map(row => row.id), [other.id], 'only the other person\'s row is left');
  const environment = app.registry.list('environments')[0];
  assert.deepEqual(environment.eventDestinations, []);
  const refused = await call(keys.full, 'PATCH', '/v1/environment', {eventDestinations: [{url: 'https://hooks.example/fabric'}]});
  assert.equal(refused.status, 422); assert.equal(refused.body.error.code, 'not_available');
  assert.deepEqual(app.registry.get('environments', environment.id).eventDestinations, [], 'nothing was set');
});

// Iteration 9, part 1b: the erase reaches the trigger tables too. A ready account loses them at its disconnect; an account disconnected earlier
// is not disconnected again, so only the delete's own step can take what is left of it. Tenant polling waits for hosting, so the environment's
// repository cannot write rows here: a second handle on its file does.
test('deleting an end user erases their feeds, runs, seen rows and events, on a ready account and on one already disconnected; another person\'s stay', async t => {
  const {app, scope, keys, call, repo, account} = await hostedSetup(t);
  const ready = await account('u1', 'g-1'), gone = await account('u1', 'g-3'), kept = await account('u2', 'g-2');
  repo().put('connections', {...repo().get('connections', gone), status: 'revoked'});
  const direct = new Store({dataDir: app.stores.open(scope).folder});
  t.after(() => direct.close());
  for (const [connectionId, n] of [[ready, 1], [gone, 2], [kept, 3]]) {
    repo().put('triggerFeeds', {id: `feed-${n}`, connectionId});
    repo().put('triggerRuns', {id: `feed-${n}`, connectionId, runs: []});
    direct.appendPoll({feedId: `feed-${n}`, seen: [{lens: 'lens', itemKey: `hashed-${n}`, valueHash: 'value', generation: 1, connectionId}],
      events: [{clientId: 'client', subscriptionId: `sub-${n}`, dedupeKey: `key-${n}`, connectionId, kind: 'trigger.event', createdAt: 1, expiresAt: Date.UTC(2030, 0, 1), payload: {n}}]});
  }
  assert.equal((await call(keys.full, 'DELETE', '/v1/users/u1')).status, 200);
  assert.deepEqual([repo().list('triggerFeeds').map(row => row.id), repo().list('triggerRuns').map(row => row.id)], [['feed-3'], ['feed-3']]);
  const accounts = table => direct.db.prepare(`SELECT connection_id FROM ${table}`).all().map(row => row.connection_id);
  assert.deepEqual([accounts('trigger_events'), accounts('trigger_seen')], [[kept], [kept]], 'only the other person\'s rows are left');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {hostedSetup} from './fixtures/hosted-fixture.mjs';
import {stampOwner} from '../lib/tenant/deployment.mjs';

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

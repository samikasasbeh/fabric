import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {hostedSetup} from './fixtures/hosted-fixture.mjs';
import {tellOpener, finish} from '../public/hosted-base.js';

// Section 6.6: a Connect link opened in the developer's popup tells its opener how it ended, by postMessage to the
// session's own opener origin (one of the environment's openerOrigins), never '*', with no names or emails. Polling
// GET /v1/connect-sessions/:id stays the authoritative signal.
const APP = 'http://localhost:5173';

test('openerOrigin must be an exact origin from the environment\'s list, for every purpose', async t => {
  const {keys, call, account} = await hostedSetup(t);
  await account('u1', 'g-1');
  const make = body => call(keys.full, 'POST', '/v1/connect-sessions', {externalUserId: 'u1', ...body});
  assert.equal((await make({appId: 'github', openerOrigin: APP})).body.error.code, 'opener_not_allowed', 'not in the list yet');
  assert.equal((await call(keys.full, 'PATCH', '/v1/environment', {openerOrigins: [APP]})).status, 200);
  for (const bad of [`${APP}/settings`, `${APP}/`, 'http://localhost:5174', 'javascript:alert(1)', 5173]) assert.equal((await make({appId: 'github', openerOrigin: bad})).body.error.code, 'opener_not_allowed', String(bad));
  assert.equal((await make({appId: 'github', openerOrigin: APP})).status, 201);
  assert.equal((await make({purpose: 'manage', openerOrigin: APP})).status, 201);
});

test('a finished session gives its page the message for its opener: state and refs only, never a name', async t => {
  const {app, keys, call, repo, account, ask, open} = await hostedSetup(t);
  const ref = await account('u1', 'g-1');
  await call(keys.full, 'PATCH', '/v1/environment', {openerOrigins: [APP]});
  // A connect link that ended connected.
  const connect = await open(keys.full, {externalUserId: 'u1', appId: 'gmail', openerOrigin: APP});
  repo().put('connectSessions', {...repo().get('connectSessions', connect.id), state: 'connected', completedAt: app.registry.now(), result: {appId: 'gmail', accountRef: ref, renewal: false}});
  const done = (await connect.person.call('GET', `/connect/${connect.id}/v1/view`)).body;
  assert.deepEqual(done.opener, {origin: APP, message: {type: 'fabric.connect', sessionId: connect.id, state: 'connected', appId: 'gmail', accountRef: ref}});
  assert.equal(JSON.stringify(done.opener).includes('example.com'), false, 'no email or name in the message');
  // Closed: cancelled with its code. Without an opener origin there is no message at all.
  const closing = await open(keys.full, {externalUserId: 'u1', appId: 'gmail', openerOrigin: APP});
  assert.deepEqual((await closing.person.call('POST', `/connect/${closing.id}/v1/close`, {})).body.opener.message, {type: 'fabric.connect', sessionId: closing.id, state: 'cancelled', errorCode: 'cancelled'});
  const plain = await open(keys.full, {externalUserId: 'u1', appId: 'gmail'});
  assert.equal((await plain.person.call('POST', `/connect/${plain.id}/v1/close`, {})).body.opener, undefined);
  // Manage Done and an approval decision end completed.
  const manage = await open(keys.full, {externalUserId: 'u1', purpose: 'manage', openerOrigin: APP});
  assert.deepEqual((await manage.person.call('POST', `/connect/${manage.id}/v1/close`, {})).body.opener.message, {type: 'fabric.connect', sessionId: manage.id, state: 'completed'});
  const waiting = await ask('u1');
  const approve = await open(keys.approve, {externalUserId: 'u1', purpose: 'approve', callRef: waiting.callRef, openerOrigin: APP});
  const shown = (await approve.person.call('GET', `/connect/${approve.id}/v1/approval`)).body.approval;
  const decided = (await approve.person.call("POST", shown.cancel.path, shown.cancel.body)).body;
  assert.deepEqual(decided.opener, {origin: APP, message: {type: 'fabric.connect', sessionId: approve.id, state: 'completed'}});
});

test('the pages post only to the session\'s opener origin, never \'*\'; a popup closes, a full page goes back', () => {
  for (const name of ['connect.js', 'hosted-base.js', 'hosted-approve.js', 'hosted-app.js', 'hosted-catalog.js', 'hosted-activity.js']) {
    const source = readFileSync(new URL(`../public/${name}`, import.meta.url), 'utf8');
    for (const call of source.matchAll(/postMessage\(([^)]*)\)/g)) assert.match(call[1], /, (view|result)\.opener\.origin$/, `${name}: ${call[0]}`);
    assert.equal(/postMessage\([^)]*['"`]\*['"`]/.test(source), false, `${name} posts to '*'`);
  }
  const sent = [], opener = {closed: false, postMessage: (message, origin) => sent.push({message, origin})};
  const result = {state: 'completed', redirect: `${APP}/back`, opener: {origin: APP, message: {type: 'fabric.connect', sessionId: 'cs_x', state: 'completed'}}};
  assert.equal(tellOpener(result, opener), true); assert.deepEqual(sent, [{message: result.opener.message, origin: APP}]);
  assert.equal(tellOpener(result, {closed: true, postMessage: () => assert.fail('a closed opener is never told')}), false);
  assert.equal(tellOpener({state: 'completed'}, opener), false, 'no opener origin, no message');
  return (async () => {
    const steps = [], api = async () => result, base = {close: '/connect/cs_x/v1/close'};
    await finish(api, base, {assign: url => steps.push(`assign ${url}`), opener, close: () => steps.push('close')});
    await finish(api, base, {assign: url => steps.push(`assign ${url}`), opener: null, close: () => steps.push('close')});
    assert.deepEqual(steps, ['close', `assign ${APP}/back`]);
  })();
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {CONTINUATIONS} from '../lib/continuations.mjs';
import {owner, fixture} from './fixtures/continuation-fixture.mjs';

// F02.3a review fixes: limits that ignore overdue requests, integrity of the state fields,
// recovery that never aborts startup, clock steps, detached dispatch, drift and
// owner-visible closures. Isolated temporary stores and a synthetic provider only.
const created = async (f, token, client, id, cap) => (await f.invoke(token, 'calls.create', f.ask(client, cap), id)).result;
const audits = (f, type) => f.store.list('activity').filter(event => event.type === type);

test('overdue handoffs free their per-client slot and the owner badge agrees', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  for (let i = 0; i < 10; i++) assert.equal((await created(f, token, client, `p${i}`)).status, 'awaiting_connection');
  assert.equal((await f.invoke(token, 'calls.create', f.ask(client), 'p10')).error.code, 'pending_limit');
  assert.equal(f.service.pendingCount(), 10);
  f.advance(31 * 60_000);
  assert.equal(f.service.pendingCount(), 0);
  assert.equal((await created(f, token, client, 'p11')).status, 'awaiting_connection', 'nobody had to read the overdue records first');
  assert.equal(f.service.pendingCount(), 1);
});

test('the global limit holds across clients, and a decline or a lapsed grant frees a slot', async t => {
  const f = await fixture(t);
  const grants = Array.from({length: 5}, () => f.grant());
  for (const [g, {client, token}] of grants.entries()) for (let i = 0; i < 10; i++) await created(f, token, client, `g${g}-${i}`);
  const sixth = f.grant();
  assert.equal((await f.invoke(sixth.token, 'calls.create', f.ask(sixth.client), 'six-a')).error.code, 'pending_limit');
  const first = f.store.list(CONTINUATIONS)[0];
  await f.service.decline(first.id, {}, owner);
  assert.equal((await created(f, sixth.token, sixth.client, 'six-b')).status, 'awaiting_connection');
  assert.equal((await f.invoke(sixth.token, 'calls.create', f.ask(sixth.client), 'six-c')).error.code, 'pending_limit');
  // Grants that lapse take their waiting requests with them, without any read.
  const g = f.protocol.createClient({name: 'Short', bindings: [], expiresInSeconds: 120, requestable: [{capabilityId: f.read.id}]}, owner);
  assert.equal((await f.invoke(g.token, 'calls.create', f.ask(g.client), 'short')).error.code, 'pending_limit');
  f.advance(31 * 60_000);
  const late = f.grant();
  assert.equal((await created(f, late.token, late.client, 'late')).status, 'awaiting_connection');
});

test('a capability edited after the grant is refused at create, and while waiting it fails the handoff', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  const waiting = await created(f, token, client, 'drift-wait');
  f.store.put('capabilities', {...f.read, description: 'Edited after the grant'});
  const refused = await f.invoke(token, 'calls.create', f.ask(client), 'drift-create');
  assert.equal(refused.error.code, 'grant_changed');
  assert.equal(f.store.list('protocolRequests').filter(row => row.requestId === 'drift-create').length, 0, 'no reservation');
  assert.equal(f.store.list(CONTINUATIONS).length, 1);
  const view = (await f.invoke(token, 'calls.get', {callId: waiting.id})).result;
  assert.equal(view.status, 'failed'); assert.equal(view.handoff.outcome, 'authority_changed');
  assert.deepEqual(f.jobs(), []);
});

test('the view digest binds identity display fields and the authority generation even with no saved policy', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const a = await created(f, token, client, 'digest-identity');
  const generation = f.store.connectionGeneration('acct-a');
  const seen = f.view(a.id).viewDigest;
  f.store.put('connections', {...f.store.get('connections', 'acct-a'), identity: {id: '101', displayName: 'someone-else', email: 'else@example.test'}});
  assert.equal(f.store.connectionGeneration('acct-a'), generation, 'precondition: display fields do not move the generation');
  await assert.rejects(f.select(a.id, 'acct-a', seen), error => error.code === 'view_changed');
  assert.equal(f.store.get(CONTINUATIONS, a.id).status, 'awaiting_owner');
  const b = await created(f, token, client, 'digest-generation');
  const seenB = f.view(b.id).viewDigest, modeBefore = f.view(b.id).accounts[0].policy.mode;
  f.store.put('connections', {...f.store.get('connections', 'acct-a'), authRevision: 'reconnected'});
  assert.ok(f.store.connectionGeneration('acct-a') > generation, 'precondition: a reconnect advances the generation');
  assert.equal(f.view(b.id).accounts[0].policy.mode, modeBefore, 'precondition: the default policy mode is unchanged');
  await assert.rejects(f.select(b.id, 'acct-a', seenB), error => error.code === 'view_changed');
  assert.deepEqual(f.jobs(), []); assert.equal(f.calls.length, 0);
});

test('state fields are integrity-checked: a rolled-back handoff cannot bind a second job', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = await created(f, token, client, 'rollback');
  await f.select(handoff.id, 'acct-a'); await f.service.settled(handoff.id);
  assert.equal(f.calls.length, 1);
  const resumed = f.store.get(CONTINUATIONS, handoff.id);
  // Status rolled back alone: the binding no longer agrees with it.
  f.store.put(CONTINUATIONS, {...resumed, status: 'awaiting_owner'});
  assert.throws(() => f.view(handoff.id), error => error.code === 'authority_changed');
  // A full rollback that agrees with itself is still refused, because the job already exists.
  f.store.put(CONTINUATIONS, {...resumed, status: 'awaiting_owner', binding: null});
  const digest = f.view(handoff.id).viewDigest;
  await assert.rejects(f.service.select(handoff.id, {connectionId: 'acct-a', viewDigest: digest}, owner), error => error.code === 'authority_changed');
  assert.equal(f.store.get(CONTINUATIONS, handoff.id).outcome.code, 'fabric_failed');
  await f.service.drain();
  assert.equal(f.jobs().length, 1); assert.equal(f.calls.length, 1);
});

test('unhashed record fields are checked, and calls.cancel on an unreadable record answers outcome_unknown', async t => {
  const f = await fixture(t);
  const a = f.grant(), b = f.grant();
  const handoff = await created(f, a.token, a.client, 'tamper-fields');
  const original = f.store.get(CONTINUATIONS, handoff.id);
  // Pointing the record at client B never shows B the request.
  f.store.put(CONTINUATIONS, {...original, clientId: b.client.id});
  for (const method of ['calls.get', 'calls.cancel']) {
    assert.equal((await f.invoke(b.token, method, {callId: handoff.id})).error.code, 'outcome_unknown', `B ${method}`);
    assert.equal((await f.invoke(a.token, method, {callId: handoff.id})).error.code, 'not_found', `A ${method}`);
  }
  for (const tamper of [{requestId: 'other'}, {schemaVersion: 2}, {revision: 0}, {status: 'mystery'}, {outcome: {code: 'owner_declined'}}]) {
    f.store.put(CONTINUATIONS, {...original, ...tamper});
    for (const method of ['calls.get', 'calls.cancel']) assert.equal((await f.invoke(a.token, method, {callId: handoff.id})).error.code, 'outcome_unknown', `${JSON.stringify(tamper)} ${method}`);
  }
  f.store.put(CONTINUATIONS, original);
  assert.equal((await f.invoke(a.token, 'calls.get', {callId: handoff.id})).result.status, 'awaiting_connection');
});

test('another client cannot tell a tampered handoff id from an unknown one', async t => {
  const f = await fixture(t);
  const a = f.grant(), b = f.grant();
  const handoff = await created(f, a.token, a.client, 'oracle');
  f.store.put(CONTINUATIONS, {...f.store.get(CONTINUATIONS, handoff.id), requestHash: 'f'.repeat(64)});
  for (const method of ['calls.get', 'calls.cancel']) {
    assert.equal((await f.invoke(b.token, method, {callId: handoff.id})).error.code, 'not_found');
    assert.equal((await f.invoke(b.token, method, {callId: '00000000-0000-4000-8000-000000000000'})).error.code, 'not_found');
  }
});

test('unreadable records stay visible to the owner as closed and do not count as pending', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  const good = await created(f, token, client, 'good'), bad = await created(f, token, client, 'bad');
  f.store.put(CONTINUATIONS, {...f.store.get(CONTINUATIONS, bad.id), args: {owner: 'evil'}, requestHash: 'f'.repeat(64)});
  const rows = f.service.ownerList();
  const row = rows.find(item => item.id === bad.id);
  assert.equal(row.integrity, 'failed'); assert.equal(row.phase, 'closed'); assert.equal(row.outcome.code, 'fabric_failed');
  assert.ok(rows.some(item => item.id === good.id && item.phase === 'awaiting_owner'));
  assert.equal(f.service.pendingCount(), 1);
});

test('recovery never aborts startup: a malformed binding is closed failed with an integrity audit', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  const handoff = await created(f, token, client, 'null-binding');
  const record = f.store.get(CONTINUATIONS, handoff.id);
  f.store.put(CONTINUATIONS, {...record, status: 'binding', binding: null, revision: record.revision + 1});
  assert.doesNotThrow(() => f.reopen());
  const stored = f.store.get(CONTINUATIONS, handoff.id);
  assert.equal(stored.status, 'failed'); assert.equal(stored.outcome.code, 'fabric_failed');
  const event = audits(f, 'continuation.failed').find(item => item.continuationId === handoff.id);
  assert.equal(event.reason, 'integrity'); assert.equal(event.code, 'fabric_failed'); assert.equal(event.clientId, undefined);
  const seen = (await f.invoke(token, 'calls.get', {callId: handoff.id})).result;
  assert.equal(seen.status, 'failed'); assert.equal(seen.handoff.outcome, 'fabric_failed');
});

test('recovery expires overdue handoffs and fails tampered waiting ones before any read', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  const overdue = await created(f, token, client, 'overdue');
  const tampered = await created(f, token, client, 'tampered-wait');
  f.store.put(CONTINUATIONS, {...f.store.get(CONTINUATIONS, tampered.id), grantEntryHash: 'f'.repeat(64)});
  f.advance(31 * 60_000);
  f.reopen();
  const expired = f.store.get(CONTINUATIONS, overdue.id);
  assert.equal(expired.status, 'expired'); assert.equal(expired.outcome.code, 'continuation_expired');
  const failed = f.store.get(CONTINUATIONS, tampered.id);
  assert.equal(failed.status, 'failed'); assert.equal(failed.outcome.code, 'fabric_failed');
});

test('recovery of a crashed binding with a queued job: the job turns uncertain and is never replayed', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const queued = await created(f, token, client, 'crash-queued');
  const dispatch = f.service.dispatch.bind(f.service);
  f.service.dispatch = () => {}; // crash before the derived job ran
  await f.select(queued.id, 'acct-a');
  f.service.dispatch = dispatch;
  const record = f.store.get(CONTINUATIONS, queued.id);
  assert.equal(f.store.get('jobs', record.binding.jobId).status, 'queued');
  f.store.put(CONTINUATIONS, {...record, status: 'binding', binding: {...record.binding, derivedRequestHash: null}});
  f.reopen();
  assert.equal(f.store.get(CONTINUATIONS, queued.id).status, 'resumed');
  assert.equal(f.store.get('jobs', record.binding.jobId).status, 'uncertain');
  assert.equal(f.calls.length, 0, 'never replayed after restart');
});

test('recovery cancels a derived job whose stored binding no longer matches it, and a pending approval survives restart', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const args = {owner: 'o', repo: 'r', body: {title: 't'}};
  const mismatched = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'mismatch')).result;
  const kept = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'kept')).result;
  const jobA = (await f.select(mismatched.id, 'acct-a')).derived.jobId, jobB = (await f.select(kept.id, 'acct-a')).derived.jobId;
  const a = f.store.get(CONTINUATIONS, mismatched.id);
  f.store.put(CONTINUATIONS, {...a, status: 'binding', binding: {...a.binding, generation: a.binding.generation + 7, derivedRequestHash: null}});
  f.reopen();
  assert.equal(f.store.get('jobs', jobA).status, 'cancelled');
  const failed = f.store.get(CONTINUATIONS, mismatched.id);
  assert.equal(failed.status, 'failed'); assert.equal(failed.outcome.code, 'authority_changed');
  const job = f.store.get('jobs', jobB);
  assert.equal(job.status, 'awaiting_approval');
  await f.runtime.approve(job.id, job.approvalDigest, owner);
  assert.equal(f.calls.length, 1);
});

test('a wall clock stepping back is not tampering, in process or across a restart', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = await created(f, token, client, 'clock');
  f.advance(-5 * 60_000);
  assert.equal((await f.invoke(token, 'calls.get', {callId: handoff.id})).result.status, 'awaiting_connection');
  assert.equal(f.view(handoff.id).phase, 'awaiting_owner');
  f.reopen();
  assert.equal(f.store.get(CONTINUATIONS, handoff.id).status, 'awaiting_owner');
  f.advance(5 * 60_000);
  await f.select(handoff.id, 'acct-a'); await f.service.settled(handoff.id);
  assert.equal(f.calls.length, 1);
});

test('a detached derived job never leaks a rejection, is drained, and is not retained after it settles', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = await created(f, token, client, 'detached');
  const unhandled = [];
  const listener = reason => unhandled.push(reason);
  process.on('unhandledRejection', listener); t.after(() => process.off('unhandledRejection', listener));
  f.runtime.execute = async () => { throw new Error('provider exploded'); };
  const audit = f.store.audit.bind(f.store);
  f.store.audit = event => { if (event.type === 'continuation.dispatch_failed') throw new Error('store closed'); return audit(event); };
  await f.select(handoff.id, 'acct-a');
  await f.service.drain();
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(unhandled, []);
  assert.equal(f.service.dispatches.size, 0);
});

test('an owner action that closes the request on read reports why, with the fresh view', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const retired = await created(f, token, client, 'closing-retired');
  const seenRetired = f.view(retired.id).viewDigest;
  f.store.put('capabilities', {...f.read, status: 'disabled'});
  assert.equal(f.service.pendingCount(), 0, 'another reader (the owner badge) applies the closure first');
  await assert.rejects(f.service.select(retired.id, {connectionId: 'acct-a', viewDigest: seenRetired}, owner),
    error => error.code === 'capability_retired' && error.view?.phase === 'closed');
  f.store.put('capabilities', f.read);
  const edited = await created(f, token, client, 'closing-edited');
  const seenEdited = f.view(edited.id).viewDigest;
  f.store.put('capabilities', {...f.read, description: 'Edited while the owner looked'});
  await assert.rejects(f.service.select(edited.id, {connectionId: 'acct-a', viewDigest: seenEdited}, owner),
    error => error.code === 'authority_changed' && error.view?.outcome?.code === 'authority_changed');
  f.store.put('capabilities', f.read);
  const revoked = await created(f, token, client, 'closing-revoked');
  const seenRevoked = f.view(revoked.id).viewDigest;
  f.store.put('clientGrants', {...f.store.get('clientGrants', client.id), expiresAt: new Date(f.now - 1).toISOString()});
  await assert.rejects(f.service.select(revoked.id, {connectionId: 'acct-a', viewDigest: seenRevoked}, owner),
    error => error.code === 'client_revoked' && error.view?.phase === 'closed');
  await assert.rejects(f.service.select(revoked.id, {connectionId: 'acct-a', viewDigest: seenRevoked}, owner), error => error.code === 'client_revoked', 'a second try still says why');
  assert.deepEqual(f.jobs(), []);
});

test('a reservation that points at another client\'s handoff replays as outcome_unknown', async t => {
  const f = await fixture(t);
  const a = f.grant(), b = f.grant();
  const theirs = await created(f, a.token, a.client, 'a-1');
  const mine = await created(f, b.token, b.client, 'b-1');
  const key = f.store.list('protocolRequests').find(row => row.clientId === b.client.id && row.requestId === 'b-1').id;
  f.store.put('protocolRequests', {...f.store.get('protocolRequests', key), continuationId: theirs.id});
  assert.equal((await f.invoke(b.token, 'calls.create', f.ask(b.client), 'b-1')).error.code, 'outcome_unknown');
  f.store.put('protocolRequests', {...f.store.get('protocolRequests', key), continuationId: mine.id});
  assert.equal((await f.invoke(b.token, 'calls.create', f.ask(b.client), 'b-1')).result.id, mine.id);
});

test('grant audit records request-only authority, and the resumed audit carries the job once', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const granted = audits(f, 'client.granted').find(event => event.clientId === client.id);
  assert.equal(granted.operationCount, 0); assert.equal(granted.requestableCount, 2);
  const handoff = await created(f, token, client, 'audit');
  await f.select(handoff.id, 'acct-a'); await f.service.settled(handoff.id);
  const resumed = audits(f, 'continuation.resumed').filter(event => event.continuationId === handoff.id);
  assert.equal(resumed.length, 1); assert.equal(resumed[0].jobId, f.store.get(CONTINUATIONS, handoff.id).binding.jobId);
});

test('at grant expiry the handoff expires with it, because its lifetime is capped at the grant', async t => {
  const f = await fixture(t);
  const g = f.protocol.createClient({name: 'Short', bindings: [], expiresInSeconds: 600, requestable: [{capabilityId: f.read.id}]}, owner);
  const handoff = await created(f, g.token, g.client, 'short-lived');
  assert.ok(Date.parse(f.store.get(CONTINUATIONS, handoff.id).expiresAt) <= Date.parse(g.client.expiresAt));
  f.advance(11 * 60_000);
  const record = f.service.current(handoff.id);
  assert.equal(record.status, 'expired'); assert.equal(record.outcome.code, 'continuation_expired');
});

test('recovery isolates a record whose processing throws, and keeps recovering the others', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  const healthy = await created(f, token, client, 'healthy');
  const broken = (await f.invoke(token, 'calls.create', f.ask(client, f.write, {owner: 'o', repo: 'r', body: {title: 't'}}), 'broken')).result;
  // A stored operation that can no longer be described makes the lazy drift check throw.
  f.store.put('capabilities', {...f.write, request: {...f.write.request, method: 5}});
  assert.throws(() => f.runtime.capabilityReference(f.store.get('capabilities', f.write.id)), 'precondition: processing this record throws');
  assert.doesNotThrow(() => f.reopen());
  assert.equal(f.store.get(CONTINUATIONS, healthy.id).status, 'awaiting_owner');
  const failed = f.store.get(CONTINUATIONS, broken.id);
  assert.equal(failed.status, 'failed'); assert.equal(failed.outcome.code, 'fabric_failed');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createApp} from '../server.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {CONTINUATIONS, ContinuationService} from '../lib/continuations.mjs';
import {owner, fixture} from './fixtures/continuation-fixture.mjs';
import {fixture as httpFixture, freePort, doc} from './fixtures/signin-fixture.mjs';

// Second review fixes (5b1c3b2): approve keeps a merely-not-ready answer, recovery labels why a record
// failed and cancels only the job it owns, /api/clients status codes, and closure reasons whoever read
// the record first. Isolated temporary stores, loopback ports and synthetic providers only.
const args = {owner: 'o', repo: 'r', body: {title: 'Synthetic issue'}};
const NOT_READY = 'Connection is not ready. Check or reconnect it first.';
const CHANGED = 'Connection authorization or permission setting changed. Create a new request.';
const audits = (f, type) => f.store.list('activity').filter(event => event.type === type);
const failedAudit = (f, id) => audits(f, 'continuation.failed').filter(event => event.continuationId === id);

/** A write handoff bound to `connectionId` under the default Ask, plus an owner-made job on the same account. */
async function awaitingApproval(f, client, token, connectionId, requestId) {
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), requestId)).result;
  const derived = f.store.get('jobs', (await f.select(handoff.id, connectionId)).derived.jobId);
  const own = await f.runtime.createJob({connectionId, capabilityId: f.write.id, args}, owner);
  assert.equal(derived.status, 'awaiting_approval', 'precondition: the derived write waits for approval');
  assert.equal(own.status, 'awaiting_approval', 'precondition: the owner-made write waits for approval');
  assert.equal(own.source.continuationId, undefined, 'precondition: the owner-made job is not continuation-derived');
  return {handoff, derived, own};
}
const update = (f, id, changes) => f.store.put('connections', {...f.store.get('connections', id), ...changes});

// ---- (a) approve on a continuation-derived Ask write -------------------------------------

test('approve answers the original readiness error when the bound account is merely not ready', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const {handoff, derived, own} = await awaitingApproval(f, client, token, 'acct-a', 'not-ready');
  const generation = f.store.connectionGeneration('acct-a');
  update(f, 'acct-a', {status: 'unavailable', error: 'Provider unreachable', lastCheckedAt: new Date(f.now).toISOString()});
  assert.equal(f.store.connectionGeneration('acct-a'), generation, 'precondition: health fields keep the generation');
  for (const [name, job] of [['derived job', derived], ['owner job', own]]) {
    await assert.rejects(f.runtime.approve(job.id, job.approvalDigest, owner),
      error => error.message === NOT_READY && error.code === undefined && error.httpStatus === undefined, name);
  }
  assert.equal(f.store.get('jobs', derived.id).status, 'awaiting_approval');
  assert.equal(f.store.get(CONTINUATIONS, handoff.id).status, 'resumed');
  // The same approval succeeds once the account is ready again: nothing was closed or poisoned.
  const {error, ...unavailable} = f.store.get('connections', 'acct-a');
  f.store.put('connections', {...unavailable, status: 'ready'});
  assert.equal(f.store.connectionGeneration('acct-a'), generation, 'precondition: recovering readiness keeps the generation');
  assert.equal((await f.runtime.approve(derived.id, derived.approvalDigest, owner)).status, 'uncertain');
  assert.equal(f.calls.length, 1);
});

test('approve answers authority_changed (409) when the bound account was revoked, reconnected or its policy changed', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  const cases = [
    ['revoked', id => update(f, id, {status: 'revoked'}), 1],
    ['reconnected', id => update(f, id, {authRevision: `reconnected-${id}`}), 1],
    ['reconnected and not ready', id => update(f, id, {authRevision: `reconnected-${id}`, status: 'unavailable'}), 1],
    ['policy changed', id => { f.runtime.permissions.set({connectionId: id, capabilityId: f.write.id, mode: 'allow'}); f.runtime.permissions.set({connectionId: id, capabilityId: f.write.id, mode: 'ask'}); }, 0],
  ];
  for (const [index, [name, change, generationStep]] of cases.entries()) {
    const id = `acct-${index}`;
    f.account(id, String(200 + index));
    const {handoff, derived} = await awaitingApproval(f, client, token, id, `changed-${index}`);
    const generation = f.store.connectionGeneration(id);
    change(id);
    assert.equal(f.store.connectionGeneration(id), generation + generationStep, `precondition: ${name} generation`);
    await assert.rejects(f.runtime.approve(derived.id, derived.approvalDigest, owner), error => error.code === 'authority_changed' && error.httpStatus === 409, name);
    assert.equal(f.store.get('jobs', derived.id).status, 'awaiting_approval', `${name}: nothing ran`);
    assert.equal(f.store.get(CONTINUATIONS, handoff.id).status, 'resumed', `${name}: the handoff is not re-derived`);
  }
  assert.equal(f.calls.length, 0);
});

test('a job that was not continued from a handoff keeps its original error in every case', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  const cases = [
    ['not ready', id => update(f, id, {status: 'unavailable', error: 'Provider unreachable'}), NOT_READY],
    ['revoked', id => update(f, id, {status: 'revoked'}), NOT_READY],
    ['reconnected', id => update(f, id, {authRevision: `reconnected-${id}`}), CHANGED],
    ['policy changed', id => { f.runtime.permissions.set({connectionId: id, capabilityId: f.write.id, mode: 'allow'}); f.runtime.permissions.set({connectionId: id, capabilityId: f.write.id, mode: 'ask'}); }, CHANGED],
  ];
  for (const [index, [name, change, message]] of cases.entries()) {
    const id = `own-${index}`;
    f.account(id, String(300 + index));
    const {own} = await awaitingApproval(f, client, token, id, `own-${index}`);
    change(id);
    await assert.rejects(f.runtime.approve(own.id, own.approvalDigest, owner),
      error => error.message === message && error.code === undefined && error.httpStatus === undefined, name);
    assert.equal(f.store.get('jobs', own.id).status, 'awaiting_approval', `${name}: nothing ran`);
  }
  assert.equal(f.calls.length, 0);
});

test('a programming error while approving a derived job is not relabelled authority_changed', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const {derived} = await awaitingApproval(f, client, token, 'acct-a', 'bug');
  const decision = f.runtime.permissions.decision;
  f.runtime.permissions.decision = () => { throw new TypeError('synthetic programming error'); };
  t.after(() => { f.runtime.permissions.decision = decision; });
  await assert.rejects(f.runtime.approve(derived.id, derived.approvalDigest, owner),
    error => error instanceof TypeError && error.message === 'synthetic programming error' && error.code === undefined && error.httpStatus === undefined);
  assert.equal(f.store.get('jobs', derived.id).status, 'awaiting_approval');
  assert.equal(f.calls.length, 0);
});

// ---- (b) failUnreadable labels and job cancellation ----------------------------------------

/** Puts a resumed write handoff back into the crash window between binding and resume. */
function crashedBinding(f, id, binding = {}) {
  const record = f.store.get(CONTINUATIONS, id);
  return {...record, status: 'binding', binding: {...record.binding, derivedRequestHash: null, ...binding}};
}

test('recovery closes a tampered bound record with an integrity audit, cancels the job it owns and lists it as fabric_failed', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const {handoff, derived} = await awaitingApproval(f, client, token, 'acct-a', 'tampered-bound');
  f.store.put(CONTINUATIONS, {...crashedBinding(f, handoff.id), requestHash: 'f'.repeat(64)});
  f.reopen();
  const stored = f.store.get(CONTINUATIONS, handoff.id);
  assert.equal(stored.status, 'failed'); assert.equal(stored.outcome.code, 'fabric_failed');
  const events = failedAudit(f, handoff.id);
  assert.equal(events.length, 1); assert.equal(events[0].reason, 'integrity'); assert.equal(events[0].code, 'fabric_failed');
  assert.equal(f.store.get('jobs', derived.id).status, 'cancelled', 'the pending job this handoff produced can never be approved');
  const row = f.service.ownerList().find(item => item.id === handoff.id);
  assert.equal(row.phase, 'closed'); assert.equal(row.status, 'failed'); assert.equal(row.integrity, 'failed'); assert.deepEqual(row.outcome, {code: 'fabric_failed'});
  assert.equal(f.calls.length, 0);
});

test('recovery of a tampered record never cancels a job that belongs to another handoff', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const theirs = await awaitingApproval(f, client, token, 'acct-a', 'theirs');
  const mine = await awaitingApproval(f, client, token, 'acct-a', 'mine');
  f.store.put(CONTINUATIONS, {...crashedBinding(f, mine.handoff.id, {jobId: theirs.derived.id}), requestHash: 'f'.repeat(64)});
  f.reopen();
  assert.equal(failedAudit(f, mine.handoff.id)[0].reason, 'integrity');
  assert.equal(f.store.get(CONTINUATIONS, mine.handoff.id).outcome.code, 'fabric_failed');
  assert.equal(f.store.get('jobs', theirs.derived.id).status, 'awaiting_approval', 'another handoff\'s job is not cancelled');
  assert.equal(f.store.get(CONTINUATIONS, theirs.handoff.id).status, 'resumed');
  const job = f.store.get('jobs', theirs.derived.id);
  assert.equal((await f.runtime.approve(job.id, job.approvalDigest, owner)).status, 'uncertain', 'the other handoff still completes');
  assert.equal(f.calls.length, 1);
});

test('a readable record whose recovery throws is audited recovery_failed and shown closed with fabric_failed', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  const healthy = (await f.invoke(token, 'calls.create', f.ask(client), 'healthy')).result;
  const broken = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'broken')).result;
  f.store.put('capabilities', {...f.write, request: {...f.write.request, method: 5}});
  assert.throws(() => f.runtime.capabilityReference(f.store.get('capabilities', f.write.id)), 'precondition: the capability reference throws');
  assert.doesNotThrow(() => f.service.load(broken.id), 'precondition: the record itself is readable');
  f.reopen();
  const events = failedAudit(f, broken.id);
  assert.equal(events.length, 1); assert.equal(events[0].reason, 'recovery_failed'); assert.equal(events[0].code, 'fabric_failed'); assert.equal(events[0].clientId, undefined);
  assert.deepEqual(failedAudit(f, healthy.id), []);
  const row = f.service.ownerList().find(item => item.id === broken.id);
  assert.equal(row.phase, 'closed'); assert.equal(row.status, 'failed');
  const view = f.view(broken.id);
  assert.equal(view.phase, 'closed'); assert.equal(view.outcome.code, 'fabric_failed'); assert.deepEqual(view.actions, []);
  assert.equal((await f.invoke(token, 'calls.get', {callId: broken.id})).result.handoff.outcome, 'fabric_failed');
  assert.equal(f.service.pendingCount(), 1);
});

test('a bound record whose recovery throws cancels its own pending job but not another handoff\'s', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const own = await awaitingApproval(f, client, token, 'acct-a', 'own-job');
  const theirs = await awaitingApproval(f, client, token, 'acct-a', 'their-job');
  const pointing = await awaitingApproval(f, client, token, 'acct-a', 'points-elsewhere');
  f.store.put(CONTINUATIONS, crashedBinding(f, own.handoff.id));
  f.store.put(CONTINUATIONS, crashedBinding(f, pointing.handoff.id, {jobId: theirs.derived.id}));
  // Processing these two records throws during recovery (as a broken stored operation would); the record stays readable.
  const failing = new Set([own.handoff.id, pointing.handoff.id]), recoverRecord = ContinuationService.prototype.recoverRecord;
  ContinuationService.prototype.recoverRecord = function (stored) { if (failing.has(stored.id)) throw new Error('synthetic recovery failure'); return recoverRecord.call(this, stored); };
  try { f.reopen(); } finally { ContinuationService.prototype.recoverRecord = recoverRecord; }
  for (const id of failing) {
    const events = failedAudit(f, id);
    assert.equal(events.length, 1, id); assert.equal(events[0].reason, 'recovery_failed', id);
    assert.equal(f.store.get(CONTINUATIONS, id).outcome.code, 'fabric_failed', id);
  }
  assert.equal(f.store.get('jobs', own.derived.id).status, 'cancelled', 'the job the record produced is cancelled');
  assert.equal(f.store.get('jobs', theirs.derived.id).status, 'awaiting_approval', 'a job of another handoff is not cancelled');
  assert.equal(f.store.get(CONTINUATIONS, theirs.handoff.id).status, 'resumed');
  const rows = f.service.ownerList().filter(item => failing.has(item.id));
  assert.deepEqual(rows.map(row => [row.phase, row.status]), [['closed', 'failed'], ['closed', 'failed']]);
  assert.equal(f.calls.length, 0);
});

// ---- (c) /api/clients status codes over HTTP ---------------------------------------------

test('legacy stores answer request-only grants on /api/clients with 404 unsupported_route', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'fabric-review2-legacy-')), port = await freePort();
  const app = await createApp({dataDir: dir, port, request: async () => { throw new Error('no provider calls in this test'); }});
  await app.start();
  t.after(async () => { await app.close(); await rm(dir, {recursive: true, force: true}); });
  const cap = {...compileOpenApi({appId: 'github', document: doc}).capabilities[0], status: 'active'};
  app.store.put('capabilities', cap);
  const first = await fetch(`${app.origin}/api/state`), state = await first.json(), cookie = first.headers.get('set-cookie').split(';')[0];
  const post = data => fetch(`${app.origin}/api/clients`, {method: 'POST', headers: {'content-type': 'application/json', 'x-fabric-csrf': state.csrfToken, cookie}, body: JSON.stringify(data)});
  for (const requestable of [[{capabilityId: cap.id}], [{capabilityId: 'unknown.capability'}], Array.from({length: 51}, (_, i) => ({capabilityId: `x${i}`}))]) {
    const response = await post({name: 'Agent', bindings: [], requestable});
    assert.equal(response.status, 404, `${requestable.length} entries`); assert.equal((await response.json()).code, 'unsupported_route');
  }
  assert.deepEqual(app.store.list('clientGrants'), []);
});

test('designated stores answer an unknown, duplicate or oversized requestable list with 400, never 404', async t => {
  const f = await httpFixture(t);
  const cases = [
    ['unknown capability', [{capabilityId: 'unknown.capability'}], /reviewed, active API operations/],
    ['duplicate entry', [{capabilityId: f.read.id}, {capabilityId: f.read.id}], /Duplicate requestable operation/],
    ['51 entries', Array.from({length: 51}, (_, i) => ({capabilityId: `x${i}`})), /at most 50 operations/],
  ];
  for (const [name, requestable, message] of cases) {
    const response = await f.json('POST', '/api/clients', {name: 'Agent', bindings: [], requestable});
    assert.equal(response.status, 400, name); assert.equal(response.body.code, 'invalid_request', name); assert.match(response.body.error, message, name);
  }
  assert.deepEqual(f.app.store.list('clientGrants'), []);
  assert.equal((await f.json('POST', '/api/clients', {name: 'Agent', bindings: [], requestable: [{capabilityId: f.read.id}]})).status, 201, 'a valid request-only grant is created');
});

// ---- (d) closure reasons regardless of first reader --------------------------------------

/** A handoff over HTTP, with one ready account the owner could choose and the digest the owner saw. */
async function handoffWithAccount(f) {
  f.app.store.put('connections', {id: 'acct-a', appId: 'github', driver: 'http', authMethod: 'token', authRevision: 'consent-a', status: 'ready', label: 'GitHub octo', identity: {id: '101', displayName: 'octo'}, allowedOrigins: ['https://api.github.com'], createdAt: new Date(f.now).toISOString()});
  const {token, id} = await f.ask();
  const seen = await f.view(id);
  assert.equal(seen.accounts[0].eligible, true, 'precondition: the owner could select the account');
  return {token, id, viewDigest: seen.viewDigest};
}

test('a retirement the client read first still answers capability_retired to the owner, with the fresh closed view', async t => {
  const f = await httpFixture(t);
  const {token, id, viewDigest} = await handoffWithAccount(f);
  f.app.store.put('capabilities', {...f.read, status: 'disabled'});
  const polled = (await f.protocol(token, 'calls.get', {callId: id})).result;
  assert.equal(polled.status, 'failed'); assert.equal(polled.handoff.outcome, 'capability_retired');
  assert.equal(f.app.store.get(CONTINUATIONS, id).status, 'failed', 'precondition: the client read closed the handoff');
  for (const attempt of ['first', 'second']) {
    const selected = await f.json('POST', `/api/continuations/${id}/select`, {connectionId: 'acct-a', viewDigest});
    assert.equal(selected.status, 409, attempt); assert.equal(selected.body.code, 'capability_retired', attempt);
    assert.equal(selected.body.view.phase, 'closed', attempt); assert.equal(selected.body.view.outcome.code, 'capability_retired', attempt);
    assert.deepEqual(selected.body.view.actions, [], attempt); assert.equal(selected.body.view.viewDigest, null, attempt);
  }
  const declined = await f.json('POST', `/api/continuations/${id}/decline`, {});
  assert.equal(declined.status, 409); assert.equal(declined.body.code, 'capability_retired');
  assert.deepEqual(f.app.store.list('jobs'), []); assert.equal(f.api.length, 0);
});

test('an operation edit the client read first still answers authority_changed to the owner', async t => {
  const f = await httpFixture(t);
  const {token, id, viewDigest} = await handoffWithAccount(f);
  f.app.store.put('capabilities', {...f.read, description: 'Edited after the request'});
  assert.equal((await f.protocol(token, 'calls.get', {callId: id})).result.handoff.outcome, 'authority_changed');
  const selected = await f.json('POST', `/api/continuations/${id}/select`, {connectionId: 'acct-a', viewDigest});
  assert.equal(selected.status, 409); assert.equal(selected.body.code, 'authority_changed');
  assert.equal(selected.body.view.phase, 'closed'); assert.equal(selected.body.view.outcome.code, 'authority_changed');
  assert.deepEqual(f.app.store.list('jobs'), []);
});

test('a retirement applied by restart recovery still answers capability_retired to the owner', async t => {
  const f = await httpFixture(t);
  const {id, viewDigest} = await handoffWithAccount(f);
  f.app.store.put('capabilities', {...f.read, status: 'disabled'});
  await f.restart();
  assert.equal(f.app.store.get(CONTINUATIONS, id).outcome.code, 'capability_retired', 'precondition: recovery closed the handoff');
  const selected = await f.json('POST', `/api/continuations/${id}/select`, {connectionId: 'acct-a', viewDigest});
  assert.equal(selected.status, 409); assert.equal(selected.body.code, 'capability_retired'); assert.equal(selected.body.view.phase, 'closed');
});

test('a handoff the owner declined still answers invalid_transition to a later select, whoever read it in between', async t => {
  const f = await httpFixture(t);
  const {token, id, viewDigest} = await handoffWithAccount(f);
  const declined = await f.json('POST', `/api/continuations/${id}/decline`, {});
  assert.equal(declined.status, 200); assert.equal(declined.body.outcome.code, 'owner_declined');
  assert.equal((await f.protocol(token, 'calls.get', {callId: id})).result.handoff.outcome, 'owner_declined');
  const selected = await f.json('POST', `/api/continuations/${id}/select`, {connectionId: 'acct-a', viewDigest});
  assert.equal(selected.status, 409); assert.equal(selected.body.code, 'invalid_transition'); assert.equal(selected.body.view, undefined);
  assert.equal((await f.json('POST', `/api/continuations/${id}/decline`, {})).body.code, 'invalid_transition');
  assert.deepEqual(f.app.store.list('jobs'), []);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {CONTINUATIONS} from '../lib/continuations.mjs';
import {canonicalHash, compileOpenApi} from '../lib/compiler.mjs';
import {validateContinuation} from '../contracts/execution.mts';
import {owner, ORIGIN, github, fixture} from './fixtures/continuation-fixture.mjs';

// F02.3a: missing-access handoff, existing-account path (docs/F02.3-MISSING-ACCESS-SPEC.md).
// Isolated temporary designated stores, synthetic HTTP provider, no private state or network.

test('request-only grants derive their binding server-side and reject anything that is not a reviewed API operation', async t => {
  const f = await fixture(t);
  const {client} = f.grant();
  assert.deepEqual(client.bindings, []);
  const entry = client.requestable.find(item => item.capabilityId === f.write.id);
  assert.deepEqual(Object.keys(entry).sort(), ['appId', 'capabilityId', 'capabilityVersion', 'definitionHash', 'effect', 'providerId']);
  assert.equal(entry.appId, 'github'); assert.equal(entry.effect, 'write'); assert.equal(entry.providerId, 'github');
  assert.equal(entry.definitionHash, f.runtime.capabilityReference(f.write).definitionHash);
  f.store.put('capabilities', {id: 'workspace.read.v1', appId: 'workspace', driver: 'workspace', status: 'active', action: {op: 'read'}});
  f.store.put('capabilities', {...f.read, id: 'github.candidate', status: 'candidate'});
  const other = compileOpenApi({appId: 'unrouted', document: {...github, servers: [{url: 'https://api.unrouted.example'}]}}).capabilities[0];
  f.store.put('capabilities', {...other, status: 'active'});
  for (const requestable of [[{capabilityId: 'workspace.read.v1'}], [{capabilityId: 'github.candidate'}], [{capabilityId: other.id}], [{capabilityId: f.read.id}, {capabilityId: f.read.id}], [{capabilityId: f.read.id, appId: 'github'}], Array.from({length: 51}, (_, i) => ({capabilityId: `x${i}`}))]) {
    assert.throws(() => f.protocol.createClient({name: 'Agent', bindings: [], requestable}, owner), error => error.code === 'invalid_request');
  }
  assert.throws(() => f.protocol.createClient({name: 'Agent', bindings: [], requestable: [{capabilityId: f.read.id}]}, {...owner, id: 'someone-else'}), error => error.code === 'unauthorized');
  assert.throws(() => f.protocol.createClient({name: 'Agent', bindings: []}, owner), error => error.code === 'invalid_request');
});

test('legacy stores refuse request-only grants, the application call shape and owner handoff routes without writing', async t => {
  const f = await fixture(t, {authority: null});
  assert.throws(() => f.protocol.createClient({name: 'Agent', bindings: [], requestable: [{capabilityId: f.read.id}]}), error => error.code === 'unsupported_route');
  assert.throws(() => f.service.ownerList(), error => error.code === 'unsupported_route');
  assert.throws(() => f.service.ownerView('00000000-0000-4000-8000-000000000000'), error => error.code === 'unsupported_route');
  assert.deepEqual(f.store.list(CONTINUATIONS), []); assert.deepEqual(f.store.list('clientGrants'), []);
});

test('capability listing adds request-only entries without disclosing accounts and fails closed on malformed grants', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101'); f.account('acct-b', '202'); f.account('acct-c', '303');
  const {client, token} = f.grant();
  const listed = (await f.invoke(token, 'capabilities.list')).result.capabilities;
  assert.equal(listed.length, 2);
  for (const item of listed) {
    assert.equal(item.connectionId, null); assert.equal(item.status, 'connection_required'); assert.equal(item.approval, 'after_connection'); assert.equal(item.signIn, 'available');
  }
  assert.equal(JSON.stringify(listed).includes('acct-'), false, 'existing accounts are never disclosed');
  f.store.put('capabilities', {...f.read, description: 'changed definition', name: 'Changed'});
  const drifted = (await f.invoke(token, 'capabilities.list')).result.capabilities.find(item => item.id === f.read.id);
  assert.equal(drifted.status, 'unavailable'); assert.equal(drifted.reason, 'grant_changed');
  const stored = f.store.get('clientGrants', client.id);
  f.store.put('clientGrants', {...stored, requestable: [{...stored.requestable[0], extra: true}]});
  assert.equal((await f.invoke(token, 'capabilities.list')).error.code, 'unauthorized');
});

test('the application call shape creates one owner handoff and nothing else', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant(), params = f.ask(client);
  const response = await f.invoke(token, 'calls.create', params, 'need-repos');
  const view = response.result;
  assert.equal(view.status, 'awaiting_connection'); assert.equal(view.connectionId, null); assert.equal(view.resumedCallId, null);
  assert.equal(view.handoff.url, `${ORIGIN}/continue/${view.id}`); assert.equal(view.handoff.state, 'awaiting_owner'); assert.equal(view.handoff.appName, 'GitHub');
  assert.equal(view.handoff.expiresAt, new Date(f.now + 30 * 60_000).toISOString());
  const record = f.store.get(CONTINUATIONS, view.id);
  assert.deepEqual(record.request.access, {kind: 'missing', appId: 'github', accountSelection: {kind: 'owner_required'}});
  assert.equal(record.request.principal.kind, 'local_client'); assert.equal(record.request.principal.id, client.id); assert.equal(record.request.policyRevision, 1);
  assert.doesNotThrow(() => validateContinuation(record.contract, {request: record.request, now: new Date(f.now).toISOString()}));
  assert.deepEqual(f.jobs(), []); assert.deepEqual(f.store.list('oauthFlows'), []); assert.equal(f.calls.length, 0);
  assert.equal(JSON.stringify(view).match(/digest|email|identity|scope/i), null, 'the client view carries no identity, scopes or digests');
});

test('handoff requests reject impersonation, mixed shapes, unknown operations and invalid arguments before reserving', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant(), params = f.ask(client, f.write, {owner: 'o', repo: 'r', body: {title: 't'}});
  for (const extra of [{principal: owner}, {scope: owner.scope}, {source: {kind: 'user'}}, {accountSelection: {kind: 'exact', accountId: 'x'}}, {connectionId: 'acct-a'}]) {
    assert.equal((await f.invoke(token, 'calls.create', {...params, ...extra})).error.code, 'invalid_request');
  }
  assert.equal((await f.invoke(token, 'calls.create', {capabilityId: f.read.id, definitionHash: params.definitionHash, args: {}})).error.code, 'invalid_request');
  assert.equal((await f.invoke(token, 'calls.create', {...params, args: {owner: 'o', repo: 'r', title: 'not a field'}})).error.code, 'invalid_request');
  assert.equal((await f.invoke(token, 'calls.create', {...params, appId: 'gitlab'})).error.code, 'permission_denied');
  assert.equal((await f.invoke(token, 'calls.create', {...params, definitionHash: 'f'.repeat(64)})).error.code, 'grant_changed');
  assert.deepEqual(f.store.list('protocolRequests'), [], 'rejected requests leave no reservation');
  assert.deepEqual(f.store.list(CONTINUATIONS), []);
});

test('the create response is identical with zero, one or three accounts and with sign-in on or off', async t => {
  const shape = async (accounts, signIn) => {
    const f = await fixture(t, {signIn});
    accounts.forEach((id, i) => f.account(id, String(100 + i)));
    const {client, token} = f.grant();
    const {result} = await f.invoke(token, 'calls.create', f.ask(client), 'oracle');
    // The card too: apart from the call id and this Fabric's own address, nothing differs.
    return JSON.stringify(result).replaceAll(result.id, 'x').replace(/http:\/\/127\.0\.0\.1:\d+/g, 'origin');
  };
  const baseline = await shape([], true);
  for (const [accounts, signIn] of [[['a'], true], [['a', 'b', 'c'], true], [['a'], false]]) assert.equal(await shape(accounts, signIn), baseline);
});

test('pending handoffs are bounded per client and replays return the same handoff', async t => {
  const f = await fixture(t);
  const {client, token} = f.grant();
  const first = (await f.invoke(token, 'calls.create', f.ask(client), 'same-id')).result;
  const again = (await f.invoke(token, 'calls.create', f.ask(client), 'same-id')).result;
  assert.equal(again.id, first.id); assert.equal(again.handoff.url, first.handoff.url);
  assert.equal((await f.invoke(token, 'calls.create', f.ask(client, f.read, {per_page: 5}), 'same-id')).error.code, 'idempotency_conflict');
  for (let i = 1; i < 10; i++) assert.equal((await f.invoke(token, 'calls.create', f.ask(client), `pending-${i}`)).result.status, 'awaiting_connection');
  assert.equal((await f.invoke(token, 'calls.create', f.ask(client), 'pending-11')).error.code, 'pending_limit');
  await f.service.decline(first.id, {}, owner);
  assert.equal((await f.invoke(token, 'calls.create', f.ask(client), 'pending-12')).result.status, 'awaiting_connection', 'terminal handoffs do not count');
  const open = f.store.list(CONTINUATIONS).find(record => record.status === 'awaiting_owner');
  await f.service.decline(open.id, {}, owner);
  const [a, b] = await Promise.all([f.invoke(token, 'calls.create', f.ask(client, f.read, {per_page: 1}), 'race'), f.invoke(token, 'calls.create', f.ask(client, f.read, {per_page: 1}), 'race')]);
  assert.equal(a.result.id, b.result.id, 'concurrent duplicates produce one handoff');
  assert.equal(f.store.list(CONTINUATIONS).filter(record => record.requestId === 'race').length, 1);
});

test('reservation crash windows link an existing handoff or stay unknown, and cross-shape reuse conflicts', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant({bindings: [{connectionId: 'acct-a', capabilityId: f.read.id}]});
  const bound = {connectionId: 'acct-a', capabilityId: f.read.id, definitionHash: client.bindings[0].definitionHash, args: {}};
  assert.equal((await f.invoke(token, 'calls.create', bound, 'shape')).result.status, 'succeeded');
  assert.equal((await f.invoke(token, 'calls.create', f.ask(client), 'shape')).error.code, 'idempotency_conflict');
  const params = f.ask(client), key = canonicalHash({clientId: client.id, requestId: 'crash'});
  f.store.put('protocolRequests', {id: key, clientId: client.id, requestId: 'crash', requestHash: canonicalHash(params), status: 'reserved', createdAt: new Date(f.now).toISOString()});
  assert.equal((await f.invoke(token, 'calls.create', params, 'crash')).error.code, 'outcome_unknown');
  const made = (await f.invoke(token, 'calls.create', params, 'linked')).result, record = f.store.get(CONTINUATIONS, made.id);
  const linkedKey = canonicalHash({clientId: client.id, requestId: 'linked'});
  f.store.put('protocolRequests', {...f.store.get('protocolRequests', linkedKey), status: 'reserved', continuationId: undefined});
  assert.equal((await f.invoke(token, 'calls.create', params, 'linked')).result.id, record.id);
});

test('other clients cannot read, cancel or act on a handoff, and owner verbs are not protocol methods', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const a = f.grant(), b = f.grant();
  const handoff = (await f.invoke(a.token, 'calls.create', f.ask(a.client), 'mine')).result;
  assert.equal((await f.invoke(b.token, 'calls.get', {callId: handoff.id})).error.code, 'not_found');
  assert.equal((await f.invoke(b.token, 'calls.cancel', {callId: handoff.id})).error.code, 'not_found');
  for (const method of ['continuations.select', 'continuations.confirm', 'approvals.approve']) assert.equal((await f.invoke(a.token, method, {})).error.code, 'method_not_found');
  await f.select(handoff.id, 'acct-a'); await f.service.settled(handoff.id);
  const derived = f.jobs()[0];
  assert.equal((await f.invoke(b.token, 'calls.get', {callId: derived.id})).error.code, 'not_found');
  assert.equal((await f.invoke(b.token, 'calls.cancel', {callId: derived.id})).error.code, 'not_found', 'B cannot tell that A\'s derived job exists');
});

test('tampered handoff records are unreadable to the client and unusable by the owner', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client), 'tamper')).result, record = f.store.get(CONTINUATIONS, handoff.id);
  for (const mutate of [r => { r.request.args = {per_page: 99}; }, r => { r.request.principal = {...r.request.principal, id: 'other'}; }, r => { r.requestHash = 'f'.repeat(64); }, r => { r.grantEntry = {...r.grantEntry, effect: 'write'}; }, r => { r.contract = {...r.contract, requestHash: 'e'.repeat(64)}; }]) {
    const copy = structuredClone(record); mutate(copy); f.store.put(CONTINUATIONS, copy);
    assert.equal((await f.invoke(token, 'calls.get', {callId: handoff.id})).error.code, 'outcome_unknown');
    assert.throws(() => f.service.ownerView(handoff.id), error => error.code === 'authority_changed');
    await assert.rejects(f.select(handoff.id, 'acct-a', 'digest'), error => error.code === 'authority_changed');
  }
  assert.deepEqual(f.jobs(), []);
});

test('the owner always chooses: one eligible account never auto-binds and is never granted to the client', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client), 'no-fallback')).result;
  assert.equal(f.view(handoff.id).accounts.length, 1);
  assert.equal((await f.invoke(token, 'calls.get', {callId: handoff.id})).result.status, 'awaiting_connection');
  assert.deepEqual(f.jobs(), []);
  const direct = await f.invoke(token, 'calls.create', {connectionId: 'acct-a', capabilityId: f.read.id, definitionHash: f.ask(client).definitionHash, args: {}}, 'direct');
  assert.equal(direct.error.code, 'permission_denied');
});

test('ineligible accounts and changed views are refused without binding', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101'); f.account('acct-b', '202');
  f.store.put('connections', {...f.store.get('connections', 'acct-b'), status: 'reconnect_required'});
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client), 'ineligible')).result;
  const revision = f.store.get(CONTINUATIONS, handoff.id).revision;
  for (const id of ['unknown', 'acct-b']) await assert.rejects(f.select(handoff.id, id), error => error.code === 'account_ineligible');
  f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'deny'});
  await assert.rejects(f.select(handoff.id, 'acct-a'), error => error.code === 'account_ineligible');
  f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'allow'});
  const seen = f.view(handoff.id).viewDigest;
  f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'ask'});
  f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'allow'});
  await assert.rejects(f.select(handoff.id, 'acct-a', seen), error => error.code === 'view_changed' && typeof error.view?.viewDigest === 'string');
  const seen2 = f.view(handoff.id).viewDigest;
  f.store.put('connections', {...f.store.get('connections', 'acct-a'), authRevision: 'reconnected'});
  await assert.rejects(f.select(handoff.id, 'acct-a', seen2), error => error.code === 'view_changed');
  assert.equal(f.store.get(CONTINUATIONS, handoff.id).status, 'awaiting_owner');
  assert.equal(f.store.get(CONTINUATIONS, handoff.id).revision, revision, 'a refused select writes nothing');
  assert.deepEqual(f.jobs(), []);
});

test('an Allow read resumes the exact request once on the selected account', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client, f.read, {per_page: 3}), 'read-1')).result;
  const view = await f.select(handoff.id, 'acct-a');
  assert.equal(view.status, 'resumed'); await f.service.settled(handoff.id);
  const [job] = f.jobs();
  assert.notEqual(job.id, handoff.id);
  assert.equal(job.executionRequest.idempotencyKey, `${handoff.id}@continuation`);
  assert.deepEqual(job.source, {kind: 'client', clientId: client.id, requestId: `${handoff.id}@continuation`, continuationId: handoff.id});
  assert.deepEqual(job.executionRequest.access, {kind: 'connection', id: 'acct-a', generation: f.store.connectionGeneration('acct-a')});
  assert.deepEqual(job.args, {per_page: 3}); assert.equal(job.executionRequest.principal.kind, 'local_client');
  assert.equal(f.calls.length, 1);
  const status = (await f.invoke(token, 'calls.get', {callId: handoff.id})).result;
  assert.equal(status.status, 'succeeded'); assert.equal(status.resumedCallId, job.id); assert.equal(status.connectionId, 'acct-a'); assert.equal(status.handoff.state, 'connected');
  assert.equal((await f.invoke(token, 'calls.get', {callId: job.id})).result.status, 'succeeded');
  assert.equal((await f.invoke(token, 'calls.create', f.ask(client, f.read, {per_page: 3}), 'read-1')).result.status, 'succeeded', 'replay returns the derived status');
  assert.deepEqual((await f.invoke(token, 'capabilities.list')).result.capabilities.map(item => item.connectionId), [null, null], 'no grant extension');
  assert.equal(f.calls.length, 1);
});

test('a write waits for its own approval; earlier approvals and digests never transfer', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101'); f.account('acct-b', '202');
  const args = {owner: 'o', repo: 'r', body: {title: 'Synthetic issue'}};
  const {client, token} = f.grant({bindings: [{connectionId: 'acct-a', capabilityId: f.write.id}]});
  const prior = (await f.invoke(token, 'calls.create', {connectionId: 'acct-a', capabilityId: f.write.id, definitionHash: client.bindings[0].definitionHash, args}, 'prior')).result;
  const priorJob = f.store.get('jobs', prior.id);
  await f.runtime.approve(priorJob.id, priorJob.approvalDigest, owner);
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'write-1')).result;
  const view = await f.select(handoff.id, 'acct-b');
  const derived = f.store.get('jobs', view.derived.jobId);
  assert.equal(derived.status, 'awaiting_approval'); assert.equal(derived.executionApproval, undefined); assert.equal(derived.approvedAt, undefined);
  assert.equal(view.phase, 'awaiting_approval'); assert.equal(view.derived.approval.digest, derived.approvalDigest);
  const before = f.calls.length;
  await assert.rejects(f.runtime.approve(derived.id, priorJob.approvalDigest, owner), /exact action/);
  assert.equal(f.calls.length, before);
  assert.equal((await f.runtime.approve(derived.id, derived.approvalDigest, owner)).status, 'uncertain');
  assert.equal(f.calls.length, before + 1);
  await assert.rejects(f.runtime.approve(derived.id, derived.approvalDigest, owner), /not awaiting approval/);
});

test('one handoff yields one job: concurrent decisions and forged jobs are refused', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101'); f.account('acct-b', '202');
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client), 'one-job')).result;
  const digest = f.view(handoff.id).viewDigest;
  const results = await Promise.allSettled([f.select(handoff.id, 'acct-a', digest), f.select(handoff.id, 'acct-b', digest), (async () => f.service.decline(handoff.id, {}, owner))()]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.ok(results.filter(r => r.status === 'rejected').every(r => ['invalid_transition', 'view_changed'].includes(r.reason.code)));
  await f.service.settled(handoff.id);
  const record = f.store.get(CONTINUATIONS, handoff.id);
  assert.equal(f.jobs().length, record.status === 'resumed' ? 1 : 0, `${record.status} must leave exactly ${record.status === 'resumed' ? 1 : 0} job`);
  assert.ok(['resumed', 'declined'].includes(record.status));
});

test('a forged derived job is refused: other job id, connection, client, generation, source shape or closed handoff', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101'); f.account('acct-b', '202');
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client), 'forged')).result;
  await f.select(handoff.id, 'acct-a'); await f.service.settled(handoff.id);
  const record = f.store.get(CONTINUATIONS, handoff.id);
  assert.equal(record.status, 'resumed');
  const real = f.store.get('jobs', record.binding.jobId);
  assert.doesNotThrow(() => f.protocol.authorizeJob(real));
  const denied = job => assert.throws(() => f.protocol.authorizeJob(job), error => error.code === 'permission_denied');
  denied({...real, id: '11111111-1111-4111-8111-111111111111'});
  denied({...real, connectionId: 'acct-b'});
  denied({...real, source: {...real.source, clientId: 'someone'}});
  denied({...real, source: {...real.source, extra: 1}});
  denied({...real, executionRequest: {...real.executionRequest, access: {...real.executionRequest.access, generation: real.executionRequest.access.generation + 1}}});
  // The resumed record pins the exact derived request; a replaced one is refused even if internally consistent.
  f.store.put(CONTINUATIONS, {...record, binding: {...record.binding, derivedRequestHash: 'a'.repeat(64)}});
  denied(real);
  // A handoff that is no longer binding or resumed authorizes nothing, even for its own job.
  f.store.put(CONTINUATIONS, {...record, status: 'failed', outcome: {code: 'authority_changed', at: new Date(f.now).toISOString()}});
  denied(real);
  f.store.put(CONTINUATIONS, record);
  // No grant extension after resume: the selected connection is still not bound to the client.
  assert.equal((await f.invoke(token, 'calls.create', {connectionId: 'acct-a', capabilityId: f.read.id, definitionHash: client.requestable.find(entry => entry.capabilityId === f.read.id).definitionHash, args: {}}, 'after-resume')).error.code, 'permission_denied');
});

test('a policy change between the owner decision and job preparation cancels the derived job', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client), 'race-policy')).result;
  const prepare = f.runtime.prepareJob.bind(f.runtime);
  f.runtime.prepareJob = async (...args) => {
    f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'ask'});
    f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'allow'});
    return prepare(...args);
  };
  await assert.rejects(f.select(handoff.id, 'acct-a'), error => error.code === 'authority_changed');
  const record = f.store.get(CONTINUATIONS, handoff.id);
  assert.equal(record.status, 'failed'); assert.equal(record.outcome.code, 'authority_changed');
  assert.deepEqual(f.jobs(), [], 'the change landed before preparation, so no job was persisted');
  assert.equal(f.calls.length, 0);
});

test('a policy change after the derived job is persisted cancels it and fails the handoff', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client), 'race-after')).result;
  const prepare = f.runtime.prepareJob.bind(f.runtime);
  f.runtime.prepareJob = async (...args) => {
    const job = await prepare(...args);
    f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'ask'});
    f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.read.id, mode: 'allow'});
    return job;
  };
  await assert.rejects(f.select(handoff.id, 'acct-a'), error => error.code === 'authority_changed');
  const record = f.store.get(CONTINUATIONS, handoff.id);
  assert.equal(record.status, 'failed'); assert.equal(record.outcome.code, 'authority_changed');
  assert.deepEqual(f.jobs().map(job => job.status), ['cancelled']);
  await f.service.drain();
  assert.equal(f.calls.length, 0);
});

test('authority changes after binding stop the derived request without creating another', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const args = {owner: 'o', repo: 'r', body: {title: 'Synthetic issue'}};
  const {client, token} = f.grant();
  const cases = [
    () => f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.write.id, mode: 'deny'}),
    () => { f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.write.id, mode: 'allow'}); f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.write.id, mode: 'ask'}); },
    () => f.store.put('connections', {...f.store.get('connections', 'acct-a'), authRevision: `again-${Math.random()}`}),
    () => f.store.put('connections', {...f.store.get('connections', 'acct-a'), status: 'revoked'}),
  ];
  for (const [index, change] of cases.entries()) {
    f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.write.id, mode: 'ask'});
    const handoff = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), `after-bind-${index}`)).result;
    const job = f.store.get('jobs', (await f.select(handoff.id, 'acct-a')).derived.jobId);
    change();
    await assert.rejects(f.runtime.approve(job.id, job.approvalDigest, owner), error => error.code === 'authority_changed' && error.httpStatus === 409, `case ${index}`);
    assert.equal(f.store.get(CONTINUATIONS, handoff.id).status, 'resumed');
    assert.equal(f.store.get('jobs', job.id).status, 'awaiting_approval', 'nothing ran and no other job was created');
    f.store.put('connections', {...f.store.get('connections', 'acct-a'), status: 'ready'});
  }
  assert.equal(f.calls.length, 0); assert.equal(f.jobs().length, cases.length);
});

test('client revocation after binding denies approval and withholds the result', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client, f.write, {owner: 'o', repo: 'r', body: {title: 't'}}), 'revoked-after')).result;
  const job = f.store.get('jobs', (await f.select(handoff.id, 'acct-a')).derived.jobId);
  f.protocol.revokeClient(client.id);
  await assert.rejects(f.runtime.approve(job.id, job.approvalDigest, owner), error => error.code === 'authority_changed');
  assert.equal(f.calls.length, 0);
});

test('a reconnected account withholds an earlier result through both the handoff id and the job id', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const handoff = (await f.invoke(token, 'calls.create', f.ask(client), 'withhold')).result;
  await f.select(handoff.id, 'acct-a'); await f.service.settled(handoff.id);
  const before = (await f.invoke(token, 'calls.get', {callId: handoff.id})).result;
  assert.equal(before.status, 'succeeded');
  f.store.put('connections', {...f.store.get('connections', 'acct-a'), authRevision: 'reconnected'});
  assert.equal((await f.invoke(token, 'calls.get', {callId: handoff.id})).error.code, 'permission_denied');
  assert.equal((await f.invoke(token, 'calls.get', {callId: before.resumedCallId})).error.code, 'permission_denied');
});

test('capability drift, client revocation, expiry, decline and client cancel close a waiting handoff', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant();
  const create = async id => (await f.invoke(token, 'calls.create', f.ask(client), id)).result;
  const retired = await create('retired');
  f.store.put('capabilities', {...f.read, status: 'retired'});
  const retiredView = (await f.invoke(token, 'calls.get', {callId: retired.id})).result;
  assert.equal(retiredView.handoff.outcome, 'capability_retired'); assert.equal(retiredView.status, 'failed');
  f.store.put('capabilities', f.read);
  const declined = await create('declined');
  await f.service.decline(declined.id, {}, owner);
  const after = (await f.invoke(token, 'calls.get', {callId: declined.id})).result;
  assert.equal(after.status, 'cancelled'); assert.equal(after.handoff.outcome, 'owner_declined');
  await assert.rejects(f.select(declined.id, 'acct-a', 'x'), error => error.code === 'invalid_transition');
  const cancelled = await create('cancelled');
  assert.equal((await f.invoke(token, 'calls.cancel', {callId: cancelled.id})).result.handoff.outcome, 'client_cancelled');
  assert.equal((await f.invoke(token, 'calls.cancel', {callId: cancelled.id})).error.code, 'invalid_transition');
  const expiring = await create('expiring');
  f.advance(30 * 60_000);
  assert.equal((await f.invoke(token, 'calls.get', {callId: expiring.id})).result.status, 'expired');
  await assert.rejects(f.select(expiring.id, 'acct-a', 'x'), error => error.code === 'continuation_expired');
  const revoked = await create('revoked');
  f.protocol.revokeClient(client.id);
  assert.equal(f.store.get(CONTINUATIONS, revoked.id).outcome.code, 'client_revoked');
  await assert.rejects(f.select(revoked.id, 'acct-a', 'x'), error => error.code === 'client_revoked' && error.view?.phase === 'closed', 'the owner learns why it closed, even though the revoke closed it eagerly');
  assert.equal((await f.invoke(token, 'calls.get', {callId: revoked.id})).error.code, 'unauthorized');
  assert.deepEqual(f.jobs(), []);
});

test('the handoff never outlives the client grant and the client cannot cancel a derived job', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const short = f.protocol.createClient({name: 'Short', bindings: [], requestable: [{capabilityId: f.read.id}], expiresInSeconds: 120}, owner);
  const handoff = (await f.invoke(short.token, 'calls.create', f.ask(short.client), 'short')).result;
  assert.equal(handoff.handoff.expiresAt, short.client.expiresAt);
  await f.select(handoff.id, 'acct-a'); await f.service.settled(handoff.id);
  const derived = f.jobs()[0];
  assert.equal((await f.invoke(short.token, 'calls.cancel', {callId: derived.id})).error.code, 'unsupported_route');
  assert.equal((await f.invoke(short.token, 'calls.cancel', {callId: handoff.id})).error.code, 'invalid_transition');
});

test('an ambiguous derived write stays uncertain and is never re-derived or replayed', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  f.runtime.permissions.set({connectionId: 'acct-a', capabilityId: f.write.id, mode: 'allow'});
  f.hooks.request = async () => { throw new Error('socket hang up after send'); };
  const {client, token} = f.grant(), params = f.ask(client, f.write, {owner: 'o', repo: 'r', body: {title: 't'}});
  const handoff = (await f.invoke(token, 'calls.create', params, 'ambiguous')).result;
  await f.select(handoff.id, 'acct-a'); await f.service.settled(handoff.id);
  assert.equal((await f.invoke(token, 'calls.get', {callId: handoff.id})).result.status, 'uncertain');
  assert.equal((await f.invoke(token, 'calls.create', params, 'ambiguous')).result.status, 'uncertain');
  await assert.rejects(f.select(handoff.id, 'acct-a', 'x'), error => error.code === 'invalid_transition');
  f.reopen();
  assert.equal(f.jobs().length, 1); assert.equal(f.calls.length, 1);
});

test('restart keeps waiting handoffs, finishes a persisted binding and fails a binding with no job', async t => {
  const f = await fixture(t);
  f.account('acct-a', '101');
  const {client, token} = f.grant(), args = {owner: 'o', repo: 'r', body: {title: 't'}};
  const waiting = (await f.invoke(token, 'calls.create', f.ask(client), 'wait')).result;
  const bound = (await f.invoke(token, 'calls.create', f.ask(client, f.write, args), 'bound')).result;
  const view = await f.select(bound.id, 'acct-a');
  // A real crash between the binding write and the resumed write leaves no derived request hash yet.
  const crashed = f.store.get(CONTINUATIONS, bound.id);
  f.store.put(CONTINUATIONS, {...crashed, status: 'binding', binding: {...crashed.binding, derivedRequestHash: null}});
  const orphan = (await f.invoke(token, 'calls.create', f.ask(client, f.write, {...args, body: {title: 'x'}}), 'orphan')).result;
  const record = f.store.get(CONTINUATIONS, orphan.id);
  f.store.put(CONTINUATIONS, {...record, status: 'binding', revision: record.revision + 1, binding: {via: 'select', connectionId: 'acct-a', generation: 1, identityHash: 'h', policyRevision: 1, mode: 'ask', decidedAt: new Date(f.now).toISOString(), jobId: '22222222-2222-4222-8222-222222222222', derivedRequestHash: null}});
  f.reopen();
  assert.equal(f.store.get(CONTINUATIONS, waiting.id).status, 'awaiting_owner');
  assert.equal(f.store.get(CONTINUATIONS, bound.id).status, 'resumed');
  assert.equal(f.store.get('jobs', view.derived.jobId).status, 'awaiting_approval', 'a pending approval stays approvable after restart');
  assert.equal(f.store.get(CONTINUATIONS, orphan.id).outcome.code, 'fabric_failed');
  const resumed = await f.select(waiting.id, 'acct-a'); await f.service.settled(waiting.id);
  assert.equal(resumed.status, 'resumed');
  assert.equal(f.jobs().length, 2);
});

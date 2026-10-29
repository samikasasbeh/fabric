import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {
  ExecutionContractError, ERROR_DEFINITIONS, EXECUTION_STATES, validateCapabilityReference,
  validateExecutionRequest, hashExecutionRequest, bindingForRequest, validateApproval,
  validateContinuation, validateExecutionError, assertStateTransition, assertIdempotencyCompatible, assertDispatchable,
} from '../contracts/execution.mts';

const createdAt = '2026-10-11T10:00:00.000Z', now = '2026-10-11T10:02:00.000Z', expiresAt = '2026-10-11T10:10:00.000Z';
const localScope = {schemaVersion: 1, kind: 'local', localOwnerId: 'owner-1'};
const tenantScope = {schemaVersion: 1, kind: 'tenant', organizationId: 'org-1', projectId: 'project-1', environmentId: 'production'};
const localOwner = {schemaVersion: 1, kind: 'local_owner', id: 'owner-1', scope: localScope};
const localClient = {schemaVersion: 1, kind: 'local_client', id: 'authenticated-grant-1', scope: localScope, delegatedBy: {kind: 'local_owner', id: 'owner-1'}};
const user = {schemaVersion: 1, kind: 'product_user', id: 'user-principal-1', subjectId: 'customer-user-1', scope: tenantScope};
const agent = {schemaVersion: 1, kind: 'agent', id: 'agent-1', scope: tenantScope, subjectId: user.subjectId, delegatedBy: {kind: 'product_user', id: user.subjectId}, delegationId: 'delegation-1'};
const service = {schemaVersion: 1, kind: 'service_client', id: 'service-1', scope: tenantScope};
const capability = {appId: 'github', id: 'github.issue.create', version: 1, definitionHash: 'a'.repeat(64), effect: 'write'};
function request(actor = localOwner, changes = {}) {
  return {...structuredClone({schemaVersion: 1, id: 'execution-1', scope: actor.scope, principal: actor,
    access: {kind: 'connection', id: 'connection-1', generation: 3}, capability, args: {title: 'Test issue', labels: ['fixture']},
    policyRevision: 7, idempotencyKey: 'key-1', createdAt, deadline: '2026-10-11T11:00:00.000Z'}), ...changes};
}
function approval(req, approver = req.principal, changes = {}) {
  return structuredClone({schemaVersion: 1, id: 'approval-1', ...bindingForRequest(req), approver,
    decision: 'approved', createdAt: '2026-10-11T10:01:00.000Z', expiresAt, ...changes});
}
function continuation(req, changes = {}) {
  return structuredClone({schemaVersion: 1, id: 'continuation-1', ...bindingForRequest(req), kind: req.access.kind === 'missing' ? 'connection' : 'approval',
    createdAt: '2026-10-11T10:01:00.000Z', expiresAt, ...changes});
}
function dispatch(req, owner = req.principal, policy = 'allow') {
  return {request: structuredClone(req), now, current: structuredClone({scope: req.scope, principal: req.principal, ownerPrincipal: owner,
    connection: {id: req.access.id, generation: req.access.generation, appId: req.capability.appId, status: 'active',
      ownership: {schemaVersion: 1, scope: req.scope, owner: {kind: owner.kind, id: owner.kind === 'product_user' ? owner.subjectId : owner.id}}},
    capability: {reference: req.capability, status: 'active'}, policy:{revision:req.policyRevision,decision:policy}})};
}
const rejects = (fn, code) => assert.throws(fn, error => error instanceof ExecutionContractError && error.code === code);

test('version-one local owner client and tenant agent requests are detached and deeply frozen', () => {
  for (const actor of [localOwner, localClient, user, agent, service]) {
    const source = request(actor), validated = validateExecutionRequest(source);
    assert.deepEqual(validated, source);
    assert.notEqual(validated, source);
    source.args.labels.push('later');
    assert.deepEqual(validated.args.labels, ['fixture']);
    assert.ok(Object.isFrozen(validated.principal.scope));
    assert.throws(() => { validated.args.labels.push('changed'); }, TypeError);
  }
});

test('capability reference rejects missing, unknown, mutable and malformed versions', () => {
  assert.deepEqual(validateCapabilityReference(capability), capability);
  for (const changes of [{version: 0}, {version: 1.5}, {version: 'latest'}, {version: Number.MAX_SAFE_INTEGER + 1}, {definitionHash: 'A'.repeat(64)}, {effect: 'execute'}, {appId: 'GitHub'}, {execute: true}]) {
    rejects(() => validateCapabilityReference({...capability, ...changes}), 'invalid_contract');
  }
});

test('request envelope rejects unknown fields versions and invalid immutable values', () => {
  for (const changes of [{schemaVersion: 2}, {idempotencyKey: ''}, {policyRevision:0}, {policyRevision:1.5}, {policyRevision:'7'}, {policyRevision:Number.MAX_SAFE_INTEGER+1}, {args: []}, {args: {n: Infinity}}, {args: {call: () => {}}},
    {createdAt: '2026-02-30T10:00:00Z'}, {deadline: createdAt}, {deadline: '2026-10-11T13:00:00+02:00'}, {execute: true}]) {
    rejects(() => validateExecutionRequest(request(localOwner, changes)), 'invalid_contract');
  }
  const missing = request(); delete missing.access;
  rejects(() => validateExecutionRequest(missing), 'invalid_contract');
  const noPolicy = request(); delete noPolicy.policyRevision;
  rejects(() => validateExecutionRequest(noPolicy), 'invalid_contract');
  rejects(() => validateExecutionRequest(request(localOwner, {access: {kind: 'connection', id: 'connection-1', generation: 0}})), 'invalid_contract');
});

test('descriptor-first JSON checks reject getters and toJSON without invoking them', () => {
  let calls = 0;
  const getter = request(); Object.defineProperty(getter, 'args', {enumerable: true, get() { calls++; return {}; }});
  const custom = request(); custom.args.toJSON = () => { calls++; return {}; };
  for (const value of [getter, custom]) rejects(() => validateExecutionRequest(value), 'invalid_contract');
  assert.equal(calls, 0);
  const cycle = request(); cycle.args.self = cycle;
  rejects(() => validateExecutionRequest(cycle), 'invalid_contract');
  const oversized = request(); oversized.args.large = 'x'.repeat(2 * 1024 * 1024);
  rejects(() => validateExecutionRequest(oversized), 'invalid_contract');
});

test('principal scope must match all local and tenant ownership dimensions', () => {
  rejects(() => validateExecutionRequest(request(user, {scope: localScope})), 'authority_changed');
  for (const key of ['organizationId', 'projectId', 'environmentId']) {
    rejects(() => validateExecutionRequest(request(user, {scope: {...tenantScope, [key]: 'other'}})), 'authority_changed');
  }
});

test('missing-access requests require explicit app and account-selection intent', () => {
  for (const accountSelection of [{kind: 'owner_required'}, {kind: 'exact', accountId: 'provider-account-1'}]) {
    assert.equal(validateExecutionRequest(request(user, {access: {kind: 'missing', appId: 'github', accountSelection}})).access.kind, 'missing');
  }
  for (const access of [{kind: 'missing', appId: 'slack', accountSelection: {kind: 'owner_required'}},
    {kind: 'missing', appId: 'github', accountSelection: {kind: 'any'}},
    {kind: 'missing', appId: 'github', accountSelection: {kind: 'exact'}},
    {kind: 'connection', id: 'connection-1', generation: 3, appId: 'github'}]) {
    rejects(() => validateExecutionRequest(request(user, {access})), 'invalid_contract');
  }
});

test('canonical request hashes ignore object order but bind every immutable field', () => {
  const original = request();
  assert.equal(hashExecutionRequest(original), hashExecutionRequest(Object.fromEntries(Object.entries(original).reverse())));
  for (const mutation of [value => { value.id = 'execution-2'; }, value => { value.args.title = 'Changed'; },
    value => { value.access.id = 'connection-2'; }, value => { value.access.generation++; },
    value => { value.capability.version++; }, value => { value.capability.definitionHash = 'b'.repeat(64); },
    value => { value.capability.effect = 'read'; }, value => { value.policyRevision++; }, value => { value.idempotencyKey = 'key-2'; },
    value => { value.createdAt = '2026-10-11T09:59:00.000Z'; }, value => { value.deadline = '2026-10-11T12:00:00.000Z'; }]) {
    const changed = structuredClone(original); mutation(changed);
    assert.notEqual(hashExecutionRequest(changed), hashExecutionRequest(original));
  }
  assert.notEqual(hashExecutionRequest(request(user)), hashExecutionRequest(request(agent)));
});

test('exact local owner and end-user delegator approvals validate immutably', () => {
  for (const [req, human] of [[request(), localOwner], [request(localClient), localOwner], [request(user), user], [request(agent), user]]) {
    const source = approval(req, human), accepted = validateApproval(source, {request: req, now});
    assert.equal(accepted.decision, 'approved');
    source.decision = 'rejected'; assert.equal(accepted.decision, 'approved');
    assert.ok(Object.isFrozen(accepted.approver));
  }
  const req = request(user), sameSubject = {...user, id: 'different-authenticated-principal-record'};
  assert.equal(validateApproval(approval(req, sameSubject), {request: req, now}).approver.subjectId, user.subjectId);
});

test('local clients cannot approve their own or another caller request; only the exact local owner can', () => {
  const req = request(localClient), anotherClient = {...localClient, id: 'authenticated-grant-2'};
  for (const target of [req, request(anotherClient), request(localOwner)]) {
    rejects(() => validateApproval(approval(target, localClient), {request: target, now}), 'policy_denied');
  }
  const otherOwner = {...localOwner, id: 'other-owner', scope: {...localScope, localOwnerId: 'other-owner'}};
  rejects(() => validateApproval(approval(req, otherOwner), {request: req, now}), 'authority_changed');
  rejects(() => validateApproval(approval(req, user), {request: req, now}), 'authority_changed');
  const decision = approval(req, localOwner);
  assert.doesNotThrow(() => validateApproval(decision, {request: req, now}));
  rejects(() => validateApproval(decision, {request: request(anotherClient), now}), 'authority_changed');
});

test('local delegated request hashes and continuations cannot be transferred between client grant IDs', () => {
  const first = request(localClient), second = request({...localClient, id: 'authenticated-grant-2'});
  assert.notEqual(hashExecutionRequest(first), hashExecutionRequest(second));
  assert.notEqual(bindingForRequest(first).principalHash, bindingForRequest(second).principalHash);
  rejects(() => validateContinuation(continuation(first), {request: second, now}), 'authority_changed');
  rejects(() => assertIdempotencyCompatible(first, second), 'invalid_contract');
  assert.doesNotThrow(() => assertIdempotencyCompatible(first, structuredClone(first)));
});

test('approval rejects another product user developer service client or agent in the same scope', () => {
  const req = request(agent);
  for (const approver of [{...user, subjectId: 'other-user'}, {...service, kind: 'developer'}, service, agent]) {
    rejects(() => validateApproval(approval(req, approver), {request: req, now}), 'policy_denied');
  }
  rejects(() => validateApproval(approval(req, {...user, scope: {...tenantScope, environmentId: 'staging'}}), {request: req, now}), 'authority_changed');
  rejects(() => validateApproval(approval(req, {...user, workspaceId: 'another-workspace'}), {request: req, now}), 'policy_denied');
});

test('service-delegated requests cannot obtain human approval through ambient user authority', () => {
  const serviceAgent = {schemaVersion: 1, kind: 'agent', id: 'service-agent', scope: tenantScope, delegatedBy: {kind: 'service_client', id: service.id}, delegationId: 'service-delegation'};
  for (const actor of [service, serviceAgent]) {
    const req = request(actor);
    rejects(() => validateApproval(approval(req, user), {request: req, now}), 'policy_denied');
    assert.doesNotThrow(() => assertDispatchable(dispatch(req, service)));
  }
});

test('approval rejects changed arguments account generation principal and capability version', () => {
  const req = request(user), decision = approval(req);
  for (const mutate of [value => { value.args.title = 'other'; }, value => { value.access.id = 'other-account'; },
    value => { value.access.generation++; }, value => { value.policyRevision++; }, value => { value.principal.id = 'other-principal'; },
    value => { value.capability.version++; }, value => { value.capability.definitionHash = 'b'.repeat(64); }]) {
    const changed = structuredClone(req); mutate(changed);
    rejects(() => validateApproval(decision, {request: changed, now}), 'authority_changed');
  }
  for (const key of ['requestHash', 'principalHash', 'accessHash', 'capabilityHash']) {
    rejects(() => validateApproval({...decision, [key]: 'f'.repeat(64)}, {request: req, now}), 'authority_changed');
  }
});

test('approval expiry is exclusive and cannot exceed request deadline or precede creation', () => {
  const req = request(), decision = approval(req);
  rejects(() => validateApproval(decision, {request: req, now: expiresAt}), 'approval_expired');
  for (const changes of [{createdAt: '2026-10-11T10:03:00.000Z'}, {createdAt: '2026-10-11T09:00:00.000Z'},
    {expiresAt: '2026-10-11T12:00:00.000Z'}, {expiresAt: createdAt}]) {
    rejects(() => validateApproval({...decision, ...changes}, {request: req, now}), 'invalid_contract');
  }
  rejects(() => validateApproval(decision, {request: req, now: req.deadline}), 'deadline_exceeded');
});

test('rejected approval is retained as a valid record but blocks dispatch', () => {
  const req = request(), decision = approval(req, localOwner, {decision: 'rejected'});
  assert.equal(validateApproval(decision, {request: req, now}).decision, 'rejected');
  rejects(() => assertDispatchable({...dispatch(req, localOwner, 'ask'), approval: decision}), 'approval_rejected');
});

test('connection continuation binds missing-access requirement selection and caller without choosing an account', () => {
  const req = request(agent, {access: {kind: 'missing', appId: 'github', accountSelection: {kind: 'exact', accountId: 'account-1'}}});
  const handoff = continuation(req), validated = validateContinuation(handoff, {request: req, now});
  assert.equal(validated.kind, 'connection'); assert.ok(Object.isFrozen(validated));
  for (const changed of [request(agent, {access: {kind: 'missing', appId: 'github', accountSelection: {kind: 'exact', accountId: 'account-2'}}}),
    request(user, {access: req.access}), request(agent)]) {
    rejects(() => validateContinuation(handoff, {request: changed, now}), changed.access.kind === 'connection' ? 'invalid_contract' : 'authority_changed');
  }
  rejects(() => assertDispatchable({request: req, now, current: {}}), 'connection_required');
  rejects(() => validateApproval(approval(req, user), {request: req, now}), 'invalid_contract');
});

test('approval continuation binds exact request and expires without granting approval', () => {
  const req = request(), handoff = continuation(req);
  assert.equal(validateContinuation(handoff, {request: req, now}).kind, 'approval');
  rejects(() => validateContinuation(handoff, {request: req, now: expiresAt}), 'continuation_expired');
  rejects(() => validateContinuation({...handoff, expiresAt: req.createdAt}, {request: req, now}), 'invalid_contract');
  rejects(() => validateContinuation(handoff, {request: {...req, args: {}}, now}), 'authority_changed');
  rejects(() => assertDispatchable(dispatch(req, localOwner, 'ask')), 'approval_required');
});

test('dispatch checks current direct or delegated ownership and exact approved requests', () => {
  for (const [req, owner] of [[request(), localOwner], [request(localClient), localOwner], [request(user), user], [request(agent), user]]) {
    const context = {...dispatch(req, owner, 'ask'), approval: approval(req, owner)};
    assert.doesNotThrow(() => assertDispatchable(context));
    assert.deepEqual(context.request, req, 'Pure guard must not modify request or context');
  }
});

test('local client dispatch requires the authenticated grant principal and its trusted local owner', () => {
  const req = request(localClient), context = dispatch(req, localOwner);
  assert.doesNotThrow(() => assertDispatchable(context));
  for (const mutate of [
    value => { value.current.principal.id = 'replacement-grant'; },
    value => { value.current.ownerPrincipal = localClient; },
    value => { value.current.ownerPrincipal = {...localOwner, id: 'other-owner', scope: {...localScope, localOwnerId: 'other-owner'}}; },
    value => { value.current.connection.ownership = {schemaVersion: 1, scope: {...localScope, localOwnerId: 'other-owner'}, owner: {kind: 'local_owner', id: 'other-owner'}}; },
    value => { value.current.connection.generation++; },
    value => { value.current.connection.status = 'revoked'; },
  ]) {
    const changed = structuredClone(context); mutate(changed);
    rejects(() => assertDispatchable(changed), 'authority_changed');
  }
  const invalidDelegation = structuredClone(context); invalidDelegation.current.principal.delegatedBy.id = 'other-owner';
  rejects(() => assertDispatchable(invalidDelegation), 'invalid_contract');
  const clientOwned = structuredClone(context); clientOwned.current.connection.ownership.owner = {kind: 'local_client', id: localClient.id};
  rejects(() => assertDispatchable(clientOwned), 'authority_changed');
});

test('local-client exact approval still expires and cannot survive policy changes or altered arguments', () => {
  const req = request(localClient), decision = approval(req, localOwner), context = {...dispatch(req, localOwner, 'ask'), approval: decision};
  assert.doesNotThrow(() => assertDispatchable(context));
  rejects(() => assertDispatchable({...context, now: expiresAt}), 'approval_expired');
  for (const policy of [{revision: 8, decision: 'deny'}, {revision: 9, decision: 'ask'}, {revision: 10, decision: 'allow'}]) {
    rejects(() => assertDispatchable({...context, current: {...context.current, policy}}), 'authority_changed');
  }
  rejects(() => validateApproval(decision, {request: {...req, args: {title: 'changed'}}, now}), 'authority_changed');
  rejects(() => assertDispatchable(dispatch(req, localOwner, 'ask')), 'approval_required');
  rejects(() => assertDispatchable(dispatch(req, localOwner, 'deny')), 'policy_denied');
});

test('dispatch rejects revoked substituted stale-generation and wrong-app connections', () => {
  const req = request(user);
  for (const changes of [{status: 'revoked'}, {id: 'other'}, {generation: 4}, {appId: 'slack'},
    {ownership: {schemaVersion: 1, scope: tenantScope, owner: {kind: 'product_user', id: 'other-user'}}}]) {
    const context = dispatch(req); Object.assign(context.current.connection, changes);
    rejects(() => assertDispatchable(context), 'authority_changed');
  }
});

test('dispatch denies cross-scope ownership ambient developers and substituted delegations', () => {
  const req = request(agent);
  for (const mutate of [value => { value.current.scope.environmentId = 'other'; },
    value => { value.current.connection.ownership.scope.projectId = 'other'; },
    value => { value.current.ownerPrincipal.subjectId = 'other-user'; },
    value => { value.current.principal.delegationId = 'replacement-grant'; }]) {
    const context = dispatch(req, user); mutate(context);
    rejects(() => assertDispatchable(context), 'authority_changed');
  }
  const developer = {...service, kind: 'developer'}, devRequest = request(developer);
  rejects(() => assertDispatchable(dispatch(devRequest, user)), 'authority_changed');
});

test('dispatch checks retirement definition changes policy denial and deadline immediately before acceptance', () => {
  const req = request();
  const retired = dispatch(req); retired.current.capability.status = 'retired';
  rejects(() => assertDispatchable(retired), 'capability_retired');
  const changed = dispatch(req); changed.current.capability.reference.definitionHash = 'c'.repeat(64);
  rejects(() => assertDispatchable(changed), 'authority_changed');
  rejects(() => assertDispatchable(dispatch(req, localOwner, 'deny')), 'policy_denied');
  rejects(() => assertDispatchable({...dispatch(req), now: req.deadline}), 'deadline_exceeded');
  rejects(() => assertDispatchable({...dispatch(req), now: '2026-10-11T09:59:00.000Z'}), 'invalid_contract');
});

test('changed policy revision invalidates old approval after deny returns to ask', () => {
  const req=request(), decision=approval(req), context={...dispatch(req,localOwner,'ask'),approval:decision};
  assert.doesNotThrow(()=>assertDispatchable(context));
  context.current.policy={revision:req.policyRevision+1,decision:'deny'};
  rejects(()=>assertDispatchable(context),'authority_changed');
  context.current.policy={revision:req.policyRevision+2,decision:'ask'};
  rejects(()=>assertDispatchable(context),'authority_changed');
});

test('changed allow policy revision cannot silently authorize an accepted request', () => {
  const req=request(), context=dispatch(req);
  context.current.policy.revision++;
  rejects(()=>assertDispatchable(context),'authority_changed');
  const rebound={...req,policyRevision:context.current.policy.revision};
  assert.doesNotThrow(()=>assertDispatchable({...context,request:rebound}));
  rejects(()=>validateApproval(approval(req),{request:rebound,now}),'authority_changed');
  rejects(()=>assertIdempotencyCompatible(req,rebound),'idempotency_conflict');
});

test('current policy requires an exact bounded revision and decision record', () => {
  const req=request();
  for(const policy of ['allow',null,{}, {decision:'allow'}, {revision:0,decision:'allow'},
    {revision:'7',decision:'allow'}, {revision:1.5,decision:'allow'}, {revision:Number.MAX_SAFE_INTEGER+1,decision:'allow'},
    {revision:7,decision:'unknown'}, {revision:7,decision:'allow',approved:true}]) {
    const context=dispatch(req);context.current.policy=policy;
    rejects(()=>assertDispatchable(context),'invalid_contract');
  }
});

test('state transitions distinguish pending cancellation expiry and in-flight uncertainty', () => {
  for (const [from, to] of [['awaiting_connection', 'awaiting_approval'], ['awaiting_approval', 'queued'], ['queued', 'running'],
    ['running', 'succeeded'], ['queued', 'cancelled'], ['awaiting_approval', 'expired'], ['running', 'uncertain'], ['uncertain', 'succeeded']]) {
    assert.doesNotThrow(() => assertStateTransition(from, to, {effect: 'write'}));
  }
  for (const to of ['cancelled', 'expired', 'queued']) rejects(() => assertStateTransition('running', to, {effect: 'write'}), 'invalid_transition');
  for (const from of ['succeeded', 'failed', 'cancelled', 'expired']) rejects(() => assertStateTransition(from, 'queued', {effect: 'read'}), 'invalid_transition');
  rejects(() => assertStateTransition('unknown', 'queued', {effect: 'read'}), 'invalid_contract');
});

test('uncertain writes and deletes cannot return to the queue while reads may retry', () => {
  for (const effect of ['write', 'delete']) rejects(() => assertStateTransition('uncertain', 'queued', {effect}), 'invalid_transition');
  assert.doesNotThrow(() => assertStateTransition('uncertain', 'queued', {effect: 'read'}));
  rejects(() => assertStateTransition('uncertain', 'queued', {effect: 'write', retrySafe: true}), 'invalid_contract');
});

test('idempotency preserves exact acceptance and reports changed immutable same-key requests', () => {
  const req = request(user);
  assert.doesNotThrow(() => assertIdempotencyCompatible(req, structuredClone(req)));
  for (const changes of [{id: 'execution-2'}, {args: {title: 'changed'}}, {createdAt: '2026-10-11T09:59:00.000Z'}]) {
    rejects(() => assertIdempotencyCompatible(req, {...req, ...changes}), 'idempotency_conflict');
  }
  rejects(() => assertIdempotencyCompatible(req, {...req, idempotencyKey: 'another-key'}), 'invalid_contract');
  rejects(() => assertIdempotencyCompatible(req, request({...user, subjectId: 'another-subject'})), 'invalid_contract');
});

test('error taxonomy attributes failures explicitly and does not imply safe automatic retries', () => {
  for (const [code, definition] of Object.entries(ERROR_DEFINITIONS)) {
    const error = {schemaVersion: 1, code, ...definition, message: 'A bounded public explanation.'};
    assert.equal(validateExecutionError(error).code, code);
    rejects(() => validateExecutionError({...error, retryable: true}), 'invalid_contract');
    rejects(() => validateExecutionError({...error, source: 'unknown'}), 'invalid_contract');
  }
  rejects(() => validateExecutionError({schemaVersion: 1, code: 'provider_failed', source: 'fabric', retryable: false, message: 'Failure'}), 'invalid_contract');
});

test('schema documents strict versioned envelopes and the exported state/error vocabulary', async () => {
  const schema = JSON.parse(await readFile(new URL('../contracts/execution.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(schema.$defs.state.enum, [...EXECUTION_STATES]);
  assert.deepEqual(schema.$defs.error.properties.code.enum, Object.keys(ERROR_DEFINITIONS));
  for (const name of ['request', 'approval', 'continuation', 'error']) {
    assert.equal(schema.$defs[name].additionalProperties, false);
    assert.equal(schema.$defs[name].properties.schemaVersion.const, 1);
  }
  assert.equal(schema.$defs.approval.properties.approver.allOf[1].properties.kind.enum.includes('agent'), false);
  assert.equal(schema.$defs.approval.properties.approver.allOf[1].properties.kind.enum.includes('local_client'), false);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {assertDerivedRequest, bindingForRequest, validateApproval, assertDispatchable, assertStateTransition} from '../contracts/execution.mts';

// F02.3 contract: a missing-access request never executes; the derived request may differ
// only in id, account access, policy revision, idempotency key and times.
const scope = {schemaVersion: 1, kind: 'local', localOwnerId: 'owner'};
const owner = {schemaVersion: 1, id: 'owner', kind: 'local_owner', scope};
const client = {schemaVersion: 1, id: 'grant', kind: 'local_client', scope, delegatedBy: {kind: 'local_owner', id: 'owner'}};
const capability = {appId: 'github', id: 'github.createIssue', version: 1, definitionHash: 'a'.repeat(64), effect: 'write'};
const original = {schemaVersion: 1, id: 'handoff-1', scope, principal: client, access: {kind: 'missing', appId: 'github', accountSelection: {kind: 'owner_required'}},
  capability, args: {owner: 'o', repo: 'r', body: {title: 't'}}, policyRevision: 1, idempotencyKey: 'req-1', createdAt: '2026-10-11T10:00:00.000Z', deadline: '2026-10-11T10:30:00.000Z'};
const continuation = {schemaVersion: 1, id: 'handoff-1', kind: 'connection', createdAt: original.createdAt, expiresAt: original.deadline, ...bindingForRequest(original)};
const binding = {connectionId: 'acct-a', generation: 4, policyRevision: 7, decidedAt: '2026-10-11T10:05:00.000Z'};
const derived = {...original, id: 'job-1', access: {kind: 'connection', id: 'acct-a', generation: 4}, policyRevision: 7, idempotencyKey: 'handoff-1@continuation', createdAt: '2026-10-11T10:05:00.000Z', deadline: '2026-10-11T10:15:00.000Z'};
const check = (overrides = {}) => assertDerivedRequest({original, continuation, derived, binding, ...overrides});
const code = (fn, expected) => assert.throws(fn, error => error.code === expected, expected);

test('a derived request may change only id, access, policy revision, idempotency key and times', () => {
  assert.doesNotThrow(() => check());
});

test('derived requests that change the caller, operation, arguments or scope are authority changes', () => {
  code(() => check({derived: {...derived, args: {...derived.args, repo: 'other'}}}), 'authority_changed');
  for (const field of ['version', 'definitionHash', 'effect']) {
    const changed = {...capability, [field]: field === 'version' ? 2 : field === 'effect' ? 'read' : 'b'.repeat(64)};
    code(() => check({derived: {...derived, capability: changed}}), 'authority_changed');
  }
  code(() => check({derived: {...derived, principal: {...client, id: 'another-grant'}}}), 'authority_changed');
  const otherScope = {schemaVersion: 1, kind: 'local', localOwnerId: 'someone'};
  code(() => check({derived: {...derived, scope: otherScope, principal: {...client, scope: otherScope, delegatedBy: {kind: 'local_owner', id: 'someone'}}}}), 'authority_changed');
});

test('derived requests must be connection-bound, new, and bound to the owner decision', () => {
  code(() => check({derived: {...derived, access: original.access}}), 'invalid_contract');
  code(() => check({derived: {...derived, id: original.id}}), 'invalid_contract');
  code(() => check({derived: {...derived, idempotencyKey: original.idempotencyKey}}), 'invalid_contract');
  code(() => check({binding: {...binding, connectionId: 'acct-b'}}), 'authority_changed');
  code(() => check({binding: {...binding, generation: 5}}), 'authority_changed');
  code(() => check({binding: {...binding, policyRevision: 6}}), 'authority_changed');
  code(() => check({derived: {...derived, createdAt: '2026-10-11T10:04:59.000Z'}}), 'invalid_contract');
  code(() => check({binding: {...binding, decidedAt: original.deadline}}), 'deadline_exceeded');
  code(() => check({original: {...original, access: derived.access}}), 'invalid_contract');
  code(() => check({continuation: {...continuation, requestHash: 'c'.repeat(64)}}), 'authority_changed');
});

test('a missing-access request can be neither approved nor dispatched', () => {
  const approval = {schemaVersion: 1, id: 'approval', ...bindingForRequest(original), approver: owner, decision: 'approved', createdAt: '2026-10-11T10:01:00.000Z', expiresAt: '2026-10-11T10:20:00.000Z'};
  assert.throws(() => validateApproval(approval, {request: original, now: '2026-10-11T10:02:00.000Z'}));
  code(() => assertDispatchable({request: original, now: '2026-10-11T10:02:00.000Z', current: {}}), 'connection_required');
  for (const to of ['running', 'succeeded']) code(() => assertStateTransition('awaiting_connection', to, {effect: 'write'}), 'invalid_transition');
  assert.doesNotThrow(() => assertStateTransition('awaiting_connection', 'awaiting_approval', {effect: 'write'}));
});

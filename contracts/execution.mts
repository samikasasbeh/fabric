import {canonicalHash} from '../lib/compiler.mjs';
import {assertOwnedRecord, assertSameScope, validatePrincipal, validateScope} from './identity.mts';
import type {LocalOwnerPrincipal, OwnedRecord, Principal, ProductUserPrincipal, Scope} from './identity.mts';

// Pure contracts, not authentication, durable acceptance, scheduling, or a grant
// evaluator. Dispatch facts must come from trusted current repositories/policy.
export type JsonValue = null | boolean | number | string | readonly JsonValue[] | {readonly [key: string]: JsonValue};
export type Effect = 'read' | 'write' | 'delete';
export type CapabilityReference = Readonly<{appId: string; id: string; version: number; definitionHash: string; effect: Effect}>;
export type ConnectionAccess = Readonly<{kind: 'connection'; id: string; generation: number}>;
export type MissingAccess = Readonly<{
  kind: 'missing'; appId: string;
  accountSelection: Readonly<{kind: 'owner_required'}> | Readonly<{kind: 'exact'; accountId: string}>;
}>;
export type AccessRequirement = ConnectionAccess | MissingAccess;
export type ExecutionRequest = Readonly<{
  schemaVersion: 1; id: string; scope: Scope; principal: Principal; access: AccessRequirement;
  capability: CapabilityReference; args: {readonly [key: string]: JsonValue};
  /** Trusted acceptance-policy snapshot; missing-access handoffs must rebind after account selection. */
  policyRevision: number;
  idempotencyKey: string; createdAt: string; deadline: string;
}>;
export type RequestBinding = Readonly<{
  scope: Scope; requestHash: string; principalHash: string; accessHash: string; capabilityHash: string;
}>;
export type ApprovalRecord = RequestBinding & Readonly<{
  schemaVersion: 1; id: string; approver: LocalOwnerPrincipal | ProductUserPrincipal; decision: 'approved' | 'rejected'; createdAt: string; expiresAt: string;
}>;
export type ContinuationRecord = RequestBinding & Readonly<{
  schemaVersion: 1; id: string; kind: 'connection' | 'approval'; createdAt: string; expiresAt: string;
}>;
export const EXECUTION_STATES = Object.freeze([
  'awaiting_connection', 'awaiting_approval', 'queued', 'running', 'succeeded', 'failed', 'uncertain', 'cancelled', 'expired',
] as const);
export type ExecutionState = typeof EXECUTION_STATES[number];

export const ERROR_DEFINITIONS = Object.freeze({
  invalid_contract: Object.freeze({source: 'caller', retryable: false}),
  connection_required: Object.freeze({source: 'credential', retryable: false}),
  approval_required: Object.freeze({source: 'policy', retryable: false}),
  approval_rejected: Object.freeze({source: 'policy', retryable: false}),
  approval_expired: Object.freeze({source: 'policy', retryable: false}),
  continuation_expired: Object.freeze({source: 'credential', retryable: false}),
  deadline_exceeded: Object.freeze({source: 'caller', retryable: false}),
  authority_changed: Object.freeze({source: 'policy', retryable: false}),
  capability_retired: Object.freeze({source: 'policy', retryable: false}),
  idempotency_conflict: Object.freeze({source: 'caller', retryable: false}),
  invalid_transition: Object.freeze({source: 'fabric', retryable: false}),
  provider_failed: Object.freeze({source: 'provider', retryable: false}),
  credential_expired: Object.freeze({source: 'credential', retryable: false}),
  policy_denied: Object.freeze({source: 'policy', retryable: false}),
  delivery_failed: Object.freeze({source: 'delivery', retryable: false}),
  fabric_failed: Object.freeze({source: 'fabric', retryable: false}),
  outcome_uncertain: Object.freeze({source: 'provider', retryable: false}),
  // F10.11 part h: an action's own refusal (a guard, a map transform or a run-time rule, the reason in details.reason), and a resource whose
  // fields changed between the read the owner approved and the send.
  input_schema_changed: Object.freeze({source: 'caller', retryable: false}),
  action_refused: Object.freeze({source: 'caller', retryable: false}),
} as const);
export type ExecutionErrorCode = keyof typeof ERROR_DEFINITIONS;
export type ExecutionErrorRecord = Readonly<{
  schemaVersion: 1; code: ExecutionErrorCode; source: 'caller' | 'fabric' | 'provider' | 'credential' | 'policy' | 'delivery';
  retryable: false; message: string;
}>;
export class ExecutionContractError extends Error {
  readonly code: ExecutionErrorCode;
  constructor(code: ExecutionErrorCode, message: string) { super(message); this.name = 'ExecutionContractError'; this.code = code; }
}

type RecordValue = Record<string, unknown>;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
// Compiler capability IDs may exceed identity/request IDs; never truncate them.
const CAPABILITY_ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/;
const HASH = /^[a-f0-9]{64}$/;
const isRecord = (value: unknown): value is RecordValue => value !== null && typeof value === 'object' && !Array.isArray(value);
function fail(code: ExecutionErrorCode, message: string): never { throw new ExecutionContractError(code, message); }
function invalid(): never { return fail('invalid_contract', 'Invalid execution contract.'); }
function bounded(value: unknown): void { try { canonicalHash(value); } catch { invalid(); } }
function shape(value: unknown, fields: readonly string[]): asserts value is RecordValue {
  if (!isRecord(value) || Object.keys(value).some(key => !fields.includes(key)) || fields.some(key => !Object.hasOwn(value, key))) invalid();
}
function id(value: unknown): asserts value is string { if (typeof value !== 'string' || !ID.test(value)) invalid(); }
function hash(value: unknown): asserts value is string { if (typeof value !== 'string' || !HASH.test(value)) invalid(); }
function positive(value: unknown): asserts value is number { if (!Number.isSafeInteger(value) || (value as number) < 1) invalid(); }
function time(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) invalid();
  const parsed = Date.parse(value), normalized = value.includes('.') ? value : value.replace('Z', '.000Z');
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== normalized) invalid();
  return parsed;
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
function detached<T>(value: unknown): T { return freeze(JSON.parse(JSON.stringify(value)) as T); }
function scopeEqual(left: Scope, right: Scope): void {
  try { assertSameScope(left, right); } catch { fail('authority_changed', 'Execution scope no longer matches.'); }
}
function principal(value: unknown): Principal { try { return validatePrincipal(value); } catch { return invalid(); } }
function scope(value: unknown): Scope { try { return validateScope(value); } catch { return invalid(); } }

export function validateCapabilityReference(value: unknown): CapabilityReference {
  bounded(value);
  shape(value, ['appId', 'id', 'version', 'definitionHash', 'effect']);
  if (typeof value.appId !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(value.appId)) invalid();
  if (typeof value.id !== 'string' || !CAPABILITY_ID.test(value.id)) invalid();
  positive(value.version); hash(value.definitionHash);
  if (!['read', 'write', 'delete'].includes(value.effect as string)) invalid();
  return detached<CapabilityReference>(value);
}

function access(value: unknown, appId: string): AccessRequirement {
  if (!isRecord(value)) invalid();
  if (value.kind === 'connection') {
    shape(value, ['kind', 'id', 'generation']); id(value.id); positive(value.generation);
  } else {
    shape(value, ['kind', 'appId', 'accountSelection']);
    if (value.kind !== 'missing' || value.appId !== appId || !isRecord(value.accountSelection)) invalid();
    if (value.accountSelection.kind === 'owner_required') shape(value.accountSelection, ['kind']);
    else { shape(value.accountSelection, ['kind', 'accountId']); if (value.accountSelection.kind !== 'exact') invalid(); id(value.accountSelection.accountId); }
  }
  return detached<AccessRequirement>(value);
}

export function validateExecutionRequest(value: unknown): ExecutionRequest {
  bounded(value);
  shape(value, ['schemaVersion', 'id', 'scope', 'principal', 'access', 'capability', 'args', 'policyRevision', 'idempotencyKey', 'createdAt', 'deadline']);
  if (value.schemaVersion !== 1) invalid();
  id(value.id); id(value.idempotencyKey); positive(value.policyRevision);
  const requestScope = scope(value.scope), actor = principal(value.principal), capability = validateCapabilityReference(value.capability);
  scopeEqual(requestScope, actor.scope);
  access(value.access, capability.appId);
  if (!isRecord(value.args) || time(value.deadline) <= time(value.createdAt)) invalid();
  return detached<ExecutionRequest>(value);
}

/** Hash includes IDs, timestamps, caller, exact account generation, policy revision and every argument. */
export function hashExecutionRequest(value: unknown): string { return canonicalHash(validateExecutionRequest(value)); }
export function bindingForRequest(value: unknown): RequestBinding {
  const request = validateExecutionRequest(value);
  return freeze({scope: request.scope, requestHash: canonicalHash(request), principalHash: canonicalHash(request.principal), accessHash: canonicalHash(request.access), capabilityHash: canonicalHash(request.capability)});
}

function recordContext(value: unknown): {request: ExecutionRequest; now: number} {
  bounded(value); shape(value, ['request', 'now']);
  const request = validateExecutionRequest(value.request), now = time(value.now);
  if (now < time(request.createdAt)) invalid();
  if (now >= time(request.deadline)) fail('deadline_exceeded', 'The execution deadline has expired.');
  return {request, now};
}
function assertBinding(value: RecordValue, request: ExecutionRequest): void {
  const binding = bindingForRequest(request);
  scopeEqual(scope(value.scope), binding.scope);
  for (const key of ['requestHash', 'principalHash', 'accessHash', 'capabilityHash'] as const) {
    hash(value[key]);
    if (value[key] !== binding[key]) fail('authority_changed', 'The record does not match the immutable execution request.');
  }
}
function recordLifetime(value: RecordValue, request: ExecutionRequest, now: number, code: 'approval_expired' | 'continuation_expired'): void {
  const created = time(value.createdAt), expires = time(value.expiresAt);
  if (created < time(request.createdAt) || created > now || expires <= created || expires > time(request.deadline)) invalid();
  if (now >= expires) fail(code, 'The execution handoff or approval has expired.');
}
function workspace(actor: Principal): string | undefined { return actor.kind === 'local_owner' || actor.kind === 'local_client' ? undefined : actor.workspaceId; }
function assertHumanOwner(approver: Principal, requester: Principal): void {
  scopeEqual(approver.scope, requester.scope);
  const local = approver.kind === 'local_owner' && (
    requester.kind === 'local_owner' && approver.id === requester.id ||
    requester.kind === 'local_client' && approver.id === requester.delegatedBy.id
  );
  const user = approver.kind === 'product_user' && workspace(approver) === workspace(requester) && (
    requester.kind === 'product_user' && approver.subjectId === requester.subjectId ||
    requester.kind === 'agent' && requester.delegatedBy.kind === 'product_user' && approver.subjectId === requester.delegatedBy.id
  );
  if (!local && !user) fail('policy_denied', 'Approval requires the exact human owner or user delegator.');
}

/** A rejected decision is a valid record; dispatch separately denies its use. */
export function validateApproval(value: unknown, context: unknown): ApprovalRecord {
  bounded(value);
  shape(value, ['schemaVersion', 'id', 'scope', 'requestHash', 'principalHash', 'accessHash', 'capabilityHash', 'approver', 'decision', 'createdAt', 'expiresAt']);
  const {request, now} = recordContext(context);
  if (value.schemaVersion !== 1 || request.access.kind !== 'connection' || !['approved', 'rejected'].includes(value.decision as string)) invalid();
  id(value.id); assertBinding(value, request); assertHumanOwner(principal(value.approver), request.principal);
  recordLifetime(value, request, now, 'approval_expired');
  return detached<ApprovalRecord>(value);
}

/** Validates the original handoff only; does not authenticate a callback or select an account. */
export function validateContinuation(value: unknown, context: unknown): ContinuationRecord {
  bounded(value);
  shape(value, ['schemaVersion', 'id', 'scope', 'requestHash', 'principalHash', 'accessHash', 'capabilityHash', 'kind', 'createdAt', 'expiresAt']);
  const {request, now} = recordContext(context);
  if (value.schemaVersion !== 1 || value.kind !== (request.access.kind === 'missing' ? 'connection' : 'approval')) invalid();
  id(value.id); assertBinding(value, request); recordLifetime(value, request, now, 'continuation_expired');
  return detached<ContinuationRecord>(value);
}

export type DerivedBinding = Readonly<{connectionId: string; generation: number; policyRevision: number; decidedAt: string}>;
/**
 * A missing-access handoff never executes. After the owner binds an exact account,
 * trusted code derives a new request that may differ from the original only in its
 * id, account access, policy revision, idempotency key and times. Pure check; it
 * neither authenticates the binding nor reads current policy.
 */
export function assertDerivedRequest(value: unknown): void {
  bounded(value);
  shape(value, ['original', 'continuation', 'derived', 'binding']);
  const original = validateExecutionRequest(value.original), derived = validateExecutionRequest(value.derived);
  shape(value.binding, ['connectionId', 'generation', 'policyRevision', 'decidedAt']);
  const binding = value.binding;
  id(binding.connectionId); positive(binding.generation); positive(binding.policyRevision);
  const decided = time(binding.decidedAt);
  if (original.access.kind !== 'missing' || derived.access.kind !== 'connection') invalid();
  // The handoff authorizes the binding decision, not the later dispatch.
  validateContinuation(value.continuation, {request: original, now: binding.decidedAt});
  if (derived.id === original.id || derived.idempotencyKey !== `${original.id}@continuation`) invalid();
  scopeEqual(derived.scope, original.scope);
  if (canonicalHash(derived.principal) !== canonicalHash(original.principal)) fail('authority_changed', 'The derived request changed its caller.');
  if (canonicalHash(derived.capability) !== canonicalHash(original.capability)) fail('authority_changed', 'The derived request changed its operation.');
  if (canonicalHash(derived.args) !== canonicalHash(original.args)) fail('authority_changed', 'The derived request changed its arguments.');
  if (derived.access.id !== binding.connectionId || derived.access.generation !== binding.generation) fail('authority_changed', 'The derived request is not bound to the selected account.');
  if (derived.policyRevision !== binding.policyRevision) fail('authority_changed', 'The derived request is not bound to the policy the owner saw.');
  if (time(derived.createdAt) < decided) invalid();
}

export function validateExecutionError(value: unknown): ExecutionErrorRecord {
  bounded(value); shape(value, ['schemaVersion', 'code', 'source', 'retryable', 'message']);
  if (value.schemaVersion !== 1 || typeof value.code !== 'string' || !Object.hasOwn(ERROR_DEFINITIONS, value.code)) invalid();
  const definition = ERROR_DEFINITIONS[value.code as ExecutionErrorCode];
  if (value.source !== definition.source || value.retryable !== definition.retryable || typeof value.message !== 'string' ||
      !value.message.trim() || value.message.length > 500 || /[\u0000-\u001f\u007f]/.test(value.message)) invalid();
  return detached<ExecutionErrorRecord>(value);
}

const TRANSITIONS: Readonly<Record<ExecutionState, readonly ExecutionState[]>> = Object.freeze({
  awaiting_connection: Object.freeze(['awaiting_approval', 'queued', 'failed', 'cancelled', 'expired'] as const),
  awaiting_approval: Object.freeze(['queued', 'failed', 'cancelled', 'expired'] as const),
  queued: Object.freeze(['running', 'failed', 'cancelled', 'expired'] as const),
  running: Object.freeze(['succeeded', 'failed', 'uncertain', 'awaiting_approval'] as const),
  uncertain: Object.freeze(['succeeded', 'failed', 'queued'] as const),
  succeeded: Object.freeze([]), failed: Object.freeze([]), cancelled: Object.freeze([]), expired: Object.freeze([]),
});
export function assertStateTransition(from: unknown, to: unknown, context: unknown): void {
  // The caller supplies the accepted immutable capability's effect, never an
  // unchecked replacement effect from a retry request. This does not enqueue.
  // F10.11 part j: a run may stop for an approval only for an action, and only while nothing but its resolving write was sent; that one
  // transition takes {effect, kind, writesSent, resolvingStepId}, every other keeps {effect}.
  const card = from === 'running' && to === 'awaiting_approval';
  bounded({from, to, context}); shape(context, card ? ['effect', 'kind', 'writesSent', 'resolvingStepId'] : ['effect']);
  if (!EXECUTION_STATES.includes(from as ExecutionState) || !EXECUTION_STATES.includes(to as ExecutionState) || !['read', 'write', 'delete'].includes(context.effect as string)) invalid();
  if (card && (!Array.isArray(context.writesSent) || !context.writesSent.every(step => typeof step === 'string') || !(context.resolvingStepId === null || typeof context.resolvingStepId === 'string'))) invalid();
  if (card && (context.kind !== 'action' || (context.writesSent as string[]).some(step => step !== context.resolvingStepId))) {
    fail('invalid_transition', 'A run stops for an approval only for an action that has sent nothing but its resolving write.');
  }
  if (!TRANSITIONS[from as ExecutionState].includes(to as ExecutionState) || from === 'uncertain' && to === 'queued' && context.effect !== 'read') {
    fail('invalid_transition', 'This execution transition is not permitted; uncertain writes cannot be replayed.');
  }
}

/** Call after lookup by scope + authenticated principal + idempotency key. */
export function assertIdempotencyCompatible(existing: unknown, incoming: unknown): void {
  const left = validateExecutionRequest(existing), right = validateExecutionRequest(incoming);
  if (canonicalHash(left.scope) !== canonicalHash(right.scope) || canonicalHash(left.principal) !== canonicalHash(right.principal) || left.idempotencyKey !== right.idempotencyKey) invalid();
  if (canonicalHash(left) !== canonicalHash(right)) fail('idempotency_conflict', 'This idempotency key is already bound to a different immutable request.');
}

export type CurrentConnection = Readonly<{id: string; generation: number; appId: string; status: 'active' | 'revoked'; ownership: OwnedRecord}>;
export type CurrentPolicy = Readonly<{revision: number; decision: 'allow' | 'ask' | 'deny'}>;
export type DispatchContext = Readonly<{
  request: ExecutionRequest; now: string; approval?: ApprovalRecord;
  /** Server-authenticated current authorization facts. Never populate these by copying unchecked request fields. */
  current: Readonly<{
    scope: Scope; principal: Principal; ownerPrincipal: Principal; connection: CurrentConnection;
    capability: Readonly<{reference: CapabilityReference; status: 'active' | 'retired'}>; policy: CurrentPolicy;
  }>;
}>;

/** Checks server-authenticated current facts for staleness; performs no authentication, dispatch or durable enforcement. */
export function assertDispatchable(value: unknown): void {
  bounded(value);
  if (!isRecord(value)) invalid();
  shape(value, Object.hasOwn(value, 'approval') ? ['request', 'now', 'current', 'approval'] : ['request', 'now', 'current']);
  const {request, now} = recordContext({request: value.request, now: value.now});
  if (request.access.kind !== 'connection') fail('connection_required', 'Connect and bind the selected account before preparing dispatch.');
  shape(value.current, ['scope', 'principal', 'ownerPrincipal', 'connection', 'capability', 'policy']);
  const current = value.current, actor = principal(current.principal), owner = principal(current.ownerPrincipal);
  scopeEqual(scope(current.scope), request.scope); scopeEqual(actor.scope, request.scope); scopeEqual(owner.scope, request.scope);
  if (canonicalHash(actor) !== canonicalHash(request.principal)) fail('authority_changed', 'The requesting principal or delegation changed.');
  shape(current.connection, ['id', 'generation', 'appId', 'status', 'ownership']);
  id(current.connection.id); positive(current.connection.generation);
  if (!['active', 'revoked'].includes(current.connection.status as string)) invalid();
  if (current.connection.status !== 'active' || current.connection.id !== request.access.id || current.connection.generation !== request.access.generation || current.connection.appId !== request.capability.appId) {
    fail('authority_changed', 'The exact connection is no longer active with the accepted generation and application.');
  }
  try { assertOwnedRecord(owner, current.connection.ownership as OwnedRecord); }
  catch { fail('authority_changed', 'Current connection ownership does not match the authorized owner.'); }
  if (actor.kind === 'local_client') {
    // The caller must already have authenticated the exact active client grant.
    // This equality check cannot establish that delegation from supplied JSON.
    if (owner.kind !== 'local_owner' || actor.delegatedBy.id !== owner.id) fail('authority_changed', 'The trusted local owner does not match this client delegation.');
  } else if (actor.kind === 'agent') {
    const matches = actor.delegatedBy.kind === 'product_user' && owner.kind === 'product_user' && actor.delegatedBy.id === owner.subjectId ||
      actor.delegatedBy.kind === 'service_client' && owner.kind === 'service_client' && actor.delegatedBy.id === owner.id;
    if (!matches || workspace(actor) !== workspace(owner)) fail('authority_changed', 'The trusted owner does not match this agent delegation.');
  } else {
    try { assertOwnedRecord(actor, current.connection.ownership as OwnedRecord); }
    catch { fail('authority_changed', 'The requester does not directly own this connection.'); }
  }
  shape(current.capability, ['reference', 'status']);
  const capability = validateCapabilityReference(current.capability.reference);
  if (!['active', 'retired'].includes(current.capability.status as string)) invalid();
  if (current.capability.status === 'retired') fail('capability_retired', 'This capability version has been retired.');
  if (canonicalHash(capability) !== canonicalHash(request.capability)) fail('authority_changed', 'The accepted capability version or definition changed.');
  shape(current.policy, ['revision', 'decision']); positive(current.policy.revision);
  if (!['allow', 'ask', 'deny'].includes(current.policy.decision as string)) invalid();
  if (current.policy.revision !== request.policyRevision) fail('authority_changed', 'The accepted policy revision changed. Prepare a new request.');
  if (current.policy.decision === 'deny') fail('policy_denied', 'Current policy denies this operation.');
  if (current.policy.decision === 'ask' && !Object.hasOwn(value, 'approval')) fail('approval_required', 'An exact human approval is required.');
  if (Object.hasOwn(value, 'approval')) {
    const approval = validateApproval(value.approval, {request, now: new Date(now).toISOString()});
    if (approval.decision !== 'approved') fail('approval_rejected', 'The human owner rejected this request.');
  }
}

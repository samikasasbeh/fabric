import { canonicalHash } from '../lib/compiler.mjs';

// These contracts prove shape and ownership equality only. Authentication,
// backend assertions, delegation grants, membership, and policy are separate.
export type LocalScope = Readonly<{ schemaVersion: 1; kind: 'local'; localOwnerId: string }>;
export type TenantScope = Readonly<{
  schemaVersion: 1; kind: 'tenant'; organizationId: string; projectId: string; environmentId: string;
}>;
export type Scope = LocalScope | TenantScope;

type PrincipalBase<Kind extends string, PrincipalScope extends Scope> = Readonly<{
  schemaVersion: 1;
  /** Fabric principal record ID; distinct from the upstream product-user subject. */
  id: string;
  kind: Kind;
  scope: PrincipalScope;
}>;
type WorkspaceContext = Readonly<{
  /** Context label only: this does not prove membership or grant workspace access. */
  workspaceId?: string;
}>;

export type LocalOwnerPrincipal = PrincipalBase<'local_owner', LocalScope>;
/** id is the authenticated local grant ID, never an owner credential or grant proof by itself. */
export type LocalClientPrincipal = PrincipalBase<'local_client', LocalScope> & Readonly<{
  delegatedBy: Readonly<{ kind: 'local_owner'; id: string }>;
  subjectId?: never;
  workspaceId?: never;
  delegationId?: never;
}>;
export type DeveloperPrincipal = PrincipalBase<'developer', TenantScope> & WorkspaceContext;
export type ServiceClientPrincipal = PrincipalBase<'service_client', TenantScope> & WorkspaceContext;
export type ProductUserPrincipal = PrincipalBase<'product_user', TenantScope> & WorkspaceContext & Readonly<{
  /** Upstream end-user ID asserted by an authenticated customer backend. */
  subjectId: string;
}>;
export type UserDelegatedAgent = PrincipalBase<'agent', TenantScope> & WorkspaceContext & Readonly<{
  subjectId: string;
  /** For product_user delegation, id equals subjectId, not a Fabric principal ID. */
  delegatedBy: Readonly<{ kind: 'product_user'; id: string }>;
  delegationId: string;
}>;
export type ServiceDelegatedAgent = PrincipalBase<'agent', TenantScope> & WorkspaceContext & Readonly<{
  subjectId?: never;
  delegatedBy: Readonly<{ kind: 'service_client'; id: string }>;
  delegationId: string;
}>;
export type Principal = LocalOwnerPrincipal | LocalClientPrincipal | DeveloperPrincipal | ServiceClientPrincipal | ProductUserPrincipal | UserDelegatedAgent | ServiceDelegatedAgent;

export type TenantOwner = Readonly<{
  /** product_user IDs are upstream subject IDs; service_client IDs are Fabric principal IDs. */
  kind: 'product_user' | 'service_client' | 'workspace';
  id: string;
}>;
export type OwnedRecord = Readonly<{
  schemaVersion: 1; scope: LocalScope; owner: Readonly<{ kind: 'local_owner'; id: string }>;
}> | Readonly<{
  schemaVersion: 1; scope: TenantScope; owner: TenantOwner;
}>;

type DataRecord = Record<string, unknown>;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const MAX_BYTES = 8192;
const has = (value: object, key: PropertyKey): boolean => Object.hasOwn(value, key);
function invalid(): never { throw new Error('Invalid identity contract.'); }
const isRecord = (value: unknown): value is DataRecord => value !== null && typeof value === 'object' && !Array.isArray(value);

function boundedJson(value: unknown): void {
  // Reuse the compiler's descriptor-first guard before any property access.
  // Never relay its source-controlled field names or values in contract errors.
  try {
    canonicalHash(value);
    if (Buffer.byteLength(JSON.stringify(value)) > MAX_BYTES) invalid();
  } catch { invalid(); }
}

function shape(value: unknown, allowed: readonly string[], required: readonly string[]): asserts value is DataRecord {
  if (!isRecord(value) || Object.keys(value).some(key => !allowed.includes(key)) || required.some(key => !has(value, key))) invalid();
}

function identifier(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !ID.test(value)) invalid();
}

function scope(value: unknown): Scope {
  if (!isRecord(value) || value.schemaVersion !== 1) invalid();
  if (value.kind === 'local') {
    shape(value, ['schemaVersion', 'kind', 'localOwnerId'], ['schemaVersion', 'kind', 'localOwnerId']);
    identifier(value.localOwnerId);
    return Object.freeze({ schemaVersion: 1, kind: 'local', localOwnerId: value.localOwnerId });
  }
  if (value.kind === 'tenant') {
    shape(value, ['schemaVersion', 'kind', 'organizationId', 'projectId', 'environmentId'], ['schemaVersion', 'kind', 'organizationId', 'projectId', 'environmentId']);
    identifier(value.organizationId); identifier(value.projectId); identifier(value.environmentId);
    return Object.freeze({ schemaVersion: 1, kind: 'tenant', organizationId: value.organizationId, projectId: value.projectId, environmentId: value.environmentId });
  }
  return invalid();
}

export function validateScope(value: unknown): Scope {
  boundedJson(value);
  return scope(value);
}

export function validatePrincipal(value: unknown): Principal {
  boundedJson(value);
  shape(value, ['schemaVersion', 'id', 'kind', 'scope', 'subjectId', 'workspaceId', 'delegatedBy', 'delegationId'], ['schemaVersion', 'id', 'kind', 'scope']);
  if (value.schemaVersion !== 1) invalid();
  identifier(value.id);
  const ownedScope = scope(value.scope);
  if (value.kind === 'local_owner') {
    shape(value, ['schemaVersion', 'id', 'kind', 'scope'], ['schemaVersion', 'id', 'kind', 'scope']);
    if (ownedScope.kind !== 'local' || value.id !== ownedScope.localOwnerId) invalid();
    return Object.freeze({ schemaVersion: 1, id: value.id, kind: 'local_owner', scope: ownedScope });
  }
  if (value.kind === 'local_client') {
    shape(value, ['schemaVersion', 'id', 'kind', 'scope', 'delegatedBy'], ['schemaVersion', 'id', 'kind', 'scope', 'delegatedBy']);
    shape(value.delegatedBy, ['kind', 'id'], ['kind', 'id']);
    identifier(value.delegatedBy.id);
    if (ownedScope.kind !== 'local' || value.delegatedBy.kind !== 'local_owner' || value.delegatedBy.id !== ownedScope.localOwnerId || value.id === value.delegatedBy.id) invalid();
    return Object.freeze({ schemaVersion: 1, id: value.id, kind: 'local_client', scope: ownedScope, delegatedBy: Object.freeze({ kind: 'local_owner', id: value.delegatedBy.id }) });
  }
  if (ownedScope.kind !== 'tenant') invalid();
  let context: WorkspaceContext = {};
  if (has(value, 'workspaceId')) { identifier(value.workspaceId); context = { workspaceId: value.workspaceId }; }
  const common = { schemaVersion: 1 as const, id: value.id, scope: ownedScope, ...context };
  if (value.kind === 'developer' || value.kind === 'service_client') {
    shape(value, ['schemaVersion', 'id', 'kind', 'scope', 'workspaceId'], ['schemaVersion', 'id', 'kind', 'scope']);
    return Object.freeze({ ...common, kind: value.kind });
  }
  if (value.kind === 'product_user') {
    shape(value, ['schemaVersion', 'id', 'kind', 'scope', 'workspaceId', 'subjectId'], ['schemaVersion', 'id', 'kind', 'scope', 'subjectId']);
    identifier(value.subjectId);
    return Object.freeze({ ...common, kind: 'product_user', subjectId: value.subjectId });
  }
  if (value.kind !== 'agent') invalid();
  identifier(value.delegationId);
  shape(value.delegatedBy, ['kind', 'id'], ['kind', 'id']);
  identifier(value.delegatedBy.id);
  if (value.id === value.delegatedBy.id) invalid();
  if (value.delegatedBy.kind === 'product_user') {
    identifier(value.subjectId);
    if (value.subjectId !== value.delegatedBy.id) invalid();
    return Object.freeze({ ...common, kind: 'agent', subjectId: value.subjectId, delegationId: value.delegationId, delegatedBy: Object.freeze({ kind: 'product_user', id: value.delegatedBy.id }) });
  }
  if (value.delegatedBy.kind !== 'service_client' || has(value, 'subjectId')) invalid();
  return Object.freeze({ ...common, kind: 'agent', delegationId: value.delegationId, delegatedBy: Object.freeze({ kind: 'service_client', id: value.delegatedBy.id }) });
}

export function assertSameScope(left: Scope, right: Scope): void {
  const a = validateScope(left);
  const b = validateScope(right);
  const same = a.kind === 'local'
    ? b.kind === 'local' && a.localOwnerId === b.localOwnerId
    : b.kind === 'tenant' && a.organizationId === b.organizationId && a.projectId === b.projectId && a.environmentId === b.environmentId;
  if (!same) throw new Error('Identity scope mismatch.');
}

function ownedRecord(value: unknown): OwnedRecord {
  boundedJson(value);
  shape(value, ['schemaVersion', 'scope', 'owner'], ['schemaVersion', 'scope', 'owner']);
  if (value.schemaVersion !== 1) invalid();
  const ownedScope = scope(value.scope);
  shape(value.owner, ['kind', 'id'], ['kind', 'id']);
  identifier(value.owner.id);
  if (ownedScope.kind === 'local') {
    if (value.owner.kind !== 'local_owner' || value.owner.id !== ownedScope.localOwnerId) invalid();
    return Object.freeze({ schemaVersion: 1, scope: ownedScope, owner: Object.freeze({ kind: 'local_owner', id: value.owner.id }) });
  }
  if (!['product_user', 'service_client', 'workspace'].includes(value.owner.kind as string)) invalid();
  return Object.freeze({ schemaVersion: 1, scope: ownedScope, owner: Object.freeze({ kind: value.owner.kind as TenantOwner['kind'], id: value.owner.id }) });
}

/** Direct ownership assertion only: never an authentication or sharing-policy check. */
export function assertOwnedRecord(principal: Principal, record: OwnedRecord): void {
  const actor = validatePrincipal(principal);
  const target = ownedRecord(record);
  assertSameScope(actor.scope, target.scope);
  const directOwner = actor.kind === 'local_owner' && target.owner.kind === 'local_owner' && actor.id === target.owner.id
    || actor.kind === 'product_user' && target.owner.kind === 'product_user' && actor.subjectId === target.owner.id
    || actor.kind === 'service_client' && target.owner.kind === 'service_client' && actor.id === target.owner.id;
  // Developers have no implicit administrative ownership. Local clients and
  // agents need a grant evaluator; workspace labels need membership/sharing policy.
  if (!directOwner) throw new Error('Direct record ownership required.');
}

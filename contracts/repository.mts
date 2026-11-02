import type {LocalScope, Scope} from './identity.mts';

/** UTC epoch milliseconds. This does not virtualize timers or driver clocks. */
export type Clock = () => number;

export function checkedClock(clock: Clock = Date.now): Clock {
  if (typeof clock !== 'function') throw new Error('A clock function is required.');
  return () => {
    const value = clock();
    if (!Number.isSafeInteger(value) || Math.abs(value) > 8_640_000_000_000_000) throw new Error('Clock must return valid integer epoch milliseconds.');
    return value;
  };
}

export type RepositoryDocument = {id: string; [key: string]: unknown};
/** Explicit designation only; never a live-store migration or lazy baseline. */
export type LocalAuthorityMode = 'new' | 'baseline' | 'require';

export interface LocalAuthorityPort {
  readonly authorityEnabled: boolean;
  /** Includes retained tombstones; an ID that never existed is rejected. */
  connectionGeneration(id: string): number;
  /** Includes tombstones; a never-written default policy has baseline 1. */
  policyRevision(id: string): number;
}

/** One poll for the trigger tables (lib/store.mjs): seen rows hold hashes only, and `payload` is any JSON of at most 8,192 bytes. */
export type TriggerSeenRow = {lens: string; itemKey: string; valueHash: string; generation: number; connectionId: string};
export type TriggerEvent = {clientId: string; subscriptionId: string; dedupeKey: string; connectionId: string; userRecordId?: string | null; kind: string; itemTime?: number; createdAt: number; expiresAt: number; payload: unknown};
export type TriggerPoll = {feedId: string; seen?: TriggerSeenRow[]; seenLimits?: Record<string, {limit: number; evict: boolean}>; events?: TriggerEvent[]};
export type TriggerPollResult = {added: Record<string, number>; overLimit: {lens: string; count: number}[]};
export type TriggerSeenState = {valueHash: string; generation: number};
export type TriggerEventRow = {sequence: number; subscriptionId: string; dedupeKey: string; connectionId: string; userRecordId: string | null; kind: string; createdAt: number; expiresAt: number; payload: unknown};

/** Existing synchronous document API; not a transactional unit of work. */
export interface DocumentStore {
  readonly authorityEnabled?: boolean;
  connectionGeneration?(id: string): number;
  policyRevision?(id: string): number;
  get(collection: string, id: string): RepositoryDocument | null;
  list(collection: string): RepositoryDocument[];
  /** Optional: the documents whose top-level field equals value, read through an index. */
  listWhere?(collection: string, field: string, value: string): RepositoryDocument[];
  put(collection: string, document: RepositoryDocument): RepositoryDocument;
  delete(collection: string, id: string): boolean;
  audit(event: Record<string, unknown>): RepositoryDocument;
  close(): void;
  /** Optional: the trigger tables, made by the first poll stored. One commit for one poll, never a general transaction. */
  appendPoll?(poll: TriggerPoll): TriggerPollResult;
  seenRows?(feedId: string, lens: string, keys: string[]): Map<string, TriggerSeenState>;
  listEvents?(clientId: string, after: number, limit: number): TriggerEventRow[];
  latestSequence?(clientId: string): number;
  deleteSubscriptionEvents?(id: string): number;
  deleteConnectionTriggerData?(connectionId: string): number;
  deleteFeedSeen?(feedId: string): number;
  deleteLensSeen?(feedId: string, lens: string): number;
  sweepEvents?(now: number): number;
}

/** Credential contents remain inside local custody; metadata commits are separate. */
export interface SecretStore {
  get(id: string): unknown;
  set(id: string, value: unknown): void;
  delete(id: string): void;
}

export type LocalRepositoryGuarantees = Readonly<{
  synchronous: true;
  documentAtomicity: true;
  uniqueness: 'collection-and-id';
  transactions: false;
  compareAndSwap: false;
  leases: false;
  fencing: false;
  tenantIsolation: false;
  atomicSecretUpdates: false;
}>;

/**
 * Local scope is a caller-supplied compatibility label for one entire store, not
 * authenticated ownership or a per-record namespace. Do not share this backend
 * among owners or tenants. Documents and authority hashes are left unchanged.
 *
 * A future hosted repository must provide scoped uniqueness, atomic acceptance
 * (request + idempotency reservation + job/outbox), atomic single-use flow
 * consumption, authorization-revision CAS and fenced expiring worker leases.
 * None of these follow from single-document SQLite writes or process-local locks.
 * Secret-store and metadata updates are not one transaction in this adapter.
 */
export interface LocalRepositoryPort extends DocumentStore, LocalAuthorityPort {
  readonly authorityEnabled: boolean;
  connectionGeneration(id: string): number;
  policyRevision(id: string): number;
  readonly scope: LocalScope;
  readonly guarantees: LocalRepositoryGuarantees;
  assertScope(scope: Scope): void;
  transaction(...args: unknown[]): never;
  compareAndSwap(...args: unknown[]): never;
  acquireLease(...args: unknown[]): never;
  renewLease(...args: unknown[]): never;
  releaseLease(...args: unknown[]): never;
}

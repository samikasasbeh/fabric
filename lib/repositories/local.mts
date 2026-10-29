import {assertSameScope, validateScope} from '../../contracts/identity.mts';
import type {LocalScope, Scope} from '../../contracts/identity.mts';
import type {DocumentStore, LocalRepositoryGuarantees, LocalRepositoryPort, RepositoryDocument} from '../../contracts/repository.mts';

const LOCAL_SCOPE: LocalScope = Object.freeze({schemaVersion: 1, kind: 'local', localOwnerId: 'local-runtime'});
const GUARANTEES: LocalRepositoryGuarantees = Object.freeze({
  synchronous: true, documentAtomicity: true, uniqueness: 'collection-and-id',
  transactions: false, compareAndSwap: false, leases: false, fencing: false,
  tenantIsolation: false, atomicSecretUpdates: false,
});

export class RepositoryError extends Error {
  readonly code: 'unsupported_repository_scope' | 'unsupported_repository_operation';
  constructor(code: 'unsupported_repository_scope' | 'unsupported_repository_operation', message: string) {
    super(message);
    this.name = 'RepositoryError';
    this.code = code;
  }
}

function localScope(value: Scope): LocalScope {
  const scope = validateScope(value);
  if (scope.kind !== 'local') throw new RepositoryError('unsupported_repository_scope', 'The local repository does not support tenant scopes.');
  return scope;
}

/** Synchronous compatibility facade. No data migration or ownership inference. */
export class LocalRepository implements LocalRepositoryPort {
  readonly #store: DocumentStore;
  readonly #scope: LocalScope;
  constructor({store, scope = LOCAL_SCOPE}: {store: DocumentStore; scope?: Scope}) {
    this.#scope = localScope(scope);
    this.#store = store;
  }
  get scope(): LocalScope { return this.#scope; }
  get guarantees(): LocalRepositoryGuarantees { return GUARANTEES; }
  get authorityEnabled(): boolean { return this.#store.authorityEnabled === true; }
  connectionGeneration(id: string): number {
    if (!this.authorityEnabled || !this.#store.connectionGeneration) return this.unsupported();
    return this.#store.connectionGeneration(id);
  }
  policyRevision(id: string): number {
    if (!this.authorityEnabled || !this.#store.policyRevision) return this.unsupported();
    return this.#store.policyRevision(id);
  }
  assertScope(scope: Scope): void { assertSameScope(this.#scope, localScope(scope)); }
  get(collection: string, id: string): RepositoryDocument | null { return this.#store.get(collection, id); }
  list(collection: string): RepositoryDocument[] { return this.#store.list(collection); }
  /** F10.21: an indexed lookup by one top-level field when the store has one (lib/store.mjs), else the collection filtered. */
  listWhere(collection: string, field: string, value: string): RepositoryDocument[] {
    return typeof this.#store.listWhere === 'function' ? this.#store.listWhere(collection, field, value) : this.#store.list(collection).filter(document => document[field] === value);
  }
  put(collection: string, document: RepositoryDocument): RepositoryDocument { return this.#store.put(collection, document); }
  delete(collection: string, id: string): boolean { return this.#store.delete(collection, id); }
  audit(event: Record<string, unknown>): RepositoryDocument { return this.#store.audit(event); }
  close(): void { this.#store.close(); }
  transaction(..._args: unknown[]): never { return this.unsupported(); }
  compareAndSwap(..._args: unknown[]): never { return this.unsupported(); }
  acquireLease(..._args: unknown[]): never { return this.unsupported(); }
  renewLease(..._args: unknown[]): never { return this.unsupported(); }
  releaseLease(..._args: unknown[]): never { return this.unsupported(); }
  private unsupported(): never {
    throw new RepositoryError('unsupported_repository_operation', 'This local repository does not implement transactions, compare-and-swap or worker leases.');
  }
}

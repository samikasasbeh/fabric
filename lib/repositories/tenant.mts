import {validateScope} from '../../contracts/identity.mts';
import type {TenantScope} from '../../contracts/identity.mts';
import type {DocumentStore, RepositoryDocument} from '../../contracts/repository.mts';

// F03.0 (docs/F03-DEVELOPER-LAYER.md): one developer environment's documents. Every document carries its environment's
// scope key: it is stamped on write and checked on read, and a document with another scope, or none, is refused. The
// reviewed platform collections are shared and read-only for tenants: writes are refused, and reads go to the platform
// catalog when one is attached (F03.0b). Not the I03 repository: no transactions, compare-and-swap or leases.

/** Collections that belong to the platform, never to one environment: the reviewed operations and how they were found. */
export const PLATFORM_COLLECTIONS: readonly string[] = Object.freeze(['capabilities', 'applicationMaps', 'applicationMapHistory', 'surfaces', 'discoverySources', 'acquisitions', 'applications']);
const COLLECTION = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
/** Collections that are only ever appended to (D11 usage records): an existing document is never replaced or deleted. */
export const APPEND_ONLY_COLLECTIONS: readonly string[] = Object.freeze(['usageEvents']);
/** Collection names are plain strings, so no other value can slip past the platform wall and be coerced back. */
function collectionName(value: unknown): string { if (typeof value !== 'string' || !COLLECTION.test(value)) throw new TenantRepositoryError('platform_read_only', 'A collection name must be a plain name.'); return value; }

export type TenantRepositoryErrorCode = 'scope_mismatch' | 'platform_read_only' | 'platform_catalog_missing' | 'unsupported_repository_operation' | 'append_only';
export class TenantRepositoryError extends Error {
  readonly code: TenantRepositoryErrorCode;
  constructor(code: TenantRepositoryErrorCode, message: string) { super(message); this.name = 'TenantRepositoryError'; this.code = code; }
}

/** The stable key of one environment: organization/project/environment. */
export function scopeKey(scope: TenantScope): string { return `${scope.organizationId}/${scope.projectId}/${scope.environmentId}`; }

type PlatformReader = {get(collection: string, id: string): RepositoryDocument | null; list(collection: string): RepositoryDocument[]};

export class TenantRepository {
  readonly #store: DocumentStore;
  readonly #scope: TenantScope;
  readonly #key: string;
  readonly #catalog: PlatformReader | null;
  constructor({store, scope, catalog = null}: {store: DocumentStore; scope: TenantScope; catalog?: PlatformReader | null}) {
    const checked = validateScope(scope);
    if (checked.kind !== 'tenant') throw new TenantRepositoryError('scope_mismatch', 'A tenant repository needs a tenant scope.');
    this.#store = store; this.#scope = checked; this.#key = scopeKey(checked); this.#catalog = catalog;
  }
  get scope(): TenantScope { return this.#scope; }
  get scopeKey(): string { return this.#key; }
  get guarantees() { return {synchronous: true, tenantIsolation: 'environment-file', transactions: false, compareAndSwap: false, leases: false, fencing: false} as const; }
  #own(document: RepositoryDocument | null, collection: string): RepositoryDocument | null {
    if (document === null) return null;
    if ((document as {scope?: unknown}).scope !== this.#key) throw new TenantRepositoryError('scope_mismatch', `A ${collection} document does not belong to this environment.`);
    return document;
  }
  get(collection: string, id: string): RepositoryDocument | null {
    collection = collectionName(collection);
    if (PLATFORM_COLLECTIONS.includes(collection)) return this.#platform().get(collection, id);
    return this.#own(this.#store.get(collection, id), collection);
  }
  list(collection: string): RepositoryDocument[] {
    collection = collectionName(collection);
    if (PLATFORM_COLLECTIONS.includes(collection)) return this.#platform().list(collection);
    return this.#store.list(collection).map(document => this.#own(document, collection) as RepositoryDocument);
  }
  /** This environment's documents whose top-level field equals value: through the store's index when it has one. */
  listWhere(collection: string, field: string, value: string): RepositoryDocument[] {
    collection = collectionName(collection);
    if (PLATFORM_COLLECTIONS.includes(collection) || typeof this.#store.listWhere !== 'function') return this.list(collection).filter(document => document[field] === value);
    return this.#store.listWhere(collection, field, value).map(document => this.#own(document, collection) as RepositoryDocument);
  }
  put(collection: string, document: RepositoryDocument): RepositoryDocument {
    collection = collectionName(collection);
    if (PLATFORM_COLLECTIONS.includes(collection)) throw new TenantRepositoryError('platform_read_only', `${collection} is part of the reviewed platform catalog; environments cannot write it.`);
    const scope = (document as {scope?: unknown})?.scope;
    if (scope !== undefined && scope !== this.#key) throw new TenantRepositoryError('scope_mismatch', `A ${collection} document for another environment cannot be written here.`);
    // An overwrite must also replace a document of this environment, never one that arrived from elsewhere.
    const existing = this.#own(this.#store.get(collection, (document as {id?: string})?.id ?? ''), collection);
    if (existing && APPEND_ONLY_COLLECTIONS.includes(collection)) throw new TenantRepositoryError('append_only', `${collection} is append-only; an existing record is never replaced.`);
    return this.#store.put(collection, {...document, scope: this.#key});
  }
  delete(collection: string, id: string): boolean {
    collection = collectionName(collection);
    if (PLATFORM_COLLECTIONS.includes(collection)) throw new TenantRepositoryError('platform_read_only', `${collection} is part of the reviewed platform catalog; environments cannot change it.`);
    if (APPEND_ONLY_COLLECTIONS.includes(collection)) throw new TenantRepositoryError('append_only', `${collection} is append-only; records are never deleted.`);
    this.#own(this.#store.get(collection, id), collection);
    return this.#store.delete(collection, id);
  }
  audit(event: Record<string, unknown>): RepositoryDocument { return this.#store.audit({...event, scope: this.#key}); }
  close(): void { this.#store.close(); }
  #platform(): PlatformReader {
    if (!this.#catalog) throw new TenantRepositoryError('platform_catalog_missing', 'No platform catalog is attached to this environment.');
    return this.#catalog;
  }
}

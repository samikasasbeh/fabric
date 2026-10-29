import {createHash} from 'node:crypto';
import type {DatabaseSync} from 'node:sqlite';
import {canonicalHash} from './compiler.mjs';
import type {LocalAuthorityMode, RepositoryDocument} from '../contracts/repository.mts';

/** The SQLite application id (header bytes 68 to 71) a designated store carries. F10.12: the live-test harness reads it to tell its own store from one
 *  an ordinary Fabric wrote (lib/certification.mjs). */
export const MARKER = 0x46414241;
const META = '_fabric_local_authority_meta';
const COUNTERS = '_fabric_local_authority_counters';
const VERSION = 2;
const HASH = /^[a-f0-9]{64}$/;
type Kind = 'connection' | 'policy' | 'browserDevice' | 'persistentSession';
type Counter = {kind: Kind; id: string; revision: number; present: number; document_hash: string | null; authority_hash: string | null};
type DocumentRow = {collection: string; id: string; document: string};

export class LocalAuthorityError extends Error {
  readonly code = 'invalid_local_authority';
  constructor() { super('Local authority is unavailable, malformed or requires explicit store designation.'); this.name = 'LocalAuthorityError'; }
}
function fail(): never { throw new LocalAuthorityError(); }
const kindFor = (collection: string): Kind | null => collection === 'connections' ? 'connection' : collection === 'permissions' ? 'policy' : collection === 'browserDevices' ? 'browserDevice' : collection === 'persistentSessions' ? 'persistentSession' : null;
const browserSide = (kind: Kind): boolean => kind === 'browserDevice' || kind === 'persistentSession';
const digest = (text: string): string => createHash('sha256').update(text).digest('hex');
const validId = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 256;
const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const next = (value: number): number => positive(value) && value < Number.MAX_SAFE_INTEGER ? value + 1 : fail();

function assertDocumentSchema(db: DatabaseSync): void {
  const table=db.prepare("SELECT type FROM sqlite_master WHERE name='documents'").get();
  if (table?.type !== 'table') fail();
  const columns=db.prepare('PRAGMA table_info(documents)').all();
  const expected=[['collection',1],['id',2],['document',0]] as const;
  if (columns.length !== expected.length || columns.some((column,index)=>column.name !== expected[index]?.[0] || column.type !== 'TEXT' || column.notnull !== 1 || column.pk !== expected[index]?.[1])) fail();
}

/** Run BEFORE Store's legacy CREATE IF NOT EXISTS; designated stores are never repaired. */
export function assertAuthorityDocumentsPresent(db: DatabaseSync, mode?: LocalAuthorityMode): void {
  const marker=db.prepare('PRAGMA application_id').get()?.application_id;
  const metadata=db.prepare('SELECT name FROM sqlite_master WHERE name IN (?,?)').all(META,COUNTERS);
  if (mode === 'require' || marker === MARKER || metadata.length) assertDocumentSchema(db);
}

// Unknown fields remain authority-relevant: new bindings cannot silently escape
// this comparison. Only known health/display fields are excluded. Driver consent
// provenance and asynchronous stale-result guards remain a separate layer. Which
// sign-in wrote a record, and when, is health: a renewal keeps the generation (T7).
// So is what that sign-in asked for and did not get (F10.5): access comes only from scopes.
const HEALTH = new Set(['label','updatedAt','lastCheckedAt','error','expiresAt','refreshAvailable','grant','status','signInRevision','signedInAt']);
const DEVICE_HEALTH = new Set(['lastHeartbeatAt','executionState','observationInvalidated','observedPage','lastReadAttempt']);
const SESSION_HEALTH = new Set(['updatedAt','lastOpenedAt','lastError','sessionEpoch','documentEpoch','observationCurrent','observedPage','lastAttempt','state']);
const IDENTITY_DISPLAY = new Set(['displayName','email','workspaceName']);
// F10.9 (R5, open point Important 1): Slack's userId repeats the second part of the reviewed id, so it is not authority either. A Slack
// connection that records it at its next sign-in or health check keeps its generation (T7).
const IDENTITY_REPEATS = new Set(['userId']);
function authorityHash(document: RepositoryDocument, kind: Kind): string {
  if (kind === 'policy') return canonicalHash(document);
  if (browserSide(kind)) {
    // All present associations are same-ID. No document can choose a different
    // owner's generation to invalidate, and profile cleanup stays ID-bound.
    if (document.connectionId !== undefined && document.connectionId !== document.id) fail();
    if (kind === 'persistentSession') {
      if (document.connectionId !== document.id || document.profileId !== document.id || !validId(document.appId) || !record(document.consent)) fail();
      if (typeof document.state !== 'string' || !['dormant','opening','available','revoked'].includes(document.state)) fail();
    }
    const health = kind === 'browserDevice' ? DEVICE_HEALTH : SESSION_HEALTH;
    const fields = Object.fromEntries(Object.entries(document).filter(([key]) => !health.has(key)));
    // Keep the original unknown `revoked` field inside fields; never overwrite it
    // with this derived predicate (which would create an authority collision).
    return canonicalHash({fields,revoked:kind === 'persistentSession' && document.state === 'revoked'});
  }
  const projection: Record<string, unknown> = Object.fromEntries(Object.entries(document).filter(([key]) => !HEALTH.has(key)));
  if (document.identity !== undefined && document.identity !== null) {
    if (!record(document.identity)) fail();
    projection.identity = Object.fromEntries(Object.entries(document.identity).filter(([key]) => !IDENTITY_DISPLAY.has(key) && !IDENTITY_REPEATS.has(key)));
  }
  // The widest set the owner approved is compared as a set, like the scopes held.
  for (const key of ['scopes','grantCeiling'] as const) {
    const value = document[key];
    if (value === undefined) continue;
    if (!Array.isArray(value) || value.length > 1000 || value.some(item => typeof item !== 'string' || !item || item.length > 2000)) fail();
    projection[key] = [...new Set(value)].sort();
  }
  if (document.status !== undefined && typeof document.status !== 'string') fail();
  for (const key of ['authRevision','signInRevision'] as const) {
    const value = document[key];
    if (value !== undefined && (typeof value !== 'string' || !value || value.length > 256)) fail();
  }
  return canonicalHash({fields:projection,revoked:document.status === 'revoked'});
}

/** Validate descriptors before reading fields or invoking JSON serialization. */
export function serializeAuthorityDocument(value: unknown, collection: string): string {
  try {
    canonicalHash(value); // Existing bounded, plain-JSON validator; no getters/toJSON.
    if (!record(value) || !validId(value.id)) fail();
    for (const key of ['generation','connectionGeneration','policyRevision']) if (Object.hasOwn(value, key)) fail();
    const kind = kindFor(collection);
    if (!kind) fail();
    authorityHash(value as RepositoryDocument, kind);
    return JSON.stringify(value);
  } catch { return fail(); }
}

// This checksum detects accidental deletion/corruption, not malicious raw SQLite
// edits. Stream rows so counter count does not inherit document-size limits.
function checksum(rows: Counter[]): string {
  const hash = createHash('sha256').update(`fabric-local-authority-v${VERSION}/default-policy=1\n`);
  for (const row of rows) hash.update(JSON.stringify([row.kind,row.id,row.revision,row.present,row.document_hash,row.authority_hash]) + '\n');
  return hash.digest('hex');
}

/** Store-private synchronous mutation guard; NOT a general transaction/CAS API. */
export class LocalAuthority {
  readonly #db: DatabaseSync;
  readonly #enabled: boolean;
  constructor(db: DatabaseSync, mode?: LocalAuthorityMode) {
    this.#db = db;
    if (mode !== undefined && !['new','baseline','require'].includes(mode)) fail();
    this.#enabled = mode !== undefined;
    this.transaction(() => {
      const designated = this.designated();
      if (!this.#enabled) { if (designated) fail(); return; }
      if (mode === 'require') { if (!designated) fail(); this.verify(); return; }
      if (designated) fail();
      const marker = this.#db.prepare('PRAGMA application_id').get()?.application_id;
      if (marker !== 0) fail();
      const documents = this.documents();
      if (mode === 'new' && this.#db.prepare('SELECT 1 FROM documents LIMIT 1').get()) fail();
      // No old browser grant has acceptance-time side history. It must be freshly
      // authorized by a future provenance-aware driver, not baseline-stamped.
      if (documents.some(row => browserSide(kindFor(row.collection)!))) fail();
      this.#db.exec(`CREATE TABLE ${META} (id INTEGER PRIMARY KEY, version INTEGER NOT NULL, default_policy_revision INTEGER NOT NULL, checksum TEXT NOT NULL);
        CREATE TABLE ${COUNTERS} (kind TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL, present INTEGER NOT NULL, document_hash TEXT, authority_hash TEXT, PRIMARY KEY(kind,id));
        PRAGMA application_id=${MARKER};`);
      for (const row of documents) {
        const document = this.parseDocument(row);
        this.save({kind:kindFor(row.collection)!,id:row.id,revision:1,present:1,document_hash:digest(row.document),authority_hash:authorityHash(document,kindFor(row.collection)!)});
      }
      this.#db.prepare(`INSERT INTO ${META} VALUES(1,?,1,?)`).run(VERSION,checksum(this.rows()));
      this.verify();
    });
  }
  get enabled(): boolean { return this.#enabled; }
  private transaction<T>(operation: () => T): T {
    // No nested caller-managed transactions: authority commits have one owner.
    if (this.#db.isTransaction) fail();
    this.#db.exec('BEGIN IMMEDIATE');
    try { const value=operation(); this.#db.exec('COMMIT'); return value; }
    catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  private designated(): boolean {
    const marker = this.#db.prepare('PRAGMA application_id').get()?.application_id;
    const tables = this.#db.prepare("SELECT name FROM sqlite_master WHERE name IN (?,?)").all(META,COUNTERS);
    if (marker === MARKER || tables.length) {
      if (marker !== MARKER || tables.length !== 2) fail();
      return true;
    }
    return false;
  }
  private documents(): DocumentRow[] {
    return this.#db.prepare("SELECT collection,id,document FROM documents WHERE collection IN ('connections','permissions','browserDevices','persistentSessions') ORDER BY collection,id").all() as DocumentRow[];
  }
  private rows(): Counter[] {
    return this.#db.prepare(`SELECT kind,id,revision,present,document_hash,authority_hash FROM ${COUNTERS} ORDER BY kind,id`).all() as Counter[];
  }
  private parseDocument(row: DocumentRow): RepositoryDocument {
    try {
      if (typeof row.document !== 'string' || Buffer.byteLength(row.document) > 2*1024*1024) fail();
      const document: unknown = JSON.parse(row.document);
      serializeAuthorityDocument(document,row.collection);
      if ((document as RepositoryDocument).id !== row.id) fail();
      return document as RepositoryDocument;
    } catch { return fail(); }
  }
  private verify(): Counter[] {
    try {
      if (!this.designated()) fail();
      assertDocumentSchema(this.#db);
      const meta = this.#db.prepare(`SELECT * FROM ${META}`).all();
      if (meta.length !== 1 || meta[0]?.id !== 1 || meta[0].version !== VERSION || meta[0].default_policy_revision !== 1 || typeof meta[0].checksum !== 'string' || !HASH.test(meta[0].checksum)) fail();
      const rows = this.rows();
      const ownerIds = new Set(rows.filter(row => row.kind === 'connection').map(row => row.id));
      const documents = new Map(this.documents().map(row => [`${kindFor(row.collection)}:${row.id}`,row]));
      for (const row of rows) {
        if (!['connection','policy','browserDevice','persistentSession'].includes(row.kind) || !validId(row.id) || !positive(row.revision) || ![0,1].includes(row.present)) fail();
        // A retained owning tombstone is sufficient for later side cleanup; an
        // owner that never existed is not. Parent deletion never erases history.
        if (browserSide(row.kind) && !ownerIds.has(row.id)) fail();
        const key = `${row.kind}:${row.id}`, documentRow = documents.get(key);
        if (row.present) {
          if (!documentRow || typeof row.document_hash !== 'string' || !HASH.test(row.document_hash) || typeof row.authority_hash !== 'string' || !HASH.test(row.authority_hash)) fail();
          const document = this.parseDocument(documentRow);
          if (digest(documentRow.document) !== row.document_hash || authorityHash(document,row.kind) !== row.authority_hash) fail();
          documents.delete(key);
        } else if (documentRow || row.document_hash !== null || row.authority_hash !== null) fail();
      }
      if (documents.size || checksum(rows) !== meta[0]!.checksum) fail();
      return rows;
    } catch { return fail(); }
  }
  private save(row: Counter): void {
    this.#db.prepare(`INSERT INTO ${COUNTERS}(kind,id,revision,present,document_hash,authority_hash) VALUES(?,?,?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET revision=excluded.revision,present=excluded.present,document_hash=excluded.document_hash,authority_hash=excluded.authority_hash`).run(row.kind,row.id,row.revision,row.present,row.document_hash,row.authority_hash);
  }
  mutate<T>(collection: string, id: string, serialized: string | null, apply: () => T): T {
    return this.transaction(() => {
      // Also guard legacy handles opened before another handle designated a store.
      if (!this.#enabled) { if (this.designated()) fail(); return apply(); }
      if (collection.startsWith('_fabric_local_authority')) fail();
      const rows = this.verify(), kind = kindFor(collection);
      if (!kind) return apply();
      if (!validId(id)) fail();
      const old = rows.find(row => row.kind === kind && row.id === id);
      const document = serialized === null ? null : this.parseDocument({collection,id,document:serialized});
      const hash = document ? authorityHash(document,kind) : null;
      const changed = kind === 'policy' || !old || old.present !== Number(document !== null) || old.authority_hash !== hash;
      const revision = old ? (changed ? next(old.revision) : old.revision) : kind === 'policy' ? 2 : 1;
      let owner: Counter | undefined;
      if (browserSide(kind)) {
        owner = rows.find(row => row.kind === 'connection' && row.id === id);
        if (!owner) fail();
        if (document) {
          if (!owner.present) fail();
          const parentRow=this.#db.prepare("SELECT collection,id,document FROM documents WHERE collection='connections' AND id=?").get(id) as DocumentRow | undefined;
          if (!parentRow) fail();
          const parent=this.parseDocument(parentRow);
          if (parent.driver !== 'browser') fail();
          if (kind === 'persistentSession') {
            if (parent.transport !== 'persistent' || parent.appId !== document.appId) fail();
          } else if (parent.transport !== undefined && parent.transport !== 'helper') fail();
          if (rows.some(row => browserSide(row.kind) && row.kind !== kind && row.id === id && row.present)) fail();
        }
        // Preflight both possible overflows before applying the document write.
        if (changed) owner = {...owner,revision:next(owner.revision)};
      }
      const value = apply();
      this.save({kind,id,revision,present:Number(document !== null),document_hash:serialized === null ? null : digest(serialized),authority_hash:hash});
      if (owner && changed) this.save(owner);
      this.#db.prepare(`UPDATE ${META} SET checksum=? WHERE id=1`).run(checksum(this.rows()));
      this.verify();
      return value;
    });
  }
  lookup(kind: Kind, id: string): number {
    if (!this.#enabled || !validId(id)) fail();
    return this.transaction(() => {
      const rows=this.verify(), row=rows.find(item=>item.kind===kind&&item.id===id);
      if (row) return row.revision;
      return kind === 'policy' ? 1 : fail();
    });
  }
}

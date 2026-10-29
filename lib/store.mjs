import { mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { checkedClock } from '../contracts/repository.mts';
import { LocalAuthority, serializeAuthorityDocument, assertAuthorityDocumentsPresent } from './local-authority.mts';
import { scrubAuthorization } from './redaction.mjs';

const SENSITIVE = /token|password|secret|authorization|cookie|verifier|credential|private.?key/i;
function safeAudit(value, depth = 0) {
  if (depth > 5) return '[truncated]';
  if (Array.isArray(value)) return value.slice(0, 30).map(v => safeAudit(v, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([k]) => !SENSITIVE.test(k)).map(([k,v]) => [k, safeAudit(v, depth + 1)]));
  if (typeof value === 'string') return scrubAuthorization(value).slice(0, 1000);
  return value;
}

export class Store {
  #authority;
  #where = new Map();
  /** secureDelete: deleted and replaced documents are overwritten in the file, so erased data leaves no bytes behind (tenant stores). */
  constructor({ dataDir, clock = Date.now, localAuthority, secureDelete = false } = {}) {
    this.clock = checkedClock(clock);
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    chmodSync(dataDir, 0o700);
    const file = join(dataDir, 'fabric.sqlite');
    this.db = new DatabaseSync(file);
    try {
      chmodSync(file, 0o600);
      assertAuthorityDocumentsPresent(this.db, localAuthority);
      if (secureDelete) this.db.exec('PRAGMA secure_delete=ON;');
      this.db.exec('PRAGMA journal_mode=DELETE; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS documents (collection TEXT NOT NULL, id TEXT NOT NULL, document TEXT NOT NULL, PRIMARY KEY(collection,id));');
      this.read = this.db.prepare('SELECT document FROM documents WHERE collection=? AND id=?');
      this.all = this.db.prepare('SELECT document FROM documents WHERE collection=? ORDER BY rowid');
      this.write = this.db.prepare('INSERT INTO documents(collection,id,document) VALUES(?,?,?) ON CONFLICT(collection,id) DO UPDATE SET document=excluded.document');
      this.remove = this.db.prepare('DELETE FROM documents WHERE collection=? AND id=?');
      this.#authority = new LocalAuthority(this.db, localAuthority);
    } catch (error) { this.db.close(); throw error; }
  }
  get authorityEnabled() { return this.#authority.enabled; }
  connectionGeneration(id) { return this.#authority.lookup('connection', id); }
  policyRevision(id) { return this.#authority.lookup('policy', id); }
  get(collection, id) { const row = this.read.get(String(collection), String(id)); return row ? JSON.parse(row.document) : null; }
  list(collection) { return this.all.all(String(collection)).map(row => JSON.parse(row.document)); }
  /**
   * The documents of one collection whose top-level field equals value, read through an index on that field (made the
   * first time the field is asked for), so only matching documents are parsed. Developer environments read one
   * person's records this way; a store nobody asks keeps its single table.
   */
  listWhere(collection, field, value) {
    if (typeof field !== 'string' || !/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(field)) throw new Error('A field name is a plain name.');
    let query = this.#where.get(field);
    if (!query) {
      this.db.exec(`CREATE INDEX IF NOT EXISTS documents_by_${field} ON documents(collection, json_extract(document, '$.${field}'))`);
      query = this.db.prepare(`SELECT document FROM documents WHERE collection=? AND json_extract(document, '$.${field}')=? ORDER BY rowid`);
      this.#where.set(field, query);
    }
    return query.all(String(collection), String(value)).map(row => JSON.parse(row.document));
  }
  put(collection, object) {
    collection = String(collection);
    const serialized = this.authorityEnabled && ['connections','permissions','browserDevices','persistentSessions'].includes(collection) ? serializeAuthorityDocument(object,collection) : null;
    if (!object || typeof object.id !== 'string' || !object.id || object.id.length > 256) throw new Error('A bounded document id is required.');
    const document = serialized ?? JSON.stringify(object);
    return this.#authority.mutate(collection,object.id,document,()=>{
      this.write.run(collection, object.id, document);
      return this.get(collection, object.id);
    });
  }
  delete(collection, id) {
    collection=String(collection);id=String(id);
    return this.#authority.mutate(collection,id,null,()=>this.remove.run(collection,id).changes>0);
  }
  audit(event) {
    // Callers must pass metadata only: request/response bodies and free-form secrets do not belong in the audit journal.
    const safe = safeAudit(event);
    return this.put('activity', { ...safe, id: randomUUID(), createdAt: new Date(this.clock()).toISOString() });
  }
  close() { this.db.close(); }
}

// F03.0b (docs/F03-DEVELOPER-LAYER.md): the platform catalog. The reviewed operations every developer environment uses
// (capabilities, application maps, proxy surfaces) live once, in the platform folder under the tenant data root. Only
// the operator's catalog command writes it (PlatformStore, under an exclusive lock); tenant processes read it through
// PlatformCatalog, which opens the database read-only and serves the platform collections and nothing else.
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {Store} from '../store.mjs';
import {PLATFORM_COLLECTIONS} from '../repositories/tenant.mts';
import {resolveTenantRoot, takeLock, releaseLock, EnvironmentError, DESIGNATION_FILE} from './environments.mjs';

export const PLATFORM_DESIGNATION = 'platform-catalog.json';
const platformFolder = root => path.join(root, 'platform');
const fail = (code, message) => { throw new EnvironmentError(code, message); };

/** The operator's writable view of the platform catalog. One holder at a time. */
export class PlatformStore {
  #store; #lock;
  /** @param {{root: string, forbiddenRoots?: string[], clock?: () => number}} options */
  constructor({root, forbiddenRoots, clock = Date.now} = {}) {
    const dir = platformFolder(resolveTenantRoot(root, forbiddenRoots));
    mkdirSync(dir, {recursive: true, mode: 0o700});
    if (existsSync(path.join(dir, DESIGNATION_FILE))) fail('designation_mismatch', 'The platform folder cannot be a developer environment.');
    const marker = path.join(dir, PLATFORM_DESIGNATION);
    if (!existsSync(marker)) {
      if (existsSync(path.join(dir, 'fabric.sqlite'))) fail('designation_mismatch', 'This folder holds data but is not the platform catalog.');
      writeFileSync(marker, `${JSON.stringify({kind: 'platform-catalog', createdAt: new Date(clock()).toISOString()})}\n`, {flag: 'wx', mode: 0o600});
    } else if (JSON.parse(readFileSync(marker, 'utf8')).kind !== 'platform-catalog') fail('designation_mismatch', 'This folder is not the platform catalog.');
    this.#lock = takeLock(path.join(dir, 'platform.lock'));
    try { this.#store = new Store({dataDir: dir, clock}); } catch (error) { releaseLock(this.#lock); throw error; }
    this.folder = dir;
  }
  #collection(collection) { if (typeof collection !== 'string' || !PLATFORM_COLLECTIONS.includes(collection)) fail('not_platform', `${String(collection).slice(0, 40)} is not a platform collection.`); return collection; }
  get(collection, id) { return this.#store.get(this.#collection(collection), id); }
  list(collection) { return this.#store.list(this.#collection(collection)); }
  put(collection, document) { return this.#store.put(this.#collection(collection), document); }
  delete(collection, id) { return this.#store.delete(this.#collection(collection), id); }
  audit(event) { return this.#store.audit(event); }
  /** Operator audit rows (catalog updates), newest last. */
  activity() { return this.#store.list('activity'); }
  close() { this.#store.close(); releaseLock(this.#lock); }
}

/** A tenant process's read-only view: the platform collections only, from a database opened read-only. */
export class PlatformCatalog {
  #db; #get; #list;
  /** @param {{root: string, forbiddenRoots?: string[]}} options */
  constructor({root, forbiddenRoots} = {}) {
    const dir = platformFolder(resolveTenantRoot(root, forbiddenRoots)), file = path.join(dir, 'fabric.sqlite');
    if (!existsSync(path.join(dir, PLATFORM_DESIGNATION)) || !existsSync(file)) fail('platform_catalog_missing', 'No platform catalog exists under this root yet.');
    this.#db = new DatabaseSync(file, {readOnly: true});
    this.#get = this.#db.prepare('SELECT document FROM documents WHERE collection=? AND id=?');
    this.#list = this.#db.prepare('SELECT document FROM documents WHERE collection=? ORDER BY rowid');
  }
  #collection(collection) { if (typeof collection !== 'string' || !PLATFORM_COLLECTIONS.includes(collection)) fail('not_platform', `${String(collection).slice(0, 40)} is not a platform collection.`); return collection; }
  get(collection, id) { const row = this.#get.get(this.#collection(collection), String(id)); return row ? JSON.parse(row.document) : null; }
  list(collection) { return this.#list.all(this.#collection(collection)).map(row => JSON.parse(row.document)); }
  close() { this.#db.close(); }
}

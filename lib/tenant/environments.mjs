// F03.0 (docs/F03-DEVELOPER-LAYER.md): sealed storage per developer environment. Each environment of each project of each
// organization gets its own folder with its own database file and its own vault key, a designation that says which
// environment the folder belongs to, and a lock so two processes never write it at once. The single-owner runtime
// (server.mjs createApp) refuses any folder that carries a designation.
import {existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync, rmSync, realpathSync, renameSync, statSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateScope} from '../../contracts/identity.mts';
import {Store} from '../store.mjs';
import {Vault} from '../vault.mjs';
import {TenantRepository, scopeKey} from '../repositories/tenant.mts';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
/** Lowercase only, so two ids can never differ only in case on a case-insensitive disk. No dots, no slashes. */
export const TENANT_ID = /^[a-z0-9][a-z0-9_-]{0,62}$/;
/** The two kinds of environment a project has; an environment's id is its own (for example env_...). */
export const ENVIRONMENT_KINDS = Object.freeze(['development', 'production']);
/** The file whose presence marks a folder as a developer environment. */
export const DESIGNATION_FILE = 'tenant-environment.json';
const LOCK_FILE = 'environment.lock';
/** The marker every tenant data root carries; the single-owner runtime refuses any folder at or under one. */
export const ROOT_MARKER = 'tenant-root.json';
/** Files that mark a folder as Fabric data of some kind. A tenant root may not be, or sit inside, such a folder. */
export const DATA_MARKERS = Object.freeze(['fabric.sqlite', path.join('vault', 'master.key'), 'tenant-environment.json', 'platform-catalog.json', 'tenant-registry.json']);
/** The local runtime's folder, plus any extra folders the operator names in FABRIC_TENANT_FORBIDDEN_ROOTS (path list). */
const defaultForbidden = () => [path.join(ROOT, '.fabric'), ...String(process.env.FABRIC_TENANT_FORBIDDEN_ROOTS || '').split(path.delimiter).filter(item => path.isAbsolute(item))];

const EMPTY_CATALOG = Object.freeze({get: () => null, list: () => []});

export class EnvironmentError extends Error {
  constructor(code, message) { super(message); this.name = 'EnvironmentError'; this.code = code; }
}
const fail = (code, message) => { throw new EnvironmentError(code, message); };

/** A validated, frozen tenant scope; ids are lowercase letters, digits, underscores and hyphens. */
export function tenantScope({organizationId, projectId, environmentId} = {}) {
  for (const [name, value] of Object.entries({organizationId, projectId, environmentId})) if (typeof value !== 'string' || !TENANT_ID.test(value)) fail('invalid_scope', `${name} must be 1 to 63 lowercase letters, digits, underscores or hyphens.`);
  return validateScope({schemaVersion: 1, kind: 'tenant', organizationId, projectId, environmentId});
}

/** The tenant data root as a real path: absolute, not a symbolic link, never in or around a forbidden folder. */
export function resolveTenantRoot(root, forbiddenRoots = defaultForbidden()) {
  if (typeof root !== 'string' || !path.isAbsolute(root)) fail('invalid_root', 'The tenant data root must be an absolute path.');
  const resolved = path.resolve(root);
  if (resolved === path.parse(resolved).root) fail('forbidden_root', 'The tenant data root cannot be the top of the disk.');
  // Real paths in the disk's own case (macOS disks ignore case), compared case-insensitively, so neither a system link
  // such as /var to /private/var nor a different spelling of .fabric can hide an overlap.
  const real = value => { let current = value, rest = []; while (!existsSync(current)) { rest.unshift(path.basename(current)); current = path.dirname(current); } return path.join(realpathSync.native(current), ...rest); };
  const fold = value => value.normalize('NFC').toLowerCase();
  const within = (child, parent) => { const relative = path.relative(fold(parent), fold(child)); return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative)); };
  const target = real(resolved);
  for (const forbidden of forbiddenRoots.map(item => real(path.resolve(item)))) {
    if (within(target, forbidden) || within(forbidden, target)) fail('forbidden_root', 'Tenant data cannot live in, or contain, the local runtime or certification folders.');
  }
  // Nor inside any folder that already holds Fabric data (a local runtime, an environment, a catalog, a registry).
  for (let current = path.dirname(target); ; current = path.dirname(current)) {
    if (DATA_MARKERS.some(marker => existsSync(path.join(current, marker)))) fail('forbidden_root', 'Tenant data cannot live inside another Fabric data folder.');
    if (current === path.dirname(current)) break;
  }
  if (existsSync(resolved) && lstatSync(resolved).isSymbolicLink()) fail('forbidden_root', 'The tenant data root cannot be a symbolic link.');
  if (existsSync(resolved) && DATA_MARKERS.some(marker => existsSync(path.join(resolved, marker)))) fail('forbidden_root', 'This folder already holds Fabric data that is not a tenant root.');
  mkdirSync(resolved, {recursive: true, mode: 0o700});
  const marker = path.join(resolved, ROOT_MARKER);
  if (!existsSync(marker)) writeFileSync(marker, `${JSON.stringify({kind: 'tenant-root'})}\n`, {mode: 0o600});
  return realpathSync.native(resolved);
}

/** True when the folder is, or sits under, a tenant data root, an environment, the platform catalog or the registry. */
export function insideTenantData(folder) {
  // The nearest folder that exists is resolved through any symbolic link, then the missing part is added back: a new
  // folder reached through a link into tenant data is still inside it.
  let current = path.resolve(folder);
  const rest = [];
  while (!existsSync(current) && current !== path.dirname(current)) { rest.unshift(path.basename(current)); current = path.dirname(current); }
  try { current = path.join(realpathSync.native(current), ...rest); } catch {}
  for (; ; current = path.dirname(current)) {
    if ([ROOT_MARKER, DESIGNATION_FILE, 'platform-catalog.json', 'tenant-registry.json'].some(marker => existsSync(path.join(current, marker)))) return true;
    if (current === path.dirname(current)) return false;
  }
}

/** Opens, caches, pins and destroys environment stores under one data root. */
export class EnvironmentStores {
  #root; #open = new Map(); #maxOpen; #clock; #catalog;
  /**
   * @param {{root: string, maxOpen?: number, clock?: () => number, forbiddenRoots?: string[], catalog?: any}} options
   * forbiddenRoots: folders tenant data must never live in or contain (the local runtime's .fabric folder by default).
   * maxOpen: how many environments stay open when idle. While every open one has work in flight the cache grows past
   * it, up to four times maxOpen, so busy environments never lock the others out (N1); idle ones close on later opens.
   */
  constructor({root, maxOpen = 16, clock = Date.now, forbiddenRoots = defaultForbidden(), catalog = null} = {}) {
    if (!Number.isSafeInteger(maxOpen) || maxOpen < 1 || maxOpen > 64) fail('invalid_root', 'maxOpen must be 1 to 64.');
    const resolved = resolveTenantRoot(root, forbiddenRoots);
    // Without a platform catalog an environment sees an empty one: nothing served, and writes still refused.
    this.#root = resolved; this.#maxOpen = maxOpen; this.#clock = clock; this.#catalog = catalog ?? EMPTY_CATALOG;
  }
  /** The folder of one environment, derived only from validated ids. */
  folder(scope) {
    const s = tenantScope(scope);
    return path.join(this.#root, 'orgs', s.organizationId, 'projects', s.projectId, 'environments', s.environmentId);
  }
  /** The environment's repository and vault, opened once and cached; the least recently used unpinned one closes first. */
  open(scope) {
    const s = tenantScope(scope), key = scopeKey(s);
    const cached = this.#open.get(key);
    if (cached) { this.#open.delete(key); this.#open.set(key, cached); return cached.handle; }
    this.#trim(this.#maxOpen - 1);
    if (this.#open.size >= this.#maxOpen * 4) fail('too_many_open', 'Every open environment has work in flight; try again shortly.');
    const dir = this.folder(s);
    this.#checkPath(dir);
    mkdirSync(dir, {recursive: true, mode: 0o700});
    const marker = path.join(dir, DESIGNATION_FILE), designation = {scopeKey: key, organizationId: s.organizationId, projectId: s.projectId, environmentId: s.environmentId};
    if (existsSync(marker)) {
      let found;
      try { found = JSON.parse(readFileSync(marker, 'utf8')); } catch { fail('designation_mismatch', 'This environment folder has an unreadable designation.'); }
      if (found?.scopeKey !== key || found.organizationId !== s.organizationId || found.projectId !== s.projectId || found.environmentId !== s.environmentId) fail('designation_mismatch', 'This folder belongs to another environment.');
    } else {
      // A folder that already holds data but no designation is not a developer environment (it could be a local runtime).
      if (existsSync(path.join(dir, 'fabric.sqlite')) || existsSync(path.join(dir, 'vault'))) fail('designation_mismatch', 'This folder holds data but is not a developer environment.');
      writeFileSync(marker, `${JSON.stringify({...designation, createdAt: new Date(this.#clock()).toISOString()})}\n`, {flag: 'wx', mode: 0o600});
    }
    const lock = this.#lock(dir);
    let store;
    try {
      store = new Store({dataDir: dir, clock: this.#clock, secureDelete: true});
      const handle = Object.freeze({scope: s, scopeKey: key, folder: dir, repository: new TenantRepository({store, scope: s, catalog: this.#catalog}), vault: new TenantVault(new Vault(dir), key)});
      this.#open.set(key, {handle, pins: 0, lock});
      return handle;
    } catch (error) { store?.close(); this.#unlock(lock); throw error; }
  }
  /** Keeps an environment with work in flight open; it is never evicted or destroyed while pinned. */
  pin(scope) { const entry = this.#entry(scope); entry.pins++; return entry.handle; }
  unpin(scope) { const entry = this.#entry(scope); if (entry.pins < 1) fail('not_pinned', 'This environment is not pinned.'); entry.pins--; }
  /**
   * Runs async work (any provider call) with the environment opened, then pinned until the work settles, so other
   * environments' traffic can never close its store and vault under it (N1).
   */
  async hold(scope, work) {
    const handle = this.open(scope);
    this.pin(scope);
    try { return await work(handle); } finally { this.unpin(scope); }
  }
  isOpen(scope) { return this.#open.has(scopeKey(tenantScope(scope))); }
  /** F10.21: the handles of every environment open now, for the developer server's minute sweep (lib/tenant/runtime-bundle.mjs sweepOpen()). */
  openHandles() { return [...this.#open.values()].map(entry => entry.handle); }
  close(scope) {
    const key = scopeKey(tenantScope(scope)), entry = this.#open.get(key);
    if (!entry) return false;
    if (entry.pins) fail('pinned', 'This environment has work in flight and cannot close.');
    this.#release(key, entry);
    return true;
  }
  closeAll() { for (const [key, entry] of [...this.#open]) if (!entry.pins) this.#release(key, entry); }
  /** Deletes one environment's database, vault key and records, and nothing else. Refused while any holder has it open. */
  destroy(scope) {
    const s = tenantScope(scope), key = scopeKey(s), dir = this.folder(s);
    if (this.#open.get(key)?.pins) fail('pinned', 'This environment has work in flight and cannot be destroyed.');
    this.close(s);
    if (!existsSync(dir)) return false;
    this.#checkPath(dir);
    const found = JSON.parse(readFileSync(path.join(dir, DESIGNATION_FILE), 'utf8'));
    if (found.scopeKey !== key) fail('designation_mismatch', 'This folder belongs to another environment.');
    // Never delete a folder holding anything that is not this environment's own (another designation, a catalog, a root).
    const foreign = folder => readdirSync(folder, {withFileTypes: true}).some(entry => entry.isDirectory()
      ? foreign(path.join(folder, entry.name))
      : [ROOT_MARKER, 'platform-catalog.json', 'tenant-registry.json'].includes(entry.name) || (entry.name === DESIGNATION_FILE && folder !== dir));
    if (foreign(dir)) fail('designation_mismatch', 'This environment folder holds other Fabric data and cannot be destroyed.');
    // Hold the lock (refused if another process has the environment open), move the folder out of the way, then delete.
    const lock = this.#lock(dir), tombstone = path.join(this.#root, `.destroyed-${randomBytes(8).toString('hex')}`);
    try { renameSync(dir, tombstone); } finally { releaseLock(lock); }
    rmSync(tombstone, {recursive: true, force: true});
    return true;
  }
  #entry(scope) { const entry = this.#open.get(scopeKey(tenantScope(scope))); if (!entry) fail('not_open', 'This environment is not open.'); return entry; }
  /** Closes the least recently used environments with nothing in flight until at most `limit` stay open. */
  #trim(limit) {
    for (const [key, entry] of this.#open) {
      if (this.#open.size <= limit) return;
      if (!entry.pins) this.#release(key, entry);
    }
  }
  #release(key, entry) { this.#open.delete(key); entry.handle.repository.close(); entry.handle.vault.close(); this.#unlock(entry.lock); }
  /** No segment between the root and the folder may be a symbolic link. */
  #checkPath(dir) {
    let current = this.#root;
    for (const part of path.relative(this.#root, dir).split(path.sep)) {
      current = path.join(current, part);
      if (existsSync(current) && lstatSync(current).isSymbolicLink()) fail('forbidden_root', 'An environment folder cannot pass through a symbolic link.');
    }
  }
  #lock(dir) { return takeLock(path.join(dir, LOCK_FILE)); }
  #unlock(lock) { releaseLock(lock); }
}

/**
 * An operating-system lock: a small SQLite file held in exclusive mode. The system releases it when the holder closes it
 * or dies, so there is no stale lock to take over and no window where two holders both believe they have it.
 */
export function takeLock(file, retried = false) {
  const db = new DatabaseSync(file);
  try { db.exec('PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;'); }
  catch (error) {
    db.close();
    if (/locked|busy/i.test(String(error.message))) fail('locked', 'This folder is open in another Fabric process.');
    // A lock file from the older process-id format holds no operating-system lock; replace it once.
    if (!retried && /not a database/i.test(String(error.message))) { rmSync(file, {force: true}); return takeLock(file, true); }
    throw error;
  }
  return db;
}
export function releaseLock(lock) { try { lock.close(); } catch {} }

/** One environment's secrets: each record is bound to the environment's scope key as well as its own vault key. */
export class TenantVault {
  #vault; #key; #closed = false;
  constructor(vault, key) { this.#vault = vault; this.#key = key; }
  /** A released handle's vault refuses every call, so it can never write with a key another holder now owns. */
  close() { this.#closed = true; }
  #id(id) { if (this.#closed) fail('closed', 'This environment was closed; open it again.'); if (typeof id !== 'string' || !id) fail('invalid_id', 'Vault id required.'); return `${this.#key}:${id}`; }
  get(id) { return this.#vault.get(this.#id(id)); }
  set(id, value) { this.#vault.set(this.#id(id), value); }
  delete(id) { this.#vault.delete(this.#id(id)); }
}

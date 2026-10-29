import { createHash } from 'node:crypto';
import { constants, closeSync, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readSync, readdirSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import type { Stats } from 'node:fs';
import { isAbsolute, join, resolve, sep } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { canonicalHash } from '../lib/compiler.mjs';
import { validateScope } from '../contracts/identity.mts';
import type { LocalScope } from '../contracts/identity.mts';

// OFFLINE SYNTHETIC FIXTURES ONLY. This is not a live-store migration, a runtime
// ownership enforcement layer, or an OS sandbox. The caller must close every
// database/vault user and exclusively control the directory for the whole call.
// Journal checks and repeated fingerprints detect changes, not idle open handles
// or every race against an attacker controlling the filesystem. No secret is
// decrypted: both original and migrated copies retain the co-located local key.
export type FailurePoint = 'after_copy' | 'during_transform' | 'before_publish';
export type MigrationOptions = Readonly<{
  rootDirectory: string; sourceName: string; destinationName: string;
  localOwnerId: string; targetVersion: 1; now: number; injectFailureAt?: FailurePoint;
}>;
export type RollbackOptions = Readonly<{
  rootDirectory: string; migratedName: string; destinationName: string;
  localOwnerId: string; targetVersion: 0;
}>;
export type MigrationReport = Readonly<{
  schemaVersion: 1; kind: 'fabric-fixture-migration'; scope: LocalScope;
  sourceFingerprint: string; migratedFingerprint: string; records: number;
  invalidated: number; schedulesPaused: number; workUncertain: number;
  createdAt: string; idempotent: boolean;
}>;
type JsonRecord = Record<string, unknown>;
type Files = Map<string, Buffer>;
type Row = { collection: string; id: string; document: string };
type Manifest = Omit<MigrationReport, 'idempotent'>;
const MARKER_KIND = 'fabric-synthetic-local-fixture';
const MAX_FILE = 16 * 1024 * 1024;
const MAX_TOTAL = 64 * 1024 * 1024;
const MAX_RECORDS = 5000;
const REASON = 'local_namespace_migration_requires_fresh_authorization';
const COLLECTIONS = new Set(['applications', 'capabilities', 'connections', 'jobs', 'permissions', 'heartbeats', 'clientGrants', 'oauthFlows', 'protocolRequests', 'activity']);
const HASH = /^[a-f0-9]{64}$/;
const fail = (message: string): never => { throw new Error(`Local fixture migration: ${message}`); };
const digest = (bytes: Buffer | string): string => createHash('sha256').update(bytes).digest('hex');
const oneOf = (value: unknown, allowed: readonly string[]): boolean => typeof value === 'string' && allowed.includes(value);
const same = (a: Stats, b: Stats): boolean => a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
const sameDirectory = (a: Stats, b: Stats): boolean => a.dev === b.dev && a.ino === b.ino && b.isDirectory() && !b.isSymbolicLink();

function record(value: unknown): JsonRecord {
  try { canonicalHash(value); } catch { fail('invalid bounded JSON'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('expected object');
  return value as JsonRecord;
}
function json(bytes: Buffer): JsonRecord {
  try { return record(JSON.parse(bytes.toString('utf8'))); } catch { return fail('invalid bounded JSON'); }
}
function scope(owner: string): LocalScope {
  return validateScope({ schemaVersion: 1, kind: 'local', localOwnerId: owner }) as LocalScope;
}
function rootPath(path: string): string {
  if (typeof path !== 'string' || !isAbsolute(path) || path.split(sep).includes('.fabric')) fail('an explicit canonical fixture root is required');
  const normalized = resolve(path);
  if (realpathSync(normalized) !== normalized || !lstatSync(normalized).isDirectory() || lstatSync(normalized).isSymbolicLink()) fail('fixture root cannot be a symlink');
  return normalized;
}
function child(root: string, name: string): string {
  if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(name)) fail('only direct named children of the fixture root are supported');
  return join(root, name);
}
function present(path: string): boolean {
  try { lstatSync(path); return true; } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}
function directory(path: string): Stats {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) fail('invalid fixture directory');
  return stat;
}
function readFile(path: string, ancestors: readonly string[]): Buffer {
  const directories = ancestors.map(directory);
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > MAX_FILE || realpathSync(path) !== path) fail('invalid or oversized fixture file');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!same(before, fstatSync(fd)) || ancestors.some((ancestor, index) => !sameDirectory(directories[index]!, directory(ancestor))) || realpathSync(path) !== path) fail('fixture changed during open');
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!count) fail('fixture changed during read');
      offset += count;
    }
    if (!same(before, fstatSync(fd)) || !same(before, lstatSync(path)) || ancestors.some((ancestor, index) => !sameDirectory(directories[index]!, directory(ancestor))) || realpathSync(path) !== path) fail('fixture changed during read');
    return bytes;
  } finally { closeSync(fd); }
}
function capture(path: string, root: string, version: 0 | 1, migrated = false): Files {
  const before = directory(path);
  const expected = migrated ? ['fabric.sqlite', 'fixture.json', 'migration.json', 'snapshot', 'vault'] : ['fabric.sqlite', 'fixture.json', 'vault'];
  if (JSON.stringify(readdirSync(path).sort()) !== JSON.stringify(expected.sort())) fail('unsupported files or active SQLite journal');
  const files: Files = new Map();
  for (const name of ['fabric.sqlite', 'fixture.json']) files.set(name, readFile(join(path, name), [root, path]));
  const marker = json(files.get('fixture.json')!);
  if (Object.keys(marker).sort().join(',') !== 'closed,kind,schemaVersion' || marker.kind !== MARKER_KIND || marker.closed !== true || marker.schemaVersion !== version) fail('unknown version or missing closed synthetic fixture marker');
  const vault = join(path, 'vault');
  const vaultBefore = directory(vault);
  const names = readdirSync(vault).sort();
  if (names.length > 1025 || !names.includes('master.key') || names.some(name => name !== 'master.key' && !/^[a-f0-9]{64}\.enc$/.test(name))) fail('unsupported vault files');
  let total = [...files.values()].reduce((sum, bytes) => sum + bytes.length, 0);
  for (const name of names) {
    const bytes = readFile(join(vault, name), [root, path, vault]);
    total += bytes.length;
    if (total > MAX_TOTAL || (name === 'master.key' && bytes.length !== 32)) fail('invalid vault key or fixture size');
    if (name !== 'master.key') {
      const envelope = json(bytes);
      if (envelope.version !== 1 || typeof envelope.nonce !== 'string' || typeof envelope.tag !== 'string' || typeof envelope.ciphertext !== 'string') fail('unknown vault envelope');
    }
    files.set(`vault/${name}`, bytes);
  }
  if (!same(before, directory(path)) || !same(vaultBefore, directory(vault))) fail('fixture changed during capture');
  return files;
}
function fingerprint(files: Files): string {
  return canonicalHash([...files.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([name, bytes]) => [name, digest(bytes)]));
}
function writeFiles(path: string, files: Files): void {
  mkdirSync(join(path, 'vault'), { mode: 0o700 });
  for (const [name, bytes] of files) writeFileSync(join(path, name), bytes, { flag: 'wx', mode: 0o600 });
}
function marker(version: 0 | 1): Buffer { return Buffer.from(JSON.stringify({ schemaVersion: version, kind: MARKER_KIND, closed: true })); }
function inject(selected: FailurePoint | undefined, point: FailurePoint): void {
  if (selected === point) fail('injected failure');
}

function rows(db: DatabaseSync): Row[] {
  if (db.prepare('PRAGMA user_version').get()?.user_version !== 0) fail('unsupported database version');
  if (db.prepare('PRAGMA journal_mode').get()?.journal_mode !== 'delete') fail('only closed DELETE-journal fixtures are supported');
  if (db.prepare('PRAGMA quick_check').get()?.quick_check !== 'ok') fail('invalid database');
  const objects = db.prepare("SELECT type,name FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").all();
  if (objects.length !== 1 || objects[0]?.type !== 'table' || objects[0]?.name !== 'documents') fail('unsupported database objects');
  const columns = db.prepare('PRAGMA table_info(documents)').all();
  if (columns.length !== 3 || columns.some((column, index) => column.name !== ['collection', 'id', 'document'][index] || column.type !== 'TEXT' || column.notnull !== 1 || column.pk !== [1, 2, 0][index])) fail('unsupported documents schema');
  const count = db.prepare('SELECT count(*) AS count FROM documents').get()?.count;
  if (typeof count !== 'number' || count > MAX_RECORDS) fail('too many fixture records');
  const result = db.prepare('SELECT collection,id,document FROM documents ORDER BY rowid').all();
  for (const row of result) {
    if (typeof row.collection !== 'string' || !COLLECTIONS.has(row.collection) || typeof row.id !== 'string' || !row.id || row.id.length > 256 || typeof row.document !== 'string' || Buffer.byteLength(row.document) > 2 * 1024 * 1024) fail('unsupported fixture record');
    const document = json(Buffer.from(row.document as string));
    if (document.id !== row.id) fail('record ID mismatch');
    if (Object.hasOwn(document, 'scope') || Object.hasOwn(document, 'owner')) fail('already scoped source record');
    if (row.collection === 'connections' && (document.driver !== 'http' || !oneOf(document.status, ['ready', 'unavailable', 'reconnect_required', 'revoked']))) fail('only HTTP connection fixtures are supported');
    if (row.collection === 'capabilities' && document.driver !== 'http') fail('only HTTP capability fixtures are supported');
    if (row.collection === 'permissions' && !oneOf(document.mode, ['allow', 'ask', 'deny'])) fail('unknown permission mode');
    if (row.collection === 'jobs' && !oneOf(document.status, ['awaiting_approval', 'queued', 'running', 'succeeded', 'failed', 'uncertain', 'cancelled'])) fail('unknown job state');
    if (row.collection === 'clientGrants' && !oneOf(document.status, ['active', 'revoked'])) fail('unknown client grant state');
    if (row.collection === 'heartbeats' && typeof document.enabled !== 'boolean') fail('unknown schedule state');
    if (row.collection === 'oauthFlows' && (typeof document.expiresAt !== 'number' || !Number.isSafeInteger(document.expiresAt))) fail('unknown OAuth state');
    if (row.collection === 'protocolRequests' && !oneOf(document.status, ['reserved', 'recorded', 'failed'])) fail('unknown protocol request state');
  }
  return result as Row[];
}

function transform(path: string, owner: LocalScope, createdAt: string, failure: FailurePoint | undefined): Pick<Manifest, 'records' | 'invalidated' | 'schedulesPaused' | 'workUncertain'> {
  const db = new DatabaseSync(join(path, 'fabric.sqlite'));
  try {
    db.exec('PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=0;');
    const documents = rows(db);
    const counts = { records: documents.length, invalidated: 0, schedulesPaused: 0, workUncertain: 0 };
    db.exec('BEGIN IMMEDIATE; CREATE TABLE local_ownership (collection TEXT NOT NULL, id TEXT NOT NULL, envelope TEXT NOT NULL, source_document_hash TEXT NOT NULL, PRIMARY KEY(collection,id)); CREATE TABLE local_migration (version INTEGER PRIMARY KEY, scope TEXT NOT NULL);');
    try {
      const update = db.prepare('UPDATE documents SET document=? WHERE collection=? AND id=?');
      const insertOwner = db.prepare('INSERT INTO local_ownership(collection,id,envelope,source_document_hash) VALUES(?,?,?,?)');
      const envelope = JSON.stringify({ schemaVersion: 1, scope: owner, owner: { kind: 'local_owner', id: owner.localOwnerId } });
      for (const row of documents) {
        const item = JSON.parse(row.document) as JsonRecord;
        let changed = false;
        if (row.collection === 'connections' && item.status !== 'revoked') {
          // Legacy health checks may restore reconnect_required with retained
          // tokens. Revocation blocks that path without deleting snapshot/AAD
          // ciphertext; only an explicit new authorization may reconnect.
          item.status = 'revoked'; item.refreshAvailable = false; item.revokedAt = createdAt;
          item.authRevision = canonicalHash({ schemaVersion: 1, scope: owner, priorDocumentHash: digest(row.document), revokedAt: createdAt });
          item.error = null; item.migrationReason = REASON; changed = true; counts.invalidated++;
        }
        if (row.collection === 'permissions' && item.mode === 'allow') {
          item.mode = 'ask'; item.migrationReason = REASON; changed = true; counts.invalidated++;
        }
        if (row.collection === 'jobs' && oneOf(item.status, ['awaiting_approval', 'queued', 'running'])) {
          if (item.status === 'awaiting_approval') { item.status = 'cancelled'; counts.invalidated++; }
          else { item.status = 'uncertain'; counts.workUncertain++; }
          for (const key of ['approvalDigest', 'approvalExpiresAt', 'approvedAt', 'approvedBy']) delete item[key];
          item.error = REASON; item.migrationReason = REASON; changed = true;
        }
        if (row.collection === 'heartbeats') {
          item.enabled = false; item.migrationReason = REASON; changed = true; counts.schedulesPaused++;
        }
        if (row.collection === 'clientGrants' && item.status === 'active') {
          item.status = 'revoked'; item.revokedAt = createdAt; item.migrationReason = REASON; changed = true; counts.invalidated++;
        }
        if (row.collection === 'oauthFlows') {
          // Current callback checks expiresAt, not status. Preserve ciphertext in
          // vault while making every old flow non-consumable by the legacy reader.
          item.expiresAt = 0; item.status = 'invalidated'; item.migrationReason = REASON; changed = true; counts.invalidated++;
        }
        if (row.collection === 'protocolRequests' && item.status === 'reserved') {
          item.status = 'failed'; item.migrationReason = REASON; changed = true; counts.invalidated++;
        }
        if (changed) { item.updatedAt = createdAt; update.run(JSON.stringify(item), row.collection, row.id); }
        insertOwner.run(row.collection, row.id, envelope, digest(row.document));
      }
      db.prepare('INSERT INTO local_migration(version,scope) VALUES(1,?)').run(JSON.stringify(owner));
      inject(failure, 'during_transform');
      db.exec('PRAGMA user_version=1; COMMIT;');
    } catch (error) { db.exec('ROLLBACK;'); throw error; }
    return counts;
  } finally { db.close(); }
}

function manifest(path: string, root: string, expectedOwner: LocalScope, verifyCurrent = true): { report: Manifest; source: Files } {
  const report = json(readFile(join(path, 'migration.json'), [root, path]));
  const keys = ['createdAt', 'invalidated', 'kind', 'migratedFingerprint', 'records', 'schemaVersion', 'scope', 'schedulesPaused', 'sourceFingerprint', 'workUncertain'].sort();
  if (Object.keys(report).sort().join(',') !== keys.join(',') || report.schemaVersion !== 1 || report.kind !== 'fabric-fixture-migration' || canonicalHash(report.scope) !== canonicalHash(expectedOwner)) fail('invalid manifest or owner reassignment');
  if (typeof report.sourceFingerprint !== 'string' || !HASH.test(report.sourceFingerprint) || typeof report.migratedFingerprint !== 'string' || !HASH.test(report.migratedFingerprint) || typeof report.createdAt !== 'string' || !Number.isFinite(Date.parse(report.createdAt)) || ['records', 'invalidated', 'schedulesPaused', 'workUncertain'].some(key => typeof report[key] !== 'number' || !Number.isSafeInteger(report[key]) || (report[key] as number) < 0)) fail('invalid migration manifest');
  const source = capture(join(path, 'snapshot'), root, 0);
  if (fingerprint(source) !== report.sourceFingerprint) fail('snapshot changed');
  if (verifyCurrent) {
    if (fingerprint(capture(path, root, 1, true)) !== report.migratedFingerprint) fail('migrated copy changed');
    const db = new DatabaseSync(join(path, 'fabric.sqlite'), { readOnly: true });
    try {
      db.exec('PRAGMA trusted_schema=OFF;');
      const owners = db.prepare('SELECT version,scope FROM local_migration').all();
      if (db.prepare('PRAGMA user_version').get()?.user_version !== 1 || owners.length !== 1 || owners[0]?.version !== 1 || typeof owners[0]?.scope !== 'string' || canonicalHash(JSON.parse(owners[0].scope)) !== canonicalHash(expectedOwner)) fail('database owner reassignment');
    } finally { db.close(); }
  }
  return { report: report as Manifest, source };
}
function freezeReport(report: Manifest, idempotent: boolean): MigrationReport {
  return Object.freeze({ ...report, scope: scope(report.scope.localOwnerId), idempotent });
}

export function migrateLocalFixture(options: MigrationOptions): MigrationReport {
  record(options);
  if (Object.keys(options).some(key => !['rootDirectory', 'sourceName', 'destinationName', 'localOwnerId', 'targetVersion', 'now', 'injectFailureAt'].includes(key)) || options.targetVersion !== 1 || !Number.isSafeInteger(options.now) || options.now < 0 || options.now > 8640000000000000 || (options.injectFailureAt !== undefined && !['after_copy', 'during_transform', 'before_publish'].includes(options.injectFailureAt))) fail('unsupported migration options');
  const root = rootPath(options.rootDirectory), source = child(root, options.sourceName), destination = child(root, options.destinationName);
  if (source === destination) fail('migration requires a fresh destination');
  const owner = scope(options.localOwnerId), original = capture(source, root, 0), sourceFingerprint = fingerprint(original);
  if (present(destination)) {
    const existing = manifest(destination, root, owner);
    if (existing.report.sourceFingerprint !== sourceFingerprint) fail('destination belongs to a different fixture');
    return freezeReport(existing.report, true);
  }
  const rootIdentity = directory(root), sourceIdentity = directory(source);
  const staging = mkdtempSync(join(root, 'fixture-migration-'));
  try {
    writeFiles(staging, original);
    mkdirSync(join(staging, 'snapshot'), { mode: 0o700 });
    writeFiles(join(staging, 'snapshot'), original);
    inject(options.injectFailureAt, 'after_copy');
    const createdAt = new Date(options.now).toISOString();
    const counts = transform(staging, owner, createdAt, options.injectFailureAt);
    writeFileSync(join(staging, 'fixture.json'), marker(1), { mode: 0o600 });
    // Reserve manifest before capturing the strict migrated directory layout.
    writeFileSync(join(staging, 'migration.json'), '{}', { flag: 'wx', mode: 0o600 });
    const report: Manifest = { schemaVersion: 1, kind: 'fabric-fixture-migration', scope: owner, sourceFingerprint, migratedFingerprint: fingerprint(capture(staging, root, 1, true)), ...counts, createdAt };
    writeFileSync(join(staging, 'migration.json'), JSON.stringify(report), { mode: 0o600 });
    inject(options.injectFailureAt, 'before_publish');
    if (!sameDirectory(rootIdentity, directory(root)) || !sameDirectory(sourceIdentity, directory(source)) || fingerprint(capture(source, root, 0)) !== sourceFingerprint || present(destination)) fail('source or destination changed before publication');
    renameSync(staging, destination);
    return freezeReport(report, false);
  } catch (error) { rmSync(staging, { recursive: true, force: true }); throw error; }
}

export function rollbackLocalFixture(options: RollbackOptions): Readonly<{ schemaVersion: 0; sourceFingerprint: string; restored: true }> {
  record(options);
  if (Object.keys(options).some(key => !['rootDirectory', 'migratedName', 'destinationName', 'localOwnerId', 'targetVersion'].includes(key)) || options.targetVersion !== 0) fail('unsupported rollback options');
  const root = rootPath(options.rootDirectory), migrated = child(root, options.migratedName), destination = child(root, options.destinationName);
  if (migrated === destination || present(destination)) fail('rollback requires a fresh destination');
  // Rollback depends on the untouched snapshot, not the current migrated DB:
  // subsequent fixture edits/corruption must not require reconstructing authority.
  const verified = manifest(migrated, root, scope(options.localOwnerId), false);
  const rootIdentity = directory(root), migratedIdentity = directory(migrated);
  const staging = mkdtempSync(join(root, 'fixture-rollback-'));
  try {
    writeFiles(staging, verified.source);
    if (fingerprint(capture(staging, root, 0)) !== verified.report.sourceFingerprint || !sameDirectory(rootIdentity, directory(root)) || !sameDirectory(migratedIdentity, directory(migrated)) || manifest(migrated, root, scope(options.localOwnerId), false).report.sourceFingerprint !== verified.report.sourceFingerprint || present(destination)) fail('fixture changed before rollback publication');
    renameSync(staging, destination);
    return Object.freeze({ schemaVersion: 0, sourceFingerprint: verified.report.sourceFingerprint, restored: true });
  } catch (error) { rmSync(staging, { recursive: true, force: true }); throw error; }
}

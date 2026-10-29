import {constants} from 'node:fs';
import {lstat, open, realpath} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildIntegrationBatch} from '../lib/integration-pipeline.mjs';

const MAX_BYTES = 2 * 1024 * 1024;
const HELP = 'Usage: node cli.mjs pipeline build BATCH.json\nOffline intake only: emits candidate packages; does not connect accounts, execute operations, or publish integrations.\n';
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

class IntakeError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const sameIdentity = (left, right) => left.dev === right.dev && left.ino === right.ino;
const sameFile = (left, right) => sameIdentity(left, right) && left.size === right.size &&
  left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
const changedSource = () => new IntakeError('source_changed', 'Input file or its directory changed during intake. Retry with stable local files.');

async function captureSourceBoundary(file, directory) {
  const relative = path.relative(directory, path.dirname(file));
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new IntakeError('source_path', 'Document files must stay inside the batch folder without symlinks.');
  }
  const locations = [directory];
  for (const segment of relative.split(path.sep).filter(Boolean)) locations.push(path.join(locations.at(-1), segment));
  const ancestors = [];
  for (const location of locations) {
    const metadata = await lstat(location);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || await realpath(location) !== location) {
      throw new IntakeError('source_path', 'Document directories must stay inside the batch folder without symlinks.');
    }
    ancestors.push({location, metadata});
  }
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || await realpath(file) !== file) {
    throw new IntakeError('source_path', 'Document files must stay inside the batch folder without symlinks.');
  }
  return {ancestors, metadata};
}

async function verifySourceBoundary(file, boundary) {
  if (await realpath(file) !== file) throw changedSource();
  for (const ancestor of boundary.ancestors) {
    const current = await lstat(ancestor.location);
    if (!current.isDirectory() || current.isSymbolicLink() || !sameIdentity(current, ancestor.metadata) ||
        await realpath(ancestor.location) !== ancestor.location) throw changedSource();
  }
  const current = await lstat(file);
  if (!current.isFile() || current.isSymbolicLink() || !sameFile(current, boundary.metadata)) throw changedSource();
}

async function readJSON(file, {directory} = {}) {
  let handle;
  try {
    const boundary = directory ? await captureSourceBoundary(file, directory) : null;
    const expected = boundary?.metadata || await lstat(file);
    if (!expected.isFile()) throw new IntakeError('source_type', 'Input must be a regular JSON file, not a symlink or directory.');
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > MAX_BYTES) throw new IntakeError('source_size', 'Input must be a regular JSON file no larger than 2 MiB.');
    if (!sameFile(metadata, expected)) throw changedSource();
    // Pin the opened file to the validated path before reading any content.
    // These checks detect filesystem changes; this local compiler is not an OS
    // sandbox against an attacker who controls and races the filesystem.
    if (boundary) await verifySourceBoundary(file, boundary);
    if (!sameFile(await handle.stat(), expected)) throw changedSource();
    // Bound the read even if another process grows the input after stat.
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const result = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    if (offset > MAX_BYTES) throw new IntakeError('source_size', 'Input exceeds the 2 MiB limit.');
    if (!sameFile(await handle.stat(), expected)) throw changedSource();
    if (boundary) await verifySourceBoundary(file, boundary);
    try { return JSON.parse(buffer.subarray(0, offset).toString('utf8')); }
    catch { throw new IntakeError('source_json', 'Input is not valid JSON.'); }
  } catch (error) {
    if (error instanceof IntakeError) throw error;
    throw new IntakeError('source_unavailable', 'Input file could not be read. Check its location and permissions.');
  } finally { await handle?.close(); }
}

async function readSource(directory, relativePath) {
  if (typeof relativePath !== 'string' || !relativePath || relativePath.length > 512 ||
      /[\u0000-\u001f\\]/.test(relativePath) || path.isAbsolute(relativePath) ||
      relativePath.split('/').some(segment => !segment || segment === '.' || segment === '..') ||
      !relativePath.endsWith('.json')) {
    throw new IntakeError('source_path', 'documentPath must name a JSON file inside the batch folder without traversal.');
  }
  const file = path.resolve(directory, relativePath);
  return readJSON(file, {directory});
}

export async function buildBatchFile(filename, {cwd = process.cwd()} = {}) {
  const batchFile = path.resolve(cwd, filename);
  const input = await readJSON(batchFile);
  if (!record(input) || Object.keys(input).some(key => !['schemaVersion', 'integrations'].includes(key)) ||
      input.schemaVersion !== 1 || !Array.isArray(input.integrations) || input.integrations.length < 1 || input.integrations.length > 25) {
    throw new IntakeError('batch_format', 'Expected schemaVersion 1 and between 1 and 25 integration entries.');
  }
  const directory = await realpath(path.dirname(batchFile));
  const failures = new Map();
  const entries = [];
  // Sequential bounded reads avoid holding multiple maximum-sized buffers at once.
  for (const [index, entry] of input.integrations.entries()) {
    try {
      if (!record(entry) || Object.keys(entry).some(key => !['manifest', 'documentPath'].includes(key)) || !Object.hasOwn(entry, 'manifest')) {
        throw new IntakeError('entry_format', 'Each entry needs a manifest and documentPath only.');
      }
      entries.push({manifest: entry.manifest, document: await readSource(directory, entry.documentPath)});
    } catch (error) {
      failures.set(index, {code: error.code || 'source_invalid', message: error instanceof IntakeError ? error.message : 'Unable to load this entry.'});
      entries.push({manifest: record(entry) ? entry.manifest : null, document: null});
    }
  }
  const report = buildIntegrationBatch(entries);
  for (const result of report.results) {
    if (failures.has(result.index)) result.intakeError = failures.get(result.index);
  }
  return report;
}

export async function runIntegrationPipelineCLI(args, {cwd = process.cwd(), stdout = process.stdout, stderr = process.stderr} = {}) {
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) { stdout.write(HELP); return 0; }
  if (args.length !== 2 || args[0] !== 'build' || typeof args[1] !== 'string' || args[1].startsWith('-')) {
    stderr.write(HELP); return 2;
  }
  try {
    const report = await buildBatchFile(args[1], {cwd});
    stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return report.counts.blocked > 0 ? 1 : 0;
  } catch (error) {
    stderr.write(`${JSON.stringify({error: {code: error.code || 'pipeline_failed', message: error instanceof IntakeError ? error.message : 'The integration batch could not be prepared. No accounts or runtime state were changed.'}})}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runIntegrationPipelineCLI(process.argv.slice(2));
}

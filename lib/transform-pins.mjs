// F10.8 part c (docs/F10.8-BUILD-MAP.md, decision 4 of 2026-10-17): each transform version is pinned to a hash of its code, and the
// harness to a hash of its own. A code hash covers the version module, every helper it imports and always _shared/error.v1.mjs (R16),
// each file's bytes with LF line ends, hashed with the domain fields kind fabric-transform-code and version 1. Schemas, caps and refusals
// are in the module's bytes, so they are covered. The harness hash covers run.mjs, the helpers it imports, lib/compiler.mjs and the file
// that imports, lib/openapi-security.mjs, because every input and output check runs through the compiler. Runtime facts (tz data, ICU,
// Unicode) are not in any hash: each entry declares the facts it reads and step 12 records them.
//
// This file lives outside lib/transforms, so it may read files. It follows imports with its own fixed reader of the import lines the
// source scan allows (open point Minor 13): only scripts/transform-scan.mjs uses TypeScript, a dev dependency. PINS is
// lib/transforms/pins.json, shape-checked at import and never compared there (open question 16); scripts/transform-pins.mjs compares.
import {createHash} from 'node:crypto';
import {existsSync, readdirSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalHash} from './compiler.mjs';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const TRANSFORMS_DIR = 'lib/transforms';
export const PINS_PATH = `${TRANSFORMS_DIR}/pins.json`;
const RUN = `${TRANSFORMS_DIR}/run.mjs`, ERROR_V1 = `${TRANSFORMS_DIR}/_shared/error.v1.mjs`, COMPILER = 'lib/compiler.mjs';
const ID = /^([a-z][a-z0-9]*)\.([a-z][A-Za-z0-9]*)@([1-9][0-9]*)$/;
const HASH = /^[a-f0-9]{64}$/;
// The import lines the source scan allows: a named import or re-export from a quoted path, over one or more lines.
const IMPORT_LINE = /^[ \t]*(?:import|export)[ \t]*\{[^}]*\}[ \t]*from[ \t]*(['"])([^'"\r\n]+)\1/gm;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const byText = (a, b) => a < b ? -1 : a > b ? 1 : 0;

/** The bytes with CRLF and a lone CR turned into LF, as test/oauth-relay.test.mjs:61 hashes, so a checkout's line endings move no hash. */
export function lfBytes(bytes) {
  const out = Buffer.alloc(bytes.length);
  let length = 0;
  for (let index = 0; index < bytes.length; index++) {
    if (bytes[index] !== 0x0d) out[length++] = bytes[index];
    else { out[length++] = 0x0a; if (bytes[index + 1] === 0x0a) index++; }
  }
  return out.subarray(0, length);
}
/** The paths a file's import lines name, in order. */
export const importsOf = text => [...text.matchAll(IMPORT_LINE)].map(match => match[2]);

/** sha256 of each file reached from `start` through relative imports, all inside `scope`; a path in `outside` is left to its own walk. */
function closure(root, start, scope, outside = []) {
  const sources = {}, queue = [start];
  while (queue.length) {
    const file = queue.shift();
    if (Object.hasOwn(sources, file)) continue;
    const location = path.join(root, file);
    if (!existsSync(location)) throw new Error(`${file} does not exist.`);
    const bytes = readFileSync(location);
    sources[file] = createHash('sha256').update(lfBytes(bytes)).digest('hex');
    for (const specifier of importsOf(bytes.toString('utf8'))) {
      // node: imports are not files; the source scan refuses them inside lib/transforms.
      if (specifier.startsWith('node:')) continue;
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
      if (outside.includes(target)) continue;
      if (!/^\.\.?\//.test(specifier) || !target.startsWith(`${scope}/`)) throw new Error(`${file} imports ${specifier}, outside ${scope}.`);
      queue.push(target);
    }
  }
  return sources;
}

/** The module file of name@version. */
export function moduleOf(id) {
  const match = typeof id === 'string' ? ID.exec(id) : null;
  if (!match) throw new Error(`${id} is not a transform id written family.name@version.`);
  return `${TRANSFORMS_DIR}/${match[1]}/${match[2]}.v${match[3]}.mjs`;
}
/** Each file one transform's pin covers, with its sha256: the module, every helper it reaches and always _shared/error.v1.mjs. */
export function sourcesOf(root, id) {
  const sources = closure(root, moduleOf(id), TRANSFORMS_DIR);
  // TransformError and the step 8 code lists live in error.v1.mjs, so every pin covers it, imported or not. A later error file is in
  // the sources only of the modules whose imports reach it, so adding one moves no existing pin.
  if (!Object.hasOwn(sources, ERROR_V1)) Object.assign(sources, closure(root, ERROR_V1, TRANSFORMS_DIR));
  return sources;
}
/** One transform's code hash. */
export const codeHash = (root, id) => canonicalHash({kind: 'fabric-transform-code', version: 1, transform: id, sources: sourcesOf(root, id)});
/** Each file the harness hash covers, with its sha256: run.mjs and the helpers it imports, then lib/compiler.mjs and the file it imports. */
export const harnessSources = root => ({...closure(root, RUN, TRANSFORMS_DIR, [COMPILER]), ...closure(root, COMPILER, 'lib')});
/** The harness hash. It is pinned and recorded, never bound into action ids (open question 22). */
export const harnessHash = root => canonicalHash({kind: 'fabric-transform-harness', version: 1, sources: harnessSources(root)});

/** Every transform id under <root>/lib/transforms, from the files <family>/<name>.v<n>.mjs, never from a loaded registry. */
export function transformIds(root) {
  const base = path.join(root, TRANSFORMS_DIR), ids = [];
  if (!existsSync(base)) return ids;
  for (const folder of readdirSync(base, {withFileTypes: true})) {
    if (!folder.isDirectory() || !/^[a-z][a-z0-9]*$/.test(folder.name)) continue;
    for (const name of readdirSync(path.join(base, folder.name))) {
      const match = /^([a-z][A-Za-z0-9]*)\.v([1-9][0-9]*)\.mjs$/.exec(name);
      if (match) ids.push(`${folder.name}.${match[1]}@${match[2]}`);
    }
  }
  return ids.sort(byText);
}
/** The pins <root> gives now: its harness hash and the code hash of each id (by default every id under <root>). */
export function computePins(root, ids = transformIds(root)) {
  return {harness: harnessHash(root), transforms: Object.fromEntries(ids.map(id => [id, codeHash(root, id)]))};
}

/** A real calendar day written YYYY-MM-DD, checked by a UTC round trip; no clock is read. */
export function validDate(value) {
  if (typeof value !== 'string' || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value)) return false;
  const [year, month, day] = value.split('-').map(Number);
  return new Date(Date.UTC(year, month - 1, day)).toISOString().slice(0, 10) === value;
}
/** A re-pin reason: 1 to 200 characters on one line. */
export const validReason = value => typeof value === 'string' && value.trim().length > 0 && value.length <= 200 && !/[\u0000-\u001f\u007f]/.test(value);
const validRepin = item => record(item) && Object.keys(item).sort(byText).join() === 'date,from,reason,to,transform' && (item.transform === 'harness' || ID.test(item.transform))
  && HASH.test(item.from) && HASH.test(item.to) && validDate(item.date) && validReason(item.reason);

/** Checks the shape of a parsed pins file and returns it; throws naming the file otherwise. */
export function checkPinsShape(value) {
  const fail = reason => { throw new Error(`${PINS_PATH}: ${reason}`); };
  if (!record(value) || Object.keys(value).sort(byText).join() !== 'harness,note,repins,schemaVersion,transforms') fail('the file holds exactly note, schemaVersion, harness, transforms and repins.');
  if (typeof value.note !== 'string' || value.schemaVersion !== 1 || typeof value.harness !== 'string' || !HASH.test(value.harness)) fail('schemaVersion is 1, with a note and a harness hash of 64 hex characters.');
  if (!record(value.transforms) || Object.entries(value.transforms).some(([id, hash]) => !ID.test(id) || typeof hash !== 'string' || !HASH.test(hash))) fail('transforms maps family.name@version to hashes of 64 hex characters.');
  if (!Array.isArray(value.repins) || !value.repins.every(validRepin)) fail('each repin is {transform, from, to, date, reason}, with a real date and a one-line reason.');
  return value;
}
/** <root>'s pins file, shape-checked, or null when there is none. */
export function readPins(root) {
  const file = path.join(root, PINS_PATH);
  if (!existsSync(file)) return null;
  let value;
  try { value = JSON.parse(readFileSync(file, 'utf8')); } catch { throw new Error(`${PINS_PATH}: the file is not JSON.`); }
  return checkPinsShape(value);
}

const deepFreeze = value => { if (value !== null && typeof value === 'object') { Object.freeze(value); for (const item of Object.values(value)) deepFreeze(item); } return value; };
/** This checkout's pins, read and shape-checked once at import; null only before the first --write, so nothing counts as pinned. */
export const PINS = deepFreeze(readPins(ROOT));

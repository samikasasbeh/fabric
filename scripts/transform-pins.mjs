// F10.8 part c (docs/F10.8-BUILD-MAP.md, decision 4 of 2026-10-17): checks and writes lib/transforms/pins.json, in the pattern of
// scripts/defaults-golden.mjs. A behaviour change is a new version file with a new pin; no existing pin moves. A re-pin is a recorded,
// reviewed exception, and every action that names that transform gets a new id (step 9). test/transforms-pins.test.mjs keeps the
// shipped pins current.
//
//   node scripts/transform-pins.mjs [--check] [--root <dir>]     the source scan, then the pins; exit 1 naming each difference
//   node scripts/transform-pins.mjs --write [--root <dir>]       adds pins for new ids only; refuses when an existing pin differs
//   node scripts/transform-pins.mjs --repin <id|harness> --reason <text> --date <YYYY-MM-DD> [--root <dir>]
//                                                                replaces one pin and records it in repins
//
// Ids, sources and pins all come from <root>, never from this checkout's loaded registry, so --root can name a worktree. It never reads
// .env, .fabric, the vault or the environment; no network, no clock.
import {writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {PINS_PATH, ROOT, codeHash, computePins, harnessHash, readPins, transformIds, validDate, validReason} from '../lib/transform-pins.mjs';
import {formatFinding, scanTransforms} from './transform-scan.mjs';

const NOTE = 'F10.8 transform pins (docs/F10.8-BUILD-MAP.md part c, decision 4 of 2026-10-17). Each transform version is pinned to the hash of its module, the helpers it imports and _shared/error.v1.mjs; the harness to the hash of run.mjs, its helpers, lib/compiler.mjs and lib/openapi-security.mjs. A behaviour change is a new version file. Written by node scripts/transform-pins.mjs --write, which adds new ids only; a reviewed re-pin is --repin with a reason and a date, recorded in repins.';
const byId = ([a], [b]) => a < b ? -1 : a > b ? 1 : 0;
const write = (root, pins) => writeFileSync(path.join(root, PINS_PATH), `${JSON.stringify({...pins, transforms: Object.fromEntries(Object.entries(pins.transforms).sort(byId))}, null, 1)}\n`);
function scanned(root) {
  const findings = scanTransforms(root);
  if (findings.length) throw new Error(`The source scan refuses this tree, so nothing is pinned:\n${findings.map(formatFinding).join('\n')}`);
}

/** Everything that keeps <root>'s pins from being current, as sentences: the scan's findings first. Empty when nothing does. */
export function pinDifferences(root = ROOT) {
  const problems = scanTransforms(root).map(formatFinding), pins = readPins(root);
  if (!pins) return [...problems, `${PINS_PATH} is missing. Run node scripts/transform-pins.mjs --write.`];
  const now = computePins(root);
  if (now.harness !== pins.harness) problems.push('The harness hash differs from its pin. A change to run.mjs, its helpers, lib/compiler.mjs or lib/openapi-security.mjs is a reviewed re-pin: --repin harness --reason <text> --date <YYYY-MM-DD>.');
  for (const [id, hash] of Object.entries(now.transforms)) {
    if (!Object.hasOwn(pins.transforms, id)) problems.push(`${id} is not pinned. Run node scripts/transform-pins.mjs --write.`);
    else if (pins.transforms[id] !== hash) problems.push(`${id} differs from its pin. A behaviour change is a new version file; a reviewed exception is --repin ${id} --reason <text> --date <YYYY-MM-DD>, and every action that names it gets a new id.`);
  }
  for (const id of Object.keys(pins.transforms)) if (!Object.hasOwn(now.transforms, id)) problems.push(`${id} is pinned but its file is gone. A version is never removed.`);
  return problems;
}

/** --write: pins every new id; refuses, naming them, when an existing pin or the harness differs or a pinned id is gone. */
export function writePins(root = ROOT) {
  scanned(root);
  const pins = readPins(root), now = computePins(root);
  if (pins) {
    const stale = [
      ...Object.keys(pins.transforms).filter(id => Object.hasOwn(now.transforms, id) && now.transforms[id] !== pins.transforms[id]).map(id => `${id} differs from its pin`),
      ...Object.keys(pins.transforms).filter(id => !Object.hasOwn(now.transforms, id)).map(id => `${id} is pinned but its file is gone`),
      ...(pins.harness !== now.harness ? ['the harness hash differs from its pin'] : [])];
    if (stale.length) throw new Error(`--write adds new ids only and changes no pin: ${stale.join('; ')}. A reviewed re-pin is --repin <id|harness> --reason <text> --date <YYYY-MM-DD>.`);
  }
  const added = Object.keys(now.transforms).filter(id => !pins || !Object.hasOwn(pins.transforms, id));
  const next = {note: NOTE, schemaVersion: 1, harness: now.harness, transforms: now.transforms, repins: pins ? [...pins.repins] : []};
  write(root, next);
  return {added, pins: next};
}

/** --repin: replaces one transform's pin, or the harness pin, and records {transform, from, to, date, reason}. */
export function repin(root = ROOT, {target, reason, date} = {}) {
  if (!validReason(reason)) throw new Error('A re-pin needs a reason of 1 to 200 characters on one line.');
  if (!validDate(date)) throw new Error(`${date} is not a real date written YYYY-MM-DD.`);
  scanned(root);
  const pins = readPins(root);
  if (!pins) throw new Error(`${PINS_PATH} is missing. Run node scripts/transform-pins.mjs --write first.`);
  let from, to;
  if (target === 'harness') [from, to] = [pins.harness, harnessHash(root)];
  else {
    if (typeof target !== 'string' || !Object.hasOwn(pins.transforms, target)) throw new Error(`${target} is not pinned. A new version is pinned with --write.`);
    if (!transformIds(root).includes(target)) throw new Error(`${target} is pinned but its file is gone.`);
    [from, to] = [pins.transforms[target], codeHash(root, target)];
  }
  if (from === to) throw new Error(`${target} already matches its pin; there is nothing to re-pin.`);
  const next = {note: NOTE, schemaVersion: 1, harness: target === 'harness' ? to : pins.harness, transforms: target === 'harness' ? pins.transforms : {...pins.transforms, [target]: to},
    repins: [...pins.repins, {transform: target, from, to, date, reason: reason.trim()}]};
  write(root, next);
  return {from, to};
}

// ---- the command line -----------------------------------------------------------------------------------------------------
const USAGE = 'Usage: node scripts/transform-pins.mjs [--check | --write] [--root <dir>]\n       node scripts/transform-pins.mjs --repin <id|harness> --reason <text> --date <YYYY-MM-DD> [--root <dir>]';
class UsageError extends Error {}
function parse(argv) {
  const options = {mode: null, root: ROOT, target: null, reason: null, date: null};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index], value = () => { const next = argv[++index]; if (next === undefined || next.startsWith('--')) throw new UsageError(`${arg} needs a value.`); return next; };
    const mode = name => { if (options.mode) throw new UsageError('Choose one of --check, --write and --repin.'); options.mode = name; };
    if (arg === '--check' || arg === '--write') mode(arg.slice(2));
    else if (arg === '--repin') { mode('repin'); options.target = value(); }
    else if (arg === '--reason') options.reason = value();
    else if (arg === '--date') options.date = value();
    else if (arg === '--root') options.root = path.resolve(value());
    else if (arg === '--help' || arg === '-h') options.mode = 'help';
    else throw new UsageError(`Unknown argument: ${arg}`);
  }
  options.mode ??= 'check';
  if (options.mode === 'repin' && (options.reason === null || options.date === null)) throw new UsageError('--repin needs --reason and --date.');
  if (options.mode !== 'repin' && (options.reason !== null || options.date !== null)) throw new UsageError('--reason and --date go with --repin only.');
  return options;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parse(process.argv.slice(2));
    if (options.mode === 'help') console.log(USAGE);
    else if (options.mode === 'write') {
      const {added, pins} = writePins(options.root);
      console.log(`Wrote ${PINS_PATH}: ${Object.keys(pins.transforms).length} transforms pinned${added.length ? `, ${added.length} new (${added.join(', ')})` : ', none new'}.`);
    } else if (options.mode === 'repin') {
      const {from, to} = repin(options.root, {target: options.target, reason: options.reason, date: options.date});
      console.log(`Re-pinned ${options.target} from ${from.slice(0, 12)} to ${to.slice(0, 12)}. Commit ${PINS_PATH} with the review that approved it.`);
    } else {
      const problems = pinDifferences(options.root);
      for (const problem of problems) console.error(problem);
      if (problems.length) process.exitCode = 1;
      else console.log(`Every transform matches its pin (${transformIds(options.root).length} pinned), the harness matches, and the source scan is clean.`);
    }
  } catch (error) {
    console.error(error instanceof UsageError ? `${error.message}\n${USAGE}` : error.message);
    process.exitCode = error instanceof UsageError ? 2 : 1;
  }
}

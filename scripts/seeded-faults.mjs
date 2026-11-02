// Exit check 9 (docs/F03-DEVELOPER-LAYER.md section 9): runs every seeded fault in test/faults/registry.mjs. For each
// runnable entry it puts the fault into the named file (the `from` text must occur there exactly once), runs that
// entry's tests with node --test, and puts the original bytes back in a finally block, on Ctrl+C, on a crash and on
// exit. Each fault is reported caught or MISSED; owed faults are listed apart. It refuses to start while git reports
// uncommitted changes to any file it would touch, or while another run (or an interrupted one) holds its lock.
//
//   node scripts/seeded-faults.mjs [--step F03.4] [--only id,id] [--json out.json] [--timeout 180] [--no-baseline] [--verbose]
//   node scripts/seeded-faults.mjs --check      checks the registry only (read-only) and reports counts
//   node scripts/seeded-faults.mjs --restore    puts back files an interrupted run left changed (only if still unchanged since)
//
// Never part of npm test: it changes product files while it runs, so run it alone, on a clean tree.
import {spawn, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync, readFileSync, writeFileSync, unlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {testEnvironment} from './test.mjs';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const REGISTRY = path.join(ROOT, 'test', 'faults', 'registry.mjs');
const sha = value => createHash('sha256').update(value).digest('hex');
const LOCK = path.join(tmpdir(), `fabric-seeded-faults-${sha(ROOT).slice(0, 16)}.json`);

function usage() {
  console.log('Usage: node scripts/seeded-faults.mjs [--step F03.4] [--only id,id] [--json out.json] [--timeout seconds] [--no-baseline] [--verbose]\n       node scripts/seeded-faults.mjs --check | --restore');
}
function parseArgs(argv) {
  const options = {steps: [], only: [], json: null, timeoutMs: 180_000, baseline: true, verbose: false, check: false, restore: false};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i], value = () => { const next = argv[++i]; if (next === undefined) throw new Error(`${arg} needs a value.`); return next; };
    if (arg === '--step') options.steps.push(...value().split(',').map(item => item.trim()).filter(Boolean));
    else if (arg === '--only') options.only.push(...value().split(',').map(item => item.trim()).filter(Boolean));
    else if (arg === '--json') options.json = path.resolve(value());
    else if (arg === '--timeout') { const seconds = Number(value()); if (!Number.isFinite(seconds) || seconds < 5) throw new Error('--timeout is a number of seconds, at least 5.'); options.timeoutMs = seconds * 1000; }
    else if (arg === '--no-baseline') options.baseline = false;
    else if (arg === '--verbose') options.verbose = true;
    else if (arg === '--check') options.check = true;
    else if (arg === '--restore') options.restore = true;
    else if (arg === '--help' || arg === '-h') { usage(); process.exit(0); }
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return options;
}

// ---- the registry, checked without touching anything ----------------------------------------------------------------
const occurrences = (text, needle) => { let count = 0; for (let at = text.indexOf(needle); at !== -1; at = text.indexOf(needle, at + needle.length)) count++; return count; };
/** A path inside the repository, relative and plain; anything else is refused. */
function inside(relative) {
  if (typeof relative !== 'string' || !relative || path.isAbsolute(relative) || relative.split(/[\\/]/).includes('..')) return null;
  return path.join(ROOT, relative);
}
/** Every edit of an entry, first one included, each with its file. */
const editsOf = entry => [{file: entry.file, from: entry.from, to: entry.to}, ...(entry.also || []).map(edit => ({file: edit.file ?? entry.file, from: edit.from, to: edit.to}))];

function validate(faults, newTests) {
  const problems = [], ids = new Set();
  for (const entry of faults) {
    const where = entry?.id ?? '(no id)';
    if (typeof entry?.id !== 'string' || !/^[a-z0-9-]+$/.test(entry.id)) problems.push({id: where, problem: 'id must be lowercase letters, digits and hyphens'});
    else if (ids.has(entry.id)) problems.push({id: where, problem: 'duplicate id'});
    ids.add(entry?.id);
    if (typeof entry?.step !== 'string' || !/^(F(03\.(\d|1[01])|10\.\d{1,2})|I07)$/.test(entry.step)) problems.push({id: where, problem: 'step must be F03.0 to F03.11, F10.<n> or I07'});
    if (typeof entry?.name !== 'string' || !entry.name.trim()) problems.push({id: where, problem: 'name is required'});
    if (entry?.owed !== undefined) {
      if (typeof entry.owed !== 'string' || entry.owed.length < 20) problems.push({id: where, problem: 'owed must say where and when the fault becomes testable'});
      if (entry.file !== undefined || entry.from !== undefined) problems.push({id: where, problem: 'an owed entry has no file or from'});
      continue;
    }
    if (!Array.isArray(entry.tests) || !entry.tests.length) problems.push({id: where, problem: 'tests must list at least one test file'});
    for (const test of entry.tests || []) {
      const file = inside(test);
      if (!file || !/^test\/.+\.test\.mjs$/.test(test)) problems.push({id: where, problem: `${test} is not a test file path`});
      else if (!existsSync(file) && !newTests.includes(test)) problems.push({id: where, problem: `${test} does not exist and is not being written`});
    }
    for (const edit of editsOf(entry)) {
      const file = inside(edit.file);
      if (!file) { problems.push({id: where, problem: `${edit.file} is not a path inside the repository`}); continue; }
      if (typeof edit.from !== 'string' || !edit.from || typeof edit.to !== 'string' || edit.from === edit.to) { problems.push({id: where, problem: `${edit.file}: from and to must be different strings`}); continue; }
      if (!existsSync(file)) { problems.push({id: where, problem: `${edit.file} does not exist`}); continue; }
      const count = occurrences(readFileSync(file, 'utf8'), edit.from);
      if (count !== 1) problems.push({id: where, problem: `${edit.file}: from occurs ${count} times (must be exactly once)`});
    }
  }
  return problems;
}

// ---- the files a run changes, and how they always come back --------------------------------------------------------
let changed = new Map(); // absolute path -> {original: Buffer, mutated: string(sha)}
let child = null, lockStarted = null, lockHeld = false;
function writeLock(extra = {}) {
  const files = Object.fromEntries([...changed].map(([file, {original, mutated}]) => [file, {original: original.toString('base64'), originalSha: sha(original), mutatedSha: mutated}]));
  writeFileSync(LOCK, JSON.stringify({pid: process.pid, root: ROOT, startedAt: lockStarted, files, ...extra}), {mode: 0o600});
}
function restoreAll() {
  for (const [file, {original}] of changed) {
    try { writeFileSync(file, original); } catch (error) { console.error(`Could not put back ${path.relative(ROOT, file)}: ${error.message}. Run node scripts/seeded-faults.mjs --restore.`); return false; }
  }
  changed = new Map();
  if (lockHeld) { try { writeLock(); } catch { /* the lock is removed on the way out */ } }
  return true;
}
function killChild() { if (child && child.exitCode === null && child.signalCode === null) { try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch {} } } }
function releaseLock() { if (lockHeld) { try { unlinkSync(LOCK); } catch {} lockHeld = false; } }
function onSignal(signal) {
  killChild();
  const restored = restoreAll();
  if (restored) releaseLock();
  console.error(`\nStopped by ${signal}; ${restored ? 'every file is back as it was' : 'some files still differ; see above'}.`);
  process.exit(130);
}

function restoreFromLock() {
  if (!existsSync(LOCK)) { console.log('Nothing to restore: no run left a lock behind.'); return 0; }
  const lock = JSON.parse(readFileSync(LOCK, 'utf8'));
  if (lock.pid && lock.pid !== process.pid && alive(lock.pid)) { console.error(`A run (pid ${lock.pid}) is still going; stop it first.`); return 2; }
  let conflicts = 0;
  for (const [file, record] of Object.entries(lock.files || {})) {
    const now = existsSync(file) ? sha(readFileSync(file)) : null;
    if (now === record.originalSha) console.log(`ok       ${path.relative(ROOT, file)} is already as it was`);
    else if (now === record.mutatedSha) { writeFileSync(file, Buffer.from(record.original, 'base64')); console.log(`restored ${path.relative(ROOT, file)}`); }
    else { conflicts++; console.error(`CONFLICT ${path.relative(ROOT, file)} changed since the run; left as it is. Its original is in ${LOCK}.`); }
  }
  if (conflicts) return 1;
  unlinkSync(LOCK);
  return 0;
}
function alive(pid) { try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; } }

// ---- running tests -----------------------------------------------------------------------------------------------
/** Runs node --test on some files; resolves {code, timedOut, failing, output}. */
function runTests(tests, {timeoutMs, faultId = null}) {
  return new Promise(resolve => {
    let output = '', timedOut = false;
    child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...tests], {cwd: ROOT, env: {...testEnvironment(process.env), ...(faultId ? {FABRIC_SEEDED_FAULT: faultId} : {})}, detached: true, stdio: ['ignore', 'pipe', 'pipe']});
    child.stdout.on('data', chunk => { output += chunk; if (output.length > 4_000_000) output = output.slice(-2_000_000); });
    child.stderr.on('data', chunk => { output += chunk; if (output.length > 4_000_000) output = output.slice(-2_000_000); });
    const timer = setTimeout(() => { timedOut = true; killChild(); }, timeoutMs);
    child.on('error', error => { clearTimeout(timer); child = null; resolve({code: -1, timedOut, failing: [], output: `${output}\n${error.message}`}); });
    child.on('close', code => {
      clearTimeout(timer); child = null;
      const failing = [...new Set([...output.matchAll(/^\s*not ok \d+ - (.*?)(?:\s+#\s+(?:SKIP|TODO).*)?$/gm)].map(match => match[1].trim()))];
      resolve({code: code ?? -1, timedOut, failing, output});
    });
  });
}
/** Whether a changed source file still parses, so a broken edit is never counted as a caught fault. */
function parses(file) {
  if (file.endsWith('.json')) { try { JSON.parse(readFileSync(file, 'utf8')); return true; } catch { return false; } }
  if (/\.(mjs|mts|js)$/.test(file)) return spawnSync(process.execPath, ['--check', file], {cwd: ROOT, encoding: 'utf8'}).status === 0;
  if (file.endsWith('.py')) {
    const probe = spawnSync('python3', ['-I', '-c', 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())', file], {encoding: 'utf8'});
    return probe.error ? true : probe.status === 0;
  }
  return true;
}

async function runEntry(entry, {timeoutMs, baselineFailed, verbose}) {
  const present = entry.tests.filter(test => existsSync(path.join(ROOT, test)));
  const usable = present.filter(test => !baselineFailed.has(test));
  const base = {id: entry.id, step: entry.step, name: entry.name, file: entry.file, tests: usable, skippedTests: entry.tests.filter(test => !usable.includes(test))};
  if (!present.length) return {...base, status: 'no_tests', detail: 'none of its test files exists yet'};
  if (!usable.length) return {...base, status: 'baseline_failed', detail: 'every test file fails without the fault'};
  const edits = editsOf(entry).map(edit => ({...edit, path: path.join(ROOT, edit.file)}));
  // Read every original first, and check every edit applies exactly once, before anything is written.
  const originals = new Map();
  for (const edit of edits) if (!originals.has(edit.path)) originals.set(edit.path, readFileSync(edit.path));
  const next = new Map([...originals].map(([file, bytes]) => [file, bytes.toString('utf8')]));
  for (const edit of edits) {
    const text = next.get(edit.path);
    if (occurrences(text, edit.from) !== 1) return {...base, status: 'stale', detail: `${edit.file}: from no longer occurs exactly once`};
    next.set(edit.path, text.replace(edit.from, () => edit.to));
  }
  const started = Date.now();
  try {
    for (const [file, original] of originals) changed.set(file, {original, mutated: sha(Buffer.from(next.get(file), 'utf8'))});
    writeLock();
    for (const [file, text] of next) writeFileSync(file, text);
    const broken = [...next.keys()].filter(file => !parses(file));
    if (broken.length) return {...base, status: 'broken', detail: `the fault does not parse in ${broken.map(file => path.relative(ROOT, file)).join(', ')}`};
    const result = await runTests(usable, {timeoutMs, faultId: entry.id});
    const status = result.timedOut ? 'timeout' : result.code !== 0 ? 'caught' : entry.equivalent ? 'equivalent' : 'missed';
    return {...base, status, seconds: Math.round((Date.now() - started) / 100) / 10, failing: result.failing.slice(0, 8), ...(entry.equivalent ? {equivalent: entry.equivalent} : {}), ...(verbose || status === 'missed' ? {output: result.output.slice(-4000)} : {})};
  } finally {
    // Always back to the original bytes, then checked.
    if (!restoreAll()) throw new Error('A changed file could not be put back.');
    for (const [file, original] of originals) if (sha(readFileSync(file)) !== sha(original)) throw new Error(`${path.relative(ROOT, file)} is not back to its original bytes.`);
  }
}

// ---- main --------------------------------------------------------------------------------------------------------
async function main() {
  let options;
  try { options = parseArgs(process.argv.slice(2)); } catch (error) { console.error(error.message); usage(); return 2; }
  if (options.restore) return restoreFromLock();
  const {FAULTS, NEW_TEST_FILES} = await import(pathToFileURL(REGISTRY).href);
  const problems = validate(FAULTS, NEW_TEST_FILES);
  const steps = [...new Set(FAULTS.map(entry => entry.step))];
  const selected = FAULTS.filter(entry => (!options.steps.length || options.steps.includes(entry.step)) && (!options.only.length || options.only.includes(entry.id)));
  const unknown = [...options.only.filter(id => !FAULTS.some(entry => entry.id === id)), ...options.steps.filter(step => !steps.includes(step))];
  if (unknown.length) { console.error(`Not in the registry: ${unknown.join(', ')}`); return 2; }
  const runnable = selected.filter(entry => entry.owed === undefined), owed = selected.filter(entry => entry.owed !== undefined);

  if (options.check) {
    console.log(`Registry: ${FAULTS.length} entries, ${FAULTS.filter(entry => entry.owed === undefined).length} runnable, ${FAULTS.filter(entry => entry.owed !== undefined).length} owed.`);
    for (const step of steps) {
      const of = FAULTS.filter(entry => entry.step === step);
      console.log(`  ${step.padEnd(7)} ${String(of.length).padStart(3)} entries  ${String(of.filter(entry => entry.owed === undefined).length).padStart(3)} runnable  ${String(of.filter(entry => entry.owed !== undefined).length).padStart(2)} owed  ${String(of.filter(entry => entry.equivalent).length).padStart(2)} equivalent`);
    }
    const pending = [...new Set(FAULTS.flatMap(entry => entry.tests || []).filter(test => !existsSync(path.join(ROOT, test))))];
    if (pending.length) console.log(`Test files named but not written yet: ${pending.join(', ')}`);
    if (problems.length) { console.log(`${problems.length} problem(s):`); for (const item of problems) console.log(`  ${item.id}: ${item.problem}`); return 1; }
    console.log('Every from text occurs exactly once in its file, and every test file exists or is being written.');
    return 0;
  }

  const blocking = problems.filter(item => runnable.some(entry => entry.id === item.id) && !/does not exist and is not being written/.test(item.problem));
  if (blocking.length) { console.error('The registry does not match the files; fix these first (node scripts/seeded-faults.mjs --check):'); for (const item of blocking) console.error(`  ${item.id}: ${item.problem}`); return 2; }

  // An interrupted run's files come back first (--restore), so its leftovers are never mistaken for someone's edits.
  if (existsSync(LOCK)) {
    const lock = (() => { try { return JSON.parse(readFileSync(LOCK, 'utf8')); } catch { return {}; } })();
    console.error(lock.pid && alive(lock.pid) ? `Refusing to start: another run (pid ${lock.pid}) is going.` : `Refusing to start: an earlier run was interrupted (${LOCK}). Run node scripts/seeded-faults.mjs --restore first.`);
    return 2;
  }
  // Refuse while git reports uncommitted changes to any file this run would touch.
  const touched = [...new Set(runnable.flatMap(entry => editsOf(entry).map(edit => edit.file)))].sort();
  const git = spawnSync('git', ['status', '--porcelain', '--untracked-files=all', '--', ...touched], {cwd: ROOT, encoding: 'utf8'});
  if (git.error || git.status !== 0) { console.error(`Refusing to start: git could not report the state of the files this run changes (${(git.error?.message || git.stderr || '').trim()}).`); return 2; }
  if (git.stdout.trim()) { console.error(`Refusing to start: these files have uncommitted changes, and a run rewrites them:\n${git.stdout.trimEnd()}`); return 2; }
  lockStarted = new Date().toISOString();
  writeFileSync(LOCK, JSON.stringify({pid: process.pid, root: ROOT, startedAt: lockStarted, files: {}}), {flag: 'wx', mode: 0o600});
  lockHeld = true;
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, () => onSignal(signal));
  process.on('exit', () => { killChild(); restoreAll(); releaseLock(); });
  process.on('uncaughtException', error => { killChild(); restoreAll(); releaseLock(); console.error(error); process.exit(1); });

  const results = [];
  try {
    // Baseline: each test file once, with no fault in place; a file that already fails cannot show a fault caught.
    const baselineFailed = new Set();
    const allTests = [...new Set(runnable.flatMap(entry => entry.tests).filter(test => existsSync(path.join(ROOT, test))))].sort();
    if (options.baseline) {
      console.log(`Baseline: ${allTests.length} test files without any fault.`);
      for (const test of allTests) {
        const result = await runTests([test], {timeoutMs: options.timeoutMs});
        if (result.code !== 0) { baselineFailed.add(test); console.log(`  fails already: ${test}${result.timedOut ? ' (timeout)' : ''}${result.failing.length ? ` (${result.failing.slice(0, 3).join('; ')})` : ''}`); }
      }
    }
    console.log(`Running ${runnable.length} seeded fault(s), one at a time.`);
    for (const entry of runnable) {
      const result = await runEntry(entry, {timeoutMs: options.timeoutMs, baselineFailed, verbose: options.verbose});
      results.push(result);
      const label = {caught: 'caught', timeout: 'caught (timeout)', missed: 'MISSED', equivalent: 'survived (equivalent)', broken: 'BROKEN', stale: 'STALE', no_tests: 'no tests yet', baseline_failed: 'not judged'}[result.status];
      console.log(`${label.padEnd(22)} ${entry.step.padEnd(7)} ${entry.id}  ${entry.name}${result.failing?.length ? `\n${' '.repeat(23)}failing: ${result.failing.slice(0, 3).join('; ')}` : ''}${result.detail ? `\n${' '.repeat(23)}${result.detail}` : ''}${result.status === 'equivalent' ? `\n${' '.repeat(23)}${entry.equivalent}` : ''}`);
      if (options.verbose && result.output) console.log(result.output);
    }
  } finally { restoreAll(); releaseLock(); }

  const count = status => results.filter(result => result.status === status).length;
  const totals = {runnable: runnable.length, caught: count('caught') + count('timeout'), missed: count('missed'), equivalent: count('equivalent'), timeouts: count('timeout'), broken: count('broken'), stale: count('stale'), noTests: count('no_tests'), notJudged: count('baseline_failed'), owed: owed.length};
  if (owed.length) { console.log(`\nOwed (${owed.length}): guarded code that does not exist yet.`); for (const entry of owed) console.log(`  ${entry.step.padEnd(7)} ${entry.id}  ${entry.name}\n${' '.repeat(10)}${entry.owed}`); }
  console.log(`\nTotals: ${totals.caught} of ${totals.runnable} caught${totals.timeouts ? ` (${totals.timeouts} by timeout)` : ''}, ${totals.missed} missed, ${totals.equivalent} survived as equivalent, ${totals.broken} broken, ${totals.stale} stale, ${totals.noTests} without tests yet, ${totals.notJudged} not judged (tests failing without the fault); ${totals.owed} owed.`);
  if (options.json) writeFileSync(options.json, `${JSON.stringify({ranAt: lockStarted, root: ROOT, totals, results, owed: owed.map(({id, step, name, owed: why}) => ({id, step, name, owed: why}))}, null, 2)}\n`);
  return totals.missed || totals.broken || totals.stale ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(code => { process.exitCode = code; }, error => { console.error(error?.stack || error); restoreAll(); releaseLock(); process.exitCode = 1; });
}
export {validate, editsOf};

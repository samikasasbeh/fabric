import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalHash} from '../lib/compiler.mjs';
import {PINS, PINS_PATH, codeHash, computePins, harnessHash, harnessSources, readPins, sourcesOf, transformIds} from '../lib/transform-pins.mjs';
import {pinDifferences, repin, writePins} from '../scripts/transform-pins.mjs';

// F10.8 part c (docs/F10.8-BUILD-MAP.md, decision 4): every transform version is pinned to the hash of its code, and the harness to the
// hash of its own. This is the only test that reads lib/transforms/pins.json; every edit under lib/transforms/ moves a pin, so no
// behaviour test names it. Temporary roots hold copies of lib/transforms, lib/compiler.mjs and lib/openapi-security.mjs, plus fake
// version modules, so the rules show before any shipped transform exists.
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SCRIPT = path.join(ROOT, 'scripts/transform-pins.mjs');
const sha = text => createHash('sha256').update(text).digest('hex');
const put = (root, file, text) => { mkdirSync(path.dirname(path.join(root, file)), {recursive: true}); writeFileSync(path.join(root, file), text); };
const cli = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], {cwd: ROOT, encoding: 'utf8', env: {PATH: process.env.PATH}});
const entryText = (facts = []) => `export const ENTRY = {runtimeFacts: ${JSON.stringify(facts)}, run() { return {}; }};\n`;
const FAKES = {
  'lib/transforms/fake/alpha.v1.mjs': `import {hasHidden} from '../_shared/hidden.v1.mjs';\n${entryText(['unicode'])}`,
  'lib/transforms/fake/beta.v1.mjs': `import {pointerReader} from '../_shared/pointer.v1.mjs';\n${entryText()}`,
  'lib/transforms/fake/gamma.v1.mjs': entryText(),
};

/**
 * A temporary root with a copy of the transform library, the two compiler files and the fake modules. With `shipped: false` the copy
 * leaves out the version folders parts d to j fill (lib/transforms/<family>/), so the fake modules are the only ids and a rule test
 * names every pin that moves without listing the shipped ones.
 */
function copyRoot(t, {fakes = true, shipped = true} = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-pins-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const base = path.join(ROOT, 'lib/transforms');
  const keep = source => shipped || !/^[a-z][a-z0-9]*$/.test(path.relative(base, source));
  cpSync(base, path.join(root, 'lib/transforms'), {recursive: true, filter: keep});
  for (const file of ['lib/compiler.mjs', 'lib/openapi-security.mjs']) cpSync(path.join(ROOT, file), path.join(root, file));
  if (fakes) for (const [file, text] of Object.entries(FAKES)) put(root, file, text);
  return root;
}
/** Which hashes moved between two computePins() results. */
function moved(before, after) {
  const ids = [...new Set([...Object.keys(before.transforms), ...Object.keys(after.transforms)])].sort();
  return {harness: before.harness !== after.harness, transforms: ids.filter(id => before.transforms[id] !== after.transforms[id])};
}
/** computePins() after appending a comment to one file, with the file put back afterwards. */
function pinsAfterEdit(root, file) {
  const original = readFileSync(path.join(root, file));
  writeFileSync(path.join(root, file), Buffer.concat([original, Buffer.from('// one more line\n')]));
  try { return computePins(root); } finally { writeFileSync(path.join(root, file), original); }
}

test('the shipped tree\'s computed pins and harness hash equal lib/transforms/pins.json, one pin per id', () => {
  const now = computePins(ROOT);
  assert.deepEqual(now, {harness: PINS.harness, transforms: {...PINS.transforms}});
  assert.deepEqual(Object.keys(PINS.transforms).sort(), transformIds(ROOT));
  assert.deepEqual(pinDifferences(ROOT), []);
  assert.equal(PINS.schemaVersion, 1);
  assert.ok(Array.isArray(PINS.repins) && typeof PINS.note === 'string' && Object.isFrozen(PINS) && Object.isFrozen(PINS.transforms));
  assert.equal(readFileSync(path.join(ROOT, PINS_PATH), 'utf8'), `${JSON.stringify(readPins(ROOT), null, 1)}\n`, 'one-space indentation and a final newline');
  assert.match(readFileSync(path.join(ROOT, '.gitattributes'), 'utf8'), /^lib\/transforms\/\*\* text eol=lf$/m);
});

test('a code hash covers exactly its module, the helpers it imports and error.v1.mjs; the harness hash covers run.mjs, its helpers and the compiler', t => {
  const root = copyRoot(t, {shipped: false});
  assert.deepEqual(transformIds(root), ['fake.alpha@1', 'fake.beta@1', 'fake.gamma@1']);
  assert.deepEqual(Object.keys(sourcesOf(root, 'fake.alpha@1')).sort(), ['lib/transforms/_shared/error.v1.mjs', 'lib/transforms/_shared/hidden.v1.mjs', 'lib/transforms/fake/alpha.v1.mjs']);
  assert.deepEqual(Object.keys(sourcesOf(root, 'fake.gamma@1')).sort(), ['lib/transforms/_shared/error.v1.mjs', 'lib/transforms/fake/gamma.v1.mjs'], 'error.v1.mjs even when not imported');
  assert.deepEqual(Object.keys(harnessSources(root)).sort(), ['lib/compiler.mjs', 'lib/openapi-security.mjs', 'lib/transforms/_shared/ascii.v1.mjs',
    'lib/transforms/_shared/error.v1.mjs', 'lib/transforms/_shared/pointer.v1.mjs', 'lib/transforms/run.mjs']);
  assert.equal(sourcesOf(root, 'fake.gamma@1')['lib/transforms/fake/gamma.v1.mjs'], sha(FAKES['lib/transforms/fake/gamma.v1.mjs']));
  assert.throws(() => sourcesOf(root, 'fake.missing@1'), /fake\/missing\.v1\.mjs/);
  put(root, 'lib/transforms/fake/out.v1.mjs', `import {canonicalHash} from '../../compiler.mjs';\n${entryText()}`);
  assert.throws(() => sourcesOf(root, 'fake.out@1'), /outside lib\/transforms/);
});

test('each edit moves exactly the pins that cover the edited file', t => {
  const root = copyRoot(t, {shipped: false}), before = computePins(root);
  assert.deepEqual(moved(before, pinsAfterEdit(root, 'lib/transforms/fake/alpha.v1.mjs')), {harness: false, transforms: ['fake.alpha@1']}, 'a version module moves its own pin only');
  assert.deepEqual(moved(before, pinsAfterEdit(root, 'lib/transforms/_shared/hidden.v1.mjs')), {harness: false, transforms: ['fake.alpha@1']}, 'a helper moves the pin of every module that imports it');
  assert.deepEqual(moved(before, pinsAfterEdit(root, 'lib/transforms/_shared/error.v1.mjs')), {harness: true, transforms: ['fake.alpha@1', 'fake.beta@1', 'fake.gamma@1']}, 'error.v1.mjs moves every pin and the harness');
  for (const file of ['lib/transforms/run.mjs', 'lib/compiler.mjs', 'lib/openapi-security.mjs']) assert.deepEqual(moved(before, pinsAfterEdit(root, file)), {harness: true, transforms: []}, file);
  assert.deepEqual(moved(before, pinsAfterEdit(root, 'lib/transforms/_shared/pointer.v1.mjs')), {harness: true, transforms: ['fake.beta@1']}, 'the pointer helper moves the harness and its importers');
  assert.deepEqual(moved(before, pinsAfterEdit(root, 'lib/transforms/index.mjs')), {harness: false, transforms: []}, 'the start checks change no output');
  put(root, 'lib/transforms/fake/delta.v1.mjs', entryText());
  const added = computePins(root);
  assert.deepEqual(moved(before, added), {harness: false, transforms: ['fake.delta@1']}, 'a new version moves no existing pin');
  put(root, 'lib/transforms/_shared/error.v2.mjs', 'export {TransformError} from \'./error.v1.mjs\';\nexport const FAMILY_CODES = Object.freeze({fake: Object.freeze([\'fake_refused\']), ids: Object.freeze([\'path_invalid\'])});\n');
  put(root, 'lib/transforms/fake/epsilon.v1.mjs', `import {TransformError} from '../_shared/error.v2.mjs';\n${entryText()}`);
  const later = computePins(root);
  assert.deepEqual(moved(added, later), {harness: false, transforms: ['fake.epsilon@1']}, 'a later error file moves no existing pin and not the harness');
  assert.deepEqual(Object.keys(sourcesOf(root, 'fake.epsilon@1')).sort(), ['lib/transforms/_shared/error.v1.mjs', 'lib/transforms/_shared/error.v2.mjs', 'lib/transforms/fake/epsilon.v1.mjs']);
  assert.ok(!Object.hasOwn(sourcesOf(root, 'fake.gamma@1'), 'lib/transforms/_shared/error.v2.mjs'));
});

test('CRLF, CR and LF copies of a file hash the same', t => {
  const root = copyRoot(t), file = 'lib/transforms/fake/gamma.v1.mjs', text = 'export const ENTRY = {\n  runtimeFacts: [],\n  run() { return {}; },\n};\n';
  const hashWith = ending => { put(root, file, text.replaceAll('\n', ending)); return codeHash(root, 'fake.gamma@1'); };
  const lf = hashWith('\n');
  assert.equal(hashWith('\r\n'), lf);
  assert.equal(hashWith('\r'), lf);
  put(root, file, text.replace('[]', '[ ]'));
  assert.notEqual(codeHash(root, 'fake.gamma@1'), lf);
});

test('known answers pin the hashing algorithm, its kinds and its version', t => {
  const root = mkdtempSync(path.join(tmpdir(), 'fabric-pins-kat-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  put(root, 'lib/transforms/_shared/error.v1.mjs', 'export {};\n');
  put(root, 'lib/transforms/kat/sample.v1.mjs', 'export const ENTRY = {};\n');
  put(root, 'lib/transforms/run.mjs', 'export {};\n');
  put(root, 'lib/compiler.mjs', 'export const x = 1;\n');
  const sources = {'lib/transforms/_shared/error.v1.mjs': sha('export {};\n'), 'lib/transforms/kat/sample.v1.mjs': sha('export const ENTRY = {};\n')};
  assert.deepEqual(sourcesOf(root, 'kat.sample@1'), sources);
  assert.equal(codeHash(root, 'kat.sample@1'), canonicalHash({kind: 'fabric-transform-code', version: 1, transform: 'kat.sample@1', sources}));
  assert.equal(codeHash(root, 'kat.sample@1'), 'deebcb59bb31f7def0516a6fd8d50543ae1ad7209d88bc33d4b134c447d98473');
  const harness = {'lib/transforms/run.mjs': sha('export {};\n'), 'lib/compiler.mjs': sha('export const x = 1;\n')};
  assert.deepEqual(harnessSources(root), harness);
  assert.equal(harnessHash(root), canonicalHash({kind: 'fabric-transform-harness', version: 1, sources: harness}));
  assert.equal(harnessHash(root), 'ad9744910ee8629ea9c8d61de03a59449b99332904702eb6e4f7751114898710');
});

test('--check takes ids from the root it is given, and names unpinned, changed and removed ids and a moved harness', t => {
  const root = copyRoot(t);
  const check = cli('--check', '--root', root);
  assert.equal(check.status, 1);
  for (const id of ['fake.alpha@1', 'fake.beta@1', 'fake.gamma@1']) assert.match(check.stderr, new RegExp(`${id.replace('.', '\\.')} is not pinned`));
  assert.equal(cli('--write', '--root', root).status, 0);
  assert.equal(cli('--check', '--root', root).status, 0);
  put(root, 'lib/transforms/fake/gamma.v1.mjs', entryText().replace('{}', '{value: 1}'));
  unlinkSync(path.join(root, 'lib/transforms/fake/beta.v1.mjs'));
  put(root, 'lib/compiler.mjs', `${readFileSync(path.join(root, 'lib/compiler.mjs'), 'utf8')}// edited\n`);
  const after = cli('--check', '--root', root);
  assert.equal(after.status, 1);
  assert.match(after.stderr, /fake\.gamma@1 differs from its pin/);
  assert.match(after.stderr, /fake\.beta@1 is pinned but its file is gone/);
  assert.match(after.stderr, /harness hash differs from its pin/);
});

test('--check and --write refuse a tree the source scan refuses', t => {
  const root = copyRoot(t);
  put(root, 'lib/transforms/fake/clock.v1.mjs', 'export const ENTRY = {runtimeFacts: [], run() { return {at: Date.now()}; }};\n');
  const check = cli('--check', '--root', root);
  assert.equal(check.status, 1);
  assert.match(check.stderr, /fake\/clock\.v1\.mjs.*date/);
  assert.throws(() => writePins(root), /source scan/);
  // An import the fixed reader cannot read would leave its helper out of the pin, so nothing is pinned over it.
  const misread = copyRoot(t);
  put(misread, 'lib/transforms/fake/split.v1.mjs', `import {hasHidden} from\n  '../_shared/hidden.v1.mjs';\n${entryText(['unicode'])}`);
  assert.ok(!Object.hasOwn(sourcesOf(misread, 'fake.split@1'), 'lib/transforms/_shared/hidden.v1.mjs'), 'the reader misses it');
  const split = cli('--check', '--root', misread);
  assert.equal(split.status, 1);
  assert.match(split.stderr, /fake\/split\.v1\.mjs.*import-form/);
  assert.throws(() => writePins(misread), /source scan/);
});

test('--write adds new ids only, and --repin replaces one pin with a recorded reason and date', t => {
  const root = copyRoot(t);
  const first = writePins(root);
  assert.deepEqual(first.added, ['fake.alpha@1', 'fake.beta@1', 'fake.gamma@1']);
  const pinned = readPins(root);
  put(root, 'lib/transforms/fake/delta.v1.mjs', entryText());
  assert.deepEqual(writePins(root).added, ['fake.delta@1']);
  assert.equal(readPins(root).transforms['fake.alpha@1'], pinned.transforms['fake.alpha@1']);
  put(root, 'lib/transforms/fake/gamma.v1.mjs', entryText().replace('{}', '{value: 2}'));
  assert.throws(() => writePins(root), /fake\.gamma@1/);
  const refused = cli('--write', '--root', root);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /fake\.gamma@1/);
  assert.equal(readPins(root).transforms['fake.gamma@1'], pinned.transforms['fake.gamma@1'], '--write never changes a pin');
  assert.equal(cli('--repin', 'fake.gamma@1', '--date', '2026-10-20', '--root', root).status, 2, 'no reason');
  assert.equal(cli('--repin', 'fake.gamma@1', '--reason', 'a reviewed fix', '--root', root).status, 2, 'no date');
  for (const date of ['2026-02-30', '20261020', 'today']) assert.throws(() => repin(root, {target: 'fake.gamma@1', reason: 'a reviewed fix', date}), /date/, date);
  for (const reason of ['', '   ', 'two\nlines', 'x'.repeat(201)]) assert.throws(() => repin(root, {target: 'fake.gamma@1', reason, date: '2026-10-20'}), /reason/, JSON.stringify(reason));
  assert.throws(() => repin(root, {target: 'fake.alpha@1', reason: 'nothing changed', date: '2026-10-20'}), /already/);
  assert.throws(() => repin(root, {target: 'fake.unknown@1', reason: 'x', date: '2026-10-20'}), /fake\.unknown@1/);
  const done = cli('--repin', 'fake.gamma@1', '--reason', 'a reviewed fix', '--date', '2026-10-20', '--root', root);
  assert.equal(done.status, 0, done.stderr);
  const after = readPins(root);
  // The copy carries the shipped re-pins; a re-pin appends after them and leaves them as they were.
  assert.deepEqual(after.repins.slice(0, pinned.repins.length), pinned.repins);
  assert.deepEqual(after.repins.slice(pinned.repins.length), [{transform: 'fake.gamma@1', from: pinned.transforms['fake.gamma@1'], to: codeHash(root, 'fake.gamma@1'), date: '2026-10-20', reason: 'a reviewed fix'}]);
  assert.equal(after.transforms['fake.gamma@1'], codeHash(root, 'fake.gamma@1'));
  put(root, 'lib/compiler.mjs', `${readFileSync(path.join(root, 'lib/compiler.mjs'), 'utf8')}// a new export\n`);
  repin(root, {target: 'harness', reason: 'F10.9 part b: compiler exports, no body change', date: '2026-10-21'});
  assert.equal(readPins(root).harness, harnessHash(root));
  assert.deepEqual(readPins(root).repins.slice(pinned.repins.length).map(entry => entry.transform), ['fake.gamma@1', 'harness']);
  assert.deepEqual(pinDifferences(root), []);
});

test('the pins file is shape-checked when read', t => {
  const root = copyRoot(t, {fakes: false}), good = readPins(root);
  const bad = {
    'an unknown field': {...good, extra: 1}, 'another schema version': {...good, schemaVersion: 2}, 'a short harness hash': {...good, harness: 'abc'},
    'an id that is not name@version': {...good, transforms: {'time.zone': 'a'.repeat(64)}}, 'a repin without a reason': {...good, repins: [{transform: 'harness', from: 'a'.repeat(64), to: 'b'.repeat(64), date: '2026-10-20'}]},
    'a repin with a false date': {...good, repins: [{transform: 'harness', from: 'a'.repeat(64), to: 'b'.repeat(64), date: '2026-02-30', reason: 'x'}]},
  };
  for (const [what, value] of Object.entries(bad)) {
    put(root, PINS_PATH, JSON.stringify(value));
    assert.throws(() => readPins(root), /pins/, what);
  }
});

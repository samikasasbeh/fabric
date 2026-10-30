import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {checkSigned} from '../scripts/defaults-golden.mjs';

// F10.11 (docs/F10.11-BUILD-MAP.md section 3): what step 11 must not move. Part b wrote these first as todos; part p made the import wall a
// test and part q the other two. The values below are recorded at 89b24af, the commit before step 11 began: the files that pin every typed
// binding, proxy-row binding, policy hash, local golden and connection generation, the signed defaults golden and the template ratchet,
// each byte for byte, text read with LF line ends. Each of them also runs in the same suite, so unchanged and passing is both shown.
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const RECORDED = Object.freeze({
  'test/f10-3-binding-churn.test.mjs': '065852b410cf9d328b5aa9b64099d4704c3f1291773fa75134cbe03314e2bd7a',
  'test/f10-6-churn.test.mjs': '07ba6a2048fb2cfe5244e11126ccb4bef02633ebcc96e6775853b6e01f4ee367',
  'test/f10-7-churn.test.mjs': '33279665e24d056a1edea921dcc0633a4cf7f2f2cbaa350c5e963a382a0059df',
  // F10.20 listed churn: step 20 certified Notion's 16 actions, which place with no map and would join this file's synthetic Notion row, so its
  // one owner-page test on that row runs with no shipped actions. That test's server line is all that moved.
  'test/local-mode-goldens.test.mjs': '27e00717b0a8204bed6c115a3557ed7a67c1debb418637806b50862dc4426afd',
  'test/provider-authority.test.mjs': '2b899188f47af3d16cd8eb429257c5630f32aa249a8a6cb8e53c6fcf4e564039',
});
const UNCHANGED = Object.freeze({
  'test/defaults-golden.test.mjs': 'ac438c6d5ca495533a094eacf696f90a47e5ccb165f90e4a3418851621d810c1',
  'test/f10-3-binding-churn.test.mjs': '065852b410cf9d328b5aa9b64099d4704c3f1291773fa75134cbe03314e2bd7a',
  'test/f10-7-churn.test.mjs': '33279665e24d056a1edea921dcc0633a4cf7f2f2cbaa350c5e963a382a0059df',
  'test/tenant-f10-invariants.test.mjs': 'b6c069a3fa3b1922752563be2ee61d08d36d5b3155fd36b25c01c4d59fa8df50',
  'test/auth-conformance.test.mjs': '5370aef2308ed450f6cd8de90c7834344e33079c51f74f3147cc2f9348ff147c',
});
const digestOf = file => createHash('sha256').update(readFileSync(path.join(ROOT, file), 'utf8').replace(/\r\n/g, '\n')).digest('hex');
// F10.13 listed churn (docs/F10.13-BUILD-MAP.md part 1): step 13 changes Calendar's defaults on purpose. Its content binding moves Calendar's
// data hash, so the golden's google-calendar entry and the ratchet's google-calendar defaults check move now, and again when Sami signs;
// the actions check moves with part 2. test/f10-13-churn.test.mjs pins what changed. The rest of each file is held to its digest at
// 89b24af, read with Calendar's entry (or those two checks) taken out.
// F10.15 listed churn (docs/F10.15-BUILD-MAP.md part 1): step 15 changes Gmail's defaults the same way (four unsupported markers and one
// content binding), and its closing commit turns the ratchet's Gmail actions check on; test/f10-15-churn.test.mjs pins what changed. Each
// file is now held to its digest at 89b24af read with Calendar's and Gmail's entries (or their defaults and actions checks) taken out.
// F10.17 listed churn (docs/F10.17-BUILD-MAP.md part 1): step 17 does the same for GitHub. Its two content bindings move GitHub's data hash,
// so the golden's github entry and the ratchet's github defaults check move now, and again when Sami signs; the actions check moves with
// part 2. test/f10-17-churn.test.mjs pins what changed. Each digest is now read with both apps' entries (or checks) taken out; the rest of
// each file is unchanged since 89b24af.
const reducedDigest = (file, reduce) => createHash('sha256').update(JSON.stringify(reduce(JSON.parse(readFileSync(path.join(ROOT, file), 'utf8'))))).digest('hex');
// F10.19 listed churn (docs/F10.19-BUILD-MAP.md part 1): Notion's Notion-Version moves to 2026-03-11, so the golden's Notion files hash and the
// sign-in file's hash move, for information only (its data hash and sign-off stay; test/f10-19-churn.test.mjs pins that). Both are put back.
const NOTION_FILES_BEFORE = Object.freeze({file: 'b88bf95f5a27ca5e063268e1b0ac3f33fe2928ac69d83a265496d30eb979b96d', hash: 'b13b2725703c946732e924a7b9117434a8947bb8e59330c00c6dfa00ece8c686'});
const notionFilesBefore = golden => { golden.apps.notion.files['catalog/auth/notion.json'] = NOTION_FILES_BEFORE.file; golden.apps.notion.filesHash = NOTION_FILES_BEFORE.hash; return golden; };
const MOVED = Object.freeze(['google-calendar', 'gmail', 'github']);
const REDUCED = Object.freeze({
  // F10.13, F10.15 and F10.17 listed churn: Calendar's, Gmail's and GitHub's entries move (their row data, and again when Sami signs), so
  // they are taken out. F10.21 listed churn: Slack's entry moves its files hash and its auth file's hash only (apiSuccessRequire), put back
  // here to the 89b24af ones; F10.19's Notion files hash is put back the same way.
  'test/fixtures/access/defaults.golden.json': [golden => { for (const appId of MOVED) delete golden.apps[appId];
    Object.assign(golden.apps.slack, {filesHash: '7b789bbb0b07a82ccb6d6bfed615d3c1b1c11422fdd4b6448f5a420593ba6ce2',
      files: {...golden.apps.slack.files, 'catalog/auth/slack.json': '791934a1f77347c6c14db55acc2b079a3f2048f8c0eecef70d1a2f00fccf5fe4'}}); return notionFilesBefore(golden); },
  'fd05d45e8c3d5c3e6c2c0e9d7c4464e728e745aba8d0449c406f88a5a3722070'],
  // F10.13, F10.15, F10.17, F10.19 part 2 and F10.21 listed churn: Calendar's, Gmail's and GitHub's checks are taken out; Notion's and Slack's
  // actions checks pass once their action files are reviewed, and each is put back to false, its recorded value. F10.14 listed churn: the
  // live passes turn each app's live-evidence and sign-in-evidence checks on as their records land (Calendar's actions; GitHub's and
  // Notion's sign-ins), so both are put back to false, their recorded value, for every app.
  'test/fixtures/access/template-ratchet.json': [ratchet => {
    for (const appId of MOVED) { delete ratchet.apps[appId].defaults; delete ratchet.apps[appId].actions; }
    ratchet.apps.notion.actions = false; ratchet.apps.slack.actions = false;
    for (const checks of Object.values(ratchet.apps)) Object.assign(checks, {'live-evidence': false, 'sign-in-evidence': false});
    return ratchet;
  }, '28bda03afbb142875ba054833c0bf3e2730572e74439ce11e3d4888a9ea3bd37'],
});

test('no typed binding, proxy-row binding, policy hash, local golden, connection generation or defaults dataHash moves', () => {
  assert.deepEqual(checkSigned().filter(problem => !MOVED.some(appId => problem.startsWith(`${appId}: `))), [],
    'every signed defaults table but Calendar\'s (F10.13), Gmail\'s (F10.15) and GitHub\'s (F10.17) still binds the data it gives now: no other dataHash moved');
  for (const [file, digest] of Object.entries(RECORDED)) assert.equal(digestOf(file), digest, `${file} records what it recorded before step 11`);
  const [reduce, digest] = REDUCED['test/fixtures/access/defaults.golden.json'];
  assert.equal(reducedDigest('test/fixtures/access/defaults.golden.json', reduce), digest, 'the golden records what it recorded before step 11, but Calendar\'s (F10.13), Gmail\'s (F10.15) and GitHub\'s (F10.17) entries and Notion\'s (F10.19) and Slack\'s (F10.21) files hashes');
});

test('test/defaults-golden.test.mjs, test/f10-3-binding-churn.test.mjs, test/f10-7-churn.test.mjs, test/tenant-f10-invariants.test.mjs, test/auth-conformance.test.mjs and the template ratchet pass unchanged', () => {
  for (const [file, digest] of Object.entries(UNCHANGED)) assert.equal(digestOf(file), digest, `${file} is as it was before step 11`);
  const [reduce, digest] = REDUCED['test/fixtures/access/template-ratchet.json'];
  assert.equal(reducedDigest('test/fixtures/access/template-ratchet.json', reduce), digest, 'the ratchet is as it was before step 11, but Calendar\'s, Gmail\'s and GitHub\'s defaults and actions checks (F10.13, F10.15, F10.17)');
});

// Part p (critique resolution 5): server code reaches the action modules only through the object lib/action-gate.mjs loads.
const CONTAINED = ['lib/action-catalog.mjs', 'lib/actions.mjs', 'lib/actions-runtime.mjs', 'lib/action-expressions.mjs', 'lib/action-placement.mjs', 'lib/choice-sources.mjs', 'lib/transform-pins.mjs', 'lib/triggers.mjs'];
const contained = file => CONTAINED.includes(file) || file.startsWith('lib/transforms/');
/** A file's relative imports: the static ones (from, and a bare import), and the import() calls with a literal path. */
function importsOf(file) {
  const text = readFileSync(path.join(ROOT, file), 'utf8'), resolve = target => path.relative(ROOT, path.resolve(path.dirname(path.join(ROOT, file)), target));
  return {static: [...text.matchAll(/(?:\bfrom\s*|\bimport\s+)(['"])(\.{1,2}\/[^'"]+)\1/g)].map(match => resolve(match[2])),
    dynamic: [...text.matchAll(/\bimport\s*\(\s*(['"])(\.{1,2}\/[^'"]+)\1\s*\)/g)].map(match => resolve(match[2]))};
}

test('server.mjs and developer-server.mjs reach no action module and no lib/triggers.mjs statically; a source scan of every walked file finds exactly one dynamic import of an action module, in lib/action-gate.mjs', () => {
  const seen = new Set(), queue = ['server.mjs', 'developer-server.mjs'], dynamic = [];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const found = importsOf(file);
    for (const next of found.static) if (/\.m?[jt]s$/.test(next)) queue.push(next);
    for (const target of found.dynamic) if (contained(target)) dynamic.push([file, target]);
  }
  assert.ok(seen.size > 40 && seen.has('lib/action-gate.mjs') && seen.has('lib/tenant/api.mjs'), 'the walk follows both servers\' import graphs to the gate');
  assert.deepEqual([...seen].filter(contained), [], 'no action module is a static import of either server');
  assert.deepEqual(dynamic, [['lib/action-gate.mjs', 'lib/action-catalog.mjs']], 'one guarded import, in the gate');
});

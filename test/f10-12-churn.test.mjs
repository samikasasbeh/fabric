import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {checkSigned} from '../scripts/defaults-golden.mjs';

// F10.12 (docs/F10.12-BUILD-MAP.md section 3, test/f10-12-churn.test.mjs): what step 12 must not move, and the walls around the harness.
// The digests below are recorded at 7af1bde, the commit before step 12 began, text read with LF line ends: every catalog file, the signed
// defaults golden and the two earlier churn walks. A later step that changes one of them on purpose lists this test as its churn.
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const digestOf = (file, undo = text => text) => createHash('sha256').update(undo(readFileSync(path.join(ROOT, file), 'utf8').replace(/\r\n/g, '\n'))).digest('hex');
const CATALOG = Object.freeze({
  'catalog/actions/README.md': '8547abc63ca794ff4e3d6279a5dbbd75cae34d87fb6dfa61cecf6a528659441a',
  'catalog/apps.json': '4f853e6ce0723f9a30e58379a4f93a25f2b3c3ad2018a28d524a0566ccd30b41',
  'catalog/auth/github.json': 'de0c61db7cb3a5ff8f6cad8a9b9d2ab31c34f67a1072d5325fd200a4267535f9',
  'catalog/auth/google.json': '00507b14f7b28dc62fc3c1fb9a2b8e0b67b94519b8bc31a62cdb04df70e1e753',
  'catalog/auth/notion.json': '23db59a52b90f4f8b60fcd57ed15cad47952af4c666adf68a6c0444dca867041',
  'catalog/auth/slack.json': 'd10ce54cb494add088f022bc5c19b8d83a31c0c22709bd32a5958ba15a53200a',
  'catalog/categories.json': '6f3ac7d6f2024babd0c0c55e80ba4f393d84d2d71865ef3cde2c7b43a183589b',
  'catalog/choices/README.md': '0bdbeeab2d6a89b91296d7f84110d96fe49ee30361b5afe7a69ee8362d6bf84a',
  'catalog/icons.json': 'f49b23582cdac7c82a9e025efc0e0e32def93a09fa6edbc3ec2e5714b0e82c89',
  'catalog/options/gmail.json': '8b77e9a11bd7f1e12cf8eeffcec3dcde08ababb37b6fee1d90df6f9d4991aac7',
  'catalog/options/google-calendar.json': '9aa77e9c47cb148426485a0ed62547e37a2f88a3660c2b00149d1efc6b29822b',
  'catalog/permissions/github.json': '063a8cc5a377304b468cb6cd3e24e416872543c4917edb95e4760e69579fec55',
  'catalog/permissions/gmail.json': '1894f7100ad5a3188fb1d5b3a9f261053fe8573a507ef32b5185db0c2d3112a1',
  'catalog/permissions/google-calendar.json': '6ac5c96b6b909e8e729fc856f61114ef0f064f0a660635850dd3c9233cfb180d',
  'catalog/permissions/notion.json': 'dffd6c11c3cd93cbcda11de54d917b15b3a6844f9611f93e17f33d4662a64faf',
  'catalog/permissions/slack.json': '992d4f63aca640e41ec72d799a08bd334f49295824b1feca66c474ba1aeaed6a',
  'catalog/providers.json': '6b9394caae379c374fd8d27f71837f5f96045ba5bdaee842f37af77c7b6c4c73',
  'catalog/proxy/github.json': '2461d854e3ca0be7c9ec7fa9a521f9430267ff66db1649a8050843688e0c3629',
  'catalog/proxy/github.routes.json': '02c708a8a6f7535f111ef1c7664cdb8563f12c04f2c3fd74e1517cf9e1a17d31',
  'catalog/proxy/gmail.json': 'c0b838a76b9c59274c6e8ee388f24c1f48ecbb26d3cdb93c112b86351ead9702',
  'catalog/proxy/google-calendar.json': '43013ef4a904f5d7bd5793abfadba534a22955b241caecdfb3758bfbc278e97a',
  'catalog/proxy/notion.json': '8c3816f2fe5c328c18e3f32d53614ec20507d4abadc3e2fc63953cd82e178148',
  'catalog/proxy/slack.json': 'ea7fae2c135817315ed29fed149bc3e8e52aab334e5e9d47bf9a03f9ddea3400',
});
// Each digest is the file after its latest listed churn (F10.13, then F10.17 part 1, which adds GitHub's bindings to both walks).
const UNCHANGED = Object.freeze({
  'test/f10-9-churn.test.mjs': '101b5b1b13184d6166596f1ec97d261cdc95bd14ac2f771737cebed0f76aa0c0',
  // F10.15, F10.17, F10.19 and F10.21 listed churn: that test's golden reduction takes out Gmail's and GitHub's entries and puts back Notion's
  // files hash and Slack's two file hashes, and its ratchet reduction takes out their checks and puts back Notion's and Slack's actions checks.
  // F10.14 listed churn: its ratchet reduction also puts every app's live-evidence and sign-in-evidence checks back to false.
  // F10.20 listed churn: step 20's digest of test/local-mode-goldens.test.mjs.
  'test/f10-11-churn.test.mjs': '8b7e6cb48628b64c6844b1001810522790b64e8f250fa5a1ab58f53ec146a432',
});
// F10.13 listed churn (docs/F10.13-BUILD-MAP.md part 1): step 13 changes some of these on purpose. Calendar's rows gain one bindContent
// block, and the file with that block taken out is byte for byte the recorded one. The golden's Calendar entry moves with it (and again
// when Sami signs), so the rest of the golden is held to its recorded digest, read with Calendar's entry taken out. The two earlier churn
// walks are held to their digests after their own listed churn. test/f10-13-churn.test.mjs pins what changed.
const CALENDAR_BINDING = ',\n   "bindContent": {\n    "calendar.events.patch": {"kind": "etag", "at": "header:If-Match"},\n    "calendar.events.update": {"kind": "etag", "at": "header:If-Match"}\n   }';
// Part 2 adds Calendar's action file and live plan, and catalog/actions/README.md says Calendar ships the first file: with that one paragraph
// put back, the README is byte for byte the recorded one.
const ACTIONS_README_BEFORE = 'No app ships an action file yet. The app slices of F10.13 to F10.21 add them with their live passes.';
const ACTIONS_README_NOW = 'Google Calendar ships the first file, `google-calendar.json` (F10.13): its 13 actions stay candidates until step 14\'s live evidence certifies them. Gmail, GitHub, Notion and Slack add theirs in F10.15 to F10.21, each with its live pass. Calendar\'s steps place only through Google\'s method map, so where no Calendar map is stored yet the file is refused rather than run: Find free time is a reviewed-read POST, which counts as a write until it places (F10.10). Fabric loads the file again when the map is stored.';
// F10.19 part 2 adds Notion's action file and live plan, and one paragraph after Calendar's in catalog/actions/README.md; with it taken out first,
// the step 13 undo reads the README as before.
const ACTIONS_README_NOTION = '\n\nNotion ships `notion.json` (F10.19): its 16 actions place by method and path, with no map, and stay candidates until step 20\'s live evidence certifies them.';
const STEP_13 = Object.freeze({'catalog/permissions/google-calendar.json': text => { assert.equal(text.split(CALENDAR_BINDING).length, 2, 'the binding block, once'); return text.replace(CALENDAR_BINDING, ''); },
  'catalog/actions/README.md': text => {
    assert.equal(text.split(ACTIONS_README_NOTION).length, 2, 'the step 19 paragraph, once');
    const before = text.replace(ACTIONS_README_NOTION, '');
    assert.equal(before.split(ACTIONS_README_NOW).length, 2, 'the step 13 paragraph, once');
    return before.replace(ACTIONS_README_NOW, ACTIONS_README_BEFORE);
  }});
const STEP_13_FILES = Object.freeze(['catalog/actions/google-calendar.json', 'catalog/live-tests/google-calendar.json']);
const STEP_19_FILES = Object.freeze(['catalog/actions/notion.json', 'catalog/live-tests/notion.json']);
// F10.19 listed churn (docs/F10.19-BUILD-MAP.md part 1): Notion's sign-in file changes one value, its Notion-Version (owner decision 7); with the
// version line put back it is byte for byte the recorded file. The golden's Notion files hash and sign-in file hash move with it, for
// information only, and are put back the same way. test/f10-19-churn.test.mjs pins what changed.
const NOTION_VERSION_NOW = '"Notion-Version": "2026-03-11"', NOTION_VERSION_BEFORE = '"Notion-Version": "2025-09-03"';
const STEP_19 = Object.freeze({'catalog/auth/notion.json': text => { assert.equal(text.split(NOTION_VERSION_NOW).length, 2, 'the new version line, once'); return text.replace(NOTION_VERSION_NOW, NOTION_VERSION_BEFORE); }});
const NOTION_FILES_BEFORE = Object.freeze({file: 'b88bf95f5a27ca5e063268e1b0ac3f33fe2928ac69d83a265496d30eb979b96d', hash: 'b13b2725703c946732e924a7b9117434a8947bb8e59330c00c6dfa00ece8c686'});
// F10.21 listed churn (docs/F10.21-BUILD-MAP.md part 1 g): Slack's definition gains apiSuccessRequire, the one block below, so with it taken
// out the file is byte for byte the recorded one. The golden's Slack entry moves only its files hash and that file's hash (no table, so no
// data hash and no sign-off); with the 3129ac4 values put back the rest of the golden is the recorded one. test/f10-21-churn.test.mjs pins it.
const SLACK_RULE = ',\n  "apiSuccessRequire": [\n    {\n      "pointer": "/ok",\n      "equals": true\n    }\n  ]\n}';
// Part 2 adds Slack's action file and live plan, and one paragraph of catalog/actions/README.md after Calendar's says Slack ships its file.
const ACTIONS_README_SLACK = '\n\nSlack ships `slack.json` (F10.21): its 13 actions stay candidates until step 22\'s live evidence certifies them. Slack\'s steps are request templates, so its file needs no map and loads wherever Fabric runs.';
const STEP_21 = Object.freeze({'catalog/auth/slack.json': text => { assert.equal(text.split(SLACK_RULE).length, 2, 'the apiSuccessRequire block, once'); return text.replace(SLACK_RULE, '\n}'); },
  'catalog/actions/README.md': text => { assert.equal(text.split(ACTIONS_README_SLACK).length, 2, 'the step 21 paragraph, once'); return text.replace(ACTIONS_README_SLACK, ''); }});
const STEP_21_FILES = Object.freeze(['catalog/actions/slack.json', 'catalog/live-tests/slack.json']);
// F10.15 listed churn (docs/F10.15-BUILD-MAP.md part 1): step 15 adds row data to three Gmail rows (four unsupported markers and one content
// binding), and the file with those three blocks taken out is byte for byte the recorded one. The golden's Gmail entry moves with it (and
// again when Sami signs), so the golden is held to its recorded digest read with Calendar's and Gmail's entries taken out, and the two
// earlier churn walks to their digests after F10.15's listed churn. test/f10-15-churn.test.mjs pins what changed.
const GMAIL_DATA = Object.freeze([',\n   "unsupported": {\n    "gmail.users.drafts.create": "Fabric\'s plain form of this operation cannot carry a whole message, so it would save an empty draft or blank one. Fabric writes drafts through its reviewed Gmail actions.",\n    "gmail.users.drafts.update": "Fabric\'s plain form of this operation cannot carry a whole message, so it would save an empty draft or blank one. Fabric writes drafts through its reviewed Gmail actions."\n   }',
  ',\n   "unsupported": {\n    "gmail.users.drafts.send": "It sends a draft by its id alone, so a draft changed after approval would go out. Fabric sends drafts through its reviewed Send draft action, which binds the message."\n   },\n   "bindContent": {\n    "gmail.users.drafts.send": {"kind": "resend", "at": "body:/message/raw"}\n   }',
  ',\n   "unsupported": {\n    "gmail.users.messages.import": "Fabric\'s plain form of this operation cannot carry a message, so it would import nothing. No reviewed action imports email."\n   }']);
// F10.15 part 2: Gmail's action file and live plan, and one paragraph after Calendar's in catalog/actions/README.md, a pure addition: with it
// taken out, the README is step 13's.
const GMAIL_ACTIONS_README = '\n\nGmail\'s file, `gmail.json`, ships with step 15 (F10.15): its 13 actions stay candidates until step 16\'s live evidence certifies them. Where no Gmail map is stored yet they load unplaced, valid in shape and never run; none is refused, since none is a reviewed-read POST. Fabric places them when the map is stored.';
const STEP_15_FILES = Object.freeze(['catalog/actions/gmail.json', 'catalog/live-tests/gmail.json']);
const STEP_15 = Object.freeze({'catalog/permissions/gmail.json': text => GMAIL_DATA.reduce((out, block) => { assert.equal(out.split(block).length, 2, 'each row data block, once'); return out.replace(block, ''); }, text),
  'catalog/actions/README.md': text => { assert.equal(text.split(GMAIL_ACTIONS_README).length, 2, 'the step 15 paragraph, once'); return text.replace(GMAIL_ACTIONS_README, ''); }});
// F10.17 listed churn (docs/F10.17-BUILD-MAP.md part 1): GitHub's rows gain two bindContent blocks and its sign-in the grant header. With
// each taken out, both files are byte for byte the recorded ones. The golden's GitHub entry moves with them (and again when Sami signs), so
// the golden is held to its recorded digest read with Calendar's, Gmail's and GitHub's entries taken out. test/f10-17-churn.test.mjs pins what changed.
const GITHUB_BINDINGS = [',\n   "bindContent": {\n    "PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge": {"kind": "sha", "at": "body:/sha"}\n   }',
  ',\n   "bindContent": {\n    "PUT /repos/{owner}/{repo}/contents/{+path}": {"kind": "sha", "at": "body:/sha"}\n   }'];
const GRANT_HEADER = '  "grantHeader": "x-oauth-scopes",\n';
// Part 2 adds GitHub's action file and live plan, and catalog/actions/README.md gains one paragraph after Calendar's.
const ACTIONS_README_GITHUB = '\nGitHub\'s file, `github.json` (F10.17), holds 15 actions that stay candidates until step 18\'s live evidence certifies them. GitHub\'s rows list their request templates, so its steps place with no map and the file loads wherever Fabric runs.\n';
const once = (text, part, what) => { assert.equal(text.split(part).length, 2, what); return text.replace(part, ''); };
const STEP_17 = Object.freeze({'catalog/permissions/github.json': text => GITHUB_BINDINGS.reduce((rest, block) => once(rest, block, 'each GitHub binding block, once'), text),
  'catalog/auth/github.json': text => once(text, GRANT_HEADER, 'the grant header line, once'),
  'catalog/actions/README.md': text => once(text, ACTIONS_README_GITHUB, 'the step 17 paragraph, once')});
const STEP_17_FILES = Object.freeze(['catalog/actions/github.json', 'catalog/live-tests/github.json']);
/** A file's listed churn taken out, step 21's first, then step 19's, 17's, 15's and 13's. */
const undone = file => text => [STEP_21[file], STEP_19[file], STEP_17[file], STEP_15[file], STEP_13[file]].filter(Boolean).reduce((value, undo) => undo(value), text);
const SLACK_FILES_BEFORE = Object.freeze({filesHash: '7b789bbb0b07a82ccb6d6bfed615d3c1b1c11422fdd4b6448f5a420593ba6ce2', auth: '791934a1f77347c6c14db55acc2b079a3f2048f8c0eecef70d1a2f00fccf5fe4'});
const GOLDEN_WITHOUT_MOVED = 'fd05d45e8c3d5c3e6c2c0e9d7c4464e728e745aba8d0449c406f88a5a3722070';
const goldenWithoutMoved = () => {
  const golden = JSON.parse(readFileSync(path.join(ROOT, 'test/fixtures/access/defaults.golden.json'), 'utf8'));
  for (const appId of ['google-calendar', 'gmail', 'github']) delete golden.apps[appId];
  golden.apps.notion.files['catalog/auth/notion.json'] = NOTION_FILES_BEFORE.file;
  golden.apps.notion.filesHash = NOTION_FILES_BEFORE.hash;
  Object.assign(golden.apps.slack, {filesHash: SLACK_FILES_BEFORE.filesHash, files: {...golden.apps.slack.files, 'catalog/auth/slack.json': SLACK_FILES_BEFORE.auth}});
  return createHash('sha256').update(JSON.stringify(golden)).digest('hex');
};
/** Every file under a folder, as repository paths. */
const filesUnder = folder => readdirSync(path.join(ROOT, folder), {withFileTypes: true}).flatMap(entry => entry.isDirectory() ? filesUnder(`${folder}/${entry.name}`) : [`${folder}/${entry.name}`]);

test('nothing under catalog/ changes except the new catalog/live-tests/README.md, step 13\'s binding, action file, plan and README paragraph, step 15\'s Gmail row data, step 17\'s GitHub bindings and grant header, and the action files, plans and README paragraphs of steps 15 to 21, and the signed defaults golden is unchanged but for Calendar\'s, Gmail\'s and GitHub\'s entries, every other sign-off binding', () => {
  const files = filesUnder('catalog').filter(file => !file.endsWith('/.DS_Store')).sort();
  assert.deepEqual(files, [...Object.keys(CATALOG), 'catalog/live-tests/README.md', ...STEP_13_FILES, ...STEP_15_FILES, ...STEP_17_FILES, ...STEP_19_FILES, ...STEP_21_FILES].sort(),
    'no catalog file appears or goes, but the plan format\'s README and the two files of steps 13, 15, 17, 19 and 21');
  for (const [file, digest] of Object.entries(CATALOG)) assert.equal(digestOf(file, undone(file)), digest, `${file} is as it was before step 12`);
  for (const [file, digest] of Object.entries(UNCHANGED)) assert.equal(digestOf(file), digest, `${file} is as it was after its listed churn`);
  assert.equal(goldenWithoutMoved(), GOLDEN_WITHOUT_MOVED, 'the golden, but Calendar\'s, Gmail\'s and GitHub\'s entries and Notion\'s and Slack\'s files hashes, is as it was before step 12');
  assert.deepEqual(checkSigned().filter(problem => !['google-calendar', 'gmail', 'github'].some(appId => problem.startsWith(`${appId}: `))), [],
    'every signed defaults table but Calendar\'s (F10.13), Gmail\'s (F10.15) and GitHub\'s (F10.17) still binds the data it gives now');
});

/** A file's relative imports: the static ones (from, and a bare import), and the import() calls with a literal path. */
function importsOf(file) {
  const text = readFileSync(path.join(ROOT, file), 'utf8'), resolve = target => path.relative(ROOT, path.resolve(path.dirname(path.join(ROOT, file)), target));
  return {static: [...text.matchAll(/(?:\bfrom\s*|\bimport\s+)(['"])(\.{1,2}\/[^'"]+)\1/g)].map(match => resolve(match[2])),
    dynamic: [...text.matchAll(/\bimport\s*\(\s*(['"])(\.{1,2}\/[^'"]+)\1\s*\)/g)].map(match => resolve(match[2]))};
}
/** Every file a start file reaches through static imports. */
function reached(...starts) {
  const seen = new Set(), queue = [...starts];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    for (const next of importsOf(file).static) if (/\.m?[jt]s$/.test(next)) queue.push(next);
  }
  return seen;
}

test('server.mjs statically reaches lib/certification.mjs and no lib/live-*.mjs; neither server imports the harness dynamically', () => {
  const seen = reached('server.mjs', 'developer-server.mjs');
  assert.ok(seen.has('lib/certification.mjs'));
  assert.deepEqual([...seen].filter(file => /^lib\/live-[^/]*\.mjs$/.test(file) || file.startsWith('scripts/')), []);
  for (const file of seen) assert.deepEqual(importsOf(file).dynamic.filter(target => /live-/.test(target)), [], file);
});

test('lib/live-certify.mjs imports none of the owner-side modules: server.mjs, lib/runtime.mjs, lib/permissions.mjs, lib/app-detail.mjs, lib/fabric-protocol.mjs', () => {
  const {static: direct, dynamic} = importsOf('lib/live-certify.mjs');
  for (const owner of ['server.mjs', 'lib/runtime.mjs', 'lib/permissions.mjs', 'lib/app-detail.mjs', 'lib/fabric-protocol.mjs']) assert.ok(!direct.includes(owner) && !dynamic.includes(owner), owner);
  assert.deepEqual(dynamic, []);
});

// The command holds the owner principal only to bind each test's grant (section 8, question 3): it may reach Fabric through these members
// alone, and never through an approve, a row setter, a reset, the owner's job routes, a POST to the approve page or the owner's CSRF header.
const ALLOWED = Object.freeze(['app.actions', 'app.close', 'app.connections.providers.resolve', 'app.origin', 'app.protocol.createClient', 'app.protocol.handle', 'app.protocol.revokeClient',
  'app.runtime.proxyPolicy.view', 'app.start', 'app.store.get', 'app.store.list']);
// The action catalog's two maps, read only: their own reading members and nothing else of the catalog (no reload, seed or runner).
const MAP_READS = Object.freeze(['app.actions.entries', 'app.actions.superseded']);
const allowed = member => ALLOWED.includes(member) || MAP_READS.some(map => member === map || /^\.(values|keys|get|has|size)$/.test(member.slice(map.length)) && member.startsWith(map));
test('scripts/live-certify.mjs uses only the members part 2 names: no approve, setRow, reset, /api/jobs, POST /approve or x-fabric-csrf', () => {
  const text = readFileSync(path.join(ROOT, 'scripts/live-certify.mjs'), 'utf8');
  const used = [...new Set([...text.matchAll(/\bapp\.([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)/g)].map(match => `app.${match[1]}`))].sort();
  assert.deepEqual(used.filter(member => !allowed(member)), [], 'only the named members');
  for (const banned of [/\bapprove\s*\(/, /\bdecide\w*\s*\(/, /\bsetRow\b/, /\.set\s*\(\s*\{/, /\breset\s*\(/, /\bpromote\b/, /\/api\/jobs/, /x-fabric-csrf/i, /\bfetch\s*\(/, /\bhttp\.request\b/, /method\s*:\s*['"]POST['"]/, /\bruntime\.approve\b/]) {
    assert.ok(!banned.test(text), String(banned));
  }
  assert.deepEqual(importsOf('scripts/live-certify.mjs').dynamic, []);
});

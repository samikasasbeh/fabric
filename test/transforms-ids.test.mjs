import test from 'node:test';
import assert from 'node:assert/strict';
import {TRANSFORMS, runTransform} from '../lib/transforms/index.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {splitOwnerRepo, validOwner, validRepo} from '../lib/transforms/_shared/ownerRepo.v1.mjs';
import {outcome, readVectors, vectorTests} from './fixtures/transform-vectors.mjs';

// F10.8 (docs/F10.8-BUILD-MAP.md parts b and i): the owner and repository rule that ids.ownerRepo@1 and text.githubQuery@1 share, and
// the four ids transforms with the vectors of test/fixtures/transforms/ids.json. No ids output is a URL or a host (I4).

test('the owner rule: 1 to 39 letters, digits or single inner hyphens', () => {
  for (const owner of ['a', 'octo', 'octo-cat', 'a1-b2-c3', 'a'.repeat(39)]) assert.equal(validOwner(owner), true, owner);
  for (const owner of ['', 'a'.repeat(40), '-a', 'a-', 'a--b', 'a.b', 'a_b', '..', 'é', 'a b', 7]) assert.equal(validOwner(owner), false, String(owner));
});

test('the repository rule: 1 to 100 letters, digits, -, _ or ., never . or ..', () => {
  for (const repo of ['b', 'hello-world', '.github', 'a_b.c-d', '...', 'a'.repeat(100)]) assert.equal(validRepo(repo), true, repo);
  for (const repo of ['', '.', '..', 'a'.repeat(101), 'a/b', 'a b', 'é', 7]) assert.equal(validRepo(repo), false, String(repo));
});

test('owner/repo splits only into one valid owner and one valid repository', () => {
  assert.deepEqual(splitOwnerRepo('octo/hello-world'), {owner: 'octo', repo: 'hello-world'});
  for (const value of ['a/b/c', '../x', '-a/b', `${'a'.repeat(40)}/b`, 'a/.', 'a/..', 'a', '/b', 'a/', '', 7]) assert.equal(splitOwnerRepo(value), null, String(value));
});

vectorTests('ids');

const NOTION = 'ids.notionId@1', SLACK = 'ids.slackLink@1', OWNER_REPO = 'ids.ownerRepo@1', REF = 'ids.gitRefName@1';
const IDS = [NOTION, SLACK, OWNER_REPO, REF];
const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${error}`);
  assert.equal(error.code, code);
  return true;
};
const run = (id, args) => runTransform(id, args);
const ID = '1429989fe8ac4effbc8f57f56486db54', HYPHENATED = '1429989f-e8ac-4eff-bc8f-57f56486db54';

test('part i registers four transforms, each with its own code and no runtime fact', () => {
  const codes = {[NOTION]: ['notion_id_invalid'], [SLACK]: ['slack_link_invalid'], [OWNER_REPO]: ['repo_invalid'], [REF]: ['ref_invalid']};
  for (const id of IDS) {
    const entry = TRANSFORMS.get(id);
    assert.ok(entry, id);
    assert.deepEqual(entry.refuses, codes[id], id);
    assert.deepEqual(entry.runtimeFacts, [], `${id} folds ASCII only`);
    assert.equal(entry.kind, 'map', id);
    assert.deepEqual(entry.stepData, {}, id);
  }
});

test('notionId: only notion.so, www.notion.so and a workspace on notion.site, over https with no user or port; the path id wins', () => {
  for (const value of [`https://www.notion.so/My-Page-${ID}`, `https://notion.so/${ID}`, `https://acme.notion.site/Page-${ID}#heading`, `https://www.notion.so/acme/Db-${ID}?v=${'0'.repeat(32)}`,
    `https://www.notion.so/a/b/c/Title-With-Dashes-${ID}?pvs=4`, ID, ID.toUpperCase(), HYPHENATED, HYPHENATED.toUpperCase()]) {
    assert.deepEqual(run(NOTION, {value}), {id: HYPHENATED}, value);
  }
  for (const value of [`https://notion.site/${ID}`, `https://a.b.notion.site/${ID}`, `https://-a.notion.site/${ID}`, `https://evil.example/${ID}`, `https://notion.so.evil.example/${ID}`,
    `https://evil.example/https://www.notion.so/${ID}`, `https://www.notion.so@evil.example/${ID}`, `https://www.notion.so:443/${ID}`, `ftp://www.notion.so/${ID}`, `//www.notion.so/${ID}`,
    `www.notion.so/${ID}`, `https://www.notion.so/${ID}x`, `https://www.notion.so/${ID.slice(1)}`, `https://www.notion.so/Page ${ID}`, `https://www.notion.so/?p=${ID}`,
    `${HYPHENATED.slice(0, 8)}${HYPHENATED.slice(9)}`, `{${HYPHENATED}}`, ` ${ID}`, `${ID}\n`, '', 'g'.repeat(32)]) {
    assert.throws(() => run(NOTION, {value}), refused('notion_id_invalid'), value);
  }
});

test('slackLink: channel, ts and thread, which is thread_ts when the link points at a reply and the ts otherwise (open point Minor 10)', () => {
  const base = 'https://acme.slack.com/archives/C024BE91L/p1355517523000008';
  assert.deepEqual(run(SLACK, {link: base}), {channel: 'C024BE91L', ts: '1355517523.000008', thread: '1355517523.000008'});
  assert.deepEqual(run(SLACK, {link: `${base}?thread_ts=1355517523.000005&cid=C024BE91L`}), {channel: 'C024BE91L', ts: '1355517523.000008', thread: '1355517523.000005', parent: '1355517523.000005'});
  assert.deepEqual(run(SLACK, {link: `${base}?cid=C024BE91L`}).thread, '1355517523.000008', 'cid alone names no thread');
  assert.deepEqual(run(SLACK, {link: 'https://ACME.Slack.COM/archives/G024BE91L/p1355517523000008'}).channel, 'G024BE91L');
  assert.deepEqual(run(SLACK, {link: 'https://my-team.slack.com/archives/D024BE91L/p1355517523000008'}).channel, 'D024BE91L');
  assert.deepEqual(run(SLACK, {link: 'https://acme.enterprise.slack.com/archives/C024BE91L/p1355517523000008'}).ts, '1355517523.000008', 'an Enterprise Grid link');
  for (const link of [`${base}/`, 'https://slack.com/archives/C024BE91L/p1355517523000008', 'https://a.b.slack.com/archives/C024BE91L/p1355517523000008', 'https://a.b.enterprise.slack.com/archives/C024BE91L/p1355517523000008',
    'https://acme.slack.com/archives/X024BE91L/p1355517523000008', 'https://acme.slack.com/archives/C024/p1355517523000008', 'https://acme.slack.com/messages/C024BE91L/p1355517523000008',
    'https://acme.slack.com/archives/C024BE91L/1355517523000008', 'https://acme.slack.com/archives/C024BE91L/p135551752300000a', `${base}?thread_ts=`, `${base}?thread_ts=1355517523000005`,
    `https://user@acme.slack.com/archives/C024BE91L/p1355517523000008`, 'https://acme.slack.com:443/archives/C024BE91L/p1355517523000008', `${base} `, '']) {
    assert.throws(() => run(SLACK, {link}), refused('slack_link_invalid'), link);
  }
  // A ts from a link feeds time.slackTs@1's step data unchanged.
  assert.equal(run('time.slackTs@1', {ts: run(SLACK, {link: base}).thread}).ts, '1355517523.000008');
});

test('ownerRepo splits through the shared rule that text.githubQuery@1 uses', () => {
  assert.deepEqual(run(OWNER_REPO, {value: 'octo-cat/hello.world_2'}), {owner: 'octo-cat', repo: 'hello.world_2'});
  for (const value of ['a/b/c', '../x', '-a/b', `${'a'.repeat(40)}/b`, 'a/.', 'a/..', 'a', '/b', 'a/', '', 'a /b', 'a/b ', 'é/b']) {
    assert.throws(() => run(OWNER_REPO, {value}), refused('repo_invalid'), value);
  }
});

test('gitRefName: each git-check-ref-format rule refuses its case under refs/heads/, and only printable ASCII passes', () => {
  for (const name of ['main', 'fabric/test-run1', 'feature/a.b', 'a-b_c', 'v1.2.3', 'a@b', 'x/y/z', 'A'.repeat(255)]) assert.deepEqual(run(REF, {name}), {name}, name);
  const cases = {
    'a component starts with a dot (rule 1)': ['.a', 'a/.b', 'a/./b'],
    'a component ends with .lock (rule 1)': ['a.lock', 'a/b.lock/c', 'a.lock/b'],
    'two dots (rule 3)': ['a..b', '..', 'a/../b'],
    'a control, a space, ~, ^ or : (rule 4)': ['a\u0000b', 'a\u001fb', 'a\u007fb', 'a b', 'a~b', 'a^b', 'a:b', 'a\tb'],
    '?, * or [ (rule 5)': ['a?b', 'a*b', 'a[b'],
    'a slash at either end or two in a row (rule 6)': ['/a', 'a/', 'a//b'],
    'a trailing dot (rule 7)': ['a.', 'a/b.'],
    '@{ (rule 8)': ['a@{b', '@{'],
    '@ alone (rule 9)': ['@'],
    'a backslash (rule 10)': ['a\\b'],
    'a leading hyphen (git\'s branch rule)': ['-a'],
    'a character outside printable ASCII (Fabric)': ['café', 'a b', 'a‮b', '😀'],
  };
  for (const [what, names] of Object.entries(cases)) for (const name of names) assert.throws(() => run(REF, {name}), refused('ref_invalid'), `${what}: ${JSON.stringify(name)}`);
  assert.throws(() => run(REF, {name: 'A'.repeat(256)}), refused('input_invalid'));
  assert.throws(() => run(REF, {name: ''}), refused('input_invalid'));
});

test('no ids output is a URL or holds a host (I4)', () => {
  // F10.21 listed churn: an emoji code is :name: (and a skin tone ::skin-tone-3), which the colon rules below would read as a scheme or a
  // port. ids.slackEmoji@1 holds no '/' or '.' at all, which test/transforms-slack.test.mjs checks on its own vectors.
  const outputs = readVectors('ids').cases.filter(item => !Object.hasOwn(item, 'refuses') && item.transform !== 'ids.slackEmoji@1').map(item => outcome(item).output);
  assert.ok(outputs.length > 10);
  const strings = value => typeof value === 'string' ? [value] : value && typeof value === 'object' ? Object.values(value).flatMap(strings) : [];
  for (const text of outputs.flatMap(strings)) {
    assert.ok(!/[:/]{2}|slack\.com|notion\.(?:so|site)|github\.com|\.example/i.test(text), text);
    assert.ok(!text.includes(':'), `no scheme or port: ${text}`);
  }
  for (const id of IDS) {
    const properties = Object.keys(TRANSFORMS.get(id).output.properties);
    assert.ok(properties.every(name => !/url|host|link|href/i.test(name)), `${id} has no URL-shaped output field`);
  }
});

// F10.17 part 1 (docs/F10.17-BUILD-MAP.md part 1, F10.8 map part k): ids.repoPath@1, the path of a file in a GitHub repository, for Read a
// file and Create or update a file. Its code path_invalid comes in _shared/error.v2.mjs, so no step 8 pin moves.
const REPO_PATH = 'ids.repoPath@1';

test('repoPath: plain segments pass; a dot segment, an empty one, a slash at either end, a backslash, any percent sign, a control or hidden character, a lone surrogate or a segment over 255 code points refuses path_invalid', () => {
  const entry = TRANSFORMS.get(REPO_PATH);
  assert.ok(entry, `${REPO_PATH} is registered`);
  assert.deepEqual([entry.kind, entry.refuses, entry.runtimeFacts, entry.stepData], ['map', ['path_invalid'], ['unicode'], {}]);
  for (const path of ['README.md', 'docs/read me.md', 'a/b/c.txt', '.github/ci.yml', 'a.b/..c', '...', '.hidden', 'x'.repeat(255), `${'x'.repeat(255)}/y`, 'é/ü.md', 'a:b*c?']) {
    assert.deepEqual(run(REPO_PATH, {path}), {path, workflow: false}, path);
  }
  const cases = {
    'a dot segment': ['a/../b', '..', '.', 'a/.', './a', '../x', 'a/..'],
    'an empty segment or a slash at either end': ['a//b', '/a', 'a/', '/'],
    'a backslash': ['a\\b', '..\\x'],
    'a percent sign, so no encoded form passes': ['%2e%2e/x', 'a/%2E/b', 'a%2Fb', 'a%20b', '%'],
    'a control, hidden or direction character': ['a\nb', 'a\tb', 'a\rb', 'a\u0000b', 'a\u007fb', 'a​b', 'a‮b', 'a⁦b', 'a﻿b'],
    'a lone surrogate': ['a\ud800', '\udc00b'],
    'a segment over 255 code points': ['x'.repeat(256), `a/${'😀'.repeat(256)}`],
  };
  for (const [what, paths] of Object.entries(cases)) for (const path of paths) assert.throws(() => run(REPO_PATH, {path}), refused('path_invalid'), `${what}: ${JSON.stringify(path)}`);
  assert.deepEqual(run(REPO_PATH, {path: `a/${'😀'.repeat(255)}`}).workflow, false, '255 code points, not UTF-16 units');
  assert.throws(() => run(REPO_PATH, {path: ''}), refused('input_invalid'));
  assert.throws(() => run(REPO_PATH, {path: `${'a/'.repeat(500)}b`}), refused('input_invalid'), 'more than 1,000 code points');
});

test('repoPath says whether a path runs in GitHub Actions: under .github/workflows/, compared with ASCII folding, so it flags more, never less (open question 6)', () => {
  for (const path of ['.github/workflows/ci.yml', '.GitHub/Workflows/ci.yml', '.GITHUB/WORKFLOWS/a/b.yml', '.github/workflows/.x']) assert.equal(run(REPO_PATH, {path}).workflow, true, path);
  for (const path of ['.github/workflows', '.github/workflowsx/a.yml', 'github/workflows/ci.yml', 'a/.github/workflows/ci.yml', '.github/workflow/ci.yml', '.github/ci.yml']) {
    assert.equal(run(REPO_PATH, {path}).workflow, false, path);
  }
  assert.deepEqual(Object.keys(TRANSFORMS.get(REPO_PATH).output.properties).sort(), ['path', 'workflow'], 'no URL-shaped output field (I4)');
});

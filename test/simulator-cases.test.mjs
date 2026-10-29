import test from 'node:test';
import assert from 'node:assert/strict';
import {caseTests} from './fixtures/provider-simulators/cases.mjs';

// F10.13 part 1 (docs/F10.13-BUILD-MAP.md part 1 and section 3): caseTests() registers one test per case an app's simulator case list
// names, from an implementation table keyed "<key> v<version>/<kind>". A listed case with no implementation fails, and so does an
// implementation the list does not name, so check 5's static list (scripts/app-template-check.mjs) and the suite cannot disagree.
/** A stand-in for node:test that keeps what is registered, so each registered test can be run and judged here. */
function recorder() {
  const registered = [];
  return {registered, test: (name, fn) => { registered.push({name, fn}); }};
}
const MANIFEST = {schemaVersion: 1, appId: 'demo', simulator: 'test/fixtures/provider-simulators/demo.mjs', tests: ['test/demo.test.mjs'],
  cases: {'list-things v1': ['succeeds', 'refused', 'provider-refusal'], 'make-thing v2': ['succeeds', 'refused', 'provider-refusal', 'unverified', 'lost-answer']}};
const ENTRIES = [{key: 'list-things', version: 1, effect: 'read'}, {key: 'make-thing', version: 2, effect: 'write'}];
const LISTED = Object.entries(MANIFEST.cases).flatMap(([key, kinds]) => kinds.map(kind => `${key}/${kind}`));

test('a complete table registers exactly one test per listed case, each running its implementation with the action\'s entry', async () => {
  const {registered, test: register} = recorder(), ran = [];
  caseTests(register, MANIFEST, ENTRIES, Object.fromEntries(LISTED.map(name => [name, async (t, entry) => { ran.push([name, entry.key, entry.version]); }])));
  assert.deepEqual(registered.map(item => item.name), LISTED.map(name => `simulator case ${name}`));
  for (const item of registered) await item.fn({});
  assert.deepEqual(ran, LISTED.map(name => [name, name.startsWith('list') ? 'list-things' : 'make-thing', name.startsWith('list') ? 1 : 2]));
});

test('a listed case with no implementation fails, an implementation the list does not name fails, and a failing implementation is not swallowed', async () => {
  const {registered, test: register} = recorder();
  const table = Object.fromEntries(LISTED.filter(name => name !== 'make-thing v2/lost-answer').map(name => [name, async () => {}]));
  table['make-thing v2/succeeds'] = async () => { throw new Error('the simulator said no'); };
  table['make-thing v3/succeeds'] = async () => {};
  table['list-things v1/unverified'] = async () => {};
  caseTests(register, MANIFEST, ENTRIES, table);
  const outcome = async name => { try { await registered.find(item => item.name === `simulator case ${name}`).fn({}); return 'passed'; } catch (error) { return error.message; } };
  assert.equal(registered.length, LISTED.length + 2, 'every listed case, and each extra implementation, is a test of its own');
  assert.match(await outcome('make-thing v2/lost-answer'), /^make-thing v2\/lost-answer is listed in demo's simulator case list but has no implementation\.$/);
  assert.match(await outcome('make-thing v3/succeeds'), /^make-thing v3\/succeeds has an implementation, but demo's simulator case list does not name it\.$/);
  assert.match(await outcome('list-things v1/unverified'), /^list-things v1\/unverified has an implementation, but demo's simulator case list does not name it\.$/);
  assert.equal(await outcome('make-thing v2/succeeds'), 'the simulator said no');
  assert.equal(await outcome('list-things v1/succeeds'), 'passed');
});

test('a listed case whose action the entries do not hold fails, though it has an implementation', async () => {
  const {registered, test: register} = recorder();
  caseTests(register, {...MANIFEST, cases: {...MANIFEST.cases, 'gone v1': ['succeeds']}}, ENTRIES, Object.fromEntries([...LISTED, 'gone v1/succeeds'].map(name => [name, async () => {}])));
  await assert.rejects(registered.find(item => item.name === 'simulator case gone v1/succeeds').fn({}), {message: 'gone v1 is listed in demo\'s simulator case list, but the action file holds no gone v1.'});
});

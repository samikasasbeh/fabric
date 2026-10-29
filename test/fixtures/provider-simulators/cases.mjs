// F10.13 part 1 (docs/F10.13-BUILD-MAP.md part 1): the simulator cases an app's case list names, as tests. The list is
// test/fixtures/provider-simulators/<appId>.cases.json, {schemaVersion: 1, appId, simulator, tests, cases: {'<key> v<version>': [kinds]}},
// which check 5 of scripts/app-template-check.mjs reads statically. caseTests() registers one test per listed case from a table of
// implementations keyed "<key> v<version>/<kind>", each called with (t, entry). A listed case with no implementation fails, a listed case
// whose action the entries do not hold fails, and an implementation the list does not name fails, so the static list and the suite cannot
// disagree. Test code only.
import assert from 'node:assert/strict';

/**
 * Registers the simulator case tests of one app.
 * @param {(name: string, fn: (t: any) => Promise<void> | void) => void} test node:test's test, or a stand-in
 * @param {{appId: string, cases: Record<string, string[]>}} manifest the app's case list
 * @param {{key: string, version: number}[]} entries the app's validated actions
 * @param {Record<string, (t: any, entry: any) => Promise<void> | void>} implementations keyed "<key> v<version>/<kind>"
 */
export function caseTests(test, manifest, entries, implementations) {
  const byKey = new Map(entries.map(entry => [`${entry.key} v${entry.version}`, entry]));
  const listed = Object.entries(manifest.cases).flatMap(([key, kinds]) => kinds.map(kind => ({key, name: `${key}/${kind}`})));
  for (const {key, name} of listed) {
    const run = Object.hasOwn(implementations, name) ? implementations[name] : null;
    test(`simulator case ${name}`, async t => {
      if (typeof run !== 'function') assert.fail(`${name} is listed in ${manifest.appId}'s simulator case list but has no implementation.`);
      if (!byKey.has(key)) assert.fail(`${key} is listed in ${manifest.appId}'s simulator case list, but the action file holds no ${key}.`);
      await run(t, byKey.get(key));
    });
  }
  const names = new Set(listed.map(item => item.name));
  for (const name of Object.keys(implementations).filter(item => !names.has(item))) {
    test(`simulator case ${name}`, () => assert.fail(`${name} has an implementation, but ${manifest.appId}'s simulator case list does not name it.`));
  }
}

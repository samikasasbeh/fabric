// F10.6 fixtures (docs/F10-FIVE-APPS-DEEP.md section 5; docs/F10.6-BUILD-MAP.md part a). Data only: nothing in lib/ reads it.
// F10.7 (open question 21) copied section 5's drafts into the catalog, so these fixtures now read it: `definitions` are the shipped
// version 2 auth definitions, and `rows(appId)` is the shipped rows file with its scope data and markers. Tests that need another
// shape build it from these. test/f10-7-catalog.test.mjs pins them to the catalog. Each test validates what it uses.
import {readFileSync} from 'node:fs';

export const F10_6_KEYS = Object.freeze(['scopeSets', 'memberScopeSets', 'unavailable', 'conditions', 'conditionalScopes', 'unsupported']);
const catalog = file => JSON.parse(readFileSync(new URL(`../../../catalog/${file}`, import.meta.url), 'utf8'));

// ---- auth definitions (section 5 tables, as shipped) -----------------------------------------------------------------------
const freeze = value => {if (value && typeof value === 'object') {for (const item of Object.values(value)) freeze(item); Object.freeze(value);} return value;};
/** Frozen; structuredClone one to change it. */
export const definitions = freeze(Object.fromEntries(['google', 'github', 'notion', 'slack'].map(providerId => [providerId, catalog(`auth/${providerId}.json`)])));
export const definitionOf = providerId => structuredClone(definitions[providerId]);

// ---- rows (section 5 scope data and markers, as shipped) --------------------------------------------------------------------
export const FIXTURE_APPS = Object.freeze(['gmail', 'google-calendar', 'github', 'notion', 'slack']);
/** The shipped rows file of one app, with its scope data and markers: a fresh plain object. */
export function rows(appId) {
  if (!FIXTURE_APPS.includes(appId)) throw new Error(`No F10.6 fixture rows for ${appId}.`);
  return catalog(`permissions/${appId}.json`);
}
/** The same rows with every F10.6 key taken out. */
export const stripped = definition => ({...definition, groups: definition.groups.map(group => Object.fromEntries(Object.entries(group).filter(([key]) => !F10_6_KEYS.includes(key))))});

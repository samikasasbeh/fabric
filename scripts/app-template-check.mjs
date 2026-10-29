// F10.1 template check skeleton (docs/F10-FIVE-APPS-DEEP.md, exit gate section 9). Says whether one app is Muse-grade:
// a full-access sign-in proven by the access closure, version 2 rows, an owner-signed defaults table, reviewed actions
// and live evidence. Today every check fails for every app; test/app-template-check.test.mjs holds the results as a
// ratchet, so a slice that makes a check pass records it on purpose and nothing slips back. F10.23 completes it.
//
//   node scripts/app-template-check.mjs <appId>      (exit 1 while the app's gate fails)
//
// Local files only; no network, no store.
import {existsSync, readFileSync, statSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {closure, operationsFromRows, membersOf} from '../lib/access-closure.mjs';
import {definitionFor, reviewedProviderIds} from '../lib/providers/definitions.mjs';
import {PERMISSION_GROUPS, memberKey} from '../lib/permission-groups.mjs';
import {validateActionFile} from '../lib/actions.mjs';
import {validateChoiceSources} from '../lib/choice-sources.mjs';
import {computePins, readPins} from '../lib/transform-pins.mjs';
import {goldenStatus, currentDataHash} from './defaults-golden.mjs';
import {methodMap} from './google-method-paths.mjs';
import {evidencePasses} from '../lib/action-catalog.mjs';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const TEMPLATE_APPS = Object.freeze(['gmail', 'google-calendar', 'github', 'notion', 'slack']);
// Slack must pass checks 1 to 5; its live checks run when the operator's Slack setup is done, and do not block the gate.
const NOT_GATING = {slack: ['live-evidence', 'sign-in-evidence']};
// Sign-in evidence the gate asks for. Notion grants pages, not scopes, so it has no partial grant to prove.
const SIGN_IN_EVIDENCE = {gmail: ['full-consent', 'partial-grant-add-access', 'renewal-kept-settings'], 'google-calendar': ['full-consent', 'partial-grant-add-access', 'renewal-kept-settings'],
  github: ['full-consent', 'partial-grant-add-access', 'scope-check'], notion: ['full-consent'], slack: ['full-consent', 'partial-grant-add-access']};

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const readJson = file => existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : undefined;

// F10.13 part 1 (docs/F10.13-BUILD-MAP.md part 1): check 5's provider simulator case list. Each app's simulator comes with its actions (steps
// 13 to 21), with a list, test/fixtures/provider-simulators/<appId>.cases.json, that names the simulator, the test files that run its cases
// (through test/fixtures/provider-simulators/cases.mjs caseTests(), so the list and the suite cannot disagree) and the kinds of case each
// action has: {schemaVersion: 1, appId, simulator, tests, cases: {'<key> v<version>': [kinds]}}.
/** The kinds of simulator case: the action works; it is refused before anything is sent; the provider refuses it; a change it sent is not
 *  confirmed when read back; the answer to a change is lost. */
export const CASE_KINDS = Object.freeze(['succeeds', 'refused', 'provider-refusal', 'unverified', 'lost-answer']);
/** The kinds one action's cases must cover: the first three for every action, all five for an action whose effect is not read. */
export const requiredKinds = entry => entry.effect === 'read' ? CASE_KINDS.slice(0, 3) : [...CASE_KINDS];
/**
 * What keeps an app's simulator case list from covering its validated actions (`entries`), in words; null when nothing does. With no list
 * the reason is the one step 11 gave. The list must name this app, a simulator and test files that are files under <root>, and exactly
 * the actions of `entries`, each with every kind requiredKinds() gives and no other.
 * @param {string} appId
 * @param {{key: string, version: number, effect: string}[]} entries
 * @param {{root?: string}} [options]
 */
export function simulatorCases(appId, entries, {root = ROOT} = {}) {
  const relative = `test/fixtures/provider-simulators/${appId}.cases.json`, location = path.join(root, relative);
  if (!existsSync(location)) return `no provider simulator for ${appId} yet (steps 13 to 21)`;
  let list;
  try { list = JSON.parse(readFileSync(location, 'utf8')); } catch { return `the simulator case list ${relative} is not JSON`; }
  if (!record(list) || Object.keys(list).sort().join() !== 'appId,cases,schemaVersion,simulator,tests' || list.schemaVersion !== 1 || !record(list.cases)) {
    return `the simulator case list ${relative} holds exactly schemaVersion 1, appId, simulator, tests and cases`;
  }
  if (list.appId !== appId) return `the simulator case list ${relative} names ${String(list.appId).slice(0, 80)}, not ${appId}: a case list holds its own app's cases`;
  // A file named by a plain relative path under <root> that is a file there.
  const isFile = value => typeof value === 'string' && /^[A-Za-z0-9._/-]{1,300}$/.test(value) && !value.split('/').some(part => part === '..' || part === '.' || part === '')
    && existsSync(path.join(root, value)) && statSync(path.join(root, value)).isFile();
  if (!isFile(list.simulator)) return `the simulator case list names a simulator that is not a file under the root: ${String(list.simulator).slice(0, 200)}`;
  if (!Array.isArray(list.tests) || !list.tests.length) return 'the simulator case list names no test file';
  const test = list.tests.find(item => !isFile(item) || !String(item).endsWith('.test.mjs'));
  if (test !== undefined) return `the simulator case list names a test file that is not a file under the root: ${String(test).slice(0, 200)}`;
  const keys = entries.map(entry => `${entry.key} v${entry.version}`), extra = Object.keys(list.cases).filter(key => !keys.includes(key)), missing = keys.filter(key => !Object.hasOwn(list.cases, key));
  if (extra.length) return `the simulator case list names ${extra.length} action${extra.length === 1 ? '' : 's'} the action file does not hold: ${extra.slice(0, 3).join(', ')}${extra.length > 3 ? ', ...' : ''}`;
  if (missing.length) return `the simulator case list leaves out ${missing.length} action${missing.length === 1 ? '' : 's'} of the action file: ${missing.slice(0, 3).join(', ')}${missing.length > 3 ? ', ...' : ''}`;
  for (const entry of entries) {
    const key = `${entry.key} v${entry.version}`, kinds = list.cases[key];
    if (!Array.isArray(kinds) || kinds.some(kind => !CASE_KINDS.includes(kind)) || new Set(kinds).size !== kinds.length) return `the simulator case list gives ${key} a kind that is not one of ${CASE_KINDS.join(', ')}`;
    const lacking = requiredKinds(entry).filter(kind => !kinds.includes(kind));
    if (lacking.length) return `the simulator case list gives ${key} no ${lacking.join(', ')} case`;
  }
  return null;
}

/** The reviewed auth definition and app entry that carry an app id. */
export function signInFor(appId, definitions = reviewedProviderIds().map(definitionFor)) {
  for (const definition of definitions) {
    const app = definition.apps?.find(item => item.appId === appId);
    if (app) return {definition, app};
  }
  throw new Error(`No reviewed sign-in definition carries ${appId}.`);
}

// In-context entries name their rows ({scope, rows}); the closure needs the scope.
const fullScopes = full => [...(full.required || []), ...(full.optional || []), ...(full.inContext || []).map(entry => typeof entry === 'string' ? entry : entry.scope)];

/**
 * Every exit-gate check for one app, each {id, label, pass, required, reason}.
 * @param {string} appId
 * `actionDeps` override the dependencies check 5 validates the action file with (validateActionFile(): by default the shipped rows and
 * proxy settings with this app's `groups`, no stored map, the shipped transforms, `root`'s pins and choice sources, and this app's sign-in);
 * `codeHashes` gives the code hash each named transform has now (computePins() over `root` by default).
 * @param {{root?: string, definitions?: any[], groups?: any, scopeFacts?: any, actionDeps?: any, codeHashes?: (ids: string[]) => Record<string, string>}} [options]
 */
export function templateChecks(appId, {root = ROOT, definitions, groups = PERMISSION_GROUPS.get(appId), scopeFacts, actionDeps, codeHashes} = {}) {
  if (!TEMPLATE_APPS.includes(appId) && !definitions) throw new Error(`${appId} is not one of the template apps (${TEMPLATE_APPS.join(', ')}).`);
  const {definition, app} = signInFor(appId, definitions);
  const full = record(app.access?.levels?.full) ? app.access.levels.full : null;
  const pages = app.access?.grant === 'pages';
  const rowsFile = path.join(root, 'catalog', 'permissions', `${appId}.json`), rows = readJson(rowsFile);
  const evidenceDir = path.join(root, 'docs', 'live-evidence', appId);
  // Discovery's facts per method, where the provider publishes them; every member's alternatives read by its member key (F10.6).
  const facts = scopeFacts ?? readJson(path.join(root, 'test', 'fixtures', 'access', `${definition.providerId}-method-scopes.json`));
  // F10.11 part a: an app reviewed by method id places its action steps through the map its provider's recorded method paths and these
  // scope facts give (scripts/google-method-paths.mjs methodMap()); a provider with no paths file has none.
  const map = methodMap(readJson(path.join(root, 'test', 'fixtures', 'access', `${definition.providerId}-method-paths.json`)), facts, appId);
  const operations = groups ? operationsFromRows(groups.groups, facts?.apps?.[appId]?.methods ?? null) : null;
  const checks = [];
  const check = (id, label, pass, reason) => checks.push({id, label, pass: Boolean(pass), required: !(NOT_GATING[appId] || []).includes(id), reason: pass ? 'passes' : reason});

  // 1. A version 2 sign-in definition with a full level, a never-request list and a consent policy (or Notion's pages grant).
  check('auth-definition', 'Version 2 sign-in definition with full access', definition.schemaVersion === 2 && full && Array.isArray(app.neverRequest) && (record(definition.consentPolicy) || pages),
    definition.schemaVersion !== 2 ? `the sign-in definition is version ${definition.schemaVersion}; the five apps move to version 2 in F10.7`
      : !full ? 'the app has no full access level' : !Array.isArray(app.neverRequest) ? 'the app has no never-request list' : 'the provider has no consent policy');

  // 2. Closure under the full level: every member granted or marked unavailable, nothing missing, no unjustified scope.
  if (!full || !groups) check('closure', 'Every permission works under full access, or says why not', false, !groups ? 'the app has no permission rows' : 'there is no full access level to measure yet (F10.7)');
  else {
    const report = closure({definition, appId, level: 'full', scopes: fullScopes(full), groups: groups.groups, operations, neverRequest: app.neverRequest || []});
    const unavailable = new Set(groups.groups.flatMap(group => record(group.unavailable) ? Object.keys(group.unavailable).map(memberKey) : []));
    const missing = report.rows.flatMap(row => row.missing), unmarked = report.rows.flatMap(row => row.cannotWork).filter(item => !unavailable.has(memberKey(item.member)));
    const unscoped = report.rows.flatMap(row => [...row.unmapped, ...row.noScopes]);
    check('closure', 'Every permission works under full access, or says why not', !missing.length && !unmarked.length && !unscoped.length && !report.unjustified.length,
      [missing.length && `${missing.length} member(s) lack a scope`, unmarked.length && `${unmarked.length} member(s) can never work and are not marked unavailable`,
        unscoped.length && `${unscoped.length} member(s) have no scope data`, report.unjustified.length && `unjustified scopes: ${report.unjustified.join(', ')}`].filter(Boolean).join('; '));
  }

  // 3. Version 2 rows (F10.3 and F10.6 add scope data, unavailable markers, locked rows, audience flags, body routes and content binding).
  check('rows', 'Version 2 permission rows', rows?.schemaVersion === 2, rows ? `the permission rows are version ${rows.schemaVersion}; version 2 arrives in F10.3 and F10.6` : 'the app has no permission rows file');

  // 3b. F10.6 (T3): every member of every row has Discovery facts, row scope data or an unavailable marker.
  const marked = new Set((groups?.groups ?? []).flatMap(group => record(group.unavailable) ? Object.keys(group.unavailable).map(memberKey) : []));
  const silent = (groups?.groups ?? []).flatMap(membersOf).filter(member => !marked.has(member) && !operations.get(member)?.scopeSets);
  check('row-scope-data', 'Every permission member has scope data or says why it never works', groups && !silent.length,
    !groups ? 'the app has no permission rows' : `${silent.length} member(s) have no Discovery facts, no row scope data and no unavailable marker (F10.7): ${silent.slice(0, 3).join(', ')}${silent.length > 3 ? ', ...' : ''}`);

  // 4. The owner-signed defaults table (F10.7, scripts/defaults-golden.mjs): passes only with a sign-off that binds the table this data
  //    gives now, computed from the same definition, rows and facts as the checks above.
  const defaults = groups ? goldenStatus(appId, {root, current: () => currentDataHash({root, appId, definition, groups, facts})}) : {pass: false, reason: 'the app has no permission rows'};
  check('defaults', 'Owner-signed defaults table matches the current data', defaults.pass, defaults.reason);

  // 5. Reviewed actions that pass the validator (F10.9), whose transforms' code still equals their pins (F10.8 map part m), and an
  //    independent provider simulator for the app. F10.11 built the action runtime and the fake app's simulator; each app's own simulator
  //    comes with its actions (steps 13 to 21) and its case list (F10.13 part 1, simulatorCases()), and only both together pass.
  const reviewed = actionsOf(appId, {root, definition, groups, map, actionDeps, codeHashes});
  const actionsReason = reviewed.reason ?? simulatorCases(appId, reviewed.entries, {root});
  check('actions', 'Reviewed actions that pass the validator', actionsReason === null, actionsReason);

  // 6. Live evidence for every action, by the id the validator computed, pins included, never a raw id field: a record counts only with
  //    the pins of every transform the action names (F10.8 map part m), and the definition hash it names, if any, is the action's. The
  //    same evidencePasses() decides at start whether an action is active (F10.11 part c), so the gate and the start cannot disagree.
  const entries = reviewed.entries, evidence = readJson(path.join(evidenceDir, 'actions.json'));
  const certified = entries.filter(entry => evidencePasses(entry, evidence?.[entry.id], reviewed.pinsOf(entry)));
  check('live-evidence', 'Live evidence for every action', entries.length > 0 && certified.length === entries.length,
    !reviewed.exists ? 'no actions to certify yet' : !entries.length ? 'the action file does not pass the validator, so no action has an id to certify'
      : `${entries.length - certified.length} of ${entries.length} actions have no passing live record for their id and the current pins of their transforms`);

  // 7. Sign-in evidence: full-access consent, a partial grant then Add access, a renewal that kept settings, a scope check.
  const signIn = readJson(path.join(evidenceDir, 'sign-in.json'));
  const kinds = SIGN_IN_EVIDENCE[appId] || ['full-consent'], absent = kinds.filter(kind => signIn?.[kind]?.passed !== true);
  check('sign-in-evidence', 'Live sign-in evidence', !absent.length, `no passing live record for: ${absent.join(', ')}`);
  return checks;
}

/**
 * F10.9 part l: one app's action file read through validateActionFile(), with the app's choice sources (catalog/choices/<appId>.json) and
 * the pins of <root>'s lib/transforms/pins.json. Returns {exists, file, entries, reason, pinsOf}: `file` is the file as parsed (null when
 * there is none or it is not JSON), `entries` the validated actions (none when the file fails), `reason` what keeps the file from
 * passing (null when nothing does), and pinsOf(entry) the pins its transforms have. The code of every transform the file names, its poll blocks' included, is computed again and compared with its pin, so a
 * transform edited without a reviewed re-pin fails here (F10.8 map part m). Gmail and Calendar steps place only through a method table:
 * `map`, built from test/fixtures/access/google-method-paths.json (F10.11 part a); an app without one has unplaced actions. As
 * loadActions() and loadChoiceSources() do, it reads a file only when it is named after its appId, so another app's actions are never
 * read, or certified, as this app's; and only a reviewed file holds reviewed actions (I8): a valid candidate still waits for its review.
 */
function actionsOf(appId, {root, definition, groups, map, actionDeps = {}, codeHashes}) {
  const relative = `catalog/actions/${appId}.json`, location = path.join(root, relative);
  let file = null;
  const none = reason => ({exists: existsSync(location), file, entries: [], reason, pinsOf: () => ({})});
  if (!existsSync(location)) return none('no action file yet (F10.13 to F10.21)');
  try { file = JSON.parse(readFileSync(location, 'utf8')); } catch { return none(`the action file ${relative} is not JSON`); }
  if (record(file) && file.appId !== appId) return none(`the action file ${relative} is not named after its appId: an action file holds its own app's actions (as loadActions() requires)`);
  const pins = actionDeps.pins ?? readPins(root)?.transforms ?? {};
  const deps = {groups: new Map([...PERMISSION_GROUPS, ...(groups ? [[appId, groups]] : [])]), identities: new Map([[appId, definition]]), pins, ...(map ? {maps: new Map([[appId, map]])} : {}), ...actionDeps};
  const choicesRelative = `catalog/choices/${appId}.json`, choicesLocation = path.join(root, choicesRelative);
  if (actionDeps.choices === undefined && existsSync(choicesLocation)) {
    let choices;
    try { choices = JSON.parse(readFileSync(choicesLocation, 'utf8')); } catch { return none(`the choice source file ${choicesRelative} is not JSON`); }
    if (record(choices) && choices.appId !== appId) return none(`the choice source file ${choicesRelative} is not named after its appId: a choice source file holds its own app's sources (as loadChoiceSources() requires)`);
    try { deps.choices = new Map([[appId, validateChoiceSources(choices, deps)]]); } catch (error) { return none(`the choice sources do not pass their validator: ${error.message}`); }
  }
  let entries;
  try { entries = validateActionFile(file, deps).actions; } catch (error) { return none(`the action file does not pass the validator: ${error.message}`); }
  const pinsOf = entry => Object.fromEntries(entry.transforms.map(id => [id, deps.pins[id]]));
  const result = reason => ({exists: true, file, entries, reason, pinsOf});
  const unplaced = entries.filter(entry => entry.unplaced);
  if (unplaced.length) return result(`${unplaced.length} of ${entries.length} actions cannot be placed: ${appId} is reviewed by operation id, and the check has no method table for it (no ${definition.providerId}-method-paths.json entry in test/fixtures/access)`);
  const named = [...new Set(entries.flatMap(entry => [...entry.transforms, ...entry.pollTransforms]))].sort();
  const now = (codeHashes ?? (ids => computePins(root, ids).transforms))(named);
  const changed = named.filter(id => now[id] !== deps.pins[id]);
  if (changed.length) return result(`the code of ${changed.join(', ')} changed since it was pinned: run node scripts/transform-pins.mjs --check (a behaviour change is a new version file; a reviewed exception is a re-pin, and gives every action that names it a new id)`);
  if (file.reviewStatus !== 'reviewed') return result('the action file is a candidate: no reviewer has marked it reviewed yet (I8)');
  return result(null);
}

/** Whether an app passes its gate: every required check passes. */
export const gatePasses = checks => checks.every(item => item.pass || !item.required);

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const appId = process.argv[2];
  if (!appId) { console.error(`Usage: node scripts/app-template-check.mjs <appId>   (${TEMPLATE_APPS.join(', ')})`); process.exit(2); }
  const checks = templateChecks(appId);
  for (const item of checks) console.log(`${item.pass ? 'pass' : 'FAIL'}  ${item.label}${item.required ? '' : ' (not required yet)'}${item.pass ? '' : `: ${item.reason}`}`);
  const passed = gatePasses(checks);
  console.log(`${appId}: ${passed ? 'Muse-grade' : `not Muse-grade yet (${checks.filter(item => item.pass).length} of ${checks.length} checks pass)`}`);
  if (!passed) process.exitCode = 1;
}

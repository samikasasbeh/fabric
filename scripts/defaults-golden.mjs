// F10.7 defaults golden (docs/F10.7-BUILD-MAP.md part i, decisions 2 to 4). For each app: the table of what every permission does
// before anyone changes it (its defaults, locks, audience flags, raw request modes, access under the full level, the members that can
// never work, conditional scopes and the upgrade lists), its data hash, which is the hash of that table and what an owner sign-off
// binds, and a files hash over the app's auth, permissions, proxy and routes files, kept for information. test/defaults-golden.test.mjs
// keeps test/fixtures/access/defaults.golden.json and docs/F10.7-DEFAULTS-REVIEW.md current, and check 4 of
// scripts/app-template-check.mjs passes only with a sign-off that binds the current table.
//
//   node scripts/defaults-golden.mjs [--check] [--root <dir>]        compares; exit 1 with what differs
//   node scripts/defaults-golden.mjs --write [--root <dir>]          writes the golden and the review document; never signs
//   node scripts/defaults-golden.mjs --sign --apps <list|all> --by <name> --date <YYYY-MM-DD> --prefix <appId>=<12 characters> ...
//   node scripts/defaults-golden.mjs --check-signed [--root <dir>]   exit 1 unless every app of every version 2 sign-in is signed
//
// --sign runs only after Sami's explicit approval of those apps, through the same signOff() checks for any signer. Everything is read
// from <root>/catalog through the validators, never from this checkout's loaded catalog, so --root can name a worktree. It never reads
// .env, .fabric, the vault or the environment; no network, no store, no clock.
import {spawnSync} from 'node:child_process';
import {existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {canonicalHash} from '../lib/compiler.mjs';
import {validatePermissionGroups, memberKey, UNAVAILABLE_REASONS, CONDITION_WORDS} from '../lib/permission-groups.mjs';
import {validateProxyConfig} from '../lib/proxy-config.mjs';
import {ProxyPolicy} from '../lib/proxy-policy.mjs';
import {groupDefault} from '../lib/permissions.mjs';
import {operationsFromRows, rowCoverage, alternativesOf, membersOf} from '../lib/access-closure.mjs';
import {validateAuthDefinition, normalizeAuthApp, effectiveScopes, fullLevelScopes} from '../contracts/auth-definition.mts';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const GOLDEN_PATH = 'test/fixtures/access/defaults.golden.json';
export const REVIEW_PATH = 'docs/F10.7-DEFAULTS-REVIEW.md';
export const RATCHET_PATH = 'test/fixtures/access/template-ratchet.json';
// What git must show committed before a sign-off: everything the table is read from, the golden, the ratchet and the review.
const COMMITTED_PATHS = ['catalog', 'test/fixtures/access', 'test/fixtures/auth-v1', REVIEW_PATH];
const NOTE = 'F10.7 defaults golden (docs/F10.7-BUILD-MAP.md part i). Per app: the table of what every permission does before anyone changes it, its dataHash (the hash of that table, which a sign-off binds) and a filesHash over its auth, permissions, proxy and routes files, for information. Written by node scripts/defaults-golden.mjs --write, which never signs. signedOff is written only by --sign, after Sami\'s explicit approval of that app.';
const PROVIDER_FILE = /^[a-z][a-z0-9-]{1,39}\.json$/, ROUTES_FILE = /^[a-z][a-z0-9-]*\.routes\.json$/, HASH = /^[a-f0-9]{64}$/;

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const readJson = file => JSON.parse(readFileSync(file, 'utf8'));
const readJsonIf = file => existsSync(file) ? readJson(file) : null;
const unique = list => [...new Set(list)].sort();
const byMember = (a, b) => a.member < b.member ? -1 : a.member > b.member ? 1 : 0;
const own = (value, key) => record(value) && Object.hasOwn(value, key) ? value[key] : undefined;
/** True when one named alternative is wholly held, as decisions read provider access. */
const named = (sets, held) => sets.some(set => set.length > 0 && set.every(scope => held.has(scope)));
const writeFile = (root, relative, text) => {const file = path.join(root, relative); mkdirSync(path.dirname(file), {recursive: true}); writeFileSync(file, text);};
const jsonText = value => `${JSON.stringify(value, null, 1)}\n`;

// ---- reading one root -----------------------------------------------------------------------------------------------------
/** The reviewed auth definitions under <root>/catalog/auth, validated, with the parsed files they came from. */
function authDefinitions(root) {
  const directory = path.join(root, 'catalog', 'auth'), out = new Map();
  if (!existsSync(directory)) return out;
  for (const name of readdirSync(directory).filter(item => PROVIDER_FILE.test(item)).sort()) {
    const raw = readJson(path.join(directory, name)), definition = validateAuthDefinition(raw);
    if (`${definition.providerId}.json` !== name) throw new Error(`catalog/auth/${name} must be named after its providerId.`);
    if (definition.reviewStatus === 'reviewed') out.set(definition.providerId, {definition, raw});
  }
  return out;
}

/** Every app a reviewed sign-in definition carries and a permissions file describes, in name order. */
export function catalogApps(root = ROOT) {
  const apps = [];
  for (const {definition} of authDefinitions(root).values()) for (const app of definition.apps) if (existsSync(path.join(root, 'catalog', 'permissions', `${app.appId}.json`))) apps.push(app.appId);
  return unique(apps);
}

/** One app's reviewed proxy settings, validated against its rows, and the parsed files they came from; none without a proxy file. */
function proxyFor(root, appId, groups) {
  const file = path.join(root, 'catalog', 'proxy', `${appId}.json`);
  if (!existsSync(file)) return {config: null, files: {}};
  const raw = readJson(file);
  if (own(raw, 'appId') !== appId) throw new Error(`catalog/proxy/${appId}.json must carry appId ${appId}.`);
  // The routes file name is checked before anything is read with it.
  const routesName = typeof raw.documentedRoutes === 'string' && ROUTES_FILE.test(raw.documentedRoutes) ? raw.documentedRoutes : null;
  const routes = routesName ? readJson(path.join(root, 'catalog', 'proxy', routesName)) : null;
  const catalog = readJsonIf(path.join(root, 'catalog', 'apps.json')) ?? [], entry = (Array.isArray(catalog) ? catalog : catalog.apps ?? []).find(item => item?.id === appId);
  const config = validateProxyConfig(raw, {groups: new Map([[appId, groups]]), allowedOrigins: entry?.apiOrigins || entry?.allowedOrigins, routes});
  return {config, files: {[`catalog/proxy/${appId}.json`]: raw, ...(routesName ? {[`catalog/proxy/${routesName}`]: routes} : {})}};
}

/** The facts-only fixtures a table reads: Discovery's scopes per method, and the version 1 sign-in the upgrade lists start from. */
function fixturesFor(root, providerId) {
  const facts = readJsonIf(path.join(root, 'test', 'fixtures', 'access', `${providerId}-method-scopes.json`));
  const v1 = readJsonIf(path.join(root, 'test', 'fixtures', 'auth-v1', `${providerId}.json`));
  return {facts, v1: v1 ? validateAuthDefinition(v1) : null};
}

/** Everything one app's table is computed from, read from <root> through the validators. */
export function loadApp(root, appId) {
  const found = [...authDefinitions(root).values()].find(({definition}) => definition.apps.some(app => app.appId === appId));
  if (!found) throw new Error(`No reviewed sign-in definition under ${path.join(root, 'catalog', 'auth')} carries ${appId}.`);
  const {definition, raw} = found, providerId = definition.providerId, rowsPath = `catalog/permissions/${appId}.json`;
  const rawRows = readJson(path.join(root, rowsPath)), groups = validatePermissionGroups(rawRows);
  if (groups.appId !== appId) throw new Error(`${rowsPath} must carry appId ${appId}.`);
  const proxy = proxyFor(root, appId, groups), {facts, v1} = fixturesFor(root, providerId);
  const catalog = readJsonIf(path.join(root, 'catalog', 'apps.json')) ?? [], entry = (Array.isArray(catalog) ? catalog : catalog.apps ?? []).find(item => item?.id === appId);
  return {appId, name: typeof entry?.name === 'string' ? entry.name : appId, providerId, definition, groups, config: proxy.config, facts, v1,
    files: {[`catalog/auth/${providerId}.json`]: raw, [rowsPath]: rawRows, ...proxy.files}};
}

// ---- the table ------------------------------------------------------------------------------------------------------------
/**
 * One app's defaults table, with no clock and no store.
 * - `signIn`: what sign-in asks for, at which version, under which consent policy, and what Fabric never asks for.
 * - `rows`, in catalog order: each row's declared, typed and raw defaults, raw modes, locks and flags, its members that stay typed,
 *   are reviewed reads, can never work (with the reason), cannot do their whole job or carry notes, its conditional scopes, and its
 *   access at sign-in (required and optional scopes), at full (plus in-context scopes) and with the required scopes only.
 * - `otherRows`: the raw rows for requests that match no permission. `unjustified`: scopes the full level asks for that no row uses.
 * - `upgrade`: the rows that start running on Allow after "Upgrade to full access", by the rule of upgradeCard() in lib/app-detail.mjs,
 *   from a version 1 read and write account, from an account holding the required scopes only, and from a read-only account.
 * The typed default is read for the row's own effect, so it is an upper bound: an operation that returns secrets asks instead.
 * @param {{appId: string, definition: any, groups: any, config?: any, facts?: any, v1?: any}} input
 */
export function defaultsTable({appId, definition, groups, config = null, facts = null, v1 = null}) {
  const entry = definition?.apps?.find(item => item.appId === appId);
  if (!entry || !Array.isArray(groups?.groups)) throw new Error(`No sign-in definition or permission rows for ${appId}.`);
  const app = normalizeAuthApp(definition, entry), full = app.levels.full, read = app.levels.read, identity = [...app.identityScopes], rows = groups.groups;
  // Discovery's facts where they name any scope, else the rows' own scope data, as the closure and the template check read them.
  const operations = operationsFromRows(rows, facts?.apps?.[appId]?.methods ?? null);
  const measure = scopes => rowCoverage({groups: rows, operations, granted: unique([...identity, ...scopes]), identityScopes: identity, neverRequest: app.neverRequest});
  const reports = {signIn: measure([...full.required, ...full.optional]), full: measure(fullLevelScopes(app)), required: measure([...full.required])};
  // The proxy's own rows give each row's raw default and the modes an owner may choose; an app with no proxy has no raw requests.
  const policy = new ProxyPolicy({store: null}), proxied = config ? new Map(policy.rows({config, definition: groups}).map(item => [item.row, item])) : null;
  const unavailableOf = group => record(group.unavailable) ? Object.entries(group.unavailable).map(([member, reason]) => ({member: memberKey(member), reason})).sort(byMember) : [];
  const table = rows.map((group, index) => {
    const proxyRow = proxied?.get(`group:${group.id}`) ?? null, members = new Set(membersOf(group));
    return {id: group.id, label: String(group.label).trim(), effect: group.effect, stayInAccount: group.stayInAccount === true,
      defaults: {declared: group.defaultMode, typed: groupDefault(group, {driver: 'http'}, group.effect), raw: proxyRow ? proxyRow.defaultMode : policy.rowDefault({row: `group:${group.id}`, group})},
      rawModes: proxyRow ? [...proxyRow.allowedModes] : null,
      locked: group.locked === 'fabric', audience: group.audience === true, proxyAllowable: Boolean(config?.proxyAllowable.includes(group.id)),
      members: members.size, typedMembers: (group.operations ?? []).length,
      typedOnly: config ? unique(config.typedOnly.filter(member => members.has(member))) : [],
      reviewedReads: unique((group.reviewedReads ?? []).map(memberKey)),
      unavailable: unavailableOf(group),
      unsupported: record(group.unsupported) ? Object.entries(group.unsupported).map(([member, words]) => ({member: memberKey(member), words})).sort(byMember) : [],
      conditions: record(group.conditions) ? Object.entries(group.conditions).map(([member, list]) => ({member: memberKey(member), conditions: unique(list)})).sort(byMember) : [],
      conditionalScopes: record(group.conditionalScopes) ? Object.fromEntries(Object.keys(group.conditionalScopes).sort().map(scope => [scope, group.conditionalScopes[scope]])) : {},
      // F10.9: shown only on a row that declares them, so a table without them keeps its bytes and its data hash.
      ...(record(group.bindContent) ? {bindContent: Object.entries(group.bindContent).map(([member, {kind, at}]) => ({member: memberKey(member), kind, at})).sort(byMember)} : {}),
      ...(record(group.sensitive) ? {sensitive: unique(Object.keys(group.sensitive).map(memberKey))} : {}),
      access: Object.fromEntries(Object.entries(reports).map(([key, report]) => {
        const row = report.rows[index];
        return [key, {status: row.status, covered: row.covered, missing: row.missing.length, cannotWork: row.cannotWork.length, noScopeData: row.noScopes.length + row.unmapped.length}];
      }))};
  });

  // upgradeCard(): a member is listed when it lacks provider access now, has no zero-scope alternative, gains access afterwards, and its
  // side defaults to Allow. A scope a granted parent grants is held, before and after. A member that can never work is never listed.
  const held = scopes => new Set(effectiveScopes(app, unique([...identity, ...scopes]))), after = held([...full.required, ...full.optional]);
  const listFrom = before => {
    const now = held(before);
    const gains = member => {const sets = alternativesOf(operations.get(member)); return sets.length > 0 && !sets.some(set => !set.length) && !named(sets, now) && named(sets, after);};
    return table.filter((row, index) => {
      const group = rows[index], off = new Set(row.unavailable.map(item => item.member)), usable = member => !off.has(member) && gains(member);
      if (row.locked) return false;
      const typed = row.defaults.typed === 'allow' && (group.operations ?? []).map(memberKey).some(usable);
      const raw = row.rawModes !== null && row.defaults.raw === 'allow' && membersOf(group).some(usable);
      return typed || raw;
    }).map(row => row.id);
  };
  const v1Entry = v1?.apps?.find(item => item.appId === appId), old = v1Entry ? normalizeAuthApp(v1, v1Entry) : null;

  return {
    signIn: {version: app.schemaVersion, grant: app.grant, consentPolicy: app.schemaVersion === 2 && record(definition.consentPolicy) ? {testing: definition.consentPolicy.testing, production: definition.consentPolicy.production} : null,
      identityScopes: identity, required: [...full.required], optional: [...full.optional], inContext: full.inContext.map(item => ({scope: item.scope, rows: [...item.rows]})),
      read: read ? {required: [...read.required], optional: [...read.optional]} : null, neverRequest: unique(app.neverRequest),
      implications: Object.fromEntries(Object.keys(app.implies).sort().map(parent => [parent, unique(app.implies[parent] ?? [])]))},
    rows: table,
    otherRows: proxied ? [...proxied.values()].filter(item => !item.group).map(item => ({row: item.row, label: item.label, effect: item.effect, default: item.defaultMode, modes: [...item.allowedModes]})) : [],
    unjustified: unique(reports.full.unjustified),
    upgrade: {fromV1ReadWrite: old ? listFrom([...old.identityScopes, ...fullLevelScopes(old)]) : null, fromRequired: listFrom([...full.required]), fromRead: read ? listFrom([...read.required, ...read.optional]) : null},
  };
}

/** Decision 2: what a sign-off binds, the hash of the app's canonical table. Key order and formatting never move it. */
export const dataHash = (appId, table) => canonicalHash({kind: 'fabric-defaults-table', version: 1, appId, table});
/** For information: the hash over each of the app's files, each parsed and hashed canonically. */
export const filesHash = (appId, files) => canonicalHash({kind: 'fabric-defaults-files', version: 1, appId, files});

/** One app's golden entry as the catalog under <root> gives it now, without any sign-off. */
export function appEntry(root, appId) {
  const app = loadApp(root, appId), table = defaultsTable(app);
  const files = Object.fromEntries(Object.keys(app.files).sort().map(file => [file, canonicalHash(app.files[file])]));
  return {name: app.name, provider: app.providerId, dataHash: dataHash(appId, table), filesHash: filesHash(appId, files), files, table};
}

/** The data hash of one app from data a caller already holds (the template check's definition, rows and facts), with the proxy
 *  settings and the version 1 fixture read from <root>. */
export function currentDataHash({root = ROOT, appId, definition, groups, facts = null}) {
  const {config} = proxyFor(root, appId, groups), {v1} = fixturesFor(root, definition.providerId);
  return dataHash(appId, defaultsTable({appId, definition, groups, config, facts, v1}));
}

// ---- sign-offs ------------------------------------------------------------------------------------------------------------
/** A real calendar day written YYYY-MM-DD, checked by a UTC round trip; no clock is read. */
export function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [year, month, day] = value.split('-').map(Number);
  return new Date(Date.UTC(year, month - 1, day)).toISOString().slice(0, 10) === value;
}
const nameProblem = by => typeof by !== 'string' || !by.trim() || by.length > 100 || /[\u0000-\u001f\u007f]/.test(by) ? 'the signer\'s name must be 1 to 100 characters on one line.'
  : by.includes('@') ? 'the signer is named, never given as an email address.' : null;
/** A sign-off record: exactly {by, date, dataHash}. */
export const validSignature = value => record(value) && Object.keys(value).sort().join() === 'by,dataHash,date' && !nameProblem(value.by) && validDate(value.date) && typeof value.dataHash === 'string' && HASH.test(value.dataHash);

export const readGolden = (root = ROOT) => readJsonIf(path.join(root, GOLDEN_PATH));

/**
 * Whether one app's defaults are signed (check 4): {state, pass, reason}. A sign-off counts only while it binds the table the data
 * gives now (`current`, a data hash or a function giving one; by default computed from <root>). When it does not, the words say whether
 * the data moved under a golden that still records the signed table, or the recorded table moved away from what was signed.
 */
export function goldenStatus(appId, {root = ROOT, golden = readGolden(root), current} = {}) {
  const entry = own(own(golden, 'apps'), appId);
  if (!record(entry)) return {state: 'missing', pass: false, reason: 'no owner-signed defaults table yet'};
  if (entry.signedOff === null || entry.signedOff === undefined) return {state: 'unsigned', pass: false, reason: 'the defaults table is not signed yet'};
  if (!validSignature(entry.signedOff)) return {state: 'unsigned', pass: false, reason: 'the defaults sign-off is not well formed, so it counts as none'};
  const now = typeof current === 'function' ? current() : current ?? appEntry(root, appId).dataHash;
  if (entry.signedOff.dataHash === now) return {state: 'signed', pass: true, reason: 'passes'};
  return entry.signedOff.dataHash === entry.dataHash ? {state: 'data-changed', pass: false, reason: 'the data changed since the owner signed the defaults'}
    : {state: 'table-changed', pass: false, reason: 'the table changed since the owner signed the defaults'};
}

/** What differs between the recorded golden (and the review document) and what the catalog under <root> gives now. Empty when current. */
export function goldenDifferences(root = ROOT) {
  const golden = readGolden(root);
  if (!record(golden) || !record(golden.apps)) return [`${GOLDEN_PATH} is missing or lists no apps`];
  const problems = [], apps = catalogApps(root);
  if (golden.schema !== 1) problems.push(`${GOLDEN_PATH}: schema must be 1`);
  if (Object.keys(golden.apps).join() !== apps.join()) problems.push(`the golden must list exactly ${apps.join(', ')}, in that order`);
  for (const appId of apps) {
    const entry = own(golden.apps, appId);
    if (!record(entry)) {problems.push(`${appId}: missing from the golden`); continue;}
    const now = appEntry(root, appId);
    for (const key of Object.keys(now)) if (!isDeepStrictEqual(entry[key], now[key])) problems.push(`${appId}: ${key} differs`);
    for (const key of Object.keys(entry)) if (!Object.hasOwn(now, key) && key !== 'signedOff' && key !== 'previousSignedOff') problems.push(`${appId}: unknown field ${key}`);
    if (!Object.hasOwn(entry, 'signedOff') || (entry.signedOff !== null && !validSignature(entry.signedOff))) problems.push(`${appId}: signedOff must be null or {by, date, dataHash}`);
    if (Object.hasOwn(entry, 'previousSignedOff') && !validSignature(entry.previousSignedOff)) problems.push(`${appId}: previousSignedOff must be {by, date, dataHash}`);
  }
  const review = path.join(root, REVIEW_PATH);
  if (!existsSync(review) || readFileSync(review, 'utf8') !== reviewText(golden)) problems.push(`${REVIEW_PATH} is not what the golden gives`);
  return problems;
}

/** Why an app's table fails T3 under its full level, in the template check's words; empty when it passes. */
export function t3Problems(table) {
  if (table?.signIn?.version !== 2) return [`the sign-in definition is version ${table?.signIn?.version}; T3 is measured under a version 2 full level`];
  const sum = key => table.rows.reduce((total, row) => total + row.access.full[key], 0), problems = [];
  if (sum('missing')) problems.push(`${sum('missing')} member(s) lack a scope`);
  if (sum('cannotWork')) problems.push(`${sum('cannotWork')} member(s) can never work and are not marked unavailable`);
  if (sum('noScopeData')) problems.push(`${sum('noScopeData')} member(s) have no scope data`);
  if (table.unjustified.length) problems.push(`unjustified scopes: ${table.unjustified.join(', ')}`);
  return problems;
}

/** Sets one app's `defaults` entry in the template ratchet, where the ratchet lists the app. */
function setRatchet(root, appId, value) {
  const file = path.join(root, RATCHET_PATH), ratchet = readJsonIf(file), entry = own(own(ratchet, 'apps'), appId);
  if (!record(entry) || entry.defaults === value) return;
  entry.defaults = value;
  writeFileSync(file, jsonText(ratchet));
}
/** One golden entry in its written key order, sign-offs first. */
const ordered = ({name, provider, signedOff, previousSignedOff, dataHash: hash, filesHash: files, files: list, table}) =>
  ({name, provider, signedOff, ...(previousSignedOff ? {previousSignedOff} : {}), dataHash: hash, filesHash: files, files: list, table});

/**
 * --write: the golden and the review document, as the catalog under <root> gives them now. It never creates a sign-off. A sign-off is
 * kept only while it binds the app's new data hash; otherwise it moves to previousSignedOff, the app's `defaults` check turns off in
 * the ratchet, and the messages say "Sami must sign <app> again".
 */
export function writeGolden({root = ROOT} = {}) {
  const previous = readGolden(root), messages = [], apps = {};
  for (const appId of catalogApps(root)) {
    const now = appEntry(root, appId), old = own(own(previous, 'apps'), appId);
    let signedOff = null, previousSignedOff = validSignature(own(old, 'previousSignedOff')) ? old.previousSignedOff : undefined;
    const signature = own(old, 'signedOff');
    if (validSignature(signature) && signature.dataHash === now.dataHash) signedOff = signature;
    else if (signature !== undefined && signature !== null) {
      if (validSignature(signature)) previousSignedOff = signature;
      messages.push(`Sami must sign ${appId} again`);
      setRatchet(root, appId, false);
    }
    apps[appId] = ordered({...now, signedOff, previousSignedOff});
  }
  const golden = {note: NOTE, schema: 1, apps};
  writeFile(root, GOLDEN_PATH, jsonText(golden));
  writeFile(root, REVIEW_PATH, reviewText(golden));
  return {golden, messages};
}

/** True when <root> is the top of a git work tree and git shows nothing uncommitted under the paths a sign-off rests on. */
export function treeCommitted(root) {
  const git = (...args) => spawnSync('git', ['-C', root, ...args], {encoding: 'utf8', shell: false});
  const top = git('rev-parse', '--show-toplevel');
  if (top.status !== 0) return false;
  try {if (realpathSync(top.stdout.trim()) !== realpathSync(root)) return false;} catch {return false;}
  const status = git('status', '--porcelain', '--untracked-files=all', '--', ...COMMITTED_PATHS);
  return status.status === 0 && status.stdout === '';
}

/**
 * --sign (decision 3): records {by, date, dataHash} for the named apps only, and turns their `defaults` check on in the ratchet. It
 * refuses unless the name and date are right, the golden and the review document are current, each app signs in with version 2 and
 * passes T3, each prefix is the first 12 characters of that app's data hash, and git shows the tree committed. Run only after Sami's
 * explicit approval of those apps. The review document is not touched: it ignores sign-offs (decision 4).
 * @param {{root?: string, apps: string[] | 'all', by: string, date: string, prefixes: Record<string, string>, committed?: (root: string) => boolean}} input
 */
export function signOff({root = ROOT, apps, by, date, prefixes = {}, committed = treeCommitted} = /** @type {any} */ ({})) {
  const refuse = message => {throw new Error(`Not signed: ${message}`);};
  const name = nameProblem(by);
  if (name) refuse(name);
  if (!validDate(date)) refuse(`${date} is not a real date written YYYY-MM-DD.`);
  const golden = readGolden(root);
  if (!record(golden) || !record(golden.apps)) refuse('there is no defaults golden; run node scripts/defaults-golden.mjs --write first.');
  const list = apps === 'all' || (Array.isArray(apps) && apps.length === 1 && apps[0] === 'all') ? Object.keys(golden.apps) : apps;
  if (!Array.isArray(list) || !list.length) refuse('Name the apps to sign, or all.');
  for (const appId of list) if (typeof appId !== 'string' || !record(own(golden.apps, appId))) refuse(`${appId} is not in the defaults golden.`);
  const stale = goldenDifferences(root);
  if (stale.length) refuse(`the defaults golden or the review document is not current (${stale.join('; ')}). Run node scripts/defaults-golden.mjs --write, review what changed and commit it first.`);
  for (const appId of list) {
    const {table, dataHash: hash} = golden.apps[appId];
    if (table.signIn.version !== 2) refuse(`${appId} signs in with version ${table.signIn.version}; only a version 2 sign-in definition is signed.`);
    const t3 = t3Problems(table);
    if (t3.length) refuse(`${appId} does not pass T3: ${t3.join('; ')}.`);
    const typed = typeof own(prefixes, appId) === 'string' ? prefixes[appId].toLowerCase() : '';
    if (typed !== hash.slice(0, 12)) refuse(`the prefix for ${appId} is not the first 12 characters of its data hash in ${REVIEW_PATH}.`);
  }
  if (!committed(root)) refuse(`git does not show the catalog, the golden and ${REVIEW_PATH} committed at ${root}.`);
  for (const appId of list) golden.apps[appId] = ordered({...golden.apps[appId], signedOff: {by: by.trim(), date, dataHash: golden.apps[appId].dataHash}});
  writeFile(root, GOLDEN_PATH, jsonText(golden));
  for (const appId of list) setRatchet(root, appId, true);
  return {signed: [...list]};
}

/** --check-signed, the merge guard: what keeps any app of a version 2 sign-in from being signed and current. Empty when none. */
export function checkSigned({root = ROOT} = {}) {
  const golden = readGolden(root), problems = goldenDifferences(root);
  for (const appId of catalogApps(root)) {
    const now = appEntry(root, appId);
    if (now.table.signIn.version !== 2) continue;
    const status = goldenStatus(appId, {root, golden, current: now.dataHash});
    if (!status.pass) problems.push(`${appId}: ${status.reason}`);
  }
  return problems;
}

// ---- the review document --------------------------------------------------------------------------------------------------
const WORD = {allow: 'Allow', ask: 'Ask', deny: 'Never'};
const SHORT_REASONS = {'service-account-only': 'service account only', 'workspace-cse-only': 'client-side encryption only', 'bot-token-only': 'bot token only',
  'client-credentials-only': 'app credentials only', 'no-oauth-scope': 'no sign-in permission covers it', 'not-requested': 'needs a permission Fabric never asks for'};
const POLICY = {full: 'the required and optional permissions', required: 'the required permissions only'};
const yes = value => value ? 'Yes' : 'No';
const code = list => list.map(item => `\`${item}\``).join(', ');
const scopeList = list => list.length ? code(list) : 'nothing';
const cell = text => String(text).replace(/\|/g, '\\|');

function defaultWords(row) {
  const {typed, raw} = row.defaults;
  if (row.rawModes === null) return WORD[typed];
  if (!row.typedMembers || typed === raw) return WORD[raw];
  return typed === 'allow' && raw === 'ask' ? 'Allow (raw requests ask)' : `${WORD[typed]} (raw requests: ${WORD[raw]})`;
}
function worksWords(row, pages) {
  if (row.locked) return 'Always off';
  const {full, signIn} = row.access, counts = new Map(), rest = [];
  for (const {reason} of row.unavailable) counts.set(reason, (counts.get(reason) ?? 0) + 1);
  for (const reason of [...counts.keys()].sort()) rest.push(`${SHORT_REASONS[reason] ?? reason} (${counts.get(reason)})`);
  if (full.missing) rest.push(`needs a permission sign-in does not ask for (${full.missing})`);
  if (full.cannotWork) rest.push(`needs a permission Fabric never asks for, and is not marked (${full.cannotWork})`);
  if (full.noScopeData) rest.push(`no scope data yet (${full.noScopeData})`);
  const later = full.covered - signIn.covered;
  if (!rest.length) return later > 0 ? 'Yes, after Add on this permission' : pages ? 'Yes, on the pages you share' : 'Yes';
  return `${full.covered} of ${row.members}${later > 0 ? ` (${later} after Add on this permission)` : ''}; the rest: ${rest.join(', ')}`;
}
function rawWords(row) {
  if (row.rawModes === null) return 'No raw requests';
  return yes(row.rawModes.includes('allow'));
}

function signInLines(entry) {
  const {signIn, rows} = entry.table, label = id => rows.find(row => row.id === id)?.label ?? id, lines = [];
  if (signIn.version !== 2) {
    lines.push(`- Version ${signIn.version} sign-in definition. Full access arrives when this step moves the definition to version 2. Until then a plain sign-in asks for the read set, and read and write access asks for more.`);
    lines.push(`- Read and write access asks for: ${scopeList(signIn.required)}.`);
    if (signIn.read) lines.push(`- Read-only access asks for: ${scopeList([...signIn.read.required, ...signIn.read.optional])}.`);
    lines.push('- A version 1 definition has no list of permissions Fabric never asks for.');
  } else if (signIn.grant === 'pages') {
    lines.push(`- Version 2 sign-in definition. Sign-in asks for no scopes: ${entry.name} shares only the pages the person picks.`);
  } else {
    lines.push(`- Version 2 sign-in definition, granting ${signIn.grant === 'user_scope' ? 'user scopes: Fabric acts as the person, not as a bot' : 'scopes'}.`);
    lines.push(`- Sign-in always asks for: ${scopeList(signIn.required)}.`);
    lines.push(`- Sign-in also asks for, where the provider lets the person decline them: ${scopeList(signIn.optional)}.`);
    if (signIn.inContext.length) lines.push(`- Asked for only from the permission that needs it: ${signIn.inContext.map(item => `\`${item.scope}\` (${item.rows.map(label).join(', ')})`).join('; ')}.`);
    lines.push(signIn.read ? `- Advanced read-only sign-in asks for: ${scopeList([...signIn.read.required, ...signIn.read.optional])}.` : '- There is no read-only sign-in.');
  }
  if (signIn.consentPolicy) lines.push(`- In Testing, sign-in asks for ${POLICY[signIn.consentPolicy.testing]}; in Production, ${POLICY[signIn.consentPolicy.production]}.`);
  if (signIn.version === 2) lines.push(`- Fabric never asks for: ${signIn.neverRequest.length ? code(signIn.neverRequest) : 'nothing listed'}. A sign-in that returns one of them is refused.`);
  if (signIn.identityScopes.length) lines.push(`- Every sign-in also asks for ${code(signIn.identityScopes)}, to know who signed in.`);
  const parents = Object.keys(signIn.implications);
  if (parents.length) lines.push(`- Scopes that grant others: ${parents.map(parent => `\`${parent}\` grants ${code(signIn.implications[parent])}`).join('; ')}.`);
  return lines;
}

/** F10.9: what a bound write carries, by kind, in words; each takes the header name or body pointer the row names. */
const BIND_WORDS = {etag: header => `the version tag read first, sent in the ${header} header`, sha: pointer => `the sha read first, sent at \`${pointer}\` in the body`,
  resend: pointer => `the content read first, sent again unchanged at \`${pointer}\` in the body`};

function appSection(appId, entry) {
  const {table} = entry, pages = table.signIn.grant === 'pages', label = id => table.rows.find(row => row.id === id)?.label ?? id;
  const labels = list => list === null ? null : list.length ? list.map(label).join('; ') : 'none';
  const v1 = table.upgrade.fromV1ReadWrite, lines = [`## ${entry.name} (\`${appId}\`)`, '', '**Sign-in**', '', ...signInLines(entry), ''];
  lines.push(`- Data hash: \`${entry.dataHash}\``, `- Sign with its first 12 characters: \`${entry.dataHash.slice(0, 12)}\``,
    `- Files hash, for information: \`${entry.filesHash}\`, over ${code(Object.keys(entry.files))}. It moves with any change to those files; only the data hash needs a new sign-off.`, '');
  lines.push('| Permission | Default | Locked by Fabric | Reaches other people | Raw requests can be set to Allow | Works with full access | Conditional scopes | Starts running on Allow after the upgrade |',
    '| --- | --- | --- | --- | --- | --- | --- | --- |');
  for (const row of table.rows) {
    const conditional = Object.keys(row.conditionalScopes);
    lines.push(`| ${cell(row.label)} (\`${row.id}\`) | ${defaultWords(row)} | ${yes(row.locked)} | ${yes(row.audience)} | ${rawWords(row)} | ${cell(worksWords(row, pages))} | ${conditional.length ? code(conditional) : 'None'} | ${v1 === null ? 'No earlier sign-in' : yes(v1.includes(row.id))} |`);
  }
  lines.push('');
  if (table.otherRows.length) {
    lines.push('Raw requests that match no permission above land in these rows:', '', '| Row | Default | Can be set to |', '| --- | --- | --- |');
    for (const row of table.otherRows) lines.push(`| ${cell(row.label)} | ${WORD[row.default]} | ${row.modes.map(mode => WORD[mode]).join(', ')} |`);
    lines.push('');
  }
  lines.push('**Upgrade lists**: the permissions that start running on Allow after "Upgrade to full access". The upgrade card lists them and asks before it starts.', '',
    `- From an account signed in before this step (version 1 read and write): ${labels(v1) ?? 'no earlier sign-in to compare'}.`,
    `- From an account that holds the required permissions only: ${labels(table.upgrade.fromRequired)}.`);
  if (table.upgrade.fromRead !== null) lines.push(`- From a read-only account: ${labels(table.upgrade.fromRead)}.`);
  if (table.signIn.version !== 2) lines.push('- A version 1 definition compares its own sets, so these lists say little until the move to version 2.');
  lines.push('');
  const never = new Map();
  for (const row of table.rows) for (const item of row.unavailable) never.set(item.reason, [...(never.get(item.reason) ?? []), item.member]);
  lines.push('**Operations that can never work through a sign-in**, by reason:', '');
  if (!never.size) lines.push('- None.');
  for (const reason of [...never.keys()].sort()) lines.push(`- ${String(UNAVAILABLE_REASONS[reason] ?? reason).replace(/\.$/, '')} (${never.get(reason).length}): ${code(never.get(reason))}.`);
  lines.push('');
  const unsupported = table.rows.flatMap(row => row.unsupported.map(item => `- \`${item.member}\` (${row.label}): ${item.words}`));
  if (unsupported.length) lines.push('**Operations that run but cannot do their whole job**:', '', ...unsupported, '');
  const notes = table.rows.flatMap(row => row.conditions.map(item => `- \`${item.member}\` (${row.label}): ${item.conditions.map(condition => CONDITION_WORDS[condition] ?? condition).join(' ')}`));
  if (notes.length) lines.push('**Notes on operations that still run**:', '', ...notes, '');
  const conditional = table.rows.flatMap(row => Object.entries(row.conditionalScopes).map(([scope, words]) => `- \`${scope}\` on ${row.label}: ${words}`));
  if (conditional.length) lines.push('**Conditional scopes**: needed only for some requests of a permission.', '', ...conditional, '');
  // F10.9: one line per member a row binds or marks sensitive, only when some row does.
  const bound = table.rows.flatMap(row => (row.bindContent ?? []).map(item => `- \`${item.member}\` (${row.label}): ${BIND_WORDS[item.kind](item.at.slice(item.at.indexOf(':') + 1))}.`));
  if (bound.length) lines.push('**Content binding**: a change through one of these must carry exactly what Fabric read first, so it never replaces a newer version (T5).', '', ...bound, '');
  const secret = table.rows.flatMap(row => (row.sensitive ?? []).map(member => `- \`${member}\` (${row.label})`));
  if (secret.length) lines.push('**Answers that can carry a secret**: an action with any step on one of these is sensitive, so it never defaults to Allow (T8).', '', ...secret, '');
  const typedOnly = table.rows.flatMap(row => row.typedOnly);
  if (typedOnly.length) lines.push(`**Typed only**: these run only as typed operations, and a raw request for one is refused: ${code(typedOnly)}.`, '');
  const asked = [...table.signIn.required, ...table.signIn.optional, ...table.signIn.inContext.map(item => item.scope)];
  if (table.unjustified.length) lines.push(`**Scopes full access asks for that no permission uses**: ${code(table.unjustified)}.`, '');
  else if (asked.length) lines.push('**Every scope full access asks for is used by a permission.**', '');
  return lines;
}

/** docs/F10.7-DEFAULTS-REVIEW.md, from the golden alone. It ignores signedOff and previousSignedOff, so signing leaves it as it is. */
export function reviewText(golden) {
  const apps = Object.entries(golden?.apps ?? {});
  const lines = ['# Defaults review (F10.7)', '',
    `This file is written by \`node scripts/defaults-golden.mjs --write\` from \`${GOLDEN_PATH}\`, and a test keeps the two equal. Do not edit it by hand.`, '',
    'It shows, for each app, what every permission does before anyone changes it. Sami reads it and signs the defaults app by app before access widens. Nothing is signed without his explicit approval, and signing changes nothing in this file.', '',
    '## How to read the tables', '',
    '- **Default**: what the permission does until the owner changes it. "Allow (raw requests ask)" means typed operations run on their own while raw requests through the proxy still ask. A typed default is an upper bound: an operation that returns keys or secrets, or a read named like a change, asks instead.',
    '- **Locked by Fabric**: Never for everyone, and no setting can change it.',
    '- **Reaches other people**: it sends, shares or invites, so it never defaults to Allow.',
    '- **Raw requests can be set to Allow**: whether the owner may let raw requests in this permission run without asking. "No raw requests" means the app has no proxy.',
    '- **Works with full access**: "Yes" when every operation works with what sign-in asks for; "Yes, on the pages you share" for a pages grant; "Yes, after Add on this permission" when it needs a permission asked for in context; otherwise how many operations work, and why the rest cannot; "Always off" for a locked permission.',
    '- **Conditional scopes**: a scope the permission needs only for some of its requests.',
    '- **Starts running on Allow after the upgrade**: whether an account signed in before this step (version 1 read and write) would start running this permission at Allow after "Upgrade to full access".', ''];
  for (const [appId, entry] of apps) lines.push(...appSection(appId, entry));
  const example = apps.map(([appId, entry]) => `--prefix ${appId}=${entry.dataHash.slice(0, 12)}`).join(' ');
  lines.push('## Signing', '',
    'Sami approves in chat, naming the apps, or runs the command himself. Either way it is this command, with one prefix per app taken from the sections above:', '',
    '```', 'node scripts/defaults-golden.mjs --sign --apps <app,app> --by <name> --date <YYYY-MM-DD> --prefix <app>=<its 12 characters>', '```', '',
    'For every app at once:', '', '```', `node scripts/defaults-golden.mjs --sign --apps all --by <name> --date <YYYY-MM-DD> ${example}`, '```', '',
    `The command refuses unless the name is 1 to 100 characters and not an email address, the date is a real day, this file and the golden are current, each app signs in with version 2 and every permission works under full access or says why not (T3), each prefix matches, and git shows the catalog, the golden and this file committed. It then writes \`signedOff: {by, date, dataHash}\` for those apps only, and turns their \`defaults\` check on in \`${RATCHET_PATH}\`.`, '',
    '## When Sami must sign again', '',
    '- `--write` keeps a sign-off only while the app\'s data hash is the one signed. Otherwise it moves the sign-off to `previousSignedOff`, turns the app\'s `defaults` check off, and prints "Sami must sign <app> again".',
    '- The data hash is the hash of the app\'s table. A change to its files that leaves the table as it is moves only the files hash, and the sign-off stays.',
    '- Steps known to edit these files: F10.9 (the action format and validator), F10.15 (Gmail\'s unsupported markers), F10.17 (GitHub\'s workflow guard and grant header), F10.19 (Notion\'s API version) and F10.21 (Slack\'s success check). Each needs a new sign-off when it changes what a table shows.',
    '- To see what changed since a sign-off, compare this file with its version in the sign-off commit.', '');
  return lines.join('\n');
}

// ---- the command line -----------------------------------------------------------------------------------------------------
const USAGE = 'Usage: node scripts/defaults-golden.mjs [--check | --write | --check-signed] [--root <dir>]\n       node scripts/defaults-golden.mjs --sign --apps <list|all> --by <name> --date <YYYY-MM-DD> --prefix <appId>=<12 characters> ... [--root <dir>]';
class UsageError extends Error {}
function parse(argv) {
  const options = {mode: null, root: ROOT, apps: null, by: null, date: null, prefixes: Object.create(null)};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index], value = () => {const next = argv[++index]; if (next === undefined || next.startsWith('--')) throw new UsageError(`${arg} needs a value.`); return next;};
    if (['--check', '--write', '--sign', '--check-signed'].includes(arg)) {if (options.mode) throw new UsageError('Choose one of --check, --write, --sign and --check-signed.'); options.mode = arg.slice(2);}
    else if (arg === '--root') options.root = path.resolve(value());
    else if (arg === '--apps') options.apps = value().split(',').map(item => item.trim()).filter(Boolean);
    else if (arg === '--by') options.by = value();
    else if (arg === '--date') options.date = value();
    else if (arg === '--prefix') {const [appId, prefix, ...more] = value().split('='); if (!appId || !prefix || more.length) throw new UsageError('--prefix is <appId>=<12 characters>.'); options.prefixes[appId] = prefix;}
    else if (arg === '--help' || arg === '-h') options.mode = 'help';
    else throw new UsageError(`Unknown argument: ${arg}`);
  }
  options.mode ??= 'check';
  if (options.mode === 'sign' && (!options.apps?.length || !options.by || !options.date || !Object.keys(options.prefixes).length)) throw new UsageError('--sign needs --apps, --by, --date and one --prefix per app.');
  return options;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parse(process.argv.slice(2));
    if (options.mode === 'help') console.log(USAGE);
    else if (options.mode === 'write') {
      const {golden, messages} = writeGolden({root: options.root});
      console.log(`Wrote ${GOLDEN_PATH} and ${REVIEW_PATH} (${Object.keys(golden.apps).length} apps). Nothing was signed.`);
      for (const message of messages) console.log(message);
    } else if (options.mode === 'sign') {
      const {signed} = signOff({root: options.root, apps: options.apps, by: options.by, date: options.date, prefixes: options.prefixes});
      console.log(`Signed the defaults of ${signed.join(', ')}. Commit ${GOLDEN_PATH} and ${RATCHET_PATH}, quoting the approval.`);
    } else {
      const problems = options.mode === 'check-signed' ? checkSigned({root: options.root}) : goldenDifferences(options.root);
      for (const problem of problems) console.error(problem);
      if (problems.length) {
        console.error(options.mode === 'check-signed' ? 'Not every app of a version 2 sign-in is signed and current.' : 'Run node scripts/defaults-golden.mjs --write, review what changed, and commit it.');
        process.exitCode = 1;
      } else if (options.mode === 'check-signed') {
        const signed = catalogApps(options.root).filter(appId => loadApp(options.root, appId).definition.schemaVersion === 2);
        console.log(signed.length ? `Every app of a version 2 sign-in is signed and current: ${signed.join(', ')}.` : 'No app signs in with version 2 yet, so there is nothing to sign.');
      } else console.log('The defaults golden and the review document are current.');
    }
  } catch (error) {
    console.error(error instanceof UsageError ? `${error.message}\n${USAGE}` : error.message);
    process.exitCode = error instanceof UsageError ? 2 : 1;
  }
}

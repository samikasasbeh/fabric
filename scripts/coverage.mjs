// F09.0 coverage harness (docs/F09-COMPILER-COVERAGE.md). Runs local API description files through the real discovery
// engine and compiler, and reports what compiles, why the rest does not, and each operation's capability id, scope
// sets and default permission mode. It never fetches: every source is a local file, and the discovery fetch is
// answered from that file.
//
//   node scripts/coverage.mjs <manifest.json> [--per-operation] [--json <out>] [--golden <file>] [--write-golden <file>] [--diff <earlier.json>]
//   node scripts/coverage.mjs --access <providerId>:<appId>:<level> [--scopes <method-scopes.json>] [--grant <scope,scope>] [--never <scope,scope>] [--json <out>]
//
// --access (F10.1) prints the access closure for one sign-in: which permission rows work, which members still lack a
// scope, which granted scopes nothing uses, and which members can never work. Per-method scopes come from a facts file
// (default test/fixtures/access/<providerId>-method-scopes.json when it exists); without one, members report no scope
// data. --grant replaces the level's scopes with an explicit list (identity scopes are always added). F10.7: <level> is full or read
// for a version 2 definition; a version 1 definition reads read and write, and full as write. The app's own never-request list
// applies unless --never replaces it (a version 1 app has none).
//
// A manifest is a JSON array of {appId, file, kind: 'openapi' | 'google-discovery', sourceUrl, apiOrigins}. Files
// resolve against the manifest's folder. --per-operation (OpenAPI only) also runs every operation alone, lifting only
// the whole-document limits, to show what paging would reach.
import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {DiscoveryEngine} from '../lib/discovery.mjs';
import {AcquisitionEngine} from '../lib/acquisition.mjs';
import {compileOpenApi} from '../lib/compiler.mjs';
import {operationDefault, operationSensitivity} from '../lib/permissions.mjs';
import {PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {closure, operationsFromRows} from '../lib/access-closure.mjs';
import {definitionFor} from '../lib/providers/definitions.mjs';

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const METHODS = ['get', 'head', 'post', 'put', 'patch', 'delete', 'options', 'trace', 'query'];

/** Just enough of the store for discovery and candidate saving, in memory. */
class MemoryStore {
  #rows = new Map();
  #collection(name) { if (!this.#rows.has(name)) this.#rows.set(name, new Map()); return this.#rows.get(name); }
  get(collection, id) { const row = this.#collection(collection).get(id); return row === undefined ? undefined : structuredClone(row); }
  put(collection, row) { this.#collection(collection).set(row.id, structuredClone(row)); return row; }
  list(collection) { return [...this.#collection(collection).values()].map(row => structuredClone(row)); }
  delete(collection, id) { this.#collection(collection).delete(id); }
  audit() {}
}

/** Groups a refusal into a stable class, dropping operation labels and names. */
export function failureClass(reason = '') {
  const text = String(reason).replace(/^Skipped [A-Z]+ \S+: /, '');
  const rules = [
    [/OpenAPI 3\.x JSON document/, 'version: not OpenAPI 3.x'],
    [/exceeds 256 operation limit|exceeds 500 documented methods/, 'limit: operation count'],
    [/size limit|exceeds \d+ bytes|nesting or size limit/, 'limit: document size'],
    [/not supported by the bearer-credential broker/, 'auth: scheme not servable'],
    [/Missing security scheme/, 'auth: undefined scheme'],
    [/Only path\/query parameters are supported/, 'parameter: header or cookie'],
    [/single application\/json request body/, 'body: media type'],
    [/request bodies are unsupported/, 'body: on GET or HEAD'],
    [/unsupported schema keyword (oneOf|anyOf|allOf|not|nullable|pattern)\b/, 'schema: $1'],
    [/unsupported schema keyword (x-\S+|example|examples|deprecated|readOnly|writeOnly|xml|discriminator|externalDocs)\b/, 'schema: annotation'],
    [/unsupported schema keyword/, 'schema: other keyword'],
    [/one explicit supported type is required/, 'schema: type missing or a type array'],
    [/recursive schemas|Reference cycle/, 'schema: recursion'],
    [/additionalProperties:false|dynamic input property maps/, 'schema: map'],
    [/unsupported format|format does not match|integer format|cannot be enforced/, 'schema: format'],
    [/pattern constraints/, 'schema: pattern'],
    [/credential-bearing parameter|transport\/authentication parameter|carries a credential/, 'parameter: credential-shaped name'],
    [/exchanges credentials/, 'auth: credential exchange'],
    [/credentials and credential exchanges are not agent inputs/, 'schema: credential-shaped input'],
    [/Unsupported parameter (style|explode|encoding)|must be primitive/, 'parameter: serialization'],
    [/placeholders must occupy|path placeholders do not match/, 'path: template shape'],
    [/Per-path\/operation servers|Exactly one fixed OpenAPI server|public DNS hostname|encoded or traversing paths|outside the selected application|Relative OpenAPI server|credential-free HTTPS/, 'url: server or path'],
    [/Invalid capability name/, 'metadata: blank name'],
    [/schema expansion exceeds|referenced metadata exceeds|Too many referenced|overly deep/, 'limit: schema size'],
    [/\$ref siblings|reference siblings|internal JSON Pointer|internal component references|internal OpenAPI references|Missing OpenAPI reference/, 'reference: shape'],
  ];
  for (const [pattern, label] of rules) { const match = text.match(pattern); if (match) return label.replace('$1', match[1] ?? ''); }
  return `other: ${text.slice(0, 80)}`;
}

/** One operation alone in its own document, with the components it references and the security schemes. */
export function singleOperationDocument(document, operationPath, method) {
  const pathItem = document.paths[operationPath];
  const item = {...(pathItem.parameters ? {parameters: pathItem.parameters} : {}), ...(pathItem.servers ? {servers: pathItem.servers} : {}), [method]: pathItem[method]};
  const result = {openapi: document.openapi, info: {title: 'One operation', version: '1'}, paths: {[operationPath]: item}};
  if (document.servers) result.servers = document.servers;
  if (document.security) result.security = document.security;
  const components = {}, seen = new Set();
  const walk = value => {
    if (Array.isArray(value)) { value.forEach(walk); return; }
    if (!record(value)) return;
    if (typeof value.$ref === 'string' && value.$ref.startsWith('#/components/')) {
      const [, , section, name] = value.$ref.split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'));
      if (!seen.has(`${section}/${name}`)) {
        seen.add(`${section}/${name}`);
        const target = document.components?.[section]?.[name];
        if (target !== undefined) { (components[section] ||= {})[name] = target; walk(target); }
      }
    }
    for (const [key, child] of Object.entries(value)) if (key !== '$ref') walk(child);
  };
  walk(result.paths);
  if (document.components?.securitySchemes) components.securitySchemes = document.components.securitySchemes;
  if (Object.keys(components).length) result.components = components;
  return result;
}

function defaultMode(store, appId, operation) {
  const capability = operation.capabilityId ? store.get('capabilities', operation.capabilityId) : null;
  return capability ? operationDefault(PERMISSION_GROUPS, capability, operation, operationSensitivity(capability, operation, store.get('applicationMaps', appId))) : null;
}

async function discover({appId, document, kind, sourceUrl, apiOrigins, rawBytes}) {
  const store = new MemoryStore(), catalog = () => [{id: appId, name: appId, discovery: {kind, url: sourceUrl}, apiOrigins}];
  const acquisition = new AcquisitionEngine({store, catalog, modelUrl: null, modelKey: null, modelName: null, request: async () => { throw new Error('The coverage harness makes no model calls.'); }});
  const request = async ({maxBytes}) => {
    if (rawBytes > maxBytes) throw new Error(`Provider response exceeded the size limit (${rawBytes} > ${maxBytes} bytes).`);
    return {status: 200, headers: {'content-type': 'application/json'}, data: structuredClone(document)};
  };
  try {
    const map = await new DiscoveryEngine({store, catalog, acquisition, request}).discover({appId});
    return {map, store};
  } catch (error) { return {error: error.message, store}; }
}

const summarize = (operations, store, appId) => operations.map(operation => ({
  id: operation.id, method: operation.method, path: operation.path, support: operation.support, capabilityId: operation.capabilityId,
  scopeSets: operation.scopeSets, defaultMode: defaultMode(store, appId, operation), sensitive: operation.sensitive ?? null,
  ...(operation.support === 'candidate' ? {} : {failure: failureClass(operation.reason), reason: String(operation.reason || '').slice(0, 300)}),
}));

/**
 * Coverage of one API description through today's code.
 * @param {{appId: string, document: Record<string, unknown>, kind?: 'openapi' | 'google-discovery', sourceUrl: string, apiOrigins: string[], rawBytes?: number}} spec
 * @param {{perOperation?: boolean}} [options]
 */
export async function runCoverage(spec, {perOperation = false} = {}) {
  const {appId, document, kind = 'openapi', sourceUrl, apiOrigins} = spec;
  const rawBytes = spec.rawBytes ?? Buffer.byteLength(JSON.stringify(document));
  const result = {appId, kind};
  if (kind === 'openapi') {
    try { result.direct = {capabilityIds: compileOpenApi({appId, document}).capabilities.map(capability => capability.id).sort()}; }
    catch (error) { result.direct = {error: failureClass(error.message), reason: error.message.slice(0, 300)}; }
  }
  const whole = await discover({appId, document, kind, sourceUrl, apiOrigins, rawBytes});
  result.discovery = whole.error ? {error: failureClass(whole.error), reason: whole.error.slice(0, 300)} : {classifierVersion: whole.map.classifierVersion ?? null, operations: summarize(whole.map.operations, whole.store, appId)};
  if (perOperation && kind === 'openapi' && typeof document.openapi === 'string' && record(document.paths)) {
    const operations = [];
    for (const [operationPath, item] of Object.entries(document.paths)) {
      if (!record(item)) continue;
      for (const method of METHODS) {
        if (!record(item[method])) continue;
        const single = await discover({appId, document: singleOperationDocument(document, operationPath, method), kind, sourceUrl, apiOrigins, rawBytes: 0});
        if (single.error) operations.push({id: item[method].operationId || `${method.toUpperCase()} ${operationPath}`, method: method.toUpperCase(), path: operationPath, support: 'unsupported', failure: failureClass(single.error), reason: single.error.slice(0, 300)});
        else operations.push(...summarize(single.map.operations, single.store, appId));
      }
    }
    result.perOperation = {operations};
  }
  return result;
}

/** Totals by support and by first failure class. */
export function tally(operations = []) {
  const counts = {total: operations.length, candidate: 0, unsupported: 0, failures: {}};
  for (const operation of operations) {
    counts[operation.support === 'candidate' ? 'candidate' : 'unsupported']++;
    if (operation.failure) counts.failures[operation.failure] = (counts.failures[operation.failure] || 0) + 1;
  }
  return counts;
}

/**
 * What changed between two saved runs (each from --json), per app: operations that stopped compiling, changed id or
 * default mode, or started compiling. Every lost or changed entry needs a listed reason (I1); growth needs none.
 */
export function diffRuns(before, after) {
  const operations = result => result?.perOperation?.operations || result?.discovery?.operations || [];
  const key = operation => `${operation.method} ${operation.path} ${operation.id}`;
  const report = {};
  for (const earlier of before) {
    const later = after.find(item => item.appId === earlier.appId);
    const now = new Map(operations(later).map(operation => [key(operation), operation]));
    const was = new Map(operations(earlier).map(operation => [key(operation), operation]));
    const entry = {lost: [], idChanged: [], defaultChanged: [], sensitiveChanged: [], gained: []};
    for (const [name, operation] of was) {
      if (operation.support !== 'candidate') continue;
      const current = now.get(name);
      if (current?.support !== 'candidate') entry.lost.push({operation: name, failure: current?.failure ?? 'missing', reason: current?.reason ?? null});
      else {
        if (current.capabilityId !== operation.capabilityId) entry.idChanged.push({operation: name});
        if (current.defaultMode !== operation.defaultMode) entry.defaultChanged.push({operation: name, from: operation.defaultMode, to: current.defaultMode, sensitive: current.sensitive ?? null});
        else if ((current.sensitive ?? null) !== (operation.sensitive ?? null)) entry.sensitiveChanged.push({operation: name, from: operation.sensitive ?? null, to: current.sensitive ?? null});
      }
    }
    for (const [name, operation] of now) if (operation.support === 'candidate' && was.get(name)?.support !== 'candidate') entry.gained.push({operation: name});
    report[earlier.appId] = entry;
  }
  return report;
}

/** Reads a manifest of local files. URLs are refused: the harness never fetches. */
export async function loadManifest(manifestPath) {
  const entries = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (!Array.isArray(entries)) throw new Error('A coverage manifest is a JSON array.');
  const folder = path.dirname(path.resolve(manifestPath));
  return Promise.all(entries.map(async entry => {
    if (!record(entry) || typeof entry.appId !== 'string' || typeof entry.file !== 'string' || !Array.isArray(entry.apiOrigins) || typeof entry.sourceUrl !== 'string') throw new Error('Each manifest entry needs appId, file, sourceUrl and apiOrigins.');
    if (/^[a-z][a-z0-9+.-]*:/i.test(entry.file)) throw new Error(`${entry.file}: the coverage harness reads local files only and never fetches.`);
    const text = await readFile(path.resolve(folder, entry.file), 'utf8');
    return {appId: entry.appId, kind: entry.kind || 'openapi', sourceUrl: entry.sourceUrl, apiOrigins: entry.apiOrigins, document: JSON.parse(text), rawBytes: Buffer.byteLength(text)};
  }));
}

/** The access closure report for `providerId:appId:level` (F10.1), from local files only. F10.7: `never` defaults to the app's own
 *  never list, and `definition` (for tests) stands in for the catalog's sign-in definition. */
export async function accessReport(target, {scopesFile, grant, never, definition} = {}) {
  const [providerId, appId, level] = String(target).split(':');
  if (!providerId || !appId || !level) throw new Error('--access needs <providerId>:<appId>:<level>, for example google:gmail:full.');
  const signIn = definition ?? definitionFor(providerId), groups = PERMISSION_GROUPS.get(appId)?.groups;
  if (!groups) throw new Error(`No permission rows for ${appId}.`);
  const file = scopesFile || fileURLToPath(new URL(`../test/fixtures/access/${providerId}-method-scopes.json`, import.meta.url));
  const facts = await readFile(file, 'utf8').then(JSON.parse, error => { if (scopesFile || error.code !== 'ENOENT') throw error; return null; });
  const methods = facts?.apps?.[appId]?.methods;
  // Discovery's facts where they name any scope, else the rows' own scope data (F10.6), every member by its member key.
  const operations = operationsFromRows(groups, methods ?? null);
  return closure({definition: signIn, appId, level, scopes: grant, groups, operations, neverRequest: never});
}

const list = value => value === undefined ? undefined : value.split(',').map(item => item.trim()).filter(Boolean);

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.argv.includes('--access')) {
  const args = process.argv.slice(2), option = name => { const at = args.indexOf(name); return at < 0 ? undefined : args[at + 1]; };
  const report = await accessReport(option('--access'), {scopesFile: option('--scopes'), grant: list(option('--grant')), never: list(option('--never'))});
  const {summary} = report;
  console.log(`${report.appId} (${report.level}): ${summary.works} of ${summary.rows} rows work, ${summary.partial} partial, ${summary.blocked} blocked${summary.unknown ? `, ${summary.unknown} with no scope data yet` : ''}${summary.locked ? `, ${summary.locked} locked` : ''}${summary.unavailable ? `, ${summary.unavailable} unavailable` : ''}; ${summary.coveredMembers} of ${summary.members} members covered${summary.unavailableMembers ? `, ${summary.unavailableMembers} never work through a sign-in` : ''}`);
  for (const row of report.rows.filter(item => item.status !== 'works')) {
    console.log(`  ${row.status.padEnd(7)} ${row.id} (${row.covered}/${row.total}) ${row.label}`);
    for (const item of row.missing) console.log(`    missing      ${item.member}: any of ${item.alternatives.map(alternative => alternative.join(' + ')).join(' | ')}`);
    for (const item of row.cannotWork) console.log(`    cannot work  ${item.member}: needs ${item.alternatives.map(alternative => alternative.join(' + ')).join(' | ')}`);
    for (const member of row.unmapped) console.log(`    unmapped     ${member}`);
    for (const item of row.unavailable) console.log(`    unavailable  ${item.member}: ${item.reason}`);
    if (row.noScopes.length) console.log(`    no scope data for ${row.noScopes.length} member(s)`);
  }
  console.log(report.unjustified.length ? `Unjustified scopes: ${report.unjustified.join(', ')}` : 'Unjustified scopes: none');
  if (option('--json')) await writeFile(option('--json'), `${JSON.stringify(report, null, 1)}\n`);
} else if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), option = name => { const at = args.indexOf(name); return at < 0 ? undefined : args[at + 1]; };
  const manifest = args.find((arg, index) => !arg.startsWith('--') && !['--json', '--golden', '--write-golden', '--diff'].includes(args[index - 1]));
  if (!manifest) { console.error('Usage: node scripts/coverage.mjs <manifest.json> [--per-operation] [--json <out>] [--golden <file>] [--write-golden <file>]'); process.exit(2); }
  const results = [];
  for (const spec of await loadManifest(manifest)) {
    const result = await runCoverage(spec, {perOperation: args.includes('--per-operation')});
    results.push(result);
    const whole = result.discovery.operations ? tally(result.discovery.operations) : null, single = result.perOperation ? tally(result.perOperation.operations) : null;
    console.log(`${spec.appId}: discovery ${whole ? `${whole.candidate}/${whole.total}` : `refused (${result.discovery.error})`}${single ? `, per operation ${single.candidate}/${single.total}` : ''}${result.direct ? `, direct ${result.direct.capabilityIds ? result.direct.capabilityIds.length : `refused (${result.direct.error})`}` : ''}`);
    for (const [failure, count] of Object.entries((single || whole)?.failures || {}).sort((a, b) => b[1] - a[1]).slice(0, 8)) console.log(`  ${String(count).padStart(5)}  ${failure}`);
  }
  if (option('--json')) await writeFile(option('--json'), `${JSON.stringify(results, null, 1)}\n`);
  if (option('--diff')) {
    for (const [appId, entry] of Object.entries(diffRuns(JSON.parse(await readFile(option('--diff'), 'utf8')), results))) {
      console.log(`${appId}: lost ${entry.lost.length}, id changed ${entry.idChanged.length}, default changed ${entry.defaultChanged.length}, sensitivity changed ${entry.sensitiveChanged.length}, gained ${entry.gained.length}`);
      for (const item of entry.lost) console.log(`  lost     ${item.operation} (${item.failure})`);
      for (const item of entry.idChanged) console.log(`  id       ${item.operation}`);
      for (const item of entry.defaultChanged) console.log(`  default  ${item.operation}: ${item.from} -> ${item.to}${item.sensitive ? ` (${item.sensitive})` : ''}`);
      for (const item of entry.sensitiveChanged) console.log(`  row      ${item.operation}: ${item.from ?? 'none'} -> ${item.to ?? 'none'} (moves to its own row)`);
    }
  }
  const ids = Object.fromEntries(results.map(result => [result.appId, [...new Set([...(result.discovery.operations || []), ...(result.perOperation?.operations || [])].map(operation => operation.capabilityId).filter(Boolean))].sort()]));
  if (option('--write-golden')) await writeFile(option('--write-golden'), `${JSON.stringify(ids, null, 1)}\n`);
  if (option('--golden')) {
    const golden = JSON.parse(await readFile(option('--golden'), 'utf8'));
    let lost = 0;
    for (const [appId, expected] of Object.entries(golden)) {
      const missing = expected.filter(id => !(ids[appId] || []).includes(id));
      lost += missing.length;
      for (const id of missing) console.log(`  missing ${appId} ${id}`);
    }
    if (lost) { console.error(`${lost} capability ids changed or disappeared (zero churn, docs/F09-COMPILER-COVERAGE.md I1).`); process.exitCode = 1; }
  }
}

// F10.11 part a (docs/F10.11-BUILD-MAP.md part a): Google's method paths, as facts. Gmail and Calendar are reviewed by method id, so an
// action step on them places only through an application map that gives each reviewed method its HTTP method and path. This command
// records those two facts per reviewed method from Google's public Discovery documents into test/fixtures/access/google-method-paths.json,
// beside the scope facts of test/fixtures/access/google-method-scopes.json, which it reads and never writes: those feed the signed
// defaults, and a change to them goes to Sami.
//
//   node scripts/google-method-paths.mjs            checks the committed file, offline (exit 1 with what is wrong)
//   node scripts/google-method-paths.mjs --record   reads the two public Discovery documents and writes the file
//
// --record is the only network path: a GET of each source in the scope facts, with Accept: application/json, one allowed origin, 30
// seconds and 4 MiB, and no Authorization header, API key, cookie or environment value. The check makes no request.
import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseTemplate, PERMISSION_GROUPS} from '../lib/permission-groups.mjs';
import {PROXY_CONFIGS} from '../lib/proxy-config.mjs';
import {templatesFor} from '../lib/proxy-match.mjs';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const PATHS_FILE = 'test/fixtures/access/google-method-paths.json';
export const SCOPES_FILE = 'test/fixtures/access/google-method-scopes.json';
/** The apps reviewed by Google method id, in file order. */
export const GOOGLE_APPS = Object.freeze(['gmail', 'google-calendar']);
/** The revision of Google's Discovery documents the scope facts were read at. */
export const SCOPES_REVISION = '20261005';
const NOTE = 'The HTTP method and path Google documents for each reviewed Gmail and Calendar method, recorded from the public Discovery documents by node scripts/google-method-paths.mjs --record. Facts only; not the documents themselves. The scope facts stay in google-method-scopes.json.';
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const MAX_BYTES = 4 * 1024 * 1024;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = message => { throw new Error(message); };
const byText = (a, b) => a < b ? -1 : a > b ? 1 : 0;

/** The method ids an app's reviewed rows name, sorted (79 for Gmail, 38 for Calendar). */
export function reviewedIds(appId, groups = PERMISSION_GROUPS) {
  const definition = groups.get(appId);
  if (!definition) fail(`${appId} has no reviewed permission rows.`);
  return [...new Set(definition.groups.flatMap(group => group.operations ?? []))].sort(byText);
}

/** Every method of a Discovery document with its resource path, walked as lib/discovery.mjs googleMethods() walks it. */
function documentMethods(document) {
  const entries = [];
  function visit(node, depth = 0) {
    if (!object(node) || depth > 24) fail('Malformed or overly nested Google resources.');
    if (node.methods !== undefined && !object(node.methods)) fail('Google methods must be an object.');
    for (const method of Object.values(node.methods || {})) entries.push(method);
    if (node.resources !== undefined && !object(node.resources)) fail('Google resources must be an object.');
    for (const child of Object.values(node.resources || {})) visit(child, depth + 1);
  }
  visit(document);
  return entries;
}

/**
 * The method and path of each reviewed id in one Discovery document: {revision, methods: {<id>: {method, path}}}, ids sorted. The method
 * is httpMethod upper-cased and the path is '/' plus `path` (never `flatPath`), as a stored application map holds them
 * (lib/discovery.mjs googleOperation()). Refuses a document that is not a v1 REST Discovery document, an id listed twice, a reviewed id
 * the document lacks, a method other than GET, POST, PUT, PATCH and DELETE, a path outside the app's proxy path prefixes and a path
 * parseTemplate() cannot read. Methods nobody reviewed are ignored.
 */
export function methodPaths(document, ids, {prefixes}) {
  if (!object(document) || document.kind !== 'discovery#restDescription' || document.discoveryVersion !== 'v1' || document.protocol !== 'rest') fail('Source is not a supported Google REST Discovery document.');
  if (!Array.isArray(ids) || !ids.length || !ids.every(id => typeof id === 'string' && id)) fail('Name the reviewed method ids.');
  if (!Array.isArray(prefixes) || !prefixes.length) fail('Name the app\'s proxy path prefixes.');
  const reviewed = new Set(ids), seen = new Set(), methods = {};
  for (const raw of documentMethods(document)) {
    if (!object(raw) || typeof raw.id !== 'string' || !raw.id || raw.id.length > 512) fail('A Google Discovery method lacks a bounded method id.');
    if (seen.has(raw.id)) fail(`The Discovery document lists ${raw.id} twice.`);
    seen.add(raw.id);
    if (!reviewed.has(raw.id)) continue;
    const method = typeof raw.httpMethod === 'string' ? raw.httpMethod.toUpperCase() : '';
    if (!METHODS.has(method)) fail(`${raw.id}: ${method || 'no method'} is not GET, POST, PUT, PATCH or DELETE.`);
    if (typeof raw.path !== 'string' || !raw.path || raw.path.length > 2048) fail(`${raw.id}: the method has no path.`);
    const location = `/${raw.path.replace(/^\//, '')}`;
    if (!prefixes.some(prefix => location.startsWith(prefix))) fail(`${raw.id}: ${location} is outside the app's proxy path prefixes (${prefixes.join(', ')}).`);
    try { parseTemplate(`${method} ${location}`); } catch (error) { fail(`${raw.id}: ${error.message}`); }
    methods[raw.id] = {method, path: location};
  }
  const missing = ids.filter(id => !Object.hasOwn(methods, id));
  if (missing.length) fail(`The Discovery document lacks ${missing.length} reviewed method(s): ${missing.slice(0, 5).join(', ')}${missing.length > 5 ? ', ...' : ''}.`);
  return {revision: typeof document.revision === 'string' ? document.revision : null, methods: Object.fromEntries(Object.keys(methods).sort(byText).map(id => [id, methods[id]]))};
}

/**
 * The application map of one app built from the two fact files, in the shape DiscoveryEngine stores (lib/discovery.mjs):
 * {id, appId, operations: [{id, method, path, requiredScopes, scopeSets}]}, by id. null when the paths file has no entry for the app.
 * Scopes come only from the scope facts, each scope its own alternative, as the access-closure tests read them.
 */
export function methodMap(paths, scopes, appId) {
  const entry = paths?.apps?.[appId];
  if (!object(entry) || !object(entry.methods)) return null;
  const facts = object(scopes?.apps?.[appId]?.methods) ? scopes.apps[appId].methods : {};
  const operations = Object.keys(entry.methods).sort(byText).map(id => {
    const required = Array.isArray(facts[id]) ? [...facts[id]] : [];
    return {id, method: entry.methods[id].method, path: entry.methods[id].path, requiredScopes: required, scopeSets: required.map(scope => [scope])};
  });
  return {id: appId, appId, operations};
}

/** The bytes the file is written with: 1-space indent and a final newline. */
export const serialize = value => `${JSON.stringify(value, null, 1)}\n`;
const readJson = file => JSON.parse(readFileSync(file, 'utf8'));

/** What is wrong with a parsed paths file, read against the reviewed rows, the proxy settings and the scope facts; empty when nothing is. */
export function checkPaths(paths, scopes, {groups = PERMISSION_GROUPS, configs = PROXY_CONFIGS} = {}) {
  const problems = [];
  if (!object(paths) || Object.keys(paths).sort(byText).join() !== 'apps,note' || typeof paths.note !== 'string' || !object(paths.apps)) return ['The file holds exactly note and apps.'];
  if (Object.keys(paths.apps).join() !== GOOGLE_APPS.join()) problems.push(`apps lists exactly ${GOOGLE_APPS.join(' and ')}, in that order.`);
  for (const appId of GOOGLE_APPS) {
    const entry = paths.apps[appId], prefixes = configs.get(appId)?.pathPrefixes ?? [];
    if (!object(entry) || Object.keys(entry).join() !== 'source,revision,methods' || !object(entry.methods)) { problems.push(`${appId} is {source, revision, methods}.`); continue; }
    if (entry.source !== scopes?.apps?.[appId]?.source) problems.push(`${appId}: source is not the scope facts' source.`);
    if (typeof entry.revision !== 'string' || !/^[0-9]{8}$/.test(entry.revision)) problems.push(`${appId}: revision is the eight-digit revision Google served.`);
    const ids = Object.keys(entry.methods), expected = reviewedIds(appId, groups), facts = Object.keys(scopes?.apps?.[appId]?.methods ?? {}).sort(byText);
    if (ids.join() !== [...ids].sort(byText).join()) problems.push(`${appId}: method ids are sorted.`);
    if ([...ids].sort(byText).join() !== expected.join()) problems.push(`${appId}: the method ids are not exactly the ${expected.length} reviewed ones.`);
    if ([...ids].sort(byText).join() !== facts.join()) problems.push(`${appId}: the method ids are not exactly the scope facts' ids.`);
    for (const [id, fact] of Object.entries(entry.methods)) {
      if (!object(fact) || Object.keys(fact).join() !== 'method,path' || !METHODS.has(fact.method) || typeof fact.path !== 'string') { problems.push(`${appId}: ${id} is {method, path} with one of the five methods.`); continue; }
      if (!prefixes.some(prefix => fact.path.startsWith(prefix))) problems.push(`${appId}: ${id} is outside the proxy path prefixes.`);
      try { parseTemplate(`${fact.method} ${fact.path}`); } catch (error) { problems.push(`${appId}: ${id}: ${error.message}`); }
    }
    if (!problems.length && !templatesFor(groups.get(appId), configs.get(appId), methodMap(paths, scopes, appId))) problems.push(`${appId}: the map built from the file does not place the reviewed rows.`);
  }
  return problems;
}

/** Each reviewed method whose served scopes differ from the scope facts, as lines to print. */
export function scopeDifferences(document, ids, recorded) {
  const served = new Map(documentMethods(document).filter(raw => object(raw) && typeof raw.id === 'string').map(raw => [raw.id, Array.isArray(raw.scopes) ? [...raw.scopes].sort(byText) : []]));
  return ids.filter(id => (served.get(id) ?? []).join(' ') !== [...(recorded?.[id] ?? [])].sort(byText).join(' '))
    .map(id => `${id}: served ${(served.get(id) ?? []).join(', ') || 'no scopes'}; recorded ${(recorded?.[id] ?? []).join(', ') || 'no scopes'}`);
}

/**
 * The only network path. Reads each app's public Discovery document with `request` (the network seam, safeRequest by default), builds
 * the file and writes it. Returns {paths, differences}: `differences` lists each reviewed method whose served scopes differ from the
 * scope facts, which this never changes.
 */
export async function recordPaths({root = ROOT, request} = {}) {
  const send = request ?? (await import('../lib/network.mjs')).safeRequest;
  const scopes = readJson(path.join(root, SCOPES_FILE)), apps = {}, differences = [];
  for (const appId of GOOGLE_APPS) {
    const source = new URL(scopes.apps[appId].source), ids = reviewedIds(appId);
    const response = await send({url: source.href, method: 'GET', headers: {Accept: 'application/json'}, allowedOrigins: [source.origin], timeoutMs: 30_000, maxBytes: MAX_BYTES});
    if (response.status !== 200 || !object(response.data)) fail(`${appId}: the Discovery source answered HTTP ${response.status}; nothing was written.`);
    const {revision, methods} = methodPaths(response.data, ids, {prefixes: PROXY_CONFIGS.get(appId).pathPrefixes});
    if (typeof revision !== 'string' || !/^[0-9]{8}$/.test(revision)) fail(`${appId}: the Discovery document has no eight-digit revision; nothing was written.`);
    if (revision !== SCOPES_REVISION) differences.push(...scopeDifferences(response.data, ids, scopes.apps[appId].methods).map(line => `${appId} (revision ${revision}, scope facts ${SCOPES_REVISION}) ${line}`));
    apps[appId] = {source: source.href, revision, methods};
  }
  const paths = {note: NOTE, apps}, problems = checkPaths(paths, scopes);
  if (problems.length) fail(`The recorded paths do not check: ${problems.join(' ')}`);
  writeFileSync(path.join(root, PATHS_FILE), serialize(paths));
  return {paths, differences};
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.some(arg => arg !== '--record')) { console.error('Usage: node scripts/google-method-paths.mjs [--record]'); process.exit(2); }
  if (args.includes('--record')) {
    const {paths, differences} = await recordPaths();
    for (const appId of GOOGLE_APPS) console.log(`${appId}: ${Object.keys(paths.apps[appId].methods).length} methods at revision ${paths.apps[appId].revision}`);
    console.log(`Wrote ${PATHS_FILE}.`);
    if (differences.length) {
      console.log(`Google now serves different scopes for ${differences.length} reviewed method(s). ${SCOPES_FILE} was not changed (it feeds the signed defaults); bring these to Sami:`);
      for (const line of differences) console.log(`  ${line}`);
    }
  } else {
    const file = path.join(ROOT, PATHS_FILE);
    const problems = existsSync(file) ? checkPaths(readJson(file), readJson(path.join(ROOT, SCOPES_FILE))) : [`${PATHS_FILE} is not recorded: run node scripts/google-method-paths.mjs --record`];
    for (const problem of problems) console.error(problem);
    if (problems.length) process.exit(1);
    console.log(`${PATHS_FILE}: ${GOOGLE_APPS.length} apps check against the reviewed rows, the proxy settings and the scope facts.`);
  }
}

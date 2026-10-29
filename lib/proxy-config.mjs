import {readdirSync, readFileSync} from 'node:fs';
import {canonicalHash} from './compiler.mjs';
import {PERMISSION_GROUPS, parseTemplate, memberKey, looseShape} from './permission-groups.mjs';
import {aliasVariants} from './proxy-match.mjs';
// An alias maps one root resource to another, e.g. /repos/{owner}/{repo} to /repositories/{repository_id}:
// one literal segment followed only by parameters, on both sides. Nothing else can be re-routed into a row.
const rootAlias = path => {try {const {segments} = parseTemplate(`GET ${path}`); return segments.length >= 2 && segments[0].kind === 'literal' && segments.slice(1).every(part => part.kind === 'param');} catch {return false;}};
import {proxyBase} from './proxy-request.mjs';

// F08.0b: each app's reviewed proxy settings (docs/F08.0-GOVERNED-PROXY.md sections 2 to 5), as data in
// catalog/proxy/<appId>.json. An app without a file has no proxy. The settings say where requests may go
// (one reviewed base and its prefixes), how they are read (REST or RPC), what callers may never send, which
// write rows the owner may set to Allow for the proxy, and which operations stay typed-only.
const KEYS = 'acceptTypes,aliases,apiBase,appId,arrayParameters,documentedRoutes,inheritFamilies,pathPrefixes,proxyAllowable,reservedBodyFields,reservedParameters,schemaVersion,style,typedOnly';
const NAME = /^[A-Za-z0-9_.~:[\]-]{1,128}$/;
const list = (value, test, max = 200) => Array.isArray(value) && value.length <= max && new Set(value).size === value.length && value.every(item => typeof item === 'string' && test(item));
function invalid(appId, message) {throw new Error(`Proxy settings for ${appId}: ${message}`);}

const ENTRY = /^((?:GET|HEAD|POST|PUT|PATCH|DELETE) \/\S*)\|([A-Za-z_][A-Za-z0-9_.-]{0,63})$/;
/** F10.7: a {+x} mark of an app with documented routes is never a guess. It is the provider's own mark (multiSegment, GitHub's
 *  x-multi-segment) or Fabric's reviewed reading of the provider's prose (reviewedMultiSegment). Both read "METHOD path|name", name
 *  being a parameter of the route. A reviewed entry is a documented route the provider does not mark itself, read at its last segment.
 *  A route list that records neither list says nothing about marks, so there is nothing to compare it with. */
function multiSegmentMarks(appId, definition, routes) {
  if (!Object.hasOwn(routes, 'multiSegment') && !Object.hasOwn(routes, 'reviewedMultiSegment')) return;
  const entries = (key, last) => {
    const value = Object.hasOwn(routes, key) ? routes[key] : [], of = entry => ENTRY.exec(entry);
    if (!list(value, entry => Boolean(of(entry)) && (last ? of(entry)[1].endsWith(`/{${of(entry)[2]}}`) : of(entry)[1].includes(`/{${of(entry)[2]}}`))))
      invalid(appId, `${key} lists "METHOD path|name" entries, each once, each naming a parameter of the route${last ? ' in its last segment' : ''}.`);
    return value;
  };
  const marks = entries('multiSegment', false), reviewed = entries('reviewedMultiSegment', true);
  for (const entry of reviewed) if (!routes.routes.includes(entry.slice(0, entry.lastIndexOf('|'))) || marks.includes(entry))
    invalid(appId, `${entry} in reviewedMultiSegment must be a documented route the provider does not mark itself.`);
  for (const group of definition.groups) for (const request of group.requests) {
    const rest = /\{\+([^}]+)\}$/.exec(request);
    if (rest && ![...marks, ...reviewed].includes(`${request.slice(0, rest.index)}{${rest[1]}}|${rest[1]}`))
      invalid(appId, `${request} marks a parameter as multi-segment, but neither the provider's own marks nor Fabric's reviewed list name it.`);
  }
}

/** Validates one app's proxy settings against its reviewed permission groups and the catalog's allowed origins. */
export function validateProxyConfig(config, {groups = PERMISSION_GROUPS, allowedOrigins, routes = null} = {}) {
  if (!config || typeof config !== 'object' || Object.keys(config).sort().join() !== KEYS || config.schemaVersion !== 1 || typeof config.appId !== 'string') throw new Error('Proxy settings need exactly the documented fields and schemaVersion 1.');
  const {appId} = config, definition = groups.get(appId);
  if (!definition) invalid(appId, 'there are no reviewed permission rows for this app.');
  let base;
  try {base = proxyBase(config.apiBase);} catch {invalid(appId, 'apiBase must be an https origin with an optional base path.');}
  if (!Array.isArray(allowedOrigins) || !allowedOrigins.includes(base.origin)) invalid(appId, `apiBase ${base.origin} is not one of the app's approved origins.`);
  if (!['rest', 'rpc'].includes(config.style)) invalid(appId, 'style is rest or rpc.');
  if (!list(config.pathPrefixes, prefix => /^\/(?:[A-Za-z0-9._~-]+\/)*$/.test(prefix), 20) || !config.pathPrefixes.length) invalid(appId, 'pathPrefixes are "/" or "/segment/.../".');
  if (!list(config.acceptTypes, type => /^[a-z]+\/[a-z0-9.+-]+$/.test(type), 20) || !config.acceptTypes.length) invalid(appId, 'acceptTypes are media types.');
  for (const field of ['reservedParameters', 'reservedBodyFields', 'arrayParameters']) if (!list(config[field], name => NAME.test(name))) invalid(appId, `${field} are parameter names.`);
  if (!list(config.inheritFamilies, name => /^[a-z][a-z0-9_]{0,63}$/.test(name), 50) || (config.style !== 'rpc' && config.inheritFamilies.length)) invalid(appId, 'inheritFamilies are lower-case method families, for RPC apps only.');
  if (!Array.isArray(config.aliases) || config.aliases.length > 20 || config.aliases.some(alias => !alias || Object.keys(alias).sort().join() !== 'from,to' || typeof alias.from !== 'string' || typeof alias.to !== 'string'
    || !rootAlias(alias.from) || !rootAlias(alias.to))) invalid(appId, 'aliases map one root resource to another: one literal segment followed only by parameters on both sides.');
  if (config.documentedRoutes !== null && (typeof config.documentedRoutes !== 'string' || !/^[a-z][a-z0-9-]*\.routes\.json$/.test(config.documentedRoutes) || !Array.isArray(routes?.routes))) invalid(appId, 'documentedRoutes names a routes file in catalog/proxy.');
  if (config.documentedRoutes !== null) multiSegmentMarks(appId, definition, routes);
  // Proxy Allow for a change is offered only on reviewed in-account rows; never for deletes, Never rows or reads, and
  // never (T4) for a row Fabric locks or one that reaches other people.
  if (!list(config.proxyAllowable, id => typeof id === 'string', 40)) invalid(appId, 'proxyAllowable lists row ids.');
  for (const id of config.proxyAllowable) {
    const group = definition.groups.find(entry => entry.id === id);
    if (!group || group.effect !== 'write' || group.defaultMode === 'deny' || group.stayInAccount !== true || group.locked || group.audience) invalid(appId, `${id} cannot be proxyAllowable: only an existing write row reviewed as staying inside the account and reversible, never a locked row or one that reaches other people.`);
  }
  // F10.3: a body route never carries a request into a row the proxy may Allow from one it may not. An RPC app has no body
  // routes: its GET requests carry their arguments in the query, which a route never reads.
  for (const group of definition.groups) for (const route of group.bodyRoutes ?? []) {
    if (config.style === 'rpc') invalid(appId, `${group.id} has body routes, which an RPC app cannot have: its GET requests carry their arguments in the query.`);
    if (config.proxyAllowable.includes(route.to) && !config.proxyAllowable.includes(group.id)) invalid(appId, `${group.id} routes requests into ${route.to}, which is proxyAllowable while ${group.id} is not.`);
  }
  // Two templates with one loose shape in different rows, alias forms included, would send one request to two rows.
  const shapes = new Map();
  for (const group of definition.groups) for (const request of group.requests) for (const variant of aliasVariants(request, config.aliases)) {
    let shape;
    try {shape = looseShape(parseTemplate(variant));} catch (error) {invalid(appId, error.message);}
    if (shapes.has(shape) && shapes.get(shape) !== group.id) invalid(appId, `${variant} routes the same requests as a template in ${shapes.get(shape)}.`);
    shapes.set(shape, group.id);
  }
  const members = new Set(definition.groups.flatMap(group => [...group.operations, ...group.requests.map(memberKey)]));
  if (!list(config.typedOnly, member => members.has(member) || members.has(memberKey(member)))) invalid(appId, 'typedOnly lists reviewed operations of this app.');
  const documented = routes?.routes ? Object.freeze([...routes.routes]) : Object.freeze([]);
  // F10.7 (open question 16): Fabric's reviewed list and its note are not hashed. No code routes by them, and the routing they allow is
  // bound through the {+x} templates of the rows; so adding them moves no proxy settings hash, binding or client proxy grant.
  const {reviewedNote, reviewedMultiSegment, ...published} = routes ?? {};
  return Object.freeze({...config, typedOnly: Object.freeze(config.typedOnly.map(memberKey)), documented, configHash: canonicalHash({config, routes: routes ? canonicalHash(published) : null})});
}

/** The reviewed proxy settings shipped in catalog/proxy, keyed by app, checked against catalog/apps.json. */
export function loadProxyConfigs(directory = new URL('../catalog/proxy/', import.meta.url), {groups = PERMISSION_GROUPS, apps = JSON.parse(readFileSync(new URL('../catalog/apps.json', import.meta.url), 'utf8'))} = {}) {
  const byApp = new Map(), catalog = Array.isArray(apps) ? apps : apps.apps;
  let files = [];
  try {files = readdirSync(directory).filter(name => name.endsWith('.json') && !name.endsWith('.routes.json')).sort();} catch {return byApp;}
  for (const name of files) {
    const raw = JSON.parse(readFileSync(new URL(name, directory), 'utf8'));
    const app = catalog.find(entry => entry.id === raw.appId);
    const routes = typeof raw.documentedRoutes === 'string' ? JSON.parse(readFileSync(new URL(raw.documentedRoutes, directory), 'utf8')) : null;
    const config = validateProxyConfig(raw, {groups, allowedOrigins: app?.apiOrigins || app?.allowedOrigins, routes});
    if (`${config.appId}.json` !== name) throw new Error(`Proxy settings file ${name} must be named after its appId.`);
    byApp.set(config.appId, config);
  }
  return byApp;
}

export const PROXY_CONFIGS = loadProxyConfigs();

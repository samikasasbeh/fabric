// F09.1 security model (docs/F09-COMPILER-COVERAGE.md). One reading of an OpenAPI operation's security for the
// compiler and discovery: which alternatives Fabric can serve, which it drops and why, which request locations
// carry credentials, and which URLs exchange them. Credentials never become agent inputs.

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = message => { throw new Error(message); };
const UNSAFE = new Set(['__proto__', 'prototype', 'constructor']);

/** Credential kinds Fabric can send today: OAuth and bearer tokens. API keys and basic come in F09.6. */
export const SERVABLE = Object.freeze(['oauth', 'bearer']);

function scheme(document, name, schemes = document.components?.securitySchemes) {
  if (UNSAFE.has(name) || !record(schemes) || !Object.hasOwn(schemes, name)) fail(`Missing security scheme ${name}.`);
  let definition = schemes[name];
  // One level of internal reference, as discovery already allowed.
  if (record(definition) && typeof definition.$ref === 'string') {
    const match = /^#\/components\/securitySchemes\/([A-Za-z0-9_.-]+)$/.exec(definition.$ref);
    if (!match || Object.keys(definition).length !== 1 || UNSAFE.has(match[1]) || !Object.hasOwn(schemes, match[1]) || !record(schemes[match[1]]) || schemes[match[1]].$ref !== undefined) fail(`Missing security scheme ${name}.`);
    definition = schemes[match[1]];
  }
  if (!record(definition)) fail(`Missing security scheme ${name}.`);
  return definition;
}

/** The credential kind a scheme asks for. The HTTP auth scheme name is case-insensitive (RFC 9110 section 11.1). */
export function schemeKind(definition) {
  if (definition.type === 'oauth2' || definition.type === 'openIdConnect') return 'oauth';
  if (definition.type === 'http' && typeof definition.scheme === 'string') {
    const name = definition.scheme.toLowerCase();
    return name === 'bearer' ? 'bearer' : name === 'basic' ? 'basic' : `http:${name}`;
  }
  if (definition.type === 'apiKey' && ['header', 'query', 'cookie'].includes(definition.in) && typeof definition.name === 'string') return `api-key:${definition.in}:${definition.name.toLowerCase()}`;
  return `other:${typeof definition.type === 'string' ? definition.type : 'unknown'}`;
}

/**
 * An operation's security alternatives. Within one alternative every scheme is required; any one alternative is
 * enough. Alternatives that need a kind Fabric cannot serve are dropped with a reason. An empty requirement means
 * anonymous access. With no requirement at all, the operation declares none.
 * @param {Record<string, any>} document
 * @param {Record<string, any>} operation
 * @param {{servable?: readonly string[], schemes?: Record<string, unknown>}} [options] `schemes` resolves names
 * against the source's own schemes when `document` is a scoped copy of one operation.
 */
export function securityRequirements(document, operation, {servable = SERVABLE, schemes: sourceSchemes} = {}) {
  const security = operation.security ?? document.security ?? [];
  if (!Array.isArray(security)) fail('OpenAPI security must be an array of alternatives.');
  const alternatives = [], dropped = [];
  for (const requirement of security) {
    if (!record(requirement)) fail('Invalid OpenAPI security requirement.');
    const kinds = [], scopes = [], schemes = Object.keys(requirement);
    for (const name of schemes) {
      const values = requirement[name];
      if (!Array.isArray(values) || values.some(value => typeof value !== 'string')) fail('Invalid OpenAPI required scopes.');
      kinds.push(schemeKind(scheme(document, name, sourceSchemes ?? document.components?.securitySchemes)));
      scopes.push(...values);
    }
    const unservable = schemes.filter((name, index) => !servable.includes(kinds[index]));
    if (unservable.length) dropped.push({schemes, reason: `Security scheme ${unservable[0]} is not supported by the bearer-credential broker.`});
    else alternatives.push({schemes, kinds, scopes: [...new Set(scopes)]});
  }
  return {declared: security.length > 0, alternatives, dropped};
}

/** Throws when an operation declares security and none of it can be served. */
export function assertServable(requirements) {
  if (requirements.declared && !requirements.alternatives.length) fail(requirements.dropped[0]?.reason || 'No security alternative can be served.');
  return requirements;
}

/** Request locations the document's API-key schemes use, as `in:name` (lowercased). Never agent inputs. */
export function credentialLocations(document) {
  const locations = new Set(), schemes = document?.components?.securitySchemes;
  if (!record(schemes)) return locations;
  for (const definition of Object.values(schemes)) {
    if (record(definition) && definition.type === 'apiKey' && typeof definition.name === 'string' && typeof definition.in === 'string') locations.add(`${definition.in}:${definition.name.toLowerCase()}`);
  }
  return locations;
}

/** OAuth endpoints the document declares, as absolute URLs without a trailing slash. An operation there exchanges
 *  credentials. A relative endpoint resolves against the server URL (OAS 3.0.3 section 4.7.2); both readings of the
 *  base, with and without a trailing slash, count, since refusing too much is the safe side. */
export function exchangeUrls(document, base) {
  const urls = new Set(), schemes = document?.components?.securitySchemes;
  if (!record(schemes)) return urls;
  for (const definition of Object.values(schemes)) {
    if (!record(definition) || definition.type !== 'oauth2' || !record(definition.flows)) continue;
    for (const flow of Object.values(definition.flows)) {
      if (!record(flow)) continue;
      for (const key of ['authorizationUrl', 'tokenUrl', 'refreshUrl']) {
        if (typeof flow[key] !== 'string') continue;
        for (const root of base ? [base, `${base}/`] : [undefined]) { try { urls.add(normalizeUrl(new URL(flow[key], root).href)); } catch {} }
      }
    }
  }
  return urls;
}

/**
 * True when an operation URL template reaches one of the endpoints: same origin, same number of path segments, and
 * every segment equal or a template segment ({x}, {x}.json) that an agent could fill with the endpoint's value.
 */
export function reachesEndpoint(template, endpoints) {
  const text = String(template).replace(/#.*$/, ''), slash = text.indexOf('/', text.indexOf('//') + 2);
  let origin;
  try { origin = new URL(text.replace(/\{[^}]*\}/g, 'x')).origin; } catch { return false; }
  const segments = (slash < 0 ? '' : text.slice(slash)).replace(/\/+$/, '').split('/');
  for (const endpoint of endpoints) {
    let url;
    try { url = new URL(endpoint); } catch { continue; }
    if (url.origin !== origin) continue;
    const parts = url.pathname.replace(/\/+$/, '').split('/');
    if (parts.length === segments.length && parts.every((part, index) => segments[index].includes('{') || segments[index] === part)) return true;
  }
  return false;
}

/** Comparable form of an endpoint URL: no fragment, query or trailing slash; scheme and host lowercased by URL. */
export function normalizeUrl(value) {
  const url = new URL(value.replace(/#.*$/, ''));
  url.search = ''; url.hash = '';
  return url.href.replace(/\/+$/, '');
}

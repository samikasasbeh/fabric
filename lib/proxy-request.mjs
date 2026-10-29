import {createHash} from 'node:crypto';
import {hasHidden} from '../public/hosted-text.js';

// F08.0a: the governed proxy's request normalizer (docs/F08.0-GOVERNED-PROXY.md section 3). It turns an
// agent's {method, path, query, headers, body} into one canonical request, or refuses it with a code,
// before anything else looks at it. What it returns is exactly what is matched, shown, hashed and sent:
// the canonical path, the sorted canonical query and the serialized body bytes.
export const LIMITS = Object.freeze({path: 2048, segments: 32, segmentBytes: 512, queryNames: 50, queryValue: 2048, queryArray: 20, query: 8192,
  headers: 16, headerValue: 1024, headerTotal: 8192, body: 65536, depth: 32, timeoutMin: 1000, timeoutMax: 30000, timeoutDefault: 15000});
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
// Names never accepted in a query, whatever the app: credentials, callbacks and method overrides, plus Google's
// system parameters ($-prefixed names are refused by the name rule itself).
const RESERVED_QUERY = new Set(['access_token', 'oauth_token', 'api_key', 'apikey', 'client_secret', 'callback', 'jsonp', '_method', 'x-http-method-override',
  'x-http-method', 'x-method-override', 'password', 'passwd', 'alt', 'uploadtype', 'upload_protocol']);
/** F10.9: true when a query name is reserved for this app, in any case: one of the names above, or one of the app's own reserved
 *  parameters. The proxy and action steps read this one list. */
export const reservedQueryName = (name, config) => typeof name === 'string'
  && (RESERVED_QUERY.has(name.toLowerCase()) || (config?.reservedParameters || []).some(item => typeof item === 'string' && item.toLowerCase() === name.toLowerCase()));
// Only this name can change an object's prototype when parsed or assigned; other names are ordinary text.
const UNSAFE_NAMES = new Set(['__proto__']);
const HEADERS = new Map([['accept', 'Accept'], ['if-match', 'If-Match'], ['if-none-match', 'If-None-Match'], ['if-modified-since', 'If-Modified-Since'], ['if-unmodified-since', 'If-Unmodified-Since']]);
/** F10.9: the headers a caller may send, by their canonical names. Action steps take the same list (lib/actions.mjs). */
export const CALLER_HEADERS = Object.freeze([...HEADERS.values()]);
// RFC 3986 pchar without ";" (and without "/", which separates segments): unreserved, sub-delims, ":" and "@".
const PCHAR = /^[A-Za-z0-9\-._~!$&'()*+,=:@]$/;
const RAW_SEGMENT = /^(?:[A-Za-z0-9\-._~!$&'()*+,=:@]|%[0-9A-Fa-f]{2})+$/;
const QUERY_NAME = /^[\w.~:[\]-]{1,128}$/;
// ignoreBOM keeps a leading U+FEFF in the text, so it is refused as an invisible character instead of vanishing.
const STRICT_UTF8 = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});

export class ProxyRequestError extends Error {
  constructor(code, message) {super(message); this.code = code;}
}
const fail = (code, message) => {throw new ProxyRequestError(code, message);};
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/** Percent-encodes one decoded segment with the pchar set (minus ";"), upper-case hex. */
function encodeSegment(text) {
  let out = '';
  for (const char of text) out += PCHAR.test(char) ? char : [...Buffer.from(char, 'utf8')].map(byte => `%${byte.toString(16).toUpperCase().padStart(2, '0')}`).join('');
  return out;
}
/** Strict query encoding: encodeURIComponent plus the five characters it leaves alone, so WHATWG URL never rewrites it. */
const encodeQuery = text => encodeURIComponent(text).replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);

/** The decoded segments and canonical form of a relative path; refuses traversal, double encoding and anything ambiguous. */
export function normalizePath(path) {
  if (typeof path !== 'string' || !path.startsWith('/')) fail('invalid_path', 'The path must be a relative path starting with "/".');
  if (path.length > LIMITS.path) fail('request_too_large', `The path is longer than ${LIMITS.path} characters.`);
  if (!/^[\x21-\x7e]+$/.test(path) || /[?#\\;]/.test(path)) fail('invalid_path', 'The path must be printable ASCII without "?", "#", "\\", ";" or spaces. Send the query separately and percent-encode other characters.');
  if (path === '/') return {segments: [], path: '/'};
  const raw = path.slice(1).split('/');
  if (raw.length > LIMITS.segments) fail('request_too_large', `The path has more than ${LIMITS.segments} segments.`);
  const segments = raw.map(segment => {
    if (!segment) fail('invalid_path', 'Empty path segments ("//" or a trailing "/") are not allowed.');
    if (!RAW_SEGMENT.test(segment)) fail('invalid_path', 'A path segment holds a character that must be percent-encoded.');
    let decoded;
    try {decoded = STRICT_UTF8.decode(Buffer.from(segment.replace(/%([0-9A-Fa-f]{2})|([^%])/g, (all, hex, char) => hex ? String.fromCharCode(parseInt(hex, 16)) : char), 'latin1'));}
    catch {fail('invalid_path', 'A path segment is not valid UTF-8 after decoding.');}
    if (!decoded) fail('invalid_path', 'Empty path segments are not allowed.');
    if (decoded === '.' || decoded === '..') fail('invalid_path', 'Dot segments are not allowed.');
    if (/[/\\%]/.test(decoded)) fail('invalid_path', 'Encoded slashes, backslashes and double encoding are not allowed.');
    if (/\p{Cc}/u.test(decoded) || hasHidden(decoded)) fail('invalid_path', 'A path segment holds a control, invisible or direction-changing character.');
    if (UNSAFE_NAMES.has(decoded)) fail('invalid_path', 'That path segment is not allowed.');
    if (Buffer.byteLength(decoded) > LIMITS.segmentBytes) fail('request_too_large', `A path segment is longer than ${LIMITS.segmentBytes} bytes.`);
    return decoded;
  });
  return {segments, path: `/${segments.map(encodeSegment).join('/')}`};
}

function normalizeQuery(query, config) {
  if (query === undefined) return '';
  if (!record(query)) fail('invalid_request', 'The query is an object of names and string values.');
  const names = Object.keys(query);
  if (names.length > LIMITS.queryNames) fail('request_too_large', `At most ${LIMITS.queryNames} query parameters.`);
  const arrays = new Set(config.arrayParameters || []), allowed = config.queryParameters ? new Set(config.queryParameters) : null;
  const value = (name, text) => {
    if (typeof text !== 'string' || text.length > LIMITS.queryValue || !text.isWellFormed() || /\p{Cc}/u.test(text)) fail('parameter_not_allowed', `The value of ${name} must be a string of at most ${LIMITS.queryValue} characters without control characters.`);
    return text;
  };
  const pairs = [];
  for (const name of names.sort()) {
    if (!QUERY_NAME.test(name) || UNSAFE_NAMES.has(name)) fail('parameter_not_allowed', `The query parameter name ${JSON.stringify(name).slice(0, 140)} is not allowed.`);
    if (reservedQueryName(name, config)) fail('parameter_not_allowed', `The query parameter ${name} is reserved: Fabric adds credentials itself and refuses overrides.`);
    if (allowed && !allowed.has(name)) fail('parameter_not_allowed', `${name} is not a documented parameter of this app.`);
    const given = query[name];
    if (Array.isArray(given)) {
      if (!arrays.has(name)) fail('parameter_not_allowed', `${name} cannot be repeated.`);
      if (!given.length || given.length > LIMITS.queryArray) fail('request_too_large', `${name} takes 1 to ${LIMITS.queryArray} values.`);
      for (const item of given) pairs.push(`${encodeQuery(name)}=${encodeQuery(value(name, item))}`);
    } else pairs.push(`${encodeQuery(name)}=${encodeQuery(value(name, given))}`);
  }
  const canonical = pairs.join('&');
  if (canonical.length > LIMITS.query) fail('request_too_large', `The query is longer than ${LIMITS.query} characters.`);
  return canonical;
}

function normalizeHeaders(headers, config) {
  if (headers === undefined) return {};
  if (!record(headers)) fail('invalid_request', 'Headers are an object of names and values.');
  const entries = Object.entries(headers);
  if (entries.length > LIMITS.headers) fail('request_too_large', `At most ${LIMITS.headers} headers.`);
  const out = {}, seen = new Set(), accept = new Set(config.acceptTypes || ['application/json']);
  let total = 0;
  for (const [name, value] of entries) {
    if (!/^[A-Za-z0-9-]{1,64}$/.test(name)) fail('header_not_allowed', `The header name ${JSON.stringify(name).slice(0, 80)} is not allowed.`);
    const key = name.toLowerCase();
    if (seen.has(key)) fail('header_not_allowed', `The header ${name} is repeated.`);
    seen.add(key);
    if (!HEADERS.has(key)) fail('header_not_allowed', `The header ${name} is not allowed: Fabric adds credentials and provider headers itself, and only Accept and conditional headers may be sent.`);
    if (typeof value !== 'string' || !/^[\x20-\x7e]*$/.test(value)) fail('header_not_allowed', `The value of ${name} must be printable ASCII.`);
    if (value.length > LIMITS.headerValue) fail('request_too_large', `The value of ${name} is longer than ${LIMITS.headerValue} characters.`);
    if (key === 'accept' && !accept.has(value)) fail('header_not_allowed', `Accept must be one of: ${[...accept].join(', ')}.`);
    total += name.length + value.length;
    out[HEADERS.get(key)] = value;
  }
  if (total > LIMITS.headerTotal) fail('request_too_large', `Headers are longer than ${LIMITS.headerTotal} characters in total.`);
  return out;
}

/** Plain JSON only: finite numbers, plain objects, bounded depth, no prototype-shaped keys, and no reserved key at any depth
 *  (F10.3), objects inside arrays included. */
function checkJson(value, depth, reserved) {
  if (depth > LIMITS.depth) fail('unsupported_body', `The body is nested deeper than ${LIMITS.depth} levels.`);
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {if (!Number.isFinite(value)) fail('unsupported_body', 'Numbers in the body must be finite.'); return;}
  if (Array.isArray(value)) {for (const item of value) checkJson(item, depth + 1, reserved); return;}
  if (typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('unsupported_body', 'The body must be plain JSON.');
  for (const key of Object.keys(value)) {
    if (UNSAFE_NAMES.has(key)) fail('unsupported_body', `The body key ${key} is not allowed.`);
    if (reserved.has(key)) fail('parameter_not_allowed', `The body field ${key} is reserved.`);
    checkJson(value[key], depth + 1, reserved);
  }
}

function normalizeBody(body, method, config, maxBodyBytes = LIMITS.body) {
  if (body === undefined) return null;
  if (method === 'GET') fail('unsupported_body', 'A GET request has no body.');
  checkJson(body, 1, new Set(['_method', ...(config.reservedBodyFields || [])]));
  const wire = JSON.stringify(body);
  if (Buffer.byteLength(wire) > maxBodyBytes) fail('request_too_large', `The body is larger than ${maxBodyBytes} bytes once serialized.`);
  return wire;
}

/** The reviewed base an app's proxy requests resolve against: an https origin and an optional base path. */
export function proxyBase(apiBase) {
  let url;
  try {url = new URL(apiBase);} catch {fail('proxy_unavailable', 'The app has no valid reviewed proxy base.');}
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || (url.port && url.port !== '443') || /%|\{|\}|\/\.\.?(\/|$)/.test(url.pathname)) fail('proxy_unavailable', 'The app has no valid reviewed proxy base.');
  return {origin: url.origin, basePath: url.pathname.replace(/\/+$/, '')};
}

/**
 * Normalizes one proxy request against an app's reviewed proxy config
 * ({apiBase, style: 'rest'|'rpc', pathPrefixes, acceptTypes, reservedParameters, reservedBodyFields, arrayParameters, queryParameters}).
 * Returns the canonical request; throws ProxyRequestError with a code on anything it cannot make exact. `maxBodyBytes` keeps the proxy's
 * own body limit unless a caller sets another: an action step's request takes the network's 1 MiB cap (F10.11 part g).
 */
export function normalizeProxyRequest(input, config, {timeoutMs, maxBodyBytes = LIMITS.body} = {}) {
  if (!record(input) || Object.keys(input).some(key => !['method', 'path', 'query', 'headers', 'body'].includes(key))) fail('invalid_request', 'A request is {method, path, query?, headers?, body?}.');
  if (!record(config) || !['rest', 'rpc'].includes(config.style)) fail('proxy_unavailable', 'This app has no reviewed proxy config.');
  const {method} = input;
  if (typeof method !== 'string' || !METHODS.has(method)) fail('method_not_allowed', 'Use GET, POST, PUT, PATCH or DELETE.');
  if (config.style === 'rpc' && !['GET', 'POST'].includes(method)) fail('method_not_allowed', 'This app takes GET or POST only.');
  const {segments, path} = normalizePath(input.path);
  if (config.style === 'rpc' && segments.length !== 1) fail('invalid_path', 'Methods of this app are a single path segment, such as /chat.postMessage.');
  const prefixes = config.pathPrefixes?.length ? config.pathPrefixes : ['/'];
  if (!prefixes.some(prefix => prefix === '/' || path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`))) fail('invalid_path', `The path must start with ${prefixes.join(' or ')}.`);
  const query = normalizeQuery(input.query, config);
  const headers = normalizeHeaders(input.headers, config);
  const body = normalizeBody(input.body, method, config, maxBodyBytes);
  // One argument cannot hide in two places for an RPC app.
  if (config.style === 'rpc' && method === 'POST' && query) fail('parameter_not_allowed', 'Send the arguments of a POST in the body, not the query.');
  const timeout = timeoutMs === undefined ? LIMITS.timeoutDefault : timeoutMs;
  if (!Number.isSafeInteger(timeout) || timeout < LIMITS.timeoutMin || timeout > LIMITS.timeoutMax) fail('invalid_request', `timeoutMs is ${LIMITS.timeoutMin} to ${LIMITS.timeoutMax}.`);
  // Backstop: the canonical path never holds an empty segment or a trailing slash.
  if (!/^\/(?:[^/]+(?:\/[^/]+)*)?$/.test(path)) fail('invalid_path', 'The path is not a single canonical path.');
  const base = proxyBase(config.apiBase);
  const url = `${base.origin}${base.basePath}${path}${query ? `?${query}` : ''}`;
  // The URL sent must be the URL shown: the parser may not rewrite the origin, the path or the query.
  const parsed = new URL(url);
  if (parsed.origin !== base.origin || parsed.pathname !== `${base.basePath}${path}` || parsed.search !== (query ? `?${query}` : '') || parsed.href !== url) fail('invalid_path', 'The request would not be sent exactly as shown.');
  return Object.freeze({method, segments: Object.freeze(segments), path, query, url, headers: Object.freeze(headers), body,
    bodyHash: body === null ? null : createHash('sha256').update(body).digest('hex'), bodyBytes: body === null ? 0 : Buffer.byteLength(body), timeoutMs: timeout});
}
